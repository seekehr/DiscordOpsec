/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { createHash } from "crypto";
import { app, IpcMainInvokeEvent, safeStorage } from "electron";
import { mkdir, readFile, rm, stat, writeFile } from "fs/promises";
import { join } from "path";

const DATA_DIR = join(app.getPath("userData"), "DiscordOpsec");
const KEY_FILE = join(DATA_DIR, "vt-key.bin");

const CDN_HOSTS = new Set(["cdn.discordapp.com", "media.discordapp.net"]);
const SHA256 = /^[a-f0-9]{64}$/;

// ---------- API key (kept only in the main process, encrypted at rest) ----------

let apiKey: string | null | undefined;

async function getApiKey() {
    if (apiKey !== undefined) return apiKey;
    try {
        apiKey = safeStorage.decryptString(await readFile(KEY_FILE));
    } catch {
        apiKey = null;
    }
    return apiKey;
}

export async function hasApiKey(_: IpcMainInvokeEvent) {
    return !!await getApiKey();
}

export async function setApiKey(_: IpcMainInvokeEvent, key: string): Promise<{ ok: true; } | { ok: false; error: string; }> {
    if (!key) {
        apiKey = null;
        await rm(KEY_FILE, { force: true });
        return { ok: true };
    }
    if (!/^[a-f0-9]{64}$/i.test(key)) return { ok: false, error: "That doesn't look like a VirusTotal API key (64 hex characters)" };
    if (!safeStorage.isEncryptionAvailable()) return { ok: false, error: "OS encryption is unavailable, refusing to store the key in plain text" };

    await mkdir(DATA_DIR, { recursive: true });
    await writeFile(KEY_FILE, safeStorage.encryptString(key), { mode: 0o600 });
    apiKey = key;
    return { ok: true };
}

// ---------- Serial queues ----------

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

function serialQueue(maxPending: number) {
    let tail: Promise<unknown> = Promise.resolve();
    let pending = 0;
    return <T>(fn: () => Promise<T>): Promise<T> => {
        if (pending >= maxPending) return Promise.reject(new Error("Too many pending requests, try again later"));
        pending++;
        const run = tail.then(fn).finally(() => pending--);
        tail = run.catch(() => { });
        return run;
    };
}

const vtQueue = serialQueue(25);
const hashQueue = serialQueue(10);

const recent: number[] = [];
let cooldownUntil = 0;

async function waitForSlot(perMinute: number) {
    const limit = Math.max(1, Math.min(perMinute || 4, 1000));
    for (; ;) {
        const now = Date.now();
        while (recent.length && now - recent[0] >= 60_000) recent.shift();
        const wait = Math.max(cooldownUntil - now, recent.length >= limit ? 60_000 - (now - recent[0]) : 0);
        if (wait <= 0) break;
        await sleep(wait + 50);
    }
    recent.push(Date.now());
}

// ---------- VirusTotal ----------

export interface VtStats {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
}

export type VtResult =
    | { kind: "found"; stats: VtStats; label?: string; scannedAt?: number; }
    | { kind: "unknown"; }
    | { kind: "error"; message: string; retryable: boolean; };

async function vtGet(path: string, perMinute: number): Promise<VtResult> {
    const key = await getApiKey();
    if (!key) return { kind: "error", message: "No VirusTotal API key set", retryable: false };

    return vtQueue(async () => {
        await waitForSlot(perMinute);
        let res: Response;
        try {
            res = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
                headers: { "x-apikey": key, accept: "application/json" },
                signal: AbortSignal.timeout(20_000)
            });
        } catch {
            return { kind: "error", message: "Couldn't reach VirusTotal", retryable: true };
        }

        if (res.status === 404) return { kind: "unknown" };
        if (res.status === 401 || res.status === 403) return { kind: "error", message: "VirusTotal rejected the API key", retryable: false };
        if (res.status === 429) {
            const body = await res.json().catch(() => null);
            const daily = body?.error?.code === "QuotaExceededError";
            cooldownUntil = Date.now() + (daily ? 60 * 60_000 : 60_000);
            return { kind: "error", message: daily ? "VirusTotal daily quota used up" : "VirusTotal rate limit hit", retryable: true };
        }
        if (!res.ok) return { kind: "error", message: `VirusTotal error ${res.status}`, retryable: true };

        const attr = (await res.json())?.data?.attributes ?? {};
        const s = attr.last_analysis_stats ?? {};
        return {
            kind: "found",
            stats: {
                malicious: s.malicious | 0,
                suspicious: s.suspicious | 0,
                harmless: s.harmless | 0,
                undetected: s.undetected | 0
            },
            label: attr.popular_threat_classification?.suggested_threat_label,
            scannedAt: attr.last_analysis_date
        };
    });
}

export function lookupFile(_: IpcMainInvokeEvent, sha256: string, perMinute: number) {
    if (!SHA256.test(sha256)) return Promise.resolve<VtResult>({ kind: "error", message: "Invalid hash", retryable: false });
    return vtGet(`files/${sha256}`, perMinute);
}

/** Only called after the user explicitly asks to check a link. Sends the URL to VirusTotal. */
export function lookupUrl(_: IpcMainInvokeEvent, url: string, perMinute: number) {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return Promise.resolve<VtResult>({ kind: "error", message: "Unsupported URL", retryable: false });
    return vtGet(`urls/${Buffer.from(u.href).toString("base64url")}`, perMinute);
}

/** Streams a Discord CDN attachment through SHA-256 without writing it anywhere. */
export function hashAttachment(_: IpcMainInvokeEvent, url: string, maxBytes: number): Promise<string> {
    const u = new URL(url);
    if (u.protocol !== "https:" || !CDN_HOSTS.has(u.hostname)) return Promise.reject(new Error("Not a Discord attachment URL"));

    return hashQueue(async () => {
        const res = await fetch(u, { signal: AbortSignal.timeout(180_000) });
        if (!res.ok || !res.body) throw new Error(`Download failed (${res.status})`);
        if (Number(res.headers.get("content-length")) > maxBytes) throw new Error("File too large to hash");

        const hash = createHash("sha256");
        const reader = res.body.getReader();
        let total = 0;
        for (; ;) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maxBytes) {
                await reader.cancel();
                throw new Error("File too large to hash");
            }
            hash.update(value);
        }
        return hash.digest("hex");
    });
}

// ---------- Domain blocklists ----------

const LISTS = {
    antiscam: {
        url: "https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.json",
        parse: (text: string) => JSON.parse(text) as string[]
    },
    phishingArmy: {
        url: "https://phishing.army/download/phishing_army_blocklist.txt",
        parse: (text: string) => text.split("\n")
    }
};

type ListName = keyof typeof LISTS;

const LIST_TTL = 24 * 60 * 60_000;
const MAX_LIST_BYTES = 30 * 1024 * 1024;
const DOMAIN = /^[a-z0-9.-]+\.[a-z0-9-]+$/;

const loaded = new Map<ListName, Set<string>>();
const loading = new Map<ListName, Promise<void>>();
const lastAttempt = new Map<ListName, number>();
const listFile = (name: ListName) => join(DATA_DIR, `list-${name}.txt`);

async function download(name: ListName) {
    const res = await fetch(LISTS[name].url, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_LIST_BYTES) throw new Error("List too large");

    const domains = LISTS[name].parse(text)
        .map(d => String(d).trim().toLowerCase())
        .filter(d => DOMAIN.test(d));
    if (domains.length < 100) throw new Error("List looks empty");

    await mkdir(DATA_DIR, { recursive: true });
    await writeFile(listFile(name), domains.join("\n"));
    loaded.set(name, new Set(domains));
}

function ensureList(name: ListName): Promise<void> {
    const inFlight = loading.get(name);
    if (inFlight) return inFlight;

    const p = (async () => {
        let age = Infinity;
        try {
            age = Date.now() - (await stat(listFile(name))).mtimeMs;
            if (!loaded.has(name))
                loaded.set(name, new Set((await readFile(listFile(name), "utf8")).split("\n")));
        } catch { }

        if (age > LIST_TTL && Date.now() - (lastAttempt.get(name) ?? 0) > 60 * 60_000) {
            lastAttempt.set(name, Date.now());
            // A stale copy keeps working while we refresh; a missing one has to wait for the download.
            const refresh = download(name).catch(e => console.warn(`[DiscordOpsec] Failed to update ${name} list:`, e));
            if (!loaded.has(name)) await refresh;
        }
    })().finally(() => loading.delete(name));

    loading.set(name, p);
    return p;
}

function syncLists(enabled: ListName[]) {
    for (const name of loaded.keys())
        if (!enabled.includes(name)) loaded.delete(name);
    return Promise.all(enabled.filter(n => n in LISTS).map(ensureList));
}

/** Loads/refreshes enabled lists and frees disabled ones. Cheap when everything is fresh. */
export async function prepareBlocklists(_: IpcMainInvokeEvent, enabled: ListName[]) {
    await syncLists(enabled);
}

/** Returns the name of the list containing the host or one of its parent domains. Only the host is checked, locally. */
export async function checkDomain(_: IpcMainInvokeEvent, host: string, enabled: ListName[]): Promise<string | null> {
    await syncLists(enabled);
    const labels = host.toLowerCase().replace(/\.$/, "").split(".");
    for (let i = 0; i < labels.length - 1; i++) {
        const candidate = labels.slice(i).join(".");
        for (const [name, set] of loaded)
            if (set.has(candidate)) return name === "antiscam" ? "Discord-AntiScam" : "Phishing Army";
    }
    return null;
}
