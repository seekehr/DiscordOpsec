/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import * as DataStore from "@api/DataStore";
import { Logger } from "@utils/Logger";
import { ChannelStore, useEffect, useReducer,UserStore } from "@webpack/common";

import type { VtResult } from "./native";
import { Native, parseList, ScanMode, ScanScope, settings } from "./settings";

const logger = new Logger("DiscordOpsec");

interface Attachment {
    id: string;
    filename: string;
    size: number;
    url: string;
}

type ScanState =
    | { step: "idle"; }
    | { step: "hashing" | "querying"; }
    | { step: "done"; sha256: string; result: VtResult; }
    | { step: "failed"; message: string; retryable: boolean; };

// ---------- Persistent cache (single DataStore entry, loaded once) ----------

const CACHE_KEY = "DiscordOpsec_vtCache";
const MAX_ENTRIES = 1000;
const TTL_FOUND = 24 * 60 * 60_000;
const TTL_UNKNOWN = 6 * 60 * 60_000;

interface Cache {
    hashes: Record<string, string>;
    results: Record<string, { at: number; result: VtResult; }>;
}

let cachePromise: Promise<Cache> | null = null;
const getCache = () => cachePromise ??= DataStore.get<Cache>(CACHE_KEY)
    .then(c => c ?? { hashes: {}, results: {} })
    .catch(() => ({ hashes: {}, results: {} }));

function trim(record: Record<string, unknown>) {
    const keys = Object.keys(record);
    for (let i = 0; i < keys.length - MAX_ENTRIES; i++) delete record[keys[i]];
}

async function saveCache(mutate: (c: Cache) => void) {
    const cache = await getCache();
    mutate(cache);
    trim(cache.hashes);
    trim(cache.results);
    DataStore.set(CACHE_KEY, cache).catch(e => logger.error("Failed to persist scan cache", e));
}

// ---------- In-memory state with per-attachment subscribers ----------

const states = new Map<string, ScanState>();
const listeners = new Map<string, Set<() => void>>();

function setState(id: string, state: ScanState) {
    states.delete(id);
    states.set(id, state);
    if (states.size > 300) states.delete(states.keys().next().value!);
    listeners.get(id)?.forEach(fn => fn());
}

function useScanState(id: string): ScanState {
    const [, rerender] = useReducer((x: number) => x + 1, 0);
    useEffect(() => {
        let set = listeners.get(id);
        if (!set) listeners.set(id, set = new Set());
        set.add(rerender);
        return () => {
            set!.delete(rerender);
            if (!set!.size) listeners.delete(id);
        };
    }, [id]);
    return states.get(id) ?? { step: "idle" };
}

// ---------- Scanning ----------

async function scan(att: Attachment) {
    const current = states.get(att.id)?.step;
    if (current === "hashing" || current === "querying") return;
    if (!Native) return setState(att.id, { step: "failed", message: "VirusTotal lookups need the desktop client", retryable: false });

    try {
        if (!await Native.hasApiKey())
            return setState(att.id, { step: "failed", message: "Add a VirusTotal API key in DiscordOpsec settings to check this file", retryable: true });

        const cache = await getCache();
        let sha256 = cache.hashes[att.id];

        if (!sha256) {
            const maxBytes = Math.max(1, settings.store.maxHashSizeMb) * 1024 * 1024;
            if (att.size > maxBytes)
                return setState(att.id, { step: "failed", message: `Larger than ${settings.store.maxHashSizeMb} MB, not hashed`, retryable: false });

            setState(att.id, { step: "hashing" });
            sha256 = await Native.hashAttachment(att.url, maxBytes);
            saveCache(c => { c.hashes[att.id] = sha256; });
        }

        const cached = cache.results[sha256];
        const ttl = cached?.result.kind === "unknown" ? TTL_UNKNOWN : TTL_FOUND;
        if (cached && Date.now() - cached.at < ttl)
            return setState(att.id, { step: "done", sha256, result: cached.result });

        setState(att.id, { step: "querying" });
        const result = await Native.lookupFile(sha256, settings.store.vtRequestsPerMinute);

        if (result.kind === "error")
            return setState(att.id, { step: "failed", message: result.message, retryable: result.retryable });

        saveCache(c => { c.results[sha256] = { at: Date.now(), result }; });
        setState(att.id, { step: "done", sha256, result });
    } catch (e) {
        logger.error("Attachment scan failed", e);
        setState(att.id, { step: "failed", message: e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : "Scan failed", retryable: true });
    }
}

// ---------- Rendering ----------

let extCache: [string, Set<string>] | null = null;
function riskyExtensions() {
    const raw = settings.store.riskyExtensions;
    if (extCache?.[0] !== raw) extCache = [raw, new Set(parseList(raw).map(e => e.replace(/^\./, "")))];
    return extCache[1];
}

function isRisky(name: string) {
    const dot = name.lastIndexOf(".");
    return dot !== -1 && riskyExtensions().has(name.slice(dot + 1).toLowerCase());
}

function shouldAutoScan(message: any) {
    if (!Native || settings.store.scanMode !== ScanMode.Auto) return false;
    if (message.author?.id === UserStore.getCurrentUser()?.id) return false;
    if (settings.store.scanScope === ScanScope.Dms) {
        const channel = ChannelStore.getChannel(message.channel_id);
        if (channel?.guild_id) return false;
    }
    return true;
}

function describe(state: ScanState): { text: string; level: "info" | "warn" | "danger" | "ok"; } | null {
    switch (state.step) {
        case "idle": return null;
        case "hashing": return { text: "Hashing file…", level: "info" };
        case "querying": return { text: "Checking VirusTotal…", level: "info" };
        case "failed": return { text: state.message, level: "info" };
    }

    const r = state.result;
    if (r.kind === "unknown") return { text: "VirusTotal has never seen this file. Unknown doesn't mean safe.", level: "warn" };
    if (r.kind !== "found") return null;

    const { malicious, suspicious, harmless, undetected } = r.stats;
    const total = malicious + suspicious + harmless + undetected;
    if (malicious > 0) return { text: `VirusTotal: ${malicious}/${total} engines flag this as malicious${r.label ? ` (${r.label})` : ""}. Don't open it.`, level: "danger" };
    if (suspicious > 0) return { text: `VirusTotal: ${suspicious}/${total} engines flag this as suspicious.`, level: "warn" };
    return { text: `VirusTotal: no detections (0/${total}). That isn't a guarantee it's safe.`, level: "ok" };
}

function AttachmentRow({ att, auto }: { att: Attachment; auto: boolean; }) {
    const state = useScanState(att.id);

    useEffect(() => {
        if (auto && !states.has(att.id)) scan(att);
    }, [att.id, auto]);

    const info = describe(state);
    const level = info?.level ?? "warn";
    const busy = state.step === "hashing" || state.step === "querying";
    const canScan = Native && !busy && (state.step === "idle" || (state.step === "failed" && state.retryable));

    return (
        <div className={`vc-opsec-file vc-opsec-${level}`}>
            <div className="vc-opsec-file-text">
                <strong>{att.filename}</strong> can run code or hide other files. Only open it if you trust the sender.
                {info && <div>{info.text}</div>}
            </div>
            <div className="vc-opsec-file-actions">
                {canScan && (
                    <button className="vc-opsec-btn" onClick={() => scan(att)} title="Downloads the file to compute its SHA-256 and looks up only the hash. The file is never uploaded.">
                        {state.step === "idle" ? "Check hash on VirusTotal" : "Retry"}
                    </button>
                )}
                {state.step === "done" && state.result.kind === "found" && (
                    <a className="vc-opsec-btn" href={`https://www.virustotal.com/gui/file/${state.sha256}`} target="_blank" rel="noreferrer">Report</a>
                )}
            </div>
        </div>
    );
}

export function AttachmentWarnings({ message }: { message: any; }) {
    if (!settings.store.scanAttachments) return null;
    const risky: Attachment[] = message?.attachments?.filter((a: Attachment) => a?.filename && isRisky(a.filename)) ?? [];
    if (!risky.length) return null;

    const auto = shouldAutoScan(message);
    return (
        <div className="vc-opsec-files">
            {risky.map(a => <AttachmentRow key={a.id} att={a} auto={auto} />)}
        </div>
    );
}
