/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Logger } from "@utils/Logger";
import { FluxDispatcher, MediaEngineStore, React, showToast } from "@webpack/common";

import { settings } from "./settings";

// Layers, strongest first:
//  1. Patch inside MediaEngineStore: the single function that hands a camera device to the voice engine.
//  2. Flux interceptor dropping camera-enable actions before any store sees them.
//  3. Media engine guard: forces the "disabled" device and blanks Camera previews.
//  4. getUserMedia guard for the web/Vesktop engine.
//  5. Watchdog that turns video back off if something still got through.

const logger = new Logger("DiscordOpsec");
const DISABLED_DEVICE = "disabled";

let active = false;
let storeGatePatched = false;
let lastToast = 0;

const restore: (() => void)[] = [];

export const status = {
    storeGate: false,
    interceptor: false,
    engineGuard: false,
    gumGuard: false
};

const isBlocking = () => active && settings.store.blockCamera;

function notifyBlocked() {
    const now = Date.now();
    if (now - lastToast < 4000) return;
    lastToast = now;
    showToast({ text: "Camera blocked by DiscordOpsec", variant: "critical" });
}

export function markStoreGatePatched() {
    storeGatePatched = true;
}

/** Called from the MediaEngineStore patch with the requested video state. */
export function gateVideo(enabled: boolean): boolean {
    if (enabled && isBlocking()) {
        notifyBlocked();
        return false;
    }
    return enabled;
}

function interceptor(action: any): boolean {
    if (!isBlocking()) return false;
    switch (action.type) {
        case "MEDIA_ENGINE_SET_VIDEO_ENABLED":
            if (action.enabled) { notifyBlocked(); return true; }
            break;
        case "MEDIA_ENGINE_SET_GO_LIVE_SOURCE":
            if (action.settings?.cameraSettings != null) { notifyBlocked(); return true; }
            break;
        case "VOICE_CHANNEL_SELECT":
            if (action.video) action.video = false;
            break;
    }
    return false;
}

function installInterceptor() {
    const d = FluxDispatcher as any;
    if (typeof d.addInterceptor !== "function") return;
    d.addInterceptor(interceptor);
    status.interceptor = true;
    restore.push(() => {
        const list = d._interceptors;
        if (Array.isArray(list)) {
            const i = list.indexOf(interceptor);
            if (i !== -1) list.splice(i, 1);
        }
        status.interceptor = false;
    });
}

function installEngineGuard() {
    const engine: any = MediaEngineStore.getMediaEngine?.();
    if (!engine) return;

    const origSet = engine.setVideoInputDevice;
    if (typeof origSet === "function") {
        engine.setVideoInputDevice = function (id: unknown, ...rest: unknown[]) {
            return origSet.call(this, isBlocking() ? DISABLED_DEVICE : id, ...rest);
        };
        restore.push(() => { engine.setVideoInputDevice = origSet; });
        status.engineGuard = true;
    }

    const OrigCamera = engine.Camera;
    if (typeof OrigCamera === "function") {
        const Guarded = (props: any) => React.createElement(OrigCamera, isBlocking() ? { ...props, disabled: true } : props);
        engine.Camera = Guarded;
        restore.push(() => { engine.Camera = OrigCamera; });
    }
}

function wantsCamera(constraints?: MediaStreamConstraints) {
    const video = constraints?.video as any;
    if (!video) return false;
    // Electron screen capture also goes through getUserMedia; let that through.
    const source = video.mandatory?.chromeMediaSource ?? video.chromeMediaSource;
    return !(source === "desktop" || source === "screen" || source === "tab");
}

function installGumGuard() {
    const md = navigator.mediaDevices;
    if (!md?.getUserMedia) return;
    const orig = md.getUserMedia;
    md.getUserMedia = function (constraints?: MediaStreamConstraints) {
        if (isBlocking() && wantsCamera(constraints)) {
            notifyBlocked();
            return Promise.reject(new DOMException("Camera blocked by DiscordOpsec", "NotAllowedError"));
        }
        return orig.call(this, constraints);
    };
    status.gumGuard = true;
    restore.push(() => {
        if (Object.prototype.hasOwnProperty.call(md, "getUserMedia")) delete (md as any).getUserMedia;
        status.gumGuard = false;
    });
}

/** Turns video off if it is on while blocking. Deferred so it never dispatches mid-dispatch. */
export function enforceCameraOff() {
    setTimeout(() => {
        try {
            if (isBlocking() && MediaEngineStore.isVideoEnabled()) {
                logger.warn("Video was enabled despite the block; turning it off");
                FluxDispatcher.dispatch({ type: "MEDIA_ENGINE_SET_VIDEO_ENABLED", enabled: false });
            }
        } catch (e) {
            logger.error("Camera watchdog failed", e);
        }
    }, 0);
}

export function startCameraGuard() {
    active = true;
    status.storeGate = storeGatePatched;

    for (const install of [installInterceptor, installEngineGuard, installGumGuard]) {
        try {
            install();
        } catch (e) {
            logger.error(`Camera guard ${install.name} failed`, e);
        }
    }

    if (settings.store.blockCamera && !storeGatePatched) {
        logger.warn("MediaEngineStore patch did not apply; relying on fallback layers");
        showToast({ text: "DiscordOpsec: primary camera block failed to apply (Discord update?). Fallbacks are active.", variant: "critical" });
    }

    enforceCameraOff();
}

export function stopCameraGuard() {
    active = false;
    while (restore.length) {
        try {
            restore.pop()!();
        } catch (e) {
            logger.error("Failed to remove camera guard", e);
        }
    }
    status.engineGuard = false;
}
