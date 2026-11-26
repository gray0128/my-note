import {
  createLocaleSwitch,
  createThemeMenu,
  type LocaleSwitchHandle,
  type ThemeMenuHandle,
} from "../components/themeMenu";
import { formatDeviceName, subscribeLocale, syncDocumentLocale, t } from "../i18n";
import { createIcon, type IconName } from "../icons";
import { initTheme } from "../theme";
import {
  b64ToBytes,
  ensurePwaWasm,
  parseWasmError,
  WasmSyncEngine,
  WasmVaultSession,
} from "../wasm/pwa";
import { mountDiagramWidget } from "../render/diagram";
import { copyDualFormat, mountMarkdownPreview } from "../render/markdown";
import {
  claimPairing,
  CloudApiError,
  connectCloudWs,
  fetchCloudKeys,
  fetchCloudStateSnapshot,
  pullCloudOps,
} from "./cloudApi";
import {
  clearAllPwaStorage,
  loadCredentials,
  loadEngineStateJson,
  saveCredentials,
  saveEngineState,
  type CiphertextStateMirror,
  type PwaCredentials,
} from "./idb";

const MOBILE_VAULT_IDLE_MS = 5 * 60 * 1000;
const isPageHidden = (): boolean => document.visibilityState === "hidden";

function isPwaMarkdownLang(lang: string): boolean {
  const norm = lang.toLowerCase();
  return norm === "markdown" || norm === "md";
}

function isPwaMermaidLang(lang: string): boolean {
  return lang.toLowerCase() === "mermaid";
}

function isPwaRenderableLang(lang: string): boolean {
  return isPwaMarkdownLang(lang) || isPwaMermaidLang(lang);
}

interface MobileLeafView {
  op_id: string;
  hlc: string;
  device_id: string;
  actor: string;
  is_display: boolean;
  is_locked: boolean;
  key_id: string | null;
  content: string | null;
  mnb1_b64: string | null;
  mnw1_b64: string | null;
  wrap_gen?: number | null;
  mnr1_b64?: string | null;
  body_state: string;
}

interface MobileBlockView {
  id: string;
  buffer_id: string;
  position: string;
  lang: string;
  public_hint: string | null;
  state: string;
  is_locked: boolean;
  has_unlocked_concurrent_version: boolean;
  display_op_id: string | null;
  updated_at_ms: number;
  versions: MobileLeafView[];
}

interface MobileBufferView {
  id: string;
  name: string;
  position: string;
  state: string;
  updated_at_ms: number;
}

interface WasmStepOutput {
  state: CiphertextStateMirror;
  installed: boolean;
  applied_ops: number;
  needs_reset: boolean;
  keys_digest: string;
  vault_header_b64: string | null;
  view: {
    buffers: MobileBufferView[];
    blocks: MobileBlockView[];
  };
}

function validateSyncUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("Invalid sync_url in pairing code");
  }
  const isHttps = u.protocol === "https:";
  const isLocalHttp = u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
  if (!isHttps && !isLocalHttp) {
    throw new Error(`Refused insecure sync_url protocol '${u.protocol}' (HTTPS required)`);
  }
  return u.toString().replace(/\/+$/, "");
}

type PwaSyncStatus =
  | { readonly kind: "idle" }
  | { readonly kind: "syncing" }
  | { readonly kind: "synced"; readonly seq: number }
  | { readonly kind: "partial"; readonly seq: number }
  | { readonly kind: "offline" };

/**
 * Mobile Read-Only PWA (`#19 [M2-5]`, D1, `SEC-08`).
 * - Strictly read-only (zero editing, zero outbox, zero CM6, zero soft keyboard on note cards).
 * - Plaintext exists ONLY in transient JS/WASM RAM while foregrounded; IndexedDB holds ciphertext ONLY.
 * - Mobile Vault unlocks via passphrase in `WasmVaultSession`, auto-zeroizes & scrubs DOM on hide/idle.
 */
export class MobilePwaApp {
  private creds: PwaCredentials | null = null;
  private engine: WasmSyncEngine | null = null;
  private stateJson = "{}";
  private keysDigest: string | null = null;
  private vaultHeaderB64: string | null = null;
  private vaultSession: WasmVaultSession | null = null;
  private vaultIdleTimer: number | null = null;
  private unlockedPlaintext = new Map<string, Map<string, string>>(); // block_id -> (op_id -> plaintext)

  private buffers: MobileBufferView[] = [];
  private blocks: MobileBlockView[] = [];
  private activeBufferId: string | null = null;
  private selectedVersionByBlock = new Map<string, string>();
  private viewModeByBlock = new Map<string, "preview" | "source">();
  private activePreviewCleanups: Array<() => void> = [];
  private searchQuery = "";
  private syncInFlight = false;
  private syncQueued = false;
  private syncAbort: AbortController | null = null;
  private wsConnected = false;
  private disconnectWs: (() => void) | null = null;
  private revoked = false;
  private pairingSnatchWarning = false;
  private syncTruncated = false;
  private pendingSwWorker: ServiceWorker | null = null;
  private swReloadWired = false;
  private syncStatus: PwaSyncStatus = { kind: "idle" };
  private toastTimer: number | null = null;
  private activeMediaStream: MediaStream | null = null;
  private qrCancelToken = 0;

  private themeMenu!: ThemeMenuHandle;
  private localeSwitch!: LocaleSwitchHandle;
  private unsubLocale: (() => void) | null = null;

  private headerEl!: HTMLElement;
  private roPillEl!: HTMLSpanElement;
  private headerDynamicActionsEl!: HTMLElement;
  private headerSubEl!: HTMLElement;
  private bannerEl!: HTMLElement;
  private mainEl!: HTMLElement;
  private footerEl!: HTMLElement;
  private modalBackdropEl!: HTMLElement;
  private modalCardEl!: HTMLElement;
  private toastEl!: HTMLElement;

  constructor(private root: HTMLElement) {
    initTheme();
    syncDocumentLocale("pwa.title");
    this.buildShell();
    this.unsubLocale = subscribeLocale(() => this.applyLocale());
    document.addEventListener("visibilitychange", this.onVisibilityChange);
    window.addEventListener("beforeunload", this.onPageHide);
    window.addEventListener("pagehide", this.onPageHide);
    window.addEventListener("pageshow", this.onPageShow);
    window.addEventListener("online", this.onOnline);
  }

  setPendingSwUpdate(worker: ServiceWorker): void {
    this.pendingSwWorker = worker;
    this.renderBanner();
  }

  private isVaultUnlocked(): boolean {
    return this.vaultSession !== null && !this.vaultSession.isLocked();
  }

  async start(): Promise<void> {
    await ensurePwaWasm();
    this.creds = await loadCredentials();
    if (!this.creds) {
      this.render();
      return;
    }
    this.initEngine();
    const cached = await loadEngineStateJson();
    if (cached) {
      this.stateJson = cached.stateJson;
      this.keysDigest = cached.meta?.keys_digest ?? null;
      this.materializeFromState();
    }
    this.render();
    this.connectWs();
    await this.syncNow();
  }

  destroy(): void {
    this.unsubLocale?.();
    this.unsubLocale = null;
    this.themeMenu?.destroy();
    this.localeSwitch?.destroy();
    this.syncAbort?.abort();
    this.stopCamera();
    this.closeModal();
    this.cleanupMountedPreviews();
    this.lockVaultNow(true);
    this.disconnectWs?.();
    this.disconnectWs = null;
    if (this.engine) {
      this.engine.zeroizeSmk();
      this.engine.free();
      this.engine = null;
    }
    if (this.toastTimer !== null) {
      window.clearTimeout(this.toastTimer);
      this.toastTimer = null;
    }
    document.removeEventListener("visibilitychange", this.onVisibilityChange);
    window.removeEventListener("beforeunload", this.onPageHide);
    window.removeEventListener("pagehide", this.onPageHide);
    window.removeEventListener("pageshow", this.onPageShow);
    window.removeEventListener("online", this.onOnline);
  }

  private buildShell(): void {
    this.root.replaceChildren();
    this.themeMenu = createThemeMenu({ idPrefix: "pwa-" });
    this.localeSwitch = createLocaleSwitch({ idPrefix: "pwa-" });
    this.headerEl = document.createElement("header");
    this.headerEl.className = "pwa-header";
    const row1 = document.createElement("div");
    row1.className = "pwa-header-row";
    const brand = document.createElement("div");
    brand.className = "pwa-brand";
    const brandName = document.createElement("span");
    brandName.textContent = "my-note";
    this.roPillEl = document.createElement("span");
    this.roPillEl.className = "ro-pill";
    this.roPillEl.textContent = t("pwa.readOnlyPill");
    brand.append(createIcon("brand-mark", "sm"), brandName, this.roPillEl);

    const actions = document.createElement("div");
    actions.className = "pwa-actions";
    this.headerDynamicActionsEl = document.createElement("div");
    this.headerDynamicActionsEl.className = "pwa-dynamic-actions";
    // Keep Theme popover & Language toggle stably mounted so background sync/visibility re-renders never detach an open popover
    actions.append(this.headerDynamicActionsEl, this.themeMenu.element, this.localeSwitch.element);

    row1.append(brand, actions);
    this.headerSubEl = document.createElement("div");
    this.headerSubEl.className = "pwa-header-sub hidden";
    this.headerEl.append(row1, this.headerSubEl);
    this.bannerEl = document.createElement("div");
    this.mainEl = document.createElement("main");
    this.mainEl.className = "pwa-main";
    this.footerEl = document.createElement("footer");
    this.footerEl.className = "pwa-footer";
    this.modalBackdropEl = document.createElement("div");
    this.modalBackdropEl.className = "modal-backdrop hidden";
    this.modalBackdropEl.addEventListener("click", (ev) => {
      if (ev.target === this.modalBackdropEl) this.closeModal();
    });
    this.modalCardEl = document.createElement("div");
    this.modalCardEl.className = "modal-card";
    this.modalCardEl.setAttribute("role", "dialog");
    this.modalCardEl.setAttribute("aria-modal", "true");
    this.modalBackdropEl.appendChild(this.modalCardEl);
    this.toastEl = document.createElement("div");
    this.toastEl.className = "toast hidden";
    this.toastEl.setAttribute("role", "status");
    this.toastEl.setAttribute("aria-live", "polite");

    this.root.append(this.headerEl, this.bannerEl, this.mainEl, this.footerEl, this.modalBackdropEl, this.toastEl);
  }

  private applyLocale(): void {
    syncDocumentLocale("pwa.title");
    this.themeMenu.refreshLocale();
    this.localeSwitch.refreshLocale();
    this.render();
  }

  private onVisibilityChange = (): void => {
    if (document.visibilityState === "hidden") {
      // SEC-08 / H18: Immediately zeroize VKEK, scrub inputs/modals, stop camera, and scrub ALL Tier 2 plaintext from RAM & DOM on hide!
      this.stopCamera();
      this.closeModal();
      this.lockVaultNow(true);
    } else if (document.visibilityState === "visible" && this.creds && !this.revoked) {
      if (!this.disconnectWs) this.connectWs();
      void this.syncNow();
    }
  };

  private onPageHide = (): void => {
    this.syncAbort?.abort();
    this.stopCamera();
    this.closeModal();
    this.disconnectWs?.();
    this.disconnectWs = null;
    this.lockVaultNow(true);
  };

  private onPageShow = (): void => {
    if (this.creds && !this.revoked) {
      if (!this.disconnectWs) this.connectWs();
      void this.syncNow();
    }
  };

  private onOnline = (): void => {
    if (this.creds && !this.revoked) {
      if (!this.disconnectWs) this.connectWs();
      void this.syncNow();
    }
  };

  private initEngine(): void {
    if (!this.creds) return;
    if (this.engine) {
      this.engine.zeroizeSmk();
      this.engine.free();
    }
    this.engine = new WasmSyncEngine(this.creds.device_id, JSON.stringify(this.creds.smks));
  }

  private connectWs(): void {
    this.disconnectWs?.();
    this.disconnectWs = null;
    if (!this.creds || this.revoked) return;
    this.disconnectWs = connectCloudWs(this.creds.sync_url, this.creds.device_token, {
      onWake: () => void this.syncNow(),
      onRevoked: () => this.handleDeviceRevoked(),
      onAbnormalClose: () => {
        if (this.creds && !this.revoked) void this.syncNow();
      },
      onStateChange: (connected) => {
        this.wsConnected = connected;
        this.renderHeader();
      },
    });
  }

  private handleDeviceRevoked(): void {
    this.revoked = true;
    this.disconnectWs?.();
    this.disconnectWs = null;
    this.lockVaultNow(true);
    this.render();
  }

  private applyStep(event: unknown): WasmStepOutput {
    if (!this.engine) throw new Error("WASM sync engine not initialized");
    const raw = this.engine.step(this.stateJson, JSON.stringify(event));
    const out = JSON.parse(raw) as WasmStepOutput;
    this.stateJson = JSON.stringify(out.state);
    this.keysDigest = out.keys_digest;
    this.vaultHeaderB64 = out.vault_header_b64;
    this.buffers = out.view.buffers;
    this.blocks = out.view.blocks;
    if (!this.activeBufferId || !this.buffers.some((b) => b.id === this.activeBufferId)) {
      this.activeBufferId = this.buffers[0]?.id ?? null;
    }
    if (this.isVaultUnlocked()) {
      this.decryptVaultBlocksInRam();
    }
    return out;
  }

  private materializeFromState(): void {
    try {
      this.applyStep({ type: "materialize_view" });
    } catch {
      this.stateJson = "{}";
      this.buffers = [];
      this.blocks = [];
    }
  }

  async syncNow(): Promise<void> {
    if (!this.creds || !this.engine || this.revoked) return;
    if (this.syncInFlight) {
      this.syncQueued = true;
      return;
    }
    this.syncInFlight = true;
    this.syncAbort = new AbortController();
    const signal = this.syncAbort.signal;
    this.syncTruncated = false;
    this.syncStatus = { kind: "syncing" };
    this.renderHeader();
    try {
      const { sync_url, device_token } = this.creds;
      let parsedState = JSON.parse(this.stateJson || "{}") as { journal_epoch?: string | null; last_seq?: number };
      let lastOut: WasmStepOutput | null = null;

      const tryInstallSnapshot = async () => {
        const snap = await fetchCloudStateSnapshot(sync_url, device_token, signal);
        if (!snap) return;
        try {
          lastOut = this.applyStep({ type: "install_snapshot", snapshot_b64: snap.snapshot_b64 });
          parsedState = lastOut.state;
        } catch {
          // INV-SYNC-7 / H20: Corrupt or unknown-SMK snapshot MUST fall back cleanly to full pull from seq=0!
          this.stateJson = "{}";
          parsedState = {};
        }
      };

      // 1. Bootstrap from latest MNP1 mobile state snapshot if cache is empty
      if (!parsedState.journal_epoch || (parsedState.last_seq ?? 0) === 0) {
        await tryInstallSnapshot();
      }

      // 2. Pull key table first if we have no keys yet (or later if digest changed)
      const fetchAndMergeKeys = async () => {
        const kr = await fetchCloudKeys(sync_url, device_token, signal);
        lastOut = this.applyStep({
          type: "merge_key_table",
          key_records: kr.key_records,
          shred_marks: kr.shred_marks,
          keyring_gen: kr.key_material.keyring?.gen ?? null,
          keyring_b64: kr.key_material.keyring?.blob_b64 ?? null,
          vault_header_gen: kr.key_material.vault_header?.gen ?? null,
          vault_header_b64: kr.key_material.vault_header?.blob_b64 ?? null,
        });
        parsedState = lastOut.state;
      };

      if (!this.keysDigest) {
        await fetchAndMergeKeys();
      }

      // 3. Pull tail ops strictly advancing cursor from PullResponse (with rollback detection & explicit cap reporting)
      let since = parsedState.last_seq ?? 0;
      let remoteDigest: string | null = null;
      let resetAttempts = 0;
      let truncated = false;
      const MAX_PAGES = 500;
      for (let page = 0; page < MAX_PAGES; page++) {
        const pull = await pullCloudOps(sync_url, device_token, since, 200, signal);
        remoteDigest = pull.keys_digest;
        if (pull.head_seq < since && resetAttempts < 2) {
          // H20: Server head_seq regressed below local cursor -> full re-bootstrap from snapshot/seq 0
          resetAttempts++;
          this.stateJson = "{}";
          parsedState = {};
          await tryInstallSnapshot();
          await fetchAndMergeKeys();
          since = parsedState.last_seq ?? 0;
          continue;
        }
        if (pull.ops.length > 0 || !parsedState.journal_epoch || parsedState.journal_epoch !== pull.epoch) {
          lastOut = this.applyStep({
            type: "apply_tail_ops",
            epoch: pull.epoch,
            ops: pull.ops,
          });
          if (lastOut.needs_reset && resetAttempts < 2) {
            // Epoch changed on server (e.g. DO PITR) — re-bootstrap cleanly from snapshot + keys + seq 0
            resetAttempts++;
            this.stateJson = "{}";
            parsedState = {};
            await tryInstallSnapshot();
            await fetchAndMergeKeys();
            since = parsedState.last_seq ?? 0;
            continue;
          }
          parsedState = lastOut.state;
          since = parsedState.last_seq ?? since;
        }
        if (!pull.has_more) break;
        if (page === MAX_PAGES - 1) truncated = true;
      }

      if (remoteDigest && remoteDigest !== this.keysDigest) {
        await fetchAndMergeKeys();
      }

      if (lastOut) {
        await saveEngineState(lastOut.state, lastOut.keys_digest);
      }
      if (truncated) {
        this.syncTruncated = true;
        this.syncStatus = { kind: "partial", seq: parsedState.last_seq ?? 0 };
      } else {
        this.syncStatus = { kind: "synced", seq: parsedState.last_seq ?? 0 };
      }
    } catch (e) {
      if (signal.aborted || (e instanceof DOMException && e.name === "AbortError")) {
        return;
      }
      if (e instanceof CloudApiError && (e.status === 401 || e.code === "DEVICE_REVOKED" || e.code === "AUTH_REQUIRED")) {
        this.handleDeviceRevoked();
        return;
      }
      this.syncStatus = { kind: "offline" };
      this.showToast(e instanceof Error ? e.message : t("pwa.toastSyncFailed"), true);
    } finally {
      this.syncAbort = null;
      this.syncInFlight = false;
      if (!signal.aborted) {
        if (this.syncQueued) {
          this.syncQueued = false;
          void this.syncNow();
        } else {
          this.render();
        }
      }
    }
  }

  private async handlePairSubmit(code: string, isRefresh = false): Promise<void> {
    this.pairingSnatchWarning = false;
    try {
      await ensurePwaWasm();
      const parsed = JSON.parse(WasmSyncEngine.parsePairingCode(code)) as {
        sync_url: string;
        pair_id: string;
        k_pair_b64u: string;
      };
      const cleanCodeUrl = validateSyncUrl(parsed.sync_url);
      const claimed = await claimPairing(cleanCodeUrl, parsed.pair_id);
      // H19: Strictly enforce read-only scope and expected ticket kind before decrypting/saving credentials!
      if (claimed.scope !== "read") {
        throw new Error(`Refused pairing ticket with scope '${claimed.scope}' — Mobile PWA strictly requires scope 'read'`);
      }
      const expectedKind = isRefresh ? "refresh" : "add";
      if (claimed.kind !== expectedKind) {
        throw new Error(`Unexpected pairing ticket kind '${claimed.kind}' (expected '${expectedKind}')`);
      }
      const payload = JSON.parse(
        WasmSyncEngine.decryptPairingTicket(parsed.pair_id, parsed.k_pair_b64u, b64ToBytes(claimed.ciphertext_b64)),
      ) as PwaCredentials;
      const cleanPayloadUrl = validateSyncUrl(payload.sync_url);
      if (cleanPayloadUrl !== cleanCodeUrl) {
        throw new Error("Pairing ticket sync_url mismatch");
      }
      if (payload.device_id !== claimed.device_id) {
        throw new Error("Pairing ticket device_id mismatch");
      }

      if (isRefresh && this.creds) {
        if (payload.device_id !== this.creds.device_id || cleanPayloadUrl !== validateSyncUrl(this.creds.sync_url)) {
          throw new Error("Refresh ticket does not match this paired mobile device");
        }
        // Merge new SMK generations while preserving existing device token
        const mergedMap = new Map(this.creds.smks.map((s) => [s.smk_kid, s.smk_b64]));
        for (const s of payload.smks) mergedMap.set(s.smk_kid, s.smk_b64);
        this.creds = {
          ...this.creds,
          smks: [...mergedMap.entries()].map(([smk_kid, smk_b64]) => ({ smk_kid, smk_b64 })),
        };
        await saveCredentials(this.creds);
        this.initEngine();
        this.closeModal();
        this.showToast(t("pwa.toastKeysRefreshed"));
        await this.syncNow();
        return;
      }

      this.creds = { ...payload, sync_url: cleanPayloadUrl };
      this.revoked = false;
      this.stateJson = "{}";
      this.keysDigest = null;
      await saveCredentials(this.creds);
      this.initEngine();
      this.stopCamera();
      this.render();
      this.connectWs();
      this.showToast(t("pwa.toastPairedSyncing"));
      await this.syncNow();
    } catch (e) {
      this.stopCamera();
      if (e instanceof CloudApiError && (e.status === 404 || e.status === 410)) {
        this.pairingSnatchWarning = true;
        this.render();
        return;
      }
      const parsed = parseWasmError(e);
      this.showToast(`${parsed.code}: ${parsed.message}`, true);
    }
  }

  private cleanupMountedPreviews(): void {
    for (const cleanup of this.activePreviewCleanups) {
      try {
        cleanup();
      } catch {
        // ignore cleanup error
      }
    }
    this.activePreviewCleanups = [];
  }

  private lockVaultNow(silent = false): void {
    this.cleanupMountedPreviews();
    if (this.vaultIdleTimer !== null) {
      window.clearTimeout(this.vaultIdleTimer);
      this.vaultIdleTimer = null;
    }
    if (this.vaultSession) {
      try {
        this.vaultSession.lockAndZeroize();
        this.vaultSession.free();
      } catch {
        // ignore
      }
      this.vaultSession = null;
    }
    this.unlockedPlaintext.clear();
    this.render();
    if (!silent) this.showToast(t("pwa.toastVaultLocked"));
  }

  private resetVaultIdleTimer(): void {
    if (!this.vaultSession) return;
    if (this.vaultIdleTimer !== null) window.clearTimeout(this.vaultIdleTimer);
    this.vaultIdleTimer = window.setTimeout(() => this.lockVaultNow(false), MOBILE_VAULT_IDLE_MS);
  }

  private decryptVaultBlocksInRam(): void {
    const sess = this.vaultSession;
    if (!sess || sess.isLocked() || isPageHidden()) return;
    this.unlockedPlaintext.clear();
    for (const blk of this.blocks) {
      if (!blk.is_locked) continue;
      const map = new Map<string, string>();
      for (const v of blk.versions) {
        if (v.content !== null) {
          map.set(v.op_id, v.content);
        } else if (v.is_locked && v.key_id && v.mnb1_b64 && v.mnw1_b64) {
          try {
            const dec = sess.decryptBlock(
              blk.id,
              v.op_id,
              v.key_id,
              b64ToBytes(v.mnb1_b64),
              b64ToBytes(v.mnw1_b64),
            );
            map.set(v.op_id, dec.content);
            dec.free();
          } catch {
            // keep locked
          }
        } else if (
          !v.is_locked &&
          v.key_id &&
          v.mnb1_b64 &&
          v.mnr1_b64 &&
          typeof v.wrap_gen === "number" &&
          this.engine
        ) {
          // H17: Concurrent Tier 1 leaf on a locked block is decrypted ONLY while Vault is unlocked, strictly into RAM!
          try {
            const plain = this.engine.decryptTier1Content(
              blk.id,
              v.op_id,
              v.key_id,
              v.wrap_gen,
              b64ToBytes(v.mnr1_b64),
              b64ToBytes(v.mnb1_b64),
            );
            map.set(v.op_id, plain);
          } catch {
            // keep unavailable
          }
        }
      }
      if (map.size > 0) this.unlockedPlaintext.set(blk.id, map);
    }
  }

  private openVaultUnlockModal(): void {
    if (!this.vaultHeaderB64) {
      this.showToast(t("pwa.noVaultConfigured"), true);
      return;
    }
    this.modalCardEl.replaceChildren();
    const title = document.createElement("h3");
    title.className = "onboard-title";
    title.textContent = t("pwa.unlockTitle");
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = t("pwa.unlockNote");
    const form = document.createElement("form");
    form.className = "pwa-form";
    const pass = document.createElement("input");
    pass.type = "password";
    pass.className = "input";
    pass.placeholder = t("vault.passPlaceholder");
    pass.dataset.testid = "pwa-vault-passphrase";
    pass.autocomplete = "current-password";
    const row = document.createElement("div");
    row.className = "pwa-row-end";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn";
    cancel.textContent = t("common.cancel");
    cancel.addEventListener("click", () => this.closeModal());
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "btn btn-primary";
    submit.dataset.testid = "pwa-vault-unlock-submit";
    submit.textContent = t("pwa.unlockSubmit");
    row.append(cancel, submit);
    form.append(pass, row);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      if (!this.vaultHeaderB64) return;
      const passphrase = pass.value;
      pass.value = "";
      submit.disabled = true;
      submit.textContent = t("pwa.derivingKey");
      window.setTimeout(() => {
        if (isPageHidden() || !this.vaultHeaderB64) {
          this.closeModal();
          return;
        }
        try {
          const sess = WasmVaultSession.unlockWithPassphrase(passphrase, b64ToBytes(this.vaultHeaderB64));
          // H18 / SEC-08: If tab/app backgrounded during Argon2id derivation, zeroize immediately and refuse to unlock!
          if (isPageHidden()) {
            sess.lockAndZeroize();
            sess.free();
            this.closeModal();
            return;
          }
          this.vaultSession = sess;
          this.decryptVaultBlocksInRam();
          this.resetVaultIdleTimer();
          this.closeModal();
          this.render();
          this.showToast(t("pwa.toastVaultUnlocked"));
        } catch (e) {
          const parsed = parseWasmError(e);
          this.showToast(`${parsed.code}: ${parsed.message}`, true);
          submit.disabled = false;
          submit.textContent = t("pwa.unlockSubmit");
        }
      }, 0);
    });
    this.modalCardEl.append(title, note, form);
    this.modalBackdropEl.classList.remove("hidden");
    pass.focus();
  }

  private openRefreshKeysModal(): void {
    this.modalCardEl.replaceChildren();
    const title = document.createElement("h3");
    title.className = "onboard-title";
    title.textContent = t("pwa.refreshKeysTitle");
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = t("pwa.refreshKeysNote");
    const cliChip = document.createElement("pre");
    cliChip.className = "cli-chip";
    const cliCode = document.createElement("code");
    cliCode.textContent = `mynote device refresh ${this.creds?.device_id ?? "<device_id>"}`;
    cliChip.appendChild(cliCode);
    const form = document.createElement("form");
    form.className = "pwa-form";
    const input = document.createElement("input");
    input.className = "input pwa-pair-input";
    input.placeholder = "mynote-pair:v1:...";
    const row = document.createElement("div");
    row.className = "pwa-row-end";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn";
    cancel.textContent = t("common.cancel");
    cancel.addEventListener("click", () => this.closeModal());
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "btn btn-primary";
    submit.textContent = t("pwa.refreshKeysSubmit");
    submit.disabled = true;
    input.addEventListener("input", () => {
      submit.disabled = input.value.trim().length === 0;
    });
    row.append(cancel, submit);
    form.append(input, row);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      if (input.value.trim()) void this.handlePairSubmit(input.value.trim(), true);
    });
    this.modalCardEl.append(title, note, cliChip, form);
    this.modalBackdropEl.classList.remove("hidden");
    input.focus();
  }

  private closeModal(): void {
    for (const el of this.modalCardEl.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input, textarea")) {
      el.value = "";
    }
    this.modalBackdropEl.classList.add("hidden");
    this.modalCardEl.replaceChildren();
  }

  private stopCamera(): void {
    this.qrCancelToken++;
    if (this.activeMediaStream) {
      for (const tTrack of this.activeMediaStream.getTracks()) tTrack.stop();
      this.activeMediaStream = null;
    }
  }

  private copyTextGesture(text: string, isTier2: boolean): void {
    const finish = (ok: boolean) => {
      if (!ok) {
        this.showToast(t("pwa.toastClipboardUnavailable"), true);
      } else if (isTier2) {
        this.resetVaultIdleTimer();
        this.showToast(t("pwa.toastCopiedVault"));
      } else {
        this.showToast(t("pwa.toastCopied"));
      }
    };
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).then(
        () => finish(true),
        () => finish(false),
      );
      return;
    }
    finish(false);
  }

  private showToast(msg: string, isError = false): void {
    const span = document.createElement("span");
    span.textContent = msg;
    this.toastEl.replaceChildren(createIcon(isError ? "alert-triangle" : "check-circle", "xs"), span);
    this.toastEl.className = `toast${isError ? " error" : ""}`;
    if (this.toastTimer !== null) window.clearTimeout(this.toastTimer);
    this.toastTimer = window.setTimeout(() => this.toastEl.classList.add("hidden"), 3400);
  }

  private formatSyncStatusLabel(): { icon: IconName; label: string } {
    if (this.syncInFlight || this.syncStatus.kind === "syncing") {
      return { icon: "refresh-cw", label: t("sync.syncing") };
    }
    switch (this.syncStatus.kind) {
      case "synced":
        return { icon: "check-circle", label: t("pwa.statusSynced", { seq: this.syncStatus.seq }) };
      case "partial":
        return { icon: "alert-triangle", label: t("pwa.statusPartial", { seq: this.syncStatus.seq }) };
      case "offline":
        return { icon: "cloud-off", label: t("pwa.statusOffline") };
      case "idle":
        return { icon: "refresh-cw", label: t("pwa.statusIdle") };
      default: {
        const _exhaustive: never = this.syncStatus;
        return _exhaustive;
      }
    }
  }

  private render(): void {
    this.renderHeader();
    this.renderBanner();
    this.renderMain();
    this.renderFooter();
  }

  private renderHeader(): void {
    const prevSearch = this.headerSubEl.querySelector<HTMLInputElement>('input[type="search"]');
    const searchHadFocus = prevSearch !== null && document.activeElement === prevSearch;
    const selStart = searchHadFocus ? prevSearch.selectionStart : null;
    const selEnd = searchHadFocus ? prevSearch.selectionEnd : null;

    this.roPillEl.textContent = t("pwa.readOnlyPill");

    const dynamicActions: HTMLElement[] = [];
    if (this.creds && !this.revoked) {
      if (this.vaultSession && !this.vaultSession.isLocked()) {
        const lockBtn = document.createElement("button");
        lockBtn.type = "button";
        lockBtn.className = "btn btn-amber btn-sm btn-has-icon";
        lockBtn.dataset.testid = "pwa-vault-lock-btn";
        const lbl = document.createElement("span");
        lbl.textContent = t("pwa.lockBtn");
        lockBtn.append(createIcon("lock-open", "xs"), lbl);
        lockBtn.addEventListener("click", () => this.lockVaultNow(false));
        dynamicActions.push(lockBtn);
      } else if (this.vaultHeaderB64) {
        const unlockBtn = document.createElement("button");
        unlockBtn.type = "button";
        unlockBtn.className = "btn btn-sm btn-has-icon";
        unlockBtn.dataset.testid = "pwa-vault-unlock-btn";
        const lbl = document.createElement("span");
        lbl.textContent = t("pwa.vaultBtn");
        unlockBtn.append(createIcon("lock", "xs"), lbl);
        unlockBtn.addEventListener("click", () => this.openVaultUnlockModal());
        dynamicActions.push(unlockBtn);
      }

      const { icon, label } = this.formatSyncStatusLabel();
      const syncBtn = document.createElement("button");
      syncBtn.type = "button";
      syncBtn.className = "btn btn-ghost btn-sm btn-has-icon";
      syncBtn.dataset.testid = "pwa-sync-btn";
      syncBtn.appendChild(createIcon(icon, "xs"));
      const syncLbl = document.createElement("span");
      syncLbl.textContent = label;
      syncBtn.appendChild(syncLbl);
      syncBtn.addEventListener("click", () => void this.syncNow());
      dynamicActions.push(syncBtn);

      const keysBtn = document.createElement("button");
      keysBtn.type = "button";
      keysBtn.className = "btn btn-sm btn-has-icon";
      keysBtn.dataset.testid = "pwa-keys-btn";
      const keysLbl = document.createElement("span");
      keysLbl.textContent = t("pwa.keysBtn");
      keysBtn.append(createIcon("key", "xs"), keysLbl);
      keysBtn.title = t("pwa.keysTitle");
      keysBtn.addEventListener("click", () => this.openRefreshKeysModal());
      dynamicActions.push(keysBtn);
    }
    this.headerDynamicActionsEl.replaceChildren(...dynamicActions);

    this.headerSubEl.replaceChildren();
    if (this.creds && !this.revoked && this.buffers.length > 0) {
      this.headerSubEl.classList.remove("hidden");
      const tabs = document.createElement("nav");
      tabs.className = "pwa-tabs";
      tabs.setAttribute("aria-label", t("topbar.buffersNav"));
      for (const b of this.buffers) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = `tab-btn${b.id === this.activeBufferId ? " active" : ""}`;
        btn.textContent = b.name;
        btn.addEventListener("click", () => {
          this.activeBufferId = b.id;
          this.render();
        });
        tabs.appendChild(btn);
      }
      this.headerSubEl.appendChild(tabs);

      const search = document.createElement("input");
      search.type = "search";
      search.className = "input";
      search.placeholder = t("pwa.searchPlaceholder");
      search.value = this.searchQuery;
      search.addEventListener("input", () => {
        this.searchQuery = search.value;
        this.renderMain();
      });
      this.headerSubEl.appendChild(search);
      if (searchHadFocus) {
        search.focus({ preventScroll: true });
        if (selStart !== null && selEnd !== null) {
          search.setSelectionRange(selStart, selEnd);
        }
      }
    } else {
      this.headerSubEl.classList.add("hidden");
    }
  }

  private resetLocalStateSync(): void {
    this.syncAbort?.abort();
    this.syncAbort = null;
    this.syncQueued = false;
    this.stopCamera();
    this.closeModal();
    this.disconnectWs?.();
    this.disconnectWs = null;
    this.wsConnected = false;
    this.lockVaultNow(true);
    if (this.engine) {
      this.engine.zeroizeSmk();
      this.engine.free();
      this.engine = null;
    }
    this.creds = null;
    this.revoked = false;
    this.stateJson = "{}";
    this.keysDigest = null;
    this.vaultHeaderB64 = null;
    this.buffers = [];
    this.blocks = [];
    this.activeBufferId = null;
    this.selectedVersionByBlock.clear();
    this.viewModeByBlock.clear();
    this.cleanupMountedPreviews();
    this.syncTruncated = false;
    this.pairingSnatchWarning = false;
    this.syncStatus = { kind: "idle" };
  }

  private renderBanner(): void {
    this.bannerEl.replaceChildren();
    if (this.revoked) {
      const b = document.createElement("div");
      b.className = "banner banner-error";
      b.dataset.testid = "pwa-revoked-banner";
      const msg = document.createElement("span");
      msg.className = "banner-msg";
      msg.append(createIcon("shield-alert", "xs"), document.createTextNode(t("pwa.revoked")));
      const resetBtn = document.createElement("button");
      resetBtn.type = "button";
      resetBtn.className = "btn btn-danger btn-sm";
      resetBtn.textContent = t("pwa.resetRepair");
      resetBtn.addEventListener("click", () => {
        this.resetLocalStateSync();
        void clearAllPwaStorage().then(() => {
          this.render();
        });
      });
      b.append(msg, resetBtn);
      this.bannerEl.appendChild(b);
    } else if (this.pairingSnatchWarning) {
      const b = document.createElement("div");
      b.className = "banner banner-error";
      b.dataset.testid = "pwa-snatch-warning";
      const msg = document.createElement("span");
      msg.className = "banner-msg";
      msg.append(createIcon("shield-alert", "xs"), document.createTextNode(t("pwa.snatchWarning")));
      b.appendChild(msg);
      this.bannerEl.appendChild(b);
    }
    if (this.syncTruncated) {
      const b = document.createElement("div");
      b.className = "banner banner-warn";
      b.dataset.testid = "pwa-truncated-banner";
      const msg = document.createElement("span");
      msg.className = "banner-msg";
      msg.append(createIcon("alert-triangle", "xs"), document.createTextNode(t("pwa.truncatedBanner")));
      b.appendChild(msg);
      this.bannerEl.appendChild(b);
    }
    if (this.pendingSwWorker) {
      const worker = this.pendingSwWorker;
      const b = document.createElement("div");
      b.className = "banner banner-info";
      b.dataset.testid = "pwa-sw-update-banner";
      const msg = document.createElement("span");
      msg.className = "banner-msg";
      msg.append(createIcon("refresh-cw", "xs"), document.createTextNode(t("pwa.swUpdate")));
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-primary btn-sm";
      btn.textContent = t("pwa.swReload");
      btn.addEventListener("click", () => {
        if (!this.swReloadWired && "serviceWorker" in navigator) {
          this.swReloadWired = true;
          navigator.serviceWorker.addEventListener("controllerchange", () => {
            window.location.reload();
          });
        }
        worker.postMessage({ type: "SKIP_WAITING" });
      });
      b.append(msg, btn);
      this.bannerEl.appendChild(b);
    }
  }

  private renderMain(): void {
    this.cleanupMountedPreviews();
    this.mainEl.replaceChildren();
    this.mainEl.classList.toggle("is-onboarding", !this.creds);
    if (!this.creds) {
      this.renderOnboarding();
      return;
    }
    const q = this.searchQuery.trim().toLowerCase();
    const visible = this.blocks.filter((b) => {
      if (this.activeBufferId && b.buffer_id !== this.activeBufferId) return false;
      if (!q) return true;
      const ramMap = this.unlockedPlaintext.get(b.id);
      const disp = b.versions.find((v) => v.is_display) ?? b.versions[0];
      const text = (disp ? (ramMap?.get(disp.op_id) ?? disp.content) : null) ?? "";
      return (
        text.toLowerCase().includes(q) ||
        b.lang.toLowerCase().includes(q) ||
        (b.public_hint ?? "").toLowerCase().includes(q)
      );
    });

    if (visible.length === 0) {
      const empty = document.createElement("div");
      empty.className = "onboard-card";
      empty.textContent = this.blocks.length === 0 ? t("pwa.emptyNoNotes") : t("pwa.emptyNoMatch");
      this.mainEl.appendChild(empty);
      return;
    }

    for (const blk of visible) {
      this.mainEl.appendChild(this.renderReadOnlyBlock(blk));
    }
  }

  private renderOnboarding(): void {
    const card = document.createElement("section");
    card.className = "onboard-card";
    const h = document.createElement("h2");
    h.className = "onboard-title";
    h.textContent = t("pwa.onboardTitle");
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = t("pwa.onboardBody");

    const cliChip = document.createElement("pre");
    cliChip.className = "cli-chip";
    const cliCode = document.createElement("code");
    const cmdHead = document.createElement("span");
    cmdHead.className = "cli-nowrap";
    cmdHead.textContent = "mynote device add";
    const flagName = document.createElement("span");
    flagName.className = "cli-nowrap";
    flagName.textContent = "--name iPhone";
    const flagScope = document.createElement("span");
    flagScope.className = "cli-nowrap";
    flagScope.textContent = "--scope read";
    cliCode.append(cmdHead, document.createTextNode(" "), flagName, document.createTextNode(" "), flagScope);
    cliChip.appendChild(cliCode);

    const form = document.createElement("form");
    form.className = "pwa-form";
    const input = document.createElement("input");
    input.className = "input pwa-pair-input";
    input.placeholder = "mynote-pair:v1:...";
    input.dataset.testid = "pwa-pair-input";
    const btnRow = document.createElement("div");
    btnRow.className = "pwa-onboard-actions";
    const qrBtn = document.createElement("button");
    qrBtn.type = "button";
    qrBtn.className = "btn btn-primary btn-has-icon";
    qrBtn.dataset.testid = "pwa-scan-qr-btn";
    const qrLbl = document.createElement("span");
    qrLbl.textContent = t("pwa.scanQr");
    qrBtn.append(createIcon("qr-code", "xs"), qrLbl);
    const pairBtn = document.createElement("button");
    pairBtn.type = "submit";
    pairBtn.className = "btn";
    pairBtn.dataset.testid = "pwa-pair-submit";
    pairBtn.textContent = t("pwa.pairSubmit");
    pairBtn.disabled = true;
    const syncPairActionState = (): void => {
      const hasCode = input.value.trim().length > 0;
      pairBtn.disabled = !hasCode;
      pairBtn.className = hasCode ? "btn btn-primary" : "btn";
      qrBtn.className = hasCode ? "btn btn-has-icon" : "btn btn-primary btn-has-icon";
    };
    input.addEventListener("input", syncPairActionState);
    btnRow.append(qrBtn, pairBtn);
    const qrHost = document.createElement("div");
    qrBtn.addEventListener("click", () => void this.startQrScanner(qrHost, input));
    form.append(input, btnRow, qrHost);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      if (input.value.trim()) void this.handlePairSubmit(input.value.trim(), false);
    });

    const privacy = document.createElement("p");
    privacy.className = "onboard-privacy";
    privacy.textContent = t("pwa.onboardPrivacy");

    card.append(h, p, cliChip, form, privacy);
    this.mainEl.appendChild(card);
  }

  private async startQrScanner(host: HTMLElement, targetInput: HTMLInputElement): Promise<void> {
    this.stopCamera();
    const token = this.qrCancelToken;
    host.replaceChildren();
    const BD = (globalThis as unknown as { BarcodeDetector?: new (opts: { formats: string[] }) => { detect(v: HTMLVideoElement): Promise<{ rawValue: string }[]> } }).BarcodeDetector;
    if (!navigator.mediaDevices?.getUserMedia || !BD) {
      const msg = document.createElement("p");
      msg.className = "muted";
      msg.textContent = t("pwa.qrUnavailable");
      host.appendChild(msg);
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      if (token !== this.qrCancelToken || isPageHidden()) {
        for (const tr of stream.getTracks()) tr.stop();
        return;
      }
      this.activeMediaStream = stream;
      const video = document.createElement("video");
      video.className = "qr-video";
      video.muted = true;
      video.setAttribute("muted", "true");
      video.setAttribute("playsinline", "true");
      video.srcObject = stream;
      await video.play();
      if (token !== this.qrCancelToken || isPageHidden()) {
        this.stopCamera();
        return;
      }
      const stopBtn = document.createElement("button");
      stopBtn.type = "button";
      stopBtn.className = "btn btn-sm";
      stopBtn.textContent = t("pwa.stopCamera");
      stopBtn.addEventListener("click", () => {
        this.stopCamera();
        host.replaceChildren();
      });
      host.append(video, stopBtn);
      const detector = new BD({ formats: ["qr_code"] });
      const tick = async () => {
        if (token !== this.qrCancelToken || !this.activeMediaStream) return;
        try {
          const hits = await detector.detect(video);
          const found = hits.find((h) => h.rawValue.startsWith("mynote-pair:v1:"));
          if (found) {
            this.stopCamera();
            host.replaceChildren();
            targetInput.value = found.rawValue;
            await this.handlePairSubmit(found.rawValue, false);
            return;
          }
        } catch {
          // continue scanning
        }
        if (token === this.qrCancelToken && this.activeMediaStream) window.setTimeout(() => void tick(), 250);
      };
      void tick();
    } catch {
      this.stopCamera();
      const msg = document.createElement("p");
      msg.className = "muted";
      msg.textContent = t("pwa.qrDenied");
      host.appendChild(msg);
    }
  }

  private renderReadOnlyBlock(blk: MobileBlockView): HTMLElement {
    const vaultOpen = this.isVaultUnlocked();
    const selectedOpId = this.selectedVersionByBlock.get(blk.id) ?? blk.display_op_id ?? blk.versions[0]?.op_id;
    const selectedLeaf = blk.versions.find((v) => v.op_id === selectedOpId) ?? blk.versions[0];
    // H17: When a block is locked and Vault is locked, NEVER expose ANY version (including concurrent Tier 1 leaves)!
    const ramPlain =
      selectedLeaf && (!blk.is_locked || vaultOpen)
        ? (this.unlockedPlaintext.get(blk.id)?.get(selectedLeaf.op_id) ?? null)
        : null;
    const effectiveText =
      blk.is_locked && !vaultOpen ? null : selectedLeaf ? (selectedLeaf.content ?? ramPlain) : null;
    const isUnlockedTier2 = blk.is_locked && vaultOpen && effectiveText !== null;

    const card = document.createElement("article");
    card.className = `ro-block${blk.is_locked ? " locked" : ""}${isUnlockedTier2 ? " unlocked" : ""}`;
    card.dataset.blockId = blk.id;

    const head = document.createElement("div");
    head.className = "ro-block-head";
    const meta = document.createElement("div");
    meta.className = "ro-block-meta";
    const lang = document.createElement("span");
    lang.className = "badge";
    lang.textContent = blk.lang;
    meta.appendChild(lang);
    if (blk.is_locked) {
      const vb = document.createElement("span");
      vb.className = `badge ${isUnlockedTier2 ? "badge-vault-open" : "badge-vault"}`;
      const vbLbl = document.createElement("span");
      vbLbl.textContent = isUnlockedTier2 ? t("vault.badgeUnlocked") : t("vault.badgeLocked");
      vb.append(createIcon(isUnlockedTier2 ? "lock-open" : "lock", "xs"), vbLbl);
      meta.appendChild(vb);
    }
    if (blk.public_hint) {
      const hint = document.createElement("span");
      hint.textContent = blk.public_hint;
      meta.appendChild(hint);
    }

    const isRenderable = effectiveText !== null && isPwaRenderableLang(blk.lang);
    const viewMode: "preview" | "source" = isRenderable
      ? (this.viewModeByBlock.get(blk.id) ?? "preview")
      : "source";
    card.dataset.viewMode = viewMode;

    head.appendChild(meta);
    let getRichCopyPayload: (() => { html: string; text: string }) | null = null;
    if (effectiveText !== null) {
      const actions = document.createElement("div");
      actions.className = "ro-block-actions";

      if (isRenderable) {
        const modeBtn = document.createElement("button");
        modeBtn.type = "button";
        modeBtn.className = "btn btn-sm";
        modeBtn.dataset.testid = `pwa-toggle-mode-${blk.id}`;
        modeBtn.setAttribute("aria-pressed", String(viewMode === "preview"));
        modeBtn.textContent = viewMode === "preview" ? t("block.modeSource") : t("block.modePreview");
        modeBtn.addEventListener("click", () => {
          this.viewModeByBlock.set(blk.id, viewMode === "preview" ? "source" : "preview");
          this.renderMain();
        });
        actions.appendChild(modeBtn);
      }

      if (isPwaMarkdownLang(blk.lang) && viewMode === "preview") {
        const copyRichBtn = document.createElement("button");
        copyRichBtn.type = "button";
        copyRichBtn.className = "btn btn-sm btn-has-icon";
        copyRichBtn.dataset.testid = `pwa-copy-rich-${blk.id}`;
        const crLbl = document.createElement("span");
        crLbl.textContent = t("block.copyRich");
        copyRichBtn.append(createIcon("file-rich", "xs"), crLbl);
        copyRichBtn.addEventListener("click", () => {
          const payload = getRichCopyPayload?.();
          if (!payload) return;
          void copyDualFormat(payload.html, payload.text).then((ok) => {
            if (!ok) {
              this.showToast(t("pwa.toastClipboardUnavailable"), true);
            } else if (blk.is_locked) {
              this.resetVaultIdleTimer();
              this.showToast(t("pwa.toastCopiedRichVault"));
            } else {
              this.showToast(t("block.toastCopiedRich"));
            }
          });
        });
        actions.appendChild(copyRichBtn);
      }

      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "btn btn-sm btn-has-icon";
      copyBtn.dataset.testid = `copy-${blk.id}`;
      const cLbl = document.createElement("span");
      cLbl.textContent = t("block.copy");
      copyBtn.append(createIcon("copy", "xs"), cLbl);
      copyBtn.addEventListener("click", () => this.copyTextGesture(effectiveText, blk.is_locked));
      actions.appendChild(copyBtn);
      head.appendChild(actions);
    }
    card.appendChild(head);

    if (blk.versions.length > 1 && (!blk.is_locked || vaultOpen)) {
      const vbar = document.createElement("div");
      vbar.className = "version-bar";
      const lbl = document.createElement("span");
      lbl.className = "version-bar-label";
      lbl.append(
        createIcon("git-branch", "xs"),
        document.createTextNode(t("pwa.concurrentVersions", { count: blk.versions.length })),
      );
      vbar.appendChild(lbl);
      blk.versions.forEach((v, idx) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = `btn btn-sm${v.op_id === selectedLeaf?.op_id ? " btn-primary" : ""}`;
        b.textContent = v.is_display
          ? t("pwa.versionDisplay", { num: idx + 1 })
          : t("pwa.versionOther", { num: idx + 1, dev: formatDeviceName(v.device_id) });
        b.addEventListener("click", () => {
          this.selectedVersionByBlock.set(blk.id, v.op_id);
          this.renderMain();
        });
        vbar.appendChild(b);
      });
      card.appendChild(vbar);
    }

    if (blk.is_locked && !vaultOpen) {
      const locked = document.createElement("div");
      locked.className = "ro-locked-body";
      const txt = document.createElement("span");
      txt.className = "ro-locked-msg";
      txt.append(createIcon("lock", "xs"), document.createTextNode(t("block.lockedCard")));
      if (blk.public_hint) {
        const hint = document.createElement("span");
        hint.className = "locked-card-hint";
        hint.textContent = blk.public_hint;
        txt.appendChild(hint);
      }
      if (blk.has_unlocked_concurrent_version) {
        const warn = document.createElement("span");
        warn.className = "locked-card-warn";
        warn.textContent = t("block.lockedConcurrentNote");
        txt.appendChild(warn);
      }
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-sm";
      btn.textContent = t("vault.unlockAction");
      btn.addEventListener("click", () => this.openVaultUnlockModal());
      locked.append(txt, btn);
      card.appendChild(locked);
    } else if (effectiveText === null) {
      const locked = document.createElement("div");
      locked.className = "ro-locked-body";
      const txt = document.createElement("span");
      txt.className = "ro-locked-msg";
      txt.append(createIcon("alert-triangle", "sm"), document.createTextNode(t("pwa.unreadable")));
      locked.appendChild(txt);
      card.appendChild(locked);
    } else if (viewMode === "preview" && isPwaMarkdownLang(blk.lang)) {
      const previewHost = document.createElement("div");
      previewHost.className = "ro-preview-host";
      const mounted = mountMarkdownPreview(previewHost, effectiveText, {
        readOnly: true,
        isTier2: blk.is_locked,
        onCopyFeedback: (msg, isError) => {
          if (!isError && blk.is_locked) {
            this.resetVaultIdleTimer();
            this.showToast(t("pwa.toastVaultSecretSuffix", { msg }));
          } else {
            this.showToast(msg, isError);
          }
        },
      });
      getRichCopyPayload = () => mounted.getCleanCopyPayload();
      this.activePreviewCleanups.push(() => mounted.destroy());
      card.appendChild(previewHost);
    } else if (viewMode === "preview" && isPwaMermaidLang(blk.lang)) {
      const previewHost = document.createElement("div");
      previewHost.className = "ro-preview-host";
      const handle = mountDiagramWidget(previewHost, effectiveText, {
        readOnly: true,
        isTier2: blk.is_locked,
        onFeedback: (msg, isError) => {
          if (!isError && blk.is_locked) {
            this.resetVaultIdleTimer();
            this.showToast(t("pwa.toastVaultSecretSuffix", { msg }));
          } else {
            this.showToast(msg, isError);
          }
        },
      });
      this.activePreviewCleanups.push(() => handle.destroy());
      card.appendChild(previewHost);
    } else {
      // Strictly read-only <pre> — NO <textarea>, NO contenteditable, NO soft keyboard!
      const pre = document.createElement("pre");
      pre.className = "ro-pre";
      pre.textContent = effectiveText;
      card.appendChild(pre);
    }

    return card;
  }

  private renderFooter(): void {
    this.footerEl.replaceChildren();
    if (!this.creds) {
      this.footerEl.classList.add("hidden");
      return;
    }
    this.footerEl.classList.remove("hidden");
    const unpair = document.createElement("button");
    unpair.type = "button";
    unpair.className = "btn btn-ghost btn-sm btn-danger pwa-unpair-btn";
    unpair.textContent = t("pwa.unpair");
    unpair.addEventListener("click", () => {
      this.resetLocalStateSync();
      void clearAllPwaStorage().then(() => {
        this.render();
        this.showToast(t("pwa.toastUnpaired"));
      });
    });
    this.footerEl.appendChild(unpair);
  }
}
