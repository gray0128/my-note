import {
  createLocaleSwitch,
  createThemeMenu,
  type LocaleSwitchHandle,
  type ThemeMenuHandle,
} from "../components/themeMenu";
import {
  CLIP_BLOB_MAX_BYTES,
  CLIP_EPHEMERAL_MAX_BYTES,
  CLIP_INLINE_TEXT_MAX_BYTES,
  CLIP_MAX_ITEMS,
  bytesToBase64Chunked,
  computeSha256Hex,
  convertImageBytesToPngBlob,
  formatClipBytes,
  generateBitmapThumbnail,
  generateUlid,
  isAllowedBitmapMime,
  truncatePreview,
  validateClipImageFile,
  type ClipMetaV1,
} from "../clipUtils";
import { formatDeviceName, formatHistoryTimestamp, subscribeLocale, syncDocumentLocale, t } from "../i18n";
import { createIcon, type IconName } from "../icons";
import { initTheme } from "../theme";
import type { AllowedClipImageMime } from "../types";
import {
  b64ToBytes,
  ensurePwaWasm,
  parseWasmError,
  WasmClipCodec,
  WasmSyncEngine,
  WasmVaultSession,
} from "../wasm/pwa";
import { mountDiagramWidget } from "../render/diagram";
import { copyDualFormat, mountMarkdownPreview } from "../render/markdown";
import {
  claimPairing,
  CloudApiError,
  connectCloudWs,
  deleteCloudClip,
  fetchCloudKeys,
  fetchCloudStateSnapshot,
  getCloudClipBlob,
  listCloudClips,
  postCloudClip,
  pullCloudOps,
  putCloudClipBlob,
} from "./cloudApi";
import {
  clearAllPwaStorage,
  clearClipItemsIdb,
  deleteClipItemIdb,
  getLastClipId,
  loadClipItems,
  loadCredentials,
  loadEngineStateJson,
  saveClipItems,
  saveCredentials,
  saveEngineState,
  setLastClipId,
  type CiphertextClipItem,
  type CiphertextStateMirror,
  type PwaCredentials,
} from "./idb";
import { consumeShareHandoffCache } from "./shareHandoff";

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
  private activeTab: "notes" | "clip" = "notes";
  private clipCodec: WasmClipCodec | null = null;
  private clipItemsCipher: CiphertextClipItem[] = [];
  private decryptedClips = new Map<string, ClipMetaV1>();
  private clipDraftText = "";
  private clipEphemeral = false;
  private clipSending = false;
  private clipErrorMsg: string | null = null;
  private activeModalObjectUrl: string | null = null;
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
      await this.consumePendingShareHandoff();
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
    this.clipItemsCipher = await loadClipItems();
    this.decryptClipsInRam();
    this.render();
    this.connectWs();
    await this.syncNow();
    await this.consumePendingShareHandoff();
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
    this.destroyClipCodec();
    this.decryptedClips.clear();
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
    this.roPillEl.textContent =
      this.creds?.scope === "read+clip" ? t("pwa.clipScopeReadClip") : t("pwa.readOnlyPill");
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

  private destroyClipCodec(): void {
    if (this.clipCodec) {
      try {
        this.clipCodec.zeroize();
        this.clipCodec.free();
      } catch {
        // ignore if already freed
      }
      this.clipCodec = null;
    }
  }

  private initClipCodecFromCreds(): void {
    this.destroyClipCodec();
    if (!this.creds?.clip_key?.clip_kid || !this.creds.clip_key.clip_key_b64) return;
    try {
      this.clipCodec = new WasmClipCodec(
        this.creds.device_id,
        this.creds.clip_key.clip_kid,
        b64ToBytes(this.creds.clip_key.clip_key_b64),
      );
    } catch {
      this.clipCodec = null;
    }
  }

  private async applyClipKeyMaterial(clipKeyMat: { gen: number; blob_b64: string } | null | undefined): Promise<void> {
    if (!clipKeyMat || !this.engine || !this.creds) return;
    let nextCodec: WasmClipCodec;
    try {
      nextCodec = this.engine.createClipCodec(this.creds.device_id, b64ToBytes(clipKeyMat.blob_b64));
    } catch {
      return;
    }
    const prevKid = this.clipCodec?.clipKid ?? null;
    const rotated = prevKid !== null && prevKid !== nextCodec.clipKid;
    this.destroyClipCodec();
    this.clipCodec = nextCodec;
    if (rotated) {
      this.clipItemsCipher = [];
      this.decryptedClips.clear();
      await clearClipItemsIdb();
    } else {
      this.decryptClipsInRam();
    }
  }

  private decryptClipsInRam(): void {
    this.decryptedClips.clear();
    const codec = this.clipCodec;
    if (!codec || codec.isZeroized()) return;
    for (const row of this.clipItemsCipher) {
      if (row.clip_kid !== codec.clipKid) continue;
      try {
        const metaJson = codec.decryptMeta(row.clip_id, row.device_id, false, b64ToBytes(row.meta_envelope_b64));
        const parsed = JSON.parse(metaJson) as ClipMetaV1;
        this.decryptedClips.set(row.clip_id, parsed);
      } catch {
        // leave undecryptable (e.g. rotated key)
      }
    }
  }

  private initEngine(): void {
    if (!this.creds) return;
    if (this.engine) {
      this.engine.zeroizeSmk();
      this.engine.free();
    }
    this.engine = new WasmSyncEngine(this.creds.device_id, JSON.stringify(this.creds.smks));
    this.initClipCodecFromCreds();
  }

  private connectWs(): void {
    this.disconnectWs?.();
    this.disconnectWs = null;
    if (!this.creds || this.revoked) return;
    this.disconnectWs = connectCloudWs(this.creds.sync_url, this.creds.device_token, {
      onWake: () => void this.syncNow(),
      onRevoked: () => this.handleDeviceRevoked(),
      onClipWake: () => void this.syncClipsNow(undefined, { full: false }),
      onClipCleared: (frame) => void this.handleRemoteClipCleared(frame.clip_id),
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
    this.destroyClipCodec();
    this.decryptedClips.clear();
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
      let keysFetchedThisSync = false;
      const fetchAndMergeKeys = async () => {
        const kr = await fetchCloudKeys(sync_url, device_token, signal);
        keysFetchedThisSync = true;
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
        await this.applyClipKeyMaterial(kr.key_material.clip_key);
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
      } else if (!this.clipCodec && !keysFetchedThisSync) {
        // `keys_digest` intentionally excludes `clip_key` (`INV-CLIP-ISOLATION`); check `/v1/keys` if codec missing.
        await fetchAndMergeKeys();
      }

      if (lastOut) {
        await saveEngineState(lastOut.state, lastOut.keys_digest);
      }

      // 4. Sync independent 100-item clipboard index (ciphertext-only into IndexedDB `clip_items`)
      await this.syncClipsNow(signal, { full: true, renderAfter: false });

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
      // H19 / D8: Mobile PWA strictly accepts only 'read' or 'read+clip' (NEVER 'read-write' or 'clip-write').
      if (claimed.scope !== "read" && claimed.scope !== "read+clip") {
        throw new Error(
          `Refused pairing ticket with scope '${claimed.scope}' — Mobile PWA strictly requires scope 'read' or 'read+clip'`,
        );
      }
      const expectedKind = isRefresh ? "refresh" : "add";
      if (claimed.kind !== expectedKind) {
        throw new Error(`Unexpected pairing ticket kind '${claimed.kind}' (expected '${expectedKind}')`);
      }
      const payload = JSON.parse(
        WasmSyncEngine.decryptPairingTicket(parsed.pair_id, parsed.k_pair_b64u, b64ToBytes(claimed.ciphertext_b64)),
      ) as PwaCredentials & { clip_kid?: string; clip_key_b64?: string };
      const cleanPayloadUrl = validateSyncUrl(payload.sync_url);
      if (cleanPayloadUrl !== cleanCodeUrl) {
        throw new Error("Pairing ticket sync_url mismatch");
      }
      if (payload.device_id !== claimed.device_id) {
        throw new Error("Pairing ticket device_id mismatch");
      }
      const ticketClipKey =
        typeof payload.clip_kid === "string" &&
        payload.clip_kid.length > 0 &&
        typeof payload.clip_key_b64 === "string" &&
        payload.clip_key_b64.length > 0
          ? { clip_kid: payload.clip_kid, clip_key_b64: payload.clip_key_b64 }
          : null;

      if (isRefresh && this.creds) {
        if (payload.device_id !== this.creds.device_id || cleanPayloadUrl !== validateSyncUrl(this.creds.sync_url)) {
          throw new Error("Refresh ticket does not match this paired mobile device");
        }
        // Merge new SMK generations while preserving existing device token
        const mergedMap = new Map(this.creds.smks.map((s) => [s.smk_kid, s.smk_b64]));
        for (const s of payload.smks) mergedMap.set(s.smk_kid, s.smk_b64);
        this.creds = {
          ...this.creds,
          scope: claimed.scope,
          clip_key: ticketClipKey ?? this.creds.clip_key ?? null,
          smks: [...mergedMap.entries()].map(([smk_kid, smk_b64]) => ({ smk_kid, smk_b64 })),
        };
        await saveCredentials(this.creds);
        this.initEngine();
        this.closeModal();
        this.showToast(t("pwa.toastKeysRefreshed"));
        await this.syncNow();
        return;
      }

      this.creds = {
        device_id: payload.device_id,
        device_token: payload.device_token,
        sync_url: cleanPayloadUrl,
        smks: payload.smks,
        scope: claimed.scope,
        clip_key: ticketClipKey,
      };
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
    if (this.activeModalObjectUrl) {
      URL.revokeObjectURL(this.activeModalObjectUrl);
      this.activeModalObjectUrl = null;
    }
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

    this.roPillEl.textContent =
      this.creds?.scope === "read+clip" ? t("pwa.clipScopeReadClip") : t("pwa.readOnlyPill");

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
    if (this.creds && !this.revoked) {
      this.headerSubEl.classList.remove("hidden");

      const viewSeg = document.createElement("div");
      viewSeg.className = "pwa-view-seg";
      viewSeg.setAttribute("role", "tablist");

      const notesTabBtn = document.createElement("button");
      notesTabBtn.type = "button";
      notesTabBtn.setAttribute("role", "tab");
      notesTabBtn.className = "pwa-view-seg-btn";
      notesTabBtn.dataset.testid = "pwa-tab-notes";
      notesTabBtn.setAttribute("aria-selected", String(this.activeTab === "notes"));
      const notesLbl = document.createElement("span");
      notesLbl.textContent = t("pwa.tabNotes");
      notesTabBtn.append(createIcon("layers", "xs"), notesLbl);
      notesTabBtn.addEventListener("click", () => {
        if (this.activeTab === "notes") return;
        this.activeTab = "notes";
        this.render();
      });

      const clipTabBtn = document.createElement("button");
      clipTabBtn.type = "button";
      clipTabBtn.setAttribute("role", "tab");
      clipTabBtn.className = "pwa-view-seg-btn";
      clipTabBtn.dataset.testid = "pwa-tab-clip";
      clipTabBtn.setAttribute("aria-selected", String(this.activeTab === "clip"));
      const clipLbl = document.createElement("span");
      clipLbl.textContent = t("pwa.tabClip");
      clipTabBtn.append(createIcon("clipboard", "xs"), clipLbl);
      clipTabBtn.addEventListener("click", () => {
        if (this.activeTab === "clip") return;
        this.activeTab = "clip";
        this.render();
      });

      viewSeg.append(notesTabBtn, clipTabBtn);
      this.headerSubEl.appendChild(viewSeg);

      if (this.activeTab === "notes" && this.buffers.length > 0) {
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
    this.destroyClipCodec();
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
    this.activeTab = "notes";
    this.clipItemsCipher = [];
    this.decryptedClips.clear();
    this.clipDraftText = "";
    this.clipEphemeral = false;
    this.clipErrorMsg = null;
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
    if (this.activeTab === "clip") {
      this.renderClipboardView();
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

  // ---------- M4 Mobile PWA Clipboard (IndexedDB v2 + WasmClipCodec + Share Target) ----------

  private canWriteClip(): boolean {
    return this.creds?.scope === "read+clip";
  }

  private async ensureClipCodec(signal?: AbortSignal): Promise<WasmClipCodec | null> {
    if (this.clipCodec && !this.clipCodec.isZeroized()) return this.clipCodec;
    if (!this.creds || !this.engine) return null;
    try {
      const kr = await fetchCloudKeys(this.creds.sync_url, this.creds.device_token, signal);
      await this.applyClipKeyMaterial(kr.key_material.clip_key);
    } catch {
      // keep null
    }
    return this.clipCodec && !this.clipCodec.isZeroized() ? this.clipCodec : null;
  }

  private async syncClipsNow(
    signal?: AbortSignal,
    opts: { full?: boolean; renderAfter?: boolean } = {},
  ): Promise<void> {
    if (!this.creds || this.revoked) return;
    const full = opts.full ?? false;
    try {
      const sinceId = full ? undefined : ((await getLastClipId()) ?? undefined);
      const res = await listCloudClips(this.creds.sync_url, this.creds.device_token, sinceId, CLIP_MAX_ITEMS, signal);

      const needKeyRefresh =
        res.items.length > 0 &&
        (!this.clipCodec || res.items.some((item) => item.clip_kid !== this.clipCodec?.clipKid));
      if (needKeyRefresh && this.engine) {
        const kr = await fetchCloudKeys(this.creds.sync_url, this.creds.device_token, signal);
        const prevKid = this.clipCodec?.clipKid ?? null;
        await this.applyClipKeyMaterial(kr.key_material.clip_key);
        if (prevKid && this.clipCodec && this.clipCodec.clipKid !== prevKid && !full) {
          // ClipKey rotated while online: pull full list under the fresh key.
          const fresh = await listCloudClips(this.creds.sync_url, this.creds.device_token, undefined, CLIP_MAX_ITEMS, signal);
          this.clipItemsCipher = await saveClipItems(fresh.items, { replaceAll: true });
          const maxId = this.clipItemsCipher.reduce<string | null>(
            (acc, r) => (!acc || r.clip_id > acc ? r.clip_id : acc),
            null,
          );
          await setLastClipId(maxId);
          this.decryptClipsInRam();
          if (opts.renderAfter !== false) this.renderMain();
          return;
        }
      }

      if (full || res.items.length > 0) {
        this.clipItemsCipher = await saveClipItems(res.items, { replaceAll: full });
        const maxId = this.clipItemsCipher.reduce<string | null>(
          (acc, r) => (!acc || r.clip_id > acc ? r.clip_id : acc),
          null,
        );
        await setLastClipId(maxId);
        this.decryptClipsInRam();
      }
      if (opts.renderAfter !== false && this.activeTab === "clip") {
        this.renderMain();
      }
    } catch (e) {
      if (signal?.aborted || (e instanceof DOMException && e.name === "AbortError")) return;
      if (e instanceof CloudApiError && (e.status === 401 || e.code === "DEVICE_REVOKED" || e.code === "AUTH_REQUIRED")) {
        this.handleDeviceRevoked();
      }
    }
  }

  private async handleRemoteClipCleared(clipId: string | null): Promise<void> {
    if (clipId) {
      await deleteClipItemIdb(clipId);
      this.clipItemsCipher = this.clipItemsCipher.filter((c) => c.clip_id !== clipId);
      this.decryptedClips.delete(clipId);
    } else {
      await clearClipItemsIdb();
      this.clipItemsCipher = [];
      this.decryptedClips.clear();
    }
    if (this.activeTab === "clip") {
      this.renderMain();
    }
  }

  /** Consume Android Web Share Target `/?clip_share=1` handoff and immediately wipe `mynote-share-handoff` (`SEC-08`). */
  async consumePendingShareHandoff(): Promise<void> {
    const hasParam =
      typeof window !== "undefined" &&
      new URLSearchParams(window.location.search).get("clip_share") === "1";
    if (hasParam && typeof history !== "undefined" && typeof history.replaceState === "function") {
      try {
        history.replaceState(null, "", "/");
      } catch {
        // ignore history error
      }
    }
    const payload = await consumeShareHandoffCache();
    if (!payload) return;

    if (!this.creds || this.revoked) {
      this.showToast(t("clip.errReadOnlyScope"), true);
      return;
    }
    this.activeTab = "clip";
    this.render();

    if (payload.kind === "error") {
      this.clipErrorMsg =
        payload.mime.includes("svg")
          ? t("clip.errSvgRejected")
          : t("clip.errUnsupportedMime", { mime: payload.mime });
      this.renderMain();
      return;
    }
    if (!this.canWriteClip()) {
      this.clipErrorMsg = t("clip.errReadOnlyScope");
      this.renderMain();
      return;
    }
    if (payload.kind === "text") {
      const ok = await this.sendClipText(payload.text, false);
      if (ok) this.showToast(t("clip.toastShareSent"));
    } else {
      const copy = new Uint8Array(payload.bytes.byteLength);
      copy.set(payload.bytes);
      const blob = new Blob([copy], { type: payload.mime });
      const ok = await this.sendClipImage(blob, payload.mime);
      if (ok) this.showToast(t("clip.toastShareSent"));
    }
  }

  private async sendClipText(text: string, ephemeral: boolean): Promise<boolean> {
    if (!this.creds || this.revoked || this.clipSending) return false;
    if (!this.canWriteClip()) {
      this.clipErrorMsg = t("clip.errReadOnlyScope");
      this.renderMain();
      return false;
    }
    if (!text.length) {
      this.clipErrorMsg = t("clip.errEmpty");
      this.renderMain();
      return false;
    }
    const utf8 = new TextEncoder().encode(text);
    if (ephemeral && utf8.byteLength > CLIP_EPHEMERAL_MAX_BYTES) {
      this.clipErrorMsg = t("clip.errEphemeralTooLarge");
      this.renderMain();
      return false;
    }
    if (utf8.byteLength > CLIP_BLOB_MAX_BYTES) {
      this.clipErrorMsg = t("clip.errTooLarge");
      this.renderMain();
      return false;
    }
    const codec = await this.ensureClipCodec();
    if (!codec) {
      this.clipErrorMsg = t("clip.errNoKey");
      this.renderMain();
      return false;
    }

    this.clipErrorMsg = null;
    this.clipSending = true;
    this.renderMain();
    try {
      const clipId = generateUlid();
      const now = Date.now();
      if (ephemeral || utf8.byteLength <= CLIP_INLINE_TEXT_MAX_BYTES) {
        const meta: ClipMetaV1 = {
          v: 1,
          kind: "text",
          mime: "text/plain",
          source_mode: "explicit",
          created_at_ms: now,
          text,
          blob: null,
        };
        const metaEnv = codec.encryptMeta(clipId, JSON.stringify(meta), ephemeral);
        const metaB64 = bytesToBase64Chunked(metaEnv);
        const res = await postCloudClip(this.creds.sync_url, this.creds.device_token, {
          clip_id: clipId,
          clip_kid: codec.clipKid,
          kind: "text",
          ephemeral,
          meta_envelope_b64: metaB64,
        });
        this.clipDraftText = "";
        this.clipEphemeral = false;
        if (ephemeral) {
          this.showToast(t("clip.toastSentEphemeral", { count: res.delivered_to ?? 0 }));
        } else {
          const cipherItem: CiphertextClipItem = {
            clip_id: clipId,
            clip_kid: codec.clipKid,
            device_id: this.creds.device_id,
            kind: "text",
            created_at_ms: res.created_at_ms ?? now,
            expires_at_ms: res.expires_at_ms ?? now + 7 * 86_400_000,
            meta_envelope_b64: metaB64,
            has_blob: false,
            blob_bytes: null,
          };
          this.clipItemsCipher = await saveClipItems([cipherItem], { replaceAll: false });
          this.decryptedClips.set(clipId, meta);
          await setLastClipId(clipId);
          this.showToast(t("clip.toastSent"));
        }
      } else {
        const sha256Hex = await computeSha256Hex(utf8);
        const meta: ClipMetaV1 = {
          v: 1,
          kind: "text",
          mime: "text/plain",
          source_mode: "explicit",
          created_at_ms: now,
          text: truncatePreview(text),
          blob: {
            byte_size: utf8.byteLength,
            sha256_hex: sha256Hex,
            width: null,
            height: null,
            thumb_mime: null,
            thumb_b64: null,
          },
        };
        const metaEnv = codec.encryptMeta(clipId, JSON.stringify(meta), false);
        const metaB64 = bytesToBase64Chunked(metaEnv);
        const blobEnv = codec.encryptBlob(clipId, utf8);
        const res = await putCloudClipBlob(
          this.creds.sync_url,
          this.creds.device_token,
          { clipId, clipKid: codec.clipKid, kind: "text", metaEnvelopeB64: metaB64 },
          blobEnv,
        );
        this.clipDraftText = "";
        this.clipEphemeral = false;
        const cipherItem: CiphertextClipItem = {
          clip_id: clipId,
          clip_kid: codec.clipKid,
          device_id: this.creds.device_id,
          kind: "text",
          created_at_ms: res.created_at_ms,
          expires_at_ms: res.expires_at_ms,
          meta_envelope_b64: metaB64,
          has_blob: true,
          blob_bytes: res.blob_bytes,
        };
        this.clipItemsCipher = await saveClipItems([cipherItem], { replaceAll: false });
        this.decryptedClips.set(clipId, meta);
        await setLastClipId(clipId);
        this.showToast(t("clip.toastSent"));
      }
      return true;
    } catch (e) {
      if (e instanceof CloudApiError && (e.status === 401 || e.code === "DEVICE_REVOKED")) {
        this.handleDeviceRevoked();
        return false;
      }
      const parsed = parseWasmError(e);
      this.clipErrorMsg = `${parsed.code}: ${parsed.message}`;
      this.showToast(this.clipErrorMsg, true);
      return false;
    } finally {
      this.clipSending = false;
      this.renderMain();
    }
  }

  private async sendClipImage(fileBlob: Blob, rawMime: string): Promise<boolean> {
    if (!this.creds || this.revoked || this.clipSending) return false;
    if (!this.canWriteClip()) {
      this.clipErrorMsg = t("clip.errReadOnlyScope");
      this.renderMain();
      return false;
    }
    const check = validateClipImageFile(rawMime, fileBlob.size);
    if (!check.ok) {
      this.clipErrorMsg =
        check.reason === "svg"
          ? t("clip.errSvgRejected")
          : check.reason === "size"
            ? t("clip.errTooLarge")
            : check.reason === "empty"
              ? t("clip.errEmpty")
              : t("clip.errUnsupportedMime", { mime: check.mime });
      this.renderMain();
      return false;
    }
    const codec = await this.ensureClipCodec();
    if (!codec) {
      this.clipErrorMsg = t("clip.errNoKey");
      this.renderMain();
      return false;
    }

    this.clipErrorMsg = null;
    this.clipSending = true;
    this.renderMain();
    try {
      const rawBytes = new Uint8Array(await fileBlob.arrayBuffer());
      const sha256Hex = await computeSha256Hex(rawBytes);
      const thumb = await generateBitmapThumbnail(fileBlob, check.mime);
      const clipId = generateUlid();
      const now = Date.now();
      const meta: ClipMetaV1 = {
        v: 1,
        kind: "image",
        mime: check.mime,
        source_mode: "explicit",
        created_at_ms: now,
        text: null,
        blob: {
          byte_size: rawBytes.byteLength,
          sha256_hex: sha256Hex,
          width: thumb.width,
          height: thumb.height,
          thumb_mime: thumb.thumb_mime,
          thumb_b64: thumb.thumb_b64,
        },
      };
      const metaEnv = codec.encryptMeta(clipId, JSON.stringify(meta), false);
      const metaB64 = bytesToBase64Chunked(metaEnv);
      const blobEnv = codec.encryptBlob(clipId, rawBytes);
      const res = await putCloudClipBlob(
        this.creds.sync_url,
        this.creds.device_token,
        { clipId, clipKid: codec.clipKid, kind: "image", metaEnvelopeB64: metaB64 },
        blobEnv,
      );
      const cipherItem: CiphertextClipItem = {
        clip_id: clipId,
        clip_kid: codec.clipKid,
        device_id: this.creds.device_id,
        kind: "image",
        created_at_ms: res.created_at_ms,
        expires_at_ms: res.expires_at_ms,
        meta_envelope_b64: metaB64,
        has_blob: true,
        blob_bytes: res.blob_bytes,
      };
      // SEC-08: ONLY ciphertext envelope saved to IndexedDB; decrypted thumb stays in RAM only!
      this.clipItemsCipher = await saveClipItems([cipherItem], { replaceAll: false });
      this.decryptedClips.set(clipId, meta);
      await setLastClipId(clipId);
      this.showToast(t("clip.toastSent"));
      return true;
    } catch (e) {
      if (e instanceof CloudApiError && (e.status === 401 || e.code === "DEVICE_REVOKED")) {
        this.handleDeviceRevoked();
        return false;
      }
      const parsed = parseWasmError(e);
      this.clipErrorMsg = `${parsed.code}: ${parsed.message}`;
      this.showToast(this.clipErrorMsg, true);
      return false;
    } finally {
      this.clipSending = false;
      this.renderMain();
    }
  }

  private async downloadAndVerifyClipBlob(item: CiphertextClipItem, meta: ClipMetaV1): Promise<Uint8Array> {
    if (!this.creds || !this.clipCodec || this.clipCodec.isZeroized()) {
      throw new Error(t("clip.errNoKey"));
    }
    const fetched = await getCloudClipBlob(this.creds.sync_url, this.creds.device_token, item.clip_id);
    const authorDev = fetched.deviceId || item.device_id;
    const rawBytes = this.clipCodec.decryptBlob(item.clip_id, authorDev, fetched.bytes);
    const expectedHash = meta.blob?.sha256_hex?.toLowerCase() ?? "";
    if (expectedHash) {
      const actualHash = await computeSha256Hex(rawBytes);
      if (actualHash !== expectedHash) {
        throw new Error(t("clip.errIntegrity"));
      }
    }
    return rawBytes;
  }

  private async fetchDecryptedPngBlob(item: CiphertextClipItem, meta: ClipMetaV1): Promise<Blob> {
    if (!isAllowedBitmapMime(meta.mime)) {
      throw new Error(t("clip.errUnsupportedMime", { mime: meta.mime }));
    }
    const rawBytes = await this.downloadAndVerifyClipBlob(item, meta);
    return convertImageBytesToPngBlob(rawBytes, meta.mime as AllowedClipImageMime);
  }

  /**
   * iOS Safari gesture-safe PNG copy: synchronously passes a `Promise<Blob>` inside `ClipboardItem`
   * directly within the `click` event handler (ZERO `await` before `navigator.clipboard.write`).
   */
  private copyClipImageSyncGesture(item: CiphertextClipItem, meta: ClipMetaV1): void {
    const ClipboardItemCtor = (globalThis as unknown as {
      ClipboardItem?: new (items: Record<string, Blob | Promise<Blob>>) => ClipboardItem;
    }).ClipboardItem;
    if (!navigator.clipboard?.write || !ClipboardItemCtor) {
      this.showToast(t("pwa.toastClipboardUnavailable"), true);
      return;
    }
    const pngBlobPromise = this.fetchDecryptedPngBlob(item, meta);
    navigator.clipboard.write([new ClipboardItemCtor({ "image/png": pngBlobPromise })]).then(
      () => this.showToast(t("clip.toastImageCopied")),
      (err) => {
        const msg = err instanceof Error && err.message ? err.message : t("pwa.toastClipboardUnavailable");
        this.showToast(msg, true);
      },
    );
  }

  private copyClipTextGesture(item: CiphertextClipItem, meta: ClipMetaV1): void {
    if (!item.has_blob) {
      this.copyTextGesture(meta.text ?? "", false);
      return;
    }
    const ClipboardItemCtor = (globalThis as unknown as {
      ClipboardItem?: new (items: Record<string, Blob | Promise<Blob>>) => ClipboardItem;
    }).ClipboardItem;
    const textPromise = this.downloadAndVerifyClipBlob(item, meta).then(
      (raw) => new Blob([new Uint8Array(raw)], { type: "text/plain" }),
    );
    if (navigator.clipboard?.write && ClipboardItemCtor) {
      navigator.clipboard.write([new ClipboardItemCtor({ "text/plain": textPromise })]).then(
        () => this.showToast(t("pwa.toastCopied")),
        () => this.showToast(t("pwa.toastClipboardUnavailable"), true),
      );
      return;
    }
    void textPromise
      .then((b) => b.text())
      .then((fullText) => this.copyTextGesture(fullText, false))
      .catch(() => this.showToast(t("pwa.toastClipboardUnavailable"), true));
  }

  private async openClipImagePreview(item: CiphertextClipItem, meta: ClipMetaV1): Promise<void> {
    if (!isAllowedBitmapMime(meta.mime)) {
      this.showToast(t("clip.errSvgRejected"), true);
      return;
    }
    this.closeModal();
    const title = document.createElement("h3");
    title.className = "onboard-title";
    title.textContent = t("clip.previewModalTitle");
    const status = document.createElement("p");
    status.className = "muted";
    status.textContent = t("clip.loadingPreview");
    const closeRow = document.createElement("div");
    closeRow.className = "pwa-row-end";
    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "btn btn-sm";
    closeBtn.textContent = t("topbar.close");
    closeBtn.addEventListener("click", () => this.closeModal());
    closeRow.appendChild(closeBtn);
    this.modalCardEl.append(title, status, closeRow);
    this.modalBackdropEl.classList.remove("hidden");

    try {
      const rawBytes = await this.downloadAndVerifyClipBlob(item, meta);
      if (this.modalBackdropEl.classList.contains("hidden")) return;
      const copy = new Uint8Array(rawBytes.byteLength);
      copy.set(rawBytes);
      const blob = new Blob([copy], { type: meta.mime });
      const objUrl = URL.createObjectURL(blob);
      this.activeModalObjectUrl = objUrl;
      const img = document.createElement("img");
      img.className = "pwa-clip-preview-img";
      img.src = objUrl;
      img.alt = t("clip.previewModalTitle");
      this.modalCardEl.replaceChildren(title, img, closeRow);
    } catch (e) {
      this.closeModal();
      this.showToast(e instanceof Error ? e.message : t("clip.errIntegrity"), true);
    }
  }

  private async handleDeleteClip(clipId: string): Promise<void> {
    if (!this.creds || !this.canWriteClip()) return;
    try {
      await deleteCloudClip(this.creds.sync_url, this.creds.device_token, clipId);
      await deleteClipItemIdb(clipId);
      this.clipItemsCipher = this.clipItemsCipher.filter((c) => c.clip_id !== clipId);
      this.decryptedClips.delete(clipId);
      this.renderMain();
      this.showToast(t("clip.toastDeleted"));
    } catch (e) {
      this.showToast(e instanceof Error ? e.message : t("pwa.toastSyncFailed"), true);
    }
  }

  private async handleClearClips(): Promise<void> {
    if (!this.creds || !this.canWriteClip()) return;
    try {
      await deleteCloudClip(this.creds.sync_url, this.creds.device_token);
      await clearClipItemsIdb();
      this.clipItemsCipher = [];
      this.decryptedClips.clear();
      this.renderMain();
      this.showToast(t("clip.toastCleared"));
    } catch (e) {
      this.showToast(e instanceof Error ? e.message : t("pwa.toastSyncFailed"), true);
    }
  }

  private renderClipboardView(): void {
    const view = document.createElement("section");
    view.className = "pwa-clip-view";
    view.dataset.testid = "pwa-clip-view";

    if (this.canWriteClip()) {
      const composer = document.createElement("div");
      composer.className = "pwa-clip-composer";

      const textarea = document.createElement("textarea");
      textarea.className = "input pwa-clip-textarea";
      textarea.rows = 3;
      textarea.placeholder = t("pwa.clipTextareaPlaceholder");
      textarea.value = this.clipDraftText;
      textarea.dataset.testid = "pwa-clip-textarea";
      textarea.addEventListener("input", () => {
        this.clipDraftText = textarea.value;
        if (this.clipErrorMsg) {
          this.clipErrorMsg = null;
          errBox.classList.add("hidden");
        }
      });
      textarea.addEventListener("paste", (ev) => {
        const files = ev.clipboardData?.files;
        if (files && files.length > 0) {
          for (let i = 0; i < files.length; i++) {
            const f = files[i];
            if (f && (f.type.toLowerCase().startsWith("image/") || f.name.toLowerCase().endsWith(".svg"))) {
              ev.preventDefault();
              const mime = f.type || (f.name.toLowerCase().endsWith(".svg") ? "image/svg+xml" : "");
              void this.sendClipImage(f, mime);
              return;
            }
          }
        }
      });

      const controls = document.createElement("div");
      controls.className = "pwa-clip-composer-row";

      const ephLabel = document.createElement("label");
      ephLabel.className = "pwa-clip-check";
      const ephCheck = document.createElement("input");
      ephCheck.type = "checkbox";
      ephCheck.checked = this.clipEphemeral;
      ephCheck.dataset.testid = "pwa-clip-ephemeral";
      ephCheck.addEventListener("change", () => {
        this.clipEphemeral = ephCheck.checked;
      });
      const ephSpan = document.createElement("span");
      ephSpan.textContent = t("clip.ephemeralShort");
      ephLabel.append(ephCheck, ephSpan);

      const actionCluster = document.createElement("div");
      actionCluster.className = "pwa-clip-actions";

      const fileLabel = document.createElement("label");
      fileLabel.className = "btn btn-sm btn-has-icon pwa-file-label";
      fileLabel.title = t("clip.pickImageTitle");
      const fileInput = document.createElement("input");
      fileInput.type = "file";
      fileInput.className = "sr-only";
      fileInput.accept = "image/png,image/jpeg,image/webp,image/gif";
      fileInput.dataset.testid = "pwa-clip-file";
      fileInput.addEventListener("change", () => {
        const file = fileInput.files?.[0];
        fileInput.value = "";
        if (file) {
          const mime = file.type || (file.name.toLowerCase().endsWith(".svg") ? "image/svg+xml" : "");
          void this.sendClipImage(file, mime);
        }
      });
      const fileText = document.createElement("span");
      fileText.textContent = t("clip.pickImage");
      fileLabel.append(createIcon("image", "xs"), fileText, fileInput);

      const sendBtn = document.createElement("button");
      sendBtn.type = "button";
      sendBtn.className = "btn btn-primary btn-sm btn-has-icon";
      sendBtn.dataset.testid = "pwa-clip-send";
      sendBtn.disabled = this.clipSending;
      const sendSpan = document.createElement("span");
      sendSpan.textContent = this.clipSending ? t("clip.sending") : t("clip.send");
      sendBtn.append(createIcon("send", "xs"), sendSpan);
      sendBtn.addEventListener("click", () => void this.sendClipText(this.clipDraftText, this.clipEphemeral));

      actionCluster.append(fileLabel, sendBtn);
      controls.append(ephLabel, actionCluster);

      const errBox = document.createElement("div");
      errBox.className = `pwa-clip-error${this.clipErrorMsg ? "" : " hidden"}`;
      errBox.dataset.testid = "pwa-clip-error";
      errBox.setAttribute("role", "alert");
      if (this.clipErrorMsg) {
        errBox.append(createIcon("alert-triangle", "xs"), document.createTextNode(this.clipErrorMsg));
      }

      composer.append(textarea, controls, errBox);
      view.appendChild(composer);
    } else {
      const notice = document.createElement("div");
      notice.className = "pwa-clip-notice";
      notice.dataset.testid = "pwa-clip-readonly-notice";
      notice.textContent = t("clip.errReadOnlyScope");
      view.appendChild(notice);
    }

    const listBar = document.createElement("div");
    listBar.className = "pwa-clip-list-bar";
    const countSpan = document.createElement("span");
    countSpan.textContent = `${t("clip.title")} · ${t("clip.count", { count: this.clipItemsCipher.length })}`;
    listBar.appendChild(countSpan);

    if (this.canWriteClip() && this.clipItemsCipher.length > 0) {
      const clearBtn = document.createElement("button");
      clearBtn.type = "button";
      clearBtn.className = "btn btn-ghost btn-danger btn-sm";
      clearBtn.dataset.testid = "pwa-clip-clear";
      clearBtn.textContent = t("clip.clearAll");
      clearBtn.addEventListener("click", () => void this.handleClearClips());
      listBar.appendChild(clearBtn);
    }
    view.appendChild(listBar);

    const list = document.createElement("div");
    list.className = "pwa-clip-list";
    list.dataset.testid = "pwa-clip-list";

    if (this.clipItemsCipher.length === 0) {
      const empty = document.createElement("div");
      empty.className = "onboard-card";
      empty.textContent = t("clip.empty");
      list.appendChild(empty);
    } else {
      for (const row of this.clipItemsCipher) {
        const meta = this.decryptedClips.get(row.clip_id);
        const card = document.createElement("article");
        card.className = "pwa-clip-card";
        card.dataset.clipId = row.clip_id;

        const head = document.createElement("div");
        head.className = "pwa-clip-card-head";

        const metaDiv = document.createElement("div");
        metaDiv.className = "pwa-clip-card-meta";
        const kindBadge = document.createElement("span");
        kindBadge.className = "badge";
        kindBadge.textContent =
          row.kind === "image"
            ? (meta?.mime ? meta.mime.replace(/^image\//, "").toUpperCase() : t("clip.kindImage"))
            : t("clip.kindText");
        metaDiv.appendChild(kindBadge);

        if (meta?.blob?.width && meta.blob.height) {
          const dim = document.createElement("span");
          dim.textContent = `${meta.blob.width}x${meta.blob.height}`;
          metaDiv.appendChild(dim);
        }
        const byteCount = meta?.blob?.byte_size ?? row.blob_bytes;
        if (byteCount) {
          const sz = document.createElement("span");
          sz.textContent = formatClipBytes(byteCount);
          metaDiv.appendChild(sz);
        }
        const dev = formatDeviceName(row.device_id);
        const ts = formatHistoryTimestamp(row.created_at_ms);
        if (dev || ts) {
          const orig = document.createElement("span");
          orig.textContent = dev && ts ? `${dev} · ${ts}` : dev || ts;
          metaDiv.appendChild(orig);
        }

        const actions = document.createElement("div");
        actions.className = "pwa-clip-card-actions";
        if (meta) {
          const copyBtn = document.createElement("button");
          copyBtn.type = "button";
          copyBtn.className = "btn btn-sm btn-has-icon";
          copyBtn.dataset.testid = `pwa-clip-copy-${row.clip_id}`;
          const cLbl = document.createElement("span");
          cLbl.textContent = row.kind === "image" ? t("pwa.clipCopyImage") : t("block.copy");
          copyBtn.append(createIcon("copy", "xs"), cLbl);
          copyBtn.addEventListener("click", () => {
            if (row.kind === "image") {
              this.copyClipImageSyncGesture(row, meta);
            } else {
              this.copyClipTextGesture(row, meta);
            }
          });
          actions.appendChild(copyBtn);

          if (row.kind === "image") {
            const prevBtn = document.createElement("button");
            prevBtn.type = "button";
            prevBtn.className = "btn btn-ghost btn-sm btn-has-icon";
            prevBtn.dataset.testid = `pwa-clip-preview-${row.clip_id}`;
            const pLbl = document.createElement("span");
            pLbl.textContent = t("clip.preview");
            prevBtn.append(createIcon("eye", "xs"), pLbl);
            prevBtn.addEventListener("click", () => void this.openClipImagePreview(row, meta));
            actions.appendChild(prevBtn);
          }
        }

        if (this.canWriteClip()) {
          const delBtn = document.createElement("button");
          delBtn.type = "button";
          delBtn.className = "btn btn-ghost btn-danger btn-sm";
          delBtn.dataset.testid = `pwa-clip-delete-${row.clip_id}`;
          delBtn.setAttribute("aria-label", t("clip.delete"));
          delBtn.appendChild(createIcon("trash", "xs"));
          delBtn.addEventListener("click", () => void this.handleDeleteClip(row.clip_id));
          actions.appendChild(delBtn);
        }

        head.append(metaDiv, actions);
        card.appendChild(head);

        if (!meta) {
          const locked = document.createElement("div");
          locked.className = "ro-locked-body";
          locked.append(createIcon("alert-triangle", "xs"), document.createTextNode(t("pwa.clipUnreadableItem")));
          card.appendChild(locked);
        } else if (row.kind === "image") {
          const thumbWrap = document.createElement("div");
          thumbWrap.className = "pwa-clip-thumb-wrap";
          if (meta.blob?.thumb_mime && meta.blob.thumb_b64 && isAllowedBitmapMime(meta.blob.thumb_mime)) {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "pwa-clip-thumb-btn";
            btn.addEventListener("click", () => void this.openClipImagePreview(row, meta));
            const img = document.createElement("img");
            img.className = "pwa-clip-thumb-img";
            img.src = `data:${meta.blob.thumb_mime};base64,${meta.blob.thumb_b64}`;
            img.alt = t("clip.kindImage");
            btn.appendChild(img);
            thumbWrap.appendChild(btn);
          } else {
            const ph = document.createElement("div");
            ph.className = "muted";
            ph.append(createIcon("image", "xs"), document.createTextNode(` ${meta.mime}`));
            thumbWrap.appendChild(ph);
          }
          card.appendChild(thumbWrap);
        } else {
          const pre = document.createElement("pre");
          pre.className = "ro-pre";
          pre.textContent = meta.text ?? "";
          card.appendChild(pre);
        }

        list.appendChild(card);
      }
    }

    view.appendChild(list);
    this.mainEl.appendChild(view);
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
