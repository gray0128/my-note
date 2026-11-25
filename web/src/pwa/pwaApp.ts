import {
  b64ToBytes,
  ensurePwaWasm,
  parseWasmError,
  WasmSyncEngine,
  WasmVaultSession,
} from "../wasm/pwa";
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
const PWA_BUILD_VERSION = "M2-0.2.0";

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
  private searchQuery = "";
  private syncInFlight = false;
  private syncQueued = false;
  private syncAbort: AbortController | null = null;
  private wsConnected = false;
  private disconnectWs: (() => void) | null = null;
  private revoked = false;
  private pairingErrorBanner: string | null = null;
  private statusText = "Idle";
  private toastTimer: number | null = null;
  private activeMediaStream: MediaStream | null = null;

  private headerEl!: HTMLElement;
  private bannerEl!: HTMLElement;
  private mainEl!: HTMLElement;
  private footerEl!: HTMLElement;
  private modalBackdropEl!: HTMLElement;
  private modalCardEl!: HTMLElement;
  private toastEl!: HTMLElement;

  constructor(private root: HTMLElement) {
    this.buildShell();
    document.addEventListener("visibilitychange", this.onVisibilityChange);
    window.addEventListener("beforeunload", this.onPageHide);
    window.addEventListener("pagehide", this.onPageHide);
    window.addEventListener("pageshow", this.onPageShow);
    window.addEventListener("online", this.onOnline);
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
    this.syncAbort?.abort();
    this.stopCamera();
    this.lockVaultNow(true);
    this.disconnectWs?.();
    if (this.engine) {
      this.engine.zeroizeSmk();
      this.engine.free();
      this.engine = null;
    }
    document.removeEventListener("visibilitychange", this.onVisibilityChange);
    window.removeEventListener("beforeunload", this.onPageHide);
    window.removeEventListener("pagehide", this.onPageHide);
    window.removeEventListener("pageshow", this.onPageShow);
    window.removeEventListener("online", this.onOnline);
  }

  private buildShell(): void {
    this.root.innerHTML = "";
    this.headerEl = document.createElement("header");
    this.headerEl.className = "pwa-header";
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
    this.modalBackdropEl.appendChild(this.modalCardEl);
    this.toastEl = document.createElement("div");
    this.toastEl.className = "toast hidden";

    this.root.append(this.headerEl, this.bannerEl, this.mainEl, this.footerEl, this.modalBackdropEl, this.toastEl);
  }

  private onVisibilityChange = (): void => {
    if (document.visibilityState === "hidden") {
      // SEC-08: Immediately zeroize VKEK and scrub ALL Tier 2 plaintext from RAM & DOM on hide!
      this.lockVaultNow(true);
    } else if (document.visibilityState === "visible" && this.creds && !this.revoked) {
      void this.syncNow();
    }
  };

  private onPageHide = (): void => {
    this.syncAbort?.abort();
    this.disconnectWs?.();
    this.lockVaultNow(true);
  };

  private onPageShow = (): void => {
    if (this.creds && !this.revoked) void this.syncNow();
  };

  private onOnline = (): void => {
    if (this.creds && !this.revoked) void this.syncNow();
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
    if (!this.creds || this.revoked) return;
    this.disconnectWs = connectCloudWs(this.creds.sync_url, this.creds.device_token, {
      onWake: () => void this.syncNow(),
      onRevoked: () => this.handleDeviceRevoked(),
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
    if (this.vaultSession && !this.vaultSession.isLocked()) {
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
    this.statusText = "Syncing…";
    this.renderHeader();
    try {
      const { sync_url, device_token } = this.creds;
      let parsedState = JSON.parse(this.stateJson || "{}") as { journal_epoch?: string | null; last_seq?: number };
      let lastOut: WasmStepOutput | null = null;

      // 1. Bootstrap from latest MNP1 mobile state snapshot if cache is empty
      if (!parsedState.journal_epoch || (parsedState.last_seq ?? 0) === 0) {
        const snap = await fetchCloudStateSnapshot(sync_url, device_token, signal);
        if (snap) {
          lastOut = this.applyStep({ type: "install_snapshot", snapshot_b64: snap.snapshot_b64 });
          parsedState = lastOut.state;
        }
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
      };

      if (!this.keysDigest) {
        await fetchAndMergeKeys();
      }

      // 3. Pull tail ops strictly advancing cursor from PullResponse
      let since = parsedState.last_seq ?? 0;
      let remoteDigest: string | null = null;
      for (let page = 0; page < 50; page++) {
        const pull = await pullCloudOps(sync_url, device_token, since, 200, signal);
        remoteDigest = pull.keys_digest;
        if (pull.ops.length > 0 || !parsedState.journal_epoch || parsedState.journal_epoch !== pull.epoch) {
          lastOut = this.applyStep({
            type: "apply_tail_ops",
            epoch: pull.epoch,
            ops: pull.ops,
          });
          if (lastOut.needs_reset) {
            // Epoch changed on server (e.g. DO PITR) — re-bootstrap cleanly from snapshot + keys + seq 0
            const snap = await fetchCloudStateSnapshot(sync_url, device_token, signal);
            if (snap) {
              lastOut = this.applyStep({ type: "install_snapshot", snapshot_b64: snap.snapshot_b64 });
            }
            await fetchAndMergeKeys();
            parsedState = lastOut.state;
            since = parsedState.last_seq ?? 0;
            continue;
          }
          parsedState = lastOut.state;
          since = parsedState.last_seq ?? since;
        }
        if (!pull.has_more) break;
      }

      if (remoteDigest && remoteDigest !== this.keysDigest) {
        await fetchAndMergeKeys();
      }

      if (lastOut) {
        await saveEngineState(lastOut.state, lastOut.keys_digest);
      }
      this.statusText = `Synced #${parsedState.last_seq ?? 0}`;
    } catch (e) {
      if (signal.aborted || (e instanceof DOMException && e.name === "AbortError")) {
        return;
      }
      if (e instanceof CloudApiError && (e.status === 401 || e.code === "DEVICE_REVOKED" || e.code === "AUTH_REQUIRED")) {
        this.handleDeviceRevoked();
        return;
      }
      this.statusText = "Offline (cached)";
      this.showToast(e instanceof Error ? e.message : "Sync failed", true);
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
    this.pairingErrorBanner = null;
    try {
      await ensurePwaWasm();
      const parsed = JSON.parse(WasmSyncEngine.parsePairingCode(code)) as {
        sync_url: string;
        pair_id: string;
        k_pair_b64u: string;
      };
      const claimed = await claimPairing(parsed.sync_url, parsed.pair_id);
      const payload = JSON.parse(
        WasmSyncEngine.decryptPairingTicket(parsed.pair_id, parsed.k_pair_b64u, b64ToBytes(claimed.ciphertext_b64)),
      ) as PwaCredentials;

      if (isRefresh && this.creds) {
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
        this.showToast("Keys refreshed — re-syncing…");
        await this.syncNow();
        return;
      }

      this.creds = payload;
      this.revoked = false;
      this.stateJson = "{}";
      this.keysDigest = null;
      await saveCredentials(payload);
      this.initEngine();
      this.stopCamera();
      this.render();
      this.connectWs();
      this.showToast("Paired read-only device — syncing…");
      await this.syncNow();
    } catch (e) {
      if (e instanceof CloudApiError && (e.status === 404 || e.status === 410)) {
        this.pairingErrorBanner =
          "Pairing ticket missing, expired, or ALREADY CLAIMED! If you did not claim it, run 'mynote device ls' and 'mynote device revoke' on your desktop immediately.";
        this.render();
        return;
      }
      const parsed = parseWasmError(e);
      this.showToast(`${parsed.code}: ${parsed.message}`, true);
    }
  }

  private lockVaultNow(silent = false): void {
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
    if (!silent) this.showToast("Vault locked — keys & plaintext wiped");
  }

  private resetVaultIdleTimer(): void {
    if (!this.vaultSession) return;
    if (this.vaultIdleTimer !== null) window.clearTimeout(this.vaultIdleTimer);
    this.vaultIdleTimer = window.setTimeout(() => this.lockVaultNow(false), MOBILE_VAULT_IDLE_MS);
  }

  private decryptVaultBlocksInRam(): void {
    const sess = this.vaultSession;
    if (!sess || sess.isLocked()) return;
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
        }
      }
      if (map.size > 0) this.unlockedPlaintext.set(blk.id, map);
    }
  }

  private openVaultUnlockModal(): void {
    if (!this.vaultHeaderB64) {
      this.showToast("No Vault configured yet — initialize Vault on desktop first", true);
      return;
    }
    this.modalCardEl.innerHTML = "";
    const title = document.createElement("h3");
    title.className = "onboard-title";
    title.textContent = "Unlock Mobile Vault";
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent =
      "VKEK is decrypted in browser WASM RAM only (never written to IndexedDB) and auto-locks immediately when you switch apps.";
    const form = document.createElement("form");
    form.style.display = "flex";
    form.style.flexDirection = "column";
    form.style.gap = "10px";
    const pass = document.createElement("input");
    pass.type = "password";
    pass.className = "input";
    pass.placeholder = "Vault passphrase";
    pass.dataset.testid = "pwa-vault-passphrase";
    pass.autocomplete = "current-password";
    const row = document.createElement("div");
    row.style.display = "flex";
    row.style.justifyContent = "flex-end";
    row.style.gap = "8px";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn";
    cancel.textContent = "Cancel";
    cancel.addEventListener("click", () => this.closeModal());
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "btn btn-primary";
    submit.dataset.testid = "pwa-vault-unlock-submit";
    submit.textContent = "Unlock";
    row.append(cancel, submit);
    form.append(pass, row);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      if (!this.vaultHeaderB64) return;
      submit.disabled = true;
      submit.textContent = "Deriving key…";
      window.setTimeout(() => {
        try {
          this.vaultSession = WasmVaultSession.unlockWithPassphrase(pass.value, b64ToBytes(this.vaultHeaderB64!));
          pass.value = "";
          this.decryptVaultBlocksInRam();
          this.resetVaultIdleTimer();
          this.closeModal();
          this.render();
          this.showToast("Vault unlocked in RAM (auto-locks on app switch)");
        } catch (e) {
          const parsed = parseWasmError(e);
          this.showToast(`${parsed.code}: ${parsed.message}`, true);
          submit.disabled = false;
          submit.textContent = "Unlock";
        }
      }, 0);
    });
    this.modalCardEl.append(title, note, form);
    this.modalBackdropEl.classList.remove("hidden");
    pass.focus();
  }

  private openRefreshKeysModal(): void {
    this.modalCardEl.innerHTML = "";
    const title = document.createElement("h3");
    title.className = "onboard-title";
    title.textContent = "Refresh Device Keys";
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "Paste the refresh code from 'mynote device refresh <device_id>' on your desktop:";
    const form = document.createElement("form");
    form.style.display = "flex";
    form.style.flexDirection = "column";
    form.style.gap = "10px";
    const input = document.createElement("input");
    input.className = "input";
    input.placeholder = "mynote-pair:v1:...";
    const row = document.createElement("div");
    row.style.display = "flex";
    row.style.justifyContent = "flex-end";
    row.style.gap = "8px";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn";
    cancel.textContent = "Cancel";
    cancel.addEventListener("click", () => this.closeModal());
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "btn btn-primary";
    submit.textContent = "Refresh Keys";
    row.append(cancel, submit);
    form.append(input, row);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      if (input.value.trim()) void this.handlePairSubmit(input.value.trim(), true);
    });
    this.modalCardEl.append(title, note, form);
    this.modalBackdropEl.classList.remove("hidden");
    input.focus();
  }

  private closeModal(): void {
    this.modalBackdropEl.classList.add("hidden");
    this.modalCardEl.innerHTML = "";
  }

  private stopCamera(): void {
    if (this.activeMediaStream) {
      for (const t of this.activeMediaStream.getTracks()) t.stop();
      this.activeMediaStream = null;
    }
  }

  private copyTextGesture(text: string, isTier2: boolean): void {
    const finish = (ok: boolean) => {
      if (!ok) {
        this.showToast("Clipboard unavailable — tap & hold text to copy", true);
      } else if (isTier2) {
        this.resetVaultIdleTimer();
        this.showToast("Copied Vault secret (Note: iOS/Universal Clipboard cannot be auto-cleared)");
      } else {
        this.showToast("Copied to clipboard");
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
    this.toastEl.textContent = msg;
    this.toastEl.className = `toast${isError ? " error" : ""}`;
    if (this.toastTimer !== null) window.clearTimeout(this.toastTimer);
    this.toastTimer = window.setTimeout(() => this.toastEl.classList.add("hidden"), 3400);
  }

  private render(): void {
    this.renderHeader();
    this.renderBanner();
    this.renderMain();
    this.renderFooter();
  }

  private renderHeader(): void {
    this.headerEl.innerHTML = "";
    const row1 = document.createElement("div");
    row1.className = "pwa-header-row";
    const brand = document.createElement("div");
    brand.className = "pwa-brand";
    brand.textContent = "my-note";
    const ro = document.createElement("span");
    ro.className = "ro-pill";
    ro.textContent = "READ-ONLY";
    brand.appendChild(ro);

    const actions = document.createElement("div");
    actions.className = "pwa-actions";
    if (this.creds && !this.revoked) {
      if (this.vaultSession && !this.vaultSession.isLocked()) {
        const lockBtn = document.createElement("button");
        lockBtn.type = "button";
        lockBtn.className = "btn btn-amber btn-sm";
        lockBtn.dataset.testid = "pwa-vault-lock-btn";
        lockBtn.textContent = "🔓 Lock";
        lockBtn.addEventListener("click", () => this.lockVaultNow(false));
        actions.appendChild(lockBtn);
      } else if (this.vaultHeaderB64) {
        const unlockBtn = document.createElement("button");
        unlockBtn.type = "button";
        unlockBtn.className = "btn btn-sm";
        unlockBtn.dataset.testid = "pwa-vault-unlock-btn";
        unlockBtn.textContent = "🔒 Vault";
        unlockBtn.addEventListener("click", () => this.openVaultUnlockModal());
        actions.appendChild(unlockBtn);
      }
      const syncBtn = document.createElement("button");
      syncBtn.type = "button";
      syncBtn.className = "btn btn-sm";
      syncBtn.textContent = this.syncInFlight ? "Syncing…" : this.wsConnected ? `● ${this.statusText}` : this.statusText;
      syncBtn.addEventListener("click", () => void this.syncNow());
      actions.appendChild(syncBtn);

      const keysBtn = document.createElement("button");
      keysBtn.type = "button";
      keysBtn.className = "btn btn-sm";
      keysBtn.textContent = "Keys";
      keysBtn.title = "Refresh device keys";
      keysBtn.addEventListener("click", () => this.openRefreshKeysModal());
      actions.appendChild(keysBtn);
    }
    row1.append(brand, actions);
    this.headerEl.appendChild(row1);

    if (this.creds && !this.revoked && this.buffers.length > 0) {
      const tabs = document.createElement("nav");
      tabs.className = "pwa-tabs";
      tabs.setAttribute("aria-label", "Buffers");
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
      this.headerEl.appendChild(tabs);

      const search = document.createElement("input");
      search.type = "search";
      search.className = "input";
      search.placeholder = "Filter blocks in memory…";
      search.value = this.searchQuery;
      search.addEventListener("input", () => {
        this.searchQuery = search.value;
        this.renderMain();
      });
      this.headerEl.appendChild(search);
    }
  }

  private renderBanner(): void {
    this.bannerEl.innerHTML = "";
    if (this.revoked) {
      const b = document.createElement("div");
      b.className = "banner banner-error";
      b.dataset.testid = "pwa-revoked-banner";
      const msg = document.createElement("span");
      msg.textContent = "DEVICE_REVOKED: This mobile device was revoked on the relay. Clear local cache and re-pair from desktop.";
      const resetBtn = document.createElement("button");
      resetBtn.type = "button";
      resetBtn.className = "btn btn-danger btn-sm";
      resetBtn.textContent = "Reset & Re-Pair";
      resetBtn.addEventListener("click", () => {
        void clearAllPwaStorage().then(() => {
          this.creds = null;
          this.revoked = false;
          this.stateJson = "{}";
          this.buffers = [];
          this.blocks = [];
          this.render();
        });
      });
      b.append(msg, resetBtn);
      this.bannerEl.appendChild(b);
    } else if (this.pairingErrorBanner) {
      const b = document.createElement("div");
      b.className = "banner banner-error";
      b.dataset.testid = "pwa-snatch-warning";
      b.textContent = this.pairingErrorBanner;
      this.bannerEl.appendChild(b);
    }
  }

  private renderMain(): void {
    this.mainEl.innerHTML = "";
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
      empty.textContent = this.blocks.length === 0 ? "No notes synced yet." : "No matching blocks in this buffer.";
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
    h.textContent = "Pair Read-Only Mobile Device";
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent =
      "Run 'mynote device add --name iPhone --scope read' on your desktop and paste or scan the pairing code below. Keys stay encrypted in IndexedDB; zero plaintext is ever persisted.";

    const form = document.createElement("form");
    form.style.display = "flex";
    form.style.flexDirection = "column";
    form.style.gap = "10px";
    const input = document.createElement("input");
    input.className = "input";
    input.placeholder = "mynote-pair:v1:...";
    input.dataset.testid = "pwa-pair-input";
    const btnRow = document.createElement("div");
    btnRow.style.display = "flex";
    btnRow.style.gap = "8px";
    btnRow.style.flexWrap = "wrap";
    const pairBtn = document.createElement("button");
    pairBtn.type = "submit";
    pairBtn.className = "btn btn-primary";
    pairBtn.dataset.testid = "pwa-pair-submit";
    pairBtn.textContent = "Pair Device";
    const qrBtn = document.createElement("button");
    qrBtn.type = "button";
    qrBtn.className = "btn";
    qrBtn.textContent = "Scan QR (Camera)";
    btnRow.append(pairBtn, qrBtn);
    const qrHost = document.createElement("div");
    qrBtn.addEventListener("click", () => void this.startQrScanner(qrHost, input));
    form.append(input, btnRow, qrHost);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      if (input.value.trim()) void this.handlePairSubmit(input.value.trim(), false);
    });
    card.append(h, p, form);
    this.mainEl.appendChild(card);
  }

  private async startQrScanner(host: HTMLElement, targetInput: HTMLInputElement): Promise<void> {
    this.stopCamera();
    host.innerHTML = "";
    const BD = (globalThis as unknown as { BarcodeDetector?: new (opts: { formats: string[] }) => { detect(v: HTMLVideoElement): Promise<{ rawValue: string }[]> } }).BarcodeDetector;
    if (!navigator.mediaDevices?.getUserMedia || !BD) {
      const msg = document.createElement("p");
      msg.className = "muted";
      msg.textContent = "In-app QR camera scanning is unavailable in this browser — paste the pairing code directly above.";
      host.appendChild(msg);
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      this.activeMediaStream = stream;
      const video = document.createElement("video");
      video.className = "qr-video";
      video.setAttribute("playsinline", "true");
      video.srcObject = stream;
      await video.play();
      host.appendChild(video);
      const detector = new BD({ formats: ["qr_code"] });
      const tick = async () => {
        if (!this.activeMediaStream) return;
        try {
          const hits = await detector.detect(video);
          const found = hits.find((h) => h.rawValue.startsWith("mynote-pair:v1:"));
          if (found) {
            this.stopCamera();
            targetInput.value = found.rawValue;
            await this.handlePairSubmit(found.rawValue, false);
            return;
          }
        } catch {
          // continue scanning
        }
        if (this.activeMediaStream) window.setTimeout(() => void tick(), 250);
      };
      void tick();
    } catch {
      const msg = document.createElement("p");
      msg.className = "muted";
      msg.textContent = "Camera permission denied — paste the pairing code directly above.";
      host.appendChild(msg);
    }
  }

  private renderReadOnlyBlock(blk: MobileBlockView): HTMLElement {
    const card = document.createElement("article");
    card.className = `ro-block${blk.is_locked ? " locked" : ""}`;
    card.dataset.blockId = blk.id;

    const selectedOpId = this.selectedVersionByBlock.get(blk.id) ?? blk.display_op_id ?? blk.versions[0]?.op_id;
    const selectedLeaf = blk.versions.find((v) => v.op_id === selectedOpId) ?? blk.versions[0];
    const ramPlain = selectedLeaf ? (this.unlockedPlaintext.get(blk.id)?.get(selectedLeaf.op_id) ?? null) : null;
    const effectiveText = selectedLeaf ? (selectedLeaf.content ?? ramPlain) : null;
    const isUnlockedTier2 = blk.is_locked && effectiveText !== null;

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
      vb.textContent = isUnlockedTier2 ? "🔓 Vault (RAM)" : "🔒 Tier 2";
      meta.appendChild(vb);
    }
    if (blk.public_hint) {
      const hint = document.createElement("span");
      hint.textContent = blk.public_hint;
      meta.appendChild(hint);
    }

    head.appendChild(meta);
    if (effectiveText !== null) {
      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "btn btn-sm";
      copyBtn.dataset.testid = `copy-${blk.id}`;
      copyBtn.textContent = "Copy";
      copyBtn.addEventListener("click", () => this.copyTextGesture(effectiveText, blk.is_locked));
      head.appendChild(copyBtn);
    }
    card.appendChild(head);

    if (blk.versions.length > 1) {
      const vbar = document.createElement("div");
      vbar.className = "version-bar";
      const lbl = document.createElement("span");
      lbl.textContent = `⚡ ${blk.versions.length} concurrent versions:`;
      vbar.appendChild(lbl);
      blk.versions.forEach((v, idx) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = `btn btn-sm${v.op_id === selectedLeaf?.op_id ? " btn-primary" : ""}`;
        b.textContent = v.is_display ? `Display (#${idx + 1})` : `Version #${idx + 1} (${v.device_id.slice(0, 8)})`;
        b.addEventListener("click", () => {
          this.selectedVersionByBlock.set(blk.id, v.op_id);
          this.renderMain();
        });
        vbar.appendChild(b);
      });
      card.appendChild(vbar);
    }

    if (blk.is_locked && effectiveText === null) {
      const locked = document.createElement("div");
      locked.className = "ro-locked-body";
      const txt = document.createElement("span");
      txt.textContent = `🔒 Locked Tier 2 Block${blk.public_hint ? ` (${blk.public_hint})` : ""}${
        blk.has_unlocked_concurrent_version ? " — has unlocked concurrent version" : ""
      }`;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-primary btn-sm";
      btn.textContent = "Unlock Vault";
      btn.addEventListener("click", () => this.openVaultUnlockModal());
      locked.append(txt, btn);
      card.appendChild(locked);
    } else if (effectiveText === null) {
      const locked = document.createElement("div");
      locked.className = "ro-locked-body";
      locked.textContent = "⚠ Content unavailable (missing key or awaiting key refresh).";
      card.appendChild(locked);
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
    this.footerEl.innerHTML = "";
    const span = document.createElement("span");
    span.textContent = `my-note Mobile Read-Only PWA ${PWA_BUILD_VERSION} · Zero-Plaintext IDB`;
    this.footerEl.appendChild(span);
    if (this.creds) {
      const sep = document.createTextNode(" · ");
      const unpair = document.createElement("button");
      unpair.type = "button";
      unpair.className = "btn btn-sm btn-danger";
      unpair.style.marginLeft = "6px";
      unpair.textContent = "Unpair";
      unpair.addEventListener("click", () => {
        void clearAllPwaStorage().then(() => {
          this.disconnectWs?.();
          this.disconnectWs = null;
          this.lockVaultNow(true);
          if (this.engine) {
            this.engine.zeroizeSmk();
            this.engine.free();
            this.engine = null;
          }
          this.creds = null;
          this.stateJson = "{}";
          this.buffers = [];
          this.blocks = [];
          this.render();
          this.showToast("Unpaired and wiped local IndexedDB");
        });
      });
      this.footerEl.append(sep, unpair);
    }
  }
}
