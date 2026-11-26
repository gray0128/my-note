import { LocalApiError, type LocalApiClient, type Tier2WritePayload } from "./api";
import { BlockStreamController, type SaveContentResult } from "./editor";
import { computeLineDiff } from "./render/diff";
import { copyDualFormat } from "./render/markdown";
import type {
  AlertFrame,
  BlockDto,
  BlockHistoryContentDto,
  BlockHistoryEntryDto,
  BufferDto,
  LocalWsFrame,
  SyncStateLabel,
  SyncStatusDto,
  TrashActionPrepareResponse,
  TrashItemDto,
  VaultHeaderDto,
} from "./types";
import {
  b64ToBytes,
  bytesToB64,
  createVaultHeaderWasm,
  formatSnippetWasm,
  parseWasmError,
  unlockVaultWithPassphraseWasm,
  unlockVaultWithRecoveryWordsWasm,
  type WasmVaultSession,
} from "./wasm/desktop";

const VAULT_IDLE_MS = 5 * 60 * 1000;
const T_GRACE_MIN_MS = 86_400_000;
const isPageHidden = (): boolean => document.visibilityState === "hidden";

interface SecretNudge {
  blockId: string;
  secretType: string;
}

export class MyNoteApp {
  private buffers: BufferDto[] = [];
  private activeBufferId: string | null = null;
  private syncStatus: SyncStatusDto | null = null;
  private vaultHeader: VaultHeaderDto | null = null;
  private recoveryPkB64: string | null = null;
  private vaultSession: WasmVaultSession | null = null;
  private vaultIdleTimer: number | null = null;
  private pendingAfterUnlock: (() => Promise<void>) | null = null;
  private secretNudge: SecretNudge | null = null;
  private wsConnected = true;
  private switchSeq = 0;
  private alerts = new Map<string, AlertFrame>();
  private trashItems: TrashItemDto[] = [];
  private trashOpen = false;
  private historyOpen = false;
  private historyBlockId: string | null = null;
  private historyBlockLocked = false;
  private historyEntries: BlockHistoryEntryDto[] = [];
  private historySelectedOpId: string | null = null;
  private historySelectedContent: string | null = null;
  private historySelectedDto: BlockHistoryContentDto | null = null;
  private historyLoading = false;
  private historyOpLoading = false;
  private historyError: string | null = null;
  private historyLoadSeq = 0;
  private historyOpSeq = 0;
  private vimEnabled = false;
  private findIndex = 0;
  private disconnectWs: (() => void) | null = null;
  private toastTimer: number | null = null;

  private bufferTabsEl!: HTMLElement;
  private vaultBtnEl!: HTMLButtonElement;
  private syncPillEl!: HTMLButtonElement;
  private trashBtnEl!: HTMLButtonElement;
  private alertStackEl!: HTMLElement;
  private findBarEl!: HTMLElement;
  private findInputEl!: HTMLInputElement;
  private replaceInputEl!: HTMLInputElement;
  private findCountEl!: HTMLElement;
  private trashDrawerEl!: HTMLElement;
  private trashActionsEl!: HTMLElement;
  private trashListEl!: HTMLElement;
  private historyDrawerEl!: HTMLElement;
  private historyTitleEl!: HTMLElement;
  private historyActionsEl!: HTMLElement;
  private historyListEl!: HTMLElement;
  private historyDiffEl!: HTMLElement;
  private modalBackdropEl!: HTMLElement;
  private modalListEl!: HTMLElement;
  private newBufInputEl!: HTMLInputElement;
  private dialogBackdropEl!: HTMLElement;
  private dialogModalEl!: HTMLElement;
  private toastEl!: HTMLElement;
  public stream!: BlockStreamController;

  constructor(private root: HTMLElement, private api: LocalApiClient) {
    this.buildShell();
    this.bindGlobalKeys();
  }

  async start(): Promise<void> {
    const boot = await this.api.bootstrap();
    this.buffers = boot.buffers;
    this.activeBufferId = boot.initial_buffer_id ?? boot.buffers[0]?.id ?? null;
    this.syncStatus = boot.sync_status;
    this.vaultHeader = boot.vault_header ?? null;
    this.recoveryPkB64 = boot.recovery_pk_b64 ?? null;
    this.updateAlertsFromStatus(boot.sync_status);
    this.renderBuffers();
    this.renderVaultBtn();
    this.renderSyncPill();
    this.updateTrashCount(boot.trash_count);
    this.stream.setBlocks(boot.blocks);

    this.disconnectWs = this.api.connectWs(
      (frame) => this.handleWsFrame(frame),
      (connected, reconnected) => {
        this.wsConnected = connected;
        this.renderSyncPill();
        if (connected && reconnected) {
          void this.resyncAfterReconnect();
        }
      },
      () => {
        this.wsConnected = false;
        this.alerts.set("AUTH_REQUIRED", {
          type: "alert",
          code: "AUTH_REQUIRED",
          details: { message: "Local session expired — run 'mynote open' to re-authenticate." },
        });
        this.renderAlerts();
        this.renderSyncPill();
      },
    );
  }

  destroy(): void {
    this.lockVaultNow({ skipFlush: true, silent: true });
    this.disconnectWs?.();
    if (this.toastTimer !== null) {
      window.clearTimeout(this.toastTimer);
      this.toastTimer = null;
    }
    this.stream.destroy();
    window.removeEventListener("keydown", this.onWindowKeyDown);
    document.removeEventListener("visibilitychange", this.onVisibilityChange);
    window.removeEventListener("pagehide", this.onPageHide);
    window.removeEventListener("beforeunload", this.onBeforeUnload);
  }

  /** Public lock helper (used by UI button, visibilitychange hidden, idle timeout, and security tests). */
  lockVaultNow(opts: { skipFlush?: boolean; silent?: boolean } = {}): void {
    if (!opts.skipFlush && this.vaultSession && this.stream.hasDirtyBlocks()) {
      void this.stream.flushAllDirty({ keepalive: true });
    }
    if (this.vaultIdleTimer !== null) {
      window.clearTimeout(this.vaultIdleTimer);
      this.vaultIdleTimer = null;
    }
    if (this.vaultSession) {
      try {
        this.vaultSession.lockAndZeroize();
        this.vaultSession.free();
      } catch {
        // ignore if already freed
      }
      this.vaultSession = null;
    }
    this.stream.clearUnlockedVaultPlaintext();
    if (this.hasLockedHistoryOpen()) {
      this.closeHistoryDrawer();
    }
    this.renderVaultBtn();
    if (!opts.silent) {
      this.showToast("Vault locked — keys & plaintext wiped from RAM");
    }
  }

  isVaultUnlocked(): boolean {
    return this.vaultSession !== null && !this.vaultSession.isLocked();
  }

  private resetVaultIdleTimer(): void {
    if (!this.vaultSession) return;
    if (this.vaultIdleTimer !== null) window.clearTimeout(this.vaultIdleTimer);
    this.vaultIdleTimer = window.setTimeout(() => {
      this.lockVaultNow({ skipFlush: false, silent: false });
    }, VAULT_IDLE_MS);
  }

  private buildShell(): void {
    this.root.innerHTML = "";

    const topbar = document.createElement("header");
    topbar.className = "topbar";

    const left = document.createElement("div");
    left.className = "topbar-left";
    const brand = document.createElement("span");
    brand.className = "brand";
    brand.textContent = "my-note";
    this.bufferTabsEl = document.createElement("nav");
    this.bufferTabsEl.className = "buffer-tabs";
    this.bufferTabsEl.setAttribute("aria-label", "Buffers");
    const switcherBtn = document.createElement("button");
    switcherBtn.type = "button";
    switcherBtn.className = "btn";
    switcherBtn.textContent = "Buffers ⌘P";
    switcherBtn.addEventListener("click", () => this.openBufferModal());
    left.append(brand, this.bufferTabsEl, switcherBtn);

    const right = document.createElement("div");
    right.className = "topbar-right";

    const newBlkBtn = document.createElement("button");
    newBlkBtn.type = "button";
    newBlkBtn.className = "btn btn-primary";
    newBlkBtn.textContent = "+ New Block";
    newBlkBtn.title = "Insert new block (Cmd/Ctrl+Enter)";
    newBlkBtn.addEventListener("click", () => void this.insertBlockAfter(this.stream.getActiveBlockId()));

    const findBtn = document.createElement("button");
    findBtn.type = "button";
    findBtn.className = "btn";
    findBtn.textContent = "Find";
    findBtn.title = "Find & replace across blocks (Cmd/Ctrl+F)";
    findBtn.addEventListener("click", () => this.toggleFindBar(true));

    const vimBtn = document.createElement("button");
    vimBtn.type = "button";
    vimBtn.className = "btn";
    vimBtn.textContent = "Vim: Off";
    vimBtn.addEventListener("click", () => {
      this.vimEnabled = !this.vimEnabled;
      vimBtn.textContent = this.vimEnabled ? "Vim: On" : "Vim: Off";
      this.stream.setVimMode(this.vimEnabled);
    });

    this.vaultBtnEl = document.createElement("button");
    this.vaultBtnEl.type = "button";
    this.vaultBtnEl.className = "btn";
    this.vaultBtnEl.dataset.testid = "vault-btn";
    this.vaultBtnEl.textContent = "Setup Vault";
    this.vaultBtnEl.addEventListener("click", () => this.openVaultModal());

    this.trashBtnEl = document.createElement("button");
    this.trashBtnEl.type = "button";
    this.trashBtnEl.className = "btn";
    this.trashBtnEl.textContent = "Trash (0)";
    this.trashBtnEl.addEventListener("click", () => void this.toggleTrash());

    this.syncPillEl = document.createElement("button");
    this.syncPillEl.type = "button";
    this.syncPillEl.className = "sync-pill";
    this.syncPillEl.dataset.state = "unconfigured";
    const syncDot = document.createElement("span");
    syncDot.className = "sync-dot";
    const syncLabel = document.createElement("span");
    syncLabel.className = "sync-label";
    syncLabel.textContent = "Local Only";
    this.syncPillEl.append(syncDot, syncLabel);
    this.syncPillEl.title = "Click to sync now";
    this.syncPillEl.addEventListener("click", () => void this.triggerSyncNow());

    right.append(newBlkBtn, findBtn, vimBtn, this.vaultBtnEl, this.trashBtnEl, this.syncPillEl);
    topbar.append(left, right);

    this.alertStackEl = document.createElement("div");
    this.alertStackEl.className = "alert-stack";

    // Find & replace bar
    this.findBarEl = document.createElement("div");
    this.findBarEl.className = "find-bar hidden";
    this.findInputEl = document.createElement("input");
    this.findInputEl.className = "input";
    this.findInputEl.placeholder = "Find across buffer...";
    this.findInputEl.addEventListener("input", () => {
      this.findIndex = 0;
      this.runFind(0);
    });
    this.findInputEl.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        this.runFind(ev.shiftKey ? -1 : 1);
      }
    });
    this.replaceInputEl = document.createElement("input");
    this.replaceInputEl.className = "input";
    this.replaceInputEl.placeholder = "Replace with...";
    this.findCountEl = document.createElement("span");
    this.findCountEl.className = "kbd";
    this.findCountEl.textContent = "0 matches";
    const nextBtn = document.createElement("button");
    nextBtn.type = "button";
    nextBtn.className = "btn btn-icon";
    nextBtn.textContent = "Next";
    nextBtn.addEventListener("click", () => this.runFind(1));
    const repBtn = document.createElement("button");
    repBtn.type = "button";
    repBtn.className = "btn btn-icon";
    repBtn.textContent = "Replace All";
    repBtn.addEventListener("click", () => void this.runReplaceAll());
    const closeFindBtn = document.createElement("button");
    closeFindBtn.type = "button";
    closeFindBtn.className = "btn btn-icon";
    closeFindBtn.textContent = "✕";
    closeFindBtn.addEventListener("click", () => this.toggleFindBar(false));
    this.findBarEl.append(this.findInputEl, this.replaceInputEl, this.findCountEl, nextBtn, repBtn, closeFindBtn);

    // Main workspace
    const workspace = document.createElement("main");
    workspace.className = "workspace";
    const streamEl = document.createElement("div");
    streamEl.className = "block-stream";
    this.stream = new BlockStreamController(streamEl, {
      onSaveContent: (blk, content, expectedHeads, opts) =>
        this.saveBlockContent(blk, content, expectedHeads, opts),
      onChangeLang: (blk, lang) => this.changeBlockLang(blk, lang),
      onInsertAfter: (afterId) => this.insertBlockAfter(afterId),
      onFormatBlock: (blk) => this.formatBlock(blk),
      onCopyBlock: (_blk, content) => this.copyBlockContent(content),
      onMoveBlock: (blk, dir) => this.moveBlock(blk, dir),
      onDeleteBlock: (blk) => this.deleteBlock(blk),
      onKeepVersion: (blk, opId) => this.keepVersion(blk, opId),
      onActiveChange: () => {},
      onUnlockVaultRequest: () => this.openVaultModal(),
      onLockBlock: (blk) => this.promptLockBlock(blk),
      onUnlockBlockToTier1: (blk) => this.promptUnlockBlockToTier1(blk),
      onPurgeHistory: (blk) => this.openTrashConfirmModal("purge_history", [blk.id], T_GRACE_MIN_MS, blk),
      onOpenHistory: (blk) => void this.openHistoryDrawer(blk),
      onCopyRich: (blk, html, text) => this.copyBlockRich(blk, html, text),
      onFeedback: (msg, isError) => this.showToast(msg, isError),
      onSecretPasted: (blk, secretType) => {
        this.secretNudge = { blockId: blk.id, secretType };
        this.renderAlerts();
      },
      onVaultActivity: () => this.resetVaultIdleTimer(),
    });

    // Recycle Bin drawer
    this.trashDrawerEl = document.createElement("aside");
    this.trashDrawerEl.className = "drawer hidden";
    const drawerHdr = document.createElement("div");
    drawerHdr.className = "drawer-header";
    const drawerTitle = document.createElement("span");
    drawerTitle.textContent = "Recycle Bin (Recoverable)";
    const closeDrawer = document.createElement("button");
    closeDrawer.type = "button";
    closeDrawer.className = "btn btn-icon";
    closeDrawer.textContent = "✕";
    closeDrawer.addEventListener("click", () => {
      this.trashOpen = false;
      this.trashDrawerEl.classList.add("hidden");
    });
    drawerHdr.append(drawerTitle, closeDrawer);
    this.trashActionsEl = document.createElement("div");
    this.trashActionsEl.className = "drawer-actions";
    this.trashListEl = document.createElement("div");
    this.trashListEl.className = "drawer-list";
    this.trashDrawerEl.append(drawerHdr, this.trashActionsEl, this.trashListEl);

    // Block History (Time Travel) drawer
    this.historyDrawerEl = document.createElement("aside");
    this.historyDrawerEl.className = "drawer history-drawer hidden";
    this.historyDrawerEl.dataset.testid = "history-drawer";
    const histHdr = document.createElement("div");
    histHdr.className = "drawer-header";
    this.historyTitleEl = document.createElement("span");
    this.historyTitleEl.textContent = "Block History";
    const closeHist = document.createElement("button");
    closeHist.type = "button";
    closeHist.className = "btn btn-icon";
    closeHist.dataset.testid = "history-close-btn";
    closeHist.textContent = "✕";
    closeHist.addEventListener("click", () => this.closeHistoryDrawer());
    histHdr.append(this.historyTitleEl, closeHist);
    this.historyActionsEl = document.createElement("div");
    this.historyActionsEl.className = "drawer-actions";
    this.historyListEl = document.createElement("div");
    this.historyListEl.className = "drawer-list history-list";
    this.historyDiffEl = document.createElement("div");
    this.historyDiffEl.className = "history-diff-pane";
    this.historyDrawerEl.append(histHdr, this.historyActionsEl, this.historyListEl, this.historyDiffEl);

    workspace.append(streamEl, this.trashDrawerEl, this.historyDrawerEl);

    // Buffer Switcher modal
    this.modalBackdropEl = document.createElement("div");
    this.modalBackdropEl.className = "modal-backdrop hidden";
    this.modalBackdropEl.addEventListener("click", (ev) => {
      if (ev.target === this.modalBackdropEl) this.closeBufferModal();
    });
    const modal = document.createElement("div");
    modal.className = "modal";
    const modalHdr = document.createElement("div");
    modalHdr.className = "drawer-header";
    modalHdr.textContent = "Switch or Create Buffer";
    this.modalListEl = document.createElement("div");
    this.modalListEl.className = "modal-list";
    const createRow = document.createElement("div");
    createRow.className = "topbar-left";
    this.newBufInputEl = document.createElement("input");
    this.newBufInputEl.className = "input";
    this.newBufInputEl.placeholder = "New buffer name...";
    const createBtn = document.createElement("button");
    createBtn.type = "button";
    createBtn.className = "btn btn-primary";
    createBtn.textContent = "Create";
    createBtn.addEventListener("click", () => void this.createBuffer());
    createRow.append(this.newBufInputEl, createBtn);
    modal.append(modalHdr, this.modalListEl, createRow);
    this.modalBackdropEl.appendChild(modal);

    // Generic M2 Dialog modal (Vault, Lock/Unlock, Trash Shred Confirmation)
    this.dialogBackdropEl = document.createElement("div");
    this.dialogBackdropEl.className = "modal-backdrop hidden";
    this.dialogBackdropEl.dataset.testid = "m2-dialog-backdrop";
    this.dialogBackdropEl.addEventListener("click", (ev) => {
      if (ev.target === this.dialogBackdropEl) this.closeDialog();
    });
    this.dialogModalEl = document.createElement("div");
    this.dialogModalEl.className = "modal";
    this.dialogBackdropEl.appendChild(this.dialogModalEl);

    this.toastEl = document.createElement("div");
    this.toastEl.className = "toast hidden";

    this.root.append(
      topbar,
      this.alertStackEl,
      this.findBarEl,
      workspace,
      this.modalBackdropEl,
      this.dialogBackdropEl,
      this.toastEl,
    );
  }

  private bindGlobalKeys(): void {
    window.addEventListener("keydown", this.onWindowKeyDown);
    document.addEventListener("visibilitychange", this.onVisibilityChange);
    window.addEventListener("pagehide", this.onPageHide);
    window.addEventListener("beforeunload", this.onBeforeUnload);
  }

  private onVisibilityChange = (): void => {
    if (document.visibilityState === "hidden") {
      // H18 / SEC-03: Wipe any open passphrase/recovery inputs immediately on hide.
      if (!this.dialogBackdropEl.classList.contains("hidden")) {
        this.closeDialog();
      }
      // Flush dirty blocks synchronously (keepalive) before immediately zeroizing Vault VKEK & scrubbing DOM (`SEC-03`).
      if (this.stream.hasDirtyBlocks()) {
        void this.stream.flushAllDirty({ keepalive: true });
      }
      if (this.vaultSession) {
        this.lockVaultNow({ skipFlush: true, silent: true });
      } else if (this.hasLockedHistoryOpen()) {
        this.closeHistoryDrawer();
      }
    }
  };

  private onPageHide = (): void => {
    if (!this.dialogBackdropEl.classList.contains("hidden")) {
      this.closeDialog();
    }
    if (this.stream.hasDirtyBlocks()) {
      void this.stream.flushAllDirty({ keepalive: true });
    }
    if (this.vaultSession) {
      this.lockVaultNow({ skipFlush: true, silent: true });
    } else if (this.hasLockedHistoryOpen()) {
      this.closeHistoryDrawer();
    }
  };

  private onBeforeUnload = (ev: BeforeUnloadEvent): void => {
    if (this.stream.hasDirtyBlocks()) {
      void this.stream.flushAllDirty({ keepalive: true });
      ev.preventDefault();
      ev.returnValue = "";
    }
  };

  private onWindowKeyDown = (ev: KeyboardEvent): void => {
    if (ev.defaultPrevented) return;
    const mod = ev.metaKey || ev.ctrlKey;
    if (!mod) {
      if (ev.key === "Escape") {
        this.closeBufferModal();
        this.closeDialog();
        this.toggleFindBar(false);
        this.closeHistoryDrawer();
      }
      return;
    }
    const key = ev.key.toLowerCase();
    if (key === "p") {
      ev.preventDefault();
      this.openBufferModal();
    } else if (key === "e" && !ev.shiftKey) {
      const targetId = this.stream.getActiveBlockId() ?? this.stream.getBlocks()[0]?.id ?? null;
      if (targetId && this.stream.toggleBlockSourcePreview(targetId)) {
        ev.preventDefault();
      }
    } else if (key === "l" && ev.shiftKey) {
      ev.preventDefault();
      const id = this.stream.getActiveBlockId();
      const blk = this.stream.getBlocks().find((b) => b.id === id);
      if (blk && !blk.is_locked) {
        void this.promptLockBlock(blk);
      } else {
        this.openVaultModal();
      }
    } else if (key === "l" && !ev.shiftKey) {
      ev.preventDefault();
      const id = this.stream.getActiveBlockId() ?? this.stream.getBlocks()[0]?.id;
      if (id) this.stream.focusLangSelector(id);
    } else if (key === "f" && ev.shiftKey) {
      ev.preventDefault();
      const id = this.stream.getActiveBlockId();
      const blk = this.stream.getBlocks().find((b) => b.id === id);
      if (blk) void this.formatBlock(blk);
    } else if (key === "c" && ev.shiftKey) {
      ev.preventDefault();
      const id = this.stream.getActiveBlockId();
      const blk = this.stream.getBlocks().find((b) => b.id === id);
      if (blk && this.stream.isBlockEditable(blk.id)) {
        void this.copyBlockContent(this.stream.getBlockDraftContent(blk.id));
      }
    } else if (key === "f" && !ev.shiftKey) {
      ev.preventDefault();
      this.toggleFindBar(true);
    } else if (key === "enter") {
      ev.preventDefault();
      void this.insertBlockAfter(this.stream.getActiveBlockId());
    }
  };

  private showToast(msg: string, isError = false): void {
    this.toastEl.textContent = msg;
    this.toastEl.className = `toast${isError ? " error" : ""}`;
    if (this.toastTimer !== null) window.clearTimeout(this.toastTimer);
    this.toastTimer = window.setTimeout(() => this.toastEl.classList.add("hidden"), 3200);
  }

  private renderBuffers(): void {
    this.bufferTabsEl.innerHTML = "";
    for (const buf of this.buffers) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `buf-tab${buf.id === this.activeBufferId ? " active" : ""}`;
      btn.textContent = buf.name;
      btn.addEventListener("click", () => void this.switchBuffer(buf.id));
      this.bufferTabsEl.appendChild(btn);
    }
  }

  private renderVaultBtn(): void {
    if (this.isVaultUnlocked()) {
      this.vaultBtnEl.className = "btn btn-amber";
      this.vaultBtnEl.textContent = "🔓 Vault: Unlocked";
      this.vaultBtnEl.title = "Vault unlocked in browser WASM RAM — click to lock or change passphrase";
    } else if (this.vaultHeader) {
      this.vaultBtnEl.className = "btn";
      this.vaultBtnEl.textContent = "🔒 Vault: Locked";
      this.vaultBtnEl.title = "Unlock Tier 2 Vault in browser WASM RAM";
    } else {
      this.vaultBtnEl.className = "btn";
      this.vaultBtnEl.textContent = "Setup Vault";
      this.vaultBtnEl.title = "Initialize Tier 2 Vault passphrase";
    }
  }

  private renderSyncPill(): void {
    const label = this.syncPillEl.querySelector(".sync-label")!;
    if (!this.wsConnected) {
      this.syncPillEl.dataset.state = "pending_offline";
      label.textContent = this.alerts.has("AUTH_REQUIRED") ? "Session Expired" : "Daemon Disconnected";
      return;
    }
    const state: SyncStateLabel = this.syncStatus?.sync_state ?? "unconfigured";
    const pending = this.syncStatus?.pending_ops ?? 0;
    this.syncPillEl.dataset.state = state;
    switch (state) {
      case "synced":
        label.textContent = "Synced";
        break;
      case "syncing":
        label.textContent = "Syncing…";
        break;
      case "pending_offline":
        label.textContent = pending > 0 ? `Offline (${pending} pending)` : "Offline";
        break;
      case "conflict_present":
        label.textContent = "Conflict";
        break;
      default:
        label.textContent = "Local Only";
    }
  }

  private updateTrashCount(count: number): void {
    this.trashBtnEl.textContent = `Trash (${count})`;
  }

  private updateAlertsFromStatus(status: SyncStatusDto): void {
    if (!status.key_self_check.ok) {
      this.alerts.set("KEY_MISSING", { type: "alert", code: "KEY_MISSING", details: { missing: status.key_self_check.blocks_missing_key } });
    } else {
      this.alerts.delete("KEY_MISSING");
    }
    if (Math.abs(status.clock_skew_ms) > 300_000) {
      this.alerts.set("CLOCK_SKEW", { type: "alert", code: "CLOCK_SKEW", details: { clock_skew_ms: status.clock_skew_ms } });
    } else {
      this.alerts.delete("CLOCK_SKEW");
    }
    if (status.recovery_drill_due) {
      this.alerts.set("RECOVERY_DRILL_DUE", { type: "alert", code: "RECOVERY_DRILL_DUE", details: {} });
    } else {
      this.alerts.delete("RECOVERY_DRILL_DUE");
    }
    if (status.trash.pending_confirm_count > 0) {
      this.alerts.set("SHRED_PENDING_CONFIRM", {
        type: "alert",
        code: "SHRED_PENDING_CONFIRM",
        details: { pending_confirm_count: status.trash.pending_confirm_count },
      });
    } else {
      this.alerts.delete("SHRED_PENDING_CONFIRM");
    }
    if (status.blocked_ops > 0) {
      this.alerts.set("NEEDS_VAULT_REKEY", {
        type: "alert",
        code: "NEEDS_VAULT_REKEY",
        details: { blocked_ops: status.blocked_ops },
      });
    } else {
      this.alerts.delete("NEEDS_VAULT_REKEY");
    }
    this.renderAlerts();
  }

  private renderAlerts(): void {
    this.alertStackEl.innerHTML = "";
    if (this.secretNudge) {
      const nudge = this.secretNudge;
      const div = document.createElement("div");
      div.className = "alert-banner";
      div.dataset.code = "SECRET_PASTE_NUDGE";
      div.dataset.severity = "warn";
      const text = document.createElement("span");
      text.textContent = `Possible secret (${nudge.secretType}) pasted into Tier 1 block — consider encrypting it in Tier 2 Vault.`;
      const actions = document.createElement("div");
      actions.className = "block-header-right";
      const lockBtn = document.createElement("button");
      lockBtn.type = "button";
      lockBtn.className = "btn btn-amber btn-icon";
      lockBtn.textContent = "🔒 Lock Block";
      lockBtn.addEventListener("click", () => {
        const blk = this.stream.getBlocks().find((b) => b.id === nudge.blockId);
        this.secretNudge = null;
        this.renderAlerts();
        if (blk && !blk.is_locked) void this.promptLockBlock(blk);
      });
      const dismissBtn = document.createElement("button");
      dismissBtn.type = "button";
      dismissBtn.className = "btn btn-icon";
      dismissBtn.textContent = "Dismiss";
      dismissBtn.addEventListener("click", () => {
        this.secretNudge = null;
        this.renderAlerts();
      });
      actions.append(lockBtn, dismissBtn);
      div.append(text, actions);
      this.alertStackEl.appendChild(div);
    }

    for (const alert of this.alerts.values()) {
      const div = document.createElement("div");
      div.className = "alert-banner";
      div.dataset.code = alert.code;
      div.dataset.severity =
        alert.code === "KEY_MISSING" || alert.code === "AUTH_REQUIRED" || alert.code === "DEVICE_REVOKED"
          ? "error"
          : "warn";
      const text = document.createElement("span");
      if (alert.code === "KEY_MISSING") {
        text.textContent = "KEY_MISSING: Active block missing encryption key — run 'mynote sync pull' and do not delete data.";
      } else if (alert.code === "AUTH_REQUIRED") {
        text.textContent = "AUTH_REQUIRED: Local daemon session expired — run 'mynote open' to obtain a fresh login ticket.";
      } else if (alert.code === "DEVICE_REVOKED") {
        text.textContent = "DEVICE_REVOKED: This device token was revoked on the relay — re-pair or re-bootstrap before syncing.";
      } else if (alert.code === "CLOCK_SKEW") {
        text.textContent = `CLOCK_SKEW: Remote clock skew detected (${JSON.stringify(alert.details)}). All versions preserved safely.`;
      } else if (alert.code === "RECOVERY_DRILL_DUE") {
        text.textContent = "RECOVERY_DRILL_DUE: Keyring rotated — run 'mynote recovery drill' to verify your 24-word bundle.";
      } else if (alert.code === "SHRED_PENDING_CONFIRM") {
        text.textContent =
          "SHRED_PENDING_CONFIRM: Batch/high-volume shred marks require explicit desktop UI confirmation before countdown starts.";
      } else if (alert.code === "NEEDS_VAULT_REKEY") {
        text.textContent =
          "NEEDS_VAULT_REKEY: Offline Tier 2 edit(s) referenced a key pending shred — unlock Vault to re-encrypt under a fresh key automatically.";
      } else {
        text.textContent = `${alert.code}: ${JSON.stringify(alert.details)}`;
      }
      div.appendChild(text);

      if (alert.code === "SHRED_PENDING_CONFIRM") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-amber btn-icon";
        btn.textContent = "Review Trash";
        btn.addEventListener("click", () => {
          if (!this.trashOpen) void this.toggleTrash();
          else void this.refreshTrash();
        });
        div.appendChild(btn);
      } else if (alert.code === "NEEDS_VAULT_REKEY") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-primary btn-icon";
        btn.textContent = "Unlock Vault to Rekey";
        btn.addEventListener("click", () => this.openVaultModal());
        div.appendChild(btn);
      }
      this.alertStackEl.appendChild(div);
    }
  }

  private async resyncAfterReconnect(): Promise<void> {
    try {
      const boot = await this.api.bootstrap();
      this.buffers = boot.buffers;
      this.syncStatus = boot.sync_status;
      this.vaultHeader = boot.vault_header ?? this.vaultHeader;
      this.recoveryPkB64 = boot.recovery_pk_b64 ?? this.recoveryPkB64;
      this.alerts.delete("AUTH_REQUIRED");
      this.updateAlertsFromStatus(boot.sync_status);
      this.updateTrashCount(boot.trash_count);
      if (this.activeBufferId && this.buffers.some((b) => b.id === this.activeBufferId)) {
        const blocks = await this.api.listBlocks(this.activeBufferId);
        this.stream.upsertBlocks(
          blocks,
          this.stream
            .getBlocks()
            .filter((b) => !blocks.some((n) => n.id === b.id))
            .map((b) => b.id),
          this.activeBufferId,
        );
      } else {
        this.activeBufferId = boot.initial_buffer_id ?? boot.buffers[0]?.id ?? null;
        this.stream.setBlocks(boot.blocks);
      }
      this.decryptVisibleLockedBlocks();
      this.renderBuffers();
      this.renderVaultBtn();
      this.renderSyncPill();
    } catch {
      // keep existing UI state until next reconnect
    }
  }

  private handleWsFrame(frame: LocalWsFrame): void {
    if (frame.type === "blocks_changed") {
      this.stream.upsertBlocks(frame.upserted, frame.deleted_ids, this.activeBufferId);
      if (this.isVaultUnlocked()) {
        this.decryptVisibleLockedBlocks();
      }
      if (this.historyOpen && this.historyBlockId) {
        if (frame.deleted_ids.includes(this.historyBlockId)) {
          this.closeHistoryDrawer();
        } else if (frame.upserted.some((b) => b.id === this.historyBlockId)) {
          this.renderHistoryDrawer();
        }
      }
    } else if (frame.type === "buffers_changed") {
      const del = new Set(frame.deleted_ids);
      let next = this.buffers.filter((b) => !del.has(b.id));
      for (const u of frame.upserted) {
        const idx = next.findIndex((b) => b.id === u.id);
        if (idx >= 0) next[idx] = u;
        else next.push(u);
      }
      next.sort((a, b) => (a.position < b.position ? -1 : a.position > b.position ? 1 : a.id < b.id ? -1 : 1));
      this.buffers = next;
      if (this.activeBufferId && del.has(this.activeBufferId)) {
        const fallback = next[0]?.id ?? null;
        if (fallback) {
          void this.switchBuffer(fallback);
        } else {
          this.activeBufferId = null;
          this.stream.setBlocks([]);
        }
      }
      this.renderBuffers();
    } else if (frame.type === "trash_changed") {
      this.updateTrashCount(frame.count);
      if (frame.pending_confirm_count > 0) {
        this.alerts.set("SHRED_PENDING_CONFIRM", {
          type: "alert",
          code: "SHRED_PENDING_CONFIRM",
          details: { pending_confirm_count: frame.pending_confirm_count },
        });
      } else {
        this.alerts.delete("SHRED_PENDING_CONFIRM");
      }
      this.renderAlerts();
      if (this.trashOpen) void this.refreshTrash();
    } else if (frame.type === "sync_status") {
      if (this.syncStatus) {
        this.syncStatus.sync_state = frame.state;
        this.syncStatus.last_seq = frame.last_seq;
        if (frame.pending_ops !== undefined) this.syncStatus.pending_ops = frame.pending_ops;
      }
      this.renderSyncPill();
    } else if (frame.type === "vault_header_changed") {
      this.vaultHeader = frame.vault_header;
      this.renderVaultBtn();
    } else if (frame.type === "alert") {
      this.alerts.set(frame.code, frame);
      this.renderAlerts();
      if (frame.code === "NEEDS_VAULT_REKEY" && this.isVaultUnlocked()) {
        void this.rescueBlockedTier2Ops();
      }
    }
  }

  private async switchBuffer(bufferId: string): Promise<void> {
    const reqSeq = ++this.switchSeq;
    await this.stream.flushAllDirty();
    if (reqSeq !== this.switchSeq) return;
    try {
      const blocks = await this.api.listBlocks(bufferId);
      if (reqSeq !== this.switchSeq) return;
      this.activeBufferId = bufferId;
      this.closeHistoryDrawer();
      this.renderBuffers();
      this.stream.setBlocks(blocks);
      if (this.isVaultUnlocked()) {
        this.decryptVisibleLockedBlocks();
      }
    } catch (e) {
      this.handleErr(e);
    }
  }

  private async insertBlockAfter(afterId: string | null): Promise<void> {
    if (!this.activeBufferId) return;
    try {
      const created = await this.api.createBlock({
        buffer_id: this.activeBufferId,
        lang: "text",
        content: "",
        after_id: afterId,
        fast_sync: true,
      });
      this.stream.upsertBlocks([created], [], this.activeBufferId);
      this.stream.focusBlock(created.id, 0);
    } catch (e) {
      this.handleErr(e);
    }
  }

  private decryptVisibleLockedBlocks(): void {
    const session = this.vaultSession;
    if (!session || session.isLocked() || isPageHidden()) return;
    const lockEpoch = this.stream.getVaultLockEpoch();
    for (const blk of this.stream.getBlocks()) {
      if (!blk.is_locked) continue;
      const leafMap = new Map<string, string>();
      let displayPlain: string | null = null;
      const pendingTier1Leaves: { opId: string; isDisplay: boolean }[] = [];
      for (const v of blk.versions) {
        if (v.content !== null) {
          leafMap.set(v.op_id, v.content);
          if (v.is_display) displayPlain = v.content;
        } else if (v.is_locked && v.key_id && v.mnb1_b64 && v.mnw1_b64) {
          try {
            const dec = session.decryptBlock(
              blk.id,
              v.op_id,
              v.key_id,
              b64ToBytes(v.mnb1_b64),
              b64ToBytes(v.mnw1_b64),
            );
            const text = dec.content;
            dec.free();
            leafMap.set(v.op_id, text);
            if (v.is_display || displayPlain === null) displayPlain = text;
          } catch {
            // leave unreadable leaf absent from leafMap
          }
        } else if (!v.is_locked && v.content === null && this.api.getTier1LeafPlaintext) {
          // H17: Concurrent Tier 1 leaf on a locked block is redacted by default; fetch on demand ONLY while Vault is unlocked.
          pendingTier1Leaves.push({ opId: v.op_id, isDisplay: v.is_display });
        }
      }
      if (displayPlain !== null) {
        this.stream.setUnlockedPlaintext(blk.id, displayPlain, leafMap);
      }
      for (const item of pendingTier1Leaves) {
        void this.api
          .getTier1LeafPlaintext!(blk.id, item.opId)
          .then((res) => {
            if (!this.isVaultUnlocked() || isPageHidden() || this.stream.getVaultLockEpoch() !== lockEpoch) {
              return;
            }
            this.stream.setUnlockedLeafPlaintext(blk.id, item.opId, res.content);
            if (item.isDisplay && displayPlain === null) {
              this.stream.setUnlockedPlaintext(blk.id, res.content);
            }
          })
          .catch(() => {
            // keep leaf unavailable if daemon cannot decrypt
          });
      }
    }
  }

  private async onVaultUnlocked(): Promise<void> {
    if (!this.isVaultUnlocked() || isPageHidden()) return;
    this.renderVaultBtn();
    this.resetVaultIdleTimer();
    this.decryptVisibleLockedBlocks();
    await this.rescueBlockedTier2Ops();
    if (!this.isVaultUnlocked() || isPageHidden()) return;
    const pending = this.pendingAfterUnlock;
    this.pendingAfterUnlock = null;
    if (pending) {
      await pending();
    }
  }

  private async rescueBlockedTier2Ops(): Promise<void> {
    if (!this.isVaultUnlocked() || !this.api.listBlockedOps || !this.api.rekeyBlockedOp) return;
    const lockEpoch = this.stream.getVaultLockEpoch();
    try {
      const blocked = await this.api.listBlockedOps();
      if (blocked.length === 0) {
        this.alerts.delete("NEEDS_VAULT_REKEY");
        this.renderAlerts();
        return;
      }
      let rescued = 0;
      let failed = 0;
      for (const op of blocked) {
        const session = this.vaultSession;
        if (!session || session.isLocked() || isPageHidden() || this.stream.getVaultLockEpoch() !== lockEpoch) {
          break;
        }
        if (!op.mnw1_b64) {
          failed++;
          continue;
        }
        try {
          const dec = session.decryptBlock(
            op.block_id,
            op.op_id,
            op.old_key_id,
            b64ToBytes(op.mnb1_b64),
            b64ToBytes(op.mnw1_b64),
          );
          const plaintext = dec.content;
          dec.free();
          const enc = session.rekeyToVault(JSON.stringify({ block_id: op.block_id }), plaintext, op.lang);
          const payload: Tier2WritePayload = {
            op_id: enc.opId,
            key_id: enc.keyId,
            mnb1_b64: bytesToB64(enc.mnb1),
            mnw1_b64: enc.mnw1 ? bytesToB64(enc.mnw1) : undefined,
          };
          enc.free();
          const updated = await this.api.rekeyBlockedOp(op.op_id, payload);
          rescued++;
          if (
            updated.buffer_id === this.activeBufferId &&
            this.isVaultUnlocked() &&
            !isPageHidden() &&
            this.stream.getVaultLockEpoch() === lockEpoch
          ) {
            this.stream.applyAuthoritativeBlock(updated, this.activeBufferId, plaintext);
          }
        } catch (opErr) {
          failed++;
          this.handleErr(opErr);
        }
      }
      if (rescued === blocked.length && failed === 0) {
        this.alerts.delete("NEEDS_VAULT_REKEY");
        this.renderAlerts();
        this.showToast(`Rescued ${rescued} blocked Tier 2 op(s) with fresh keys`);
      } else if (rescued > 0) {
        this.showToast(`Rescued ${rescued}/${blocked.length} blocked Tier 2 op(s); ${blocked.length - rescued} still pending`, true);
      }
    } catch (e) {
      this.handleErr(e);
    }
  }

  private findTier2KeyMaterial(block: BlockDto): { keyId: string; mnw1B64: string } | null {
    const preferred = block.versions.find((v) => v.is_display && v.key_id && v.mnw1_b64);
    if (preferred?.key_id && preferred.mnw1_b64) {
      return { keyId: preferred.key_id, mnw1B64: preferred.mnw1_b64 };
    }
    const any = block.versions.find((v) => v.key_id && v.mnw1_b64);
    if (any?.key_id && any.mnw1_b64) {
      return { keyId: any.key_id, mnw1B64: any.mnw1_b64 };
    }
    return null;
  }

  private async saveBlockContent(
    block: BlockDto,
    content: string,
    expectedHeads: string[],
    opts: { fastSync: boolean; isMerge: boolean; keepalive?: boolean },
  ): Promise<SaveContentResult> {
    const lockEpoch = this.stream.getVaultLockEpoch();
    try {
      let patchPromise: Promise<BlockDto>;
      if (block.is_locked) {
        const session = this.vaultSession;
        if (!session || session.isLocked()) {
          this.showToast("Vault is locked — unlock Vault to save Tier 2 changes", true);
          return { status: "error" };
        }
        const mat = this.findTier2KeyMaterial(block);
        if (!mat) {
          this.showToast("Missing MNW1 key material for Tier 2 block", true);
          return { status: "error" };
        }
        // Encrypt synchronously BEFORE awaiting fetch so visibilitychange keepalive flush completes cleanly before lockVaultNow!
        const enc = session.encryptUpdate(
          JSON.stringify({ block_id: block.id }),
          mat.keyId,
          b64ToBytes(mat.mnw1B64),
          content,
          block.lang,
        );
        const op_id = enc.opId;
        const key_id = enc.keyId;
        const mnb1_b64 = bytesToB64(enc.mnb1);
        enc.free();
        this.resetVaultIdleTimer();
        patchPromise = this.api.patchBlock(
          block.id,
          {
            expected_heads: expectedHeads,
            op_id,
            key_id,
            mnb1_b64,
            fast_sync: opts.fastSync,
          },
          { keepalive: opts.keepalive },
        );
      } else {
        patchPromise = this.api.patchBlock(
          block.id,
          {
            expected_heads: expectedHeads,
            content,
            fast_sync: opts.fastSync,
          },
          { keepalive: opts.keepalive },
        );
      }
      const updated = await patchPromise;
      if (
        updated.is_locked &&
        this.isVaultUnlocked() &&
        !isPageHidden() &&
        this.stream.getVaultLockEpoch() === lockEpoch
      ) {
        this.stream.setUnlockedPlaintext(updated.id, content);
      }
      if (opts.isMerge) this.showToast("Merged versions cleanly");
      return { status: "ok", updated };
    } catch (e) {
      if (e instanceof LocalApiError && e.body.code === "HEAD_MISMATCH") {
        this.showToast("Concurrent update detected — your draft is preserved; choose Save Over or Reload", true);
        if (this.activeBufferId) {
          try {
            const latest = await this.api.listBlocks(this.activeBufferId);
            this.stream.upsertBlocks(latest, [], this.activeBufferId);
            if (this.isVaultUnlocked() && !isPageHidden()) this.decryptVisibleLockedBlocks();
          } catch {
            // ignore refresh failure; mismatch banner still protects draft
          }
        }
        return { status: "head_mismatch" };
      }
      this.handleErr(e);
      return { status: "error" };
    }
  }

  private async changeBlockLang(block: BlockDto, lang: string): Promise<void> {
    try {
      const updated = await this.api.patchBlock(block.id, { lang });
      this.stream.upsertBlocks([updated], [], this.activeBufferId);
    } catch (e) {
      this.handleErr(e);
    }
  }

  private async formatBlock(block: BlockDto): Promise<void> {
    await this.stream.waitForSaveIdle(block.id);
    const cur = this.stream.getBlocks().find((b) => b.id === block.id) ?? block;
    if (!this.stream.isBlockEditable(cur.id)) {
      this.showToast(
        cur.is_locked ? "Unlock Vault to format this Tier 2 block in browser WASM" : "Cannot format an unreadable block",
        true,
      );
      return;
    }
    if (cur.has_conflict) {
      this.showToast("Resolve concurrent versions before formatting", true);
      return;
    }
    try {
      const content = this.stream.getBlockDraftContent(cur.id);
      const expectedHeads = this.stream.getExpectedHeadsForBlock(cur.id);
      if (cur.is_locked) {
        // SEC-03 HARD INVARIANT: Unlocked Tier 2 blocks MUST format strictly in browser WASM (ZERO /v1/local/format HTTP calls!)
        const session = this.vaultSession;
        const lockEpoch = this.stream.getVaultLockEpoch();
        if (!session || session.isLocked()) {
          this.showToast("Vault is locked", true);
          return;
        }
        const mat = this.findTier2KeyMaterial(cur);
        if (!mat) {
          this.showToast("Missing MNW1 key material for Tier 2 block", true);
          return;
        }
        const formatted = await formatSnippetWasm(content, cur.lang);
        if (
          !this.isVaultUnlocked() ||
          this.vaultSession !== session ||
          isPageHidden() ||
          this.stream.getVaultLockEpoch() !== lockEpoch
        ) {
          return;
        }
        const enc = session.encryptUpdate(
          JSON.stringify({ block_id: cur.id }),
          mat.keyId,
          b64ToBytes(mat.mnw1B64),
          formatted,
          cur.lang,
        );
        const op_id = enc.opId;
        const key_id = enc.keyId;
        const mnb1_b64 = bytesToB64(enc.mnb1);
        enc.free();
        this.resetVaultIdleTimer();
        const updated = await this.api.patchBlock(cur.id, {
          expected_heads: expectedHeads,
          op_id,
          key_id,
          mnb1_b64,
          fast_sync: true,
        });
        const keepUnlocked =
          this.isVaultUnlocked() && !isPageHidden() && this.stream.getVaultLockEpoch() === lockEpoch;
        this.stream.applyAuthoritativeBlock(updated, this.activeBufferId, keepUnlocked ? formatted : undefined);
        this.showToast(`Formatted (${cur.lang}) in WASM`);
        return;
      }

      const { formatted } = await this.api.formatSnippet({ content, lang: cur.lang, block_id: cur.id });
      const updated = await this.api.patchBlock(cur.id, {
        expected_heads: expectedHeads,
        content: formatted,
        fast_sync: true,
      });
      this.stream.applyAuthoritativeBlock(updated, this.activeBufferId);
      this.showToast(`Formatted (${cur.lang})`);
    } catch (e) {
      this.handleErr(e);
    }
  }

  private async copyBlockContent(content: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(content);
      this.showToast("Copied block to clipboard");
    } catch {
      this.showToast("Clipboard permission unavailable", true);
    }
  }

  private async copyBlockRich(block: BlockDto, html: string, text: string): Promise<void> {
    const ok = await copyDualFormat(html, text);
    if (ok) {
      if (block.is_locked) this.resetVaultIdleTimer();
      this.showToast("Copied rich HTML + plain text");
    } else {
      this.showToast("Clipboard permission unavailable", true);
    }
  }

  private async moveBlock(block: BlockDto, dir: -1 | 1): Promise<void> {
    const list = this.stream.getBlocks();
    const idx = list.findIndex((b) => b.id === block.id);
    const neighbor = list[idx + dir];
    if (!neighbor) return;
    try {
      const updated = await this.api.patchBlock(block.id, dir === -1 ? { before_id: neighbor.id } : { after_id: neighbor.id });
      this.stream.upsertBlocks([updated], [], this.activeBufferId);
    } catch (e) {
      this.handleErr(e);
    }
  }

  private async deleteBlock(block: BlockDto): Promise<void> {
    try {
      await this.stream.waitForSaveIdle(block.id);
      const cur = this.stream.getBlocks().find((b) => b.id === block.id) ?? block;
      await this.api.deleteBlock(cur.id, cur.head_op_ids);
      if (this.historyOpen && this.historyBlockId === cur.id) {
        this.closeHistoryDrawer();
      }
      this.stream.upsertBlocks([], [cur.id], this.activeBufferId);
      this.showToast("Moved block to Recycle Bin");
      await this.refreshTrash();
    } catch (e) {
      this.handleErr(e);
    }
  }

  private async keepVersion(block: BlockDto, opId: string): Promise<void> {
    try {
      if (block.is_locked) {
        const session = this.vaultSession;
        const lockEpoch = this.stream.getVaultLockEpoch();
        if (!session || session.isLocked()) {
          this.openVaultModal();
          return;
        }
        const chosen =
          this.stream.getUnlockedLeafContent(block.id, opId) ??
          block.versions.find((v) => v.op_id === opId)?.content ??
          null;
        if (chosen === null) {
          this.showToast("Selected version cannot be decrypted", true);
          return;
        }
        const mat = this.findTier2KeyMaterial(block);
        let payload: { op_id: string; key_id: string; mnb1_b64: string; mnw1_b64?: string };
        if (mat) {
          const enc = session.encryptUpdate(
            JSON.stringify({ block_id: block.id }),
            mat.keyId,
            b64ToBytes(mat.mnw1B64),
            chosen,
            block.lang,
          );
          payload = { op_id: enc.opId, key_id: enc.keyId, mnb1_b64: bytesToB64(enc.mnb1) };
          enc.free();
        } else {
          const enc = session.rekeyToVault(JSON.stringify({ block_id: block.id }), chosen, block.lang);
          payload = {
            op_id: enc.opId,
            key_id: enc.keyId,
            mnb1_b64: bytesToB64(enc.mnb1),
            mnw1_b64: enc.mnw1 ? bytesToB64(enc.mnw1) : undefined,
          };
          enc.free();
        }
        const updated = await this.api.resolveBlock(block.id, {
          expected_heads: block.head_op_ids,
          ...payload,
        });
        const keepUnlocked =
          this.isVaultUnlocked() && !isPageHidden() && this.stream.getVaultLockEpoch() === lockEpoch;
        this.stream.applyAuthoritativeBlock(updated, this.activeBufferId, keepUnlocked ? chosen : undefined);
        this.showToast("Tier 2 conflict resolved");
        return;
      }

      const updated = await this.api.resolveBlock(block.id, {
        expected_heads: block.head_op_ids,
        keep_op_id: opId,
      });
      this.stream.applyAuthoritativeBlock(updated, this.activeBufferId);
      this.showToast("Conflict resolved to selected version");
    } catch (e) {
      this.handleErr(e);
    }
  }

  // ---------- M2 Tier 2 Vault Modals & Block Lock/Unlock ----------

  private closeDialog(clearPending = true): void {
    for (const el of this.dialogModalEl.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input, textarea")) {
      el.value = "";
    }
    this.dialogBackdropEl.classList.add("hidden");
    this.dialogModalEl.innerHTML = "";
    if (clearPending) {
      this.pendingAfterUnlock = null;
    }
  }

  private openVaultModal(forceMode?: "init" | "unlock" | "recover" | "unlocked"): void {
    const mode = forceMode ?? (this.isVaultUnlocked() ? "unlocked" : this.vaultHeader ? "unlock" : "init");
    this.dialogModalEl.innerHTML = "";

    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "btn btn-icon";
    closeBtn.textContent = "✕";
    closeBtn.addEventListener("click", () => this.closeDialog());
    hdr.append(title, closeBtn);
    this.dialogModalEl.appendChild(hdr);

    const form = document.createElement("form");
    form.className = "dialog-form";

    if (mode === "init") {
      title.textContent = "Initialize Tier 2 Vault";
      const note = document.createElement("p");
      note.className = "dialog-note";
      note.textContent =
        "Set a Vault passphrase. Your VKEK is wrapped by both Argon2id(passphrase) and your 24-word recovery public key, and stays strictly in browser WASM RAM while unlocked.";
      const p1 = document.createElement("input");
      p1.type = "password";
      p1.className = "input";
      p1.placeholder = "New Vault passphrase (min 8 chars)";
      p1.dataset.testid = "vault-passphrase-input";
      p1.autocomplete = "new-password";
      const p2 = document.createElement("input");
      p2.type = "password";
      p2.className = "input";
      p2.placeholder = "Confirm Vault passphrase";
      p2.dataset.testid = "vault-passphrase-confirm";
      p2.autocomplete = "new-password";
      const submit = document.createElement("button");
      submit.type = "submit";
      submit.className = "btn btn-primary";
      submit.textContent = "Initialize & Unlock Vault";
      submit.dataset.testid = "vault-submit-btn";
      form.append(note, p1, p2, submit);
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        void (async () => {
          const pass = p1.value;
          const confirm = p2.value;
          if (pass.length < 8) {
            this.showToast("Passphrase must be at least 8 characters", true);
            return;
          }
          if (pass !== confirm) {
            this.showToast("Passphrases do not match", true);
            return;
          }
          if (!this.recoveryPkB64 || !this.api.putVaultHeader) {
            this.showToast("Recovery public key unavailable from local daemon", true);
            return;
          }
          p1.value = "";
          p2.value = "";
          submit.disabled = true;
          submit.textContent = "Deriving Argon2id key…";
          try {
            const { gen, blob_b64 } = await createVaultHeaderWasm(pass, this.recoveryPkB64);
            const saved = await this.api.putVaultHeader(gen, blob_b64);
            this.vaultHeader = saved;
            if (isPageHidden()) {
              this.closeDialog();
              this.renderVaultBtn();
              return;
            }
            const sess = await unlockVaultWithPassphraseWasm(pass, saved.blob_b64);
            if (isPageHidden()) {
              sess.lockAndZeroize();
              sess.free();
              this.closeDialog();
              this.renderVaultBtn();
              return;
            }
            this.vaultSession = sess;
            this.closeDialog(false);
            await this.onVaultUnlocked();
            this.showToast("Vault initialized and unlocked in RAM");
          } catch (e) {
            this.handleErr(e);
            submit.disabled = false;
            submit.textContent = "Initialize & Unlock Vault";
          }
        })();
      });
      this.dialogModalEl.appendChild(form);
      this.dialogBackdropEl.classList.remove("hidden");
      p1.focus();
      return;
    }

    if (mode === "unlock") {
      title.textContent = "Unlock Tier 2 Vault";
      const note = document.createElement("p");
      note.className = "dialog-note";
      note.textContent = "VKEK is decrypted in browser WASM RAM only and auto-zeroizes on tab switch or 5 min idle.";
      const p1 = document.createElement("input");
      p1.type = "password";
      p1.className = "input";
      p1.placeholder = "Vault passphrase";
      p1.dataset.testid = "vault-passphrase-input";
      p1.autocomplete = "current-password";
      const row = document.createElement("div");
      row.className = "dialog-actions";
      const submit = document.createElement("button");
      submit.type = "submit";
      submit.className = "btn btn-primary";
      submit.textContent = "Unlock Vault";
      submit.dataset.testid = "vault-submit-btn";
      const recoverBtn = document.createElement("button");
      recoverBtn.type = "button";
      recoverBtn.className = "btn";
      recoverBtn.textContent = "Forgot? Use 24 Words";
      recoverBtn.addEventListener("click", () => this.openVaultModal("recover"));
      row.append(recoverBtn, submit);
      form.append(note, p1, row);
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        void (async () => {
          if (!this.vaultHeader) return;
          const pass = p1.value;
          p1.value = "";
          submit.disabled = true;
          submit.textContent = "Unlocking…";
          try {
            const sess = await unlockVaultWithPassphraseWasm(pass, this.vaultHeader.blob_b64);
            // H18 / SEC-03: If tab hid during Argon2id derivation, zeroize immediately and do NOT install session!
            if (isPageHidden()) {
              sess.lockAndZeroize();
              sess.free();
              this.closeDialog();
              return;
            }
            this.vaultSession = sess;
            this.closeDialog(false);
            await this.onVaultUnlocked();
            this.showToast("Vault unlocked in browser WASM RAM");
          } catch (e) {
            const parsed = parseWasmError(e);
            this.showToast(`${parsed.code}: ${parsed.message}`, true);
            submit.disabled = false;
            submit.textContent = "Unlock Vault";
          }
        })();
      });
      this.dialogModalEl.appendChild(form);
      this.dialogBackdropEl.classList.remove("hidden");
      p1.focus();
      return;
    }

    if (mode === "recover") {
      title.textContent = "Recover Vault with 24-Word Bundle";
      const note = document.createElement("p");
      note.className = "dialog-note";
      note.textContent = "Enter your 24 recovery words to unseal VKEK locally and optionally set a new Vault passphrase.";
      const words = document.createElement("textarea");
      words.className = "input";
      words.rows = 3;
      words.placeholder = "24 BIP39 recovery words separated by spaces…";
      const newPass = document.createElement("input");
      newPass.type = "password";
      newPass.className = "input";
      newPass.placeholder = "Optional new Vault passphrase (min 8 chars)";
      const row = document.createElement("div");
      row.className = "dialog-actions";
      const backBtn = document.createElement("button");
      backBtn.type = "button";
      backBtn.className = "btn";
      backBtn.textContent = "Back";
      backBtn.addEventListener("click", () => this.openVaultModal("unlock"));
      const submit = document.createElement("button");
      submit.type = "submit";
      submit.className = "btn btn-primary";
      submit.textContent = "Recover & Unlock";
      row.append(backBtn, submit);
      form.append(note, words, newPass, row);
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        void (async () => {
          if (!this.vaultHeader) return;
          const wordsText = words.value.trim();
          const nextPass = newPass.value;
          words.value = "";
          newPass.value = "";
          submit.disabled = true;
          try {
            const sess = await unlockVaultWithRecoveryWordsWasm(wordsText, this.vaultHeader.blob_b64);
            if (isPageHidden()) {
              sess.lockAndZeroize();
              sess.free();
              this.closeDialog();
              return;
            }
            if (nextPass.length > 0) {
              if (nextPass.length < 8) {
                sess.lockAndZeroize();
                sess.free();
                this.showToast("New passphrase must be at least 8 characters", true);
                submit.disabled = false;
                return;
              }
              if (this.api.putVaultHeader) {
                const updatedRaw = sess.changePassphrase(b64ToBytes(this.vaultHeader.blob_b64), nextPass);
                const parsed = JSON.parse(updatedRaw) as { gen: number; blob_b64: string };
                this.vaultHeader = await this.api.putVaultHeader(parsed.gen, parsed.blob_b64);
              }
            }
            if (isPageHidden()) {
              sess.lockAndZeroize();
              sess.free();
              this.closeDialog();
              return;
            }
            this.vaultSession = sess;
            this.closeDialog(false);
            await this.onVaultUnlocked();
            this.showToast("Vault recovered and unlocked");
          } catch (e) {
            const parsed = parseWasmError(e);
            this.showToast(`${parsed.code}: ${parsed.message}`, true);
            submit.disabled = false;
          }
        })();
      });
      this.dialogModalEl.appendChild(form);
      this.dialogBackdropEl.classList.remove("hidden");
      words.focus();
      return;
    }

    // mode === "unlocked"
    title.textContent = "Tier 2 Vault (Unlocked in RAM)";
    const note = document.createElement("p");
    note.className = "dialog-note";
    note.textContent =
      "Unlocked in browser WASM RAM only. Local daemon never sees VKEK or Tier 2 plaintext. Auto-locks on tab switch or 5 min idle.";
    const lockBtn = document.createElement("button");
    lockBtn.type = "button";
    lockBtn.className = "btn btn-danger";
    lockBtn.dataset.testid = "vault-lock-now-btn";
    lockBtn.textContent = "🔒 Lock Vault Now (Zeroize RAM)";
    lockBtn.addEventListener("click", () => {
      this.closeDialog();
      this.lockVaultNow();
    });

    const sep = document.createElement("hr");
    sep.className = "dialog-sep";
    const sub = document.createElement("div");
    sub.className = "dialog-subtitle";
    sub.textContent = "Change Vault Passphrase";
    const np1 = document.createElement("input");
    np1.type = "password";
    np1.className = "input";
    np1.placeholder = "New passphrase (min 8 chars)";
    const np2 = document.createElement("input");
    np2.type = "password";
    np2.className = "input";
    np2.placeholder = "Confirm new passphrase";
    const chgBtn = document.createElement("button");
    chgBtn.type = "submit";
    chgBtn.className = "btn btn-primary";
    chgBtn.textContent = "Update Passphrase";
    form.append(note, lockBtn, sep, sub, np1, np2, chgBtn);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void (async () => {
        if (!this.isVaultUnlocked() || !this.vaultSession || !this.vaultHeader || !this.api.putVaultHeader) return;
        const p1 = np1.value;
        const p2 = np2.value;
        if (p1.length < 8) {
          this.showToast("New passphrase must be at least 8 characters", true);
          return;
        }
        if (p1 !== p2) {
          this.showToast("Passphrases do not match", true);
          return;
        }
        np1.value = "";
        np2.value = "";
        chgBtn.disabled = true;
        try {
          const raw = this.vaultSession.changePassphrase(b64ToBytes(this.vaultHeader.blob_b64), p1);
          const parsed = JSON.parse(raw) as { gen: number; blob_b64: string };
          this.vaultHeader = await this.api.putVaultHeader(parsed.gen, parsed.blob_b64);
          this.closeDialog();
          this.showToast("Vault passphrase updated");
        } catch (e) {
          this.handleErr(e);
          chgBtn.disabled = false;
        }
      })();
    });
    this.dialogModalEl.appendChild(form);
    this.dialogBackdropEl.classList.remove("hidden");
  }

  private async promptLockBlock(block: BlockDto): Promise<void> {
    if (!this.isVaultUnlocked()) {
      this.pendingAfterUnlock = () => this.promptLockBlock(block);
      this.openVaultModal();
      return;
    }
    this.dialogModalEl.innerHTML = "";
    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    title.textContent = "Lock Block in Tier 2 Vault";
    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "btn btn-icon";
    closeBtn.textContent = "✕";
    closeBtn.addEventListener("click", () => this.closeDialog());
    hdr.append(title, closeBtn);

    const form = document.createElement("form");
    form.className = "dialog-form";
    const note = document.createElement("p");
    note.className = "dialog-note";
    note.textContent =
      "Content will be re-encrypted inside browser WASM with a new Vault-wrapped key (MNW1). Old Tier 1 key will be scheduled for cryptographic shred (24h min grace).";
    const hintInput = document.createElement("input");
    hintInput.className = "input";
    hintInput.placeholder = "Optional public hint (e.g. 'Prod AWS root') — stored unencrypted in Tier 1 metadata";
    hintInput.dataset.testid = "lock-hint-input";
    const actions = document.createElement("div");
    actions.className = "dialog-actions";
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "btn";
    cancelBtn.textContent = "Cancel";
    cancelBtn.addEventListener("click", () => this.closeDialog());
    const confirmBtn = document.createElement("button");
    confirmBtn.type = "submit";
    confirmBtn.className = "btn btn-primary";
    confirmBtn.textContent = "🔒 Lock Block";
    confirmBtn.dataset.testid = "lock-confirm-btn";
    actions.append(cancelBtn, confirmBtn);
    form.append(note, hintInput, actions);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void (async () => {
        const session = this.vaultSession;
        const lockEpoch = this.stream.getVaultLockEpoch();
        if (!session || session.isLocked() || !this.api.lockBlock) return;
        confirmBtn.disabled = true;
        try {
          await this.stream.waitForSaveIdle(block.id);
          if (
            !this.isVaultUnlocked() ||
            this.vaultSession !== session ||
            isPageHidden() ||
            this.stream.getVaultLockEpoch() !== lockEpoch
          ) {
            this.closeDialog();
            return;
          }
          const cur = this.stream.getBlocks().find((b) => b.id === block.id) ?? block;
          const content = this.stream.getBlockDraftContent(cur.id);
          const expectedHeads = this.stream.getExpectedHeadsForBlock(cur.id);
          const enc = session.rekeyToVault(JSON.stringify({ block_id: cur.id }), content, cur.lang);
          const op_id = enc.opId;
          const key_id = enc.keyId;
          const mnb1_b64 = bytesToB64(enc.mnb1);
          const mnw1_b64 = enc.mnw1 ? bytesToB64(enc.mnw1) : "";
          enc.free();
          const public_hint = hintInput.value.trim() || null;
          const updated = await this.api.lockBlock(cur.id, {
            expected_heads: expectedHeads,
            op_id,
            key_id,
            mnb1_b64,
            mnw1_b64,
            public_hint,
          });
          const keepUnlocked =
            this.isVaultUnlocked() && !isPageHidden() && this.stream.getVaultLockEpoch() === lockEpoch;
          if (keepUnlocked) this.resetVaultIdleTimer();
          this.stream.applyAuthoritativeBlock(updated, this.activeBufferId, keepUnlocked ? content : undefined);
          this.closeDialog();
          this.showToast("Block locked in Tier 2 Vault");
        } catch (e) {
          this.handleErr(e);
          confirmBtn.disabled = false;
        }
      })();
    });
    this.dialogModalEl.append(hdr, form);
    this.dialogBackdropEl.classList.remove("hidden");
    hintInput.focus();
  }

  private async promptUnlockBlockToTier1(block: BlockDto): Promise<void> {
    if (!this.isVaultUnlocked() || !this.stream.isBlockEditable(block.id)) {
      this.openVaultModal();
      return;
    }
    this.dialogModalEl.innerHTML = "";
    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    title.textContent = "Downgrade Block to Tier 1";
    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "btn btn-icon";
    closeBtn.textContent = "✕";
    closeBtn.addEventListener("click", () => this.closeDialog());
    hdr.append(title, closeBtn);

    const form = document.createElement("form");
    form.className = "dialog-form";
    const note = document.createElement("p");
    note.className = "dialog-note";
    note.textContent =
      "Downgrading removes the Tier 2 Vault lock and re-encrypts this block under Tier 1 (accessible to CLI and AI agents on this device).";
    const chkLabel = document.createElement("label");
    chkLabel.className = "dialog-check";
    const chk = document.createElement("input");
    chk.type = "checkbox";
    // Per docs/sync-protocol.md §4.2, default retains old Tier 2 key unless explicitly opted in.
    chk.checked = false;
    const chkText = document.createElement("span");
    chkText.textContent = "Also schedule old Tier 2 key for cryptographic shred (24h min grace)";
    chkLabel.append(chk, chkText);
    const actions = document.createElement("div");
    actions.className = "dialog-actions";
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "btn";
    cancelBtn.textContent = "Cancel";
    cancelBtn.addEventListener("click", () => this.closeDialog());
    const confirmBtn = document.createElement("button");
    confirmBtn.type = "submit";
    confirmBtn.className = "btn btn-amber";
    confirmBtn.textContent = "Downgrade to Tier 1";
    actions.append(cancelBtn, confirmBtn);
    form.append(note, chkLabel, actions);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void (async () => {
        if (!this.api.unlockBlock) return;
        const lockEpoch = this.stream.getVaultLockEpoch();
        confirmBtn.disabled = true;
        try {
          await this.stream.waitForSaveIdle(block.id);
          if (!this.isVaultUnlocked() || isPageHidden() || this.stream.getVaultLockEpoch() !== lockEpoch) {
            this.closeDialog();
            return;
          }
          const cur = this.stream.getBlocks().find((b) => b.id === block.id) ?? block;
          const content = this.stream.getBlockDraftContent(cur.id);
          const expectedHeads = this.stream.getExpectedHeadsForBlock(cur.id);
          const updated = await this.api.unlockBlock(cur.id, {
            expected_heads: expectedHeads,
            content,
            lang: cur.lang,
            shred_old_key: chk.checked,
          });
          this.stream.applyAuthoritativeBlock(updated, this.activeBufferId);
          this.closeDialog();
          this.showToast("Block downgraded to Tier 1");
        } catch (e) {
          this.handleErr(e);
          confirmBtn.disabled = false;
        }
      })();
    });
    this.dialogModalEl.append(hdr, form);
    this.dialogBackdropEl.classList.remove("hidden");
  }

  // ---------- M3 Block History (Time Travel) Drawer ----------

  private hasLockedHistoryOpen(): boolean {
    if (!this.historyOpen) return false;
    if (this.historyBlockLocked || this.historySelectedDto?.is_locked) return true;
    if (this.historyEntries.some((e) => e.is_locked)) return true;
    return this.stream.getBlocks().some((b) => b.id === this.historyBlockId && b.is_locked);
  }

  closeHistoryDrawer(): void {
    this.historyLoadSeq++;
    this.historyOpSeq++;
    this.historyOpen = false;
    this.historyBlockId = null;
    this.historyBlockLocked = false;
    this.historyEntries = [];
    this.historySelectedOpId = null;
    this.historySelectedContent = null;
    this.historySelectedDto = null;
    this.historyLoading = false;
    this.historyOpLoading = false;
    this.historyError = null;
    this.historyDrawerEl.classList.add("hidden");
    this.historyTitleEl.textContent = "Block History";
    this.historyActionsEl.replaceChildren();
    this.historyListEl.replaceChildren();
    this.historyDiffEl.replaceChildren();
  }

  private async openHistoryDrawer(block: BlockDto): Promise<void> {
    if (!this.api.getBlockHistory) {
      this.showToast("Block history API unavailable", true);
      return;
    }
    const cur = this.stream.getBlocks().find((b) => b.id === block.id) ?? block;
    if (cur.is_locked && !this.isVaultUnlocked()) {
      this.pendingAfterUnlock = () => this.openHistoryDrawer(cur);
      this.openVaultModal();
      return;
    }
    if (this.trashOpen) {
      this.trashOpen = false;
      this.trashDrawerEl.classList.add("hidden");
    }

    const reqSeq = ++this.historyLoadSeq;
    const lockEpoch = this.stream.getVaultLockEpoch();
    this.historyOpSeq++;
    this.historyOpen = true;
    this.historyBlockId = cur.id;
    this.historyBlockLocked = cur.is_locked;
    this.historyEntries = [];
    this.historySelectedOpId = null;
    this.historySelectedContent = null;
    this.historySelectedDto = null;
    this.historyLoading = true;
    this.historyOpLoading = false;
    this.historyError = null;
    this.historyDrawerEl.classList.remove("hidden");
    this.renderHistoryDrawer();

    try {
      const entries = await this.api.getBlockHistory(cur.id, 100);
      if (reqSeq !== this.historyLoadSeq || !this.historyOpen || this.historyBlockId !== cur.id) {
        return;
      }
      const hasLockedEntries = cur.is_locked || entries.some((e) => e.is_locked);
      if (hasLockedEntries && cur.is_locked && (!this.isVaultUnlocked() || isPageHidden() || this.stream.getVaultLockEpoch() !== lockEpoch)) {
        this.closeHistoryDrawer();
        return;
      }
      this.historyEntries = entries;
      this.historyLoading = false;
      this.renderHistoryDrawer();
    } catch (e) {
      if (reqSeq !== this.historyLoadSeq || !this.historyOpen) return;
      this.historyLoading = false;
      this.historyError = e instanceof Error ? e.message : "Failed to load block history";
      this.renderHistoryDrawer();
      this.handleErr(e);
    }
  }

  private async selectHistoryEntry(entry: BlockHistoryEntryDto): Promise<void> {
    if (!this.historyOpen || !this.historyBlockId || !this.api.getBlockHistoryOp) return;
    if (!entry.has_content || entry.shredded || !entry.content_available) return;
    const blockId = this.historyBlockId;
    if (entry.is_locked && !this.isVaultUnlocked()) {
      this.openVaultModal();
      return;
    }

    const reqSeq = ++this.historyOpSeq;
    const lockEpoch = this.stream.getVaultLockEpoch();
    this.historySelectedOpId = entry.op_id;
    this.historySelectedContent = null;
    this.historySelectedDto = null;
    this.historyOpLoading = true;
    this.historyError = null;
    this.renderHistoryDrawer();

    try {
      const dto = await this.api.getBlockHistoryOp(blockId, entry.op_id);
      if (reqSeq !== this.historyOpSeq || !this.historyOpen || this.historyBlockId !== blockId) {
        return;
      }
      let plain: string;
      if (dto.is_locked) {
        const session = this.vaultSession;
        if (!session || session.isLocked() || isPageHidden() || this.stream.getVaultLockEpoch() !== lockEpoch) {
          this.closeHistoryDrawer();
          return;
        }
        if (!dto.mnb1_b64 || !dto.mnw1_b64) {
          throw new Error("Missing Tier 2 ciphertext or key wrap for historical version");
        }
        const dec = session.decryptBlock(
          dto.block_id,
          dto.op_id,
          dto.key_id,
          b64ToBytes(dto.mnb1_b64),
          b64ToBytes(dto.mnw1_b64),
        );
        plain = dec.content;
        dec.free();
        this.resetVaultIdleTimer();
      } else {
        plain = dto.content ?? "";
      }
      this.historySelectedDto = dto;
      this.historySelectedContent = plain;
      this.historyOpLoading = false;
      this.renderHistoryDrawer();
    } catch (e) {
      if (reqSeq !== this.historyOpSeq || !this.historyOpen) return;
      this.historyOpLoading = false;
      this.historyError = e instanceof Error ? e.message : "Failed to load historical content";
      this.renderHistoryDrawer();
      this.handleErr(e);
    }
  }

  private encryptTier2RevertPayload(
    block: BlockDto,
    plaintext: string,
    session: WasmVaultSession,
  ): { op_id: string; key_id: string; mnb1_b64: string; mnw1_b64?: string } {
    const mat = this.findTier2KeyMaterial(block);
    if (mat) {
      const enc = session.encryptUpdate(
        JSON.stringify({ block_id: block.id }),
        mat.keyId,
        b64ToBytes(mat.mnw1B64),
        plaintext,
        block.lang,
      );
      const payload = { op_id: enc.opId, key_id: enc.keyId, mnb1_b64: bytesToB64(enc.mnb1) };
      enc.free();
      return payload;
    }
    const enc = session.rekeyToVault(JSON.stringify({ block_id: block.id }), plaintext, block.lang);
    const payload = {
      op_id: enc.opId,
      key_id: enc.keyId,
      mnb1_b64: bytesToB64(enc.mnb1),
      mnw1_b64: enc.mnw1 ? bytesToB64(enc.mnw1) : undefined,
    };
    enc.free();
    return payload;
  }

  private async revertToSelectedHistory(): Promise<void> {
    if (!this.historyOpen || !this.historyBlockId || !this.historySelectedOpId || !this.api.revertBlock) return;
    const blockId = this.historyBlockId;
    const targetOpId = this.historySelectedOpId;
    const targetPlaintext = this.historySelectedContent;
    const lockEpoch = this.stream.getVaultLockEpoch();

    await this.stream.waitForSaveIdle(blockId);
    const cur = this.stream.getBlocks().find((b) => b.id === blockId);
    if (!cur) return;
    if (cur.has_conflict) {
      this.showToast("Resolve concurrent versions before reverting", true);
      return;
    }
    const expectedHeads = this.stream.getExpectedHeadsForBlock(cur.id);
    try {
      let updated: BlockDto;
      if (cur.is_locked) {
        const session = this.vaultSession;
        if (!session || session.isLocked() || isPageHidden() || this.stream.getVaultLockEpoch() !== lockEpoch) {
          this.openVaultModal();
          return;
        }
        if (targetPlaintext === null) {
          this.showToast("Selected version content is unavailable", true);
          return;
        }
        const payload = this.encryptTier2RevertPayload(cur, targetPlaintext, session);
        this.resetVaultIdleTimer();
        updated = await this.api.revertBlock(cur.id, {
          expected_heads: expectedHeads,
          ...payload,
        });
        const keepUnlocked =
          this.isVaultUnlocked() && !isPageHidden() && this.stream.getVaultLockEpoch() === lockEpoch;
        this.stream.applyAuthoritativeBlock(updated, this.activeBufferId, keepUnlocked ? targetPlaintext : undefined);
      } else {
        updated = await this.api.revertBlock(cur.id, {
          to_op_id: targetOpId,
          expected_heads: expectedHeads,
        });
        this.stream.applyAuthoritativeBlock(updated, this.activeBufferId);
      }
      this.showToast("Reverted block to selected version");
      if (this.historyOpen && this.historyBlockId === cur.id) {
        await this.openHistoryDrawer(updated);
      }
    } catch (e) {
      this.handleErr(e);
    }
  }

  private async undoActorBatch(actor: string, predecessor: BlockHistoryEntryDto): Promise<void> {
    if (!this.historyOpen || !this.historyBlockId || !this.api.revertBlock) return;
    const blockId = this.historyBlockId;
    const lockEpoch = this.stream.getVaultLockEpoch();

    await this.stream.waitForSaveIdle(blockId);
    const cur = this.stream.getBlocks().find((b) => b.id === blockId);
    if (!cur) return;
    if (cur.has_conflict) {
      this.showToast("Resolve concurrent versions before reverting", true);
      return;
    }
    const expectedHeads = this.stream.getExpectedHeadsForBlock(cur.id);
    try {
      let updated: BlockDto;
      if (cur.is_locked) {
        const session = this.vaultSession;
        if (
          !session ||
          session.isLocked() ||
          isPageHidden() ||
          this.stream.getVaultLockEpoch() !== lockEpoch ||
          !this.api.getBlockHistoryOp
        ) {
          this.openVaultModal();
          return;
        }
        const dto = await this.api.getBlockHistoryOp(cur.id, predecessor.op_id);
        if (!this.isVaultUnlocked() || this.vaultSession !== session || isPageHidden() || this.stream.getVaultLockEpoch() !== lockEpoch) {
          this.closeHistoryDrawer();
          return;
        }
        let plain: string;
        if (dto.is_locked) {
          if (!dto.mnb1_b64 || !dto.mnw1_b64) {
            throw new Error("Missing Tier 2 ciphertext or key wrap for predecessor version");
          }
          const dec = session.decryptBlock(
            dto.block_id,
            dto.op_id,
            dto.key_id,
            b64ToBytes(dto.mnb1_b64),
            b64ToBytes(dto.mnw1_b64),
          );
          plain = dec.content;
          dec.free();
        } else {
          plain = dto.content ?? "";
        }
        const payload = this.encryptTier2RevertPayload(cur, plain, session);
        this.resetVaultIdleTimer();
        updated = await this.api.revertBlock(cur.id, {
          expected_heads: expectedHeads,
          ...payload,
        });
        const keepUnlocked =
          this.isVaultUnlocked() && !isPageHidden() && this.stream.getVaultLockEpoch() === lockEpoch;
        this.stream.applyAuthoritativeBlock(updated, this.activeBufferId, keepUnlocked ? plain : undefined);
      } else {
        updated = await this.api.revertBlock(cur.id, {
          undo_actor: actor,
          expected_heads: expectedHeads,
        });
        this.stream.applyAuthoritativeBlock(updated, this.activeBufferId);
      }
      this.showToast(`Undid ${actor} batch`);
      if (this.historyOpen && this.historyBlockId === cur.id) {
        await this.openHistoryDrawer(updated);
      }
    } catch (e) {
      this.handleErr(e);
    }
  }

  private formatHistoryTime(ms: number): string {
    if (!Number.isFinite(ms) || ms <= 0) return "";
    return new Date(ms).toISOString().slice(0, 19).replace("T", " ") + "Z";
  }

  private renderHistoryDrawer(): void {
    if (!this.historyOpen || !this.historyBlockId) return;
    const cur = this.stream.getBlocks().find((b) => b.id === this.historyBlockId) ?? null;
    this.historyTitleEl.textContent = cur
      ? `History · ${cur.lang} · ${cur.id.slice(0, 8)}`
      : `History · ${this.historyBlockId.slice(0, 8)}`;

    this.historyActionsEl.replaceChildren();
    this.historyListEl.replaceChildren();
    this.historyDiffEl.replaceChildren();

    if (this.historyLoading) {
      const loading = document.createElement("div");
      loading.className = "empty-state";
      loading.textContent = "Loading history…";
      this.historyListEl.appendChild(loading);
      return;
    }

    // Undo <actor> batch button when the most recent content-bearing op(s) came from a non-human actor
    const contentEntries = this.historyEntries.filter((e) => e.has_content);
    const latestContent = contentEntries[0];
    if (latestContent && latestContent.actor && latestContent.actor !== "human") {
      const badActor = latestContent.actor;
      const predecessor = contentEntries.find((e) => e.actor !== badActor) ?? null;
      const undoBtn = document.createElement("button");
      undoBtn.type = "button";
      undoBtn.className = "btn btn-amber btn-icon";
      undoBtn.dataset.testid = "history-undo-actor-btn";
      undoBtn.textContent = `Undo ${badActor} batch`;
      if (!predecessor) {
        undoBtn.disabled = true;
        undoBtn.title = `No earlier version outside actor '${badActor}'`;
      } else if (predecessor.shredded || !predecessor.content_available) {
        undoBtn.disabled = true;
        undoBtn.title = "Predecessor version is shredded or unavailable";
      } else {
        undoBtn.addEventListener("click", () => void this.undoActorBatch(badActor, predecessor));
      }
      this.historyActionsEl.appendChild(undoBtn);
    }

    if (cur?.has_conflict) {
      const conflictHint = document.createElement("div");
      conflictHint.className = "history-conflict-note";
      conflictHint.textContent = "Conflict present — resolve concurrent versions before reverting.";
      this.historyActionsEl.appendChild(conflictHint);
    }

    if (this.historyEntries.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = this.historyError ? `Error: ${this.historyError}` : "No history entries found.";
      this.historyListEl.appendChild(empty);
      return;
    }

    for (const entry of this.historyEntries) {
      const row = document.createElement("div");
      const isSelected = entry.op_id === this.historySelectedOpId;
      const unavailable = entry.shredded || (entry.has_content && !entry.content_available);
      const selectable = entry.has_content && !unavailable;
      row.className = `history-item${isSelected ? " selected" : ""}${unavailable ? " unavailable" : ""}`;
      row.dataset.opId = entry.op_id;

      const topRow = document.createElement("div");
      topRow.className = "history-item-top";

      const opBadge = document.createElement("span");
      opBadge.className = "kbd";
      opBadge.textContent = entry.op_type;
      topRow.appendChild(opBadge);

      const actorBadge = document.createElement("span");
      actorBadge.className = entry.actor !== "human" ? "actor-badge actor-badge-agent" : "actor-badge actor-badge-human";
      actorBadge.textContent = entry.actor;
      topRow.appendChild(actorBadge);

      if (entry.is_locked) {
        const lockBadge = document.createElement("span");
        lockBadge.className = "vault-badge";
        lockBadge.textContent = "🔒";
        lockBadge.title = "Tier 2 Vault version";
        topRow.appendChild(lockBadge);
      }

      if (cur && cur.display_op_id === entry.op_id) {
        const curBadge = document.createElement("span");
        curBadge.className = "history-current-badge";
        curBadge.textContent = "Current";
        topRow.appendChild(curBadge);
      }

      if (unavailable) {
        const shredBadge = document.createElement("span");
        shredBadge.className = "history-badge-shredded";
        shredBadge.dataset.testid = "history-shredded-badge";
        shredBadge.textContent = "Shredded / Unavailable";
        topRow.appendChild(shredBadge);
      } else if (!entry.has_content) {
        const metaBadge = document.createElement("span");
        metaBadge.className = "kbd";
        metaBadge.textContent = "meta";
        topRow.appendChild(metaBadge);
      }

      const metaRow = document.createElement("div");
      metaRow.className = "history-item-meta";
      metaRow.textContent = `${this.formatHistoryTime(entry.created_at_ms)} · ${entry.device_id}`;

      const btnRow = document.createElement("div");
      btnRow.className = "history-item-actions";
      const viewBtn = document.createElement("button");
      viewBtn.type = "button";
      viewBtn.className = `btn btn-icon${isSelected ? " btn-primary" : ""}`;
      viewBtn.dataset.testid = `history-select-${entry.op_id}`;
      viewBtn.textContent = isSelected ? "Inspecting" : "Diff & Inspect";
      viewBtn.disabled = !selectable;
      if (selectable) {
        viewBtn.addEventListener("click", (ev) => {
          ev.stopPropagation();
          void this.selectHistoryEntry(entry);
        });
        row.addEventListener("click", () => void this.selectHistoryEntry(entry));
      }
      btnRow.appendChild(viewBtn);

      row.append(topRow, metaRow, btnRow);
      this.historyListEl.appendChild(row);
    }

    // Selected entry diff & revert panel
    if (this.historyOpLoading) {
      const loading = document.createElement("div");
      loading.className = "history-diff-empty";
      loading.textContent = "Loading version content…";
      this.historyDiffEl.appendChild(loading);
    } else if (this.historyError) {
      const errEl = document.createElement("div");
      errEl.className = "history-diff-error";
      errEl.textContent = this.historyError;
      this.historyDiffEl.appendChild(errEl);
    } else if (this.historySelectedOpId && this.historySelectedContent !== null) {
      const diffHdr = document.createElement("div");
      diffHdr.className = "history-diff-header";
      const titleSpan = document.createElement("span");
      titleSpan.textContent = `Selected (${this.historySelectedOpId.slice(0, 8)}) → Current`;

      const revertBtn = document.createElement("button");
      revertBtn.type = "button";
      revertBtn.className = "btn btn-primary btn-icon";
      revertBtn.dataset.testid = "history-revert-btn";
      revertBtn.textContent = "Revert to this version";
      revertBtn.addEventListener("click", () => void this.revertToSelectedHistory());
      diffHdr.append(titleSpan, revertBtn);

      const currentContent = cur ? this.stream.getBlockDraftContent(cur.id) : "";
      const diffLines = computeLineDiff(this.historySelectedContent, currentContent);

      const diffView = document.createElement("div");
      diffView.className = "diff-view";
      diffView.dataset.testid = "history-diff-view";
      if (diffLines.length === 0) {
        const emptyLine = document.createElement("div");
        emptyLine.className = "diff-line diff-ctx";
        emptyLine.textContent = "(empty)";
        diffView.appendChild(emptyLine);
      } else {
        for (const line of diffLines) {
          const lineEl = document.createElement("div");
          const cls = line.kind === "add" ? "diff-add" : line.kind === "del" ? "diff-del" : "diff-ctx";
          lineEl.className = `diff-line ${cls}`;

          const sign = document.createElement("span");
          sign.className = "diff-sign";
          sign.textContent = line.kind === "add" ? "+" : line.kind === "del" ? "-" : " ";

          const text = document.createElement("span");
          text.className = "diff-text";
          text.textContent = line.text;

          lineEl.append(sign, text);
          diffView.appendChild(lineEl);
        }
      }

      const rawDetails = document.createElement("details");
      rawDetails.className = "history-raw-details";
      const rawSummary = document.createElement("summary");
      rawSummary.textContent = "Raw historical content";
      const rawPre = document.createElement("pre");
      rawPre.className = "history-raw-pre";
      rawPre.textContent = this.historySelectedContent;
      rawDetails.append(rawSummary, rawPre);

      this.historyDiffEl.append(diffHdr, diffView, rawDetails);
    }
  }

  // ---------- M2 Recycle Bin & Controlled Shred Confirmation ----------

  private async toggleTrash(): Promise<void> {
    this.trashOpen = !this.trashOpen;
    if (this.trashOpen) this.closeHistoryDrawer();
    this.trashDrawerEl.classList.toggle("hidden", !this.trashOpen);
    if (this.trashOpen) await this.refreshTrash();
  }

  private async refreshTrash(): Promise<void> {
    try {
      this.trashItems = await this.api.listTrash();
      this.updateTrashCount(this.trashItems.length);
      this.renderTrash();
    } catch (e) {
      this.handleErr(e);
    }
  }

  private formatShredTime(ms: number | null): string {
    if (!ms) return "";
    const d = new Date(ms);
    return ` · ≥ ${d.toISOString().slice(0, 16).replace("T", " ")}Z`;
  }

  private renderTrash(): void {
    this.trashActionsEl.innerHTML = "";
    const pendingConfirm = this.trashItems.filter((t) => t.shred_state === "pending_confirm");
    if (pendingConfirm.length > 0 && this.api.prepareTrashAction) {
      const confirmBtn = document.createElement("button");
      confirmBtn.type = "button";
      confirmBtn.className = "btn btn-amber btn-icon";
      confirmBtn.textContent = `Confirm Pending (${pendingConfirm.length})`;
      confirmBtn.addEventListener("click", () =>
        void this.openTrashConfirmModal("confirm_pending", pendingConfirm.map((x) => x.id), undefined),
      );
      this.trashActionsEl.appendChild(confirmBtn);
    }
    const expeditableItems = this.trashItems.filter(
      (t) => t.shred_state !== "executed" && t.shred_state !== "pending_confirm",
    );
    if (expeditableItems.length > 0 && this.api.prepareTrashAction) {
      const expAllBtn = document.createElement("button");
      expAllBtn.type = "button";
      expAllBtn.className = "btn btn-danger btn-icon";
      expAllBtn.textContent = "Expedite All (24h min)";
      expAllBtn.addEventListener("click", () =>
        void this.openTrashConfirmModal(
          "expedite",
          expeditableItems.map((x) => x.id),
          T_GRACE_MIN_MS,
        ),
      );
      this.trashActionsEl.appendChild(expAllBtn);
    }

    this.trashListEl.innerHTML = "";
    if (this.trashItems.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "Recycle Bin is empty.";
      this.trashListEl.appendChild(empty);
      return;
    }
    for (const item of this.trashItems) {
      const card = document.createElement("div");
      card.className = "trash-item";
      card.dataset.trashId = item.id;
      const meta = document.createElement("div");
      meta.className = "leaf-meta";
      const info = document.createElement("span");
      info.textContent = `${item.buffer_name} · ${item.shred_state}${this.formatShredTime(item.shred_not_before_ms)}`;
      const btns = document.createElement("div");
      btns.className = "block-header-right";
      const restoreBtn = document.createElement("button");
      restoreBtn.type = "button";
      restoreBtn.className = "btn btn-primary btn-icon";
      restoreBtn.textContent = "Restore";
      restoreBtn.addEventListener("click", () => void this.restoreTrashItem(item));
      btns.appendChild(restoreBtn);
      if (this.api.prepareTrashAction && item.shred_state !== "executed" && item.shred_state !== "pending_confirm") {
        const expBtn = document.createElement("button");
        expBtn.type = "button";
        expBtn.className = "btn btn-danger btn-icon";
        expBtn.textContent = "Expedite";
        expBtn.title = "Shorten shred countdown to 24h minimum grace";
        expBtn.addEventListener("click", () => void this.openTrashConfirmModal("expedite", [item.id], T_GRACE_MIN_MS));
        btns.appendChild(expBtn);
      }
      meta.append(info, btns);
      const preview = document.createElement("pre");
      preview.className = "trash-preview";
      preview.textContent = item.is_locked ? "🔒 <locked Tier 2 block>" : item.preview ?? "";
      card.append(meta, preview);
      this.trashListEl.appendChild(card);
    }
  }

  private async openTrashConfirmModal(
    action: "expedite" | "confirm_pending" | "purge_history",
    blockIds?: string[],
    graceMs?: number,
    targetBlock?: BlockDto,
  ): Promise<void> {
    if (!this.api.prepareTrashAction || !this.api.commitTrashAction) {
      this.showToast("Trash confirmation API unavailable", true);
      return;
    }
    if (action === "purge_history" && targetBlock) {
      if (targetBlock.is_locked && !this.isVaultUnlocked()) {
        this.openVaultModal();
        return;
      }
      await this.stream.flushAllDirty();
    }
    let prep: TrashActionPrepareResponse;
    try {
      prep = await this.api.prepareTrashAction({ action, block_ids: blockIds, grace_ms: graceMs });
    } catch (e) {
      this.handleErr(e);
      return;
    }

    this.dialogModalEl.innerHTML = "";
    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    title.textContent =
      action === "expedite"
        ? "Confirm Expedite Cryptographic Shred"
        : action === "confirm_pending"
          ? "Confirm Pending Batch Shred"
          : "Confirm Purge Historical Versions";
    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "btn btn-icon";
    closeBtn.textContent = "✕";
    closeBtn.addEventListener("click", () => this.closeDialog());
    hdr.append(title, closeBtn);

    const body = document.createElement("div");
    body.className = "dialog-form";
    const graceHours = Math.round(prep.summary.grace_ms / 3_600_000);
    const details = document.createElement("div");
    details.className = "confirm-summary";
    details.textContent = [
      `Action: ${prep.summary.action}`,
      `Target blocks: ${prep.summary.block_count}`,
      `Keys affected: ${prep.summary.key_count}`,
      `Grace period: ${graceHours}h (server enforces ≥ 24h mandatory minimum)`,
      prep.summary.earliest_not_before_ms
        ? `Current earliest shred: ${new Date(prep.summary.earliest_not_before_ms).toISOString()}`
        : "",
    ]
      .filter(Boolean)
      .join("\n");
    const warn = document.createElement("p");
    warn.className = "dialog-note";
    warn.textContent =
      "Once the server-enforced grace countdown expires, affected encryption keys are permanently erased and ciphertext becomes unreadable. You may still restore or cancel before execution.";

    const actions = document.createElement("div");
    actions.className = "dialog-actions";
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "btn";
    cancelBtn.textContent = "Cancel";
    cancelBtn.addEventListener("click", () => this.closeDialog());
    const confirmBtn = document.createElement("button");
    confirmBtn.type = "button";
    confirmBtn.className = "btn btn-danger";
    confirmBtn.dataset.testid = "trash-confirm-commit-btn";
    confirmBtn.textContent = "Confirm Shred Schedule";
    confirmBtn.addEventListener("click", () => {
      void (async () => {
        confirmBtn.disabled = true;
        const lockEpoch = this.stream.getVaultLockEpoch();
        try {
          let tier2: Tier2WritePayload | undefined;
          let plainForRam: string | undefined;
          let expectedHeads: string[] | undefined;
          if (action === "purge_history" && targetBlock) {
            const cur = this.stream.getBlocks().find((b) => b.id === targetBlock.id) ?? targetBlock;
            expectedHeads = this.stream.getExpectedHeadsForBlock(cur.id);
            if (cur.is_locked) {
              const session = this.vaultSession;
              if (!session || session.isLocked()) {
                this.showToast("Vault must be unlocked to rekey a locked block", true);
                confirmBtn.disabled = false;
                return;
              }
              plainForRam = this.stream.getBlockDraftContent(cur.id);
              const enc = session.rekeyToVault(JSON.stringify({ block_id: cur.id }), plainForRam, cur.lang);
              tier2 = {
                op_id: enc.opId,
                key_id: enc.keyId,
                mnb1_b64: bytesToB64(enc.mnb1),
                mnw1_b64: enc.mnw1 ? bytesToB64(enc.mnw1) : undefined,
              };
              enc.free();
            }
          }
          await this.api.commitTrashAction!({ confirm_nonce: prep.confirm_nonce, tier2, expected_heads: expectedHeads });
          this.closeDialog();
          if (action === "purge_history" && targetBlock && this.activeBufferId) {
            const latest = await this.api.listBlocks(this.activeBufferId);
            this.stream.upsertBlocks(latest, [], this.activeBufferId);
            if (
              plainForRam !== undefined &&
              this.isVaultUnlocked() &&
              !isPageHidden() &&
              this.stream.getVaultLockEpoch() === lockEpoch
            ) {
              this.stream.setUnlockedPlaintext(targetBlock.id, plainForRam);
            }
            this.showToast("Current version rekeyed; old history keys scheduled for shred (≥24h)");
          } else {
            await this.refreshTrash();
            if (this.api.getSyncStatus) {
              this.syncStatus = await this.api.getSyncStatus();
              this.updateAlertsFromStatus(this.syncStatus);
            }
            this.showToast(`Confirmed ${action} schedule`);
          }
        } catch (e) {
          this.handleErr(e);
          // Re-prepare a fresh single-use confirm_nonce so retry does not fail on consumed nonce.
          try {
            prep = await this.api.prepareTrashAction!({ action, block_ids: blockIds, grace_ms: graceMs });
            confirmBtn.disabled = false;
          } catch {
            this.closeDialog();
          }
        }
      })();
    });
    actions.append(cancelBtn, confirmBtn);
    body.append(details, warn, actions);
    this.dialogModalEl.append(hdr, body);
    this.dialogBackdropEl.classList.remove("hidden");
  }

  private async restoreTrashItem(item: TrashItemDto): Promise<void> {
    try {
      let restored: BlockDto;
      let restoredPlain: string | undefined;
      const lockEpoch = this.stream.getVaultLockEpoch();
      if (item.is_locked) {
        if (!this.isVaultUnlocked() || !this.vaultSession || !this.api.getTrashTier2Blob) {
          this.pendingAfterUnlock = () => this.restoreTrashItem(item);
          this.openVaultModal();
          return;
        }
        const blob = await this.api.getTrashTier2Blob(item.id);
        const session = this.vaultSession;
        if (!session || session.isLocked() || document.visibilityState === "hidden" || this.stream.getVaultLockEpoch() !== lockEpoch) {
          return;
        }
        const dec = session.decryptBlock(
          item.id,
          blob.op_id,
          blob.key_id,
          b64ToBytes(blob.mnb1_b64),
          b64ToBytes(blob.mnw1_b64),
        );
        restoredPlain = dec.content;
        dec.free();
        const enc = session.encryptUpdate(
          JSON.stringify({ block_id: item.id }),
          blob.key_id,
          b64ToBytes(blob.mnw1_b64),
          restoredPlain,
          "text",
        );
        const tier2 = { op_id: enc.opId, key_id: enc.keyId, mnb1_b64: bytesToB64(enc.mnb1) };
        enc.free();
        restored = await this.api.restoreTrash(item.id, tier2);
      } else {
        restored = await this.api.restoreTrash(item.id);
      }
      const keepUnlocked =
        item.is_locked &&
        this.isVaultUnlocked() &&
        document.visibilityState !== "hidden" &&
        this.stream.getVaultLockEpoch() === lockEpoch;
      this.stream.applyAuthoritativeBlock(restored, this.activeBufferId, keepUnlocked ? restoredPlain : undefined);
      await this.refreshTrash();
      this.showToast("Restored block from Recycle Bin");
    } catch (e) {
      this.handleErr(e);
    }
  }

  private openBufferModal(): void {
    this.modalListEl.innerHTML = "";
    for (const buf of this.buffers) {
      const row = document.createElement("div");
      row.className = "modal-row";
      const name = document.createElement("span");
      name.textContent = buf.name;
      const right = document.createElement("div");
      right.className = "block-header-right";
      const renBtn = document.createElement("button");
      renBtn.type = "button";
      renBtn.className = "btn btn-icon";
      renBtn.textContent = "Rename";
      renBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const nextName = window.prompt("New buffer name:", buf.name);
        if (nextName && nextName.trim()) {
          void this.api.renameBuffer(buf.id, nextName.trim()).then((updated) => {
            this.buffers = this.buffers.map((b) => (b.id === updated.id ? updated : b));
            this.renderBuffers();
            this.openBufferModal();
          });
        }
      });
      right.appendChild(renBtn);
      row.append(name, right);
      row.addEventListener("click", () => {
        this.closeBufferModal();
        void this.switchBuffer(buf.id);
      });
      this.modalListEl.appendChild(row);
    }
    this.modalBackdropEl.classList.remove("hidden");
    this.newBufInputEl.focus();
  }

  private closeBufferModal(): void {
    this.modalBackdropEl.classList.add("hidden");
  }

  private async createBuffer(): Promise<void> {
    const name = this.newBufInputEl.value.trim();
    if (!name) return;
    try {
      const created = await this.api.createBuffer({ name });
      this.buffers.push(created);
      this.newBufInputEl.value = "";
      this.closeBufferModal();
      await this.switchBuffer(created.id);
    } catch (e) {
      this.handleErr(e);
    }
  }

  private toggleFindBar(show: boolean): void {
    this.findBarEl.classList.toggle("hidden", !show);
    if (show) {
      this.findInputEl.focus();
      this.findInputEl.select();
    }
  }

  private runFind(delta: number): void {
    const matches = this.stream.findAcrossBlocks(this.findInputEl.value);
    this.findCountEl.textContent = `${matches.length} matches`;
    if (matches.length === 0) return;
    this.findIndex = (this.findIndex + delta + matches.length) % matches.length;
    const hit = matches[this.findIndex];
    this.stream.highlightBlockMatch(hit.blockId, hit.from, hit.to);
  }

  private async runReplaceAll(): Promise<void> {
    const q = this.findInputEl.value;
    if (!q) return;
    const count = await this.stream.replaceAllAcrossBlocks(q, this.replaceInputEl.value);
    this.showToast(`Replaced ${count} occurrence(s)`);
    this.runFind(0);
  }

  private async triggerSyncNow(): Promise<void> {
    try {
      this.syncStatus = await this.api.syncNow();
      this.updateAlertsFromStatus(this.syncStatus);
      this.renderSyncPill();
      this.showToast(`Sync: ${this.syncStatus.sync_state}`);
    } catch (e) {
      this.handleErr(e);
    }
  }

  private handleErr(e: unknown): void {
    if (e instanceof LocalApiError) {
      this.showToast(`${e.body.code}: ${e.body.message}`, true);
    } else {
      const parsed = parseWasmError(e);
      this.showToast(parsed.code !== "WASM_ERROR" ? `${parsed.code}: ${parsed.message}` : parsed.message, true);
    }
  }
}
