import { LocalApiError, type LocalApiClient } from "./api";
import { BlockStreamController, type SaveContentResult } from "./editor";
import type { AlertFrame, BlockDto, BufferDto, LocalWsFrame, SyncStateLabel, SyncStatusDto, TrashItemDto } from "./types";

export class MyNoteApp {
  private buffers: BufferDto[] = [];
  private activeBufferId: string | null = null;
  private syncStatus: SyncStatusDto | null = null;
  private wsConnected = true;
  private switchSeq = 0;
  private alerts = new Map<string, AlertFrame>();
  private trashItems: TrashItemDto[] = [];
  private trashOpen = false;
  private vimEnabled = false;
  private findIndex = 0;
  private disconnectWs: (() => void) | null = null;
  private toastTimer: number | null = null;

  private bufferTabsEl!: HTMLElement;
  private syncPillEl!: HTMLButtonElement;
  private trashBtnEl!: HTMLButtonElement;
  private alertStackEl!: HTMLElement;
  private findBarEl!: HTMLElement;
  private findInputEl!: HTMLInputElement;
  private replaceInputEl!: HTMLInputElement;
  private findCountEl!: HTMLElement;
  private trashDrawerEl!: HTMLElement;
  private trashListEl!: HTMLElement;
  private modalBackdropEl!: HTMLElement;
  private modalListEl!: HTMLElement;
  private newBufInputEl!: HTMLInputElement;
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
    this.updateAlertsFromStatus(boot.sync_status);
    this.renderBuffers();
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

    right.append(newBlkBtn, findBtn, vimBtn, this.trashBtnEl, this.syncPillEl);
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
    this.trashListEl = document.createElement("div");
    this.trashListEl.className = "drawer-list";
    this.trashDrawerEl.append(drawerHdr, this.trashListEl);
    workspace.append(streamEl, this.trashDrawerEl);

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

    this.toastEl = document.createElement("div");
    this.toastEl.className = "toast hidden";

    this.root.append(topbar, this.alertStackEl, this.findBarEl, workspace, this.modalBackdropEl, this.toastEl);
  }

  private bindGlobalKeys(): void {
    window.addEventListener("keydown", this.onWindowKeyDown);
    document.addEventListener("visibilitychange", this.onVisibilityChange);
    window.addEventListener("pagehide", this.onPageHide);
    window.addEventListener("beforeunload", this.onBeforeUnload);
  }

  private onVisibilityChange = (): void => {
    if (document.visibilityState === "hidden" && this.stream.hasDirtyBlocks()) {
      void this.stream.flushAllDirty({ keepalive: true });
    }
  };

  private onPageHide = (): void => {
    if (this.stream.hasDirtyBlocks()) {
      void this.stream.flushAllDirty({ keepalive: true });
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
        this.toggleFindBar(false);
      }
      return;
    }
    const key = ev.key.toLowerCase();
    if (key === "p") {
      ev.preventDefault();
      this.openBufferModal();
    } else if (key === "l") {
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
      if (blk && !blk.is_locked && blk.content !== null) {
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
    this.renderAlerts();
  }

  private renderAlerts(): void {
    this.alertStackEl.innerHTML = "";
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
      } else {
        text.textContent = `${alert.code}: ${JSON.stringify(alert.details)}`;
      }
      div.appendChild(text);
      this.alertStackEl.appendChild(div);
    }
  }

  private async resyncAfterReconnect(): Promise<void> {
    try {
      const boot = await this.api.bootstrap();
      this.buffers = boot.buffers;
      this.syncStatus = boot.sync_status;
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
      this.renderBuffers();
      this.renderSyncPill();
    } catch {
      // keep existing UI state until next reconnect
    }
  }

  private handleWsFrame(frame: LocalWsFrame): void {
    if (frame.type === "blocks_changed") {
      this.stream.upsertBlocks(frame.upserted, frame.deleted_ids, this.activeBufferId);
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
      if (this.trashOpen) void this.refreshTrash();
    } else if (frame.type === "sync_status") {
      if (this.syncStatus) {
        this.syncStatus.sync_state = frame.state;
        this.syncStatus.last_seq = frame.last_seq;
        if (frame.pending_ops !== undefined) this.syncStatus.pending_ops = frame.pending_ops;
      }
      this.renderSyncPill();
    } else if (frame.type === "alert") {
      this.alerts.set(frame.code, frame);
      this.renderAlerts();
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
      this.renderBuffers();
      this.stream.setBlocks(blocks);
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

  private async saveBlockContent(
    block: BlockDto,
    content: string,
    expectedHeads: string[],
    opts: { fastSync: boolean; isMerge: boolean; keepalive?: boolean },
  ): Promise<SaveContentResult> {
    try {
      const updated = await this.api.patchBlock(
        block.id,
        {
          expected_heads: expectedHeads,
          content,
          fast_sync: opts.fastSync,
        },
        { keepalive: opts.keepalive },
      );
      if (opts.isMerge) this.showToast("Merged versions cleanly");
      return { status: "ok", updated };
    } catch (e) {
      if (e instanceof LocalApiError && e.body.code === "HEAD_MISMATCH") {
        this.showToast("Concurrent update detected — your draft is preserved; choose Save Over or Reload", true);
        if (this.activeBufferId) {
          try {
            const latest = await this.api.listBlocks(this.activeBufferId);
            // Upsert latest metadata/versions WITHOUT destroying the user's dirty draft!
            this.stream.upsertBlocks(latest, [], this.activeBufferId);
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
    if (block.is_locked) {
      this.showToast("Locked Tier 2 blocks cannot be sent to external formatters", true);
      return;
    }
    if (block.content === null) {
      this.showToast("Cannot format an unreadable block until its key is available", true);
      return;
    }
    if (block.has_conflict) {
      this.showToast("Resolve concurrent versions before formatting", true);
      return;
    }
    try {
      const content = this.stream.getBlockDraftContent(block.id);
      const expectedHeads = this.stream.getExpectedHeadsForBlock(block.id);
      const { formatted } = await this.api.formatSnippet({ content, lang: block.lang });
      const updated = await this.api.patchBlock(block.id, {
        expected_heads: expectedHeads,
        content: formatted,
        fast_sync: true,
      });
      this.stream.applyAuthoritativeBlock(updated, this.activeBufferId);
      this.showToast(`Formatted (${block.lang})`);
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
      await this.api.deleteBlock(block.id, block.head_op_ids);
      this.stream.upsertBlocks([], [block.id], this.activeBufferId);
      this.showToast("Moved block to Recycle Bin");
      await this.refreshTrash();
    } catch (e) {
      this.handleErr(e);
    }
  }

  private async keepVersion(block: BlockDto, opId: string): Promise<void> {
    try {
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

  private async toggleTrash(): Promise<void> {
    this.trashOpen = !this.trashOpen;
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

  private renderTrash(): void {
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
      info.textContent = `${item.buffer_name} · ${item.shred_state}`;
      const restoreBtn = document.createElement("button");
      restoreBtn.type = "button";
      restoreBtn.className = "btn btn-primary btn-icon";
      restoreBtn.textContent = "Restore";
      restoreBtn.addEventListener("click", () => void this.restoreTrashItem(item.id));
      meta.append(info, restoreBtn);
      const preview = document.createElement("pre");
      preview.className = "trash-preview";
      preview.textContent = item.is_locked ? "🔒 <locked block>" : item.preview ?? "";
      card.append(meta, preview);
      this.trashListEl.appendChild(card);
    }
  }

  private async restoreTrashItem(id: string): Promise<void> {
    try {
      const restored = await this.api.restoreTrash(id);
      this.stream.upsertBlocks([restored], [], this.activeBufferId);
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
      this.showToast(e instanceof Error ? e.message : "Unexpected error", true);
    }
  }
}
