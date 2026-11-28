import { LocalApiError, type LocalApiClient } from "../api";
import {
  bytesToBase64Chunked,
  CLIP_CLOUD_QUOTA_WARN_RATIO,
  CLIP_EPHEMERAL_MAX_BYTES,
  CLIP_PAGE_LIMIT,
  extForClipMime,
  formatClipBytes,
  generateBitmapThumbnail,
  isSafeThumbDataUrl,
  validateClipImageFile,
} from "../clipUtils";
import { formatDeviceName, formatHistoryTimestamp, t } from "../i18n";
import { createIcon } from "../icons";
import { formatShortcutTitle, SHORTCUT_NEW_BLOCK } from "../shortcuts";
import type {
  BlockDto,
  ClipAutoApplyMirrorMode,
  ClipItemDto,
  ClipKind,
  ClipPruneInput,
  ClipScope,
  CloudClipQuotaDto,
} from "../types";

export interface ClipDrawerCallbacks {
  getActiveBufferId: () => string | null;
  onBlockPromoted: (block: BlockDto) => void;
  onFeedback: (msg: string, isError?: boolean) => void;
  onError: (err: unknown) => void;
  onCountChange?: (count: number) => void;
  onOpenChange?: (open: boolean) => void;
}

export interface ClipWsChangeFrame {
  upserted: ClipItemDto[];
  deleted_ids: string[];
  cleared: boolean;
  watch_enabled?: boolean;
  watch_paused: boolean;
  auto_apply_mirror?: ClipAutoApplyMirrorMode;
  cloud_quota?: CloudClipQuotaDto | null;
}

type CleanupRuleKey = "30d" | "7d" | "keep200" | "images" | "all";

function sortClipsDesc(items: readonly ClipItemDto[]): ClipItemDto[] {
  return [...items].sort((a, b) => {
    if (b.created_at_ms !== a.created_at_ms) return b.created_at_ms - a.created_at_ms;
    return b.clip_id < a.clip_id ? -1 : b.clip_id > a.clip_id ? 1 : 0;
  });
}

export class ClipDrawerController {
  public readonly element: HTMLElement;
  public readonly previewBackdropEl: HTMLElement;

  private openState = false;
  private items: ClipItemDto[] = [];
  private totalCount = 0;
  private hasMore = false;
  private loadingMore = false;
  private localBlobBytes = 0;
  private cloudQuota: CloudClipQuotaDto | null = null;
  private filterKind: "all" | ClipKind = "all";
  private searchQuery = "";
  private searchTimer: number | null = null;
  private cleanupOpen = false;
  private cleanupScope: ClipScope = "local";
  private cleanupRule: CleanupRuleKey = "30d";
  private cleanupPreviewText = "";
  private cleanupBusy = false;
  private hasUndo = false;
  private watchEnabled = false;
  private watchPaused = false;
  private autoApplyMirror: ClipAutoApplyMirrorMode = "inbox-only";
  private sending = false;
  private errorMessage: string | null = null;
  private activePreviewUrl: string | null = null;
  private previewReqSeq = 0;

  private titleEl!: HTMLSpanElement;
  private countPillEl!: HTMLSpanElement;
  private closeBtnEl!: HTMLButtonElement;
  private undoBtnEl!: HTMLButtonElement;
  private cleanupToggleBtnEl!: HTMLButtonElement;
  private clearBtnEl!: HTMLButtonElement;
  private watchBtnEl!: HTMLButtonElement;
  private watchPauseBtnEl!: HTMLButtonElement;
  private watchModeBtnEl!: HTMLButtonElement;
  private storageBarEl!: HTMLElement;
  private cleanupPanelEl!: HTMLElement;
  private cleanupScopeSelEl!: HTMLSelectElement;
  private cleanupRuleSelEl!: HTMLSelectElement;
  private cleanupPreviewBtnEl!: HTMLButtonElement;
  private cleanupRunBtnEl!: HTMLButtonElement;
  private cleanupPreviewEl!: HTMLElement;
  private composerInputEl!: HTMLTextAreaElement;
  private ephemeralCheckEl!: HTMLInputElement;
  private ephemeralTextEl!: HTMLSpanElement;
  private fileInputEl!: HTMLInputElement;
  private fileLabelEl!: HTMLLabelElement;
  private fileLabelTextEl!: HTMLSpanElement;
  private sendBtnEl!: HTMLButtonElement;
  private errorEl!: HTMLElement;
  private filterBarEl!: HTMLElement;
  private searchInputEl!: HTMLInputElement;
  private filterSegEl!: HTMLElement;
  private listEl!: HTMLElement;
  private previewModalEl!: HTMLElement;
  private previewTitleEl!: HTMLSpanElement;
  private previewCloseBtnEl!: HTMLButtonElement;
  private previewBodyEl!: HTMLElement;

  constructor(private api: LocalApiClient, private cb: ClipDrawerCallbacks) {
    this.element = document.createElement("aside");
    this.element.className = "drawer clip-drawer hidden";
    this.element.dataset.testid = "clip-drawer";

    this.previewBackdropEl = document.createElement("div");
    this.previewBackdropEl.className = "modal-backdrop hidden";
    this.previewBackdropEl.dataset.testid = "clip-preview-modal";
    this.previewBackdropEl.addEventListener("click", (ev) => {
      if (ev.target === this.previewBackdropEl) this.closeImagePreview();
    });

    this.buildDom();
  }

  isOpen(): boolean {
    return this.openState;
  }

  isPreviewOpen(): boolean {
    return !this.previewBackdropEl.classList.contains("hidden");
  }

  async open(): Promise<void> {
    if (this.openState) return;
    this.openState = true;
    this.element.classList.remove("hidden");
    this.cb.onOpenChange?.(true);
    await this.refresh();
  }

  close(): void {
    this.closeImagePreview();
    if (!this.openState) return;
    this.openState = false;
    this.element.classList.add("hidden");
    this.cb.onOpenChange?.(false);
  }

  async toggle(): Promise<void> {
    if (this.openState) this.close();
    else await this.open();
  }

  destroy(): void {
    if (this.searchTimer !== null) {
      window.clearTimeout(this.searchTimer);
      this.searchTimer = null;
    }
    this.closeImagePreview();
  }

  getItems(): readonly ClipItemDto[] {
    return this.items;
  }

  async refresh(opts: { silent?: boolean; append?: boolean } = {}): Promise<void> {
    if (!this.api.listClips) {
      if (!opts.silent) {
        this.setError(t("clip.errApiUnavailable"));
        this.renderList();
      }
      return;
    }
    const append = Boolean(opts.append);
    const beforeId = append ? this.items[this.items.length - 1]?.clip_id : undefined;
    if (append) {
      if (this.loadingMore || !this.hasMore || !beforeId) return;
      this.loadingMore = true;
      this.renderList();
    }
    try {
      const res = await this.api.listClips({
        limit: CLIP_PAGE_LIMIT,
        ...(beforeId ? { before_id: beforeId } : {}),
        ...(this.filterKind !== "all" ? { kind: this.filterKind } : {}),
        ...(this.searchQuery.trim() ? { q: this.searchQuery.trim() } : {}),
      });
      if (append) {
        const byId = new Map<string, ClipItemDto>();
        for (const it of this.items) byId.set(it.clip_id, it);
        for (const it of res.items) byId.set(it.clip_id, it);
        this.items = sortClipsDesc([...byId.values()]);
      } else {
        this.items = sortClipsDesc(res.items);
      }
      this.hasMore = Boolean(res.has_more);
      this.totalCount = res.total_count ?? this.items.length;
      if (res.local_blob_bytes !== undefined) {
        this.localBlobBytes = res.local_blob_bytes;
      }
      if (res.cloud_quota !== undefined) {
        this.cloudQuota = res.cloud_quota;
      }
      this.hasUndo = res.has_undo;
      this.watchEnabled = res.watch_enabled;
      this.watchPaused = res.watch_paused;
      this.autoApplyMirror = res.auto_apply_mirror;
      if (this.filterKind === "all" && !this.searchQuery.trim()) {
        this.cb.onCountChange?.(this.totalCount);
      }
      this.renderHeaderState();
      this.renderStorageBar();
      if (this.openState) {
        this.renderList();
      }
    } catch (e) {
      if (!opts.silent) {
        this.cb.onError(e);
      }
    } finally {
      if (append) {
        this.loadingMore = false;
        if (this.openState) this.renderList();
      }
    }
  }

  applyWsUpdate(frame: ClipWsChangeFrame): void {
    if (frame.watch_enabled !== undefined) {
      this.watchEnabled = frame.watch_enabled;
    }
    this.watchPaused = frame.watch_paused;
    if (frame.auto_apply_mirror !== undefined) {
      this.autoApplyMirror = frame.auto_apply_mirror;
    }
    if (frame.cloud_quota !== undefined) {
      this.cloudQuota = frame.cloud_quota;
    }
    const prevIds = new Set(this.items.map((x) => x.clip_id));
    const byId = new Map<string, ClipItemDto>();
    if (!frame.cleared) {
      for (const item of this.items) {
        byId.set(item.clip_id, item);
      }
    } else {
      this.totalCount = 0;
      this.hasMore = false;
      this.localBlobBytes = 0;
    }
    let removedExisting = 0;
    for (const delId of frame.deleted_ids) {
      if (byId.delete(delId)) removedExisting++;
    }
    let addedNew = 0;
    for (const up of frame.upserted) {
      if (!prevIds.has(up.clip_id) || frame.cleared) addedNew++;
      byId.set(up.clip_id, up);
    }
    this.items = sortClipsDesc([...byId.values()]);
    if (frame.cleared) {
      this.totalCount = this.items.length;
    } else {
      this.totalCount = Math.max(this.items.length, this.totalCount - removedExisting + addedNew);
    }
    this.cb.onCountChange?.(this.totalCount);
    this.renderHeaderState();
    this.renderStorageBar();
    if (this.openState) {
      this.renderList();
    }
  }

  refreshLocale(): void {
    this.titleEl.textContent = t("clip.title");
    this.closeBtnEl.setAttribute("aria-label", t("topbar.close"));
    this.closeBtnEl.title = t("topbar.close");
    const closeSr = this.closeBtnEl.querySelector<HTMLElement>(".sr-only");
    if (closeSr) closeSr.textContent = t("topbar.close");

    this.composerInputEl.placeholder = t("clip.placeholder");
    this.ephemeralTextEl.textContent = t("clip.ephemeral");
    this.fileLabelTextEl.textContent = t("clip.pickImage");
    this.fileLabelEl.title = t("clip.pickImageTitle");
    this.searchInputEl.placeholder = t("clip.searchPlaceholder");
    this.previewTitleEl.textContent = t("clip.previewModalTitle");
    this.previewCloseBtnEl.setAttribute("aria-label", t("topbar.close"));
    this.previewCloseBtnEl.title = t("topbar.close");

    this.renderHeaderState();
    this.renderStorageBar();
    this.renderCleanupPanel();
    this.renderFilterBar();
    this.renderList();
  }

  closeImagePreview(): void {
    this.previewReqSeq++;
    if (this.activePreviewUrl) {
      URL.revokeObjectURL(this.activePreviewUrl);
      this.activePreviewUrl = null;
    }
    this.previewBackdropEl.classList.add("hidden");
    this.previewBodyEl.replaceChildren();
  }

  private buildDom(): void {
    const hdr = document.createElement("div");
    hdr.className = "drawer-header";

    const titleGroup = document.createElement("div");
    titleGroup.className = "clip-drawer-title-group";
    this.titleEl = document.createElement("span");
    this.titleEl.className = "drawer-header-title";
    this.titleEl.textContent = t("clip.title");
    this.countPillEl = document.createElement("span");
    this.countPillEl.className = "clip-count-pill";
    titleGroup.append(this.titleEl, this.countPillEl);

    this.closeBtnEl = document.createElement("button");
    this.closeBtnEl.type = "button";
    this.closeBtnEl.className = "btn btn-ghost btn-icon btn-icon-only";
    this.closeBtnEl.dataset.testid = "clip-close-btn";
    this.closeBtnEl.setAttribute("aria-label", t("topbar.close"));
    this.closeBtnEl.title = t("topbar.close");
    const closeSr = document.createElement("span");
    closeSr.className = "sr-only";
    closeSr.textContent = t("topbar.close");
    this.closeBtnEl.append(createIcon("x", "xs"), closeSr);
    this.closeBtnEl.addEventListener("click", () => this.close());
    hdr.append(titleGroup, this.closeBtnEl);

    // Header actions row: Undo Overwrite, Cleanup, & Clear All
    const actionsRow = document.createElement("div");
    actionsRow.className = "drawer-actions clip-header-actions";

    this.undoBtnEl = document.createElement("button");
    this.undoBtnEl.type = "button";
    this.undoBtnEl.className = "btn btn-icon btn-has-icon";
    this.undoBtnEl.dataset.testid = "clip-undo-btn";
    this.undoBtnEl.addEventListener("click", () => void this.handleUndo());

    const rightActions = document.createElement("div");
    rightActions.className = "clip-composer-buttons";

    this.cleanupToggleBtnEl = document.createElement("button");
    this.cleanupToggleBtnEl.type = "button";
    this.cleanupToggleBtnEl.className = "btn btn-ghost btn-icon";
    this.cleanupToggleBtnEl.dataset.testid = "clip-cleanup-btn";
    this.cleanupToggleBtnEl.addEventListener("click", () => {
      this.cleanupOpen = !this.cleanupOpen;
      this.cleanupPreviewText = "";
      this.renderCleanupPanel();
    });

    this.clearBtnEl = document.createElement("button");
    this.clearBtnEl.type = "button";
    this.clearBtnEl.className = "btn btn-ghost btn-danger btn-icon";
    this.clearBtnEl.dataset.testid = "clip-clear-btn";
    this.clearBtnEl.addEventListener("click", () => void this.handleClearAll());

    rightActions.append(this.cleanupToggleBtnEl, this.clearBtnEl);
    actionsRow.append(this.undoBtnEl, rightActions);

    // Compact Auto-Watch control strip (honest enabled/paused/receive-mode state)
    const watchBar = document.createElement("div");
    watchBar.className = "clip-watch-bar";
    watchBar.dataset.testid = "clip-watch-bar";

    this.watchBtnEl = document.createElement("button");
    this.watchBtnEl.type = "button";
    this.watchBtnEl.className = "btn btn-icon btn-has-icon";
    this.watchBtnEl.dataset.testid = "clip-watch-toggle";
    this.watchBtnEl.addEventListener("click", () => void this.handleToggleWatchEnabled());

    this.watchPauseBtnEl = document.createElement("button");
    this.watchPauseBtnEl.type = "button";
    this.watchPauseBtnEl.className = "btn btn-ghost btn-icon btn-has-icon hidden";
    this.watchPauseBtnEl.dataset.testid = "clip-watch-pause";
    this.watchPauseBtnEl.addEventListener("click", () => void this.handleToggleWatchPaused());

    this.watchModeBtnEl = document.createElement("button");
    this.watchModeBtnEl.type = "button";
    this.watchModeBtnEl.className = "btn btn-ghost btn-icon hidden";
    this.watchModeBtnEl.dataset.testid = "clip-watch-mode";
    this.watchModeBtnEl.addEventListener("click", () => void this.handleToggleWatchMode());

    watchBar.append(this.watchBtnEl, this.watchPauseBtnEl, this.watchModeBtnEl);

    // Local archive & cloud 5 GiB quota bar
    this.storageBarEl = document.createElement("div");
    this.storageBarEl.className = "clip-storage-bar";
    this.storageBarEl.dataset.testid = "clip-storage-bar";

    // Collapsible manual cleanup panel
    this.cleanupPanelEl = document.createElement("div");
    this.cleanupPanelEl.className = "clip-cleanup-panel hidden";
    this.cleanupPanelEl.dataset.testid = "clip-cleanup-panel";

    const cleanupRow1 = document.createElement("div");
    cleanupRow1.className = "clip-cleanup-row";
    this.cleanupScopeSelEl = document.createElement("select");
    this.cleanupScopeSelEl.className = "input clip-cleanup-select";
    this.cleanupScopeSelEl.dataset.testid = "clip-cleanup-scope";
    this.cleanupScopeSelEl.addEventListener("change", () => {
      this.cleanupScope = this.cleanupScopeSelEl.value as ClipScope;
      this.cleanupPreviewText = "";
      this.renderCleanupPanel();
    });
    this.cleanupRuleSelEl = document.createElement("select");
    this.cleanupRuleSelEl.className = "input clip-cleanup-select";
    this.cleanupRuleSelEl.dataset.testid = "clip-cleanup-rule";
    this.cleanupRuleSelEl.addEventListener("change", () => {
      this.cleanupRule = this.cleanupRuleSelEl.value as CleanupRuleKey;
      this.cleanupPreviewText = "";
      this.renderCleanupPanel();
    });
    cleanupRow1.append(this.cleanupScopeSelEl, this.cleanupRuleSelEl);

    const cleanupRow2 = document.createElement("div");
    cleanupRow2.className = "clip-cleanup-row";
    this.cleanupPreviewBtnEl = document.createElement("button");
    this.cleanupPreviewBtnEl.type = "button";
    this.cleanupPreviewBtnEl.className = "btn btn-ghost btn-icon";
    this.cleanupPreviewBtnEl.dataset.testid = "clip-cleanup-preview-btn";
    this.cleanupPreviewBtnEl.addEventListener("click", () => void this.handleCleanup(true));

    this.cleanupRunBtnEl = document.createElement("button");
    this.cleanupRunBtnEl.type = "button";
    this.cleanupRunBtnEl.className = "btn btn-danger btn-icon";
    this.cleanupRunBtnEl.dataset.testid = "clip-cleanup-run-btn";
    this.cleanupRunBtnEl.addEventListener("click", () => void this.handleCleanup(false));

    cleanupRow2.append(this.cleanupPreviewBtnEl, this.cleanupRunBtnEl);

    this.cleanupPreviewEl = document.createElement("div");
    this.cleanupPreviewEl.className = "clip-cleanup-preview hidden";
    this.cleanupPreviewEl.dataset.testid = "clip-cleanup-preview";

    this.cleanupPanelEl.append(cleanupRow1, cleanupRow2, this.cleanupPreviewEl);

    // Composer
    const composer = document.createElement("div");
    composer.className = "clip-composer";

    this.composerInputEl = document.createElement("textarea");
    this.composerInputEl.className = "input clip-composer-input";
    this.composerInputEl.rows = 2;
    this.composerInputEl.placeholder = t("clip.placeholder");
    this.composerInputEl.dataset.testid = "clip-send-text";
    this.composerInputEl.addEventListener("input", () => {
      if (this.errorMessage) this.setError(null);
    });
    this.composerInputEl.addEventListener("keydown", (ev) => {
      if ((ev.metaKey || ev.ctrlKey) && ev.key === "Enter") {
        ev.preventDefault();
        void this.handleSendText();
      }
    });
    this.composerInputEl.addEventListener("paste", (ev) => {
      const cd = ev.clipboardData;
      if (!cd) return;
      const imageFile = this.extractPastedImageFile(cd);
      if (imageFile) {
        ev.preventDefault();
        void this.handleSendImageFile(imageFile);
      }
    });

    const controlsRow = document.createElement("div");
    controlsRow.className = "clip-composer-controls";

    const ephLabel = document.createElement("label");
    ephLabel.className = "dialog-check clip-ephemeral-check";
    this.ephemeralCheckEl = document.createElement("input");
    this.ephemeralCheckEl.type = "checkbox";
    this.ephemeralCheckEl.dataset.testid = "clip-send-ephemeral";
    this.ephemeralTextEl = document.createElement("span");
    this.ephemeralTextEl.textContent = t("clip.ephemeral");
    ephLabel.append(this.ephemeralCheckEl, this.ephemeralTextEl);

    const btnCluster = document.createElement("div");
    btnCluster.className = "clip-composer-buttons";

    this.fileLabelEl = document.createElement("label");
    this.fileLabelEl.className = "btn btn-icon btn-has-icon clip-file-label";
    this.fileLabelEl.title = t("clip.pickImageTitle");
    this.fileInputEl = document.createElement("input");
    this.fileInputEl.type = "file";
    this.fileInputEl.className = "sr-only";
    this.fileInputEl.accept = "image/png,image/jpeg,image/webp,image/gif";
    this.fileInputEl.dataset.testid = "clip-send-image";
    this.fileInputEl.addEventListener("change", () => {
      const file = this.fileInputEl.files?.[0];
      this.fileInputEl.value = "";
      if (file) {
        void this.handleSendImageFile(file);
      }
    });
    this.fileLabelTextEl = document.createElement("span");
    this.fileLabelTextEl.textContent = t("clip.pickImage");
    this.fileLabelEl.append(createIcon("image", "xs"), this.fileLabelTextEl, this.fileInputEl);

    this.sendBtnEl = document.createElement("button");
    this.sendBtnEl.type = "button";
    this.sendBtnEl.className = "btn btn-primary btn-icon btn-has-icon";
    this.sendBtnEl.dataset.testid = "clip-send-submit";
    this.sendBtnEl.addEventListener("click", () => void this.handleSendText());

    btnCluster.append(this.fileLabelEl, this.sendBtnEl);
    controlsRow.append(ephLabel, btnCluster);

    this.errorEl = document.createElement("div");
    this.errorEl.className = "clip-error hidden";
    this.errorEl.dataset.testid = "clip-error";
    this.errorEl.setAttribute("role", "alert");

    composer.append(this.composerInputEl, controlsRow, this.errorEl);

    // Kind filter & search bar
    this.filterBarEl = document.createElement("div");
    this.filterBarEl.className = "clip-filter-bar";

    this.searchInputEl = document.createElement("input");
    this.searchInputEl.type = "search";
    this.searchInputEl.className = "input clip-search-input";
    this.searchInputEl.placeholder = t("clip.searchPlaceholder");
    this.searchInputEl.dataset.testid = "clip-search-input";
    this.searchInputEl.addEventListener("input", () => {
      this.searchQuery = this.searchInputEl.value;
      if (this.searchTimer !== null) window.clearTimeout(this.searchTimer);
      this.searchTimer = window.setTimeout(() => {
        this.searchTimer = null;
        void this.refresh({ silent: true });
      }, 180);
    });

    this.filterSegEl = document.createElement("div");
    this.filterSegEl.className = "mode-seg clip-filter-seg";
    this.filterBarEl.append(this.searchInputEl, this.filterSegEl);

    // Paginated archive list
    this.listEl = document.createElement("div");
    this.listEl.className = "drawer-list clip-list";
    this.listEl.dataset.testid = "clip-list";

    this.element.append(
      hdr,
      actionsRow,
      watchBar,
      this.storageBarEl,
      this.cleanupPanelEl,
      composer,
      this.filterBarEl,
      this.listEl,
    );

    // Image Preview Modal
    this.previewModalEl = document.createElement("div");
    this.previewModalEl.className = "modal clip-preview-modal";
    this.previewModalEl.setAttribute("role", "dialog");
    this.previewModalEl.setAttribute("aria-modal", "true");
    const previewHdr = document.createElement("div");
    previewHdr.className = "drawer-header";
    this.previewTitleEl = document.createElement("span");
    this.previewTitleEl.className = "drawer-header-title";
    this.previewTitleEl.textContent = t("clip.previewModalTitle");
    this.previewCloseBtnEl = document.createElement("button");
    this.previewCloseBtnEl.type = "button";
    this.previewCloseBtnEl.className = "btn btn-ghost btn-icon btn-icon-only";
    this.previewCloseBtnEl.dataset.testid = "clip-preview-close";
    this.previewCloseBtnEl.setAttribute("aria-label", t("topbar.close"));
    this.previewCloseBtnEl.title = t("topbar.close");
    const pSr = document.createElement("span");
    pSr.className = "sr-only";
    pSr.textContent = t("topbar.close");
    this.previewCloseBtnEl.append(createIcon("x", "xs"), pSr);
    this.previewCloseBtnEl.addEventListener("click", () => this.closeImagePreview());
    previewHdr.append(this.previewTitleEl, this.previewCloseBtnEl);

    this.previewBodyEl = document.createElement("div");
    this.previewBodyEl.className = "clip-preview-body";
    this.previewModalEl.append(previewHdr, this.previewBodyEl);
    this.previewBackdropEl.appendChild(this.previewModalEl);

    this.renderHeaderState();
    this.renderStorageBar();
    this.renderCleanupPanel();
    this.renderFilterBar();
    this.renderList();
  }

  private extractPastedImageFile(cd: DataTransfer): File | null {
    if (cd.files && cd.files.length > 0) {
      for (let i = 0; i < cd.files.length; i++) {
        const f = cd.files[i];
        if (f && (f.type.toLowerCase().startsWith("image/") || f.name.toLowerCase().endsWith(".svg"))) {
          return f;
        }
      }
    }
    if (cd.items && cd.items.length > 0) {
      for (let i = 0; i < cd.items.length; i++) {
        const item = cd.items[i];
        if (item.kind === "file" && item.type.toLowerCase().startsWith("image/")) {
          const f = item.getAsFile();
          if (f) return f;
        }
      }
    }
    return null;
  }

  private setError(msg: string | null): void {
    this.errorMessage = msg;
    if (!msg) {
      this.errorEl.textContent = "";
      this.errorEl.classList.add("hidden");
    } else {
      this.errorEl.replaceChildren(createIcon("alert-triangle", "xs"), document.createTextNode(msg));
      this.errorEl.classList.remove("hidden");
    }
  }

  private renderHeaderState(): void {
    const shownCount = Math.max(this.totalCount, this.items.length);
    this.countPillEl.textContent = t("clip.count", { count: shownCount });

    this.undoBtnEl.disabled = !this.hasUndo;
    this.undoBtnEl.title = t("clip.undoTitle");
    const undoLbl = document.createElement("span");
    undoLbl.textContent = t("clip.undo");
    this.undoBtnEl.replaceChildren(createIcon("rotate-ccw", "xs"), undoLbl);

    this.cleanupToggleBtnEl.setAttribute("aria-expanded", String(this.cleanupOpen));
    this.cleanupToggleBtnEl.textContent = t("clip.cleanup");

    this.watchBtnEl.setAttribute("aria-pressed", String(this.watchEnabled));
    this.watchBtnEl.className = `btn btn-icon btn-has-icon${
      !this.watchEnabled ? "" : this.watchPaused ? " btn-amber" : " btn-accent-soft"
    }`;
    this.watchBtnEl.title = this.watchEnabled ? t("clip.watchDisableTitle") : t("clip.watchEnableTitle");
    const watchLbl = document.createElement("span");
    watchLbl.textContent = this.watchEnabled ? t("clip.watchOn") : t("clip.watchOff");
    this.watchBtnEl.replaceChildren(
      createIcon(this.watchEnabled ? (this.watchPaused ? "pause" : "check-circle") : "play", "xs"),
      watchLbl,
    );

    this.watchPauseBtnEl.classList.toggle("hidden", !this.watchEnabled);
    this.watchPauseBtnEl.setAttribute("aria-pressed", String(this.watchPaused));
    this.watchPauseBtnEl.className = `btn btn-icon btn-has-icon${
      this.watchPaused ? " btn-amber" : " btn-ghost"
    }${this.watchEnabled ? "" : " hidden"}`;
    this.watchPauseBtnEl.title = this.watchPaused ? t("clip.watchPaused") : t("clip.watchActive");
    const pauseLbl = document.createElement("span");
    pauseLbl.textContent = this.watchPaused ? t("clip.watchResumeShort") : t("clip.watchPauseShort");
    this.watchPauseBtnEl.replaceChildren(createIcon(this.watchPaused ? "play" : "pause", "xs"), pauseLbl);

    const isAutoApply = this.autoApplyMirror === "auto-apply";
    this.watchModeBtnEl.className = `btn btn-ghost btn-icon clip-watch-mode-btn${
      this.watchEnabled ? "" : " hidden"
    }`;
    this.watchModeBtnEl.dataset.mode = this.autoApplyMirror;
    this.watchModeBtnEl.textContent = isAutoApply
      ? t("clip.watchModeAutoApply")
      : t("clip.watchModeInbox");
    this.watchModeBtnEl.title = isAutoApply
      ? t("clip.watchModeAutoApplyTitle")
      : t("clip.watchModeInboxTitle");

    this.clearBtnEl.disabled = this.items.length === 0 && this.totalCount === 0;
    this.clearBtnEl.textContent = t("clip.clearAll");

    this.sendBtnEl.disabled = this.sending;
    this.sendBtnEl.title = `${t("clip.send")} (${formatShortcutTitle(SHORTCUT_NEW_BLOCK)})`;
    const sendLbl = document.createElement("span");
    sendLbl.textContent = this.sending ? t("clip.sending") : t("clip.send");
    this.sendBtnEl.replaceChildren(createIcon("send", "xs"), sendLbl);
  }

  private renderStorageBar(): void {
    this.storageBarEl.replaceChildren();
    const row = document.createElement("div");
    row.className = "clip-storage-row";

    const localSpan = document.createElement("span");
    localSpan.textContent = t("clip.storageLocal", {
      count: Math.max(this.totalCount, this.items.length),
      bytes: formatClipBytes(this.localBlobBytes) || "0 B",
    });
    row.appendChild(localSpan);

    if (this.cloudQuota) {
      const q = this.cloudQuota;
      const cloudSpan = document.createElement("span");
      cloudSpan.textContent = t("clip.storageCloud", {
        used: formatClipBytes(q.used_bytes) || "0 B",
        limit: formatClipBytes(q.limit_bytes) || "5.00 GiB",
        items: q.item_count,
        max: q.item_limit,
      });
      row.appendChild(cloudSpan);
    }
    this.storageBarEl.appendChild(row);

    if (this.cloudQuota && this.cloudQuota.limit_bytes > 0) {
      const ratio = this.cloudQuota.used_bytes / this.cloudQuota.limit_bytes;
      const pct = Math.min(100, Math.round(ratio * 100));
      const meter = document.createElement("progress");
      meter.className = `clip-quota-meter${ratio >= 1 ? " is-full" : ratio >= CLIP_CLOUD_QUOTA_WARN_RATIO ? " is-warn" : ""}`;
      meter.max = 100;
      meter.value = pct;
      meter.dataset.testid = "clip-quota-meter";
      this.storageBarEl.appendChild(meter);

      if (ratio >= CLIP_CLOUD_QUOTA_WARN_RATIO) {
        const warn = document.createElement("div");
        warn.className = `clip-quota-warn${ratio >= 1 ? " is-full" : ""}`;
        warn.dataset.testid = "clip-quota-warn";
        warn.textContent = ratio >= 1 ? t("clip.quotaFull") : t("clip.quotaWarn");
        this.storageBarEl.appendChild(warn);
      }
    }
  }

  private renderCleanupPanel(): void {
    this.cleanupPanelEl.classList.toggle("hidden", !this.cleanupOpen);
    this.cleanupToggleBtnEl.setAttribute("aria-expanded", String(this.cleanupOpen));

    const scopes: readonly { value: ClipScope; label: string }[] = [
      { value: "local", label: t("clip.cleanupScopeLocal") },
      { value: "cloud", label: t("clip.cleanupScopeCloud") },
      { value: "all", label: t("clip.cleanupScopeAll") },
    ];
    this.cleanupScopeSelEl.replaceChildren();
    for (const sc of scopes) {
      const opt = document.createElement("option");
      opt.value = sc.value;
      opt.textContent = sc.label;
      opt.selected = sc.value === this.cleanupScope;
      this.cleanupScopeSelEl.appendChild(opt);
    }

    const rules: readonly { value: CleanupRuleKey; label: string }[] = [
      { value: "30d", label: t("clip.cleanupRule30d") },
      { value: "7d", label: t("clip.cleanupRule7d") },
      { value: "keep200", label: t("clip.cleanupRuleKeep200") },
      { value: "images", label: t("clip.cleanupRuleImages") },
      { value: "all", label: t("clip.cleanupRuleAll") },
    ];
    this.cleanupRuleSelEl.replaceChildren();
    for (const r of rules) {
      const opt = document.createElement("option");
      opt.value = r.value;
      opt.textContent = r.label;
      opt.selected = r.value === this.cleanupRule;
      this.cleanupRuleSelEl.appendChild(opt);
    }

    this.cleanupPreviewBtnEl.textContent = t("clip.cleanupPreview");
    this.cleanupPreviewBtnEl.disabled = this.cleanupBusy || this.cleanupRule === "all";
    this.cleanupRunBtnEl.textContent = t("clip.cleanupExecute");
    this.cleanupRunBtnEl.disabled = this.cleanupBusy;

    if (this.cleanupPreviewText) {
      this.cleanupPreviewEl.textContent = this.cleanupPreviewText;
      this.cleanupPreviewEl.classList.remove("hidden");
    } else {
      this.cleanupPreviewEl.textContent = "";
      this.cleanupPreviewEl.classList.add("hidden");
    }
  }

  private renderFilterBar(): void {
    this.filterSegEl.replaceChildren();
    const modes: readonly { key: "all" | ClipKind; label: string }[] = [
      { key: "all", label: t("clip.filterAll") },
      { key: "text", label: t("clip.filterText") },
      { key: "image", label: t("clip.filterImage") },
    ];
    for (const m of modes) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn mode-seg-btn";
      btn.dataset.testid = `clip-filter-${m.key}`;
      btn.setAttribute("aria-pressed", String(this.filterKind === m.key));
      btn.textContent = m.label;
      btn.addEventListener("click", () => {
        this.filterKind = m.key;
        this.renderFilterBar();
        if (this.searchQuery.trim() || this.hasMore) {
          void this.refresh({ silent: true });
        } else {
          this.renderList();
        }
      });
      this.filterSegEl.appendChild(btn);
    }
  }

  private renderList(): void {
    this.listEl.replaceChildren();
    const visible =
      this.filterKind === "all" ? this.items : this.items.filter((i) => i.kind === this.filterKind);
    if (visible.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = t("clip.empty");
      this.listEl.appendChild(empty);
      return;
    }

    for (const item of visible) {
      this.listEl.appendChild(this.renderClipCard(item));
    }

    if (this.hasMore) {
      const moreBtn = document.createElement("button");
      moreBtn.type = "button";
      moreBtn.className = "btn btn-ghost clip-load-more";
      moreBtn.dataset.testid = "clip-load-more";
      moreBtn.disabled = this.loadingMore;
      moreBtn.textContent = this.loadingMore ? t("clip.loadingMore") : t("clip.loadMore");
      moreBtn.addEventListener("click", () => void this.refresh({ append: true }));
      this.listEl.appendChild(moreBtn);
    }
  }

  private renderClipCard(item: ClipItemDto): HTMLElement {
    const card = document.createElement("article");
    card.className = "clip-item";
    card.dataset.clipId = item.clip_id;
    card.dataset.clipKind = item.kind;

    const metaRow = document.createElement("div");
    metaRow.className = "clip-item-meta";

    const badges = document.createElement("div");
    badges.className = "clip-item-badges";

    const kindBadge = document.createElement("span");
    kindBadge.className = "clip-badge";
    kindBadge.textContent = item.kind === "image" ? item.mime.replace(/^image\//, "").toUpperCase() : t("clip.kindText");
    badges.appendChild(kindBadge);

    if (item.source_mode === "auto") {
      const autoBadge = document.createElement("span");
      autoBadge.className = "clip-badge clip-badge-auto";
      autoBadge.textContent = t("clip.sourceAuto");
      badges.appendChild(autoBadge);
    }

    if (item.width && item.height) {
      const dimBadge = document.createElement("span");
      dimBadge.className = "clip-meta-detail";
      dimBadge.textContent = `${item.width}x${item.height}`;
      badges.appendChild(dimBadge);
    }

    if (item.blob_bytes !== null && item.blob_bytes > 0) {
      const szBadge = document.createElement("span");
      szBadge.className = "clip-meta-detail";
      szBadge.textContent = formatClipBytes(item.blob_bytes);
      badges.appendChild(szBadge);
    }

    const origin = document.createElement("span");
    origin.className = "clip-meta-origin";
    const devLabel = formatDeviceName(item.device_id);
    const tsLabel = formatHistoryTimestamp(item.created_at_ms);
    origin.textContent = devLabel && tsLabel ? `${devLabel} · ${tsLabel}` : devLabel || tsLabel;
    if (item.created_at_ms > 0) {
      origin.title = new Date(item.created_at_ms).toISOString();
    }

    metaRow.append(badges, origin);
    card.appendChild(metaRow);

    if (item.kind === "image") {
      const body = document.createElement("div");
      body.className = "clip-image-body";
      // Strictly verify bitmap data URL — NEVER render image/svg+xml!
      if (isSafeThumbDataUrl(item.thumb_data_url)) {
        const imgBtn = document.createElement("button");
        imgBtn.type = "button";
        imgBtn.className = "clip-thumb-btn";
        imgBtn.addEventListener("click", () => void this.handlePreviewImage(item));
        const img = document.createElement("img");
        img.className = "clip-thumb-img";
        img.src = item.thumb_data_url!;
        img.alt = t("clip.kindImage");
        imgBtn.appendChild(img);
        body.appendChild(imgBtn);
      } else {
        const placeholder = document.createElement("div");
        placeholder.className = "clip-thumb-placeholder";
        placeholder.append(createIcon("image", "sm"), document.createTextNode(item.mime));
        body.appendChild(placeholder);
      }
      card.appendChild(body);
    } else {
      const pre = document.createElement("pre");
      pre.className = "clip-text-preview";
      pre.textContent = item.text_preview ?? "";
      card.appendChild(pre);
    }

    const actions = document.createElement("div");
    actions.className = "clip-item-actions";

    const applyBtn = document.createElement("button");
    applyBtn.type = "button";
    applyBtn.className = "btn btn-icon btn-has-icon";
    applyBtn.dataset.testid = `clip-apply-${item.clip_id}`;
    applyBtn.title = t("clip.applyTitle");
    const applyLbl = document.createElement("span");
    applyLbl.textContent = t("clip.apply");
    applyBtn.append(createIcon("copy", "xs"), applyLbl);
    applyBtn.addEventListener("click", () => void this.handleApply(item));
    actions.appendChild(applyBtn);

    if (item.kind === "image") {
      const prevBtn = document.createElement("button");
      prevBtn.type = "button";
      prevBtn.className = "btn btn-ghost btn-icon btn-has-icon";
      prevBtn.dataset.testid = `clip-preview-${item.clip_id}`;
      const prevLbl = document.createElement("span");
      prevLbl.textContent = t("clip.preview");
      prevBtn.append(createIcon("eye", "xs"), prevLbl);
      prevBtn.addEventListener("click", () => void this.handlePreviewImage(item));
      actions.appendChild(prevBtn);

      const saveBtn = document.createElement("button");
      saveBtn.type = "button";
      saveBtn.className = "btn btn-ghost btn-icon btn-has-icon";
      saveBtn.dataset.testid = `clip-save-${item.clip_id}`;
      const saveLbl = document.createElement("span");
      saveLbl.textContent = t("clip.saveAs");
      saveBtn.append(createIcon("download", "xs"), saveLbl);
      saveBtn.addEventListener("click", () => void this.handleSaveAs(item));
      actions.appendChild(saveBtn);
    } else {
      // Promote to Note Block is text items ONLY!
      const promoteBtn = document.createElement("button");
      promoteBtn.type = "button";
      promoteBtn.className = "btn btn-ghost btn-icon btn-has-icon";
      promoteBtn.dataset.testid = `clip-promote-${item.clip_id}`;
      promoteBtn.title = t("clip.promoteTitle");
      const promLbl = document.createElement("span");
      promLbl.textContent = t("clip.promote");
      promoteBtn.append(createIcon("file-plus", "xs"), promLbl);
      promoteBtn.addEventListener("click", () => void this.handlePromote(item));
      actions.appendChild(promoteBtn);
    }

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "btn btn-ghost btn-danger btn-icon btn-icon-only";
    delBtn.dataset.testid = `clip-delete-${item.clip_id}`;
    delBtn.title = t("clip.delete");
    delBtn.setAttribute("aria-label", t("clip.delete"));
    const delSr = document.createElement("span");
    delSr.className = "sr-only";
    delSr.textContent = t("clip.delete");
    delBtn.append(createIcon("trash", "xs"), delSr);
    delBtn.addEventListener("click", () => void this.handleDelete(item));
    actions.appendChild(delBtn);

    card.appendChild(actions);
    return card;
  }

  private async handleSendText(): Promise<void> {
    if (this.sending) return;
    if (!this.api.pushClipText) {
      this.setError(t("clip.errApiUnavailable"));
      return;
    }
    const text = this.composerInputEl.value;
    if (!text.length) {
      this.setError(t("clip.errEmpty"));
      return;
    }
    const ephemeral = this.ephemeralCheckEl.checked;
    const byteLen = new TextEncoder().encode(text).byteLength;
    if (ephemeral && byteLen > CLIP_EPHEMERAL_MAX_BYTES) {
      this.setError(t("clip.errEphemeralTooLarge"));
      return;
    }
    if (byteLen > 10 * 1024 * 1024) {
      this.setError(t("clip.errTooLarge"));
      return;
    }
    this.setError(null);
    this.sending = true;
    this.renderHeaderState();
    try {
      const res = await this.api.pushClipText({ text, ephemeral });
      this.composerInputEl.value = "";
      this.ephemeralCheckEl.checked = false;
      if (res.item) {
        this.upsertItemLocal(res.item);
      }
      if (res.ephemeral) {
        this.cb.onFeedback(t("clip.toastSentEphemeral", { count: res.delivered_to ?? 0 }));
      } else {
        this.cb.onFeedback(t("clip.toastSent"));
      }
    } catch (e) {
      this.handleUploadError(e);
    } finally {
      this.sending = false;
      this.renderHeaderState();
    }
  }

  private handleUploadError(e: unknown): void {
    if (e instanceof LocalApiError && e.body.code === "CLIP_QUOTA_EXCEEDED") {
      this.setError(t("clip.quotaFull"));
      this.cleanupOpen = true;
      this.cleanupScope = "cloud";
      this.cleanupRule = "images";
      this.cleanupPreviewText = "";
      this.renderCleanupPanel();
    }
    this.cb.onError(e);
  }

  private async handleSendImageFile(file: File): Promise<void> {
    if (this.sending) return;
    const effectiveMime =
      file.type || (file.name.toLowerCase().endsWith(".svg") ? "image/svg+xml" : "");
    const check = validateClipImageFile(effectiveMime, file.size);
    if (!check.ok) {
      if (check.reason === "svg") {
        this.setError(t("clip.errSvgRejected"));
      } else if (check.reason === "size") {
        this.setError(t("clip.errTooLarge"));
      } else if (check.reason === "empty") {
        this.setError(t("clip.errEmpty"));
      } else {
        this.setError(t("clip.errUnsupportedMime", { mime: check.mime }));
      }
      return;
    }
    if (!this.api.pushClipImage) {
      this.setError(t("clip.errApiUnavailable"));
      return;
    }
    this.setError(null);
    this.sending = true;
    this.renderHeaderState();
    try {
      const rawBytes = new Uint8Array(await file.arrayBuffer());
      const thumb = await generateBitmapThumbnail(file, check.mime);
      const res = await this.api.pushClipImage({
        mime: check.mime,
        data_b64: bytesToBase64Chunked(rawBytes),
        ...(thumb.width !== null ? { width: thumb.width } : {}),
        ...(thumb.height !== null ? { height: thumb.height } : {}),
        ...(thumb.thumb_mime && thumb.thumb_b64
          ? { thumb_mime: thumb.thumb_mime, thumb_b64: thumb.thumb_b64 }
          : {}),
      });
      if (res.item) {
        this.upsertItemLocal(res.item);
      }
      this.cb.onFeedback(t("clip.toastSent"));
    } catch (e) {
      this.handleUploadError(e);
    } finally {
      this.sending = false;
      this.renderHeaderState();
    }
  }

  private upsertItemLocal(item: ClipItemDto): void {
    const existed = this.items.some((x) => x.clip_id === item.clip_id);
    const next = this.items.filter((x) => x.clip_id !== item.clip_id);
    next.unshift(item);
    this.items = sortClipsDesc(next);
    if (!existed) {
      this.totalCount = Math.max(this.items.length, this.totalCount + 1);
    }
    this.cb.onCountChange?.(this.totalCount);
    this.renderHeaderState();
    this.renderStorageBar();
    this.renderList();
  }

  private async handleApply(item: ClipItemDto): Promise<void> {
    if (!this.api.applyClip) return;
    try {
      const res = await this.api.applyClip(item.clip_id);
      this.hasUndo = res.has_undo;
      this.renderHeaderState();
      this.cb.onFeedback(t("clip.toastApplied"));
    } catch (e) {
      this.cb.onError(e);
    }
  }

  private async handlePreviewImage(item: ClipItemDto): Promise<void> {
    if (!this.api.getClipBlob) return;
    this.closeImagePreview();
    const seq = ++this.previewReqSeq;
    this.previewBackdropEl.classList.remove("hidden");
    const loading = document.createElement("div");
    loading.className = "clip-preview-loading";
    loading.textContent = t("clip.loadingPreview");
    this.previewBodyEl.replaceChildren(loading);
    try {
      const { blob, contentType } = await this.api.getClipBlob(item.clip_id);
      if (seq !== this.previewReqSeq || this.previewBackdropEl.classList.contains("hidden")) {
        return;
      }
      const check = validateClipImageFile(contentType || item.mime, blob.size);
      if (!check.ok) {
        this.closeImagePreview();
        this.setError(check.reason === "svg" ? t("clip.errSvgRejected") : t("clip.errUnsupportedMime", { mime: check.mime }));
        return;
      }
      const safeBlob = blob.type === check.mime ? blob : new Blob([blob], { type: check.mime });
      const objUrl = URL.createObjectURL(safeBlob);
      this.activePreviewUrl = objUrl;
      const img = document.createElement("img");
      img.className = "clip-preview-img";
      img.src = objUrl;
      img.alt = t("clip.previewModalTitle");
      this.previewBodyEl.replaceChildren(img);
    } catch (e) {
      if (seq === this.previewReqSeq) {
        this.closeImagePreview();
        this.cb.onError(e);
      }
    }
  }

  private async handleSaveAs(item: ClipItemDto): Promise<void> {
    if (!this.api.getClipBlob) return;
    try {
      const { blob, contentType } = await this.api.getClipBlob(item.clip_id);
      const ext = extForClipMime(contentType || item.mime);
      const objUrl = URL.createObjectURL(blob);
      try {
        const a = document.createElement("a");
        a.href = objUrl;
        a.download = `clip-${item.clip_id}.${ext}`;
        a.className = "sr-only";
        document.body.appendChild(a);
        a.click();
        a.remove();
      } finally {
        URL.revokeObjectURL(objUrl);
      }
    } catch (e) {
      this.cb.onError(e);
    }
  }

  private async handlePromote(item: ClipItemDto): Promise<void> {
    if (!this.api.promoteClip || item.kind !== "text") return;
    try {
      const bufId = this.cb.getActiveBufferId();
      const res = await this.api.promoteClip(item.clip_id, bufId ? { buffer_id: bufId } : {});
      this.cb.onBlockPromoted(res.block);
      this.cb.onFeedback(t("clip.toastPromoted"));
    } catch (e) {
      this.cb.onError(e);
    }
  }

  private async handleDelete(item: ClipItemDto): Promise<void> {
    if (!this.api.deleteClip) return;
    try {
      const res = await this.api.deleteClip(item.clip_id);
      const beforeLen = this.items.length;
      this.items = this.items.filter((x) => x.clip_id !== item.clip_id);
      if (this.items.length < beforeLen) {
        this.totalCount = Math.max(this.items.length, this.totalCount - 1);
      }
      if (res.cloud_quota !== undefined) {
        this.cloudQuota = res.cloud_quota;
      }
      this.cb.onCountChange?.(this.totalCount);
      this.renderHeaderState();
      this.renderStorageBar();
      this.renderList();
      this.cb.onFeedback(t("clip.toastDeleted"));
    } catch (e) {
      this.cb.onError(e);
    }
  }

  private async handleUndo(): Promise<void> {
    if (!this.api.undoClip) return;
    try {
      const res = await this.api.undoClip();
      if (res.restored) {
        this.hasUndo = false;
        this.renderHeaderState();
        this.cb.onFeedback(t("clip.toastUndone"));
      }
    } catch (e) {
      this.cb.onError(e);
    }
  }

  private async handleClearAll(): Promise<void> {
    if (!this.api.clearClips) return;
    try {
      const res = await this.api.clearClips();
      this.items = [];
      this.totalCount = 0;
      this.hasMore = false;
      this.localBlobBytes = 0;
      if (res.cloud_quota !== undefined) {
        this.cloudQuota = res.cloud_quota;
      }
      this.cb.onCountChange?.(0);
      this.renderHeaderState();
      this.renderStorageBar();
      this.renderList();
      this.cb.onFeedback(t("clip.toastCleared"));
    } catch (e) {
      this.cb.onError(e);
    }
  }

  private buildPruneInput(dryRun: boolean): ClipPruneInput {
    const base: ClipPruneInput = { scope: this.cleanupScope, dry_run: dryRun };
    switch (this.cleanupRule) {
      case "30d":
        return { ...base, before_days: 30 };
      case "7d":
        return { ...base, before_days: 7 };
      case "keep200":
        return { ...base, keep_latest: 200 };
      case "images":
        return { ...base, kind: "image" };
      case "all":
        return base;
    }
  }

  private async handleCleanup(dryRun: boolean): Promise<void> {
    if (this.cleanupBusy) return;
    this.cleanupBusy = true;
    this.renderCleanupPanel();
    try {
      if (this.cleanupRule === "all") {
        if (!this.api.clearClips) return;
        const res = await this.api.clearClips(this.cleanupScope);
        if (res.cloud_quota !== undefined) {
          this.cloudQuota = res.cloud_quota;
        }
        if (this.cleanupScope !== "cloud") {
          this.items = [];
          this.totalCount = 0;
          this.hasMore = false;
          this.localBlobBytes = 0;
          this.cb.onCountChange?.(0);
        }
        this.cleanupPreviewText = "";
        this.setError(null);
        this.renderHeaderState();
        this.renderStorageBar();
        this.renderList();
        this.cb.onFeedback(
          t("clip.toastPruned", {
            count: res.deleted_count,
            bytes: formatClipBytes(res.freed_bytes ?? 0) || "0 B",
          }),
        );
        return;
      }

      if (!this.api.pruneClips) {
        this.setError(t("clip.errApiUnavailable"));
        return;
      }
      const res = await this.api.pruneClips(this.buildPruneInput(dryRun));
      if (res.cloud_quota !== undefined) {
        this.cloudQuota = res.cloud_quota;
      }
      if (dryRun) {
        this.cleanupPreviewText =
          res.matched_count > 0
            ? t("clip.cleanupPreviewResult", {
                count: res.matched_count,
                bytes: formatClipBytes(res.freed_bytes) || "0 B",
              })
            : t("clip.cleanupPreviewNone");
      } else {
        this.cleanupPreviewText = "";
        this.setError(null);
        await this.refresh({ silent: true });
        this.cb.onFeedback(
          t("clip.toastPruned", {
            count: res.deleted_count,
            bytes: formatClipBytes(res.freed_bytes) || "0 B",
          }),
        );
      }
      this.renderStorageBar();
    } catch (e) {
      this.cb.onError(e);
    } finally {
      this.cleanupBusy = false;
      this.renderCleanupPanel();
    }
  }

  private async handleToggleWatchEnabled(): Promise<void> {
    if (!this.api.patchClipWatch) return;
    try {
      const nextEnabled = !this.watchEnabled;
      const res = await this.api.patchClipWatch({ enabled: nextEnabled, paused: false });
      this.watchEnabled = res.watch_enabled;
      this.watchPaused = res.watch_paused;
      this.autoApplyMirror = res.auto_apply_mirror;
      this.renderHeaderState();
      this.cb.onFeedback(this.watchEnabled ? t("clip.toastWatchEnabled") : t("clip.toastWatchDisabled"));
    } catch (e) {
      this.cb.onError(e);
    }
  }

  private async handleToggleWatchPaused(): Promise<void> {
    if (!this.api.patchClipWatch || !this.watchEnabled) return;
    try {
      const nextPaused = !this.watchPaused;
      const res = await this.api.patchClipWatch({ paused: nextPaused });
      this.watchEnabled = res.watch_enabled;
      this.watchPaused = res.watch_paused;
      this.autoApplyMirror = res.auto_apply_mirror;
      this.renderHeaderState();
      this.cb.onFeedback(this.watchPaused ? t("clip.toastWatchPaused") : t("clip.toastWatchResumed"));
    } catch (e) {
      this.cb.onError(e);
    }
  }

  private async handleToggleWatchMode(): Promise<void> {
    if (!this.api.patchClipWatch || !this.watchEnabled) return;
    try {
      const nextMode: ClipAutoApplyMirrorMode =
        this.autoApplyMirror === "auto-apply" ? "inbox-only" : "auto-apply";
      const res = await this.api.patchClipWatch({ auto_apply_mirror: nextMode });
      this.watchEnabled = res.watch_enabled;
      this.watchPaused = res.watch_paused;
      this.autoApplyMirror = res.auto_apply_mirror;
      this.renderHeaderState();
      this.cb.onFeedback(
        this.autoApplyMirror === "auto-apply"
          ? t("clip.toastWatchModeAutoApply")
          : t("clip.toastWatchModeInbox"),
      );
    } catch (e) {
      this.cb.onError(e);
    }
  }
}
