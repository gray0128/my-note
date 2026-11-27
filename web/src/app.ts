import { LocalApiError, type LocalApiClient, type Tier2WritePayload } from "./api";
import { ClipDrawerController } from "./components/clipDrawer";
import {
  createLocaleSwitch,
  createThemeMenu,
  type LocaleSwitchHandle,
  type ThemeMenuHandle,
} from "./components/themeMenu";
import { BlockStreamController, type SaveContentResult } from "./editor";
import {
  formatDeviceName,
  formatHistoryTimestamp,
  formatLocalDateTime,
  formatOpTypeLabel,
  formatShredStateLabel,
  subscribeLocale,
  syncDocumentLocale,
  t,
} from "./i18n";
import { createIcon, type IconName } from "./icons";
import { computeLineDiff } from "./render/diff";
import { copyDualFormat } from "./render/markdown";
import {
  createShortcutHint,
  formatShortcutTitle,
  SHORTCUT_CLIPBOARD,
  SHORTCUT_COPY_BLOCK,
  SHORTCUT_EDGE_ARROWS,
  SHORTCUT_ESC,
  SHORTCUT_FIND,
  SHORTCUT_FORMAT,
  SHORTCUT_HELP,
  SHORTCUT_LANG,
  SHORTCUT_LOCK_VAULT,
  SHORTCUT_MARKDOWN_MODE,
  SHORTCUT_MOVE_BLOCK_PAIR,
  SHORTCUT_NEW_BLOCK,
  SHORTCUT_SWITCH_BLOCK_PAIR,
  SHORTCUT_SWITCH_BUFFER,
  type ShortcutKeyToken,
} from "./shortcuts";
import { initTheme } from "./theme";
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
  private lastFindMatchCount = 0;
  private lastTrashCount = 0;
  private bufferFilterQuery = "";
  private bufferActiveIndex = 0;
  private creatingBuffer = false;
  private vaultFieldSeq = 0;
  private knownBufferBlockCounts = new Map<string, number>();
  private disconnectWs: (() => void) | null = null;
  private toastTimer: number | null = null;
  private themeMenu!: ThemeMenuHandle;
  private localeSwitch!: LocaleSwitchHandle;
  private unsubLocale: (() => void) | null = null;

  private bufferTabsEl!: HTMLElement;
  private switcherBtnEl!: HTMLButtonElement;
  private switcherLabelEl!: HTMLSpanElement;
  private newBlkBtnEl!: HTMLButtonElement;
  private newBlkLabelEl!: HTMLSpanElement;
  private findBtnEl!: HTMLButtonElement;
  private findBtnLabelEl!: HTMLSpanElement;
  private vimBtnEl!: HTMLButtonElement;
  private vaultBtnEl!: HTMLButtonElement;
  private syncPillEl!: HTMLButtonElement;
  private syncIconEl!: HTMLSpanElement;
  private trashBtnEl!: HTMLButtonElement;
  private trashCountEl!: HTMLSpanElement;
  private clipInboxBtnEl!: HTMLButtonElement;
  private clipInboxLabelEl!: HTMLSpanElement;
  private clipInboxCountEl!: HTMLSpanElement;
  private shortcutsBtnEl!: HTMLButtonElement;
  private shortcutsBtnLabelEl!: HTMLSpanElement;
  private clipDrawer!: ClipDrawerController;
  private lastClipCount = 0;
  private initialDaemonVersion: string | null = null;
  private alertStackEl!: HTMLElement;
  private findBarEl!: HTMLElement;
  private findInputEl!: HTMLInputElement;
  private replaceInputEl!: HTMLInputElement;
  private findCountEl!: HTMLElement;
  private findPrevBtnEl!: HTMLButtonElement;
  private findNextBtnEl!: HTMLButtonElement;
  private findReplaceBtnEl!: HTMLButtonElement;
  private findCloseBtnEl!: HTMLButtonElement;
  private trashDrawerEl!: HTMLElement;
  private trashTitleEl!: HTMLSpanElement;
  private trashHeaderActionsEl!: HTMLElement;
  private trashCloseBtnEl!: HTMLButtonElement;
  private trashActionsEl!: HTMLElement;
  private trashListEl!: HTMLElement;
  private historyDrawerEl!: HTMLElement;
  private historyTitleEl!: HTMLElement;
  private historyHeaderActionsEl!: HTMLElement;
  private historyCloseBtnEl!: HTMLButtonElement;
  private historyActionsEl!: HTMLElement;
  private historyListEl!: HTMLElement;
  private historyDiffEl!: HTMLElement;
  private modalBackdropEl!: HTMLElement;
  private bufferModalEl!: HTMLElement;
  private bufferModalCloseBtnEl!: HTMLButtonElement;
  private bufferFilterInputEl!: HTMLInputElement;
  private modalListEl!: HTMLElement;
  private bufferFooterEl!: HTMLElement;
  private dialogBackdropEl!: HTMLElement;
  private dialogModalEl!: HTMLElement;
  private shortcutsBackdropEl!: HTMLElement;
  private shortcutsModalEl!: HTMLElement;
  private toastEl!: HTMLElement;
  public stream!: BlockStreamController;

  constructor(private root: HTMLElement, private api: LocalApiClient) {
    initTheme();
    syncDocumentLocale("app.title");
    this.buildShell();
    this.bindGlobalKeys();
    this.unsubLocale = subscribeLocale(() => this.applyLocale());
  }

  async start(): Promise<void> {
    const boot = await this.api.bootstrap();
    this.initialDaemonVersion = boot.daemon_version ?? null;
    this.setBuffers(boot.buffers);
    this.activeBufferId = boot.initial_buffer_id ?? this.buffers[0]?.id ?? null;
    this.syncStatus = boot.sync_status;
    this.vaultHeader = boot.vault_header ?? null;
    this.recoveryPkB64 = boot.recovery_pk_b64 ?? null;
    this.updateAlertsFromStatus(boot.sync_status);
    this.renderBuffers();
    this.renderVaultBtn();
    this.renderSyncPill();
    this.updateTrashCount(boot.trash_count);
    this.updateClipCount(boot.clip_count ?? 0);
    void this.clipDrawer.refresh({ silent: true });
    this.stream.setBlocks(boot.blocks);
    if (this.activeBufferId) {
      this.knownBufferBlockCounts.set(this.activeBufferId, boot.blocks.length);
    }

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
    this.unsubLocale?.();
    this.unsubLocale = null;
    this.themeMenu?.destroy();
    this.localeSwitch?.destroy();
    this.clipDrawer?.destroy();
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
      this.showToast(t("vault.toastLocked"));
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

  private createCloseButton(onClick: () => void, testId?: string): HTMLButtonElement {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btn-ghost btn-icon btn-icon-only";
    if (testId) btn.dataset.testid = testId;
    btn.setAttribute("aria-label", t("topbar.close"));
    btn.title = t("topbar.close");
    const sr = document.createElement("span");
    sr.className = "sr-only";
    sr.textContent = t("topbar.close");
    btn.append(createIcon("x", "xs"), sr);
    btn.addEventListener("click", onClick);
    return btn;
  }

  private updateCloseButtonLocale(btn: HTMLButtonElement): void {
    btn.setAttribute("aria-label", t("topbar.close"));
    btn.title = t("topbar.close");
    const sr = btn.querySelector<HTMLElement>(".sr-only");
    if (sr) sr.textContent = t("topbar.close");
  }

  private createTopbarSep(): HTMLSpanElement {
    const sep = document.createElement("span");
    sep.className = "topbar-sep";
    sep.setAttribute("aria-hidden", "true");
    return sep;
  }

  private buildShell(): void {
    this.root.replaceChildren();

    const topbar = document.createElement("header");
    topbar.className = "topbar";

    const left = document.createElement("div");
    left.className = "topbar-left";
    const brand = document.createElement("span");
    brand.className = "brand";
    const brandText = document.createElement("span");
    brandText.textContent = "my-note";
    brand.append(createIcon("brand-mark", "sm"), brandText);

    this.bufferTabsEl = document.createElement("nav");
    this.bufferTabsEl.className = "buffer-tabs";
    this.bufferTabsEl.setAttribute("aria-label", t("topbar.buffersNav"));

    this.switcherBtnEl = document.createElement("button");
    this.switcherBtnEl.type = "button";
    this.switcherBtnEl.className = "btn btn-ghost btn-has-icon switcher-btn";
    this.switcherBtnEl.dataset.testid = "buffers-btn";
    this.switcherLabelEl = document.createElement("span");
    this.switcherLabelEl.className = "sr-only";
    this.switcherLabelEl.textContent = t("topbar.buffers");
    const switcherTokens: readonly ShortcutKeyToken[] = [{ kind: "mod" }, { kind: "char", label: "P" }];
    const switcherKbd = createShortcutHint(switcherTokens, "topbar-kbd-collapsible");
    this.switcherBtnEl.append(createIcon("layers", "xs"), this.switcherLabelEl, switcherKbd);
    this.switcherBtnEl.title = `${t("topbar.buffers")} (${formatShortcutTitle(switcherTokens)})`;
    this.switcherBtnEl.addEventListener("click", () => this.openBufferModal());
    left.append(brand, this.createTopbarSep(), this.bufferTabsEl, this.createTopbarSep(), this.switcherBtnEl);

    const right = document.createElement("div");
    right.className = "topbar-right";

    this.newBlkBtnEl = document.createElement("button");
    this.newBlkBtnEl.type = "button";
    this.newBlkBtnEl.className = "btn btn-ghost btn-icon-only";
    this.newBlkBtnEl.dataset.testid = "new-block-btn";
    this.newBlkLabelEl = document.createElement("span");
    this.newBlkLabelEl.className = "sr-only";
    this.newBlkLabelEl.textContent = t("topbar.newBlock");
    this.newBlkBtnEl.append(createIcon("plus", "xs"), this.newBlkLabelEl);
    this.newBlkBtnEl.title = t("topbar.newBlockTitle");
    this.newBlkBtnEl.addEventListener("click", () =>
      void this.insertBlockAfter(this.stream.getActiveBlockId()),
    );

    this.findBtnEl = document.createElement("button");
    this.findBtnEl.type = "button";
    this.findBtnEl.className = "btn btn-ghost btn-icon-only";
    this.findBtnEl.dataset.testid = "find-btn";
    this.findBtnLabelEl = document.createElement("span");
    this.findBtnLabelEl.className = "sr-only";
    this.findBtnLabelEl.textContent = t("topbar.find");
    this.findBtnEl.append(createIcon("search", "xs"), this.findBtnLabelEl);
    this.findBtnEl.title = t("topbar.findTitle");
    this.findBtnEl.addEventListener("click", () => this.toggleFindBar(true));

    this.vimBtnEl = document.createElement("button");
    this.vimBtnEl.type = "button";
    this.vimBtnEl.className = "btn btn-chip btn-toggle";
    this.vimBtnEl.dataset.testid = "vim-btn";
    this.vimBtnEl.setAttribute("aria-pressed", "false");
    this.vimBtnEl.textContent = t("topbar.vim");
    this.vimBtnEl.title = t("topbar.vimTitleOff");
    this.vimBtnEl.addEventListener("click", () => {
      this.vimEnabled = !this.vimEnabled;
      this.vimBtnEl.setAttribute("aria-pressed", String(this.vimEnabled));
      this.vimBtnEl.title = this.vimEnabled ? t("topbar.vimTitleOn") : t("topbar.vimTitleOff");
      this.stream.setVimMode(this.vimEnabled);
    });

    this.vaultBtnEl = document.createElement("button");
    this.vaultBtnEl.type = "button";
    this.vaultBtnEl.className = "btn btn-ghost btn-has-icon";
    this.vaultBtnEl.dataset.testid = "vault-btn";
    this.vaultBtnEl.addEventListener("click", () => this.openVaultModal());
    this.renderVaultBtn();

    this.trashBtnEl = document.createElement("button");
    this.trashBtnEl.type = "button";
    this.trashBtnEl.className = "btn btn-ghost btn-has-icon trash-btn";
    this.trashBtnEl.dataset.testid = "trash-btn";
    this.trashBtnEl.setAttribute("aria-pressed", "false");
    this.trashCountEl = document.createElement("span");
    this.trashCountEl.className = "trash-count";
    this.trashBtnEl.append(createIcon("trash", "xs"), this.trashCountEl);
    this.trashBtnEl.addEventListener("click", () => void this.toggleTrash());
    this.updateTrashCount(0);

    this.clipInboxBtnEl = document.createElement("button");
    this.clipInboxBtnEl.type = "button";
    this.clipInboxBtnEl.className = "btn btn-ghost btn-has-icon trash-btn clip-inbox-btn";
    this.clipInboxBtnEl.dataset.testid = "clip-inbox-btn";
    this.clipInboxBtnEl.setAttribute("aria-pressed", "false");
    this.clipInboxLabelEl = document.createElement("span");
    this.clipInboxLabelEl.className = "btn-label btn-label-collapsible";
    this.clipInboxLabelEl.textContent = t("topbar.clipInbox");
    this.clipInboxCountEl = document.createElement("span");
    this.clipInboxCountEl.className = "trash-count";
    this.clipInboxBtnEl.append(createIcon("clipboard", "xs"), this.clipInboxLabelEl, this.clipInboxCountEl);
    this.clipInboxBtnEl.addEventListener("click", () => void this.toggleClipDrawer());
    this.updateClipCount(0);

    this.shortcutsBtnEl = document.createElement("button");
    this.shortcutsBtnEl.type = "button";
    this.shortcutsBtnEl.className = "btn btn-ghost btn-icon-only";
    this.shortcutsBtnEl.dataset.testid = "shortcuts-btn";
    this.shortcutsBtnEl.setAttribute("aria-label", t("topbar.shortcuts"));
    this.shortcutsBtnEl.title = t("topbar.shortcutsTitle", {
      shortcut: formatShortcutTitle(SHORTCUT_HELP),
    });
    this.shortcutsBtnLabelEl = document.createElement("span");
    this.shortcutsBtnLabelEl.className = "sr-only";
    this.shortcutsBtnLabelEl.textContent = t("topbar.shortcuts");
    this.shortcutsBtnEl.append(createIcon("keyboard", "xs"), this.shortcutsBtnLabelEl);
    this.shortcutsBtnEl.addEventListener("click", () => this.toggleShortcutsModal());

    this.syncPillEl = document.createElement("button");
    this.syncPillEl.type = "button";
    this.syncPillEl.className = "sync-pill";
    this.syncPillEl.dataset.testid = "sync-pill";
    this.syncPillEl.dataset.state = "unconfigured";
    this.syncIconEl = document.createElement("span");
    this.syncIconEl.className = "sync-icon";
    const syncLabel = document.createElement("span");
    syncLabel.className = "sync-label";
    syncLabel.textContent = t("sync.localOnly");
    this.syncPillEl.append(this.syncIconEl, syncLabel);
    this.syncPillEl.title = t("sync.title");
    this.syncPillEl.addEventListener("click", () => void this.triggerSyncNow());
    this.renderSyncPill();

    this.themeMenu = createThemeMenu();
    this.localeSwitch = createLocaleSwitch();

    right.append(
      this.newBlkBtnEl,
      this.findBtnEl,
      this.vimBtnEl,
      this.createTopbarSep(),
      this.clipInboxBtnEl,
      this.vaultBtnEl,
      this.trashBtnEl,
      this.createTopbarSep(),
      this.syncPillEl,
      this.createTopbarSep(),
      this.shortcutsBtnEl,
      this.themeMenu.element,
      this.localeSwitch.element,
    );
    topbar.append(left, right);

    this.alertStackEl = document.createElement("div");
    this.alertStackEl.className = "alert-stack";

    // Find & replace bar
    this.findBarEl = document.createElement("div");
    this.findBarEl.className = "find-bar hidden";
    const findInner = document.createElement("div");
    findInner.className = "find-bar-inner";

    const findInputWrap = document.createElement("div");
    findInputWrap.className = "find-input-wrap";
    findInputWrap.appendChild(createIcon("search", "xs", "find-input-icon"));
    this.findInputEl = document.createElement("input");
    this.findInputEl.className = "input";
    this.findInputEl.placeholder = t("find.placeholder");
    this.findInputEl.addEventListener("input", () => {
      this.findIndex = 0;
      this.runFind(0);
    });
    this.findInputEl.addEventListener("keydown", (ev) => {
      if (ev.isComposing || ev.keyCode === 229) return;
      if (ev.key === "Enter") {
        ev.preventDefault();
        this.runFind(ev.shiftKey ? -1 : 1);
      }
    });
    findInputWrap.appendChild(this.findInputEl);

    this.replaceInputEl = document.createElement("input");
    this.replaceInputEl.className = "input find-replace-input";
    this.replaceInputEl.placeholder = t("find.replacePlaceholder");
    this.findCountEl = document.createElement("span");
    this.findCountEl.className = "find-count";
    this.findCountEl.textContent = "";
    this.findPrevBtnEl = document.createElement("button");
    this.findPrevBtnEl.type = "button";
    this.findPrevBtnEl.className = "btn btn-icon";
    this.findPrevBtnEl.dataset.testid = "find-prev-btn";
    this.findPrevBtnEl.textContent = t("find.prev");
    this.findPrevBtnEl.addEventListener("click", () => this.runFind(-1));
    this.findNextBtnEl = document.createElement("button");
    this.findNextBtnEl.type = "button";
    this.findNextBtnEl.className = "btn btn-icon";
    this.findNextBtnEl.dataset.testid = "find-next-btn";
    this.findNextBtnEl.textContent = t("find.next");
    this.findNextBtnEl.addEventListener("click", () => this.runFind(1));
    this.findReplaceBtnEl = document.createElement("button");
    this.findReplaceBtnEl.type = "button";
    this.findReplaceBtnEl.className = "btn btn-icon";
    this.findReplaceBtnEl.textContent = t("find.replaceAll");
    this.findReplaceBtnEl.addEventListener("click", () => void this.runReplaceAll());
    this.findCloseBtnEl = this.createCloseButton(() => this.toggleFindBar(false));
    findInner.append(
      findInputWrap,
      this.replaceInputEl,
      this.findCountEl,
      this.findPrevBtnEl,
      this.findNextBtnEl,
      this.findReplaceBtnEl,
      this.findCloseBtnEl,
    );
    this.findBarEl.appendChild(findInner);

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
      onOpenShortcuts: () => this.openShortcutsModal(),
    });

    // Recycle Bin drawer
    this.trashDrawerEl = document.createElement("aside");
    this.trashDrawerEl.className = "drawer hidden";
    const drawerHdr = document.createElement("div");
    drawerHdr.className = "drawer-header";
    this.trashTitleEl = document.createElement("span");
    this.trashTitleEl.className = "drawer-header-title";
    this.trashTitleEl.textContent = t("trash.title");
    this.trashHeaderActionsEl = document.createElement("div");
    this.trashHeaderActionsEl.className = "drawer-header-actions";
    this.trashCloseBtnEl = this.createCloseButton(() => {
      this.trashOpen = false;
      this.trashDrawerEl.classList.add("hidden");
      this.syncTrashBtnState();
    });
    const trashHdrRight = document.createElement("div");
    trashHdrRight.className = "drawer-header-right";
    trashHdrRight.append(this.trashHeaderActionsEl, this.trashCloseBtnEl);
    drawerHdr.append(this.trashTitleEl, trashHdrRight);
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
    this.historyTitleEl.className = "drawer-header-title";
    this.historyTitleEl.textContent = t("history.title");
    this.historyHeaderActionsEl = document.createElement("div");
    this.historyHeaderActionsEl.className = "drawer-header-actions";
    this.historyCloseBtnEl = this.createCloseButton(() => this.closeHistoryDrawer(), "history-close-btn");
    const histHdrRight = document.createElement("div");
    histHdrRight.className = "drawer-header-right";
    histHdrRight.append(this.historyHeaderActionsEl, this.historyCloseBtnEl);
    histHdr.append(this.historyTitleEl, histHdrRight);
    this.historyActionsEl = document.createElement("div");
    this.historyActionsEl.className = "drawer-actions";
    this.historyListEl = document.createElement("div");
    this.historyListEl.className = "drawer-list history-list";
    this.historyDiffEl = document.createElement("div");
    this.historyDiffEl.className = "history-diff-pane";
    this.historyDrawerEl.append(histHdr, this.historyActionsEl, this.historyListEl, this.historyDiffEl);

    // M4 Cross-Device 100-item Clipboard Drawer
    this.clipDrawer = new ClipDrawerController(this.api, {
      getActiveBufferId: () => this.activeBufferId,
      onBlockPromoted: (blk) => {
        if (blk.buffer_id === this.activeBufferId) {
          this.stream.upsertBlocks([blk], [], this.activeBufferId);
          this.knownBufferBlockCounts.set(this.activeBufferId, this.stream.getBlocks().length);
        }
      },
      onFeedback: (msg, isError) => this.showToast(msg, isError),
      onError: (err) => this.handleErr(err),
      onCountChange: (count) => this.updateClipCount(count),
      onOpenChange: (open) => this.syncClipBtnState(open),
    });

    const workspaceMain = document.createElement("div");
    workspaceMain.className = "workspace-main";
    workspaceMain.append(this.findBarEl, streamEl);
    workspace.append(workspaceMain, this.trashDrawerEl, this.historyDrawerEl, this.clipDrawer.element);

    // Buffer Switcher modal (Quick Switcher ⌘P — single unified Filter / Create command bar)
    this.modalBackdropEl = document.createElement("div");
    this.modalBackdropEl.className = "modal-backdrop hidden";
    this.modalBackdropEl.addEventListener("click", (ev) => {
      if (ev.target === this.modalBackdropEl) this.closeBufferModal();
    });
    const modal = document.createElement("div");
    modal.className = "modal buffer-switcher-modal";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-label", t("buffer.modalTitle"));
    this.bufferModalEl = modal;

    const filterRow = document.createElement("div");
    filterRow.className = "modal-search-row";
    const filterWrap = document.createElement("div");
    filterWrap.className = "find-input-wrap modal-filter-wrap";
    filterWrap.appendChild(createIcon("search", "xs", "find-input-icon"));
    this.bufferFilterInputEl = document.createElement("input");
    this.bufferFilterInputEl.type = "search";
    this.bufferFilterInputEl.className = "input";
    this.bufferFilterInputEl.placeholder = t("buffer.filterPlaceholder");
    this.bufferFilterInputEl.dataset.testid = "buffer-filter-input";
    this.bufferFilterInputEl.addEventListener("input", () => {
      this.bufferFilterQuery = this.bufferFilterInputEl.value;
      this.bufferActiveIndex = 0;
      this.renderBufferModalList();
    });
    this.bufferFilterInputEl.addEventListener("keydown", (ev) => {
      if (ev.isComposing || ev.keyCode === 229) return;
      const options = this.getBufferModalOptions();
      if (ev.key === "ArrowDown") {
        ev.preventDefault();
        if (options.length > 0) {
          this.bufferActiveIndex = (this.bufferActiveIndex + 1) % options.length;
          this.syncBufferModalHighlight();
        }
      } else if (ev.key === "ArrowUp") {
        ev.preventDefault();
        if (options.length > 0) {
          this.bufferActiveIndex = (this.bufferActiveIndex - 1 + options.length) % options.length;
          this.syncBufferModalHighlight();
        }
      } else if (ev.key === "Enter") {
        ev.preventDefault();
        const picked = options[this.bufferActiveIndex];
        if (!picked) return;
        if (picked.kind === "buffer") {
          this.closeBufferModal();
          void this.switchBuffer(picked.buffer.id);
        } else {
          void this.createBufferByName(picked.name);
        }
      } else if (ev.key === "Escape") {
        ev.preventDefault();
        this.closeBufferModal();
      }
    });
    filterWrap.appendChild(this.bufferFilterInputEl);
    this.bufferModalCloseBtnEl = this.createCloseButton(() => this.closeBufferModal(), "buffer-modal-close");
    filterRow.append(filterWrap, this.bufferModalCloseBtnEl);

    this.modalListEl = document.createElement("div");
    this.modalListEl.className = "modal-list";
    this.modalListEl.setAttribute("role", "listbox");

    this.bufferFooterEl = document.createElement("div");
    this.bufferFooterEl.className = "modal-hints";
    this.renderBufferModalHints();

    modal.append(filterRow, this.modalListEl, this.bufferFooterEl);
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
    this.dialogModalEl.setAttribute("role", "dialog");
    this.dialogModalEl.setAttribute("aria-modal", "true");
    this.dialogBackdropEl.appendChild(this.dialogModalEl);

    // Keyboard Shortcuts reference modal
    this.shortcutsBackdropEl = document.createElement("div");
    this.shortcutsBackdropEl.className = "modal-backdrop hidden";
    this.shortcutsBackdropEl.dataset.testid = "shortcuts-modal-backdrop";
    this.shortcutsBackdropEl.addEventListener("click", (ev) => {
      if (ev.target === this.shortcutsBackdropEl) this.closeShortcutsModal();
    });
    this.shortcutsModalEl = document.createElement("div");
    this.shortcutsModalEl.className = "modal shortcuts-modal";
    this.shortcutsModalEl.dataset.testid = "shortcuts-modal";
    this.shortcutsModalEl.setAttribute("role", "dialog");
    this.shortcutsModalEl.setAttribute("aria-modal", "true");
    this.shortcutsBackdropEl.appendChild(this.shortcutsModalEl);

    this.toastEl = document.createElement("div");
    this.toastEl.className = "toast hidden";
    this.toastEl.setAttribute("role", "status");
    this.toastEl.setAttribute("aria-live", "polite");

    this.root.append(
      topbar,
      this.alertStackEl,
      workspace,
      this.modalBackdropEl,
      this.dialogBackdropEl,
      this.shortcutsBackdropEl,
      this.clipDrawer.previewBackdropEl,
      this.toastEl,
    );
  }

  private applyLocale(): void {
    syncDocumentLocale("app.title");
    this.bufferTabsEl.setAttribute("aria-label", t("topbar.buffersNav"));
    this.switcherLabelEl.textContent = t("topbar.buffers");
    this.switcherBtnEl.title = `${t("topbar.buffers")} (${formatShortcutTitle([{ kind: "mod" }, { kind: "char", label: "P" }])})`;
    this.newBlkLabelEl.textContent = t("topbar.newBlock");
    this.newBlkBtnEl.title = t("topbar.newBlockTitle");
    this.findBtnLabelEl.textContent = t("topbar.find");
    this.findBtnEl.title = t("topbar.findTitle");
    this.vimBtnEl.textContent = t("topbar.vim");
    this.vimBtnEl.title = this.vimEnabled ? t("topbar.vimTitleOn") : t("topbar.vimTitleOff");

    this.findInputEl.placeholder = t("find.placeholder");
    this.replaceInputEl.placeholder = t("find.replacePlaceholder");
    this.findCountEl.textContent = this.formatFindCounter();
    this.findPrevBtnEl.textContent = t("find.prev");
    this.findNextBtnEl.textContent = t("find.next");
    this.findReplaceBtnEl.textContent = t("find.replaceAll");
    this.updateCloseButtonLocale(this.findCloseBtnEl);

    this.trashTitleEl.textContent = t("trash.title");
    this.updateCloseButtonLocale(this.trashCloseBtnEl);
    this.updateCloseButtonLocale(this.historyCloseBtnEl);

    this.bufferModalEl.setAttribute("aria-label", t("buffer.modalTitle"));
    this.updateCloseButtonLocale(this.bufferModalCloseBtnEl);
    this.bufferFilterInputEl.placeholder = t("buffer.filterPlaceholder");
    this.renderBufferModalHints();

    this.themeMenu.refreshLocale();
    this.localeSwitch.refreshLocale();
    this.shortcutsBtnEl.setAttribute("aria-label", t("topbar.shortcuts"));
    this.shortcutsBtnEl.title = t("topbar.shortcutsTitle", {
      shortcut: formatShortcutTitle(SHORTCUT_HELP),
    });
    this.shortcutsBtnLabelEl.textContent = t("topbar.shortcuts");
    this.renderVaultBtn();
    this.renderSyncPill();
    this.updateTrashCount(this.lastTrashCount);
    this.updateClipCount(this.lastClipCount);
    this.clipDrawer.refreshLocale();
    if (!this.shortcutsBackdropEl.classList.contains("hidden")) {
      this.renderShortcutsModal();
    }
    this.renderAlerts();

    if (this.trashOpen) {
      this.renderTrash();
    }
    if (this.historyOpen) {
      this.renderHistoryDrawer();
    } else {
      this.historyTitleEl.textContent = t("history.title");
    }
    if (!this.modalBackdropEl.classList.contains("hidden")) {
      this.renderBufferModalList();
    }

    // In-place update across all block cards without unmounting CM6 views or clearing Vault RAM
    this.stream.refreshLocale();
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
    if (ev.defaultPrevented || ev.isComposing) return;
    const mod = ev.metaKey || ev.ctrlKey;
    const shortcutsOpen = !this.shortcutsBackdropEl.classList.contains("hidden");
    const modalOpen =
      !this.modalBackdropEl.classList.contains("hidden") ||
      !this.dialogBackdropEl.classList.contains("hidden") ||
      shortcutsOpen;
    if (!mod) {
      if (ev.key === "Escape") {
        if (this.clipDrawer.isPreviewOpen()) {
          this.clipDrawer.closeImagePreview();
          return;
        }
        this.closeShortcutsModal();
        this.closeBufferModal();
        this.closeDialog();
        this.toggleFindBar(false);
        this.closeHistoryDrawer();
        this.clipDrawer.close();
      }
      return;
    }
    if (!ev.shiftKey && !ev.altKey && (ev.key === "/" || ev.code === "Slash")) {
      if (!modalOpen || shortcutsOpen) {
        ev.preventDefault();
        this.toggleShortcutsModal();
      }
      return;
    }
    if (modalOpen) return;
    if (!ev.shiftKey && !ev.altKey && (ev.key === "\\" || ev.code === "Backslash")) {
      ev.preventDefault();
      void this.toggleClipDrawer();
      return;
    }
    if (ev.altKey && (ev.key === "ArrowUp" || ev.key === "ArrowDown")) {
      ev.preventDefault();
      const dir: -1 | 1 = ev.key === "ArrowUp" ? -1 : 1;
      if (ev.shiftKey) {
        const id = this.stream.getActiveBlockId();
        const blk = this.stream.getBlocks().find((b) => b.id === id);
        if (blk) void this.moveBlock(blk, dir);
      } else {
        this.stream.navigateBlock(dir);
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
    const textSpan = document.createElement("span");
    textSpan.textContent = msg;
    this.toastEl.replaceChildren(createIcon(isError ? "alert-triangle" : "check-circle", "xs"), textSpan);
    this.toastEl.className = `toast${isError ? " error" : ""}`;
    if (this.toastTimer !== null) window.clearTimeout(this.toastTimer);
    this.toastTimer = window.setTimeout(() => this.toastEl.classList.add("hidden"), 3200);
  }

  private setBuffers(list: readonly BufferDto[]): void {
    const byId = new Map<string, BufferDto>();
    for (const b of list) {
      byId.set(b.id, b);
    }
    this.buffers = [...byId.values()].sort((a, b) =>
      a.position < b.position ? -1 : a.position > b.position ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
    );
  }

  private upsertBuffers(upserted: readonly BufferDto[], deletedIds: readonly string[] = []): void {
    const del = new Set(deletedIds);
    const byId = new Map<string, BufferDto>();
    for (const b of this.buffers) {
      if (!del.has(b.id)) byId.set(b.id, b);
    }
    for (const u of upserted) {
      if (!del.has(u.id)) byId.set(u.id, u);
    }
    this.buffers = [...byId.values()].sort((a, b) =>
      a.position < b.position ? -1 : a.position > b.position ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
    );
  }

  private renderBuffers(): void {
    this.bufferTabsEl.replaceChildren();
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
    const labelSpan = document.createElement("span");
    labelSpan.className = "btn-label";
    if (this.isVaultUnlocked()) {
      this.vaultBtnEl.className = "btn btn-amber btn-has-icon";
      labelSpan.textContent = t("vault.unlocked");
      this.vaultBtnEl.title = t("vault.unlockedTitle");
      this.vaultBtnEl.replaceChildren(createIcon("lock-open", "xs"), labelSpan);
    } else if (this.vaultHeader) {
      this.vaultBtnEl.className = "btn btn-ghost btn-has-icon";
      labelSpan.textContent = t("vault.locked");
      this.vaultBtnEl.title = t("vault.lockedTitle");
      this.vaultBtnEl.replaceChildren(createIcon("lock", "xs"), labelSpan);
    } else {
      this.vaultBtnEl.className = "btn btn-ghost btn-has-icon";
      labelSpan.textContent = t("vault.setup");
      this.vaultBtnEl.title = t("vault.setupTitle");
      this.vaultBtnEl.replaceChildren(createIcon("lock", "xs"), labelSpan);
    }
  }

  private renderSyncPill(): void {
    const label = this.syncPillEl.querySelector<HTMLElement>(".sync-label")!;
    const setIcon = (name: IconName): void => {
      this.syncIconEl.replaceChildren(createIcon(name, "xs"));
    };
    const setQuietDot = (): void => {
      const dot = document.createElement("span");
      dot.className = "sync-dot";
      dot.setAttribute("aria-hidden", "true");
      this.syncIconEl.replaceChildren(dot);
    };

    if (!this.wsConnected) {
      this.syncPillEl.dataset.state = "pending_offline";
      this.syncPillEl.classList.remove("is-quiet");
      setIcon("cloud-off");
      label.className = "sync-label";
      label.textContent = this.alerts.has("AUTH_REQUIRED")
        ? t("sync.sessionExpired")
        : t("sync.daemonDisconnected");
      this.syncPillEl.title = t("sync.title");
      return;
    }

    const state: SyncStateLabel = this.syncStatus?.sync_state ?? "unconfigured";
    const pending = this.syncStatus?.pending_ops ?? 0;
    this.syncPillEl.dataset.state = state;

    switch (state) {
      case "synced":
        this.syncPillEl.classList.add("is-quiet");
        setQuietDot();
        label.className = "sync-label btn-label-collapsible";
        label.textContent = t("sync.synced");
        this.syncPillEl.title = t("sync.syncedTitle");
        break;
      case "syncing":
        this.syncPillEl.classList.remove("is-quiet");
        setIcon("refresh-cw");
        label.className = "sync-label";
        label.textContent = t("sync.syncing");
        this.syncPillEl.title = t("sync.title");
        break;
      case "pending_offline":
        this.syncPillEl.classList.remove("is-quiet");
        setIcon("cloud-off");
        label.className = "sync-label";
        label.textContent =
          pending > 0 ? t("sync.offlinePending", { count: pending }) : t("sync.offline");
        this.syncPillEl.title = t("sync.title");
        break;
      case "conflict_present":
        this.syncPillEl.classList.remove("is-quiet");
        setIcon("alert-triangle");
        label.className = "sync-label";
        label.textContent = t("sync.conflict");
        this.syncPillEl.title = t("sync.title");
        break;
      default:
        this.syncPillEl.classList.add("is-quiet");
        setQuietDot();
        label.className = "sync-label btn-label-collapsible";
        label.textContent = t("sync.localOnly");
        this.syncPillEl.title = t("sync.localOnlyTitle");
    }
  }

  private syncTrashBtnState(): void {
    this.trashBtnEl.setAttribute("aria-pressed", String(this.trashOpen));
    this.trashBtnEl.classList.toggle("is-active", this.trashOpen);
  }

  private syncClipBtnState(open: boolean): void {
    this.clipInboxBtnEl.setAttribute("aria-pressed", String(open));
    this.clipInboxBtnEl.classList.toggle("is-active", open);
  }

  private updateClipCount(count: number): void {
    this.lastClipCount = count;
    this.clipInboxLabelEl.textContent = t("topbar.clipInbox");
    this.clipInboxBtnEl.title = t("topbar.clipInboxTitle", {
      shortcut: formatShortcutTitle(SHORTCUT_CLIPBOARD),
    });
    this.clipInboxCountEl.replaceChildren();
    if (count > 0) {
      const num = document.createElement("span");
      num.className = "trash-badge-num";
      num.textContent = String(count);
      this.clipInboxCountEl.appendChild(num);
      this.clipInboxCountEl.classList.remove("hidden");
    } else {
      this.clipInboxCountEl.classList.add("hidden");
    }
    this.clipInboxBtnEl.classList.toggle("has-items", count > 0);
  }

  private async toggleClipDrawer(): Promise<void> {
    if (!this.clipDrawer.isOpen()) {
      if (this.trashOpen) {
        this.trashOpen = false;
        this.trashDrawerEl.classList.add("hidden");
        this.syncTrashBtnState();
      }
      this.closeHistoryDrawer();
    }
    await this.clipDrawer.toggle();
  }

  private updateTrashCount(count: number): void {
    this.lastTrashCount = count;
    const fullText = t("topbar.trashCount", { count });
    this.trashBtnEl.title = fullText;
    const numStr = String(count);
    const idx = fullText.indexOf(numStr);
    this.trashCountEl.replaceChildren();
    if (idx >= 0) {
      const before = document.createElement("span");
      before.className = "sr-only";
      before.textContent = fullText.slice(0, idx);
      const num = document.createElement("span");
      num.className = count > 0 ? "trash-badge-num" : "sr-only";
      num.textContent = numStr;
      const after = document.createElement("span");
      after.className = "sr-only";
      after.textContent = fullText.slice(idx + numStr.length);
      this.trashCountEl.append(before, num, after);
    } else {
      const fallback = document.createElement("span");
      fallback.className = "sr-only";
      fallback.textContent = fullText;
      this.trashCountEl.appendChild(fallback);
    }
    this.trashBtnEl.classList.toggle("has-items", count > 0);
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
    this.alertStackEl.replaceChildren();
    if (this.secretNudge) {
      const nudge = this.secretNudge;
      const div = document.createElement("div");
      div.className = "alert-banner";
      div.dataset.code = "SECRET_PASTE_NUDGE";
      div.dataset.severity = "warn";
      const text = document.createElement("span");
      text.className = "alert-banner-msg";
      text.append(
        createIcon("alert-triangle", "xs"),
        document.createTextNode(t("alert.secretNudge", { type: nudge.secretType })),
      );
      const actions = document.createElement("div");
      actions.className = "block-header-right";
      const lockBtn = document.createElement("button");
      lockBtn.type = "button";
      lockBtn.className = "btn btn-amber btn-icon btn-has-icon";
      const lockLbl = document.createElement("span");
      lockLbl.textContent = t("alert.lockBlock");
      lockBtn.append(createIcon("lock", "xs"), lockLbl);
      lockBtn.addEventListener("click", () => {
        const blk = this.stream.getBlocks().find((b) => b.id === nudge.blockId);
        this.secretNudge = null;
        this.renderAlerts();
        if (blk && !blk.is_locked) void this.promptLockBlock(blk);
      });
      const dismissBtn = document.createElement("button");
      dismissBtn.type = "button";
      dismissBtn.className = "btn btn-icon";
      dismissBtn.textContent = t("alert.dismiss");
      dismissBtn.addEventListener("click", () => {
        this.secretNudge = null;
        this.renderAlerts();
      });
      actions.append(lockBtn, dismissBtn);
      div.append(text, actions);
      this.alertStackEl.appendChild(div);
    }

    for (const alert of this.alerts.values()) {
      const isErr =
        alert.code === "KEY_MISSING" || alert.code === "AUTH_REQUIRED" || alert.code === "DEVICE_REVOKED";
      const div = document.createElement("div");
      div.className = "alert-banner";
      div.dataset.code = alert.code;
      div.dataset.severity = isErr ? "error" : "warn";
      const text = document.createElement("span");
      text.className = "alert-banner-msg";
      let msgText: string;
      if (alert.code === "KEY_MISSING") {
        msgText = t("alert.keyMissing");
      } else if (alert.code === "AUTH_REQUIRED") {
        msgText = t("alert.authRequired");
      } else if (alert.code === "DEVICE_REVOKED") {
        msgText = t("alert.deviceRevoked");
      } else if (alert.code === "CLOCK_SKEW") {
        msgText = t("alert.clockSkew", { details: JSON.stringify(alert.details) });
      } else if (alert.code === "RECOVERY_DRILL_DUE") {
        msgText = t("alert.recoveryDrillDue");
      } else if (alert.code === "SHRED_PENDING_CONFIRM") {
        msgText = t("alert.shredPendingConfirm");
      } else if (alert.code === "NEEDS_VAULT_REKEY") {
        msgText = t("alert.needsVaultRekey");
      } else if (alert.code === "CLIP_SECRET_BLOCKED") {
        const pattern =
          typeof alert.details.pattern === "string"
            ? alert.details.pattern
            : JSON.stringify(alert.details);
        msgText = t("alert.clipSecretBlocked", { details: pattern });
      } else if (alert.code === "DAEMON_UPDATED") {
        const version =
          typeof alert.details.version === "string" ? alert.details.version : "";
        msgText = t("alert.daemonUpdated", { version });
      } else {
        msgText = `${alert.code}: ${JSON.stringify(alert.details)}`;
      }
      text.append(
        createIcon(isErr ? "shield-alert" : "alert-triangle", "xs"),
        document.createTextNode(msgText),
      );
      div.appendChild(text);

      if (alert.code === "SHRED_PENDING_CONFIRM") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-amber btn-icon";
        btn.textContent = t("alert.reviewTrash");
        btn.addEventListener("click", () => {
          if (!this.trashOpen) void this.toggleTrash();
          else void this.refreshTrash();
        });
        div.appendChild(btn);
      } else if (alert.code === "NEEDS_VAULT_REKEY") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-primary btn-icon";
        btn.textContent = t("alert.unlockRekey");
        btn.addEventListener("click", () => this.openVaultModal());
        div.appendChild(btn);
      } else if (alert.code === "CLIP_SECRET_BLOCKED") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-icon";
        btn.textContent = t("alert.dismiss");
        btn.addEventListener("click", () => {
          this.alerts.delete("CLIP_SECRET_BLOCKED");
          this.renderAlerts();
        });
        div.appendChild(btn);
      } else if (alert.code === "DAEMON_UPDATED") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-primary btn-icon";
        btn.textContent = t("alert.refreshPage");
        btn.addEventListener("click", () => window.location.reload());
        div.appendChild(btn);
      }
      this.alertStackEl.appendChild(div);
    }
  }

  private async resyncAfterReconnect(): Promise<void> {
    try {
      const boot = await this.api.bootstrap();
      this.setBuffers(boot.buffers);
      this.syncStatus = boot.sync_status;
      this.vaultHeader = boot.vault_header ?? this.vaultHeader;
      this.recoveryPkB64 = boot.recovery_pk_b64 ?? this.recoveryPkB64;
      this.alerts.delete("AUTH_REQUIRED");
      if (
        boot.daemon_version &&
        this.initialDaemonVersion &&
        boot.daemon_version !== this.initialDaemonVersion
      ) {
        this.alerts.set("DAEMON_UPDATED", {
          type: "alert",
          code: "DAEMON_UPDATED",
          details: { version: boot.daemon_version },
        });
      }
      this.updateAlertsFromStatus(boot.sync_status);
      this.updateTrashCount(boot.trash_count);
      if (boot.clip_count !== undefined) {
        this.updateClipCount(boot.clip_count);
      }
      void this.clipDrawer.refresh({ silent: true });
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
        this.knownBufferBlockCounts.set(this.activeBufferId, this.stream.getBlocks().length);
      } else {
        this.activeBufferId = boot.initial_buffer_id ?? boot.buffers[0]?.id ?? null;
        this.stream.setBlocks(boot.blocks);
        if (this.activeBufferId) {
          this.knownBufferBlockCounts.set(this.activeBufferId, boot.blocks.length);
        }
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
      if (this.activeBufferId) {
        this.knownBufferBlockCounts.set(this.activeBufferId, this.stream.getBlocks().length);
      }
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
      this.upsertBuffers(frame.upserted, frame.deleted_ids);
      if (this.activeBufferId && del.has(this.activeBufferId)) {
        const fallback = this.buffers[0]?.id ?? null;
        if (fallback) {
          void this.switchBuffer(fallback);
        } else {
          this.activeBufferId = null;
          this.stream.setBlocks([]);
        }
      }
      this.renderBuffers();
      if (!this.modalBackdropEl.classList.contains("hidden")) {
        this.renderBufferModalList();
      }
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
    } else if (frame.type === "clip_changed") {
      this.clipDrawer.applyWsUpdate(frame);
    } else if (frame.type === "alert") {
      this.alerts.set(frame.code, frame);
      this.renderAlerts();
      if (frame.code === "CLIP_SECRET_BLOCKED") {
        const pattern =
          typeof frame.details.pattern === "string"
            ? frame.details.pattern
            : JSON.stringify(frame.details);
        this.showToast(t("alert.clipSecretBlocked", { details: pattern }), true);
      }
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
      this.knownBufferBlockCounts.set(bufferId, blocks.length);
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
      this.knownBufferBlockCounts.set(this.activeBufferId, this.stream.getBlocks().length);
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
        this.showToast(t("vault.toastRescuedAll", { count: rescued }));
      } else if (rescued > 0) {
        this.showToast(
          t("vault.toastRescuedPartial", {
            rescued,
            total: blocked.length,
            remaining: blocked.length - rescued,
          }),
          true,
        );
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
          this.showToast(t("vault.errLockedSave"), true);
          return { status: "error" };
        }
        const mat = this.findTier2KeyMaterial(block);
        if (!mat) {
          this.showToast(t("vault.errMissingMnw1"), true);
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
      if (opts.isMerge) this.showToast(t("block.toastMerged"));
      return { status: "ok", updated };
    } catch (e) {
      if (e instanceof LocalApiError && e.body.code === "HEAD_MISMATCH") {
        this.showToast(t("block.toastHeadMismatch"), true);
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
        cur.is_locked ? t("vault.errUnlockToFormat") : t("block.toastCannotFormatUnreadable"),
        true,
      );
      return;
    }
    if (cur.has_conflict) {
      this.showToast(t("block.toastResolveBeforeFormat"), true);
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
          this.showToast(t("vault.errLocked"), true);
          return;
        }
        const mat = this.findTier2KeyMaterial(cur);
        if (!mat) {
          this.showToast(t("vault.errMissingMnw1"), true);
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
        this.showToast(t("block.toastFormattedWasm", { lang: cur.lang }));
        return;
      }

      const { formatted } = await this.api.formatSnippet({ content, lang: cur.lang, block_id: cur.id });
      const updated = await this.api.patchBlock(cur.id, {
        expected_heads: expectedHeads,
        content: formatted,
        fast_sync: true,
      });
      this.stream.applyAuthoritativeBlock(updated, this.activeBufferId);
      this.showToast(t("block.toastFormatted", { lang: cur.lang }));
    } catch (e) {
      this.handleErr(e);
    }
  }

  private async copyBlockContent(content: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(content);
      this.showToast(t("block.toastCopied"));
    } catch {
      this.showToast(t("block.toastClipboardUnavailable"), true);
    }
  }

  private async copyBlockRich(block: BlockDto, html: string, text: string): Promise<void> {
    const ok = await copyDualFormat(html, text);
    if (ok) {
      if (block.is_locked) this.resetVaultIdleTimer();
      this.showToast(t("block.toastCopiedRich"));
    } else {
      this.showToast(t("block.toastClipboardUnavailable"), true);
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
      this.stream.scrollBlockIntoView(updated.id);
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
      if (this.activeBufferId) {
        this.knownBufferBlockCounts.set(this.activeBufferId, this.stream.getBlocks().length);
      }
      this.showToast(t("block.toastMovedToTrash"));
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
          this.showToast(t("block.toastCannotDecryptSelected"), true);
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
        this.showToast(t("block.toastConflictResolvedT2"));
        return;
      }

      const updated = await this.api.resolveBlock(block.id, {
        expected_heads: block.head_op_ids,
        keep_op_id: opId,
      });
      this.stream.applyAuthoritativeBlock(updated, this.activeBufferId);
      this.showToast(t("block.toastConflictResolved"));
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

  private createPasswordField(opts: {
    label: string;
    name: string;
    placeholder: string;
    autocomplete: "current-password" | "new-password";
    testId?: string;
    required?: boolean;
  }): { field: HTMLDivElement; input: HTMLInputElement } {
    const id = `vault-field-${++this.vaultFieldSeq}`;
    const field = document.createElement("div");
    field.className = "dialog-field";

    const labelEl = document.createElement("label");
    labelEl.className = "dialog-label";
    labelEl.htmlFor = id;
    labelEl.textContent = opts.label;

    const wrap = document.createElement("div");
    wrap.className = "password-input-wrap";

    const input = document.createElement("input");
    input.id = id;
    input.name = opts.name;
    input.type = "password";
    input.className = "input";
    input.placeholder = opts.placeholder;
    input.autocomplete = opts.autocomplete;
    if (opts.required) input.required = true;
    if (opts.testId) input.dataset.testid = opts.testId;
    input.addEventListener("input", () => {
      input.removeAttribute("aria-invalid");
    });

    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "btn btn-ghost btn-icon-only password-toggle-btn";
    toggleBtn.setAttribute("aria-pressed", "false");
    toggleBtn.setAttribute("aria-label", t("vault.showPass"));
    toggleBtn.title = t("vault.showPass");
    const syncToggleIcon = (shown: boolean): void => {
      toggleBtn.setAttribute("aria-pressed", String(shown));
      const lbl = shown ? t("vault.hidePass") : t("vault.showPass");
      toggleBtn.setAttribute("aria-label", lbl);
      toggleBtn.title = lbl;
      toggleBtn.replaceChildren(createIcon(shown ? "eye-off" : "eye", "xs"));
    };
    syncToggleIcon(false);
    toggleBtn.addEventListener("click", () => {
      const nextShown = input.type === "password";
      input.type = nextShown ? "text" : "password";
      syncToggleIcon(nextShown);
    });

    wrap.append(input, toggleBtn);
    field.append(labelEl, wrap);
    return { field, input };
  }

  private createVaultLockedTabs(active: "unlock" | "passwd"): HTMLElement {
    const tabs = document.createElement("div");
    tabs.className = "mode-seg vault-mode-seg";
    tabs.setAttribute("role", "tablist");
    const items: Array<{ key: "unlock" | "passwd"; label: string; testId: string }> = [
      { key: "unlock", label: t("vault.tabUnlock"), testId: "vault-tab-unlock" },
      { key: "passwd", label: t("vault.tabChangePass"), testId: "vault-tab-passwd" },
    ];
    for (const item of items) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-icon btn-static mode-seg-btn vault-mode-tab";
      btn.setAttribute("role", "tab");
      btn.setAttribute("aria-selected", String(active === item.key));
      btn.setAttribute("aria-pressed", String(active === item.key));
      btn.dataset.testid = item.testId;
      btn.textContent = item.label;
      btn.addEventListener("click", () => {
        if (active !== item.key) this.openVaultModal(item.key);
      });
      tabs.appendChild(btn);
    }
    return tabs;
  }

  private openVaultModal(forceMode?: "init" | "unlock" | "passwd" | "recover" | "unlocked"): void {
    const mode = forceMode ?? (this.isVaultUnlocked() ? "unlocked" : this.vaultHeader ? "unlock" : "init");
    this.dialogModalEl.replaceChildren();

    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    const closeBtn = this.createCloseButton(() => this.closeDialog());
    hdr.append(title, closeBtn);
    this.dialogModalEl.appendChild(hdr);

    const form = document.createElement("form");
    form.className = "dialog-form";
    form.noValidate = true;

    if (mode === "init") {
      title.textContent = t("vault.initTitle");
      const note = document.createElement("p");
      note.className = "dialog-note";
      note.textContent = t("vault.initNote");
      const { field: f1, input: p1 } = this.createPasswordField({
        label: t("vault.newPassLabel"),
        name: "new_passphrase",
        placeholder: t("vault.newPassPlaceholder"),
        autocomplete: "new-password",
        testId: "vault-passphrase-input",
        required: true,
      });
      const { field: f2, input: p2 } = this.createPasswordField({
        label: t("vault.confirmPassLabel"),
        name: "confirm_passphrase",
        placeholder: t("vault.confirmPassPlaceholder"),
        autocomplete: "new-password",
        testId: "vault-passphrase-confirm",
        required: true,
      });
      const submit = document.createElement("button");
      submit.type = "submit";
      submit.className = "btn btn-primary";
      submit.textContent = t("vault.initSubmit");
      submit.dataset.testid = "vault-submit-btn";
      form.append(note, f1, f2, submit);
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        void (async () => {
          const pass = p1.value;
          const confirm = p2.value;
          if (pass.length < 8) {
            p1.setAttribute("aria-invalid", "true");
            p1.focus();
            this.showToast(t("vault.errMinLen"), true);
            return;
          }
          if (pass !== confirm) {
            p2.setAttribute("aria-invalid", "true");
            p2.focus();
            this.showToast(t("vault.errMismatch"), true);
            return;
          }
          if (!this.recoveryPkB64 || !this.api.putVaultHeader) {
            this.showToast(t("vault.errNoRecoveryPk"), true);
            return;
          }
          p1.value = "";
          p2.value = "";
          submit.disabled = true;
          submit.textContent = t("vault.deriving");
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
            this.showToast(t("vault.toastInitOk"));
          } catch (e) {
            this.handleErr(e);
            submit.disabled = false;
            submit.textContent = t("vault.initSubmit");
          }
        })();
      });
      this.dialogModalEl.appendChild(form);
      this.dialogBackdropEl.classList.remove("hidden");
      p1.focus();
      return;
    }

    if (mode === "unlock") {
      title.textContent = t("vault.unlockTitle");
      this.dialogModalEl.appendChild(this.createVaultLockedTabs("unlock"));
      const note = document.createElement("p");
      note.className = "dialog-note";
      note.textContent = t("vault.unlockNote");
      const { field: f1, input: p1 } = this.createPasswordField({
        label: t("vault.passLabel"),
        name: "current_passphrase",
        placeholder: t("vault.passPlaceholder"),
        autocomplete: "current-password",
        testId: "vault-passphrase-input",
        required: true,
      });
      const row = document.createElement("div");
      row.className = "dialog-actions";
      const submit = document.createElement("button");
      submit.type = "submit";
      submit.className = "btn btn-primary";
      submit.textContent = t("vault.unlockSubmit");
      submit.dataset.testid = "vault-submit-btn";
      const recoverBtn = document.createElement("button");
      recoverBtn.type = "button";
      recoverBtn.className = "btn";
      recoverBtn.textContent = t("vault.forgotBtn");
      recoverBtn.addEventListener("click", () => this.openVaultModal("recover"));
      row.append(recoverBtn, submit);
      form.append(note, f1, row);
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        void (async () => {
          if (!this.vaultHeader) return;
          const pass = p1.value;
          p1.value = "";
          submit.disabled = true;
          submit.textContent = t("vault.unlocking");
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
            this.showToast(t("vault.toastUnlocked"));
          } catch (e) {
            const parsed = parseWasmError(e);
            p1.setAttribute("aria-invalid", "true");
            this.showToast(`${parsed.code}: ${parsed.message}`, true);
            submit.disabled = false;
            submit.textContent = t("vault.unlockSubmit");
            p1.focus();
          }
        })();
      });
      this.dialogModalEl.appendChild(form);
      this.dialogBackdropEl.classList.remove("hidden");
      p1.focus();
      return;
    }

    if (mode === "passwd") {
      title.textContent = t("vault.changePassModalTitle");
      this.dialogModalEl.appendChild(this.createVaultLockedTabs("passwd"));
      const note = document.createElement("p");
      note.className = "dialog-note";
      note.textContent = t("vault.changePassLockedNote");
      const { field: curField, input: curPassInput } = this.createPasswordField({
        label: t("vault.currentPassLabel"),
        name: "current_passphrase",
        placeholder: t("vault.currentPassPlaceholder"),
        autocomplete: "current-password",
        testId: "vault-current-passphrase-input",
        required: true,
      });
      const { field: np1Field, input: np1 } = this.createPasswordField({
        label: t("vault.newPassLabel"),
        name: "new_passphrase",
        placeholder: t("vault.changeNewPassPlaceholder"),
        autocomplete: "new-password",
        testId: "vault-new-passphrase-input",
        required: true,
      });
      const { field: np2Field, input: np2 } = this.createPasswordField({
        label: t("vault.confirmPassLabel"),
        name: "confirm_new_passphrase",
        placeholder: t("vault.changeConfirmPlaceholder"),
        autocomplete: "new-password",
        testId: "vault-confirm-passphrase-input",
        required: true,
      });
      const row = document.createElement("div");
      row.className = "dialog-actions";
      const recoverBtn = document.createElement("button");
      recoverBtn.type = "button";
      recoverBtn.className = "btn";
      recoverBtn.textContent = t("vault.forgotBtn");
      recoverBtn.addEventListener("click", () => this.openVaultModal("recover"));
      const submit = document.createElement("button");
      submit.type = "submit";
      submit.className = "btn btn-primary";
      submit.textContent = t("vault.updatePassBtn");
      submit.dataset.testid = "vault-change-pass-submit";
      row.append(recoverBtn, submit);
      form.append(note, curField, np1Field, np2Field, row);
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        void (async () => {
          if (!this.vaultHeader || !this.api.putVaultHeader) return;
          const curPass = curPassInput.value;
          const p1 = np1.value;
          const p2 = np2.value;
          if (!curPass) {
            curPassInput.setAttribute("aria-invalid", "true");
            curPassInput.focus();
            this.showToast(t("vault.errCurrentRequired"), true);
            return;
          }
          if (p1.length < 8) {
            np1.setAttribute("aria-invalid", "true");
            np1.focus();
            this.showToast(t("vault.errNewMinLen"), true);
            return;
          }
          if (p1 !== p2) {
            np2.setAttribute("aria-invalid", "true");
            np2.focus();
            this.showToast(t("vault.errMismatch"), true);
            return;
          }
          curPassInput.value = "";
          np1.value = "";
          np2.value = "";
          submit.disabled = true;
          submit.textContent = t("vault.updatingPass");
          let tempSess: WasmVaultSession | null = null;
          try {
            const headerBlob = this.vaultHeader.blob_b64;
            tempSess = await unlockVaultWithPassphraseWasm(curPass, headerBlob);
            if (isPageHidden()) {
              this.closeDialog();
              return;
            }
            const raw = tempSess.changePassphrase(b64ToBytes(headerBlob), p1);
            const parsed = JSON.parse(raw) as { gen: number; blob_b64: string };
            this.vaultHeader = await this.api.putVaultHeader(parsed.gen, parsed.blob_b64);
            this.closeDialog();
            this.showToast(t("vault.toastPassUpdated"));
          } catch (e) {
            const parsed = parseWasmError(e);
            curPassInput.setAttribute("aria-invalid", "true");
            this.showToast(
              parsed.code !== "WASM_ERROR" ? `${parsed.code}: ${parsed.message}` : parsed.message,
              true,
            );
            submit.disabled = false;
            submit.textContent = t("vault.updatePassBtn");
            curPassInput.focus();
          } finally {
            if (tempSess) {
              try {
                tempSess.lockAndZeroize();
                tempSess.free();
              } catch {
                // ignore if already freed
              }
            }
          }
        })();
      });
      this.dialogModalEl.appendChild(form);
      this.dialogBackdropEl.classList.remove("hidden");
      curPassInput.focus();
      return;
    }

    if (mode === "recover") {
      title.textContent = t("vault.recoverTitle");
      const note = document.createElement("p");
      note.className = "dialog-note";
      note.textContent = t("vault.recoverNote");
      const words = document.createElement("textarea");
      words.className = "input";
      words.rows = 3;
      words.placeholder = t("vault.wordsPlaceholder");
      const { field: newPassField, input: newPass } = this.createPasswordField({
        label: t("vault.newPassLabel"),
        name: "optional_new_passphrase",
        placeholder: t("vault.optionalNewPass"),
        autocomplete: "new-password",
      });
      const row = document.createElement("div");
      row.className = "dialog-actions";
      const backBtn = document.createElement("button");
      backBtn.type = "button";
      backBtn.className = "btn";
      backBtn.textContent = t("vault.back");
      backBtn.addEventListener("click", () => this.openVaultModal("unlock"));
      const submit = document.createElement("button");
      submit.type = "submit";
      submit.className = "btn btn-primary";
      submit.textContent = t("vault.recoverSubmit");
      row.append(backBtn, submit);
      form.append(note, words, newPassField, row);
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
                this.showToast(t("vault.errNewMinLen"), true);
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
            this.showToast(t("vault.toastRecovered"));
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
    title.textContent = t("vault.unlockedModalTitle");
    const note = document.createElement("p");
    note.className = "dialog-note";
    note.textContent = t("vault.unlockedModalNote");
    const lockBtn = document.createElement("button");
    lockBtn.type = "button";
    lockBtn.className = "btn btn-danger btn-has-icon";
    lockBtn.dataset.testid = "vault-lock-now-btn";
    const lockNowLbl = document.createElement("span");
    lockNowLbl.textContent = t("vault.lockNowBtn");
    lockBtn.append(createIcon("lock", "xs"), lockNowLbl);
    lockBtn.addEventListener("click", () => {
      this.closeDialog();
      this.lockVaultNow();
    });

    const sep = document.createElement("hr");
    sep.className = "dialog-sep";
    const sub = document.createElement("div");
    sub.className = "dialog-subtitle";
    sub.textContent = t("vault.changePassSubtitle");
    const { field: np1Field, input: np1 } = this.createPasswordField({
      label: t("vault.newPassLabel"),
      name: "new_passphrase",
      placeholder: t("vault.changeNewPassPlaceholder"),
      autocomplete: "new-password",
      testId: "vault-new-passphrase-input",
      required: true,
    });
    const { field: np2Field, input: np2 } = this.createPasswordField({
      label: t("vault.confirmPassLabel"),
      name: "confirm_new_passphrase",
      placeholder: t("vault.changeConfirmPlaceholder"),
      autocomplete: "new-password",
      testId: "vault-confirm-passphrase-input",
      required: true,
    });
    const chgBtn = document.createElement("button");
    chgBtn.type = "submit";
    chgBtn.className = "btn btn-primary";
    chgBtn.textContent = t("vault.updatePassBtn");
    chgBtn.dataset.testid = "vault-change-pass-submit";
    form.append(note, lockBtn, sep, sub, np1Field, np2Field, chgBtn);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void (async () => {
        if (!this.isVaultUnlocked() || !this.vaultSession || !this.vaultHeader || !this.api.putVaultHeader) return;
        const p1 = np1.value;
        const p2 = np2.value;
        if (p1.length < 8) {
          np1.setAttribute("aria-invalid", "true");
          np1.focus();
          this.showToast(t("vault.errNewMinLen"), true);
          return;
        }
        if (p1 !== p2) {
          np2.setAttribute("aria-invalid", "true");
          np2.focus();
          this.showToast(t("vault.errMismatch"), true);
          return;
        }
        np1.value = "";
        np2.value = "";
        chgBtn.disabled = true;
        chgBtn.textContent = t("vault.updatingPass");
        try {
          if (isPageHidden()) {
            this.closeDialog();
            return;
          }
          const raw = this.vaultSession.changePassphrase(b64ToBytes(this.vaultHeader.blob_b64), p1);
          const parsed = JSON.parse(raw) as { gen: number; blob_b64: string };
          this.vaultHeader = await this.api.putVaultHeader(parsed.gen, parsed.blob_b64);
          this.closeDialog();
          this.showToast(t("vault.toastPassUpdated"));
        } catch (e) {
          this.handleErr(e);
          chgBtn.disabled = false;
          chgBtn.textContent = t("vault.updatePassBtn");
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
    this.dialogModalEl.replaceChildren();
    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    title.textContent = t("lockModal.title");
    const closeBtn = this.createCloseButton(() => this.closeDialog());
    hdr.append(title, closeBtn);

    const form = document.createElement("form");
    form.className = "dialog-form";
    const note = document.createElement("p");
    note.className = "dialog-note";
    note.textContent = t("lockModal.note");
    const hintInput = document.createElement("input");
    hintInput.className = "input";
    hintInput.placeholder = t("lockModal.hintPlaceholder");
    hintInput.dataset.testid = "lock-hint-input";
    const actions = document.createElement("div");
    actions.className = "dialog-actions";
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "btn";
    cancelBtn.textContent = t("common.cancel");
    cancelBtn.addEventListener("click", () => this.closeDialog());
    const confirmBtn = document.createElement("button");
    confirmBtn.type = "submit";
    confirmBtn.className = "btn btn-primary btn-has-icon";
    const confirmLbl = document.createElement("span");
    confirmLbl.textContent = t("lockModal.confirm");
    confirmBtn.append(createIcon("lock", "xs"), confirmLbl);
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
          this.showToast(t("lockModal.toastLocked"));
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
    this.dialogModalEl.replaceChildren();
    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    title.textContent = t("downgradeModal.title");
    const closeBtn = this.createCloseButton(() => this.closeDialog());
    hdr.append(title, closeBtn);

    const form = document.createElement("form");
    form.className = "dialog-form";
    const note = document.createElement("p");
    note.className = "dialog-note";
    note.textContent = t("downgradeModal.note");
    const chkLabel = document.createElement("label");
    chkLabel.className = "dialog-check";
    const chk = document.createElement("input");
    chk.type = "checkbox";
    // Per docs/sync-protocol.md §4.2, default retains old Tier 2 key unless explicitly opted in.
    chk.checked = false;
    const chkText = document.createElement("span");
    chkText.textContent = t("downgradeModal.shredOpt");
    chkLabel.append(chk, chkText);
    const actions = document.createElement("div");
    actions.className = "dialog-actions";
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "btn";
    cancelBtn.textContent = t("common.cancel");
    cancelBtn.addEventListener("click", () => this.closeDialog());
    const confirmBtn = document.createElement("button");
    confirmBtn.type = "submit";
    confirmBtn.className = "btn btn-amber";
    confirmBtn.textContent = t("downgradeModal.confirm");
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
          this.showToast(t("downgradeModal.toastDowngraded"));
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
    this.stream.setHistoryTargetBlock(null);
    this.historyDrawerEl.classList.add("hidden");
    this.historyTitleEl.textContent = t("history.title");
    this.historyHeaderActionsEl.replaceChildren();
    this.historyActionsEl.replaceChildren();
    this.historyListEl.replaceChildren();
    this.historyDiffEl.replaceChildren();
  }

  private async openHistoryDrawer(block: BlockDto): Promise<void> {
    if (!this.api.getBlockHistory) {
      this.showToast(t("history.apiUnavailable"), true);
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
      this.syncTrashBtnState();
    }
    this.clipDrawer.close();

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
    this.stream.setHistoryTargetBlock(cur.id, { scrollIntoView: true });
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
      this.historyError = e instanceof Error ? e.message : t("history.loadFailed");
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
          throw new Error(t("history.missingTier2Blob"));
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
      this.historyError = e instanceof Error ? e.message : t("history.loadOpFailed");
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
      this.showToast(t("history.resolveBeforeRevert"), true);
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
          this.showToast(t("history.selectedUnavailable"), true);
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
      this.showToast(t("history.toastReverted"));
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
      this.showToast(t("history.resolveBeforeRevert"), true);
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
            throw new Error(t("history.missingTier2PredBlob"));
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
      this.showToast(t("history.toastUndidActor", { actor }));
      if (this.historyOpen && this.historyBlockId === cur.id) {
        await this.openHistoryDrawer(updated);
      }
    } catch (e) {
      this.handleErr(e);
    }
  }

  private formatHistoryTime(ms: number): string {
    return formatHistoryTimestamp(ms);
  }

  private formatIsoTitle(ms: number): string {
    if (!Number.isFinite(ms) || ms <= 0) return "";
    return new Date(ms).toISOString();
  }

  private renderHistoryDrawer(): void {
    if (!this.historyOpen || !this.historyBlockId) return;
    const cur = this.stream.getBlocks().find((b) => b.id === this.historyBlockId) ?? null;
    this.historyTitleEl.textContent = cur
      ? t("history.titleWithBlock", { lang: cur.lang })
      : t("history.titleFallback");

    this.historyHeaderActionsEl.replaceChildren();
    this.historyActionsEl.replaceChildren();
    this.historyListEl.replaceChildren();
    this.historyDiffEl.replaceChildren();

    if (this.historyLoading) {
      const loading = document.createElement("div");
      loading.className = "empty-state";
      loading.textContent = t("history.loading");
      this.historyListEl.appendChild(loading);
      return;
    }

    // Place Undo <actor> batch in the dedicated action strip below the drawer header (away from the close button).
    const contentEntries = this.historyEntries.filter((e) => e.has_content);
    const latestContent = contentEntries[0];
    if (latestContent && latestContent.actor && latestContent.actor !== "human") {
      const badActor = latestContent.actor;
      const predecessor = contentEntries.find((e) => e.actor !== badActor) ?? null;
      const undoBtn = document.createElement("button");
      undoBtn.type = "button";
      undoBtn.className = "btn btn-accent-soft btn-icon";
      undoBtn.dataset.testid = "history-undo-actor-btn";
      undoBtn.textContent = t("history.undoActor", { actor: badActor });
      if (!predecessor) {
        undoBtn.disabled = true;
        undoBtn.title = t("history.noPredecessor", { actor: badActor });
      } else if (predecessor.shredded || !predecessor.content_available) {
        undoBtn.disabled = true;
        undoBtn.title = t("history.predUnavailable");
      } else {
        undoBtn.addEventListener("click", () => void this.undoActorBatch(badActor, predecessor));
      }
      this.historyActionsEl.appendChild(undoBtn);
    }

    if (cur?.has_conflict) {
      const conflictHint = document.createElement("div");
      conflictHint.className = "history-conflict-note";
      conflictHint.textContent = t("history.conflictHint");
      this.historyActionsEl.appendChild(conflictHint);
    }

    if (this.historyEntries.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = this.historyError
        ? t("history.errorPrefix", { msg: this.historyError })
        : t("history.empty");
      this.historyListEl.appendChild(empty);
      return;
    }

    for (const entry of this.historyEntries) {
      const row = document.createElement("button");
      row.type = "button";
      const isSelected = entry.op_id === this.historySelectedOpId;
      const unavailable = entry.shredded || (entry.has_content && !entry.content_available);
      const selectable = entry.has_content && !unavailable;
      row.className = `history-item${isSelected ? " selected" : ""}${unavailable ? " unavailable" : ""}`;
      row.dataset.opId = entry.op_id;
      row.dataset.testid = `history-select-${entry.op_id}`;
      row.disabled = !selectable;
      row.setAttribute("aria-pressed", String(isSelected));
      if (selectable) {
        row.addEventListener("click", () => void this.selectHistoryEntry(entry));
      }

      const topRow = document.createElement("div");
      topRow.className = "history-item-top";

      const opLabel = document.createElement("span");
      opLabel.className = "history-op-label";
      opLabel.textContent = formatOpTypeLabel(entry.op_type);
      topRow.appendChild(opLabel);

      // Only badge non-human actors so real badges (agent:*, Shredded, Current) retain clear visual signal.
      if (entry.actor && entry.actor !== "human") {
        const actorBadge = document.createElement("span");
        actorBadge.className = "actor-badge actor-badge-agent";
        actorBadge.textContent = entry.actor;
        topRow.appendChild(actorBadge);
      }

      if (entry.is_locked) {
        const lockBadge = document.createElement("span");
        lockBadge.className = "vault-badge";
        const sr = document.createElement("span");
        sr.className = "sr-only";
        sr.textContent = t("vault.badgeLocked");
        lockBadge.append(createIcon("lock", "xs"), sr);
        lockBadge.title = t("history.vaultVersionTitle");
        topRow.appendChild(lockBadge);
      }

      if (cur && cur.display_op_id === entry.op_id) {
        const curBadge = document.createElement("span");
        curBadge.className = "history-current-badge";
        curBadge.textContent = t("history.current");
        topRow.appendChild(curBadge);
      }

      if (unavailable) {
        const shredBadge = document.createElement("span");
        shredBadge.className = "history-badge-shredded";
        shredBadge.dataset.testid = "history-shredded-badge";
        shredBadge.textContent = t("history.shredded");
        topRow.appendChild(shredBadge);
      } else if (!entry.has_content) {
        const metaBadge = document.createElement("span");
        metaBadge.className = "history-badge-meta";
        metaBadge.textContent = t("history.meta");
        topRow.appendChild(metaBadge);
      }

      const metaRow = document.createElement("div");
      metaRow.className = "history-item-meta";
      const timeStr = this.formatHistoryTime(entry.created_at_ms);
      const devStr = formatDeviceName(entry.device_id);
      metaRow.textContent = devStr ? `${timeStr} · ${devStr}` : timeStr;
      metaRow.title = `${this.formatIsoTitle(entry.created_at_ms)} · ${entry.device_id}`;

      row.append(topRow, metaRow);
      this.historyListEl.appendChild(row);
    }

    // Selected entry diff & revert panel
    if (this.historyOpLoading) {
      const loading = document.createElement("div");
      loading.className = "history-diff-empty";
      loading.textContent = t("history.loadingOp");
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
      titleSpan.textContent = t("history.diffTitle");

      const revertBtn = document.createElement("button");
      revertBtn.type = "button";
      revertBtn.className = "btn btn-primary btn-icon";
      revertBtn.dataset.testid = "history-revert-btn";
      revertBtn.textContent = t("history.revertBtn");
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
        emptyLine.textContent = t("history.diffEmpty");
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
      rawSummary.className = "history-raw-summary";
      const rawSummaryLbl = document.createElement("span");
      rawSummaryLbl.textContent = t("history.rawDetails");
      rawSummary.append(createIcon("chevron-right", "xs", "history-raw-chevron"), rawSummaryLbl);
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
    if (this.trashOpen) {
      this.closeHistoryDrawer();
      this.clipDrawer.close();
    }
    this.trashDrawerEl.classList.toggle("hidden", !this.trashOpen);
    this.syncTrashBtnState();
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
    return t("trash.shredEarliest", { time: formatLocalDateTime(ms) });
  }

  private renderTrash(): void {
    this.trashHeaderActionsEl.replaceChildren();
    this.trashActionsEl.replaceChildren();
    const pendingConfirm = this.trashItems.filter((tItem) => tItem.shred_state === "pending_confirm");
    if (pendingConfirm.length > 0 && this.api.prepareTrashAction) {
      const confirmBtn = document.createElement("button");
      confirmBtn.type = "button";
      confirmBtn.className = "btn btn-amber btn-icon";
      confirmBtn.textContent = t("trash.confirmPending", { count: pendingConfirm.length });
      confirmBtn.addEventListener("click", () =>
        void this.openTrashConfirmModal("confirm_pending", pendingConfirm.map((x) => x.id), undefined),
      );
      this.trashActionsEl.appendChild(confirmBtn);
    }
    const expeditableItems = this.trashItems.filter(
      (tItem) => tItem.shred_state !== "executed" && tItem.shred_state !== "pending_confirm",
    );
    if (expeditableItems.length > 0 && this.api.prepareTrashAction) {
      const expAllBtn = document.createElement("button");
      expAllBtn.type = "button";
      expAllBtn.className = "btn btn-danger btn-icon";
      expAllBtn.textContent = t("trash.expediteAll");
      expAllBtn.title = t("trash.expediteAllTitle");
      expAllBtn.addEventListener("click", () =>
        void this.openTrashConfirmModal(
          "expedite",
          expeditableItems.map((x) => x.id),
          T_GRACE_MIN_MS,
        ),
      );
      this.trashActionsEl.appendChild(expAllBtn);
    }

    this.trashListEl.replaceChildren();
    if (this.trashItems.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = t("trash.empty");
      this.trashListEl.appendChild(empty);
      return;
    }
    for (const item of this.trashItems) {
      const card = document.createElement("div");
      card.className = "trash-item";
      card.dataset.trashId = item.id;

      const head = document.createElement("div");
      head.className = "trash-item-head";
      const titleGroup = document.createElement("div");
      titleGroup.className = "trash-item-title-group";
      const bufName = document.createElement("span");
      bufName.className = "trash-buffer-name";
      bufName.textContent = item.buffer_name;
      titleGroup.appendChild(bufName);
      // Suppress default "Scheduled" / "Recoverable" pills (timestamp underneath conveys default state);
      // show pills strictly for non-default states like Pending Confirmation, Expedited, or Shredded.
      if (item.shred_state && item.shred_state !== "scheduled" && item.shred_state !== "unscheduled") {
        const statePill = document.createElement("span");
        statePill.className = `trash-state-pill trash-state-${item.shred_state}`;
        statePill.textContent = formatShredStateLabel(item.shred_state);
        titleGroup.appendChild(statePill);
      }

      const btns = document.createElement("div");
      btns.className = "trash-item-actions";
      const restoreBtn = document.createElement("button");
      restoreBtn.type = "button";
      restoreBtn.className = "btn btn-icon";
      restoreBtn.textContent = t("trash.restore");
      restoreBtn.addEventListener("click", () => void this.restoreTrashItem(item));
      btns.appendChild(restoreBtn);
      if (this.api.prepareTrashAction && item.shred_state !== "executed" && item.shred_state !== "pending_confirm") {
        const expBtn = document.createElement("button");
        expBtn.type = "button";
        expBtn.className = "btn btn-ghost btn-danger btn-icon";
        expBtn.textContent = t("trash.expedite");
        expBtn.title = t("trash.expediteTitle");
        expBtn.addEventListener("click", () => void this.openTrashConfirmModal("expedite", [item.id], T_GRACE_MIN_MS));
        btns.appendChild(expBtn);
      }
      head.append(titleGroup, btns);
      card.appendChild(head);

      const shredStr = this.formatShredTime(item.shred_not_before_ms);
      if (shredStr) {
        const sub = document.createElement("div");
        sub.className = "trash-item-sub";
        sub.textContent = shredStr;
        if (item.shred_not_before_ms) {
          sub.title = new Date(item.shred_not_before_ms).toISOString();
        }
        card.appendChild(sub);
      }

      if (item.is_locked) {
        const lockedRow = document.createElement("div");
        lockedRow.className = "trash-preview-locked-row";
        lockedRow.append(createIcon("lock", "xs"), document.createTextNode(t("trash.lockedPreview")));
        card.appendChild(lockedRow);
      } else {
        const preview = document.createElement("pre");
        preview.className = "trash-preview";
        preview.textContent = item.preview ?? "";
        card.appendChild(preview);
      }
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
      this.showToast(t("trash.apiUnavailable"), true);
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

    this.dialogModalEl.replaceChildren();
    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    title.textContent =
      action === "expedite"
        ? t("shred.titleExpedite")
        : action === "confirm_pending"
          ? t("shred.titlePending")
          : t("shred.titlePurge");
    const closeBtn = this.createCloseButton(() => this.closeDialog());
    hdr.append(title, closeBtn);

    const body = document.createElement("div");
    body.className = "dialog-form";
    const graceHours = Math.round(prep.summary.grace_ms / 3_600_000);
    const details = document.createElement("div");
    details.className = "confirm-summary";
    details.textContent = [
      t("shred.summaryAction", { action: prep.summary.action }),
      t("shred.summaryBlocks", { count: prep.summary.block_count }),
      t("shred.summaryKeys", { count: prep.summary.key_count }),
      t("shred.summaryGrace", { hours: graceHours }),
      prep.summary.earliest_not_before_ms
        ? t("shred.summaryEarliest", { iso: new Date(prep.summary.earliest_not_before_ms).toISOString() })
        : "",
    ]
      .filter(Boolean)
      .join("\n");
    const warn = document.createElement("p");
    warn.className = "dialog-note";
    warn.textContent = t("shred.warn");

    const actions = document.createElement("div");
    actions.className = "dialog-actions";
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "btn";
    cancelBtn.textContent = t("common.cancel");
    cancelBtn.addEventListener("click", () => this.closeDialog());
    const confirmBtn = document.createElement("button");
    confirmBtn.type = "button";
    confirmBtn.className = "btn btn-danger";
    confirmBtn.dataset.testid = "trash-confirm-commit-btn";
    confirmBtn.textContent = t("shred.confirmBtn");
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
                this.showToast(t("vault.errUnlockToRekey"), true);
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
            this.showToast(t("trash.toastPurgeScheduled"));
          } else {
            await this.refreshTrash();
            if (this.api.getSyncStatus) {
              this.syncStatus = await this.api.getSyncStatus();
              this.updateAlertsFromStatus(this.syncStatus);
            }
            this.showToast(t("trash.toastActionConfirmed", { action }));
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
      if (this.activeBufferId) {
        this.knownBufferBlockCounts.set(this.activeBufferId, this.stream.getBlocks().length);
      }
      await this.refreshTrash();
      this.showToast(t("trash.toastRestored"));
    } catch (e) {
      this.handleErr(e);
    }
  }

  private getFilteredBuffers(): BufferDto[] {
    const q = this.bufferFilterQuery.trim().toLowerCase();
    if (!q) return this.buffers;
    return this.buffers.filter((b) => b.name.toLowerCase().includes(q));
  }

  private getBufferModalOptions(): Array<
    { readonly kind: "buffer"; readonly buffer: BufferDto } | { readonly kind: "create"; readonly name: string }
  > {
    const filtered = this.getFilteredBuffers();
    const out: Array<
      { readonly kind: "buffer"; readonly buffer: BufferDto } | { readonly kind: "create"; readonly name: string }
    > = filtered.map((buffer) => ({ kind: "buffer", buffer }));
    const trimmed = this.bufferFilterQuery.trim();
    if (trimmed && !this.buffers.some((b) => b.name.toLowerCase() === trimmed.toLowerCase())) {
      out.push({ kind: "create", name: trimmed });
    }
    return out;
  }

  private openShortcutsModal(): void {
    this.renderShortcutsModal();
    this.shortcutsBackdropEl.classList.remove("hidden");
  }

  private closeShortcutsModal(): void {
    this.shortcutsBackdropEl.classList.add("hidden");
  }

  private toggleShortcutsModal(): void {
    if (this.shortcutsBackdropEl.classList.contains("hidden")) {
      this.openShortcutsModal();
    } else {
      this.closeShortcutsModal();
    }
  }

  private renderShortcutsModal(): void {
    this.shortcutsModalEl.replaceChildren();
    this.shortcutsModalEl.setAttribute("aria-label", t("shortcuts.modalTitle"));

    const hdr = document.createElement("div");
    hdr.className = "drawer-header";
    const title = document.createElement("span");
    title.className = "drawer-header-title";
    title.textContent = t("shortcuts.modalTitle");
    const closeBtn = this.createCloseButton(() => this.closeShortcutsModal(), "shortcuts-modal-close");
    hdr.append(title, closeBtn);

    const groupsEl = document.createElement("div");
    groupsEl.className = "shortcuts-groups";

    const groups: ReadonlyArray<{
      readonly title: string;
      readonly items: ReadonlyArray<{ readonly label: string; readonly tokens: readonly ShortcutKeyToken[] }>;
    }> = [
      {
        title: t("shortcuts.groupBlocks"),
        items: [
          { label: t("shortcuts.itemNewBlock"), tokens: SHORTCUT_NEW_BLOCK },
          { label: t("shortcuts.itemSwitchBlock"), tokens: SHORTCUT_SWITCH_BLOCK_PAIR },
          { label: t("shortcuts.itemEdgeArrows"), tokens: SHORTCUT_EDGE_ARROWS },
          { label: t("shortcuts.itemMoveBlock"), tokens: SHORTCUT_MOVE_BLOCK_PAIR },
          { label: t("shortcuts.itemFocusLang"), tokens: SHORTCUT_LANG },
          { label: t("shortcuts.itemToggleMarkdown"), tokens: SHORTCUT_MARKDOWN_MODE },
          { label: t("shortcuts.itemFormatBlock"), tokens: SHORTCUT_FORMAT },
          { label: t("shortcuts.itemCopyBlock"), tokens: SHORTCUT_COPY_BLOCK },
        ],
      },
      {
        title: t("shortcuts.groupNavigation"),
        items: [
          { label: t("shortcuts.itemSwitchBuffer"), tokens: SHORTCUT_SWITCH_BUFFER },
          { label: t("shortcuts.itemFind"), tokens: SHORTCUT_FIND },
          { label: t("shortcuts.itemToggleClip"), tokens: SHORTCUT_CLIPBOARD },
          { label: t("shortcuts.itemShowShortcuts"), tokens: SHORTCUT_HELP },
          { label: t("shortcuts.itemClose"), tokens: SHORTCUT_ESC },
        ],
      },
      {
        title: t("shortcuts.groupVault"),
        items: [{ label: t("shortcuts.itemLockVault"), tokens: SHORTCUT_LOCK_VAULT }],
      },
    ];

    for (const grp of groups) {
      const sec = document.createElement("section");
      sec.className = "shortcuts-group";
      const h = document.createElement("h3");
      h.className = "shortcuts-group-title";
      h.textContent = grp.title;
      sec.appendChild(h);
      for (const item of grp.items) {
        const row = document.createElement("div");
        row.className = "shortcuts-row";
        const lbl = document.createElement("span");
        lbl.className = "shortcuts-row-label";
        lbl.textContent = item.label;
        row.append(lbl, createShortcutHint(item.tokens));
        sec.appendChild(row);
      }
      groupsEl.appendChild(sec);
    }

    const footer = document.createElement("div");
    footer.className = "modal-hints";
    const escHint = document.createElement("span");
    escHint.className = "modal-hint-item";
    const escLbl = document.createElement("span");
    escLbl.textContent = t("buffer.hintClose");
    escHint.append(createShortcutHint(SHORTCUT_ESC), escLbl);
    footer.appendChild(escHint);

    this.shortcutsModalEl.append(hdr, groupsEl, footer);
  }

  private renderBufferModalHints(): void {
    this.bufferFooterEl.replaceChildren();
    const mkHint = (tokens: readonly ShortcutKeyToken[], labelText: string): HTMLSpanElement => {
      const span = document.createElement("span");
      span.className = "modal-hint-item";
      const kbdGroup = createShortcutHint(tokens);
      const lbl = document.createElement("span");
      lbl.textContent = labelText;
      span.append(kbdGroup, lbl);
      return span;
    };
    this.bufferFooterEl.append(
      mkHint([{ kind: "up" }, { kind: "down" }], t("buffer.hintNavigate")),
      mkHint([{ kind: "enter" }], t("buffer.hintOpen")),
      mkHint([{ kind: "esc" }], t("buffer.hintClose")),
    );
  }

  private renderBufferModalList(): void {
    this.modalListEl.replaceChildren();
    const options = this.getBufferModalOptions();
    if (options.length === 0) {
      const empty = document.createElement("div");
      empty.className = "modal-empty";
      empty.textContent = t("buffer.emptyFilter");
      this.modalListEl.appendChild(empty);
      return;
    }
    if (this.bufferActiveIndex >= options.length) {
      this.bufferActiveIndex = 0;
    }
    options.forEach((opt, idx) => {
      const isHighlighted = idx === this.bufferActiveIndex;
      if (opt.kind === "create") {
        const row = document.createElement("div");
        row.className = `modal-row modal-row-create${isHighlighted ? " is-highlighted" : ""}`;
        row.setAttribute("role", "option");
        row.setAttribute("aria-selected", String(isHighlighted));
        row.dataset.testid = "buffer-create-inline-row";

        const leftGroup = document.createElement("span");
        leftGroup.className = "modal-row-main";
        leftGroup.appendChild(createIcon("plus", "xs", "modal-row-create-icon"));
        const name = document.createElement("span");
        name.className = "modal-row-name";
        name.textContent = t("buffer.createInline", { name: opt.name });
        leftGroup.appendChild(name);
        row.appendChild(leftGroup);

        row.addEventListener("mouseenter", () => {
          if (this.bufferActiveIndex !== idx) {
            this.bufferActiveIndex = idx;
            this.syncBufferModalHighlight();
          }
        });
        row.addEventListener("click", () => {
          void this.createBufferByName(opt.name);
        });
        this.modalListEl.appendChild(row);
        return;
      }

      const buf = opt.buffer;
      const isCurrent = buf.id === this.activeBufferId;
      const row = document.createElement("div");
      row.className = `modal-row${isCurrent ? " is-current" : ""}${isHighlighted ? " is-highlighted" : ""}`;
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", String(isHighlighted));

      const leftGroup = document.createElement("span");
      leftGroup.className = "modal-row-main";
      if (isCurrent) {
        leftGroup.appendChild(createIcon("check", "xs", "modal-row-check"));
      } else {
        const spacer = document.createElement("span");
        spacer.className = "modal-row-check-spacer";
        spacer.setAttribute("aria-hidden", "true");
        leftGroup.appendChild(spacer);
      }
      const name = document.createElement("span");
      name.className = "modal-row-name";
      name.textContent = buf.name;
      leftGroup.appendChild(name);

      const right = document.createElement("div");
      right.className = "modal-row-actions";
      const allCountsKnown = options.every(
        (item) => item.kind !== "buffer" || this.knownBufferBlockCounts.has(item.buffer.id),
      );
      const knownCount = allCountsKnown ? this.knownBufferBlockCounts.get(buf.id) : undefined;
      if (knownCount !== undefined) {
        const countEl = document.createElement("span");
        countEl.className = "modal-row-count";
        countEl.textContent =
          knownCount === 1 ? t("buffer.blockCountOne") : t("buffer.blockCount", { count: knownCount });
        right.appendChild(countEl);
      }

      const renBtn = document.createElement("button");
      renBtn.type = "button";
      renBtn.className = "btn btn-ghost btn-icon btn-icon-only modal-row-rename";
      renBtn.title = t("buffer.rename");
      const renSr = document.createElement("span");
      renSr.className = "sr-only";
      renSr.textContent = t("buffer.rename");
      renBtn.append(createIcon("pencil", "xs"), renSr);
      renBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const nextName = window.prompt(t("buffer.renamePrompt"), buf.name);
        if (nextName && nextName.trim()) {
          void this.api.renameBuffer(buf.id, nextName.trim()).then((updated) => {
            this.upsertBuffers([updated]);
            this.renderBuffers();
            this.renderBufferModalList();
          });
        }
      });
      right.appendChild(renBtn);
      row.append(leftGroup, right);
      row.addEventListener("mouseenter", () => {
        if (this.bufferActiveIndex !== idx) {
          this.bufferActiveIndex = idx;
          this.syncBufferModalHighlight();
        }
      });
      row.addEventListener("click", () => {
        this.closeBufferModal();
        void this.switchBuffer(buf.id);
      });
      this.modalListEl.appendChild(row);
    });
  }

  private syncBufferModalHighlight(): void {
    const rows = Array.from(this.modalListEl.querySelectorAll<HTMLElement>(".modal-row"));
    rows.forEach((row, i) => {
      const active = i === this.bufferActiveIndex;
      row.classList.toggle("is-highlighted", active);
      row.setAttribute("aria-selected", String(active));
      if (active) row.scrollIntoView?.({ block: "nearest" });
    });
  }

  private openBufferModal(): void {
    this.bufferFilterQuery = "";
    this.bufferFilterInputEl.value = "";
    const curIdx = this.buffers.findIndex((b) => b.id === this.activeBufferId);
    this.bufferActiveIndex = curIdx >= 0 ? curIdx : 0;
    this.renderBufferModalList();
    this.modalBackdropEl.classList.remove("hidden");
    this.bufferFilterInputEl.focus();
  }

  private closeBufferModal(): void {
    this.modalBackdropEl.classList.add("hidden");
  }

  private async createBufferByName(rawName: string): Promise<void> {
    const name = rawName.trim();
    if (!name || this.creatingBuffer) return;
    this.creatingBuffer = true;
    try {
      const created = await this.api.createBuffer({ name });
      this.upsertBuffers([created]);
      this.bufferFilterQuery = "";
      this.bufferFilterInputEl.value = "";
      this.closeBufferModal();
      await this.switchBuffer(created.id);
    } catch (e) {
      this.handleErr(e);
    } finally {
      this.creatingBuffer = false;
    }
  }

  private formatFindCounter(): string {
    if (!this.findInputEl?.value) return "";
    if (this.lastFindMatchCount === 0) return "0 / 0";
    return `${this.findIndex + 1} / ${this.lastFindMatchCount}`;
  }

  private toggleFindBar(show: boolean): void {
    this.findBarEl.classList.toggle("hidden", !show);
    if (show) {
      this.findInputEl.focus();
      this.findInputEl.select();
      if (this.findInputEl.value) {
        this.runFind(0);
      } else {
        this.lastFindMatchCount = 0;
        this.findCountEl.textContent = "";
      }
    } else {
      this.stream.setFindHighlights("", null);
    }
  }

  private runFind(delta: number): void {
    const query = this.findInputEl.value;
    const matches = this.stream.findAcrossBlocks(query);
    this.lastFindMatchCount = matches.length;
    if (matches.length === 0) {
      this.findIndex = 0;
      this.findCountEl.textContent = this.formatFindCounter();
      this.stream.setFindHighlights(query, null);
      return;
    }
    this.findIndex = (this.findIndex + delta + matches.length) % matches.length;
    this.findCountEl.textContent = this.formatFindCounter();
    const hit = matches[this.findIndex];
    this.stream.setFindHighlights(query, hit);
    this.stream.highlightBlockMatch(hit.blockId, hit.from, hit.to);
  }

  private async runReplaceAll(): Promise<void> {
    const q = this.findInputEl.value;
    if (!q) return;
    const count = await this.stream.replaceAllAcrossBlocks(q, this.replaceInputEl.value);
    this.showToast(t("find.toastReplaced", { count }));
    this.runFind(0);
  }

  private async triggerSyncNow(): Promise<void> {
    try {
      this.syncStatus = await this.api.syncNow();
      this.updateAlertsFromStatus(this.syncStatus);
      this.renderSyncPill();
      this.showToast(t("sync.toastStatus", { state: this.syncStatus.sync_state }));
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
