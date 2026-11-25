import { Annotation, Compartment, EditorState, type Extension } from "@codemirror/state";
import { EditorView, keymap } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { loadLangExtension, loadVimExtension, SUPPORTED_LANGS } from "./langs";
import type { BlockDto } from "./types";
import { detectSecretPatternFast } from "./wasm/desktop";

const REMOTE_SYNC_ANN = Annotation.define<boolean>();
const INITIAL_MOUNT_WINDOW = 20;
const LARGE_BLOCK_BYTES = 64 * 1024;

export type SaveContentResult =
  | { status: "ok"; updated: BlockDto }
  | { status: "head_mismatch" }
  | { status: "error" };

export interface BlockEditorCallbacks {
  onSaveContent(
    block: BlockDto,
    content: string,
    expectedHeads: string[],
    opts: { fastSync: boolean; isMerge: boolean; keepalive?: boolean },
  ): Promise<SaveContentResult>;
  onChangeLang(block: BlockDto, lang: string): Promise<void>;
  onInsertAfter(afterBlockId: string): Promise<void>;
  onFormatBlock(block: BlockDto): Promise<void>;
  onCopyBlock(block: BlockDto, content: string): Promise<void>;
  onMoveBlock(block: BlockDto, dir: -1 | 1): Promise<void>;
  onDeleteBlock(block: BlockDto): Promise<void>;
  onKeepVersion(block: BlockDto, opId: string): Promise<void>;
  onActiveChange(blockId: string | null): void;
  onUnlockVaultRequest?(): void;
  onLockBlock?(block: BlockDto): Promise<void>;
  onUnlockBlockToTier1?(block: BlockDto): Promise<void>;
  onPurgeHistory?(block: BlockDto): Promise<void>;
  onSecretPasted?(block: BlockDto, secretType: string): void;
  onVaultActivity?(): void;
}

interface MountedEditor {
  view: EditorView;
  langComp: Compartment;
  vimComp: Compartment;
  langLoaded: string;
}

interface DirtyDraft {
  text: string;
  baseHeads: string[];
  mismatch: boolean;
}

/**
 * Candidate A (ADR-07 Accepted): Viewport-virtualized per-block CodeMirror 6 stream.
 * - Physically isolates block boundaries against Vim `dd`/`dG` and `Mod-a`+`Backspace`.
 * - Bridges `ArrowUp`/`ArrowDown` cursor jumps and 2-stage `Mod-a`.
 * - Preserves original `baseHeads` per dirty draft so concurrent remote edits trigger `HEAD_MISMATCH`
 *   instead of silently overwriting sibling writes (`AGENTS.md` §3.1).
 * - Serializes per-block in-flight saves so keystrokes typed during PATCH are never clobbered.
 * - Holds decrypted Tier 2 plaintext strictly in RAM (`unlockedPlaintext`) and scrubs DOM/editors on lock (`SEC-03`).
 */
export class BlockStreamController {
  private blocks: BlockDto[] = [];
  private mounted = new Map<string, MountedEditor>();
  private cards = new Map<string, HTMLElement>();
  private dirty = new Map<string, DirtyDraft>();
  private saving = new Set<string>();
  private savingPromises = new Map<string, Promise<void>>();
  private pendingResave = new Map<string, { fastSync: boolean; isMerge: boolean; keepalive?: boolean }>();
  private saveTimers = new Map<string, number>();
  private unlockedPlaintext = new Map<string, string>();
  private unlockedLeafPlaintext = new Map<string, Map<string, string>>();
  private activeBlockId: string | null = null;
  private bufferAllSelected = false;
  private vimMode = false;
  private observer: IntersectionObserver | null = null;

  constructor(private container: HTMLElement, private cb: BlockEditorCallbacks) {
    if (typeof IntersectionObserver !== "undefined") {
      this.observer = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            const id = (entry.target as HTMLElement).dataset.blockId;
            if (!id) continue;
            const blk = this.blocks.find((b) => b.id === id);
            if (!blk) continue;
            if (entry.isIntersecting) {
              if (this.isEditable(blk) && !this.mounted.has(id)) {
                this.mountEditorForBlock(blk);
              }
            } else if (
              this.mounted.has(id) &&
              id !== this.activeBlockId &&
              !this.dirty.has(id) &&
              !this.saving.has(id)
            ) {
              this.unmountEditorForBlock(blk);
            }
          }
        },
        { root: container, rootMargin: "400px 0px" },
      );
    }
  }

  private isEditable(block: BlockDto): boolean {
    if (block.is_locked) {
      return this.unlockedPlaintext.has(block.id);
    }
    return block.content !== null;
  }

  isBlockEditable(id: string): boolean {
    const blk = this.blocks.find((b) => b.id === id);
    return blk ? this.isEditable(blk) : false;
  }

  private getEffectiveContent(block: BlockDto): string | null {
    if (block.is_locked) {
      return this.unlockedPlaintext.get(block.id) ?? null;
    }
    return block.content;
  }

  setUnlockedPlaintext(blockId: string, content: string, leafMap?: Map<string, string>): void {
    this.unlockedPlaintext.set(blockId, content);
    if (leafMap) {
      this.unlockedLeafPlaintext.set(blockId, leafMap);
    }
    this.syncDomAndEditors();
  }

  /** Immediately wipe all transient Tier 2 plaintext from RAM, destroy Tier 2 CM6 views, and restore locked cards (`SEC-03`). */
  clearUnlockedVaultPlaintext(): void {
    const lockedIds = new Set(this.blocks.filter((b) => b.is_locked).map((b) => b.id));
    for (const id of [...this.unlockedPlaintext.keys(), ...lockedIds]) {
      this.clearTimer(id);
      this.dirty.delete(id);
      this.pendingResave.delete(id);
      const m = this.mounted.get(id);
      if (m) {
        m.view.destroy();
        this.mounted.delete(id);
      }
      const card = this.cards.get(id);
      if (card) {
        const host = card.querySelector<HTMLElement>(".block-editor-host");
        if (host) host.textContent = "";
      }
    }
    this.unlockedPlaintext.clear();
    this.unlockedLeafPlaintext.clear();
    this.syncDomAndEditors();
  }

  getBlocks(): BlockDto[] {
    return this.blocks;
  }

  getActiveBlockId(): string | null {
    return this.activeBlockId;
  }

  hasDirtyBlocks(): boolean {
    return this.dirty.size > 0;
  }

  getExpectedHeadsForBlock(id: string): string[] {
    const entry = this.dirty.get(id);
    if (entry) return [...entry.baseHeads];
    return [...(this.blocks.find((b) => b.id === id)?.head_op_ids ?? [])];
  }

  getBlockDraftContent(id: string): string {
    const m = this.mounted.get(id);
    if (m) return m.view.state.doc.toString();
    const d = this.dirty.get(id);
    if (d) return d.text;
    if (this.unlockedPlaintext.has(id)) return this.unlockedPlaintext.get(id) ?? "";
    return this.blocks.find((b) => b.id === id)?.content ?? "";
  }

  clearDirty(id: string): void {
    this.clearTimer(id);
    this.dirty.delete(id);
    this.pendingResave.delete(id);
    this.updateDirtyBadge(id, false);
    this.renderMismatchNotice(id, false);
  }

  getUnlockedLeafContent(blockId: string, opId: string): string | null {
    return this.unlockedLeafPlaintext.get(blockId)?.get(opId) ?? null;
  }

  /** Apply an authoritative server block (e.g. after format or conflict keep) replacing any local draft. */
  applyAuthoritativeBlock(updated: BlockDto, currentBufferId: string | null, decryptedContent?: string): void {
    if (updated.is_locked && decryptedContent !== undefined) {
      this.unlockedPlaintext.set(updated.id, decryptedContent);
    } else if (!updated.is_locked) {
      this.unlockedPlaintext.delete(updated.id);
      this.unlockedLeafPlaintext.delete(updated.id);
    }
    this.clearDirty(updated.id);
    this.upsertBlocks([updated], [], currentBufferId);
  }

  setVimMode(enabled: boolean): void {
    this.vimMode = enabled;
    const apply = async () => {
      const ext = enabled ? await loadVimExtension() : [];
      if (this.vimMode !== enabled) return;
      for (const [id, m] of this.mounted.entries()) {
        if (this.mounted.get(id) === m) {
          m.view.dispatch({ effects: m.vimComp.reconfigure(ext) });
        }
      }
    };
    void apply();
  }

  setBlocks(nextBlocks: BlockDto[]): void {
    const nextIds = new Set(nextBlocks.map((b) => b.id));
    for (const id of [...this.saveTimers.keys()]) {
      if (!nextIds.has(id)) this.clearTimer(id);
    }
    for (const id of [...this.dirty.keys()]) {
      if (!nextIds.has(id)) this.dirty.delete(id);
    }
    for (const id of [...this.pendingResave.keys()]) {
      if (!nextIds.has(id)) this.pendingResave.delete(id);
    }
    for (const [id, m] of [...this.mounted.entries()]) {
      if (!nextIds.has(id)) {
        m.view.destroy();
        this.mounted.delete(id);
      }
    }
    if (this.activeBlockId && !nextIds.has(this.activeBlockId)) {
      this.activeBlockId = null;
    }
    this.blocks = nextBlocks;
    this.renderStream();
  }

  upsertBlocks(upserted: BlockDto[], deletedIds: string[], currentBufferId: string | null): void {
    const delSet = new Set(deletedIds);
    let list = this.blocks.filter((b) => !delSet.has(b.id));
    for (const u of upserted) {
      const idx = list.findIndex((b) => b.id === u.id);
      if (currentBufferId && u.buffer_id !== currentBufferId) {
        if (idx >= 0) {
          list.splice(idx, 1);
          delSet.add(u.id);
        }
        continue;
      }
      if (idx >= 0) list[idx] = u;
      else list.push(u);
    }
    for (const id of delSet) {
      this.clearTimer(id);
      this.dirty.delete(id);
      this.pendingResave.delete(id);
      if (this.activeBlockId === id) this.activeBlockId = null;
    }
    list.sort((a, b) => (a.position < b.position ? -1 : a.position > b.position ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    this.blocks = list;
    this.syncDomAndEditors();
  }

  focusBlock(id: string, pos = 0): void {
    const blk = this.blocks.find((b) => b.id === id);
    if (!blk || !this.isEditable(blk)) return;
    if (!this.mounted.has(id)) this.mountEditorForBlock(blk);
    const m = this.mounted.get(id);
    if (!m) return;
    const clamped = Math.max(0, Math.min(pos, m.view.state.doc.length));
    m.view.dispatch({ selection: { anchor: clamped } });
    m.view.focus();
    this.setActive(id);
  }

  /** Highlight a search match inside a block WITHOUT stealing keyboard focus from the Find bar input. */
  highlightBlockMatch(id: string, from: number, to: number): void {
    const blk = this.blocks.find((b) => b.id === id);
    if (!blk || !this.isEditable(blk)) return;
    if (!this.mounted.has(id)) this.mountEditorForBlock(blk);
    const m = this.mounted.get(id);
    if (!m) return;
    const max = m.view.state.doc.length;
    const a = Math.max(0, Math.min(from, max));
    const b = Math.max(a, Math.min(to, max));
    m.view.dispatch({ selection: { anchor: a, head: b }, scrollIntoView: true });
    this.cards.get(id)?.scrollIntoView?.({ block: "nearest" });
    this.setActive(id);
  }

  focusLangSelector(id: string): void {
    const card = this.cards.get(id);
    const sel = card?.querySelector<HTMLSelectElement>(".lang-select");
    sel?.focus();
  }

  async flushAllDirty(opts: { keepalive?: boolean } = {}): Promise<void> {
    const ids = [...this.dirty.entries()]
      .filter(([, d]) => !d.mismatch)
      .map(([id]) => id);
    await Promise.all(
      ids.map((id) => {
        const blk = this.blocks.find((b) => b.id === id);
        if (!blk || blk.has_conflict) return Promise.resolve();
        return this.flushDirtyBlock(id, { fastSync: true, isMerge: false, keepalive: opts.keepalive });
      }),
    );
  }

  async waitForSaveIdle(id: string): Promise<void> {
    this.clearTimer(id);
    while (this.savingPromises.has(id)) {
      await this.savingPromises.get(id);
    }
  }

  async flushDirtyBlock(id: string, opts: { fastSync: boolean; isMerge?: boolean; keepalive?: boolean }): Promise<void> {
    this.clearTimer(id);
    const blk = this.blocks.find((b) => b.id === id);
    if (!blk || !this.isEditable(blk)) return;

    const entry = this.dirty.get(id);
    const isMerge = opts.isMerge ?? blk.has_conflict;
    if (!entry && !isMerge) return;
    if (entry?.mismatch && !isMerge) return;

    if (this.saving.has(id)) {
      const prev = this.pendingResave.get(id);
      this.pendingResave.set(id, {
        fastSync: opts.fastSync || (prev?.fastSync ?? false),
        isMerge: isMerge || (prev?.isMerge ?? false),
        keepalive: opts.keepalive || prev?.keepalive,
      });
      return;
    }

    const draft = this.getBlockDraftContent(id);
    // Use ORIGINAL baseHeads captured when editing began (so concurrent remote updates trigger HEAD_MISMATCH
    // rather than silently overwriting!). Explicit merge intentionally passes all current remote head_op_ids.
    const expectedHeads = isMerge ? [...blk.head_op_ids] : [...(entry?.baseHeads ?? blk.head_op_ids)];

    this.saving.add(id);
    const run = (async () => {
      try {
        const res = await this.cb.onSaveContent(blk, draft, expectedHeads, {
          fastSync: opts.fastSync,
          isMerge,
          keepalive: opts.keepalive,
        });
        if (res.status === "ok") {
          const currentDraft = this.getBlockDraftContent(id);
          if (currentDraft === draft) {
            this.dirty.delete(id);
            this.updateDirtyBadge(id, false);
            this.renderMismatchNotice(id, false);
          } else {
            // User continued typing while PATCH was in flight: advance baseHeads to the saved head and re-queue save!
            this.dirty.set(id, { text: currentDraft, baseHeads: [...res.updated.head_op_ids], mismatch: false });
            this.updateDirtyBadge(id, true);
            this.renderMismatchNotice(id, false);
            const prev = this.pendingResave.get(id);
            this.pendingResave.set(id, {
              fastSync: opts.fastSync || (prev?.fastSync ?? false),
              isMerge: false,
              keepalive: opts.keepalive || prev?.keepalive,
            });
          }
          this.upsertBlocks([res.updated], [], res.updated.buffer_id);
        } else if (res.status === "head_mismatch") {
          // Keep the user's draft intact in the editor, halt auto-save, and offer explicit Merge or Reload!
          this.clearTimer(id);
          this.dirty.set(id, {
            text: this.getBlockDraftContent(id),
            baseHeads: expectedHeads,
            mismatch: true,
          });
          this.updateDirtyBadge(id, true, "● conflict (unsaved draft)");
          this.renderMismatchNotice(id, true);
        } else {
          this.updateDirtyBadge(id, true, "● save failed");
        }
      } finally {
        this.saving.delete(id);
        this.savingPromises.delete(id);
        const next = this.pendingResave.get(id);
        if (next) {
          this.pendingResave.delete(id);
          void this.flushDirtyBlock(id, next);
        }
      }
    })();
    this.savingPromises.set(id, run);
    await run;
  }

  findAcrossBlocks(query: string): { blockId: string; from: number; to: number }[] {
    if (!query) return [];
    const lower = query.toLowerCase();
    const out: { blockId: string; from: number; to: number }[] = [];
    for (const b of this.blocks) {
      if (!this.isEditable(b)) continue;
      const text = this.getBlockDraftContent(b.id).toLowerCase();
      let idx = 0;
      while ((idx = text.indexOf(lower, idx)) !== -1) {
        out.push({ blockId: b.id, from: idx, to: idx + query.length });
        idx += Math.max(1, query.length);
      }
    }
    return out;
  }

  async replaceAllAcrossBlocks(query: string, replacement: string): Promise<number> {
    if (!query) return 0;
    let total = 0;
    for (const b of this.blocks) {
      if (!this.isEditable(b) || b.has_conflict) continue;
      const text = this.getBlockDraftContent(b.id);
      const parts = text.split(query);
      if (parts.length <= 1) continue;
      total += parts.length - 1;
      const next = parts.join(replacement);
      const expectedHeads = this.getExpectedHeadsForBlock(b.id);
      this.clearTimer(b.id);
      const m = this.mounted.get(b.id);
      if (m) {
        m.view.dispatch({
          changes: { from: 0, to: m.view.state.doc.length, insert: next },
          annotations: REMOTE_SYNC_ANN.of(true),
        });
      }
      const res = await this.cb.onSaveContent(b, next, expectedHeads, { fastSync: true, isMerge: false });
      if (res.status === "ok") {
        this.applyAuthoritativeBlock(res.updated, b.buffer_id, b.is_locked ? next : undefined);
      }
    }
    return total;
  }

  isBufferAllSelected(): boolean {
    return this.bufferAllSelected;
  }

  destroy(): void {
    this.observer?.disconnect();
    for (const id of [...this.saveTimers.keys()]) this.clearTimer(id);
    for (const m of this.mounted.values()) m.view.destroy();
    this.mounted.clear();
    this.cards.clear();
    this.dirty.clear();
    this.saving.clear();
    this.pendingResave.clear();
  }

  private clearTimer(id: string): void {
    const t = this.saveTimers.get(id);
    if (t !== undefined) {
      window.clearTimeout(t);
      this.saveTimers.delete(id);
    }
  }

  private setActive(id: string | null): void {
    if (this.activeBlockId === id) return;
    if (this.activeBlockId) this.cards.get(this.activeBlockId)?.classList.remove("focused");
    this.activeBlockId = id;
    if (id) this.cards.get(id)?.classList.add("focused");
    this.cb.onActiveChange(id);
  }

  private updateDirtyBadge(id: string, isDirty: boolean, label = "● unsaved"): void {
    const badge = this.cards.get(id)?.querySelector<HTMLElement>(".dirty-badge");
    if (badge) badge.textContent = isDirty ? label : "";
  }

  private renderMismatchNotice(id: string, show: boolean): void {
    const card = this.cards.get(id);
    if (!card) return;
    let slot = card.querySelector<HTMLElement>(".mismatch-slot");
    if (!slot) {
      slot = document.createElement("div");
      slot.className = "mismatch-slot";
      card.appendChild(slot);
    }
    slot.innerHTML = "";
    if (!show) return;

    const bar = document.createElement("div");
    bar.className = "conflict-panel mismatch-panel";
    const msg = document.createElement("span");
    msg.textContent = "Concurrent edit detected on server — your unsaved draft is preserved.";
    const actions = document.createElement("div");
    actions.className = "block-header-right";

    const mergeBtn = document.createElement("button");
    mergeBtn.type = "button";
    mergeBtn.className = "btn btn-primary btn-icon";
    mergeBtn.textContent = "Save My Draft Over Latest";
    mergeBtn.addEventListener("click", () => {
      void this.flushDirtyBlock(id, { fastSync: true, isMerge: true });
    });

    const reloadBtn = document.createElement("button");
    reloadBtn.type = "button";
    reloadBtn.className = "btn btn-icon";
    reloadBtn.textContent = "Discard Draft & Load Latest";
    reloadBtn.addEventListener("click", () => {
      this.clearDirty(id);
      const blk = this.blocks.find((b) => b.id === id);
      if (blk) this.syncDomAndEditors();
    });

    actions.append(mergeBtn, reloadBtn);
    bar.append(msg, actions);
    slot.appendChild(bar);
  }

  private jumpAdjacent(currentId: string, dir: -1 | 1): boolean {
    const editable = this.blocks.filter((b) => this.isEditable(b));
    const idx = editable.findIndex((b) => b.id === currentId);
    const target = editable[idx + dir];
    if (!target) return false;
    const cur = this.mounted.get(currentId);
    if (!this.mounted.has(target.id)) this.mountEditorForBlock(target);
    const next = this.mounted.get(target.id);
    if (!cur || !next) return false;

    const head = cur.view.state.selection.main.head;
    const curLine = cur.view.state.doc.lineAt(head);
    const col = head - curLine.from;
    const targetLine = dir === 1 ? next.view.state.doc.line(1) : next.view.state.doc.line(next.view.state.doc.lines);
    const targetPos = Math.min(targetLine.from + col, targetLine.to);

    next.view.dispatch({ selection: { anchor: targetPos } });
    next.view.focus();
    this.setActive(target.id);
    this.bufferAllSelected = false;
    this.container.classList.remove("buffer-all-selected");
    return true;
  }

  private renderStream(): void {
    this.observer?.disconnect();
    for (const m of this.mounted.values()) m.view.destroy();
    this.mounted.clear();
    this.cards.clear();
    this.container.innerHTML = "";

    if (this.blocks.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "This buffer has no blocks yet. Press Ctrl/Cmd+Enter or click '+ New Block' to start writing.";
      this.container.appendChild(empty);
      return;
    }

    this.blocks.forEach((block, index) => {
      const card = this.buildCard(block);
      this.cards.set(block.id, card);
      this.container.appendChild(card);
      this.observer?.observe(card);

      if (this.isEditable(block) && (index < INITIAL_MOUNT_WINDOW || block.id === this.activeBlockId || this.dirty.has(block.id))) {
        this.mountEditorForBlock(block);
      }
      if (this.dirty.get(block.id)?.mismatch) {
        this.renderMismatchNotice(block.id, true);
      }
    });
  }

  /**
   * Incremental DOM reconciliation: adds/removes/reorders cards in place so inserting or deleting
   * another block NEVER destroys, blurs, or resets undo history on an actively edited CodeMirror view.
   */
  private syncDomAndEditors(): void {
    if (this.blocks.length === 0) {
      this.renderStream();
      return;
    }
    const emptyEl = this.container.querySelector(".empty-state");
    if (emptyEl) emptyEl.remove();

    const desiredIds = new Set(this.blocks.map((b) => b.id));
    for (const [id, card] of [...this.cards.entries()]) {
      if (!desiredIds.has(id)) {
        this.observer?.unobserve(card);
        const m = this.mounted.get(id);
        if (m) {
          m.view.destroy();
          this.mounted.delete(id);
        }
        card.remove();
        this.cards.delete(id);
      }
    }

    this.blocks.forEach((b, index) => {
      let card = this.cards.get(b.id);
      const desiredEditable = this.isEditable(b);
      const modeChanged =
        !card ||
        card.dataset.locked !== String(b.is_locked) ||
        card.dataset.editable !== String(desiredEditable);

      if (modeChanged) {
        if (card) {
          this.observer?.unobserve(card);
          const oldMounted = this.mounted.get(b.id);
          if (oldMounted) {
            oldMounted.view.destroy();
            this.mounted.delete(b.id);
          }
          card.remove();
        }
        card = this.buildCard(b);
        this.cards.set(b.id, card);
        this.observer?.observe(card);
      }

      const currentChild = this.container.children[index];
      if (currentChild !== card) {
        this.container.insertBefore(card!, currentChild ?? null);
      }

      if (modeChanged && desiredEditable && (index < INITIAL_MOUNT_WINDOW || b.id === this.activeBlockId || this.dirty.has(b.id))) {
        this.mountEditorForBlock(b);
      }

      card!.classList.toggle("has-conflict", b.has_conflict);
      card!.classList.toggle("focused", b.id === this.activeBlockId);
      card!.dataset.lang = b.lang;

      const sel = card!.querySelector<HTMLSelectElement>(".lang-select");
      if (sel && sel.value !== b.lang) sel.value = b.lang;

      const m = this.mounted.get(b.id);
      const effContent = this.getEffectiveContent(b);
      if (m) {
        if (!this.dirty.has(b.id) && !this.saving.has(b.id) && effContent !== null) {
          const curDoc = m.view.state.doc.toString();
          if (curDoc !== effContent) {
            m.view.dispatch({
              changes: { from: 0, to: curDoc.length, insert: effContent },
              annotations: REMOTE_SYNC_ANN.of(true),
            });
          }
        }
        if (m.langLoaded !== b.lang) {
          const targetLang = b.lang;
          m.langLoaded = targetLang;
          void loadLangExtension(targetLang).then((ext) => {
            if (this.mounted.get(b.id) === m && m.langLoaded === targetLang) {
              m.view.dispatch({ effects: m.langComp.reconfigure(ext) });
            }
          });
        }
      } else if (desiredEditable) {
        const pre = card!.querySelector<HTMLElement>(".block-placeholder");
        if (pre && !this.dirty.has(b.id) && effContent !== null) pre.textContent = effContent;
      }

      this.renderConflictSection(card!, b);
      if (this.dirty.get(b.id)?.mismatch) {
        this.renderMismatchNotice(b.id, true);
      }
    });
  }

  private buildCard(block: BlockDto): HTMLElement {
    const editable = this.isEditable(block);
    const effContent = this.getEffectiveContent(block);
    const card = document.createElement("section");
    card.className = `block-card${block.has_conflict ? " has-conflict" : ""}${block.id === this.activeBlockId ? " focused" : ""}${block.is_locked ? " is-vault-block" : ""}`;
    card.dataset.blockId = block.id;
    card.dataset.lang = block.lang;
    card.dataset.locked = String(block.is_locked);
    card.dataset.editable = String(editable);

    const header = document.createElement("div");
    header.className = "block-header";

    const left = document.createElement("div");
    left.className = "block-header-left";

    const select = document.createElement("select");
    select.className = "lang-select";
    select.setAttribute("aria-label", "Block language");
    const langs = SUPPORTED_LANGS.includes(block.lang as (typeof SUPPORTED_LANGS)[number])
      ? [...SUPPORTED_LANGS]
      : [block.lang, ...SUPPORTED_LANGS];
    for (const l of langs) {
      const opt = document.createElement("option");
      opt.value = l;
      opt.textContent = l;
      if (l === block.lang) opt.selected = true;
      select.appendChild(opt);
    }
    select.addEventListener("change", () => {
      const cur = this.blocks.find((x) => x.id === block.id);
      if (cur) void this.cb.onChangeLang(cur, select.value);
    });
    left.appendChild(select);

    if (block.is_locked) {
      const vBadge = document.createElement("span");
      vBadge.className = `vault-badge${editable ? " unlocked" : ""}`;
      vBadge.textContent = editable ? "🔓 Vault (RAM)" : "🔒 Tier 2";
      left.appendChild(vBadge);
    }

    const displayLeaf = block.versions.find((v) => v.is_display);
    if (displayLeaf && displayLeaf.actor && displayLeaf.actor !== "human") {
      const actorBadge = document.createElement("span");
      actorBadge.className = "actor-badge";
      actorBadge.textContent = displayLeaf.actor;
      left.appendChild(actorBadge);
    }

    const dirtyBadge = document.createElement("span");
    dirtyBadge.className = "dirty-badge";
    const d = this.dirty.get(block.id);
    dirtyBadge.textContent = d ? (d.mismatch ? "● conflict (unsaved draft)" : "● unsaved") : "";
    left.appendChild(dirtyBadge);

    const right = document.createElement("div");
    right.className = "block-header-right";

    const mkBtn = (label: string, title: string, cls: string, onClick: () => void) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `btn btn-icon ${cls}`.trim();
      btn.textContent = label;
      btn.title = title;
      btn.addEventListener("mousedown", (ev) => ev.preventDefault());
      btn.addEventListener("click", onClick);
      return btn;
    };

    if (editable) {
      right.appendChild(
        mkBtn("Format", block.is_locked ? "Format in browser WASM only (zero network)" : "Format block (Cmd/Ctrl+Shift+F)", "", () => {
          const cur = this.blocks.find((x) => x.id === block.id);
          if (cur) void this.cb.onFormatBlock(cur);
        }),
      );
      right.appendChild(
        mkBtn("Copy", "Copy entire block (Cmd/Ctrl+Shift+C)", "", () => {
          const cur = this.blocks.find((x) => x.id === block.id);
          if (cur) void this.cb.onCopyBlock(cur, this.getBlockDraftContent(block.id));
        }),
      );
      if (!block.is_locked && this.cb.onLockBlock) {
        right.appendChild(
          mkBtn("🔒 Lock", "Encrypt block into Tier 2 Vault", "", () => {
            const cur = this.blocks.find((x) => x.id === block.id);
            if (cur) void this.cb.onLockBlock?.(cur);
          }),
        );
      } else if (block.is_locked && this.cb.onUnlockBlockToTier1) {
        right.appendChild(
          mkBtn("To Tier 1", "Downgrade block back to Tier 1", "", () => {
            const cur = this.blocks.find((x) => x.id === block.id);
            if (cur) void this.cb.onUnlockBlockToTier1?.(cur);
          }),
        );
      }
      if (this.cb.onPurgeHistory) {
        right.appendChild(
          mkBtn("Purge Hist", "Schedule old historical keys for cryptographic shred (24h min grace)", "", () => {
            const cur = this.blocks.find((x) => x.id === block.id);
            if (cur) void this.cb.onPurgeHistory?.(cur);
          }),
        );
      }
    }
    right.appendChild(
      mkBtn("↑", "Move block up", "", () => {
        const cur = this.blocks.find((x) => x.id === block.id);
        if (cur) void this.cb.onMoveBlock(cur, -1);
      }),
    );
    right.appendChild(
      mkBtn("↓", "Move block down", "", () => {
        const cur = this.blocks.find((x) => x.id === block.id);
        if (cur) void this.cb.onMoveBlock(cur, 1);
      }),
    );
    right.appendChild(
      mkBtn("+ Below", "New block below (Cmd/Ctrl+Enter)", "", () => {
        void this.cb.onInsertAfter(block.id);
      }),
    );
    right.appendChild(
      mkBtn("Trash", "Move block to recycle bin", "btn-danger", () => {
        const cur = this.blocks.find((x) => x.id === block.id);
        if (cur) void this.cb.onDeleteBlock(cur);
      }),
    );

    header.append(left, right);
    card.appendChild(header);

    if (block.is_locked && !editable) {
      const locked = document.createElement("div");
      locked.className = "locked-card";
      const label = document.createElement("span");
      label.textContent = `🔒 Locked Tier 2 Block${block.public_hint ? ` (${block.public_hint})` : ""}${
        block.has_unlocked_concurrent_version ? " — ⚠ has unlocked concurrent version" : ""
      }`;
      locked.appendChild(label);
      if (this.cb.onUnlockVaultRequest) {
        const unlockBtn = document.createElement("button");
        unlockBtn.type = "button";
        unlockBtn.className = "btn btn-primary btn-icon";
        unlockBtn.textContent = "Unlock Vault";
        unlockBtn.addEventListener("click", () => this.cb.onUnlockVaultRequest?.());
        locked.appendChild(unlockBtn);
      }
      card.appendChild(locked);
    } else if (effContent === null) {
      // Anti-wipe UI guard: NEVER mount an editable empty editor over KEY_UNAVAILABLE / DECRYPT_FAILED!
      const unreadable = document.createElement("div");
      unreadable.className = "unreadable-card";
      unreadable.textContent =
        "⚠ Block content unavailable (missing encryption key or decryption failed) — read-only until keys sync or keyring is unlocked.";
      card.appendChild(unreadable);
    } else {
      const host = document.createElement("div");
      host.className = "block-editor-host";
      const pre = document.createElement("pre");
      pre.className = "block-placeholder";
      pre.textContent = this.dirty.get(block.id)?.text ?? effContent;
      pre.addEventListener("click", () => {
        const cur = this.blocks.find((x) => x.id === block.id);
        if (cur && this.isEditable(cur)) {
          this.mountEditorForBlock(cur);
          this.focusBlock(cur.id);
        }
      });
      host.appendChild(pre);
      card.appendChild(host);
    }

    const mismatchSlot = document.createElement("div");
    mismatchSlot.className = "mismatch-slot";
    card.appendChild(mismatchSlot);

    const conflictSlot = document.createElement("div");
    conflictSlot.className = "conflict-slot";
    card.appendChild(conflictSlot);
    this.renderConflictSection(card, block);
    return card;
  }

  private renderConflictSection(card: HTMLElement, block: BlockDto): void {
    const slot = card.querySelector<HTMLElement>(".conflict-slot");
    if (!slot) return;
    slot.innerHTML = "";
    if (block.versions.length <= 1) return;
    if (block.is_locked && !this.isEditable(block)) return;

    const panel = document.createElement("div");
    panel.className = "conflict-panel";

    const title = document.createElement("div");
    title.className = "conflict-title";
    const span = document.createElement("span");
    span.textContent = `⚡ ${block.versions.length} concurrent versions — review & merge manually (zero silent overwrite)`;
    const commitBtn = document.createElement("button");
    commitBtn.type = "button";
    commitBtn.className = "btn btn-primary btn-icon";
    commitBtn.textContent = "Commit Merged Editor Text";
    commitBtn.disabled = !this.isEditable(block);
    commitBtn.addEventListener("click", () => {
      void this.flushDirtyBlock(block.id, { fastSync: true, isMerge: true });
    });
    title.append(span, commitBtn);
    panel.appendChild(title);

    const leavesGrid = document.createElement("div");
    leavesGrid.className = "conflict-leaves";
    for (const v of block.versions) {
      const leafCard = document.createElement("div");
      leafCard.className = "leaf-card";
      const meta = document.createElement("div");
      meta.className = "leaf-meta";
      const label = document.createElement("span");
      label.textContent = `${v.is_display ? "Displayed" : "Other device"} · ${v.device_id} · ${v.actor}`;
      const keepBtn = document.createElement("button");
      keepBtn.type = "button";
      keepBtn.className = "btn btn-amber btn-icon";
      keepBtn.textContent = "Keep this version";
      const leafText = v.content ?? this.unlockedLeafPlaintext.get(block.id)?.get(v.op_id) ?? null;
      if (leafText === null) {
        keepBtn.disabled = true;
        keepBtn.title = "Cannot keep an unreadable or sealed version";
      } else {
        keepBtn.addEventListener("click", () => {
          const cur = this.blocks.find((x) => x.id === block.id);
          if (cur) void this.cb.onKeepVersion(cur, v.op_id);
        });
      }
      meta.append(label, keepBtn);
      const body = document.createElement("pre");
      body.className = "leaf-body";
      body.textContent = leafText ?? (v.is_locked ? "<sealed>" : "<unavailable — missing key or decrypt failed>");
      leafCard.append(meta, body);
      leavesGrid.appendChild(leafCard);
    }
    panel.appendChild(leavesGrid);
    slot.appendChild(panel);
  }

  private unmountEditorForBlock(block: BlockDto): void {
    const m = this.mounted.get(block.id);
    if (!m) return;
    m.view.destroy();
    this.mounted.delete(block.id);
    const card = this.cards.get(block.id);
    const host = card?.querySelector<HTMLElement>(".block-editor-host");
    if (!host) return;
    host.innerHTML = "";
    const pre = document.createElement("pre");
    pre.className = "block-placeholder";
    pre.textContent = this.getEffectiveContent(block) ?? "";
    pre.addEventListener("click", () => {
      const cur = this.blocks.find((x) => x.id === block.id);
      if (cur && this.isEditable(cur)) {
        this.mountEditorForBlock(cur);
        this.focusBlock(cur.id);
      }
    });
    host.appendChild(pre);
  }

  private mountEditorForBlock(block: BlockDto): void {
    if (!this.isEditable(block)) return;
    const card = this.cards.get(block.id);
    const host = card?.querySelector<HTMLElement>(".block-editor-host");
    if (!card || !host || this.mounted.has(block.id)) return;
    host.innerHTML = "";

    const langComp = new Compartment();
    const vimComp = new Compartment();

    const bridgeKeymap = keymap.of([
      {
        key: "ArrowUp",
        run: (view) => {
          const line = view.state.doc.lineAt(view.state.selection.main.head);
          return line.number === 1 ? this.jumpAdjacent(block.id, -1) : false;
        },
      },
      {
        key: "ArrowDown",
        run: (view) => {
          const line = view.state.doc.lineAt(view.state.selection.main.head);
          return line.number === view.state.doc.lines ? this.jumpAdjacent(block.id, 1) : false;
        },
      },
      {
        key: "Mod-a",
        run: (view) => {
          const sel = view.state.selection.main;
          if (sel.from === 0 && sel.to === view.state.doc.length) {
            this.bufferAllSelected = true;
            this.container.classList.add("buffer-all-selected");
            return true;
          }
          this.bufferAllSelected = false;
          this.container.classList.remove("buffer-all-selected");
          view.dispatch({ selection: { anchor: 0, head: view.state.doc.length } });
          return true;
        },
      },
      {
        key: "Mod-Enter",
        run: () => {
          void this.cb.onInsertAfter(block.id);
          return true;
        },
      },
      {
        key: "Mod-s",
        run: () => {
          void this.flushDirtyBlock(block.id, { fastSync: true });
          return true;
        },
      },
    ]);

    const cspNonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content ?? "";
    const exts: Extension[] = [
      ...(cspNonce ? [EditorView.cspNonce.of(cspNonce)] : []),
      vimComp.of([]),
      bridgeKeymap,
      history(),
      syntaxHighlighting(defaultHighlightStyle),
      langComp.of([]),
      keymap.of([...defaultKeymap, ...historyKeymap]),
      EditorView.domEventHandlers({
        blur: () => {
          const cur = this.blocks.find((x) => x.id === block.id);
          const entry = this.dirty.get(block.id);
          if (cur && !cur.has_conflict && entry && !entry.mismatch) {
            void this.flushDirtyBlock(block.id, { fastSync: true, isMerge: false });
          }
          return false;
        },
      }),
      EditorView.updateListener.of((u) => {
        if (u.focusChanged && u.view.hasFocus) {
          this.setActive(block.id);
          const cur = this.blocks.find((x) => x.id === block.id);
          if (cur?.is_locked) this.cb.onVaultActivity?.();
        }
        if (u.docChanged) {
          const isRemote = u.transactions.every((tr) => tr.annotation(REMOTE_SYNC_ANN) === true);
          if (isRemote) return;
          this.bufferAllSelected = false;
          this.container.classList.remove("buffer-all-selected");
          const text = u.state.doc.toString();
          const cur = this.blocks.find((x) => x.id === block.id);
          if (cur?.is_locked) this.cb.onVaultActivity?.();
          const prevDirty = this.dirty.get(block.id);
          const baseHeads = prevDirty ? prevDirty.baseHeads : [...(cur?.head_op_ids ?? block.head_op_ids)];
          const mismatch = prevDirty?.mismatch ?? false;
          this.dirty.set(block.id, { text, baseHeads, mismatch });
          this.updateDirtyBadge(block.id, true, mismatch ? "● conflict (unsaved draft)" : "● unsaved");
          const isPaste = u.transactions.some((tr) => tr.isUserEvent("input.paste"));
          if (isPaste && cur && !cur.is_locked && this.cb.onSecretPasted) {
            let pasted = "";
            for (const tr of u.transactions) {
              tr.changes.iterChanges((_fa, _ta, _fb, _tb, ins) => {
                pasted += ins.toString();
              });
            }
            const secretHit = detectSecretPatternFast(pasted || text);
            if (secretHit) this.cb.onSecretPasted(cur, secretHit);
          }
          // Conflicted or mismatched blocks require explicit merge confirmation so edits never silently discard sibling leaves
          if (!cur || cur.has_conflict || mismatch) return;
          const delayMs = isPaste ? 50 : text.length > LARGE_BLOCK_BYTES ? 3500 : 450;
          this.clearTimer(block.id);
          this.saveTimers.set(
            block.id,
            window.setTimeout(() => {
              void this.flushDirtyBlock(block.id, { fastSync: isPaste, isMerge: false });
            }, delayMs),
          );
        }
      }),
    ];

    const initialDoc = this.dirty.get(block.id)?.text ?? this.getEffectiveContent(block) ?? "";
    const view = new EditorView({
      state: EditorState.create({ doc: initialDoc, extensions: exts }),
      parent: host,
    });
    const entry: MountedEditor = { view, langComp, vimComp, langLoaded: block.lang };
    this.mounted.set(block.id, entry);

    const initialLang = block.lang;
    void loadLangExtension(initialLang).then((ext) => {
      if (this.mounted.get(block.id) === entry && entry.langLoaded === initialLang) {
        entry.view.dispatch({ effects: entry.langComp.reconfigure(ext) });
      }
    });
    if (this.vimMode) {
      void loadVimExtension().then((ext) => {
        if (this.mounted.get(block.id) === entry && this.vimMode) {
          entry.view.dispatch({ effects: entry.vimComp.reconfigure(ext) });
        }
      });
    }
  }
}
