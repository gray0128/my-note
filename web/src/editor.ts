import { Annotation, Compartment, EditorState, type Extension } from "@codemirror/state";
import { EditorView, keymap } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { loadLangExtension, loadVimExtension, SUPPORTED_LANGS } from "./langs";
import type { BlockDto } from "./types";

const REMOTE_SYNC_ANN = Annotation.define<boolean>();
const INITIAL_MOUNT_WINDOW = 20;
const LARGE_BLOCK_BYTES = 64 * 1024;

export interface BlockEditorCallbacks {
  onSaveContent(block: BlockDto, content: string, opts: { fastSync: boolean; isMerge: boolean }): Promise<void>;
  onChangeLang(block: BlockDto, lang: string): Promise<void>;
  onInsertAfter(afterBlockId: string): Promise<void>;
  onFormatBlock(block: BlockDto): Promise<void>;
  onCopyBlock(block: BlockDto, content: string): Promise<void>;
  onMoveBlock(block: BlockDto, dir: -1 | 1): Promise<void>;
  onDeleteBlock(block: BlockDto): Promise<void>;
  onKeepVersion(block: BlockDto, opId: string): Promise<void>;
  onActiveChange(blockId: string | null): void;
}

interface MountedEditor {
  view: EditorView;
  langComp: Compartment;
  vimComp: Compartment;
  langLoaded: string;
}

/**
 * Candidate A (ADR-07 Accepted): Viewport-virtualized per-block CodeMirror 6 stream.
 * - Physically isolates block boundaries against Vim `dd`/`dG` and `Mod-a`+`Backspace`.
 * - Bridges `ArrowUp`/`ArrowDown` cursor jumps and 2-stage `Mod-a`.
 * - Distinguishes explicit user edits from remote hydration (`REMOTE_SYNC_ANN`).
 */
export class BlockStreamController {
  private blocks: BlockDto[] = [];
  private mounted = new Map<string, MountedEditor>();
  private cards = new Map<string, HTMLElement>();
  private dirty = new Map<string, string>();
  private saveTimers = new Map<string, number>();
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
            if (entry.isIntersecting) {
              const blk = this.blocks.find((b) => b.id === id);
              if (blk && !blk.is_locked && !this.mounted.has(id)) {
                this.mountEditorForBlock(blk);
              }
            }
          }
        },
        { root: container, rootMargin: "400px 0px" },
      );
    }
  }

  getBlocks(): BlockDto[] {
    return this.blocks;
  }

  getActiveBlockId(): string | null {
    return this.activeBlockId;
  }

  getBlockDraftContent(id: string): string {
    const m = this.mounted.get(id);
    if (m) return m.view.state.doc.toString();
    if (this.dirty.has(id)) return this.dirty.get(id)!;
    return this.blocks.find((b) => b.id === id)?.content ?? "";
  }

  setVimMode(enabled: boolean): void {
    this.vimMode = enabled;
    const apply = async () => {
      const ext = enabled ? await loadVimExtension() : [];
      for (const m of this.mounted.values()) {
        m.view.dispatch({ effects: m.vimComp.reconfigure(ext) });
      }
    };
    void apply();
  }

  setBlocks(nextBlocks: BlockDto[]): void {
    const nextIds = new Set(nextBlocks.map((b) => b.id));
    for (const [id, m] of [...this.mounted.entries()]) {
      if (!nextIds.has(id)) {
        m.view.destroy();
        this.mounted.delete(id);
        this.dirty.delete(id);
        this.clearTimer(id);
      }
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
        if (idx >= 0) list.splice(idx, 1);
        continue;
      }
      if (idx >= 0) list[idx] = u;
      else list.push(u);
    }
    list.sort((a, b) => (a.position < b.position ? -1 : a.position > b.position ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    this.blocks = list;
    this.syncDomAndEditors();
  }

  focusBlock(id: string, pos = 0): void {
    const blk = this.blocks.find((b) => b.id === id);
    if (!blk || blk.is_locked) return;
    if (!this.mounted.has(id)) this.mountEditorForBlock(blk);
    const m = this.mounted.get(id);
    if (!m) return;
    const clamped = Math.max(0, Math.min(pos, m.view.state.doc.length));
    m.view.dispatch({ selection: { anchor: clamped } });
    m.view.focus();
    this.setActive(id);
  }

  focusLangSelector(id: string): void {
    const card = this.cards.get(id);
    const sel = card?.querySelector<HTMLSelectElement>(".lang-select");
    sel?.focus();
  }

  async flushDirtyBlock(id: string, opts: { fastSync: boolean; isMerge?: boolean }): Promise<void> {
    this.clearTimer(id);
    const blk = this.blocks.find((b) => b.id === id);
    if (!blk || blk.is_locked) return;
    const draft = this.getBlockDraftContent(id);
    const isMerge = opts.isMerge ?? blk.has_conflict;
    if (!this.dirty.has(id) && !isMerge) return;
    await this.cb.onSaveContent(blk, draft, { fastSync: opts.fastSync, isMerge });
    this.dirty.delete(id);
    this.updateDirtyBadge(id, false);
  }

  findAcrossBlocks(query: string): { blockId: string; from: number; to: number }[] {
    if (!query) return [];
    const lower = query.toLowerCase();
    const out: { blockId: string; from: number; to: number }[] = [];
    for (const b of this.blocks) {
      if (b.is_locked) continue;
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
      if (b.is_locked || b.has_conflict) continue;
      const text = this.getBlockDraftContent(b.id);
      const parts = text.split(query);
      if (parts.length <= 1) continue;
      total += parts.length - 1;
      const next = parts.join(replacement);
      const m = this.mounted.get(b.id);
      if (m) {
        m.view.dispatch({
          changes: { from: 0, to: m.view.state.doc.length, insert: next },
          annotations: REMOTE_SYNC_ANN.of(true),
        });
      }
      await this.cb.onSaveContent(b, next, { fastSync: true, isMerge: false });
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

  private updateDirtyBadge(id: string, isDirty: boolean): void {
    const badge = this.cards.get(id)?.querySelector<HTMLElement>(".dirty-badge");
    if (badge) badge.textContent = isDirty ? "● unsaved" : "";
  }

  private jumpAdjacent(currentId: string, dir: -1 | 1): boolean {
    const editable = this.blocks.filter((b) => !b.is_locked);
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

      if (!block.is_locked && (index < INITIAL_MOUNT_WINDOW || block.id === this.activeBlockId || this.dirty.has(block.id))) {
        this.mountEditorForBlock(block);
      }
    });
  }

  private syncDomAndEditors(): void {
    // Reconcile cleanly while preserving mounted editors that are still present and updating remote text
    const currentOrder = [...this.cards.keys()];
    const desiredOrder = this.blocks.map((b) => b.id);
    const structureChanged =
      currentOrder.length !== desiredOrder.length ||
      currentOrder.some((id, idx) => id !== desiredOrder[idx]) ||
      this.blocks.some((b) => {
        const card = this.cards.get(b.id);
        return !card || card.classList.contains("has-conflict") !== b.has_conflict || card.dataset.locked !== String(b.is_locked);
      });

    if (structureChanged) {
      this.renderStream();
      return;
    }

    for (const b of this.blocks) {
      const card = this.cards.get(b.id);
      if (!card) continue;
      const sel = card.querySelector<HTMLSelectElement>(".lang-select");
      if (sel && sel.value !== b.lang) sel.value = b.lang;
      const m = this.mounted.get(b.id);
      if (m && !this.dirty.has(b.id) && b.content !== null) {
        const curDoc = m.view.state.doc.toString();
        if (curDoc !== b.content) {
          m.view.dispatch({
            changes: { from: 0, to: curDoc.length, insert: b.content },
            annotations: REMOTE_SYNC_ANN.of(true),
          });
        }
        if (m.langLoaded !== b.lang) {
          m.langLoaded = b.lang;
          void loadLangExtension(b.lang).then((ext) => m.view.dispatch({ effects: m.langComp.reconfigure(ext) }));
        }
      } else if (!m && !b.is_locked) {
        const pre = card.querySelector<HTMLElement>(".block-placeholder");
        if (pre && b.content !== null) pre.textContent = b.content;
      }
      this.renderConflictSection(card, b);
    }
  }

  private buildCard(block: BlockDto): HTMLElement {
    const card = document.createElement("section");
    card.className = `block-card${block.has_conflict ? " has-conflict" : ""}${block.id === this.activeBlockId ? " focused" : ""}`;
    card.dataset.blockId = block.id;
    card.dataset.lang = block.lang;
    card.dataset.locked = String(block.is_locked);

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

    const displayLeaf = block.versions.find((v) => v.is_display);
    if (displayLeaf && displayLeaf.actor && displayLeaf.actor !== "human") {
      const actorBadge = document.createElement("span");
      actorBadge.className = "actor-badge";
      actorBadge.textContent = displayLeaf.actor;
      left.appendChild(actorBadge);
    }

    const dirtyBadge = document.createElement("span");
    dirtyBadge.className = "dirty-badge";
    dirtyBadge.textContent = this.dirty.has(block.id) ? "● unsaved" : "";
    left.appendChild(dirtyBadge);

    const right = document.createElement("div");
    right.className = "block-header-right";

    const mkBtn = (label: string, title: string, cls: string, onClick: () => void) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `btn btn-icon ${cls}`.trim();
      btn.textContent = label;
      btn.title = title;
      btn.addEventListener("click", onClick);
      return btn;
    };

    if (!block.is_locked) {
      right.appendChild(
        mkBtn("Format", "Format block (Cmd/Ctrl+Shift+F)", "", () => {
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

    if (block.is_locked) {
      const locked = document.createElement("div");
      locked.className = "locked-card";
      locked.textContent = `🔒 Locked Tier 2 Block${block.public_hint ? ` (${block.public_hint})` : ""}${
        block.has_unlocked_concurrent_version ? " — has unlocked concurrent version" : ""
      }`;
      card.appendChild(locked);
    } else {
      const host = document.createElement("div");
      host.className = "block-editor-host";
      const pre = document.createElement("pre");
      pre.className = "block-placeholder";
      pre.textContent = this.dirty.get(block.id) ?? block.content ?? "";
      pre.addEventListener("click", () => {
        const cur = this.blocks.find((x) => x.id === block.id);
        if (cur) {
          this.mountEditorForBlock(cur);
          this.focusBlock(cur.id);
        }
      });
      host.appendChild(pre);
      card.appendChild(host);
    }

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
    if (block.versions.length <= 1 || block.is_locked) return;

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
      keepBtn.addEventListener("click", () => {
        const cur = this.blocks.find((x) => x.id === block.id);
        if (cur) void this.cb.onKeepVersion(cur, v.op_id);
      });
      meta.append(label, keepBtn);
      const body = document.createElement("pre");
      body.className = "leaf-body";
      body.textContent = v.content ?? "<sealed>";
      leafCard.append(meta, body);
      leavesGrid.appendChild(leafCard);
    }
    panel.appendChild(leavesGrid);
    slot.appendChild(panel);
  }

  private mountEditorForBlock(block: BlockDto): void {
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
          if (cur && !cur.has_conflict && this.dirty.has(block.id)) {
            void this.flushDirtyBlock(block.id, { fastSync: true, isMerge: false });
          }
          return false;
        },
      }),
      EditorView.updateListener.of((u) => {
        if (u.focusChanged && u.view.hasFocus) {
          this.setActive(block.id);
        }
        if (u.docChanged) {
          const isRemote = u.transactions.every((tr) => tr.annotation(REMOTE_SYNC_ANN) === true);
          if (isRemote) return;
          this.bufferAllSelected = false;
          this.container.classList.remove("buffer-all-selected");
          const text = u.state.doc.toString();
          this.dirty.set(block.id, text);
          this.updateDirtyBadge(block.id, true);
          const cur = this.blocks.find((x) => x.id === block.id);
          // Conflicted multi-leaf blocks require explicit merge confirmation so edits never silently discard sibling leaves
          if (!cur || cur.has_conflict) return;
          const isPaste = u.transactions.some((tr) => tr.isUserEvent("input.paste"));
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

    const initialDoc = this.dirty.get(block.id) ?? block.content ?? "";
    const view = new EditorView({
      state: EditorState.create({ doc: initialDoc, extensions: exts }),
      parent: host,
    });
    this.mounted.set(block.id, { view, langComp, vimComp, langLoaded: block.lang });

    void loadLangExtension(block.lang).then((ext) => {
      const m = this.mounted.get(block.id);
      if (m) m.view.dispatch({ effects: m.langComp.reconfigure(ext) });
    });
    if (this.vimMode) {
      void loadVimExtension().then((ext) => {
        const m = this.mounted.get(block.id);
        if (m) m.view.dispatch({ effects: m.vimComp.reconfigure(ext) });
      });
    }
  }
}
