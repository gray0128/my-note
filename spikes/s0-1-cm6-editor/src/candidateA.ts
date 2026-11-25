import { EditorState, Extension } from "@codemirror/state";
import { EditorView, keymap } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { markdown } from "@codemirror/lang-markdown";
import { sql } from "@codemirror/lang-sql";
import { vim } from "@replit/codemirror-vim";
import { Block, BlockLang } from "./model";

function langExtension(lang: BlockLang): Extension {
  switch (lang) {
    case "javascript":
      return javascript();
    case "json":
      return json();
    case "sql":
      return sql();
    case "markdown":
      return markdown();
    default:
      return [];
  }
}

export interface CandidateAHandle {
  getBlocks(): Block[];
  focusBlock(id: string, pos?: number): void;
  getActiveBlockId(): string | null;
  getView(id: string): EditorView | undefined;
  findAcrossBlocks(query: string): { blockId: string; from: number; to: number }[];
  replaceAllAcrossBlocks(query: string, replacement: string): number;
  isBufferAllSelected(): boolean;
  togglePreview(id: string): void;
  destroy(): void;
}

export function mountCandidateA(
  container: HTMLElement,
  initialBlocks: Block[],
  options: { vimMode?: boolean; virtualize?: boolean } = {},
): CandidateAHandle {
  container.innerHTML = "";
  const blocks: Block[] = initialBlocks.map((b) => ({ ...b }));
  const views = new Map<string, EditorView>();
  let activeBlockId: string | null = null;
  let bufferAllSelected = false;

  const editableIds = () => blocks.filter((b) => !b.locked && !b.preview).map((b) => b.id);

  function jumpAdjacent(currentId: string, dir: -1 | 1): boolean {
    const ids = editableIds();
    const idx = ids.indexOf(currentId);
    const targetId = ids[idx + dir];
    if (!targetId) return false;
    const curView = views.get(currentId);
    const targetView = views.get(targetId);
    if (!curView || !targetView) return false;

    const head = curView.state.selection.main.head;
    const curLine = curView.state.doc.lineAt(head);
    const col = head - curLine.from;
    const targetLine = dir === 1 ? targetView.state.doc.line(1) : targetView.state.doc.line(targetView.state.doc.lines);
    const targetPos = Math.min(targetLine.from + col, targetLine.to);

    targetView.dispatch({ selection: { anchor: targetPos } });
    targetView.focus();
    activeBlockId = targetId;
    bufferAllSelected = false;
    return true;
  }

  function insertBlockAfter(currentId: string): boolean {
    const idx = blocks.findIndex((b) => b.id === currentId);
    if (idx < 0) return false;
    const newId = `blk_new_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    blocks.splice(idx + 1, 0, { id: newId, lang: "text", content: "", locked: false, preview: false });
    renderAll();
    const v = views.get(newId);
    if (v) {
      v.focus();
      activeBlockId = newId;
    }
    return true;
  }

  function renderAll(): void {
    for (const v of views.values()) v.destroy();
    views.clear();
    container.innerHTML = "";

    for (const block of blocks) {
      const card = document.createElement("section");
      card.className = "block-card";
      card.dataset.blockId = block.id;
      card.dataset.lang = block.lang;

      const header = document.createElement("div");
      header.className = "block-header";
      header.textContent = `${block.id} [${block.lang}]${block.locked ? " 🔒 LOCKED" : block.preview ? " 👁 PREVIEW" : ""}`;
      card.appendChild(header);

      if (block.locked) {
        const lockedEl = document.createElement("div");
        lockedEl.className = "locked-card";
        lockedEl.textContent = `🔒 Locked Block (${block.publicHint ?? "Vault"}) — Unlock required`;
        card.appendChild(lockedEl);
        container.appendChild(card);
        continue;
      }

      if (block.preview) {
        const previewEl = document.createElement("div");
        previewEl.className = "preview-card";
        previewEl.textContent = block.content;
        card.appendChild(previewEl);
        container.appendChild(card);
        continue;
      }

      const host = document.createElement("div");
      host.className = "block-editor-host";
      card.appendChild(host);
      container.appendChild(card);

      // In virtualized mode, mount only the initial visible viewport + overscan (first 16 blocks);
      // off-screen blocks render a lightweight <pre> placeholder until scrolled/focused.
      const idx = blocks.indexOf(block);
      if (options.virtualize && idx >= 16) {
        const pre = document.createElement("pre");
        pre.className = "block-placeholder";
        pre.textContent = block.content;
        host.appendChild(pre);
        continue;
      }

      const bridgeKeymap = keymap.of([
        {
          key: "ArrowUp",
          run: (view) => {
            const line = view.state.doc.lineAt(view.state.selection.main.head);
            if (line.number === 1) return jumpAdjacent(block.id, -1);
            return false;
          },
        },
        {
          key: "ArrowDown",
          run: (view) => {
            const line = view.state.doc.lineAt(view.state.selection.main.head);
            if (line.number === view.state.doc.lines) return jumpAdjacent(block.id, 1);
            return false;
          },
        },
        {
          key: "Mod-a",
          run: (view) => {
            const sel = view.state.selection.main;
            if (sel.from === 0 && sel.to === view.state.doc.length) {
              bufferAllSelected = true;
              container.classList.add("buffer-all-selected");
              return true;
            }
            bufferAllSelected = false;
            container.classList.remove("buffer-all-selected");
            view.dispatch({ selection: { anchor: 0, head: view.state.doc.length } });
            return true;
          },
        },
        {
          key: "Mod-Enter",
          run: () => insertBlockAfter(block.id),
        },
      ]);

      const exts: Extension[] = [
        bridgeKeymap,
        history(),
        syntaxHighlighting(defaultHighlightStyle),
        langExtension(block.lang),
        keymap.of([...defaultKeymap, ...historyKeymap]),
        EditorView.updateListener.of((u) => {
          if (u.docChanged) {
            block.content = u.state.doc.toString();
            bufferAllSelected = false;
          }
          if (u.focusChanged && u.view.hasFocus) {
            activeBlockId = block.id;
          }
        }),
      ];
      if (options.vimMode) exts.unshift(vim());

      const view = new EditorView({
        state: EditorState.create({ doc: block.content, extensions: exts }),
        parent: host,
      });
      views.set(block.id, view);
    }
  }

  renderAll();

  return {
    getBlocks: () => blocks.map((b) => ({ ...b })),
    focusBlock(id: string, pos = 0) {
      const v = views.get(id);
      if (v) {
        const clamped = Math.max(0, Math.min(pos, v.state.doc.length));
        v.dispatch({ selection: { anchor: clamped } });
        v.focus();
        activeBlockId = id;
      }
    },
    getActiveBlockId: () => activeBlockId,
    getView: (id: string) => views.get(id),
    findAcrossBlocks(query: string) {
      if (!query) return [];
      const matches: { blockId: string; from: number; to: number }[] = [];
      for (const b of blocks) {
        if (b.locked) continue; // Locked blocks never participate in plaintext search
        let start = 0;
        while (true) {
          const idx = b.content.indexOf(query, start);
          if (idx === -1) break;
          matches.push({ blockId: b.id, from: idx, to: idx + query.length });
          start = idx + query.length;
        }
      }
      return matches;
    },
    replaceAllAcrossBlocks(query: string, replacement: string) {
      if (!query) return 0;
      let count = 0;
      for (const b of blocks) {
        if (b.locked || b.preview) continue;
        const v = views.get(b.id);
        if (!v) continue;
        const text = v.state.doc.toString();
        const changes: { from: number; to: number; insert: string }[] = [];
        let start = 0;
        while (true) {
          const idx = text.indexOf(query, start);
          if (idx === -1) break;
          changes.push({ from: idx, to: idx + query.length, insert: replacement });
          count++;
          start = idx + query.length;
        }
        if (changes.length > 0) v.dispatch({ changes });
      }
      return count;
    },
    isBufferAllSelected: () => bufferAllSelected,
    togglePreview(id: string) {
      const b = blocks.find((x) => x.id === id);
      if (b && !b.locked) {
        b.preview = !b.preview;
        renderAll();
      }
    },
    destroy() {
      for (const v of views.values()) v.destroy();
      views.clear();
    },
  };
}
