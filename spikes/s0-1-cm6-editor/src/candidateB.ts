import {
  Annotation,
  ChangeSpec,
  EditorState,
  Extension,
  RangeSetBuilder,
  StateEffect,
  StateField,
  Text,
} from "@codemirror/state";
import { Decoration, DecorationSet, EditorView, WidgetType, keymap } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { Language, LanguageSupport, defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { search, searchKeymap, SearchCursor } from "@codemirror/search";
import { javascriptLanguage } from "@codemirror/lang-javascript";
import { jsonLanguage } from "@codemirror/lang-json";
import { markdownLanguage } from "@codemirror/lang-markdown";
import { sql } from "@codemirror/lang-sql";
import { NodeSet, NodeType, Parser, PartialParse, Tree, parseMixed, Input, TreeFragment } from "@lezer/common";
import { vim } from "@replit/codemirror-vim";
import { Block, BlockLang } from "./model";

const HDR_PREFIX = "\uE000BLK:";
const HDR_SUFFIX = "\uE001";
const LOCKED_SENTINEL = "\uE002";

const sqlParser = sql().language.parser;

const internalChange = Annotation.define<boolean>();
const setBlockMetaEffect = StateEffect.define<Map<string, Omit<Block, "content">>>();

interface BlockRange {
  id: string;
  headerFrom: number;
  headerTo: number;
  bodyFrom: number;
  bodyTo: number;
  meta: Omit<Block, "content">;
}

function serializeBlocks(blocks: Block[]): { doc: string; metaMap: Map<string, Omit<Block, "content">> } {
  const parts: string[] = [];
  const metaMap = new Map<string, Omit<Block, "content">>();
  for (const b of blocks) {
    metaMap.set(b.id, {
      id: b.id,
      lang: b.lang,
      locked: b.locked,
      preview: b.preview,
      publicHint: b.publicHint,
    });
    const body = b.locked ? LOCKED_SENTINEL : b.content;
    parts.push(`${HDR_PREFIX}${b.id}${HDR_SUFFIX}\n${body}`);
  }
  return { doc: parts.join("\n"), metaMap };
}

function computeBlockRanges(doc: Text, metaMap: Map<string, Omit<Block, "content">>): BlockRange[] {
  const ranges: BlockRange[] = [];
  let cur: { id: string; headerFrom: number; headerTo: number; bodyFrom: number } | null = null;
  for (let i = 1; i <= doc.lines; i++) {
    const line = doc.line(i);
    if (line.text.startsWith(HDR_PREFIX) && line.text.endsWith(HDR_SUFFIX)) {
      if (cur) {
        const prevLineEnd = Math.max(cur.bodyFrom, line.from - 1);
        const meta = metaMap.get(cur.id) ?? { id: cur.id, lang: "text" as BlockLang, locked: false, preview: false };
        ranges.push({ ...cur, bodyTo: prevLineEnd, meta });
      }
      const id = line.text.slice(HDR_PREFIX.length, line.text.length - HDR_SUFFIX.length);
      const bodyFrom = Math.min(line.to + 1, doc.length);
      cur = { id, headerFrom: line.from, headerTo: line.to, bodyFrom };
    }
  }
  if (cur) {
    const meta = metaMap.get(cur.id) ?? { id: cur.id, lang: "text" as BlockLang, locked: false, preview: false };
    ranges.push({ ...cur, bodyTo: doc.length, meta });
  }
  return ranges;
}

class BlockHeaderWidget extends WidgetType {
  constructor(private readonly meta: Omit<Block, "content">) {
    super();
  }
  eq(other: BlockHeaderWidget): boolean {
    return (
      this.meta.id === other.meta.id &&
      this.meta.lang === other.meta.lang &&
      this.meta.locked === other.meta.locked &&
      this.meta.preview === other.meta.preview
    );
  }
  toDOM(): HTMLElement {
    const el = document.createElement("span");
    el.className = "cm-block-header-widget";
    el.dataset.blockId = this.meta.id;
    el.textContent = `${this.meta.id} [${this.meta.lang}]${this.meta.locked ? " 🔒 LOCKED" : this.meta.preview ? " 👁 PREVIEW" : ""}`;
    return el;
  }
  ignoreEvent(): boolean {
    return true;
  }
}

class LockedBodyWidget extends WidgetType {
  constructor(private readonly hint?: string) {
    super();
  }
  eq(other: LockedBodyWidget): boolean {
    return this.hint === other.hint;
  }
  toDOM(): HTMLElement {
    const el = document.createElement("div");
    el.className = "locked-card";
    el.textContent = `🔒 Locked Block (${this.hint ?? "Vault"}) — Unlock required`;
    return el;
  }
  ignoreEvent(): boolean {
    return true;
  }
}

class PreviewBodyWidget extends WidgetType {
  constructor(private readonly content: string) {
    super();
  }
  eq(other: PreviewBodyWidget): boolean {
    return this.content === other.content;
  }
  toDOM(): HTMLElement {
    const el = document.createElement("div");
    el.className = "preview-card";
    el.textContent = this.content;
    return el;
  }
  ignoreEvent(): boolean {
    return true;
  }
}

const blockMetaField = StateField.define<Map<string, Omit<Block, "content">>>({
  create: () => new Map(),
  update(value, tr) {
    for (const e of tr.effects) {
      if (e.is(setBlockMetaEffect)) return e.value;
    }
    return value;
  },
});

const blockRangesField = StateField.define<BlockRange[]>({
  create: (state) => computeBlockRanges(state.doc, state.field(blockMetaField)),
  update(value, tr) {
    if (tr.docChanged || tr.effects.some((e) => e.is(setBlockMetaEffect))) {
      return computeBlockRanges(tr.newDoc, tr.state.field(blockMetaField));
    }
    return value;
  },
});

function buildDecorations(state: EditorState): DecorationSet {
  const ranges = state.field(blockRangesField);
  const builder = new RangeSetBuilder<Decoration>();
  for (const r of ranges) {
    builder.add(r.headerFrom, r.headerTo, Decoration.replace({ widget: new BlockHeaderWidget(r.meta) }));
    if (r.meta.locked) {
      builder.add(r.bodyFrom, r.bodyTo, Decoration.replace({ block: true, widget: new LockedBodyWidget(r.meta.publicHint) }));
    } else if (r.meta.preview) {
      const bodyText = state.doc.sliceString(r.bodyFrom, r.bodyTo);
      builder.add(r.bodyFrom, r.bodyTo, Decoration.replace({ block: true, widget: new PreviewBodyWidget(bodyText) }));
    }
  }
  return builder.finish();
}

const blockDecorationsField = StateField.define<DecorationSet>({
  create: (state) => buildDecorations(state),
  update(value, tr) {
    if (tr.docChanged || tr.effects.some((e) => e.is(setBlockMetaEffect))) {
      return buildDecorations(tr.state);
    }
    return value;
  },
  provide: (f) => [
    EditorView.decorations.from(f),
    EditorView.atomicRanges.of((view) => view.state.field(f)),
  ],
});

// Multi-language nested parser using Lezer parseMixed for per-block syntax highlighting in ONE CM6 doc
const DocNode = NodeType.define({ id: 0, name: "MultiBlockDoc", top: true });
const BlockNode = NodeType.define({ id: 1, name: "BlockBody" });
const multiNodeSet = new NodeSet([DocNode, BlockNode]);

function makeMultiBlockLanguage(getMeta: () => Map<string, Omit<Block, "content">>): LanguageSupport {
  class BlockBoundaryParser extends Parser {
    createParse(input: Input, _fragments: readonly TreeFragment[], ranges: readonly { from: number; to: number }[]): PartialParse {
      let done = false;
      const to = ranges[ranges.length - 1]?.to ?? input.length;
      const parseOnce = (): Tree => {
        done = true;
        const full = input.read(0, to);
        const children: Tree[] = [];
        const positions: number[] = [];
        const lines = full.split("\n");
        let offset = 0;
        let curId: string | null = null;
        let bodyStart = 0;

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const lineStart = offset;
          const lineEnd = offset + line.length;
          if (line.startsWith(HDR_PREFIX) && line.endsWith(HDR_SUFFIX)) {
            if (curId !== null) {
              const bodyEnd = Math.max(bodyStart, lineStart - 1);
              if (bodyEnd > bodyStart) {
                children.push(new Tree(BlockNode, [], [], bodyEnd - bodyStart));
                positions.push(bodyStart);
              }
            }
            curId = line.slice(HDR_PREFIX.length, line.length - HDR_SUFFIX.length);
            bodyStart = Math.min(lineEnd + 1, to);
          }
          offset = lineEnd + 1;
        }
        if (curId !== null && to > bodyStart) {
          children.push(new Tree(BlockNode, [], [], to - bodyStart));
          positions.push(bodyStart);
        }
        return new Tree(DocNode, children, positions, to);
      };
      return {
        parsedPos: 0,
        stopAt() {},
        stoppedAt: null,
        advance() {
          return done ? null : parseOnce();
        },
      };
    }
  }

  const mixedWrap = parseMixed((node, input) => {
    if (node.type.id !== BlockNode.id) return null;
    // Locate preceding header sentinel to determine block language
    const prefixStart = Math.max(0, node.from - 80);
    const before = input.read(prefixStart, node.from);
    const idx = before.lastIndexOf(HDR_PREFIX);
    if (idx === -1) return null;
    const endIdx = before.indexOf(HDR_SUFFIX, idx);
    if (endIdx === -1) return null;
    const id = before.slice(idx + HDR_PREFIX.length, endIdx);
    const meta = getMeta().get(id);
    if (!meta || meta.locked || meta.preview) return null;
    switch (meta.lang) {
      case "javascript":
        return { parser: javascriptLanguage.parser };
      case "json":
        return { parser: jsonLanguage.parser };
      case "sql":
        return { parser: sqlParser };
      case "markdown":
        return { parser: markdownLanguage.parser };
      default:
        return null;
    }
  });

  class MixedBlockParser extends BlockBoundaryParser {
    createParse(input: Input, fragments: readonly TreeFragment[], ranges: readonly { from: number; to: number }[]): PartialParse {
      const inner = super.createParse(input, fragments, ranges);
      return mixedWrap(inner, input, fragments, ranges);
    }
  }

  const lang = new Language(EditorState.languageData, new MixedBlockParser(), [], "mynote-multiblock");
  return new LanguageSupport(lang);
}

// Strict boundary protection filter: prevents Backspace/Delete/Vim dd/dG/SelectAll+Delete from corrupting block sentinels or locked/preview blocks.
const boundaryGuardFilter = EditorState.transactionFilter.of((tr) => {
  if (!tr.docChanged || tr.annotation(internalChange)) return tr;

  const ranges = tr.startState.field(blockRangesField);
  const editableSpans = ranges.filter((r) => !r.meta.locked && !r.meta.preview).map((r) => ({ from: r.bodyFrom, to: r.bodyTo }));

  let touchesProtected = false;
  const sanitizedChanges: ChangeSpec[] = [];

  tr.changes.iterChanges((fromA, toA, _fromB, _toB, inserted) => {
    const insText = inserted.toString();
    // Never allow users to type or paste raw sentinel characters
    const cleanIns = insText.replaceAll(HDR_PREFIX, "").replaceAll(HDR_SUFFIX, "").replaceAll(LOCKED_SENTINEL, "");

    // Check if [fromA, toA] lies completely inside a single editable body span
    const containing = editableSpans.find((s) => fromA >= s.from && toA <= s.to);
    if (containing) {
      if (cleanIns !== insText) touchesProtected = true;
      sanitizedChanges.push({ from: fromA, to: toA, insert: cleanIns });
      return;
    }

    // Otherwise, this change crosses a block header, boundary newline, locked block, or preview block!
    touchesProtected = true;

    // Project deletion safely onto only overlapping editable body spans (e.g. SelectAll+Delete or Vim dG)
    if (fromA < toA) {
      let insertedPlaced = false;
      for (const s of editableSpans) {
        const ovFrom = Math.max(fromA, s.from);
        const ovTo = Math.min(toA, s.to);
        if (ovFrom < ovTo) {
          sanitizedChanges.push({
            from: ovFrom,
            to: ovTo,
            insert: !insertedPlaced ? cleanIns : "",
          });
          insertedPlaced = true;
        }
      }
    }
  });

  if (!touchesProtected) return tr;
  if (sanitizedChanges.length === 0) return [];
  return {
    changes: sanitizedChanges,
    annotations: [internalChange.of(true)],
  };
});

export interface CandidateBHandle {
  view: EditorView;
  getBlocks(): Block[];
  getBlockRange(id: string): BlockRange | undefined;
  focusBlock(id: string, offsetInBlock?: number): void;
  findAcrossBlocks(query: string): { blockId: string; from: number; to: number }[];
  replaceAllAcrossBlocks(query: string, replacement: string): number;
  togglePreview(id: string): void;
  insertBlockAfter(id: string): string;
  destroy(): void;
}

export function mountCandidateB(
  container: HTMLElement,
  initialBlocks: Block[],
  options: { vimMode?: boolean } = {},
): CandidateBHandle {
  container.innerHTML = "";
  const { doc, metaMap } = serializeBlocks(initialBlocks);
  let liveMeta = metaMap;

  function insertBlockAfterImpl(view: EditorView, afterId: string): string {
    const ranges = view.state.field(blockRangesField);
    const target = ranges.find((r) => r.id === afterId) ?? ranges[ranges.length - 1];
    const newId = `blk_new_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const nextMeta = new Map(view.state.field(blockMetaField));
    nextMeta.set(newId, { id: newId, lang: "text", locked: false, preview: false });
    liveMeta = nextMeta;
    const insertPos = target ? target.bodyTo : view.state.doc.length;
    const snippet = `\n${HDR_PREFIX}${newId}${HDR_SUFFIX}\n`;
    view.dispatch({
      changes: { from: insertPos, insert: snippet },
      selection: { anchor: insertPos + snippet.length },
      effects: setBlockMetaEffect.of(nextMeta),
      annotations: internalChange.of(true),
    });
    return newId;
  }

  const blockKeymap = keymap.of([
    {
      key: "Mod-Enter",
      run: (view) => {
        const head = view.state.selection.main.head;
        const ranges = view.state.field(blockRangesField);
        const cur = ranges.find((r) => head >= r.headerFrom && head <= r.bodyTo);
        if (!cur) return false;
        insertBlockAfterImpl(view, cur.id);
        return true;
      },
    },
  ]);

  const exts: Extension[] = [
    blockMetaField.init(() => metaMap),
    blockRangesField,
    blockDecorationsField,
    boundaryGuardFilter,
    history(),
    search(),
    syntaxHighlighting(defaultHighlightStyle),
    makeMultiBlockLanguage(() => liveMeta),
    blockKeymap,
    keymap.of([...searchKeymap, ...defaultKeymap, ...historyKeymap]),
  ];
  if (options.vimMode) exts.unshift(vim());

  const view = new EditorView({
    state: EditorState.create({ doc, extensions: exts }),
    parent: container,
  });

  return {
    view,
    getBlocks() {
      const ranges = view.state.field(blockRangesField);
      return ranges.map((r) => ({
        ...r.meta,
        content: r.meta.locked ? "" : view.state.doc.sliceString(r.bodyFrom, r.bodyTo),
      }));
    },
    getBlockRange(id: string) {
      return view.state.field(blockRangesField).find((r) => r.id === id);
    },
    focusBlock(id: string, offsetInBlock = 0) {
      const r = view.state.field(blockRangesField).find((x) => x.id === id);
      if (r && !r.meta.locked && !r.meta.preview) {
        const pos = Math.min(r.bodyFrom + offsetInBlock, r.bodyTo);
        view.dispatch({ selection: { anchor: pos } });
        view.focus();
      }
    },
    findAcrossBlocks(query: string) {
      if (!query) return [];
      const ranges = view.state.field(blockRangesField);
      const cursor = new SearchCursor(view.state.doc, query);
      const out: { blockId: string; from: number; to: number }[] = [];
      while (!cursor.next().done) {
        const { from, to } = cursor.value;
        const owner = ranges.find((r) => !r.meta.locked && from >= r.bodyFrom && to <= r.bodyTo);
        if (owner) out.push({ blockId: owner.id, from: from - owner.bodyFrom, to: to - owner.bodyFrom });
      }
      return out;
    },
    replaceAllAcrossBlocks(query: string, replacement: string) {
      if (!query) return 0;
      const ranges = view.state.field(blockRangesField);
      const cursor = new SearchCursor(view.state.doc, query);
      const changes: ChangeSpec[] = [];
      while (!cursor.next().done) {
        const { from, to } = cursor.value;
        const owner = ranges.find((r) => !r.meta.locked && !r.meta.preview && from >= r.bodyFrom && to <= r.bodyTo);
        if (owner) changes.push({ from, to, insert: replacement });
      }
      if (changes.length > 0) view.dispatch({ changes });
      return changes.length;
    },
    togglePreview(id: string) {
      const nextMeta = new Map(view.state.field(blockMetaField));
      const cur = nextMeta.get(id);
      if (cur && !cur.locked) {
        nextMeta.set(id, { ...cur, preview: !cur.preview });
        liveMeta = nextMeta;
        view.dispatch({ effects: setBlockMetaEffect.of(nextMeta) });
      }
    },
    insertBlockAfter(id: string) {
      return insertBlockAfterImpl(view, id);
    },
    destroy() {
      view.destroy();
    },
  };
}
