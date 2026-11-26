import { HighlightStyle, syntaxHighlighting, syntaxTree } from "@codemirror/language";
import type { Extension, Range } from "@codemirror/state";
import { Decoration, EditorView, ViewPlugin, type DecorationSet, type ViewUpdate } from "@codemirror/view";
import { tags as t } from "@lezer/highlight";

const CODE_LINE_DECO = Decoration.line({ class: "cm-md-code-line" });
const CODE_LINE_FIRST_DECO = Decoration.line({ class: "cm-md-code-line cm-md-code-first" });
const CODE_LINE_LAST_DECO = Decoration.line({ class: "cm-md-code-line cm-md-code-last" });
const CODE_LINE_SINGLE_DECO = Decoration.line({
  class: "cm-md-code-line cm-md-code-first cm-md-code-last",
});
const INLINE_CODE_MARK = Decoration.mark({ class: "cm-md-inline-code" });

function buildMarkdownCodeDecorations(view: EditorView): DecorationSet {
  const ranges: Range<Decoration>[] = [];
  const doc = view.state.doc;
  const tree = syntaxTree(view.state);
  const decoratedLines = new Set<number>();

  for (const { from, to } of view.visibleRanges) {
    tree.iterate({
      from,
      to,
      enter(node) {
        if (node.name === "FencedCode") {
          const startLine = doc.lineAt(node.from).number;
          const endPos = node.to > node.from ? node.to - 1 : node.from;
          const endLine = doc.lineAt(endPos).number;
          for (let ln = startLine; ln <= endLine; ln += 1) {
            if (decoratedLines.has(ln)) continue;
            decoratedLines.add(ln);
            const line = doc.line(ln);
            const deco =
              startLine === endLine
                ? CODE_LINE_SINGLE_DECO
                : ln === startLine
                  ? CODE_LINE_FIRST_DECO
                  : ln === endLine
                    ? CODE_LINE_LAST_DECO
                    : CODE_LINE_DECO;
            ranges.push(deco.range(line.from));
          }
          return false;
        }
        if (node.name === "InlineCode" && node.to > node.from) {
          ranges.push(INLINE_CODE_MARK.range(node.from, node.to));
          return false;
        }
        return undefined;
      },
    });
  }

  return ranges.length > 0 ? Decoration.set(ranges, true) : Decoration.none;
}

const markdownCodeDecorationsPlugin = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;
    constructor(view: EditorView) {
      this.decorations = buildMarkdownCodeDecorations(view);
    }
    update(update: ViewUpdate) {
      if (
        update.docChanged ||
        update.viewportChanged ||
        syntaxTree(update.startState) !== syntaxTree(update.state)
      ) {
        this.decorations = buildMarkdownCodeDecorations(update.view);
      }
    }
  },
  {
    decorations: (v) => v.decorations,
  },
);

export const myNoteEditorTheme: Extension = EditorView.theme({
  "&": {
    backgroundColor: "transparent",
    color: "var(--text)",
    fontFamily: "var(--mono)",
    fontSize: "13px",
    lineHeight: "1.6",
  },
  ".cm-content": {
    padding: "12px 6px",
    caretColor: "var(--accent)",
    fontFamily: "var(--mono)",
  },
  ".cm-line": {
    padding: "0 10px",
  },
  ".cm-line.cm-md-code-line": {
    backgroundColor: "var(--bg-inset)",
  },
  ".cm-line.cm-md-code-line:not(.cm-md-code-first)": {
    boxShadow: "0 -1px 0 var(--bg-inset)",
  },
  ".cm-line.cm-md-code-first": {
    borderTopLeftRadius: "6px",
    borderTopRightRadius: "6px",
    paddingTop: "4px",
  },
  ".cm-line.cm-md-code-last": {
    borderBottomLeftRadius: "6px",
    borderBottomRightRadius: "6px",
    paddingBottom: "4px",
  },
  ".cm-md-inline-code": {
    backgroundColor: "var(--syn-code-bg)",
    borderRadius: "3px",
    padding: "0 2px",
  },
  ".cm-scroller": {
    fontFamily: "var(--mono)",
    lineHeight: "1.6",
    overflowX: "auto",
  },
  "&.cm-focused": {
    outline: "none",
  },
  ".cm-cursor, .cm-dropCursor": {
    borderLeftColor: "var(--accent)",
    borderLeftWidth: "1.75px",
  },
  "&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection":
    {
      backgroundColor: "var(--cm-selection)",
    },
  ".cm-activeLine": {
    backgroundColor: "var(--cm-active-line)",
  },
  ".cm-gutters": {
    backgroundColor: "transparent",
    borderRight: "1px solid var(--border)",
    color: "var(--text-muted)",
  },
  ".cm-activeLineGutter": {
    backgroundColor: "var(--cm-active-line)",
    color: "var(--text-secondary)",
  },
  ".cm-matchingBracket, &.cm-focused .cm-matchingBracket": {
    backgroundColor: "var(--cm-matching-bracket)",
    outline: "1px solid var(--border-control)",
  },
  ".cm-find-match": {
    backgroundColor: "var(--find-match)",
    borderRadius: "2px",
  },
  ".cm-find-match-active": {
    backgroundColor: "var(--find-active)",
    borderRadius: "2px",
    boxShadow: "0 0 0 1px var(--amber)",
  },
  ".cm-panels": {
    backgroundColor: "var(--bg-elev)",
    color: "var(--text)",
    borderTop: "1px solid var(--border)",
  },
  ".cm-panels.cm-panels-top": {
    borderBottom: "1px solid var(--border)",
    borderTop: "none",
  },
  ".cm-panel input, .cm-panel button": {
    color: "var(--text)",
    fontFamily: "var(--mono)",
  },
  ".cm-placeholder": {
    color: "var(--text-muted)",
  },
});

export const myNoteHighlightStyle: HighlightStyle = HighlightStyle.define([
  {
    tag: [t.keyword, t.controlKeyword, t.operatorKeyword, t.moduleKeyword, t.modifier],
    color: "var(--syn-keyword)",
  },
  {
    tag: [t.string, t.special(t.string), t.regexp, t.inserted],
    color: "var(--syn-string)",
  },
  {
    tag: [t.number, t.integer, t.float, t.bool, t.atom, t.null, t.constant(t.variableName)],
    color: "var(--syn-number)",
  },
  {
    tag: [t.comment, t.lineComment, t.blockComment, t.docComment],
    color: "var(--syn-comment)",
    fontStyle: "italic",
  },
  {
    tag: [t.function(t.variableName), t.function(t.propertyName), t.definition(t.variableName)],
    color: "var(--syn-function)",
  },
  {
    tag: [t.typeName, t.className, t.namespace, t.self],
    color: "var(--syn-type)",
  },
  {
    tag: [t.propertyName, t.labelName, t.special(t.variableName), t.local(t.variableName)],
    color: "var(--syn-property)",
  },
  {
    tag: [t.operator, t.punctuation, t.bracket, t.separator, t.derefOperator],
    color: "var(--syn-operator)",
  },
  {
    tag: [t.tagName, t.deleted],
    color: "var(--syn-tag)",
  },
  {
    tag: [t.attributeName, t.escape],
    color: "var(--syn-attr)",
  },
  {
    tag: [t.meta, t.processingInstruction, t.annotation],
    color: "var(--syn-meta)",
  },
  {
    tag: [t.monospace],
    color: "var(--syn-code)",
  },
  {
    tag: [t.quote],
    color: "var(--text-secondary)",
    fontStyle: "italic",
  },
  {
    tag: [t.contentSeparator],
    color: "var(--border-control)",
  },
  {
    tag: [t.heading, t.heading1, t.heading2, t.heading3, t.heading4, t.heading5, t.heading6],
    color: "var(--syn-heading)",
    fontWeight: "700",
  },
  {
    tag: [t.link],
    color: "var(--syn-link)",
  },
  {
    tag: [t.url],
    color: "var(--syn-link)",
    textDecoration: "underline",
  },
  {
    tag: [t.strong],
    fontWeight: "700",
  },
  {
    tag: [t.emphasis],
    fontStyle: "italic",
  },
  {
    tag: [t.strikethrough],
    textDecoration: "line-through",
  },
  {
    tag: [t.invalid],
    color: "var(--syn-invalid)",
    textDecoration: "underline wavy",
  },
]);

/**
 * Avoid Chromium Blink's `ReplaceSelectionCommand` copying highlighted `<span>`
 * computed color onto `<div class="cm-line" style="color: ...">` when typing
 * directly over a non-collapsed selection, which violates strict `style-src-attr` CSP.
 * IME composition (`isComposing` / `insertCompositionText`) passes through untouched.
 */
const cspSafeReplaceSelection: Extension = EditorView.domEventHandlers({
  beforeinput(event, view) {
    if (
      event.isComposing ||
      event.inputType !== "insertText" ||
      typeof event.data !== "string" ||
      !view.state.facet(EditorView.editable) ||
      view.state.readOnly ||
      view.state.selection.ranges.every((r) => r.empty)
    ) {
      return false;
    }
    event.preventDefault();
    view.dispatch(view.state.replaceSelection(event.data), {
      userEvent: "input.type",
      scrollIntoView: true,
    });
    return true;
  },
});

export const myNoteCmExtensions: readonly Extension[] = [
  myNoteEditorTheme,
  EditorView.lineWrapping,
  syntaxHighlighting(myNoteHighlightStyle),
  markdownCodeDecorationsPlugin,
  cspSafeReplaceSelection,
];
