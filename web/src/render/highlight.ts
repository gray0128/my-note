import { highlightTree, tagHighlighter, tags as t, type Highlighter } from "@lezer/highlight";

export interface HighlightToken {
  readonly text: string;
  readonly cls: string;
}

type SyntaxTreeLike = Parameters<typeof highlightTree>[0];

interface SimpleParser {
  parse(input: string): SyntaxTreeLike;
}

export const previewTagHighlighter: Highlighter = tagHighlighter([
  { tag: [t.keyword, t.controlKeyword, t.operatorKeyword, t.moduleKeyword, t.modifier], class: "tok-kw" },
  { tag: [t.string, t.special(t.string), t.regexp, t.inserted], class: "tok-str" },
  { tag: [t.number, t.integer, t.float, t.bool, t.atom, t.null, t.constant(t.variableName)], class: "tok-num" },
  { tag: [t.comment, t.lineComment, t.blockComment, t.docComment], class: "tok-cmt" },
  { tag: [t.function(t.variableName), t.function(t.propertyName), t.definition(t.variableName)], class: "tok-fn" },
  { tag: [t.typeName, t.className, t.namespace, t.self], class: "tok-type" },
  { tag: [t.propertyName, t.labelName, t.special(t.variableName), t.local(t.variableName)], class: "tok-prop" },
  { tag: [t.operator, t.punctuation, t.bracket, t.separator, t.derefOperator], class: "tok-op" },
  { tag: [t.tagName, t.deleted], class: "tok-tag" },
  { tag: [t.attributeName, t.escape], class: "tok-attr" },
  { tag: [t.meta, t.processingInstruction, t.annotation], class: "tok-meta" },
  { tag: [t.heading, t.heading1, t.heading2, t.heading3], class: "tok-head" },
  { tag: [t.invalid], class: "tok-invalid" },
]);

const parserCache = new Map<string, Promise<SimpleParser | null>>();

export function normalizeCodeLang(rawLang: string): string {
  const norm = rawLang.trim().toLowerCase();
  switch (norm) {
    case "ts":
    case "typescript":
      return "typescript";
    case "tsx":
      return "tsx";
    case "js":
    case "javascript":
    case "mjs":
    case "cjs":
      return "javascript";
    case "jsx":
      return "jsx";
    case "json":
    case "json5":
    case "jsonc":
      return "json";
    case "rs":
    case "rust":
      return "rust";
    case "py":
    case "python":
      return "python";
    case "sql":
    case "sqlite":
    case "postgres":
    case "postgresql":
      return "sql";
    case "yml":
    case "yaml":
      return "yaml";
    case "html":
    case "htm":
      return "html";
    case "css":
      return "css";
    case "xml":
    case "svg":
      return "xml";
    case "mermaid":
    case "mmd":
      return "mermaid";
    case "toml":
      return "toml";
    case "sh":
    case "bash":
    case "shell":
    case "zsh":
      return "shell";
    default:
      return norm;
  }
}

function loadParser(rawLang: string): Promise<SimpleParser | null> {
  const norm = normalizeCodeLang(rawLang);
  if (!norm || norm === "text" || norm === "plain" || norm === "txt") {
    return Promise.resolve(null);
  }
  const existing = parserCache.get(norm);
  if (existing) return existing;

  const promise = (async (): Promise<SimpleParser | null> => {
    switch (norm) {
      case "typescript":
        return (await import("@codemirror/lang-javascript")).typescriptLanguage.parser;
      case "tsx":
        return (await import("@codemirror/lang-javascript")).tsxLanguage.parser;
      case "javascript":
        return (await import("@codemirror/lang-javascript")).javascriptLanguage.parser;
      case "jsx":
        return (await import("@codemirror/lang-javascript")).jsxLanguage.parser;
      case "json":
        return (await import("@codemirror/lang-json")).jsonLanguage.parser;
      case "rust":
        return (await import("@codemirror/lang-rust")).rustLanguage.parser;
      case "python":
        return (await import("@codemirror/lang-python")).pythonLanguage.parser;
      case "sql":
        return (await import("@codemirror/lang-sql")).sql().language.parser;
      case "yaml":
        return (await import("@codemirror/lang-yaml")).yamlLanguage.parser;
      case "html":
        return (await import("@codemirror/lang-html")).htmlLanguage.parser;
      case "css":
        return (await import("@codemirror/lang-css")).cssLanguage.parser;
      case "xml":
        return (await import("@codemirror/lang-xml")).xmlLanguage.parser;
      case "mermaid":
        return (await import("../cmStreamLangs")).mermaidLanguage.parser;
      case "toml":
        return (await import("../cmStreamLangs")).tomlLanguage.parser;
      case "shell":
        return (await import("../cmStreamLangs")).shellLanguage.parser;
      default:
        return null;
    }
  })().catch(() => null);

  parserCache.set(norm, promise);
  return promise;
}

const MAX_HIGHLIGHT_CHARS = 32_000;

export async function highlightCodeSnippet(code: string, lang: string): Promise<HighlightToken[] | null> {
  if (!code || code.length > MAX_HIGHLIGHT_CHARS) return null;
  const parser = await loadParser(lang);
  if (!parser) return null;

  const tree = parser.parse(code);
  const tokens: HighlightToken[] = [];
  let pos = 0;

  highlightTree(tree, previewTagHighlighter, (from, to, classes) => {
    if (from > pos) {
      tokens.push({ text: code.slice(pos, from), cls: "" });
    }
    if (to > from) {
      tokens.push({ text: code.slice(from, to), cls: classes });
    }
    pos = to;
  });

  if (pos < code.length) {
    tokens.push({ text: code.slice(pos), cls: "" });
  }
  return tokens;
}
