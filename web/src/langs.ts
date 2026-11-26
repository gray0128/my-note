import { LanguageDescription, LanguageSupport } from "@codemirror/language";
import type { Extension } from "@codemirror/state";
import { styleTags, tags as t } from "@lezer/highlight";
import { mermaidLanguage, shellLanguage, tomlLanguage } from "./cmStreamLangs";

export const SUPPORTED_LANGS = [
  "text",
  "markdown",
  "json",
  "yaml",
  "toml",
  "sql",
  "xml",
  "javascript",
  "typescript",
  "python",
  "rust",
  "html",
  "css",
  "mermaid",
] as const;

const CODE_LANGUAGE_DESCRIPTIONS: readonly LanguageDescription[] = [
  LanguageDescription.of({
    name: "typescript",
    alias: ["ts"],
    async load() {
      const mod = await import("@codemirror/lang-javascript");
      return mod.javascript({ typescript: true });
    },
  }),
  LanguageDescription.of({
    name: "tsx",
    async load() {
      const mod = await import("@codemirror/lang-javascript");
      return mod.javascript({ typescript: true, jsx: true });
    },
  }),
  LanguageDescription.of({
    name: "javascript",
    alias: ["js", "jsx", "mjs", "cjs"],
    async load() {
      const mod = await import("@codemirror/lang-javascript");
      return mod.javascript({ jsx: true });
    },
  }),
  LanguageDescription.of({
    name: "json",
    alias: ["json5", "jsonc"],
    async load() {
      return (await import("@codemirror/lang-json")).json();
    },
  }),
  LanguageDescription.of({
    name: "rust",
    alias: ["rs"],
    async load() {
      return (await import("@codemirror/lang-rust")).rust();
    },
  }),
  LanguageDescription.of({
    name: "python",
    alias: ["py"],
    async load() {
      return (await import("@codemirror/lang-python")).python();
    },
  }),
  LanguageDescription.of({
    name: "sql",
    alias: ["sqlite", "postgres", "postgresql"],
    async load() {
      return (await import("@codemirror/lang-sql")).sql();
    },
  }),
  LanguageDescription.of({
    name: "yaml",
    alias: ["yml"],
    async load() {
      return (await import("@codemirror/lang-yaml")).yaml();
    },
  }),
  LanguageDescription.of({
    name: "html",
    alias: ["htm"],
    async load() {
      return (await import("@codemirror/lang-html")).html();
    },
  }),
  LanguageDescription.of({
    name: "css",
    async load() {
      return (await import("@codemirror/lang-css")).css();
    },
  }),
  LanguageDescription.of({
    name: "xml",
    alias: ["svg"],
    async load() {
      return (await import("@codemirror/lang-xml")).xml();
    },
  }),
  LanguageDescription.of({
    name: "mermaid",
    alias: ["mmd"],
    support: new LanguageSupport(mermaidLanguage),
  }),
  LanguageDescription.of({
    name: "toml",
    support: new LanguageSupport(tomlLanguage),
  }),
  LanguageDescription.of({
    name: "shell",
    alias: ["sh", "bash", "zsh"],
    support: new LanguageSupport(shellLanguage),
  }),
];

const cache = new Map<string, Extension>();

/** Dynamically load language support chunks so initial page load stays tiny (< 220 KiB gzip target). */
export async function loadLangExtension(lang: string): Promise<Extension> {
  const norm = lang.toLowerCase();
  if (cache.has(norm)) return cache.get(norm)!;
  let ext: Extension = [];
  switch (norm) {
    case "json":
    case "json5":
      ext = (await import("@codemirror/lang-json")).json();
      break;
    case "javascript":
    case "js":
      ext = (await import("@codemirror/lang-javascript")).javascript({ jsx: true });
      break;
    case "typescript":
    case "ts":
      ext = (await import("@codemirror/lang-javascript")).javascript({ typescript: true, jsx: true });
      break;
    case "markdown":
    case "md": {
      const mdMod = await import("@codemirror/lang-markdown");
      ext = mdMod.markdown({
        base: mdMod.markdownLanguage,
        codeLanguages: CODE_LANGUAGE_DESCRIPTIONS,
        // Override unparsed fenced CodeText to plain content so plain fences never inherit inline-code terracotta.
        extensions: [{ props: [styleTags({ CodeText: t.content })] }],
      });
      break;
    }
    case "sql":
      ext = (await import("@codemirror/lang-sql")).sql();
      break;
    case "yaml":
    case "yml":
      ext = (await import("@codemirror/lang-yaml")).yaml();
      break;
    case "xml":
      ext = (await import("@codemirror/lang-xml")).xml();
      break;
    case "python":
    case "py":
      ext = (await import("@codemirror/lang-python")).python();
      break;
    case "rust":
    case "rs":
      ext = (await import("@codemirror/lang-rust")).rust();
      break;
    case "html":
      ext = (await import("@codemirror/lang-html")).html();
      break;
    case "css":
      ext = (await import("@codemirror/lang-css")).css();
      break;
    case "mermaid":
    case "mmd":
      ext = new LanguageSupport(mermaidLanguage);
      break;
    case "toml":
      ext = new LanguageSupport(tomlLanguage);
      break;
    case "sh":
    case "bash":
    case "shell":
    case "zsh":
      ext = new LanguageSupport(shellLanguage);
      break;
    default:
      ext = [];
  }
  cache.set(norm, ext);
  return ext;
}

let vimCache: Extension | null = null;
export async function loadVimExtension(): Promise<Extension> {
  if (!vimCache) {
    vimCache = (await import("@replit/codemirror-vim")).vim();
  }
  return vimCache;
}
