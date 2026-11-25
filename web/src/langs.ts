import type { Extension } from "@codemirror/state";

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
    case "md":
      ext = (await import("@codemirror/lang-markdown")).markdown();
      break;
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
