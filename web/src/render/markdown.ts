import { Marked, type Tokens } from "marked";
import createDOMPurify, { type DOMPurify as DOMPurifyInstance } from "dompurify";
import { getLocale, t, type Locale } from "../i18n";
import { createIcon, createIconSwap } from "../icons";
import {
  mountDiagramWidget,
  type DiagramRenderer,
  type DiagramWidgetHandle,
} from "./diagram";

export interface CodeBlockMeta {
  lang: string;
  code: string;
}

export interface SafeMarkdownResult {
  html: string;
  mermaidBlocks: string[];
  codeBlocks: CodeBlockMeta[];
}

export interface MountMarkdownOptions {
  readOnly: boolean;
  onToggleTask?: (nextSource: string) => void;
  onCopyFeedback?: (msg: string, isError?: boolean) => void;
  diagramRenderer?: DiagramRenderer;
  isTier2?: boolean;
}

export interface MountedMarkdownPreview {
  destroy(): void;
  refreshLocale?(): void;
  getCleanCopyPayload(): { html: string; text: string };
}

const ALLOWED_HTML_TAGS = [
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "p",
  "br",
  "hr",
  "blockquote",
  "pre",
  "code",
  "ul",
  "ol",
  "li",
  "dl",
  "dt",
  "dd",
  "table",
  "thead",
  "tbody",
  "tfoot",
  "tr",
  "th",
  "td",
  "a",
  "strong",
  "b",
  "em",
  "i",
  "del",
  "s",
  "sup",
  "sub",
  "span",
  "div",
  "input",
];

const ALLOWED_HTML_TAGS_SET = new Set(ALLOWED_HTML_TAGS);

const ALLOWED_HTML_ATTRS = [
  "href",
  "title",
  "target",
  "rel",
  "class",
  "type",
  "checked",
  "disabled",
  "align",
  "start",
  "colspan",
  "rowspan",
];

const ALLOWED_HTML_ATTRS_SET = new Set(ALLOWED_HTML_ATTRS);

const FORBID_HTML_TAGS = [
  "script",
  "iframe",
  "object",
  "embed",
  "form",
  "style",
  "foreignObject",
  "foreignobject",
  "img",
  "svg",
  "math",
  "link",
  "meta",
  "base",
  "button",
  "textarea",
  "select",
  "option",
  "audio",
  "video",
  "source",
  "track",
  "canvas",
  "noscript",
  "template",
];

const FORBID_HTML_ATTRS = [
  "style",
  "onerror",
  "onload",
  "onclick",
  "onmouseover",
  "onfocus",
  "onblur",
  "ontoggle",
  "oninput",
  "onchange",
  "onsubmit",
  "src",
  "srcdoc",
  "action",
  "formaction",
  "xlink:href",
  "autofocus",
];

const SAFE_ALIGN_VALUES = new Set(["left", "center", "right"]);
const SAFE_CLASS_RE = /^[a-zA-Z0-9 _-]+$/;
const SAFE_LANG_RE = /^[a-z0-9_-]{1,32}$/;
// Allows http:, https:, mailto:, #fragments, and non-URI attribute tokens (e.g. type="checkbox",
// target="_blank", align="left") while blocking javascript:, vbscript:, data:, file:, etc.
const ALLOWED_URI_RE = /^(?:(?:https?|mailto):|#|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;

let cachedHtmlPurify: DOMPurifyInstance | null = null;
const copyTimers = new WeakMap<HTMLButtonElement, ReturnType<typeof setTimeout>>();
let lastMarkdownStatusMessage = "";

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stripControlChars(input: string): string {
  let out = "";
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    if (code > 0x1f && code !== 0x7f) {
      out += input[i];
    }
  }
  return out;
}

function sanitizeHref(rawHref: string | null | undefined): string | null {
  if (!rawHref) {
    return null;
  }
  const cleaned = stripControlChars(rawHref).trim();
  if (!cleaned) {
    return null;
  }
  if (cleaned.startsWith("#")) {
    return cleaned;
  }
  if (cleaned.startsWith("//")) {
    return null;
  }
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(cleaned);
  if (!schemeMatch) {
    return null;
  }
  const scheme = schemeMatch[1].toLowerCase();
  if (scheme === "mailto") {
    return cleaned;
  }
  if (scheme === "http" || scheme === "https") {
    try {
      const parsed = new URL(cleaned);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        return parsed.href;
      }
    } catch {
      return null;
    }
  }
  return null;
}

function sanitizeExternalImageHref(rawHref: string | null | undefined): string | null {
  if (!rawHref) {
    return null;
  }
  const cleaned = stripControlChars(rawHref).trim();
  if (cleaned.startsWith("//")) {
    return sanitizeHref(`https:${cleaned}`);
  }
  const safe = sanitizeHref(cleaned);
  if (safe && (safe.startsWith("http://") || safe.startsWith("https://"))) {
    return safe;
  }
  return null;
}

function ensureSpecCompliantNodeName(win: Window): void {
  const nodeCtor = (win as Window & { Node?: typeof Node }).Node ?? globalThis.Node;
  if (!nodeCtor?.prototype) {
    return;
  }
  const probe = win.document.createElement("div");
  const desc = Object.getOwnPropertyDescriptor(nodeCtor.prototype, "nodeName");
  if (!desc?.get || !desc.configurable) {
    return;
  }
  if (desc.get.call(probe) === "DIV") {
    return;
  }
  const origGet = desc.get;
  Object.defineProperty(nodeCtor.prototype, "nodeName", {
    configurable: true,
    enumerable: desc.enumerable ?? false,
    get(this: Node) {
      if (this.nodeType === 1) {
        return (this as Element).tagName;
      }
      if (this.nodeType === 3) {
        return "#text";
      }
      if (this.nodeType === 8) {
        return "#comment";
      }
      if (this.nodeType === 9) {
        return "#document";
      }
      if (this.nodeType === 11) {
        return "#document-fragment";
      }
      return origGet.call(this);
    },
  });
}

function getHtmlPurify(): DOMPurifyInstance {
  if (cachedHtmlPurify) {
    return cachedHtmlPurify;
  }
  const win = typeof window !== "undefined" ? window : null;
  if (win) {
    ensureSpecCompliantNodeName(win);
    cachedHtmlPurify = createDOMPurify(win);
    return cachedHtmlPurify;
  }
  cachedHtmlPurify = createDOMPurify;
  return cachedHtmlPurify;
}

function enforceStrictHtmlDom(root: Element): void {
  const walk = (parent: Element): void => {
    for (const child of Array.from(parent.childNodes)) {
      if (child.nodeType === 8 || child.nodeType === 7) {
        child.parentNode?.removeChild(child);
        continue;
      }
      if (child.nodeType !== 1) {
        continue;
      }
      const el = child as Element;
      const tag = el.localName.toLowerCase();
      if (!ALLOWED_HTML_TAGS_SET.has(tag)) {
        el.parentNode?.removeChild(el);
        continue;
      }

      if (tag === "input") {
        const typeAttr = (el.getAttribute("type") ?? "").trim().toLowerCase();
        if (typeAttr !== "checkbox") {
          el.parentNode?.removeChild(el);
          continue;
        }
        for (const attr of Array.from(el.attributes)) {
          const attrName = attr.name.toLowerCase();
          if (attrName !== "type" && attrName !== "checked" && attrName !== "disabled") {
            el.removeAttribute(attr.name);
          }
        }
        el.setAttribute("type", "checkbox");
        continue;
      }

      for (const attr of Array.from(el.attributes)) {
        const attrName = attr.name.toLowerCase();
        if (
          !ALLOWED_HTML_ATTRS_SET.has(attrName) ||
          attrName.startsWith("on") ||
          attrName.startsWith("data-") ||
          attrName.startsWith("aria-") ||
          attrName === "style"
        ) {
          el.removeAttribute(attr.name);
          continue;
        }
        if (attrName === "align" && !SAFE_ALIGN_VALUES.has(attr.value.toLowerCase())) {
          el.removeAttribute(attr.name);
        } else if (attrName === "class" && !SAFE_CLASS_RE.test(attr.value)) {
          el.removeAttribute(attr.name);
        }
      }

      if (tag === "a") {
        const safeHref = sanitizeHref(el.getAttribute("href"));
        if (!safeHref) {
          el.removeAttribute("href");
          el.removeAttribute("target");
          el.removeAttribute("rel");
        } else {
          el.setAttribute("href", safeHref);
          if (!safeHref.startsWith("#")) {
            el.setAttribute("rel", "noopener noreferrer");
            el.setAttribute("target", "_blank");
          }
        }
      }

      walk(el);
    }
  };

  walk(root);
}

function sanitizeHtmlToElement(rawHtml: string): HTMLElement {
  const purify = getHtmlPurify();
  const clean = purify.sanitize(rawHtml, {
    ALLOWED_TAGS: [...ALLOWED_HTML_TAGS, "#text"],
    ALLOWED_ATTR: ALLOWED_HTML_ATTRS,
    FORBID_TAGS: FORBID_HTML_TAGS,
    FORBID_ATTR: FORBID_HTML_ATTRS,
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
    KEEP_CONTENT: false,
    ALLOWED_URI_REGEXP: ALLOWED_URI_RE,
  });

  const parser = new DOMParser();
  const parsedDoc = parser.parseFromString(`<body>${clean}</body>`, "text/html");
  enforceStrictHtmlDom(parsedDoc.body);
  return parsedDoc.body;
}

export function renderSafeMarkdown(source: string): SafeMarkdownResult {
  const mermaidBlocks: string[] = [];
  const codeBlocks: CodeBlockMeta[] = [];
  let insideAnchor = false;

  const instance = new Marked({
    gfm: true,
    breaks: false,
  });

  instance.use({
    renderer: {
      html({ text }: Tokens.HTML | Tokens.Tag): string {
        return escapeHtml(text);
      },

      image({ href, text }: Tokens.Image): string {
        const externalHref = sanitizeExternalImageHref(href);
        const label = escapeHtml(text.trim() || (href ?? "").trim() || "image");
        if (externalHref) {
          const prefix = escapeHtml(t("md.blockedExtImg"));
          if (insideAnchor) {
            return `<span class="md-blocked-img">${prefix} ${label}</span>`;
          }
          return `<span class="md-blocked-img">${prefix} <a href="${escapeHtml(externalHref)}" rel="noopener noreferrer" target="_blank">${label}</a></span>`;
        }
        const prefix = escapeHtml(t("md.blockedImg"));
        return `<span class="md-blocked-img">${prefix} ${label}</span>`;
      },

      link({ href, title, tokens }: Tokens.Link): string {
        const safeHref = sanitizeHref(href);
        if (!safeHref) {
          return this.parser.parseInline(tokens);
        }
        const prevInside = insideAnchor;
        insideAnchor = true;
        let body = "";
        try {
          body = this.parser.parseInline(tokens);
        } finally {
          insideAnchor = prevInside;
        }
        const titleAttr = title ? ` title="${escapeHtml(title)}"` : "";
        if (safeHref.startsWith("#")) {
          return `<a href="${escapeHtml(safeHref)}"${titleAttr}>${body}</a>`;
        }
        return `<a href="${escapeHtml(safeHref)}" rel="noopener noreferrer" target="_blank"${titleAttr}>${body}</a>`;
      },

      code({ text, lang }: Tokens.Code): string {
        const rawLang = (lang ?? "").trim().split(/\s+/)[0]?.toLowerCase() ?? "";
        if (rawLang === "mermaid") {
          mermaidBlocks.push(text);
          return '<div class="md-mermaid-slot"></div>\n';
        }
        const safeLang = SAFE_LANG_RE.test(rawLang) ? rawLang : "";
        codeBlocks.push({ lang: safeLang, code: text });
        const classAttr = safeLang ? ` class="language-${safeLang}"` : "";
        return `<pre><code${classAttr}>${escapeHtml(text)}</code></pre>\n`;
      },

      checkbox({ checked }: Tokens.Checkbox): string {
        return `<input type="checkbox"${checked ? " checked" : ""} disabled />`;
      },
    },
  });

  const rawHtml = instance.parse(source, { async: false });
  const sanitizedBody = sanitizeHtmlToElement(rawHtml);

  return {
    html: sanitizedBody.innerHTML,
    mermaidBlocks,
    codeBlocks,
  };
}

export function toggleMarkdownTaskCheckbox(source: string, checkboxIndex: number): string {
  if (!Number.isInteger(checkboxIndex) || checkboxIndex < 0) {
    return source;
  }

  const parts = source.split(/(\r?\n)/);
  let inFence = false;
  let fenceChar = "";
  let fenceLen = 0;
  let seen = 0;

  const openFenceRe = /^\s{0,3}(`{3,}|~{3,})(.*)$/;
  const closeFenceRe = /^\s{0,3}(`{3,}|~{3,})\s*$/;
  const taskLineRe = /^(\s*(?:[-*+]|\d+[.)])\s+\[)([ xX])(\])(?=\s|$)/;

  for (let i = 0; i < parts.length; i += 2) {
    const line = parts[i];
    if (!inFence) {
      const openMatch = openFenceRe.exec(line);
      if (openMatch) {
        const marker = openMatch[1];
        const info = openMatch[2];
        if (marker[0] !== "`" || !info.includes("`")) {
          inFence = true;
          fenceChar = marker[0];
          fenceLen = marker.length;
          continue;
        }
      }
      const taskMatch = taskLineRe.exec(line);
      if (taskMatch) {
        if (seen === checkboxIndex) {
          const nextMark = taskMatch[2] === " " ? "x" : " ";
          parts[i] =
            taskMatch[1] + nextMark + taskMatch[3] + line.slice(taskMatch[0].length);
          return parts.join("");
        }
        seen += 1;
      }
    } else {
      const closeMatch = closeFenceRe.exec(line);
      if (closeMatch && closeMatch[1][0] === fenceChar && closeMatch[1].length >= fenceLen) {
        inFence = false;
        fenceChar = "";
        fenceLen = 0;
      }
    }
  }

  return source;
}

function getTableRows(table: HTMLTableElement): HTMLTableRowElement[] {
  const rows: HTMLTableRowElement[] = [];
  const collectSection = (section: Element): void => {
    for (const child of Array.from(section.children)) {
      if (child.localName.toLowerCase() === "tr") {
        rows.push(child as HTMLTableRowElement);
      }
    }
  };
  for (const child of Array.from(table.children)) {
    const tag = child.localName.toLowerCase();
    if (tag === "thead" || tag === "tbody" || tag === "tfoot") {
      collectSection(child);
    } else if (tag === "tr") {
      rows.push(child as HTMLTableRowElement);
    }
  }
  return rows;
}

function getRowCells(row: HTMLTableRowElement): HTMLTableCellElement[] {
  const cells: HTMLTableCellElement[] = [];
  for (const child of Array.from(row.children)) {
    const tag = child.localName.toLowerCase();
    if (tag === "th" || tag === "td") {
      cells.push(child as HTMLTableCellElement);
    }
  }
  return cells;
}

function escapeTsvCell(raw: string): string {
  const trimmed = raw.trim();
  if (/[\t\r\n"]/.test(trimmed)) {
    return `"${trimmed.replace(/"/g, '""')}"`;
  }
  return trimmed;
}

export function tableToTsv(table: HTMLTableElement): string {
  const rows = getTableRows(table);
  return rows
    .map((row) =>
      getRowCells(row)
        .map((cell) => escapeTsvCell(cell.textContent ?? ""))
        .join("\t"),
    )
    .join("\n");
}

function escapeMarkdownTableCell(raw: string): string {
  return raw
    .trim()
    .replace(/\r?\n/g, " ")
    .replace(/\|/g, "\\|");
}

function alignmentMarker(align: string | null): string {
  switch ((align ?? "").toLowerCase()) {
    case "left":
      return ":---";
    case "center":
      return ":---:";
    case "right":
      return "---:";
    default:
      return "---";
  }
}

export function tableToMarkdown(table: HTMLTableElement): string {
  const rows = getTableRows(table);
  if (rows.length === 0) {
    return "";
  }

  const matrix = rows.map((row) => getRowCells(row));
  const colCount = matrix.reduce((max, cells) => Math.max(max, cells.length), 0);
  if (colCount === 0) {
    return "";
  }

  const formatRow = (cells: HTMLTableCellElement[]): string => {
    const values: string[] = [];
    for (let c = 0; c < colCount; c += 1) {
      values.push(escapeMarkdownTableCell(cells[c]?.textContent ?? ""));
    }
    return `| ${values.join(" | ")} |`;
  };

  const headerCells = matrix[0];
  const separatorCells: string[] = [];
  for (let c = 0; c < colCount; c += 1) {
    separatorCells.push(alignmentMarker(headerCells[c]?.getAttribute("align") ?? null));
  }

  const lines = [formatRow(headerCells), `| ${separatorCells.join(" | ")} |`];
  for (let r = 1; r < matrix.length; r += 1) {
    lines.push(formatRow(matrix[r]));
  }
  return lines.join("\n");
}

export async function copyDualFormat(html: string, text: string): Promise<boolean> {
  if (typeof navigator === "undefined" || !navigator.clipboard) {
    return false;
  }

  if (
    typeof navigator.clipboard.write === "function" &&
    typeof ClipboardItem !== "undefined"
  ) {
    try {
      const item = new ClipboardItem({
        "text/html": new Blob([html], { type: "text/html" }),
        "text/plain": new Blob([text], { type: "text/plain" }),
      });
      await navigator.clipboard.write([item]);
      return true;
    } catch {
      // Fall through to plain text clipboard write.
    }
  }

  if (typeof navigator.clipboard.writeText === "function") {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }

  return false;
}

function reportCopyFeedback(
  button: HTMLButtonElement,
  tip: HTMLSpanElement,
  ok: boolean,
  successText: string,
  failText: string,
  onFeedback?: (msg: string, isError?: boolean) => void,
): void {
  const existing = copyTimers.get(button);
  if (existing !== undefined) {
    clearTimeout(existing);
  }
  button.removeAttribute("data-copied");
  button.removeAttribute("data-failed");
  tip.textContent = "";

  const baseMessage = ok ? successText : failText;
  let announced = baseMessage;
  if (announced === lastMarkdownStatusMessage) {
    announced += "\u00A0";
  }
  lastMarkdownStatusMessage = announced;

  button.setAttribute(ok ? "data-copied" : "data-failed", "");
  const setStatus = (): void => {
    tip.textContent = announced;
  };
  if (typeof requestAnimationFrame === "function") {
    requestAnimationFrame(setStatus);
  } else {
    setStatus();
  }

  const timer = setTimeout(() => {
    button.removeAttribute("data-copied");
    button.removeAttribute("data-failed");
    tip.textContent = "";
    copyTimers.delete(button);
  }, 2000);
  copyTimers.set(button, timer);

  onFeedback?.(baseMessage, !ok);
}

function createCopyControl(label: string, extraClass: string): {
  wrapper: HTMLSpanElement;
  button: HTMLButtonElement;
  labelEl: HTMLSpanElement;
  tip: HTMLSpanElement;
} {
  const wrapper = document.createElement("span");
  wrapper.className = "copy";

  const button = document.createElement("button");
  button.type = "button";
  button.className = `btn btn-icon btn-has-icon copy-button ${extraClass}`;
  const labelEl = document.createElement("span");
  labelEl.className = "copy-btn-label";
  labelEl.textContent = label;
  button.append(createIconSwap("copy", "check", "xs"), labelEl);

  const tip = document.createElement("span");
  tip.className = "copy-tip";
  tip.setAttribute("role", "status");

  wrapper.append(button, tip);
  return { wrapper, button, labelEl, tip };
}

function extractCleanPlainText(root: Element): string {
  const chunks: string[] = [];

  for (const child of Array.from(root.children)) {
    const tag = child.localName.toLowerCase();
    if (tag === "table") {
      chunks.push(tableToTsv(child as HTMLTableElement));
    } else if (tag === "pre") {
      chunks.push((child.textContent ?? "").replace(/\n$/, ""));
    } else if (tag === "ul" || tag === "ol") {
      const items: string[] = [];
      for (const li of Array.from(child.children)) {
        if (li.localName.toLowerCase() === "li") {
          const cb = li.querySelector('input[type="checkbox"]') as HTMLInputElement | null;
          const prefix = cb ? (cb.checked ? "[x] " : "[ ] ") : "- ";
          items.push(`${prefix}${(li.textContent ?? "").trim()}`);
        }
      }
      chunks.push(items.join("\n"));
    } else {
      const text = (child.textContent ?? "").trim();
      if (text) {
        chunks.push(text);
      }
    }
  }

  if (chunks.length === 0) {
    return (root.textContent ?? "").trim();
  }
  return chunks.join("\n\n");
}

function buildCleanCopyPayload(rendered: SafeMarkdownResult): { html: string; text: string } {
  const cleanBody = sanitizeHtmlToElement(rendered.html);
  const slots = Array.from(cleanBody.querySelectorAll(".md-mermaid-slot"));
  slots.forEach((slot, idx) => {
    const mermaidSrc = rendered.mermaidBlocks[idx] ?? "";
    const pre = cleanBody.ownerDocument.createElement("pre");
    const code = cleanBody.ownerDocument.createElement("code");
    code.className = "language-mermaid";
    code.textContent = mermaidSrc;
    pre.appendChild(code);
    slot.replaceWith(pre);
  });

  return {
    html: cleanBody.innerHTML,
    text: extractCleanPlainText(cleanBody),
  };
}

export function mountMarkdownPreview(
  container: HTMLElement,
  source: string,
  options: MountMarkdownOptions,
): MountedMarkdownPreview {
  const rendered = renderSafeMarkdown(source);
  let cachedPayloadSource = source;
  let cachedPayloadLocale: Locale = getLocale();
  let cleanPayload = buildCleanCopyPayload(rendered);

  const sanitizedBody = sanitizeHtmlToElement(rendered.html);
  const previewRoot = document.createElement("div");
  previewRoot.className = "md-preview";
  for (const child of Array.from(sanitizedBody.childNodes)) {
    previewRoot.appendChild(document.importNode(child, true));
  }

  const cleanups: Array<() => void> = [];
  const diagramHandles: DiagramWidgetHandle[] = [];
  const trackedButtons: HTMLButtonElement[] = [];
  const localeRefreshes: Array<() => void> = [];
  let destroyed = false;

  // Post-sanitization icon decoration for blocked images (keeps rendered.html 100% <svg>-free for SEC-06).
  const initialExtPrefix = t("md.blockedExtImg");
  const initialGenPrefix = t("md.blockedImg");
  for (const badge of Array.from(previewRoot.querySelectorAll(".md-blocked-img"))) {
    const firstNode = badge.firstChild;
    const isExt =
      badge.querySelector("a") !== null ||
      (firstNode?.nodeType === 3 && (firstNode.textContent ?? "").startsWith(initialExtPrefix));
    if (firstNode && firstNode.nodeType === 3) {
      const currentText = firstNode.textContent ?? "";
      const prefixUsed = isExt ? initialExtPrefix : initialGenPrefix;
      const tail = currentText.startsWith(prefixUsed) ? currentText.slice(prefixUsed.length) : currentText;
      const prefixSpan = document.createElement("span");
      prefixSpan.className = "md-blocked-img-prefix";
      prefixSpan.textContent = prefixUsed;
      firstNode.textContent = tail;
      badge.insertBefore(prefixSpan, firstNode);
      badge.insertBefore(createIcon("image-off", "xs"), prefixSpan);
      localeRefreshes.push(() => {
        prefixSpan.textContent = isExt ? t("md.blockedExtImg") : t("md.blockedImg");
      });
    } else {
      badge.insertBefore(createIcon("image-off", "xs"), badge.firstChild);
    }
  }

  let currentSource = source;
  const checkboxes = Array.from(
    previewRoot.querySelectorAll('input[type="checkbox"]'),
  ) as HTMLInputElement[];

  checkboxes.forEach((cb, idx) => {
    const li = cb.closest("li");
    if (li) {
      li.classList.add("md-task-item");
      const listEl = li.parentElement;
      if (listEl && (listEl.localName.toLowerCase() === "ul" || listEl.localName.toLowerCase() === "ol")) {
        listEl.classList.add("md-task-list");
      }
    }
    if (options.readOnly) {
      cb.disabled = true;
      return;
    }
    cb.disabled = false;
    const onChange = (): void => {
      const next = toggleMarkdownTaskCheckbox(currentSource, idx);
      currentSource = next;
      options.onToggleTask?.(next);
    };
    cb.addEventListener("change", onChange);
    cleanups.push(() => cb.removeEventListener("change", onChange));
  });

  const preNodes = Array.from(previewRoot.querySelectorAll("pre")).filter((pre) =>
    Array.from(pre.children).some((child) => child.localName.toLowerCase() === "code"),
  );
  preNodes.forEach((pre, idx) => {
    const meta = rendered.codeBlocks[idx];
    const codeEl = pre.querySelector("code");
    const rawCode = meta ? meta.code : codeEl?.textContent ?? "";

    const wrap = document.createElement("div");
    wrap.className = "md-code-wrap copyable";

    const toolbar = document.createElement("div");
    toolbar.className = "md-code-toolbar";

    if (meta?.lang) {
      const langBadge = document.createElement("span");
      langBadge.className = "md-code-lang";
      langBadge.textContent = meta.lang;
      toolbar.appendChild(langBadge);
    }

    const copyCtrl = createCopyControl(t("md.copyCode"), "md-copy-code");
    trackedButtons.push(copyCtrl.button);
    localeRefreshes.push(() => {
      copyCtrl.labelEl.textContent = t("md.copyCode");
    });
    toolbar.appendChild(copyCtrl.wrapper);

    pre.setAttribute("tabindex", "0");
    pre.parentNode?.insertBefore(wrap, pre);
    wrap.append(toolbar, pre);

    if (meta?.lang && codeEl) {
      void import("./highlight")
        .then(({ highlightCodeSnippet }) => highlightCodeSnippet(rawCode, meta.lang))
        .then((tokens) => {
          if (destroyed || !tokens || tokens.length === 0 || !codeEl.isConnected) return;
          const frag = document.createDocumentFragment();
          for (const tok of tokens) {
            if (!tok.cls) {
              frag.appendChild(document.createTextNode(tok.text));
            } else {
              const span = document.createElement("span");
              span.className = tok.cls;
              span.textContent = tok.text;
              frag.appendChild(span);
            }
          }
          codeEl.replaceChildren(frag);
        });
    }

    const onCopyCode = async (): Promise<void> => {
      try {
        if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
          throw new Error("Clipboard unavailable");
        }
        await navigator.clipboard.writeText(rawCode);
        reportCopyFeedback(
          copyCtrl.button,
          copyCtrl.tip,
          true,
          t("md.copied"),
          t("md.copyFailed"),
          options.onCopyFeedback,
        );
      } catch {
        reportCopyFeedback(
          copyCtrl.button,
          copyCtrl.tip,
          false,
          t("md.copied"),
          t("md.copyFailed"),
          options.onCopyFeedback,
        );
      }
    };
    copyCtrl.button.addEventListener("click", onCopyCode);
    cleanups.push(() => copyCtrl.button.removeEventListener("click", onCopyCode));
  });

  const tables = Array.from(previewRoot.querySelectorAll("table")) as HTMLTableElement[];
  tables.forEach((table) => {
    const wrap = document.createElement("div");
    wrap.className = "md-table-wrap copyable";

    const scroll = document.createElement("div");
    scroll.className = "md-table-scroll";

    const toolbar = document.createElement("div");
    toolbar.className = "md-table-toolbar";

    const tsvCtrl = createCopyControl(t("md.copyTsv"), "md-copy-tsv");
    const mdCtrl = createCopyControl(t("md.copyMd"), "md-copy-md");
    tsvCtrl.button.title = t("md.copiedTsv");
    mdCtrl.button.title = t("md.copiedMd");
    trackedButtons.push(tsvCtrl.button, mdCtrl.button);
    localeRefreshes.push(() => {
      tsvCtrl.labelEl.textContent = t("md.copyTsv");
      mdCtrl.labelEl.textContent = t("md.copyMd");
    });

    toolbar.append(tsvCtrl.wrapper, mdCtrl.wrapper);
    table.parentNode?.insertBefore(wrap, table);
    scroll.appendChild(table);
    wrap.append(toolbar, scroll);

    const onCopyTsv = async (): Promise<void> => {
      try {
        if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
          throw new Error("Clipboard unavailable");
        }
        await navigator.clipboard.writeText(tableToTsv(table));
        reportCopyFeedback(
          tsvCtrl.button,
          tsvCtrl.tip,
          true,
          t("md.copiedTsv"),
          t("md.copyFailed"),
          options.onCopyFeedback,
        );
      } catch {
        reportCopyFeedback(
          tsvCtrl.button,
          tsvCtrl.tip,
          false,
          t("md.copiedTsv"),
          t("md.copyFailed"),
          options.onCopyFeedback,
        );
      }
    };

    const onCopyMd = async (): Promise<void> => {
      try {
        if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
          throw new Error("Clipboard unavailable");
        }
        await navigator.clipboard.writeText(tableToMarkdown(table));
        reportCopyFeedback(
          mdCtrl.button,
          mdCtrl.tip,
          true,
          t("md.copiedMd"),
          t("md.copyFailed"),
          options.onCopyFeedback,
        );
      } catch {
        reportCopyFeedback(
          mdCtrl.button,
          mdCtrl.tip,
          false,
          t("md.copiedMd"),
          t("md.copyFailed"),
          options.onCopyFeedback,
        );
      }
    };

    tsvCtrl.button.addEventListener("click", onCopyTsv);
    mdCtrl.button.addEventListener("click", onCopyMd);
    cleanups.push(() => {
      tsvCtrl.button.removeEventListener("click", onCopyTsv);
      mdCtrl.button.removeEventListener("click", onCopyMd);
    });
  });

  const mermaidSlots = Array.from(previewRoot.querySelectorAll(".md-mermaid-slot"));
  mermaidSlots.forEach((slot, idx) => {
    const mermaidSrc = rendered.mermaidBlocks[idx];
    if (mermaidSrc !== undefined) {
      const handle = mountDiagramWidget(slot as HTMLElement, mermaidSrc, {
        renderer: options.diagramRenderer,
        readOnly: options.readOnly,
        onFeedback: options.onCopyFeedback,
        isTier2: options.isTier2,
      });
      diagramHandles.push(handle);
    }
  });

  container.replaceChildren(previewRoot);

  return {
    destroy() {
      destroyed = true;
      for (const cleanup of cleanups) {
        cleanup();
      }
      for (const handle of diagramHandles) {
        handle.destroy();
      }
      for (const btn of trackedButtons) {
        const timer = copyTimers.get(btn);
        if (timer !== undefined) {
          clearTimeout(timer);
          copyTimers.delete(btn);
        }
      }
    },
    refreshLocale() {
      for (const fn of localeRefreshes) {
        fn();
      }
      for (const handle of diagramHandles) {
        handle.refreshLocale?.();
      }
    },
    getCleanCopyPayload() {
      const loc = getLocale();
      if (currentSource !== cachedPayloadSource || loc !== cachedPayloadLocale) {
        cachedPayloadSource = currentSource;
        cachedPayloadLocale = loc;
        cleanPayload = buildCleanCopyPayload(renderSafeMarkdown(currentSource));
      }
      return {
        html: cleanPayload.html,
        text: cleanPayload.text,
      };
    },
  };
}
