import createDOMPurify, { type DOMPurify as DOMPurifyInstance } from "dompurify";

export interface DiagramRenderResult {
  svg: string;
  width: number;
  height: number;
  type: string;
}

export interface DiagramRenderer {
  readonly id: string;
  render(source: string): Promise<DiagramRenderResult>;
}

export interface PanZoomController {
  zoomIn(): void;
  zoomOut(): void;
  reset(): void;
  destroy(): void;
}

export interface DiagramWidgetOptions {
  renderer?: DiagramRenderer;
  readOnly?: boolean;
  onFeedback?: (msg: string, isError?: boolean) => void;
  isTier2?: boolean;
}

export interface DiagramWidgetHandle {
  readonly ready: Promise<boolean>;
  update(nextSource: string): Promise<boolean>;
  destroy(): void;
}

const SVG_NS = "http://www.w3.org/2000/svg";

const SAFE_SVG_PRESENTATION_PROPS = new Set([
  "fill",
  "stroke",
  "stroke-width",
  "stroke-dasharray",
  "opacity",
  "fill-opacity",
  "stroke-opacity",
  "rx",
  "ry",
  "font-weight",
]);

const FORBIDDEN_SVG_TAGS = [
  "foreignObject",
  "foreignobject",
  "script",
  "iframe",
  "object",
  "embed",
  "style",
  "link",
  "meta",
  "animate",
  "set",
  "image",
];

const FORBIDDEN_SVG_TAGS_LOWER = new Set(FORBIDDEN_SVG_TAGS.map((t) => t.toLowerCase()));

const FORBIDDEN_SVG_ATTRS = [
  "style",
  "onload",
  "onerror",
  "onclick",
  "onmouseover",
  "onfocus",
  "href",
  "xlink:href",
];

const FORBIDDEN_SVG_ATTRS_LOWER = new Set(FORBIDDEN_SVG_ATTRS.map((a) => a.toLowerCase()));

const UNSAFE_CSS_VALUE_RE =
  /url\s*\(|expression\s*\(|javascript:|vbscript:|data:|@import|[\\;"'<>]/i;
const SAFE_VAR_RE = /^var\(\s*--_[a-zA-Z0-9_-]+\s*\)$/;
const SAFE_HEX_COLOR_RE = /^#[0-9a-fA-F]{3,8}$/;
const SAFE_RGB_COLOR_RE =
  /^rgba?\(\s*\d{1,3}(?:\.\d+)?%?(?:\s*,\s*\d{1,3}(?:\.\d+)?%?){2}(?:\s*,\s*(?:0(?:\.\d+)?|1(?:\.0+)?|\.\d+))?\s*\)$/;
const SAFE_NAMED_COLOR_RE = /^(?:none|currentColor|transparent|inherit|[a-z]{3,20})$/i;
const SAFE_NUMBER_OR_PX_RE = /^\d+(?:\.\d+)?(?:px|%|em|rem)?$/;
const SAFE_OPACITY_RE = /^(?:0(?:\.\d+)?|1(?:\.0+)?|\.\d+)$/;
const SAFE_DASHARRAY_RE = /^(?:none|\d+(?:\.\d+)?(?:[\s,]+\d+(?:\.\d+)?)*)$/;
const SAFE_FONT_WEIGHT_RE = /^(?:normal|bold|bolder|lighter|italic|[1-9]00)$/;

const PELE_DEFAULT_TOKENS: Readonly<Record<string, string>> = {
  "--_bg": "#ffffff",
  "--_fg": "#1f1f1f",
  "--_m": "#6e6e6e",
  "--_l": "#1f1f1f",
  "--_s": "#f3f3f3",
  "--_a": "#e6e6e6",
  "--_b": "#8a8a8a",
  "--_c": "#5b7bd5",
  "--_r": "4",
  "--_hw": "bold",
  "--_fm": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
  "--pele-bg": "#ffffff",
  "--pele-fg": "#1f1f1f",
  "--pele-fg-on-light": "#1f1f1f",
  "--pele-fg-on-dark": "#ffffff",
  "--pele-muted": "#6e6e6e",
  "--pele-line": "#1f1f1f",
  "--pele-surface": "#f3f3f3",
  "--pele-surface-alt": "#e6e6e6",
  "--pele-border": "#8a8a8a",
  "--pele-accent": "#5b7bd5",
  "--pele-radius": "4",
  "--pele-heading-weight": "bold",
  "--pele-font": "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif",
  "--pele-font-mono": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
};

const PELE_TO_THEME_FALLBACKS: Readonly<Record<string, readonly string[]>> = {
  "--_bg": ["--_bg", "--pele-bg", "--bg-card", "--bg"],
  "--_fg": ["--_fg", "--pele-fg", "--text"],
  "--_m": ["--_m", "--pele-muted", "--text-muted"],
  "--_l": ["--_l", "--pele-line", "--text-muted"],
  "--_s": ["--_s", "--pele-surface", "--bg-elev"],
  "--_a": ["--_a", "--pele-surface-alt", "--bg-hover"],
  "--_b": ["--_b", "--pele-border", "--border"],
  "--_c": ["--_c", "--pele-accent", "--accent"],
  "--_r": ["--_r", "--pele-radius"],
  "--_hw": ["--_hw", "--pele-heading-weight"],
  "--_fm": ["--_fm", "--pele-font-mono", "--mono"],
};

type PeleModule = typeof import("pele");
let peleModulePromise: Promise<PeleModule> | null = null;
let cachedPurify: DOMPurifyInstance | null = null;
const copyTimers = new WeakMap<HTMLButtonElement, ReturnType<typeof setTimeout>>();
let lastDiagramStatusMessage = "";

function loadPele(): Promise<PeleModule> {
  if (!peleModulePromise) {
    peleModulePromise = import("pele");
  }
  return peleModulePromise;
}

function getSvgPurify(): DOMPurifyInstance {
  if (cachedPurify) {
    return cachedPurify;
  }
  const win = typeof window !== "undefined" ? window : null;
  if (win) {
    ensureSpecCompliantNodeName(win);
    cachedPurify = createDOMPurify(win);
    return cachedPurify;
  }
  cachedPurify = createDOMPurify;
  return cachedPurify;
}

/**
 * DOMPurify 3.5 caches `Object.getOwnPropertyDescriptor(Node.prototype, "nodeName").get`
 * to resist DOM clobbering. Older test DOMs (happy-dom 17.x) return `""` from
 * `Node.prototype.nodeName` on Element nodes instead of delegating to `tagName`.
 * This check is a complete no-op in every real browser and spec-compliant DOM.
 */
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

function isSafeSvgPresentationValue(prop: string, value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed || UNSAFE_CSS_VALUE_RE.test(trimmed)) {
    return false;
  }
  if (SAFE_VAR_RE.test(trimmed)) {
    return true;
  }
  switch (prop) {
    case "fill":
    case "stroke":
      return (
        SAFE_HEX_COLOR_RE.test(trimmed) ||
        SAFE_RGB_COLOR_RE.test(trimmed) ||
        SAFE_NAMED_COLOR_RE.test(trimmed)
      );
    case "stroke-width":
    case "rx":
    case "ry":
      return SAFE_NUMBER_OR_PX_RE.test(trimmed);
    case "stroke-dasharray":
      return SAFE_DASHARRAY_RE.test(trimmed);
    case "opacity":
    case "fill-opacity":
    case "stroke-opacity":
      return SAFE_OPACITY_RE.test(trimmed);
    case "font-weight":
      return SAFE_FONT_WEIGHT_RE.test(trimmed);
    default:
      return false;
  }
}

function normalizeSvgLengthAttrValue(rawVal: string): string | null {
  let trimmed = rawVal.trim();
  const varMatch = /^var\(\s*(--_[a-zA-Z0-9_-]+)\s*\)$/.exec(trimmed);
  if (varMatch) {
    trimmed = PELE_DEFAULT_TOKENS[varMatch[1]] ?? "";
  }
  if (trimmed.endsWith("px")) {
    trimmed = trimmed.slice(0, -2).trim();
  }
  return /^\d+(?:\.\d+)?$/.test(trimmed) ? trimmed : null;
}

/**
 * Rename raw `style=` attributes inside XML start-tags to `data-pele-style=` before
 * `DOMParser().parseFromString(..., "image/svg+xml")` runs. WebKit/Safari enforces
 * `style-src 'self'` on inline `style` attributes at XML parse time (firing
 * `securitypolicyviolation` before post-parse promotion can strip them).
 */
function neutralizeInlineStyleAttrsBeforeXmlParse(rawSvg: string): string {
  const out: string[] = [];
  let i = 0;
  const len = rawSvg.length;

  while (i < len) {
    const lt = rawSvg.indexOf("<", i);
    if (lt === -1) {
      out.push(rawSvg.slice(i));
      break;
    }
    if (lt > i) {
      out.push(rawSvg.slice(i, lt));
    }
    if (rawSvg.startsWith("<!--", lt)) {
      const end = rawSvg.indexOf("-->", lt + 4);
      const next = end === -1 ? len : end + 3;
      out.push(rawSvg.slice(lt, next));
      i = next;
      continue;
    }
    if (rawSvg.startsWith("<![CDATA[", lt)) {
      const end = rawSvg.indexOf("]]>", lt + 9);
      const next = end === -1 ? len : end + 3;
      out.push(rawSvg.slice(lt, next));
      i = next;
      continue;
    }
    if (rawSvg.startsWith("<?", lt) || rawSvg.startsWith("<!", lt) || rawSvg.startsWith("</", lt)) {
      const end = rawSvg.indexOf(">", lt + 2);
      const next = end === -1 ? len : end + 1;
      out.push(rawSvg.slice(lt, next));
      i = next;
      continue;
    }

    let pos = lt + 1;
    let inQuote: string | null = null;
    while (pos < len) {
      const ch = rawSvg[pos];
      if (inQuote) {
        if (ch === inQuote) inQuote = null;
      } else if (ch === '"' || ch === "'") {
        inQuote = ch;
      } else if (ch === ">") {
        pos += 1;
        break;
      }
      pos += 1;
    }

    const tagText = rawSvg.slice(lt, pos);
    let rewritten = "";
    let t = 0;
    while (t < tagText.length && !/[\s/>]/.test(tagText[t])) {
      rewritten += tagText[t];
      t += 1;
    }
    while (t < tagText.length) {
      if (/[\s/>]/.test(tagText[t])) {
        rewritten += tagText[t];
        t += 1;
        continue;
      }
      const nameStart = t;
      while (t < tagText.length && !/[\s=/>]/.test(tagText[t])) {
        t += 1;
      }
      const attrName = tagText.slice(nameStart, t);
      const wsStart = t;
      while (t < tagText.length && /\s/.test(tagText[t])) {
        t += 1;
      }
      if (t < tagText.length && tagText[t] === "=") {
        rewritten += attrName.toLowerCase() === "style" ? "data-pele-style" : attrName;
        rewritten += tagText.slice(wsStart, t + 1);
        t += 1;
        while (t < tagText.length && /\s/.test(tagText[t])) {
          rewritten += tagText[t];
          t += 1;
        }
        if (t < tagText.length && (tagText[t] === '"' || tagText[t] === "'")) {
          const q = tagText[t];
          const valStart = t;
          t += 1;
          while (t < tagText.length && tagText[t] !== q) {
            t += 1;
          }
          if (t < tagText.length) t += 1;
          rewritten += tagText.slice(valStart, t);
        } else {
          const valStart = t;
          while (t < tagText.length && !/[\s/>]/.test(tagText[t])) {
            t += 1;
          }
          rewritten += tagText.slice(valStart, t);
        }
      } else {
        rewritten += attrName + tagText.slice(wsStart, t);
      }
    }

    out.push(rewritten);
    i = pos;
  }

  return out.join("");
}

function promoteSafeInlineStyles(svgEl: Element): void {
  const stack: Element[] = [svgEl];
  while (stack.length > 0) {
    const el = stack.pop();
    if (!el) {
      continue;
    }
    const rawParts = [el.getAttribute("data-pele-style"), el.getAttribute("style")].filter(
      (v): v is string => v !== null,
    );
    if (rawParts.length > 0) {
      const styleAttr = rawParts.join(";");
      const isRootSvg = el.localName.toLowerCase() === "svg";
      for (const declaration of styleAttr.split(";")) {
        const colonIdx = declaration.indexOf(":");
        if (colonIdx <= 0) {
          continue;
        }
        const prop = declaration.slice(0, colonIdx).trim().toLowerCase();
        const val = declaration.slice(colonIdx + 1).trim();
        if (prop.startsWith("--")) {
          continue;
        }
        if (isRootSvg && (prop === "max-width" || prop === "height")) {
          continue;
        }
        if (prop === "rx" || prop === "ry") {
          if (isSafeSvgPresentationValue(prop, val)) {
            const normalized = normalizeSvgLengthAttrValue(val);
            if (normalized !== null) {
              el.setAttribute(prop, normalized);
            }
          }
          continue;
        }
        if (SAFE_SVG_PRESENTATION_PROPS.has(prop) && isSafeSvgPresentationValue(prop, val)) {
          el.setAttribute(prop, val);
        }
      }
      el.removeAttribute("data-pele-style");
      el.removeAttribute("style");
    }
    for (const lenAttr of ["rx", "ry"] as const) {
      const existing = el.getAttribute(lenAttr);
      if (existing !== null && (existing.includes("var(") || existing.endsWith("px"))) {
        const normalized = normalizeSvgLengthAttrValue(existing);
        if (normalized !== null) {
          el.setAttribute(lenAttr, normalized);
        } else {
          el.removeAttribute(lenAttr);
        }
      }
    }
    for (let i = 0; i < el.children.length; i += 1) {
      const child = el.children[i];
      if (child) {
        stack.push(child);
      }
    }
  }
}

function scrubForbiddenSvgNodesAndAttrs(root: Element): void {
  const cleanElement = (el: Element): void => {
    for (const attr of Array.from(el.attributes)) {
      const nameLower = attr.name.toLowerCase();
      if (
        FORBIDDEN_SVG_ATTRS_LOWER.has(nameLower) ||
        nameLower.startsWith("on") ||
        nameLower.startsWith("data-") ||
        nameLower.endsWith(":href")
      ) {
        el.removeAttribute(attr.name);
        continue;
      }
      if (UNSAFE_CSS_VALUE_RE.test(attr.value)) {
        el.removeAttribute(attr.name);
      }
    }

    for (const child of Array.from(el.childNodes)) {
      if (child.nodeType === 8 || child.nodeType === 7) {
        child.parentNode?.removeChild(child);
        continue;
      }
      if (child.nodeType === 1) {
        const childEl = child as Element;
        const tagLower = childEl.localName.toLowerCase();
        if (FORBIDDEN_SVG_TAGS_LOWER.has(tagLower)) {
          childEl.parentNode?.removeChild(childEl);
          continue;
        }
        cleanElement(childEl);
      }
    }
  };

  cleanElement(root);
}

function parseSvgDocument(svgMarkup: string): SVGSVGElement {
  const parser = new DOMParser();
  const doc = parser.parseFromString(svgMarkup, "image/svg+xml");
  const root = doc.documentElement;
  if (!root || root.localName.toLowerCase() !== "svg") {
    throw new Error("Invalid SVG markup");
  }
  return root as unknown as SVGSVGElement;
}

function sanitizeRenderedSvg(rawSvg: string): string {
  const preNeutralized = neutralizeInlineStyleAttrsBeforeXmlParse(rawSvg);
  const parsed = parseSvgDocument(preNeutralized);
  promoteSafeInlineStyles(parsed);
  scrubForbiddenSvgNodesAndAttrs(parsed);

  const serializer = new XMLSerializer();
  const promotedSvg = serializer.serializeToString(parsed);

  const purify = getSvgPurify();
  const sanitized = purify.sanitize(promotedSvg, {
    USE_PROFILES: { svg: true, svgFilters: true },
    FORBID_TAGS: FORBIDDEN_SVG_TAGS,
    FORBID_ATTR: FORBIDDEN_SVG_ATTRS,
    ADD_ATTR: ["role"],
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: true,
  });

  const verifiedRoot = parseSvgDocument(sanitized);
  scrubForbiddenSvgNodesAndAttrs(verifiedRoot);
  if (!verifiedRoot.getAttribute("xmlns")) {
    verifiedRoot.setAttribute("xmlns", SVG_NS);
  }
  return serializer.serializeToString(verifiedRoot);
}

export const peleDiagramRenderer: DiagramRenderer = {
  id: "pele",
  async render(source: string): Promise<DiagramRenderResult> {
    const pele = await loadPele();
    const result = pele.render(source, {
      links: false,
      images: false,
    });
    const svg = sanitizeRenderedSvg(result.svg);
    return {
      svg,
      width: result.width,
      height: result.height,
      type: result.type,
    };
  },
};

function parseViewBox(svgEl: SVGSVGElement): { x: number; y: number; w: number; h: number } {
  const raw = svgEl.getAttribute("viewBox");
  if (raw) {
    const parts = raw
      .trim()
      .split(/[\s,]+/)
      .map((n) => Number.parseFloat(n));
    if (parts.length === 4 && parts.every((n) => Number.isFinite(n)) && parts[2] > 0 && parts[3] > 0) {
      return { x: parts[0], y: parts[1], w: parts[2], h: parts[3] };
    }
  }
  const widthAttr = Number.parseFloat(svgEl.getAttribute("width") ?? "");
  const heightAttr = Number.parseFloat(svgEl.getAttribute("height") ?? "");
  const w = Number.isFinite(widthAttr) && widthAttr > 0 ? widthAttr : 300;
  const h = Number.isFinite(heightAttr) && heightAttr > 0 ? heightAttr : 150;
  return { x: 0, y: 0, w, h };
}

function readComputedTokenMap(target: Element): Map<string, string> {
  const tokens = new Map<string, string>();
  let computed: CSSStyleDeclaration | null = null;
  try {
    computed = typeof getComputedStyle === "function" ? getComputedStyle(target) : null;
  } catch {
    computed = null;
  }

  for (const [token, defaultValue] of Object.entries(PELE_DEFAULT_TOKENS)) {
    const candidates = PELE_TO_THEME_FALLBACKS[token] ?? [token];
    let resolved = "";
    if (computed) {
      for (const candidate of candidates) {
        const val = computed.getPropertyValue(candidate).trim();
        if (val) {
          resolved = val;
          break;
        }
      }
    }
    tokens.set(token, resolved || defaultValue);
  }

  if (computed) {
    const fontFamily =
      computed.getPropertyValue("--pele-font").trim() ||
      computed.getPropertyValue("--sans").trim() ||
      computed.fontFamily?.trim();
    if (fontFamily) {
      tokens.set("--pele-font", fontFamily);
    }
  }

  return tokens;
}

function resolveCssVarExpression(
  value: string,
  tokens: Map<string, string>,
  computed: CSSStyleDeclaration | null,
): string {
  let current = value;
  const varPattern = /var\(\s*(--[a-zA-Z0-9_-]+)\s*(?:,\s*([^()]+))?\)/g;

  for (let depth = 0; depth < 4 && current.includes("var("); depth += 1) {
    current = current.replace(varPattern, (_match, rawName: string, rawFallback?: string) => {
      const name = rawName.trim();
      const fromMap = tokens.get(name);
      if (fromMap) {
        return fromMap;
      }
      const fromComputed = computed?.getPropertyValue(name).trim();
      if (fromComputed) {
        return fromComputed;
      }
      if (rawFallback !== undefined && rawFallback.trim()) {
        return rawFallback.trim();
      }
      return PELE_DEFAULT_TOKENS[name] ?? "";
    });
  }

  return current.trim();
}

export function resolveSvgForStandaloneExport(
  svgEl: SVGSVGElement,
  themeContainer?: Element,
): string {
  const target = themeContainer ?? svgEl;
  const tokens = readComputedTokenMap(target);
  let computed: CSSStyleDeclaration | null = null;
  try {
    computed = typeof getComputedStyle === "function" ? getComputedStyle(target) : null;
  } catch {
    computed = null;
  }

  const clone = svgEl.cloneNode(true) as SVGSVGElement;
  scrubForbiddenSvgNodesAndAttrs(clone);

  const stack: Element[] = [clone];
  while (stack.length > 0) {
    const el = stack.pop();
    if (!el) {
      continue;
    }
    for (const attr of Array.from(el.attributes)) {
      if (attr.value.includes("var(")) {
        let resolved = resolveCssVarExpression(attr.value, tokens, computed);
        if ((attr.name === "rx" || attr.name === "ry") && resolved.endsWith("px")) {
          resolved = resolved.slice(0, -2);
        }
        if (resolved) {
          el.setAttribute(attr.name, resolved);
        } else {
          el.removeAttribute(attr.name);
        }
      } else if ((attr.name === "rx" || attr.name === "ry") && attr.value.endsWith("px")) {
        el.setAttribute(attr.name, attr.value.slice(0, -2));
      }
    }
    for (let i = 0; i < el.children.length; i += 1) {
      const child = el.children[i];
      if (child) {
        stack.push(child);
      }
    }
  }

  const vb = parseViewBox(clone);
  clone.setAttribute("xmlns", SVG_NS);
  clone.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
  clone.setAttribute("width", String(Math.ceil(vb.w)));
  clone.setAttribute("height", String(Math.ceil(vb.h)));

  const resolvedFg = tokens.get("--_fg") ?? PELE_DEFAULT_TOKENS["--_fg"];
  const resolvedBg = tokens.get("--_bg") ?? PELE_DEFAULT_TOKENS["--_bg"];
  const resolvedFont = tokens.get("--pele-font") ?? PELE_DEFAULT_TOKENS["--pele-font"];
  clone.setAttribute("fill", resolvedFg);
  clone.setAttribute("font-family", resolvedFont);
  if (!clone.getAttribute("font-size")) {
    clone.setAttribute("font-size", "16");
  }

  const doc = clone.ownerDocument ?? document;
  const bgRect = doc.createElementNS(SVG_NS, "rect");
  bgRect.setAttribute("x", String(vb.x));
  bgRect.setAttribute("y", String(vb.y));
  bgRect.setAttribute("width", String(vb.w));
  bgRect.setAttribute("height", String(vb.h));
  bgRect.setAttribute("fill", resolvedBg);
  bgRect.setAttribute("stroke", "none");
  clone.insertBefore(bgRect, clone.firstChild);

  const serialized = new XMLSerializer().serializeToString(clone);
  return serialized;
}

export async function svgToPngBlob(
  svgEl: SVGSVGElement,
  scale = 2,
  themeContainer?: Element,
): Promise<Blob> {
  const safeScale = Number.isFinite(scale) && scale > 0 ? scale : 2;
  const vb = parseViewBox(svgEl);
  const standaloneSvg = resolveSvgForStandaloneExport(svgEl, themeContainer);
  const dataUrl = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(standaloneSvg)}`;

  const img = await new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("Failed to rasterize SVG diagram"));
    image.src = dataUrl;
  });

  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.ceil(vb.w * safeScale));
  canvas.height = Math.max(1, Math.ceil(vb.h * safeScale));

  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error("Canvas 2D context unavailable");
  }
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob && blob.size > 0) {
        resolve(blob);
      } else {
        reject(new Error("Failed to encode PNG blob"));
      }
    }, "image/png");
  });
}

export async function copyDiagramPng(
  svgEl: SVGSVGElement,
  themeContainer?: Element,
): Promise<Blob> {
  const blob = await svgToPngBlob(svgEl, 2, themeContainer);
  if (
    typeof navigator === "undefined" ||
    !navigator.clipboard ||
    typeof navigator.clipboard.write !== "function" ||
    typeof ClipboardItem === "undefined"
  ) {
    throw new Error("Clipboard image write is unavailable");
  }
  await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
  return blob;
}

function roundCoord(value: number): string {
  return String(Math.round(value * 100) / 100);
}

export function attachSvgViewBoxPanZoom(
  viewportEl: HTMLElement,
  svgEl: SVGSVGElement,
): PanZoomController {
  const initial = parseViewBox(svgEl);
  let state = { ...initial };
  const minZoom = 0.25;
  const maxZoom = 8;

  const activePointers = new Map<number, { clientX: number; clientY: number }>();
  let lastPinchDist: number | null = null;
  let lastPinchMid: { x: number; y: number } | null = null;

  const applyViewBox = (): void => {
    svgEl.setAttribute(
      "viewBox",
      `${roundCoord(state.x)} ${roundCoord(state.y)} ${roundCoord(state.w)} ${roundCoord(state.h)}`,
    );
  };

  const clampZoomWidth = (candidateW: number): number => {
    const minW = initial.w / maxZoom;
    const maxW = initial.w / minZoom;
    return Math.min(maxW, Math.max(minW, candidateW));
  };

  const zoomAt = (factor: number, normX = 0.5, normY = 0.5): void => {
    if (!Number.isFinite(factor) || factor <= 0) {
      return;
    }
    const nextW = clampZoomWidth(state.w / factor);
    const nextH = nextW * (initial.h / initial.w);
    state = {
      x: state.x + (state.w - nextW) * normX,
      y: state.y + (state.h - nextH) * normY,
      w: nextW,
      h: nextH,
    };
    applyViewBox();
  };

  const getRectSize = (): { left: number; top: number; width: number; height: number } => {
    const rect = svgEl.getBoundingClientRect();
    return {
      left: rect.left,
      top: rect.top,
      width: rect.width > 0 ? rect.width : initial.w,
      height: rect.height > 0 ? rect.height : initial.h,
    };
  };

  const onWheel = (event: WheelEvent): void => {
    if (!event.ctrlKey && !event.metaKey && !event.shiftKey) {
      return;
    }
    event.preventDefault();
    const rect = getRectSize();
    const normX = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
    const normY = Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height));
    const factor = event.deltaY < 0 ? 1.15 : 1 / 1.15;
    zoomAt(factor, normX, normY);
  };

  const onPointerDown = (event: PointerEvent): void => {
    if (event.pointerType === "mouse" && event.button !== 0) {
      return;
    }
    activePointers.set(event.pointerId, { clientX: event.clientX, clientY: event.clientY });
    try {
      viewportEl.setPointerCapture?.(event.pointerId);
    } catch {
      // Synthetic pointer events in tests may not be capturable.
    }
    if (activePointers.size === 2) {
      const [p1, p2] = Array.from(activePointers.values());
      lastPinchDist = Math.hypot(p2.clientX - p1.clientX, p2.clientY - p1.clientY);
      lastPinchMid = {
        x: (p1.clientX + p2.clientX) / 2,
        y: (p1.clientY + p2.clientY) / 2,
      };
    } else {
      lastPinchDist = null;
      lastPinchMid = null;
    }
  };

  const onPointerMove = (event: PointerEvent): void => {
    const prev = activePointers.get(event.pointerId);
    if (!prev) {
      return;
    }
    const rect = getRectSize();

    if (activePointers.size === 1) {
      const dx = event.clientX - prev.clientX;
      const dy = event.clientY - prev.clientY;
      activePointers.set(event.pointerId, { clientX: event.clientX, clientY: event.clientY });
      state = {
        ...state,
        x: state.x - dx * (state.w / rect.width),
        y: state.y - dy * (state.h / rect.height),
      };
      applyViewBox();
      return;
    }

    activePointers.set(event.pointerId, { clientX: event.clientX, clientY: event.clientY });
    if (activePointers.size === 2) {
      const [p1, p2] = Array.from(activePointers.values());
      const nextDist = Math.hypot(p2.clientX - p1.clientX, p2.clientY - p1.clientY);
      const nextMid = {
        x: (p1.clientX + p2.clientX) / 2,
        y: (p1.clientY + p2.clientY) / 2,
      };

      if (lastPinchMid) {
        const mdx = nextMid.x - lastPinchMid.x;
        const mdy = nextMid.y - lastPinchMid.y;
        state = {
          ...state,
          x: state.x - mdx * (state.w / rect.width),
          y: state.y - mdy * (state.h / rect.height),
        };
        applyViewBox();
      }

      if (lastPinchDist && lastPinchDist > 0 && nextDist > 0) {
        const normX = Math.min(1, Math.max(0, (nextMid.x - rect.left) / rect.width));
        const normY = Math.min(1, Math.max(0, (nextMid.y - rect.top) / rect.height));
        zoomAt(nextDist / lastPinchDist, normX, normY);
      }

      lastPinchDist = nextDist;
      lastPinchMid = nextMid;
    }
  };

  const onPointerUpOrCancel = (event: PointerEvent): void => {
    activePointers.delete(event.pointerId);
    if (activePointers.size < 2) {
      lastPinchDist = null;
      lastPinchMid = null;
    }
  };

  viewportEl.addEventListener("wheel", onWheel, { passive: false });
  viewportEl.addEventListener("pointerdown", onPointerDown);
  viewportEl.addEventListener("pointermove", onPointerMove);
  viewportEl.addEventListener("pointerup", onPointerUpOrCancel);
  viewportEl.addEventListener("pointercancel", onPointerUpOrCancel);

  return {
    zoomIn() {
      zoomAt(1.25);
    },
    zoomOut() {
      zoomAt(0.8);
    },
    reset() {
      state = { ...initial };
      applyViewBox();
    },
    destroy() {
      viewportEl.removeEventListener("wheel", onWheel);
      viewportEl.removeEventListener("pointerdown", onPointerDown);
      viewportEl.removeEventListener("pointermove", onPointerMove);
      viewportEl.removeEventListener("pointerup", onPointerUpOrCancel);
      viewportEl.removeEventListener("pointercancel", onPointerUpOrCancel);
      activePointers.clear();
    },
  };
}

function reportWidgetCopyFeedback(
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
  if (announced === lastDiagramStatusMessage) {
    announced += "\u00A0";
  }
  lastDiagramStatusMessage = announced;

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

function formatDiagramError(err: unknown): string {
  if (err instanceof Error && err.message.trim()) {
    return `Diagram syntax error: ${err.message.trim()}`;
  }
  return "Diagram syntax error: unable to render Mermaid diagram";
}

function createCopyControl(label: string, extraClass: string): {
  wrapper: HTMLSpanElement;
  button: HTMLButtonElement;
  tip: HTMLSpanElement;
} {
  const wrapper = document.createElement("span");
  wrapper.className = "copy";

  const button = document.createElement("button");
  button.type = "button";
  button.className = `btn btn-icon copy-button ${extraClass}`;
  button.textContent = label;

  const tip = document.createElement("span");
  tip.className = "copy-tip";
  tip.setAttribute("role", "status");

  wrapper.append(button, tip);
  return { wrapper, button, tip };
}

export function mountDiagramWidget(
  host: HTMLElement,
  initialSource: string,
  opts?: DiagramWidgetOptions,
): DiagramWidgetHandle {
  const renderer = opts?.renderer ?? peleDiagramRenderer;
  const onFeedback = opts?.onFeedback;

  const widget = document.createElement("div");
  widget.className = "diagram-widget";

  const toolbar = document.createElement("div");
  toolbar.className = "diagram-toolbar";
  toolbar.setAttribute("role", "toolbar");
  toolbar.setAttribute("aria-label", "Diagram controls");

  const zoomInBtn = document.createElement("button");
  zoomInBtn.type = "button";
  zoomInBtn.className = "btn btn-icon diagram-btn";
  zoomInBtn.setAttribute("aria-label", "Zoom in");
  zoomInBtn.textContent = "+";

  const zoomOutBtn = document.createElement("button");
  zoomOutBtn.type = "button";
  zoomOutBtn.className = "btn btn-icon diagram-btn";
  zoomOutBtn.setAttribute("aria-label", "Zoom out");
  zoomOutBtn.textContent = "-";

  const resetBtn = document.createElement("button");
  resetBtn.type = "button";
  resetBtn.className = "btn btn-icon diagram-btn";
  resetBtn.textContent = "Reset";

  const copyPngCtrl = createCopyControl("Copy PNG", "diagram-copy-png");
  const copySvgCtrl = createCopyControl("Copy SVG", "diagram-copy-svg");
  const copySrcCtrl = createCopyControl("Copy Source", "diagram-copy-source");

  toolbar.append(
    zoomInBtn,
    zoomOutBtn,
    resetBtn,
    copyPngCtrl.wrapper,
    copySvgCtrl.wrapper,
    copySrcCtrl.wrapper,
  );

  const hintEl = document.createElement("div");
  hintEl.className = "diagram-syntax-hint hidden";
  hintEl.setAttribute("role", "alert");
  hintEl.hidden = true;

  const viewportEl = document.createElement("div");
  viewportEl.className = "diagram-viewport";

  widget.append(toolbar, hintEl, viewportEl);
  host.replaceChildren(widget);

  let currentSource = initialSource;
  let currentSvgEl: SVGSVGElement | null = null;
  let panZoom: PanZoomController | null = null;
  let renderSeq = 0;
  let destroyed = false;

  const onZoomIn = (): void => panZoom?.zoomIn();
  const onZoomOut = (): void => panZoom?.zoomOut();
  const onReset = (): void => panZoom?.reset();

  const onCopyPng = async (): Promise<void> => {
    if (!currentSvgEl) {
      reportWidgetCopyFeedback(
        copyPngCtrl.button,
        copyPngCtrl.tip,
        false,
        "PNG copied",
        "Copy failed",
        onFeedback,
      );
      return;
    }
    try {
      await copyDiagramPng(currentSvgEl, widget);
      reportWidgetCopyFeedback(
        copyPngCtrl.button,
        copyPngCtrl.tip,
        true,
        "PNG copied",
        "Copy failed",
        onFeedback,
      );
    } catch {
      reportWidgetCopyFeedback(
        copyPngCtrl.button,
        copyPngCtrl.tip,
        false,
        "PNG copied",
        "Copy failed",
        onFeedback,
      );
    }
  };

  const onCopySvg = async (): Promise<void> => {
    if (!currentSvgEl) {
      reportWidgetCopyFeedback(
        copySvgCtrl.button,
        copySvgCtrl.tip,
        false,
        "SVG copied",
        "Copy failed",
        onFeedback,
      );
      return;
    }
    try {
      const standalone = resolveSvgForStandaloneExport(currentSvgEl, widget);
      if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
        throw new Error("Clipboard unavailable");
      }
      await navigator.clipboard.writeText(standalone);
      reportWidgetCopyFeedback(
        copySvgCtrl.button,
        copySvgCtrl.tip,
        true,
        "SVG copied",
        "Copy failed",
        onFeedback,
      );
    } catch {
      reportWidgetCopyFeedback(
        copySvgCtrl.button,
        copySvgCtrl.tip,
        false,
        "SVG copied",
        "Copy failed",
        onFeedback,
      );
    }
  };

  const onCopySource = async (): Promise<void> => {
    try {
      if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
        throw new Error("Clipboard unavailable");
      }
      await navigator.clipboard.writeText(currentSource);
      reportWidgetCopyFeedback(
        copySrcCtrl.button,
        copySrcCtrl.tip,
        true,
        "Copied",
        "Copy failed",
        onFeedback,
      );
    } catch {
      reportWidgetCopyFeedback(
        copySrcCtrl.button,
        copySrcCtrl.tip,
        false,
        "Copied",
        "Copy failed",
        onFeedback,
      );
    }
  };

  zoomInBtn.addEventListener("click", onZoomIn);
  zoomOutBtn.addEventListener("click", onZoomOut);
  resetBtn.addEventListener("click", onReset);
  copyPngCtrl.button.addEventListener("click", onCopyPng);
  copySvgCtrl.button.addEventListener("click", onCopySvg);
  copySrcCtrl.button.addEventListener("click", onCopySource);

  const update = async (nextSource: string): Promise<boolean> => {
    currentSource = nextSource;
    const seq = ++renderSeq;
    try {
      const rendered = await renderer.render(nextSource);
      if (destroyed || seq !== renderSeq) {
        return false;
      }
      const parsedSvg = parseSvgDocument(rendered.svg);
      const adoptedSvg = document.importNode(parsedSvg, true) as SVGSVGElement;
      panZoom?.destroy();
      viewportEl.replaceChildren(adoptedSvg);
      currentSvgEl = adoptedSvg;
      panZoom = attachSvgViewBoxPanZoom(viewportEl, adoptedSvg);
      hintEl.textContent = "";
      hintEl.classList.add("hidden");
      hintEl.hidden = true;
      return true;
    } catch (err) {
      if (destroyed || seq !== renderSeq) {
        return false;
      }
      hintEl.textContent = formatDiagramError(err);
      hintEl.classList.remove("hidden");
      hintEl.hidden = false;
      return false;
    }
  };

  const ready = update(initialSource);

  return {
    ready,
    update,
    destroy() {
      destroyed = true;
      panZoom?.destroy();
      panZoom = null;
      currentSvgEl = null;
      zoomInBtn.removeEventListener("click", onZoomIn);
      zoomOutBtn.removeEventListener("click", onZoomOut);
      resetBtn.removeEventListener("click", onReset);
      copyPngCtrl.button.removeEventListener("click", onCopyPng);
      copySvgCtrl.button.removeEventListener("click", onCopySvg);
      copySrcCtrl.button.removeEventListener("click", onCopySource);
      for (const btn of [copyPngCtrl.button, copySvgCtrl.button, copySrcCtrl.button]) {
        const timer = copyTimers.get(btn);
        if (timer !== undefined) {
          clearTimeout(timer);
          copyTimers.delete(btn);
        }
      }
    },
  };
}
