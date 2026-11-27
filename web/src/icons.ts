const SVG_NS = "http://www.w3.org/2000/svg";

export type IconSize = "kbd" | "xs" | "sm" | "md";

export type IconName =
  | "brand-mark"
  | "plus"
  | "search"
  | "layers"
  | "trash"
  | "history"
  | "copy"
  | "check"
  | "code-format"
  | "lock"
  | "lock-open"
  | "shield-off"
  | "shield-alert"
  | "eraser"
  | "sun"
  | "moon"
  | "monitor"
  | "chevron-down"
  | "chevron-right"
  | "key"
  | "refresh-cw"
  | "check-circle"
  | "cloud-off"
  | "file-rich"
  | "zoom-in"
  | "zoom-out"
  | "rotate-ccw"
  | "camera"
  | "qr-code"
  | "x"
  | "arrow-up"
  | "arrow-down"
  | "corner-down-left"
  | "eye"
  | "eye-off"
  | "git-branch"
  | "alert-triangle"
  | "image-off"
  | "more-horizontal"
  | "pencil"
  | "clipboard"
  | "image"
  | "send"
  | "download"
  | "file-plus"
  | "pause"
  | "play";

type SvgPrimitive =
  | { readonly tag: "path"; readonly attrs: Readonly<Record<string, string>> }
  | { readonly tag: "line"; readonly attrs: Readonly<Record<string, string>> }
  | { readonly tag: "rect"; readonly attrs: Readonly<Record<string, string>> }
  | { readonly tag: "circle"; readonly attrs: Readonly<Record<string, string>> }
  | { readonly tag: "polyline"; readonly attrs: Readonly<Record<string, string>> };

const ICON_DEFS: Readonly<Record<IconName, readonly SvgPrimitive[]>> = {
  "brand-mark": [
    { tag: "rect", attrs: { x: "3.5", y: "3.5", width: "17", height: "17", rx: "3" } },
    { tag: "line", attrs: { x1: "7.5", y1: "9", x2: "16.5", y2: "9" } },
    { tag: "line", attrs: { x1: "7.5", y1: "12.5", x2: "14.5", y2: "12.5" } },
    { tag: "line", attrs: { x1: "7.5", y1: "16", x2: "12", y2: "16" } },
  ],
  plus: [
    { tag: "line", attrs: { x1: "12", y1: "5", x2: "12", y2: "19" } },
    { tag: "line", attrs: { x1: "5", y1: "12", x2: "19", y2: "12" } },
  ],
  search: [
    { tag: "circle", attrs: { cx: "11", cy: "11", r: "7" } },
    { tag: "line", attrs: { x1: "20", y1: "20", x2: "16.2", y2: "16.2" } },
  ],
  layers: [
    { tag: "path", attrs: { d: "M12 3 2.5 8 12 13 21.5 8 12 3z" } },
    { tag: "path", attrs: { d: "M2.5 12.5 12 17.5 21.5 12.5" } },
    { tag: "path", attrs: { d: "M2.5 16.5 12 21.5 21.5 16.5" } },
  ],
  trash: [
    { tag: "path", attrs: { d: "M3 6h18" } },
    { tag: "path", attrs: { d: "M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" } },
    { tag: "path", attrs: { d: "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" } },
    { tag: "line", attrs: { x1: "10", y1: "11", x2: "10", y2: "17" } },
    { tag: "line", attrs: { x1: "14", y1: "11", x2: "14", y2: "17" } },
  ],
  history: [
    { tag: "path", attrs: { d: "M3 12a9 9 0 1 0 3-6.7L3 8" } },
    { tag: "path", attrs: { d: "M3 3v5h5" } },
    { tag: "path", attrs: { d: "M12 7v5l3 2" } },
  ],
  copy: [
    { tag: "rect", attrs: { x: "9", y: "9", width: "11", height: "11", rx: "2" } },
    { tag: "path", attrs: { d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" } },
  ],
  check: [{ tag: "polyline", attrs: { points: "20 6 9 17 4 12" } }],
  "code-format": [
    { tag: "polyline", attrs: { points: "8 7 3 12 8 17" } },
    { tag: "polyline", attrs: { points: "16 7 21 12 16 17" } },
    { tag: "line", attrs: { x1: "13.5", y1: "5", x2: "10.5", y2: "19" } },
  ],
  lock: [
    { tag: "rect", attrs: { x: "5", y: "11", width: "14", height: "10", rx: "2" } },
    { tag: "path", attrs: { d: "M8 11V7a4 4 0 0 1 8 0v4" } },
  ],
  "lock-open": [
    { tag: "rect", attrs: { x: "5", y: "11", width: "14", height: "10", rx: "2" } },
    { tag: "path", attrs: { d: "M8 11V7a4 4 0 0 1 7.6-1.7" } },
  ],
  "shield-off": [
    { tag: "path", attrs: { d: "M19.7 14a6.9 6.9 0 0 0 .3-2V5l-8-3-3.2 1.2" } },
    { tag: "path", attrs: { d: "M4.7 4.7 4 5v7c0 6 8 10 8 10a20.3 20.3 0 0 0 5.6-4.4" } },
    { tag: "line", attrs: { x1: "2", y1: "2", x2: "22", y2: "22" } },
  ],
  "shield-alert": [
    { tag: "path", attrs: { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" } },
    { tag: "line", attrs: { x1: "12", y1: "8", x2: "12", y2: "12" } },
    { tag: "line", attrs: { x1: "12", y1: "16", x2: "12.01", y2: "16" } },
  ],
  eraser: [
    { tag: "path", attrs: { d: "M7 21h13" } },
    { tag: "path", attrs: { d: "m19.5 11.5-7-7a2.1 2.1 0 0 0-3 0l-6 6a2.1 2.1 0 0 0 0 3l4.5 4.5H13l6.5-6.5z" } },
    { tag: "line", attrs: { x1: "8.5", y1: "9.5", x2: "14.5", y2: "15.5" } },
  ],
  sun: [
    { tag: "circle", attrs: { cx: "12", cy: "12", r: "4" } },
    { tag: "line", attrs: { x1: "12", y1: "2.5", x2: "12", y2: "4.5" } },
    { tag: "line", attrs: { x1: "12", y1: "19.5", x2: "12", y2: "21.5" } },
    { tag: "line", attrs: { x1: "5.28", y1: "5.28", x2: "6.7", y2: "6.7" } },
    { tag: "line", attrs: { x1: "17.3", y1: "17.3", x2: "18.72", y2: "18.72" } },
    { tag: "line", attrs: { x1: "2.5", y1: "12", x2: "4.5", y2: "12" } },
    { tag: "line", attrs: { x1: "19.5", y1: "12", x2: "21.5", y2: "12" } },
    { tag: "line", attrs: { x1: "5.28", y1: "18.72", x2: "6.7", y2: "17.3" } },
    { tag: "line", attrs: { x1: "17.3", y1: "6.7", x2: "18.72", y2: "5.28" } },
  ],
  moon: [{ tag: "path", attrs: { d: "M21 12.8A8.5 8.5 0 1 1 11.2 3a6.7 6.7 0 0 0 9.8 9.8z" } }],
  monitor: [
    { tag: "rect", attrs: { x: "3", y: "4", width: "18", height: "12", rx: "2" } },
    { tag: "line", attrs: { x1: "8", y1: "20", x2: "16", y2: "20" } },
    { tag: "line", attrs: { x1: "12", y1: "16", x2: "12", y2: "20" } },
  ],
  "chevron-down": [{ tag: "polyline", attrs: { points: "6 9 12 15 18 9" } }],
  "chevron-right": [{ tag: "polyline", attrs: { points: "9 6 15 12 9 18" } }],
  key: [
    { tag: "circle", attrs: { cx: "7.5", cy: "15.5", r: "4.5" } },
    { tag: "path", attrs: { d: "m11 12 9-9" } },
    { tag: "path", attrs: { d: "m16.5 6.5 2.5 2.5" } },
    { tag: "path", attrs: { d: "m19 4 2 2" } },
  ],
  "refresh-cw": [
    { tag: "path", attrs: { d: "M21 12a9 9 0 0 0-15.4-6.4L3 8" } },
    { tag: "path", attrs: { d: "M3 3v5h5" } },
    { tag: "path", attrs: { d: "M3 12a9 9 0 0 0 15.4 6.4L21 16" } },
    { tag: "path", attrs: { d: "M16 16h5v5" } },
  ],
  "check-circle": [
    { tag: "circle", attrs: { cx: "12", cy: "12", r: "9" } },
    { tag: "polyline", attrs: { points: "8.5 12.2 10.8 14.5 15.8 9.5" } },
  ],
  "cloud-off": [
    { tag: "path", attrs: { d: "M22 15a4 4 0 0 0-3-3.9 5.5 5.5 0 0 0-9-3.9" } },
    { tag: "path", attrs: { d: "M5 10.2A4.5 4.5 0 0 0 6.5 19H18" } },
    { tag: "line", attrs: { x1: "2", y1: "2", x2: "22", y2: "22" } },
  ],
  "file-rich": [
    { tag: "path", attrs: { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" } },
    { tag: "polyline", attrs: { points: "14 2 14 8 20 8" } },
    { tag: "line", attrs: { x1: "8", y1: "13", x2: "16", y2: "13" } },
    { tag: "line", attrs: { x1: "8", y1: "17", x2: "13", y2: "17" } },
  ],
  "zoom-in": [
    { tag: "circle", attrs: { cx: "11", cy: "11", r: "7" } },
    { tag: "line", attrs: { x1: "20", y1: "20", x2: "16.2", y2: "16.2" } },
    { tag: "line", attrs: { x1: "11", y1: "8", x2: "11", y2: "14" } },
    { tag: "line", attrs: { x1: "8", y1: "11", x2: "14", y2: "11" } },
  ],
  "zoom-out": [
    { tag: "circle", attrs: { cx: "11", cy: "11", r: "7" } },
    { tag: "line", attrs: { x1: "20", y1: "20", x2: "16.2", y2: "16.2" } },
    { tag: "line", attrs: { x1: "8", y1: "11", x2: "14", y2: "11" } },
  ],
  "rotate-ccw": [
    { tag: "path", attrs: { d: "M3 12a9 9 0 1 0 3-6.7L3 8" } },
    { tag: "path", attrs: { d: "M3 3v5h5" } },
  ],
  camera: [
    { tag: "path", attrs: { d: "M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" } },
    { tag: "circle", attrs: { cx: "12", cy: "13", r: "4" } },
  ],
  "qr-code": [
    { tag: "path", attrs: { d: "M3 7V5a2 2 0 0 1 2-2h2" } },
    { tag: "path", attrs: { d: "M17 3h2a2 2 0 0 1 2 2v2" } },
    { tag: "path", attrs: { d: "M21 17v2a2 2 0 0 1-2 2h-2" } },
    { tag: "path", attrs: { d: "M7 21H5a2 2 0 0 1-2-2v-2" } },
    { tag: "rect", attrs: { x: "7", y: "7", width: "4", height: "4", rx: "0.75" } },
    { tag: "rect", attrs: { x: "13", y: "7", width: "4", height: "4", rx: "0.75" } },
    { tag: "rect", attrs: { x: "7", y: "13", width: "4", height: "4", rx: "0.75" } },
    { tag: "path", attrs: { d: "M13 13h2v2h-2z" } },
    { tag: "line", attrs: { x1: "17", y1: "13", x2: "17", y2: "17" } },
    { tag: "line", attrs: { x1: "13", y1: "17", x2: "15", y2: "17" } },
  ],
  x: [
    { tag: "line", attrs: { x1: "18", y1: "6", x2: "6", y2: "18" } },
    { tag: "line", attrs: { x1: "6", y1: "6", x2: "18", y2: "18" } },
  ],
  "arrow-up": [
    { tag: "line", attrs: { x1: "12", y1: "19", x2: "12", y2: "5" } },
    { tag: "polyline", attrs: { points: "6 11 12 5 18 11" } },
  ],
  "arrow-down": [
    { tag: "line", attrs: { x1: "12", y1: "5", x2: "12", y2: "19" } },
    { tag: "polyline", attrs: { points: "6 13 12 19 18 13" } },
  ],
  "corner-down-left": [
    { tag: "polyline", attrs: { points: "9 10 4 15 9 20" } },
    { tag: "path", attrs: { d: "M20 4v7a4 4 0 0 1-4 4H4" } },
  ],
  eye: [
    { tag: "path", attrs: { d: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" } },
    { tag: "circle", attrs: { cx: "12", cy: "12", r: "3" } },
  ],
  "eye-off": [
    { tag: "path", attrs: { d: "M9.9 4.2A10.4 10.4 0 0 1 12 4c6.5 0 10 8 10 8a17.7 17.7 0 0 1-3.2 4.3" } },
    { tag: "path", attrs: { d: "M6.6 6.6A17.7 17.7 0 0 0 2 12s3.5 8 10 8a10.2 10.2 0 0 0 5.4-1.6" } },
    { tag: "path", attrs: { d: "M14.1 14.1a3 3 0 0 1-4.2-4.2" } },
    { tag: "line", attrs: { x1: "2", y1: "2", x2: "22", y2: "22" } },
  ],
  "git-branch": [
    { tag: "line", attrs: { x1: "6", y1: "3", x2: "6", y2: "15" } },
    { tag: "circle", attrs: { cx: "18", cy: "6", r: "3" } },
    { tag: "circle", attrs: { cx: "6", cy: "18", r: "3" } },
    { tag: "path", attrs: { d: "M18 9a9 9 0 0 1-9 9" } },
  ],
  "alert-triangle": [
    { tag: "path", attrs: { d: "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" } },
    { tag: "line", attrs: { x1: "12", y1: "9", x2: "12", y2: "13" } },
    { tag: "line", attrs: { x1: "12", y1: "17", x2: "12.01", y2: "17" } },
  ],
  "image-off": [
    { tag: "line", attrs: { x1: "2", y1: "2", x2: "22", y2: "22" } },
    { tag: "path", attrs: { d: "M10.4 4H19a2 2 0 0 1 2 2v8.6" } },
    { tag: "path", attrs: { d: "M19 19a2 2 0 0 1-1.4.6H5a2 2 0 0 1-2-2V6a2 2 0 0 1 .6-1.4" } },
    { tag: "path", attrs: { d: "m3 16 4-4 3 3" } },
    { tag: "path", attrs: { d: "m14 14 2-2 4.5 4.5" } },
  ],
  "more-horizontal": [
    { tag: "circle", attrs: { cx: "5", cy: "12", r: "1.25" } },
    { tag: "circle", attrs: { cx: "12", cy: "12", r: "1.25" } },
    { tag: "circle", attrs: { cx: "19", cy: "12", r: "1.25" } },
  ],
  pencil: [
    { tag: "path", attrs: { d: "M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z" } },
    { tag: "path", attrs: { d: "m15 5 4 4" } },
  ],
  clipboard: [
    { tag: "rect", attrs: { x: "8", y: "2", width: "8", height: "4", rx: "1" } },
    { tag: "path", attrs: { d: "M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" } },
  ],
  image: [
    { tag: "rect", attrs: { x: "3", y: "3", width: "18", height: "18", rx: "2" } },
    { tag: "circle", attrs: { cx: "8.5", cy: "8.5", r: "1.5" } },
    { tag: "polyline", attrs: { points: "21 15 16 10 5 21" } },
  ],
  send: [
    { tag: "line", attrs: { x1: "22", y1: "2", x2: "11", y2: "13" } },
    { tag: "path", attrs: { d: "M22 2 15 22 11 13 2 9 22 2z" } },
  ],
  download: [
    { tag: "path", attrs: { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" } },
    { tag: "polyline", attrs: { points: "7 10 12 15 17 10" } },
    { tag: "line", attrs: { x1: "12", y1: "15", x2: "12", y2: "3" } },
  ],
  "file-plus": [
    { tag: "path", attrs: { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" } },
    { tag: "polyline", attrs: { points: "14 2 14 8 20 8" } },
    { tag: "line", attrs: { x1: "12", y1: "18", x2: "12", y2: "12" } },
    { tag: "line", attrs: { x1: "9", y1: "15", x2: "15", y2: "15" } },
  ],
  pause: [
    { tag: "rect", attrs: { x: "6", y: "4", width: "4", height: "16", rx: "1" } },
    { tag: "rect", attrs: { x: "14", y: "4", width: "4", height: "16", rx: "1" } },
  ],
  play: [
    { tag: "path", attrs: { d: "M6 4l14 8-14 8V4z" } },
  ],
};

function resolveSizeClass(size: IconSize | number): string {
  if (size === "kbd" || (typeof size === "number" && size <= 11)) return "icon-kbd";
  if (size === "xs" || (typeof size === "number" && size <= 14)) return "icon-xs";
  if (size === "md" || (typeof size === "number" && size >= 18)) return "icon-md";
  return "icon-sm";
}

export function createIcon(
  name: IconName,
  size: IconSize | number = "sm",
  extraClass = "",
): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.5");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const sizeClass = resolveSizeClass(size);
  svg.setAttribute("class", extraClass ? `icon ${sizeClass} ${extraClass}` : `icon ${sizeClass}`);

  for (const prim of ICON_DEFS[name]) {
    const node = document.createElementNS(SVG_NS, prim.tag);
    for (const [k, v] of Object.entries(prim.attrs)) {
      node.setAttribute(k, v);
    }
    svg.appendChild(node);
  }
  return svg;
}

export function createIconSwap(
  baseName: IconName,
  activeName: IconName,
  size: IconSize = "xs",
): HTMLSpanElement {
  const wrap = document.createElement("span");
  wrap.className = "icon-swap";
  wrap.setAttribute("aria-hidden", "true");
  wrap.append(
    createIcon(baseName, size, "icon-swap-base"),
    createIcon(activeName, size, "icon-swap-active"),
  );
  return wrap;
}
