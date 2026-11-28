import type { AllowedClipImageMime, ClipKind, ClipSourceMode } from "./types";

export const CLIP_CLOUD_MAX_ITEMS = 1000;
export const CLIP_MAX_ITEMS = CLIP_CLOUD_MAX_ITEMS;
export const CLIP_PAGE_LIMIT = 50;
export const CLIP_CLOUD_QUOTA_BYTES = 5 * 1024 * 1024 * 1024;
export const CLIP_CLOUD_QUOTA_WARN_RATIO = 0.8;
export const CLIP_INLINE_TEXT_MAX_BYTES = 64 * 1024;
export const CLIP_EPHEMERAL_MAX_BYTES = 256 * 1024;
export const CLIP_BLOB_MAX_BYTES = 10 * 1024 * 1024;
export const CLIP_THUMB_MAX_BYTES = 12 * 1024;
export const CLIP_PREVIEW_MAX_CHARS = 240;

export const ALLOWED_CLIP_IMAGE_MIMES: readonly AllowedClipImageMime[] = [
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
];

const ALLOWED_CLIP_IMAGE_MIME_SET = new Set<string>(ALLOWED_CLIP_IMAGE_MIMES);
const CROCKFORD_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export interface ClipBlobMetaV1 {
  byte_size: number;
  sha256_hex: string;
  width: number | null;
  height: number | null;
  thumb_mime: AllowedClipImageMime | null;
  thumb_b64: string | null;
}

export interface ClipMetaV1 {
  v: 1;
  kind: ClipKind;
  mime: string;
  source_mode: ClipSourceMode;
  created_at_ms: number;
  text: string | null;
  blob: ClipBlobMetaV1 | null;
}

export function normalizeMime(raw: string | null | undefined): string {
  return (raw ?? "").split(";")[0].trim().toLowerCase();
}

export function isAllowedBitmapMime(mime: string | null | undefined): mime is AllowedClipImageMime {
  const norm = normalizeMime(mime);
  return ALLOWED_CLIP_IMAGE_MIME_SET.has(norm);
}

export function isSvgMime(mime: string | null | undefined): boolean {
  const norm = normalizeMime(mime);
  return norm === "image/svg+xml" || norm.includes("svg");
}

export function isSafeThumbDataUrl(url: string | null | undefined): boolean {
  if (!url || typeof url !== "string") return false;
  const commaIdx = url.indexOf(",");
  if (commaIdx <= 0) return false;
  const prefix = url.slice(0, commaIdx).toLowerCase();
  if (!prefix.startsWith("data:") || !prefix.endsWith(";base64")) return false;
  const mime = prefix.slice(5, -7);
  return isAllowedBitmapMime(mime);
}

export type ClipImageValidationResult =
  | { readonly ok: true; readonly mime: AllowedClipImageMime }
  | { readonly ok: false; readonly reason: "svg" | "mime" | "empty" | "size"; readonly mime: string };

export function validateClipImageFile(mime: string | null | undefined, byteSize: number): ClipImageValidationResult {
  const norm = normalizeMime(mime);
  if (isSvgMime(norm)) {
    return { ok: false, reason: "svg", mime: norm };
  }
  if (!isAllowedBitmapMime(norm)) {
    return { ok: false, reason: "mime", mime: norm || "unknown" };
  }
  if (!Number.isFinite(byteSize) || byteSize <= 0) {
    return { ok: false, reason: "empty", mime: norm };
  }
  if (byteSize > CLIP_BLOB_MAX_BYTES) {
    return { ok: false, reason: "size", mime: norm };
  }
  return { ok: true, mime: norm };
}

export function truncatePreview(text: string, maxChars = CLIP_PREVIEW_MAX_CHARS): string {
  const chars = Array.from(text);
  if (chars.length <= maxChars) return text;
  return chars.slice(0, maxChars).join("");
}

export function formatClipBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

export function extForClipMime(mime: string): string {
  switch (normalizeMime(mime)) {
    case "image/png":
      return "png";
    case "image/jpeg":
      return "jpg";
    case "image/webp":
      return "webp";
    case "image/gif":
      return "gif";
    default:
      return "txt";
  }
}

export function bytesToBase64Chunked(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const sub = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    let s = "";
    for (let j = 0; j < sub.length; j++) {
      s += String.fromCharCode(sub[j]);
    }
    parts.push(s);
  }
  return btoa(parts.join(""));
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let lastUlidMs = 0;
const lastUlidRand = new Uint8Array(10);

export function generateUlid(nowMs = Date.now()): string {
  const ts = Math.max(0, Math.floor(nowMs));
  const bytes = new Uint8Array(16);
  let t = ts;
  for (let i = 5; i >= 0; i--) {
    bytes[i] = t & 0xff;
    t = Math.floor(t / 256);
  }
  if (ts === lastUlidMs) {
    for (let i = 9; i >= 0; i--) {
      if (lastUlidRand[i] < 255) {
        lastUlidRand[i]++;
        break;
      }
      lastUlidRand[i] = 0;
    }
  } else {
    lastUlidMs = ts;
    crypto.getRandomValues(lastUlidRand);
  }
  bytes.set(lastUlidRand, 6);

  let out = "";
  let acc = 0;
  let bits = 2;
  for (let i = 0; i < 16; i++) {
    acc = (acc << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CROCKFORD_B32[(acc >>> bits) & 31];
    }
  }
  return out;
}

export async function computeSha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) {
    hex += arr[i].toString(16).padStart(2, "0");
  }
  return hex;
}

export interface GeneratedThumbnail {
  width: number | null;
  height: number | null;
  thumb_mime: AllowedClipImageMime | null;
  thumb_b64: string | null;
}

async function decodeImageSource(
  blob: Blob,
): Promise<{ width: number; height: number; draw: (ctx: CanvasRenderingContext2D, w: number, h: number) => void; close: () => void } | null> {
  if (typeof createImageBitmap === "function") {
    try {
      const bmp = await createImageBitmap(blob);
      return {
        width: bmp.width,
        height: bmp.height,
        draw: (ctx, w, h) => ctx.drawImage(bmp, 0, 0, w, h),
        close: () => {
          try {
            bmp.close();
          } catch {
            // ignore
          }
        },
      };
    } catch {
      // fall through to HTMLImageElement
    }
  }
  if (typeof Image === "undefined" || typeof URL.createObjectURL !== "function") {
    return null;
  }
  const objUrl = URL.createObjectURL(blob);
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => reject(new Error("image decode failed"));
      el.src = objUrl;
    });
    return {
      width: img.naturalWidth || img.width,
      height: img.naturalHeight || img.height,
      draw: (ctx, w, h) => ctx.drawImage(img, 0, 0, w, h),
      close: () => URL.revokeObjectURL(objUrl),
    };
  } catch {
    URL.revokeObjectURL(objUrl);
    return null;
  }
}

function canvasToBlob(canvas: HTMLCanvasElement, mime: AllowedClipImageMime, quality?: number): Promise<Blob | null> {
  return new Promise((resolve) => {
    try {
      canvas.toBlob((b) => resolve(b), mime, quality);
    } catch {
      resolve(null);
    }
  });
}

/** Generate a <= 12 KiB WebP/JPEG thumbnail & dimensions via offscreen canvas (never SVG). */
export async function generateBitmapThumbnail(
  blob: Blob,
  _fallbackMime: AllowedClipImageMime,
): Promise<GeneratedThumbnail> {
  if (typeof document === "undefined") {
    return { width: null, height: null, thumb_mime: null, thumb_b64: null };
  }
  const decoded = await decodeImageSource(blob);
  if (!decoded || decoded.width <= 0 || decoded.height <= 0) {
    return { width: null, height: null, thumb_mime: null, thumb_b64: null };
  }
  try {
    const { width, height } = decoded;
    const maxEdges = [320, 220, 140];
    const candidates: readonly { mime: AllowedClipImageMime; quality: number }[] = [
      { mime: "image/webp", quality: 0.72 },
      { mime: "image/jpeg", quality: 0.72 },
      { mime: "image/jpeg", quality: 0.5 },
    ];
    for (const maxEdge of maxEdges) {
      const scale = Math.min(1, maxEdge / Math.max(width, height));
      const tw = Math.max(1, Math.round(width * scale));
      const th = Math.max(1, Math.round(height * scale));
      const canvas = document.createElement("canvas");
      canvas.width = tw;
      canvas.height = th;
      const ctx = canvas.getContext("2d");
      if (!ctx) break;
      decoded.draw(ctx, tw, th);
      for (const c of candidates) {
        const tb = await canvasToBlob(canvas, c.mime, c.quality);
        if (!tb || tb.size === 0 || tb.size > CLIP_THUMB_MAX_BYTES) continue;
        const actualMime = normalizeMime(tb.type);
        if (!isAllowedBitmapMime(actualMime)) continue;
        const raw = new Uint8Array(await tb.arrayBuffer());
        if (raw.byteLength <= CLIP_THUMB_MAX_BYTES) {
          return {
            width,
            height,
            thumb_mime: actualMime,
            thumb_b64: bytesToBase64Chunked(raw),
          };
        }
      }
    }
    return { width, height, thumb_mime: null, thumb_b64: null };
  } finally {
    decoded.close();
  }
}

/** Convert verified bitmap bytes to `image/png` Blob (pass-through if already PNG). */
export async function convertImageBytesToPngBlob(
  bytes: Uint8Array,
  mime: AllowedClipImageMime,
): Promise<Blob> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  if (mime === "image/png") {
    return new Blob([copy], { type: "image/png" });
  }
  const srcBlob = new Blob([copy], { type: mime });
  const decoded = await decodeImageSource(srcBlob);
  if (!decoded || decoded.width <= 0 || decoded.height <= 0 || typeof document === "undefined") {
    throw new Error("Unable to convert image to PNG in this browser environment");
  }
  try {
    const canvas = document.createElement("canvas");
    canvas.width = decoded.width;
    canvas.height = decoded.height;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Canvas 2D context unavailable");
    decoded.draw(ctx, decoded.width, decoded.height);
    const pngBlob = await canvasToBlob(canvas, "image/png");
    if (!pngBlob) throw new Error("Canvas PNG encoding failed");
    return pngBlob;
  } finally {
    decoded.close();
  }
}
