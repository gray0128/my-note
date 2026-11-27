import { isAllowedBitmapMime, normalizeMime } from "../clipUtils";
import type { AllowedClipImageMime } from "../types";

export const SHARE_HANDOFF_CACHE = "mynote-share-handoff";
export const SHARE_HANDOFF_URL = "/__share-handoff/latest";

export type ShareHandoffPayload =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "image"; readonly mime: AllowedClipImageMime; readonly bytes: Uint8Array; readonly filename: string }
  | { readonly kind: "error"; readonly code: "DISALLOWED_MIME"; readonly mime: string };

/**
 * Read and immediately wipe the transient Android Web Share Target handoff cache (`SEC-08`).
 * Deletion ALWAYS runs in `finally` so plaintext shared payloads never linger in Cache Storage.
 */
export async function consumeShareHandoffCache(
  cachesApi: Pick<CacheStorage, "open" | "delete" | "has"> | undefined = typeof caches !== "undefined" ? caches : undefined,
): Promise<ShareHandoffPayload | null> {
  if (!cachesApi) return null;
  let hasCache = false;
  try {
    hasCache = await cachesApi.has(SHARE_HANDOFF_CACHE);
  } catch {
    return null;
  }
  if (!hasCache) return null;

  try {
    const cache = await cachesApi.open(SHARE_HANDOFF_CACHE);
    const resp = await cache.match(SHARE_HANDOFF_URL);
    if (!resp) return null;

    const shareKind = resp.headers.get("x-share-kind") ?? "";
    const contentType = normalizeMime(resp.headers.get("content-type"));

    if (shareKind === "error") {
      const data = (await resp.json().catch(() => ({}))) as { mime?: string };
      return { kind: "error", code: "DISALLOWED_MIME", mime: String(data.mime ?? "unknown") };
    }

    if (shareKind === "image") {
      if (!isAllowedBitmapMime(contentType)) {
        return { kind: "error", code: "DISALLOWED_MIME", mime: contentType || "unknown" };
      }
      const bytes = new Uint8Array(await resp.arrayBuffer());
      const rawName = resp.headers.get("x-share-filename") ?? "shared-image";
      let filename = rawName;
      try {
        filename = decodeURIComponent(rawName);
      } catch {
        // keep raw name
      }
      return { kind: "image", mime: contentType, bytes, filename };
    }

    if (shareKind === "text" || contentType === "application/json") {
      const data = (await resp.json().catch(() => ({}))) as { kind?: string; text?: string; mime?: string };
      if (data.kind === "error") {
        return { kind: "error", code: "DISALLOWED_MIME", mime: String(data.mime ?? "unknown") };
      }
      const text = typeof data.text === "string" ? data.text : "";
      return text ? { kind: "text", text } : null;
    }

    return null;
  } finally {
    // SEC-08: Plaintext share handoff cache MUST ALWAYS be purged immediately!
    try {
      await cachesApi.delete(SHARE_HANDOFF_CACHE);
    } catch {
      // ignore cleanup errors
    }
  }
}
