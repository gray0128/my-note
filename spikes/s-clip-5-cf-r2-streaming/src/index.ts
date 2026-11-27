export interface Env {
  ARCHIVE_BUCKET: R2Bucket;
}

export const MAX_CLIP_BLOB_BYTES = 10.5 * 1024 * 1024; // 11,010,048 bytes (exact 10.5 MiB)
const CLIP_ID_RE = /^[0-9A-Za-z_-]{1,64}$/;
const BLOB_ITEM_PATH_RE = /^\/v1\/clip\/([^/]+)\/blob$/;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function errorJson(code: string, message: string, status: number): Response {
  return json({ ok: false, error: { code, message } }, status);
}

async function cancelBody(req: Request): Promise<void> {
  if (!req.body) return;
  try {
    await req.body.cancel();
  } catch {
    // Ignore already-disturbed or closed stream errors on early rejection.
  }
}

function parseContentLength(raw: string | null): number | null {
  if (raw === null || !/^\d+$/.test(raw.trim())) {
    return null;
  }
  const n = Number(raw.trim());
  if (!Number.isSafeInteger(n) || n <= 0) {
    return null;
  }
  return n;
}

function blobKey(clipId: string): string {
  return `clip/blobs/${clipId}.mnc1`;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    // PUT /v1/clip/blob — zero-buffer streaming write directly into R2 clip/blobs/<clip_id>.mnc1
    if (req.method === "PUT" && url.pathname === "/v1/clip/blob") {
      const clipId = req.headers.get("X-Clip-Id")?.trim() ?? "";
      if (!CLIP_ID_RE.test(clipId)) {
        await cancelBody(req);
        return errorJson("INVALID_ARGUMENT", "Missing or invalid X-Clip-Id header", 400);
      }

      const contentLength = parseContentLength(req.headers.get("Content-Length"));
      if (contentLength === null) {
        await cancelBody(req);
        return errorJson("INVALID_ARGUMENT", "Missing or invalid Content-Length header (must be > 0)", 400);
      }

      if (contentLength > MAX_CLIP_BLOB_BYTES) {
        await cancelBody(req);
        return errorJson(
          "PAYLOAD_TOO_LARGE",
          `Blob size ${contentLength} exceeds limit of ${MAX_CLIP_BLOB_BYTES} bytes (10.5 MiB)`,
          413,
        );
      }

      if (!req.body) {
        return errorJson("INVALID_ARGUMENT", "Request body is required", 400);
      }

      const key = blobKey(clipId);
      // In workerd / HTTP/2 / HTTP/3, req.body may not carry an internal known-length
      // descriptor even when Content-Length is present, causing R2Bucket.put(key, req.body)
      // to throw TypeError("Provided readable stream must have a known length").
      // Piping through FixedLengthStream(contentLength) keeps O(1) memory (zero buffering)
      // while also enforcing exact byte count against spoofed/truncated Content-Length.
      const fixed = new FixedLengthStream(contentLength);
      const pipePromise = req.body.pipeTo(fixed.writable);
      const putPromise = env.ARCHIVE_BUCKET.put(key, fixed.readable, {
        httpMetadata: {
          contentType: "application/octet-stream",
        },
        customMetadata: {
          clip_id: clipId,
        },
      });

      const [pipeResult, putResult] = await Promise.allSettled([pipePromise, putPromise]);
      if (pipeResult.status === "rejected" || putResult.status === "rejected") {
        // Ensure no partial/orphan object remains in R2 on stream mismatch or abort.
        await env.ARCHIVE_BUCKET.delete(key).catch(() => {});
        const reason =
          pipeResult.status === "rejected"
            ? String(pipeResult.reason)
            : String((putResult as PromiseRejectedResult).reason);
        const isLengthMismatch = /FixedLengthStream|expected|length|exceeded|short/i.test(reason);
        return errorJson(
          isLengthMismatch ? "CONTENT_LENGTH_MISMATCH" : "UPLOAD_FAILED",
          `Streaming upload aborted: ${reason}`,
          isLengthMismatch ? 400 : 500,
        );
      }

      const uploaded = putResult.value;
      if (!uploaded) {
        return errorJson("INTERNAL_ERROR", "R2 put returned null", 500);
      }

      return json({
        ok: true,
        clip_id: clipId,
        r2_key: uploaded.key,
        blob_bytes: uploaded.size,
        etag: uploaded.etag,
      });
    }

    // GET /v1/clip/:id/blob and DELETE /v1/clip/:id/blob
    const match = BLOB_ITEM_PATH_RE.exec(url.pathname);
    if (match) {
      const clipId = match[1];
      if (!CLIP_ID_RE.test(clipId)) {
        return errorJson("INVALID_ARGUMENT", "Invalid clip_id", 400);
      }

      const key = blobKey(clipId);

      if (req.method === "GET") {
        const obj = await env.ARCHIVE_BUCKET.get(key);
        if (!obj) {
          return errorJson("NOT_FOUND", `Clip blob not found: ${clipId}`, 404);
        }

        // Zero-buffer streaming response directly from R2 ReadableStream
        return new Response(obj.body, {
          status: 200,
          headers: {
            "Content-Type": "application/octet-stream",
            "Content-Length": String(obj.size),
            ETag: obj.httpEtag,
            "X-Clip-Id": clipId,
          },
        });
      }

      if (req.method === "DELETE") {
        await env.ARCHIVE_BUCKET.delete(key);
        return json({
          ok: true,
          clip_id: clipId,
          r2_key: key,
          deleted: true,
        });
      }
    }

    return errorJson("NOT_FOUND", `Route not found: ${req.method} ${url.pathname}`, 404);
  },
} satisfies ExportedHandler<Env>;
