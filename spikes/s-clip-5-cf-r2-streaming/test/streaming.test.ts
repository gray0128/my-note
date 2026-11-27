import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { MAX_CLIP_BLOB_BYTES } from "../src/index";

const TEN_MIB = 10 * 1024 * 1024; // 10,485,760 bytes
const CHUNK_SIZE = 64 * 1024; // 64 KiB streaming chunks

/**
 * Deterministic byte generator for streaming tests without allocating a full 10 MiB buffer.
 * Writes an MNC1-like 4-byte magic prefix at offset 0 followed by deterministic non-repeating pattern.
 */
function fillDeterministicChunk(buf: Uint8Array, byteOffset: number): void {
  let offset = byteOffset;
  for (let i = 0; i < buf.length; i++, offset++) {
    if (offset === 0) buf[i] = 0x4d; // 'M'
    else if (offset === 1) buf[i] = 0x4e; // 'N'
    else if (offset === 2) buf[i] = 0x43; // 'C'
    else if (offset === 3) buf[i] = 0x31; // '1'
    else buf[i] = ((offset * 31) ^ (offset >>> 8) ^ (offset >>> 16)) & 0xff;
  }
}

function createDeterministicStream(totalBytes: number, chunkSize = CHUNK_SIZE): ReadableStream<Uint8Array> {
  let produced = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (produced >= totalBytes) {
        controller.close();
        return;
      }
      const len = Math.min(chunkSize, totalBytes - produced);
      const chunk = new Uint8Array(len);
      fillDeterministicChunk(chunk, produced);
      produced += len;
      controller.enqueue(chunk);
    },
  });
}

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Computes SHA-256 of a ReadableStream incrementally via workerd's native crypto.DigestStream
 * without ever materializing the full 10 MiB payload in memory.
 */
async function streamSha256AndBytes(
  stream: ReadableStream<Uint8Array>,
): Promise<{ totalBytes: number; chunkCount: number; sha256Hex: string }> {
  const digestStream = new crypto.DigestStream("SHA-256");
  const digestWriter = digestStream.getWriter();
  const reader = stream.getReader();

  let totalBytes = 0;
  let chunkCount = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      chunkCount += 1;
      await digestWriter.write(value);
    }
    await digestWriter.close();
  } finally {
    reader.releaseLock();
  }

  const digest = await digestStream.digest;
  return { totalBytes, chunkCount, sha256Hex: toHex(digest) };
}

describe("S-Clip-5: real workerd zero-buffer R2 streaming for /v1/clip/blob", () => {
  it("streams a 10 MiB binary payload to R2 via PUT, stream-verifies SHA-256 via GET, and deletes cleanly", async () => {
    const clipId = "01JDFCLIP10MIBSTREAM000001";
    const expected = await streamSha256AndBytes(createDeterministicStream(TEN_MIB));
    expect(expected.totalBytes).toBe(TEN_MIB);

    // 1. PUT /v1/clip/blob with 10 MiB ReadableStream
    const putStart = performance.now();
    const putRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(TEN_MIB),
        "X-Clip-Id": clipId,
      },
      body: createDeterministicStream(TEN_MIB),
      duplex: "half",
    } as RequestInit);
    const putElapsedMs = Math.round((performance.now() - putStart) * 100) / 100;

    expect(putRes.status).toBe(200);
    const putJson = (await putRes.json()) as {
      ok: boolean;
      clip_id: string;
      r2_key: string;
      blob_bytes: number;
      etag: string;
    };
    expect(putJson.ok).toBe(true);
    expect(putJson.clip_id).toBe(clipId);
    expect(putJson.r2_key).toBe(`clip/blobs/${clipId}.mnc1`);
    expect(putJson.blob_bytes).toBe(TEN_MIB);
    expect(putJson.etag.length).toBeGreaterThan(0);

    // Verify object exists in R2 directly under clip/blobs/
    const head = await env.ARCHIVE_BUCKET.head(`clip/blobs/${clipId}.mnc1`);
    expect(head).not.toBeNull();
    expect(head?.size).toBe(TEN_MIB);

    // 2. GET /v1/clip/:id/blob — stream-verify exact length & SHA-256 hash
    const getStart = performance.now();
    const getRes = await SELF.fetch(`https://relay.test/v1/clip/${clipId}/blob`, {
      method: "GET",
    });
    expect(getRes.status).toBe(200);
    expect(getRes.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(getRes.headers.get("Content-Length")).toBe(String(TEN_MIB));
    expect(getRes.headers.get("X-Clip-Id")).toBe(clipId);
    expect(getRes.body).not.toBeNull();

    const actual = await streamSha256AndBytes(getRes.body!);
    const getElapsedMs = Math.round((performance.now() - getStart) * 100) / 100;

    expect(actual.totalBytes).toBe(TEN_MIB);
    expect(actual.chunkCount).toBeGreaterThan(100); // proves chunked streaming, not single-buffer materialization
    expect(actual.sha256Hex).toBe(expected.sha256Hex);

    // 3. DELETE /v1/clip/:id/blob and confirm subsequent GET returns 404
    const delRes = await SELF.fetch(`https://relay.test/v1/clip/${clipId}/blob`, {
      method: "DELETE",
    });
    expect(delRes.status).toBe(200);
    expect(await delRes.json()).toMatchObject({
      ok: true,
      clip_id: clipId,
      r2_key: `clip/blobs/${clipId}.mnc1`,
      deleted: true,
    });

    const afterDelGet = await SELF.fetch(`https://relay.test/v1/clip/${clipId}/blob`);
    expect(afterDelGet.status).toBe(404);
    expect(await afterDelGet.json()).toMatchObject({
      ok: false,
      error: { code: "NOT_FOUND" },
    });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${clipId}.mnc1`)).toBeNull();

    console.log(
      JSON.stringify({
        metric: "s_clip_5_10mib_roundtrip",
        bytes: TEN_MIB,
        put_ms: putElapsedMs,
        get_ms: getElapsedMs,
        get_chunks: actual.chunkCount,
        sha256: actual.sha256Hex,
      }),
    );
  });

  it("accepts exact 10.5 MiB boundary and rejects > 10.5 MiB (HTTP 413) without writing to R2", async () => {
    // Boundary + 1 byte must be rejected with 413 and ZERO R2 write
    const overClipId = "01JDFCLIPOVERLIMIT00000001";
    const overSize = MAX_CLIP_BLOB_BYTES + 1; // 11,010,049 bytes

    const overRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(overSize),
        "X-Clip-Id": overClipId,
      },
      body: createDeterministicStream(1024), // small stream; Worker must reject by Content-Length header first
      duplex: "half",
    } as RequestInit);

    expect(overRes.status).toBe(413);
    expect(await overRes.json()).toMatchObject({
      ok: false,
      error: { code: "PAYLOAD_TOO_LARGE" },
    });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${overClipId}.mnc1`)).toBeNull();

    const overGet = await SELF.fetch(`https://relay.test/v1/clip/${overClipId}/blob`);
    expect(overGet.status).toBe(404);

    // Exact 10.5 MiB boundary must succeed
    const exactClipId = "01JDFCLIPEXACT105MIB000001";
    const exactRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(MAX_CLIP_BLOB_BYTES),
        "X-Clip-Id": exactClipId,
      },
      body: createDeterministicStream(MAX_CLIP_BLOB_BYTES),
      duplex: "half",
    } as RequestInit);

    expect(exactRes.status).toBe(200);
    const exactJson = (await exactRes.json()) as { ok: boolean; blob_bytes: number };
    expect(exactJson.ok).toBe(true);
    expect(exactJson.blob_bytes).toBe(MAX_CLIP_BLOB_BYTES);

    // Clean up boundary object
    const cleanRes = await SELF.fetch(`https://relay.test/v1/clip/${exactClipId}/blob`, {
      method: "DELETE",
    });
    expect(cleanRes.status).toBe(200);
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${exactClipId}.mnc1`)).toBeNull();
  });

  it("rejects missing, zero, or invalid Content-Length (HTTP 400) without writing to R2", async () => {
    const zeroClipId = "01JDFCLIPZEROLENGTH0000001";
    const zeroRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": "0",
        "X-Clip-Id": zeroClipId,
      },
      body: new Uint8Array(0),
    });
    expect(zeroRes.status).toBe(400);
    expect(await zeroRes.json()).toMatchObject({
      ok: false,
      error: { code: "INVALID_ARGUMENT" },
    });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${zeroClipId}.mnc1`)).toBeNull();

    const noLenClipId = "01JDFCLIPNOLENGTH000000001";
    const noLenRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Clip-Id": noLenClipId,
      },
      body: createDeterministicStream(512),
      duplex: "half",
    } as RequestInit);
    expect(noLenRes.status).toBe(400);
    expect(await noLenRes.json()).toMatchObject({
      ok: false,
      error: { code: "INVALID_ARGUMENT" },
    });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${noLenClipId}.mnc1`)).toBeNull();
  });

  it("rejects spoofed/truncated Content-Length streams via FixedLengthStream without leaving orphan R2 objects", async () => {
    // 1. Over-streaming: header claims 1024 B, stream tries to send 8192 B
    const spoofClipId = "01JDFCLIPSPOOFOVER00000001";
    const spoofRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": "1024",
        "X-Clip-Id": spoofClipId,
      },
      body: createDeterministicStream(8192, 512),
      duplex: "half",
    } as RequestInit);
    expect(spoofRes.status).toBe(400);
    expect(await spoofRes.json()).toMatchObject({
      ok: false,
      error: { code: "CONTENT_LENGTH_MISMATCH" },
    });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${spoofClipId}.mnc1`)).toBeNull();

    // 2. Truncated stream: header claims 8192 B, stream ends after 1024 B
    const truncClipId = "01JDFCLIPTRUNCATED00000001";
    const truncRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": "8192",
        "X-Clip-Id": truncClipId,
      },
      body: createDeterministicStream(1024, 512),
      duplex: "half",
    } as RequestInit);
    expect(truncRes.status).toBe(400);
    expect(await truncRes.json()).toMatchObject({
      ok: false,
      error: { code: "CONTENT_LENGTH_MISMATCH" },
    });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${truncClipId}.mnc1`)).toBeNull();
  });

  it("handles 3x 10 MiB sequential streaming round-trips cleanly without buffering OOM", async () => {
    const expected = await streamSha256AndBytes(createDeterministicStream(TEN_MIB));
    const start = performance.now();

    for (let i = 1; i <= 3; i++) {
      const clipId = `01JDFCLIPBATCH10MIB000000${i}`;
      const putRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
        method: "PUT",
        headers: {
          "Content-Type": "application/octet-stream",
          "Content-Length": String(TEN_MIB),
          "X-Clip-Id": clipId,
        },
        body: createDeterministicStream(TEN_MIB),
        duplex: "half",
      } as RequestInit);
      expect(putRes.status).toBe(200);
      expect(await putRes.json()).toMatchObject({ ok: true, blob_bytes: TEN_MIB });

      const getRes = await SELF.fetch(`https://relay.test/v1/clip/${clipId}/blob`);
      expect(getRes.status).toBe(200);
      const got = await streamSha256AndBytes(getRes.body!);
      expect(got.totalBytes).toBe(TEN_MIB);
      expect(got.sha256Hex).toBe(expected.sha256Hex);

      const delRes = await SELF.fetch(`https://relay.test/v1/clip/${clipId}/blob`, { method: "DELETE" });
      expect(delRes.status).toBe(200);
    }

    const totalMs = Math.round((performance.now() - start) * 100) / 100;
    console.log(
      JSON.stringify({
        metric: "s_clip_5_3x10mib_sequential",
        total_bytes_uploaded: TEN_MIB * 3,
        total_bytes_downloaded: TEN_MIB * 3,
        total_ms: totalMs,
      }),
    );
  });
});
