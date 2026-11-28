import { env, SELF, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import { encode } from "@msgpack/msgpack";
import type { SyncJournalDO } from "../src/index";

const TEN_MIB = 10 * 1024 * 1024; // 10,485,760 bytes
const MAX_BLOB = 11_010_048; // 10.5 MiB
const DAY_MS = 86_400_000;
const CLIP_KID = "01JDFC11PK1D00000000000001";

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64(text: string): string {
  return btoa(text);
}

function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

function ulidFor(prefix: string, seq: number): string {
  // Valid Crockford Base32 26-char ULID with monotonic decimal suffix (excludes I, L, O, U)
  const tail = String(seq).padStart(26 - prefix.length, "0");
  const id = `${prefix}${tail}`;
  expect(id, `invalid test ULID: ${id}`).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  return id;
}

function createDeterministicStream(totalBytes: number, chunkSize = 64 * 1024): ReadableStream<Uint8Array> {
  let produced = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (produced >= totalBytes) {
        controller.close();
        return;
      }
      const len = Math.min(chunkSize, totalBytes - produced);
      const chunk = new Uint8Array(len);
      for (let i = 0; i < len; i++, produced++) {
        if (produced === 0) chunk[i] = 0x4d; // 'M'
        else if (produced === 1) chunk[i] = 0x4e; // 'N'
        else if (produced === 2) chunk[i] = 0x43; // 'C'
        else if (produced === 3) chunk[i] = 0x31; // '1'
        else chunk[i] = ((produced * 31) ^ (produced >>> 8) ^ (produced >>> 16)) & 0xff;
      }
      controller.enqueue(chunk);
    },
  });
}

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
  const digest = new Uint8Array(await digestStream.digest);
  return { totalBytes, chunkCount, sha256Hex: [...digest].map((b) => b.toString(16).padStart(2, "0")).join("") };
}

async function bootstrapDevice(
  deviceName: string,
  token: string,
  opts: { deviceId?: string; fetcher?: Pick<typeof SELF, "fetch"> } = {},
) {
  const f = opts.fetcher ?? SELF;
  const res = await f.fetch("https://relay.test/v1/devices/bootstrap", {
    method: "POST",
    headers: { authorization: `Bearer ${env.BOOTSTRAP_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({
      device_name: deviceName,
      token_sha256_hex: await sha256Hex(token),
      device_id: opts.deviceId,
    }),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { ok: boolean; device_id: string; scope: string; epoch: string };
}

async function pairDevice(
  adminToken: string,
  deviceName: string,
  scope: string,
  newToken: string,
  opts: { fetcher?: Pick<typeof SELF, "fetch"> } = {},
) {
  const f = opts.fetcher ?? SELF;
  const addRes = await f.fetch("https://relay.test/v1/devices", {
    method: "POST",
    headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
    body: JSON.stringify({
      device_name: deviceName,
      scope,
      token_sha256_hex: await sha256Hex(newToken),
      ciphertext_b64: b64(`pair_ct_${scope}_${deviceName}`),
    }),
  });
  expect(addRes.status).toBe(200);
  const addJson = (await addRes.json()) as { device_id: string; pair_id: string };
  const claimRes = await f.fetch("https://relay.test/v1/devices/pair-claim", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ pair_id: addJson.pair_id }),
  });
  expect(claimRes.status).toBe(200);
  const claimJson = (await claimRes.json()) as { ok: boolean; device_id: string; scope: string };
  expect(claimJson.scope).toBe(scope);
  return addJson.device_id;
}

describe("M4a-2: Independent 100-item Clip Channel, 4-State Scopes, Streaming R2 & Live Migration", () => {
  it("INV-CLIP-ISOLATION: 105 mixed text + streaming blobs (incl. 10 MiB), eviction, 7d TTL alarm, DO rollback orphan cleanup, >10.5 MiB 413, and zero note/archive mutation", async () => {
    const deskAToken = "tok-clip-iso-desk-a";
    const deskBToken = "tok-clip-iso-desk-b";
    const phoneToken = "tok-clip-iso-phone-rc";
    const boot = await bootstrapDevice("MacClip", deskAToken, { deviceId: "dev_clipmac00001" });
    await pairDevice(deskAToken, "OmarchyClip", "read-write", deskBToken);
    await pairDevice(deskAToken, "iPhoneClip", "read+clip", phoneToken);

    const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("primary"));
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(0));

    // Seed baseline note state (keyring + block_key + 2 ops + 1 shred_mark + 1 mobile snapshot + daily archive)
    const krBytes = encode({
      v: 1,
      recovery_kid: new Uint8Array(16),
      recovery_pk: new Uint8Array(32),
      keyring_gen: 1,
      current_smk_kid: "01JDF8Z9X4K7M2N5P8Q1R3S600",
      smk_entries: [],
    });
    const noteKeyId = "01JDF8Z9X4K7M2N5P8Q1R3N001";
    const shredKeyId = "01JDF8Z9X4K7M2N5P8Q1R3N002";
    expect(
      (
        await SELF.fetch("https://relay.test/v1/keys", {
          method: "POST",
          headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
          body: JSON.stringify({
            key_records: [
              { key_id: noteKeyId, wrap_gen: 1, key_record_b64: b64("mnr1_note_1") },
              { key_id: shredKeyId, wrap_gen: 1, key_record_b64: b64("mnr1_note_2") },
            ],
            key_material: { keyring: { gen: 1, blob_b64: bytesToB64(krBytes) } },
          }),
        })
      ).status,
    ).toBe(200);

    expect(
      (
        await SELF.fetch("https://relay.test/v1/sync/push", {
          method: "POST",
          headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
          body: JSON.stringify({
            expected_epoch: boot.epoch,
            seen_seq: 0,
            ops: [
              { op_id: "01JDF9N0TE0000000000000001", key_id: noteKeyId, envelope_b64: b64("mns1_note_1") },
              { op_id: "01JDF9N0TE0000000000000002", key_id: null, envelope_b64: b64("mns1_note_2") },
            ],
            shred_marks: [{ mark_id: "01JDF9MARK0000000000000N01", key_id: shredKeyId, grace_ms: 30 * DAY_MS }],
          }),
        })
      ).status,
    ).toBe(200);

    expect(
      (
        await SELF.fetch("https://relay.test/v1/snapshots/state", {
          method: "PUT",
          headers: {
            authorization: `Bearer ${deskAToken}`,
            "content-type": "application/octet-stream",
            "x-journal-epoch": boot.epoch,
            "x-covers-seq": "2",
            "x-snapshot-id": "01JDF9SNAP0000000000000001",
          },
          body: new TextEncoder().encode("MNP1_BASELINE_SNAPSHOT"),
        })
      ).status,
    ).toBe(200);

    // Run baseline daily archive
    await runDurableObjectAlarm(stub);

    // Capture baseline snapshots of all note tables & R2 archive prefixes
    const basePull = await (await SELF.fetch("https://relay.test/v1/sync/pull?since=0", { headers: { authorization: `Bearer ${deskAToken}` } })).json();
    const baseKeys = (await (await SELF.fetch("https://relay.test/v1/keys", { headers: { authorization: `Bearer ${deskAToken}` } })).json()) as {
      key_records: unknown[];
      shred_marks: unknown[];
      digest: string;
    };
    const baseSnap = new TextDecoder().decode(
      await (await SELF.fetch("https://relay.test/v1/snapshots/state", { headers: { authorization: `Bearer ${deskAToken}` } })).arrayBuffer(),
    );
    const baseOpsArchive = (await env.ARCHIVE_BUCKET.list({ prefix: "archives/ops/" })).objects.map((o) => `${o.key}:${o.size}`).sort();
    const baseKeysArchive = (await env.ARCHIVE_BUCKET.list({ prefix: "archives/keys/" })).objects.map((o) => `${o.key}:${o.size}`).sort();
    expect(baseOpsArchive.length).toBeGreaterThan(0);
    expect(baseKeysArchive.length).toBeGreaterThan(0);

    // Connect DeskB + PhoneRC WebSockets to observe clip_wake and clip_cleared
    const wsDeskBRes = await SELF.fetch("https://relay.test/v1/sync/ws", {
      headers: { authorization: `Bearer ${deskBToken}`, upgrade: "websocket" },
    });
    expect(wsDeskBRes.status).toBe(101);
    const wsDeskB = wsDeskBRes.webSocket!;
    wsDeskB.accept();
    const deskBMsgs: Record<string, unknown>[] = [];
    wsDeskB.addEventListener("message", (ev) => { deskBMsgs.push(JSON.parse(String(ev.data)) as Record<string, unknown>); });

    const wsPhoneRes = await SELF.fetch("https://relay.test/v1/sync/ws", {
      headers: { authorization: `Bearer ${phoneToken}`, upgrade: "websocket" },
    });
    expect(wsPhoneRes.status).toBe(101);
    const wsPhone = wsPhoneRes.webSocket!;
    wsPhone.accept();
    const phoneMsgs: Record<string, unknown>[] = [];
    wsPhone.addEventListener("message", (ev) => { phoneMsgs.push(JSON.parse(String(ev.data)) as Record<string, unknown>); });

    // Verify default production window is 1000 items / 30 days / 5 GiB, then lower maxItems to 100 for fast eviction check
    const initialList = (await (await SELF.fetch("https://relay.test/v1/clip", { headers: { authorization: `Bearer ${deskAToken}` } })).json()) as {
      ok: boolean;
      has_more: boolean;
      quota: { used_bytes: number; limit_bytes: number; item_count: number; item_limit: number };
    };
    expect(initialList.ok).toBe(true);
    expect(initialList.has_more).toBe(false);
    expect(initialList.quota).toEqual({
      used_bytes: 0,
      limit_bytes: 5 * 1024 * 1024 * 1024,
      item_count: 0,
      item_limit: 1000,
    });
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClipLimitsForTest({ maxItems: 100 }));

    // Push 105 mixed clips (0..104):
    // - indices 0..4 include 3 blobs (0, 2, 4) so eviction MUST delete their R2 blobs
    // - index 50 is a real 10 MiB streaming blob uploaded via ReadableStream
    const expected10MiB = await streamSha256AndBytes(createDeterministicStream(TEN_MIB));
    const bigClipId = ulidFor("01JDFC11P0000000000000", 50);

    for (let i = 0; i < 105; i++) {
      const clipId = ulidFor("01JDFC11P0000000000000", i);
      const isBig = i === 50;
      const isBlob = isBig || i % 2 === 0;
      if (isBlob) {
        const size = isBig ? TEN_MIB : 1024 + i;
        const kind = i % 4 === 0 ? "image" : "text";
        const putRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
          method: "PUT",
          headers: {
            authorization: `Bearer ${deskAToken}`,
            "content-type": "application/octet-stream",
            "content-length": String(size),
            "x-clip-id": clipId,
            "x-clip-kid": CLIP_KID,
            "x-clip-kind": kind,
            "x-clip-meta-b64": b64(`MNC1_META_BLOB_${i}`),
          },
          body: isBig ? createDeterministicStream(TEN_MIB) : createDeterministicStream(size, 512),
          duplex: "half",
        } as RequestInit);
        expect(putRes.status, `blob clip ${i}`).toBe(200);
        const pj = (await putRes.json()) as { ok: boolean; clip_id: string; blob_bytes: number; created_at_ms: number; expires_at_ms: number };
        expect(pj.ok).toBe(true);
        expect(pj.clip_id).toBe(clipId);
        expect(pj.blob_bytes).toBe(size);
        expect(pj.expires_at_ms - pj.created_at_ms).toBe(30 * DAY_MS);
      } else {
        const postRes = await SELF.fetch("https://relay.test/v1/clip", {
          method: "POST",
          headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
          body: JSON.stringify({
            clip_id: clipId,
            clip_kid: CLIP_KID,
            kind: "text",
            meta_envelope_b64: b64(`MNC1_TEXT_${i}`),
          }),
        });
        expect(postRes.status, `text clip ${i}`).toBe(200);
        const tj = (await postRes.json()) as { ok: boolean; clip_id: string; created_at_ms: number; expires_at_ms: number };
        expect(tj.ok).toBe(true);
        expect(tj.clip_id).toBe(clipId);
        expect(tj.expires_at_ms - tj.created_at_ms).toBe(30 * DAY_MS);
      }
    }

    // Both DeskB & PhoneRC WS received clip_wake frames
    await vi.waitFor(() => {
      expect(deskBMsgs.some((m) => m.type === "clip_wake" && m.clip_id === bigClipId)).toBe(true);
      expect(phoneMsgs.some((m) => m.type === "clip_wake" && m.clip_id === bigClipId)).toBe(true);
    });

    // Verify 100-item ring buffer retained newest 100 (indices 5..104) in clip_id ASC order
    const listRes = await SELF.fetch("https://relay.test/v1/clip", {
      headers: { authorization: `Bearer ${phoneToken}` },
    });
    expect(listRes.status).toBe(200);
    const listJson = (await listRes.json()) as {
      ok: boolean;
      items: { clip_id: string; has_blob: boolean; blob_bytes: number | null; kind: string }[];
    };
    expect(listJson.ok).toBe(true);
    expect(listJson.items).toHaveLength(100);
    expect(listJson.items[0].clip_id).toBe(ulidFor("01JDFC11P0000000000000", 5));
    expect(listJson.items[99].clip_id).toBe(ulidFor("01JDFC11P0000000000000", 104));

    // Pagination via since_id & limit reports has_more + next_since_id
    const pageRes = await SELF.fetch(`https://relay.test/v1/clip?since_id=${ulidFor("01JDFC11P0000000000000", 100)}&limit=2`, {
      headers: { authorization: `Bearer ${phoneToken}` },
    });
    expect(pageRes.status).toBe(200);
    const pageJson = (await pageRes.json()) as { items: { clip_id: string }[]; has_more: boolean; next_since_id: string };
    expect(pageJson.items.map((x) => x.clip_id)).toEqual([
      ulidFor("01JDFC11P0000000000000", 101),
      ulidFor("01JDFC11P0000000000000", 102),
    ]);
    expect(pageJson.has_more).toBe(true);
    expect(pageJson.next_since_id).toBe(ulidFor("01JDFC11P0000000000000", 102));

    // Evicted oldest 5 items (indices 0, 2, 4 were blobs) MUST have 0 leftover R2 objects
    for (const evictedIdx of [0, 2, 4]) {
      const evId = ulidFor("01JDFC11P0000000000000", evictedIdx);
      expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${evId}.mnc1`)).toBeNull();
      const evGet = await SELF.fetch(`https://relay.test/v1/clip/${evId}/blob`, {
        headers: { authorization: `Bearer ${phoneToken}` },
      });
      expect(evGet.status).toBe(404);
    }

    // Stream-download the 10 MiB blob via GET /v1/clip/:id/blob and verify SHA-256 + chunked streaming
    const bigGet = await SELF.fetch(`https://relay.test/v1/clip/${bigClipId}/blob`, {
      headers: { authorization: `Bearer ${phoneToken}` },
    });
    expect(bigGet.status).toBe(200);
    expect(bigGet.headers.get("content-type")).toBe("application/octet-stream");
    expect(bigGet.headers.get("x-clip-id")).toBe(bigClipId);
    expect(bigGet.headers.get("x-clip-kid")).toBe(CLIP_KID);
    expect(bigGet.headers.get("x-clip-device-id")).toBe("dev_clipmac00001");
    const got10MiB = await streamSha256AndBytes(bigGet.body!);
    expect(got10MiB.totalBytes).toBe(TEN_MIB);
    expect(got10MiB.chunkCount).toBeGreaterThan(100);
    expect(got10MiB.sha256Hex).toBe(expected10MiB.sha256Hex);

    // >10.5 MiB upload returns 413 PAYLOAD_TOO_LARGE with 0 R2 write
    const overId = ulidFor("01JDFC11P0VER000000000", 1);
    const overRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        authorization: `Bearer ${deskAToken}`,
        "content-type": "application/octet-stream",
        "content-length": String(MAX_BLOB + 1),
        "x-clip-id": overId,
        "x-clip-kid": CLIP_KID,
        "x-clip-kind": "image",
        "x-clip-meta-b64": b64("meta_over"),
      },
      body: createDeterministicStream(1024),
      duplex: "half",
    } as RequestInit);
    expect(overRes.status).toBe(413);
    expect(await overRes.json()).toMatchObject({ ok: false, error: { code: "PAYLOAD_TOO_LARGE" } });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${overId}.mnc1`)).toBeNull();

    // Content-Length mismatch (truncated AND over-streaming) returns 400 INVALID_ARGUMENT with 0 R2 orphan
    const truncId = ulidFor("01JDFC11PTRVN000000000", 1);
    const truncRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        authorization: `Bearer ${deskAToken}`,
        "content-type": "application/octet-stream",
        "content-length": "4096",
        "x-clip-id": truncId,
        "x-clip-kid": CLIP_KID,
        "x-clip-kind": "image",
        "x-clip-meta-b64": b64("meta_trunc"),
      },
      body: createDeterministicStream(512, 256),
      duplex: "half",
    } as RequestInit);
    expect(truncRes.status).toBe(400);
    expect(await truncRes.json()).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${truncId}.mnc1`)).toBeNull();

    const spoofId = ulidFor("01JDFC11PSP00F00000000", 1);
    const spoofRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        authorization: `Bearer ${deskAToken}`,
        "content-type": "application/octet-stream",
        "content-length": "1024",
        "x-clip-id": spoofId,
        "x-clip-kid": CLIP_KID,
        "x-clip-kind": "image",
        "x-clip-meta-b64": b64("meta_spoof"),
      },
      body: createDeterministicStream(8192, 512),
      duplex: "half",
    } as RequestInit);
    expect(spoofRes.status).toBe(400);
    expect(await spoofRes.json()).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${spoofId}.mnc1`)).toBeNull();

    // Idempotent retry of existing text clip & blob clip returns 200 without duplicating or evicting
    const replayTextId = ulidFor("01JDFC11P0000000000000", 103);
    const replayTextRes = await SELF.fetch("https://relay.test/v1/clip", {
      method: "POST",
      headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
      body: JSON.stringify({ clip_id: replayTextId, clip_kid: CLIP_KID, kind: "text", meta_envelope_b64: b64("MNC1_TEXT_103") }),
    });
    expect(replayTextRes.status).toBe(200);
    const replayBlobRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        authorization: `Bearer ${deskAToken}`,
        "content-type": "application/octet-stream",
        "content-length": String(TEN_MIB),
        "x-clip-id": bigClipId,
        "x-clip-kid": CLIP_KID,
        "x-clip-kind": "text",
        "x-clip-meta-b64": b64("MNC1_META_BLOB_50"),
      },
      body: createDeterministicStream(1024),
      duplex: "half",
    } as RequestInit);
    expect(replayBlobRes.status).toBe(200);
    expect(await replayBlobRes.json()).toMatchObject({ ok: true, clip_id: bigClipId, blob_bytes: TEN_MIB });

    // Inject DO registration failure on PUT /v1/clip/blob -> R2 blob rolled back with 0 orphans!
    const failId = ulidFor("01JDFC11PFA11000000000", 1);
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setFailNextClipBlobRegister(true));
    const failRes = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        authorization: `Bearer ${deskAToken}`,
        "content-type": "application/octet-stream",
        "content-length": "2048",
        "x-clip-id": failId,
        "x-clip-kid": CLIP_KID,
        "x-clip-kind": "image",
        "x-clip-meta-b64": b64("meta_fail"),
      },
      body: createDeterministicStream(2048, 512),
      duplex: "half",
    } as RequestInit);
    expect(failRes.status).toBe(503);
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${failId}.mnc1`)).toBeNull();

    // DELETE single blob item removes R2 object and broadcasts clip_cleared (scope: all)
    const delOneRes = await SELF.fetch(`https://relay.test/v1/clip/${bigClipId}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${deskAToken}` },
    });
    expect(delOneRes.status).toBe(200);
    expect(await delOneRes.json()).toMatchObject({ ok: true, deleted_count: 1, freed_bytes: TEN_MIB });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${bigClipId}.mnc1`)).toBeNull();
    await vi.waitFor(() => {
      expect(phoneMsgs.some((m) => m.type === "clip_cleared" && m.clip_id === bigClipId && m.scope === "all")).toBe(true);
    });

    // Zero changes to ops, block_keys, shred_marks, phone_snapshots, and R2 archives/ before alarm
    expect(await (await SELF.fetch("https://relay.test/v1/sync/pull?since=0", { headers: { authorization: `Bearer ${deskAToken}` } })).json()).toEqual(basePull);
    const midKeys = (await (await SELF.fetch("https://relay.test/v1/keys", { headers: { authorization: `Bearer ${deskAToken}` } })).json()) as {
      key_records: unknown[];
      shred_marks: unknown[];
      digest: string;
    };
    expect(midKeys.key_records).toEqual(baseKeys.key_records);
    expect(midKeys.shred_marks).toEqual(baseKeys.shred_marks);
    expect(midKeys.digest).toBe(baseKeys.digest);
    expect(
      new TextDecoder().decode(
        await (await SELF.fetch("https://relay.test/v1/snapshots/state", { headers: { authorization: `Bearer ${deskAToken}` } })).arrayBuffer(),
      ),
    ).toBe(baseSnap);
    expect((await env.ARCHIVE_BUCKET.list({ prefix: "archives/ops/" })).objects.map((o) => `${o.key}:${o.size}`).sort()).toEqual(baseOpsArchive);
    expect((await env.ARCHIVE_BUCKET.list({ prefix: "archives/keys/" })).objects.map((o) => `${o.key}:${o.size}`).sort()).toEqual(baseKeysArchive);

    // Advance virtual clock > 30 days and trigger DO alarm -> ALL clip_items + ALL clip/blobs/* purged
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(30 * DAY_MS + 60_000));
    await runDurableObjectAlarm(stub);

    const afterExpList = (await (await SELF.fetch("https://relay.test/v1/clip", { headers: { authorization: `Bearer ${deskAToken}` } })).json()) as { items: unknown[] };
    expect(afterExpList.items).toHaveLength(0);
    const remainingClipBlobs = await env.ARCHIVE_BUCKET.list({ prefix: "clip/blobs/" });
    expect(remainingClipBlobs.objects).toHaveLength(0);

    // Note ops archive STILL unchanged (zero clip leakage into archives/ops/)
    expect((await env.ARCHIVE_BUCKET.list({ prefix: "archives/ops/" })).objects.map((o) => `${o.key}:${o.size}`).sort()).toEqual(baseOpsArchive);

    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClipLimitsForTest({ maxItems: null, ttlMs: null, quotaBytes: null }));
    wsDeskB.close();
    wsPhone.close();
  });

  it("ephemeral: true performs 0 SQLite / 0 R2 writes, delivers only to other online read-write WS, and returns 409 NO_ONLINE_DESKTOP when none online", async () => {
    const deskAToken = "tok-eph-desk-a";
    const deskBToken = "tok-eph-desk-b";
    const phoneToken = "tok-eph-phone-rc";
    const scToken = "tok-eph-shortcut";
    const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("primary"));
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(0));
    await bootstrapDevice("MacEph", deskAToken, { deviceId: "dev_ephmaca00001" });
    await pairDevice(deskAToken, "OmarchyEph", "read-write", deskBToken);
    await pairDevice(deskAToken, "PhoneEph", "read+clip", phoneToken);
    const scDeviceId = await pairDevice(deskAToken, "ShortcutEph", "clip-write", scToken);

    // Connect ONLY Phone (read+clip) and DeskA (sender) — no other read-write desktop online
    const wsPhone = (await SELF.fetch("https://relay.test/v1/sync/ws", { headers: { authorization: `Bearer ${phoneToken}`, upgrade: "websocket" } })).webSocket!;
    wsPhone.accept();
    const phoneMsgs: string[] = [];
    wsPhone.addEventListener("message", (ev) => { phoneMsgs.push(String(ev.data)); });

    const wsDeskA = (await SELF.fetch("https://relay.test/v1/sync/ws", { headers: { authorization: `Bearer ${deskAToken}`, upgrade: "websocket" } })).webSocket!;
    wsDeskA.accept();
    const deskAMsgs: string[] = [];
    wsDeskA.addEventListener("message", (ev) => { deskAMsgs.push(String(ev.data)); });

    // DeskA sends ephemeral with only itself + read+clip phone connected -> 409 NO_ONLINE_DESKTOP
    const noDeskRes = await SELF.fetch("https://relay.test/v1/clip", {
      method: "POST",
      headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        clip_id: ulidFor("01JDFEPHEMERA100000000", 1),
        clip_kid: CLIP_KID,
        kind: "text",
        ephemeral: true,
        meta_envelope_b64: b64("MNC1_EPHEMERAL_SECRET"),
      }),
    });
    expect(noDeskRes.status).toBe(409);
    expect(await noDeskRes.json()).toMatchObject({ ok: false, error: { code: "NO_ONLINE_DESKTOP", retryable: true } });

    // Connect DeskB (read-write) WS
    const wsDeskB = (await SELF.fetch("https://relay.test/v1/sync/ws", { headers: { authorization: `Bearer ${deskBToken}`, upgrade: "websocket" } })).webSocket!;
    wsDeskB.accept();
    const deskBMsgs: Record<string, unknown>[] = [];
    wsDeskB.addEventListener("message", (ev) => { deskBMsgs.push(JSON.parse(String(ev.data)) as Record<string, unknown>); });

    // Advance virtual clock so any accidental UPDATE devices SET last_seen_at_ms would be immediately detected
    const beforeState = await runInDurableObject(stub, (_inst, state) => {
      const lastSeen = state.storage.sql.exec(`SELECT last_seen_at_ms FROM devices WHERE device_id = ?`, scDeviceId).toArray()[0]?.last_seen_at_ms;
      const clipCount = Number(state.storage.sql.exec(`SELECT COUNT(*) AS c FROM clip_items`).toArray()[0]?.c ?? 0);
      return { lastSeen, clipCount };
    });
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(500_000));

    // Shortcut (clip-write) sends 256 KiB exact boundary ephemeral payload -> 200 delivered to DeskA + DeskB (2), NOT Phone
    const maxEphBytes = new Uint8Array(256 * 1024);
    maxEphBytes.fill(0x5a);
    const maxEphB64 = bytesToB64(maxEphBytes);
    const ephId = ulidFor("01JDFEPHEMERA100000000", 2);
    const okRes = await SELF.fetch("https://relay.test/v1/clip", {
      method: "POST",
      headers: { authorization: `Bearer ${scToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        clip_id: ephId,
        clip_kid: CLIP_KID,
        kind: "text",
        ephemeral: true,
        meta_envelope_b64: maxEphB64,
      }),
    });
    expect(okRes.status).toBe(200);
    expect(await okRes.json()).toEqual({ ok: true, clip_id: ephId, delivered_to: 2 });

    await vi.waitFor(() => {
      expect(deskBMsgs.some((m) => m.type === "clip_ephemeral" && m.clip_id === ephId && m.device_id === scDeviceId && m.envelope_b64 === maxEphB64)).toBe(true);
      expect(deskAMsgs.some((m) => m.includes(ephId))).toBe(true);
    });
    expect(phoneMsgs.some((m) => m.includes("clip_ephemeral"))).toBe(false);

    // Prove ZERO SQLite writes (clip_items still 0 AND Shortcut last_seen_at_ms untouched!) and ZERO R2 writes
    const afterState = await runInDurableObject(stub, (_inst, state) => {
      const lastSeen = state.storage.sql.exec(`SELECT last_seen_at_ms FROM devices WHERE device_id = ?`, scDeviceId).toArray()[0]?.last_seen_at_ms;
      const clipCount = Number(state.storage.sql.exec(`SELECT COUNT(*) AS c FROM clip_items`).toArray()[0]?.c ?? 0);
      return { lastSeen, clipCount };
    });
    expect(afterState.clipCount).toBe(beforeState.clipCount);
    expect(afterState.lastSeen).toBe(beforeState.lastSeen);
    expect((await env.ARCHIVE_BUCKET.list({ prefix: "clip/blobs/" })).objects).toHaveLength(0);

    // 256 KiB + 1 B ephemeral payload rejected with 413 PAYLOAD_TOO_LARGE
    const overEphBytes = new Uint8Array(256 * 1024 + 1);
    const overEphRes = await SELF.fetch("https://relay.test/v1/clip", {
      method: "POST",
      headers: { authorization: `Bearer ${scToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        clip_id: ulidFor("01JDFEPHEMERA100000000", 3),
        clip_kid: CLIP_KID,
        kind: "text",
        ephemeral: true,
        meta_envelope_b64: bytesToB64(overEphBytes),
      }),
    });
    expect(overEphRes.status).toBe(413);
    expect(await overEphRes.json()).toMatchObject({ ok: false, error: { code: "PAYLOAD_TOO_LARGE" } });

    wsDeskA.close();
    wsDeskB.close();
    wsPhone.close();
  });

  it("SEC-09: enforces full 4-state token scope matrix across all note, key, shred, snapshot, device, WS, and clip endpoints", async () => {
    const rwToken = "tok-sec09-rw";
    const rcToken = "tok-sec09-readclip";
    const cwToken = "tok-sec09-clipwrite";
    const roToken = "tok-sec09-read";

    const boot = await bootstrapDevice("MacSec09", rwToken);
    const rcId = await pairDevice(rwToken, "PhoneRC", "read+clip", rcToken);
    await pairDevice(rwToken, "ShortcutCW", "clip-write", cwToken);
    await pairDevice(rwToken, "PhoneRO", "read", roToken);

    // Reject unknown scope on POST /v1/devices
    const badScope = await SELF.fetch("https://relay.test/v1/devices", {
      method: "POST",
      headers: { authorization: `Bearer ${rwToken}`, "content-type": "application/json" },
      body: JSON.stringify({ device_name: "Bad", scope: "super-admin", token_sha256_hex: await sha256Hex("bad"), ciphertext_b64: b64("x") }),
    });
    expect(badScope.status).toBe(400);

    // Ensure a mobile snapshot exists so GET /v1/snapshots/state returns 200 for authorized scopes
    const snapCheck = await SELF.fetch("https://relay.test/v1/snapshots/state", { headers: { authorization: `Bearer ${rwToken}` } });
    if (snapCheck.status === 404) {
      expect(
        (
          await SELF.fetch("https://relay.test/v1/snapshots/state", {
            method: "PUT",
            headers: { authorization: `Bearer ${rwToken}`, "x-journal-epoch": boot.epoch, "x-covers-seq": "0", "x-snapshot-id": "snap0" },
            body: new TextEncoder().encode("MNP1_0"),
          })
        ).status,
      ).toBe(200);
    }

    const seedBlobId = ulidFor("01JDFSEC09B10B00000000", 1);
    const cwPut = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        authorization: `Bearer ${cwToken}`,
        "content-type": "application/octet-stream",
        "content-length": "16",
        "x-clip-id": seedBlobId,
        "x-clip-kid": CLIP_KID,
        "x-clip-kind": "image",
        "x-clip-meta-b64": b64("meta_cw"),
      },
      body: new Uint8Array(16).fill(1),
    });
    expect(cwPut.status).toBe(200);

    // Reject invalid X-Clip-Kind (e.g. image/svg+xml)
    const badKind = await SELF.fetch("https://relay.test/v1/clip/blob", {
      method: "PUT",
      headers: {
        authorization: `Bearer ${cwToken}`,
        "content-type": "application/octet-stream",
        "content-length": "16",
        "x-clip-id": ulidFor("01JDFSEC09SVG000000000", 1),
        "x-clip-kid": CLIP_KID,
        "x-clip-kind": "image/svg+xml",
        "x-clip-meta-b64": b64("meta_svg"),
      },
      body: new Uint8Array(16).fill(2),
    });
    expect(badKind.status).toBe(400);

    const cwTextId = ulidFor("01JDFSEC09TEXT00000000", 1);
    expect(
      (
        await SELF.fetch("https://relay.test/v1/clip", {
          method: "POST",
          headers: { authorization: `Bearer ${cwToken}`, "content-type": "application/json" },
          body: JSON.stringify({ clip_id: cwTextId, clip_kid: CLIP_KID, kind: "text", meta_envelope_b64: b64("cw_text") }),
        })
      ).status,
    ).toBe(200);

    const expectForbidden = async (token: string, method: string, path: string, body?: BodyInit | null, extraHeaders?: Record<string, string>) => {
      const res = await SELF.fetch(`https://relay.test${path}`, {
        method,
        headers: { authorization: `Bearer ${token}`, ...(extraHeaders ?? {}) },
        ...(body !== undefined && body !== null ? { body } : {}),
      });
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(await res.json(), `${method} ${path}`).toMatchObject({ ok: false, error: { code: "TOKEN_SCOPE_FORBIDDEN" } });
    };

    const noteWriteEndpoints: [string, string, BodyInit | null, Record<string, string>?][] = [
      ["POST", "/v1/sync/push", JSON.stringify({ expected_epoch: boot.epoch, ops: [] }), { "content-type": "application/json" }],
      ["POST", "/v1/keys", JSON.stringify({ key_records: [] }), { "content-type": "application/json" }],
      ["POST", "/v1/keys/shred", JSON.stringify({ seen_seq: 0, marks: [] }), { "content-type": "application/json" }],
      ["POST", "/v1/keys/cancel", JSON.stringify({ key_ids: [] }), { "content-type": "application/json" }],
      ["POST", "/v1/keys/confirm", JSON.stringify({ key_ids: [], grace_ms: DAY_MS }), { "content-type": "application/json" }],
      ["PUT", "/v1/snapshots/state", new Uint8Array([1, 2, 3]), { "x-journal-epoch": boot.epoch, "x-covers-seq": "0" }],
      ["POST", "/v1/devices", JSON.stringify({ device_name: "X", scope: "read", token_sha256_hex: await sha256Hex("x"), ciphertext_b64: b64("x") }), { "content-type": "application/json" }],
      ["POST", `/v1/devices/${rcId}/refresh`, JSON.stringify({ ciphertext_b64: b64("x") }), { "content-type": "application/json" }],
      ["GET", "/v1/devices", null],
      ["DELETE", `/v1/devices/${rcId}`, null],
    ];

    // 1. clip-write MUST get 403 on ALL GETs, ALL DELETEs, POST /v1/clip/prune, WS upgrade, and ALL note/key/shred/snapshot/device routes
    for (const [m, p, body, hdrs] of [
      ["GET", "/v1/clip", null],
      ["GET", `/v1/clip/${seedBlobId}/blob`, null],
      ["POST", "/v1/clip/prune", JSON.stringify({ kind: "image" }), { "content-type": "application/json" }],
      ["DELETE", `/v1/clip/${seedBlobId}`, null],
      ["DELETE", "/v1/clip", null],
      ["GET", "/v1/sync/pull?since=0", null],
      ["GET", "/v1/sync/ws", null, { upgrade: "websocket" }],
      ["GET", "/v1/keys", null],
      ["GET", "/v1/snapshots/state", null],
      ...noteWriteEndpoints,
    ] as [string, string, BodyInit | null, Record<string, string>?][]) {
      await expectForbidden(cwToken, m, p, body, hdrs);
    }

    // 2. read+clip ALLOWED on read routes + WS + all /v1/clip* routes, FORBIDDEN on all note/key/shred/snapshot/device writes
    expect((await SELF.fetch("https://relay.test/v1/sync/pull?since=0", { headers: { authorization: `Bearer ${rcToken}` } })).status).toBe(200);
    expect((await SELF.fetch("https://relay.test/v1/keys", { headers: { authorization: `Bearer ${rcToken}` } })).status).toBe(200);
    expect((await SELF.fetch("https://relay.test/v1/snapshots/state", { headers: { authorization: `Bearer ${rcToken}` } })).status).toBe(200);
    const rcWs = await SELF.fetch("https://relay.test/v1/sync/ws", { headers: { authorization: `Bearer ${rcToken}`, upgrade: "websocket" } });
    expect(rcWs.status).toBe(101);
    rcWs.webSocket?.accept();
    rcWs.webSocket?.close();

    const rcTextId = ulidFor("01JDFSEC09RC0000000000", 1);
    expect(
      (
        await SELF.fetch("https://relay.test/v1/clip", {
          method: "POST",
          headers: { authorization: `Bearer ${rcToken}`, "content-type": "application/json" },
          body: JSON.stringify({ clip_id: rcTextId, clip_kid: CLIP_KID, kind: "text", meta_envelope_b64: b64("rc_text") }),
        })
      ).status,
    ).toBe(200);
    expect((await SELF.fetch("https://relay.test/v1/clip", { headers: { authorization: `Bearer ${rcToken}` } })).status).toBe(200);
    expect((await SELF.fetch(`https://relay.test/v1/clip/${seedBlobId}/blob`, { headers: { authorization: `Bearer ${rcToken}` } })).status).toBe(200);
    expect((await SELF.fetch(`https://relay.test/v1/clip/${rcTextId}`, { method: "DELETE", headers: { authorization: `Bearer ${rcToken}` } })).status).toBe(200);

    for (const [m, p, body, hdrs] of noteWriteEndpoints) {
      await expectForbidden(rcToken, m, p, body, hdrs);
    }

    // 3. read ALLOWED on read routes + GET /v1/clip* + WS, FORBIDDEN on clip write/delete and all note/key/shred/snapshot/device writes
    expect((await SELF.fetch("https://relay.test/v1/clip", { headers: { authorization: `Bearer ${roToken}` } })).status).toBe(200);
    expect((await SELF.fetch(`https://relay.test/v1/clip/${seedBlobId}/blob`, { headers: { authorization: `Bearer ${roToken}` } })).status).toBe(200);

    await expectForbidden(roToken, "POST", "/v1/clip", JSON.stringify({ clip_id: ulidFor("01JDFSEC09R00000000000", 1), clip_kid: CLIP_KID, kind: "text", meta_envelope_b64: b64("x") }), { "content-type": "application/json" });
    await expectForbidden(roToken, "PUT", "/v1/clip/blob", new Uint8Array([1, 2, 3]), {
      "content-type": "application/octet-stream",
      "content-length": "3",
      "x-clip-id": ulidFor("01JDFSEC09R00000000000", 2),
      "x-clip-kid": CLIP_KID,
      "x-clip-kind": "image",
      "x-clip-meta-b64": b64("x"),
    });
    await expectForbidden(roToken, "DELETE", `/v1/clip/${seedBlobId}`, null);
    await expectForbidden(roToken, "DELETE", "/v1/clip", null);
    await expectForbidden(roToken, "POST", "/v1/clip/prune", JSON.stringify({ kind: "image" }), { "content-type": "application/json" });
    for (const [m, p, body, hdrs] of noteWriteEndpoints) {
      await expectForbidden(roToken, m, p, body, hdrs);
    }

    // 4. read+clip can DELETE /v1/clip (clear all) and removes remaining blob from R2
    const clearAll = await SELF.fetch("https://relay.test/v1/clip", { method: "DELETE", headers: { authorization: `Bearer ${rcToken}` } });
    expect(clearAll.status).toBe(200);
    expect(await clearAll.json()).toMatchObject({ ok: true, deleted_count: 2 });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${seedBlobId}.mnc1`)).toBeNull();
  });

  it("POST /v1/keys supports monotonic clip_key CAS + clear_clips: true without altering computeKeysDigest", async () => {
    const deskAToken = "tok-ck-desk-a";
    const deskBToken = "tok-ck-desk-b";
    await bootstrapDevice("MacCK", deskAToken);
    await pairDevice(deskAToken, "OmarchyCK", "read-write", deskBToken);

    const k0 = (await (await SELF.fetch("https://relay.test/v1/keys", { headers: { authorization: `Bearer ${deskAToken}` } })).json()) as {
      key_material: { keyring: unknown; vault_header: unknown; clip_key: unknown };
      digest: string;
    };
    expect(k0.key_material.clip_key).toBeNull();

    // Seed a text clip + a blob clip
    const blobId = ulidFor("01JDFCKB10B00000000000", 1);
    expect(
      (
        await SELF.fetch("https://relay.test/v1/clip/blob", {
          method: "PUT",
          headers: {
            authorization: `Bearer ${deskAToken}`,
            "content-type": "application/octet-stream",
            "content-length": "32",
            "x-clip-id": blobId,
            "x-clip-kid": CLIP_KID,
            "x-clip-kind": "image",
            "x-clip-meta-b64": b64("ck_meta"),
          },
          body: new Uint8Array(32).fill(7),
        })
      ).status,
    ).toBe(200);
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${blobId}.mnc1`)).not.toBeNull();

    const wsDeskB = (await SELF.fetch("https://relay.test/v1/sync/ws", { headers: { authorization: `Bearer ${deskBToken}`, upgrade: "websocket" } })).webSocket!;
    wsDeskB.accept();
    const deskBMsgs: Record<string, unknown>[] = [];
    wsDeskB.addEventListener("message", (ev) => { deskBMsgs.push(JSON.parse(String(ev.data)) as Record<string, unknown>); });

    // Set clip_key gen=1 -> digest MUST stay byte-identical
    const ck1 = b64("clip_key_material_v1");
    const r1 = await SELF.fetch("https://relay.test/v1/keys", {
      method: "POST",
      headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
      body: JSON.stringify({ key_material: { clip_key: { gen: 1, blob_b64: ck1 } } }),
    });
    expect(r1.status).toBe(200);
    expect(await r1.json()).toMatchObject({ ok: true, key_material_gens: { clip_key: 1 } });

    const k1 = (await (await SELF.fetch("https://relay.test/v1/keys", { headers: { authorization: `Bearer ${deskAToken}` } })).json()) as {
      key_material: { clip_key: { gen: number; blob_b64: string } | null };
      digest: string;
    };
    expect(k1.key_material.clip_key).toEqual({ gen: 1, blob_b64: ck1 });
    expect(k1.digest).toBe(k0.digest);

    // Same gen different blob -> 409 INTEGRITY_ERROR; lower gen -> 409 CAS_MISMATCH
    expect(
      (
        await SELF.fetch("https://relay.test/v1/keys", {
          method: "POST",
          headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
          body: JSON.stringify({ key_material: { clip_key: { gen: 1, blob_b64: b64("conflict") } } }),
        })
      ).status,
    ).toBe(409);
    const stale = await SELF.fetch("https://relay.test/v1/keys", {
      method: "POST",
      headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
      body: JSON.stringify({ key_material: { clip_key: { gen: 0, blob_b64: ck1 } } }),
    });
    expect(stale.status).toBe(409);
    expect(await stale.json()).toMatchObject({ ok: false, error: { code: "CAS_MISMATCH" } });

    // Rotate clip_key gen=2 with clear_clips: true -> clears clip_items + R2 blobs + broadcasts clip_cleared
    const ck2 = b64("clip_key_material_v2");
    const r2 = await SELF.fetch("https://relay.test/v1/keys", {
      method: "POST",
      headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
      body: JSON.stringify({ key_material: { clip_key: { gen: 2, blob_b64: ck2 } }, clear_clips: true }),
    });
    expect(r2.status).toBe(200);
    expect(await r2.json()).toMatchObject({ ok: true, key_material_gens: { clip_key: 2 } });

    const k2 = (await (await SELF.fetch("https://relay.test/v1/keys", { headers: { authorization: `Bearer ${deskAToken}` } })).json()) as {
      key_material: { clip_key: { gen: number; blob_b64: string } | null };
      digest: string;
    };
    expect(k2.key_material.clip_key).toEqual({ gen: 2, blob_b64: ck2 });
    expect(k2.digest).toBe(k0.digest);

    expect(((await (await SELF.fetch("https://relay.test/v1/clip", { headers: { authorization: `Bearer ${deskAToken}` } })).json()) as { items: unknown[] }).items).toHaveLength(0);
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${blobId}.mnc1`)).toBeNull();
    await vi.waitFor(() => {
      expect(deskBMsgs.some((m) => m.type === "clip_cleared" && m.clip_id === null)).toBe(true);
    });

    wsDeskB.close();
  });

  it("live M2 -> M4 DO schema migration preserves existing devices, pairing_tickets, and key_material while upgrading CHECK constraints idempotently", async () => {
    const migStub = env.SYNC_DO.get(env.SYNC_DO.idFromName("live-m2-to-m4-migration"));
    const oldMacToken = "tok-legacy-m2-mac";
    const oldPhoneToken = "tok-legacy-m2-phone";
    const oldMacHash = await sha256Hex(oldMacToken);
    const oldPhoneHash = await sha256Hex(oldPhoneToken);
    const now = Date.now();

    // Seed exact old M2 production schema & live rows (including FK from pairing_tickets -> devices)
    const preCheck = await runInDurableObject(migStub, (_inst, state) => {
      const sql = state.storage.sql;
      sql.exec(`
        DROP TABLE IF EXISTS clip_items;
        DROP TABLE IF EXISTS pairing_tickets;
        DROP TABLE IF EXISTS devices;
        DROP TABLE IF EXISTS key_material;
        CREATE TABLE devices (device_id TEXT PRIMARY KEY, device_name TEXT NOT NULL, token_sha256_hex TEXT NOT NULL UNIQUE, scope TEXT NOT NULL CHECK (scope IN ('read', 'read-write')), last_pulled_seq INTEGER NOT NULL DEFAULT 0, last_seen_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, claimed_at_ms INTEGER, revoked_at_ms INTEGER);
        CREATE TABLE pairing_tickets (pair_id TEXT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'pair' CHECK (kind IN ('pair', 'refresh')), device_id TEXT NOT NULL REFERENCES devices(device_id), scope TEXT NOT NULL CHECK (scope IN ('read', 'read-write')), ciphertext BLOB NOT NULL, created_by TEXT NOT NULL, expires_at_ms INTEGER NOT NULL);
        CREATE TABLE key_material (kind TEXT PRIMARY KEY CHECK (kind IN ('keyring', 'vault_header')), gen INTEGER NOT NULL, blob BLOB NOT NULL, updated_at_ms INTEGER NOT NULL);
      `);
      sql.exec(
        `INSERT INTO devices (device_id, device_name, token_sha256_hex, scope, last_pulled_seq, last_seen_at_ms, created_at_ms, claimed_at_ms, revoked_at_ms) VALUES (?, ?, ?, 'read-write', 42, ?, ?, ?, NULL)`,
        "dev_m2mac000001", "LegacyMac", oldMacHash, now, now - 1000, now - 1000,
      );
      sql.exec(
        `INSERT INTO devices (device_id, device_name, token_sha256_hex, scope, last_pulled_seq, last_seen_at_ms, created_at_ms, claimed_at_ms, revoked_at_ms) VALUES (?, ?, ?, 'read', 0, ?, ?, NULL, NULL)`,
        "dev_m2phone0001", "LegacyPhone", oldPhoneHash, now, now,
      );
      sql.exec(
        `INSERT INTO pairing_tickets (pair_id, kind, device_id, scope, ciphertext, created_by, expires_at_ms) VALUES (?, 'pair', ?, 'read', ?, ?, ?)`,
        "legacy_pair_ticket_01", "dev_m2phone0001", new TextEncoder().encode("legacy_ct"), "dev_m2mac000001", now + 600_000,
      );
      sql.exec(
        `INSERT INTO key_material (kind, gen, blob, updated_at_ms) VALUES ('keyring', 3, ?, ?), ('vault_header', 1700000000000, ?, ?)`,
        new TextEncoder().encode("legacy_kr"), now, new TextEncoder().encode("legacy_vh"), now,
      );

      // Verify old M2 CHECK constraints actively reject new M4 values before migration
      let scopeRejected = false;
      try {
        sql.exec(`INSERT INTO devices (device_id, device_name, token_sha256_hex, scope, last_seen_at_ms, created_at_ms) VALUES ('dev_bad1', 'X', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'read+clip', 1, 1)`);
      } catch {
        scopeRejected = true;
      }
      let kmRejected = false;
      try {
        sql.exec(`INSERT INTO key_material (kind, gen, blob, updated_at_ms) VALUES ('clip_key', 1, X'01', 1)`);
      } catch {
        kmRejected = true;
      }
      return { scopeRejected, kmRejected };
    });
    expect(preCheck).toEqual({ scopeRejected: true, kmRejected: true });

    // Run initSchema() migration twice to prove upgrade + idempotency
    const postMig = await runInDurableObject(migStub, (inst, state) => {
      (inst as SyncJournalDO).runInitSchemaForTest();
      (inst as SyncJournalDO).runInitSchemaForTest();
      const sql = state.storage.sql;
      const ddl = (name: string) => String(sql.exec(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, name).toArray()[0]?.sql ?? "");
      return {
        devDdl: ddl("devices"),
        pairDdl: ddl("pairing_tickets"),
        kmDdl: ddl("key_material"),
        clipDdl: ddl("clip_items"),
        devices: sql.exec(`SELECT device_id, scope, last_pulled_seq, claimed_at_ms FROM devices ORDER BY device_id`).toArray(),
        tickets: sql.exec(`SELECT pair_id, device_id, scope FROM pairing_tickets`).toArray(),
        keyMaterial: sql.exec(`SELECT kind, gen FROM key_material ORDER BY kind`).toArray(),
      };
    });

    expect(postMig.devDdl).toContain("'read+clip'");
    expect(postMig.devDdl).toContain("'clip-write'");
    expect(postMig.pairDdl).toContain("'read+clip'");
    expect(postMig.pairDdl).toContain("REFERENCES devices(device_id)");
    expect(postMig.kmDdl).toContain("'clip_key'");
    expect(postMig.clipDdl).toContain("clip_items");
    expect(postMig.devices).toEqual([
      { device_id: "dev_m2mac000001", scope: "read-write", last_pulled_seq: 42, claimed_at_ms: now - 1000 },
      { device_id: "dev_m2phone0001", scope: "read", last_pulled_seq: 0, claimed_at_ms: null },
    ]);
    expect(postMig.tickets).toEqual([{ pair_id: "legacy_pair_ticket_01", device_id: "dev_m2phone0001", scope: "read" }]);
    expect(postMig.keyMaterial).toEqual([
      { kind: "keyring", gen: 3 },
      { kind: "vault_header", gen: 1700000000000 },
    ]);

    // Verify migrated DO works end-to-end over HTTP with existing rows AND new M4 scopes/clip_key/clip_items
    const legacyClaim = await migStub.fetch("https://relay.test/v1/devices/pair-claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pair_id: "legacy_pair_ticket_01" }),
    });
    expect(legacyClaim.status).toBe(200);

    const newRcToken = "tok-migrated-rc";
    const newCwToken = "tok-migrated-cw";
    await pairDevice(oldMacToken, "MigratedPhoneRC", "read+clip", newRcToken, { fetcher: migStub });
    await pairDevice(oldMacToken, "MigratedShortcutCW", "clip-write", newCwToken, { fetcher: migStub });

    const setCk = await migStub.fetch("https://relay.test/v1/keys", {
      method: "POST",
      headers: { authorization: `Bearer ${oldMacToken}`, "content-type": "application/json" },
      body: JSON.stringify({ key_material: { clip_key: { gen: 1, blob_b64: b64("migrated_ck") } } }),
    });
    expect(setCk.status).toBe(200);

    const keysAfter = (await (await migStub.fetch("https://relay.test/v1/keys", { headers: { authorization: `Bearer ${oldMacToken}` } })).json()) as {
      key_material: { keyring: { gen: number }; vault_header: { gen: number }; clip_key: { gen: number } };
    };
    expect(keysAfter.key_material.keyring.gen).toBe(3);
    expect(keysAfter.key_material.vault_header.gen).toBe(1700000000000);
    expect(keysAfter.key_material.clip_key.gen).toBe(1);

    const postClip = await migStub.fetch("https://relay.test/v1/clip", {
      method: "POST",
      headers: { authorization: `Bearer ${newCwToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        clip_id: ulidFor("01JDFM1GRATED000000000", 1),
        clip_kid: CLIP_KID,
        kind: "text",
        meta_envelope_b64: b64("migrated_clip"),
      }),
    });
    expect(postClip.status).toBe(200);
  });

  it("D8': enforces hard cloud blob quota (507 CLIP_QUOTA_EXCEEDED), allows text while full, supports POST /v1/clip/prune and scoped DELETE /v1/clip", async () => {
    const deskAToken = "tok-d8p-desk-a";
    const deskBToken = "tok-d8p-desk-b";
    const phoneToken = "tok-d8p-phone-rc";
    const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("d8-prime-quota-prune"));
    await bootstrapDevice("MacD8P", deskAToken, { deviceId: "dev_d8pmac000001", fetcher: stub });
    await pairDevice(deskAToken, "LinuxD8P", "read-write", deskBToken, { fetcher: stub });
    await pairDevice(deskAToken, "PhoneD8P", "read+clip", phoneToken, { fetcher: stub });

    // Set a tight 5000 B quota via test hook so we can test exact 507 boundary fast
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClipLimitsForTest({ maxItems: 1000, quotaBytes: 5000 }));

    const wsDeskBRes = await stub.fetch("https://relay.test/v1/sync/ws", {
      headers: { authorization: `Bearer ${deskBToken}`, upgrade: "websocket" },
    });
    const wsDeskB = wsDeskBRes.webSocket!;
    wsDeskB.accept();
    const deskBMsgs: Record<string, unknown>[] = [];
    wsDeskB.addEventListener("message", (ev) => { deskBMsgs.push(JSON.parse(String(ev.data)) as Record<string, unknown>); });

    const putBlob = (id: string, size: number, kind: "image" | "text" = "image") =>
      stub.fetch("https://relay.test/v1/clip/blob", {
        method: "PUT",
        headers: {
          authorization: `Bearer ${deskAToken}`,
          "content-type": "application/octet-stream",
          "content-length": String(size),
          "x-clip-id": id,
          "x-clip-kid": CLIP_KID,
          "x-clip-kind": kind,
          "x-clip-meta-b64": b64(`meta_${id}`),
        },
        body: new Uint8Array(size).fill(3),
      });

    const b1 = ulidFor("01JDFD8PQV0TA000000000", 1);
    const b2 = ulidFor("01JDFD8PQV0TA000000000", 2);
    const b3 = ulidFor("01JDFD8PQV0TA000000000", 3);
    const t1 = ulidFor("01JDFD8PQV0TA000000000", 4);

    // Upload 2 x 2000 B blobs = 4000 B / 5000 B
    expect((await putBlob(b1, 2000, "image")).status).toBe(200);
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(10_000));
    const r2 = await putBlob(b2, 2000, "image");
    expect(r2.status).toBe(200);
    expect(await r2.json()).toMatchObject({ ok: true, quota: { used_bytes: 4000, limit_bytes: 5000, item_count: 2, item_limit: 1000 } });

    // 3rd blob (2000 B -> 6000 > 5000) MUST return 507 CLIP_QUOTA_EXCEEDED with 0 R2 write
    const r3 = await putBlob(b3, 2000, "image");
    expect(r3.status).toBe(507);
    expect(await r3.json()).toMatchObject({
      ok: false,
      error: {
        code: "CLIP_QUOTA_EXCEEDED",
        retryable: false,
        details: { used_bytes: 4000, limit_bytes: 5000, incoming_bytes: 2000 },
      },
    });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${b3}.mnc1`)).toBeNull();

    // Small inline text POST /v1/clip MUST STILL SUCCEED even when blob quota is nearly full
    const rt1 = await stub.fetch("https://relay.test/v1/clip", {
      method: "POST",
      headers: { authorization: `Bearer ${deskAToken}`, "content-type": "application/json" },
      body: JSON.stringify({ clip_id: t1, clip_kid: CLIP_KID, kind: "text", meta_envelope_b64: b64("small_text_ok") }),
    });
    expect(rt1.status).toBe(200);

    // Dry-run prune keeping latest 1 image matches b1 (2000 B) without deleting anything
    const dryRes = await stub.fetch("https://relay.test/v1/clip/prune", {
      method: "POST",
      headers: { authorization: `Bearer ${phoneToken}`, "content-type": "application/json" },
      body: JSON.stringify({ kind: "image", keep_latest: 1, dry_run: true }),
    });
    expect(dryRes.status).toBe(200);
    expect(await dryRes.json()).toMatchObject({ ok: true, dry_run: true, matched_count: 1, deleted_count: 0, freed_bytes: 2000 });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${b1}.mnc1`)).not.toBeNull();

    // Execute prune keeping latest 1 image -> frees b1 (2000 B), keeps b2 + t1, broadcasts scope='cloud'
    const pruneRes = await stub.fetch("https://relay.test/v1/clip/prune", {
      method: "POST",
      headers: { authorization: `Bearer ${phoneToken}`, "content-type": "application/json" },
      body: JSON.stringify({ kind: "image", keep_latest: 1 }),
    });
    expect(pruneRes.status).toBe(200);
    expect(await pruneRes.json()).toMatchObject({
      ok: true,
      dry_run: false,
      matched_count: 1,
      deleted_count: 1,
      freed_bytes: 2000,
      quota: { used_bytes: 2000, limit_bytes: 5000, item_count: 2, item_limit: 1000 },
    });
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${b1}.mnc1`)).toBeNull();
    expect(await env.ARCHIVE_BUCKET.head(`clip/blobs/${b2}.mnc1`)).not.toBeNull();
    await vi.waitFor(() => {
      expect(deskBMsgs.some((m) => m.type === "clip_cleared" && m.clip_id === null && m.scope === "cloud" && m.pruned === true)).toBe(true);
    });

    // Now b3 (2000 B -> 4000 <= 5000) succeeds!
    expect((await putBlob(b3, 2000, "image")).status).toBe(200);

    // DELETE /v1/clip defaults to scope='cloud' (protects desktop local archive); explicit ?scope=all broadcasts scope='all'
    const clearCloudRes = await stub.fetch("https://relay.test/v1/clip", {
      method: "DELETE",
      headers: { authorization: `Bearer ${phoneToken}` },
    });
    expect(clearCloudRes.status).toBe(200);
    expect(await clearCloudRes.json()).toMatchObject({ ok: true, deleted_count: 3, freed_bytes: 4000, scope: "cloud" });
    await vi.waitFor(() => {
      expect(deskBMsgs.some((m) => m.type === "clip_cleared" && m.clip_id === null && m.scope === "cloud" && !m.pruned)).toBe(true);
    });

    const clearAllRes = await stub.fetch("https://relay.test/v1/clip?scope=all", {
      method: "DELETE",
      headers: { authorization: `Bearer ${deskAToken}` },
    });
    expect(clearAllRes.status).toBe(200);
    expect(await clearAllRes.json()).toMatchObject({ ok: true, deleted_count: 0, scope: "all" });
    await vi.waitFor(() => {
      expect(deskBMsgs.some((m) => m.type === "clip_cleared" && m.clip_id === null && m.scope === "all")).toBe(true);
    });

    wsDeskB.close();
  });
});
