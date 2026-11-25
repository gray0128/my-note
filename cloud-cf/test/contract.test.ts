import { env, SELF, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import { encode } from "@msgpack/msgpack";
import type { SyncJournalDO } from "../src/index";

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64(text: string): string {
  return btoa(text);
}

async function bootstrapDevice(deviceName: string, token: string, opts: { deviceId?: string; revokeExisting?: boolean } = {}) {
  const res = await SELF.fetch("https://relay.test/v1/devices/bootstrap", {
    method: "POST",
    headers: { authorization: "Bearer test-bootstrap-secret-token", "content-type": "application/json" },
    body: JSON.stringify({
      device_name: deviceName,
      token_sha256_hex: await sha256Hex(token),
      device_id: opts.deviceId,
      revoke_existing: opts.revokeExisting,
    }),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { ok: boolean; device_id: string; scope: string; epoch: string };
}

describe("cloud-cf M1 Thin Blind Sync Relay Contract Suite (real workerd)", () => {
  it("handles 500-op batch push (>100 SQL bind params), idempotent replay, and atomic KEY_UNKNOWN rollback", async () => {
    const token = "tok-batch-500";
    const boot = await bootstrapDevice("MacBook", token);

    const ops = Array.from({ length: 500 }, (_, i) => ({
      op_id: `01JDF910A2B3C4D5E6F7${String(i).padStart(6, "0")}`,
      key_id: "01JDF8Z9X4K7M2N5P8Q1R3S6T1",
      envelope_b64: b64(`mns1_payload_${i}`),
    }));

    const pushRes = await SELF.fetch("https://relay.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        expected_epoch: boot.epoch,
        key_records: [{ key_id: "01JDF8Z9X4K7M2N5P8Q1R3S6T1", wrap_gen: 1, key_record_b64: b64("mnr1_key_1") }],
        ops,
      }),
    });
    expect(pushRes.status).toBe(200);
    const pushJson = (await pushRes.json()) as { ok: boolean; epoch: string; acked: { op_id: string; seq: number }[]; head_seq: number };
    expect(pushJson.ok).toBe(true);
    expect(pushJson.acked).toHaveLength(500);
    expect(pushJson.head_seq).toBe(500);

    // Idempotent replay of first 10 ops returns exact same seqs and does not advance head_seq
    const replayRes = await SELF.fetch("https://relay.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ expected_epoch: boot.epoch, ops: ops.slice(0, 10) }),
    });
    expect(replayRes.status).toBe(200);
    const replayJson = (await replayRes.json()) as { acked: { op_id: string; seq: number }[]; head_seq: number };
    expect(replayJson.acked).toEqual(pushJson.acked.slice(0, 10));
    expect(replayJson.head_seq).toBe(500);

    // Atomic KEY_UNKNOWN rollback: valid op + unknown-key op must roll back ENTIRE batch
    const badRes = await SELF.fetch("https://relay.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        expected_epoch: boot.epoch,
        ops: [
          { op_id: "01JDF910A2B3C4D5E6F7999991", key_id: "01JDF8Z9X4K7M2N5P8Q1R3S6T1", envelope_b64: b64("valid_before_bad") },
          { op_id: "01JDF910A2B3C4D5E6F7999992", key_id: "01JDF8Z9X4K7M2N5P8Q1R3S699", envelope_b64: b64("unknown_key_op") },
        ],
      }),
    });
    expect(badRes.status).toBe(409);
    expect(await badRes.json()).toMatchObject({ ok: false, error: { code: "KEY_UNKNOWN" } });

    const pullCheck = await SELF.fetch("https://relay.test/v1/sync/pull?since=498", {
      headers: { authorization: `Bearer ${token}` },
    });
    const pullJson = (await pullCheck.json()) as { ops: unknown[]; head_seq: number };
    expect(pullJson.head_seq).toBe(500);
    expect(pullJson.ops).toHaveLength(2);
  });

  it("enforces BOOTSTRAP_TOKEN auth, read-only scope 403, one-time pairing/refresh tickets, 10m TTL cleanup, and revoke WS 4401", async () => {
    // Wrong BOOTSTRAP_TOKEN rejected
    const badBoot = await SELF.fetch("https://relay.test/v1/devices/bootstrap", {
      method: "POST",
      headers: { authorization: "Bearer wrong-secret", "content-type": "application/json" },
      body: JSON.stringify({ device_name: "Evil", token_sha256_hex: await sha256Hex("evil") }),
    });
    expect(badBoot.status).toBe(401);

    const macToken = "tok-mac-desktop";
    const boot = await bootstrapDevice("MacBook", macToken);

    // Pair a read-only phone device (server never sees plaintext token or K_pair)
    const phoneToken = "tok-iphone-readonly";
    const addRes = await SELF.fetch("https://relay.test/v1/devices", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        device_name: "iPhone",
        scope: "read",
        token_sha256_hex: await sha256Hex(phoneToken),
        ciphertext_b64: b64("MNPR_opaque_k_pair_ciphertext"),
      }),
    });
    expect(addRes.status).toBe(200);
    const addJson = (await addRes.json()) as { ok: boolean; device_id: string; pair_id: string; expires_at_ms: number };

    // Before pair-claim, phone token is NOT yet active (401)
    const preClaim = await SELF.fetch("https://relay.test/v1/sync/pull?since=0", {
      headers: { authorization: `Bearer ${phoneToken}` },
    });
    expect(preClaim.status).toBe(401);

    // First pair-claim succeeds and atomically deletes ticket + activates device
    const claim1 = await SELF.fetch("https://relay.test/v1/devices/pair-claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pair_id: addJson.pair_id }),
    });
    expect(claim1.status).toBe(200);
    expect(await claim1.json()).toMatchObject({
      ok: true,
      kind: "add",
      device_id: addJson.device_id,
      scope: "read",
      ciphertext_b64: b64("MNPR_opaque_k_pair_ciphertext"),
    });

    // Second pair-claim MUST return 404 NOT_FOUND
    const claim2 = await SELF.fetch("https://relay.test/v1/devices/pair-claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pair_id: addJson.pair_id }),
    });
    expect(claim2.status).toBe(404);

    // Read-only phone token can pull & GET /v1/keys, but gets 403 on ALL write & device routes
    expect((await SELF.fetch("https://relay.test/v1/sync/pull?since=0", { headers: { authorization: `Bearer ${phoneToken}` } })).status).toBe(200);
    expect((await SELF.fetch("https://relay.test/v1/keys", { headers: { authorization: `Bearer ${phoneToken}` } })).status).toBe(200);

    for (const [method, path, payload] of [
      ["POST", "/v1/sync/push", { expected_epoch: boot.epoch, ops: [] }],
      ["POST", "/v1/keys", { key_records: [] }],
      ["POST", "/v1/devices", { device_name: "X", scope: "read", token_sha256_hex: await sha256Hex("x"), ciphertext_b64: b64("x") }],
      ["GET", "/v1/devices", null],
      ["DELETE", `/v1/devices/${boot.device_id}`, null],
    ] as const) {
      const r = await SELF.fetch(`https://relay.test${path}`, {
        method,
        headers: { authorization: `Bearer ${phoneToken}`, ...(payload ? { "content-type": "application/json" } : {}) },
        ...(payload ? { body: JSON.stringify(payload) } : {}),
      });
      expect(r.status).toBe(403);
      expect(await r.json()).toMatchObject({ ok: false, error: { code: "TOKEN_SCOPE_FORBIDDEN" } });
    }

    // Refresh ticket for active device
    const refRes = await SELF.fetch(`https://relay.test/v1/devices/${addJson.device_id}/refresh`, {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({ ciphertext_b64: b64("MNPR_refreshed_smks") }),
    });
    expect(refRes.status).toBe(200);
    const refJson = (await refRes.json()) as { pair_id: string };
    const claimRef = await SELF.fetch("https://relay.test/v1/devices/pair-claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pair_id: refJson.pair_id }),
    });
    expect(claimRef.status).toBe(200);
    expect(await claimRef.json()).toMatchObject({ ok: true, kind: "refresh", device_id: addJson.device_id, ciphertext_b64: b64("MNPR_refreshed_smks") });

    // Connect phone WebSocket -> verify ping/pong + wake-only + immediate revoke disconnect (4401)
    const wsRes = await SELF.fetch("https://relay.test/v1/sync/ws", {
      headers: { authorization: `Bearer ${phoneToken}`, upgrade: "websocket" },
    });
    expect(wsRes.status).toBe(101);
    const ws = wsRes.webSocket!;
    ws.accept();
    const msgs: string[] = [];
    let closeCode = 0;
    ws.addEventListener("message", (ev) => { msgs.push(String(ev.data)); });
    ws.addEventListener("close", (ev) => { closeCode = ev.code; });

    ws.send("ping");
    await vi.waitFor(() => expect(msgs).toContain("pong"));

    // Push op from Mac -> phone receives wake-only frame (no op envelope)
    await SELF.fetch("https://relay.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        expected_epoch: boot.epoch,
        ops: [{ op_id: "01JDF910A2B3C4D5E6F7WS0001", key_id: null, envelope_b64: b64("secret_envelope_not_in_ws") }],
      }),
    });
    await vi.waitFor(() => expect(msgs.some((m) => m.includes('"type":"wake"'))).toBe(true));
    expect(msgs.some((m) => m.includes("secret_envelope_not_in_ws"))).toBe(false);

    // Revoke phone -> WS receives device_revoked & closes with 4401, subsequent HTTP returns 401 DEVICE_REVOKED
    const revRes = await SELF.fetch(`https://relay.test/v1/devices/${addJson.device_id}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${macToken}` },
    });
    expect(revRes.status).toBe(200);
    await vi.waitFor(() => expect(closeCode).toBe(4401));
    const afterRev = await SELF.fetch("https://relay.test/v1/sync/pull?since=0", {
      headers: { authorization: `Bearer ${phoneToken}` },
    });
    expect(afterRev.status).toBe(401);
    expect(await afterRev.json()).toMatchObject({ ok: false, error: { code: "DEVICE_REVOKED" } });

    // Create an unclaimed pairing ticket, advance clock past 10 minutes, trigger alarm -> ticket & ghost device removed
    const ghostAdd = await SELF.fetch("https://relay.test/v1/devices", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        device_name: "GhostLaptop",
        scope: "read-write",
        token_sha256_hex: await sha256Hex("tok-ghost"),
        ciphertext_b64: b64("ghost_ticket"),
      }),
    });
    const ghostJson = (await ghostAdd.json()) as { device_id: string; pair_id: string };
    const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("primary"));
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(11 * 60 * 1000));
    await runDurableObjectAlarm(stub);

    const expiredClaim = await SELF.fetch("https://relay.test/v1/devices/pair-claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pair_id: ghostJson.pair_id }),
    });
    expect(expiredClaim.status).toBe(404);
    const listAfter = (await (await SELF.fetch("https://relay.test/v1/devices", { headers: { authorization: `Bearer ${macToken}` } })).json()) as {
      devices: { device_id: string }[];
    };
    expect(listAfter.devices.some((d) => d.device_id === ghostJson.device_id)).toBe(false);
  });

  it("enforces monotonic key_material gen, produces binary MNA1 + latest.mnks / history/*.mnks via alarm, and exposes zero /v1/archive/* routes", async () => {
    const token = "tok-archive-test";
    const boot = await bootstrapDevice("Omarchy", token);

    // Zero /v1/archive/* or /v1/blobs/* routes
    expect((await SELF.fetch("https://relay.test/v1/archive/list", { headers: { authorization: `Bearer ${token}` } })).status).toBe(404);
    expect((await SELF.fetch("https://relay.test/v1/blobs/abc", { headers: { authorization: `Bearer ${token}` } })).status).toBe(404);

    // Upload valid msgpack keyring gen=1 and a key_record + op
    const fakeKeyringBytes = encode({
      v: 1,
      recovery_kid: new Uint8Array(16),
      recovery_pk: new Uint8Array(32),
      keyring_gen: 1,
      current_smk_kid: "01JDF8Z9X4K7M2N5P8Q1R3S600",
      smk_entries: [],
    });
    const krB64 = btoa(String.fromCharCode(...fakeKeyringBytes));

    const kmRes1 = await SELF.fetch("https://relay.test/v1/keys", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        key_records: [{ key_id: "01JDF8Z9X4K7M2N5P8Q1R3S6A1", wrap_gen: 1, key_record_b64: b64("mnr1_a1") }],
        key_material: { keyring: { gen: 1, blob_b64: krB64 } },
      }),
    });
    expect(kmRes1.status).toBe(200);

    // Lower gen -> 409 CAS_MISMATCH
    const staleKm = await SELF.fetch("https://relay.test/v1/keys", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ key_material: { keyring: { gen: 0, blob_b64: krB64 } } }),
    });
    expect(staleKm.status).toBe(409);
    expect(await staleKm.json()).toMatchObject({ ok: false, error: { code: "CAS_MISMATCH" } });

    const pushRes = await SELF.fetch("https://relay.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        expected_epoch: boot.epoch,
        ops: [{ op_id: "01JDF910A2B3C4D5E6F7AR0001", key_id: "01JDF8Z9X4K7M2N5P8Q1R3S6A1", envelope_b64: b64("mns1_archive_1") }],
      }),
    });
    expect(pushRes.status).toBe(200);
    const pushJson = (await pushRes.json()) as { acked: { seq: number }[] };
    const seqStr = String(pushJson.acked[0].seq).padStart(12, "0");

    const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("primary"));
    const ran = await runDurableObjectAlarm(stub);
    expect(ran).toBe(true);

    const opsList = await env.ARCHIVE_BUCKET.list({ prefix: `archives/ops/${boot.epoch}/` });
    const latestOpsKey = opsList.objects.map((o) => o.key).find((k) => k.endsWith(`-${seqStr}.mna1`));
    expect(latestOpsKey).toBeDefined();
    const opsObj = await env.ARCHIVE_BUCKET.get(latestOpsKey!);
    expect(opsObj).not.toBeNull();
    const opsBytes = new Uint8Array(await opsObj!.arrayBuffer());
    expect(new TextDecoder().decode(opsBytes.slice(0, 4))).toBe("MNA1");
    expect(opsBytes[4]).toBe(1);

    const latestMnks = await env.ARCHIVE_BUCKET.get("archives/keys/latest.mnks");
    expect(latestMnks).not.toBeNull();
    const mnksBytes = new Uint8Array(await latestMnks!.arrayBuffer());
    expect(new TextDecoder().decode(mnksBytes.slice(0, 4))).toBe("MNKS");
    expect(mnksBytes[4]).toBe(1);

    const hist = await env.ARCHIVE_BUCKET.list({ prefix: "archives/keys/history/" });
    expect(hist.objects.length).toBe(1);

    // Re-running alarm with no new ops is idempotent (no duplicate op archive segments)
    const beforeCount = (await env.ARCHIVE_BUCKET.list({ prefix: "archives/ops/" })).objects.length;
    await runDurableObjectAlarm(stub);
    const afterCount = (await env.ARCHIVE_BUCKET.list({ prefix: "archives/ops/" })).objects.length;
    expect(afterCount).toBe(beforeCount);
  });

  it("does NOT starve daily archive alarm on DO hibernation wakeups and chunks >500 ops into bounded MNA1 segments", async () => {
    const token = "tok-hibernation-chunk";
    const boot = await bootstrapDevice("MacBook", token);
    const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("primary"));

    // Reset virtual clock to 0 and establish a fresh daily schedule baseline via alarm
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(0));
    await runDurableObjectAlarm(stub);
    const existingKeys = new Set(
      (await env.ARCHIVE_BUCKET.list({ prefix: `archives/ops/${boot.epoch}/` })).objects.map((o) => o.key),
    );

    // Record initial scheduled daily alarm timestamp
    const alarm0 = await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).simulateWakeupReschedule());
    expect(alarm0).not.toBeNull();

    // Advance virtual clock by 12 hours and simulate DO hibernation wakeup reschedule:
    // the scheduled alarm MUST move 12h closer in wall-clock (same virtual target), NOT push 24h forward!
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(12 * 3_600_000));
    const alarm12h = await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).simulateWakeupReschedule());
    expect(alarm12h!).toBeLessThan(alarm0! - 11 * 3_600_000);

    // Push 620 ops across two batches (> 500 MAX_PUSH_OPS) to verify chunked MNA1 archiving
    let firstSeq = 0;
    let lastSeq = 0;
    for (let batch = 0; batch < 2; batch++) {
      const count = batch === 0 ? 500 : 120;
      const ops = Array.from({ length: count }, (_, i) => ({
        op_id: `01JDF920A2B3C4D5${batch}${String(i).padStart(9, "0")}`,
        key_id: null,
        envelope_b64: b64(`chunk_op_${batch}_${i}`),
      }));
      const r = await SELF.fetch("https://relay.test/v1/sync/push", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ expected_epoch: boot.epoch, ops }),
      });
      expect(r.status).toBe(200);
      const j = (await r.json()) as { acked: { seq: number }[] };
      if (batch === 0) firstSeq = j.acked[0].seq;
      lastSeq = j.acked[j.acked.length - 1].seq;
    }

    // Create an unclaimed ticket expiring in 10m; expiring it at +12h11m MUST clean up ticket WITHOUT triggering early daily archive
    const ghostRes = await SELF.fetch("https://relay.test/v1/devices", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        device_name: "Ghost2",
        scope: "read",
        token_sha256_hex: await sha256Hex("tok-ghost2"),
        ciphertext_b64: b64("ghost2_ct"),
      }),
    });
    expect(ghostRes.status).toBe(200);
    const ghostJson = (await ghostRes.json()) as { pair_id: string };
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(12 * 3_600_000 + 11 * 60_000));
    await runDurableObjectAlarm(stub);
    const afterTicketKeys = (await env.ARCHIVE_BUCKET.list({ prefix: `archives/ops/${boot.epoch}/` })).objects
      .map((o) => o.key)
      .filter((k) => !existingKeys.has(k));
    expect(afterTicketKeys).toHaveLength(0);
    expect(
      (
        await SELF.fetch("https://relay.test/v1/devices/pair-claim", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ pair_id: ghostJson.pair_id }),
        })
      ).status,
    ).toBe(404);

    // Advance past 24h -> daily archive fires and splits 620 ops into 2 bounded segments (500 + 120)
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(25 * 3_600_000));
    await runDurableObjectAlarm(stub);
    const newSegs = (await env.ARCHIVE_BUCKET.list({ prefix: `archives/ops/${boot.epoch}/` })).objects
      .map((o) => o.key)
      .filter((k) => !existingKeys.has(k))
      .sort();
    const pad = (n: number) => String(n).padStart(12, "0");
    expect(newSegs).toEqual([
      `archives/ops/${boot.epoch}/${pad(firstSeq)}-${pad(firstSeq + 499)}.mna1`,
      `archives/ops/${boot.epoch}/${pad(firstSeq + 500)}-${pad(lastSeq)}.mna1`,
    ]);
  });

  it("INV-GRACE & M2: enforces 24h min grace, rolling N=20 pending_confirm -> confirm, read-only 403 on shred/put-snapshot, R2 2-snapshot pruning, and Rust<->TS keys_digest parity", async () => {
    const { computeKeysDigest } = await import("../src/wire");
    const te = new TextEncoder();
    const digestVec = computeKeysDigest(
      [{ key_id: "01JDF9M20000000000000000K1", wrap_gen: 1, key_record: te.encode("mnr1_vec"), created_at_ms: 1_795_521_600_000 }],
      [{
        mark_id: "01JDF9M20000000000000000M1", key_id: "01JDF9M20000000000000000K1", seen_seq: 1,
        requested_by: "dev_mac00001", requested_at_ms: 1_795_521_600_000, grace_ms: 604_800_000,
        not_before_ms: 1_796_126_400_000, state: "scheduled", confirmed_at_ms: null, cancelled_by: null, executed_at_ms: null,
      }],
      { gen: 1, blob: te.encode("kr_vec") },
      { gen: 1_795_521_600_000, blob: te.encode("vh_vec") },
    );
    // Must match crates/mynote-core/src/keys.rs::cross_language_keys_digest_vector_matches_wire_ts byte-for-byte!
    expect(digestVec).toBe("blake3:38ec33ece0a92a473a0c05a51973dcd64784a8aaffabc71aa87f71046443aae0");

    const macToken = "tok-inv-grace-mac";
    const boot = await bootstrapDevice("MacBookGrace", macToken);
    const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("primary"));
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(0));

    // Pair read-only phone token to test M2 scope boundaries
    const phoneToken = "tok-inv-grace-phone";
    const addRes = await SELF.fetch("https://relay.test/v1/devices", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({ device_name: "PhoneGrace", scope: "read", token_sha256_hex: await sha256Hex(phoneToken), ciphertext_b64: b64("ct") }),
    });
    const addJson = (await addRes.json()) as { pair_id: string };
    await SELF.fetch("https://relay.test/v1/devices/pair-claim", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ pair_id: addJson.pair_id }),
    });

    // Read-only token gets 403 on shred, cancel, confirm, and PUT snapshot
    for (const [method, path, body] of [
      ["POST", "/v1/keys/shred", JSON.stringify({ seen_seq: 0, marks: [] })],
      ["POST", "/v1/keys/cancel", JSON.stringify({ key_ids: [] })],
      ["POST", "/v1/keys/confirm", JSON.stringify({ key_ids: [], grace_ms: 86_400_000 })],
      ["PUT", "/v1/snapshots/state", new Uint8Array([1, 2, 3])],
    ] as const) {
      const r = await SELF.fetch(`https://relay.test${path}`, {
        method,
        headers: {
          authorization: `Bearer ${phoneToken}`,
          ...(typeof body === "string" ? { "content-type": "application/json" } : { "x-journal-epoch": boot.epoch, "x-covers-seq": "1" }),
        },
        body,
      });
      expect(r.status, `${method} ${path}`).toBe(403);
      expect(await r.json()).toMatchObject({ ok: false, error: { code: "TOKEN_SCOPE_FORBIDDEN" } });
    }

    // Create 22 keys to test rolling 24h batch limit N=20!
    const keyRecords = Array.from({ length: 22 }, (_, i) => ({
      key_id: `01JDF9GRACE0000000000000${String(i).padStart(2, "0")}`,
      wrap_gen: 1,
      key_record_b64: b64(`mnr1_grace_${i}`),
    }));
    const postK = await SELF.fetch("https://relay.test/v1/keys", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({ key_records: keyRecords }),
    });
    expect(postK.status).toBe(200);

    // Submit 22 shred marks at once: first 20 -> scheduled, 21st & 22nd -> pending_confirm (not_before_ms = null)!
    const marks = keyRecords.map((kr, i) => ({
      mark_id: `01JDF9MARK00000000000000${String(i).padStart(2, "0")}`,
      key_id: kr.key_id,
      grace_ms: 7 * 86_400_000,
    }));
    const shredRes = await SELF.fetch("https://relay.test/v1/keys/shred", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({ seen_seq: 99999, marks }),
    });
    expect(shredRes.status).toBe(200);
    const shredJson = (await shredRes.json()) as { results: { key_id: string; state: string; not_before_ms: number | null }[] };
    expect(shredJson.results.slice(0, 20).every((r) => r.state === "scheduled" && r.not_before_ms !== null)).toBe(true);
    expect(shredJson.results.slice(20).every((r) => r.state === "pending_confirm" && r.not_before_ms === null)).toBe(true);

    // Confirming with grace_ms < 24h -> 422 GRACE_TOO_SHORT
    const badConf = await SELF.fetch("https://relay.test/v1/keys/confirm", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({ key_ids: [keyRecords[20].key_id], grace_ms: 1000 }),
    });
    expect(badConf.status).toBe(422);
    expect(await badConf.json()).toMatchObject({ ok: false, error: { code: "GRACE_TOO_SHORT" } });

    // Confirm 21st key with 24h grace -> transitions to scheduled with not_before_ms >= now + 24h
    const confRes = await SELF.fetch("https://relay.test/v1/keys/confirm", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({ key_ids: [keyRecords[20].key_id], grace_ms: 86_400_000 }),
    });
    expect(confRes.status).toBe(200);
    const confJson = (await confRes.json()) as { results: { key_id: string; state: string; not_before_ms: number }[] };
    expect(confJson.results[0].state).toBe("scheduled");
    expect(confJson.results[0].not_before_ms).toBeGreaterThanOrEqual(Date.now() + 86_000_000);

    // Upload 3 mobile snapshots -> R2 only keeps latest 2; phone read token can GET latest!
    for (const seq of [10, 20, 30]) {
      const up = await SELF.fetch("https://relay.test/v1/snapshots/state", {
        method: "PUT",
        headers: {
          authorization: `Bearer ${macToken}`,
          "content-type": "application/octet-stream",
          "x-journal-epoch": boot.epoch,
          "x-covers-seq": String(seq),
          "x-snapshot-id": `01JDF9SNAP00000000000000${seq}`,
        },
        body: new TextEncoder().encode(`MNP1_BODY_${seq}`),
      });
      expect(up.status).toBe(200);
    }
    const r2Snaps = await env.ARCHIVE_BUCKET.list({ prefix: `snapshots/state/${boot.epoch}/` });
    expect(r2Snaps.objects.length).toBe(2);

    const phoneSnap = await SELF.fetch("https://relay.test/v1/snapshots/state", {
      headers: { authorization: `Bearer ${phoneToken}` },
    });
    expect(phoneSnap.status).toBe(200);
    expect(phoneSnap.headers.get("x-covers-seq")).toBe("30");
    expect(await phoneSnap.text()).toBe("MNP1_BODY_30");

    // Verify browser WS auth via Sec-WebSocket-Protocol (no token in query string)
    const wsRes = await SELF.fetch("https://relay.test/v1/sync/ws", {
      headers: { upgrade: "websocket", "sec-websocket-protocol": `mynote-v1, bearer.${phoneToken}` },
    });
    expect(wsRes.status).toBe(101);
    expect(wsRes.headers.get("sec-websocket-protocol")).toBe("mynote-v1");
    wsRes.webSocket?.accept();
    wsRes.webSocket?.close();

    // Verify Mobile Read-Only PWA static assets are served with strict per-origin CSP & security headers (H13)
    const pwaRes = await SELF.fetch("https://relay.test/");
    expect(pwaRes.status).toBe(200);
    const csp = pwaRes.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).not.toContain("'unsafe-inline'");
    expect(csp).toContain("connect-src 'self' wss://relay.test");
    expect(csp).toContain("form-action 'none'");
    expect(pwaRes.headers.get("x-frame-options")).toBe("DENY");
    expect(pwaRes.headers.get("referrer-policy")).toBe("no-referrer");
    expect(await pwaRes.text()).toContain("pwa-app");
  });

  it("PR #38 regressions: H10 idempotent push/shred retry, H11 snapshot header checks, H12 input validation, H14 fresh DO migration_exempt block, confirm default grace & expedite pending_confirm guard", async () => {
    const freshStub = env.SYNC_DO.get(env.SYNC_DO.idFromName("pr38-regressions-fresh"));
    const macToken = "tok_reg_mac";
    const bootRes = await freshStub.fetch("https://relay.test/v1/devices/bootstrap", {
      method: "POST",
      headers: { authorization: `Bearer ${env.BOOTSTRAP_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ device_name: "RegMac", token_sha256_hex: await sha256Hex(macToken), device_id: "dev_regmac00001" }),
    });
    expect(bootRes.status).toBe(200);
    const boot = (await bootRes.json()) as { epoch: string };
    const auth = { authorization: `Bearer ${macToken}`, "content-type": "application/json" };

    // H12: Non-string b64 -> 400 INVALID_ARGUMENT
    const badB64 = await freshStub.fetch("https://relay.test/v1/keys", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ key_records: [{ key_id: "01JREGK0000000000000000001", wrap_gen: 1, key_record_b64: null }] }),
    });
    expect(badB64.status).toBe(400);

    // Push 1 valid key + op + shred mark (fresh DO -> seq = 1, state = scheduled)
    const kid = "01JREGK0000000000000000001";
    const opId = "01JREGOP000000000000000001";
    const markId = "01JREGMK000000000000000001";
    const push1 = await freshStub.fetch("https://relay.test/v1/sync/push", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        expected_epoch: boot.epoch,
        seen_seq: 0,
        key_records: [{ key_id: kid, wrap_gen: 1, key_record_b64: b64("mnr1_reg") }],
        ops: [{ op_id: opId, key_id: kid, device_id: "dev_regmac00001", envelope_b64: b64("env_reg_1") }],
        shred_marks: [{ mark_id: markId, key_id: kid, grace_ms: 7 * 86_400_000 }],
      }),
    });
    expect(push1.status).toBe(200);
    const push1Json = (await push1.json()) as { acked: { op_id: string; seq: number }[]; head_seq: number };
    expect(push1Json.acked[0]).toEqual({ op_id: opId, seq: 1 });

    // H10: Exact idempotent replay of the SAME push (op_id + mark_id) MUST succeed even though kid is now scheduled and seq 1 > seen_seq 0!
    const push1Replay = await freshStub.fetch("https://relay.test/v1/sync/push", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        expected_epoch: boot.epoch,
        seen_seq: 0,
        key_records: [{ key_id: kid, wrap_gen: 1, key_record_b64: b64("mnr1_reg") }],
        ops: [{ op_id: opId, key_id: kid, device_id: "dev_regmac00001", envelope_b64: b64("env_reg_1") }],
        shred_marks: [{ mark_id: markId, key_id: kid, grace_ms: 7 * 86_400_000 }],
      }),
    });
    expect(push1Replay.status).toBe(200);
    const replayJson = (await push1Replay.json()) as { acked: { op_id: string; seq: number }[]; shred_results: { key_id: string; state: string }[] };
    expect(replayJson.acked[0]).toEqual({ op_id: opId, seq: 1 });
    expect(replayJson.shred_results[0].state).toBe("scheduled");

    // H12: String/float seen_seq and float grace_ms rejected with 400
    const badSeen = await freshStub.fetch("https://relay.test/v1/keys/shred", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ seen_seq: "9999", marks: [{ mark_id: "01JREGMK000000000000000099", key_id: kid, grace_ms: 86_400_000 }] }),
    });
    expect(badSeen.status).toBe(400);
    const badGrace = await freshStub.fetch("https://relay.test/v1/keys/shred", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ seen_seq: 1, marks: [{ mark_id: "01JREGMK000000000000000098", key_id: kid, grace_ms: 86_400_000.5 }] }),
    });
    expect(badGrace.status).toBe(400);

    // H11: Snapshot with malformed x-covers-seq, covers_seq > head_seq, or bad x-snapshot-id -> 400 INVALID_ARGUMENT
    const badSnapSeq = await freshStub.fetch("https://relay.test/v1/snapshots/state", {
      method: "PUT",
      headers: { authorization: `Bearer ${macToken}`, "x-journal-epoch": boot.epoch, "x-covers-seq": "abc", "x-snapshot-id": "snap1" },
      body: new Uint8Array([1, 2, 3]),
    });
    expect(badSnapSeq.status).toBe(400);
    const futureSnapSeq = await freshStub.fetch("https://relay.test/v1/snapshots/state", {
      method: "PUT",
      headers: { authorization: `Bearer ${macToken}`, "x-journal-epoch": boot.epoch, "x-covers-seq": "999", "x-snapshot-id": "snap2" },
      body: new Uint8Array([1, 2, 3]),
    });
    expect(futureSnapSeq.status).toBe(400);
    const badSnapId = await freshStub.fetch("https://relay.test/v1/snapshots/state", {
      method: "PUT",
      headers: { authorization: `Bearer ${macToken}`, "x-journal-epoch": boot.epoch, "x-covers-seq": "1", "x-snapshot-id": "../evil" },
      body: new Uint8Array([1, 2, 3]),
    });
    expect(badSnapId.status).toBe(400);

    // H14: Fresh DO MUST NOT grant migration_exempt bypass! Submitting 21 keys with migration_exempt:true still caps at N=20 -> pending_confirm!
    const extraKeys = Array.from({ length: 21 }, (_, i) => ({
      key_id: `01JREGEXEMPT000000000000${String(i).padStart(2, "0")}`,
      wrap_gen: 1,
      key_record_b64: b64(`mnr1_ex_${i}`),
    }));
    expect((await freshStub.fetch("https://relay.test/v1/keys", { method: "POST", headers: auth, body: JSON.stringify({ key_records: extraKeys }) })).status).toBe(200);
    const exRes = await freshStub.fetch("https://relay.test/v1/keys/shred", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        seen_seq: 1,
        migration_exempt: true,
        marks: extraKeys.map((k, i) => ({
          mark_id: `01JREGEMK000000000000000${String(i).padStart(2, "0")}`,
          key_id: k.key_id,
          grace_ms: 7 * 86_400_000,
        })),
      }),
    });
    expect(exRes.status).toBe(200);
    const exJson = (await exRes.json()) as { results: { key_id: string; state: string }[] };
    const pendingKey = exJson.results.find((r) => r.state === "pending_confirm");
    expect(pendingKey).toBeDefined();

    // Expediting a pending_confirm key MUST be rejected (must confirm first)
    const expPending = await freshStub.fetch("https://relay.test/v1/keys/shred", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        seen_seq: 1,
        expedite: true,
        marks: [{ mark_id: "01JREGEXP00000000000000001", key_id: pendingKey!.key_id, grace_ms: 86_400_000 }],
      }),
    });
    expect(expPending.status).toBe(409);

    // Confirming pending_confirm WITHOUT grace_ms preserves the mark's original 7-day grace (NOT shortened to 24h!)
    const confDefault = await freshStub.fetch("https://relay.test/v1/keys/confirm", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ key_ids: [pendingKey!.key_id] }),
    });
    expect(confDefault.status).toBe(200);
    const confDefaultJson = (await confDefault.json()) as { results: { key_id: string; state: string; not_before_ms: number }[] };
    expect(confDefaultJson.results[0].state).toBe("scheduled");
    expect(confDefaultJson.results[0].not_before_ms).toBeGreaterThanOrEqual(Date.now() + 6 * 86_400_000);
  });
});
