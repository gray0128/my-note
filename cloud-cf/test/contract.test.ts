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

    const opsObj = await env.ARCHIVE_BUCKET.get(`archives/ops/${boot.epoch}/${seqStr}-${seqStr}.mna1`);
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
});
