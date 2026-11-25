import { env, SELF, runDurableObjectAlarm } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function registerDevice(deviceId: string, token: string, scope: "read" | "read-write") {
  const res = await SELF.fetch("https://spike.test/v1/devices/bootstrap", {
    method: "POST",
    headers: {
      authorization: "Bearer spike-bootstrap-secret",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      device_id: deviceId,
      token_sha256: await sha256Hex(token),
      scope,
    }),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { ok: boolean; epoch: string };
}

describe("S0-4 Cloudflare Paid Echo Relay Spike (real workerd)", () => {
  it("enforces read vs read-write token scopes and handles 150-op batch (>100 SQL bind params)", async () => {
    const rwToken = "tok-mac-rw";
    const roToken = "tok-iphone-ro";
    await registerDevice("dev_mac", rwToken, "read-write");
    await registerDevice("dev_iphone", roToken, "read");

    // 1. Read-only token is blocked on push & shred with 403 TOKEN_SCOPE_FORBIDDEN
    const roPush = await SELF.fetch("https://spike.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${roToken}`, "content-type": "application/json" },
      body: JSON.stringify({ ops: [] }),
    });
    expect(roPush.status).toBe(403);
    expect(await roPush.json()).toMatchObject({ ok: false, error: { code: "TOKEN_SCOPE_FORBIDDEN" } });

    const roShred = await SELF.fetch("https://spike.test/v1/keys/shred", {
      method: "POST",
      headers: { authorization: `Bearer ${roToken}`, "content-type": "application/json" },
      body: JSON.stringify({ mark_id: "m1", key_id: "k1", grace_ms: 86_400_000 }),
    });
    expect(roShred.status).toBe(403);

    // 2. Push 150 ops in one batch (would fail if concatenated into >100 bind params SQL)
    const ops = Array.from({ length: 150 }, (_, i) => ({
      op_id: `op_${String(i).padStart(4, "0")}`,
      key_id: "key_batch_1",
      payload: `enc_payload_${i}`,
    }));
    const pushRes = await SELF.fetch("https://spike.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${rwToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        key_records: [{ key_id: "key_batch_1", key_record: "mnr1_cipher" }],
        ops,
      }),
    });
    expect(pushRes.status).toBe(200);
    const pushJson = (await pushRes.json()) as { ok: boolean; acked: { op_id: string; seq: number }[]; head_seq: number };
    expect(pushJson.ok).toBe(true);
    expect(pushJson.acked).toHaveLength(150);
    expect(pushJson.head_seq).toBe(150);

    // 3. Idempotent replay returns exact same seqs and does not bump head_seq
    const replayRes = await SELF.fetch("https://spike.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${rwToken}`, "content-type": "application/json" },
      body: JSON.stringify({ ops: ops.slice(0, 5) }),
    });
    const replayJson = (await replayRes.json()) as { acked: { op_id: string; seq: number }[]; head_seq: number };
    expect(replayJson.acked).toEqual(pushJson.acked.slice(0, 5));
    expect(replayJson.head_seq).toBe(150);

    // 4. Read-only token can pull all 150 ops
    const pullRes = await SELF.fetch("https://spike.test/v1/sync/pull?since=0", {
      headers: { authorization: `Bearer ${roToken}` },
    });
    expect(pullRes.status).toBe(200);
    const pullJson = (await pullRes.json()) as { ops: unknown[]; head_seq: number };
    expect(pullJson.ops).toHaveLength(150);
    expect(pullJson.head_seq).toBe(150);
  });

  it("supports WebSocket Hibernation auto-response ping/pong, attachment survival, and wake-only broadcast", async () => {
    const macToken = "tok-ws-mac";
    const linuxToken = "tok-ws-linux";
    await registerDevice("dev_ws_mac", macToken, "read-write");
    await registerDevice("dev_ws_linux", linuxToken, "read-write");

    const wsResp = await SELF.fetch("https://spike.test/v1/sync/ws", {
      headers: {
        authorization: `Bearer ${linuxToken}`,
        upgrade: "websocket",
      },
    });
    expect(wsResp.status).toBe(101);
    const ws = wsResp.webSocket!;
    ws.accept();

    const received: string[] = [];
    ws.addEventListener("message", (ev) => {
      received.push(String(ev.data));
    });

    // Edge auto-response: "ping" -> "pong"
    ws.send("ping");
    await vi.waitFor(() => expect(received).toContain("pong"));

    // Verify deserializeAttachment preserved device metadata
    const dbg = await SELF.fetch("https://spike.test/v1/debug/state", {
      headers: { authorization: `Bearer ${macToken}` },
    });
    const dbgJson = (await dbg.json()) as { wsAttachments: { deviceId: string; scope: string }[] };
    expect(dbgJson.wsAttachments).toContainEqual({ deviceId: "dev_ws_linux", scope: "read-write" });

    // Push from Mac wakes Linux with wake-only frame (no op payload leaked)
    await SELF.fetch("https://spike.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${macToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        key_records: [{ key_id: "key_ws_1", key_record: "mnr1_ws" }],
        ops: [{ op_id: "op_ws_1", key_id: "key_ws_1", payload: "SECRET_CIPHERTEXT_MUST_NOT_BE_IN_WS" }],
      }),
    });

    await vi.waitFor(() => expect(received.length).toBeGreaterThanOrEqual(2));
    const wakeFrame = JSON.parse(received.find((m) => m.startsWith("{"))!) as {
      type: string;
      epoch: string;
      head_seq: number;
    };
    expect(wakeFrame.type).toBe("wake");
    expect(wakeFrame.head_seq).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(wakeFrame)).not.toContain("SECRET_CIPHERTEXT");

    ws.close(1000, "done");
  });

  it("enforces T_grace_min and multiplexes DO Alarm for key shredding, R2 archive/dual-track snapshots, and pairing TTL", async () => {
    const rwToken = "tok-alarm-mac";
    const { epoch } = await registerDevice("dev_alarm_mac", rwToken, "read-write");

    // Seed two keys + one op
    await SELF.fetch("https://spike.test/v1/sync/push", {
      method: "POST",
      headers: { authorization: `Bearer ${rwToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        key_records: [
          { key_id: "key_keep", key_record: "mnr1_keep" },
          { key_id: "key_shred", key_record: "mnr1_shred" },
        ],
        ops: [{ op_id: "op_arch_1", key_id: "key_keep", payload: "mns1_cipher_1" }],
      }),
    });

    // Reject grace_ms < T_grace_min (24h)
    const shortRes = await SELF.fetch("https://spike.test/v1/keys/shred", {
      method: "POST",
      headers: { authorization: `Bearer ${rwToken}`, "content-type": "application/json" },
      body: JSON.stringify({ mark_id: "m_short", key_id: "key_shred", grace_ms: 1000 }),
    });
    expect(shortRes.status).toBe(422);

    // Schedule key_shred with valid T_grace_min (24h from now)
    const schedRes = await SELF.fetch("https://spike.test/v1/keys/shred", {
      method: "POST",
      headers: { authorization: `Bearer ${rwToken}`, "content-type": "application/json" },
      body: JSON.stringify({ mark_id: "m_due", key_id: "key_shred", grace_ms: 86_400_000 }),
    });
    expect(schedRes.status).toBe(200);

    // Register an unclaimed pairing ticket (10m TTL)
    await SELF.fetch("https://spike.test/v1/devices/pair-ticket", {
      method: "POST",
      headers: { authorization: `Bearer ${rwToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        pair_id: "pair_expired_1",
        device_id: "dev_ghost_unclaimed",
        token_sha256: await sha256Hex("ghost-tok"),
      }),
    });

    const id = env.SYNC_DO.idFromName("primary");
    const stub = env.SYNC_DO.get(id);

    // 1. Premature alarm (at t=0): key_shred MUST NOT be shredded yet!
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const beforeDue = (await (
      await SELF.fetch("https://spike.test/v1/debug/state", {
        headers: { authorization: `Bearer ${rwToken}` },
      })
    ).json()) as { keys: { key_id: string; key_record: string | null }[]; marks: { mark_id: string; state: string }[] };
    expect(beforeDue.keys.find((k) => k.key_id === "key_shred")?.key_record).toBe("mnr1_shred");
    expect(beforeDue.marks.find((m) => m.mark_id === "m_due")?.state).toBe("scheduled");

    // 2. Advance injectable virtual clock by +25h and fire DO Alarm
    await SELF.fetch("https://spike.test/v1/debug/clock", {
      method: "POST",
      headers: { authorization: `Bearer ${rwToken}`, "content-type": "application/json" },
      body: JSON.stringify({ offset_ms: 25 * 3600 * 1000 }),
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    // Check DO state: key_shred nulled, key_keep intact, ghost device & ticket purged
    const dbg = (await (
      await SELF.fetch("https://spike.test/v1/debug/state", {
        headers: { authorization: `Bearer ${rwToken}` },
      })
    ).json()) as {
      keys: { key_id: string; key_record: string | null }[];
      marks: { mark_id: string; state: string }[];
      tickets: unknown[];
      devices: { device_id: string }[];
    };

    expect(dbg.keys.find((k) => k.key_id === "key_shred")?.key_record).toBeNull();
    expect(dbg.keys.find((k) => k.key_id === "key_keep")?.key_record).toBe("mnr1_keep");
    expect(dbg.marks.find((m) => m.mark_id === "m_due")?.state).toBe("executed");
    expect(dbg.tickets).toHaveLength(0);
    expect(dbg.devices.some((d) => d.device_id === "dev_ghost_unclaimed")).toBe(false);

    // Check R2 dual-track objects: permanent op archive + latest.mnks (only active keys!) + history/<day>.mnks
    const r2List = await env.ARCHIVE_BUCKET.list();
    const keys = r2List.objects.map((o) => o.key);
    expect(keys.some((k) => k.startsWith(`archives/ops/${epoch}/`) && k.endsWith(".mna1"))).toBe(true);
    expect(keys).toContain("archives/keys/latest.mnks");
    expect(keys.some((k) => k.startsWith("archives/keys/history/") && k.endsWith(".mnks"))).toBe(true);

    const latestObj = await env.ARCHIVE_BUCKET.get("archives/keys/latest.mnks");
    const latestJson = (await latestObj!.json()) as { active_keys: { key_id: string }[] };
    const activeIds = latestJson.active_keys.map((k) => k.key_id);
    expect(activeIds).toContain("key_keep");
    expect(activeIds).not.toContain("key_shred");

    // 3. Re-running alarm is idempotent (no duplicate op archives created)
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const r2ListAfter = await env.ARCHIVE_BUCKET.list({ prefix: "archives/ops/" });
    expect(r2ListAfter.objects).toHaveLength(1);
  });
});
