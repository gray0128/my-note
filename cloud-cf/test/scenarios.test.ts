import { env, SELF, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import scenario from "../../tests/scenarios/m1_relay_contract.json";
import m2Scenario from "../../tests/scenarios/m2_shred_and_snapshot_contract.json";
import type { SyncJournalDO } from "../src/index";

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("Shared DST/Worker Protocol Scenarios (F-12)", () => {
  it(`executes shared scenario '${scenario.name}' identically against real SyncJournalDO`, async () => {
    const tokens = new Map<string, string>();
    let currentEpoch = "";
    let previousEpoch = "";

    for (const dev of scenario.devices) {
      const tok = `tok_${dev.device_id}`;
      tokens.set(dev.device_id, tok);
      const res = await SELF.fetch("https://relay.test/v1/devices/bootstrap", {
        method: "POST",
        headers: { authorization: "Bearer test-bootstrap-secret-token", "content-type": "application/json" },
        body: JSON.stringify({
          device_id: dev.device_id,
          device_name: dev.device_name,
          token_sha256_hex: await sha256Hex(tok),
        }),
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as { epoch: string };
      currentEpoch = json.epoch;
    }

    for (const step of scenario.steps) {
      if (step.action === "pitr_rollback") {
        previousEpoch = currentEpoch;
        const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("primary"));
        currentEpoch = await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).simulatePitrRollback(step.keep_seq!, step.new_epoch!));
        expect(currentEpoch).toBe(step.new_epoch);
        continue;
      }

      const token = tokens.get(step.as_device!)!;
      if (step.action === "push") {
        const expectedEpoch = step.use_epoch === "previous" ? previousEpoch : currentEpoch;
        const res = await SELF.fetch("https://relay.test/v1/sync/push", {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({
            expected_epoch: expectedEpoch,
            key_records: step.key_records ?? [],
            ops: step.ops ?? [],
          }),
        });
        expect(res.status, `step=${step.id}`).toBe(step.expect!.status);
        const body = (await res.json()) as {
          ok: boolean;
          acked?: { op_id: string; seq: number }[];
          head_seq?: number;
          error?: { code: string; details?: { head_seq?: number } };
        };
        if (step.expect!.status === 200) {
          expect(body.ok).toBe(true);
          expect(body.acked!.map((a) => a.seq)).toEqual(step.expect!.acked_seqs);
          expect(body.head_seq).toBe(step.expect!.head_seq);
        } else {
          expect(body.ok).toBe(false);
          expect(body.error!.code).toBe(step.expect!.error_code);
          if (step.expect!.head_seq !== undefined) {
            expect(body.error!.details?.head_seq).toBe(step.expect!.head_seq);
          }
        }
      } else if (step.action === "pull") {
        const res = await SELF.fetch(`https://relay.test/v1/sync/pull?since=${step.since}&limit=${step.limit}`, {
          headers: { authorization: `Bearer ${token}` },
        });
        expect(res.status, `step=${step.id}`).toBe(step.expect!.status);
        const body = (await res.json()) as {
          ok: boolean;
          ops: { op_id: string; seq: number; device_id: string }[];
          has_more: boolean;
          head_seq: number;
          keys_digest: string;
        };
        expect(body.ok).toBe(true);
        expect(body.ops.map((o) => o.op_id)).toEqual(step.expect!.op_ids);
        expect(body.ops.map((o) => o.seq)).toEqual(step.expect!.seqs);
        if ("device_ids" in step.expect! && step.expect!.device_ids) {
          expect(body.ops.map((o) => o.device_id)).toEqual(step.expect!.device_ids);
        }
        expect(body.has_more).toBe(step.expect!.has_more);
        expect(body.head_seq).toBe(step.expect!.head_seq);
        expect(body.keys_digest).toMatch(/^blake3:[0-9a-f]{64}$/);
      } else if (step.action === "keys_post") {
        const res = await SELF.fetch("https://relay.test/v1/keys", {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({
            key_records: step.key_records ?? [],
            ...(step.keyring ? { key_material: { keyring: step.keyring } } : {}),
          }),
        });
        expect(res.status, `step=${step.id}`).toBe(step.expect!.status);
        const body = (await res.json()) as { ok: boolean; error?: { code: string } };
        if (step.expect!.status === 200) {
          expect(body.ok).toBe(true);
        } else {
          expect(body.ok).toBe(false);
          expect(body.error!.code).toBe(step.expect!.error_code);
        }
      }
    }
  });

  it(`executes shared M2 scenario '${m2Scenario.name}' identically against real SyncJournalDO`, async () => {
    const tokens = new Map<string, string>();
    const stub = env.SYNC_DO.get(env.SYNC_DO.idFromName("primary"));
    let epoch = await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).simulatePitrRollback(0));
    await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(0));
    let clockOffset = 0;

    for (const dev of m2Scenario.devices) {
      const tok = `tok_m2_${dev.device_id}`;
      tokens.set(dev.device_id, tok);
      const res = await SELF.fetch("https://relay.test/v1/devices/bootstrap", {
        method: "POST",
        headers: { authorization: "Bearer test-bootstrap-secret-token", "content-type": "application/json" },
        body: JSON.stringify({ device_id: dev.device_id, device_name: dev.device_name, token_sha256_hex: await sha256Hex(tok) }),
      });
      expect(res.status).toBe(200);
      epoch = ((await res.json()) as { epoch: string }).epoch;
    }

    for (const step of m2Scenario.steps as Array<Record<string, unknown>>) {
      const id = String(step.id);
      const exp = step.expect as Record<string, unknown>;
      if (step.action === "advance_and_alarm") {
        clockOffset += Number(step.delta_ms);
        await runInDurableObject(stub, (inst) => (inst as SyncJournalDO).setClockOffsetMs(clockOffset));
        await runDurableObjectAlarm(stub);
        const keysRes = await SELF.fetch("https://relay.test/v1/keys", {
          headers: { authorization: `Bearer ${tokens.get("dev_mac00001")}` },
        });
        const keysJson = (await keysRes.json()) as { key_records: { key_id: string; key_record_b64: string | null }[] };
        const byId = new Map(keysJson.key_records.map((r) => [r.key_id, r.key_record_b64]));
        for (const k of exp.shredded_keys as string[]) expect(byId.get(k), `step=${id} ${k}`).toBeNull();
        for (const k of exp.alive_keys as string[]) expect(byId.get(k), `step=${id} ${k}`).not.toBeNull();
        continue;
      }
      const token = tokens.get(String(step.as_device))!;
      if (step.action === "push") {
        const res = await SELF.fetch("https://relay.test/v1/sync/push", {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({
            expected_epoch: epoch,
            seen_seq: step.seen_seq ?? 0,
            key_records: step.key_records ?? [],
            cancel_key_ids: step.cancel_key_ids ?? [],
            ops: step.ops ?? [],
            shred_marks: step.shred_marks ?? [],
          }),
        });
        expect(res.status, `step=${id}`).toBe(exp.status);
        const body = (await res.json()) as {
          ok: boolean;
          acked?: { seq: number }[];
          head_seq?: number;
          shred_results?: { state: string }[];
          error?: { code: string };
        };
        if (exp.status === 200) {
          expect(body.acked!.map((a) => a.seq), `step=${id}`).toEqual(exp.acked_seqs);
          expect(body.head_seq, `step=${id}`).toBe(exp.head_seq);
          if (exp.shred_states) expect(body.shred_results!.map((r) => r.state), `step=${id}`).toEqual(exp.shred_states);
        } else {
          expect(body.error!.code, `step=${id}`).toBe(exp.error_code);
        }
      } else if (step.action === "keys_shred") {
        const res = await SELF.fetch("https://relay.test/v1/keys/shred", {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ seen_seq: step.seen_seq ?? 0, expedite: Boolean(step.expedite), marks: step.marks }),
        });
        expect(res.status, `step=${id}`).toBe(exp.status);
        const body = (await res.json()) as { ok: boolean; results?: { state: string }[]; error?: { code: string } };
        if (exp.status === 200) expect(body.results!.map((r) => r.state), `step=${id}`).toEqual(exp.shred_states);
        else expect(body.error!.code, `step=${id}`).toBe(exp.error_code);
      } else if (step.action === "keys_cancel") {
        const res = await SELF.fetch("https://relay.test/v1/keys/cancel", {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ key_ids: step.key_ids }),
        });
        expect(res.status, `step=${id}`).toBe(exp.status);
        const body = (await res.json()) as { ok: boolean; error?: { code: string } };
        if (exp.status !== 200) expect(body.error!.code, `step=${id}`).toBe(exp.error_code);
      } else if (step.action === "snapshot_put") {
        const raw = Uint8Array.from(atob(String(step.body_b64)), (c) => c.charCodeAt(0));
        const res = await SELF.fetch("https://relay.test/v1/snapshots/state", {
          method: "PUT",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/octet-stream",
            "x-journal-epoch": epoch,
            "x-covers-seq": String(step.covers_seq),
            "x-snapshot-id": String(step.snapshot_id),
          },
          body: raw,
        });
        expect(res.status, `step=${id}`).toBe(exp.status);
        if (exp.status !== 200) {
          const body = (await res.json()) as { error: { code: string } };
          expect(body.error.code, `step=${id}`).toBe(exp.error_code);
        }
      } else if (step.action === "snapshot_get") {
        const res = await SELF.fetch("https://relay.test/v1/snapshots/state", {
          headers: { authorization: `Bearer ${token}` },
        });
        expect(res.status, `step=${id}`).toBe(exp.status);
        expect(Number(res.headers.get("x-covers-seq")), `step=${id}`).toBe(exp.covers_seq);
        const gotBytes = new Uint8Array(await res.arrayBuffer());
        expect(btoa(String.fromCharCode(...gotBytes)), `step=${id}`).toBe(exp.body_b64);
      }
    }
  });
});
