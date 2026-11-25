import { env, SELF, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import scenario from "../../tests/scenarios/m1_relay_contract.json";
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
});
