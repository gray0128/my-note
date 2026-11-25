import { DurableObject } from "cloudflare:workers";
import {
  b64ToBytes, bytesEqual, bytesToB64, computeKeysDigest, encodeMna1, encodeMnks,
  KeyMaterialEntry, KeyRecordWire, randomDeviceId, randomPairId, sha256Hex, ShredMarkState,
  ShredMarkWire, timingSafeEqualStr, toU8,
} from "./wire";

export interface Env {
  SYNC_DO: DurableObjectNamespace<SyncJournalDO>;
  ARCHIVE_BUCKET: R2Bucket;
  BOOTSTRAP_TOKEN: string;
  DAILY_ARCHIVE_INTERVAL_MS?: string;
  PAIRING_TTL_MS?: string;
  T_GRACE_MIN_MS?: string;
  SHRED_BATCH_LIMIT_24H?: string;
  ALLOW_TEST_HOOKS?: string;
  ASSETS?: Fetcher;
}
type Scope = "read" | "read-write";
interface WsMeta { deviceId: string; scope: Scope; }
interface KeyRecIn { key_id: string; wrap_gen: number; key_record_b64: string; }
interface ShredMarkIn { mark_id: string; key_id: string; grace_ms: number; requested_by?: string; }
interface ShredResultOut { key_id: string; state: ShredMarkState; not_before_ms: number | null; }
class RelayError extends Error {
  constructor(public status: number, public code: string, message: string, public retryable = false, public details?: Record<string, unknown>) { super(message); }
}
const jsonRes = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const MAX_PUSH_OPS = 500, MAX_PUSH_BYTES = 4 * 1024 * 1024, MAX_ARCHIVE_BYTES = 8 * 1024 * 1024, MAX_SNAP_BYTES = 16 * 1024 * 1024, HEX64 = /^[0-9a-f]{64}$/i;
const PWA_CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' wss: https:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'";

export class SyncJournalDO extends DurableObject<Env> {
  private sql: SqlStorage;
  private epoch = "";
  private clockOffsetMs = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    this.ctx.blockConcurrencyWhile(async () => { this.initSchema(); await this.rescheduleAlarm(this.nowMs()); });
  }

  private assertTestHook(): void { if (this.env.ALLOW_TEST_HOOKS !== "1") throw new Error("test hooks disabled"); }
  private archiveIntervalMs(): number { return Number(this.env.DAILY_ARCHIVE_INTERVAL_MS || 86_400_000); }
  private tGraceMinMs(): number { return Number(this.env.T_GRACE_MIN_MS || 86_400_000); }
  private shredBatchLimit24h(): number { return Number(this.env.SHRED_BATCH_LIMIT_24H || 20); }
  private nowMs(): number { return Date.now() + this.clockOffsetMs; }
  private headSeq(): number { return Number(this.sql.exec(`SELECT COALESCE(MAX(seq), 0) AS h FROM ops`).toArray()[0]?.h ?? 0); }
  private metaGet(key: string): string | null { const r = this.sql.exec(`SELECT value FROM journal_meta WHERE key = ?`, key).toArray()[0]; return r ? String(r.value) : null; }
  private metaSet(key: string, val: string): void { this.sql.exec(`INSERT OR REPLACE INTO journal_meta (key, value) VALUES (?, ?)`, key, val); }

  setClockOffsetMs(offsetMs: number): number { this.assertTestHook(); this.clockOffsetMs = offsetMs; return this.nowMs(); }
  async simulateWakeupReschedule(): Promise<number | null> { this.assertTestHook(); await this.rescheduleAlarm(this.nowMs()); return this.ctx.storage.getAlarm(); }
  simulatePitrRollback(keepSeq: number, newEpoch?: string): string {
    this.assertTestHook();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(`DELETE FROM ops WHERE seq > ?`, keepSeq);
      this.epoch = newEpoch ?? crypto.randomUUID();
      this.metaSet("journal_epoch", this.epoch);
      this.metaSet("last_archive_seq", "0");
    });
    return this.epoch;
  }

  private initSchema(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS journal_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, device_name TEXT NOT NULL, token_sha256_hex TEXT NOT NULL UNIQUE, scope TEXT NOT NULL CHECK (scope IN ('read', 'read-write')), last_pulled_seq INTEGER NOT NULL DEFAULT 0, last_seen_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, claimed_at_ms INTEGER, revoked_at_ms INTEGER);
      CREATE TABLE IF NOT EXISTS pairing_tickets (pair_id TEXT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'pair' CHECK (kind IN ('pair', 'refresh')), device_id TEXT NOT NULL REFERENCES devices(device_id), scope TEXT NOT NULL CHECK (scope IN ('read', 'read-write')), ciphertext BLOB NOT NULL, created_by TEXT NOT NULL, expires_at_ms INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS ops (seq INTEGER PRIMARY KEY, op_id TEXT NOT NULL UNIQUE, device_id TEXT NOT NULL, created_at INTEGER NOT NULL, key_id TEXT, envelope BLOB NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_ops_key ON ops (key_id, seq) WHERE key_id IS NOT NULL;
      CREATE TABLE IF NOT EXISTS block_keys (key_id TEXT PRIMARY KEY, wrap_gen INTEGER NOT NULL, key_record BLOB, created_by_device TEXT NOT NULL, created_at_ms INTEGER NOT NULL, shredded_at_ms INTEGER);
      CREATE TABLE IF NOT EXISTS shred_marks (mark_id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES block_keys(key_id), seen_seq INTEGER NOT NULL, requested_by TEXT NOT NULL, requested_at_ms INTEGER NOT NULL, grace_ms INTEGER NOT NULL, not_before_ms INTEGER, state TEXT NOT NULL CHECK (state IN ('pending_confirm', 'scheduled', 'cancelled', 'executed')), confirmed_at_ms INTEGER, cancelled_by TEXT, executed_at_ms INTEGER);
      CREATE INDEX IF NOT EXISTS idx_shred_marks_due ON shred_marks (not_before_ms) WHERE state = 'scheduled';
      CREATE INDEX IF NOT EXISTS idx_shred_marks_key ON shred_marks (key_id);
      CREATE TABLE IF NOT EXISTS key_material (kind TEXT PRIMARY KEY CHECK (kind IN ('keyring', 'vault_header')), gen INTEGER NOT NULL, blob BLOB NOT NULL, updated_at_ms INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS phone_snapshots (snapshot_id TEXT PRIMARY KEY, journal_epoch TEXT NOT NULL, covers_seq INTEGER NOT NULL, r2_key TEXT NOT NULL, created_by TEXT NOT NULL, created_at_ms INTEGER NOT NULL, UNIQUE (journal_epoch, covers_seq));
    `);
    const existing = this.metaGet("journal_epoch");
    if (existing) this.epoch = existing;
    else { this.epoch = crypto.randomUUID(); this.metaSet("journal_epoch", this.epoch); this.metaSet("last_archive_seq", "0"); }
    this.sql.exec(`INSERT OR IGNORE INTO journal_meta (key, value) VALUES ('next_archive_at_ms', ?)`, String(this.nowMs() + this.archiveIntervalMs()));
  }

  private loadKeyState() {
    const records: KeyRecordWire[] = this.sql.exec(`SELECT key_id, wrap_gen, key_record, created_at_ms FROM block_keys ORDER BY key_id ASC`).toArray()
      .map((r) => ({ key_id: String(r.key_id), wrap_gen: Number(r.wrap_gen), key_record: r.key_record === null ? null : toU8(r.key_record), created_at_ms: Number(r.created_at_ms) }));
    const marks: ShredMarkWire[] = this.sql.exec(`SELECT mark_id, key_id, seen_seq, requested_by, requested_at_ms, grace_ms, not_before_ms, state, confirmed_at_ms, cancelled_by, executed_at_ms FROM shred_marks ORDER BY mark_id ASC`).toArray()
      .map((m) => ({
        mark_id: String(m.mark_id), key_id: String(m.key_id), seen_seq: Number(m.seen_seq), requested_by: String(m.requested_by),
        requested_at_ms: Number(m.requested_at_ms), grace_ms: Number(m.grace_ms), not_before_ms: m.not_before_ms === null ? null : Number(m.not_before_ms),
        state: String(m.state) as ShredMarkState, confirmed_at_ms: m.confirmed_at_ms === null ? null : Number(m.confirmed_at_ms),
        cancelled_by: m.cancelled_by === null ? null : String(m.cancelled_by), executed_at_ms: m.executed_at_ms === null ? null : Number(m.executed_at_ms),
      }));
    let keyring: KeyMaterialEntry | null = null, vaultHeader: KeyMaterialEntry | null = null;
    for (const m of this.sql.exec(`SELECT kind, gen, blob FROM key_material`).toArray()) {
      const entry = { gen: Number(m.gen), blob: toU8(m.blob) };
      if (m.kind === "keyring") keyring = entry;
      else if (m.kind === "vault_header") vaultHeader = entry;
    }
    return { records, marks, keyring, vaultHeader, digest: computeKeysDigest(records, marks, keyring, vaultHeader) };
  }

  private upsertKeyRecord(rec: KeyRecIn, deviceId: string, now: number): void {
    const raw = b64ToBytes(rec.key_record_b64);
    const cur = this.sql.exec(`SELECT wrap_gen, key_record FROM block_keys WHERE key_id = ?`, rec.key_id).toArray()[0];
    if (!cur) {
      this.sql.exec(`INSERT INTO block_keys (key_id, wrap_gen, key_record, created_by_device, created_at_ms) VALUES (?, ?, ?, ?, ?)`, rec.key_id, rec.wrap_gen, raw, deviceId, now);
      return;
    }
    if (cur.key_record === null) throw new RelayError(410, "KEY_SHREDDED", `key ${rec.key_id} shredded`, false, { key_id: rec.key_id });
    const curGen = Number(cur.wrap_gen);
    if (rec.wrap_gen > curGen) this.sql.exec(`UPDATE block_keys SET wrap_gen = ?, key_record = ? WHERE key_id = ?`, rec.wrap_gen, raw, rec.key_id);
    else if (rec.wrap_gen === curGen && !bytesEqual(toU8(cur.key_record), raw)) {
      throw new RelayError(409, "INTEGRITY_ERROR", `conflicting key_record at wrap_gen=${curGen}`, false, { key_id: rec.key_id });
    }
  }

  private upsertKeyMaterial(kind: "keyring" | "vault_header", gen: number, blobB64: string, now: number): number {
    const raw = b64ToBytes(blobB64);
    const cur = this.sql.exec(`SELECT gen, blob FROM key_material WHERE kind = ?`, kind).toArray()[0];
    if (!cur) {
      this.sql.exec(`INSERT INTO key_material (kind, gen, blob, updated_at_ms) VALUES (?, ?, ?, ?)`, kind, gen, raw, now);
      return gen;
    }
    const curGen = Number(cur.gen);
    if (gen < curGen) throw new RelayError(409, "CAS_MISMATCH", `${kind} gen ${gen} < ${curGen}`, true, { kind, current_gen: curGen });
    if (gen === curGen) {
      if (!bytesEqual(toU8(cur.blob), raw)) throw new RelayError(409, "INTEGRITY_ERROR", `conflicting ${kind} at gen=${curGen}`, false, { kind, gen });
      return curGen;
    }
    this.sql.exec(`UPDATE key_material SET gen = ?, blob = ?, updated_at_ms = ? WHERE kind = ?`, gen, raw, now, kind);
    return gen;
  }

  private cancelKeyMarks(keyIds: string[], deviceId: string): string[] {
    const cancelled: string[] = [];
    for (const kid of keyIds) {
      const kr = this.sql.exec(`SELECT key_record FROM block_keys WHERE key_id = ?`, kid).toArray()[0];
      const execMark = this.sql.exec(`SELECT 1 FROM shred_marks WHERE key_id = ? AND state = 'executed' LIMIT 1`, kid).toArray()[0];
      if ((kr && kr.key_record === null) || execMark) throw new RelayError(410, "KEY_SHREDDED", `key ${kid} already shredded`, false, { key_id: kid });
      const active = this.sql.exec(`SELECT mark_id FROM shred_marks WHERE key_id = ? AND state IN ('pending_confirm', 'scheduled')`, kid).toArray();
      if (active.length > 0) {
        this.sql.exec(`UPDATE shred_marks SET state = 'cancelled', cancelled_by = ? WHERE key_id = ? AND state IN ('pending_confirm', 'scheduled')`, deviceId, kid);
        cancelled.push(kid);
      }
    }
    return cancelled;
  }

  private applyShredMarks(
    marks: ShredMarkIn[], seenSeq: number, preBatchHeadSeq: number, expedite: boolean,
    migrationExempt: boolean, deviceId: string, now: number, rejectExecuted: boolean,
  ): ShredResultOut[] {
    const minGrace = this.tGraceMinMs(), limit24h = this.shredBatchLimit24h();
    const allowExempt = migrationExempt && this.metaGet("m2_migration_exempt_used") !== "1";
    let rolling = Number(
      this.sql.exec(`SELECT COUNT(DISTINCT key_id) AS c FROM shred_marks WHERE requested_at_ms > ? AND state IN ('scheduled', 'executed')`, now - 86_400_000).toArray()[0]?.c ?? 0,
    );
    const results: ShredResultOut[] = [];
    for (const m of marks) {
      if (!m.mark_id || !m.key_id || !Number.isFinite(m.grace_ms)) throw new RelayError(400, "INVALID_ARGUMENT", "invalid shred mark payload");
      if (m.grace_ms < minGrace) throw new RelayError(422, "GRACE_TOO_SHORT", `grace_ms ${m.grace_ms} < ${minGrace}`, false, { key_id: m.key_id, min_grace_ms: minGrace });
      const kr = this.sql.exec(`SELECT key_record FROM block_keys WHERE key_id = ?`, m.key_id).toArray()[0];
      if (!kr) throw new RelayError(409, "KEY_UNKNOWN", `unknown key_id ${m.key_id}`, false, { key_id: m.key_id });
      if (kr.key_record === null) {
        if (rejectExecuted) throw new RelayError(410, "KEY_SHREDDED", `key ${m.key_id} already shredded`, false, { key_id: m.key_id });
        results.push({ key_id: m.key_id, state: "executed", not_before_ms: null });
        continue;
      }
      const stale = this.sql.exec(`SELECT 1 FROM ops WHERE key_id = ? AND seq > ? AND seq <= ? LIMIT 1`, m.key_id, seenSeq, preBatchHeadSeq).toArray()[0];
      if (stale) throw new RelayError(409, "SHRED_STALE", `newer ops exist for key ${m.key_id} after seen_seq=${seenSeq}`, true, { key_id: m.key_id, head_seq: preBatchHeadSeq });
      if (expedite) {
        const cur = this.sql.exec(`SELECT mark_id, requested_at_ms, not_before_ms FROM shred_marks WHERE key_id = ? AND state = 'scheduled' ORDER BY not_before_ms ASC LIMIT 1`, m.key_id).toArray()[0];
        if (cur) {
          const candidate = Math.max(now + Math.max(m.grace_ms, minGrace), Number(cur.requested_at_ms) + minGrace);
          const nextNb = cur.not_before_ms === null ? candidate : Math.min(Number(cur.not_before_ms), candidate);
          this.sql.exec(`UPDATE shred_marks SET not_before_ms = ? WHERE mark_id = ?`, nextNb, cur.mark_id);
          results.push({ key_id: m.key_id, state: "scheduled", not_before_ms: nextNb });
          continue;
        }
      }
      const dup = this.sql.exec(`SELECT state, not_before_ms FROM shred_marks WHERE mark_id = ?`, m.mark_id).toArray()[0];
      if (dup) {
        results.push({ key_id: m.key_id, state: String(dup.state) as ShredMarkState, not_before_ms: dup.not_before_ms === null ? null : Number(dup.not_before_ms) });
        continue;
      }
      let state: ShredMarkState = "scheduled", notBefore: number | null = now + m.grace_ms;
      if (!allowExempt && rolling >= limit24h) { state = "pending_confirm"; notBefore = null; }
      else if (!allowExempt) { rolling++; }
      this.sql.exec(
        `INSERT INTO shred_marks (mark_id, key_id, seen_seq, requested_by, requested_at_ms, grace_ms, not_before_ms, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        m.mark_id, m.key_id, seenSeq, m.requested_by || deviceId, now, m.grace_ms, notBefore, state,
      );
      results.push({ key_id: m.key_id, state, not_before_ms: notBefore });
    }
    if (allowExempt && marks.length > 0) this.metaSet("m2_migration_exempt_used", "1");
    return results;
  }

  private broadcastWake(excludeDeviceId: string | null, headSeq: number): void {
    const wake = JSON.stringify({ type: "wake", epoch: this.epoch, head_seq: headSeq });
    for (const ws of this.ctx.getWebSockets()) {
      const meta = ws.deserializeAttachment() as WsMeta | null;
      if (!excludeDeviceId || meta?.deviceId !== excludeDeviceId) { try { ws.send(wake); } catch { /* ignore */ } }
    }
  }

  private disconnectDeviceWs(deviceId: string): void {
    const msg = JSON.stringify({ type: "device_revoked" });
    for (const ws of this.ctx.getWebSockets()) {
      if ((ws.deserializeAttachment() as WsMeta | null)?.deviceId === deviceId) {
        try { ws.send(msg); ws.close(4401, "device_revoked"); } catch { /* ignore */ }
      }
    }
  }

  private async authenticate(req: Request, now: number): Promise<WsMeta> {
    const auth = req.headers.get("authorization") ?? "";
    let token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token && req.headers.get("upgrade")?.toLowerCase() === "websocket") {
      const protos = (req.headers.get("sec-websocket-protocol") ?? "").split(",").map((s) => s.trim());
      const bearerProto = protos.find((p) => p.startsWith("bearer."));
      if (bearerProto) token = bearerProto.slice(7);
    }
    if (!token) throw new RelayError(401, "AUTH_REQUIRED", "missing bearer token");
    const row = this.sql
      .exec(`SELECT device_id, scope, claimed_at_ms, revoked_at_ms FROM devices WHERE token_sha256_hex = ?`, await sha256Hex(token))
      .toArray()[0];
    if (!row || row.claimed_at_ms === null) throw new RelayError(401, "AUTH_REQUIRED", "unknown or unclaimed device token");
    if (row.revoked_at_ms !== null) throw new RelayError(401, "DEVICE_REVOKED", "device token revoked");
    this.sql.exec(`UPDATE devices SET last_seen_at_ms = ? WHERE device_id = ?`, now, row.device_id);
    return { deviceId: String(row.device_id), scope: String(row.scope) as Scope };
  }

  private async rescheduleAlarm(now: number): Promise<void> {
    const meta = this.metaGet("next_archive_at_ms");
    let nextAt = meta ? Number(meta) : now + this.archiveIntervalMs();
    if (!meta) this.metaSet("next_archive_at_ms", String(nextAt));
    const duePair = this.sql.exec(`SELECT MIN(expires_at_ms) AS t FROM pairing_tickets`).toArray()[0];
    if (duePair?.t !== null && duePair?.t !== undefined) nextAt = Math.min(nextAt, Number(duePair.t));
    const dueShred = this.sql.exec(`SELECT MIN(not_before_ms) AS t FROM shred_marks WHERE state = 'scheduled' AND not_before_ms IS NOT NULL`).toArray()[0];
    if (dueShred?.t !== null && dueShred?.t !== undefined) nextAt = Math.min(nextAt, Number(dueShred.t));
    await this.ctx.storage.setAlarm(Math.max(Date.now() + 1_000, nextAt - this.clockOffsetMs));
  }

  async fetch(req: Request): Promise<Response> {
    try { return await this.route(req); } catch (e) {
      const err = e instanceof RelayError ? e : new RelayError(400, "INVALID_ARGUMENT", e instanceof Error ? e.message : "bad request");
      return jsonRes({ ok: false, error: { code: err.code, message: err.message, retryable: err.retryable, ...(err.details ? { details: err.details } : {}) } }, err.status);
    }
  }

  private async route(req: Request): Promise<Response> {
    const url = new URL(req.url), path = url.pathname, now = this.nowMs();

    if (req.method === "POST" && path === "/v1/devices/bootstrap") {
      const authHdr = req.headers.get("authorization") ?? "", presented = authHdr.startsWith("Bearer ") ? authHdr.slice(7) : "";
      if (!this.env.BOOTSTRAP_TOKEN || !timingSafeEqualStr(presented, this.env.BOOTSTRAP_TOKEN)) throw new RelayError(401, "AUTH_REQUIRED", "invalid BOOTSTRAP_TOKEN");
      const b = (await req.json()) as { device_name: string; token_sha256_hex: string; revoke_existing?: boolean; device_id?: string };
      if (!b.device_name || !HEX64.test(b.token_sha256_hex ?? "")) throw new RelayError(400, "INVALID_ARGUMENT", "invalid bootstrap payload");
      const deviceId = b.device_id ?? randomDeviceId(), revoked: string[] = [];
      this.ctx.storage.transactionSync(() => {
        if (b.revoke_existing) {
          for (const d of this.sql.exec(`SELECT device_id FROM devices WHERE revoked_at_ms IS NULL AND device_id != ?`, deviceId).toArray()) revoked.push(String(d.device_id));
          this.sql.exec(`UPDATE devices SET revoked_at_ms = ? WHERE revoked_at_ms IS NULL AND device_id != ?`, now, deviceId);
          this.sql.exec(`DELETE FROM pairing_tickets`);
        }
        this.sql.exec(`DELETE FROM pairing_tickets WHERE device_id = ?`, deviceId);
        this.sql.exec(
          `INSERT INTO devices (device_id, device_name, token_sha256_hex, scope, last_pulled_seq, last_seen_at_ms, created_at_ms, claimed_at_ms, revoked_at_ms)
           VALUES (?, ?, ?, 'read-write', 0, ?, ?, ?, NULL)
           ON CONFLICT(device_id) DO UPDATE SET device_name=excluded.device_name, token_sha256_hex=excluded.token_sha256_hex, scope='read-write', last_seen_at_ms=excluded.last_seen_at_ms, claimed_at_ms=excluded.claimed_at_ms, revoked_at_ms=NULL`,
          deviceId, b.device_name, b.token_sha256_hex.toLowerCase(), now, now, now,
        );
      });
      for (const rid of revoked) this.disconnectDeviceWs(rid);
      return jsonRes({ ok: true, device_id: deviceId, scope: "read-write", epoch: this.epoch });
    }

    if (req.method === "POST" && path === "/v1/devices/pair-claim") {
      const { pair_id } = (await req.json()) as { pair_id?: string };
      if (!pair_id) throw new RelayError(400, "INVALID_ARGUMENT", "pair_id required");
      const claimed = this.ctx.storage.transactionSync(() => {
        const t = this.sql.exec(`SELECT kind, device_id, scope, ciphertext, expires_at_ms FROM pairing_tickets WHERE pair_id = ?`, pair_id).toArray()[0];
        if (!t) return null;
        this.sql.exec(`DELETE FROM pairing_tickets WHERE pair_id = ?`, pair_id);
        if (Number(t.expires_at_ms) <= now) {
          if (t.kind === "pair") this.sql.exec(`DELETE FROM devices WHERE device_id = ? AND claimed_at_ms IS NULL`, t.device_id);
          return null;
        }
        if (t.kind === "pair") this.sql.exec(`UPDATE devices SET claimed_at_ms = ?, last_seen_at_ms = ? WHERE device_id = ?`, now, now, t.device_id);
        return { kind: t.kind === "pair" ? "add" : "refresh", device_id: String(t.device_id), scope: String(t.scope), ciphertext_b64: bytesToB64(toU8(t.ciphertext)) };
      });
      await this.rescheduleAlarm(now);
      if (!claimed) throw new RelayError(404, "NOT_FOUND", "ticket missing, expired, or already claimed");
      return jsonRes({ ok: true, ...claimed });
    }

    const auth = await this.authenticate(req, now);

    if (req.method === "GET" && path === "/v1/sync/ws" && req.headers.get("upgrade")?.toLowerCase() === "websocket") {
      const [client, server] = Object.values(new WebSocketPair());
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment(auth);
      const headers = new Headers();
      if ((req.headers.get("sec-websocket-protocol") ?? "").includes("mynote-v1")) {
        headers.set("Sec-WebSocket-Protocol", "mynote-v1");
      }
      return new Response(null, { status: 101, webSocket: client, headers });
    }

    if (req.method === "GET" && path === "/v1/sync/pull") {
      const since = Math.max(0, Number.parseInt(url.searchParams.get("since") ?? "0", 10) || 0);
      const limit = Math.min(MAX_PUSH_OPS, Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "500", 10) || 500));
      const rows = this.sql.exec(`SELECT seq, op_id, key_id, device_id, created_at, envelope FROM ops WHERE seq > ? ORDER BY seq ASC LIMIT ?`, since, limit + 1).toArray();
      const hasMore = rows.length > limit;
      const ops = rows.slice(0, limit).map((r) => ({
        seq: Number(r.seq), op_id: String(r.op_id), key_id: r.key_id === null ? null : String(r.key_id),
        device_id: String(r.device_id), created_at: Number(r.created_at), envelope_b64: bytesToB64(toU8(r.envelope)),
      }));
      if (ops.length > 0) this.sql.exec(`UPDATE devices SET last_pulled_seq = MAX(last_pulled_seq, ?) WHERE device_id = ?`, ops[ops.length - 1].seq, auth.deviceId);
      return jsonRes({ ok: true, epoch: this.epoch, ops, keys_digest: this.loadKeyState().digest, head_seq: this.headSeq(), has_more: hasMore });
    }

    if (req.method === "GET" && path === "/v1/keys") {
      const { records, marks, keyring, vaultHeader, digest } = this.loadKeyState();
      return jsonRes({
        ok: true,
        key_material: {
          keyring: keyring ? { gen: keyring.gen, blob_b64: bytesToB64(keyring.blob) } : null,
          vault_header: vaultHeader ? { gen: vaultHeader.gen, blob_b64: bytesToB64(vaultHeader.blob) } : null,
        },
        key_records: records.map((r) => ({ key_id: r.key_id, wrap_gen: r.wrap_gen, key_record_b64: r.key_record ? bytesToB64(r.key_record) : null, created_at_ms: r.created_at_ms })),
        shred_marks: marks, digest,
      });
    }

    if (req.method === "GET" && path === "/v1/snapshots/state") {
      const row = this.sql.exec(`SELECT snapshot_id, journal_epoch, covers_seq, r2_key FROM phone_snapshots WHERE journal_epoch = ? ORDER BY covers_seq DESC LIMIT 1`, this.epoch).toArray()[0];
      if (!row) throw new RelayError(404, "NOT_FOUND", "no mobile state snapshot for current epoch");
      const obj = await this.env.ARCHIVE_BUCKET.get(String(row.r2_key));
      if (!obj) throw new RelayError(404, "NOT_FOUND", "snapshot blob missing from R2");
      return new Response(await obj.arrayBuffer(), {
        status: 200,
        headers: {
          "content-type": "application/octet-stream", "cache-control": "no-store",
          "x-journal-epoch": String(row.journal_epoch), "x-covers-seq": String(row.covers_seq), "x-snapshot-id": String(row.snapshot_id),
        },
      });
    }

    if (auth.scope !== "read-write") {
      throw new RelayError(403, "TOKEN_SCOPE_FORBIDDEN", "read-only token cannot invoke write or device routes");
    }

    if (req.method === "POST" && path === "/v1/sync/push") {
      const raw = await req.text();
      if (raw.length > MAX_PUSH_BYTES) throw new RelayError(400, "INVALID_ARGUMENT", "push body exceeds 4 MiB");
      const b = JSON.parse(raw) as {
        expected_epoch?: string; seen_seq?: number; key_records?: KeyRecIn[]; cancel_key_ids?: string[];
        ops?: { op_id: string; key_id: string | null; device_id?: string; envelope_b64: string }[]; shred_marks?: ShredMarkIn[];
      };
      if (b.expected_epoch !== this.epoch) throw new RelayError(409, "CAS_MISMATCH", "Journal epoch changed; reconcile before pushing", true, { remote_epoch: this.epoch, head_seq: this.headSeq() });
      const ops = b.ops ?? [], marksIn = b.shred_marks ?? [], cancels = b.cancel_key_ids ?? [];
      if (ops.length > MAX_PUSH_OPS) throw new RelayError(400, "INVALID_ARGUMENT", `batch exceeds ${MAX_PUSH_OPS} ops`);
      const acked: { op_id: string; seq: number }[] = [];
      let shredResults: ShredResultOut[] = [], headSeq = 0;
      this.ctx.storage.transactionSync(() => {
        const preBatchHeadSeq = this.headSeq();
        for (const rec of b.key_records ?? []) this.upsertKeyRecord(rec, auth.deviceId, now);
        if (cancels.length > 0) this.cancelKeyMarks(cancels, auth.deviceId);
        for (const op of ops) {
          if (op.key_id !== null && op.key_id !== undefined) {
            const k = this.sql.exec(`SELECT key_record FROM block_keys WHERE key_id = ?`, op.key_id).toArray()[0];
            if (!k) throw new RelayError(409, "KEY_UNKNOWN", `unknown key_id ${op.key_id}`, false, { key_id: op.key_id });
            if (k.key_record === null) throw new RelayError(410, "KEY_SHREDDED", `shredded key_id ${op.key_id}`, false, { key_id: op.key_id });
            const pend = this.sql.exec(`SELECT 1 FROM shred_marks WHERE key_id = ? AND state IN ('pending_confirm', 'scheduled') LIMIT 1`, op.key_id).toArray()[0];
            if (pend) throw new RelayError(409, "KEY_PENDING_SHRED", `key_id ${op.key_id} has pending/scheduled shred mark`, true, { key_id: op.key_id });
          }
          const dup = this.sql.exec(`SELECT seq FROM ops WHERE op_id = ?`, op.op_id).toArray()[0];
          if (dup) { acked.push({ op_id: op.op_id, seq: Number(dup.seq) }); continue; }
          const row = this.sql.exec(
            `INSERT INTO ops (op_id, device_id, created_at, key_id, envelope) VALUES (?, ?, ?, ?, ?) RETURNING seq`,
            op.op_id, op.device_id || auth.deviceId, now, op.key_id ?? null, b64ToBytes(op.envelope_b64),
          ).toArray()[0];
          acked.push({ op_id: op.op_id, seq: Number(row.seq) });
        }
        if (marksIn.length > 0) shredResults = this.applyShredMarks(marksIn, b.seen_seq ?? 0, preBatchHeadSeq, false, false, auth.deviceId, now, false);
        headSeq = this.headSeq();
      });
      if (shredResults.length > 0) await this.rescheduleAlarm(now);
      if (acked.length > 0 || shredResults.length > 0 || cancels.length > 0) this.broadcastWake(auth.deviceId, headSeq);
      return jsonRes({ ok: true, epoch: this.epoch, acked, ...(shredResults.length > 0 ? { shred_results: shredResults } : {}), head_seq: headSeq });
    }

    if (req.method === "POST" && path === "/v1/keys") {
      const b = (await req.json()) as { key_records?: KeyRecIn[]; key_material?: { keyring?: { gen: number; blob_b64: string }; vault_header?: { gen: number; blob_b64: string } } };
      const ackedKeyIds: string[] = [], matGens: { keyring?: number; vault_header?: number } = {};
      this.ctx.storage.transactionSync(() => {
        for (const rec of b.key_records ?? []) { this.upsertKeyRecord(rec, auth.deviceId, now); ackedKeyIds.push(rec.key_id); }
        if (b.key_material?.keyring) matGens.keyring = this.upsertKeyMaterial("keyring", b.key_material.keyring.gen, b.key_material.keyring.blob_b64, now);
        if (b.key_material?.vault_header) matGens.vault_header = this.upsertKeyMaterial("vault_header", b.key_material.vault_header.gen, b.key_material.vault_header.blob_b64, now);
      });
      return jsonRes({ ok: true, acked_key_ids: ackedKeyIds, key_material_gens: matGens });
    }

    if (req.method === "POST" && path === "/v1/keys/shred") {
      const b = (await req.json()) as { seen_seq?: number; expedite?: boolean; migration_exempt?: boolean; marks?: ShredMarkIn[] };
      const marksIn = b.marks ?? [];
      let results: ShredResultOut[] = [];
      this.ctx.storage.transactionSync(() => {
        results = this.applyShredMarks(marksIn, b.seen_seq ?? 0, this.headSeq(), Boolean(b.expedite), Boolean(b.migration_exempt), auth.deviceId, now, true);
      });
      await this.rescheduleAlarm(now);
      if (results.length > 0) this.broadcastWake(auth.deviceId, this.headSeq());
      return jsonRes({ ok: true, results });
    }

    if (req.method === "POST" && path === "/v1/keys/cancel") {
      const b = (await req.json()) as { key_ids?: string[] };
      let cancelled: string[] = [];
      this.ctx.storage.transactionSync(() => { cancelled = this.cancelKeyMarks(b.key_ids ?? [], auth.deviceId); });
      if (cancelled.length > 0) this.broadcastWake(auth.deviceId, this.headSeq());
      return jsonRes({ ok: true, cancelled });
    }

    if (req.method === "POST" && path === "/v1/keys/confirm") {
      const b = (await req.json()) as { key_ids?: string[]; grace_ms?: number };
      const minGrace = this.tGraceMinMs(), graceMs = Number(b.grace_ms ?? minGrace);
      if (!Number.isFinite(graceMs) || graceMs < minGrace) throw new RelayError(422, "GRACE_TOO_SHORT", `grace_ms ${graceMs} < ${minGrace}`, false, { min_grace_ms: minGrace });
      const results: ShredResultOut[] = [];
      this.ctx.storage.transactionSync(() => {
        for (const kid of b.key_ids ?? []) {
          const kr = this.sql.exec(`SELECT key_record FROM block_keys WHERE key_id = ?`, kid).toArray()[0];
          if (!kr) throw new RelayError(409, "KEY_UNKNOWN", `unknown key_id ${kid}`, false, { key_id: kid });
          if (kr.key_record === null) throw new RelayError(410, "KEY_SHREDDED", `key ${kid} already shredded`, false, { key_id: kid });
          const nb = now + Math.max(graceMs, minGrace);
          const pending = this.sql.exec(`SELECT mark_id FROM shred_marks WHERE key_id = ? AND state = 'pending_confirm'`, kid).toArray();
          if (pending.length > 0) {
            this.sql.exec(`UPDATE shred_marks SET state = 'scheduled', confirmed_at_ms = ?, not_before_ms = ? WHERE key_id = ? AND state = 'pending_confirm'`, now, nb, kid);
            results.push({ key_id: kid, state: "scheduled", not_before_ms: nb });
          }
        }
      });
      await this.rescheduleAlarm(now);
      if (results.length > 0) this.broadcastWake(auth.deviceId, this.headSeq());
      return jsonRes({ ok: true, results });
    }

    if (req.method === "PUT" && path === "/v1/snapshots/state") {
      const reqEpoch = req.headers.get("x-journal-epoch") ?? "", coversSeq = Number.parseInt(req.headers.get("x-covers-seq") ?? "-1", 10);
      if (reqEpoch !== this.epoch || !Number.isFinite(coversSeq) || coversSeq < 0) {
        throw new RelayError(409, "CAS_MISMATCH", "snapshot epoch mismatch or invalid covers_seq", true, { remote_epoch: this.epoch });
      }
      const latest = this.sql.exec(`SELECT covers_seq FROM phone_snapshots WHERE journal_epoch = ? ORDER BY covers_seq DESC LIMIT 1`, this.epoch).toArray()[0];
      if (latest && coversSeq <= Number(latest.covers_seq)) {
        throw new RelayError(409, "CAS_MISMATCH", `covers_seq ${coversSeq} <= latest ${latest.covers_seq}`, true, { latest_covers_seq: Number(latest.covers_seq) });
      }
      const bytes = new Uint8Array(await req.arrayBuffer());
      if (bytes.byteLength === 0 || bytes.byteLength > MAX_SNAP_BYTES) throw new RelayError(400, "INVALID_ARGUMENT", "invalid snapshot body size");
      const snapshotId = req.headers.get("x-snapshot-id") || crypto.randomUUID();
      const r2Key = `snapshots/state/${this.epoch}/${String(coversSeq).padStart(12, "0")}-${snapshotId}.mnp1`;
      await this.env.ARCHIVE_BUCKET.put(r2Key, bytes);
      const pruneKeys: string[] = [];
      this.ctx.storage.transactionSync(() => {
        this.sql.exec(`INSERT INTO phone_snapshots (snapshot_id, journal_epoch, covers_seq, r2_key, created_by, created_at_ms) VALUES (?, ?, ?, ?, ?, ?)`, snapshotId, this.epoch, coversSeq, r2Key, auth.deviceId, now);
        const all = this.sql.exec(`SELECT snapshot_id, r2_key FROM phone_snapshots ORDER BY created_at_ms DESC, covers_seq DESC`).toArray();
        for (const old of all.slice(2)) {
          this.sql.exec(`DELETE FROM phone_snapshots WHERE snapshot_id = ?`, old.snapshot_id);
          pruneKeys.push(String(old.r2_key));
        }
      });
      for (const k of pruneKeys) { try { await this.env.ARCHIVE_BUCKET.delete(k); } catch { /* best-effort R2 trim */ } }
      return jsonRes({ ok: true, snapshot_id: snapshotId, journal_epoch: this.epoch, covers_seq: coversSeq });
    }

    if (req.method === "POST" && path === "/v1/devices") {
      const b = (await req.json()) as { device_name: string; scope: Scope; token_sha256_hex: string; ciphertext_b64: string; device_id?: string; pair_id?: string };
      if (!b.device_name || (b.scope !== "read" && b.scope !== "read-write") || !HEX64.test(b.token_sha256_hex ?? "")) throw new RelayError(400, "INVALID_ARGUMENT", "invalid pairing request");
      const deviceId = b.device_id ?? randomDeviceId(), pairId = b.pair_id ?? randomPairId(), expiresAt = now + Number(this.env.PAIRING_TTL_MS || 600_000);
      this.ctx.storage.transactionSync(() => {
        this.sql.exec(`INSERT INTO devices (device_id, device_name, token_sha256_hex, scope, last_pulled_seq, last_seen_at_ms, created_at_ms, claimed_at_ms, revoked_at_ms) VALUES (?, ?, ?, ?, 0, ?, ?, NULL, NULL)`, deviceId, b.device_name, b.token_sha256_hex.toLowerCase(), b.scope, now, now);
        this.sql.exec(`INSERT INTO pairing_tickets (pair_id, kind, device_id, scope, ciphertext, created_by, expires_at_ms) VALUES (?, 'pair', ?, ?, ?, ?, ?)`, pairId, deviceId, b.scope, b64ToBytes(b.ciphertext_b64), auth.deviceId, expiresAt);
      });
      await this.rescheduleAlarm(now);
      return jsonRes({ ok: true, device_id: deviceId, pair_id: pairId, expires_at_ms: expiresAt });
    }

    const refreshMatch = path.match(/^\/v1\/devices\/([^/]+)\/refresh$/);
    if (req.method === "POST" && refreshMatch) {
      const targetId = decodeURIComponent(refreshMatch[1]);
      const b = (await req.json()) as { ciphertext_b64: string; pair_id?: string };
      const target = this.sql.exec(`SELECT scope, claimed_at_ms, revoked_at_ms FROM devices WHERE device_id = ?`, targetId).toArray()[0];
      if (!target || target.claimed_at_ms === null || target.revoked_at_ms !== null) throw new RelayError(404, "NOT_FOUND", `active device ${targetId} not found`);
      const pairId = b.pair_id ?? randomPairId(), expiresAt = now + Number(this.env.PAIRING_TTL_MS || 600_000);
      this.sql.exec(`INSERT INTO pairing_tickets (pair_id, kind, device_id, scope, ciphertext, created_by, expires_at_ms) VALUES (?, 'refresh', ?, ?, ?, ?, ?)`, pairId, targetId, String(target.scope), b64ToBytes(b.ciphertext_b64), auth.deviceId, expiresAt);
      await this.rescheduleAlarm(now);
      return jsonRes({ ok: true, device_id: targetId, pair_id: pairId, expires_at_ms: expiresAt });
    }

    if (req.method === "GET" && path === "/v1/devices") {
      return jsonRes({ ok: true, devices: this.sql.exec(`SELECT device_id, device_name, scope, last_pulled_seq, last_seen_at_ms, created_at_ms, claimed_at_ms, revoked_at_ms FROM devices ORDER BY created_at_ms ASC`).toArray() });
    }

    const deleteMatch = path.match(/^\/v1\/devices\/([^/]+)$/);
    if (req.method === "DELETE" && deleteMatch) {
      const targetId = decodeURIComponent(deleteMatch[1]);
      if (!this.sql.exec(`SELECT 1 FROM devices WHERE device_id = ?`, targetId).toArray()[0]) throw new RelayError(404, "NOT_FOUND", `device ${targetId} not found`);
      this.ctx.storage.transactionSync(() => {
        this.sql.exec(`UPDATE devices SET revoked_at_ms = COALESCE(revoked_at_ms, ?) WHERE device_id = ?`, now, targetId);
        this.sql.exec(`DELETE FROM pairing_tickets WHERE device_id = ?`, targetId);
      });
      this.disconnectDeviceWs(targetId);
      return jsonRes({ ok: true, device_id: targetId, revoked_at_ms: now });
    }

    throw new RelayError(404, "NOT_FOUND", `unknown endpoint ${req.method} ${path}`);
  }

  async webSocketMessage(_ws: WebSocket, _msg: string | ArrayBuffer): Promise<void> {}
  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> { try { ws.close(code === 1005 || code === 1006 || code === 1015 ? 1000 : code, reason); } catch { /* ignore */ } }
  async webSocketError(ws: WebSocket): Promise<void> { try { ws.close(1011, "error"); } catch { /* ignore */ } }

  async alarm(info?: AlarmInvocationInfo): Promise<void> {
    const now = this.nowMs();
    let expiredTickets = 0, executedShreds = 0;
    this.ctx.storage.transactionSync(() => {
      for (const m of this.sql.exec(`SELECT mark_id, key_id FROM shred_marks WHERE state = 'scheduled' AND not_before_ms IS NOT NULL AND not_before_ms <= ?`, now).toArray()) {
        executedShreds++;
        this.sql.exec(`UPDATE block_keys SET key_record = NULL, shredded_at_ms = COALESCE(shredded_at_ms, ?) WHERE key_id = ?`, now, m.key_id);
        this.sql.exec(`UPDATE shred_marks SET state = 'executed', executed_at_ms = ? WHERE mark_id = ?`, now, m.mark_id);
      }
      for (const t of this.sql.exec(`SELECT pair_id, kind, device_id FROM pairing_tickets WHERE expires_at_ms <= ?`, now).toArray()) {
        expiredTickets++;
        this.sql.exec(`DELETE FROM pairing_tickets WHERE pair_id = ?`, t.pair_id);
        if (t.kind === "pair") this.sql.exec(`DELETE FROM devices WHERE device_id = ? AND claimed_at_ms IS NULL`, t.device_id);
      }
    });
    if (executedShreds > 0) this.broadcastWake(null, this.headSeq());
    const nextArchiveAt = Number(this.metaGet("next_archive_at_ms") ?? 0);
    if (now >= nextArchiveAt || (expiredTickets === 0 && executedShreds === 0)) {
      try {
        let lastArchived = Number(this.metaGet("last_archive_seq") ?? 0);
        for (;;) {
          const batch = this.sql.exec(`SELECT seq, op_id, key_id, device_id, created_at, envelope FROM ops WHERE seq > ? ORDER BY seq ASC LIMIT ?`, lastArchived, MAX_PUSH_OPS).toArray()
            .map((r) => ({ seq: Number(r.seq), op_id: String(r.op_id), key_id: r.key_id === null ? null : String(r.key_id), device_id: String(r.device_id), created_at: Number(r.created_at), envelope: toU8(r.envelope) }));
          if (batch.length === 0) break;
          const seg: typeof batch = [];
          let bytes = 0;
          for (const op of batch) {
            if (seg.length > 0 && bytes + op.envelope.byteLength > MAX_ARCHIVE_BYTES) break;
            seg.push(op); bytes += op.envelope.byteLength;
          }
          const r2Key = `archives/ops/${this.epoch}/${String(seg[0].seq).padStart(12, "0")}-${String(seg[seg.length - 1].seq).padStart(12, "0")}.mna1`;
          if (!(await this.env.ARCHIVE_BUCKET.head(r2Key))) await this.env.ARCHIVE_BUCKET.put(r2Key, encodeMna1(this.epoch, seg, now));
          lastArchived = seg[seg.length - 1].seq;
          this.metaSet("last_archive_seq", String(lastArchived));
        }
        const { records, marks, keyring, vaultHeader } = this.loadKeyState();
        if (keyring) {
          const mnks = encodeMnks(now, keyring, vaultHeader, records.filter((r) => r.key_record !== null), marks);
          await this.env.ARCHIVE_BUCKET.put("archives/keys/latest.mnks", mnks);
          await this.env.ARCHIVE_BUCKET.put(`archives/keys/history/${new Date(now).toISOString().slice(0, 10)}.mnks`, mnks);
        }
        this.metaSet("next_archive_at_ms", String(now + this.archiveIntervalMs()));
      } catch (err) {
        if ((info?.retryCount ?? 0) >= 5) { await this.rescheduleAlarm(now); return; }
        throw err;
      }
    }
    await this.rescheduleAlarm(now);
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/v1/")) return env.SYNC_DO.get(env.SYNC_DO.idFromName("primary")).fetch(req);
    if (env.ASSETS) {
      const res = await env.ASSETS.fetch(req), h = new Headers(res.headers);
      const isLoopbackHttp = url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost");
      h.set("content-security-policy", isLoopbackHttp ? PWA_CSP.replace("wss: https:", "ws: wss: http: https:") : PWA_CSP);
      h.set("x-content-type-options", "nosniff");
      h.set("referrer-policy", "no-referrer");
      h.set("x-frame-options", "DENY");
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
    }
    return env.SYNC_DO.get(env.SYNC_DO.idFromName("primary")).fetch(req);
  },
};
