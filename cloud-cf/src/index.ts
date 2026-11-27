import { DurableObject } from "cloudflare:workers";
import { b64ToBytes, bytesEqual, bytesToB64, computeKeysDigest, encodeMna1, encodeMnks, KeyMaterialEntry, KeyRecordWire, randomDeviceId, randomPairId, sha256Hex, ShredMarkState, ShredMarkWire, timingSafeEqualStr, toU8 } from "./wire";

export interface Env {
  SYNC_DO: DurableObjectNamespace<SyncJournalDO>; ARCHIVE_BUCKET: R2Bucket; BOOTSTRAP_TOKEN: string; ASSETS?: Fetcher;
  DAILY_ARCHIVE_INTERVAL_MS?: string; PAIRING_TTL_MS?: string; T_GRACE_MIN_MS?: string; SHRED_BATCH_LIMIT_24H?: string; ALLOW_TEST_HOOKS?: string;
}
type Scope = "read" | "read+clip" | "clip-write" | "read-write";
type ClipKind = "text" | "image";
interface WsMeta { deviceId: string; scope: Scope; }
interface KeyRecIn { key_id: string; wrap_gen: number; key_record_b64: string; }
interface ShredMarkIn { mark_id: string; key_id: string; grace_ms: number; requested_by?: string; }
interface ShredResultOut { key_id: string; state: ShredMarkState; not_before_ms: number | null; }
class RelayError extends Error { constructor(public status: number, public code: string, message: string, public retryable = false, public details?: Record<string, unknown>) { super(message); } }
const jsonRes = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const cancelBody = async (req: Request): Promise<void> => { if (req.body && !req.bodyUsed) { try { await req.body.cancel(); } catch { /* ignore */ } } };
const VALID_SCOPES = new Set<string>(["read", "read+clip", "clip-write", "read-write"]);
const isScope = (v: unknown): v is Scope => typeof v === "string" && VALID_SCOPES.has(v);
const isClipKind = (v: unknown): v is ClipKind => v === "text" || v === "image";
const MAX_PUSH_OPS = 500, MAX_PUSH_BYTES = 4 * 1024 * 1024, MAX_ARCHIVE_BYTES = 8 * 1024 * 1024, MAX_SNAP_BYTES = 16 * 1024 * 1024;
const CLIP_MAX_ITEMS = 100, CLIP_MAX_META_BYTES = 96 * 1024, CLIP_MAX_BLOB_META_BYTES = 32 * 1024, CLIP_MAX_BLOB_BYTES = 11_010_048, CLIP_MAX_EPHEMERAL_BYTES = 256 * 1024, MAX_CLIP_JSON_BYTES = 512 * 1024;
const HEX64 = /^[0-9a-f]{64}$/i, DEV_ID_RE = /^dev_[a-z0-9_]{4,44}$/, SNAP_ID_RE = /^[0-9A-Za-z_-]{1,64}$/, ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/, INT_RE = /^\d+$/, DAY_MS = 86_400_000, WEEK_MS = 7 * DAY_MS, CLIP_TTL_MS = WEEK_MS;
const posInt = (raw: string | undefined, def: number): number => { const n = Number(raw); return Number.isSafeInteger(n) && n > 0 ? n : def; };
const buildPwaCsp = (u: URL): string => `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; manifest-src 'self'; worker-src 'self'; connect-src 'self' ${u.protocol === "http:" ? "ws:" : "wss:"}//${u.host}; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`;

export class SyncJournalDO extends DurableObject<Env> {
  private sql: SqlStorage;
  private epoch = "";
  private clockOffsetMs = 0;
  private failNextClipBlobRegister = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    this.ctx.blockConcurrencyWhile(async () => { this.initSchema(); await this.rescheduleAlarm(this.nowMs()); });
  }

  private assertTestHook(): void { if (this.env.ALLOW_TEST_HOOKS !== "1") throw new Error("test hooks disabled"); }
  private archiveIntervalMs(): number { return posInt(this.env.DAILY_ARCHIVE_INTERVAL_MS, DAY_MS); }
  private tGraceMinMs(): number { return posInt(this.env.T_GRACE_MIN_MS, DAY_MS); }
  private shredBatchLimit24h(): number { return posInt(this.env.SHRED_BATCH_LIMIT_24H, 20); }
  private pairingTtlMs(): number { return posInt(this.env.PAIRING_TTL_MS, 600_000); }
  private nowMs(): number { return Date.now() + this.clockOffsetMs; }
  private headSeq(): number { return Number(this.sql.exec(`SELECT COALESCE(MAX(seq), 0) AS h FROM ops`).toArray()[0]?.h ?? 0); }
  private metaGet(key: string): string | null { const r = this.sql.exec(`SELECT value FROM journal_meta WHERE key = ?`, key).toArray()[0]; return r ? String(r.value) : null; }
  private metaSet(key: string, val: string): void { this.sql.exec(`INSERT OR REPLACE INTO journal_meta (key, value) VALUES (?, ?)`, key, val); }

  setClockOffsetMs(offsetMs: number): number { this.assertTestHook(); this.clockOffsetMs = offsetMs; return this.nowMs(); }
  setFailNextClipBlobRegister(fail: boolean): void { this.assertTestHook(); this.failNextClipBlobRegister = fail; }
  runInitSchemaForTest(): void { this.assertTestHook(); this.initSchema(); }
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
      CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, device_name TEXT NOT NULL, token_sha256_hex TEXT NOT NULL UNIQUE, scope TEXT NOT NULL CHECK (scope IN ('read', 'read+clip', 'clip-write', 'read-write')), last_pulled_seq INTEGER NOT NULL DEFAULT 0, last_seen_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, claimed_at_ms INTEGER, revoked_at_ms INTEGER);
      CREATE TABLE IF NOT EXISTS pairing_tickets (pair_id TEXT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'pair' CHECK (kind IN ('pair', 'refresh')), device_id TEXT NOT NULL REFERENCES devices(device_id), scope TEXT NOT NULL CHECK (scope IN ('read', 'read+clip', 'clip-write', 'read-write')), ciphertext BLOB NOT NULL, created_by TEXT NOT NULL, expires_at_ms INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS ops (seq INTEGER PRIMARY KEY, op_id TEXT NOT NULL UNIQUE, device_id TEXT NOT NULL, created_at INTEGER NOT NULL, key_id TEXT, envelope BLOB NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_ops_key ON ops (key_id, seq) WHERE key_id IS NOT NULL;
      CREATE TABLE IF NOT EXISTS block_keys (key_id TEXT PRIMARY KEY, wrap_gen INTEGER NOT NULL, key_record BLOB, created_by_device TEXT NOT NULL, created_at_ms INTEGER NOT NULL, shredded_at_ms INTEGER);
      CREATE TABLE IF NOT EXISTS shred_marks (mark_id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES block_keys(key_id), seen_seq INTEGER NOT NULL, requested_by TEXT NOT NULL, requested_at_ms INTEGER NOT NULL, grace_ms INTEGER NOT NULL, not_before_ms INTEGER, state TEXT NOT NULL CHECK (state IN ('pending_confirm', 'scheduled', 'cancelled', 'executed')), confirmed_at_ms INTEGER, cancelled_by TEXT, executed_at_ms INTEGER);
      CREATE INDEX IF NOT EXISTS idx_shred_marks_due ON shred_marks (not_before_ms) WHERE state = 'scheduled';
      CREATE INDEX IF NOT EXISTS idx_shred_marks_key ON shred_marks (key_id);
      CREATE TABLE IF NOT EXISTS key_material (kind TEXT PRIMARY KEY CHECK (kind IN ('keyring', 'vault_header', 'clip_key')), gen INTEGER NOT NULL, blob BLOB NOT NULL, updated_at_ms INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS phone_snapshots (snapshot_id TEXT PRIMARY KEY, journal_epoch TEXT NOT NULL, covers_seq INTEGER NOT NULL, r2_key TEXT NOT NULL, created_by TEXT NOT NULL, created_at_ms INTEGER NOT NULL, UNIQUE (journal_epoch, covers_seq));
      CREATE TABLE IF NOT EXISTS clip_items (clip_id TEXT PRIMARY KEY, clip_kid TEXT NOT NULL, device_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('text', 'image')), created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, meta_envelope BLOB NOT NULL, r2_key TEXT, blob_bytes INTEGER);
      CREATE INDEX IF NOT EXISTS idx_clip_items_expires ON clip_items (expires_at_ms);
    `);
    const tableSql = (name: string): string => String(this.sql.exec(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, name).toArray()[0]?.sql ?? "");
    const needsScopeMig = !tableSql("devices").includes("'read+clip'") || !tableSql("pairing_tickets").includes("'read+clip'");
    const needsKmMig = !tableSql("key_material").includes("'clip_key'");
    if (needsScopeMig || needsKmMig) {
      this.ctx.storage.transactionSync(() => {
        if (needsScopeMig) {
          this.sql.exec(`
            CREATE TABLE devices_m4 (device_id TEXT PRIMARY KEY, device_name TEXT NOT NULL, token_sha256_hex TEXT NOT NULL UNIQUE, scope TEXT NOT NULL CHECK (scope IN ('read', 'read+clip', 'clip-write', 'read-write')), last_pulled_seq INTEGER NOT NULL DEFAULT 0, last_seen_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, claimed_at_ms INTEGER, revoked_at_ms INTEGER);
            INSERT INTO devices_m4 SELECT device_id, device_name, token_sha256_hex, scope, last_pulled_seq, last_seen_at_ms, created_at_ms, claimed_at_ms, revoked_at_ms FROM devices;
            CREATE TABLE pairing_tickets_tmp (pair_id TEXT PRIMARY KEY, kind TEXT NOT NULL, device_id TEXT NOT NULL, scope TEXT NOT NULL, ciphertext BLOB NOT NULL, created_by TEXT NOT NULL, expires_at_ms INTEGER NOT NULL);
            INSERT INTO pairing_tickets_tmp SELECT pair_id, kind, device_id, scope, ciphertext, created_by, expires_at_ms FROM pairing_tickets;
            DROP TABLE pairing_tickets;
            DROP TABLE devices;
            ALTER TABLE devices_m4 RENAME TO devices;
            CREATE TABLE pairing_tickets (pair_id TEXT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'pair' CHECK (kind IN ('pair', 'refresh')), device_id TEXT NOT NULL REFERENCES devices(device_id), scope TEXT NOT NULL CHECK (scope IN ('read', 'read+clip', 'clip-write', 'read-write')), ciphertext BLOB NOT NULL, created_by TEXT NOT NULL, expires_at_ms INTEGER NOT NULL);
            INSERT INTO pairing_tickets SELECT pair_id, kind, device_id, scope, ciphertext, created_by, expires_at_ms FROM pairing_tickets_tmp;
            DROP TABLE pairing_tickets_tmp;
          `);
        }
        if (needsKmMig) {
          this.sql.exec(`
            CREATE TABLE key_material_m4 (kind TEXT PRIMARY KEY CHECK (kind IN ('keyring', 'vault_header', 'clip_key')), gen INTEGER NOT NULL, blob BLOB NOT NULL, updated_at_ms INTEGER NOT NULL);
            INSERT INTO key_material_m4 SELECT kind, gen, blob, updated_at_ms FROM key_material;
            DROP TABLE key_material;
            ALTER TABLE key_material_m4 RENAME TO key_material;
          `);
        }
      });
    }
    const existing = this.metaGet("journal_epoch");
    if (existing) this.epoch = existing;
    else { this.epoch = crypto.randomUUID(); this.metaSet("journal_epoch", this.epoch); this.metaSet("last_archive_seq", "0"); this.metaSet("m2_migration_exempt_used", "1"); }
    this.sql.exec(`INSERT OR IGNORE INTO journal_meta (key, value) VALUES ('next_archive_at_ms', ?)`, String(this.nowMs() + this.archiveIntervalMs()));
  }

  private loadKeyState() {
    const records: KeyRecordWire[] = this.sql.exec(`SELECT key_id, wrap_gen, key_record, created_at_ms FROM block_keys ORDER BY key_id ASC`).toArray().map((r) => ({ key_id: String(r.key_id), wrap_gen: Number(r.wrap_gen), key_record: r.key_record === null ? null : toU8(r.key_record), created_at_ms: Number(r.created_at_ms) }));
    const marks: ShredMarkWire[] = this.sql.exec(`SELECT mark_id, key_id, seen_seq, requested_by, requested_at_ms, grace_ms, not_before_ms, state, confirmed_at_ms, cancelled_by, executed_at_ms FROM shred_marks ORDER BY mark_id ASC`).toArray().map((m) => ({
      mark_id: String(m.mark_id), key_id: String(m.key_id), seen_seq: Number(m.seen_seq), requested_by: String(m.requested_by), requested_at_ms: Number(m.requested_at_ms), grace_ms: Number(m.grace_ms),
      not_before_ms: m.not_before_ms === null ? null : Number(m.not_before_ms), state: String(m.state) as ShredMarkState, confirmed_at_ms: m.confirmed_at_ms === null ? null : Number(m.confirmed_at_ms), cancelled_by: m.cancelled_by === null ? null : String(m.cancelled_by), executed_at_ms: m.executed_at_ms === null ? null : Number(m.executed_at_ms),
    }));
    let keyring: KeyMaterialEntry | null = null, vaultHeader: KeyMaterialEntry | null = null, clipKey: KeyMaterialEntry | null = null;
    for (const m of this.sql.exec(`SELECT kind, gen, blob FROM key_material`).toArray()) {
      const entry = { gen: Number(m.gen), blob: toU8(m.blob) };
      if (m.kind === "keyring") keyring = entry;
      else if (m.kind === "vault_header") vaultHeader = entry;
      else if (m.kind === "clip_key") clipKey = entry;
    }
    return { records, marks, keyring, vaultHeader, clipKey, digest: computeKeysDigest(records, marks, keyring, vaultHeader) };
  }

  private upsertKeyRecord(rec: KeyRecIn, deviceId: string, now: number): void {
    if (!rec.key_id || !Number.isSafeInteger(rec.wrap_gen) || rec.wrap_gen < 1) throw new RelayError(400, "INVALID_ARGUMENT", "invalid key record");
    const raw = b64ToBytes(rec.key_record_b64);
    const cur = this.sql.exec(`SELECT wrap_gen, key_record FROM block_keys WHERE key_id = ?`, rec.key_id).toArray()[0];
    if (!cur) { this.sql.exec(`INSERT INTO block_keys (key_id, wrap_gen, key_record, created_by_device, created_at_ms) VALUES (?, ?, ?, ?, ?)`, rec.key_id, rec.wrap_gen, raw, deviceId, now); return; }
    if (cur.key_record === null) throw new RelayError(410, "KEY_SHREDDED", `key ${rec.key_id} shredded`, false, { key_id: rec.key_id });
    const curGen = Number(cur.wrap_gen);
    if (rec.wrap_gen > curGen) this.sql.exec(`UPDATE block_keys SET wrap_gen = ?, key_record = ? WHERE key_id = ?`, rec.wrap_gen, raw, rec.key_id);
    else if (rec.wrap_gen === curGen && !bytesEqual(toU8(cur.key_record), raw)) throw new RelayError(409, "INTEGRITY_ERROR", `conflicting key_record at wrap_gen=${curGen}`, false, { key_id: rec.key_id });
  }

  private upsertKeyMaterial(kind: "keyring" | "vault_header" | "clip_key", gen: number, blobB64: string, now: number): number {
    if (!Number.isSafeInteger(gen) || gen < 0) throw new RelayError(400, "INVALID_ARGUMENT", `invalid ${kind} gen`);
    const raw = b64ToBytes(blobB64);
    const cur = this.sql.exec(`SELECT gen, blob FROM key_material WHERE kind = ?`, kind).toArray()[0];
    if (!cur) { this.sql.exec(`INSERT INTO key_material (kind, gen, blob, updated_at_ms) VALUES (?, ?, ?, ?)`, kind, gen, raw, now); return gen; }
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
    if (!Number.isSafeInteger(seenSeq) || seenSeq < 0) throw new RelayError(400, "INVALID_ARGUMENT", "seen_seq must be a non-negative safe integer");
    const minGrace = this.tGraceMinMs(), limit24h = this.shredBatchLimit24h();
    const allowExempt = migrationExempt && !expedite && this.metaGet("m2_migration_exempt_used") !== "1";
    const rolling = new Set(this.sql.exec(`SELECT DISTINCT key_id FROM shred_marks WHERE requested_at_ms > ? AND state IN ('scheduled', 'executed')`, now - DAY_MS).toArray().map((r) => String(r.key_id)));
    const results: ShredResultOut[] = [];
    for (const m of marks) {
      if (typeof m.mark_id !== "string" || !m.mark_id || typeof m.key_id !== "string" || !m.key_id || !Number.isSafeInteger(m.grace_ms) || m.grace_ms < 0 || now + m.grace_ms > Number.MAX_SAFE_INTEGER) {
        throw new RelayError(400, "INVALID_ARGUMENT", "invalid shred mark payload");
      }
      if (m.grace_ms < minGrace || (allowExempt && m.grace_ms < WEEK_MS)) {
        throw new RelayError(422, "GRACE_TOO_SHORT", `grace_ms ${m.grace_ms} < ${allowExempt ? WEEK_MS : minGrace}`, false, { key_id: m.key_id, min_grace_ms: allowExempt ? WEEK_MS : minGrace });
      }
      const kr = this.sql.exec(`SELECT key_record FROM block_keys WHERE key_id = ?`, m.key_id).toArray()[0];
      if (!kr) throw new RelayError(409, "KEY_UNKNOWN", `unknown key_id ${m.key_id}`, false, { key_id: m.key_id });
      if (kr.key_record === null) {
        if (rejectExecuted) throw new RelayError(410, "KEY_SHREDDED", `key ${m.key_id} already shredded`, false, { key_id: m.key_id });
        results.push({ key_id: m.key_id, state: "executed", not_before_ms: null });
        continue;
      }
      if (!expedite) {
        const dup = this.sql.exec(`SELECT key_id, state, not_before_ms FROM shred_marks WHERE mark_id = ?`, m.mark_id).toArray()[0];
        if (dup) {
          if (String(dup.key_id) !== m.key_id) throw new RelayError(409, "INTEGRITY_ERROR", `mark_id ${m.mark_id} belongs to another key`, false, { key_id: m.key_id });
          results.push({ key_id: m.key_id, state: String(dup.state) as ShredMarkState, not_before_ms: dup.not_before_ms === null ? null : Number(dup.not_before_ms) });
          continue;
        }
      }
      const stale = this.sql.exec(`SELECT 1 FROM ops WHERE key_id = ? AND seq > ? AND seq <= ? LIMIT 1`, m.key_id, seenSeq, preBatchHeadSeq).toArray()[0];
      if (stale) throw new RelayError(409, "SHRED_STALE", `newer ops exist for key ${m.key_id} after seen_seq=${seenSeq}`, true, { key_id: m.key_id, head_seq: preBatchHeadSeq });
      if (expedite) {
        const cur = this.sql.exec(`SELECT mark_id, state, requested_at_ms, not_before_ms FROM shred_marks WHERE key_id = ? AND state IN ('scheduled', 'pending_confirm') ORDER BY CASE state WHEN 'scheduled' THEN 0 ELSE 1 END, not_before_ms ASC LIMIT 1`, m.key_id).toArray()[0];
        if (cur) {
          if (cur.state === "pending_confirm") throw new RelayError(409, "INVALID_ARGUMENT", `key ${m.key_id} requires confirm before expedite`, false, { key_id: m.key_id });
          const candidate = Math.max(now + Math.max(m.grace_ms, minGrace), Number(cur.requested_at_ms) + minGrace);
          const nextNb = cur.not_before_ms === null ? candidate : Math.min(Number(cur.not_before_ms), candidate);
          this.sql.exec(`UPDATE shred_marks SET not_before_ms = ? WHERE key_id = ? AND state = 'scheduled'`, nextNb, m.key_id);
          results.push({ key_id: m.key_id, state: "scheduled", not_before_ms: nextNb });
          continue;
        }
      } else {
        const active = this.sql.exec(`SELECT mark_id, state, not_before_ms FROM shred_marks WHERE key_id = ? AND state IN ('scheduled', 'pending_confirm') LIMIT 1`, m.key_id).toArray()[0];
        if (active) {
          let nb = active.not_before_ms === null ? null : Number(active.not_before_ms);
          if (active.state === "scheduled" && nb !== null && now + m.grace_ms < nb) {
            nb = now + m.grace_ms;
            this.sql.exec(`UPDATE shred_marks SET not_before_ms = ? WHERE mark_id = ?`, nb, active.mark_id);
          }
          results.push({ key_id: m.key_id, state: String(active.state) as ShredMarkState, not_before_ms: nb });
          continue;
        }
      }
      let state: ShredMarkState = "scheduled", notBefore: number | null = now + m.grace_ms;
      if (!allowExempt && !rolling.has(m.key_id) && rolling.size >= limit24h) { state = "pending_confirm"; notBefore = null; }
      else if (!allowExempt) rolling.add(m.key_id);
      const reqBy = typeof m.requested_by === "string" && DEV_ID_RE.test(m.requested_by) ? m.requested_by : deviceId;
      this.sql.exec(`INSERT INTO shred_marks (mark_id, key_id, seen_seq, requested_by, requested_at_ms, grace_ms, not_before_ms, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, m.mark_id, m.key_id, seenSeq, reqBy, now, m.grace_ms, notBefore, state);
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

  private broadcastClip(excludeDeviceId: string | null, payload: Record<string, unknown>): void {
    const msg = JSON.stringify(payload);
    for (const ws of this.ctx.getWebSockets()) {
      const meta = ws.deserializeAttachment() as WsMeta | null;
      if (meta && meta.scope !== "clip-write" && (!excludeDeviceId || meta.deviceId !== excludeDeviceId)) { try { ws.send(msg); } catch { /* ignore */ } }
    }
  }

  private async deleteR2Keys(keys: string[]): Promise<void> {
    for (const k of keys) { try { await this.env.ARCHIVE_BUCKET.delete(k); } catch { /* best-effort R2 cleanup */ } }
  }

  private pruneClipOverflow(): string[] {
    const evicted: string[] = [];
    for (const r of this.sql.exec(`SELECT clip_id, r2_key FROM clip_items ORDER BY clip_id DESC LIMIT -1 OFFSET ?`, CLIP_MAX_ITEMS).toArray()) {
      this.sql.exec(`DELETE FROM clip_items WHERE clip_id = ?`, r.clip_id);
      if (r.r2_key !== null) evicted.push(String(r.r2_key));
    }
    return evicted;
  }

  private disconnectDeviceWs(deviceId: string): void {
    const msg = JSON.stringify({ type: "device_revoked" });
    for (const ws of this.ctx.getWebSockets()) {
      if ((ws.deserializeAttachment() as WsMeta | null)?.deviceId === deviceId) { try { ws.send(msg); ws.close(4401, "device_revoked"); } catch { /* ignore */ } }
    }
  }

  private async authenticate(req: Request, now: number, touchLastSeen = true): Promise<WsMeta> {
    const auth = req.headers.get("authorization") ?? "";
    let token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token && req.headers.get("upgrade")?.toLowerCase() === "websocket") {
      const bearerProto = (req.headers.get("sec-websocket-protocol") ?? "").split(",").map((s) => s.trim()).find((p) => p.startsWith("bearer."));
      if (bearerProto) token = bearerProto.slice(7);
    }
    if (!token) throw new RelayError(401, "AUTH_REQUIRED", "missing bearer token");
    const row = this.sql.exec(`SELECT device_id, scope, claimed_at_ms, revoked_at_ms FROM devices WHERE token_sha256_hex = ?`, await sha256Hex(token)).toArray()[0];
    if (!row || row.claimed_at_ms === null) throw new RelayError(401, "AUTH_REQUIRED", "unknown or unclaimed device token");
    if (row.revoked_at_ms !== null) throw new RelayError(401, "DEVICE_REVOKED", "device token revoked");
    if (!isScope(row.scope)) throw new RelayError(500, "INTEGRITY_ERROR", "invalid stored device scope");
    if (touchLastSeen) this.sql.exec(`UPDATE devices SET last_seen_at_ms = ? WHERE device_id = ?`, now, row.device_id);
    return { deviceId: String(row.device_id), scope: row.scope };
  }

  private async rescheduleAlarm(now: number): Promise<void> {
    const meta = this.metaGet("next_archive_at_ms");
    let nextAt = meta ? Number(meta) : now + this.archiveIntervalMs();
    if (!meta) this.metaSet("next_archive_at_ms", String(nextAt));
    const duePair = this.sql.exec(`SELECT MIN(expires_at_ms) AS t FROM pairing_tickets`).toArray()[0];
    if (duePair?.t !== null && duePair?.t !== undefined) nextAt = Math.min(nextAt, Number(duePair.t));
    const dueShred = this.sql.exec(`SELECT MIN(not_before_ms) AS t FROM shred_marks WHERE state = 'scheduled' AND not_before_ms IS NOT NULL`).toArray()[0];
    if (dueShred?.t !== null && dueShred?.t !== undefined) nextAt = Math.min(nextAt, Number(dueShred.t));
    const dueClip = this.sql.exec(`SELECT MIN(expires_at_ms) AS t FROM clip_items`).toArray()[0];
    if (dueClip?.t !== null && dueClip?.t !== undefined) nextAt = Math.min(nextAt, Number(dueClip.t));
    await this.ctx.storage.setAlarm(Math.max(Date.now() + 1_000, nextAt - this.clockOffsetMs));
  }

  private async handleClipPost(req: Request, auth: WsMeta, now: number): Promise<Response> {
    const raw = await req.text();
    if (raw.length > MAX_CLIP_JSON_BYTES) throw new RelayError(413, "PAYLOAD_TOO_LARGE", "clip request body too large");
    const b = JSON.parse(raw) as { clip_id?: unknown; clip_kid?: unknown; kind?: unknown; ephemeral?: unknown; meta_envelope_b64?: unknown };
    if (typeof b.clip_id !== "string" || !ULID_RE.test(b.clip_id) || typeof b.clip_kid !== "string" || !ULID_RE.test(b.clip_kid) || b.kind !== "text") {
      throw new RelayError(400, "INVALID_ARGUMENT", "invalid clip_id, clip_kid, or kind");
    }
    if (b.ephemeral !== undefined && typeof b.ephemeral !== "boolean") throw new RelayError(400, "INVALID_ARGUMENT", "ephemeral must be boolean");
    const envBytes = b64ToBytes(b.meta_envelope_b64);
    if (envBytes.byteLength === 0) throw new RelayError(400, "INVALID_ARGUMENT", "empty meta_envelope_b64");
    if (b.ephemeral === true) {
      if (envBytes.byteLength > CLIP_MAX_EPHEMERAL_BYTES) throw new RelayError(413, "PAYLOAD_TOO_LARGE", "ephemeral clip exceeds 256 KiB");
      const frame = JSON.stringify({ type: "clip_ephemeral", clip_id: b.clip_id, clip_kid: b.clip_kid, device_id: auth.deviceId, envelope_b64: b.meta_envelope_b64 });
      let deliveredTo = 0;
      for (const ws of this.ctx.getWebSockets()) {
        const meta = ws.deserializeAttachment() as WsMeta | null;
        if (meta?.scope === "read-write" && meta.deviceId !== auth.deviceId) { try { ws.send(frame); deliveredTo++; } catch { /* ignore stale socket */ } }
      }
      if (deliveredTo === 0) throw new RelayError(409, "NO_ONLINE_DESKTOP", "no online desktop daemon to receive ephemeral clip", true);
      return jsonRes({ ok: true, clip_id: b.clip_id, delivered_to: deliveredTo });
    }
    if (envBytes.byteLength > CLIP_MAX_META_BYTES) throw new RelayError(413, "PAYLOAD_TOO_LARGE", "clip meta envelope exceeds 96 KiB");
    let createdAtMs = now, expiresAtMs = now + CLIP_TTL_MS, inserted = false, evictedR2Keys: string[] = [];
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(`UPDATE devices SET last_seen_at_ms = ? WHERE device_id = ?`, now, auth.deviceId);
      const existing = this.sql.exec(`SELECT created_at_ms, expires_at_ms FROM clip_items WHERE clip_id = ?`, b.clip_id as string).toArray()[0];
      if (existing) { createdAtMs = Number(existing.created_at_ms); expiresAtMs = Number(existing.expires_at_ms); return; }
      this.sql.exec(`INSERT INTO clip_items (clip_id, clip_kid, device_id, kind, created_at_ms, expires_at_ms, meta_envelope, r2_key, blob_bytes) VALUES (?, ?, ?, 'text', ?, ?, ?, NULL, NULL)`, b.clip_id as string, b.clip_kid as string, auth.deviceId, createdAtMs, expiresAtMs, envBytes);
      evictedR2Keys = this.pruneClipOverflow();
      inserted = true;
    });
    if (evictedR2Keys.length > 0) await this.deleteR2Keys(evictedR2Keys);
    if (inserted) { await this.rescheduleAlarm(now); this.broadcastClip(auth.deviceId, { type: "clip_wake", clip_id: b.clip_id, kind: "text", created_at_ms: createdAtMs }); }
    return jsonRes({ ok: true, clip_id: b.clip_id, created_at_ms: createdAtMs, expires_at_ms: expiresAtMs });
  }

  private async handleClipBlobPut(req: Request, auth: WsMeta, now: number): Promise<Response> {
    const clipId = req.headers.get("x-clip-id")?.trim() ?? "", clipKid = req.headers.get("x-clip-kid")?.trim() ?? "", kind = req.headers.get("x-clip-kind")?.trim() ?? "", metaB64 = req.headers.get("x-clip-meta-b64")?.trim() ?? "", clRaw = req.headers.get("content-length")?.trim() ?? "";
    if (!ULID_RE.test(clipId) || !ULID_RE.test(clipKid) || !isClipKind(kind) || !metaB64) throw new RelayError(400, "INVALID_ARGUMENT", "invalid X-Clip-* headers");
    const metaBytes = b64ToBytes(metaB64);
    if (metaBytes.byteLength === 0 || metaBytes.byteLength > CLIP_MAX_BLOB_META_BYTES) throw new RelayError(400, "INVALID_ARGUMENT", "X-Clip-Meta-B64 must decode to 1..32768 bytes");
    if (!INT_RE.test(clRaw)) throw new RelayError(400, "INVALID_ARGUMENT", "missing or invalid Content-Length");
    const contentLength = Number(clRaw);
    if (!Number.isSafeInteger(contentLength) || contentLength <= 0) throw new RelayError(400, "INVALID_ARGUMENT", "Content-Length must be positive");
    if (contentLength > CLIP_MAX_BLOB_BYTES) throw new RelayError(413, "PAYLOAD_TOO_LARGE", `clip blob exceeds ${CLIP_MAX_BLOB_BYTES} bytes`);
    if (!req.body) throw new RelayError(400, "INVALID_ARGUMENT", "request body required");
    const existing0 = this.sql.exec(`SELECT created_at_ms, expires_at_ms, blob_bytes FROM clip_items WHERE clip_id = ?`, clipId).toArray()[0];
    if (existing0) {
      await cancelBody(req);
      return jsonRes({ ok: true, clip_id: clipId, blob_bytes: Number(existing0.blob_bytes ?? contentLength), created_at_ms: Number(existing0.created_at_ms), expires_at_ms: Number(existing0.expires_at_ms) });
    }
    const r2Key = `clip/blobs/${clipId}.mnc1`;
    const fixed = new FixedLengthStream(contentLength);
    const [pipeRes, putRes] = await Promise.allSettled([
      req.body.pipeTo(fixed.writable),
      this.env.ARCHIVE_BUCKET.put(r2Key, fixed.readable, { httpMetadata: { contentType: "application/octet-stream" }, customMetadata: { clip_id: clipId, clip_kid: clipKid, device_id: auth.deviceId } }),
    ]);
    if (pipeRes.status === "rejected" || putRes.status === "rejected" || !putRes.value) {
      await this.deleteR2Keys([r2Key]);
      const reason = pipeRes.status === "rejected" ? String(pipeRes.reason) : putRes.status === "rejected" ? String(putRes.reason) : "R2 put returned null";
      throw new RelayError(400, "INVALID_ARGUMENT", `CONTENT_LENGTH_MISMATCH: ${reason}`);
    }
    let createdAtMs = now, expiresAtMs = now + CLIP_TTL_MS, blobBytes = contentLength, inserted = false, evictedR2Keys: string[] = [];
    try {
      this.ctx.storage.transactionSync(() => {
        if (this.failNextClipBlobRegister) { this.failNextClipBlobRegister = false; throw new RelayError(503, "SYNC_OFFLINE", "injected DO clip registration failure", true); }
        const existing = this.sql.exec(`SELECT created_at_ms, expires_at_ms, blob_bytes FROM clip_items WHERE clip_id = ?`, clipId).toArray()[0];
        if (existing) { createdAtMs = Number(existing.created_at_ms); expiresAtMs = Number(existing.expires_at_ms); blobBytes = Number(existing.blob_bytes ?? contentLength); return; }
        this.sql.exec(`INSERT INTO clip_items (clip_id, clip_kid, device_id, kind, created_at_ms, expires_at_ms, meta_envelope, r2_key, blob_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, clipId, clipKid, auth.deviceId, kind, createdAtMs, expiresAtMs, metaBytes, r2Key, contentLength);
        evictedR2Keys = this.pruneClipOverflow();
        inserted = true;
      });
    } catch (err) {
      await this.deleteR2Keys([r2Key]);
      throw err;
    }
    if (evictedR2Keys.length > 0) await this.deleteR2Keys(evictedR2Keys);
    if (inserted) { await this.rescheduleAlarm(now); this.broadcastClip(auth.deviceId, { type: "clip_wake", clip_id: clipId, kind, created_at_ms: createdAtMs }); }
    return jsonRes({ ok: true, clip_id: clipId, blob_bytes: blobBytes, created_at_ms: createdAtMs, expires_at_ms: expiresAtMs });
  }

  async fetch(req: Request): Promise<Response> {
    try { return await this.route(req); } catch (e) {
      await cancelBody(req);
      if (e instanceof RelayError) return jsonRes({ ok: false, error: { code: e.code, message: e.message, retryable: e.retryable, ...(e.details ? { details: e.details } : {}) } }, e.status);
      const badInput = e instanceof SyntaxError || e instanceof TypeError || (e instanceof Error && e.name === "InvalidCharacterError");
      return jsonRes({ ok: false, error: { code: badInput ? "INVALID_ARGUMENT" : "SYNC_OFFLINE", message: e instanceof Error ? e.message : "relay error", retryable: !badInput } }, badInput ? 400 : 503);
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
      if (b.revoke_existing) await this.rescheduleAlarm(now);
      return jsonRes({ ok: true, device_id: deviceId, scope: "read-write", epoch: this.epoch });
    }

    if (req.method === "POST" && path === "/v1/devices/pair-claim") {
      const { pair_id } = (await req.json()) as { pair_id?: string };
      if (!pair_id) throw new RelayError(400, "INVALID_ARGUMENT", "pair_id required");
      let deleted = false;
      const claimed = this.ctx.storage.transactionSync(() => {
        const t = this.sql.exec(`SELECT kind, device_id, scope, ciphertext, expires_at_ms FROM pairing_tickets WHERE pair_id = ?`, pair_id).toArray()[0];
        if (!t) return null;
        deleted = true;
        this.sql.exec(`DELETE FROM pairing_tickets WHERE pair_id = ?`, pair_id);
        if (Number(t.expires_at_ms) <= now) {
          if (t.kind === "pair") this.sql.exec(`DELETE FROM devices WHERE device_id = ? AND claimed_at_ms IS NULL`, t.device_id);
          return null;
        }
        if (t.kind === "pair") this.sql.exec(`UPDATE devices SET claimed_at_ms = ?, last_seen_at_ms = ? WHERE device_id = ?`, now, now, t.device_id);
        return { kind: t.kind === "pair" ? "add" : "refresh", device_id: String(t.device_id), scope: String(t.scope), ciphertext_b64: bytesToB64(toU8(t.ciphertext)) };
      });
      if (deleted) await this.rescheduleAlarm(now);
      if (!claimed) throw new RelayError(404, "NOT_FOUND", "ticket missing, expired, or already claimed");
      return jsonRes({ ok: true, ...claimed });
    }

    const isClipPost = req.method === "POST" && path === "/v1/clip";
    const auth = await this.authenticate(req, now, !isClipPost);

    if (isClipPost) {
      if (auth.scope === "read") throw new RelayError(403, "TOKEN_SCOPE_FORBIDDEN", "read-only token cannot write clip items");
      return await this.handleClipPost(req, auth, now);
    }

    if (req.method === "PUT" && path === "/v1/clip/blob") {
      if (auth.scope === "read") throw new RelayError(403, "TOKEN_SCOPE_FORBIDDEN", "read-only token cannot upload clip blobs");
      return await this.handleClipBlobPut(req, auth, now);
    }

    if (auth.scope === "clip-write") throw new RelayError(403, "TOKEN_SCOPE_FORBIDDEN", "clip-write token may only invoke POST /v1/clip and PUT /v1/clip/blob");

    if (req.method === "GET" && path === "/v1/clip") {
      const sinceId = url.searchParams.get("since_id") ?? "";
      if (sinceId && !ULID_RE.test(sinceId)) throw new RelayError(400, "INVALID_ARGUMENT", "invalid since_id");
      const limit = Math.min(CLIP_MAX_ITEMS, Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? String(CLIP_MAX_ITEMS), 10) || CLIP_MAX_ITEMS));
      const rows = this.sql.exec(`SELECT clip_id, clip_kid, device_id, kind, created_at_ms, expires_at_ms, meta_envelope, r2_key, blob_bytes FROM clip_items WHERE expires_at_ms > ? AND clip_id > ? ORDER BY clip_id ASC LIMIT ?`, now, sinceId, limit).toArray();
      return jsonRes({
        ok: true,
        items: rows.map((r) => ({
          clip_id: String(r.clip_id), clip_kid: String(r.clip_kid), device_id: String(r.device_id), kind: String(r.kind),
          created_at_ms: Number(r.created_at_ms), expires_at_ms: Number(r.expires_at_ms), meta_envelope_b64: bytesToB64(toU8(r.meta_envelope)),
          has_blob: r.r2_key !== null, blob_bytes: r.blob_bytes === null ? null : Number(r.blob_bytes),
        })),
      });
    }

    const clipBlobMatch = path.match(/^\/v1\/clip\/([^/]+)\/blob$/);
    if (req.method === "GET" && clipBlobMatch) {
      const clipId = decodeURIComponent(clipBlobMatch[1]);
      if (!ULID_RE.test(clipId)) throw new RelayError(400, "INVALID_ARGUMENT", "invalid clip_id");
      const row = this.sql.exec(`SELECT clip_id, clip_kid, device_id, expires_at_ms, r2_key FROM clip_items WHERE clip_id = ?`, clipId).toArray()[0];
      if (!row || Number(row.expires_at_ms) <= now || row.r2_key === null) throw new RelayError(404, "NOT_FOUND", "clip blob not found or expired");
      const obj = await this.env.ARCHIVE_BUCKET.get(String(row.r2_key));
      if (!obj) throw new RelayError(404, "NOT_FOUND", "clip blob missing from R2");
      return new Response(obj.body, {
        status: 200,
        headers: {
          "content-type": "application/octet-stream", "content-length": String(obj.size), "cache-control": "no-store",
          "x-clip-id": String(row.clip_id), "x-clip-kid": String(row.clip_kid), "x-clip-device-id": String(row.device_id),
        },
      });
    }

    const clipDelMatch = path === "/v1/clip" ? ["", ""] : path.match(/^\/v1\/clip\/([^/]+)$/);
    if (req.method === "DELETE" && clipDelMatch) {
      if (auth.scope === "read") throw new RelayError(403, "TOKEN_SCOPE_FORBIDDEN", "read-only token cannot delete clip items");
      const targetId = clipDelMatch[1] ? decodeURIComponent(clipDelMatch[1]) : null;
      if (targetId !== null && !ULID_RE.test(targetId)) throw new RelayError(400, "INVALID_ARGUMENT", "invalid clip_id");
      let deletedCount = 0;
      const r2Keys: string[] = [];
      this.ctx.storage.transactionSync(() => {
        const rows = targetId !== null
          ? this.sql.exec(`SELECT clip_id, r2_key FROM clip_items WHERE clip_id = ?`, targetId).toArray()
          : this.sql.exec(`SELECT clip_id, r2_key FROM clip_items`).toArray();
        deletedCount = rows.length;
        for (const r of rows) if (r.r2_key !== null) r2Keys.push(String(r.r2_key));
        if (deletedCount > 0) {
          if (targetId !== null) this.sql.exec(`DELETE FROM clip_items WHERE clip_id = ?`, targetId);
          else this.sql.exec(`DELETE FROM clip_items`);
        }
      });
      if (r2Keys.length > 0) await this.deleteR2Keys(r2Keys);
      await this.rescheduleAlarm(now);
      this.broadcastClip(auth.deviceId, { type: "clip_cleared", clip_id: targetId });
      return jsonRes({ ok: true, deleted_count: deletedCount });
    }

    if (req.method === "GET" && path === "/v1/sync/ws" && req.headers.get("upgrade")?.toLowerCase() === "websocket") {
      const [client, server] = Object.values(new WebSocketPair());
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment(auth);
      const headers = new Headers();
      if ((req.headers.get("sec-websocket-protocol") ?? "").split(",").map((s) => s.trim()).includes("mynote-v1")) headers.set("Sec-WebSocket-Protocol", "mynote-v1");
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
      const { records, marks, keyring, vaultHeader, clipKey, digest } = this.loadKeyState();
      return jsonRes({
        ok: true,
        key_material: {
          keyring: keyring ? { gen: keyring.gen, blob_b64: bytesToB64(keyring.blob) } : null,
          vault_header: vaultHeader ? { gen: vaultHeader.gen, blob_b64: bytesToB64(vaultHeader.blob) } : null,
          clip_key: clipKey ? { gen: clipKey.gen, blob_b64: bytesToB64(clipKey.blob) } : null,
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

    if (auth.scope !== "read-write") throw new RelayError(403, "TOKEN_SCOPE_FORBIDDEN", "token scope cannot invoke note write, key, shred, snapshot, or device routes");

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
      let shredResults: ShredResultOut[] = [], cancelledKeys: string[] = [], headSeq = 0;
      this.ctx.storage.transactionSync(() => {
        const preBatchHeadSeq = this.headSeq();
        for (const rec of b.key_records ?? []) this.upsertKeyRecord(rec, auth.deviceId, now);
        if (cancels.length > 0) cancelledKeys = this.cancelKeyMarks(cancels, auth.deviceId);
        for (const op of ops) {
          const dup = this.sql.exec(`SELECT seq FROM ops WHERE op_id = ?`, op.op_id).toArray()[0];
          if (dup) { acked.push({ op_id: op.op_id, seq: Number(dup.seq) }); continue; }
          if (op.key_id !== null && op.key_id !== undefined) {
            const k = this.sql.exec(`SELECT key_record FROM block_keys WHERE key_id = ?`, op.key_id).toArray()[0];
            if (!k) throw new RelayError(409, "KEY_UNKNOWN", `unknown key_id ${op.key_id}`, false, { key_id: op.key_id });
            if (k.key_record === null) throw new RelayError(410, "KEY_SHREDDED", `shredded key_id ${op.key_id}`, false, { key_id: op.key_id });
            const pend = this.sql.exec(`SELECT 1 FROM shred_marks WHERE key_id = ? AND state IN ('pending_confirm', 'scheduled') LIMIT 1`, op.key_id).toArray()[0];
            if (pend) throw new RelayError(409, "KEY_PENDING_SHRED", `key_id ${op.key_id} has pending/scheduled shred mark`, true, { key_id: op.key_id });
          }
          const row = this.sql.exec(
            `INSERT INTO ops (op_id, device_id, created_at, key_id, envelope) VALUES (?, ?, ?, ?, ?) RETURNING seq`,
            op.op_id, op.device_id || auth.deviceId, now, op.key_id ?? null, b64ToBytes(op.envelope_b64),
          ).toArray()[0];
          acked.push({ op_id: op.op_id, seq: Number(row.seq) });
        }
        if (marksIn.length > 0) shredResults = this.applyShredMarks(marksIn, b.seen_seq ?? 0, preBatchHeadSeq, false, false, auth.deviceId, now, false);
        headSeq = this.headSeq();
      });
      if (shredResults.length > 0 || cancelledKeys.length > 0) await this.rescheduleAlarm(now);
      if (acked.length > 0 || shredResults.length > 0 || cancelledKeys.length > 0) this.broadcastWake(auth.deviceId, headSeq);
      return jsonRes({ ok: true, epoch: this.epoch, acked, ...(shredResults.length > 0 ? { shred_results: shredResults } : {}), head_seq: headSeq });
    }

    if (req.method === "POST" && path === "/v1/keys") {
      const b = (await req.json()) as {
        key_records?: KeyRecIn[];
        key_material?: { keyring?: { gen: number; blob_b64: string }; vault_header?: { gen: number; blob_b64: string }; clip_key?: { gen: number; blob_b64: string } };
        clear_clips?: boolean;
      };
      const ackedKeyIds: string[] = [], matGens: { keyring?: number; vault_header?: number; clip_key?: number } = {}, clearedR2Keys: string[] = [];
      this.ctx.storage.transactionSync(() => {
        for (const rec of b.key_records ?? []) { this.upsertKeyRecord(rec, auth.deviceId, now); ackedKeyIds.push(rec.key_id); }
        if (b.key_material?.keyring) matGens.keyring = this.upsertKeyMaterial("keyring", b.key_material.keyring.gen, b.key_material.keyring.blob_b64, now);
        if (b.key_material?.vault_header) matGens.vault_header = this.upsertKeyMaterial("vault_header", b.key_material.vault_header.gen, b.key_material.vault_header.blob_b64, now);
        if (b.key_material?.clip_key) matGens.clip_key = this.upsertKeyMaterial("clip_key", b.key_material.clip_key.gen, b.key_material.clip_key.blob_b64, now);
        if (b.clear_clips === true) {
          for (const r of this.sql.exec(`SELECT r2_key FROM clip_items WHERE r2_key IS NOT NULL`).toArray()) clearedR2Keys.push(String(r.r2_key));
          this.sql.exec(`DELETE FROM clip_items`);
        }
      });
      if (b.clear_clips === true) {
        if (clearedR2Keys.length > 0) await this.deleteR2Keys(clearedR2Keys);
        await this.rescheduleAlarm(now);
        this.broadcastClip(auth.deviceId, { type: "clip_cleared", clip_id: null });
      }
      if (ackedKeyIds.length > 0 || Object.keys(matGens).length > 0) this.broadcastWake(auth.deviceId, this.headSeq());
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
      if (cancelled.length > 0) { await this.rescheduleAlarm(now); this.broadcastWake(auth.deviceId, this.headSeq()); }
      return jsonRes({ ok: true, cancelled });
    }

    if (req.method === "POST" && path === "/v1/keys/confirm") {
      const b = (await req.json()) as { key_ids?: string[]; grace_ms?: number };
      const minGrace = this.tGraceMinMs(), hasGrace = b.grace_ms !== undefined && b.grace_ms !== null;
      if (hasGrace) {
        if (!Number.isSafeInteger(b.grace_ms) || (b.grace_ms as number) < 0 || now + (b.grace_ms as number) > Number.MAX_SAFE_INTEGER) throw new RelayError(400, "INVALID_ARGUMENT", "invalid grace_ms");
        if ((b.grace_ms as number) < minGrace) throw new RelayError(422, "GRACE_TOO_SHORT", `grace_ms ${b.grace_ms} < ${minGrace}`, false, { min_grace_ms: minGrace });
      }
      const results: ShredResultOut[] = [];
      this.ctx.storage.transactionSync(() => {
        for (const kid of b.key_ids ?? []) {
          const kr = this.sql.exec(`SELECT key_record FROM block_keys WHERE key_id = ?`, kid).toArray()[0];
          if (!kr) throw new RelayError(409, "KEY_UNKNOWN", `unknown key_id ${kid}`, false, { key_id: kid });
          if (kr.key_record === null) throw new RelayError(410, "KEY_SHREDDED", `key ${kid} already shredded`, false, { key_id: kid });
          const pending = this.sql.exec(`SELECT mark_id, grace_ms FROM shred_marks WHERE key_id = ? AND state = 'pending_confirm'`, kid).toArray();
          if (pending.length > 0) {
            let minNb = Number.MAX_SAFE_INTEGER;
            for (const p of pending) {
              const effGrace = hasGrace ? (b.grace_ms as number) : Math.max(Number(p.grace_ms), minGrace);
              const nb = now + effGrace;
              minNb = Math.min(minNb, nb);
              this.sql.exec(`UPDATE shred_marks SET state = 'scheduled', grace_ms = ?, confirmed_at_ms = ?, not_before_ms = ? WHERE mark_id = ?`, effGrace, now, nb, p.mark_id);
            }
            results.push({ key_id: kid, state: "scheduled", not_before_ms: minNb });
          }
        }
      });
      await this.rescheduleAlarm(now);
      if (results.length > 0) this.broadcastWake(auth.deviceId, this.headSeq());
      return jsonRes({ ok: true, results });
    }

    if (req.method === "PUT" && path === "/v1/snapshots/state") {
      const reqEpoch = req.headers.get("x-journal-epoch") ?? "", coversRaw = req.headers.get("x-covers-seq") ?? "";
      if (reqEpoch !== this.epoch) throw new RelayError(409, "CAS_MISMATCH", "snapshot epoch mismatch", true, { remote_epoch: this.epoch });
      const coversSeq = INT_RE.test(coversRaw) ? Number(coversRaw) : -1;
      if (!Number.isSafeInteger(coversSeq) || coversSeq < 0 || coversSeq > this.headSeq()) throw new RelayError(400, "INVALID_ARGUMENT", "invalid x-covers-seq");
      const snapshotId = req.headers.get("x-snapshot-id") || crypto.randomUUID();
      if (!SNAP_ID_RE.test(snapshotId)) throw new RelayError(400, "INVALID_ARGUMENT", "invalid x-snapshot-id");
      const epochAtStart = this.epoch;
      const latest0 = this.sql.exec(`SELECT covers_seq FROM phone_snapshots WHERE journal_epoch = ? ORDER BY covers_seq DESC LIMIT 1`, epochAtStart).toArray()[0];
      if (latest0 && coversSeq <= Number(latest0.covers_seq)) throw new RelayError(409, "CAS_MISMATCH", `covers_seq ${coversSeq} <= latest ${latest0.covers_seq}`, true, { latest_covers_seq: Number(latest0.covers_seq) });
      const bytes = new Uint8Array(await req.arrayBuffer());
      if (bytes.byteLength === 0 || bytes.byteLength > MAX_SNAP_BYTES) throw new RelayError(400, "INVALID_ARGUMENT", "invalid snapshot body size");
      const r2Key = `snapshots/state/${epochAtStart}/${String(coversSeq).padStart(12, "0")}-${snapshotId}.mnp1`;
      await this.env.ARCHIVE_BUCKET.put(r2Key, bytes);
      const pruneKeys: string[] = [];
      try {
        this.ctx.storage.transactionSync(() => {
          if (this.epoch !== epochAtStart) throw new RelayError(409, "CAS_MISMATCH", "epoch changed during upload", true, { remote_epoch: this.epoch });
          const latest = this.sql.exec(`SELECT covers_seq FROM phone_snapshots WHERE journal_epoch = ? ORDER BY covers_seq DESC LIMIT 1`, epochAtStart).toArray()[0];
          if (latest && coversSeq <= Number(latest.covers_seq)) throw new RelayError(409, "CAS_MISMATCH", `covers_seq ${coversSeq} <= latest ${latest.covers_seq}`, true, { latest_covers_seq: Number(latest.covers_seq) });
          this.sql.exec(`INSERT INTO phone_snapshots (snapshot_id, journal_epoch, covers_seq, r2_key, created_by, created_at_ms) VALUES (?, ?, ?, ?, ?, ?)`, snapshotId, epochAtStart, coversSeq, r2Key, auth.deviceId, now);
          const cur = this.sql.exec(`SELECT snapshot_id, r2_key FROM phone_snapshots WHERE journal_epoch = ? ORDER BY covers_seq DESC`, epochAtStart).toArray();
          const stale = this.sql.exec(`SELECT snapshot_id, r2_key FROM phone_snapshots WHERE journal_epoch != ?`, epochAtStart).toArray();
          for (const old of [...cur.slice(2), ...stale]) { this.sql.exec(`DELETE FROM phone_snapshots WHERE snapshot_id = ?`, old.snapshot_id); pruneKeys.push(String(old.r2_key)); }
        });
      } catch (err) {
        try { await this.env.ARCHIVE_BUCKET.delete(r2Key); } catch { /* best-effort orphan cleanup */ }
        throw err;
      }
      await this.deleteR2Keys(pruneKeys);
      return jsonRes({ ok: true, snapshot_id: snapshotId, journal_epoch: epochAtStart, covers_seq: coversSeq });
    }

    if (req.method === "POST" && path === "/v1/devices") {
      const b = (await req.json()) as { device_name: string; scope: unknown; token_sha256_hex: string; ciphertext_b64: string; device_id?: string; pair_id?: string };
      if (!b.device_name || !isScope(b.scope) || !HEX64.test(b.token_sha256_hex ?? "")) throw new RelayError(400, "INVALID_ARGUMENT", "invalid pairing request");
      const deviceId = b.device_id ?? randomDeviceId(), pairId = b.pair_id ?? randomPairId(), expiresAt = now + this.pairingTtlMs();
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
      const pairId = b.pair_id ?? randomPairId(), expiresAt = now + this.pairingTtlMs();
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
      await this.rescheduleAlarm(now);
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
    let expiredTickets = 0, executedShreds = 0, expiredClips = 0;
    const expiredClipR2Keys: string[] = [];
    this.ctx.storage.transactionSync(() => {
      for (const m of this.sql.exec(`SELECT DISTINCT key_id FROM shred_marks WHERE state = 'scheduled' AND not_before_ms IS NOT NULL AND not_before_ms <= ?`, now).toArray()) {
        executedShreds++;
        this.sql.exec(`UPDATE block_keys SET key_record = NULL, shredded_at_ms = COALESCE(shredded_at_ms, ?) WHERE key_id = ?`, now, m.key_id);
        this.sql.exec(`UPDATE shred_marks SET state = 'executed', executed_at_ms = ? WHERE key_id = ? AND state IN ('pending_confirm', 'scheduled')`, now, m.key_id);
      }
      for (const t of this.sql.exec(`SELECT pair_id, kind, device_id FROM pairing_tickets WHERE expires_at_ms <= ?`, now).toArray()) {
        expiredTickets++;
        this.sql.exec(`DELETE FROM pairing_tickets WHERE pair_id = ?`, t.pair_id);
        if (t.kind === "pair") this.sql.exec(`DELETE FROM devices WHERE device_id = ? AND claimed_at_ms IS NULL`, t.device_id);
      }
      for (const c of this.sql.exec(`SELECT clip_id, r2_key FROM clip_items WHERE expires_at_ms <= ?`, now).toArray()) {
        expiredClips++;
        if (c.r2_key !== null) expiredClipR2Keys.push(String(c.r2_key));
        this.sql.exec(`DELETE FROM clip_items WHERE clip_id = ?`, c.clip_id);
      }
    });
    if (expiredClipR2Keys.length > 0) await this.deleteR2Keys(expiredClipR2Keys);
    if (executedShreds > 0) this.broadcastWake(null, this.headSeq());
    const nextArchiveAt = Number(this.metaGet("next_archive_at_ms") ?? 0);
    if (now >= nextArchiveAt || (expiredTickets === 0 && executedShreds === 0 && expiredClips === 0)) {
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
        if ((info?.retryCount ?? 0) >= 5) { this.metaSet("next_archive_at_ms", String(now + 3_600_000)); await this.rescheduleAlarm(now); return; }
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
      h.set("content-security-policy", buildPwaCsp(url));
      h.set("x-content-type-options", "nosniff");
      h.set("referrer-policy", "no-referrer");
      h.set("x-frame-options", "DENY");
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
    }
    return env.SYNC_DO.get(env.SYNC_DO.idFromName("primary")).fetch(req);
  },
};
