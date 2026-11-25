import { DurableObject } from "cloudflare:workers";

export interface Env {
  SYNC_DO: DurableObjectNamespace<SyncEchoDO>;
  ARCHIVE_BUCKET: R2Bucket;
  BOOTSTRAP_TOKEN: string;
  T_GRACE_MIN_MS: string;
  DAILY_ARCHIVE_INTERVAL_MS: string;
}

interface WsMeta {
  deviceId: string;
  scope: "read" | "read-write";
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function jsonRes(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export class SyncEchoDO extends DurableObject<Env> {
  private sql: SqlStorage;
  private epoch: string;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    this.epoch = "";
    this.ctx.blockConcurrencyWhile(async () => {
      this.initSchema();
      await this.rescheduleAlarm(this.nowMs());
    });
  }

  private nowMs(): number {
    const row = this.sql.exec(`SELECT v FROM meta WHERE k = 'clock_offset_ms'`).toArray()[0];
    return Date.now() + (row ? Number(row.v) : 0);
  }

  private initSchema(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        token_sha256 TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL CHECK (scope IN ('read', 'read-write')),
        claimed_at_ms INTEGER,
        revoked_at_ms INTEGER
      );
      CREATE TABLE IF NOT EXISTS pairing_tickets (
        pair_id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        expires_at_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS ops (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        op_id TEXT NOT NULL UNIQUE,
        key_id TEXT,
        payload TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS block_keys (
        key_id TEXT PRIMARY KEY,
        key_record TEXT,
        shredded_at_ms INTEGER
      );
      CREATE TABLE IF NOT EXISTS shred_marks (
        mark_id TEXT PRIMARY KEY,
        key_id TEXT NOT NULL,
        not_before_ms INTEGER NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('scheduled', 'cancelled', 'executed'))
      );
    `);
    const row = this.sql.exec(`SELECT v FROM meta WHERE k = 'epoch'`).toArray()[0];
    if (row) {
      this.epoch = String(row.v);
    } else {
      this.epoch = crypto.randomUUID();
      this.sql.exec(`INSERT INTO meta (k, v) VALUES ('epoch', ?), ('last_archive_seq', '0')`, this.epoch);
    }
  }

  private async authenticate(req: Request): Promise<WsMeta | Response> {
    const auth = req.headers.get("authorization") ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token) return jsonRes({ ok: false, error: { code: "AUTH_REQUIRED" } }, 401);
    const hash = await sha256Hex(token);
    const row = this.sql
      .exec(`SELECT device_id, scope, claimed_at_ms, revoked_at_ms FROM devices WHERE token_sha256 = ?`, hash)
      .toArray()[0];
    if (!row || row.claimed_at_ms === null) return jsonRes({ ok: false, error: { code: "AUTH_REQUIRED" } }, 401);
    if (row.revoked_at_ms !== null) return jsonRes({ ok: false, error: { code: "DEVICE_REVOKED" } }, 401);
    return { deviceId: String(row.device_id), scope: String(row.scope) as "read" | "read-write" };
  }

  private async rescheduleAlarm(now: number): Promise<void> {
    const interval = Number(this.env.DAILY_ARCHIVE_INTERVAL_MS || 86_400_000);
    let nextAt = now + interval;
    const dueShred = this.sql.exec(`SELECT MIN(not_before_ms) AS t FROM shred_marks WHERE state = 'scheduled'`).toArray()[0];
    if (dueShred?.t !== null && dueShred?.t !== undefined) nextAt = Math.min(nextAt, Number(dueShred.t));
    const duePair = this.sql.exec(`SELECT MIN(expires_at_ms) AS t FROM pairing_tickets`).toArray()[0];
    if (duePair?.t !== null && duePair?.t !== undefined) nextAt = Math.min(nextAt, Number(duePair.t));
    await this.ctx.storage.setAlarm(Math.max(Date.now() + 1_000, nextAt));
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const now = this.nowMs();

    // 1. Bootstrap & device registration for spike
    if (req.method === "POST" && url.pathname === "/v1/devices/bootstrap") {
      if (req.headers.get("authorization") !== `Bearer ${this.env.BOOTSTRAP_TOKEN}`) {
        return jsonRes({ ok: false, error: { code: "AUTH_REQUIRED" } }, 401);
      }
      const { device_id, token_sha256, scope = "read-write" } = (await req.json()) as {
        device_id: string;
        token_sha256: string;
        scope?: "read" | "read-write";
      };
      this.sql.exec(
        `INSERT OR REPLACE INTO devices (device_id, token_sha256, scope, claimed_at_ms, revoked_at_ms) VALUES (?, ?, ?, ?, NULL)`,
        device_id,
        token_sha256,
        scope,
        now,
      );
      return jsonRes({ ok: true, device_id, scope, epoch: this.epoch });
    }

    const auth = await this.authenticate(req);
    if (auth instanceof Response) return auth;

    // 2. WebSocket Hibernation wakeup channel
    if (url.pathname === "/v1/sync/ws" && req.headers.get("upgrade") === "websocket") {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment(auth);
      return new Response(null, { status: 101, webSocket: client });
    }

    // 3. Read-only pull
    if (req.method === "GET" && url.pathname === "/v1/sync/pull") {
      const since = Number(url.searchParams.get("since") ?? "0");
      const ops = this.sql.exec(`SELECT seq, op_id, key_id, payload FROM ops WHERE seq > ? ORDER BY seq ASC LIMIT 500`, since).toArray();
      const head = Number(this.sql.exec(`SELECT COALESCE(MAX(seq), 0) AS h FROM ops`).toArray()[0]?.h ?? 0);
      return jsonRes({ ok: true, epoch: this.epoch, ops, head_seq: head });
    }

    // 4. Write-scope guard (read token -> 403)
    if (auth.scope !== "read-write") {
      if (req.body) await req.arrayBuffer();
      return jsonRes({ ok: false, error: { code: "TOKEN_SCOPE_FORBIDDEN" } }, 403);
    }

    // 5. Idempotent push + key records + single-row loop (<= 100 bind params rule) + WS wake
    if (req.method === "POST" && url.pathname === "/v1/sync/push") {
      const body = (await req.json()) as {
        key_records?: { key_id: string; key_record: string }[];
        ops?: { op_id: string; key_id: string | null; payload: string }[];
      };
      const acked: { op_id: string; seq: number }[] = [];
      let headSeq = 0;
      this.ctx.storage.transactionSync(() => {
        for (const k of body.key_records ?? []) {
          this.sql.exec(`INSERT OR IGNORE INTO block_keys (key_id, key_record) VALUES (?, ?)`, k.key_id, k.key_record);
        }
        for (const op of body.ops ?? []) {
          if (op.key_id !== null) {
            const exists = this.sql.exec(`SELECT 1 FROM block_keys WHERE key_id = ?`, op.key_id).toArray()[0];
            if (!exists) throw new Error(`KEY_UNKNOWN:${op.key_id}`);
          }
          this.sql.exec(`INSERT OR IGNORE INTO ops (op_id, key_id, payload) VALUES (?, ?, ?)`, op.op_id, op.key_id, op.payload);
          const row = this.sql.exec(`SELECT seq FROM ops WHERE op_id = ?`, op.op_id).toArray()[0];
          acked.push({ op_id: op.op_id, seq: Number(row.seq) });
        }
        headSeq = Number(this.sql.exec(`SELECT COALESCE(MAX(seq), 0) AS h FROM ops`).toArray()[0]?.h ?? 0);
      });
      const wakeMsg = JSON.stringify({ type: "wake", epoch: this.epoch, head_seq: headSeq });
      for (const ws of this.ctx.getWebSockets()) {
        const meta = ws.deserializeAttachment() as WsMeta | null;
        if (meta && meta.deviceId !== auth.deviceId) ws.send(wakeMsg);
      }
      return jsonRes({ ok: true, epoch: this.epoch, acked, head_seq: headSeq });
    }

    // 6. Schedule shred mark (enforces T_grace_min) or pairing ticket TTL test
    if (req.method === "POST" && url.pathname === "/v1/keys/shred") {
      const { mark_id, key_id, grace_ms } = (await req.json()) as { mark_id: string; key_id: string; grace_ms: number };
      const minGrace = Number(this.env.T_GRACE_MIN_MS || 86_400_000);
      if (grace_ms < minGrace) return jsonRes({ ok: false, error: { code: "GRACE_TOO_SHORT" } }, 422);
      const notBefore = now + grace_ms;
      this.sql.exec(
        `INSERT OR IGNORE INTO shred_marks (mark_id, key_id, not_before_ms, state) VALUES (?, ?, ?, 'scheduled')`,
        mark_id,
        key_id,
        notBefore,
      );
      await this.rescheduleAlarm(now);
      return jsonRes({ ok: true, key_id, state: "scheduled", not_before_ms: notBefore });
    }

    if (req.method === "POST" && url.pathname === "/v1/devices/pair-ticket") {
      const { pair_id, device_id, token_sha256, ttl_ms = 600_000 } = (await req.json()) as {
        pair_id: string;
        device_id: string;
        token_sha256: string;
        ttl_ms?: number;
      };
      this.sql.exec(
        `INSERT INTO devices (device_id, token_sha256, scope, claimed_at_ms) VALUES (?, ?, 'read', NULL)`,
        device_id,
        token_sha256,
      );
      this.sql.exec(`INSERT INTO pairing_tickets (pair_id, device_id, expires_at_ms) VALUES (?, ?, ?)`, pair_id, device_id, now + ttl_ms);
      await this.rescheduleAlarm(now);
      return jsonRes({ ok: true, pair_id, expires_at_ms: now + ttl_ms });
    }

    if (req.method === "POST" && url.pathname === "/v1/debug/clock") {
      const { offset_ms } = (await req.json()) as { offset_ms: number };
      this.sql.exec(`INSERT OR REPLACE INTO meta (k, v) VALUES ('clock_offset_ms', ?)`, String(offset_ms));
      return jsonRes({ ok: true, now_ms: this.nowMs() });
    }

    if (req.method === "GET" && url.pathname === "/v1/debug/state") {
      return jsonRes({
        ok: true,
        keys: this.sql.exec(`SELECT * FROM block_keys ORDER BY key_id`).toArray(),
        marks: this.sql.exec(`SELECT * FROM shred_marks ORDER BY mark_id`).toArray(),
        tickets: this.sql.exec(`SELECT * FROM pairing_tickets`).toArray(),
        devices: this.sql.exec(`SELECT device_id, scope, claimed_at_ms FROM devices ORDER BY device_id`).toArray(),
        wsAttachments: this.ctx.getWebSockets().map((w) => w.deserializeAttachment()),
      });
    }

    return jsonRes({ ok: false, error: { code: "NOT_FOUND" } }, 404);
  }

  async webSocketMessage(_ws: WebSocket, _msg: string | ArrayBuffer): Promise<void> {}
  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    ws.close(code, reason);
  }

  // Single multiplexed DO Alarm: shred due keys + expire pairing tickets + R2 archive & dual-track key snapshots
  async alarm(): Promise<void> {
    const now = this.nowMs();
    this.ctx.storage.transactionSync(() => {
      const due = this.sql
        .exec(`SELECT mark_id, key_id FROM shred_marks WHERE state = 'scheduled' AND not_before_ms <= ?`, now)
        .toArray();
      for (const m of due) {
        this.sql.exec(`UPDATE block_keys SET key_record = NULL, shredded_at_ms = ? WHERE key_id = ?`, now, m.key_id);
        this.sql.exec(`UPDATE shred_marks SET state = 'executed' WHERE mark_id = ?`, m.mark_id);
      }
      const expired = this.sql.exec(`SELECT pair_id, device_id FROM pairing_tickets WHERE expires_at_ms <= ?`, now).toArray();
      for (const t of expired) {
        this.sql.exec(`DELETE FROM pairing_tickets WHERE pair_id = ?`, t.pair_id);
        this.sql.exec(`DELETE FROM devices WHERE device_id = ? AND claimed_at_ms IS NULL`, t.device_id);
      }
    });

    const lastArchived = Number(this.sql.exec(`SELECT v FROM meta WHERE k = 'last_archive_seq'`).toArray()[0]?.v ?? 0);
    const newOps = this.sql.exec(`SELECT seq, op_id, key_id, payload FROM ops WHERE seq > ? ORDER BY seq ASC`, lastArchived).toArray();
    if (newOps.length > 0) {
      const fromSeq = String(newOps[0].seq).padStart(12, "0");
      const toSeq = String(newOps[newOps.length - 1].seq).padStart(12, "0");
      const r2Key = `archives/ops/${this.epoch}/${fromSeq}-${toSeq}.mna1`;
      if (!(await this.env.ARCHIVE_BUCKET.head(r2Key))) {
        await this.env.ARCHIVE_BUCKET.put(r2Key, JSON.stringify({ epoch: this.epoch, ops: newOps }));
      }
      this.sql.exec(`UPDATE meta SET v = ? WHERE k = 'last_archive_seq'`, String(newOps[newOps.length - 1].seq));
    }

    const activeKeys = this.sql.exec(`SELECT key_id, key_record FROM block_keys WHERE key_record IS NOT NULL`).toArray();
    const snapPayload = JSON.stringify({ created_at_ms: now, active_keys: activeKeys });
    const day = new Date(now).toISOString().slice(0, 10);
    await this.env.ARCHIVE_BUCKET.put("archives/keys/latest.mnks", snapPayload);
    await this.env.ARCHIVE_BUCKET.put(`archives/keys/history/${day}.mnks`, snapPayload);

    await this.rescheduleAlarm(now);
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const id = env.SYNC_DO.idFromName("primary");
    return env.SYNC_DO.get(id).fetch(req);
  },
};
