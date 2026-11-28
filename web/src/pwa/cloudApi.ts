import { bytesToB64 } from "../wasm/pwa";

export class CloudApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public retryable = false,
  ) {
    super(message);
  }
}

export type DeviceScope = "read" | "read+clip" | "clip-write" | "read-write";

export interface ClaimPairingResponse {
  ok: true;
  kind: "add" | "refresh";
  device_id: string;
  scope: DeviceScope;
  ciphertext_b64: string;
}

export interface CloudKeysResponse {
  ok: true;
  key_material: {
    keyring: { gen: number; blob_b64: string } | null;
    vault_header: { gen: number; blob_b64: string } | null;
    clip_key: { gen: number; blob_b64: string } | null;
  };
  key_records: {
    key_id: string;
    wrap_gen: number;
    key_record_b64: string | null;
    created_at_ms: number;
  }[];
  shred_marks: {
    mark_id: string;
    key_id: string;
    seen_seq: number;
    requested_by: string;
    requested_at_ms: number;
    grace_ms: number;
    not_before_ms: number | null;
    state: "pending_confirm" | "scheduled" | "cancelled" | "executed";
    confirmed_at_ms: number | null;
    cancelled_by: string | null;
    executed_at_ms: number | null;
  }[];
  digest: string;
}

export interface CloudPullResponse {
  ok: true;
  epoch: string;
  ops: {
    seq: number;
    op_id: string;
    key_id: string | null;
    device_id: string;
    created_at: number;
    envelope_b64: string;
  }[];
  keys_digest: string;
  head_seq: number;
  has_more: boolean;
}

export interface CloudSnapshotResponse {
  snapshot_b64: string;
  journal_epoch: string;
  covers_seq: number;
  snapshot_id: string;
}

export interface CloudClipQuotaWire {
  used_bytes: number;
  limit_bytes: number;
  item_count: number;
  item_limit: number;
}

export interface CloudClipItemWire {
  clip_id: string;
  clip_kid: string;
  device_id: string;
  kind: "text" | "image";
  created_at_ms: number;
  expires_at_ms: number;
  meta_envelope_b64: string;
  has_blob: boolean;
  blob_bytes: number | null;
}

export interface CloudClipListResponse {
  ok: true;
  items: CloudClipItemWire[];
  has_more?: boolean;
  next_since_id?: string | null;
  quota?: CloudClipQuotaWire;
}

export interface CloudClipPostPayload {
  clip_id: string;
  clip_kid: string;
  kind: "text";
  ephemeral?: boolean;
  meta_envelope_b64: string;
}

export interface CloudClipPostResponse {
  ok: true;
  clip_id: string;
  created_at_ms?: number;
  expires_at_ms?: number;
  delivered_to?: number;
  quota?: CloudClipQuotaWire;
}

export interface CloudClipBlobPutHeaders {
  clipId: string;
  clipKid: string;
  kind: "text" | "image";
  metaEnvelopeB64: string;
}

export interface CloudClipBlobPutResponse {
  ok: true;
  clip_id: string;
  blob_bytes: number;
  created_at_ms: number;
  expires_at_ms: number;
  quota?: CloudClipQuotaWire;
}

export interface CloudClipBlobGetResponse {
  bytes: Uint8Array;
  clipId: string;
  clipKid: string;
  deviceId: string;
}

export interface CloudClipDeleteResponse {
  ok: true;
  deleted_count: number;
  freed_bytes?: number;
  scope?: "cloud" | "all";
  quota?: CloudClipQuotaWire;
}

export interface CloudClipPruneResponse {
  ok: true;
  dry_run: boolean;
  matched_count: number;
  deleted_count: number;
  freed_bytes: number;
  quota?: CloudClipQuotaWire;
}

function baseUrl(syncUrl: string): string {
  return syncUrl.replace(/\/+$/, "");
}

async function reqCloudJson<T extends { ok: true }>(
  url: string,
  init: RequestInit = {},
  token?: string,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("X-Mynote-Protocol", "1");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  const res = await fetch(url, { ...init, headers, redirect: "manual", cache: "no-store" });
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
    throw new CloudApiError(res.status || 302, "REDIRECT_REFUSED", `Refused HTTP ${res.status || 302} redirect`);
  }
  const ct = res.headers.get("content-type") ?? "";
  const text = await res.text();
  let parsed: unknown = null;
  if (ct.includes("application/json")) {
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new CloudApiError(res.status, "INVALID_RESPONSE", "Malformed JSON from cloud relay", true);
    }
  }
  if (!res.ok) {
    const err = (parsed as { error?: { code?: string; message?: string; retryable?: boolean } })?.error;
    throw new CloudApiError(
      res.status,
      err?.code ?? (res.status === 401 ? "AUTH_REQUIRED" : `HTTP_${res.status}`),
      err?.message ?? `Cloud relay returned HTTP ${res.status}`,
      err?.retryable ?? res.status >= 500,
    );
  }
  if (!parsed || typeof parsed !== "object" || (parsed as { ok?: unknown }).ok !== true) {
    throw new CloudApiError(res.status, "INVALID_RESPONSE", "Cloud relay response missing ok:true", true);
  }
  return parsed as T;
}

export async function claimPairing(syncUrl: string, pairId: string): Promise<ClaimPairingResponse> {
  return reqCloudJson<ClaimPairingResponse>(`${baseUrl(syncUrl)}/v1/devices/pair-claim`, {
    method: "POST",
    body: JSON.stringify({ pair_id: pairId }),
  });
}

export async function fetchCloudKeys(syncUrl: string, token: string, signal?: AbortSignal): Promise<CloudKeysResponse> {
  return reqCloudJson<CloudKeysResponse>(`${baseUrl(syncUrl)}/v1/keys`, { method: "GET", signal }, token);
}

export async function pullCloudOps(
  syncUrl: string,
  token: string,
  since: number,
  limit = 200,
  signal?: AbortSignal,
): Promise<CloudPullResponse> {
  return reqCloudJson<CloudPullResponse>(
    `${baseUrl(syncUrl)}/v1/sync/pull?since=${encodeURIComponent(String(since))}&limit=${limit}`,
    { method: "GET", signal },
    token,
  );
}

export async function fetchCloudStateSnapshot(
  syncUrl: string,
  token: string,
  signal?: AbortSignal,
): Promise<CloudSnapshotResponse | null> {
  const res = await fetch(`${baseUrl(syncUrl)}/v1/snapshots/state`, {
    method: "GET",
    headers: {
      "X-Mynote-Protocol": "1",
      Authorization: `Bearer ${token}`,
    },
    redirect: "manual",
    cache: "no-store",
    signal,
  });
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
    throw new CloudApiError(res.status || 302, "REDIRECT_REFUSED", `Refused HTTP ${res.status || 302} redirect`);
  }
  if (res.status === 404) return null;
  if (!res.ok) {
    let code = res.status === 401 ? "AUTH_REQUIRED" : `HTTP_${res.status}`;
    let msg = `Snapshot fetch failed with HTTP ${res.status}`;
    try {
      const parsed = (await res.json()) as { error?: { code?: string; message?: string } };
      if (parsed?.error?.code) code = parsed.error.code;
      if (parsed?.error?.message) msg = parsed.error.message;
    } catch {
      // ignore
    }
    throw new CloudApiError(res.status, code, msg, res.status >= 500);
  }
  const bytes = new Uint8Array(await res.arrayBuffer());
  const coversSeq = Number.parseInt(res.headers.get("x-covers-seq") ?? "0", 10) || 0;
  return {
    snapshot_b64: bytesToB64(bytes),
    journal_epoch: res.headers.get("x-journal-epoch") ?? "",
    covers_seq: coversSeq,
    snapshot_id: res.headers.get("x-snapshot-id") ?? "",
  };
}

export async function listCloudClips(
  syncUrl: string,
  token: string,
  sinceId?: string,
  limit = 100,
  signal?: AbortSignal,
): Promise<CloudClipListResponse> {
  const params = new URLSearchParams();
  params.set("limit", String(Math.min(100, Math.max(1, limit))));
  if (sinceId) params.set("since_id", sinceId);
  return reqCloudJson<CloudClipListResponse>(
    `${baseUrl(syncUrl)}/v1/clip?${params.toString()}`,
    { method: "GET", signal },
    token,
  );
}

/** Drain all incremental pages from `GET /v1/clip` (up to 20 pages safety cap). */
export async function listAllCloudClipsSince(
  syncUrl: string,
  token: string,
  sinceId?: string,
  signal?: AbortSignal,
): Promise<{ items: CloudClipItemWire[]; quota: CloudClipQuotaWire | null }> {
  const collected: CloudClipItemWire[] = [];
  let cursor = sinceId || undefined;
  let latestQuota: CloudClipQuotaWire | null = null;
  for (let pageIdx = 0; pageIdx < 20; pageIdx++) {
    const res = await listCloudClips(syncUrl, token, cursor, 100, signal);
    if (res.quota) latestQuota = res.quota;
    collected.push(...res.items);
    if (!res.has_more || res.items.length === 0) break;
    const nextCursor = res.next_since_id ?? res.items[res.items.length - 1]?.clip_id;
    if (!nextCursor || nextCursor === cursor) break;
    cursor = nextCursor;
  }
  return { items: collected, quota: latestQuota };
}

export async function postCloudClip(
  syncUrl: string,
  token: string,
  payload: CloudClipPostPayload,
  signal?: AbortSignal,
): Promise<CloudClipPostResponse> {
  return reqCloudJson<CloudClipPostResponse>(
    `${baseUrl(syncUrl)}/v1/clip`,
    {
      method: "POST",
      body: JSON.stringify(payload),
      signal,
    },
    token,
  );
}

export async function putCloudClipBlob(
  syncUrl: string,
  token: string,
  headers: CloudClipBlobPutHeaders,
  mnc1Bytes: Uint8Array,
  signal?: AbortSignal,
): Promise<CloudClipBlobPutResponse> {
  const bodyBuf = new Uint8Array(mnc1Bytes.byteLength);
  bodyBuf.set(mnc1Bytes);
  return reqCloudJson<CloudClipBlobPutResponse>(
    `${baseUrl(syncUrl)}/v1/clip/blob`,
    {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Clip-Id": headers.clipId,
        "X-Clip-Kid": headers.clipKid,
        "X-Clip-Kind": headers.kind,
        "X-Clip-Meta-B64": headers.metaEnvelopeB64,
      },
      body: bodyBuf,
      signal,
    },
    token,
  );
}

export async function getCloudClipBlob(
  syncUrl: string,
  token: string,
  clipId: string,
  signal?: AbortSignal,
): Promise<CloudClipBlobGetResponse> {
  const res = await fetch(`${baseUrl(syncUrl)}/v1/clip/${encodeURIComponent(clipId)}/blob`, {
    method: "GET",
    headers: {
      "X-Mynote-Protocol": "1",
      Authorization: `Bearer ${token}`,
    },
    redirect: "manual",
    cache: "no-store",
    signal,
  });
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
    throw new CloudApiError(res.status || 302, "REDIRECT_REFUSED", `Refused HTTP ${res.status || 302} redirect`);
  }
  if (!res.ok) {
    let code = res.status === 401 ? "AUTH_REQUIRED" : `HTTP_${res.status}`;
    let msg = `Clip blob fetch failed with HTTP ${res.status}`;
    try {
      const parsed = (await res.json()) as { error?: { code?: string; message?: string; retryable?: boolean } };
      if (parsed?.error?.code) code = parsed.error.code;
      if (parsed?.error?.message) msg = parsed.error.message;
    } catch {
      // ignore
    }
    throw new CloudApiError(res.status, code, msg, res.status >= 500);
  }
  return {
    bytes: new Uint8Array(await res.arrayBuffer()),
    clipId: res.headers.get("x-clip-id") ?? clipId,
    clipKid: res.headers.get("x-clip-kid") ?? "",
    deviceId: res.headers.get("x-clip-device-id") ?? "",
  };
}

export async function deleteCloudClip(
  syncUrl: string,
  token: string,
  clipId?: string,
  signal?: AbortSignal,
  scope: "cloud" | "all" = "cloud",
): Promise<CloudClipDeleteResponse> {
  const path = clipId
    ? `/v1/clip/${encodeURIComponent(clipId)}`
    : scope === "all"
      ? "/v1/clip?scope=all"
      : "/v1/clip";
  return reqCloudJson<CloudClipDeleteResponse>(`${baseUrl(syncUrl)}${path}`, { method: "DELETE", signal }, token);
}

export async function pruneCloudClips(
  syncUrl: string,
  token: string,
  input: { before_ms?: number; keep_latest?: number; kind?: "text" | "image"; dry_run?: boolean },
  signal?: AbortSignal,
): Promise<CloudClipPruneResponse> {
  return reqCloudJson<CloudClipPruneResponse>(
    `${baseUrl(syncUrl)}/v1/clip/prune`,
    {
      method: "POST",
      body: JSON.stringify(input),
      signal,
    },
    token,
  );
}

export function connectCloudWs(
  syncUrl: string,
  token: string,
  callbacks: {
    onWake: () => void;
    onRevoked: () => void;
    onStateChange: (connected: boolean) => void;
    onAbnormalClose?: () => void;
    onClipWake?: (frame: { clip_id: string; kind: "text" | "image"; created_at_ms: number }) => void;
    onClipCleared?: (frame: { clip_id: string | null }) => void;
  },
): () => void {
  let closed = false;
  let hasOpenedOnce = false;
  let ws: WebSocket | null = null;
  let pingTimer: number | null = null;
  let retryTimer: number | null = null;
  let retryMs = 1500;

  const wsUrl = `${baseUrl(syncUrl).replace(/^http/, "ws")}/v1/sync/ws`;

  const clearTimers = () => {
    if (pingTimer !== null) {
      window.clearInterval(pingTimer);
      pingTimer = null;
    }
    if (retryTimer !== null) {
      window.clearTimeout(retryTimer);
      retryTimer = null;
    }
  };

  const open = () => {
    if (closed) return;
    try {
      ws = new WebSocket(wsUrl, ["mynote-v1", `bearer.${token}`]);
    } catch {
      callbacks.onStateChange(false);
      return;
    }
    ws.onopen = () => {
      const reconnected = hasOpenedOnce;
      hasOpenedOnce = true;
      retryMs = 1500;
      callbacks.onStateChange(true);
      if (reconnected) callbacks.onWake();
      if (pingTimer !== null) window.clearInterval(pingTimer);
      pingTimer = window.setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) ws.send("ping");
      }, 30_000);
    };
    ws.onmessage = (ev) => {
      const raw = String(ev.data);
      if (raw === "pong") return;
      try {
        const msg = JSON.parse(raw) as {
          type?: string;
          clip_id?: unknown;
          kind?: unknown;
          created_at_ms?: unknown;
        };
        if (msg.type === "wake") callbacks.onWake();
        else if (msg.type === "clip_wake" && typeof msg.clip_id === "string") {
          callbacks.onClipWake?.({
            clip_id: msg.clip_id,
            kind: msg.kind === "image" ? "image" : "text",
            created_at_ms: typeof msg.created_at_ms === "number" ? msg.created_at_ms : Date.now(),
          });
        } else if (msg.type === "clip_cleared") {
          callbacks.onClipCleared?.({
            clip_id: typeof msg.clip_id === "string" ? msg.clip_id : null,
          });
        } else if (msg.type === "device_revoked") {
          closed = true;
          clearTimers();
          callbacks.onRevoked();
        }
      } catch {
        // ignore non-JSON frames
      }
    };
    ws.onclose = (ev) => {
      if (pingTimer !== null) {
        window.clearInterval(pingTimer);
        pingTimer = null;
      }
      callbacks.onStateChange(false);
      if (ev.code === 4401) {
        closed = true;
        callbacks.onRevoked();
        return;
      }
      if (!closed) {
        if (ev.code === 1006 || ev.code === 1008) {
          callbacks.onAbnormalClose?.();
        }
        retryTimer = window.setTimeout(open, retryMs);
        retryMs = Math.min(30_000, retryMs * 2);
      }
    };
  };

  open();
  return () => {
    closed = true;
    clearTimers();
    ws?.close();
  };
}
