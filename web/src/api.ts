import type {
  ApiErrorBody,
  BlockDto,
  BlockedTier2OpDto,
  BlockHistoryContentDto,
  BlockHistoryEntryDto,
  BootstrapResponse,
  BufferDto,
  ClipApplyResponse,
  ClipAutoApplyMirrorMode,
  ClipDeleteResponse,
  ClipKind,
  ClipListResponse,
  ClipPromoteResponse,
  ClipPushImageInput,
  ClipPushResponse,
  ClipUndoResponse,
  ClipWatchResponse,
  LocalWsFrame,
  SyncStatusDto,
  TrashActionPrepareResponse,
  TrashItemDto,
  VaultHeaderDto,
} from "./types";
import { isAllowedBitmapMime, normalizeMime } from "./clipUtils";

export class LocalApiError extends Error {
  constructor(public status: number, public body: ApiErrorBody) {
    super(body.message || body.code);
  }
}

async function reqJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const res = await fetch(path, { ...init, headers, credentials: "same-origin", redirect: "manual" });
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
    throw new LocalApiError(res.status || 302, {
      code: "REDIRECT_REFUSED",
      message: `Unexpected redirect HTTP ${res.status || 302}; refusing to follow`,
    });
  }
  const text = await res.text();
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    throw new LocalApiError(res.status, { code: "INVALID_RESPONSE", message: `HTTP ${res.status}` });
  }
  if (!res.ok) {
    const err = (parsed as { error?: ApiErrorBody })?.error ?? { code: "HTTP_ERROR", message: `HTTP ${res.status}` };
    throw new LocalApiError(res.status, err);
  }
  if (parsed && typeof parsed === "object" && "ok" in parsed) {
    const env = parsed as { ok?: unknown; data?: T; error?: ApiErrorBody };
    if (env.ok !== true) {
      throw new LocalApiError(res.status, env.error ?? { code: "INVALID_RESPONSE", message: "API returned ok !== true" });
    }
    return env.data as T;
  }
  return parsed as T;
}

async function reqBlob(path: string): Promise<{ blob: Blob; contentType: string }> {
  const res = await fetch(path, { method: "GET", credentials: "same-origin", redirect: "manual" });
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
    throw new LocalApiError(res.status || 302, {
      code: "REDIRECT_REFUSED",
      message: `Unexpected redirect HTTP ${res.status || 302}; refusing to follow`,
    });
  }
  if (!res.ok) {
    let err: ApiErrorBody = { code: "HTTP_ERROR", message: `HTTP ${res.status}` };
    try {
      const parsed = (await res.json()) as { error?: ApiErrorBody };
      if (parsed?.error) err = parsed.error;
    } catch {
      // non-JSON error body
    }
    throw new LocalApiError(res.status, err);
  }
  const contentType = normalizeMime(res.headers.get("content-type"));
  if (contentType && contentType !== "text/plain" && !isAllowedBitmapMime(contentType)) {
    throw new LocalApiError(422, {
      code: "INVALID_ARGUMENT",
      message: `Refused disallowed clipboard blob MIME '${contentType}'`,
    });
  }
  return { blob: await res.blob(), contentType: contentType || "application/octet-stream" };
}

export interface Tier2WritePayload {
  op_id: string;
  key_id: string;
  mnb1_b64: string;
  mnw1_b64?: string;
}

export interface LocalApiClient {
  bootstrap(): Promise<BootstrapResponse>;
  getSyncStatus?(): Promise<SyncStatusDto>;
  listBlocks(bufferId: string): Promise<BlockDto[]>;
  createBlock(input: {
    buffer_id: string;
    lang: string;
    content?: string;
    after_id?: string | null;
    block_id?: string;
    op_id?: string;
    key_id?: string;
    mnb1_b64?: string;
    mnw1_b64?: string;
    public_hint?: string | null;
    fast_sync?: boolean;
  }): Promise<BlockDto>;
  patchBlock(
    id: string,
    input: {
      expected_heads?: string[];
      content?: string;
      op_id?: string;
      key_id?: string;
      mnb1_b64?: string;
      mnw1_b64?: string;
      public_hint?: string | null;
      lang?: string;
      after_id?: string;
      before_id?: string;
      buffer_id?: string;
      fast_sync?: boolean;
    },
    opts?: { keepalive?: boolean },
  ): Promise<BlockDto>;
  resolveBlock(
    id: string,
    input: {
      expected_heads: string[];
      content?: string;
      keep_op_id?: string;
      op_id?: string;
      key_id?: string;
      mnb1_b64?: string;
      mnw1_b64?: string;
    },
  ): Promise<BlockDto>;
  lockBlock?(
    id: string,
    input: {
      expected_heads: string[];
      op_id: string;
      key_id: string;
      mnb1_b64: string;
      mnw1_b64: string;
      public_hint?: string | null;
    },
  ): Promise<BlockDto>;
  unlockBlock?(
    id: string,
    input: { expected_heads: string[]; content: string; lang?: string; shred_old_key?: boolean },
  ): Promise<BlockDto>;
  getTier1LeafPlaintext?(
    blockId: string,
    opId: string,
  ): Promise<{ block_id: string; op_id: string; content: string }>;
  deleteBlock(id: string, expectedHeads: string[]): Promise<{ in_trash: boolean; shred_state: string; shred_not_before_ms: number | null }>;
  createBuffer(input: { name: string; after_id?: string }): Promise<BufferDto>;
  renameBuffer(id: string, name: string): Promise<BufferDto>;
  deleteBuffer(id: string): Promise<BufferDto>;
  listTrash(): Promise<TrashItemDto[]>;
  getTrashTier2Blob?(id: string): Promise<{ op_id: string; key_id: string; mnb1_b64: string; mnw1_b64: string }>;
  restoreTrash(id: string, tier2?: { op_id: string; key_id: string; mnb1_b64: string; mnw1_b64?: string }): Promise<BlockDto>;
  prepareTrashAction?(input: {
    action: "expedite" | "confirm_pending" | "purge_history";
    block_ids?: string[];
    grace_ms?: number;
  }): Promise<TrashActionPrepareResponse>;
  commitTrashAction?(input: { confirm_nonce: string; tier2?: Tier2WritePayload; expected_heads?: string[] }): Promise<unknown>;
  putVaultHeader?(gen: number, blobB64: string): Promise<VaultHeaderDto>;
  listBlockedOps?(): Promise<BlockedTier2OpDto[]>;
  rekeyBlockedOp?(opId: string, payload: Tier2WritePayload): Promise<BlockDto>;
  getBlockHistory?(id: string, limit?: number): Promise<BlockHistoryEntryDto[]>;
  getBlockHistoryOp?(id: string, opId: string): Promise<BlockHistoryContentDto>;
  revertBlock?(
    id: string,
    input: {
      to_op_id?: string;
      undo_actor?: string;
      expected_heads?: string[];
      op_id?: string;
      key_id?: string;
      mnb1_b64?: string;
      mnw1_b64?: string;
    },
  ): Promise<BlockDto>;
  formatSnippet(input: { content: string; lang: string; action?: string; block_id?: string }): Promise<{ formatted: string }>;
  syncNow(): Promise<SyncStatusDto>;
  listClips?(opts?: { limit?: number; kind?: ClipKind }): Promise<ClipListResponse>;
  pushClipText?(input: { text: string; ephemeral?: boolean }): Promise<ClipPushResponse>;
  pushClipImage?(input: Omit<ClipPushImageInput, "kind">): Promise<ClipPushResponse>;
  getClipBlob?(clipId: string): Promise<{ blob: Blob; contentType: string }>;
  deleteClip?(clipId: string): Promise<ClipDeleteResponse>;
  clearClips?(): Promise<ClipDeleteResponse>;
  applyClip?(clipId: string): Promise<ClipApplyResponse>;
  promoteClip?(clipId: string, opts?: { buffer_id?: string; lang?: string }): Promise<ClipPromoteResponse>;
  undoClip?(): Promise<ClipUndoResponse>;
  patchClipWatch?(input: {
    paused?: boolean;
    enabled?: boolean;
    auto_apply_mirror?: ClipAutoApplyMirrorMode;
  }): Promise<ClipWatchResponse>;
  connectWs(
    onFrame: (frame: LocalWsFrame) => void,
    onConnChange?: (connected: boolean, reconnected?: boolean) => void,
    onAuthExpired?: () => void,
  ): () => void;
}

export function createLocalApiClient(): LocalApiClient {
  return {
    bootstrap: () => reqJson<BootstrapResponse>("/v1/local/bootstrap"),
    getSyncStatus: () => reqJson<SyncStatusDto>("/v1/local/sync/status"),
    listBlocks: (bufferId) => reqJson<BlockDto[]>(`/v1/local/blocks?buffer_id=${encodeURIComponent(bufferId)}`),
    createBlock: (input) => reqJson<BlockDto>("/v1/local/blocks", { method: "POST", body: JSON.stringify(input) }),
    patchBlock: (id, input, opts) =>
      reqJson<BlockDto>(`/v1/local/blocks/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: JSON.stringify(input),
        keepalive: opts?.keepalive,
      }),
    resolveBlock: (id, input) => reqJson<BlockDto>(`/v1/local/blocks/${encodeURIComponent(id)}/resolve`, { method: "POST", body: JSON.stringify(input) }),
    lockBlock: (id, input) => reqJson<BlockDto>(`/v1/local/blocks/${encodeURIComponent(id)}/lock`, { method: "POST", body: JSON.stringify(input) }),
    unlockBlock: (id, input) => reqJson<BlockDto>(`/v1/local/blocks/${encodeURIComponent(id)}/unlock`, { method: "POST", body: JSON.stringify(input) }),
    getTier1LeafPlaintext: (blockId, opId) =>
      reqJson<{ block_id: string; op_id: string; content: string }>(
        `/v1/local/blocks/${encodeURIComponent(blockId)}/tier1-leaf/${encodeURIComponent(opId)}`,
      ),
    deleteBlock: (id, expectedHeads) =>
      reqJson(`/v1/local/blocks/${encodeURIComponent(id)}`, { method: "DELETE", body: JSON.stringify({ expected_heads: expectedHeads }) }),
    createBuffer: (input) => reqJson<BufferDto>("/v1/local/buffers", { method: "POST", body: JSON.stringify(input) }),
    renameBuffer: (id, name) => reqJson<BufferDto>(`/v1/local/buffers/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ name }) }),
    deleteBuffer: (id) => reqJson<BufferDto>(`/v1/local/buffers/${encodeURIComponent(id)}`, { method: "DELETE" }),
    listTrash: () => reqJson<TrashItemDto[]>("/v1/local/trash"),
    getTrashTier2Blob: (id) => reqJson(`/v1/local/trash/${encodeURIComponent(id)}/tier2-blob`),
    restoreTrash: (id, tier2) =>
      reqJson<BlockDto>(`/v1/local/trash/${encodeURIComponent(id)}/restore`, {
        method: "POST",
        body: tier2 ? JSON.stringify(tier2) : undefined,
      }),
    prepareTrashAction: (input) =>
      reqJson<TrashActionPrepareResponse>("/v1/local/trash/actions/prepare", { method: "POST", body: JSON.stringify(input) }),
    commitTrashAction: (input) =>
      reqJson("/v1/local/trash/actions/commit", { method: "POST", body: JSON.stringify(input) }),
    putVaultHeader: (gen, blob_b64) =>
      reqJson<VaultHeaderDto>("/v1/local/vault/header", { method: "PUT", body: JSON.stringify({ gen, blob_b64 }) }),
    listBlockedOps: () => reqJson<BlockedTier2OpDto[]>("/v1/local/blocked-ops"),
    rekeyBlockedOp: (opId, payload) =>
      reqJson<BlockDto>(`/v1/local/blocked-ops/${encodeURIComponent(opId)}/rekey`, {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    getBlockHistory: (id, limit) => {
      const q = limit !== undefined ? `?limit=${encodeURIComponent(String(limit))}` : "";
      return reqJson<BlockHistoryEntryDto[]>(`/v1/local/blocks/${encodeURIComponent(id)}/history${q}`);
    },
    getBlockHistoryOp: (id, opId) =>
      reqJson<BlockHistoryContentDto>(
        `/v1/local/blocks/${encodeURIComponent(id)}/history/${encodeURIComponent(opId)}`,
      ),
    revertBlock: (id, input) =>
      reqJson<BlockDto>(`/v1/local/blocks/${encodeURIComponent(id)}/revert`, {
        method: "POST",
        body: JSON.stringify(input),
      }),
    formatSnippet: (input) => reqJson<{ formatted: string }>("/v1/local/format", { method: "POST", body: JSON.stringify(input) }),
    syncNow: () => reqJson<SyncStatusDto>("/v1/local/sync/now", { method: "POST" }),
    listClips: (opts) => {
      const params = new URLSearchParams();
      params.set("limit", String(opts?.limit ?? 100));
      if (opts?.kind) params.set("kind", opts.kind);
      return reqJson<ClipListResponse>(`/v1/local/clip?${params.toString()}`);
    },
    pushClipText: (input) =>
      reqJson<ClipPushResponse>("/v1/local/clip", {
        method: "POST",
        body: JSON.stringify({
          kind: "text",
          text: input.text,
          ...(input.ephemeral !== undefined ? { ephemeral: input.ephemeral } : {}),
        }),
      }),
    pushClipImage: (input) =>
      reqJson<ClipPushResponse>("/v1/local/clip", {
        method: "POST",
        body: JSON.stringify({ kind: "image", ...input }),
      }),
    getClipBlob: (clipId) => reqBlob(`/v1/local/clip/${encodeURIComponent(clipId)}/blob`),
    deleteClip: (clipId) => reqJson<ClipDeleteResponse>(`/v1/local/clip/${encodeURIComponent(clipId)}`, { method: "DELETE" }),
    clearClips: () => reqJson<ClipDeleteResponse>("/v1/local/clip", { method: "DELETE" }),
    applyClip: (clipId) => reqJson<ClipApplyResponse>(`/v1/local/clip/${encodeURIComponent(clipId)}/apply`, { method: "POST" }),
    promoteClip: (clipId, opts) =>
      reqJson<ClipPromoteResponse>(`/v1/local/clip/${encodeURIComponent(clipId)}/promote`, {
        method: "POST",
        body: JSON.stringify(opts ?? {}),
      }),
    undoClip: () => reqJson<ClipUndoResponse>("/v1/local/clip/undo", { method: "POST" }),
    patchClipWatch: (input) =>
      reqJson<ClipWatchResponse>("/v1/local/clip/watch", {
        method: "PATCH",
        body: JSON.stringify(input),
      }),
    connectWs(onFrame, onConnChange, onAuthExpired) {
      let closed = false;
      let hasConnectedOnce = false;
      let retryMs = 500;
      let ws: WebSocket | null = null;
      let timer: number | null = null;

      const scheduleReconnect = () => {
        if (closed) return;
        timer = window.setTimeout(open, retryMs);
        retryMs = Math.min(10_000, retryMs * 2);
      };

      const open = () => {
        if (closed) return;
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(`${proto}//${location.host}/v1/local/ws`);
        ws.onopen = () => {
          const reconnected = hasConnectedOnce;
          hasConnectedOnce = true;
          retryMs = 500;
          onConnChange?.(true, reconnected);
        };
        ws.onmessage = (ev) => {
          try {
            onFrame(JSON.parse(String(ev.data)) as LocalWsFrame);
          } catch {
            // ignore non-JSON frame
          }
        };
        ws.onclose = () => {
          onConnChange?.(false, false);
          if (closed) return;
          // Distinguish 401 session expiration from transient daemon/network disconnect
          void fetch("/v1/local/sync/status", { credentials: "same-origin", redirect: "manual" })
            .then((res) => {
              if (res.status === 401) {
                closed = true;
                onAuthExpired?.();
              } else {
                scheduleReconnect();
              }
            })
            .catch(() => {
              scheduleReconnect();
            });
        };
      };

      open();
      return () => {
        closed = true;
        if (timer !== null) window.clearTimeout(timer);
        ws?.close();
      };
    },
  };
}
