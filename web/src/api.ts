import type { ApiErrorBody, BlockDto, BootstrapResponse, BufferDto, LocalWsFrame, SyncStatusDto, TrashItemDto } from "./types";

export class LocalApiError extends Error {
  constructor(public status: number, public body: ApiErrorBody) {
    super(body.message || body.code);
  }
}

async function reqJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const res = await fetch(path, { ...init, headers, credentials: "same-origin" });
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
  if (parsed && typeof parsed === "object" && "ok" in parsed && "data" in parsed) {
    return (parsed as { data: T }).data;
  }
  return parsed as T;
}

export interface LocalApiClient {
  bootstrap(): Promise<BootstrapResponse>;
  listBlocks(bufferId: string): Promise<BlockDto[]>;
  createBlock(input: { buffer_id: string; lang: string; content: string; after_id?: string | null; fast_sync?: boolean }): Promise<BlockDto>;
  patchBlock(
    id: string,
    input: { expected_heads?: string[]; content?: string; lang?: string; after_id?: string; before_id?: string; buffer_id?: string; fast_sync?: boolean },
  ): Promise<BlockDto>;
  resolveBlock(id: string, input: { expected_heads: string[]; content?: string; keep_op_id?: string }): Promise<BlockDto>;
  deleteBlock(id: string, expectedHeads: string[]): Promise<{ in_trash: boolean; shred_state: string; shred_not_before_ms: number | null }>;
  createBuffer(input: { name: string; after_id?: string }): Promise<BufferDto>;
  renameBuffer(id: string, name: string): Promise<BufferDto>;
  deleteBuffer(id: string): Promise<BufferDto>;
  listTrash(): Promise<TrashItemDto[]>;
  restoreTrash(id: string): Promise<BlockDto>;
  formatSnippet(input: { content: string; lang: string; action?: string }): Promise<{ formatted: string }>;
  syncNow(): Promise<SyncStatusDto>;
  connectWs(onFrame: (frame: LocalWsFrame) => void, onConnChange?: (connected: boolean) => void): () => void;
}

export function createLocalApiClient(): LocalApiClient {
  return {
    bootstrap: () => reqJson<BootstrapResponse>("/v1/local/bootstrap"),
    listBlocks: (bufferId) => reqJson<BlockDto[]>(`/v1/local/blocks?buffer_id=${encodeURIComponent(bufferId)}`),
    createBlock: (input) => reqJson<BlockDto>("/v1/local/blocks", { method: "POST", body: JSON.stringify(input) }),
    patchBlock: (id, input) => reqJson<BlockDto>(`/v1/local/blocks/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(input) }),
    resolveBlock: (id, input) => reqJson<BlockDto>(`/v1/local/blocks/${encodeURIComponent(id)}/resolve`, { method: "POST", body: JSON.stringify(input) }),
    deleteBlock: (id, expectedHeads) =>
      reqJson(`/v1/local/blocks/${encodeURIComponent(id)}`, { method: "DELETE", body: JSON.stringify({ expected_heads: expectedHeads }) }),
    createBuffer: (input) => reqJson<BufferDto>("/v1/local/buffers", { method: "POST", body: JSON.stringify(input) }),
    renameBuffer: (id, name) => reqJson<BufferDto>(`/v1/local/buffers/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ name }) }),
    deleteBuffer: (id) => reqJson<BufferDto>(`/v1/local/buffers/${encodeURIComponent(id)}`, { method: "DELETE" }),
    listTrash: () => reqJson<TrashItemDto[]>("/v1/local/trash"),
    restoreTrash: (id) => reqJson<BlockDto>(`/v1/local/trash/${encodeURIComponent(id)}/restore`, { method: "POST" }),
    formatSnippet: (input) => reqJson<{ formatted: string }>("/v1/local/format", { method: "POST", body: JSON.stringify(input) }),
    syncNow: () => reqJson<SyncStatusDto>("/v1/local/sync/now", { method: "POST" }),
    connectWs(onFrame, onConnChange) {
      let closed = false;
      let retryMs = 500;
      let ws: WebSocket | null = null;
      let timer: number | null = null;

      const open = () => {
        if (closed) return;
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(`${proto}//${location.host}/v1/local/ws`);
        ws.onopen = () => {
          retryMs = 500;
          onConnChange?.(true);
        };
        ws.onmessage = (ev) => {
          try {
            onFrame(JSON.parse(String(ev.data)) as LocalWsFrame);
          } catch {
            // ignore non-JSON frame
          }
        };
        ws.onclose = () => {
          onConnChange?.(false);
          if (!closed) {
            timer = window.setTimeout(open, retryMs);
            retryMs = Math.min(10_000, retryMs * 2);
          }
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
