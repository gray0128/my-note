import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { MyNoteApp } from "./app";
import { MobilePwaApp } from "./pwa/pwaApp";
import type { LocalApiClient } from "./api";
import type {
  BlockDto,
  BootstrapResponse,
  BufferDto,
  ClipItemDto,
  LocalWsFrame,
  SyncStatusDto,
} from "./types";
import {
  PWA_ALL_STORES,
  clearAllPwaStorage,
  clearClipItemsIdb,
  deleteClipItemIdb,
  getLastClipId,
  loadClipItems,
  loadCredentials,
  openPwaDb,
  saveClipItems,
  saveCredentials,
  setLastClipId,
  type CiphertextClipItem,
  type PwaCredentials,
} from "./pwa/idb";
import {
  SHARE_HANDOFF_CACHE,
  SHARE_HANDOFF_URL,
  consumeShareHandoffCache,
} from "./pwa/shareHandoff";
import {
  deleteCloudClip,
  getCloudClipBlob,
  listCloudClips,
  postCloudClip,
  putCloudClipBlob,
} from "./pwa/cloudApi";
import { WasmClipCodec, bytesToB64, initPwaWasmSync } from "./wasm/pwa";
import { computeSha256Hex, isSafeThumbDataUrl, validateClipImageFile } from "./clipUtils";

// Forbidden UI emoji code points checked without embedding literal glyphs (`ARCH-06`).
const FORBIDDEN_EMOJIS = ["\u{1F512}", "\u{1F513}", "\u26A1", "\u26A0", "\u{1F5BC}"];

// Minimal valid 1x1 PNG (67 bytes) for real binary round-trip tests.
const SAMPLE_PNG_BYTES = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
  0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
  0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
  0x42, 0x60, 0x82,
]);

// --- Lightweight in-memory IDBFactory shim for testing real `web/src/pwa/idb.ts` in happy-dom ---
interface FakeStoreData {
  keyPath: string | null;
  indexes: Map<string, string | string[]>;
  records: Map<string, unknown>;
}

interface FakeDbState {
  version: number;
  stores: Map<string, FakeStoreData>;
}

function createFakeIdbFactory(): {
  factory: IDBFactory;
  databases: Map<string, FakeDbState>;
} {
  const databases = new Map<string, FakeDbState>();

  function makeReq<T>(result: T): IDBRequest<T> {
    const req = {
      result,
      error: null,
      onsuccess: null as ((ev: Event) => void) | null,
      onerror: null as ((ev: Event) => void) | null,
    };
    queueMicrotask(() => req.onsuccess?.(new Event("success")));
    return req as unknown as IDBRequest<T>;
  }

  function makeDomStringList(items: string[]): DOMStringList {
    const arr = [...items];
    const obj = arr as unknown as DOMStringList & { contains(v: string): boolean; item(i: number): string | null };
    obj.contains = (v: string) => arr.includes(v);
    obj.item = (i: number) => arr[i] ?? null;
    return obj;
  }

  function wrapDb(state: FakeDbState): IDBDatabase {
    const db = {
      get version() {
        return state.version;
      },
      get objectStoreNames() {
        return makeDomStringList([...state.stores.keys()]);
      },
      createObjectStore(name: string, opts?: IDBObjectStoreParameters) {
        const storeData: FakeStoreData = {
          keyPath: typeof opts?.keyPath === "string" ? opts.keyPath : null,
          indexes: new Map(),
          records: new Map(),
        };
        state.stores.set(name, storeData);
        return {
          name,
          keyPath: storeData.keyPath,
          get indexNames() {
            return makeDomStringList([...storeData.indexes.keys()]);
          },
          createIndex(indexName: string, keyPath: string | string[]) {
            storeData.indexes.set(indexName, keyPath);
            return { name: indexName, keyPath };
          },
        } as unknown as IDBObjectStore;
      },
      transaction(storeNames: string | string[]) {
        const names = Array.isArray(storeNames) ? storeNames : [storeNames];
        for (const n of names) {
          if (!state.stores.has(n)) throw new Error(`Missing object store: ${n}`);
        }
        const tx = {
          error: null,
          oncomplete: null as ((ev: Event) => void) | null,
          onerror: null as ((ev: Event) => void) | null,
          onabort: null as ((ev: Event) => void) | null,
          objectStore(name: string) {
            const st = state.stores.get(name);
            if (!st) throw new Error(`Missing object store: ${name}`);
            return {
              name,
              keyPath: st.keyPath,
              get indexNames() {
                return makeDomStringList([...st.indexes.keys()]);
              },
              index(idxName: string) {
                const kp = st.indexes.get(idxName);
                if (!kp) throw new Error(`Missing index: ${idxName}`);
                return { name: idxName, keyPath: kp };
              },
              get(key: IDBValidKey) {
                return makeReq(st.records.get(String(key)));
              },
              getAll() {
                return makeReq([...st.records.values()]);
              },
              put(value: unknown, key?: IDBValidKey) {
                let k: string;
                if (st.keyPath && value && typeof value === "object") {
                  k = String((value as Record<string, unknown>)[st.keyPath]);
                } else {
                  k = String(key);
                }
                st.records.set(k, value);
                return makeReq(k);
              },
              delete(key: IDBValidKey) {
                st.records.delete(String(key));
                return makeReq(undefined);
              },
              clear() {
                st.records.clear();
                return makeReq(undefined);
              },
            } as unknown as IDBObjectStore;
          },
        };
        queueMicrotask(() => tx.oncomplete?.(new Event("complete")));
        return tx as unknown as IDBTransaction;
      },
      close() {
        // no-op
      },
    };
    return db as unknown as IDBDatabase;
  }

  const factory = {
    open(name: string, version = 1) {
      let state = databases.get(name);
      const needsUpgrade = !state || version > state.version;
      if (!state) {
        state = { version: 0, stores: new Map() };
        databases.set(name, state);
      }
      const db = wrapDb(state);
      const req = {
        result: db,
        error: null,
        onupgradeneeded: null as ((ev: IDBVersionChangeEvent) => void) | null,
        onsuccess: null as ((ev: Event) => void) | null,
        onerror: null as ((ev: Event) => void) | null,
      };
      queueMicrotask(() => {
        if (needsUpgrade) {
          state!.version = version;
          req.onupgradeneeded?.(new Event("upgradeneeded") as IDBVersionChangeEvent);
        }
        req.onsuccess?.(new Event("success"));
      });
      return req as unknown as IDBOpenDBRequest;
    },
    deleteDatabase(name: string) {
      databases.delete(name);
      return makeReq(undefined) as unknown as IDBOpenDBRequest;
    },
  } as unknown as IDBFactory;

  return { factory, databases };
}

interface ShortcutsModule {
  encryptMnc1Meta(opts: {
    clipKey: Uint8Array;
    clipKid: string;
    clipId: string;
    deviceId: string;
    meta: Record<string, unknown> | string;
    ephemeral?: boolean;
  }): Uint8Array;
  decryptMnc1Meta(opts: {
    clipKey: Uint8Array;
    clipKid: string;
    clipId: string;
    deviceId: string;
    envelope: Uint8Array;
    ephemeral?: boolean;
  }): Record<string, unknown>;
  encryptMnc1Blob(opts: {
    clipKey: Uint8Array;
    clipKid: string;
    clipId: string;
    deviceId: string;
    bytes: Uint8Array;
  }): Uint8Array;
  decryptMnc1Blob(opts: {
    clipKey: Uint8Array;
    clipKid: string;
    clipId: string;
    deviceId: string;
    envelope: Uint8Array;
  }): Uint8Array;
  prepareClipUpload(opts: {
    clipKey: Uint8Array;
    clipKid: string;
    deviceId: string;
    kind: "text" | "image";
    mime?: string;
    text?: string | null;
    rawBytes?: Uint8Array | null;
    ephemeral?: boolean;
    width?: number | null;
    height?: number | null;
  }): {
    mode: "inline" | "blob";
    method: "POST" | "PUT";
    path: string;
    clipId: string;
    meta: {
      v: number;
      kind: "text" | "image";
      mime: string;
      source_mode: string;
      created_at_ms: number;
      text: string | null;
      blob: { byte_size: number; sha256_hex: string; width: number | null; height: number | null } | null;
    };
    jsonBody?: {
      clip_id: string;
      clip_kid: string;
      kind: "text";
      ephemeral: boolean;
      meta_envelope_b64: string;
    };
    headers?: Record<string, string>;
    bodyBytes?: Uint8Array;
  };
  validateImageMime(mime: string): string;
  sha256Hex(bytes: Uint8Array): string;
  generateUlid(nowMs?: number): string;
  bytesToBase64(bytes: Uint8Array): string;
  base64ToBytes(b64: string): Uint8Array;
  parsePairingCode(code: string): { sync_url: string; pair_id: string; k_pair_b64u: string };
}

async function loadPwaWasmAndShortcuts(): Promise<ShortcutsModule> {
  const fsMod = (await import(/* @vite-ignore */ "node:" + "fs")) as {
    readFileSync(p: string): Uint8Array;
  };
  const pathMod = (await import(/* @vite-ignore */ "node:" + "path")) as {
    resolve(...parts: string[]): string;
  };
  const modMod = (await import(/* @vite-ignore */ "node:" + "module")) as {
    createRequire(base: string): (id: string) => unknown;
  };

  const wasmBytes = fsMod.readFileSync("src/wasm/pkg-pwa/mynote_wasm_bg.wasm");
  initPwaWasmSync(new Uint8Array(wasmBytes));

  const req = modMod.createRequire(import.meta.url);
  const scriptPath = pathMod.resolve("../deploy/ios-shortcuts/mynote-clip-push.js");
  return req(scriptPath) as ShortcutsModule;
}

function makeDesktopClipMockApi(initialClips: ClipItemDto[] = []) {
  const buffers: BufferDto[] = [
    { id: "01BUF000000000000000000001", name: "scratch", position: "a0", updated_at_ms: 1000 },
  ];
  const blocks: BlockDto[] = [
    {
      id: "01BLK000000000000000000001",
      buffer_id: buffers[0].id,
      position: "a0",
      lang: "text",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01OP0000000000000000000001"],
      display_op_id: "01OP0000000000000000000001",
      has_conflict: false,
      content: "hello",
      versions: [
        {
          op_id: "01OP0000000000000000000001",
          hlc: "000000000001000-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01KEY000000000000000000001",
          content: "hello",
        },
      ],
      updated_at_ms: 1000,
    },
  ];
  let clips: ClipItemDto[] = [...initialClips];
  let hasUndo = false;
  let watchEnabled = true;
  let watchPaused = false;
  let autoApplyMirror: "inbox-only" | "auto-apply" = "inbox-only";
  let wsListener: ((frame: LocalWsFrame) => void) | null = null;
  let seq = 1;

  const calls = {
    pushText: [] as Array<{ text: string; ephemeral?: boolean }>,
    pushImage: [] as Array<{ mime: string; data_b64: string }>,
    getBlob: [] as string[],
    apply: [] as string[],
    promote: [] as Array<{ clipId: string; bufferId?: string }>,
    del: [] as string[],
    clear: 0,
    undo: 0,
    patchWatch: [] as Array<{ paused?: boolean; enabled?: boolean; auto_apply_mirror?: string }>,
  };

  const status: SyncStatusDto = {
    sync_state: "synced",
    epoch: "00000000-0000-4000-8000-000000000001",
    last_seq: 1,
    pending_ops: 0,
    blocked_ops: 0,
    clock_skew_ms: 0,
    key_self_check: { ok: true, last_run_ms: 1000, blocks_missing_key: 0 },
    trash: { count: 0, pending_confirm_count: 0, next_shred_ms: null },
    recovery_drill_due: false,
    last_recovery_drill_ms: 1000,
    last_local_backup_ms: 1000,
  };

  const api: LocalApiClient = {
    async bootstrap(): Promise<BootstrapResponse> {
      return {
        buffers: [...buffers],
        initial_buffer_id: buffers[0].id,
        blocks: [...blocks],
        sync_status: { ...status },
        vault_header: null,
        trash_count: 0,
        device_id: "dev_mac0000000001",
        last_hlc: null,
      };
    },
    async listBlocks(bufferId) {
      return blocks.filter((b) => b.buffer_id === bufferId);
    },
    async createBlock(input) {
      seq++;
      const textContent = input.content ?? "";
      const created: BlockDto = {
        id: `01BLK00000000000000000000${seq}`,
        buffer_id: input.buffer_id,
        position: "z0",
        lang: input.lang ?? "text",
        is_locked: false,
        has_unlocked_concurrent_version: false,
        public_hint: null,
        head_op_ids: [`01OP000000000000000000000${seq}`],
        display_op_id: `01OP000000000000000000000${seq}`,
        has_conflict: false,
        content: textContent,
        versions: [
          {
            op_id: `01OP000000000000000000000${seq}`,
            hlc: `00000000000${seq}000-00000-dev_mac0000000001`,
            device_id: "dev_mac0000000001",
            actor: "human",
            is_display: true,
            is_locked: false,
            key_id: `01KEY00000000000000000000${seq}`,
            content: textContent,
          },
        ],
        updated_at_ms: Date.now(),
      };
      blocks.push(created);
      return created;
    },
    async patchBlock(id, input) {
      const found = blocks.find((b) => b.id === id)!;
      if (input.content !== undefined) found.content = input.content;
      return found;
    },
    async deleteBlock() {
      return { in_trash: true, shred_state: "scheduled", shred_not_before_ms: null };
    },
    async resolveBlock(id) {
      return blocks.find((b) => b.id === id)!;
    },
    async formatSnippet(input) {
      return { formatted: input.content };
    },
    async createBuffer(input) {
      const b: BufferDto = {
        id: `01BUF00000000000000000000${++seq}`,
        name: input.name,
        position: "z0",
        updated_at_ms: Date.now(),
      };
      buffers.push(b);
      return b;
    },
    async renameBuffer(id, name) {
      const b = buffers.find((x) => x.id === id)!;
      b.name = name;
      return b;
    },
    async deleteBuffer(id) {
      return buffers.find((x) => x.id === id) ?? buffers[0];
    },
    async syncNow() {
      return { ...status };
    },
    async listTrash() {
      return [];
    },
    async restoreTrash() {
      return blocks[0];
    },
    async getBlockHistory() {
      return [];
    },
    async getBlockHistoryOp() {
      throw new Error("not used");
    },
    async revertBlock() {
      return blocks[0];
    },
    async putVaultHeader(gen, blob_b64) {
      return { gen, blob_b64, updated_at_ms: Date.now() };
    },
    async lockBlock(id) {
      return blocks.find((b) => b.id === id)!;
    },
    async unlockBlock(id) {
      return blocks.find((b) => b.id === id)!;
    },
    async listClips(params) {
      const limit = params?.limit ?? 100;
      const filtered = params?.kind ? clips.filter((c) => c.kind === params.kind) : clips;
      return {
        items: filtered.slice(0, limit),
        has_undo: hasUndo,
        watch_enabled: watchEnabled,
        watch_paused: watchPaused,
        auto_apply_mirror: autoApplyMirror,
      };
    },
    async pushClipText(input) {
      calls.pushText.push({ text: input.text, ephemeral: input.ephemeral });
      const clip_id = `01CLIPTEXT000000000000000${++seq}`;
      if (input.ephemeral) {
        return { clip_id, ephemeral: true, delivered_to: 1, item: null };
      }
      const item: ClipItemDto = {
        clip_id,
        clip_kid: "01CKID00000000000000000001",
        device_id: "dev_mac0000000001",
        kind: "text",
        mime: "text/plain",
        source_mode: "explicit",
        created_at_ms: Date.now(),
        expires_at_ms: Date.now() + 7 * 86_400_000,
        text_preview: input.text,
        has_blob: false,
        blob_bytes: null,
        blob_sha256: null,
        width: null,
        height: null,
        thumb_mime: null,
        thumb_data_url: null,
        cached_locally: true,
      };
      clips = [item, ...clips];
      return { clip_id, ephemeral: false, item };
    },
    async pushClipImage(input) {
      calls.pushImage.push({ mime: input.mime, data_b64: input.data_b64 });
      const clip_id = `01CLIPIMG0000000000000000${++seq}`;
      const item: ClipItemDto = {
        clip_id,
        clip_kid: "01CKID00000000000000000001",
        device_id: "dev_mac0000000001",
        kind: "image",
        mime: input.mime,
        source_mode: "explicit",
        created_at_ms: Date.now(),
        expires_at_ms: Date.now() + 7 * 86_400_000,
        text_preview: null,
        has_blob: true,
        blob_bytes: SAMPLE_PNG_BYTES.length,
        blob_sha256: "a".repeat(64),
        width: input.width ?? 1,
        height: input.height ?? 1,
        thumb_mime: input.thumb_mime ?? "image/png",
        thumb_data_url: input.thumb_b64 ? `data:${input.thumb_mime ?? "image/png"};base64,${input.thumb_b64}` : null,
        cached_locally: true,
      };
      clips = [item, ...clips];
      return { clip_id, ephemeral: false, item };
    },
    async getClipBlob(clipId) {
      calls.getBlob.push(clipId);
      return {
        blob: new Blob([SAMPLE_PNG_BYTES], { type: "image/png" }),
        contentType: "image/png",
      };
    },
    async deleteClip(clipId) {
      calls.del.push(clipId);
      const before = clips.length;
      clips = clips.filter((c) => c.clip_id !== clipId);
      return { deleted_count: before - clips.length };
    },
    async clearClips() {
      calls.clear++;
      const count = clips.length;
      clips = [];
      return { deleted_count: count };
    },
    async applyClip(clipId) {
      calls.apply.push(clipId);
      hasUndo = true;
      return { applied: true, clip_id: clipId, has_undo: true };
    },
    async promoteClip(clipId, input) {
      calls.promote.push({ clipId, bufferId: input?.buffer_id });
      const target = clips.find((c) => c.clip_id === clipId);
      const promoted = await api.createBlock({
        buffer_id: input?.buffer_id ?? buffers[0].id,
        content: target?.text_preview ?? "",
        lang: input?.lang ?? "text",
      });
      return { block: promoted };
    },
    async undoClip() {
      calls.undo++;
      hasUndo = false;
      return { restored: true };
    },
    async patchClipWatch(input) {
      calls.patchWatch.push({ ...input });
      if (input.paused !== undefined) watchPaused = input.paused;
      if (input.enabled !== undefined) watchEnabled = input.enabled;
      if (input.auto_apply_mirror !== undefined) autoApplyMirror = input.auto_apply_mirror;
      return {
        watch_enabled: watchEnabled,
        watch_paused: watchPaused,
        auto_apply_mirror: autoApplyMirror,
      };
    },
    connectWs(onFrame) {
      wsListener = onFrame;
      return () => {
        wsListener = null;
      };
    },
  };

  return {
    api,
    calls,
    pushWs(frame: LocalWsFrame) {
      wsListener?.(frame);
    },
  };
}

describe("M4a-4: Desktop Clipboard UI, Mobile PWA Clipboard/IDB v2/ShareTarget, and iOS Scriptable Interop", () => {
  beforeEach(() => {
    document.body.innerHTML = '<div id="app"></div>';
    try {
      localStorage.clear();
    } catch {
      // happy-dom/node fallback
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("1. Bidirectional wire interop: real Rust WasmClipCodec <-> deploy/ios-shortcuts/mynote-clip-push.js (meta, ephemeral, blob, SHA-256, SVG rejection)", async () => {
    const shortcuts = await loadPwaWasmAndShortcuts();
    const clipKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) clipKey[i] = (i * 17 + 11) & 0xff;
    const clipKid = "01JCK000000000000000000001";
    const iosDeviceId = "dev_iphone_shortcuts_01";
    const pwaDeviceId = "dev_pwa_iphone_00000002";

    const pwaCodec = new WasmClipCodec(pwaDeviceId, clipKid, clipKey);
    const iosCodec = new WasmClipCodec(iosDeviceId, clipKid, clipKey);

    try {
      // 1a. JS prepareClipUpload (inline short text, UTF-8 + CJK) -> Rust WasmClipCodec.decryptMeta
      const textUpload = shortcuts.prepareClipUpload({
        clipKey,
        clipKid,
        deviceId: iosDeviceId,
        kind: "text",
        text: "Hello my-note M4a-4 跨端剪贴板测试",
        ephemeral: false,
      });
      expect(textUpload.mode).toBe("inline");
      expect(textUpload.method).toBe("POST");
      expect(textUpload.path).toBe("/v1/clip");
      const metaEnvBytes = shortcuts.base64ToBytes(textUpload.jsonBody!.meta_envelope_b64);
      const decodedByWasm = JSON.parse(
        pwaCodec.decryptMeta(textUpload.clipId, iosDeviceId, false, metaEnvBytes),
      ) as { kind: string; mime: string; text?: string; source_mode: string };
      expect(decodedByWasm.kind).toBe("text");
      expect(decodedByWasm.mime).toBe("text/plain");
      expect(decodedByWasm.text).toBe("Hello my-note M4a-4 跨端剪贴板测试");
      expect(decodedByWasm.source_mode).toBe("explicit");

      // 1b. Ephemeral text: decrypts with ephemeral=true, MUST fail cross-channel replay with ephemeral=false
      const ephUpload = shortcuts.prepareClipUpload({
        clipKey,
        clipKid,
        deviceId: iosDeviceId,
        kind: "text",
        text: "ONE_TIME_OTP_998877",
        ephemeral: true,
      });
      expect(ephUpload.mode).toBe("inline");
      expect(ephUpload.jsonBody!.ephemeral).toBe(true);
      const ephEnvBytes = shortcuts.base64ToBytes(ephUpload.jsonBody!.meta_envelope_b64);
      const ephDecoded = JSON.parse(
        pwaCodec.decryptMeta(ephUpload.clipId, iosDeviceId, true, ephEnvBytes),
      ) as { text?: string };
      expect(ephDecoded.text).toBe("ONE_TIME_OTP_998877");
      expect(() => pwaCodec.decryptMeta(ephUpload.clipId, iosDeviceId, false, ephEnvBytes)).toThrow();

      // 1c. Reverse direction: Rust WasmClipCodec.encryptMeta -> JS decryptMnc1Meta
      const revClipId = shortcuts.generateUlid();
      const revMeta = {
        v: 1,
        kind: "text",
        mime: "text/plain",
        source_mode: "explicit",
        created_at_ms: 1764200000000,
        text: "From Rust WASM to iOS Scriptable",
        blob: null,
      };
      const wasmMetaEnv = pwaCodec.encryptMeta(revClipId, JSON.stringify(revMeta), false);
      const jsDecodedMeta = shortcuts.decryptMnc1Meta({
        clipKey,
        clipKid,
        clipId: revClipId,
        deviceId: pwaDeviceId,
        envelope: wasmMetaEnv,
        ephemeral: false,
      });
      expect(jsDecodedMeta.text).toBe("From Rust WASM to iOS Scriptable");

      // 1d. Long text (> 64 KiB) switches automatically to streaming PUT /v1/clip/blob + 240-char preview + SHA-256
      const longText = "LONG_CLIP_LINE_".repeat(5000); // 75,000 bytes > 65,536
      const longUpload = shortcuts.prepareClipUpload({
        clipKey,
        clipKid,
        deviceId: iosDeviceId,
        kind: "text",
        text: longText,
      });
      expect(longUpload.mode).toBe("blob");
      expect(longUpload.method).toBe("PUT");
      expect(longUpload.path).toBe("/v1/clip/blob");
      const longMetaEnv = shortcuts.base64ToBytes(longUpload.headers!["X-Clip-Meta-B64"]);
      const longMeta = JSON.parse(
        pwaCodec.decryptMeta(longUpload.clipId, iosDeviceId, false, longMetaEnv),
      ) as { text: string; blob: { sha256_hex: string; byte_size: number } };
      expect(longMeta.text.length).toBeLessThanOrEqual(240);
      expect(longMeta.blob.byte_size).toBe(longText.length);
      const longPlainBytes = pwaCodec.decryptBlob(longUpload.clipId, iosDeviceId, longUpload.bodyBytes!);
      expect(new TextDecoder().decode(longPlainBytes)).toBe(longText);
      expect(await computeSha256Hex(longPlainBytes)).toBe(longMeta.blob.sha256_hex);

      // 1e. Binary PNG image: JS prepareClipUpload -> Rust decryptBlob & reverse Rust encryptBlob -> JS decryptMnc1Blob
      const imgUpload = shortcuts.prepareClipUpload({
        clipKey,
        clipKid,
        deviceId: iosDeviceId,
        kind: "image",
        mime: "image/png",
        rawBytes: SAMPLE_PNG_BYTES,
        width: 1,
        height: 1,
      });
      expect(imgUpload.mode).toBe("blob");
      expect(imgUpload.headers!["X-Clip-Kind"]).toBe("image");
      expect(imgUpload.headers!["Content-Type"]).toBe("application/octet-stream");
      const decodedImgBytes = pwaCodec.decryptBlob(imgUpload.clipId, iosDeviceId, imgUpload.bodyBytes!);
      expect(Array.from(decodedImgBytes)).toEqual(Array.from(SAMPLE_PNG_BYTES));
      expect(await computeSha256Hex(decodedImgBytes)).toBe(imgUpload.meta.blob!.sha256_hex);

      const wasmBlobEnv = iosCodec.encryptBlob(revClipId, SAMPLE_PNG_BYTES);
      const jsDecodedBlob = shortcuts.decryptMnc1Blob({
        clipKey,
        clipKid,
        clipId: revClipId,
        deviceId: iosDeviceId,
        envelope: wasmBlobEnv,
      });
      expect(Array.from(jsDecodedBlob)).toEqual(Array.from(SAMPLE_PNG_BYTES));

      // 1f. SVG strictly blocked on BOTH iOS Scriptable JS and Rust WasmClipCodec (`SEC-09`)
      expect(() =>
        shortcuts.prepareClipUpload({
          clipKey,
          clipKid,
          deviceId: iosDeviceId,
          kind: "image",
          mime: "image/svg+xml",
          rawBytes: new TextEncoder().encode("<svg onload=alert(1)/>"),
        }),
      ).toThrow();
      expect(() =>
        pwaCodec.encryptMeta(
          revClipId,
          JSON.stringify({
            v: 1,
            kind: "image",
            mime: "image/svg+xml",
            source_mode: "explicit",
            created_at_ms: 1764200000000,
          }),
          false,
        ),
      ).toThrow();

      // 1g. Pairing code parser check (matches Rust WasmSyncEngine.parsePairingCode!) + WasmClipCodec.zeroize()
      const pairPayloadB64u = bytesToB64(
        new TextEncoder().encode(
          JSON.stringify({
            u: "https://sync.example.com",
            p: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            k: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          }),
        ),
      )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
      const pairCode = `mynote-pair:v1:${pairPayloadB64u}`;
      const parsedPair = shortcuts.parsePairingCode(pairCode);
      expect(parsedPair.sync_url).toBe("https://sync.example.com");
      expect(parsedPair.pair_id).toBe("01ARZ3NDEKTSV4RRFFQ69G5FAV");
      expect(parsedPair.k_pair_b64u).toBe("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

      pwaCodec.zeroize();
      expect(pwaCodec.isZeroized()).toBe(true);
      expect(() => pwaCodec.encryptBlob(revClipId, SAMPLE_PNG_BYTES)).toThrow();
    } finally {
      pwaCodec.free();
      iosCodec.free();
    }
  });

  it("2. Desktop ClipDrawer & MyNoteApp: 100-item list, SVG block, bitmap preview/revokeObjectURL, promote/apply/undo/watch, WS clip_changed & CLIP_SECRET_BLOCKED, zero emojis/inline styles", async () => {
    const validPngThumb = `data:image/png;base64,${bytesToB64(SAMPLE_PNG_BYTES)}`;
    const maliciousSvgThumb = `data:image/svg+xml;base64,${btoa("<svg onload=alert(1)/>")}`;

    const initialClips: ClipItemDto[] = [
      {
        clip_id: "01CLIP00000000000000000001",
        clip_kid: "01CKID00000000000000000001",
        device_id: "dev_mac0000000001",
        kind: "text",
        mime: "text/plain",
        source_mode: "explicit",
        created_at_ms: 1764200005000,
        expires_at_ms: 1764804805000,
        text_preview: "Pinned desktop clip note",
        has_blob: false,
        blob_bytes: null,
        blob_sha256: null,
        width: null,
        height: null,
        thumb_mime: null,
        thumb_data_url: null,
        cached_locally: true,
      },
      {
        clip_id: "01CLIP00000000000000000002",
        clip_kid: "01CKID00000000000000000001",
        device_id: "dev_iphone00000001",
        kind: "image",
        mime: "image/png",
        source_mode: "explicit",
        created_at_ms: 1764200004000,
        expires_at_ms: 1764804804000,
        text_preview: null,
        has_blob: true,
        blob_bytes: SAMPLE_PNG_BYTES.length,
        blob_sha256: "b".repeat(64),
        width: 1,
        height: 1,
        thumb_mime: "image/png",
        thumb_data_url: validPngThumb,
        cached_locally: true,
      },
      {
        clip_id: "01CLIP00000000000000000003",
        clip_kid: "01CKID00000000000000000001",
        device_id: "dev_bad00000000001",
        kind: "image",
        mime: "image/png",
        source_mode: "explicit",
        created_at_ms: 1764200003000,
        expires_at_ms: 1764804803000,
        text_preview: null,
        has_blob: true,
        blob_bytes: 120,
        blob_sha256: "c".repeat(64),
        width: 10,
        height: 10,
        thumb_mime: "image/svg+xml",
        thumb_data_url: maliciousSvgThumb,
        cached_locally: false,
      },
    ];

    expect(isSafeThumbDataUrl(validPngThumb)).toBe(true);
    expect(isSafeThumbDataUrl(maliciousSvgThumb)).toBe(false);
    expect(validateClipImageFile("image/svg+xml", 100)).toEqual({
      ok: false,
      reason: "svg",
      mime: "image/svg+xml",
    });

    const createdUrls: string[] = [];
    const revokedUrls: string[] = [];
    vi.spyOn(URL, "createObjectURL").mockImplementation(() => {
      const u = `blob:test-clip-${createdUrls.length + 1}`;
      createdUrls.push(u);
      return u;
    });
    vi.spyOn(URL, "revokeObjectURL").mockImplementation((u) => {
      revokedUrls.push(u);
    });

    const { api, calls, pushWs } = makeDesktopClipMockApi(initialClips);
    const root = document.getElementById("app")!;
    const app = new MyNoteApp(root, api);
    await app.start();

    // Open clipboard drawer
    const inboxBtn = root.querySelector<HTMLButtonElement>('[data-testid="clip-inbox-btn"]')!;
    expect(inboxBtn).not.toBeNull();
    inboxBtn.click();
    await new Promise((r) => setTimeout(r, 30));

    const drawer = root.querySelector<HTMLElement>('[data-testid="clip-drawer"]')!;
    expect(drawer.classList.contains("hidden")).toBe(false);

    // Bitmap thumbnail renders; malicious SVG data URL thumbnail MUST NOT render <img>
    const validCard = drawer.querySelector<HTMLElement>('[data-clip-id="01CLIP00000000000000000002"]')!;
    expect(validCard.querySelector<HTMLImageElement>("img.clip-thumb-img")?.src).toBe(validPngThumb);
    const badThumbCard = drawer.querySelector<HTMLElement>('[data-clip-id="01CLIP00000000000000000003"]')!;
    expect(badThumbCard.querySelector("img")).toBeNull();

    // Promote button exists on text item, ABSENT on image item
    expect(drawer.querySelector('[data-testid="clip-promote-01CLIP00000000000000000001"]')).not.toBeNull();
    expect(drawer.querySelector('[data-testid="clip-promote-01CLIP00000000000000000002"]')).toBeNull();

    // Promote text item -> calls promoteClip
    drawer.querySelector<HTMLButtonElement>('[data-testid="clip-promote-01CLIP00000000000000000001"]')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.promote.length).toBe(1);
    expect(calls.promote[0].clipId).toBe("01CLIP00000000000000000001");

    // Apply -> enables Undo -> click Undo
    drawer.querySelector<HTMLButtonElement>('[data-testid="clip-apply-01CLIP00000000000000000001"]')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.apply).toEqual(["01CLIP00000000000000000001"]);
    const undoBtn = drawer.querySelector<HTMLButtonElement>('[data-testid="clip-undo-btn"]')!;
    expect(undoBtn.disabled).toBe(false);
    undoBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.undo).toBe(1);

    // Preview Full Image -> fetches on-demand blob -> creates objectURL -> closing revokes objectURL
    drawer.querySelector<HTMLButtonElement>('[data-testid="clip-preview-01CLIP00000000000000000002"]')!.click();
    await new Promise((r) => setTimeout(r, 30));
    expect(calls.getBlob).toContain("01CLIP00000000000000000002");
    const previewModal = root.querySelector<HTMLElement>('[data-testid="clip-preview-modal"]')!;
    expect(previewModal).not.toBeNull();
    expect(previewModal.querySelector<HTMLImageElement>("img")?.src).toBe("blob:test-clip-1");
    previewModal.querySelector<HTMLButtonElement>('[data-testid="clip-preview-close"]')!.click();
    expect(revokedUrls).toContain("blob:test-clip-1");

    // Save As downloads blob and revokes URL
    drawer.querySelector<HTMLButtonElement>('[data-testid="clip-save-01CLIP00000000000000000002"]')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(revokedUrls.length).toBeGreaterThanOrEqual(2);

    // Send ephemeral text
    const textInput = drawer.querySelector<HTMLTextAreaElement>('[data-testid="clip-send-text"]')!;
    const ephCheck = drawer.querySelector<HTMLInputElement>('[data-testid="clip-send-ephemeral"]')!;
    textInput.value = "Quick send from desktop";
    ephCheck.checked = true;
    drawer.querySelector<HTMLButtonElement>('[data-testid="clip-send-submit"]')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.pushText).toEqual([{ text: "Quick send from desktop", ephemeral: true }]);

    // Reject SVG upload via file picker -> visible error notice, ZERO pushClipImage calls
    const fileInput = drawer.querySelector<HTMLInputElement>('[data-testid="clip-send-image"]')!;
    const svgFile = new File(["<svg onload=alert(1)/>"], "evil.svg", { type: "image/svg+xml" });
    Object.defineProperty(fileInput, "files", { value: [svgFile], configurable: true });
    fileInput.dispatchEvent(new Event("change"));
    await new Promise((r) => setTimeout(r, 20));
    const errEl = drawer.querySelector<HTMLElement>('[data-testid="clip-error"]')!;
    expect(errEl.classList.contains("hidden")).toBe(false);
    expect(calls.pushImage.length).toBe(0);

    // Reject SVG paste too -> ZERO pushClipImage calls
    const pasteEv = new Event("paste", { bubbles: true, cancelable: true }) as ClipboardEvent;
    Object.defineProperty(pasteEv, "clipboardData", {
      value: {
        items: [{ kind: "file", type: "image/svg+xml", getAsFile: () => svgFile }],
      },
    });
    textInput.dispatchEvent(pasteEv);
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.pushImage.length).toBe(0);

    // Auto-Watch pause toggle calls PATCH /v1/local/clip/watch
    const watchBtn = drawer.querySelector<HTMLButtonElement>('[data-testid="clip-watch-toggle"]')!;
    watchBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.patchWatch).toEqual([{ paused: true }]);

    // Delete single clip & Clear All
    drawer.querySelector<HTMLButtonElement>('[data-testid="clip-delete-01CLIP00000000000000000003"]')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.del).toEqual(["01CLIP00000000000000000003"]);

    // WS clip_changed live update with 105 items caps display cleanly at 100 items
    const manyItems: ClipItemDto[] = Array.from({ length: 105 }, (_, idx) => ({
      clip_id: `01CLIPBULK${String(idx).padStart(16, "0")}`,
      clip_kid: "01CKID00000000000000000001",
      device_id: "dev_mac0000000001",
      kind: "text",
      mime: "text/plain",
      source_mode: "explicit",
      created_at_ms: 1764201000000 + idx,
      expires_at_ms: 1764900000000,
      text_preview: `Item #${idx}`,
      has_blob: false,
      blob_bytes: null,
      blob_sha256: null,
      width: null,
      height: null,
      thumb_mime: null,
      thumb_data_url: null,
      cached_locally: true,
    }));
    pushWs({
      type: "clip_changed",
      upserted: manyItems,
      deleted_ids: [],
      cleared: true,
      watch_paused: false,
    });
    expect(drawer.querySelectorAll('[data-testid="clip-list"] > .clip-item').length).toBe(100);

    // Clear All button
    drawer.querySelector<HTMLButtonElement>('[data-testid="clip-clear-btn"]')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.clear).toBe(1);
    expect(drawer.querySelectorAll('[data-testid="clip-list"] > .clip-item').length).toBe(0);

    // WS alert CLIP_SECRET_BLOCKED displays alert banner
    pushWs({
      type: "alert",
      code: "CLIP_SECRET_BLOCKED",
      details: { reason: "Blocked secret pattern" },
    });
    const alertBanner = root.querySelector<HTMLElement>('.alert-banner[data-code="CLIP_SECRET_BLOCKED"]')!;
    expect(alertBanner).not.toBeNull();
    expect(alertBanner.textContent?.toLowerCase()).toContain("secret");

    // Strict CSP & emoji hygiene: ZERO inline style attributes & ZERO forbidden UI emojis inside clip drawer
    expect(drawer.querySelectorAll("[style]").length).toBe(0);
    for (const emoji of FORBIDDEN_EMOJIS) {
      expect(root.textContent ?? "").not.toContain(emoji);
    }

    app.destroy();
  });

  it("3. Mobile PWA IndexedDB v2 (7 stores + ciphertext-only clip_items + 100-item cap + clearAllPwaStorage) & share_target handoff cleanup", async () => {
    const { factory, databases } = createFakeIdbFactory();
    const origIdb = globalThis.indexedDB;
    Object.defineProperty(globalThis, "indexedDB", { value: factory, configurable: true });

    try {
      // 3a. Open DB v2 -> exact 7 object stores & clip_items by_created index
      const db = await openPwaDb();
      const storeNames = Array.from(db.objectStoreNames).sort();
      expect(storeNames).toEqual([...PWA_ALL_STORES].sort());
      expect(storeNames.length).toBe(7);
      const tx = db.transaction("clip_items", "readonly");
      const idx = tx.objectStore("clip_items").index("by_created");
      expect(idx.keyPath).toEqual(["created_at_ms", "clip_id"]);
      db.close();

      // 3b. PwaCredentials with scope="read+clip" & clip_key stored encrypted inside creds_wrapped (non-extractable key)
      const creds: PwaCredentials = {
        device_id: "dev_pwa_01",
        device_token: "SECRET_DEVICE_TOKEN_NEVER_PLAINTEXT",
        sync_url: "https://sync.example.com",
        smks: [{ smk_kid: "01SMK1", smk_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }],
        scope: "read+clip",
        clip_key: {
          clip_kid: "01CKID1",
          clip_key_b64: "SECRET_CLIP_KEY_NEVER_PLAINTEXT_0123456789==",
          gen: 2,
        },
      };
      await saveCredentials(creds);
      const loadedCreds = await loadCredentials();
      expect(loadedCreds).toEqual(creds);

      // Verify raw IDB dump does NOT contain plaintext token or ClipKey and CryptoKey is non-extractable
      const rawDb = databases.get("mynote_pwa_v1")!;
      const wrapKey = rawDb.stores.get("device_keystore")!.records.get("device_wrap_key") as CryptoKey;
      expect(wrapKey.extractable).toBe(false);
      const rawMetaDump = JSON.stringify([...rawDb.stores.get("meta")!.records.entries()]);
      expect(rawMetaDump).not.toContain("SECRET_DEVICE_TOKEN_NEVER_PLAINTEXT");
      expect(rawMetaDump).not.toContain("SECRET_CLIP_KEY_NEVER_PLAINTEXT");

      // 3c. saveClipItems strips any tainted plaintext/thumbnail/blob fields (`SEC-08`) and prunes to 100 unexpired items
      const future = Date.now() + 86_400_000;
      const taintedBatch = Array.from({ length: 105 }, (_, i) => ({
        clip_id: `01CLIPIDB${String(i).padStart(17, "0")}`,
        clip_kid: "01CKID1",
        device_id: "dev_mac",
        kind: "text" as const,
        created_at_ms: 1764200000000 + i,
        expires_at_ms: future,
        meta_envelope_b64: "TU5DMV9DSVBIRVJURVhU",
        has_blob: false,
        blob_bytes: null,
        // Deliberately inject disallowed plaintext fields to prove they are stripped before IDB write!
        plaintext: `LEAKED_PLAINTEXT_${i}`,
        text_preview: `LEAKED_PREVIEW_${i}`,
        thumb_data_url: "data:image/png;base64,LEAKED_THUMB",
        blob_raw: new Uint8Array([1, 2, 3]),
      })) as unknown as CiphertextClipItem[];

      const saved = await saveClipItems(taintedBatch);
      expect(saved.length).toBe(100);
      const loaded = await loadClipItems();
      expect(loaded.length).toBe(100);
      // Sorted newest first
      expect(loaded[0].created_at_ms).toBe(1764200000104);
      const clipDump = JSON.stringify([...rawDb.stores.get("clip_items")!.records.values()]);
      expect(clipDump).not.toContain("LEAKED_PLAINTEXT");
      expect(clipDump).not.toContain("LEAKED_PREVIEW");
      expect(clipDump).not.toContain("LEAKED_THUMB");
      expect(clipDump).not.toContain("blob_raw");

      // Delete single clip, last_clip_id cursor, clearClipItemsIdb, and clearAllPwaStorage
      await deleteClipItemIdb(loaded[0].clip_id);
      expect((await loadClipItems()).length).toBe(99);
      await setLastClipId(loaded[1].clip_id);
      expect(await getLastClipId()).toBe(loaded[1].clip_id);
      await clearClipItemsIdb();
      expect((await loadClipItems()).length).toBe(0);

      await saveClipItems(taintedBatch.slice(0, 3));
      expect((await loadClipItems()).length).toBe(3);
      await clearAllPwaStorage();
      for (const storeName of PWA_ALL_STORES) {
        expect(rawDb.stores.get(storeName)!.records.size).toBe(0);
      }
    } finally {
      Object.defineProperty(globalThis, "indexedDB", { value: origIdb, configurable: true });
    }

    // 3d. share_target handoff cache consumption ALWAYS deletes transient cache (`SEC-08`)
    const cacheMap = new Map<string, Map<string, Response>>();
    const deletedCaches: string[] = [];
    const fakeCaches = {
      async has(name: string) {
        return cacheMap.has(name);
      },
      async open(name: string) {
        if (!cacheMap.has(name)) cacheMap.set(name, new Map());
        const store = cacheMap.get(name)!;
        return {
          async match(key: string) {
            return store.get(key);
          },
          async put(key: string, res: Response) {
            store.set(key, res);
          },
          async delete(key: string) {
            return store.delete(key);
          },
        };
      },
      async delete(name: string) {
        deletedCaches.push(name);
        return cacheMap.delete(name);
      },
    };
    const origCaches = globalThis.caches;
    Object.defineProperty(globalThis, "caches", { value: fakeCaches, configurable: true });
    try {
      // Text handoff
      const c1 = await fakeCaches.open(SHARE_HANDOFF_CACHE);
      await c1.put(
        SHARE_HANDOFF_URL,
        new Response(JSON.stringify({ kind: "text", text: "Shared from Android" }), {
          headers: { "content-type": "application/json", "x-share-kind": "text" },
        }),
      );
      const res1 = await consumeShareHandoffCache();
      expect(res1).toEqual({ kind: "text", text: "Shared from Android" });
      expect(deletedCaches).toContain(SHARE_HANDOFF_CACHE);
      expect(cacheMap.has(SHARE_HANDOFF_CACHE)).toBe(false);

      // Bitmap image handoff
      const c2 = await fakeCaches.open(SHARE_HANDOFF_CACHE);
      await c2.put(
        SHARE_HANDOFF_URL,
        new Response(SAMPLE_PNG_BYTES, {
          headers: {
            "content-type": "image/png",
            "x-share-kind": "image",
            "x-share-filename": "photo.png",
          },
        }),
      );
      const res2 = await consumeShareHandoffCache();
      expect(res2?.kind).toBe("image");
      if (res2?.kind === "image") {
        expect(res2.mime).toBe("image/png");
        expect(Array.from(res2.bytes)).toEqual(Array.from(SAMPLE_PNG_BYTES));
      }
      expect(cacheMap.has(SHARE_HANDOFF_CACHE)).toBe(false);

      // SVG error handoff still wipes cache
      const c3 = await fakeCaches.open(SHARE_HANDOFF_CACHE);
      await c3.put(
        SHARE_HANDOFF_URL,
        new Response(JSON.stringify({ kind: "error", code: "DISALLOWED_MIME", mime: "image/svg+xml" }), {
          headers: { "content-type": "application/json", "x-share-kind": "error" },
        }),
      );
      const res3 = await consumeShareHandoffCache();
      expect(res3).toEqual({ kind: "error", code: "DISALLOWED_MIME", mime: "image/svg+xml" });
      expect(cacheMap.has(SHARE_HANDOFF_CACHE)).toBe(false);
    } finally {
      Object.defineProperty(globalThis, "caches", { value: origCaches, configurable: true });
    }

    // 3e. Static checks on manifest.webmanifest & sw.js
    const fsMod = (await import(/* @vite-ignore */ "node:" + "fs")) as {
      readFileSync(p: string, enc: string): string;
    };
    const manifest = JSON.parse(fsMod.readFileSync("public-pwa/manifest.webmanifest", "utf8")) as {
      share_target: {
        action: string;
        method: string;
        enctype: string;
        params: { files: Array<{ name: string; accept: string[] }> };
      };
    };
    expect(manifest.share_target.action).toBe("/clip-share");
    expect(manifest.share_target.method).toBe("POST");
    expect(manifest.share_target.enctype).toBe("multipart/form-data");
    expect(manifest.share_target.params.files[0].accept).toContain("image/png");
    expect(manifest.share_target.params.files[0].accept).not.toContain("image/svg+xml");

    const swJs = fsMod.readFileSync("public-pwa/sw.js", "utf8");
    expect(swJs).toContain('CACHE_NAME = "mynote-pwa-shell-v5"');
    expect(swJs).toContain("mynote-share-handoff");
    expect(swJs).toContain('url.pathname === "/clip-share"');
    expect(swJs).toContain('url.pathname.startsWith("/v1/")');
  });

  it("4. cloudApi.ts clip routes enforce redirect:'manual' (ARCH-05) and reject 302 redirects", async () => {
    const fetchCalls: Array<{ url: string; init: RequestInit | undefined }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      fetchCalls.push({ url, init });
      if (url.includes("/302-test")) {
        return new Response("", { status: 302, headers: { location: "https://captive.invalid" } });
      }
      if (url.endsWith("/blob") && init?.method === "GET") {
        return new Response(new Uint8Array([0x4d, 0x4e, 0x43, 0x31]), {
          status: 200,
          headers: { "content-type": "application/octet-stream" },
        });
      }
      return new Response(JSON.stringify({ ok: true, items: [], deleted_count: 1, clip_id: "01C1", created_at_ms: 1, expires_at_ms: 2, ephemeral: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    await listCloudClips("https://sync.example.com", "tok", "01SINCE", 50);
    await postCloudClip("https://sync.example.com", "tok", {
      clip_id: "01C1",
      clip_kid: "01CK1",
      kind: "text",
      meta_envelope_b64: "AAA",
      ephemeral: false,
    });
    await putCloudClipBlob(
      "https://sync.example.com",
      "tok",
      {
        clipId: "01C2",
        clipKid: "01CK1",
        kind: "image",
        metaEnvelopeB64: "BBB",
      },
      new Uint8Array([1, 2, 3]),
    );
    const blobRes = await getCloudClipBlob("https://sync.example.com", "tok", "01C2");
    expect(Array.from(blobRes.bytes)).toEqual([0x4d, 0x4e, 0x43, 0x31]);
    await deleteCloudClip("https://sync.example.com", "tok", "01C2");
    await deleteCloudClip("https://sync.example.com", "tok");

    expect(fetchCalls.length).toBe(6);
    for (const c of fetchCalls) {
      expect(c.init?.redirect).toBe("manual");
    }

    await expect(listCloudClips("https://sync.example.com/302-test", "tok")).rejects.toMatchObject({
      code: "REDIRECT_REFUSED",
    });
  });

  it("5. MobilePwaApp Clipboard tab: Notes strictly read-only (.ro-block textarea/contenteditable == 0) + iOS synchronous ClipboardItem Promise<Blob> PNG copy with WasmClipCodec & SHA-256 verification", async () => {
    await loadPwaWasmAndShortcuts();

    const clipKey = new Uint8Array(32).fill(7);
    const clipKid = "01CK00PWA00000000000000001";
    const devId = "dev_iphone_pwa_001";
    const codec = new WasmClipCodec(devId, clipKid, clipKey);
    const imgClipId = "01C000MG0PWA00000000000001";
    const txtClipId = "01C000TX0PWA00000000000002";
    const pngSha = await computeSha256Hex(SAMPLE_PNG_BYTES);
    const encryptedPngBlob = codec.encryptBlob(imgClipId, SAMPLE_PNG_BYTES);

    const pwaRoot = document.createElement("div");
    pwaRoot.className = "pwa-shell";
    document.body.appendChild(pwaRoot);

    const pwa = new MobilePwaApp(pwaRoot);
    const internals = pwa as unknown as {
      creds: PwaCredentials;
      buffers: Array<{ id: string; name: string; position: string; state: string; updated_at_ms: number }>;
      blocks: Array<Record<string, unknown>>;
      activeBufferId: string;
      clipCodec: WasmClipCodec | null;
      clipItemsCipher: CiphertextClipItem[];
      decryptClipsInRam(): void;
      render(): void;
    };

    internals.creds = {
      device_id: devId,
      device_token: "tok_pwa",
      sync_url: "https://sync.example.com",
      smks: [],
      scope: "read+clip",
      clip_key: { clip_kid: clipKid, clip_key_b64: bytesToB64(clipKey) },
    };
    internals.buffers = [{ id: "01BUF1", name: "notes", position: "a0", state: "active", updated_at_ms: 1000 }];
    internals.activeBufferId = "01BUF1";
    internals.blocks = [
      {
        id: "01BLK_RO",
        buffer_id: "01BUF1",
        position: "a0",
        lang: "text",
        public_hint: null,
        state: "active",
        is_locked: false,
        has_unlocked_concurrent_version: false,
        display_op_id: "01OP1",
        updated_at_ms: 1000,
        versions: [
          {
            op_id: "01OP1",
            hlc: "000000000001000-00000-dev_mac",
            device_id: "dev_mac",
            actor: "human",
            is_display: true,
            is_locked: false,
            key_id: "01K1",
            content: "Strictly read-only note body",
            mnb1_b64: null,
            mnw1_b64: null,
            body_state: "ok",
          },
        ],
      },
    ];
    const txtMetaEnv = codec.encryptMeta(
      txtClipId,
      JSON.stringify({
        v: 1,
        kind: "text",
        mime: "text/plain",
        source_mode: "explicit",
        created_at_ms: 1764200002000,
        text: "Decrypted RAM-only text clip",
        blob: null,
      }),
      false,
    );
    const imgMetaEnv = codec.encryptMeta(
      imgClipId,
      JSON.stringify({
        v: 1,
        kind: "image",
        mime: "image/png",
        source_mode: "explicit",
        created_at_ms: 1764200001000,
        text: null,
        blob: {
          byte_size: SAMPLE_PNG_BYTES.length,
          sha256_hex: pngSha,
          width: 1,
          height: 1,
          thumb_mime: "image/png",
          thumb_b64: bytesToB64(SAMPLE_PNG_BYTES),
        },
      }),
      false,
    );
    internals.clipCodec = codec;
    internals.clipItemsCipher = [
      {
        clip_id: txtClipId,
        clip_kid: clipKid,
        device_id: devId,
        kind: "text",
        created_at_ms: 1764200002000,
        expires_at_ms: 1764900000000,
        meta_envelope_b64: bytesToB64(txtMetaEnv),
        has_blob: false,
        blob_bytes: null,
      },
      {
        clip_id: imgClipId,
        clip_kid: clipKid,
        device_id: devId,
        kind: "image",
        created_at_ms: 1764200001000,
        expires_at_ms: 1764900000000,
        meta_envelope_b64: bytesToB64(imgMetaEnv),
        has_blob: true,
        blob_bytes: SAMPLE_PNG_BYTES.length,
      },
    ];
    internals.decryptClipsInRam();
    internals.render();

    // Notes tab is default and strictly read-only
    expect(pwaRoot.querySelectorAll(".ro-block textarea, .ro-block [contenteditable]").length).toBe(0);

    // Switch to Clipboard tab
    pwaRoot.querySelector<HTMLButtonElement>('[data-testid="pwa-tab-clip"]')!.click();
    const clipView = pwaRoot.querySelector<HTMLElement>('[data-testid="pwa-clip-view"]')!;
    expect(clipView).not.toBeNull();
    expect(clipView.textContent).toContain("Decrypted RAM-only text clip");
    expect(clipView.querySelectorAll("[style]").length).toBe(0);
    for (const emoji of FORBIDDEN_EMOJIS) {
      expect(pwaRoot.textContent ?? "").not.toContain(emoji);
    }

    // Prepare deferred fetch & mock ClipboardItem / navigator.clipboard.write to prove SYNCHRONOUS invocation inside click
    let resolveFetch!: (res: Response) => void;
    const fetchPromise = new Promise<Response>((res) => {
      resolveFetch = res;
    });
    vi.spyOn(globalThis, "fetch").mockImplementation(() => fetchPromise);

    let capturedItems: Array<Record<string, Blob | Promise<Blob>>> = [];
    let writeCalledSynchronously = false;
    class FakeClipboardItem {
      data: Record<string, Blob | Promise<Blob>>;
      constructor(data: Record<string, Blob | Promise<Blob>>) {
        this.data = data;
      }
    }
    const origClipboardItem = globalThis.ClipboardItem;
    Object.defineProperty(globalThis, "ClipboardItem", { value: FakeClipboardItem, configurable: true });
    Object.defineProperty(navigator, "clipboard", {
      value: {
        write: vi.fn((items: FakeClipboardItem[]) => {
          writeCalledSynchronously = true;
          capturedItems = items.map((x) => x.data);
          return Promise.resolve();
        }),
        writeText: vi.fn(() => Promise.resolve()),
      },
      configurable: true,
    });

    try {
      // Click Copy on the image clip item — MUST invoke navigator.clipboard.write BEFORE fetch resolves!
      const copyImgBtn = clipView.querySelector<HTMLButtonElement>(`[data-testid="pwa-clip-copy-${imgClipId}"]`)!;
      copyImgBtn.click();
      expect(writeCalledSynchronously).toBe(true);
      expect(capturedItems.length).toBe(1);
      expect(capturedItems[0]["image/png"]).toBeInstanceOf(Promise);

      // Now settle the network response with encrypted MNC1 PNG blob
      resolveFetch(
        new Response(new Blob([new Uint8Array(encryptedPngBlob)]), {
          status: 200,
          headers: { "content-type": "application/octet-stream" },
        }),
      );
      const resolvedPngBlob = await capturedItems[0]["image/png"];
      expect(resolvedPngBlob).toBeInstanceOf(Blob);
      expect(resolvedPngBlob.type).toBe("image/png");
      const outBytes = new Uint8Array(await resolvedPngBlob.arrayBuffer());
      expect(Array.from(outBytes)).toEqual(Array.from(SAMPLE_PNG_BYTES));

      // SVG file upload rejected in PWA Clipboard composer with zero network calls
      const fetchMock = vi.spyOn(globalThis, "fetch");
      fetchMock.mockClear();
      const fileInput = clipView.querySelector<HTMLInputElement>('[data-testid="pwa-clip-file"]')!;
      const svgFile = new File(["<svg/>"], "x.svg", { type: "image/svg+xml" });
      Object.defineProperty(fileInput, "files", { value: [svgFile], configurable: true });
      fileInput.dispatchEvent(new Event("change"));
      await new Promise((r) => setTimeout(r, 20));
      expect(pwaRoot.querySelector<HTMLElement>('[data-testid="pwa-clip-error"]')?.classList.contains("hidden")).toBe(
        false,
      );
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(globalThis, "ClipboardItem", { value: origClipboardItem, configurable: true });
      pwa.destroy();
      pwaRoot.remove();
    }
  });
});
