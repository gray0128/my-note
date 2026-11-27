/**
 * IndexedDB ciphertext-only storage for Mobile PWA (`docs/data-structures.md` §6, `SEC-08`).
 *
 * Hard invariants:
 * - Database `mynote_pwa_v1` (Schema v2) with exact 7 stores:
 *   `device_keystore`, `meta`, `buffers`, `blocks`, `block_keys`, `vault_header`, `clip_items`.
 * - Non-extractable AES-256-GCM WebCrypto `CryptoKey` in `device_keystore` wraps `creds_wrapped`
 *   and `engine_state_wrapped` in `meta`.
 * - `clip_items` stores ONLY ciphertext `meta_envelope_b64` + envelope headers — ZERO decrypted
 *   text, ZERO decrypted thumbnails, ZERO full image blobs (`SEC-08`).
 * - ZERO plaintext of ANY Tier 1 or Tier 2 block or buffer name, ZERO raw SMK/VKEK/ClipKey/passphrase
 *   ever touches IndexedDB, `localStorage`, `sessionStorage`, or Cache Storage.
 */

const DB_NAME = "mynote_pwa_v1";
const DB_VERSION = 2;
const WRAP_KEY_ID = "device_wrap_key";
const CLIP_MAX_ITEMS = 100;

export const PWA_ALL_STORES = [
  "device_keystore",
  "meta",
  "buffers",
  "blocks",
  "block_keys",
  "vault_header",
  "clip_items",
] as const;

export interface SmkEntry {
  smk_kid: string;
  smk_b64: string;
}

export interface PwaClipKeyEntry {
  clip_kid: string;
  clip_key_b64: string;
  gen?: number;
}

export interface PwaCredentials {
  device_id: string;
  device_token: string;
  sync_url: string;
  smks: SmkEntry[];
  scope?: "read" | "read+clip";
  clip_key?: PwaClipKeyEntry | null;
}

export interface PwaSyncMeta {
  epoch: string | null;
  last_seq: number;
  keys_digest: string | null;
  updated_at_ms: number;
}

/**
 * Ciphertext-only clipboard index record stored in IndexedDB `clip_items`.
 * Contains ONLY ciphertext `meta_envelope_b64` and non-secret envelope headers.
 */
export interface CiphertextClipItem {
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

interface WrappedBlob {
  iv: Uint8Array;
  ct: ArrayBuffer;
}

export interface CiphertextStateMirror {
  journal_epoch?: string | null;
  last_seq?: number;
  buffers?: Record<string, Record<string, unknown>>;
  blocks?: Record<string, Record<string, unknown>>;
  keys?: {
    records?: Record<string, Record<string, unknown>>;
    vault_header_material?: [number, number[]] | null;
  };
}

function reqPromise<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB request failed"));
  });
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
  });
}

function toStrictCiphertextClipRecord(item: CiphertextClipItem): CiphertextClipItem {
  return {
    clip_id: String(item.clip_id),
    clip_kid: String(item.clip_kid),
    device_id: String(item.device_id),
    kind: item.kind === "image" ? "image" : "text",
    created_at_ms: Number(item.created_at_ms),
    expires_at_ms: Number(item.expires_at_ms),
    meta_envelope_b64: String(item.meta_envelope_b64),
    has_blob: Boolean(item.has_blob),
    blob_bytes: item.blob_bytes === null || item.blob_bytes === undefined ? null : Number(item.blob_bytes),
  };
}

function sortClipsDesc(items: readonly CiphertextClipItem[]): CiphertextClipItem[] {
  return [...items].sort((a, b) => {
    if (b.created_at_ms !== a.created_at_ms) return b.created_at_ms - a.created_at_ms;
    return b.clip_id < a.clip_id ? -1 : b.clip_id > a.clip_id ? 1 : 0;
  });
}

export function openPwaDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("device_keystore")) db.createObjectStore("device_keystore");
      if (!db.objectStoreNames.contains("meta")) db.createObjectStore("meta");
      if (!db.objectStoreNames.contains("buffers")) db.createObjectStore("buffers", { keyPath: "id" });
      if (!db.objectStoreNames.contains("blocks")) db.createObjectStore("blocks", { keyPath: "id" });
      if (!db.objectStoreNames.contains("block_keys")) db.createObjectStore("block_keys", { keyPath: "key_id" });
      if (!db.objectStoreNames.contains("vault_header")) db.createObjectStore("vault_header", { keyPath: "id" });
      if (!db.objectStoreNames.contains("clip_items")) {
        const clipStore = db.createObjectStore("clip_items", { keyPath: "clip_id" });
        clipStore.createIndex("by_created", ["created_at_ms", "clip_id"], { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("Failed to open mynote_pwa_v1"));
  });
}

async function getOrCreateWrapKey(db: IDBDatabase): Promise<CryptoKey> {
  const rtx = db.transaction("device_keystore", "readonly");
  const existing = await reqPromise<CryptoKey | undefined>(rtx.objectStore("device_keystore").get(WRAP_KEY_ID));
  if (existing) return existing;

  // SEC-08: extractable MUST be false so raw wrapping key bytes can never be exported via JS.
  const created = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const wtx = db.transaction("device_keystore", "readwrite");
  wtx.objectStore("device_keystore").put(created, WRAP_KEY_ID);
  await txDone(wtx);
  return created;
}

async function encryptJson(wrapKey: CryptoKey, value: unknown): Promise<WrappedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(value));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, encoded);
  return { iv, ct };
}

async function decryptJson<T>(wrapKey: CryptoKey, blob: WrappedBlob): Promise<T> {
  const iv = new Uint8Array(blob.iv);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrapKey, blob.ct);
  return JSON.parse(new TextDecoder().decode(plainBuf)) as T;
}

export async function saveCredentials(creds: PwaCredentials): Promise<void> {
  const db = await openPwaDb();
  try {
    const key = await getOrCreateWrapKey(db);
    const wrapped = await encryptJson(key, creds);
    const tx = db.transaction("meta", "readwrite");
    tx.objectStore("meta").put(wrapped, "creds_wrapped");
    await txDone(tx);
  } finally {
    db.close();
  }
}

export async function loadCredentials(): Promise<PwaCredentials | null> {
  const db = await openPwaDb();
  try {
    const rtx = db.transaction(["device_keystore", "meta"], "readonly");
    const key = await reqPromise<CryptoKey | undefined>(rtx.objectStore("device_keystore").get(WRAP_KEY_ID));
    const wrapped = await reqPromise<WrappedBlob | undefined>(rtx.objectStore("meta").get("creds_wrapped"));
    if (!key || !wrapped) return null;
    return await decryptJson<PwaCredentials>(key, wrapped);
  } catch {
    // Graceful recovery after partial browser eviction or corrupt wrapped record
    return null;
  } finally {
    db.close();
  }
}

export async function loadEngineStateJson(): Promise<{ stateJson: string; meta: PwaSyncMeta | null } | null> {
  const db = await openPwaDb();
  try {
    const rtx = db.transaction(["device_keystore", "meta"], "readonly");
    const key = await reqPromise<CryptoKey | undefined>(rtx.objectStore("device_keystore").get(WRAP_KEY_ID));
    const wrapped = await reqPromise<WrappedBlob | undefined>(rtx.objectStore("meta").get("engine_state_wrapped"));
    const meta = (await reqPromise<PwaSyncMeta | undefined>(rtx.objectStore("meta").get("sync_meta"))) ?? null;
    if (!key || !wrapped) return null;
    const stateJson = await decryptJson<string>(key, wrapped);
    return { stateJson, meta };
  } catch {
    return null;
  } finally {
    db.close();
  }
}

/**
 * Persist ciphertext-only `MobileReadState` (wrapped under non-extractable WebCrypto key in `meta`)
 * and synchronize the ciphertext-only mirrors in `buffers`, `blocks`, `block_keys`, and `vault_header`.
 * Shredded entities are omitted so evicted/shredded records vanish from IndexedDB immediately.
 */
export async function saveEngineState(stateObj: CiphertextStateMirror, keysDigest: string | null): Promise<void> {
  const db = await openPwaDb();
  try {
    const key = await getOrCreateWrapKey(db);
    const stateJson = JSON.stringify(stateObj);
    const wrappedState = await encryptJson(key, stateJson);
    const syncMeta: PwaSyncMeta = {
      epoch: typeof stateObj.journal_epoch === "string" ? stateObj.journal_epoch : null,
      last_seq: typeof stateObj.last_seq === "number" ? stateObj.last_seq : 0,
      keys_digest: keysDigest,
      updated_at_ms: Date.now(),
    };

    const tx = db.transaction(["meta", "buffers", "blocks", "block_keys", "vault_header"], "readwrite");
    const metaStore = tx.objectStore("meta");
    metaStore.put(wrappedState, "engine_state_wrapped");
    metaStore.put(syncMeta, "sync_meta");

    const bufStore = tx.objectStore("buffers");
    bufStore.clear();
    if (stateObj.buffers) {
      for (const [id, buf] of Object.entries(stateObj.buffers)) {
        // Ciphertext-only fields (`name_mnb1` stays encrypted; ZERO plaintext!)
        bufStore.put({
          id,
          position: buf.position,
          key_id: buf.key_id,
          name_op_id: buf.name_op_id,
          name_mnb1: buf.name_mnb1,
          updated_at_ms: buf.updated_at_ms,
        });
      }
    }

    const blkStore = tx.objectStore("blocks");
    blkStore.clear();
    if (stateObj.blocks) {
      for (const [id, blk] of Object.entries(stateObj.blocks)) {
        // Ciphertext-only fields (`leaves[*].body.d.mnb1` stays encrypted; ZERO plaintext!)
        blkStore.put({
          id,
          buffer_id: blk.buffer_id,
          position: blk.position,
          lang: blk.lang,
          public_hint: blk.public_hint ?? null,
          leaves: blk.leaves,
          updated_at_ms: blk.updated_at_ms,
        });
      }
    }

    const keyStore = tx.objectStore("block_keys");
    keyStore.clear();
    if (stateObj.keys?.records) {
      for (const [key_id, rec] of Object.entries(stateObj.keys.records)) {
        keyStore.put({
          key_id,
          wrap_gen: rec.wrap_gen,
          key_record: rec.key_record ?? null,
          created_at_ms: rec.created_at_ms,
        });
      }
    }

    const vhStore = tx.objectStore("vault_header");
    vhStore.clear();
    if (stateObj.keys?.vault_header_material) {
      const [gen, blob] = stateObj.keys.vault_header_material;
      vhStore.put({ id: "current", gen, blob });
    }

    await txDone(tx);
  } finally {
    db.close();
  }
}

/**
 * Save ciphertext-only clipboard items into `clip_items` (pruned to latest 100 unexpired items).
 * Strictly strips any extra properties so plaintext/thumbnails/blobs NEVER enter IndexedDB.
 */
export async function saveClipItems(
  items: readonly CiphertextClipItem[],
  opts: { replaceAll?: boolean } = {},
): Promise<CiphertextClipItem[]> {
  const now = Date.now();
  const db = await openPwaDb();
  try {
    let mergedMap = new Map<string, CiphertextClipItem>();
    if (!opts.replaceAll) {
      const rtx = db.transaction("clip_items", "readonly");
      const existing = await reqPromise<CiphertextClipItem[]>(rtx.objectStore("clip_items").getAll());
      for (const row of existing) {
        if (row.expires_at_ms > now) {
          mergedMap.set(row.clip_id, toStrictCiphertextClipRecord(row));
        }
      }
    }
    for (const item of items) {
      if (item.expires_at_ms > now) {
        mergedMap.set(item.clip_id, toStrictCiphertextClipRecord(item));
      }
    }
    const retained = sortClipsDesc([...mergedMap.values()]).slice(0, CLIP_MAX_ITEMS);
    const tx = db.transaction("clip_items", "readwrite");
    const store = tx.objectStore("clip_items");
    store.clear();
    for (const row of retained) {
      store.put(row);
    }
    await txDone(tx);
    return retained;
  } finally {
    db.close();
  }
}

export async function loadClipItems(): Promise<CiphertextClipItem[]> {
  const now = Date.now();
  const db = await openPwaDb();
  try {
    const rtx = db.transaction("clip_items", "readonly");
    const all = await reqPromise<CiphertextClipItem[]>(rtx.objectStore("clip_items").getAll());
    return sortClipsDesc(all.filter((row) => row.expires_at_ms > now).map(toStrictCiphertextClipRecord)).slice(
      0,
      CLIP_MAX_ITEMS,
    );
  } catch {
    return [];
  } finally {
    db.close();
  }
}

export async function deleteClipItemIdb(clipId: string): Promise<void> {
  const db = await openPwaDb();
  try {
    const tx = db.transaction("clip_items", "readwrite");
    tx.objectStore("clip_items").delete(clipId);
    await txDone(tx);
  } finally {
    db.close();
  }
}

export async function clearClipItemsIdb(): Promise<void> {
  const db = await openPwaDb();
  try {
    const tx = db.transaction(["clip_items", "meta"], "readwrite");
    tx.objectStore("clip_items").clear();
    tx.objectStore("meta").delete("last_clip_id");
    await txDone(tx);
  } finally {
    db.close();
  }
}

export async function getLastClipId(): Promise<string | null> {
  const db = await openPwaDb();
  try {
    const rtx = db.transaction("meta", "readonly");
    const val = await reqPromise<unknown>(rtx.objectStore("meta").get("last_clip_id"));
    return typeof val === "string" && val.length > 0 ? val : null;
  } catch {
    return null;
  } finally {
    db.close();
  }
}

export async function setLastClipId(clipId: string | null): Promise<void> {
  const db = await openPwaDb();
  try {
    const tx = db.transaction("meta", "readwrite");
    if (clipId) {
      tx.objectStore("meta").put(clipId, "last_clip_id");
    } else {
      tx.objectStore("meta").delete("last_clip_id");
    }
    await txDone(tx);
  } finally {
    db.close();
  }
}

export async function clearAllPwaStorage(): Promise<void> {
  const db = await openPwaDb();
  try {
    const tx = db.transaction([...PWA_ALL_STORES], "readwrite");
    for (const name of PWA_ALL_STORES) {
      tx.objectStore(name).clear();
    }
    await txDone(tx);
  } finally {
    db.close();
  }
}
