/**
 * IndexedDB ciphertext-only storage for Mobile Read-Only PWA (`docs/data-structures.md` §4.3, `SEC-08`).
 *
 * Hard invariants:
 * - Database `mynote_pwa_v1` with exact 6 stores:
 *   `device_keystore`, `meta`, `buffers`, `blocks`, `block_keys`, `vault_header`.
 * - Non-extractable AES-256-GCM WebCrypto `CryptoKey` in `device_keystore` wraps `creds_wrapped`
 *   and `engine_state_wrapped` in `meta`.
 * - ZERO plaintext of ANY Tier 1 or Tier 2 block or buffer name, ZERO raw SMK/VKEK/passphrase
 *   ever touches IndexedDB, `localStorage`, `sessionStorage`, or Cache Storage.
 */

const DB_NAME = "mynote_pwa_v1";
const DB_VERSION = 1;
const WRAP_KEY_ID = "device_wrap_key";

export interface SmkEntry {
  smk_kid: string;
  smk_b64: string;
}

export interface PwaCredentials {
  device_id: string;
  device_token: string;
  sync_url: string;
  smks: SmkEntry[];
}

export interface PwaSyncMeta {
  epoch: string | null;
  last_seq: number;
  keys_digest: string | null;
  updated_at_ms: number;
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

export async function clearAllPwaStorage(): Promise<void> {
  const db = await openPwaDb();
  try {
    const tx = db.transaction(["device_keystore", "meta", "buffers", "blocks", "block_keys", "vault_header"], "readwrite");
    for (const name of ["device_keystore", "meta", "buffers", "blocks", "block_keys", "vault_header"]) {
      tx.objectStore(name).clear();
    }
    await txDone(tx);
  } finally {
    db.close();
  }
}
