import { encode } from "@msgpack/msgpack";
import { blake3 } from "@noble/hashes/blake3";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ", LOWER_B32 = "0123456789abcdefghjkmnpqrstvwxyz", TE = new TextEncoder();
const CROCKFORD_MAP = new Int8Array(128).fill(-1);
for (let i = 0; i < 32; i++) CROCKFORD_MAP[CROCKFORD.charCodeAt(i)] = i;

export const b64ToBytes = (b64: unknown): Uint8Array => { if (typeof b64 !== "string") throw new TypeError("base64 payload must be a string"); return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)); };
export const bytesToB64 = (b: Uint8Array): string => { let s = ""; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
export const toU8 = (v: unknown): Uint8Array => (v instanceof Uint8Array ? v : new Uint8Array(v as ArrayBuffer));
export const hexEncode = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const randomPairId = (): string => hexEncode(crypto.getRandomValues(new Uint8Array(16)));
export const sha256Hex = async (s: string): Promise<string> => hexEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", TE.encode(s))));

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export const timingSafeEqualStr = (a: string, b: string): boolean => bytesEqual(blake3(TE.encode(a)), blake3(TE.encode(b)));

export function randomDeviceId(): string {
  let val = 0n;
  for (const b of crypto.getRandomValues(new Uint8Array(10))) val = (val << 8n) | BigInt(b);
  let out = "dev_";
  for (let i = 0; i < 16; i++) out += LOWER_B32[Number((val >> BigInt((15 - i) * 5)) & 31n)];
  return out;
}

export function ulidToBytes(s: string): Uint8Array {
  if (s.length !== 26) return TE.encode(s);
  let val = 0n;
  for (let i = 0; i < 26; i++) {
    const c = s.charCodeAt(i), v = c < 128 ? CROCKFORD_MAP[c] : -1;
    if (v < 0 || (i === 0 && v > 7)) return TE.encode(s);
    val = (val << 5n) | BigInt(v);
  }
  const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) { out[i] = Number(val & 0xffn); val >>= 8n; }
  return out;
}

const uuidToBytes = (uuid: string): Uint8Array => {
  const hex = uuid.replace(/-/g, "");
  return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
};
const u32le = (n: number): Uint8Array => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const i64le = (n: number): Uint8Array => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(Math.trunc(n)), true); return b; };
const concat = (parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((acc, p) => acc + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

export type ShredMarkState = "pending_confirm" | "scheduled" | "cancelled" | "executed";
export interface KeyRecordWire { key_id: string; wrap_gen: number; key_record: Uint8Array | null; created_at_ms: number; }
export interface ShredMarkWire { mark_id: string; key_id: string; seen_seq: number; requested_by: string; requested_at_ms: number; grace_ms: number; not_before_ms: number | null; state: ShredMarkState; confirmed_at_ms: number | null; cancelled_by: string | null; executed_at_ms: number | null; }
export interface KeyMaterialEntry { gen: number; blob: Uint8Array; }

const STATE_RANK: Record<ShredMarkState, number> = { pending_confirm: 0, scheduled: 1, cancelled: 2, executed: 3 };

/** Byte-identical to Rust `mynote_core::keys::KeyTableState::digest()`. */
export function computeKeysDigest(records: KeyRecordWire[], marks: ShredMarkWire[], keyring: KeyMaterialEntry | null, vaultHeader: KeyMaterialEntry | null): string {
  const h = blake3.create({});
  h.update(TE.encode("mynote-keys-digest-v1\0"));
  for (const r of [...records].sort((a, b) => (a.key_id < b.key_id ? -1 : a.key_id > b.key_id ? 1 : 0))) {
    h.update(ulidToBytes(r.key_id));
    h.update(u32le(r.wrap_gen));
    if (r.key_record) { h.update(new Uint8Array([1])); h.update(u32le(r.key_record.length)); h.update(r.key_record); } else h.update(new Uint8Array([0]));
  }
  h.update(TE.encode("\0marks\0"));
  for (const m of [...marks].sort((a, b) => (a.mark_id < b.mark_id ? -1 : a.mark_id > b.mark_id ? 1 : 0))) {
    h.update(ulidToBytes(m.mark_id)); h.update(ulidToBytes(m.key_id));
    h.update(new Uint8Array([STATE_RANK[m.state]])); h.update(i64le(m.not_before_ms ?? -1));
  }
  h.update(TE.encode("\0mat\0"));
  if (keyring) { h.update(new Uint8Array([1])); h.update(u32le(keyring.gen)); h.update(keyring.blob); } else h.update(new Uint8Array([0]));
  if (vaultHeader) { h.update(new Uint8Array([1])); h.update(i64le(vaultHeader.gen)); h.update(vaultHeader.blob); } else h.update(new Uint8Array([0]));
  return `blake3:${hexEncode(h.digest())}`;
}

const hashedContainer = (magic: string, hdr: Uint8Array, body: Uint8Array): Uint8Array => {
  const prefix = concat([TE.encode(magic), new Uint8Array([1]), u32le(hdr.length), hdr, body]);
  return concat([prefix, blake3(prefix)]);
};

export const encodeMna1 = (epoch: string, rows: { seq: number; op_id: string; key_id: string | null; device_id: string; created_at: number; envelope: Uint8Array }[], createdAtMs: number): Uint8Array =>
  hashedContainer("MNA1", encode({ journal_epoch: uuidToBytes(epoch), from_seq: rows[0].seq, to_seq: rows[rows.length - 1].seq, row_count: rows.length, created_at_ms: createdAtMs }), encode(rows));

export const encodeMnks = (createdAtMs: number, keyring: KeyMaterialEntry, vaultHeader: KeyMaterialEntry | null, records: KeyRecordWire[], marks: ShredMarkWire[] = []): Uint8Array =>
  hashedContainer("MNKS", encode({ created_at_ms: createdAtMs, keyring_gen: keyring.gen, record_count: records.length }), concat([new Uint8Array([0x84]), encode("keyring"), keyring.blob, encode("vault_header"), vaultHeader ? vaultHeader.blob : new Uint8Array([0xc0]), encode("records"), encode(records), encode("marks"), encode(marks)]));
