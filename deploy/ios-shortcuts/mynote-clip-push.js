// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: blue; icon-glyph: clipboard;
//
// my-note Cross-Device Clipboard Sender for iOS Shortcuts + Scriptable (M4a, D8)
//
// Zero-dependency, pure synchronous JavaScript MNC1 (XChaCha20-Poly1305) + SHA-256 sender.
// - Credentials (`sync_url`, `device_id`, `device_token`, `clip_kid`, `clip_key_b64`) are stored
//   STRICTLY in Scriptable's native iOS Keychain (NEVER hardcoded in Shortcut files).
// - Uses `scope = clip-write` one-way token (cannot read notes or clipboard history).
// - Text <= 64 KiB (or ephemeral <= 256 KiB): POST /v1/clip (JSON envelope).
// - Text > 64 KiB or bitmap image (PNG/JPEG/WebP/GIF <= 10 MiB): PUT /v1/clip/blob with raw
//   binary MNC1 stream (ZERO Base64 bloat on body). Strictly rejects image/svg+xml.
// - Spec SSOT: docs/data-structures.md §3.1, §3.2, §3.3, §3.8 & docs/interface-contracts.md §4.2(7).

(function (root) {
  "use strict";

  const VER = 1;
  const HDR = 45;
  const TAG = 16;
  const F_EPH = 1;
  const F_BLOB = 2;
  const F_RES = 0xfc;

  const INLINE_TEXT_MAX_BYTES = 64 * 1024;
  const EPHEMERAL_MAX_BYTES = 256 * 1024;
  const BLOB_MAX_BYTES = 10 * 1024 * 1024;
  const PREVIEW_MAX_CHARS = 240;
  const ALLOWED_IMAGE_MIMES = ["image/png", "image/jpeg", "image/webp", "image/gif"];
  const KEYCHAIN_KEY = "mynote.clip.credentials.v1";

  const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const B32D = new Int8Array(128).fill(-1);
  for (let i = 0; i < 32; i++) B32D[B32.charCodeAt(i)] = i;

  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const B64D = new Int8Array(128).fill(-1);
  for (let i = 0; i < 64; i++) B64D[B64.charCodeAt(i)] = i;
  B64D[45] = 62; // '-' (base64url)
  B64D[95] = 63; // '_' (base64url)

  const P26 = 67108864;
  const INV13 = 1 / 8192;
  const INV26 = 1 / 67108864;
  const IS_LE = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1;

  const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const w32 = (b, o, v) => {
    b[o] = v & 255;
    b[o + 1] = (v >>> 8) & 255;
    b[o + 2] = (v >>> 16) & 255;
    b[o + 3] = (v >>> 24) & 255;
  };
  const fail = (m) => {
    throw new Error("INTEGRITY_ERROR: " + m);
  };
  const argErr = (m) => {
    throw new Error("INVALID_ARGUMENT: " + m);
  };

  // ---------- Strict UTF-8 Encode / Decode ----------

  function utf8Encode(s) {
    if (typeof s !== "string") throw new TypeError("expected string");
    const n = s.length;
    const o = new Uint8Array(n * 3);
    let p = 0;
    for (let i = 0; i < n; i++) {
      let c = s.charCodeAt(i);
      if (c < 0x80) {
        o[p++] = c;
      } else if (c < 0x800) {
        o[p++] = 0xc0 | (c >> 6);
        o[p++] = 0x80 | (c & 63);
      } else if (c >= 0xd800 && c <= 0xdbff) {
        if (i + 1 >= n) fail("lone high surrogate");
        const l = s.charCodeAt(++i);
        if (l < 0xdc00 || l > 0xdfff) fail("bad surrogate");
        c = 0x10000 + (((c - 0xd800) << 10) | (l - 0xdc00));
        o[p++] = 0xf0 | (c >> 18);
        o[p++] = 0x80 | ((c >> 12) & 63);
        o[p++] = 0x80 | ((c >> 6) & 63);
        o[p++] = 0x80 | (c & 63);
      } else if (c >= 0xdc00 && c <= 0xdfff) {
        fail("lone low surrogate");
      } else {
        o[p++] = 0xe0 | (c >> 12);
        o[p++] = 0x80 | ((c >> 6) & 63);
        o[p++] = 0x80 | (c & 63);
      }
    }
    return o.subarray(0, p);
  }

  function utf8Decode(b) {
    let o = "";
    let i = 0;
    const n = b.length;
    while (i < n) {
      const a = b[i++];
      if (a < 0x80) {
        o += String.fromCharCode(a);
      } else if (a >= 0xc2 && a <= 0xdf) {
        if (i >= n || (b[i] & 0xc0) !== 0x80) fail("bad utf8");
        o += String.fromCharCode(((a & 31) << 6) | (b[i++] & 63));
      } else if (a >= 0xe0 && a <= 0xef) {
        if (i + 1 >= n || (b[i] & 0xc0) !== 0x80 || (b[i + 1] & 0xc0) !== 0x80) fail("bad utf8");
        const c = ((a & 15) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63);
        if (c < 0x800 || (c >= 0xd800 && c <= 0xdfff)) fail("bad utf8");
        o += String.fromCharCode(c);
      } else if (a >= 0xf0 && a <= 0xf4) {
        if (
          i + 2 >= n ||
          (b[i] & 0xc0) !== 0x80 ||
          (b[i + 1] & 0xc0) !== 0x80 ||
          (b[i + 2] & 0xc0) !== 0x80
        ) {
          fail("bad utf8");
        }
        const c = ((a & 7) << 18) | ((b[i++] & 63) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63);
        if (c < 0x10000 || c > 0x10ffff) fail("bad utf8");
        const u = c - 0x10000;
        o += String.fromCharCode(0xd800 | (u >> 10), 0xdc00 | (u & 0x3ff));
      } else {
        fail("bad utf8");
      }
    }
    return o;
  }

  // ---------- Pure JS Base64 / Base64URL ----------

  function bytesToBase64(bytes) {
    const n = bytes.length;
    let out = "";
    let i = 0;
    for (; i + 2 < n; i += 3) {
      const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64[(v >>> 18) & 63] + B64[(v >>> 12) & 63] + B64[(v >>> 6) & 63] + B64[v & 63];
    }
    if (i < n) {
      const v0 = bytes[i];
      const v1 = i + 1 < n ? bytes[i + 1] : 0;
      const v = (v0 << 16) | (v1 << 8);
      out += B64[(v >>> 18) & 63] + B64[(v >>> 12) & 63];
      out += i + 1 < n ? B64[(v >>> 6) & 63] + "=" : "==";
    }
    return out;
  }

  function base64ToBytes(str) {
    const clean = String(str).replace(/[\s=]+$/g, "").replace(/\s+/g, "");
    const n = clean.length;
    if ((n & 3) === 1) fail("invalid base64 length");
    const outLen = (n * 3) >>> 2;
    const out = new Uint8Array(outLen);
    let p = 0;
    for (let i = 0; i < n; i += 4) {
      const c0 = clean.charCodeAt(i);
      const c1 = clean.charCodeAt(i + 1);
      const v0 = c0 < 128 ? B64D[c0] : -1;
      const v1 = c1 < 128 ? B64D[c1] : -1;
      if (v0 < 0 || v1 < 0) fail("invalid base64 char");
      const has2 = i + 2 < n;
      const has3 = i + 3 < n;
      const c2 = has2 ? clean.charCodeAt(i + 2) : 65;
      const c3 = has3 ? clean.charCodeAt(i + 3) : 65;
      const v2 = c2 < 128 ? B64D[c2] : -1;
      const v3 = c3 < 128 ? B64D[c3] : -1;
      if (v2 < 0 || v3 < 0) fail("invalid base64 char");
      out[p++] = (v0 << 2) | (v1 >>> 4);
      if (has2 && p < outLen) out[p++] = ((v1 & 15) << 4) | (v2 >>> 2);
      if (has3 && p < outLen) out[p++] = ((v2 & 3) << 6) | v3;
    }
    return out;
  }

  // ---------- Pure Synchronous SHA-256 (FIPS 180-4) ----------

  const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function sha256Bytes(data) {
    const bytes = data instanceof Uint8Array ? data : utf8Encode(String(data));
    const len = bytes.length;
    const bitLenHi = Math.floor(len / 0x20000000);
    const bitLenLo = (len << 3) >>> 0;
    const total = ((len + 9 + 63) & ~63);
    const buf = new Uint8Array(total);
    buf.set(bytes, 0);
    buf[len] = 0x80;
    buf[total - 8] = (bitLenHi >>> 24) & 255;
    buf[total - 7] = (bitLenHi >>> 16) & 255;
    buf[total - 6] = (bitLenHi >>> 8) & 255;
    buf[total - 5] = bitLenHi & 255;
    buf[total - 4] = (bitLenLo >>> 24) & 255;
    buf[total - 3] = (bitLenLo >>> 16) & 255;
    buf[total - 2] = (bitLenLo >>> 8) & 255;
    buf[total - 1] = bitLenLo & 255;

    let h0 = 0x6a09e667 | 0;
    let h1 = 0xbb67ae85 | 0;
    let h2 = 0x3c6ef372 | 0;
    let h3 = 0xa54ff53a | 0;
    let h4 = 0x510e527f | 0;
    let h5 = 0x9b05688c | 0;
    let h6 = 0x1f83d9ab | 0;
    let h7 = 0x5be0cd19 | 0;
    const w = new Int32Array(64);

    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) {
        const j = off + i * 4;
        w[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
      }
      for (let i = 16; i < 64; i++) {
        const v15 = w[i - 15];
        const s0 = ((v15 >>> 7) | (v15 << 25)) ^ ((v15 >>> 18) | (v15 << 14)) ^ (v15 >>> 3);
        const v2 = w[i - 2];
        const s1 = ((v2 >>> 17) | (v2 << 15)) ^ ((v2 >>> 19) | (v2 << 13)) ^ (v2 >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let a = h0;
      let b = h1;
      let c = h2;
      let d = h3;
      let e = h4;
      let f = h5;
      let g = h6;
      let h = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h = g;
        g = f;
        f = e;
        e = (d + t1) | 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0;
      h1 = (h1 + b) | 0;
      h2 = (h2 + c) | 0;
      h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0;
      h5 = (h5 + f) | 0;
      h6 = (h6 + g) | 0;
      h7 = (h7 + h) | 0;
    }

    const out = new Uint8Array(32);
    const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
    for (let i = 0; i < 8; i++) {
      const v = hs[i] >>> 0;
      out[i * 4] = (v >>> 24) & 255;
      out[i * 4 + 1] = (v >>> 16) & 255;
      out[i * 4 + 2] = (v >>> 8) & 255;
      out[i * 4 + 3] = v & 255;
    }
    return out;
  }

  function sha256Hex(data) {
    const d = sha256Bytes(data);
    let hex = "";
    for (let i = 0; i < 32; i++) {
      const b = d[i];
      hex += (b < 16 ? "0" : "") + b.toString(16);
    }
    return hex;
  }

  // ---------- CSPRNG & ULID ----------

  let rngCounter = 0;
  function randomBytes(len) {
    if (root.crypto && typeof root.crypto.getRandomValues === "function") {
      return root.crypto.getRandomValues(new Uint8Array(len));
    }
    if (typeof UUID !== "undefined" && typeof UUID.string === "function") {
      // iOS Scriptable native Foundation NSUUID (122 bits of SecRandomCopyBytes per call), hashed via SHA-256.
      const out = new Uint8Array(len);
      let pos = 0;
      while (pos < len) {
        const seed = UUID.string() + ":" + UUID.string() + ":" + Date.now() + ":" + (++rngCounter);
        const block = sha256Bytes(seed);
        const take = Math.min(32, len - pos);
        out.set(block.subarray(0, take), pos);
        pos += take;
      }
      return out;
    }
    throw new Error("CSPRNG unavailable: WebCrypto or iOS UUID required");
  }

  function ulidToBytes(s) {
    if (typeof s !== "string" || s.length !== 26) fail("bad ulid len");
    const c0 = s.charCodeAt(0);
    const v0 = c0 < 128 ? B32D[c0] : -1;
    if (v0 < 0 || v0 > 7) fail("bad ulid");
    const o = new Uint8Array(16);
    let acc = v0;
    let bits = 3;
    let p = 0;
    for (let i = 1; i < 26; i++) {
      const c = s.charCodeAt(i);
      const v = c < 128 ? B32D[c] : -1;
      if (v < 0) fail("bad ulid");
      acc = (acc << 5) | v;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        o[p++] = (acc >>> bits) & 255;
      }
    }
    return o;
  }

  function bytesToUlid(b) {
    if (!(b instanceof Uint8Array) || b.length !== 16) fail("bad ulid bytes");
    let o = "";
    let acc = 0;
    let bits = 2;
    for (let i = 0; i < 16; i++) {
      acc = (acc << 8) | b[i];
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        o += B32[(acc >>> bits) & 31];
      }
    }
    return o;
  }

  function generateUlid(nowMs, rand10) {
    const ts = Math.max(0, Math.floor(nowMs !== undefined ? nowMs : Date.now()));
    const r = rand10 !== undefined ? rand10 : randomBytes(10);
    if (!(r instanceof Uint8Array) || r.length !== 10) fail("bad ulid rand");
    const b = new Uint8Array(16);
    let t = ts;
    for (let i = 5; i >= 0; i--) {
      b[i] = t & 255;
      t = Math.floor(t / 256);
    }
    b.set(r, 6);
    return bytesToUlid(b);
  }

  // ---------- Bijective 256-Byte Bucket Padding ----------

  function pad256(raw) {
    const n = raw.length;
    const z = (256 - ((n + 1) & 255)) & 255;
    const o = new Uint8Array(n + z + 1);
    o.set(raw, 0);
    o[n + z] = z;
    return o;
  }

  function unpad256(b) {
    const n = b.length;
    if (n < 256 || (n & 255) !== 0) fail("bad pad len");
    const p = b[n - 1];
    const end = n - 1 - p;
    for (let i = end; i < n - 1; i++) if (b[i] !== 0) fail("non-zero pad");
    return b.subarray(0, end);
  }

  // ---------- LLInt-Fast Inlined XChaCha20-Poly1305 (Zero BigInt) ----------

  function chachaCore(mode, key, w12, w13, w14, w15, src, sOff, len, dst, dOff) {
    const k0 = u32(key, 0) | 0;
    const k1 = u32(key, 4) | 0;
    const k2 = u32(key, 8) | 0;
    const k3 = u32(key, 12) | 0;
    const k4 = u32(key, 16) | 0;
    const k5 = u32(key, 20) | 0;
    const k6 = u32(key, 24) | 0;
    const k7 = u32(key, 28) | 0;
    const ks = mode === 2 ? new Uint8Array(64) : null;
    const ks32 = ks && IS_LE ? new Int32Array(ks.buffer) : null;
    let ctr = w12 | 0;
    let pos = 0;

    do {
      let x0 = 0x61707865;
      let x1 = 0x3320646e;
      let x2 = 0x79622d32;
      let x3 = 0x6b206574;
      let x4 = k0;
      let x5 = k1;
      let x6 = k2;
      let x7 = k3;
      let x8 = k4;
      let x9 = k5;
      let x10 = k6;
      let x11 = k7;
      let x12 = ctr;
      let x13 = w13 | 0;
      let x14 = w14 | 0;
      let x15 = w15 | 0;
      for (let r = 0; r < 10; r++) {
        x0 = (x0 + x4) | 0; x12 ^= x0; x12 = (x12 << 16) | (x12 >>> 16);
        x8 = (x8 + x12) | 0; x4 ^= x8; x4 = (x4 << 12) | (x4 >>> 20);
        x0 = (x0 + x4) | 0; x12 ^= x0; x12 = (x12 << 8) | (x12 >>> 24);
        x8 = (x8 + x12) | 0; x4 ^= x8; x4 = (x4 << 7) | (x4 >>> 25);
        x1 = (x1 + x5) | 0; x13 ^= x1; x13 = (x13 << 16) | (x13 >>> 16);
        x9 = (x9 + x13) | 0; x5 ^= x9; x5 = (x5 << 12) | (x5 >>> 20);
        x1 = (x1 + x5) | 0; x13 ^= x1; x13 = (x13 << 8) | (x13 >>> 24);
        x9 = (x9 + x13) | 0; x5 ^= x9; x5 = (x5 << 7) | (x5 >>> 25);
        x2 = (x2 + x6) | 0; x14 ^= x2; x14 = (x14 << 16) | (x14 >>> 16);
        x10 = (x10 + x14) | 0; x6 ^= x10; x6 = (x6 << 12) | (x6 >>> 20);
        x2 = (x2 + x6) | 0; x14 ^= x2; x14 = (x14 << 8) | (x14 >>> 24);
        x10 = (x10 + x14) | 0; x6 ^= x10; x6 = (x6 << 7) | (x6 >>> 25);
        x3 = (x3 + x7) | 0; x15 ^= x3; x15 = (x15 << 16) | (x15 >>> 16);
        x11 = (x11 + x15) | 0; x7 ^= x11; x7 = (x7 << 12) | (x7 >>> 20);
        x3 = (x3 + x7) | 0; x15 ^= x3; x15 = (x15 << 8) | (x15 >>> 24);
        x11 = (x11 + x15) | 0; x7 ^= x11; x7 = (x7 << 7) | (x7 >>> 25);
        x0 = (x0 + x5) | 0; x15 ^= x0; x15 = (x15 << 16) | (x15 >>> 16);
        x10 = (x10 + x15) | 0; x5 ^= x10; x5 = (x5 << 12) | (x5 >>> 20);
        x0 = (x0 + x5) | 0; x15 ^= x0; x15 = (x15 << 8) | (x15 >>> 24);
        x10 = (x10 + x15) | 0; x5 ^= x10; x5 = (x5 << 7) | (x5 >>> 25);
        x1 = (x1 + x6) | 0; x12 ^= x1; x12 = (x12 << 16) | (x12 >>> 16);
        x11 = (x11 + x12) | 0; x6 ^= x11; x6 = (x6 << 12) | (x6 >>> 20);
        x1 = (x1 + x6) | 0; x12 ^= x1; x12 = (x12 << 8) | (x12 >>> 24);
        x11 = (x11 + x12) | 0; x6 ^= x11; x6 = (x6 << 7) | (x6 >>> 25);
        x2 = (x2 + x7) | 0; x13 ^= x2; x13 = (x13 << 16) | (x13 >>> 16);
        x8 = (x8 + x13) | 0; x7 ^= x8; x7 = (x7 << 12) | (x7 >>> 20);
        x2 = (x2 + x7) | 0; x13 ^= x2; x13 = (x13 << 8) | (x13 >>> 24);
        x8 = (x8 + x13) | 0; x7 ^= x8; x7 = (x7 << 7) | (x7 >>> 25);
        x3 = (x3 + x4) | 0; x14 ^= x3; x14 = (x14 << 16) | (x14 >>> 16);
        x9 = (x9 + x14) | 0; x4 ^= x9; x4 = (x4 << 12) | (x4 >>> 20);
        x3 = (x3 + x4) | 0; x14 ^= x3; x14 = (x14 << 8) | (x14 >>> 24);
        x9 = (x9 + x14) | 0; x4 ^= x9; x4 = (x4 << 7) | (x4 >>> 25);
      }
      if (mode === 0) {
        w32(dst, 0, x0); w32(dst, 4, x1); w32(dst, 8, x2); w32(dst, 12, x3);
        w32(dst, 16, x12); w32(dst, 20, x13); w32(dst, 24, x14); w32(dst, 28, x15);
        return;
      }
      x0 = (x0 + 0x61707865) | 0; x1 = (x1 + 0x3320646e) | 0;
      x2 = (x2 + 0x79622d32) | 0; x3 = (x3 + 0x6b206574) | 0;
      x4 = (x4 + k0) | 0; x5 = (x5 + k1) | 0; x6 = (x6 + k2) | 0; x7 = (x7 + k3) | 0;
      if (mode === 1) {
        w32(dst, 0, x0); w32(dst, 4, x1); w32(dst, 8, x2); w32(dst, 12, x3);
        w32(dst, 16, x4); w32(dst, 20, x5); w32(dst, 24, x6); w32(dst, 28, x7);
        return;
      }
      x8 = (x8 + k4) | 0; x9 = (x9 + k5) | 0; x10 = (x10 + k6) | 0; x11 = (x11 + k7) | 0;
      x12 = (x12 + ctr) | 0; x13 = (x13 + w13) | 0; x14 = (x14 + w14) | 0; x15 = (x15 + w15) | 0;
      ctr = (ctr + 1) | 0;

      if (ks32) {
        ks32[0] = x0; ks32[1] = x1; ks32[2] = x2; ks32[3] = x3;
        ks32[4] = x4; ks32[5] = x5; ks32[6] = x6; ks32[7] = x7;
        ks32[8] = x8; ks32[9] = x9; ks32[10] = x10; ks32[11] = x11;
        ks32[12] = x12; ks32[13] = x13; ks32[14] = x14; ks32[15] = x15;
      } else {
        w32(ks, 0, x0); w32(ks, 4, x1); w32(ks, 8, x2); w32(ks, 12, x3);
        w32(ks, 16, x4); w32(ks, 20, x5); w32(ks, 24, x6); w32(ks, 28, x7);
        w32(ks, 32, x8); w32(ks, 36, x9); w32(ks, 40, x10); w32(ks, 44, x11);
        w32(ks, 48, x12); w32(ks, 52, x13); w32(ks, 56, x14); w32(ks, 60, x15);
      }
      const n = len - pos < 64 ? len - pos : 64;
      const si = sOff + pos;
      const di = dOff + pos;
      for (let i = 0; i < n; i++) dst[di + i] = src[si + i] ^ ks[i];
      pos += n;
    } while (pos < len);
  }

  function hchacha20(key, n16) {
    const o = new Uint8Array(32);
    chachaCore(0, key, u32(n16, 0), u32(n16, 4), u32(n16, 8), u32(n16, 12), null, 0, 0, o, 0);
    return o;
  }

  function poly1305Compute(otk, segs, tagOut, tagOff) {
    const t0 = u32(otk, 0) & 0x0fffffff;
    const t1 = u32(otk, 4) & 0x0ffffffc;
    const t2 = u32(otk, 8) & 0x0ffffffc;
    const t3 = u32(otk, 12) & 0x0ffffffc;
    const r0 = t0 & 0x3ffffff;
    const r1 = ((t0 >>> 26) | (t1 << 6)) & 0x3ffffff;
    const r2 = ((t1 >>> 20) | (t2 << 12)) & 0x3ffffff;
    const r3 = ((t2 >>> 14) | (t3 << 18)) & 0x3ffffff;
    const r4 = t3 >>> 8;
    const s1 = r1 * 5;
    const s2 = r2 * 5;
    const s3 = r3 * 5;
    const s4 = r4 * 5;
    let h0 = 0;
    let h1 = 0;
    let h2 = 0;
    let h3 = 0;
    let h4 = 0;
    const tail = new Uint8Array(16);

    for (let si = 0; si < segs.length; si++) {
      const seg = segs[si];
      const buf = seg[0];
      const off = seg[1];
      const len = seg[2];
      const full = len & ~15;
      let pos = 0;
      for (;;) {
        let b;
        let o;
        if (pos < full) {
          b = buf;
          o = off + pos;
          pos += 16;
        } else if (pos < len) {
          const rem = len - pos;
          tail.fill(0);
          for (let i = 0; i < rem; i++) tail[i] = buf[off + pos + i];
          b = tail;
          o = 0;
          pos = len;
        } else {
          break;
        }
        const m0 = (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
        const m1 = (b[o + 4] | (b[o + 5] << 8) | (b[o + 6] << 16) | (b[o + 7] << 24)) >>> 0;
        const m2 = (b[o + 8] | (b[o + 9] << 8) | (b[o + 10] << 16) | (b[o + 11] << 24)) >>> 0;
        const m3 = (b[o + 12] | (b[o + 13] << 8) | (b[o + 14] << 16) | (b[o + 15] << 24)) >>> 0;

        h0 += m0 & 0x3ffffff;
        h1 += ((m0 >>> 26) | (m1 << 6)) & 0x3ffffff;
        h2 += ((m1 >>> 20) | (m2 << 12)) & 0x3ffffff;
        h3 += ((m2 >>> 14) | (m3 << 18)) & 0x3ffffff;
        h4 += (m3 >>> 8) | 0x1000000;

        const l0 = h0 & 0x1fff, u0 = h0 >>> 13;
        const l1 = h1 & 0x1fff, u1 = h1 >>> 13;
        const l2 = h2 & 0x1fff, u2 = h2 >>> 13;
        const l3 = h3 & 0x1fff, u3 = h3 >>> 13;
        const l4 = h4 & 0x1fff, u4 = h4 >>> 13;

        let d0 = l0 * r0 + l1 * s4 + l2 * s3 + l3 * s2 + l4 * s1;
        let d1 = l0 * r1 + l1 * r0 + l2 * s4 + l3 * s3 + l4 * s2;
        let d2 = l0 * r2 + l1 * r1 + l2 * r0 + l3 * s4 + l4 * s3;
        let d3 = l0 * r3 + l1 * r2 + l2 * r1 + l3 * r0 + l4 * s4;
        let d4 = l0 * r4 + l1 * r3 + l2 * r2 + l3 * r1 + l4 * r0;

        const e0 = u0 * r0 + u1 * s4 + u2 * s3 + u3 * s2 + u4 * s1;
        const e1 = u0 * r1 + u1 * r0 + u2 * s4 + u3 * s3 + u4 * s2;
        const e2 = u0 * r2 + u1 * r1 + u2 * r0 + u3 * s4 + u4 * s3;
        const e3 = u0 * r3 + u1 * r2 + u2 * r1 + u3 * r0 + u4 * s4;
        const e4 = u0 * r4 + u1 * r3 + u2 * r2 + u3 * r1 + u4 * r0;

        let q = Math.floor(e0 * INV13); d0 += (e0 - q * 8192) * 8192; d1 += q;
        q = Math.floor(e1 * INV13); d1 += (e1 - q * 8192) * 8192; d2 += q;
        q = Math.floor(e2 * INV13); d2 += (e2 - q * 8192) * 8192; d3 += q;
        q = Math.floor(e3 * INV13); d3 += (e3 - q * 8192) * 8192; d4 += q;
        q = Math.floor(e4 * INV13); d4 += (e4 - q * 8192) * 8192; d0 += q * 5;

        let c = Math.floor(d0 * INV26); h0 = d0 - c * P26; d1 += c;
        c = Math.floor(d1 * INV26); h1 = d1 - c * P26; d2 += c;
        c = Math.floor(d2 * INV26); h2 = d2 - c * P26; d3 += c;
        c = Math.floor(d3 * INV26); h3 = d3 - c * P26; d4 += c;
        c = Math.floor(d4 * INV26); h4 = d4 - c * P26; h0 += c * 5;
        c = h0 >>> 26; h0 &= 0x3ffffff; h1 += c;
      }
    }

    let c = h1 >>> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >>> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >>> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >>> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >>> 26; h0 &= 0x3ffffff; h1 += c;

    let g0 = h0 + 5; c = g0 >>> 26; g0 &= 0x3ffffff;
    let g1 = h1 + c; c = g1 >>> 26; g1 &= 0x3ffffff;
    let g2 = h2 + c; c = g2 >>> 26; g2 &= 0x3ffffff;
    let g3 = h3 + c; c = g3 >>> 26; g3 &= 0x3ffffff;
    const g4 = h4 + c - P26;
    const m = g4 >> 31;
    const nm = ~m;
    h0 = (h0 & m) | (g0 & nm);
    h1 = (h1 & m) | (g1 & nm);
    h2 = (h2 & m) | (g2 & nm);
    h3 = (h3 & m) | (g3 & nm);
    h4 = (h4 & m) | (g4 & nm);

    const f0 = ((h0 | (h1 << 26)) >>> 0) + u32(otk, 16);
    const f1 = (((h1 >>> 6) | (h2 << 20)) >>> 0) + u32(otk, 20) + (f0 > 0xffffffff ? 1 : 0);
    const f2 = (((h2 >>> 12) | (h3 << 14)) >>> 0) + u32(otk, 24) + (f1 > 0xffffffff ? 1 : 0);
    const f3 = (((h3 >>> 18) | (h4 << 8)) >>> 0) + u32(otk, 28) + (f2 > 0xffffffff ? 1 : 0);
    w32(tagOut, tagOff, f0 >>> 0);
    w32(tagOut, tagOff + 4, f1 >>> 0);
    w32(tagOut, tagOff + 8, f2 >>> 0);
    w32(tagOut, tagOff + 12, f3 >>> 0);
  }

  function poly1305Aead(otk, aad, ct, ctOff, ctLen, out, o) {
    const lens = new Uint8Array(16);
    w32(lens, 0, aad.length >>> 0);
    w32(lens, 4, Math.floor(aad.length / 0x100000000) >>> 0);
    w32(lens, 8, ctLen >>> 0);
    w32(lens, 12, Math.floor(ctLen / 0x100000000) >>> 0);
    poly1305Compute(otk, [[aad, 0, aad.length], [ct, ctOff, ctLen], [lens, 0, 16]], out, o);
  }

  function prepSubkey(key, n24) {
    if (!(key instanceof Uint8Array) || key.length !== 32) fail("bad key");
    if (!(n24 instanceof Uint8Array) || n24.length !== 24) fail("bad nonce");
    const sub = hchacha20(key, n24);
    const otk = new Uint8Array(32);
    const n1 = u32(n24, 16);
    const n2 = u32(n24, 20);
    chachaCore(1, sub, 0, 0, n1, n2, null, 0, 0, otk, 0);
    return { sub, otk, n1, n2 };
  }

  function xchacha20Poly1305EncryptInto(key, n24, aad, pt, out, outOff) {
    const { sub, otk, n1, n2 } = prepSubkey(key, n24);
    if (pt.length > 0) chachaCore(2, sub, 1, 0, n1, n2, pt, 0, pt.length, out, outOff);
    poly1305Aead(otk, aad, out, outOff, pt.length, out, outOff + pt.length);
    sub.fill(0);
    otk.fill(0);
  }

  function xchacha20Poly1305Decrypt(key, n24, aad, ctTag, off, len) {
    if (len < TAG) fail("truncated ct");
    const ctLen = len - TAG;
    const { sub, otk, n1, n2 } = prepSubkey(key, n24);
    const exp = new Uint8Array(16);
    poly1305Aead(otk, aad, ctTag, off, ctLen, exp, 0);
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= exp[i] ^ ctTag[off + ctLen + i];
    if (diff !== 0) {
      sub.fill(0);
      otk.fill(0);
      fail("tag/aad mismatch");
    }
    const pt = new Uint8Array(ctLen);
    if (ctLen > 0) chachaCore(2, sub, 1, 0, n1, n2, ctTag, off, ctLen, pt, 0);
    sub.fill(0);
    otk.fill(0);
    return pt;
  }

  // ---------- MNC1 Codec (`docs/data-structures.md` §3.3 & §3.8) ----------

  function buildMnc1Aad(kidB, idB, deviceId, flags) {
    if ((flags & ~0xff) !== 0 || (flags & F_RES) !== 0) fail("reserved flags");
    const dev = utf8Encode(deviceId);
    const aad = new Uint8Array(38 + dev.length);
    aad[0] = 0x4d;
    aad[1] = 0x4e;
    aad[2] = 0x43;
    aad[3] = 0x31;
    aad[4] = VER;
    aad.set(kidB, 5);
    aad.set(idB, 21);
    aad.set(dev, 37);
    aad[37 + dev.length] = flags;
    return aad;
  }

  const asUlid = (id) => (id instanceof Uint8Array ? (id.length === 16 ? id : fail("bad ulid bytes")) : ulidToBytes(id));

  function getNonce(n) {
    if (n != null) {
      if (!(n instanceof Uint8Array) || n.length !== 24) fail("bad nonce");
      return n;
    }
    return randomBytes(24);
  }

  function encryptMnc1Raw({ clipKey, clipKid, clipId, deviceId, flags, plaintext, nonce }) {
    const kidB = asUlid(clipKid);
    const idB = asUlid(clipId);
    const n24 = getNonce(nonce);
    const aad = buildMnc1Aad(kidB, idB, deviceId, flags);
    const out = new Uint8Array(HDR + plaintext.length + TAG);
    out[0] = 0x4d;
    out[1] = 0x4e;
    out[2] = 0x43;
    out[3] = 0x31;
    out[4] = VER;
    out.set(kidB, 5);
    out.set(n24, 21);
    xchacha20Poly1305EncryptInto(clipKey, n24, aad, plaintext, out, HDR);
    return out;
  }

  function decryptMnc1Raw({ clipKey, clipKid, clipId, deviceId, flags, envelope }) {
    if (!(envelope instanceof Uint8Array) || envelope.length < HDR + TAG) fail("truncated");
    if (envelope[0] !== 0x4d || envelope[1] !== 0x4e || envelope[2] !== 0x43 || envelope[3] !== 0x31) fail("bad magic");
    if (envelope[4] !== VER) fail("bad ver");
    const kidB = asUlid(clipKid);
    for (let i = 0; i < 16; i++) if (envelope[5 + i] !== kidB[i]) fail("kid mismatch");
    const aad = buildMnc1Aad(kidB, asUlid(clipId), deviceId, flags);
    return xchacha20Poly1305Decrypt(clipKey, envelope.subarray(21, 45), aad, envelope, HDR, envelope.length - HDR);
  }

  function normalizeMime(mime) {
    return String(mime || "").split(";")[0].trim().toLowerCase();
  }

  function validateImageMime(mime) {
    const norm = normalizeMime(mime);
    if (norm === "image/svg+xml" || norm.indexOf("svg") !== -1) {
      argErr("disallowed image/svg+xml mime; sync SVG as plain text instead");
    }
    if (ALLOWED_IMAGE_MIMES.indexOf(norm) === -1) {
      argErr("unsupported clip image mime: " + (norm || "unknown"));
    }
    return norm;
  }

  function truncateChars(str, maxChars) {
    const chars = Array.from(str);
    return chars.length <= maxChars ? str : chars.slice(0, maxChars).join("");
  }

  function buildClipMeta({
    kind,
    mime,
    text = null,
    rawBytes = null,
    ephemeral = false,
    width = null,
    height = null,
    thumbMime = null,
    thumbB64 = null,
    sourceMode = "explicit",
    createdAtMs = Date.now(),
  }) {
    if (kind === "image") {
      if (ephemeral) argErr("ephemeral mode supports text only");
      const normMime = validateImageMime(mime);
      if (!(rawBytes instanceof Uint8Array) || rawBytes.length === 0) argErr("image rawBytes required");
      if (rawBytes.length > BLOB_MAX_BYTES) argErr("image exceeds 10 MiB limit");
      if (thumbMime != null) validateImageMime(thumbMime);
      return {
        v: 1,
        kind: "image",
        mime: normMime,
        source_mode: sourceMode,
        created_at_ms: Math.floor(createdAtMs),
        text: null,
        blob: {
          byte_size: rawBytes.length,
          sha256_hex: sha256Hex(rawBytes),
          width: width != null ? Math.floor(width) : null,
          height: height != null ? Math.floor(height) : null,
          thumb_mime: thumbMime != null ? normalizeMime(thumbMime) : null,
          thumb_b64: thumbB64 != null ? String(thumbB64) : null,
        },
      };
    }

    if (kind !== "text") argErr("unsupported clip kind: " + String(kind));
    if (typeof text !== "string" || text.length === 0) argErr("text clip requires non-empty text");
    const utf8 = rawBytes instanceof Uint8Array ? rawBytes : utf8Encode(text);
    if (ephemeral) {
      if (utf8.length > EPHEMERAL_MAX_BYTES) argErr("ephemeral text exceeds 256 KiB limit");
      return {
        v: 1,
        kind: "text",
        mime: "text/plain",
        source_mode: sourceMode,
        created_at_ms: Math.floor(createdAtMs),
        text,
        blob: null,
      };
    }
    if (utf8.length <= INLINE_TEXT_MAX_BYTES) {
      return {
        v: 1,
        kind: "text",
        mime: "text/plain",
        source_mode: sourceMode,
        created_at_ms: Math.floor(createdAtMs),
        text,
        blob: null,
      };
    }
    if (utf8.length > BLOB_MAX_BYTES) argErr("text exceeds 10 MiB limit");
    return {
      v: 1,
      kind: "text",
      mime: "text/plain",
      source_mode: sourceMode,
      created_at_ms: Math.floor(createdAtMs),
      text: truncateChars(text, PREVIEW_MAX_CHARS),
      blob: {
        byte_size: utf8.length,
        sha256_hex: sha256Hex(utf8),
        width: null,
        height: null,
        thumb_mime: null,
        thumb_b64: null,
      },
    };
  }

  function encryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, meta, ephemeral = false, nonce }) {
    const obj = typeof meta === "string" ? JSON.parse(meta) : meta;
    if (obj && obj.kind === "image") validateImageMime(obj.mime);
    const json = typeof meta === "string" ? meta : JSON.stringify(meta);
    return encryptMnc1Raw({
      clipKey,
      clipKid,
      clipId,
      deviceId,
      flags: ephemeral ? F_EPH : 0,
      plaintext: pad256(utf8Encode(json)),
      nonce,
    });
  }

  function decryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, envelope, ephemeral = false }) {
    const raw = decryptMnc1Raw({
      clipKey,
      clipKid,
      clipId,
      deviceId,
      flags: ephemeral ? F_EPH : 0,
      envelope,
    });
    const parsed = JSON.parse(utf8Decode(unpad256(raw)));
    if (parsed && parsed.kind === "image") validateImageMime(parsed.mime);
    return parsed;
  }

  function encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes, nonce }) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("expected Uint8Array");
    if (bytes.length > BLOB_MAX_BYTES) argErr("blob exceeds 10 MiB limit");
    return encryptMnc1Raw({
      clipKey,
      clipKid,
      clipId,
      deviceId,
      flags: F_BLOB,
      plaintext: bytes,
      nonce,
    });
  }

  function decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope }) {
    return decryptMnc1Raw({
      clipKey,
      clipKid,
      clipId,
      deviceId,
      flags: F_BLOB,
      envelope,
    });
  }

  function prepareClipUpload({
    clipKey,
    clipKid,
    clipId = generateUlid(),
    deviceId,
    kind,
    mime = "text/plain",
    text = null,
    rawBytes = null,
    ephemeral = false,
    width = null,
    height = null,
    thumbMime = null,
    thumbB64 = null,
    createdAtMs = Date.now(),
    nonceMeta,
    nonceBlob,
  }) {
    const payloadBytes =
      kind === "image"
        ? rawBytes
        : rawBytes instanceof Uint8Array
          ? rawBytes
          : utf8Encode(String(text || ""));
    const meta = buildClipMeta({
      kind,
      mime,
      text,
      rawBytes: payloadBytes,
      ephemeral,
      width,
      height,
      thumbMime,
      thumbB64,
      createdAtMs,
    });
    const metaEnvelope = encryptMnc1Meta({
      clipKey,
      clipKid,
      clipId,
      deviceId,
      meta,
      ephemeral,
      nonce: nonceMeta,
    });
    const metaB64 = bytesToBase64(metaEnvelope);

    if (meta.blob === null) {
      return {
        mode: "inline",
        method: "POST",
        path: "/v1/clip",
        clipId,
        meta,
        jsonBody: {
          clip_id: clipId,
          clip_kid: clipKid,
          kind: "text",
          ephemeral: Boolean(ephemeral),
          meta_envelope_b64: metaB64,
        },
      };
    }

    const blobEnvelope = encryptMnc1Blob({
      clipKey,
      clipKid,
      clipId,
      deviceId,
      bytes: payloadBytes,
      nonce: nonceBlob,
    });
    return {
      mode: "blob",
      method: "PUT",
      path: "/v1/clip/blob",
      clipId,
      meta,
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Clip-Id": clipId,
        "X-Clip-Kid": clipKid,
        "X-Clip-Kind": kind,
        "X-Clip-Meta-B64": metaB64,
      },
      bodyBytes: blobEnvelope,
    };
  }

  // ---------- Minimal MessagePack Decoder + Pairing Ticket Claim (`mynote-pair:v1:...`) ----------

  function decodeMsgpack(buf) {
    let pos = 0;
    const read = () => {
      if (pos >= buf.length) fail("msgpack eof");
      const b = buf[pos++];
      if (b <= 0x7f) return b;
      if (b >= 0xe0) return b - 256;
      if ((b & 0xf0) === 0x80) return readMap(b & 0x0f);
      if ((b & 0xf0) === 0x90) return readArr(b & 0x0f);
      if ((b & 0xe0) === 0xa0) return readStr(b & 0x1f);
      switch (b) {
        case 0xc0: return null;
        case 0xc2: return false;
        case 0xc3: return true;
        case 0xc4: return readBin(buf[pos++]);
        case 0xc5: return readBin((buf[pos++] << 8) | buf[pos++]);
        case 0xc6: return readBin(((buf[pos++] << 24) | (buf[pos++] << 16) | (buf[pos++] << 8) | buf[pos++]) >>> 0);
        case 0xcc: return buf[pos++];
        case 0xcd: return (buf[pos++] << 8) | buf[pos++];
        case 0xce: return ((buf[pos++] << 24) | (buf[pos++] << 16) | (buf[pos++] << 8) | buf[pos++]) >>> 0;
        case 0xd9: return readStr(buf[pos++]);
        case 0xda: return readStr((buf[pos++] << 8) | buf[pos++]);
        case 0xdb: return readStr(((buf[pos++] << 24) | (buf[pos++] << 16) | (buf[pos++] << 8) | buf[pos++]) >>> 0);
        case 0xdc: return readArr((buf[pos++] << 8) | buf[pos++]);
        case 0xdd: return readArr(((buf[pos++] << 24) | (buf[pos++] << 16) | (buf[pos++] << 8) | buf[pos++]) >>> 0);
        case 0xde: return readMap((buf[pos++] << 8) | buf[pos++]);
        case 0xdf: return readMap(((buf[pos++] << 24) | (buf[pos++] << 16) | (buf[pos++] << 8) | buf[pos++]) >>> 0);
        default: fail("unsupported msgpack tag 0x" + b.toString(16));
      }
    };
    const readStr = (n) => {
      const s = utf8Decode(buf.subarray(pos, pos + n));
      pos += n;
      return s;
    };
    const readBin = (n) => {
      const out = buf.slice(pos, pos + n);
      pos += n;
      return out;
    };
    const readArr = (n) => {
      const a = new Array(n);
      for (let i = 0; i < n; i++) a[i] = read();
      return a;
    };
    const readMap = (n) => {
      const m = {};
      for (let i = 0; i < n; i++) {
        const k = read();
        m[String(k)] = read();
      }
      return m;
    };
    return read();
  }

  function parsePairingCode(code) {
    const trimmed = String(code || "").trim();
    const prefix = "mynote-pair:v1:";
    if (!trimmed.startsWith(prefix)) argErr("pairing code must start with mynote-pair:v1:");
    const parsed = JSON.parse(utf8Decode(base64ToBytes(trimmed.slice(prefix.length))));
    if (!parsed || !parsed.u || !parsed.p || !parsed.k) argErr("malformed pairing code");
    return { sync_url: String(parsed.u).replace(/\/+$/, ""), pair_id: String(parsed.p), k_pair_b64u: String(parsed.k) };
  }

  function decryptPairingTicket(pairId, kPairB64u, ciphertext) {
    const kPair = base64ToBytes(kPairB64u);
    if (kPair.length !== 32) fail("k_pair must be 32 bytes");
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 5 + 24 + TAG) fail("pairing ticket truncated");
    if (ciphertext[0] !== 0x4d || ciphertext[1] !== 0x4e || ciphertext[2] !== 0x50 || ciphertext[3] !== 0x52 || ciphertext[4] !== VER) {
      fail("invalid MNPR pairing ticket header");
    }
    const pairBytes = utf8Encode(pairId);
    const aad = new Uint8Array(5 + pairBytes.length);
    aad[0] = 0x4d; aad[1] = 0x4e; aad[2] = 0x50; aad[3] = 0x52; aad[4] = VER;
    aad.set(pairBytes, 5);
    const pt = xchacha20Poly1305Decrypt(kPair, ciphertext.subarray(5, 29), aad, ciphertext, 29, ciphertext.length - 29);
    const decoded = decodeMsgpack(pt);
    kPair.fill(0);
    pt.fill(0);

    const clipKidRaw = decoded.clip_kid;
    const clipKeyRaw = decoded.clip_key;
    const clipKid =
      typeof clipKidRaw === "string"
        ? clipKidRaw
        : clipKidRaw instanceof Uint8Array
          ? bytesToUlid(clipKidRaw)
          : Array.isArray(clipKidRaw)
            ? bytesToUlid(new Uint8Array(clipKidRaw))
            : null;
    const clipKeyBytes =
      clipKeyRaw instanceof Uint8Array
        ? clipKeyRaw
        : Array.isArray(clipKeyRaw)
          ? new Uint8Array(clipKeyRaw)
          : null;
    return {
      sync_url: String(decoded.sync_url || "").replace(/\/+$/, ""),
      device_id: String(decoded.device_id || ""),
      device_token: decoded.device_token ? String(decoded.device_token) : null,
      clip_kid: clipKid,
      clip_key_b64: clipKeyBytes ? bytesToBase64(clipKeyBytes) : null,
    };
  }

  const api = {
    WIRE_VERSION: VER,
    HEADER_LEN: HDR,
    TAG_LEN: TAG,
    FLAG_EPHEMERAL: F_EPH,
    FLAG_PAYLOAD_BLOB: F_BLOB,
    INLINE_TEXT_MAX_BYTES,
    EPHEMERAL_MAX_BYTES,
    BLOB_MAX_BYTES,
    ALLOWED_IMAGE_MIMES,
    KEYCHAIN_KEY,
    utf8Encode,
    utf8Decode,
    bytesToBase64,
    base64ToBytes,
    sha256Bytes,
    sha256Hex,
    ulidToBytes,
    bytesToUlid,
    generateUlid,
    pad256,
    unpad256,
    validateImageMime,
    buildClipMeta,
    encryptMnc1Meta,
    decryptMnc1Meta,
    encryptMnc1Blob,
    decryptMnc1Blob,
    prepareClipUpload,
    parsePairingCode,
    decryptPairingTicket,
  };

  if (typeof module === "object" && module && module.exports) {
    module.exports = api;
    return;
  }
  root.MyNoteClipPush = api;

  // ---------- Scriptable iOS Runtime Entrypoint (Keychain + Binary Stream Upload) ----------

  const isScriptable =
    typeof Keychain !== "undefined" &&
    typeof Request !== "undefined" &&
    typeof Script !== "undefined";

  if (!isScriptable) return;

  function loadKeychainCreds() {
    if (!Keychain.contains(KEYCHAIN_KEY)) return null;
    try {
      const parsed = JSON.parse(Keychain.get(KEYCHAIN_KEY));
      if (!parsed || !parsed.sync_url || !parsed.device_id || !parsed.device_token || !parsed.clip_kid || !parsed.clip_key_b64) {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }

  function saveKeychainCreds(creds) {
    Keychain.set(KEYCHAIN_KEY, JSON.stringify(creds));
  }

  async function importCredentialsInteractive() {
    const alert = new Alert();
    alert.title = "my-note Clipboard Setup";
    alert.message =
      "Paste a 'mynote-pair:v1:...' pairing code from:\nmynote device add --name iPhoneShortcuts --scope clip-write\n\nOr paste credentials JSON.";
    alert.addTextField("mynote-pair:v1:... or JSON", "");
    alert.addAction("Save to Keychain");
    alert.addCancelAction("Cancel");
    const choice = await alert.presentAlert();
    if (choice === -1) return null;
    const raw = (alert.textFieldValue(0) || "").trim();
    if (!raw) throw new Error("Empty setup input");

    if (raw.startsWith("mynote-pair:v1:")) {
      const code = parsePairingCode(raw);
      const req = new Request(code.sync_url + "/v1/devices/pair-claim");
      req.method = "POST";
      req.headers = { "Content-Type": "application/json", "X-Mynote-Protocol": "1" };
      req.body = JSON.stringify({ pair_id: code.pair_id });
      const res = await req.loadJSON();
      if (!res || res.ok !== true || !res.ciphertext_b64) {
        throw new Error("Pair claim failed: " + JSON.stringify(res));
      }
      if (res.scope !== "clip-write" && res.scope !== "read+clip") {
        throw new Error("Refused unsupported Shortcuts scope: " + String(res.scope));
      }
      const creds = decryptPairingTicket(code.pair_id, code.k_pair_b64u, base64ToBytes(res.ciphertext_b64));
      if (!creds.device_token || !creds.clip_kid || !creds.clip_key_b64) {
        throw new Error("Pairing ticket missing device_token or ClipKey");
      }
      saveKeychainCreds(creds);
      return creds;
    }

    const parsed = JSON.parse(raw);
    if (!parsed.sync_url || !parsed.device_id || !parsed.device_token || !parsed.clip_kid || !parsed.clip_key_b64) {
      throw new Error("JSON must include sync_url, device_id, device_token, clip_kid, clip_key_b64");
    }
    const creds = {
      sync_url: String(parsed.sync_url).replace(/\/+$/, ""),
      device_id: String(parsed.device_id),
      device_token: String(parsed.device_token),
      clip_kid: String(parsed.clip_kid),
      clip_key_b64: String(parsed.clip_key_b64),
    };
    saveKeychainCreds(creds);
    return creds;
  }

  function detectBitmapMimeFromMagic(bytes) {
    if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
      return "image/png";
    }
    if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
      return "image/jpeg";
    }
    if (bytes.length >= 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
        bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x50 && bytes[11] === 0x56) {
      return "image/webp";
    }
    if (bytes.length >= 6 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
      return "image/gif";
    }
    return null;
  }

  function dataToUint8Array(dataObj) {
    const arr = dataObj.getBytes();
    return new Uint8Array(arr);
  }

  async function runScriptable() {
    let creds = loadKeychainCreds();
    if (!creds) {
      creds = await importCredentialsInteractive();
      if (!creds) {
        Script.complete();
        return;
      }
    }

    const param = typeof args !== "undefined" ? args.shortcutParameter : null;
    let ephemeral = false;
    let textInput = null;
    let imageBytes = null;
    let imageMime = null;
    let imageWidth = null;
    let imageHeight = null;

    if (param && typeof param === "object" && typeof param.ephemeral === "boolean") {
      ephemeral = param.ephemeral;
    }

    // 1. Check Shortcuts / Share Sheet image or file input
    if (typeof args !== "undefined" && args.fileURLs && args.fileURLs.length > 0) {
      const filePath = args.fileURLs[0];
      if (String(filePath).toLowerCase().endsWith(".svg")) {
        argErr("image/svg+xml is blocked; share SVG as plain text");
      }
      const fm = FileManager.local();
      const rawData = fm.read(filePath);
      const bytes = dataToUint8Array(rawData);
      const detected = detectBitmapMimeFromMagic(bytes);
      if (detected) {
        imageBytes = bytes;
        imageMime = detected;
      } else {
        textInput = rawData.toRawString();
      }
    } else if (typeof args !== "undefined" && args.images && args.images.length > 0) {
      const img = args.images[0];
      const jpegData = Data.fromJPEG(img, 0.85);
      imageBytes = dataToUint8Array(jpegData);
      imageMime = "image/jpeg";
      imageWidth = img.size ? Math.round(img.size.width) : null;
      imageHeight = img.size ? Math.round(img.size.height) : null;
    } else if (param && typeof param === "object" && typeof param.getBytes === "function") {
      const bytes = dataToUint8Array(param);
      const detected = detectBitmapMimeFromMagic(bytes);
      if (detected) {
        imageBytes = bytes;
        imageMime = detected;
      } else {
        textInput = param.toRawString();
      }
    } else if (typeof param === "string" && param.length > 0) {
      textInput = param;
    } else if (param && typeof param === "object" && typeof param.text === "string" && param.text.length > 0) {
      textInput = param.text;
    } else if (typeof args !== "undefined" && args.plainTexts && args.plainTexts.length > 0) {
      textInput = args.plainTexts.join("\n");
    } else if (typeof args !== "undefined" && args.urls && args.urls.length > 0) {
      textInput = args.urls.join("\n");
    } else if (typeof Pasteboard !== "undefined") {
      const pastedText = Pasteboard.pasteString();
      if (pastedText && pastedText.length > 0) {
        textInput = pastedText;
      } else {
        const pastedImg = Pasteboard.pasteImage();
        if (pastedImg) {
          const pngData = Data.fromPNG(pastedImg);
          imageBytes = dataToUint8Array(pngData);
          imageMime = "image/png";
          imageWidth = pastedImg.size ? Math.round(pastedImg.size.width) : null;
          imageHeight = pastedImg.size ? Math.round(pastedImg.size.height) : null;
        }
      }
    }

    if (!imageBytes && (!textInput || textInput.length === 0)) {
      throw new Error("Nothing to send (no text or image provided)");
    }

    const clipKey = base64ToBytes(creds.clip_key_b64);
    const upload = prepareClipUpload({
      clipKey,
      clipKid: creds.clip_kid,
      deviceId: creds.device_id,
      kind: imageBytes ? "image" : "text",
      mime: imageBytes ? imageMime : "text/plain",
      text: textInput,
      rawBytes: imageBytes,
      ephemeral,
      width: imageWidth,
      height: imageHeight,
    });
    clipKey.fill(0);

    const req = new Request(creds.sync_url + upload.path);
    req.method = upload.method;
    if (upload.mode === "inline") {
      req.headers = {
        Authorization: "Bearer " + creds.device_token,
        "X-Mynote-Protocol": "1",
        "Content-Type": "application/json",
      };
      req.body = JSON.stringify(upload.jsonBody);
    } else {
      req.headers = Object.assign(
        {
          Authorization: "Bearer " + creds.device_token,
          "X-Mynote-Protocol": "1",
        },
        upload.headers,
      );
      // Pure binary body via Data.fromBytes — ZERO Base64 inflation on request body!
      req.body = Data.fromBytes(Array.from(upload.bodyBytes));
    }

    const resp = await req.loadJSON();
    if (!resp || resp.ok !== true) {
      throw new Error("Relay rejected clip: " + JSON.stringify(resp));
    }
    const summary = "Sent " + (imageBytes ? imageMime : "text") + " (" + upload.clipId + ")";
    if (typeof Script.setShortcutOutput === "function") {
      Script.setShortcutOutput(summary);
    }
    Script.complete();
  }

  runScriptable().catch((err) => {
    const msg = err instanceof Error ? err.message : String(err);
    if (typeof Script.setShortcutOutput === "function") {
      Script.setShortcutOutput("ERROR: " + msg);
    }
    Script.complete();
  });
})(typeof globalThis !== "undefined" ? globalThis : this);
