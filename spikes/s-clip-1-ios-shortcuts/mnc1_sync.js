// Pure synchronous JS XChaCha20-Poly1305 + MNC1 codec (zero deps, zero crypto.subtle, zero BigInt).
// Zero JS function calls inside ChaCha20/Poly1305 hot loops so JSC LLInt (no-JIT iOS App Extensions) stays fast.
// Spec SSOT: docs/data-structures.md §3.1, §3.2, §3.3, §3.8 & crates/mynote-core/src/{crypto,ids}.rs.
(function (root) {
  "use strict";

  const VER = 1, HDR = 45, TAG = 16, F_EPH = 1, F_BLOB = 2, F_RES = 0xfc;
  const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const B32D = new Int8Array(128).fill(-1);
  for (let i = 0; i < 32; i++) B32D[B32.charCodeAt(i)] = i;
  const P26 = 67108864, INV13 = 1 / 8192, INV26 = 1 / 67108864;

  const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const w32 = (b, o, v) => { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = (v >>> 24) & 255; };
  const fail = (m) => { throw new Error("INTEGRITY_ERROR: " + m); };

  // Strict UTF-8 encode/decode (bare JSC / iOS Scriptable may omit TextEncoder/TextDecoder).
  function utf8Encode(s) {
    if (typeof s !== "string") throw new TypeError("expected string");
    const n = s.length, o = new Uint8Array(n * 3);
    let p = 0;
    for (let i = 0; i < n; i++) {
      let c = s.charCodeAt(i);
      if (c < 0x80) o[p++] = c;
      else if (c < 0x800) { o[p++] = 0xc0 | (c >> 6); o[p++] = 0x80 | (c & 63); }
      else if (c >= 0xd800 && c <= 0xdbff) {
        if (i + 1 >= n) fail("lone high surrogate");
        const l = s.charCodeAt(++i);
        if (l < 0xdc00 || l > 0xdfff) fail("bad surrogate");
        c = 0x10000 + (((c - 0xd800) << 10) | (l - 0xdc00));
        o[p++] = 0xf0 | (c >> 18); o[p++] = 0x80 | ((c >> 12) & 63);
        o[p++] = 0x80 | ((c >> 6) & 63); o[p++] = 0x80 | (c & 63);
      } else if (c >= 0xdc00 && c <= 0xdfff) fail("lone low surrogate");
      else { o[p++] = 0xe0 | (c >> 12); o[p++] = 0x80 | ((c >> 6) & 63); o[p++] = 0x80 | (c & 63); }
    }
    return o.subarray(0, p);
  }

  function utf8Decode(b) {
    let o = "", i = 0, n = b.length;
    while (i < n) {
      const a = b[i++];
      if (a < 0x80) o += String.fromCharCode(a);
      else if (a >= 0xc2 && a <= 0xdf) {
        if (i >= n || (b[i] & 0xc0) !== 0x80) fail("bad utf8");
        o += String.fromCharCode(((a & 31) << 6) | (b[i++] & 63));
      } else if (a >= 0xe0 && a <= 0xef) {
        if (i + 1 >= n || (b[i] & 0xc0) !== 0x80 || (b[i + 1] & 0xc0) !== 0x80) fail("bad utf8");
        const c = ((a & 15) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63);
        if (c < 0x800 || (c >= 0xd800 && c <= 0xdfff)) fail("bad utf8");
        o += String.fromCharCode(c);
      } else if (a >= 0xf0 && a <= 0xf4) {
        if (i + 2 >= n || (b[i] & 0xc0) !== 0x80 || (b[i + 1] & 0xc0) !== 0x80 || (b[i + 2] & 0xc0) !== 0x80) fail("bad utf8");
        const c = ((a & 7) << 18) | ((b[i++] & 63) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63);
        if (c < 0x10000 || c > 0x10ffff) fail("bad utf8");
        const u = c - 0x10000;
        o += String.fromCharCode(0xd800 | (u >> 10), 0xdc00 | (u & 0x3ff));
      } else fail("bad utf8");
    }
    return o;
  }

  // Canonical 26-char uppercase Crockford Base32 ULID <-> 16-byte big-endian Uint8Array.
  function ulidToBytes(s) {
    if (typeof s !== "string" || s.length !== 26) fail("bad ulid len");
    const c0 = s.charCodeAt(0), v0 = c0 < 128 ? B32D[c0] : -1;
    if (v0 < 0 || v0 > 7) fail("bad ulid");
    const o = new Uint8Array(16);
    let acc = v0, bits = 3, p = 0;
    for (let i = 1; i < 26; i++) {
      const c = s.charCodeAt(i), v = c < 128 ? B32D[c] : -1;
      if (v < 0) fail("bad ulid");
      acc = (acc << 5) | v; bits += 5;
      if (bits >= 8) { bits -= 8; o[p++] = (acc >>> bits) & 255; }
    }
    return o;
  }

  function bytesToUlid(b) {
    if (!(b instanceof Uint8Array) || b.length !== 16) fail("bad ulid bytes");
    let o = "", acc = 0, bits = 2;
    for (let i = 0; i < 16; i++) {
      acc = (acc << 8) | b[i]; bits += 8;
      while (bits >= 5) { bits -= 5; o += B32[(acc >>> bits) & 31]; }
    }
    return o;
  }

  // Bijective 256-byte bucket padding (docs/data-structures.md §3.1).
  function pad256(raw) {
    const n = raw.length, z = (256 - ((n + 1) & 255)) & 255, o = new Uint8Array(n + z + 1);
    o.set(raw, 0); o[n + z] = z; return o;
  }

  function unpad256(b) {
    const n = b.length;
    if (n < 256 || (n & 255) !== 0) fail("bad pad len");
    const p = b[n - 1], end = n - 1 - p;
    for (let i = end; i < n - 1; i++) if (b[i] !== 0) fail("non-zero pad");
    return b.subarray(0, end);
  }

  const IS_LE = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1;

  // Unified ChaCha20 core: mode 0 = HChaCha20 (writes 32B subkey), mode 1 = OTK (32B), mode 2 = XOR stream.
  // Scalar register variables + zero per-block JS calls keeps both JIT and LLInt (no-JIT) fast.
  function chachaCore(mode, key, w12, w13, w14, w15, src, sOff, len, dst, dOff) {
    const k0 = u32(key, 0) | 0, k1 = u32(key, 4) | 0, k2 = u32(key, 8) | 0, k3 = u32(key, 12) | 0;
    const k4 = u32(key, 16) | 0, k5 = u32(key, 20) | 0, k6 = u32(key, 24) | 0, k7 = u32(key, 28) | 0;
    const ks = mode === 2 ? new Uint8Array(64) : null;
    const ks32 = ks && IS_LE ? new Int32Array(ks.buffer) : null;
    let ctr = w12 | 0, pos = 0;

    do {
      let x0 = 0x61707865, x1 = 0x3320646e, x2 = 0x79622d32, x3 = 0x6b206574;
      let x4 = k0, x5 = k1, x6 = k2, x7 = k3, x8 = k4, x9 = k5, x10 = k6, x11 = k7;
      let x12 = ctr, x13 = w13 | 0, x14 = w14 | 0, x15 = w15 | 0;
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
      const si = sOff + pos, di = dOff + pos;
      for (let i = 0; i < n; i++) dst[di + i] = src[si + i] ^ ks[i];
      pos += n;
    } while (pos < len);
  }

  function hchacha20(key, n16) {
    const o = new Uint8Array(32);
    chachaCore(0, key, u32(n16, 0), u32(n16, 4), u32(n16, 8), u32(n16, 12), null, 0, 0, o, 0);
    return o;
  }

  function chacha20Xor(key, ctr, n12, src, sOff, len, dst, dOff) {
    if (src === null) {
      chachaCore(1, key, ctr, u32(n12, 0), u32(n12, 4), u32(n12, 8), null, 0, 0, dst, dOff);
    } else if (len > 0) {
      chachaCore(2, key, ctr, u32(n12, 0), u32(n12, 4), u32(n12, 8), src, sOff, len, dst, dOff);
    }
  }

  // BigInt-free streaming Poly1305 (5x26-bit limbs split 13+13; max intermediate < 2^45 << 2^53).
  // Hot 16-byte loop is fully inlined (zero per-block JS calls).
  function poly1305Compute(otk, segs, rawLast, tagOut, tagOff) {
    const t0 = u32(otk, 0) & 0x0fffffff, t1 = u32(otk, 4) & 0x0ffffffc;
    const t2 = u32(otk, 8) & 0x0ffffffc, t3 = u32(otk, 12) & 0x0ffffffc;
    const r0 = t0 & 0x3ffffff, r1 = ((t0 >>> 26) | (t1 << 6)) & 0x3ffffff;
    const r2 = ((t1 >>> 20) | (t2 << 12)) & 0x3ffffff, r3 = ((t2 >>> 14) | (t3 << 18)) & 0x3ffffff, r4 = t3 >>> 8;
    const s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    let h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    const tail = new Uint8Array(16);

    for (let si = 0; si < segs.length; si++) {
      const seg = segs[si], buf = seg[0], off = seg[1], len = seg[2];
      const full = len & ~15;
      let pos = 0, hi = 0x1000000;
      for (;;) {
        let b, o;
        if (pos < full) {
          b = buf; o = off + pos; pos += 16;
        } else if (pos < len) {
          const rem = len - pos;
          tail.fill(0);
          for (let i = 0; i < rem; i++) tail[i] = buf[off + pos + i];
          if (rawLast) { tail[rem] = 1; hi = 0; }
          b = tail; o = 0; pos = len;
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
        h4 += (m3 >>> 8) | hi;

        const l0 = h0 & 0x1fff, u0 = h0 >>> 13, l1 = h1 & 0x1fff, u1 = h1 >>> 13;
        const l2 = h2 & 0x1fff, u2 = h2 >>> 13, l3 = h3 & 0x1fff, u3 = h3 >>> 13, l4 = h4 & 0x1fff, u4 = h4 >>> 13;

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
    const g4 = h4 + c - P26, m = g4 >> 31, nm = ~m;
    h0 = (h0 & m) | (g0 & nm); h1 = (h1 & m) | (g1 & nm);
    h2 = (h2 & m) | (g2 & nm); h3 = (h3 & m) | (g3 & nm); h4 = (h4 & m) | (g4 & nm);

    const f0 = ((h0 | (h1 << 26)) >>> 0) + u32(otk, 16);
    const f1 = (((h1 >>> 6) | (h2 << 20)) >>> 0) + u32(otk, 20) + (f0 > 0xffffffff ? 1 : 0);
    const f2 = (((h2 >>> 12) | (h3 << 14)) >>> 0) + u32(otk, 24) + (f1 > 0xffffffff ? 1 : 0);
    const f3 = (((h3 >>> 18) | (h4 << 8)) >>> 0) + u32(otk, 28) + (f2 > 0xffffffff ? 1 : 0);
    w32(tagOut, tagOff, f0 >>> 0); w32(tagOut, tagOff + 4, f1 >>> 0);
    w32(tagOut, tagOff + 8, f2 >>> 0); w32(tagOut, tagOff + 12, f3 >>> 0);
  }

  function poly1305Raw(otk, msg) {
    const t = new Uint8Array(16);
    poly1305Compute(otk, [[msg, 0, msg.length]], true, t, 0);
    return t;
  }

  function poly1305Aead(otk, aad, ct, ctOff, ctLen, out, o) {
    const lens = new Uint8Array(16);
    w32(lens, 0, aad.length >>> 0); w32(lens, 4, Math.floor(aad.length / 0x100000000) >>> 0);
    w32(lens, 8, ctLen >>> 0); w32(lens, 12, Math.floor(ctLen / 0x100000000) >>> 0);
    poly1305Compute(otk, [[aad, 0, aad.length], [ct, ctOff, ctLen], [lens, 0, 16]], false, out, o);
  }

  function prepSubkey(key, n24) {
    if (!(key instanceof Uint8Array) || key.length !== 32) fail("bad key");
    if (!(n24 instanceof Uint8Array) || n24.length !== 24) fail("bad nonce");
    const sub = hchacha20(key, n24), otk = new Uint8Array(32);
    const n1 = u32(n24, 16), n2 = u32(n24, 20);
    chachaCore(1, sub, 0, 0, n1, n2, null, 0, 0, otk, 0);
    return { sub, otk, n1, n2 };
  }

  function xchacha20Poly1305EncryptInto(key, n24, aad, pt, out, outOff) {
    const { sub, otk, n1, n2 } = prepSubkey(key, n24);
    if (pt.length > 0) chachaCore(2, sub, 1, 0, n1, n2, pt, 0, pt.length, out, outOff);
    poly1305Aead(otk, aad, out, outOff, pt.length, out, outOff + pt.length);
    sub.fill(0); otk.fill(0);
  }

  function xchacha20Poly1305Decrypt(key, n24, aad, ctTag, off, len) {
    if (len < TAG) fail("truncated ct");
    const ctLen = len - TAG, { sub, otk, n1, n2 } = prepSubkey(key, n24), exp = new Uint8Array(16);
    poly1305Aead(otk, aad, ctTag, off, ctLen, exp, 0);
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= exp[i] ^ ctTag[off + ctLen + i];
    if (diff !== 0) { sub.fill(0); otk.fill(0); fail("tag/aad mismatch"); }
    const pt = new Uint8Array(ctLen);
    if (ctLen > 0) chachaCore(2, sub, 1, 0, n1, n2, ctTag, off, ctLen, pt, 0);
    sub.fill(0); otk.fill(0);
    return pt;
  }

  // Exact MNC1 AAD (docs/data-structures.md §3.3):
  // "MNC1" || 0x01 || clip_kid(16B) || clip_id(16B) || utf8(device_id) || flags(1B)
  function buildMnc1Aad(kidB, idB, deviceId, flags) {
    if ((flags & ~0xff) !== 0 || (flags & F_RES) !== 0) fail("reserved flags");
    const dev = utf8Encode(deviceId), aad = new Uint8Array(38 + dev.length);
    aad[0] = 0x4d; aad[1] = 0x4e; aad[2] = 0x43; aad[3] = 0x31; aad[4] = VER;
    aad.set(kidB, 5); aad.set(idB, 21); aad.set(dev, 37); aad[37 + dev.length] = flags;
    return aad;
  }

  const asUlid = (id) => (id instanceof Uint8Array ? (id.length === 16 ? id : fail("bad ulid bytes")) : ulidToBytes(id));

  function getNonce(n) {
    if (n != null) { if (!(n instanceof Uint8Array) || n.length !== 24) fail("bad nonce"); return n; }
    if (root.crypto && typeof root.crypto.getRandomValues === "function") return root.crypto.getRandomValues(new Uint8Array(24));
    throw new Error("CSPRNG unavailable: pass explicit 24-byte random nonce");
  }

  function encryptMnc1Raw({ clipKey, clipKid, clipId, deviceId, flags, plaintext, nonce }) {
    const kidB = asUlid(clipKid), idB = asUlid(clipId), n24 = getNonce(nonce);
    const aad = buildMnc1Aad(kidB, idB, deviceId, flags);
    const out = new Uint8Array(HDR + plaintext.length + TAG);
    out[0] = 0x4d; out[1] = 0x4e; out[2] = 0x43; out[3] = 0x31; out[4] = VER;
    out.set(kidB, 5); out.set(n24, 21);
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

  function encryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, meta, ephemeral = false, nonce }) {
    const json = typeof meta === "string" ? meta : JSON.stringify(meta);
    return encryptMnc1Raw({ clipKey, clipKid, clipId, deviceId, flags: ephemeral ? F_EPH : 0, plaintext: pad256(utf8Encode(json)), nonce });
  }

  function decryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, envelope, ephemeral = false, flags }) {
    const f = flags !== undefined ? flags : (ephemeral ? F_EPH : 0);
    if ((f & F_RES) !== 0 || (f & F_BLOB) !== 0) fail("bad meta flags");
    return JSON.parse(utf8Decode(unpad256(decryptMnc1Raw({ clipKey, clipKid, clipId, deviceId, flags: f, envelope }))));
  }

  function encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes, ephemeral = false, nonce }) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("expected Uint8Array");
    return encryptMnc1Raw({ clipKey, clipKid, clipId, deviceId, flags: F_BLOB | (ephemeral ? F_EPH : 0), plaintext: bytes, nonce });
  }

  function decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope, ephemeral = false, flags }) {
    const f = flags !== undefined ? flags : (F_BLOB | (ephemeral ? F_EPH : 0));
    if ((f & F_RES) !== 0 || (f & F_BLOB) === 0) fail("bad blob flags");
    return decryptMnc1Raw({ clipKey, clipKid, clipId, deviceId, flags: f, envelope });
  }

  const api = {
    WIRE_VERSION: VER, HEADER_LEN: HDR, TAG_LEN: TAG,
    FLAG_EPHEMERAL: F_EPH, FLAG_PAYLOAD_BLOB: F_BLOB, FLAGS_RESERVED_MASK: F_RES,
    utf8Encode, utf8Decode, ulidToBytes, bytesToUlid, pad256, unpad256,
    hchacha20, chacha20Xor, poly1305Raw, poly1305Aead,
    xchacha20Poly1305EncryptInto, xchacha20Poly1305Decrypt,
    buildMnc1Aad, encryptMnc1Raw, decryptMnc1Raw,
    encryptMnc1Meta, decryptMnc1Meta, encryptMnc1Blob, decryptMnc1Blob,
  };
  if (typeof module === "object" && module && module.exports) module.exports = api;
  else root.Mnc1Sync = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
