// Reproducible performance benchmark for mnc1_sync.js across Node.js (V8) and macOS JavaScriptCore (jsc).
// Modes:
//   default (warm): warmup + N timed runs (median, min, max, MiB/s) + round-trip verification & anti-DCE checksum.
//   --cold-once:    single cold invocation (no warmup) for measuring fresh-process Shortcut / Scriptable startup cost.
const __JSC_ARGS__ = typeof arguments !== "undefined" ? Array.from(arguments) : [];
(function () {
  "use strict";

  const isNode = typeof process !== "undefined" && process.versions && process.versions.node;
  let M, nowMs, argv, logFn, getMemKb;

  if (isNode) {
    const path = require("path");
    M = require(path.join(__dirname, "mnc1_sync.js"));
    nowMs = () => Number(process.hrtime.bigint()) / 1e6;
    argv = process.argv.slice(2);
    logFn = (s) => console.log(s);
    getMemKb = () => Math.round(process.memoryUsage().rss / 1024);
  } else {
    const jsPath = __JSC_ARGS__[0] || "spikes/s-clip-1-ios-shortcuts/mnc1_sync.js";
    load(jsPath);
    M = globalThis.Mnc1Sync;
    nowMs = () => (typeof preciseTime === "function" ? preciseTime() * 1000 : performance.now());
    argv = __JSC_ARGS__.slice(1);
    logFn = (s) => print(s);
    getMemKb = () => null;
  }

  const clipKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) clipKey[i] = (i * 11 + 7) & 0xff;
  const clipKid = "01JDF8Z9X4K7M2N5P8Q1R3S6T9";
  const clipId = "01JDF910A1B2C3D4E5F6G7H8J9";
  const deviceId = "dev_01jdf8z9x4k7m2n5";
  const nonce = new Uint8Array(24);
  for (let i = 0; i < 24; i++) nonce[i] = (i * 17 + 3) & 0xff;

  // Deterministic payloads:
  // 1) 256 B text wrapped in ClipMetaV1 (payload_type=0, pad256)
  const text256 = "A".repeat(220) + "中文测试🚀" + "01234567890123456789"; // ~256 UTF-8 bytes
  const textMetaObj = {
    v: 1,
    kind: "text",
    mime: "text/plain",
    source_mode: "explicit",
    created_at_ms: 1795600000000,
    text: text256,
    blob: null,
  };
  const textUtf8Len = M.utf8Encode(text256).length;

  // 2) 500 KiB binary buffer (512,000 B)
  const buf500k = new Uint8Array(500 * 1024);
  for (let i = 0; i < buf500k.length; i++) buf500k[i] = (i * 73 + 19) & 0xff;

  // 3) 1.5 MiB binary buffer (1,572,864 B)
  const buf15m = new Uint8Array(1536 * 1024);
  for (let i = 0; i < buf15m.length; i++) buf15m[i] = (i * 41 + 13) & 0xff;

  function checksum(u8) {
    let acc = 0;
    const step = Math.max(1, u8.length >> 8);
    for (let i = 0; i < u8.length; i += step) acc = (acc + u8[i]) | 0;
    return (acc + u8[0] + u8[u8.length - 1]) | 0;
  }

  function stats(arr) {
    const s = arr.slice().sort((a, b) => a - b);
    const mid = s.length >> 1;
    const median = s.length % 2 === 1 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
    return {
      runs: s.length,
      median_ms: Number(median.toFixed(3)),
      min_ms: Number(s[0].toFixed(3)),
      max_ms: Number(s[s.length - 1].toFixed(3)),
    };
  }

  const coldIdx = argv.indexOf("--cold-case");
  const coldCase = coldIdx !== -1 ? argv[coldIdx + 1] : null;
  const coldOnce = argv.indexOf("--cold-once") !== -1;
  const breakdown = argv.indexOf("--breakdown") !== -1;

  if (coldCase) {
    // Uncontaminated cold single-payload run (fresh process, zero prior JIT compilation).
    let t0, env, ok;
    if (coldCase === "text") {
      t0 = nowMs();
      env = M.encryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, meta: textMetaObj, nonce });
      const dt = nowMs() - t0;
      ok = M.decryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, envelope: env }).text === text256;
      if (!ok) throw new Error("cold text verify failed");
      logFn(JSON.stringify({ mode: "cold", case: "text_256b", engine: isNode ? ("Node.js " + process.version + " (V8)") : "macOS JavaScriptCore (jsc)", ms: Number(dt.toFixed(3)), env_bytes: env.length, rss_kb: getMemKb(), sink: checksum(env) >>> 0 }));
    } else if (coldCase === "500k") {
      t0 = nowMs();
      env = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf500k, nonce });
      const dt = nowMs() - t0;
      ok = M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: env }).length === buf500k.length;
      if (!ok) throw new Error("cold 500k verify failed");
      logFn(JSON.stringify({ mode: "cold", case: "blob_500kib", engine: isNode ? ("Node.js " + process.version + " (V8)") : "macOS JavaScriptCore (jsc)", ms: Number(dt.toFixed(3)), env_bytes: env.length, rss_kb: getMemKb(), sink: checksum(env) >>> 0 }));
    } else if (coldCase === "15m") {
      t0 = nowMs();
      env = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf15m, nonce });
      const dt = nowMs() - t0;
      ok = M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: env }).length === buf15m.length;
      if (!ok) throw new Error("cold 15m verify failed");
      logFn(JSON.stringify({ mode: "cold", case: "blob_1536kib", engine: isNode ? ("Node.js " + process.version + " (V8)") : "macOS JavaScriptCore (jsc)", ms: Number(dt.toFixed(3)), env_bytes: env.length, rss_kb: getMemKb(), sink: checksum(env) >>> 0 }));
    } else {
      throw new Error("unknown --cold-case: " + coldCase);
    }
    return;
  }

  if (breakdown) {
    // Isolate ChaCha20 vs Poly1305 share on 1.5 MiB to identify exact CPU limiter.
    const subkey = M.hchacha20(clipKey, nonce);
    const n12 = new Uint8Array(12);
    n12.set(nonce.subarray(16, 24), 4);
    const otk = new Uint8Array(32);
    M.chacha20Xor(subkey, 0, n12, null, 0, 32, otk, 0);
    const aad = M.buildMnc1Aad(M.ulidToBytes(clipKid), M.ulidToBytes(clipId), deviceId, M.FLAG_PAYLOAD_BLOB);
    const dst = new Uint8Array(buf15m.length + 16);
    for (let w = 0; w < 5; w++) {
      M.chacha20Xor(subkey, 1, n12, buf15m, 0, buf15m.length, dst, 0);
      M.poly1305Aead(otk, aad, dst, 0, buf15m.length, dst, buf15m.length);
    }
    const cc = [], poly = [];
    let sink = 0;
    for (let r = 0; r < 7; r++) {
      let t = nowMs();
      M.chacha20Xor(subkey, 1, n12, buf15m, 0, buf15m.length, dst, 0);
      cc.push(nowMs() - t);
      sink ^= dst[buf15m.length - 1];
      t = nowMs();
      M.poly1305Aead(otk, aad, dst, 0, buf15m.length, dst, buf15m.length);
      poly.push(nowMs() - t);
      sink ^= dst[buf15m.length + 15];
    }
    const sCc = stats(cc), sPoly = stats(poly);
    const tot = sCc.median_ms + sPoly.median_ms;
    logFn(JSON.stringify({
      mode: "breakdown_1536kib",
      engine: isNode ? ("Node.js " + process.version + " (V8)") : "macOS JavaScriptCore (jsc)",
      chacha20: sCc,
      poly1305: sPoly,
      chacha20_pct: Number(((sCc.median_ms / tot) * 100).toFixed(1)),
      poly1305_pct: Number(((sPoly.median_ms / tot) * 100).toFixed(1)),
      sink: sink >>> 0,
    }, null, 2));
    return;
  }

  if (coldOnce) {
    // Run exactly once per case with ZERO warmup, verifying every output (Q4 & Q7).
    const t0 = nowMs();
    const eText = M.encryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, meta: textMetaObj, nonce });
    const dtText = nowMs() - t0;

    const t1 = nowMs();
    const e500 = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf500k, nonce });
    const dt500 = nowMs() - t1;

    const t2 = nowMs();
    const e15 = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf15m, nonce });
    const dt15 = nowMs() - t2;

    // Verify all outputs decrypted back correctly outside timed region
    const dText = M.decryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, envelope: eText });
    const d500 = M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: e500 });
    const d15 = M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: e15 });
    if (dText.text !== text256 || d500.length !== buf500k.length || d15.length !== buf15m.length) {
      throw new Error("cold-once verification mismatch");
    }

    logFn(JSON.stringify({
      mode: "cold-once",
      engine: isNode ? ("Node.js " + process.version + " (V8)") : "macOS JavaScriptCore (jsc)",
      text_256b_encrypt_ms: Number(dtText.toFixed(3)),
      blob_500kib_encrypt_ms: Number(dt500.toFixed(3)),
      blob_1536kib_encrypt_ms: Number(dt15.toFixed(3)),
      rss_kb: getMemKb(),
      sink: (checksum(eText) ^ checksum(e500) ^ checksum(e15)) >>> 0,
    }));
  } else {
    const WARMUP = 5;
    const RUNS = 7;
    const TEXT_ITERS = 200; // amortize timer resolution for sub-millisecond 256B encrypt/decrypt

    let sink = 0;

    // Correctness check first
    const chkTextEnv = M.encryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, meta: textMetaObj, nonce });
    const chkTextDec = M.decryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, envelope: chkTextEnv });
    if (chkTextDec.text !== text256) throw new Error("text roundtrip failed");

    const chk500Env = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf500k, nonce });
    const chk500Dec = M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: chk500Env });
    if (chk500Dec.length !== buf500k.length || chk500Dec[500000] !== buf500k[500000]) throw new Error("500k roundtrip failed");

    const chk15Env = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf15m, nonce });
    const chk15Dec = M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: chk15Env });
    if (chk15Dec.length !== buf15m.length || chk15Dec[1500000] !== buf15m[1500000]) throw new Error("1.5m roundtrip failed");

    // Warmup all paths
    for (let w = 0; w < WARMUP; w++) {
      for (let i = 0; i < 50; i++) {
        sink ^= checksum(M.encryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, meta: textMetaObj, nonce }));
      }
      sink ^= checksum(M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf500k, nonce }));
      sink ^= checksum(M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf15m, nonce }));
      sink ^= checksum(M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: chk500Env }));
      sink ^= checksum(M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: chk15Env }));
    }

    const rTextEnc = [], rTextDec = [], r500Enc = [], r500Dec = [], r15Enc = [], r15Dec = [];

    // Interleaved runs across all 6 operations so drift/thermal noise affects all cases equally
    for (let run = 0; run < RUNS; run++) {
      let t = nowMs();
      for (let i = 0; i < TEXT_ITERS; i++) {
        const out = M.encryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, meta: textMetaObj, nonce });
        sink ^= out[out.length - 1];
      }
      rTextEnc.push((nowMs() - t) / TEXT_ITERS);

      t = nowMs();
      for (let i = 0; i < TEXT_ITERS; i++) {
        const obj = M.decryptMnc1Meta({ clipKey, clipKid, clipId, deviceId, envelope: chkTextEnv });
        sink ^= obj.text.length;
      }
      rTextDec.push((nowMs() - t) / TEXT_ITERS);

      t = nowMs();
      const e500 = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf500k, nonce });
      r500Enc.push(nowMs() - t);
      sink ^= checksum(e500);

      t = nowMs();
      const d500 = M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: e500 });
      r500Dec.push(nowMs() - t);
      sink ^= checksum(d500);

      t = nowMs();
      const e15 = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: buf15m, nonce });
      r15Enc.push(nowMs() - t);
      sink ^= checksum(e15);

      t = nowMs();
      const d15 = M.decryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, envelope: e15 });
      r15Dec.push(nowMs() - t);
      sink ^= checksum(d15);
    }

    const sTextEnc = stats(rTextEnc);
    const sTextDec = stats(rTextDec);
    const s500Enc = stats(r500Enc);
    const s500Dec = stats(r500Dec);
    const s15Enc = stats(r15Enc);
    const s15Dec = stats(r15Dec);

    const mibPerSec = (bytes, ms) => Number(((bytes / (1024 * 1024)) / (ms / 1000)).toFixed(2));

    logFn(JSON.stringify({
      mode: "warm",
      engine: isNode ? ("Node.js " + process.version + " (V8)") : "macOS JavaScriptCore (jsc)",
      warmup_rounds: WARMUP,
      timed_runs: RUNS,
      text_256b_utf8_bytes: textUtf8Len,
      text_256b_envelope_bytes: chkTextEnv.length,
      results: {
        text_256b_meta_encrypt: sTextEnc,
        text_256b_meta_decrypt: sTextDec,
        blob_500kib_encrypt: Object.assign(s500Enc, { mib_per_sec: mibPerSec(buf500k.length, s500Enc.median_ms) }),
        blob_500kib_decrypt: Object.assign(s500Dec, { mib_per_sec: mibPerSec(buf500k.length, s500Dec.median_ms) }),
        blob_1536kib_encrypt: Object.assign(s15Enc, { mib_per_sec: mibPerSec(buf15m.length, s15Enc.median_ms) }),
        blob_1536kib_decrypt: Object.assign(s15Dec, { mib_per_sec: mibPerSec(buf15m.length, s15Dec.median_ms) }),
      },
      rss_kb: getMemKb(),
      errors: 0,
      sink: sink >>> 0,
    }, null, 2));
  }
})();
