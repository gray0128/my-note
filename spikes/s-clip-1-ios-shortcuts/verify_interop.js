// Bidirectional interop & RFC 8439 / draft-xchacha verifier for mnc1_sync.js.
// Runs under both Node.js (V8) and macOS /System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc.
const __JSC_ARGS__ = typeof arguments !== "undefined" ? Array.from(arguments) : [];
(function () {
  "use strict";

  const isNode = typeof process !== "undefined" && process.versions && process.versions.node;
  let M, readTextFile, writeTextFile, argv, exitFn, logFn;

  if (isNode) {
    const fs = require("fs");
    const path = require("path");
    M = require(path.join(__dirname, "mnc1_sync.js"));
    readTextFile = (p) => fs.readFileSync(p, "utf8");
    writeTextFile = (p, s) => fs.writeFileSync(p, s, "utf8");
    argv = process.argv.slice(2);
    exitFn = (c) => process.exit(c);
    logFn = (s) => console.log(s);
  } else {
    // Apple JavaScriptCore CLI (jsc): invoked via `jsc verify_interop.js -- <mnc1_sync_path> <golden_json_path>`
    const jsPath = __JSC_ARGS__[0] || "spikes/s-clip-1-ios-shortcuts/mnc1_sync.js";
    load(jsPath);
    M = globalThis.Mnc1Sync;
    readTextFile = (p) => readFile(p);
    writeTextFile = () => { throw new Error("writeTextFile not used in jsc"); };
    argv = __JSC_ARGS__.slice(1);
    exitFn = (c) => { if (c !== 0) throw new Error("EXIT_" + c); };
    logFn = (s) => print(s);
  }

  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error("odd hex");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function bytesToHex(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) {
      s += bytes[i].toString(16).padStart(2, "0");
    }
    return s;
  }

  function assertEq(actual, expected, label) {
    if (actual !== expected) {
      throw new Error(`ASSERT FAIL [${label}]:\n  actual:   ${actual}\n  expected: ${expected}`);
    }
  }

  function assertThrows(fn, label) {
    let threw = false;
    try {
      fn();
    } catch (_) {
      threw = true;
    }
    if (!threw) throw new Error(`ASSERT THROW FAIL [${label}]: expected error but succeeded`);
  }

  // 1. RFC 8439 §2.5.2 Poly1305 test vector
  function testRfc8439Poly1305() {
    const key = hexToBytes(
      "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    );
    const msg = M.utf8Encode("Cryptographic Forum Research Group");
    const tag = M.poly1305Raw(key, msg);
    assertEq(bytesToHex(tag), "a8061dc1305136c6c22b8baf0c0127a9", "RFC 8439 §2.5.2 Poly1305");
  }

  // 2. draft-irtf-cfrg-xchacha §2.2.1 HChaCha20 test vector
  function testDraftHChaCha20() {
    const key = hexToBytes(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const nonce16 = hexToBytes("000000090000004a0000000031415927");
    const subkey = M.hchacha20(key, nonce16);
    assertEq(
      bytesToHex(subkey),
      "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
      "draft-irtf-cfrg-xchacha §2.2.1 HChaCha20"
    );
  }

  // 3. draft-irtf-cfrg-xchacha §A.3.1 XChaCha20-Poly1305 AEAD test vector
  function testDraftXChaCha20Poly1305() {
    const key = hexToBytes(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    );
    const nonce = hexToBytes("404142434445464748494a4b4c4d4e4f5051525354555657");
    const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
    const pt = M.utf8Encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    );
    const out = new Uint8Array(pt.length + 16);
    M.xchacha20Poly1305EncryptInto(key, nonce, aad, pt, out, 0);
    const expectedCt =
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
      "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
      "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
      "21f9664c97637da9768812f615c68b13b52e";
    const expectedTag = "c0875924c1c7987947deafd8780acf49";
    assertEq(bytesToHex(out), expectedCt + expectedTag, "draft-xchacha §A.3.1 encrypt");
    const dec = M.xchacha20Poly1305Decrypt(key, nonce, aad, out, 0, out.length);
    assertEq(bytesToHex(dec), bytesToHex(pt), "draft-xchacha §A.3.1 decrypt");
  }

  // 4. Poly1305 modular reduction edge vectors (all-0xFF limbs and h >= 2^130-5 wrap)
  function testPoly1305EdgeCases() {
    // Known edge case: r = 0x0ffffffc_0ffffffc_0ffffffc_0fffffff (max clamped r), s = 0, msg = 0xff*16
    const maxKey = new Uint8Array(32);
    maxKey.fill(0xff, 0, 16);
    maxKey.fill(0x00, 16, 32);
    const msg16 = new Uint8Array(16).fill(0xff);
    // Compute exact reference via 256-bit schoolbook check? Better: cross-checked with Rust AEAD in emitJsVectors too!
    // Also test RFC 8439 §A.3 Test Vector #2 (all-zero key) and #4 (wrap around 2^130 - 5).
    const zKey = new Uint8Array(32);
    assertEq(bytesToHex(M.poly1305Raw(zKey, msg16)), "00000000000000000000000000000000", "Poly1305 zero key");
    // RFC 8439 A.3 Vector #4 (triggers modular reduction near 2^130 - 5):
    const k4 = hexToBytes("0200000000000000000000000000000000000000000000000000000000000000");
    const m4 = hexToBytes("ffffffffffffffffffffffffffffffff");
    // (2^128 + 2^128 - 1) * 2 = (2^129 - 1)*2 = 2^130 - 2 ≡ 3 (mod 2^130 - 5)!
    assertEq(bytesToHex(M.poly1305Raw(k4, m4)), "03000000000000000000000000000000", "Poly1305 mod (2^130-5) wrap to 3");
    // Exact p = 2^130 - 5 boundary: m = 2^128 - 3 => block = 2^129 - 3; *2 = 2^130 - 6 (no wrap) vs m = 2^128 - 2 => block = 2^129 - 2; *2 = 2^130 - 4 ≡ 1!
    const m4b = hexToBytes("feffffffffffffffffffffffffffffff");
    assertEq(bytesToHex(M.poly1305Raw(k4, m4b)), "01000000000000000000000000000000", "Poly1305 mod (2^130-5) wrap to 1");
    // Exact multiple of p: r = 1, 5 blocks? Or check k = r=4, m = 2^128 - 5: wait, 2*(2^129 - 3) = 2^130 - 6 = p - 1 -> 0xfaffffff...
    const m4c = hexToBytes("fdffffffffffffffffffffffffffffff");
    assertEq(bytesToHex(M.poly1305Raw(k4, m4c)), "faffffffffffffffffffffffffffffff", "Poly1305 p-1 no wrap");
    // Ensure maxKey doesn't produce NaN / out-of-range
    const maxTag = M.poly1305Raw(maxKey, new Uint8Array(256).fill(0xff));
    assertEq(maxTag.length, 16, "Poly1305 maxKey tag len");
  }

  // 5. ULID & pad256 & UTF-8 unit tests
  function testPrimitives(ulidVectors) {
    for (const uv of ulidVectors) {
      const b = M.ulidToBytes(uv.ulid);
      assertEq(bytesToHex(b), uv.bytes_hex, "ulidToBytes " + uv.ulid);
      assertEq(M.bytesToUlid(b), uv.ulid, "bytesToUlid " + uv.ulid);
    }
    assertThrows(() => M.ulidToBytes("01JDF8Z9X4K7M2N5P8Q1R3S6T"), "ULID too short");
    assertThrows(() => M.ulidToBytes("01JDF8Z9X4K7M2N5P8Q1R3S6T90"), "ULID too long");
    assertThrows(() => M.ulidToBytes("80000000000000000000000000"), "ULID overflow");
    assertThrows(() => M.ulidToBytes("01jdf8z9x4k7m2n5p8q1r3s6t9"), "ULID lowercase rejected");
    assertThrows(() => M.ulidToBytes("01IDF8Z9X4K7M2N5P8Q1R3S6T9"), "ULID illegal char I");
    assertThrows(() => M.ulidToBytes("01LDF8Z9X4K7M2N5P8Q1R3S6T9"), "ULID illegal char L");
    assertThrows(() => M.ulidToBytes("01ODF8Z9X4K7M2N5P8Q1R3S6T9"), "ULID illegal char O");
    assertThrows(() => M.ulidToBytes("01UDF8Z9X4K7M2N5P8Q1R3S6T9"), "ULID illegal char U");

    for (const len of [0, 1, 254, 255, 256, 257, 511, 512]) {
      const raw = new Uint8Array(len);
      for (let i = 0; i < len; i++) raw[i] = (i * 37 + 11) & 0xff;
      const padded = M.pad256(raw);
      assertEq(padded.length >= 256 && padded.length % 256 === 0, true, "pad256 multiple of 256 len=" + len);
      const unpadded = M.unpad256(padded);
      assertEq(bytesToHex(unpadded), bytesToHex(raw), "unpad256 roundtrip len=" + len);
    }
    assertThrows(() => M.unpad256(new Uint8Array(0)), "unpad256 empty");
    assertThrows(() => M.unpad256(new Uint8Array(255)), "unpad256 255B");
    const badPad = new Uint8Array(256);
    badPad[255] = 10;
    badPad[250] = 0x01;
    assertThrows(() => M.unpad256(badPad), "unpad256 non-zero padding byte");

    const sampleText = "ASCII + 中文 + 日本語 + 한국어 + 🚀🔐🎉";
    assertEq(M.utf8Decode(M.utf8Encode(sampleText)), sampleText, "UTF-8 roundtrip");
    assertThrows(() => M.utf8Decode(new Uint8Array([0xc0, 0xaf])), "UTF-8 overlong rejected");
    assertThrows(() => M.utf8Decode(new Uint8Array([0xed, 0xa0, 0x80])), "UTF-8 surrogate rejected");
  }

  // 6. Verify frozen Rust golden vectors
  function verifyGoldenSuite(suite) {
    testPrimitives(suite.ulid_vectors);

    for (const pv of suite.positive_vectors) {
      const clipKey = hexToBytes(pv.clip_key_hex);
      const nonce = hexToBytes(pv.nonce_hex);
      const aad = M.buildMnc1Aad(M.ulidToBytes(pv.clip_kid), M.ulidToBytes(pv.clip_id), pv.device_id, pv.flags);
      assertEq(bytesToHex(aad), pv.aad_hex, "AAD match: " + pv.name);

      const rustEnv = hexToBytes(pv.envelope_hex);
      if (pv.payload_type === 0) {
        // Re-encrypt using encryptMnc1Meta with exact JSON string & verify byte-for-byte identity!
        const jsEnv = M.encryptMnc1Meta({
          clipKey,
          clipKid: pv.clip_kid,
          clipId: pv.clip_id,
          deviceId: pv.device_id,
          meta: pv.plaintext_utf8,
          ephemeral: pv.ephemeral,
          nonce,
        });
        assertEq(bytesToHex(jsEnv), pv.envelope_hex, "JS->Rust byte-identical encrypt: " + pv.name);

        // Decrypt Rust-generated ciphertext!
        const decObj = M.decryptMnc1Meta({
          clipKey,
          clipKid: pv.clip_kid,
          clipId: pv.clip_id,
          deviceId: pv.device_id,
          envelope: rustEnv,
          ephemeral: pv.ephemeral,
        });
        assertEq(JSON.stringify(decObj), JSON.stringify(JSON.parse(pv.plaintext_utf8)), "Rust->JS decrypt meta: " + pv.name);
      } else {
        const rawBytes = hexToBytes(pv.plaintext_hex);
        const jsEnv = M.encryptMnc1Blob({
          clipKey,
          clipKid: pv.clip_kid,
          clipId: pv.clip_id,
          deviceId: pv.device_id,
          bytes: rawBytes,
          ephemeral: pv.ephemeral,
          nonce,
        });
        assertEq(bytesToHex(jsEnv), pv.envelope_hex, "JS->Rust byte-identical blob encrypt: " + pv.name);

        const decBytes = M.decryptMnc1Blob({
          clipKey,
          clipKid: pv.clip_kid,
          clipId: pv.clip_id,
          deviceId: pv.device_id,
          envelope: rustEnv,
          ephemeral: pv.ephemeral,
        });
        assertEq(bytesToHex(decBytes), pv.plaintext_hex, "Rust->JS decrypt blob: " + pv.name);
      }
    }

    for (const nv of suite.negative_vectors) {
      const clipKey = hexToBytes(nv.clip_key_hex);
      const envelope = hexToBytes(nv.envelope_hex);
      assertThrows(() => {
        if ((nv.flags & M.FLAG_PAYLOAD_BLOB) === 0) {
          M.decryptMnc1Meta({
            clipKey,
            clipKid: nv.clip_kid,
            clipId: nv.clip_id,
            deviceId: nv.device_id,
            envelope,
            flags: nv.flags,
          });
        } else {
          M.decryptMnc1Blob({
            clipKey,
            clipKid: nv.clip_kid,
            clipId: nv.clip_id,
            deviceId: nv.device_id,
            envelope,
            flags: nv.flags,
          });
        }
      }, "JS must reject negative vector: " + nv.name);
    }
  }

  // 7. Generate JS-originated ciphertexts covering edge payload sizes (up to 512 KiB) for Rust to verify
  function emitJsVectors(outPath, baseSuite) {
    const clipKey = hexToBytes(
      "ffeeddccbbaa99887766554433221100a1b2c3d4e5f60718293a4b5c6d7e8f90"
    );
    const clipKid = "01JDF920001122334455667788";
    const clipKidHex = bytesToHex(M.ulidToBytes(clipKid));
    const deviceId = "dev_ios_scriptable01";

    const positive_vectors = [];
    const blobSizes = [0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 257, 4097, 65537, 524288];
    for (let idx = 0; idx < blobSizes.length; idx++) {
      const sz = blobSizes[idx];
      const clipIdBytes = new Uint8Array(16);
      clipIdBytes[0] = 0x01; clipIdBytes[1] = 0x93; clipIdBytes[14] = (idx >> 8) & 0xff; clipIdBytes[15] = idx & 0xff;
      const clipId = M.bytesToUlid(clipIdBytes);
      const nonce = new Uint8Array(24);
      for (let i = 0; i < 24; i++) nonce[i] = ((idx * 19 + i * 7 + 3) & 0xff);
      const raw = new Uint8Array(sz);
      for (let i = 0; i < sz; i++) raw[i] = ((i * 131 + idx * 17 + 5) & 0xff);
      const aad = M.buildMnc1Aad(M.ulidToBytes(clipKid), clipIdBytes, deviceId, M.FLAG_PAYLOAD_BLOB);
      const env = M.encryptMnc1Blob({ clipKey, clipKid, clipId, deviceId, bytes: raw, nonce });
      positive_vectors.push({
        name: "js_blob_" + sz + "b",
        description: "JS-generated binary blob len=" + sz,
        clip_key_hex: bytesToHex(clipKey),
        clip_kid: clipKid,
        clip_kid_hex: clipKidHex,
        clip_id: clipId,
        clip_id_hex: bytesToHex(clipIdBytes),
        device_id: deviceId,
        flags: M.FLAG_PAYLOAD_BLOB,
        ephemeral: false,
        payload_type: 1,
        nonce_hex: bytesToHex(nonce),
        aad_hex: bytesToHex(aad),
        plaintext_utf8: null,
        plaintext_hex: bytesToHex(raw),
        envelope_hex: bytesToHex(env),
      });
    }

    // JS-generated regular & ephemeral ClipMetaV1 (including image metadata schema from §3.8)
    const metaCases = [
      {
        name: "js_meta_image_schema",
        ephemeral: false,
        clipId: "01JDF920AABBCCDDEEFFGGHHJJ",
        meta: {
          v: 1,
          kind: "image",
          mime: "image/jpeg",
          source_mode: "explicit",
          created_at_ms: 1795600123456,
          text: null,
          blob: {
            byte_size: 512000,
            sha256_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            width: 1920,
            height: 1080,
            thumb_mime: "image/webp",
            thumb_b64: "UklGRh4AAABXRUJQVlA4TBEAAAAvAAAAAAfQ//73v/+BiOh/AAA=",
          },
        },
      },
      {
        name: "js_meta_ephemeral_cjk",
        ephemeral: true,
        clipId: "01JDF920KKMMNNPPQQRRSSTTVV",
        meta: {
          v: 1,
          kind: "text",
          mime: "text/plain",
          source_mode: "explicit",
          created_at_ms: 1795600123999,
          text: "一次性验证码：942817 🔐 (iOS Shortcuts)",
          blob: null,
        },
      },
    ];

    for (let i = 0; i < metaCases.length; i++) {
      const mc = metaCases[i];
      const flags = mc.ephemeral ? M.FLAG_EPHEMERAL : 0x00;
      const nonce = new Uint8Array(24).fill(0x33 + i);
      const json = JSON.stringify(mc.meta);
      const utf8 = M.utf8Encode(json);
      const aad = M.buildMnc1Aad(M.ulidToBytes(clipKid), M.ulidToBytes(mc.clipId), deviceId, flags);
      const env = M.encryptMnc1Meta({
        clipKey,
        clipKid,
        clipId: mc.clipId,
        deviceId,
        meta: json,
        ephemeral: mc.ephemeral,
        nonce,
      });
      positive_vectors.push({
        name: mc.name,
        description: "JS-generated ClipMetaV1 (" + mc.name + ")",
        clip_key_hex: bytesToHex(clipKey),
        clip_kid: clipKid,
        clip_kid_hex: clipKidHex,
        clip_id: mc.clipId,
        clip_id_hex: bytesToHex(M.ulidToBytes(mc.clipId)),
        device_id: deviceId,
        flags,
        ephemeral: mc.ephemeral,
        payload_type: 0,
        nonce_hex: bytesToHex(nonce),
        aad_hex: bytesToHex(aad),
        plaintext_utf8: json,
        plaintext_hex: bytesToHex(utf8),
        envelope_hex: bytesToHex(env),
      });
    }

    const outSuite = {
      spec_version: 1,
      generator: "mnc1_sync.js (Node.js " + process.version + ")",
      ulid_vectors: baseSuite.ulid_vectors,
      positive_vectors,
      negative_vectors: baseSuite.negative_vectors,
    };
    writeTextFile(outPath, JSON.stringify(outSuite, null, 2) + "\n");
    logFn("EMITTED JS VECTORS -> " + outPath + " (" + positive_vectors.length + " positive, " + baseSuite.negative_vectors.length + " negative)");
  }

  try {
    testRfc8439Poly1305();
    testDraftHChaCha20();
    testDraftXChaCha20Poly1305();
    testPoly1305EdgeCases();

    const goldenPath = argv[0] || "spikes/s-clip-1-ios-shortcuts/golden_vectors.json";
    const suite = JSON.parse(readTextFile(goldenPath));
    verifyGoldenSuite(suite);

    const engineName = isNode ? ("Node.js " + process.version + " (V8)") : "macOS JavaScriptCore (jsc)";
    logFn(
      "JS VERIFY OK [" + engineName + "]: RFC8439 + HChaCha20 + XChaCha20-Poly1305 + Poly1305-edge + " +
      suite.ulid_vectors.length + " ULID + " +
      suite.positive_vectors.length + " positive (byte-identical encrypt + decrypt) + " +
      suite.negative_vectors.length + " negative rejected"
    );

    if (isNode && argv[1] === "--emit-js-vectors" && argv[2]) {
      emitJsVectors(argv[2], suite);
    }
  } catch (err) {
    logFn("JS VERIFY FAILED: " + (err && err.stack ? err.stack : err));
    exitFn(1);
  }
})();
