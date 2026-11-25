use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::slice;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct BlockPlaintextV1 {
    content: String,
}

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    let _ = Vec::from_raw_parts(ptr, 0, len);
}

/// Real Argon2id derivation writing 32-byte key into `out_ptr`.
/// Returns 0 on success, negative error code on failure.
#[no_mangle]
pub unsafe extern "C" fn derive_argon2id(
    pass_ptr: *const u8,
    pass_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
    out_ptr: *mut u8,
) -> i32 {
    let pass = slice::from_raw_parts(pass_ptr, pass_len);
    let salt = slice::from_raw_parts(salt_ptr, salt_len);
    let out = slice::from_raw_parts_mut(out_ptr, 32);

    let params = match Params::new(m_kib, t_cost, p_cost, Some(32)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = Zeroizing::new([0u8; 32]);
    if argon2.hash_password_into(pass, salt, derived.as_mut()).is_err() {
        return -2;
    }
    out.copy_from_slice(derived.as_ref());
    0
}

/// Exercise XChaCha20-Poly1305 + HKDF-SHA256 + BLAKE3 + X25519 + MessagePack + 256B padding
/// so the linker retains all real code paths used by MNS1/MNB1/MNR1/MNRS/MNVH.
#[no_mangle]
pub unsafe extern "C" fn crypto_roundtrip_smoke(
    key_ptr: *const u8,
    nonce_ptr: *const u8,
    input_ptr: *const u8,
    input_len: usize,
    out_hash_ptr: *mut u8,
) -> i32 {
    let key = slice::from_raw_parts(key_ptr, 32);
    let nonce_bytes = slice::from_raw_parts(nonce_ptr, 24);
    let input = slice::from_raw_parts(input_ptr, input_len);
    let out_hash = slice::from_raw_parts_mut(out_hash_ptr, 32);

    // 1. HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(Some(b"mynote-recovery-v1"), key);
    let mut subkey = Zeroizing::new([0u8; 32]);
    if hk.expand(b"x25519-recovery", subkey.as_mut()).is_err() {
        return -1;
    }

    // 2. X25519 Diffie-Hellman (MNRS sealed box)
    let sk = StaticSecret::from(*subkey);
    let pk = PublicKey::from(&sk);
    let shared = sk.diffie_hellman(&pk);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return -2;
    }

    // 3. MessagePack + optional compression + 256B bijective padding
    let text = String::from_utf8_lossy(input).into_owned();
    let msg = BlockPlaintextV1 { content: text };
    let packed = match rmp_serde::to_vec_named(&msg) {
        Ok(v) => v,
        Err(_) => return -3,
    };

    let compressed = compress_or_pass(&packed);
    let padded = pad256(&compressed);

    // 4. XChaCha20-Poly1305 encrypt & decrypt with AAD
    let cipher = XChaCha20Poly1305::new(shared.as_bytes().into());
    let nonce = XNonce::try_from(nonce_bytes).map_err(|_| -4).unwrap();
    let aad = b"MNB1\x01entity_op_key";
    let ct = match cipher.encrypt(&nonce, Payload { msg: &padded, aad }) {
        Ok(c) => c,
        Err(_) => return -4,
    };
    let pt = match cipher.decrypt(&nonce, Payload { msg: &ct, aad }) {
        Ok(p) => p,
        Err(_) => return -5,
    };

    let unpadded = match unpad256(&pt) {
        Some(u) => u,
        None => return -6,
    };
    let decompressed = match decompress_or_pass(unpadded) {
        Some(d) => d,
        None => return -7,
    };
    let decoded: BlockPlaintextV1 = match rmp_serde::from_slice(&decompressed) {
        Ok(v) => v,
        Err(_) => return -8,
    };

    // 5. Optional Layer 1 formatters
    let final_str = format_smoke(&decoded.content);

    // 6. BLAKE3 digest
    let digest = blake3::hash(final_str.as_bytes());
    out_hash.copy_from_slice(digest.as_bytes());
    final_str.len() as i32
}

fn pad256(raw: &[u8]) -> Vec<u8> {
    let pad_zeros = (256 - ((raw.len() + 1) % 256)) % 256;
    let mut out = Vec::with_capacity(raw.len() + pad_zeros + 1);
    out.extend_from_slice(raw);
    out.resize(raw.len() + pad_zeros, 0u8);
    out.push(pad_zeros as u8);
    out
}

fn unpad256(padded: &[u8]) -> Option<&[u8]> {
    if padded.len() < 256 || padded.len() % 256 != 0 {
        return None;
    }
    let p = *padded.last()? as usize;
    if p + 1 > padded.len() {
        return None;
    }
    let data_end = padded.len() - 1 - p;
    if padded[data_end..padded.len() - 1].iter().any(|&b| b != 0) {
        return None;
    }
    Some(&padded[..data_end])
}

fn compress_or_pass(data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "comp-ruzstd-rw")]
    {
        return ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest);
    }
    #[cfg(all(not(feature = "comp-ruzstd-rw"), feature = "comp-miniz-rw"))]
    {
        return miniz_oxide::deflate::compress_to_vec(data, 6);
    }
    #[cfg(all(not(feature = "comp-ruzstd-rw"), not(feature = "comp-miniz-rw"), feature = "comp-zstd-c"))]
    {
        return zstd::encode_all(data, 3).unwrap_or_default();
    }
    #[cfg(all(not(feature = "comp-ruzstd-rw"), not(feature = "comp-miniz-rw"), not(feature = "comp-zstd-c")))]
    {
        data.to_vec()
    }
}

fn decompress_or_pass(data: &[u8]) -> Option<Vec<u8>> {
    #[cfg(any(feature = "comp-ruzstd-decode", feature = "comp-ruzstd-rw"))]
    {
        use std::io::Read;
        // In decode-only mode, if input isn't a zstd frame (smoke test didn't compress), return it directly
        // while keeping the full StreamingDecoder code path reachable & un-DCE'd.
        if data.len() >= 4 && data[0..4] == [0x28, 0xB5, 0x2F, 0xFD] {
            let mut decoder = ruzstd::decoding::StreamingDecoder::new(data).ok()?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok()?;
            return Some(out);
        }
        return Some(data.to_vec());
    }
    #[cfg(all(not(any(feature = "comp-ruzstd-decode", feature = "comp-ruzstd-rw")), feature = "comp-miniz-rw"))]
    {
        return miniz_oxide::inflate::decompress_to_vec(data).ok();
    }
    #[cfg(all(not(any(feature = "comp-ruzstd-decode", feature = "comp-ruzstd-rw")), not(feature = "comp-miniz-rw"), feature = "comp-zstd-c"))]
    {
        return zstd::decode_all(data).ok();
    }
    #[cfg(all(not(any(feature = "comp-ruzstd-decode", feature = "comp-ruzstd-rw")), not(feature = "comp-miniz-rw"), not(feature = "comp-zstd-c")))]
    {
        Some(data.to_vec())
    }
}

fn format_smoke(input: &str) -> String {
    #[cfg(feature = "fmt-layer1")]
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(input) {
            if let Ok(s) = serde_json::to_string_pretty(&v) {
                return s;
            }
        }
        if let Ok(v) = toml::from_str::<toml::Value>(input) {
            if let Ok(s) = toml::to_string_pretty(&v) {
                return s;
            }
        }
        if let Ok(v) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(input) {
            if let Ok(s) = serde_yaml_ng::to_string(&v) {
                return s;
            }
        }
        if input.trim_start().starts_with('<') {
            let mut reader = quick_xml::Reader::from_str(input);
            let mut count = 0usize;
            let mut buf = Vec::new();
            while let Ok(ev) = reader.read_event_into(&mut buf) {
                if matches!(ev, quick_xml::events::Event::Eof) {
                    break;
                }
                count += 1;
                buf.clear();
            }
            if count > 0 {
                return input.to_string();
            }
        }
        return sqlformat::format(input, &sqlformat::QueryParams::None, &sqlformat::FormatOptions::default());
    }
    #[cfg(not(feature = "fmt-layer1"))]
    {
        input.to_string()
    }
}

#[cfg(all(test, feature = "comp-ruzstd-rw", feature = "comp-zstd-c"))]
mod interop_tests {
    use std::io::Read;

    #[test]
    fn ruzstd_and_native_zstd_frames_are_mutually_compatible() {
        let samples = [
            b"".as_slice(),
            b"hello my-note",
            &b"{\"key\":\"value\",\"list\":[1,2,3]}\n".repeat(500),
            &"中文与Emoji 🚀 块内容测试\n".repeat(200).into_bytes(),
        ];
        for sample in samples {
            // 1. Native C zstd compress -> pure-Rust ruzstd decompress (Desktop -> Mobile PWA)
            let c_compressed = zstd::encode_all(sample, 3).expect("zstd encode");
            let mut dec = ruzstd::decoding::StreamingDecoder::new(c_compressed.as_slice()).expect("ruzstd init");
            let mut dec_out = Vec::new();
            dec.read_to_end(&mut dec_out).expect("ruzstd decode");
            assert_eq!(dec_out.as_slice(), sample, "native zstd -> ruzstd mismatch");

            // 2. Pure-Rust ruzstd compress -> native C zstd decompress (Desktop WASM Tier 2 -> Desktop Daemon/CLI)
            let rust_compressed = ruzstd::encoding::compress_to_vec(sample, ruzstd::encoding::CompressionLevel::Fastest);
            let c_dec = zstd::decode_all(rust_compressed.as_slice()).expect("zstd decode");
            assert_eq!(c_dec.as_slice(), sample, "ruzstd -> native zstd mismatch");
        }
    }
}

