use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

const MAGIC_MNC1: &[u8; 4] = b"MNC1";
const WIRE_VERSION: u8 = 0x01;
const HEADER_LEN: usize = 4 + 1 + 16 + 24; // 45 bytes
const AEAD_TAG_LEN: usize = 16;

const FLAG_EPHEMERAL: u8 = 0x01;
const FLAG_PAYLOAD_BLOB: u8 = 0x02;
const FLAGS_RESERVED_MASK: u8 = 0xFC;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'H' => Some(b - b'A' + 10),
        b'J'..=b'K' => Some(b - b'J' + 18),
        b'M'..=b'N' => Some(b - b'M' + 20),
        b'P'..=b'T' => Some(b - b'P' + 22),
        b'V'..=b'Z' => Some(b - b'V' + 27),
        _ => None,
    }
}

/// Exact copy of `crates/mynote-core/src/ids.rs` `Ulid::parse`.
fn ulid_parse(s: &str) -> Result<[u8; 16], String> {
    let bytes = s.as_bytes();
    if bytes.len() != 26 {
        return Err(format!("invalid ULID length {}: expected 26", bytes.len()));
    }
    let first = crockford_val(bytes[0]).ok_or_else(|| format!("invalid ULID char in '{s}'"))?;
    if first > 7 {
        return Err(format!("ULID overflow in '{s}'"));
    }
    let mut val: u128 = first as u128;
    for &b in &bytes[1..] {
        let v = crockford_val(b).ok_or_else(|| format!("invalid ULID char in '{s}'"))?;
        val = (val << 5) | (v as u128);
    }
    Ok(val.to_be_bytes())
}

/// Exact copy of `crates/mynote-core/src/ids.rs` `Ulid::encode`.
fn ulid_encode(raw: &[u8; 16]) -> String {
    let val = u128::from_be_bytes(*raw);
    let mut out = [0u8; 26];
    for (i, slot) in out.iter_mut().enumerate() {
        let shift = (25 - i) * 5;
        *slot = CROCKFORD[((val >> shift) & 0x1F) as usize];
    }
    String::from_utf8(out.to_vec()).expect("ASCII")
}

/// Exact copy of `crates/mynote-core/src/crypto.rs` `pad256` (`docs/data-structures.md` §3.1).
fn pad256(raw: &[u8]) -> Vec<u8> {
    let pad_zeros = (256 - ((raw.len() + 1) % 256)) % 256;
    let mut out = Vec::with_capacity(raw.len() + pad_zeros + 1);
    out.extend_from_slice(raw);
    out.resize(raw.len() + pad_zeros, 0u8);
    out.push(pad_zeros as u8);
    out
}

/// Exact copy of `crates/mynote-core/src/crypto.rs` `unpad256` (`docs/data-structures.md` §3.1).
fn unpad256(padded: &[u8]) -> Result<&[u8], String> {
    if padded.len() < 256 || !padded.len().is_multiple_of(256) {
        return Err(format!("invalid padded length {}", padded.len()));
    }
    let p = padded[padded.len() - 1] as usize;
    if p + 1 > padded.len() {
        return Err("padding length exceeds frame".to_string());
    }
    let data_end = padded.len() - 1 - p;
    if padded[data_end..padded.len() - 1].iter().any(|&b| b != 0) {
        return Err("non-canonical non-zero padding byte detected".to_string());
    }
    Ok(&padded[..data_end])
}

/// Exact MNC1 AAD (`docs/data-structures.md` §3.3):
/// `"MNC1" || 0x01 || clip_kid (16B) || clip_id (16B) || device_id.as_bytes() || flags (1B)`
fn aad_mnc1(clip_kid: &[u8; 16], clip_id: &[u8; 16], device_id: &str, flags: u8) -> Result<Vec<u8>, String> {
    if flags & FLAGS_RESERVED_MASK != 0 {
        return Err(format!("non-zero reserved bits in flags: 0x{flags:02x}"));
    }
    let dev = device_id.as_bytes();
    let mut aad = Vec::with_capacity(4 + 1 + 16 + 16 + dev.len() + 1);
    aad.extend_from_slice(MAGIC_MNC1);
    aad.push(WIRE_VERSION);
    aad.extend_from_slice(clip_kid);
    aad.extend_from_slice(clip_id);
    aad.extend_from_slice(dev);
    aad.push(flags);
    Ok(aad)
}

fn encrypt_mnc1_raw(
    clip_key: &[u8; 32],
    clip_kid: &[u8; 16],
    clip_id: &[u8; 16],
    device_id: &str,
    flags: u8,
    nonce: [u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let aad = aad_mnc1(clip_kid, clip_id, device_id, flags)?;
    let cipher = XChaCha20Poly1305::new(clip_key.into());
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| "XChaCha20-Poly1305 encryption failed".to_string())?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC_MNC1);
    out.push(WIRE_VERSION);
    out.extend_from_slice(clip_kid);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn encrypt_mnc1_unchecked_flags_for_neg_test(
    clip_key: &[u8; 32],
    clip_kid: &[u8; 16],
    clip_id: &[u8; 16],
    device_id: &str,
    flags: u8,
    nonce: [u8; 24],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(MAGIC_MNC1);
    aad.push(WIRE_VERSION);
    aad.extend_from_slice(clip_kid);
    aad.extend_from_slice(clip_id);
    aad.extend_from_slice(device_id.as_bytes());
    aad.push(flags);
    let cipher = XChaCha20Poly1305::new(clip_key.into());
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: &aad })
        .expect("encrypt neg vector");
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC_MNC1);
    out.push(WIRE_VERSION);
    out.extend_from_slice(clip_kid);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn decrypt_mnc1(
    clip_key: &[u8; 32],
    expected_clip_kid: &[u8; 16],
    clip_id: &[u8; 16],
    device_id: &str,
    flags: u8,
    envelope: &[u8],
) -> Result<Vec<u8>, String> {
    if flags & FLAGS_RESERVED_MASK != 0 {
        return Err(format!("non-zero reserved bits in flags: 0x{flags:02x}"));
    }
    if envelope.len() < HEADER_LEN + AEAD_TAG_LEN {
        return Err("envelope truncated".to_string());
    }
    if &envelope[0..4] != MAGIC_MNC1 {
        return Err("envelope magic mismatch".to_string());
    }
    if envelope[4] != WIRE_VERSION {
        return Err(format!("unsupported envelope version {}", envelope[4]));
    }
    if &envelope[5..21] != expected_clip_kid {
        return Err("envelope header clip_kid mismatch".to_string());
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&envelope[21..45]);
    let aad = aad_mnc1(expected_clip_kid, clip_id, device_id, flags)?;
    let cipher = XChaCha20Poly1305::new(clip_key.into());
    let pt = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &envelope[45..],
                aad: &aad,
            },
        )
        .map_err(|_| "AEAD tag or AAD verification failed".to_string())?;
    if flags & FLAG_PAYLOAD_BLOB == 0 {
        let unpadded = unpad256(&pt)?;
        Ok(unpadded.to_vec())
    } else {
        Ok(pt)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16).ok_or("bad hex")? as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or("bad hex")? as u8;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn from_hex_arr<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = from_hex(s)?;
    v.try_into().map_err(|_| format!("expected {N} bytes"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PositiveVector {
    name: String,
    description: String,
    clip_key_hex: String,
    clip_kid: String,
    clip_kid_hex: String,
    clip_id: String,
    clip_id_hex: String,
    device_id: String,
    flags: u8,
    ephemeral: bool,
    payload_type: u8,
    nonce_hex: String,
    aad_hex: String,
    plaintext_utf8: Option<String>,
    plaintext_hex: String,
    envelope_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NegativeVector {
    name: String,
    reason: String,
    clip_key_hex: String,
    clip_kid: String,
    clip_id: String,
    device_id: String,
    flags: u8,
    envelope_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UlidVector {
    ulid: String,
    bytes_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoldenVectorSuite {
    spec_version: u8,
    generator: String,
    ulid_vectors: Vec<UlidVector>,
    positive_vectors: Vec<PositiveVector>,
    negative_vectors: Vec<NegativeVector>,
}

/// Deterministic minimal valid 1x1 PNG + extra deterministic binary bytes to test binary blob path.
fn sample_png_bytes() -> Vec<u8> {
    let mut png: Vec<u8> = vec![
        // 8-byte PNG signature
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        // IHDR chunk (13 bytes: 1x1 RGBA)
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89,
        // IDAT chunk
        0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54,
        0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
        0x0D, 0x0A, 0x2D, 0xB4,
        // IEND chunk
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
        0xAE, 0x42, 0x60, 0x82,
    ];
    // Deterministic 519-byte non-16-aligned binary payload is also tested separately; keep sample_png exact valid PNG.
    png.shrink_to_fit();
    png
}

fn generate_suite() -> GoldenVectorSuite {
    let clip_key: [u8; 32] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    ];
    let clip_kid_str = "01JDF8Z9X4K7M2N5P8Q1R3S6T9";
    let clip_kid = ulid_parse(clip_kid_str).unwrap();
    let device_id = "dev_01jdf8z9x4k7m2n5";

    let ulid_samples = [
        "00000000000000000000000000",
        "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ];
    let ulid_vectors: Vec<UlidVector> = ulid_samples
        .iter()
        .map(|u| {
            let b = ulid_parse(u).unwrap();
            assert_eq!(ulid_encode(&b), *u);
            UlidVector {
                ulid: (*u).to_string(),
                bytes_hex: to_hex(&b),
            }
        })
        .collect();

    let mut positive_vectors = Vec::new();

    // (a) payload_type=0, ephemeral=0: regular ClipMetaV1 text item (ASCII + CJK + Emoji)
    let clip_id_a_str = "01JDF910A1B2C3D4E5F6G7H8J9";
    let clip_id_a = ulid_parse(clip_id_a_str).unwrap();
    let nonce_a: [u8; 24] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    ];
    let meta_a = serde_json::json!({
        "v": 1,
        "kind": "text",
        "mime": "text/plain",
        "source_mode": "explicit",
        "created_at_ms": 1795600000123_i64,
        "text": "hello my-note 剪贴板同步 🚀 line1\nline2",
        "blob": null
    })
    .to_string();
    let padded_a = pad256(meta_a.as_bytes());
    let aad_a = aad_mnc1(&clip_kid, &clip_id_a, device_id, 0x00).unwrap();
    let env_a = encrypt_mnc1_raw(&clip_key, &clip_kid, &clip_id_a, device_id, 0x00, nonce_a, &padded_a).unwrap();
    assert_eq!(
        decrypt_mnc1(&clip_key, &clip_kid, &clip_id_a, device_id, 0x00, &env_a).unwrap(),
        meta_a.as_bytes()
    );
    positive_vectors.push(PositiveVector {
        name: "meta_text_regular".to_string(),
        description: "payload_type=0, ephemeral=0: ClipMetaV1 text with ASCII + CJK + Emoji".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_kid_hex: to_hex(&clip_kid),
        clip_id: clip_id_a_str.to_string(),
        clip_id_hex: to_hex(&clip_id_a),
        device_id: device_id.to_string(),
        flags: 0x00,
        ephemeral: false,
        payload_type: 0,
        nonce_hex: to_hex(&nonce_a),
        aad_hex: to_hex(&aad_a),
        plaintext_utf8: Some(meta_a.clone()),
        plaintext_hex: to_hex(meta_a.as_bytes()),
        envelope_hex: to_hex(&env_a),
    });

    // (b) payload_type=0, ephemeral=1: ephemeral OTP text item
    let clip_id_b_str = "01JDF910K2M3N4P5Q6R7S8T9V0";
    let clip_id_b = ulid_parse(clip_id_b_str).unwrap();
    let nonce_b: [u8; 24] = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    ];
    let meta_b = serde_json::json!({
        "v": 1,
        "kind": "text",
        "mime": "text/plain",
        "source_mode": "explicit",
        "created_at_ms": 1795600005456_i64,
        "text": "OTP-849201-ephemeral-secret",
        "blob": null
    })
    .to_string();
    let padded_b = pad256(meta_b.as_bytes());
    let aad_b = aad_mnc1(&clip_kid, &clip_id_b, device_id, FLAG_EPHEMERAL).unwrap();
    let env_b = encrypt_mnc1_raw(&clip_key, &clip_kid, &clip_id_b, device_id, FLAG_EPHEMERAL, nonce_b, &padded_b).unwrap();
    assert_eq!(
        decrypt_mnc1(&clip_key, &clip_kid, &clip_id_b, device_id, FLAG_EPHEMERAL, &env_b).unwrap(),
        meta_b.as_bytes()
    );
    positive_vectors.push(PositiveVector {
        name: "meta_text_ephemeral".to_string(),
        description: "payload_type=0, ephemeral=1: ephemeral ClipMetaV1 text item".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_kid_hex: to_hex(&clip_kid),
        clip_id: clip_id_b_str.to_string(),
        clip_id_hex: to_hex(&clip_id_b),
        device_id: device_id.to_string(),
        flags: FLAG_EPHEMERAL,
        ephemeral: true,
        payload_type: 0,
        nonce_hex: to_hex(&nonce_b),
        aad_hex: to_hex(&aad_b),
        plaintext_utf8: Some(meta_b.clone()),
        plaintext_hex: to_hex(meta_b.as_bytes()),
        envelope_hex: to_hex(&env_b),
    });

    // (c1) payload_type=1, ephemeral=0: binary PNG bytes (NO pad256, NO JSON wrapper)
    let clip_id_c_str = "01JDF910W1X2Y3Z40516273849";
    let clip_id_c = ulid_parse(clip_id_c_str).unwrap();
    let nonce_c: [u8; 24] = [
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    ];
    let png_bytes = sample_png_bytes();
    let aad_c = aad_mnc1(&clip_kid, &clip_id_c, device_id, FLAG_PAYLOAD_BLOB).unwrap();
    let env_c = encrypt_mnc1_raw(&clip_key, &clip_kid, &clip_id_c, device_id, FLAG_PAYLOAD_BLOB, nonce_c, &png_bytes).unwrap();
    assert_eq!(env_c.len(), HEADER_LEN + png_bytes.len() + AEAD_TAG_LEN);
    assert_eq!(
        decrypt_mnc1(&clip_key, &clip_kid, &clip_id_c, device_id, FLAG_PAYLOAD_BLOB, &env_c).unwrap(),
        png_bytes
    );
    positive_vectors.push(PositiveVector {
        name: "blob_png_binary".to_string(),
        description: "payload_type=1, ephemeral=0: raw binary PNG stream (67B, unpadded, non-16B aligned)".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_kid_hex: to_hex(&clip_kid),
        clip_id: clip_id_c_str.to_string(),
        clip_id_hex: to_hex(&clip_id_c),
        device_id: device_id.to_string(),
        flags: FLAG_PAYLOAD_BLOB,
        ephemeral: false,
        payload_type: 1,
        nonce_hex: to_hex(&nonce_c),
        aad_hex: to_hex(&aad_c),
        plaintext_utf8: None,
        plaintext_hex: to_hex(&png_bytes),
        envelope_hex: to_hex(&env_c),
    });

    // (c2) payload_type=1, ephemeral=0: multi-block 1029B deterministic binary blob (exercises ChaCha20 multi-block + Poly1305)
    let clip_id_c2_str = "01JDF9110A1B2C3D4E5F6G7H8J";
    let clip_id_c2 = ulid_parse(clip_id_c2_str).unwrap();
    let nonce_c2: [u8; 24] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    ];
    let mut big_blob = Vec::with_capacity(1029);
    for i in 0..1029usize {
        big_blob.push(((i * 73 + 19) & 0xff) as u8);
    }
    let aad_c2 = aad_mnc1(&clip_kid, &clip_id_c2, device_id, FLAG_PAYLOAD_BLOB).unwrap();
    let env_c2 = encrypt_mnc1_raw(&clip_key, &clip_kid, &clip_id_c2, device_id, FLAG_PAYLOAD_BLOB, nonce_c2, &big_blob).unwrap();
    assert_eq!(
        decrypt_mnc1(&clip_key, &clip_kid, &clip_id_c2, device_id, FLAG_PAYLOAD_BLOB, &env_c2).unwrap(),
        big_blob
    );
    positive_vectors.push(PositiveVector {
        name: "blob_multiblock_1029b".to_string(),
        description: "payload_type=1, ephemeral=0: 1029B deterministic binary stream (17 ChaCha20 blocks)".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_kid_hex: to_hex(&clip_kid),
        clip_id: clip_id_c2_str.to_string(),
        clip_id_hex: to_hex(&clip_id_c2),
        device_id: device_id.to_string(),
        flags: FLAG_PAYLOAD_BLOB,
        ephemeral: false,
        payload_type: 1,
        nonce_hex: to_hex(&nonce_c2),
        aad_hex: to_hex(&aad_c2),
        plaintext_utf8: None,
        plaintext_hex: to_hex(&big_blob),
        envelope_hex: to_hex(&env_c2),
    });

    // (c3) payload_type=0, ephemeral=0: exact 255-byte JSON boundary (pad_zeros = 0 -> 256B frame)
    let clip_id_c3_str = "01JDF911K9M8N7P6Q5R4S3T2V1";
    let clip_id_c3 = ulid_parse(clip_id_c3_str).unwrap();
    let nonce_c3: [u8; 24] = [0x5a; 24];
    let prefix = r#"{"v":1,"kind":"text","mime":"text/plain","source_mode":"explicit","created_at_ms":1795600009999,"blob":null,"text":""#;
    let suffix = r#""}"#;
    let fill_len = 255 - prefix.len() - suffix.len();
    let meta_255 = format!("{}{}{}", prefix, "A".repeat(fill_len), suffix);
    assert_eq!(meta_255.len(), 255);
    let padded_255 = pad256(meta_255.as_bytes());
    assert_eq!(padded_255.len(), 256);
    assert_eq!(*padded_255.last().unwrap(), 0);
    let aad_c3 = aad_mnc1(&clip_kid, &clip_id_c3, device_id, 0x00).unwrap();
    let env_c3 = encrypt_mnc1_raw(&clip_key, &clip_kid, &clip_id_c3, device_id, 0x00, nonce_c3, &padded_255).unwrap();
    positive_vectors.push(PositiveVector {
        name: "meta_pad256_boundary_255b".to_string(),
        description: "payload_type=0, ephemeral=0: exact 255B UTF-8 JSON boundary (pad_zeros=0 -> 256B)".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_kid_hex: to_hex(&clip_kid),
        clip_id: clip_id_c3_str.to_string(),
        clip_id_hex: to_hex(&clip_id_c3),
        device_id: device_id.to_string(),
        flags: 0x00,
        ephemeral: false,
        payload_type: 0,
        nonce_hex: to_hex(&nonce_c3),
        aad_hex: to_hex(&aad_c3),
        plaintext_utf8: Some(meta_255.clone()),
        plaintext_hex: to_hex(meta_255.as_bytes()),
        envelope_hex: to_hex(&env_c3),
    });

    // (d) Negative vectors
    let mut negative_vectors = vec![
        // 1. Tampered AAD: wrong clip_id
        NegativeVector {
            name: "tampered_aad_clip_id".to_string(),
            reason: "AAD clip_id mismatch must fail Poly1305 verification".to_string(),
            clip_key_hex: to_hex(&clip_key),
            clip_kid: clip_kid_str.to_string(),
            clip_id: clip_id_b_str.to_string(), // encrypted with clip_id_a
            device_id: device_id.to_string(),
            flags: 0x00,
            envelope_hex: to_hex(&env_a),
        },
        // 2. Tampered AAD: wrong device_id
        NegativeVector {
            name: "tampered_aad_device_id".to_string(),
            reason: "AAD device_id mismatch must fail Poly1305 verification".to_string(),
            clip_key_hex: to_hex(&clip_key),
            clip_kid: clip_kid_str.to_string(),
            clip_id: clip_id_a_str.to_string(),
            device_id: "dev_otherdevice0001".to_string(),
            flags: 0x00,
            envelope_hex: to_hex(&env_a),
        },
        // 3. Tampered AAD: wrong flags (ephemeral downgrade/upgrade)
        NegativeVector {
            name: "tampered_aad_flags_ephemeral".to_string(),
            reason: "AAD flags mismatch (ephemeral=0 ciphertext decrypted as ephemeral=1)".to_string(),
            clip_key_hex: to_hex(&clip_key),
            clip_kid: clip_kid_str.to_string(),
            clip_id: clip_id_a_str.to_string(),
            device_id: device_id.to_string(),
            flags: FLAG_EPHEMERAL,
            envelope_hex: to_hex(&env_a),
        },
        // 4. Tampered AAD: payload_type swap
        NegativeVector {
            name: "tampered_aad_flags_payload_type".to_string(),
            reason: "AAD flags mismatch (payload_type=1 blob decrypted as payload_type=0)".to_string(),
            clip_key_hex: to_hex(&clip_key),
            clip_kid: clip_kid_str.to_string(),
            clip_id: clip_id_c_str.to_string(),
            device_id: device_id.to_string(),
            flags: 0x00,
            envelope_hex: to_hex(&env_c),
        },
    ];

    // 5. Tampered Poly1305 tag (1-bit flip in last byte)
    let mut env_bad_tag = env_a.clone();
    *env_bad_tag.last_mut().unwrap() ^= 0x01;
    negative_vectors.push(NegativeVector {
        name: "tampered_tag_bitflip".to_string(),
        reason: "1-bit flip in Poly1305 tag must fail verification".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_a_str.to_string(),
        device_id: device_id.to_string(),
        flags: 0x00,
        envelope_hex: to_hex(&env_bad_tag),
    });

    // 6. Tampered ciphertext body (1-bit flip at offset 45)
    let mut env_bad_ct = env_c.clone();
    env_bad_ct[45] ^= 0x80;
    negative_vectors.push(NegativeVector {
        name: "tampered_ciphertext_bitflip".to_string(),
        reason: "1-bit flip in ciphertext body must fail verification".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_c_str.to_string(),
        device_id: device_id.to_string(),
        flags: FLAG_PAYLOAD_BLOB,
        envelope_hex: to_hex(&env_bad_ct),
    });

    // 7. Tampered header magic
    let mut env_bad_magic = env_a.clone();
    env_bad_magic[2] = b'S'; // "MNS1"
    negative_vectors.push(NegativeVector {
        name: "tampered_header_magic".to_string(),
        reason: "Wrong header magic (MNS1 instead of MNC1) must be rejected".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_a_str.to_string(),
        device_id: device_id.to_string(),
        flags: 0x00,
        envelope_hex: to_hex(&env_bad_magic),
    });

    // 8. Tampered header version
    let mut env_bad_ver = env_a.clone();
    env_bad_ver[4] = 0x02;
    negative_vectors.push(NegativeVector {
        name: "tampered_header_version".to_string(),
        reason: "Unsupported header version 0x02 must be rejected".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_a_str.to_string(),
        device_id: device_id.to_string(),
        flags: 0x00,
        envelope_hex: to_hex(&env_bad_ver),
    });

    // 9. Non-zero reserved flag bit 2 (0x04) — even with valid AEAD computed using flags=0x04!
    let env_res_04 = encrypt_mnc1_unchecked_flags_for_neg_test(
        &clip_key,
        &clip_kid,
        &clip_id_a,
        device_id,
        0x04,
        nonce_a,
        &padded_a,
    );
    negative_vectors.push(NegativeVector {
        name: "reserved_flag_bit2_0x04".to_string(),
        reason: "Non-zero reserved flag bit 2 (0x04) MUST be rejected even when AEAD tag is valid".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_a_str.to_string(),
        device_id: device_id.to_string(),
        flags: 0x04,
        envelope_hex: to_hex(&env_res_04),
    });

    // 10. Non-zero reserved flag bit 7 (0x82) on blob — even with valid AEAD!
    let env_res_82 = encrypt_mnc1_unchecked_flags_for_neg_test(
        &clip_key,
        &clip_kid,
        &clip_id_c,
        device_id,
        0x82,
        nonce_c,
        &png_bytes,
    );
    negative_vectors.push(NegativeVector {
        name: "reserved_flag_bit7_0x82".to_string(),
        reason: "Non-zero reserved flag bit 7 (0x82) MUST be rejected even when AEAD tag is valid".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_c_str.to_string(),
        device_id: device_id.to_string(),
        flags: 0x82,
        envelope_hex: to_hex(&env_res_82),
    });

    // 11. Non-canonical pad256: non-zero byte inside zero-padding region (valid AEAD!)
    let mut bad_pad_nonzero = pad256(meta_a.as_bytes());
    let len_bp = bad_pad_nonzero.len();
    bad_pad_nonzero[len_bp - 2] = 0x01; // corrupt one zero padding byte before final count byte
    let env_bad_pad_nonzero = encrypt_mnc1_raw(
        &clip_key,
        &clip_kid,
        &clip_id_a,
        device_id,
        0x00,
        nonce_a,
        &bad_pad_nonzero,
    )
    .unwrap();
    negative_vectors.push(NegativeVector {
        name: "non_canonical_pad256_nonzero_byte".to_string(),
        reason: "Valid AEAD over 256B frame with non-zero byte in padding region MUST fail unpad256".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_a_str.to_string(),
        device_id: device_id.to_string(),
        flags: 0x00,
        envelope_hex: to_hex(&env_bad_pad_nonzero),
    });

    // 12. Non-canonical pad256: plaintext length not multiple of 256 (valid AEAD!)
    let env_bad_pad_len = encrypt_mnc1_raw(
        &clip_key,
        &clip_kid,
        &clip_id_a,
        device_id,
        0x00,
        nonce_a,
        meta_a.as_bytes(), // unpadded JSON!
    )
    .unwrap();
    negative_vectors.push(NegativeVector {
        name: "non_canonical_pad256_bad_length".to_string(),
        reason: "Valid AEAD over unpadded payload_type=0 plaintext MUST fail unpad256 length check".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_a_str.to_string(),
        device_id: device_id.to_string(),
        flags: 0x00,
        envelope_hex: to_hex(&env_bad_pad_len),
    });

    // 13. Truncated envelope (< 61 bytes)
    negative_vectors.push(NegativeVector {
        name: "truncated_envelope".to_string(),
        reason: "Envelope shorter than 61 bytes (45B header + 16B tag) MUST be rejected".to_string(),
        clip_key_hex: to_hex(&clip_key),
        clip_kid: clip_kid_str.to_string(),
        clip_id: clip_id_a_str.to_string(),
        device_id: device_id.to_string(),
        flags: 0x00,
        envelope_hex: to_hex(&env_a[..60]),
    });

    // Verify all negative vectors are rejected by Rust itself
    for nv in &negative_vectors {
        let key: [u8; 32] = from_hex_arr(&nv.clip_key_hex).unwrap();
        let kid = ulid_parse(&nv.clip_kid).unwrap();
        let cid = ulid_parse(&nv.clip_id).unwrap();
        let env_bytes = from_hex(&nv.envelope_hex).unwrap();
        let res = decrypt_mnc1(&key, &kid, &cid, &nv.device_id, nv.flags, &env_bytes);
        assert!(
            res.is_err(),
            "Rust MUST reject negative vector '{}', but succeeded!",
            nv.name
        );
    }

    GoldenVectorSuite {
        spec_version: WIRE_VERSION,
        generator: "rust chacha20poly1305 0.11.0 (s-clip-1-rust-interop)".to_string(),
        ulid_vectors,
        positive_vectors,
        negative_vectors,
    }
}

fn verify_suite(path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let suite: GoldenVectorSuite =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;

    for uv in &suite.ulid_vectors {
        let parsed = ulid_parse(&uv.ulid)?;
        let expected: [u8; 16] = from_hex_arr(&uv.bytes_hex)?;
        if parsed != expected {
            return Err(format!("ULID mismatch for {}", uv.ulid));
        }
        if ulid_encode(&parsed) != uv.ulid {
            return Err(format!("ULID roundtrip mismatch for {}", uv.ulid));
        }
    }

    for pv in &suite.positive_vectors {
        let key: [u8; 32] = from_hex_arr(&pv.clip_key_hex)?;
        let kid = ulid_parse(&pv.clip_kid)?;
        let cid = ulid_parse(&pv.clip_id)?;
        let nonce: [u8; 24] = from_hex_arr(&pv.nonce_hex)?;
        let expected_pt = from_hex(&pv.plaintext_hex)?;
        let expected_env = from_hex(&pv.envelope_hex)?;

        // 1. Decrypt the envelope (could be JS-generated!)
        let decrypted = decrypt_mnc1(&key, &kid, &cid, &pv.device_id, pv.flags, &expected_env)
            .map_err(|e| format!("decrypt failed on '{}': {e}", pv.name))?;
        if decrypted != expected_pt {
            return Err(format!("plaintext mismatch on '{}'", pv.name));
        }
        if let Some(ref utf8_expected) = pv.plaintext_utf8 {
            let s = String::from_utf8(decrypted.clone())
                .map_err(|e| format!("UTF-8 decode failed on '{}': {e}", pv.name))?;
            if &s != utf8_expected {
                return Err(format!("UTF-8 string mismatch on '{}'", pv.name));
            }
        }

        // 2. Re-encrypt with Rust and assert byte-for-byte identical ciphertext!
        let to_encrypt = if pv.flags & FLAG_PAYLOAD_BLOB == 0 {
            pad256(&expected_pt)
        } else {
            expected_pt.clone()
        };
        let re_env = encrypt_mnc1_raw(&key, &kid, &cid, &pv.device_id, pv.flags, nonce, &to_encrypt)?;
        if re_env != expected_env {
            return Err(format!(
                "ciphertext byte mismatch on '{}': rust len={} vs input len={}",
                pv.name,
                re_env.len(),
                expected_env.len()
            ));
        }
    }

    for nv in &suite.negative_vectors {
        let key: [u8; 32] = from_hex_arr(&nv.clip_key_hex)?;
        let kid = ulid_parse(&nv.clip_kid)?;
        let cid = ulid_parse(&nv.clip_id)?;
        let env_bytes = from_hex(&nv.envelope_hex)?;
        if decrypt_mnc1(&key, &kid, &cid, &nv.device_id, nv.flags, &env_bytes).is_ok() {
            return Err(format!("Rust accepted negative vector '{}'", nv.name));
        }
    }

    println!(
        "RUST VERIFY OK ({}): {} ULID, {} positive (decrypt + byte-identical re-encrypt), {} negative rejected",
        path.display(),
        suite.ulid_vectors.len(),
        suite.positive_vectors.len(),
        suite.negative_vectors.len()
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <generate|verify> <json-path>", args[0]);
        std::process::exit(2);
    }
    match args[1].as_str() {
        "generate" => {
            let suite = generate_suite();
            let json = serde_json::to_string_pretty(&suite).expect("serialize suite");
            fs::write(&args[2], format!("{json}\n")).expect("write golden vectors");
            println!(
                "GENERATED {} ({} ULID, {} positive, {} negative)",
                args[2],
                suite.ulid_vectors.len(),
                suite.positive_vectors.len(),
                suite.negative_vectors.len()
            );
        }
        "verify" => {
            if let Err(e) = verify_suite(Path::new(&args[2])) {
                eprintln!("RUST VERIFY FAILED: {e}");
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("Unknown subcommand: {other}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_suite_self_consistent() {
        let suite = generate_suite();
        assert_eq!(suite.positive_vectors.len(), 5);
        assert_eq!(suite.negative_vectors.len(), 13);
        for pv in &suite.positive_vectors {
            let key: [u8; 32] = from_hex_arr(&pv.clip_key_hex).unwrap();
            let kid = ulid_parse(&pv.clip_kid).unwrap();
            let cid = ulid_parse(&pv.clip_id).unwrap();
            let env = from_hex(&pv.envelope_hex).unwrap();
            let pt = decrypt_mnc1(&key, &kid, &cid, &pv.device_id, pv.flags, &env).unwrap();
            assert_eq!(to_hex(&pt), pv.plaintext_hex);
        }
    }

    #[test]
    fn pad256_boundaries() {
        for len in [0usize, 1, 254, 255, 256, 257, 511, 512] {
            let raw: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let padded = pad256(&raw);
            assert!(padded.len() >= 256 && padded.len().is_multiple_of(256));
            assert_eq!(unpad256(&padded).unwrap(), raw.as_slice());
        }
    }
}
