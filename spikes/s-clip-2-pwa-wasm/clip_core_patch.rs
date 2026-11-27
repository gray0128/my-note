//! S-Clip-2 prototype for `mynote_core::clip` (`MNC1` dual-payload codec).
//!
//! SSOT references:
//! - Envelope & AAD: `docs/data-structures.md` §3.2, §3.3, §3.8
//! - Limits & bitmap MIME whitelist: `docs/data-structures.md` §3.8, `AGENTS.md` §3.3

use crate::crypto::{pad256, unpad256, WIRE_VERSION};
use crate::error::{CoreError, ErrorCode};
use crate::ids::{DeviceId, Ulid};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const MAGIC_MNC1: &[u8; 4] = b"MNC1";
pub const MNC1_HEADER_LEN: usize = 4 + 1 + 16 + 24; // 45 bytes
pub const MNC1_TAG_LEN: usize = 16;

/// `flags` bitmask (`docs/data-structures.md` §3.8).
pub const CLIP_FLAG_EPHEMERAL: u8 = 0x01;
pub const CLIP_FLAG_BLOB_PAYLOAD: u8 = 0x02;
pub const CLIP_FLAGS_RESERVED_MASK: u8 = !(CLIP_FLAG_EPHEMERAL | CLIP_FLAG_BLOB_PAYLOAD);

/// Hard upper bound for a single clipboard blob payload (`10 MiB`, D8 / Q2).
pub const MAX_CLIP_BLOB_BYTES: usize = 10 * 1024 * 1024;
/// Hard upper bound for ephemeral direct-push metadata JSON (`256 KiB`, D8).
pub const MAX_EPHEMERAL_META_BYTES: usize = 256 * 1024;
/// Hard upper bound for regular DO-inlined metadata JSON (`96 KiB`, `docs/interface-contracts.md` §4.2(7)).
pub const MAX_REGULAR_META_BYTES: usize = 96 * 1024;

/// Strictly allowed bitmap image MIME types (`image/svg+xml` is ALWAYS rejected, T4 / SEC-06 / SEC-09).
pub const ALLOWED_CLIP_IMAGE_MIMES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipBlobMetaV1 {
    pub byte_size: u64,
    pub sha256_hex: String,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub thumb_mime: Option<String>,
    #[serde(default)]
    pub thumb_b64: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipMetaV1 {
    pub v: u8,
    pub kind: String,
    pub mime: String,
    pub source_mode: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub blob: Option<ClipBlobMetaV1>,
}

fn clip_integrity_err(msg: impl Into<String>) -> CoreError {
    CoreError::new(
        ErrorCode::IntegrityError,
        msg,
        "MNC1 clipboard envelope authentication or format check failed",
    )
}

fn clip_arg_err(msg: impl Into<String>) -> CoreError {
    CoreError::new(
        ErrorCode::InvalidArgument,
        msg,
        "Check clipboard payload kind, MIME whitelist, and 10 MiB limit",
    )
}

/// Validate `ClipMetaV1` invariants, including strict bitmap MIME whitelist (rejecting `image/svg+xml`).
pub fn validate_clip_meta(meta: &ClipMetaV1) -> Result<(), CoreError> {
    if meta.v != 1 {
        return Err(clip_arg_err(format!("unsupported ClipMetaV1 version {}", meta.v)));
    }
    if meta.source_mode != "explicit" && meta.source_mode != "auto" {
        return Err(clip_arg_err(format!("invalid source_mode '{}'", meta.source_mode)));
    }
    match meta.kind.as_str() {
        "text" => {
            if meta.mime != "text/plain" {
                return Err(clip_arg_err(format!(
                    "text clip must use mime 'text/plain', got '{}'",
                    meta.mime
                )));
            }
        }
        "image" => {
            if !ALLOWED_CLIP_IMAGE_MIMES.contains(&meta.mime.as_str()) {
                return Err(clip_arg_err(format!(
                    "disallowed image mime '{}' (only png/jpeg/webp/gif allowed; SVG must sync as text/plain)",
                    meta.mime
                )));
            }
            if let Some(blob) = &meta.blob {
                if blob.byte_size as usize > MAX_CLIP_BLOB_BYTES {
                    return Err(clip_arg_err(format!(
                        "image blob byte_size {} exceeds 10 MiB limit",
                        blob.byte_size
                    )));
                }
                if let Some(tm) = &blob.thumb_mime {
                    if !ALLOWED_CLIP_IMAGE_MIMES.contains(&tm.as_str()) {
                        return Err(clip_arg_err(format!("disallowed thumb_mime '{tm}'")));
                    }
                }
            }
        }
        other => {
            return Err(clip_arg_err(format!("invalid clip kind '{other}'")));
        }
    }
    Ok(())
}

/// Canonical `MNC1` AAD (`docs/data-structures.md` §3.3):
/// `"MNC1" || 0x01 || clip_kid (16B) || clip_id (16B) || device_id.as_bytes() || flags (1B)`
pub fn aad_mnc1(clip_kid: Ulid, clip_id: Ulid, device_id: &DeviceId, flags: u8) -> Result<Vec<u8>, CoreError> {
    if flags & CLIP_FLAGS_RESERVED_MASK != 0 {
        return Err(clip_integrity_err(format!(
            "non-zero reserved MNC1 flags bits: 0x{flags:02x}"
        )));
    }
    let dev = device_id.as_bytes();
    let mut aad = Vec::with_capacity(5 + 16 + 16 + dev.len() + 1);
    aad.extend_from_slice(MAGIC_MNC1);
    aad.push(WIRE_VERSION);
    aad.extend_from_slice(clip_kid.as_bytes());
    aad.extend_from_slice(clip_id.as_bytes());
    aad.extend_from_slice(dev);
    aad.push(flags);
    Ok(aad)
}

fn encrypt_mnc1_in_place(
    clip_kid: Ulid,
    clip_key: &[u8; 32],
    nonce: [u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut out = vec![0u8; MNC1_HEADER_LEN + plaintext.len() + MNC1_TAG_LEN];
    out[0..4].copy_from_slice(MAGIC_MNC1);
    out[4] = WIRE_VERSION;
    out[5..21].copy_from_slice(clip_kid.as_bytes());
    out[21..45].copy_from_slice(&nonce);

    let ct_end = MNC1_HEADER_LEN + plaintext.len();
    let cipher = XChaCha20Poly1305::new(clip_key.into());
    let xnonce = XNonce::from(nonce);
    let inout = chacha20poly1305::aead::inout::InOutBuf::new(plaintext, &mut out[MNC1_HEADER_LEN..ct_end])
        .map_err(|_| clip_integrity_err("MNC1 inout buffer length mismatch"))?;
    let tag = cipher
        .encrypt_inout_detached(&xnonce, aad, inout)
        .map_err(|_| clip_integrity_err("MNC1 XChaCha20-Poly1305 encryption failed"))?;
    out[ct_end..].copy_from_slice(tag.as_slice());
    Ok(out)
}

fn decrypt_mnc1_in_place(
    expected_clip_kid: Ulid,
    clip_key: &[u8; 32],
    aad: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if envelope.len() < MNC1_HEADER_LEN + MNC1_TAG_LEN {
        return Err(clip_integrity_err("MNC1 envelope truncated"));
    }
    if &envelope[0..4] != MAGIC_MNC1 {
        return Err(clip_integrity_err("MNC1 magic mismatch"));
    }
    if envelope[4] != WIRE_VERSION {
        return Err(clip_integrity_err(format!(
            "unsupported MNC1 version {}",
            envelope[4]
        )));
    }
    if &envelope[5..21] != expected_clip_kid.as_bytes() {
        return Err(clip_integrity_err("MNC1 clip_kid mismatch"));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&envelope[21..45]);
    let ct_end = envelope.len() - MNC1_TAG_LEN;
    let mut tag_bytes = [0u8; MNC1_TAG_LEN];
    tag_bytes.copy_from_slice(&envelope[ct_end..]);
    let tag = Tag::from(tag_bytes);

    let pt_len = ct_end - MNC1_HEADER_LEN;
    let mut out = vec![0u8; pt_len];

    let cipher = XChaCha20Poly1305::new(clip_key.into());
    let xnonce = XNonce::from(nonce);
    let inout = chacha20poly1305::aead::inout::InOutBuf::new(&envelope[MNC1_HEADER_LEN..ct_end], &mut out)
        .map_err(|_| clip_integrity_err("MNC1 inout buffer length mismatch"))?;
    if cipher
        .decrypt_inout_detached(&xnonce, aad, inout, &tag)
        .is_err()
    {
        out.zeroize();
        return Err(clip_integrity_err("MNC1 AEAD tag or AAD verification failed"));
    }
    Ok(out)
}

/// Encrypt `ClipMetaV1` UTF-8 JSON with `pad256` (`payload_type = 0`).
pub fn encrypt_mnc1_meta(
    clip_kid: Ulid,
    clip_key: &[u8; 32],
    clip_id: Ulid,
    device_id: &DeviceId,
    meta_json: &str,
    ephemeral: bool,
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let max_len = if ephemeral {
        MAX_EPHEMERAL_META_BYTES
    } else {
        MAX_REGULAR_META_BYTES
    };
    if meta_json.len() > max_len {
        return Err(clip_arg_err(format!(
            "clip meta JSON length {} exceeds {} byte limit",
            meta_json.len(),
            max_len
        )));
    }
    let parsed: ClipMetaV1 = serde_json::from_str(meta_json)
        .map_err(|e| clip_arg_err(format!("invalid ClipMetaV1 JSON: {e}")))?;
    validate_clip_meta(&parsed)?;

    let flags = if ephemeral { CLIP_FLAG_EPHEMERAL } else { 0x00 };
    let aad = aad_mnc1(clip_kid, clip_id, device_id, flags)?;
    let mut padded = pad256(meta_json.as_bytes());
    let res = encrypt_mnc1_in_place(clip_kid, clip_key, nonce, &aad, &padded);
    padded.zeroize();
    res
}

/// Decrypt `MNC1` metadata frame (`payload_type = 0`), verify `pad256`, UTF-8, and `ClipMetaV1`.
pub fn decrypt_mnc1_meta(
    clip_kid: Ulid,
    clip_key: &[u8; 32],
    clip_id: Ulid,
    author_device_id: &DeviceId,
    ephemeral: bool,
    envelope: &[u8],
) -> Result<String, CoreError> {
    let flags = if ephemeral { CLIP_FLAG_EPHEMERAL } else { 0x00 };
    let aad = aad_mnc1(clip_kid, clip_id, author_device_id, flags)?;
    let mut padded = decrypt_mnc1_in_place(clip_kid, clip_key, &aad, envelope)?;
    let raw = unpad256(&padded)?.to_vec();
    padded.zeroize();
    let json = String::from_utf8(raw)
        .map_err(|e| clip_integrity_err(format!("MNC1 meta is not valid UTF-8: {e}")))?;
    let parsed: ClipMetaV1 = serde_json::from_str(&json)
        .map_err(|e| clip_integrity_err(format!("invalid decrypted ClipMetaV1 JSON: {e}")))?;
    validate_clip_meta(&parsed)?;
    Ok(json)
}

/// Encrypt raw image or large-text bytes as `MNC1` (`payload_type = 1`, zero JSON/Base64/pad256 overhead).
pub fn encrypt_mnc1_blob(
    clip_kid: Ulid,
    clip_key: &[u8; 32],
    clip_id: Ulid,
    device_id: &DeviceId,
    raw_bytes: &[u8],
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    if raw_bytes.len() > MAX_CLIP_BLOB_BYTES {
        return Err(clip_arg_err(format!(
            "clip blob length {} exceeds 10 MiB limit",
            raw_bytes.len()
        )));
    }
    let aad = aad_mnc1(clip_kid, clip_id, device_id, CLIP_FLAG_BLOB_PAYLOAD)?;
    encrypt_mnc1_in_place(clip_kid, clip_key, nonce, &aad, raw_bytes)
}

/// Decrypt `MNC1` raw binary blob (`payload_type = 1`).
pub fn decrypt_mnc1_blob(
    clip_kid: Ulid,
    clip_key: &[u8; 32],
    clip_id: Ulid,
    author_device_id: &DeviceId,
    envelope: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if envelope.len() > MNC1_HEADER_LEN + MAX_CLIP_BLOB_BYTES + MNC1_TAG_LEN {
        return Err(clip_arg_err("MNC1 blob envelope exceeds 10 MiB payload limit"));
    }
    let aad = aad_mnc1(clip_kid, clip_id, author_device_id, CLIP_FLAG_BLOB_PAYLOAD)?;
    decrypt_mnc1_in_place(clip_kid, clip_key, &aad, envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnc1_meta_and_blob_roundtrip_and_aad_isolation() {
        let clip_kid = Ulid::from_parts(1_795_600_000_000, [0x11; 10]);
        let clip_id = Ulid::from_parts(1_795_600_000_001, [0x22; 10]);
        let dev = DeviceId::parse("dev_iphone000001").unwrap();
        let key = [0xA5u8; 32];
        let nonce = [0x33u8; 24];

        let meta_json = r#"{"v":1,"kind":"text","mime":"text/plain","source_mode":"explicit","created_at_ms":1795600000001,"text":"hello clip","blob":null}"#;
        let ct = encrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, meta_json, false, nonce).unwrap();
        assert_eq!(&ct[0..4], b"MNC1");
        assert_eq!(ct[4], 0x01);
        assert_eq!(ct.len(), MNC1_HEADER_LEN + 256 + MNC1_TAG_LEN);

        let dec = decrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, false, &ct).unwrap();
        assert_eq!(dec, meta_json);

        // Cross-channel replay (regular meta replayed as ephemeral or blob) MUST fail AAD verification.
        assert!(decrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, true, &ct).is_err());
        assert!(decrypt_mnc1_blob(clip_kid, &key, clip_id, &dev, &ct).is_err());

        // SVG image MIME MUST be rejected.
        let svg_json = r#"{"v":1,"kind":"image","mime":"image/svg+xml","source_mode":"explicit","created_at_ms":1795600000001,"text":null,"blob":null}"#;
        assert!(encrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, svg_json, false, nonce).is_err());

        // Reserved flags bits MUST be rejected.
        assert!(aad_mnc1(clip_kid, clip_id, &dev, 0x04).is_err());

        // Blob roundtrip (exact length: 45 + len + 16, zero padding/base64 bloat).
        let raw = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];
        let blob_ct = encrypt_mnc1_blob(clip_kid, &key, clip_id, &dev, &raw, nonce).unwrap();
        assert_eq!(blob_ct.len(), MNC1_HEADER_LEN + raw.len() + MNC1_TAG_LEN);
        let blob_pt = decrypt_mnc1_blob(clip_kid, &key, clip_id, &dev, &blob_ct).unwrap();
        assert_eq!(blob_pt, raw);

        // Tamper 1 bit -> AEAD failure.
        let mut bad = blob_ct.clone();
        bad[MNC1_HEADER_LEN] ^= 0x01;
        assert!(decrypt_mnc1_blob(clip_kid, &key, clip_id, &dev, &bad).is_err());
    }
}
