//! Independent 100-item text & bitmap clipboard channel (`MNC1` dual-payload codec + `ClipKey`).
//!
//! SSOT references:
//! - Wire layout, AAD & `ClipMetaV1` / `ClipKeyMaterialV1`: `docs/data-structures.md` §3.2, §3.3, §3.8
//! - Limits, MIME whitelist & isolation: `docs/interface-contracts.md` §4.2(7), §5; `AGENTS.md` §3.3
//!
//! Hard invariants:
//! - Strictly isolated from notes (`ops`, `block_keys`, `shred_marks`, `RecoveryKeyringV1`, `KeyTableState::digest`).
//! - Uses independent rotatable `ClipKey` (`MNCK`-wrapped by current `SMK`); rotation never retains old keys.
//! - Bitmap MIME whitelist strictly allows `image/png`, `image/jpeg`, `image/webp`, `image/gif`;
//!   `image/svg+xml` is ALWAYS rejected (SVG must sync as `kind = "text"`, `mime = "text/plain"`).
//! - Single-pass `AeadInOut` encryption/decryption avoids extra 10 MiB allocations on blob payloads.

use crate::crypto::{pad256, peek_envelope_kid, unpad256, MAGIC_MNC1, MAGIC_MNCK, WIRE_VERSION};
use crate::error::{CoreError, ErrorCode};
use crate::ids::{ClipId, ClipKid, DeviceId, SmkKid};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// `flags` bit 0: ephemeral pure-memory WS direct push (zero DB / zero R2).
pub const CLIP_FLAG_EPHEMERAL: u8 = 0x01;
/// `flags` bit 1: payload type (`0` = `pad256(utf8_json(ClipMetaV1))`, `1` = raw unpadded binary blob).
pub const CLIP_FLAG_PAYLOAD_BLOB: u8 = 0x02;
/// Mask of all valid `MNC1` flags bits (`bits 2..7` MUST be zero).
pub const CLIP_FLAG_VALID_MASK: u8 = 0x03;

/// Maximum inline UTF-8 text payload stored directly in `ClipMetaV1.text` (`64 KiB`).
pub const CLIP_INLINE_TEXT_MAX_BYTES: usize = 64 * 1024;
/// Maximum raw binary blob payload (`10 MiB`).
pub const CLIP_BLOB_MAX_BYTES: usize = 10 * 1024 * 1024;
/// Maximum HTTP envelope size for blob uploads (`10.5 MiB`).
pub const CLIP_BLOB_ENVELOPE_MAX_BYTES: usize = 10 * 1024 * 1024 + 512 * 1024;
/// Maximum ephemeral direct-push payload (`256 KiB`).
pub const CLIP_EPHEMERAL_MAX_BYTES: usize = 256 * 1024;
/// Maximum decoded thumbnail size (`16 KiB`).
pub const CLIP_THUMB_MAX_BYTES: usize = 16 * 1024;
/// Maximum number of retained items in the ring queue (`100`).
pub const CLIP_MAX_ITEMS: usize = 100;
/// Default clipboard retention TTL (`7 days` in milliseconds).
pub const CLIP_DEFAULT_TTL_MS: i64 = 7 * 86_400_000;

/// Maximum UTF-8 JSON length for regular DO-stored `ClipMetaV1` (`96 KiB`).
pub const CLIP_META_JSON_MAX_BYTES: usize = 96 * 1024;
/// Maximum character count for long-text previews (`240` chars, plus optional `"..."` suffix).
pub const CLIP_PREVIEW_MAX_CHARS: usize = 240;

/// Standard 45-byte envelope header: `magic (4B) || ver (1B) || kid (16B) || nonce (24B)`.
pub const MNC1_HEADER_LEN: usize = 4 + 1 + 16 + 24;
pub const MNC1_TAG_LEN: usize = 16;
pub const MNCK_HEADER_LEN: usize = 4 + 1 + 16 + 24;
pub const MNCK_ENVELOPE_LEN: usize = MNCK_HEADER_LEN + 32 + 16;

/// Strictly allowed bitmap image MIME types (`image/svg+xml` is ALWAYS rejected).
pub const ALLOWED_CLIP_IMAGE_MIMES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/gif"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClipKind {
    Text,
    Image,
}

impl ClipKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClipSourceMode {
    Explicit,
    Auto,
}

impl ClipSourceMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Auto => "auto",
        }
    }
}

/// R2 blob descriptor embedded inside `ClipMetaV1` (`docs/data-structures.md` §3.8).
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

/// Compact UTF-8 JSON metadata frame inside `MNC1` (`payload_type = 0`, `docs/data-structures.md` §3.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipMetaV1 {
    pub v: u8,
    pub kind: ClipKind,
    pub mime: String,
    pub source_mode: ClipSourceMode,
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
        "MNC1/MNCK clipboard envelope authentication or wire format check failed",
    )
}

fn clip_arg_err(msg: impl Into<String>) -> CoreError {
    CoreError::new(
        ErrorCode::InvalidArgument,
        msg,
        "Check clipboard payload kind, bitmap MIME whitelist, and size limits",
    )
}

/// Strictly enforce the bitmap image MIME whitelist (`image/png`, `image/jpeg`, `image/webp`, `image/gif`).
/// Rejects `image/svg+xml` and every other MIME type with `ErrorCode::InvalidArgument`.
pub fn validate_clip_image_mime(mime: &str) -> Result<(), CoreError> {
    if ALLOWED_CLIP_IMAGE_MIMES.contains(&mime) {
        Ok(())
    } else {
        Err(clip_arg_err(format!(
            "disallowed clip image mime '{mime}' (only image/png, image/jpeg, image/webp, image/gif allowed; SVG must sync as text/plain)"
        )))
    }
}

fn validate_sha256_hex(hex: &str) -> Result<(), CoreError> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(clip_arg_err(format!(
            "invalid blob sha256_hex length or characters (expected 64 hex chars, got {})",
            hex.len()
        )));
    }
    Ok(())
}

impl ClipMetaV1 {
    /// Validate `ClipMetaV1` for standard (non-ephemeral) queue storage.
    pub fn validate(&self) -> Result<(), CoreError> {
        self.validate_for_channel(false)
    }

    /// Validate `ClipMetaV1` invariants, accounting for regular (`<= 64 KiB` inline text) vs
    /// ephemeral (`<= 256 KiB` inline text, zero R2 blobs) channel limits.
    pub fn validate_for_channel(&self, ephemeral: bool) -> Result<(), CoreError> {
        if self.v != WIRE_VERSION {
            return Err(clip_arg_err(format!("unsupported ClipMetaV1 version {}", self.v)));
        }
        if ephemeral && self.blob.is_some() {
            return Err(clip_arg_err(
                "ephemeral clipboard item cannot reference an R2 blob",
            ));
        }

        match self.kind {
            ClipKind::Text => {
                if self.mime != "text/plain" {
                    return Err(clip_arg_err(format!(
                        "text clip must use mime 'text/plain', got '{}'",
                        self.mime
                    )));
                }
                match (&self.text, &self.blob) {
                    (Some(text), None) => {
                        let max_bytes = if ephemeral {
                            CLIP_EPHEMERAL_MAX_BYTES
                        } else {
                            CLIP_INLINE_TEXT_MAX_BYTES
                        };
                        if text.len() > max_bytes {
                            return Err(clip_arg_err(format!(
                                "inline text length {} exceeds {} byte limit",
                                text.len(),
                                max_bytes
                            )));
                        }
                    }
                    (text_opt, Some(blob)) => {
                        if blob.byte_size == 0 || blob.byte_size as usize > CLIP_BLOB_MAX_BYTES {
                            return Err(clip_arg_err(format!(
                                "text blob byte_size {} must be in 1..={CLIP_BLOB_MAX_BYTES}",
                                blob.byte_size
                            )));
                        }
                        validate_sha256_hex(&blob.sha256_hex)?;
                        if blob.thumb_b64.is_some() || blob.thumb_mime.is_some() {
                            return Err(clip_arg_err(
                                "text clip blob metadata must not carry image thumbnail fields",
                            ));
                        }
                        if let Some(preview) = text_opt {
                            if preview.chars().count() > CLIP_PREVIEW_MAX_CHARS + 3 {
                                return Err(clip_arg_err(format!(
                                    "long-text preview exceeds {CLIP_PREVIEW_MAX_CHARS}-char limit"
                                )));
                            }
                        }
                    }
                    (None, None) => {
                        return Err(clip_arg_err(
                            "text clip must carry either inline text or blob metadata",
                        ));
                    }
                }
            }
            ClipKind::Image => {
                validate_clip_image_mime(&self.mime)?;
                if ephemeral {
                    return Err(clip_arg_err(
                        "ephemeral direct-push channel only supports inline text clips",
                    ));
                }
                if self.text.is_some() {
                    return Err(clip_arg_err("image clip must not carry inline text"));
                }
                let blob = self
                    .blob
                    .as_ref()
                    .ok_or_else(|| clip_arg_err("image clip requires blob metadata"))?;
                if blob.byte_size == 0 || blob.byte_size as usize > CLIP_BLOB_MAX_BYTES {
                    return Err(clip_arg_err(format!(
                        "image blob byte_size {} must be in 1..={CLIP_BLOB_MAX_BYTES}",
                        blob.byte_size
                    )));
                }
                validate_sha256_hex(&blob.sha256_hex)?;
                if let Some(tm) = &blob.thumb_mime {
                    validate_clip_image_mime(tm)?;
                }
                if let Some(tb64) = &blob.thumb_b64 {
                    if blob.thumb_mime.is_none() {
                        return Err(clip_arg_err("thumb_b64 requires thumb_mime"));
                    }
                    let max_b64_len = CLIP_THUMB_MAX_BYTES.div_ceil(3) * 4 + 4;
                    if tb64.len() > max_b64_len {
                        return Err(clip_arg_err(format!(
                            "thumb_b64 exceeds {CLIP_THUMB_MAX_BYTES} byte thumbnail limit"
                        )));
                    }
                    let decoded = B64
                        .decode(tb64)
                        .map_err(|e| clip_arg_err(format!("invalid thumb_b64 base64: {e}")))?;
                    if decoded.len() > CLIP_THUMB_MAX_BYTES {
                        return Err(clip_arg_err(format!(
                            "decoded thumbnail size {} exceeds {CLIP_THUMB_MAX_BYTES} byte limit",
                            decoded.len()
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Compute lowercase hexadecimal SHA-256 digest for `ClipBlobMetaV1.sha256_hex`.
pub fn clip_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Verify decrypted blob bytes against `ClipBlobMetaV1.sha256_hex` (`docs/data-structures.md` §3.8).
pub fn verify_clip_blob_sha256(raw_bytes: &[u8], expected_hex: &str) -> Result<(), CoreError> {
    if expected_hex.len() != 64 || !expected_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(clip_integrity_err("invalid expected blob sha256_hex"));
    }
    let actual = clip_sha256_hex(raw_bytes);
    if !actual.eq_ignore_ascii_case(expected_hex) {
        return Err(clip_integrity_err(format!(
            "decrypted clip blob sha256 mismatch: expected {expected_hex}, got {actual}"
        )));
    }
    Ok(())
}

/// Canonical `MNC1` AAD (`docs/data-structures.md` §3.3):
/// `"MNC1" || 0x01 || clip_kid (16B) || clip_id (16B) || device_id.as_bytes() || flags (1B)`.
///
/// Rejects any non-zero reserved flag bits (`flags & !CLIP_FLAG_VALID_MASK != 0`) with `IntegrityError`.
pub fn aad_mnc1(
    clip_kid: ClipKid,
    clip_id: ClipId,
    device_id: &DeviceId,
    flags: u8,
) -> Result<Vec<u8>, CoreError> {
    if flags & !CLIP_FLAG_VALID_MASK != 0 {
        return Err(clip_integrity_err(format!(
            "non-zero reserved MNC1 flags bits: 0x{flags:02x}"
        )));
    }
    let dev = device_id.as_bytes();
    let mut aad = Vec::with_capacity(4 + 1 + 16 + 16 + dev.len() + 1);
    aad.extend_from_slice(MAGIC_MNC1);
    aad.push(WIRE_VERSION);
    aad.extend_from_slice(clip_kid.as_bytes());
    aad.extend_from_slice(clip_id.as_bytes());
    aad.extend_from_slice(dev);
    aad.push(flags);
    Ok(aad)
}

/// Extract the 16-byte `clip_kid` from a 45-byte `MNC1` header without decrypting.
pub fn peek_mnc1_kid(envelope: &[u8]) -> Result<ClipKid, CoreError> {
    let raw = peek_envelope_kid(MAGIC_MNC1, envelope)?;
    Ok(ClipKid::from_bytes(raw))
}

fn encrypt_mnc1_inout(
    clip_kid: ClipKid,
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

fn decrypt_mnc1_inout(
    expected_clip_kid: ClipKid,
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
        return Err(clip_integrity_err("MNC1 header clip_kid mismatch"));
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
    if cipher.decrypt_inout_detached(&xnonce, aad, inout, &tag).is_err() {
        out.zeroize();
        return Err(clip_integrity_err("MNC1 AEAD tag or AAD verification failed"));
    }
    Ok(out)
}

/// Low-level `MNC1` decryption honoring `flags`: rejects non-zero reserved bits with `IntegrityError`,
/// applies strict `unpad256` iff `payload_type == 0`, and returns raw unpadded bytes for `payload_type == 1`.
pub fn decrypt_mnc1_raw(
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    clip_id: ClipId,
    author_device_id: &DeviceId,
    flags: u8,
    envelope: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let aad = aad_mnc1(clip_kid, clip_id, author_device_id, flags)?;
    let mut decrypted = decrypt_mnc1_inout(clip_kid, clip_key, &aad, envelope)?;
    if flags & CLIP_FLAG_PAYLOAD_BLOB == 0 {
        let unpadded = unpad256(&decrypted)?.to_vec();
        decrypted.zeroize();
        Ok(unpadded)
    } else {
        Ok(decrypted)
    }
}

/// Encrypt a validated `ClipMetaV1` UTF-8 JSON string as `MNC1` (`payload_type = 0`, `pad256` padded).
/// Preserves the caller's exact JSON byte layout (required for WASM JSON callers and golden-vector parity).
pub fn encrypt_mnc1_meta_json(
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    clip_id: ClipId,
    device_id: &DeviceId,
    meta_json: &str,
    ephemeral: bool,
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let max_json_len = if ephemeral {
        CLIP_EPHEMERAL_MAX_BYTES
    } else {
        CLIP_META_JSON_MAX_BYTES
    };
    if meta_json.len() > max_json_len {
        return Err(clip_arg_err(format!(
            "clip meta JSON length {} exceeds {} byte limit",
            meta_json.len(),
            max_json_len
        )));
    }
    let parsed: ClipMetaV1 =
        serde_json::from_str(meta_json).map_err(|e| clip_arg_err(format!("invalid ClipMetaV1 JSON: {e}")))?;
    parsed.validate_for_channel(ephemeral)?;

    let flags = if ephemeral { CLIP_FLAG_EPHEMERAL } else { 0x00 };
    let aad = aad_mnc1(clip_kid, clip_id, device_id, flags)?;
    let mut padded = pad256(meta_json.as_bytes());
    let res = encrypt_mnc1_inout(clip_kid, clip_key, nonce, &aad, &padded);
    padded.zeroize();
    res
}

/// Encrypt a typed `ClipMetaV1` struct as `MNC1` (`payload_type = 0`, `pad256` padded).
pub fn encrypt_mnc1_meta(
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    clip_id: ClipId,
    device_id: &DeviceId,
    meta: &ClipMetaV1,
    ephemeral: bool,
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    meta.validate_for_channel(ephemeral)?;
    let json = serde_json::to_string(meta)
        .map_err(|e| clip_arg_err(format!("failed serializing ClipMetaV1: {e}")))?;
    encrypt_mnc1_meta_json(clip_kid, clip_key, clip_id, device_id, &json, ephemeral, nonce)
}

fn decrypt_mnc1_meta_pair(
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    clip_id: ClipId,
    author_device_id: &DeviceId,
    ephemeral: bool,
    envelope: &[u8],
) -> Result<(ClipMetaV1, String), CoreError> {
    let max_env_len = if ephemeral {
        MNC1_HEADER_LEN + CLIP_EPHEMERAL_MAX_BYTES + 256 + MNC1_TAG_LEN
    } else {
        MNC1_HEADER_LEN + CLIP_META_JSON_MAX_BYTES + 256 + MNC1_TAG_LEN
    };
    if envelope.len() > max_env_len {
        return Err(clip_arg_err(format!(
            "MNC1 meta envelope length {} exceeds {} byte limit",
            envelope.len(),
            max_env_len
        )));
    }
    let flags = if ephemeral { CLIP_FLAG_EPHEMERAL } else { 0x00 };
    let raw = decrypt_mnc1_raw(clip_kid, clip_key, clip_id, author_device_id, flags, envelope)?;
    let json = String::from_utf8(raw)
        .map_err(|e| clip_integrity_err(format!("MNC1 meta is not valid UTF-8: {e}")))?;
    let parsed: ClipMetaV1 = serde_json::from_str(&json)
        .map_err(|e| clip_integrity_err(format!("invalid decrypted ClipMetaV1 JSON: {e}")))?;
    parsed.validate_for_channel(ephemeral)?;
    Ok((parsed, json))
}

/// Decrypt an `MNC1` metadata envelope (`payload_type = 0`), verify `pad256`, UTF-8, and
/// `ClipMetaV1` invariants (including strict bitmap MIME whitelist / SVG rejection).
pub fn decrypt_mnc1_meta(
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    clip_id: ClipId,
    author_device_id: &DeviceId,
    ephemeral: bool,
    envelope: &[u8],
) -> Result<ClipMetaV1, CoreError> {
    let (meta, _) =
        decrypt_mnc1_meta_pair(clip_kid, clip_key, clip_id, author_device_id, ephemeral, envelope)?;
    Ok(meta)
}

/// Decrypt an `MNC1` metadata envelope (`payload_type = 0`) and return the validated UTF-8 JSON string.
pub fn decrypt_mnc1_meta_json(
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    clip_id: ClipId,
    author_device_id: &DeviceId,
    ephemeral: bool,
    envelope: &[u8],
) -> Result<String, CoreError> {
    let (_, json) =
        decrypt_mnc1_meta_pair(clip_kid, clip_key, clip_id, author_device_id, ephemeral, envelope)?;
    Ok(json)
}

/// Encrypt raw image or large-text bytes as `MNC1` (`payload_type = 1`, zero `pad256`/JSON/Base64 overhead).
/// Uses `AeadInOut::encrypt_inout_detached` to avoid an extra 10 MiB buffer copy.
pub fn encrypt_mnc1_blob(
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    clip_id: ClipId,
    device_id: &DeviceId,
    raw_bytes: &[u8],
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    if raw_bytes.len() > CLIP_BLOB_MAX_BYTES {
        return Err(clip_arg_err(format!(
            "clip blob length {} exceeds 10 MiB limit ({CLIP_BLOB_MAX_BYTES} bytes)",
            raw_bytes.len()
        )));
    }
    let aad = aad_mnc1(clip_kid, clip_id, device_id, CLIP_FLAG_PAYLOAD_BLOB)?;
    encrypt_mnc1_inout(clip_kid, clip_key, nonce, &aad, raw_bytes)
}

/// Decrypt an `MNC1` raw binary blob (`payload_type = 1`, unpadded) via single-pass `AeadInOut`.
pub fn decrypt_mnc1_blob(
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    clip_id: ClipId,
    author_device_id: &DeviceId,
    envelope: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if envelope.len() > CLIP_BLOB_ENVELOPE_MAX_BYTES
        || envelope.len() > MNC1_HEADER_LEN + CLIP_BLOB_MAX_BYTES + MNC1_TAG_LEN
    {
        return Err(clip_arg_err(format!(
            "MNC1 blob envelope length {} exceeds 10 MiB payload limit",
            envelope.len()
        )));
    }
    decrypt_mnc1_raw(
        clip_kid,
        clip_key,
        clip_id,
        author_device_id,
        CLIP_FLAG_PAYLOAD_BLOB,
        envelope,
    )
}

// ---------- Independent Rotatable ClipKey Material (`MNCK`, `docs/data-structures.md` §3.8) ----------

/// `key_material(kind = 'clip_key')` payload (`docs/data-structures.md` §3.8).
/// Stored separately from `RecoveryKeyringV1` and replaced destructively on rotation (old keys never kept).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipKeyMaterialV1 {
    pub v: u8,
    pub clip_kid: ClipKid,
    pub smk_kid: SmkKid,
    pub wrapped_clip_key: Vec<u8>,
}

/// Canonical `MNCK` AAD: `"MNCK" || 0x01 || smk_kid (16B) || clip_kid (16B)`.
pub fn aad_mnck(smk_kid: SmkKid, clip_kid: ClipKid) -> [u8; 4 + 1 + 16 + 16] {
    let mut aad = [0u8; 37];
    aad[0..4].copy_from_slice(MAGIC_MNCK);
    aad[4] = WIRE_VERSION;
    aad[5..21].copy_from_slice(smk_kid.as_bytes());
    aad[21..37].copy_from_slice(clip_kid.as_bytes());
    aad
}

/// Wrap a 32-byte `ClipKey` using the current `SMK` into a 93-byte `MNCK` envelope inside `ClipKeyMaterialV1`.
pub fn wrap_clip_key_material(
    smk_kid: SmkKid,
    smk: &[u8; 32],
    clip_kid: ClipKid,
    clip_key: &[u8; 32],
    nonce: [u8; 24],
) -> Result<ClipKeyMaterialV1, CoreError> {
    let aad = aad_mnck(smk_kid, clip_kid);
    let mut out = vec![0u8; MNCK_ENVELOPE_LEN];
    out[0..4].copy_from_slice(MAGIC_MNCK);
    out[4] = WIRE_VERSION;
    out[5..21].copy_from_slice(smk_kid.as_bytes());
    out[21..45].copy_from_slice(&nonce);

    let cipher = XChaCha20Poly1305::new(smk.into());
    let xnonce = XNonce::from(nonce);
    let inout = chacha20poly1305::aead::inout::InOutBuf::new(
        clip_key.as_slice(),
        &mut out[MNCK_HEADER_LEN..MNCK_HEADER_LEN + 32],
    )
    .map_err(|_| clip_integrity_err("MNCK inout buffer length mismatch"))?;
    let tag = cipher
        .encrypt_inout_detached(&xnonce, &aad, inout)
        .map_err(|_| clip_integrity_err("MNCK XChaCha20-Poly1305 encryption failed"))?;
    out[MNCK_HEADER_LEN + 32..].copy_from_slice(tag.as_slice());

    Ok(ClipKeyMaterialV1 {
        v: WIRE_VERSION,
        clip_kid,
        smk_kid,
        wrapped_clip_key: out,
    })
}

/// Unwrap a `ClipKeyMaterialV1` using the corresponding `SMK`, returning `Zeroizing<[u8; 32]>`.
pub fn unwrap_clip_key_material(
    material: &ClipKeyMaterialV1,
    smk: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    if material.v != WIRE_VERSION {
        return Err(clip_integrity_err(format!(
            "unsupported ClipKeyMaterialV1 version {}",
            material.v
        )));
    }
    let env = &material.wrapped_clip_key;
    if env.len() != MNCK_ENVELOPE_LEN {
        return Err(clip_integrity_err(format!(
            "invalid MNCK length {}: expected {MNCK_ENVELOPE_LEN}",
            env.len()
        )));
    }
    if &env[0..4] != MAGIC_MNCK {
        return Err(clip_integrity_err("MNCK magic mismatch"));
    }
    if env[4] != WIRE_VERSION {
        return Err(clip_integrity_err(format!("unsupported MNCK version {}", env[4])));
    }
    if &env[5..21] != material.smk_kid.as_bytes() {
        return Err(clip_integrity_err("MNCK header smk_kid mismatch"));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&env[21..45]);
    let mut tag_bytes = [0u8; MNC1_TAG_LEN];
    tag_bytes.copy_from_slice(&env[MNCK_HEADER_LEN + 32..]);
    let tag = Tag::from(tag_bytes);

    let aad = aad_mnck(material.smk_kid, material.clip_kid);
    let mut out = Zeroizing::new([0u8; 32]);
    let cipher = XChaCha20Poly1305::new(smk.into());
    let xnonce = XNonce::from(nonce);
    let inout = chacha20poly1305::aead::inout::InOutBuf::new(
        &env[MNCK_HEADER_LEN..MNCK_HEADER_LEN + 32],
        out.as_mut_slice(),
    )
    .map_err(|_| clip_integrity_err("MNCK inout buffer length mismatch"))?;
    if cipher.decrypt_inout_detached(&xnonce, &aad, inout, &tag).is_err() {
        out.zeroize();
        return Err(clip_integrity_err("MNCK AEAD tag or AAD verification failed"));
    }
    Ok(out)
}

/// Unwrap `ClipKeyMaterialV1` by resolving `material.smk_kid` in the device's SMK keyring.
pub fn unwrap_clip_key_material_with_keyring(
    material: &ClipKeyMaterialV1,
    smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let smk = smks.get(&material.smk_kid).ok_or_else(|| {
        CoreError::new(
            ErrorCode::KeyMissing,
            format!(
                "missing SMK generation {} required to unwrap ClipKey {}",
                material.smk_kid, material.clip_kid
            ),
            "Refresh device keys from desktop or unlock keyring with the 24-word recovery bundle",
        )
    })?;
    unwrap_clip_key_material(material, smk)
}

/// Encode `ClipKeyMaterialV1` as named-field MessagePack for `key_material(kind = 'clip_key').blob`.
pub fn encode_clip_key_material(material: &ClipKeyMaterialV1) -> Result<Vec<u8>, CoreError> {
    if material.v != WIRE_VERSION {
        return Err(clip_integrity_err(format!(
            "unsupported ClipKeyMaterialV1 version {}",
            material.v
        )));
    }
    rmp_serde::to_vec_named(material)
        .map_err(|e| clip_integrity_err(format!("failed encoding ClipKeyMaterialV1: {e}")))
}

/// Decode and validate a MessagePack `ClipKeyMaterialV1` blob from `key_material`.
pub fn decode_clip_key_material(raw: &[u8]) -> Result<ClipKeyMaterialV1, CoreError> {
    let material: ClipKeyMaterialV1 = rmp_serde::from_slice(raw)
        .map_err(|e| clip_integrity_err(format!("corrupt ClipKeyMaterialV1 payload: {e}")))?;
    if material.v != WIRE_VERSION {
        return Err(clip_integrity_err(format!(
            "unsupported ClipKeyMaterialV1 version {}",
            material.v
        )));
    }
    if material.wrapped_clip_key.len() != MNCK_ENVELOPE_LEN
        || &material.wrapped_clip_key[0..4] != MAGIC_MNCK
        || material.wrapped_clip_key[4] != WIRE_VERSION
        || &material.wrapped_clip_key[5..21] != material.smk_kid.as_bytes()
    {
        return Err(clip_integrity_err(
            "ClipKeyMaterialV1 carries malformed MNCK envelope header",
        ));
    }
    Ok(material)
}

/// Rotate to a fresh `(ClipKid, Zeroizing<[u8; 32]>)` wrapped under the current `SMK`.
/// Never retains any prior `ClipKey` generation (`docs/data-structures.md` §3.8).
pub fn rotate_clip_key(
    smk_kid: SmkKid,
    smk: &[u8; 32],
    new_clip_kid: ClipKid,
    new_clip_key: [u8; 32],
    nonce: [u8; 24],
) -> Result<(ClipKid, Zeroizing<[u8; 32]>, ClipKeyMaterialV1), CoreError> {
    let key = Zeroizing::new(new_clip_key);
    let material = wrap_clip_key_material(smk_kid, smk, new_clip_kid, &key, nonce)?;
    Ok((new_clip_kid, key, material))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Ulid;
    use crate::model::KeyMaterialKind;
    use crate::sync::{EngineSnapshot, StoreMutation};
    use proptest::prelude::*;

    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn decode_hex_32(s: &str) -> [u8; 32] {
        decode_hex(s).try_into().unwrap()
    }

    fn decode_hex_24(s: &str) -> [u8; 24] {
        decode_hex(s).try_into().unwrap()
    }

    // ---------- Embedded S-Clip-1 Golden Vectors (JS <-> Rust byte-for-byte parity) ----------

    struct PositiveVector {
        name: &'static str,
        clip_key_hex: &'static str,
        clip_kid: &'static str,
        clip_id: &'static str,
        device_id: &'static str,
        flags: u8,
        ephemeral: bool,
        payload_type: u8,
        nonce_hex: &'static str,
        aad_hex: &'static str,
        plaintext_utf8: Option<&'static str>,
        plaintext_hex: &'static str,
        envelope_hex: &'static str,
    }

    struct NegativeVector {
        name: &'static str,
        clip_key_hex: &'static str,
        clip_kid: &'static str,
        clip_id: &'static str,
        device_id: &'static str,
        flags: u8,
        envelope_hex: &'static str,
    }

    const ULID_VECTORS: &[(&str, &str)] = &[
        ("00000000000000000000000000", "00000000000000000000000000000000"),
        ("7ZZZZZZZZZZZZZZZZZZZZZZZZZ", "ffffffffffffffffffffffffffffffff"),
        ("01JDF8Z9X4K7M2N5P8Q1R3S6T9", "01935e8fa7a499e82a96c8b8703c9b49"),
        ("01ARZ3NDEKTSV4RRFFQ69G5FAV", "01563e3ab5d3d6764c61efb99302bd5b"),
    ];

    const POSITIVE_VECTORS: &[PositiveVector] = &[
        PositiveVector {
            name: "meta_text_regular",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            ephemeral: false,
            payload_type: 0,
            nonce_hex: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
            aad_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b4901935e90814158983691c579a078a2496465765f30316a6466387a3978346b376d326e3500",
            plaintext_utf8: Some("{\"blob\":null,\"created_at_ms\":1795600000123,\"kind\":\"text\",\"mime\":\"text/plain\",\"source_mode\":\"explicit\",\"text\":\"hello my-note 剪贴板同步 🚀 line1\\nline2\",\"v\":1}"),
            plaintext_hex: "7b22626c6f62223a6e756c6c2c22637265617465645f61745f6d73223a313739353630303030303132332c226b696e64223a2274657874222c226d696d65223a22746578742f706c61696e222c22736f757263655f6d6f6465223a226578706c69636974222c2274657874223a2268656c6c6f206d792d6e6f746520e589aae8b4b4e69dbfe5908ce6ada520f09f9a80206c696e65315c6e6c696e6532222c2276223a317d",
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bdf83ce79c60ed7a398fb0dbd02842ba8d0b9",
        },
        PositiveVector {
            name: "meta_text_ephemeral",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910K2M3N4P5Q6R7S8T9V0",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 1,
            ephemeral: true,
            payload_type: 0,
            nonce_hex: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7",
            aad_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b4901935e908262a0ea4b16e6c1f28d27606465765f30316a6466387a3978346b376d326e3501",
            plaintext_utf8: Some("{\"blob\":null,\"created_at_ms\":1795600005456,\"kind\":\"text\",\"mime\":\"text/plain\",\"source_mode\":\"explicit\",\"text\":\"OTP-849201-ephemeral-secret\",\"v\":1}"),
            plaintext_hex: "7b22626c6f62223a6e756c6c2c22637265617465645f61745f6d73223a313739353630303030353435362c226b696e64223a2274657874222c226d696d65223a22746578742f706c61696e222c22736f757263655f6d6f6465223a226578706c69636974222c2274657874223a224f54502d3834393230312d657068656d6572616c2d736563726574222c2276223a317d",
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8ccde28e1c3f0beca37addaedc53d5279bb02d11173ed50ab611d889ff49fc71ccd46dd1635e39c048efa8e60fca4fab543ab010d4c80c078302a0c1e86ed011dec6258757ccd536111a53f22dff740a3978c75f8a8a39dfd97a74425f3d95454a143e7f80e2ba6e4c4dc577fb80a291716f7ac7447997a5830dfad0f70e9b1f19284dfd88aee95dc56bd8e5b3c6b87b4334a4c9371fa78355ebce239feb83b461e2d25877417674994f183cbe701360e0d92dd0c265ee6c13fdec5d1c58b6005a2911de42827f2d45f3dc6aa6b20cc7456485ae91ba71564808434547f6d6af5ee0aa9f0c4f908d6698de81f350f3a7c5d8adc8630f58199bd524a525a4dcdc31908275ae2d4013ae61117ec2bec60",
        },
        PositiveVector {
            name: "blob_png_binary",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910W1X2Y3Z40516273849",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 2,
            ephemeral: false,
            payload_type: 1,
            nonce_hex: "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7",
            aad_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b4901935e908381e8bc3f9005098471a0896465765f30316a6466387a3978346b376d326e3502",
            plaintext_utf8: None,
            plaintext_hex: "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082",
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f70b3bd683773396a161a5e6111e4509e080359417155fa1e783da0ea15e64382296cd4a1d8b4dbfd75654a134df380776027d42ce7e877ce7dee4756773e7a4aebf20b211f19dd56629ff48232dbc7f8986aa41",
        },
        PositiveVector {
            name: "blob_multiblock_1029b",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF9110A1B2C3D4E5F6G7H8J",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 2,
            ephemeral: false,
            payload_type: 1,
            nonce_hex: "0123456789abcdeffedcba98765432100011223344556677",
            aad_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b4901935e90840a0ac4c1b48e2bcd03c5126465765f30316a6466387a3978346b376d326e3502",
            plaintext_utf8: None,
            plaintext_hex: "135ca5ee3780c9125ba4ed367fc8115aa3ec357ec71059a2eb347dc60f58a1ea337cc50e57a0e9327bc40d569fe8317ac30c559ee73079c20b549de62f78c10a539ce52e77c009529be42d76bf08519ae32c75be075099e22b74bd064f98e12a73bc054e97e02972bb044d96df2871ba034c95de2770b9024b94dd266fb8014a93dc256eb7004992db246db6ff4891da236cb5fe4790d9226bb4fd468fd8216ab3fc458ed72069b2fb448dd61f68b1fa438cd51e67b0f9428bd41d66aff8418ad31c65aef74089d21b64adf63f88d11a63acf53e87d01962abf43d86cf1861aaf33c85ce1760a9f23b84cd165fa8f13a83cc155ea7f03982cb145da6ef3881ca135ca5ee3780c9125ba4ed367fc8115aa3ec357ec71059a2eb347dc60f58a1ea337cc50e57a0e9327bc40d569fe8317ac30c559ee73079c20b549de62f78c10a539ce52e77c009529be42d76bf08519ae32c75be075099e22b74bd064f98e12a73bc054e97e02972bb044d96df2871ba034c95de2770b9024b94dd266fb8014a93dc256eb7004992db246db6ff4891da236cb5fe4790d9226bb4fd468fd8216ab3fc458ed72069b2fb448dd61f68b1fa438cd51e67b0f9428bd41d66aff8418ad31c65aef74089d21b64adf63f88d11a63acf53e87d01962abf43d86cf1861aaf33c85ce1760a9f23b84cd165fa8f13a83cc155ea7f03982cb145da6ef3881ca135ca5ee3780c9125ba4ed367fc8115aa3ec357ec71059a2eb347dc60f58a1ea337cc50e57a0e9327bc40d569fe8317ac30c559ee73079c20b549de62f78c10a539ce52e77c009529be42d76bf08519ae32c75be075099e22b74bd064f98e12a73bc054e97e02972bb044d96df2871ba034c95de2770b9024b94dd266fb8014a93dc256eb7004992db246db6ff4891da236cb5fe4790d9226bb4fd468fd8216ab3fc458ed72069b2fb448dd61f68b1fa438cd51e67b0f9428bd41d66aff8418ad31c65aef74089d21b64adf63f88d11a63acf53e87d01962abf43d86cf1861aaf33c85ce1760a9f23b84cd165fa8f13a83cc155ea7f03982cb145da6ef3881ca135ca5ee3780c9125ba4ed367fc8115aa3ec357ec71059a2eb347dc60f58a1ea337cc50e57a0e9327bc40d569fe8317ac30c559ee73079c20b549de62f78c10a539ce52e77c009529be42d76bf08519ae32c75be075099e22b74bd064f98e12a73bc054e97e02972bb044d96df2871ba034c95de2770b9024b94dd266fb8014a93dc256eb7004992db246db6ff4891da236cb5fe4790d9226bb4fd468fd8216ab3fc458ed72069b2fb448dd61f68b1fa438cd51e67b0f9428bd41d66aff8418ad31c65aef74089d21b64adf63f88d11a63acf53e87d01962abf43d86cf1861aaf33c85ce1760a9f23b84cd165fa8f13a83cc155ea7f03982cb145da6ef3881ca135ca5ee37",
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b490123456789abcdeffedcba987654321000112233445566771a942d85fed21ee15c339ce319d3a5cd79e1f20defeec5ee713c738710f29d3efd2a7ea467a558b9b64f6f823542c6f71694a89e744879b0f16f10c5e83a89b66f1d661b2ac04f90da878ae7a13f98a2baf5e05c63821945a2b9a5a8b8b6a3a2fbd7395e03bcae97b214cbf3e873cf732e95cfe9c7f5f2bd6e95c22c274351d3f7dffa04a4073ee0fe81c743aa3b3591a941328fd2bcd3c2e8aa571f6c04e7bd4a3ad08106e07244ef5bb6a5e9b620e770e276bc6a1719347beadc26424b6fda986c62730936ce1ff868a3f58894d66d675a9682a0e5f15d1ffca2f223abc6df9d634d7e48af3d1204c3750772c4bc76ba81649cedd5ae7cce264c35caf7c74aeaa0c30589811a7ee53af8cde2b52066c3dfbb20e0da813d4a15c02b1cbf969c1f9b7f0dc8a77fe38a83382616acb5b921c6ee632c1efdcef5d1e23e348944c975fbc02fe1100338ad6c91bd8ae32a64545c22e572c51bf152469749a22b639acb386e3ff554f8354ace5ecc3f364bf92d5ccff5428d192b706913e93c1cefaa49b26d9bdd0f12191c3e0dd1eeb4f7272cfddc05ea7f01272a5df45a548c6bd86d656585c9648e4e24021c0349ab57412e967ae2122728a92169531e294292df102bb94a7ca138c3da6e98d21a56ed7ee6bfc19156585a34566523a6823f146164e0e94f0e895e58d1732fbb7bc576e4062699977fad47ac49014e177bab7fda1b6c43c4cf8d773397f473850aabe7a149feb6ee7e879336d1c5d4e3b268a10dfacb3d1e75c30a4fd2ea4bf75ebf47b9fa2feb74ba69e36aab97c935dac9739bb6190062066623f3fcd0ad37beb7bdf1c8a41f2fa1a51511ae02008a1ff7ff1f93a6c60fc0d6c95cb196ad6a06498b4140ddeacf33749e4c02c5ba6fc12127cdb758b48ee056b97e57b6708d64d57da95df78984f52d404b8c741e3154ad5c36adbf3a1a8108b533ff770a6cfa775d9c802d15791e350b1ea24e92d726bb0ca82a76b9a663e16af2da5cc3558c77d5e703dbd9fcd317604705506a2af8ed925c7ea092ed2b53c96d2aa21ffa59009ff393918471138774949926f638320b98090d94f4adeb253a3df70c5683a6140141e2e4a5389bca8ec9127cdc2ebb7e5cd43509b57ab70fded084216b6fef8715472be032aeae483b56b8c300a827846faf109b7c0a3fe14a626e992fb5e12e7b6b2ef9220ed08424bc11485751b36fab094dfddaa10f6998ce82e9cde1c88ce779bd8c9019b61b5f1a66430d927d8d98cf46b37be34e3c8f9e34920650c03917f674cbe41f474290ea0ef902292a91805b13f61dd8b8cc376525d1bd28f7fe0282517e497a0683864b351dd633ed97dfdee188c279fc93c1d93749244b45cea73fd45fb1c812b0814c9869b48e2ca456ac0fc792d6e2158e11490b5002f07fd2a980af87730e2d73ce2a657919036749d3a2288de73da669200839630bdcc9dc945ac99c8ce5",
        },
        PositiveVector {
            name: "meta_pad256_boundary_255b",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF911K9M8N7P6Q5R4S3T2V1",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            ephemeral: false,
            payload_type: 0,
            nonce_hex: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            aad_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b4901935e908669a22a7b1ae5c1323d0b616465765f30316a6466387a3978346b376d326e3500",
            plaintext_utf8: Some("{\"v\":1,\"kind\":\"text\",\"mime\":\"text/plain\",\"source_mode\":\"explicit\",\"created_at_ms\":1795600009999,\"blob\":null,\"text\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}"),
            plaintext_hex: "7b2276223a312c226b696e64223a2274657874222c226d696d65223a22746578742f706c61696e222c22736f757263655f6d6f6465223a226578706c69636974222c22637265617465645f61745f6d73223a313739353630303030393939392c22626c6f62223a6e756c6c2c2274657874223a224141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141227d",
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b495a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5aa291a84a4d1b2e3df9f327512c4066c62a87df5e61d9cf06d35aede7f01517f9ac71048e4cb976125eeab7e26412e5412060258cd33d57ab743200f504344962de6ce6ab89e1196ea61e74cf4315156adf427b1f6ad3bb1c502d957dd40d9dd848a2a9c674536927e0bc4c91298c118734884a9e4dfe1dd85bc890c7c02f98a4df000cc5fce362edc79718746c0905db66cf16b5292d66c6c6b98e6d4e0db38fac69ea4624663021797533bc01a5fee06bf8be74ccf5e98aa9d23e1ebc8f315651df0ffd3d0a8efac732f1990817c8d60ff2504c91dee2da2bab4f42c80db9d09e2b0dde8f8b190ebe6d8a1a23a7fe65a89a4a393dc86a5261fedf9ad2ddaa456d60b795a93ea56b9e85cfc1ec84ecb8",
        },
    ];

    const NEGATIVE_VECTORS: &[NegativeVector] = &[
        NegativeVector {
            name: "tampered_aad_clip_id",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910K2M3N4P5Q6R7S8T9V0",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bdf83ce79c60ed7a398fb0dbd02842ba8d0b9",
        },
        NegativeVector {
            name: "tampered_aad_device_id",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_otherdevice0001",
            flags: 0,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bdf83ce79c60ed7a398fb0dbd02842ba8d0b9",
        },
        NegativeVector {
            name: "tampered_aad_flags_ephemeral",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 1,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bdf83ce79c60ed7a398fb0dbd02842ba8d0b9",
        },
        NegativeVector {
            name: "tampered_aad_flags_payload_type",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910W1X2Y3Z40516273849",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f70b3bd683773396a161a5e6111e4509e080359417155fa1e783da0ea15e64382296cd4a1d8b4dbfd75654a134df380776027d42ce7e877ce7dee4756773e7a4aebf20b211f19dd56629ff48232dbc7f8986aa41",
        },
        NegativeVector {
            name: "tampered_tag_bitflip",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bdf83ce79c60ed7a398fb0dbd02842ba8d0b8",
        },
        NegativeVector {
            name: "tampered_ciphertext_bitflip",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910W1X2Y3Z40516273849",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 2,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f78b3bd683773396a161a5e6111e4509e080359417155fa1e783da0ea15e64382296cd4a1d8b4dbfd75654a134df380776027d42ce7e877ce7dee4756773e7a4aebf20b211f19dd56629ff48232dbc7f8986aa41",
        },
        NegativeVector {
            name: "tampered_header_magic",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            envelope_hex: "4d4e53310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bdf83ce79c60ed7a398fb0dbd02842ba8d0b9",
        },
        NegativeVector {
            name: "tampered_header_version",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            envelope_hex: "4d4e43310201935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bdf83ce79c60ed7a398fb0dbd02842ba8d0b9",
        },
        NegativeVector {
            name: "reserved_flag_bit2_0x04",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 4,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bdf8360d1f5c1aaba5ee2574fd90fff3c9a2f",
        },
        NegativeVector {
            name: "reserved_flag_bit7_0x82",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910W1X2Y3Z40516273849",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 130,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f70b3bd683773396a161a5e6111e4509e080359417155fa1e783da0ea15e64382296cd4a1d8b4dbfd75654a134df380776027d42ce7e877ce7dee4756773e7a4aebf20b2c98b02acf64b9da80549047be5ccb473",
        },
        NegativeVector {
            name: "non_canonical_pad256_nonzero_byte",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc7115040dca36e96ba1592fbae2e066168d13d68dd89da22bf0e37cd07b663955a0d3a1a8132a6dda12586d6fd9e59dcbbcc69fde9b10d5b1d86ce948eb6b516a89394414f76bbfb7863e492ea5a89927a8b75663f4ac75a77c9c8f1bde837eeae1de7e4450d78a6e4be059ef8a7d",
        },
        NegativeVector {
            name: "non_canonical_pad256_bad_length",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b3c3b12c77a9aca62c5802cb12bf02aca24c0b745498d5845f9dfd26618cfd9b6a43094b3a73859bcab23374f6ca09e5ee4c74e85165d6aa929377ae4c528ed78026f95c56ecff2d19c085f844c16764207d8d011b19c3c9afcd5ee80330b217de42eb4917f1c9b32d22714ad186a39da0a02626cc18f7652ccbfb15eb1b940ced7aa7bbbe1fff86b9b86c428907ba814c361dc711504469443cd9a5d30a4105c2ea932fc27e0",
        },
        NegativeVector {
            name: "truncated_envelope",
            clip_key_hex: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            clip_kid: "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
            clip_id: "01JDF910A1B2C3D4E5F6G7H8J9",
            device_id: "dev_01jdf8z9x4k7m2n5",
            flags: 0,
            envelope_hex: "4d4e43310101935e8fa7a499e82a96c8b8703c9b49a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70ed91cf7965d3bd4470fe227aa416b",
        },
    ];

    #[test]
    fn s_clip_1_embedded_golden_vectors_match_byte_for_byte() {
        for &(ulid_str, hex_str) in ULID_VECTORS {
            let kid = ClipKid::parse(ulid_str).unwrap();
            assert_eq!(kid.as_bytes().as_slice(), decode_hex(hex_str).as_slice());
            assert_eq!(kid.to_string(), ulid_str);
        }

        for v in POSITIVE_VECTORS {
            let clip_key = decode_hex_32(v.clip_key_hex);
            let clip_kid = ClipKid::parse(v.clip_kid).unwrap();
            let clip_id = ClipId::parse(v.clip_id).unwrap();
            let dev = DeviceId::parse(v.device_id).unwrap();
            let nonce = decode_hex_24(v.nonce_hex);
            let expected_aad = decode_hex(v.aad_hex);
            let expected_pt = decode_hex(v.plaintext_hex);
            let expected_env = decode_hex(v.envelope_hex);

            let aad = aad_mnc1(clip_kid, clip_id, &dev, v.flags).unwrap();
            assert_eq!(aad, expected_aad, "AAD mismatch for vector {}", v.name);
            assert_eq!(
                peek_mnc1_kid(&expected_env).unwrap(),
                clip_kid,
                "peek_mnc1_kid mismatch for {}",
                v.name
            );

            if v.payload_type == 0 {
                let pt_utf8 = v.plaintext_utf8.expect("meta vector has utf8 plaintext");
                assert_eq!(pt_utf8.as_bytes(), expected_pt.as_slice());
                let env =
                    encrypt_mnc1_meta_json(clip_kid, &clip_key, clip_id, &dev, pt_utf8, v.ephemeral, nonce)
                        .unwrap();
                assert_eq!(
                    env, expected_env,
                    "encrypt_mnc1_meta_json mismatch for {}",
                    v.name
                );

                let dec_json =
                    decrypt_mnc1_meta_json(clip_kid, &clip_key, clip_id, &dev, v.ephemeral, &expected_env)
                        .unwrap();
                assert_eq!(
                    dec_json, pt_utf8,
                    "decrypt_mnc1_meta_json mismatch for {}",
                    v.name
                );

                let dec_meta =
                    decrypt_mnc1_meta(clip_kid, &clip_key, clip_id, &dev, v.ephemeral, &expected_env)
                        .unwrap();
                assert_eq!(dec_meta.v, 1);
                assert_eq!(dec_meta.kind, ClipKind::Text);
            } else {
                let env = encrypt_mnc1_blob(clip_kid, &clip_key, clip_id, &dev, &expected_pt, nonce).unwrap();
                assert_eq!(env, expected_env, "encrypt_mnc1_blob mismatch for {}", v.name);

                let dec = decrypt_mnc1_blob(clip_kid, &clip_key, clip_id, &dev, &expected_env).unwrap();
                assert_eq!(dec, expected_pt, "decrypt_mnc1_blob mismatch for {}", v.name);
            }
        }

        for v in NEGATIVE_VECTORS {
            let clip_key = decode_hex_32(v.clip_key_hex);
            let clip_kid = ClipKid::parse(v.clip_kid).unwrap();
            let clip_id = ClipId::parse(v.clip_id).unwrap();
            let dev = DeviceId::parse(v.device_id).unwrap();
            let env = decode_hex(v.envelope_hex);
            let err = decrypt_mnc1_raw(clip_kid, &clip_key, clip_id, &dev, v.flags, &env)
                .expect_err(&format!("negative vector {} must fail", v.name));
            assert_eq!(
                err.code(),
                ErrorCode::IntegrityError,
                "negative vector {} must fail with IntegrityError",
                v.name
            );
        }
    }

    proptest! {
        #[test]
        fn mnc1_meta_and_blob_dual_payload_roundtrip(
            text in ".*",
            ephemeral in any::<bool>(),
            auto_mode in any::<bool>(),
            blob in prop::collection::vec(any::<u8>(), 0..4096),
            key in prop::array::uniform32(any::<u8>()),
            nonce_meta in prop::array::uniform24(any::<u8>()),
            nonce_blob in prop::array::uniform24(any::<u8>()),
            ts in 1_000_000_000_000u64..2_000_000_000_000u64,
        ) {
            let clip_kid = ClipKid::from_ulid(Ulid::from_parts(ts, [0x11; 10]));
            let clip_id = ClipId::from_ulid(Ulid::from_parts(ts + 1, [0x22; 10]));
            let dev = DeviceId::parse("dev_01jdf8z9x4k7m2n5").unwrap();

            let meta = ClipMetaV1 {
                v: 1,
                kind: ClipKind::Text,
                mime: "text/plain".into(),
                source_mode: if auto_mode { ClipSourceMode::Auto } else { ClipSourceMode::Explicit },
                created_at_ms: ts as i64,
                text: Some(text),
                blob: None,
            };

            let meta_env = encrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, &meta, ephemeral, nonce_meta).unwrap();
            prop_assert_eq!((meta_env.len() - MNC1_HEADER_LEN - MNC1_TAG_LEN) % 256, 0);
            prop_assert_eq!(peek_mnc1_kid(&meta_env).unwrap(), clip_kid);
            let dec_meta = decrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, ephemeral, &meta_env).unwrap();
            prop_assert_eq!(dec_meta, meta);
            // Cross-channel ephemeral bit mismatch MUST fail
            prop_assert_eq!(
                decrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, !ephemeral, &meta_env).unwrap_err().code(),
                ErrorCode::IntegrityError
            );
            // Cross-payload-type replay MUST fail
            prop_assert_eq!(
                decrypt_mnc1_blob(clip_kid, &key, clip_id, &dev, &meta_env).unwrap_err().code(),
                ErrorCode::IntegrityError
            );

            // Blob payload: zero padding overhead (exact 45 + len + 16)
            let blob_env = encrypt_mnc1_blob(clip_kid, &key, clip_id, &dev, &blob, nonce_blob).unwrap();
            prop_assert_eq!(blob_env.len(), MNC1_HEADER_LEN + blob.len() + MNC1_TAG_LEN);
            let dec_blob = decrypt_mnc1_blob(clip_kid, &key, clip_id, &dev, &blob_env).unwrap();
            prop_assert_eq!(dec_blob, blob);
        }

        #[test]
        fn mnc1_rejects_all_nonzero_reserved_flag_bits(reserved in 1u8..=63u8, low in 0u8..=3u8) {
            let flags = (reserved << 2) | low;
            let clip_kid = ClipKid::from_ulid(Ulid::from_parts(1_795_600_000_000, [0x01; 10]));
            let clip_id = ClipId::from_ulid(Ulid::from_parts(1_795_600_000_001, [0x02; 10]));
            let dev = DeviceId::parse("dev_01jdf8z9x4k7m2n5").unwrap();
            let err = aad_mnc1(clip_kid, clip_id, &dev, flags).unwrap_err();
            prop_assert_eq!(err.code(), ErrorCode::IntegrityError);
        }
    }

    #[test]
    fn strict_bitmap_whitelist_rejects_svg_on_both_encrypt_and_decrypt() {
        for ok_mime in ["image/png", "image/jpeg", "image/webp", "image/gif"] {
            assert!(validate_clip_image_mime(ok_mime).is_ok());
        }
        for bad_mime in [
            "image/svg+xml",
            "IMAGE/PNG",
            "image/png; charset=utf-8",
            "text/html",
            "image/bmp",
            "image/tiff",
            "application/octet-stream",
        ] {
            let err = validate_clip_image_mime(bad_mime).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
        }

        let clip_kid = ClipKid::from_ulid(Ulid::from_parts(1_795_600_000_000, [0x11; 10]));
        let clip_id = ClipId::from_ulid(Ulid::from_parts(1_795_600_000_001, [0x22; 10]));
        let dev = DeviceId::parse("dev_mac00001").unwrap();
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 24];

        let svg_meta = ClipMetaV1 {
            v: 1,
            kind: ClipKind::Image,
            mime: "image/svg+xml".into(),
            source_mode: ClipSourceMode::Explicit,
            created_at_ms: 1_795_600_000_001,
            text: None,
            blob: Some(ClipBlobMetaV1 {
                byte_size: 128,
                sha256_hex: clip_sha256_hex(b"<svg/>"),
                width: Some(100),
                height: Some(100),
                thumb_mime: None,
                thumb_b64: None,
            }),
        };
        assert_eq!(
            encrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, &svg_meta, false, nonce)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );

        // Even if a malicious sender constructs a cryptographically valid MNC1 envelope carrying image/svg+xml,
        // decrypt_mnc1_meta MUST reject it!
        let svg_json = serde_json::to_string(&svg_meta).unwrap();
        let aad = aad_mnc1(clip_kid, clip_id, &dev, 0x00).unwrap();
        let forged_env =
            encrypt_mnc1_inout(clip_kid, &key, nonce, &aad, &pad256(svg_json.as_bytes())).unwrap();
        assert_eq!(
            decrypt_mnc1_meta(clip_kid, &key, clip_id, &dev, false, &forged_env)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );

        // SVG hidden inside thumb_mime MUST also be rejected
        let bad_thumb_meta = ClipMetaV1 {
            v: 1,
            kind: ClipKind::Image,
            mime: "image/png".into(),
            source_mode: ClipSourceMode::Explicit,
            created_at_ms: 1_795_600_000_001,
            text: None,
            blob: Some(ClipBlobMetaV1 {
                byte_size: 128,
                sha256_hex: clip_sha256_hex(b"pngbytes"),
                width: Some(100),
                height: Some(100),
                thumb_mime: Some("image/svg+xml".into()),
                thumb_b64: Some(B64.encode(b"<svg/>")),
            }),
        };
        assert_eq!(
            bad_thumb_meta.validate().unwrap_err().code(),
            ErrorCode::InvalidArgument
        );

        // Oversized thumbnail (> 16 KiB) rejected
        let big_thumb = ClipMetaV1 {
            v: 1,
            kind: ClipKind::Image,
            mime: "image/png".into(),
            source_mode: ClipSourceMode::Explicit,
            created_at_ms: 1_795_600_000_001,
            text: None,
            blob: Some(ClipBlobMetaV1 {
                byte_size: 128,
                sha256_hex: clip_sha256_hex(b"pngbytes"),
                width: Some(100),
                height: Some(100),
                thumb_mime: Some("image/webp".into()),
                thumb_b64: Some(B64.encode(vec![0u8; CLIP_THUMB_MAX_BYTES + 1])),
            }),
        };
        assert_eq!(
            big_thumb.validate().unwrap_err().code(),
            ErrorCode::InvalidArgument
        );

        // Regular inline text > 64 KiB rejected; ephemeral inline text up to 256 KiB allowed
        let large_text_meta = ClipMetaV1 {
            v: 1,
            kind: ClipKind::Text,
            mime: "text/plain".into(),
            source_mode: ClipSourceMode::Explicit,
            created_at_ms: 1_795_600_000_001,
            text: Some("x".repeat(CLIP_INLINE_TEXT_MAX_BYTES + 1)),
            blob: None,
        };
        assert_eq!(
            large_text_meta.validate().unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert!(large_text_meta.validate_for_channel(true).is_ok());
    }

    #[test]
    fn clip_key_material_wrap_unwrap_rotation_and_isolation() {
        let smk_kid = SmkKid::from_ulid(Ulid::from_parts(1_795_600_000_000, [0x01; 10]));
        let other_smk_kid = SmkKid::from_ulid(Ulid::from_parts(1_795_600_000_005, [0x02; 10]));
        let smk = [0xAAu8; 32];
        let wrong_smk = [0xBBu8; 32];
        let clip_kid_v1 = ClipKid::from_ulid(Ulid::from_parts(1_795_600_000_010, [0x10; 10]));
        let clip_key_v1 = [0x11u8; 32];
        let clip_id = ClipId::from_ulid(Ulid::from_parts(1_795_600_000_020, [0x20; 10]));
        let dev = DeviceId::parse("dev_mac00001").unwrap();

        let mat_v1 = wrap_clip_key_material(smk_kid, &smk, clip_kid_v1, &clip_key_v1, [0x33; 24]).unwrap();
        assert_eq!(mat_v1.v, 1);
        assert_eq!(mat_v1.wrapped_clip_key.len(), MNCK_ENVELOPE_LEN);
        assert_eq!(&mat_v1.wrapped_clip_key[0..4], MAGIC_MNCK);
        assert_eq!(mat_v1.wrapped_clip_key[4], WIRE_VERSION);
        assert_eq!(&mat_v1.wrapped_clip_key[5..21], smk_kid.as_bytes());

        // MsgPack roundtrip + unwrap
        let encoded = encode_clip_key_material(&mat_v1).unwrap();
        let decoded = decode_clip_key_material(&encoded).unwrap();
        assert_eq!(decoded, mat_v1);
        let unwrapped = unwrap_clip_key_material(&decoded, &smk).unwrap();
        assert_eq!(*unwrapped, clip_key_v1);

        // Wrong SMK or swapped clip_kid / smk_kid fails with IntegrityError
        assert_eq!(
            unwrap_clip_key_material(&decoded, &wrong_smk).unwrap_err().code(),
            ErrorCode::IntegrityError
        );
        let mut swapped_clip_kid = decoded.clone();
        swapped_clip_kid.clip_kid = ClipKid::from_ulid(Ulid::from_parts(1_795_600_000_099, [0x99; 10]));
        assert_eq!(
            unwrap_clip_key_material(&swapped_clip_kid, &smk)
                .unwrap_err()
                .code(),
            ErrorCode::IntegrityError
        );
        let mut swapped_smk_kid = decoded.clone();
        swapped_smk_kid.smk_kid = other_smk_kid;
        assert_eq!(
            unwrap_clip_key_material(&swapped_smk_kid, &smk)
                .unwrap_err()
                .code(),
            ErrorCode::IntegrityError
        );

        // Encrypt clipboard blob under v1, then rotate to v2 -> v2 CANNOT decrypt v1 ciphertext
        let old_blob =
            encrypt_mnc1_blob(clip_kid_v1, &unwrapped, clip_id, &dev, b"secret clip", [0x44; 24]).unwrap();
        let clip_kid_v2 = ClipKid::from_ulid(Ulid::from_parts(1_795_600_000_030, [0x30; 10]));
        let (rotated_kid, rotated_key, mat_v2) =
            rotate_clip_key(smk_kid, &smk, clip_kid_v2, [0x22u8; 32], [0x55; 24]).unwrap();
        assert_eq!(rotated_kid, clip_kid_v2);
        assert_ne!(rotated_kid, clip_kid_v1);
        assert_eq!(*unwrap_clip_key_material(&mat_v2, &smk).unwrap(), *rotated_key);

        assert_eq!(
            decrypt_mnc1_blob(rotated_kid, &rotated_key, clip_id, &dev, &old_blob)
                .unwrap_err()
                .code(),
            ErrorCode::IntegrityError
        );
        assert_eq!(
            decrypt_mnc1_blob(clip_kid_v1, &rotated_key, clip_id, &dev, &old_blob)
                .unwrap_err()
                .code(),
            ErrorCode::IntegrityError
        );

        // INV-CLIP-ISOLATION: UpsertKeyMaterial(ClipKey) does NOT pollute note KeyTableState::digest()!
        let mut snap = EngineSnapshot::new(dev, 1_795_600_000_000);
        let digest_before = snap.keys.digest();
        snap.apply_mutations(&[StoreMutation::UpsertKeyMaterial {
            kind: KeyMaterialKind::ClipKey,
            gen: 1,
            blob: encoded,
            updated_at_ms: 1_795_600_000_010,
        }]);
        assert_eq!(snap.keys.digest(), digest_before);
    }

    #[test]
    fn blob_sha256_verification_roundtrip() {
        let payload = b"mynote bitmap png bytes";
        let hex = clip_sha256_hex(payload);
        assert_eq!(hex.len(), 64);
        assert!(verify_clip_blob_sha256(payload, &hex).is_ok());
        assert!(verify_clip_blob_sha256(payload, &hex.to_uppercase()).is_ok());
        assert_eq!(
            verify_clip_blob_sha256(b"tampered", &hex).unwrap_err().code(),
            ErrorCode::IntegrityError
        );
    }
}
