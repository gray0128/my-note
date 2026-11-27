use crate::error::{CoreError, ErrorCode};
use crate::ids::{BlockId, ClipKid, DeviceId, JournalEpoch, KeyId, OpId, SmkKid, Ulid, VkekKid};
use crate::model::{BlockPlaintextV1, InnerOpV1, KeyRecordRow, ShredMarkRow};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Read;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const WIRE_VERSION: u8 = 0x01;
pub const MAGIC_MNS1: &[u8; 4] = b"MNS1";
pub const MAGIC_MNB1: &[u8; 4] = b"MNB1";
pub const MAGIC_MNR1: &[u8; 4] = b"MNR1";
pub const MAGIC_MNW1: &[u8; 4] = b"MNW1";
pub const MAGIC_MNRS: &[u8; 4] = b"MNRS";
pub const MAGIC_MNVH: &[u8; 4] = b"MNVH";
pub const MAGIC_MNA1: &[u8; 4] = b"MNA1";
pub const MAGIC_MNKS: &[u8; 4] = b"MNKS";
pub const MAGIC_PAIR: &[u8; 4] = b"MNPR";
pub const MAGIC_MNC1: &[u8; 4] = b"MNC1";
pub const MAGIC_MNCK: &[u8; 4] = b"MNCK";

pub const MNRS_KIND_SMK: u8 = 0x01;
pub const MNRS_KIND_VKEK: u8 = 0x02;

const HEADER_LEN: usize = 4 + 1 + 16 + 24; // 45 bytes
const MNRS_HEADER_LEN: usize = 4 + 1 + 16 + 1 + 16 + 32 + 24; // 94 bytes
const AEAD_TAG_LEN: usize = 16;

fn integrity_err(msg: impl Into<String>) -> CoreError {
    CoreError::new(
        ErrorCode::IntegrityError,
        msg,
        "Envelope or container authentication failed; data was tampered with or key/AAD mismatched",
    )
}

/// Deterministic bijective 256-byte bucket padding (`docs/data-structures.md` §3.1).
pub fn pad256(raw: &[u8]) -> Vec<u8> {
    let pad_zeros = (256 - ((raw.len() + 1) % 256)) % 256;
    let mut out = Vec::with_capacity(raw.len() + pad_zeros + 1);
    out.extend_from_slice(raw);
    out.resize(raw.len() + pad_zeros, 0u8);
    out.push(pad_zeros as u8);
    out
}

/// Strict canonical unpadding rejecting non-zero padding bytes or invalid length (`docs/data-structures.md` §3.1).
pub fn unpad256(padded: &[u8]) -> Result<&[u8], CoreError> {
    if padded.len() < 256 || !padded.len().is_multiple_of(256) {
        return Err(integrity_err(format!(
            "invalid padded length {}: must be positive multiple of 256",
            padded.len()
        )));
    }
    let p = padded[padded.len() - 1] as usize;
    if p + 1 > padded.len() {
        return Err(integrity_err("padding length exceeds frame"));
    }
    let data_end = padded.len() - 1 - p;
    if padded[data_end..padded.len() - 1].iter().any(|&b| b != 0) {
        return Err(integrity_err("non-canonical non-zero padding byte detected"));
    }
    Ok(&padded[..data_end])
}

/// Pure-Rust Zstandard compression (verified frame-compatible with native libzstd in S0-3).
pub fn compress_zstd(raw: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(raw, ruzstd::encoding::CompressionLevel::Fastest)
}

/// Pure-Rust Zstandard decompression (`docs/spikes/s0-3-wasm-argon2.md`).
pub fn decompress_zstd(compressed: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(compressed)
        .map_err(|e| integrity_err(format!("zstd header error: {e}")))?;
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| integrity_err(format!("zstd decode error: {e}")))?;
    Ok(out)
}

fn encrypt_envelope(
    magic: &[u8; 4],
    kid: &[u8; 16],
    key: &[u8; 32],
    nonce: [u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from(nonce);
    let ct = cipher
        .encrypt(&xnonce, Payload { msg: plaintext, aad })
        .map_err(|_| integrity_err("XChaCha20-Poly1305 encryption failed"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(magic);
    out.push(WIRE_VERSION);
    out.extend_from_slice(kid);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

struct EnvelopeHeader<'a> {
    kid: [u8; 16],
    nonce: [u8; 24],
    ciphertext: &'a [u8],
}

fn parse_header<'a>(expected_magic: &[u8; 4], data: &'a [u8]) -> Result<EnvelopeHeader<'a>, CoreError> {
    if data.len() < HEADER_LEN + AEAD_TAG_LEN {
        return Err(integrity_err("envelope truncated"));
    }
    if &data[0..4] != expected_magic {
        return Err(integrity_err("envelope magic mismatch"));
    }
    if data[4] != WIRE_VERSION {
        return Err(integrity_err(format!("unsupported envelope version {}", data[4])));
    }
    let mut kid = [0u8; 16];
    kid.copy_from_slice(&data[5..21]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[21..45]);
    Ok(EnvelopeHeader {
        kid,
        nonce,
        ciphertext: &data[45..],
    })
}

fn decrypt_envelope(
    expected_magic: &[u8; 4],
    expected_kid: &[u8; 16],
    key: &[u8; 32],
    aad: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let hdr = parse_header(expected_magic, data)?;
    if &hdr.kid != expected_kid {
        return Err(integrity_err("envelope header kid does not match expected kid"));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from(hdr.nonce);
    cipher
        .decrypt(
            &xnonce,
            Payload {
                msg: hdr.ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| integrity_err("AEAD tag or AAD verification failed"))
}

/// Extract the 16-byte `kid` from a standard 45-byte envelope header without decrypting.
pub fn peek_envelope_kid(expected_magic: &[u8; 4], data: &[u8]) -> Result<[u8; 16], CoreError> {
    Ok(parse_header(expected_magic, data)?.kid)
}

// ---------- Exact AAD builders (SINGLE SOURCE OF TRUTH: docs/data-structures.md §3.3) ----------

fn aad_mns1(smk_kid: SmkKid, op_id: OpId, device_id: &DeviceId, key_id: Option<KeyId>) -> Vec<u8> {
    let dev = device_id.as_bytes();
    let mut aad = Vec::with_capacity(5 + 16 + 16 + dev.len() + 16);
    aad.extend_from_slice(MAGIC_MNS1);
    aad.push(WIRE_VERSION);
    aad.extend_from_slice(smk_kid.as_bytes());
    aad.extend_from_slice(op_id.as_bytes());
    aad.extend_from_slice(dev);
    match key_id {
        Some(k) => aad.extend_from_slice(k.as_bytes()),
        None => aad.extend_from_slice(&[0u8; 16]),
    }
    aad
}

fn aad_mnb1(entity_id: &[u8; 16], op_id: OpId, key_id: KeyId) -> [u8; 5 + 16 + 16 + 16] {
    let mut aad = [0u8; 53];
    aad[0..4].copy_from_slice(MAGIC_MNB1);
    aad[4] = WIRE_VERSION;
    aad[5..21].copy_from_slice(entity_id);
    aad[21..37].copy_from_slice(op_id.as_bytes());
    aad[37..53].copy_from_slice(key_id.as_bytes());
    aad
}

fn aad_mnr1(smk_kid: SmkKid, key_id: KeyId, wrap_gen: u32) -> [u8; 5 + 16 + 16 + 4] {
    let mut aad = [0u8; 41];
    aad[0..4].copy_from_slice(MAGIC_MNR1);
    aad[4] = WIRE_VERSION;
    aad[5..21].copy_from_slice(smk_kid.as_bytes());
    aad[21..37].copy_from_slice(key_id.as_bytes());
    aad[37..41].copy_from_slice(&wrap_gen.to_le_bytes());
    aad
}

fn aad_mnw1(vkek_kid: VkekKid, key_id: KeyId, block_id: BlockId) -> [u8; 5 + 16 + 16 + 16] {
    let mut aad = [0u8; 53];
    aad[0..4].copy_from_slice(MAGIC_MNW1);
    aad[4] = WIRE_VERSION;
    aad[5..21].copy_from_slice(vkek_kid.as_bytes());
    aad[21..37].copy_from_slice(key_id.as_bytes());
    aad[37..53].copy_from_slice(block_id.as_bytes());
    aad
}

fn aad_mnrs(recovery_kid: &[u8; 16], kind: u8, kid: &[u8; 16]) -> [u8; 5 + 16 + 1 + 16] {
    let mut aad = [0u8; 38];
    aad[0..4].copy_from_slice(MAGIC_MNRS);
    aad[4] = WIRE_VERSION;
    aad[5..21].copy_from_slice(recovery_kid);
    aad[21] = kind;
    aad[22..38].copy_from_slice(kid);
    aad
}

fn aad_mnvh(vkek_kid: VkekKid, kdf: &KdfParamsV1) -> Result<Vec<u8>, CoreError> {
    let kdf_bytes = rmp_serde::to_vec_named(kdf).map_err(|e| integrity_err(e.to_string()))?;
    let mut aad = Vec::with_capacity(5 + 16 + kdf_bytes.len());
    aad.extend_from_slice(MAGIC_MNVH);
    aad.push(WIRE_VERSION);
    aad.extend_from_slice(vkek_kid.as_bytes());
    aad.extend_from_slice(&kdf_bytes);
    Ok(aad)
}

// ---------- (1) MNS1 Op Envelope ----------

pub fn encrypt_mns1(
    smk_kid: SmkKid,
    smk: &[u8; 32],
    op_id: OpId,
    device_id: &DeviceId,
    inner: &InnerOpV1,
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let packed = rmp_serde::to_vec_named(inner).map_err(|e| integrity_err(e.to_string()))?;
    let padded = pad256(&packed);
    let aad = aad_mns1(smk_kid, op_id, device_id, inner.key_id());
    encrypt_envelope(MAGIC_MNS1, smk_kid.as_bytes(), smk, nonce, &aad, &padded)
}

pub fn decrypt_mns1(
    smk_kid: SmkKid,
    smk: &[u8; 32],
    op_id: OpId,
    device_id: &DeviceId,
    outer_key_id: Option<KeyId>,
    envelope: &[u8],
) -> Result<InnerOpV1, CoreError> {
    let aad = aad_mns1(smk_kid, op_id, device_id, outer_key_id);
    let padded = decrypt_envelope(MAGIC_MNS1, smk_kid.as_bytes(), smk, &aad, envelope)?;
    let raw = unpad256(&padded)?;
    let inner: InnerOpV1 = rmp_serde::from_slice(raw).map_err(|e| integrity_err(e.to_string()))?;
    if inner.key_id() != outer_key_id {
        return Err(integrity_err("inner key_id does not match outer key_id"));
    }
    Ok(inner)
}

// ---------- (2) MNB1 Block/Buffer Content Envelope ----------

pub fn encrypt_mnb1(
    entity_id: &[u8; 16],
    op_id: OpId,
    key_id: KeyId,
    bdek: &[u8; 32],
    content: &str,
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let pt = BlockPlaintextV1 {
        content: content.to_string(),
    };
    let packed = Zeroizing::new(rmp_serde::to_vec_named(&pt).map_err(|e| integrity_err(e.to_string()))?);
    let compressed = Zeroizing::new(compress_zstd(&packed));
    let padded = Zeroizing::new(pad256(&compressed));
    let aad = aad_mnb1(entity_id, op_id, key_id);
    encrypt_envelope(MAGIC_MNB1, key_id.as_bytes(), bdek, nonce, &aad, &padded)
}

pub fn decrypt_mnb1(
    entity_id: &[u8; 16],
    op_id: OpId,
    key_id: KeyId,
    bdek: &[u8; 32],
    mnb1: &[u8],
) -> Result<String, CoreError> {
    let aad = aad_mnb1(entity_id, op_id, key_id);
    let padded = decrypt_envelope(MAGIC_MNB1, key_id.as_bytes(), bdek, &aad, mnb1)?;
    let compressed = unpad256(&padded)?;
    let packed = Zeroizing::new(decompress_zstd(compressed)?);
    let pt: BlockPlaintextV1 = rmp_serde::from_slice(&packed).map_err(|e| integrity_err(e.to_string()))?;
    Ok(pt.content)
}

// ---------- (3) MNR1 Key Record Envelope ----------

/// Plaintext inside `MNR1` (`docs/data-structures.md` §3.4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecordV1 {
    pub v: u8,
    pub key_id: KeyId,
    /// Owning entity ULID (`BlockId` for blocks, `BufferId` for buffers).
    pub block_id: Ulid,
    /// `1` (Tier 1 raw 32B BDEK) or `2` (Tier 2 `MNW1` wrapped BDEK).
    pub tier: u8,
    pub created_hlc: String,
    pub created_by: DeviceId,
    pub bdek: Vec<u8>,
}

pub fn encrypt_mnr1(
    smk_kid: SmkKid,
    smk: &[u8; 32],
    wrap_gen: u32,
    record: &KeyRecordV1,
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let packed = Zeroizing::new(rmp_serde::to_vec_named(record).map_err(|e| integrity_err(e.to_string()))?);
    let aad = aad_mnr1(smk_kid, record.key_id, wrap_gen);
    encrypt_envelope(MAGIC_MNR1, smk_kid.as_bytes(), smk, nonce, &aad, &packed)
}

pub fn decrypt_mnr1(
    smk_kid: SmkKid,
    smk: &[u8; 32],
    expected_key_id: KeyId,
    wrap_gen: u32,
    mnr1: &[u8],
) -> Result<KeyRecordV1, CoreError> {
    let aad = aad_mnr1(smk_kid, expected_key_id, wrap_gen);
    let packed = decrypt_envelope(MAGIC_MNR1, smk_kid.as_bytes(), smk, &aad, mnr1)?;
    let rec: KeyRecordV1 = rmp_serde::from_slice(&packed).map_err(|e| integrity_err(e.to_string()))?;
    if rec.key_id != expected_key_id {
        return Err(integrity_err("MNR1 inner key_id mismatch"));
    }
    Ok(rec)
}

// ---------- (4) MNW1 Tier 2 BDEK Wrapper (M2 ready) ----------

pub fn encrypt_mnw1(
    vkek_kid: VkekKid,
    vkek: &[u8; 32],
    key_id: KeyId,
    block_id: BlockId,
    bdek: &[u8; 32],
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let aad = aad_mnw1(vkek_kid, key_id, block_id);
    encrypt_envelope(MAGIC_MNW1, vkek_kid.as_bytes(), vkek, nonce, &aad, bdek)
}

pub fn decrypt_mnw1(
    vkek_kid: VkekKid,
    vkek: &[u8; 32],
    key_id: KeyId,
    block_id: BlockId,
    mnw1: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let aad = aad_mnw1(vkek_kid, key_id, block_id);
    let raw = decrypt_envelope(MAGIC_MNW1, vkek_kid.as_bytes(), vkek, &aad, mnw1)?;
    if raw.len() != 32 {
        return Err(integrity_err("MNW1 unwrapped BDEK must be 32 bytes"));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    Ok(out)
}

// ---------- (5) Unified 24-Word Recovery Bundle, MNRS Sealed Box, RecoveryKeyringV1, VaultHeaderV1 ----------

/// Default Argon2id parameters for `VaultHeaderV1`, calibrated on iPhone standalone PWA
/// (`docs/spikes/s0-3-wasm-argon2.md`: 1553 ms median, 33.19 MiB peak linear memory).
pub const DEFAULT_ARGON2_M_KIB: u32 = 32_768;
pub const DEFAULT_ARGON2_T: u32 = 2;
pub const DEFAULT_ARGON2_P: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParamsV1 {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: [u8; 16],
}

impl KdfParamsV1 {
    pub fn argon2id_default(salt: [u8; 16]) -> Self {
        Self {
            alg: "argon2id".to_string(),
            m_kib: DEFAULT_ARGON2_M_KIB,
            t: DEFAULT_ARGON2_T,
            p: DEFAULT_ARGON2_P,
            salt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryKeyringV1 {
    pub v: u8,
    pub recovery_kid: [u8; 16],
    pub recovery_pk: [u8; 32],
    pub keyring_gen: u32,
    pub current_smk_kid: SmkKid,
    pub smk_entries: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredVkekV1 {
    pub vkek_kid: VkekKid,
    pub wrapped_vkek: Vec<u8>,
    pub sealed_vkek: Vec<u8>,
    pub retired_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeaderV1 {
    pub v: u8,
    pub vkek_kid: VkekKid,
    pub kdf: KdfParamsV1,
    pub wrapped_vkek: Vec<u8>,
    pub sealed_vkek: Vec<u8>,
    pub retired: Vec<RetiredVkekV1>,
    pub updated_at_ms: i64,
}

pub struct RecoveryKeypair {
    pub recovery_kid: [u8; 16],
    pub recovery_pk: [u8; 32],
    recovery_sk: Zeroizing<[u8; 32]>,
}

impl RecoveryKeypair {
    /// Derive recovery keypair from 256-bit entropy (`docs/data-structures.md` §3.5).
    pub fn from_entropy(entropy: &[u8; 32]) -> Result<(Self, String), CoreError> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                e.to_string(),
                "Provide 32 bytes of entropy",
            )
        })?;
        let words = mnemonic.to_string();
        let kp = Self::derive_from_entropy_bytes(entropy)?;
        Ok((kp, words))
    }

    /// Re-derive recovery keypair offline from the 24 English recovery words.
    pub fn from_mnemonic_words(words: &str) -> Result<Self, CoreError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, words).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid 24-word recovery bundle: {e}"),
                "Verify all 24 BIP-39 English words and their order",
            )
        })?;
        let entropy_vec = Zeroizing::new(mnemonic.to_entropy());
        if entropy_vec.len() != 32 {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "recovery bundle must have 24 words (256-bit entropy)",
                "Provide the 24-word unified recovery bundle",
            ));
        }
        let mut entropy = Zeroizing::new([0u8; 32]);
        entropy.copy_from_slice(&entropy_vec);
        Self::derive_from_entropy_bytes(&entropy)
    }

    fn derive_from_entropy_bytes(entropy: &[u8; 32]) -> Result<Self, CoreError> {
        let hk1 = Hkdf::<Sha256>::new(Some(b"mynote-recovery-v1"), entropy);
        let mut root_seed = Zeroizing::new([0u8; 32]);
        hk1.expand(b"seed", root_seed.as_mut())
            .map_err(|_| integrity_err("HKDF seed expansion failed"))?;

        let hk2 = Hkdf::<Sha256>::new(None, root_seed.as_ref());
        let mut sk_bytes = Zeroizing::new([0u8; 32]);
        hk2.expand(b"x25519-recovery", sk_bytes.as_mut())
            .map_err(|_| integrity_err("HKDF x25519 expansion failed"))?;

        let sk = StaticSecret::from(*sk_bytes);
        let pk = PublicKey::from(&sk);
        let pk_bytes = pk.to_bytes();
        let digest = blake3::hash(&pk_bytes);
        let mut recovery_kid = [0u8; 16];
        recovery_kid.copy_from_slice(&digest.as_bytes()[..16]);

        Ok(Self {
            recovery_kid,
            recovery_pk: pk_bytes,
            recovery_sk: Zeroizing::new(sk.to_bytes()),
        })
    }

    pub fn unseal_mnrs(
        &self,
        expected_kind: u8,
        mnrs: &[u8],
    ) -> Result<([u8; 16], Zeroizing<[u8; 32]>), CoreError> {
        if mnrs.len() != MNRS_HEADER_LEN + 32 + AEAD_TAG_LEN {
            return Err(integrity_err("invalid MNRS length"));
        }
        if &mnrs[0..4] != MAGIC_MNRS || mnrs[4] != WIRE_VERSION {
            return Err(integrity_err("invalid MNRS magic or version"));
        }
        let mut rec_kid = [0u8; 16];
        rec_kid.copy_from_slice(&mnrs[5..21]);
        if rec_kid != self.recovery_kid {
            return Err(integrity_err("MNRS recovery_kid does not match recovery bundle"));
        }
        let kind = mnrs[21];
        if kind != expected_kind {
            return Err(integrity_err("MNRS key kind mismatch"));
        }
        let mut kid = [0u8; 16];
        kid.copy_from_slice(&mnrs[22..38]);
        let mut eph_pk_bytes = [0u8; 32];
        eph_pk_bytes.copy_from_slice(&mnrs[38..70]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&mnrs[70..94]);
        let ct = &mnrs[94..];

        let sk = StaticSecret::from(*self.recovery_sk);
        let eph_pk = PublicKey::from(eph_pk_bytes);
        let shared = sk.diffie_hellman(&eph_pk);
        if shared.as_bytes().iter().all(|&b| b == 0) {
            return Err(integrity_err(
                "rejected low-order X25519 point (all-zero shared secret)",
            ));
        }

        let mut salt = [0u8; 64];
        salt[0..32].copy_from_slice(&eph_pk_bytes);
        salt[32..64].copy_from_slice(&self.recovery_pk);
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut aead_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"mynote-seal-v1", aead_key.as_mut())
            .map_err(|_| integrity_err("HKDF MNRS expansion failed"))?;

        let aad = aad_mnrs(&rec_kid, kind, &kid);
        let cipher = XChaCha20Poly1305::new((&*aead_key).into());
        let xnonce = XNonce::from(nonce);
        let pt = Zeroizing::new(
            cipher
                .decrypt(&xnonce, Payload { msg: ct, aad: &aad })
                .map_err(|_| integrity_err("MNRS AEAD decryption failed"))?,
        );
        if pt.len() != 32 {
            return Err(integrity_err("MNRS plaintext must be 32 bytes"));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&pt);
        Ok((kid, secret))
    }

    /// Unseal ALL historical and current SMK generations from `RecoveryKeyringV1`.
    pub fn unseal_all_smks(&self, keyring: &RecoveryKeyringV1) -> Result<Vec<UnsealedSmk>, CoreError> {
        let mut out = Vec::with_capacity(keyring.smk_entries.len());
        for entry in &keyring.smk_entries {
            let (kid_bytes, smk) = self.unseal_mnrs(MNRS_KIND_SMK, entry)?;
            out.push((SmkKid::from_bytes(kid_bytes), smk));
        }
        Ok(out)
    }
}

pub type UnsealedSmk = (SmkKid, Zeroizing<[u8; 32]>);

/// Seal a 32-byte SMK or VKEK to a device-stored `recovery_pk` (NO 24 words needed!).
pub fn seal_mnrs(
    recovery_pk: &[u8; 32],
    kind: u8,
    kid: &[u8; 16],
    secret_32: &[u8; 32],
    eph_sk_bytes: [u8; 32],
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let eph_sk_bytes = Zeroizing::new(eph_sk_bytes);
    let digest = blake3::hash(recovery_pk);
    let mut recovery_kid = [0u8; 16];
    recovery_kid.copy_from_slice(&digest.as_bytes()[..16]);

    let eph_sk = StaticSecret::from(*eph_sk_bytes);
    let eph_pk = PublicKey::from(&eph_sk);
    let eph_pk_bytes = eph_pk.to_bytes();
    let rec_pk = PublicKey::from(*recovery_pk);

    let shared = eph_sk.diffie_hellman(&rec_pk);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(integrity_err(
            "rejected low-order X25519 point (all-zero shared secret)",
        ));
    }

    let mut salt = [0u8; 64];
    salt[0..32].copy_from_slice(&eph_pk_bytes);
    salt[32..64].copy_from_slice(recovery_pk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut aead_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"mynote-seal-v1", aead_key.as_mut())
        .map_err(|_| integrity_err("HKDF MNRS expansion failed"))?;

    let aad = aad_mnrs(&recovery_kid, kind, kid);
    let cipher = XChaCha20Poly1305::new((&*aead_key).into());
    let xnonce = XNonce::from(nonce);
    let ct = cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: secret_32,
                aad: &aad,
            },
        )
        .map_err(|_| integrity_err("MNRS encryption failed"))?;

    let mut out = Vec::with_capacity(MNRS_HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC_MNRS);
    out.push(WIRE_VERSION);
    out.extend_from_slice(&recovery_kid);
    out.push(kind);
    out.extend_from_slice(kid);
    out.extend_from_slice(&eph_pk_bytes);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Safe Argon2id KDF parameter bounds (`docs/threat-model.md` §2.1 & WASM DoS protection).
pub const MIN_ARGON2_M_KIB: u32 = 19_456;
pub const MAX_ARGON2_M_KIB: u32 = 262_144;
pub const MIN_ARGON2_T: u32 = 1;
pub const MAX_ARGON2_T: u32 = 10;
pub const MIN_ARGON2_P: u32 = 1;
pub const MAX_ARGON2_P: u32 = 4;

/// Derive a 32-byte key from a Vault passphrase using Argon2id parameters stored in `VaultHeaderV1`.
pub fn derive_passphrase_key(passphrase: &[u8], kdf: &KdfParamsV1) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    if kdf.alg != "argon2id" {
        return Err(integrity_err(format!("unsupported KDF algorithm '{}'", kdf.alg)));
    }
    if !(MIN_ARGON2_M_KIB..=MAX_ARGON2_M_KIB).contains(&kdf.m_kib)
        || !(MIN_ARGON2_T..=MAX_ARGON2_T).contains(&kdf.t)
        || !(MIN_ARGON2_P..=MAX_ARGON2_P).contains(&kdf.p)
    {
        return Err(integrity_err(format!(
            "Argon2id params out of safe bounds (m_kib={}, t={}, p={})",
            kdf.m_kib, kdf.t, kdf.p
        )));
    }
    let params = argon2::Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32))
        .map_err(|e| integrity_err(format!("invalid Argon2id params: {e}")))?;
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(passphrase, &kdf.salt, out.as_mut())
        .map_err(|e| integrity_err(format!("Argon2id derivation failed: {e}")))?;
    Ok(out)
}

/// Wrap VKEK with passphrase-derived key (`MNVH`, `docs/data-structures.md` §3.2 / §3.3).
pub fn encrypt_mnvh(
    vkek_kid: VkekKid,
    pass_key: &[u8; 32],
    kdf: &KdfParamsV1,
    vkek: &[u8; 32],
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let aad = aad_mnvh(vkek_kid, kdf)?;
    encrypt_envelope(MAGIC_MNVH, vkek_kid.as_bytes(), pass_key, nonce, &aad, vkek)
}

pub fn decrypt_mnvh(
    vkek_kid: VkekKid,
    pass_key: &[u8; 32],
    kdf: &KdfParamsV1,
    mnvh: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let aad = aad_mnvh(vkek_kid, kdf)?;
    let raw = decrypt_envelope(MAGIC_MNVH, vkek_kid.as_bytes(), pass_key, &aad, mnvh)?;
    if raw.len() != 32 {
        return Err(integrity_err("MNVH unwrapped VKEK must be 32 bytes"));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    Ok(out)
}

// ---------- One-Time Pairing Ticket Ciphertext (`pairing_tickets.ciphertext`) ----------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmkGenerationBytes {
    pub smk_kid: SmkKid,
    pub key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingPayloadV1 {
    pub smks: Vec<SmkGenerationBytes>,
    pub device_token: Option<String>,
    pub device_id: DeviceId,
    pub sync_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clip_kid: Option<ClipKid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clip_key: Option<[u8; 32]>,
}

pub fn encrypt_pairing_ticket(
    pair_id: &str,
    k_pair: &[u8; 32],
    payload: &PairingPayloadV1,
    nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let packed = Zeroizing::new(rmp_serde::to_vec_named(payload).map_err(|e| integrity_err(e.to_string()))?);
    let mut aad = Vec::with_capacity(5 + pair_id.len());
    aad.extend_from_slice(MAGIC_PAIR);
    aad.push(WIRE_VERSION);
    aad.extend_from_slice(pair_id.as_bytes());
    let cipher = XChaCha20Poly1305::new(k_pair.into());
    let xnonce = XNonce::from(nonce);
    let ct = cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: &packed,
                aad: &aad,
            },
        )
        .map_err(|_| integrity_err("pairing ticket encryption failed"))?;
    let mut out = Vec::with_capacity(5 + 24 + ct.len());
    out.extend_from_slice(MAGIC_PAIR);
    out.push(WIRE_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_pairing_ticket(
    pair_id: &str,
    k_pair: &[u8; 32],
    ciphertext: &[u8],
) -> Result<PairingPayloadV1, CoreError> {
    if ciphertext.len() < 5 + 24 + AEAD_TAG_LEN {
        return Err(integrity_err("pairing ticket truncated"));
    }
    if &ciphertext[0..4] != MAGIC_PAIR || ciphertext[4] != WIRE_VERSION {
        return Err(integrity_err("invalid pairing ticket magic/version"));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&ciphertext[5..29]);
    let ct = &ciphertext[29..];
    let mut aad = Vec::with_capacity(5 + pair_id.len());
    aad.extend_from_slice(MAGIC_PAIR);
    aad.push(WIRE_VERSION);
    aad.extend_from_slice(pair_id.as_bytes());
    let cipher = XChaCha20Poly1305::new(k_pair.into());
    let xnonce = XNonce::from(nonce);
    let pt = Zeroizing::new(
        cipher
            .decrypt(&xnonce, Payload { msg: ct, aad: &aad })
            .map_err(|_| integrity_err("pairing ticket decryption failed"))?,
    );
    rmp_serde::from_slice(&pt).map_err(|e| integrity_err(e.to_string()))
}

// ---------- R2 Archive Containers: MNA1 (ops) & MNKS (key snapshot) (`docs/data-structures.md` §3.7) ----------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveOpsHeaderV1 {
    pub journal_epoch: JournalEpoch,
    pub from_seq: i64,
    pub to_seq: i64,
    pub row_count: u32,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedOpRow {
    pub seq: i64,
    pub op_id: OpId,
    pub key_id: Option<KeyId>,
    pub device_id: DeviceId,
    pub created_at: i64,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySnapshotHeaderV1 {
    pub created_at_ms: i64,
    pub keyring_gen: u32,
    pub record_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySnapshotBodyV1 {
    pub keyring: RecoveryKeyringV1,
    pub vault_header: Option<VaultHeaderV1>,
    pub records: Vec<KeyRecordRow>,
    pub marks: Vec<ShredMarkRow>,
}

fn encode_hashed_container<H: Serialize, B: Serialize>(
    magic: &[u8; 4],
    header: &H,
    body: &B,
) -> Result<Vec<u8>, CoreError> {
    let hdr_bytes = rmp_serde::to_vec_named(header).map_err(|e| integrity_err(e.to_string()))?;
    let body_bytes = rmp_serde::to_vec_named(body).map_err(|e| integrity_err(e.to_string()))?;
    let mut out = Vec::with_capacity(4 + 1 + 4 + hdr_bytes.len() + body_bytes.len() + 32);
    out.extend_from_slice(magic);
    out.push(WIRE_VERSION);
    out.extend_from_slice(&(hdr_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&hdr_bytes);
    out.extend_from_slice(&body_bytes);
    let digest = blake3::hash(&out);
    out.extend_from_slice(digest.as_bytes());
    Ok(out)
}

fn decode_hashed_container<H: for<'de> Deserialize<'de>, B: for<'de> Deserialize<'de>>(
    expected_magic: &[u8; 4],
    raw: &[u8],
) -> Result<(H, B), CoreError> {
    if raw.len() < 4 + 1 + 4 + 32 {
        return Err(integrity_err("archive container truncated"));
    }
    if &raw[0..4] != expected_magic || raw[4] != WIRE_VERSION {
        return Err(integrity_err("archive container magic/version mismatch"));
    }
    let payload_end = raw.len() - 32;
    let expected_hash = blake3::hash(&raw[..payload_end]);
    if expected_hash.as_bytes() != &raw[payload_end..] {
        return Err(integrity_err("archive container BLAKE3 checksum mismatch"));
    }
    let hdr_len = u32::from_le_bytes([raw[5], raw[6], raw[7], raw[8]]) as usize;
    let hdr_end = 9usize
        .checked_add(hdr_len)
        .filter(|&e| e <= payload_end)
        .ok_or_else(|| integrity_err("archive container header length out of bounds"))?;
    let header: H = rmp_serde::from_slice(&raw[9..hdr_end]).map_err(|e| integrity_err(e.to_string()))?;
    let body: B =
        rmp_serde::from_slice(&raw[hdr_end..payload_end]).map_err(|e| integrity_err(e.to_string()))?;
    Ok((header, body))
}

pub fn encode_mna1(header: &ArchiveOpsHeaderV1, rows: &[ArchivedOpRow]) -> Result<Vec<u8>, CoreError> {
    encode_hashed_container(MAGIC_MNA1, header, &rows)
}

pub fn decode_mna1(raw: &[u8]) -> Result<(ArchiveOpsHeaderV1, Vec<ArchivedOpRow>), CoreError> {
    decode_hashed_container(MAGIC_MNA1, raw)
}

pub fn encode_mnks(header: &KeySnapshotHeaderV1, body: &KeySnapshotBodyV1) -> Result<Vec<u8>, CoreError> {
    encode_hashed_container(MAGIC_MNKS, header, body)
}

pub fn decode_mnks(raw: &[u8]) -> Result<(KeySnapshotHeaderV1, KeySnapshotBodyV1), CoreError> {
    decode_hashed_container(MAGIC_MNKS, raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;
    use crate::ids::{BufferId, MonotonicUlidGen};
    use crate::model::{EntityType, OpBodyV1, OpType};
    use proptest::prelude::*;

    proptest! {
        // SEC-04: Bijective 256B padding lossless roundtrip across random lengths & boundary bytes
        #[test]
        fn sec04_pad256_roundtrip_and_alignment(data in prop::collection::vec(any::<u8>(), 0..8192)) {
            let padded = pad256(&data);
            prop_assert!(padded.len() >= 256);
            prop_assert_eq!(padded.len() % 256, 0);
            let recovered = unpad256(&padded).unwrap();
            prop_assert_eq!(recovered, data.as_slice());
        }
    }

    #[test]
    fn sec04_pad256_boundary_and_tamper_rejection() {
        for len in [0usize, 1, 254, 255, 256, 257, 511, 512] {
            for fill in [0x00u8, 0x80u8, 0xFFu8] {
                let raw = vec![fill; len];
                let mut padded = pad256(&raw);
                assert_eq!(unpad256(&padded).unwrap(), raw.as_slice());
                // Flip a padding zero byte when pad_zeros > 0 -> must reject
                let p = *padded.last().unwrap() as usize;
                if p > 0 {
                    let flip_idx = padded.len() - 2;
                    padded[flip_idx] = 0x01;
                    assert!(unpad256(&padded).is_err());
                }
            }
        }
    }

    #[test]
    fn all_envelopes_roundtrip_and_reject_tampering_or_aad_swap() {
        let mut g = MonotonicUlidGen::new();
        let smk_kid = SmkKid::from_ulid(g.next(100, [1; 10]));
        let smk = [0x11u8; 32];
        let vkek_kid = VkekKid::from_ulid(g.next(100, [2; 10]));
        let vkek = [0x22u8; 32];
        let bdek = [0x33u8; 32];
        let key_id = KeyId::from_ulid(g.next(100, [3; 10]));
        let block_id = BlockId::from_ulid(g.next(100, [4; 10]));
        let other_block = BlockId::from_ulid(g.next(100, [5; 10]));
        let op_id = OpId::from_ulid(g.next(100, [6; 10]));
        let other_op = OpId::from_ulid(g.next(100, [7; 10]));
        let dev = DeviceId::parse("dev_mac00001").unwrap();
        let other_dev = DeviceId::parse("dev_lin00002").unwrap();

        // 1. MNB1 roundtrip + swap entity_id / op_id / key_id -> MUST fail
        let mnb1 = encrypt_mnb1(
            block_id.as_bytes(),
            op_id,
            key_id,
            &bdek,
            "secret note 中文",
            [1u8; 24],
        )
        .unwrap();
        assert_eq!(
            decrypt_mnb1(block_id.as_bytes(), op_id, key_id, &bdek, &mnb1).unwrap(),
            "secret note 中文"
        );
        assert!(decrypt_mnb1(other_block.as_bytes(), op_id, key_id, &bdek, &mnb1).is_err());
        assert!(decrypt_mnb1(block_id.as_bytes(), other_op, key_id, &bdek, &mnb1).is_err());
        let mut flipped = mnb1.clone();
        flipped[50] ^= 0x01;
        assert!(decrypt_mnb1(block_id.as_bytes(), op_id, key_id, &bdek, &flipped).is_err());

        // 2. MNS1 roundtrip + device_id / op_id / key_id swap -> MUST fail
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: block_id.to_string(),
            op_type: OpType::Create,
            parent_op_ids: vec![],
            hlc: Hlc::new(1000, 0, dev.clone()),
            actor: "human".into(),
            body: OpBodyV1::BlockContent {
                buffer_id: Some(BufferId::from_ulid(g.next(100, [8; 10]))),
                position: Some("V0001".into()),
                lang: Some("markdown".into()),
                public_hint: None,
                tier: 1,
                key_id,
                mnb1: mnb1.clone(),
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &dev, &inner, [2u8; 24]).unwrap();
        assert_eq!(
            decrypt_mns1(smk_kid, &smk, op_id, &dev, Some(key_id), &mns1).unwrap(),
            inner
        );
        assert!(decrypt_mns1(smk_kid, &smk, op_id, &other_dev, Some(key_id), &mns1).is_err());
        assert!(decrypt_mns1(smk_kid, &smk, other_op, &dev, Some(key_id), &mns1).is_err());
        assert!(decrypt_mns1(smk_kid, &smk, op_id, &dev, None, &mns1).is_err());

        // 3. MNR1 + MNW1 roundtrip + wrap_gen / block_id swap -> MUST fail
        let mnw1 = encrypt_mnw1(vkek_kid, &vkek, key_id, block_id, &bdek, [3u8; 24]).unwrap();
        assert_eq!(
            *decrypt_mnw1(vkek_kid, &vkek, key_id, block_id, &mnw1).unwrap(),
            bdek
        );
        assert!(decrypt_mnw1(vkek_kid, &vkek, key_id, other_block, &mnw1).is_err());

        let rec = KeyRecordV1 {
            v: 1,
            key_id,
            block_id: block_id.0,
            tier: 2,
            created_hlc: Hlc::new(1000, 0, dev.clone()).canonical_string(),
            created_by: dev.clone(),
            bdek: mnw1,
        };
        let mnr1 = encrypt_mnr1(smk_kid, &smk, 1, &rec, [4u8; 24]).unwrap();
        assert_eq!(decrypt_mnr1(smk_kid, &smk, key_id, 1, &mnr1).unwrap(), rec);
        assert!(decrypt_mnr1(smk_kid, &smk, key_id, 2, &mnr1).is_err()); // wrong wrap_gen!

        // 4. Pairing ticket roundtrip + pair_id swap -> MUST fail
        let pair_payload = PairingPayloadV1 {
            smks: vec![SmkGenerationBytes { smk_kid, key: smk }],
            device_token: Some("tok_secret_123".into()),
            device_id: other_dev.clone(),
            sync_url: "https://note.example.com".into(),
            clip_kid: None,
            clip_key: None,
        };
        let k_pair = [0x99u8; 32];
        let pair_ct = encrypt_pairing_ticket("pair_abc", &k_pair, &pair_payload, [5u8; 24]).unwrap();
        assert_eq!(
            decrypt_pairing_ticket("pair_abc", &k_pair, &pair_ct).unwrap(),
            pair_payload
        );
        assert!(decrypt_pairing_ticket("pair_wrong", &k_pair, &pair_ct).is_err());

        // 4b. PairingPayloadV1 backwards-compat & optional clip_kid/clip_key
        #[derive(Serialize)]
        struct LegacyPairingPayload<'a> {
            smks: &'a [SmkGenerationBytes],
            device_token: Option<&'a str>,
            device_id: &'a DeviceId,
            sync_url: &'a str,
        }
        let legacy_bytes = rmp_serde::to_vec_named(&LegacyPairingPayload {
            smks: &pair_payload.smks,
            device_token: pair_payload.device_token.as_deref(),
            device_id: &pair_payload.device_id,
            sync_url: &pair_payload.sync_url,
        })
        .unwrap();
        assert_eq!(
            rmp_serde::from_slice::<PairingPayloadV1>(&legacy_bytes).unwrap(),
            pair_payload
        );

        let clip_kid = ClipKid::from_ulid(g.next(101, [9; 10]));
        let clip_payload = PairingPayloadV1 {
            smks: vec![],
            device_token: Some("tok_clip_write".into()),
            device_id: other_dev,
            sync_url: "https://note.example.com".into(),
            clip_kid: Some(clip_kid),
            clip_key: Some([0xCC; 32]),
        };
        let clip_pair_ct = encrypt_pairing_ticket("pair_clip", &k_pair, &clip_payload, [6u8; 24]).unwrap();
        assert_eq!(
            decrypt_pairing_ticket("pair_clip", &k_pair, &clip_pair_ct).unwrap(),
            clip_payload
        );
    }

    #[test]
    fn unified_24_word_recovery_unseals_all_smk_generations_across_rotations_and_archives() {
        let mut g = MonotonicUlidGen::new();
        let entropy = [0x5Au8; 32];
        let (kp, words) = RecoveryKeypair::from_entropy(&entropy).unwrap();
        assert_eq!(words.split_whitespace().count(), 24);

        // Simulate 3 SMK rotations sealed using ONLY recovery_pk (zero 24-word input needed!)
        let smk1_kid = SmkKid::from_ulid(g.next(100, [1; 10]));
        let smk1 = [0xA1u8; 32];
        let smk2_kid = SmkKid::from_ulid(g.next(200, [2; 10]));
        let smk2 = [0xA2u8; 32];
        let smk3_kid = SmkKid::from_ulid(g.next(300, [3; 10]));
        let smk3 = [0xA3u8; 32];

        let e1 = seal_mnrs(
            &kp.recovery_pk,
            MNRS_KIND_SMK,
            smk1_kid.as_bytes(),
            &smk1,
            [11u8; 32],
            [1u8; 24],
        )
        .unwrap();
        let e2 = seal_mnrs(
            &kp.recovery_pk,
            MNRS_KIND_SMK,
            smk2_kid.as_bytes(),
            &smk2,
            [12u8; 32],
            [2u8; 24],
        )
        .unwrap();
        let e3 = seal_mnrs(
            &kp.recovery_pk,
            MNRS_KIND_SMK,
            smk3_kid.as_bytes(),
            &smk3,
            [13u8; 32],
            [3u8; 24],
        )
        .unwrap();

        let keyring = RecoveryKeyringV1 {
            v: 1,
            recovery_kid: kp.recovery_kid,
            recovery_pk: kp.recovery_pk,
            keyring_gen: 3,
            current_smk_kid: smk3_kid,
            smk_entries: vec![e1, e2, e3],
        };

        // Pack MNKS and MNA1, verify BLAKE3 tamper detection
        let mnks_hdr = KeySnapshotHeaderV1 {
            created_at_ms: 9999,
            keyring_gen: 3,
            record_count: 0,
        };
        let mnks_body = KeySnapshotBodyV1 {
            keyring: keyring.clone(),
            vault_header: None,
            records: vec![],
            marks: vec![],
        };
        let mnks_bytes = encode_mnks(&mnks_hdr, &mnks_body).unwrap();
        let (dec_hdr, dec_body) = decode_mnks(&mnks_bytes).unwrap();
        assert_eq!(dec_hdr, mnks_hdr);
        assert_eq!(dec_body, mnks_body);

        let mut bad_mnks = mnks_bytes.clone();
        bad_mnks[15] ^= 0x80;
        assert!(decode_mnks(&bad_mnks).is_err());

        // Offline recovery from ONLY the original 24 words recovers ALL 3 generations!
        let recovered_kp = RecoveryKeypair::from_mnemonic_words(&words).unwrap();
        let smks = recovered_kp.unseal_all_smks(&dec_body.keyring).unwrap();
        assert_eq!(smks.len(), 3);
        assert_eq!(smks[0].0, smk1_kid);
        assert_eq!(*smks[0].1, smk1);
        assert_eq!(smks[1].0, smk2_kid);
        assert_eq!(*smks[1].1, smk2);
        assert_eq!(smks[2].0, smk3_kid);
        assert_eq!(*smks[2].1, smk3);
    }

    #[test]
    fn default_argon2id_params_match_s03_iphone_wasm_vector() {
        let salt: [u8; 16] = core::array::from_fn(|i| (i + 1) as u8);
        let kdf = KdfParamsV1::argon2id_default(salt);
        assert_eq!(kdf.alg, "argon2id");
        assert_eq!((kdf.m_kib, kdf.t, kdf.p), (32_768, 2, 1));
        let key = derive_passphrase_key(b"correct-horse-battery-staple-2026", &kdf).unwrap();
        assert_eq!(&key[..6], &[0x41, 0x67, 0x18, 0x33, 0x32, 0x87]);
    }
}
