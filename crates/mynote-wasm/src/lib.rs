//! `mynote-wasm`: Opaque Rust WASM security boundary for Desktop UI (Tier 2 Vault + Layer 1 format)
//! and Mobile Read-Only PWA (`WasmSyncEngine` + `WasmVaultSession`).
//!
//! SSOT contract: `docs/interface-contracts.md` §5, `docs/data-structures.md` §3.3–§3.6.
//!
//! Hard invariants:
//! - Unlocked `VKEK` and `SMK` key bytes NEVER leave Rust WASM linear memory as raw bytes.
//! - `lockAndZeroize()` / `zeroizeSmk()` / `Drop` deterministically overwrite all key bytes via `Zeroize`.
//! - `WasmVaultSession` generates `(op_id, key_id)` BEFORE encrypting `MNB1` so `MNB1` AAD binds
//!   the exact `op_id` that Desktop Daemon reuses verbatim for outer `MNS1` (F-01).
//! - `WasmSyncEngine` is strictly read-only (D1): zero write ops, zero outbox.

use base64::engine::general_purpose::STANDARD as B64;
#[cfg(feature = "pwa")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use mynote_core::crypto::{decrypt_mnb1, VaultHeaderV1};
#[cfg(feature = "pwa")]
use mynote_core::crypto::{
    decrypt_mnr1, decrypt_mns1, decrypt_pairing_ticket, peek_envelope_kid, MAGIC_MNR1, MAGIC_MNS1,
};
#[cfg(feature = "desktop")]
use mynote_core::crypto::{encrypt_mnb1, RecoveryKeypair};
use mynote_core::error::CoreError;
pub use mynote_core::error::ErrorCode;
#[cfg(feature = "desktop")]
use mynote_core::format::format_snippet as core_format_snippet;
use mynote_core::ids::{BlockId, KeyId, OpId};
#[cfg(feature = "pwa")]
use mynote_core::ids::{DeviceId, SmkKid};
#[cfg(feature = "desktop")]
use mynote_core::ids::{MonotonicUlidGen, VkekKid};
#[cfg(feature = "pwa")]
use mynote_core::model::{BlockState, KeyRecordRow, LeafBody, ShredMarkRow};
#[cfg(feature = "pwa")]
use mynote_core::snapshot::{decode_mnp1, MobileReadState};
#[cfg(feature = "pwa")]
use mynote_core::sync::RemoteEnvelopeRow;
#[cfg(feature = "desktop")]
use mynote_core::vault::{
    change_vault_passphrase, create_vault_header, detect_secret_pattern as core_detect_secret,
    unseal_vault_with_recovery,
};
use mynote_core::vault::{unlock_vault_with_passphrase, UnlockedVaultKeys};
use serde::Deserialize;
#[cfg(feature = "pwa")]
use serde::Serialize;
#[cfg(feature = "pwa")]
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
#[cfg(feature = "pwa")]
use zeroize::Zeroize;
#[cfg(any(feature = "desktop", feature = "pwa"))]
use zeroize::Zeroizing;

#[cfg(all(target_arch = "wasm32", feature = "desktop"))]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "crypto"], js_name = getRandomValues)]
    fn js_get_random_values(buf: &mut [u8]);

    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn js_date_now() -> f64;
}

#[cfg(feature = "desktop")]
fn fill_random<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut buf = [0u8; N];
    #[cfg(target_arch = "wasm32")]
    {
        js_get_random_values(&mut buf);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::fill(&mut buf).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("CSPRNG error: {e}"),
                "Check system randomness source",
            )
        })?;
    }
    Ok(buf)
}

#[cfg(feature = "desktop")]
fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_date_now() as u64).max(1)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1)
            .max(1)
    }
}

fn err_to_js(err: CoreError) -> JsValue {
    let payload = serde_json::json!({
        "code": err.code().as_str(),
        "message": err.message(),
        "hint": err.hint(),
        "retryable": err.code().retryable(),
    });
    JsValue::from_str(&payload.to_string())
}

#[cfg(feature = "desktop")]
#[derive(Deserialize)]
struct OpContextIn {
    block_id: Option<String>,
    #[allow(dead_code)]
    buffer_id: Option<String>,
    #[allow(dead_code)]
    parents: Option<Vec<String>>,
    #[allow(dead_code)]
    device_id: Option<String>,
    #[allow(dead_code)]
    last_hlc: Option<String>,
}

/// Tier 2 WASM encryption output (`docs/interface-contracts.md` §5).
/// Daemon reuses `opId` and `keyId` verbatim when wrapping outer `MNS1` and `MNR1`.
#[cfg(feature = "desktop")]
#[wasm_bindgen]
pub struct Tier2EncryptedOp {
    op_id: String,
    block_id: String,
    key_id: String,
    mnb1: Vec<u8>,
    mnw1: Option<Vec<u8>>,
}

#[cfg(feature = "desktop")]
#[wasm_bindgen]
impl Tier2EncryptedOp {
    #[wasm_bindgen(getter, js_name = opId)]
    pub fn op_id(&self) -> String {
        self.op_id.clone()
    }

    #[wasm_bindgen(getter, js_name = blockId)]
    pub fn block_id(&self) -> String {
        self.block_id.clone()
    }

    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn mnb1(&self) -> Vec<u8> {
        self.mnb1.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn mnw1(&self) -> Option<Vec<u8>> {
        self.mnw1.clone()
    }
}

/// Decrypted Tier 2 block payload returned only for transient UI rendering.
#[wasm_bindgen]
pub struct DecryptedBlockPayload {
    content: String,
}

#[wasm_bindgen]
impl DecryptedBlockPayload {
    #[wasm_bindgen(getter)]
    pub fn content(&self) -> String {
        self.content.clone()
    }
}

/// Opaque Tier 2 Vault session holding `VKEK` strictly in Rust WASM linear memory (`Zeroizing<[u8; 32]>`).
#[wasm_bindgen]
pub struct WasmVaultSession {
    keys: Option<UnlockedVaultKeys>,
    #[cfg(feature = "desktop")]
    ulid_gen: MonotonicUlidGen,
}

impl WasmVaultSession {
    fn require_keys(&self) -> Result<&UnlockedVaultKeys, CoreError> {
        self.keys.as_ref().ok_or_else(|| {
            CoreError::new(
                ErrorCode::BlockLocked,
                "Vault session is locked or zeroized",
                "Unlock the Vault with your passphrase before accessing Tier 2 blocks",
            )
        })
    }

    /// Native-testable unlock with passphrase.
    pub fn unlock_passphrase_inner(passphrase: &str, vault_header_bytes: &[u8]) -> Result<Self, CoreError> {
        let header: VaultHeaderV1 = rmp_serde::from_slice(vault_header_bytes).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("corrupt VaultHeaderV1: {e}"),
                "Sync the latest VaultHeaderV1 from the server",
            )
        })?;
        let keys = unlock_vault_with_passphrase(passphrase.as_bytes(), &header)?;
        Ok(Self {
            keys: Some(keys),
            #[cfg(feature = "desktop")]
            ulid_gen: MonotonicUlidGen::new(),
        })
    }

    /// Native-testable unlock with 24-word unified recovery bundle (desktop only).
    #[cfg(feature = "desktop")]
    pub fn unlock_recovery_inner(recovery_words: &str, vault_header_bytes: &[u8]) -> Result<Self, CoreError> {
        let header: VaultHeaderV1 = rmp_serde::from_slice(vault_header_bytes).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("corrupt VaultHeaderV1: {e}"),
                "Sync the latest VaultHeaderV1 from the server",
            )
        })?;
        let kp = RecoveryKeypair::from_mnemonic_words(recovery_words)?;
        let keys = unseal_vault_with_recovery(&kp, &header)?;
        Ok(Self {
            keys: Some(keys),
            ulid_gen: MonotonicUlidGen::new(),
        })
    }

    /// Native-testable `VaultHeaderV1` initializer (desktop only).
    #[cfg(feature = "desktop")]
    pub fn create_header_inner(
        passphrase: &str,
        recovery_pk_bytes: &[u8],
    ) -> Result<(Vec<u8>, i64), CoreError> {
        if recovery_pk_bytes.len() != 32 {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "recovery_pk must be 32 bytes",
                "Provide the 32-byte X25519 recovery public key from /v1/local/bootstrap",
            ));
        }
        let mut recovery_pk = [0u8; 32];
        recovery_pk.copy_from_slice(recovery_pk_bytes);
        let now = now_ms();
        let mut ugen = MonotonicUlidGen::new();
        let vkek_kid = VkekKid::from_ulid(ugen.next(now, fill_random::<10>()?));
        let vkek = Zeroizing::new(fill_random::<32>()?);
        let header = create_vault_header(
            passphrase.as_bytes(),
            &recovery_pk,
            vkek_kid,
            &vkek,
            fill_random::<16>()?,
            fill_random::<24>()?,
            fill_random::<32>()?,
            fill_random::<24>()?,
            now as i64,
        )?;
        let gen = header.updated_at_ms;
        let bytes = rmp_serde::to_vec_named(&header).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("failed encoding VaultHeaderV1: {e}"),
                "Internal serialization error",
            )
        })?;
        Ok((bytes, gen))
    }

    #[cfg(feature = "desktop")]
    pub fn change_passphrase_inner(
        &self,
        current_header_bytes: &[u8],
        new_passphrase: &str,
    ) -> Result<(Vec<u8>, i64), CoreError> {
        let keys = self.require_keys()?;
        let cur: VaultHeaderV1 = rmp_serde::from_slice(current_header_bytes).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("corrupt VaultHeaderV1: {e}"),
                "Sync the latest VaultHeaderV1",
            )
        })?;
        let mut retired_nonces = Vec::with_capacity(cur.retired.len());
        for _ in 0..cur.retired.len() {
            retired_nonces.push(fill_random::<24>()?);
        }
        let updated = change_vault_passphrase(
            &cur,
            keys,
            new_passphrase.as_bytes(),
            fill_random::<16>()?,
            fill_random::<24>()?,
            &retired_nonces,
            now_ms() as i64,
        )?;
        let gen = updated.updated_at_ms;
        let bytes = rmp_serde::to_vec_named(&updated).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("failed encoding updated VaultHeaderV1: {e}"),
                "Internal serialization error",
            )
        })?;
        Ok((bytes, gen))
    }

    #[cfg(feature = "desktop")]
    pub fn encrypt_new_or_rekey_inner(
        &mut self,
        ctx_json: &str,
        content: &str,
        _lang: &str,
        require_existing_block_id: bool,
    ) -> Result<Tier2EncryptedOp, CoreError> {
        let ctx: OpContextIn = serde_json::from_str(ctx_json).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid OpContextJson: {e}"),
                "Pass valid OpContextJson",
            )
        })?;
        let now = now_ms();
        let block_id = match ctx.block_id {
            Some(ref s) if !s.is_empty() => BlockId::parse(s)?,
            _ if require_existing_block_id => {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "block_id is required for rekeyToVault",
                    "Pass block_id in OpContextJson",
                ));
            }
            _ => BlockId::from_ulid(self.ulid_gen.next(now, fill_random::<10>()?)),
        };
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, fill_random::<10>()?));
        let key_id = KeyId::from_ulid(self.ulid_gen.next(now, fill_random::<10>()?));
        let bdek = Zeroizing::new(fill_random::<32>()?);
        let mnw1 = {
            let keys = self.require_keys()?;
            keys.wrap_bdek(key_id, block_id, &bdek, fill_random::<24>()?)?
        };
        let mnb1 = encrypt_mnb1(
            block_id.as_bytes(),
            op_id,
            key_id,
            &bdek,
            content,
            fill_random::<24>()?,
        )?;
        Ok(Tier2EncryptedOp {
            op_id: op_id.to_string(),
            block_id: block_id.to_string(),
            key_id: key_id.to_string(),
            mnb1,
            mnw1: Some(mnw1),
        })
    }

    #[cfg(feature = "desktop")]
    pub fn encrypt_update_inner(
        &mut self,
        ctx_json: &str,
        key_id_str: &str,
        mnw1: &[u8],
        content: &str,
        _lang: &str,
    ) -> Result<Tier2EncryptedOp, CoreError> {
        let ctx: OpContextIn = serde_json::from_str(ctx_json).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid OpContextJson: {e}"),
                "Pass valid OpContextJson",
            )
        })?;
        let blk_str = ctx.block_id.ok_or_else(|| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                "block_id is required for encryptUpdate",
                "Pass block_id in OpContextJson",
            )
        })?;
        let block_id = BlockId::parse(&blk_str)?;
        let key_id = KeyId::parse(key_id_str)?;
        let bdek = {
            let keys = self.require_keys()?;
            keys.unwrap_bdek(key_id, block_id, mnw1)?
        };
        let now = now_ms();
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, fill_random::<10>()?));
        let mnb1 = encrypt_mnb1(
            block_id.as_bytes(),
            op_id,
            key_id,
            &bdek,
            content,
            fill_random::<24>()?,
        )?;
        Ok(Tier2EncryptedOp {
            op_id: op_id.to_string(),
            block_id: block_id.to_string(),
            key_id: key_id.to_string(),
            mnb1,
            mnw1: None,
        })
    }

    pub fn decrypt_block_inner(
        &self,
        entity_id: &str,
        op_id_str: &str,
        key_id_str: &str,
        mnb1: &[u8],
        mnw1: &[u8],
    ) -> Result<DecryptedBlockPayload, CoreError> {
        let keys = self.require_keys()?;
        let block_id = BlockId::parse(entity_id)?;
        let op_id = OpId::parse(op_id_str)?;
        let key_id = KeyId::parse(key_id_str)?;
        let bdek = keys.unwrap_bdek(key_id, block_id, mnw1)?;
        let content = decrypt_mnb1(block_id.as_bytes(), op_id, key_id, &bdek, mnb1)?;
        Ok(DecryptedBlockPayload { content })
    }
}

#[wasm_bindgen]
impl WasmVaultSession {
    #[wasm_bindgen(js_name = unlockWithPassphrase)]
    pub fn unlock_with_passphrase(
        passphrase: &str,
        vault_header_bytes: &[u8],
    ) -> Result<WasmVaultSession, JsValue> {
        Self::unlock_passphrase_inner(passphrase, vault_header_bytes).map_err(err_to_js)
    }

    #[cfg(feature = "desktop")]
    #[wasm_bindgen(js_name = unlockWithRecoveryWords)]
    pub fn unlock_with_recovery_words(
        recovery_words: &str,
        vault_header_bytes: &[u8],
    ) -> Result<WasmVaultSession, JsValue> {
        Self::unlock_recovery_inner(recovery_words, vault_header_bytes).map_err(err_to_js)
    }

    /// Initialize a new `VaultHeaderV1` (returns JSON `{ gen, blob_b64 }`).
    #[cfg(feature = "desktop")]
    #[wasm_bindgen(js_name = createVaultHeader)]
    pub fn create_vault_header(passphrase: &str, recovery_pk_bytes: &[u8]) -> Result<String, JsValue> {
        let (bytes, gen) = Self::create_header_inner(passphrase, recovery_pk_bytes).map_err(err_to_js)?;
        Ok(serde_json::json!({ "gen": gen, "blob_b64": B64.encode(bytes) }).to_string())
    }

    /// Change Vault passphrase without changing VKEK (returns JSON `{ gen, blob_b64 }`).
    #[cfg(feature = "desktop")]
    #[wasm_bindgen(js_name = changePassphrase)]
    pub fn change_passphrase(
        &self,
        current_header_bytes: &[u8],
        new_passphrase: &str,
    ) -> Result<String, JsValue> {
        let (bytes, gen) = self
            .change_passphrase_inner(current_header_bytes, new_passphrase)
            .map_err(err_to_js)?;
        Ok(serde_json::json!({ "gen": gen, "blob_b64": B64.encode(bytes) }).to_string())
    }

    #[cfg(feature = "desktop")]
    #[wasm_bindgen(js_name = encryptNewBlock)]
    pub fn encrypt_new_block(
        &mut self,
        ctx_json: &str,
        content: &str,
        lang: &str,
    ) -> Result<Tier2EncryptedOp, JsValue> {
        self.encrypt_new_or_rekey_inner(ctx_json, content, lang, false)
            .map_err(err_to_js)
    }

    #[cfg(feature = "desktop")]
    #[wasm_bindgen(js_name = encryptUpdate)]
    pub fn encrypt_update(
        &mut self,
        ctx_json: &str,
        key_id: &str,
        mnw1: &[u8],
        content: &str,
        lang: &str,
    ) -> Result<Tier2EncryptedOp, JsValue> {
        self.encrypt_update_inner(ctx_json, key_id, mnw1, content, lang)
            .map_err(err_to_js)
    }

    #[cfg(feature = "desktop")]
    #[wasm_bindgen(js_name = rekeyToVault)]
    pub fn rekey_to_vault(
        &mut self,
        ctx_json: &str,
        content: &str,
        lang: &str,
    ) -> Result<Tier2EncryptedOp, JsValue> {
        self.encrypt_new_or_rekey_inner(ctx_json, content, lang, true)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = decryptBlock)]
    pub fn decrypt_block(
        &self,
        entity_id: &str,
        op_id: &str,
        key_id: &str,
        mnb1: &[u8],
        mnw1: &[u8],
    ) -> Result<DecryptedBlockPayload, JsValue> {
        self.decrypt_block_inner(entity_id, op_id, key_id, mnb1, mnw1)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = isLocked)]
    pub fn is_locked(&self) -> bool {
        self.keys.is_none()
    }

    #[wasm_bindgen(js_name = lockAndZeroize)]
    pub fn lock_and_zeroize(&mut self) {
        if let Some(mut k) = self.keys.take() {
            k.zeroize_all();
        }
    }
}

impl Drop for WasmVaultSession {
    fn drop(&mut self) {
        self.lock_and_zeroize();
    }
}

// ---------- Mobile Read-Only PWA Bridge (`WasmSyncEngine`) ----------

#[cfg(feature = "pwa")]
#[derive(Clone, Serialize, Deserialize)]
struct SmkEntryJson {
    smk_kid: String,
    smk_b64: String,
}

#[cfg(feature = "pwa")]
#[derive(Deserialize)]
struct PairingCodeInner {
    u: String,
    p: String,
    k: String,
}

#[cfg(feature = "pwa")]
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MobileStepEvent {
    InstallSnapshot {
        snapshot_b64: String,
    },
    ApplyTailOps {
        epoch: String,
        ops: Vec<MobileWireOp>,
    },
    MergeKeyTable {
        key_records: Vec<MobileWireKeyRecord>,
        shred_marks: Vec<ShredMarkRow>,
        keyring_gen: Option<u32>,
        keyring_b64: Option<String>,
        vault_header_gen: Option<i64>,
        vault_header_b64: Option<String>,
    },
    MaterializeView,
}

#[cfg(feature = "pwa")]
#[derive(Deserialize)]
struct MobileWireOp {
    seq: i64,
    op_id: String,
    key_id: Option<String>,
    device_id: String,
    created_at: i64,
    envelope_b64: String,
}

#[cfg(feature = "pwa")]
#[derive(Deserialize)]
struct MobileWireKeyRecord {
    key_id: String,
    wrap_gen: u32,
    key_record_b64: Option<String>,
    created_at_ms: i64,
}

#[cfg(feature = "pwa")]
#[derive(Serialize)]
struct MobileLeafView {
    op_id: String,
    hlc: String,
    device_id: String,
    actor: String,
    is_display: bool,
    is_locked: bool,
    key_id: Option<String>,
    content: Option<String>,
    mnb1_b64: Option<String>,
    mnw1_b64: Option<String>,
    body_state: String,
}

#[cfg(feature = "pwa")]
#[derive(Serialize)]
struct MobileBlockView {
    id: String,
    buffer_id: String,
    position: String,
    lang: String,
    public_hint: Option<String>,
    state: BlockState,
    is_locked: bool,
    has_unlocked_concurrent_version: bool,
    display_op_id: Option<String>,
    updated_at_ms: i64,
    versions: Vec<MobileLeafView>,
}

#[cfg(feature = "pwa")]
#[derive(Serialize)]
struct MobileBufferView {
    id: String,
    name: String,
    position: String,
    state: BlockState,
    updated_at_ms: i64,
}

/// Mobile Read-Only PWA Sans-I/O sync & decryption bridge (`docs/interface-contracts.md` §5, D1).
/// Strictly read-only: holds SMK generations in `Zeroizing<[u8; 32]>` and never generates write ops.
#[cfg(feature = "pwa")]
#[wasm_bindgen]
pub struct WasmSyncEngine {
    device_id: String,
    smks: BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
}

#[cfg(feature = "pwa")]
impl WasmSyncEngine {
    pub fn new_inner(device_id: &str, smk_keyring_json: &str) -> Result<Self, CoreError> {
        let entries: Vec<SmkEntryJson> = serde_json::from_str(smk_keyring_json).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid smk_keyring JSON: {e}"),
                "Provide JSON array of { smk_kid, smk_b64 }",
            )
        })?;
        let mut smks = BTreeMap::new();
        for e in entries {
            let kid = SmkKid::parse(&e.smk_kid)?;
            let raw = B64.decode(&e.smk_b64).map_err(|err| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid base64 SMK: {err}"),
                    "Re-pair or refresh device keys",
                )
            })?;
            if raw.len() != 32 {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    "SMK length must be 32 bytes",
                    "Re-pair or refresh device keys",
                ));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&raw);
            smks.insert(kid, key);
        }
        Ok(Self {
            device_id: device_id.to_string(),
            smks,
        })
    }

    pub fn parse_pairing_code_inner(code: &str) -> Result<String, CoreError> {
        let trimmed = code.trim();
        let encoded = trimmed.strip_prefix("mynote-pair:v1:").ok_or_else(|| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                "pairing code must start with 'mynote-pair:v1:'",
                "Paste or scan the pairing code generated by 'mynote device add --type mobile'",
            )
        })?;
        let raw = B64U.decode(encoded).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid pairing code encoding: {e}"),
                "Ensure the full pairing code was pasted",
            )
        })?;
        let inner: PairingCodeInner = serde_json::from_slice(&raw).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("malformed pairing code JSON: {e}"),
                "Generate a fresh pairing code from desktop",
            )
        })?;
        Ok(serde_json::json!({
            "sync_url": inner.u,
            "pair_id": inner.p,
            "k_pair_b64u": inner.k,
        })
        .to_string())
    }

    pub fn decrypt_pairing_ticket_inner(
        pair_id: &str,
        k_pair_b64u: &str,
        ciphertext: &[u8],
    ) -> Result<String, CoreError> {
        let raw_k = B64U.decode(k_pair_b64u).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid k_pair base64url: {e}"),
                "Check pairing code",
            )
        })?;
        if raw_k.len() != 32 {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                "k_pair must be 32 bytes",
                "Check pairing code",
            ));
        }
        let mut k_pair = Zeroizing::new([0u8; 32]);
        k_pair.copy_from_slice(&raw_k);
        let payload = decrypt_pairing_ticket(pair_id, &k_pair, ciphertext)?;
        let smks: Vec<SmkEntryJson> = payload
            .smks
            .iter()
            .map(|s| SmkEntryJson {
                smk_kid: s.smk_kid.to_string(),
                smk_b64: B64.encode(s.key),
            })
            .collect();
        Ok(serde_json::json!({
            "device_id": payload.device_id.to_string(),
            "device_token": payload.device_token,
            "sync_url": payload.sync_url,
            "smks": smks,
        })
        .to_string())
    }

    pub fn unpack_snapshot_inner(&self, snapshot_bytes: &[u8]) -> Result<String, CoreError> {
        let (header, body) = decode_mnp1(&self.smks, snapshot_bytes)?;
        serde_json::to_string(&serde_json::json!({ "header": header, "body": body })).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("snapshot JSON serialization error: {e}"),
                "Internal error",
            )
        })
    }

    pub fn unwrap_key_record_inner(
        &self,
        key_id_str: &str,
        wrap_gen: u32,
        mnr1_bytes: &[u8],
    ) -> Result<String, CoreError> {
        let key_id = KeyId::parse(key_id_str)?;
        let smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNR1, mnr1_bytes)?);
        let smk = self.smks.get(&smk_kid).ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("unknown SMK generation {smk_kid}"),
                "Run 'mynote device refresh' on desktop and refresh keys on mobile",
            )
        })?;
        let kr = decrypt_mnr1(smk_kid, smk, key_id, wrap_gen, mnr1_bytes)?;
        Ok(serde_json::json!({
            "key_id": kr.key_id.to_string(),
            "block_id": kr.block_id.to_string(),
            "tier": kr.tier,
            "bdek_b64": B64.encode(&kr.bdek),
        })
        .to_string())
    }

    pub fn decrypt_tier1_content_inner(
        &self,
        entity_id: &str,
        op_id_str: &str,
        key_id_str: &str,
        wrap_gen: u32,
        mnr1_bytes: &[u8],
        mnb1_bytes: &[u8],
    ) -> Result<String, CoreError> {
        let entity_ulid = mynote_core::ids::Ulid::parse(entity_id)?;
        let op_id = OpId::parse(op_id_str)?;
        let key_id = KeyId::parse(key_id_str)?;
        let smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNR1, mnr1_bytes)?);
        let smk = self.smks.get(&smk_kid).ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("unknown SMK generation {smk_kid}"),
                "Refresh keys from desktop",
            )
        })?;
        let kr = decrypt_mnr1(smk_kid, smk, key_id, wrap_gen, mnr1_bytes)?;
        if kr.tier != 1 || kr.bdek.len() != 32 {
            return Err(CoreError::new(
                ErrorCode::BlockLocked,
                "key record is Tier 2 Vault-locked",
                "Unlock Vault with passphrase to view this block",
            ));
        }
        let mut bdek = Zeroizing::new([0u8; 32]);
        bdek.copy_from_slice(&kr.bdek);
        decrypt_mnb1(entity_ulid.as_bytes(), op_id, key_id, &bdek, mnb1_bytes)
    }

    pub fn step_inner(&self, state_json: &str, event_json: &str) -> Result<String, CoreError> {
        let mut state: MobileReadState = if state_json.trim().is_empty() || state_json.trim() == "{}" {
            MobileReadState::new()
        } else {
            serde_json::from_str(state_json).map_err(|e| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid MobileReadState JSON: {e}"),
                    "Reset mobile cache and re-sync",
                )
            })?
        };
        let event: MobileStepEvent = serde_json::from_str(event_json).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid MobileStepEvent JSON: {e}"),
                "Internal sync event error",
            )
        })?;

        let mut installed = false;
        let mut applied_ops = 0usize;
        let mut needs_reset = false;

        match event {
            MobileStepEvent::InstallSnapshot { snapshot_b64 } => {
                let raw = B64.decode(&snapshot_b64).map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        format!("bad snapshot b64: {e}"),
                        "Re-fetch snapshot",
                    )
                })?;
                let (hdr, body) = decode_mnp1(&self.smks, &raw)?;
                installed = state.install_snapshot(hdr, body);
                state.prune_shredded_cache();
            }
            MobileStepEvent::ApplyTailOps { epoch, ops } => {
                let remote_epoch = mynote_core::ids::JournalEpoch::parse(&epoch)?;
                if state.journal_epoch.is_some_and(|e| e != remote_epoch) {
                    state.reset_for_epoch(remote_epoch);
                    needs_reset = true;
                } else {
                    if state.journal_epoch.is_none() {
                        state.journal_epoch = Some(remote_epoch);
                    }
                    for op in ops {
                        let env = B64.decode(&op.envelope_b64).map_err(|e| {
                            CoreError::new(
                                ErrorCode::IntegrityError,
                                format!("bad envelope b64: {e}"),
                                "Re-pull",
                            )
                        })?;
                        let row = RemoteEnvelopeRow {
                            seq: op.seq,
                            op_id: OpId::parse(&op.op_id)?,
                            key_id: op.key_id.as_deref().map(KeyId::parse).transpose()?,
                            device_id: DeviceId::parse(&op.device_id)?,
                            created_at: op.created_at,
                            envelope: env,
                        };
                        state.apply_tail_envelope(&row, &self.smks)?;
                        applied_ops += 1;
                    }
                    state.prune_shredded_cache();
                }
            }
            MobileStepEvent::MergeKeyTable {
                key_records,
                shred_marks,
                keyring_gen,
                keyring_b64,
                vault_header_gen,
                vault_header_b64,
            } => {
                let mut remote = mynote_core::keys::KeyTableState::default();
                for r in key_records {
                    let bytes = r
                        .key_record_b64
                        .as_deref()
                        .map(|s| B64.decode(s))
                        .transpose()
                        .map_err(|e| {
                            CoreError::new(
                                ErrorCode::IntegrityError,
                                format!("bad mnr1 b64: {e}"),
                                "Re-fetch keys",
                            )
                        })?;
                    remote.insert_record(KeyRecordRow {
                        key_id: KeyId::parse(&r.key_id)?,
                        wrap_gen: r.wrap_gen,
                        key_record: bytes,
                        created_at_ms: r.created_at_ms,
                    });
                }
                for m in shred_marks {
                    remote.insert_mark(m);
                }
                if let (Some(g), Some(b)) = (keyring_gen, keyring_b64) {
                    if let Ok(raw) = B64.decode(&b) {
                        remote.update_keyring_material(g, raw);
                    }
                }
                if let (Some(g), Some(b)) = (vault_header_gen, vault_header_b64) {
                    if let Ok(raw) = B64.decode(&b) {
                        remote.update_vault_header_material(g, raw);
                    }
                }
                state.merge_key_table(&remote, &self.smks);
            }
            MobileStepEvent::MaterializeView => {
                state.prune_shredded_cache();
            }
        }

        // Build transient UI view (Tier 1 decrypted ONLY in transient RAM output, NEVER stored in `state`!)
        let buffers: Vec<MobileBufferView> = state
            .all_non_shredded_buffers(&self.smks)
            .into_iter()
            .filter(|b| b.state == BlockState::Active)
            .map(|b| MobileBufferView {
                id: b.id.to_string(),
                name: b.name,
                position: b.position,
                state: b.state,
                updated_at_ms: b.updated_at_ms,
            })
            .collect();

        let blocks: Vec<MobileBlockView> = state
            .all_non_shredded_blocks(&self.smks)
            .into_iter()
            .filter(|b| b.state == BlockState::Active)
            .map(|b| {
                let versions: Vec<MobileLeafView> = b
                    .leaves
                    .iter()
                    .filter(|l| l.is_live())
                    .map(|l| {
                        let is_display = b.display_op_id == Some(l.op_id);
                        match &l.body {
                            LeafBody::Plaintext(text) => MobileLeafView {
                                op_id: l.op_id.to_string(),
                                hlc: l.hlc.canonical_string(),
                                device_id: l.device_id.to_string(),
                                actor: l.actor.clone(),
                                is_display,
                                is_locked: false,
                                key_id: None,
                                content: Some(text.clone()),
                                mnb1_b64: None,
                                mnw1_b64: None,
                                body_state: "PLAINTEXT".into(),
                            },
                            LeafBody::Sealed { key_id, mnb1 } => {
                                // Unwrap outer MNR1 using SMK to yield inner MNW1 for WasmVaultSession!
                                let mnw1_b64 = state
                                    .keys
                                    .records
                                    .get(key_id)
                                    .and_then(|r| r.key_record.as_ref().map(|mnr1| (r.wrap_gen, mnr1)))
                                    .and_then(|(wg, mnr1)| {
                                        let sk =
                                            SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNR1, mnr1).ok()?);
                                        let smk = self.smks.get(&sk)?;
                                        let kr = decrypt_mnr1(sk, smk, *key_id, wg, mnr1).ok()?;
                                        Some(B64.encode(&kr.bdek))
                                    });
                                MobileLeafView {
                                    op_id: l.op_id.to_string(),
                                    hlc: l.hlc.canonical_string(),
                                    device_id: l.device_id.to_string(),
                                    actor: l.actor.clone(),
                                    is_display,
                                    is_locked: true,
                                    key_id: Some(key_id.to_string()),
                                    content: None,
                                    mnb1_b64: Some(B64.encode(mnb1)),
                                    mnw1_b64,
                                    body_state: "SEALED".into(),
                                }
                            }
                            LeafBody::KeyUnavailable { key_id, .. } => MobileLeafView {
                                op_id: l.op_id.to_string(),
                                hlc: l.hlc.canonical_string(),
                                device_id: l.device_id.to_string(),
                                actor: l.actor.clone(),
                                is_display,
                                is_locked: false,
                                key_id: Some(key_id.to_string()),
                                content: None,
                                mnb1_b64: None,
                                mnw1_b64: None,
                                body_state: "KEY_UNAVAILABLE".into(),
                            },
                            LeafBody::DecryptFailed { .. } => MobileLeafView {
                                op_id: l.op_id.to_string(),
                                hlc: l.hlc.canonical_string(),
                                device_id: l.device_id.to_string(),
                                actor: l.actor.clone(),
                                is_display,
                                is_locked: false,
                                key_id: None,
                                content: None,
                                mnb1_b64: None,
                                mnw1_b64: None,
                                body_state: "DECRYPT_FAILED".into(),
                            },
                            LeafBody::Tombstone { .. } => MobileLeafView {
                                op_id: l.op_id.to_string(),
                                hlc: l.hlc.canonical_string(),
                                device_id: l.device_id.to_string(),
                                actor: l.actor.clone(),
                                is_display: false,
                                is_locked: false,
                                key_id: None,
                                content: None,
                                mnb1_b64: None,
                                mnw1_b64: None,
                                body_state: "TOMBSTONE".into(),
                            },
                        }
                    })
                    .collect();
                MobileBlockView {
                    id: b.id.to_string(),
                    buffer_id: b.buffer_id.to_string(),
                    position: b.position,
                    lang: b.lang,
                    public_hint: b.public_hint,
                    state: b.state,
                    is_locked: b.is_locked,
                    has_unlocked_concurrent_version: b.has_unlocked_concurrent_version,
                    display_op_id: b.display_op_id.map(|id| id.to_string()),
                    updated_at_ms: b.updated_at_ms,
                    versions,
                }
            })
            .collect();

        let vault_header_b64 = state
            .keys
            .vault_header_material
            .as_ref()
            .map(|(_, blob)| B64.encode(blob));

        serde_json::to_string(&serde_json::json!({
            "state": state,
            "installed": installed,
            "applied_ops": applied_ops,
            "needs_reset": needs_reset,
            "keys_digest": state.keys.digest(),
            "vault_header_b64": vault_header_b64,
            "view": {
                "buffers": buffers,
                "blocks": blocks,
            }
        }))
        .map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("step output serialization failed: {e}"),
                "Internal error",
            )
        })
    }
}

#[cfg(feature = "pwa")]
#[wasm_bindgen]
impl WasmSyncEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(device_id: &str, smk_keyring_json: &str) -> Result<WasmSyncEngine, JsValue> {
        Self::new_inner(device_id, smk_keyring_json).map_err(err_to_js)
    }

    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> String {
        self.device_id.clone()
    }

    #[wasm_bindgen(js_name = parsePairingCode)]
    pub fn parse_pairing_code(code: &str) -> Result<String, JsValue> {
        Self::parse_pairing_code_inner(code).map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = decryptPairingTicket)]
    pub fn decrypt_pairing_ticket(
        pair_id: &str,
        k_pair_b64u: &str,
        ciphertext: &[u8],
    ) -> Result<String, JsValue> {
        Self::decrypt_pairing_ticket_inner(pair_id, k_pair_b64u, ciphertext).map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = unpackStateSnapshot)]
    pub fn unpack_state_snapshot(&self, snapshot_bytes: &[u8]) -> Result<String, JsValue> {
        self.unpack_snapshot_inner(snapshot_bytes).map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = unwrapKeyRecord)]
    pub fn unwrap_key_record(
        &self,
        key_id: &str,
        wrap_gen: u32,
        mnr1_bytes: &[u8],
    ) -> Result<String, JsValue> {
        self.unwrap_key_record_inner(key_id, wrap_gen, mnr1_bytes)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = decryptTier1Content)]
    pub fn decrypt_tier1_content(
        &self,
        entity_id: &str,
        op_id: &str,
        key_id: &str,
        wrap_gen: u32,
        mnr1_bytes: &[u8],
        mnb1_bytes: &[u8],
    ) -> Result<String, JsValue> {
        self.decrypt_tier1_content_inner(entity_id, op_id, key_id, wrap_gen, mnr1_bytes, mnb1_bytes)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = decryptOpEnvelope)]
    pub fn decrypt_op_envelope(
        &self,
        op_id: &str,
        device_id: &str,
        key_id: Option<String>,
        envelope_bytes: &[u8],
    ) -> Result<String, JsValue> {
        let oid = OpId::parse(op_id).map_err(err_to_js)?;
        let did = DeviceId::parse(device_id).map_err(err_to_js)?;
        let kid = key_id
            .as_deref()
            .map(KeyId::parse)
            .transpose()
            .map_err(err_to_js)?;
        let smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNS1, envelope_bytes).map_err(err_to_js)?);
        let smk = self.smks.get(&smk_kid).ok_or_else(|| {
            err_to_js(CoreError::new(
                ErrorCode::KeyMissing,
                format!("unknown SMK {smk_kid}"),
                "Refresh keys from desktop",
            ))
        })?;
        let inner = decrypt_mns1(smk_kid, smk, oid, &did, kid, envelope_bytes).map_err(err_to_js)?;
        serde_json::to_string(&inner).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn step(&self, engine_state_json: &str, sync_event_json: &str) -> Result<String, JsValue> {
        self.step_inner(engine_state_json, sync_event_json)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = zeroizeSmk)]
    pub fn zeroize_smk(&mut self) {
        for v in self.smks.values_mut() {
            v.zeroize();
        }
        self.smks.clear();
    }
}

#[cfg(feature = "pwa")]
impl Drop for WasmSyncEngine {
    fn drop(&mut self) {
        self.zeroize_smk();
    }
}

/// Layer 1 millisecond pure-memory formatter (`docs/interface-contracts.md` §5).
/// Desktop unlocked Tier 2 blocks MUST use this WASM function and NEVER call `/v1/local/format`!
#[cfg(feature = "desktop")]
#[wasm_bindgen(js_name = formatSnippet)]
pub fn format_snippet(content: &str, lang: &str, action: Option<String>) -> Result<String, JsValue> {
    let act = action.as_deref().filter(|s| !s.is_empty());
    core_format_snippet(content, lang, act).map_err(err_to_js)
}

/// Fast local high-risk credential scanner (`docs/interface-contracts.md` §5).
#[cfg(feature = "desktop")]
#[wasm_bindgen(js_name = detectSecretPattern)]
pub fn detect_secret_pattern(pasted_text: &str) -> Option<String> {
    core_detect_secret(pasted_text).map(ToString::to_string)
}

#[cfg(all(test, feature = "desktop", feature = "pwa"))]
mod tests {
    use super::*;
    use mynote_core::crypto::{
        encrypt_mnb1, encrypt_mnr1, encrypt_mns1, encrypt_pairing_ticket, KeyRecordV1, PairingPayloadV1,
        SmkGenerationBytes,
    };
    use mynote_core::hlc::Hlc;
    use mynote_core::ids::{BufferId, JournalEpoch, SnapshotId};
    use mynote_core::model::{EntityType, InnerOpV1, OpBodyV1, OpType};
    use mynote_core::snapshot::pack_state_snapshot;
    use mynote_core::sync::{EngineSnapshot, LocalOpRecord};

    #[test]
    fn wasm_vault_session_roundtrip_passwd_recovery_and_zeroize() {
        let (kp, words) = RecoveryKeypair::from_entropy(&[0x55; 32]).unwrap();
        let (hdr1, gen1) = WasmVaultSession::create_header_inner("my-secret-pass", &kp.recovery_pk).unwrap();
        assert!(gen1 > 0);

        let mut sess = WasmVaultSession::unlock_passphrase_inner("my-secret-pass", &hdr1).unwrap();
        assert!(!sess.is_locked());

        // Encrypt new Tier 2 block -> verify op_id bound to AAD & decrypts identically
        let enc = sess
            .encrypt_new_or_rekey_inner(
                r#"{"buffer_id":"01JDF9M20000000000000000B1"}"#,
                "TOP_SECRET_CANARY",
                "text",
                false,
            )
            .unwrap();
        let mnw1 = enc.mnw1().expect("new block returns mnw1");
        let dec = sess
            .decrypt_block_inner(&enc.block_id(), &enc.op_id(), &enc.key_id(), &enc.mnb1(), &mnw1)
            .unwrap();
        assert_eq!(dec.content(), "TOP_SECRET_CANARY");

        // Encrypt update reusing same key_id (no new mnw1)
        let upd = sess
            .encrypt_update_inner(
                &format!(r#"{{"block_id":"{}"}}"#, enc.block_id()),
                &enc.key_id(),
                &mnw1,
                "UPDATED_SECRET",
                "text",
            )
            .unwrap();
        assert!(upd.mnw1().is_none());
        let dec2 = sess
            .decrypt_block_inner(&upd.block_id(), &upd.op_id(), &upd.key_id(), &upd.mnb1(), &mnw1)
            .unwrap();
        assert_eq!(dec2.content(), "UPDATED_SECRET");

        // Change passphrase -> old passphrase fails, new passphrase & 24-word recovery both decrypt!
        let (hdr2, gen2) = sess.change_passphrase_inner(&hdr1, "brand-new-pass").unwrap();
        assert!(gen2 > gen1);
        assert!(WasmVaultSession::unlock_passphrase_inner("my-secret-pass", &hdr2).is_err());

        let sess_new = WasmVaultSession::unlock_passphrase_inner("brand-new-pass", &hdr2).unwrap();
        let dec3 = sess_new
            .decrypt_block_inner(&upd.block_id(), &upd.op_id(), &upd.key_id(), &upd.mnb1(), &mnw1)
            .unwrap();
        assert_eq!(dec3.content(), "UPDATED_SECRET");

        let sess_rec = WasmVaultSession::unlock_recovery_inner(&words, &hdr2).unwrap();
        let dec4 = sess_rec
            .decrypt_block_inner(&upd.block_id(), &upd.op_id(), &upd.key_id(), &upd.mnb1(), &mnw1)
            .unwrap();
        assert_eq!(dec4.content(), "UPDATED_SECRET");

        // lockAndZeroize invalidates session immediately
        sess.lock_and_zeroize();
        assert!(sess.is_locked());
        assert!(sess
            .decrypt_block_inner(&upd.block_id(), &upd.op_id(), &upd.key_id(), &upd.mnb1(), &mnw1)
            .is_err());
    }

    #[test]
    fn wasm_sync_engine_pairs_unpacks_mnp1_merges_keys_and_unwraps_tier2_for_vault() {
        let mut g = MonotonicUlidGen::new();
        let smk_kid = SmkKid::from_ulid(g.next(1000, [1; 10]));
        let smk = [0x42u8; 32];
        let dev_mac = DeviceId::parse("dev_mac00001").unwrap();
        let dev_mob = DeviceId::parse("dev_mob00002").unwrap();

        // 1. Pairing ticket roundtrip
        let k_pair = [0x77u8; 32];
        let pair_ct = encrypt_pairing_ticket(
            "pair_01",
            &k_pair,
            &PairingPayloadV1 {
                smks: vec![SmkGenerationBytes { smk_kid, key: smk }],
                device_token: Some("tok_mobile_ro".into()),
                device_id: dev_mob.clone(),
                sync_url: "https://sync.example.com".into(),
            },
            [9; 24],
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(
            &WasmSyncEngine::decrypt_pairing_ticket_inner("pair_01", &B64U.encode(k_pair), &pair_ct).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed["device_token"], "tok_mobile_ro");

        // 2. Build a desktop EngineSnapshot with 1 buffer + 1 Tier 1 block + 1 Tier 2 locked block, pack MNP1
        let (kp, _) = RecoveryKeypair::from_entropy(&[0x88; 32]).unwrap();
        let (vh_bytes, vh_gen) = WasmVaultSession::create_header_inner("mob-pass", &kp.recovery_pk).unwrap();
        let mut vault = WasmVaultSession::unlock_passphrase_inner("mob-pass", &vh_bytes).unwrap();

        let epoch = JournalEpoch::from_random_bytes([0xAB; 16]);
        let mut desk = EngineSnapshot::new(dev_mac.clone(), 1000);
        desk.bootstrap_completed = true;
        desk.journal_epoch = Some(epoch);
        desk.smks.insert(smk_kid, Zeroizing::new(smk));
        desk.keys.update_vault_header_material(vh_gen, vh_bytes.clone());

        let buf_id = BufferId::from_ulid(g.next(1001, [2; 10]));
        let buf_kid = KeyId::from_ulid(g.next(1001, [3; 10]));
        let buf_bdek = [0x11u8; 32];
        let buf_op = OpId::from_ulid(g.next(1001, [4; 10]));
        let buf_hlc = Hlc::new(1001, 0, dev_mac.clone());
        let buf_mnb1 =
            encrypt_mnb1(buf_id.as_bytes(), buf_op, buf_kid, &buf_bdek, "scratch", [1; 24]).unwrap();
        let buf_mnr1 = encrypt_mnr1(
            smk_kid,
            &smk,
            1,
            &KeyRecordV1 {
                v: 1,
                key_id: buf_kid,
                block_id: buf_id.0,
                tier: 1,
                created_hlc: buf_hlc.canonical_string(),
                created_by: dev_mac.clone(),
                bdek: buf_bdek.to_vec(),
            },
            [2; 24],
        )
        .unwrap();
        desk.keys.insert_record(KeyRecordRow {
            key_id: buf_kid,
            wrap_gen: 1,
            key_record: Some(buf_mnr1.clone()),
            created_at_ms: 1001,
        });
        let buf_inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Buffer,
            entity_id: buf_id.to_string(),
            op_type: OpType::Create,
            parent_op_ids: vec![],
            hlc: buf_hlc.clone(),
            actor: "human".into(),
            body: OpBodyV1::BufferMeta {
                key_id: buf_kid,
                name_mnb1: Some(buf_mnb1),
                position: Some("V0001".into()),
            },
        };
        let buf_env = encrypt_mns1(smk_kid, &smk, buf_op, &dev_mac, &buf_inner, [3; 24]).unwrap();
        desk.ops.insert(
            buf_op,
            LocalOpRecord {
                op_id: buf_op,
                server_seq: Some(1),
                sync_blocked_reason: None,
                device_id: dev_mac.clone(),
                entity_type: EntityType::Buffer,
                entity_id: buf_id.to_string(),
                parent_op_ids: vec![],
                op_type: OpType::Create,
                hlc: buf_hlc,
                actor: "human".into(),
                key_id: Some(buf_kid),
                smk_kid,
                envelope: buf_env,
                created_at_ms: 1001,
            },
        );

        // Tier 2 block encrypted by WasmVaultSession
        let t2 = vault
            .encrypt_new_or_rekey_inner(
                &format!(r#"{{"buffer_id":"{buf_id}"}}"#),
                "MOBILE_T2_SECRET",
                "text",
                false,
            )
            .unwrap();
        let t2_blk = BlockId::parse(&t2.block_id()).unwrap();
        let t2_op = OpId::parse(&t2.op_id()).unwrap();
        let t2_kid = KeyId::parse(&t2.key_id()).unwrap();
        let t2_hlc = Hlc::new(1002, 0, dev_mac.clone());
        let t2_mnr1 = encrypt_mnr1(
            smk_kid,
            &smk,
            1,
            &KeyRecordV1 {
                v: 1,
                key_id: t2_kid,
                block_id: t2_blk.0,
                tier: 2,
                created_hlc: t2_hlc.canonical_string(),
                created_by: dev_mac.clone(),
                bdek: t2.mnw1().unwrap(),
            },
            [4; 24],
        )
        .unwrap();
        desk.keys.insert_record(KeyRecordRow {
            key_id: t2_kid,
            wrap_gen: 1,
            key_record: Some(t2_mnr1.clone()),
            created_at_ms: 1002,
        });
        let t2_inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: t2_blk.to_string(),
            op_type: OpType::Create,
            parent_op_ids: vec![],
            hlc: t2_hlc.clone(),
            actor: "human".into(),
            body: OpBodyV1::BlockContent {
                buffer_id: Some(buf_id),
                position: Some("V0001".into()),
                lang: Some("text".into()),
                public_hint: Some(Some("mobile hint".into())),
                tier: 2,
                key_id: t2_kid,
                mnb1: t2.mnb1(),
            },
        };
        let t2_env = encrypt_mns1(smk_kid, &smk, t2_op, &dev_mac, &t2_inner, [5; 24]).unwrap();
        desk.ops.insert(
            t2_op,
            LocalOpRecord {
                op_id: t2_op,
                server_seq: Some(2),
                sync_blocked_reason: None,
                device_id: dev_mac.clone(),
                entity_type: EntityType::Block,
                entity_id: t2_blk.to_string(),
                parent_op_ids: vec![],
                op_type: OpType::Create,
                hlc: t2_hlc,
                actor: "human".into(),
                key_id: Some(t2_kid),
                smk_kid,
                envelope: t2_env,
                created_at_ms: 1002,
            },
        );

        let snap_id = SnapshotId::from_ulid(g.next(1003, [6; 10]));
        let (_, mnp1_bytes) =
            pack_state_snapshot(&desk, snap_id, 2, smk_kid, &smk, 1003, [7; 24], [8; 24]).unwrap();

        // 3. Drive WasmSyncEngine (Mobile Read-Only)
        let mut engine = WasmSyncEngine::new_inner(
            &dev_mob.to_string(),
            &serde_json::to_string(&parsed["smks"]).unwrap(),
        )
        .unwrap();

        let step1_raw = engine
            .step_inner(
                "{}",
                &serde_json::json!({ "type": "install_snapshot", "snapshot_b64": B64.encode(&mnp1_bytes) })
                    .to_string(),
            )
            .unwrap();
        let step1: serde_json::Value = serde_json::from_str(&step1_raw).unwrap();
        assert_eq!(step1["installed"], true);

        let step2_raw = engine
            .step_inner(
                &step1["state"].to_string(),
                &serde_json::json!({
                    "type": "merge_key_table",
                    "key_records": [
                        { "key_id": buf_kid.to_string(), "wrap_gen": 1, "key_record_b64": B64.encode(&buf_mnr1), "created_at_ms": 1001 },
                        { "key_id": t2_kid.to_string(), "wrap_gen": 1, "key_record_b64": B64.encode(&t2_mnr1), "created_at_ms": 1002 }
                    ],
                    "shred_marks": [],
                    "vault_header_gen": vh_gen,
                    "vault_header_b64": B64.encode(&vh_bytes),
                })
                .to_string(),
            )
            .unwrap();
        let step2: serde_json::Value = serde_json::from_str(&step2_raw).unwrap();
        assert_eq!(step2["view"]["buffers"][0]["name"], "scratch");
        let blk_view = &step2["view"]["blocks"][0];
        assert_eq!(blk_view["is_locked"], true);
        assert_eq!(blk_view["public_hint"], "mobile hint");
        assert!(blk_view["versions"][0]["content"].is_null());

        // Mobile unlocks Vault using vault_header_b64 and decrypts Tier 2 block using mnb1_b64 + mnw1_b64!
        let mob_vault = WasmVaultSession::unlock_passphrase_inner(
            "mob-pass",
            &B64.decode(step2["vault_header_b64"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let pt = mob_vault
            .decrypt_block_inner(
                blk_view["id"].as_str().unwrap(),
                blk_view["versions"][0]["op_id"].as_str().unwrap(),
                blk_view["versions"][0]["key_id"].as_str().unwrap(),
                &B64.decode(blk_view["versions"][0]["mnb1_b64"].as_str().unwrap())
                    .unwrap(),
                &B64.decode(blk_view["versions"][0]["mnw1_b64"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(pt.content(), "MOBILE_T2_SECRET");

        // Zeroize SMK clears keys
        engine.zeroize_smk();
        assert!(engine.unpack_snapshot_inner(&mnp1_bytes).is_err());
    }
}
