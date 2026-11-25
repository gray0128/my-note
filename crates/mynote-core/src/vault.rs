//! Tier 2 Vault key management (`VaultHeaderV1`, `MNW1` double-wrapping, passphrase & 24-word recovery)
//! and local high-risk credential pattern detection (`#15 [M2-1]`, `#16 [M2-2]`).
//!
//! SSOT references:
//! - `docs/data-structures.md` §3.4, §3.5
//! - `docs/threat-model.md` §2, §4, §7.4, §8
//! - `docs/spikes/s0-3-wasm-argon2.md` (iPhone calibrated Argon2id `(32768, 2, 1)`)

use crate::crypto::{
    decrypt_mnvh, decrypt_mnw1, derive_passphrase_key, encrypt_mnvh, encrypt_mnw1, peek_envelope_kid,
    seal_mnrs, KdfParamsV1, RecoveryKeypair, RetiredVkekV1, VaultHeaderV1, MAGIC_MNW1, MNRS_KIND_VKEK,
};
use crate::error::{CoreError, ErrorCode};
use crate::ids::{BlockId, KeyId, VkekKid};
use zeroize::{Zeroize, Zeroizing};

/// Default trash/shred grace period: 7 days (`docs/threat-model.md` §3.3).
pub const T_GRACE_DEFAULT_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Server-enforced minimum grace period: 24 hours (`docs/threat-model.md` §3.3).
pub const T_GRACE_MIN_MS: i64 = 24 * 60 * 60 * 1000;
/// Rolling 24-hour shred batch threshold before entering `pending_confirm`.
pub const SHRED_BATCH_LIMIT_24H: usize = 20;
/// Snapshot/backup & retired VKEK retention period: 30 days.
pub const T_SNAP_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Unlocked in-memory Tier 2 Vault key material (NEVER persisted; deterministically zeroized on lock/drop).
pub struct UnlockedVaultKeys {
    pub active_kid: VkekKid,
    pub active_vkek: Zeroizing<[u8; 32]>,
    pub retired: Vec<(VkekKid, Zeroizing<[u8; 32]>)>,
}

impl UnlockedVaultKeys {
    /// Look up active or retired VKEK by `VkekKid`.
    pub fn find_vkek(&self, kid: VkekKid) -> Option<&[u8; 32]> {
        if kid == self.active_kid {
            return Some(&self.active_vkek);
        }
        self.retired.iter().find(|(k, _)| *k == kid).map(|(_, v)| &**v)
    }

    /// Wrap a 32-byte Tier 2 BDEK with the active VKEK into an `MNW1` envelope.
    pub fn wrap_bdek(
        &self,
        key_id: KeyId,
        block_id: BlockId,
        bdek: &[u8; 32],
        nonce: [u8; 24],
    ) -> Result<Vec<u8>, CoreError> {
        encrypt_mnw1(self.active_kid, &self.active_vkek, key_id, block_id, bdek, nonce)
    }

    /// Unwrap a Tier 2 `MNW1` envelope using the matching active or retired VKEK.
    pub fn unwrap_bdek(
        &self,
        key_id: KeyId,
        block_id: BlockId,
        mnw1: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, CoreError> {
        let kid_bytes = peek_envelope_kid(MAGIC_MNW1, mnw1)?;
        let vkek_kid = VkekKid::from_bytes(kid_bytes);
        let vkek = self.find_vkek(vkek_kid).ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("unknown VKEK generation {vkek_kid} in MNW1 envelope"),
                "Sync the latest VaultHeaderV1 or recover with your 24-word recovery bundle",
            )
        })?;
        decrypt_mnw1(vkek_kid, vkek, key_id, block_id, mnw1)
    }

    /// Deterministically overwrite all held VKEK bytes in memory.
    pub fn zeroize_all(&mut self) {
        self.active_vkek.zeroize();
        for (_, k) in &mut self.retired {
            k.zeroize();
        }
        self.retired.clear();
    }
}

impl Drop for UnlockedVaultKeys {
    fn drop(&mut self) {
        self.zeroize_all();
    }
}

/// Initialize a new `VaultHeaderV1` wrapping `vkek` with both:
/// 1. Passphrase-derived Argon2id `(32768, 2, 1)` key (`MNVH`), and
/// 2. Device-stored X25519 `recovery_pk` (`MNRS`, NO second 24-word bundle!).
#[allow(clippy::too_many_arguments)]
pub fn create_vault_header(
    passphrase: &[u8],
    recovery_pk: &[u8; 32],
    vkek_kid: VkekKid,
    vkek: &[u8; 32],
    kdf_salt: [u8; 16],
    mnvh_nonce: [u8; 24],
    mnrs_eph_sk: [u8; 32],
    mnrs_nonce: [u8; 24],
    updated_at_ms: i64,
) -> Result<VaultHeaderV1, CoreError> {
    if passphrase.is_empty() {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "Vault passphrase cannot be empty",
            "Provide a non-empty passphrase",
        ));
    }
    let kdf = KdfParamsV1::argon2id_default(kdf_salt);
    let pass_key = derive_passphrase_key(passphrase, &kdf)?;
    let wrapped_vkek = encrypt_mnvh(vkek_kid, &pass_key, &kdf, vkek, mnvh_nonce)?;
    let sealed_vkek = seal_mnrs(
        recovery_pk,
        MNRS_KIND_VKEK,
        vkek_kid.as_bytes(),
        vkek,
        mnrs_eph_sk,
        mnrs_nonce,
    )?;
    Ok(VaultHeaderV1 {
        v: 1,
        vkek_kid,
        kdf,
        wrapped_vkek,
        sealed_vkek,
        retired: Vec::new(),
        updated_at_ms,
    })
}

/// Unlock `VaultHeaderV1` using the Vault passphrase (Argon2id parameters read from header).
pub fn unlock_vault_with_passphrase(
    passphrase: &[u8],
    header: &VaultHeaderV1,
) -> Result<UnlockedVaultKeys, CoreError> {
    if header.v != 1 {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            format!("unsupported VaultHeaderV1 version {}", header.v),
            "Upgrade mynote to read this Vault header",
        ));
    }
    let pass_key = derive_passphrase_key(passphrase, &header.kdf)?;
    let active_vkek =
        decrypt_mnvh(header.vkek_kid, &pass_key, &header.kdf, &header.wrapped_vkek).map_err(|_| {
            CoreError::new(
                ErrorCode::AuthRequired,
                "incorrect Vault passphrase or corrupted VaultHeaderV1",
                "Verify your Vault passphrase, or recover with your 24-word unified recovery bundle",
            )
        })?;
    let mut retired = Vec::with_capacity(header.retired.len());
    for r in &header.retired {
        let rk = decrypt_mnvh(r.vkek_kid, &pass_key, &header.kdf, &r.wrapped_vkek).map_err(|_| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("failed to decrypt retired VKEK {}", r.vkek_kid),
                "Vault header retired entry may be corrupted",
            )
        })?;
        retired.push((r.vkek_kid, rk));
    }
    Ok(UnlockedVaultKeys {
        active_kid: header.vkek_kid,
        active_vkek,
        retired,
    })
}

/// Unseal `VaultHeaderV1` offline using the 24-word unified recovery bundle (`RecoveryKeypair`).
pub fn unseal_vault_with_recovery(
    kp: &RecoveryKeypair,
    header: &VaultHeaderV1,
) -> Result<UnlockedVaultKeys, CoreError> {
    if header.v != 1 {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            format!("unsupported VaultHeaderV1 version {}", header.v),
            "Upgrade mynote to read this Vault header",
        ));
    }
    let (kid_bytes, active_vkek) = kp.unseal_mnrs(MNRS_KIND_VKEK, &header.sealed_vkek)?;
    let unsealed_kid = VkekKid::from_bytes(kid_bytes);
    if unsealed_kid != header.vkek_kid {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            "VaultHeaderV1 sealed_vkek kid does not match header vkek_kid",
            "VaultHeaderV1 is tampered or inconsistent",
        ));
    }
    let mut retired = Vec::with_capacity(header.retired.len());
    for r in &header.retired {
        let (rk_bytes, rk_secret) = kp.unseal_mnrs(MNRS_KIND_VKEK, &r.sealed_vkek)?;
        if VkekKid::from_bytes(rk_bytes) != r.vkek_kid {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                "retired VKEK kid mismatch",
                "VaultHeaderV1 retired entry is inconsistent",
            ));
        }
        retired.push((r.vkek_kid, rk_secret));
    }
    Ok(UnlockedVaultKeys {
        active_kid: header.vkek_kid,
        active_vkek,
        retired,
    })
}

/// Change Vault passphrase without changing VKEK or touching `block_keys` (`docs/data-structures.md` §3.5).
/// Generates fresh Argon2id salt, re-wraps active + retired VKEKs, and monotonically bumps `updated_at_ms`.
#[allow(clippy::too_many_arguments)]
pub fn change_vault_passphrase(
    header: &VaultHeaderV1,
    keys: &UnlockedVaultKeys,
    new_passphrase: &[u8],
    new_salt: [u8; 16],
    active_nonce: [u8; 24],
    retired_nonces: &[[u8; 24]],
    now_ms: i64,
) -> Result<VaultHeaderV1, CoreError> {
    if new_passphrase.is_empty() {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "new Vault passphrase cannot be empty",
            "Provide a non-empty passphrase",
        ));
    }
    if retired_nonces.len() < header.retired.len() {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "insufficient nonces for retired VKEK entries",
            "Provide one 24-byte nonce per retired VKEK",
        ));
    }
    let kdf = KdfParamsV1::argon2id_default(new_salt);
    let pass_key = derive_passphrase_key(new_passphrase, &kdf)?;
    let wrapped_vkek = encrypt_mnvh(keys.active_kid, &pass_key, &kdf, &keys.active_vkek, active_nonce)?;
    let mut new_retired = Vec::with_capacity(header.retired.len());
    for (idx, r) in header.retired.iter().enumerate() {
        let rk = keys.find_vkek(r.vkek_kid).ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("missing retired VKEK {}", r.vkek_kid),
                "Unlock all retired VKEK generations before changing passphrase",
            )
        })?;
        let wrapped = encrypt_mnvh(r.vkek_kid, &pass_key, &kdf, rk, retired_nonces[idx])?;
        new_retired.push(RetiredVkekV1 {
            vkek_kid: r.vkek_kid,
            wrapped_vkek: wrapped,
            sealed_vkek: r.sealed_vkek.clone(),
            retired_at_ms: r.retired_at_ms,
        });
    }
    Ok(VaultHeaderV1 {
        v: 1,
        vkek_kid: header.vkek_kid,
        kdf,
        wrapped_vkek,
        sealed_vkek: header.sealed_vkek.clone(),
        retired: new_retired,
        updated_at_ms: now_ms.max(header.updated_at_ms.saturating_add(1)),
    })
}

/// Rotate VKEK to a new generation, retiring the previous VKEK and pruning retired entries older than `T_SNAP_MS`.
#[allow(clippy::too_many_arguments)]
pub fn rotate_vault_vkek(
    header: &VaultHeaderV1,
    old_keys: &UnlockedVaultKeys,
    passphrase: &[u8],
    recovery_pk: &[u8; 32],
    new_vkek_kid: VkekKid,
    new_vkek: &[u8; 32],
    new_salt: [u8; 16],
    active_nonce: [u8; 24],
    old_active_nonce: [u8; 24],
    retired_nonces: &[[u8; 24]],
    mnrs_eph_sk: [u8; 32],
    mnrs_nonce: [u8; 24],
    now_ms: i64,
) -> Result<VaultHeaderV1, CoreError> {
    let kdf = KdfParamsV1::argon2id_default(new_salt);
    let pass_key = derive_passphrase_key(passphrase, &kdf)?;
    let wrapped_vkek = encrypt_mnvh(new_vkek_kid, &pass_key, &kdf, new_vkek, active_nonce)?;
    let sealed_vkek = seal_mnrs(
        recovery_pk,
        MNRS_KIND_VKEK,
        new_vkek_kid.as_bytes(),
        new_vkek,
        mnrs_eph_sk,
        mnrs_nonce,
    )?;

    let mut retired = Vec::new();
    let prev_wrapped = encrypt_mnvh(
        old_keys.active_kid,
        &pass_key,
        &kdf,
        &old_keys.active_vkek,
        old_active_nonce,
    )?;
    retired.push(RetiredVkekV1 {
        vkek_kid: old_keys.active_kid,
        wrapped_vkek: prev_wrapped,
        sealed_vkek: header.sealed_vkek.clone(),
        retired_at_ms: now_ms,
    });

    let cutoff = now_ms.saturating_sub(T_SNAP_MS);
    for (idx, r) in header.retired.iter().enumerate() {
        if r.retired_at_ms < cutoff {
            continue;
        }
        if let (Some(rk), Some(nonce)) = (old_keys.find_vkek(r.vkek_kid), retired_nonces.get(idx)) {
            let wrapped = encrypt_mnvh(r.vkek_kid, &pass_key, &kdf, rk, *nonce)?;
            retired.push(RetiredVkekV1 {
                vkek_kid: r.vkek_kid,
                wrapped_vkek: wrapped,
                sealed_vkek: r.sealed_vkek.clone(),
                retired_at_ms: r.retired_at_ms,
            });
        }
    }

    Ok(VaultHeaderV1 {
        v: 1,
        vkek_kid: new_vkek_kid,
        kdf,
        wrapped_vkek,
        sealed_vkek,
        retired,
        updated_at_ms: now_ms.max(header.updated_at_ms.saturating_add(1)),
    })
}

/// Fast, zero-regex credential pattern scanner for paste-time lock nudge (`docs/threat-model.md` §4 #6,
/// `docs/interface-contracts.md` §5).
///
/// Detects:
/// - PEM private keys (`pem_private_key`)
/// - AWS access keys `AKIA...` / `ASIA...` (`aws_access_key`)
/// - GitHub PATs `ghp_...` / `github_pat_...` / `gho_...` / `ghs_...` (`github_token`)
/// - Slack tokens `xox[baprs]-...` (`slack_token`)
/// - API keys `sk-...` (`api_key`)
/// - High-entropy JWT tokens `eyJ....eyJ....<sig>` (`jwt_token`)
pub fn detect_secret_pattern(text: &str) -> Option<&'static str> {
    // 1. PEM Private Key block
    if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
        return Some("pem_private_key");
    }

    let bytes = text.as_bytes();
    let is_token_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.';
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && !is_token_char(bytes[i]) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_token_char(bytes[i]) {
            i += 1;
        }
        if start == i {
            break;
        }
        let tok = &text[start..i];
        if let Some(kind) = classify_secret_token(tok) {
            return Some(kind);
        }
    }
    None
}

fn classify_secret_token(tok: &str) -> Option<&'static str> {
    let b = tok.as_bytes();

    // AWS Access Key ID: AKIA / ASIA + 16 uppercase alphanumeric chars
    if b.len() == 20
        && (tok.starts_with("AKIA") || tok.starts_with("ASIA"))
        && b[4..]
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Some("aws_access_key");
    }

    // GitHub tokens
    if let Some(rest) = tok.strip_prefix("github_pat_") {
        if rest.len() >= 20 && rest.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            return Some("github_token");
        }
    }
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if let Some(rest) = tok.strip_prefix(prefix) {
            if rest.len() >= 20 && rest.bytes().all(|c| c.is_ascii_alphanumeric()) {
                return Some("github_token");
            }
        }
    }

    // Slack tokens: xox[baprs]-...
    if b.len() >= 15
        && tok.starts_with("xox")
        && matches!(b[3], b'b' | b'a' | b'p' | b'r' | b's')
        && b[4] == b'-'
        && b[5..].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
    {
        return Some("slack_token");
    }

    // OpenAI / Anthropic / Stripe style sk-... keys
    if let Some(rest) = tok.strip_prefix("sk-") {
        if rest.len() >= 20
            && rest
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Some("api_key");
        }
    }

    // JWT (3 base64url segments: eyJ... . eyJ... . <sig>=16+)
    if tok.starts_with("eyJ") {
        let mut parts = tok.split('.');
        if let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) {
            let is_b64u = |seg: &str| {
                seg.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            };
            if h.len() >= 10
                && p.len() >= 10
                && p.starts_with("eyJ")
                && s.len() >= 16
                && is_b64u(h)
                && is_b64u(p)
                && is_b64u(s)
            {
                return Some("jwt_token");
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::MonotonicUlidGen;

    #[test]
    fn passphrase_and_24_word_recovery_independently_unseal_same_vkek_and_passwd_bumps_gen() {
        let mut g = MonotonicUlidGen::new();
        let entropy = [0x33u8; 32];
        let (kp, words) = RecoveryKeypair::from_entropy(&entropy).unwrap();
        let vkek_kid = VkekKid::from_ulid(g.next(1_795_521_600_000, [1; 10]));
        let vkek = [0xABu8; 32];
        let bdek = [0xCDu8; 32];
        let key_id = KeyId::from_ulid(g.next(1_795_521_600_001, [2; 10]));
        let block_id = BlockId::from_ulid(g.next(1_795_521_600_002, [3; 10]));

        let hdr1 = create_vault_header(
            b"strong-vault-passphrase-2026",
            &kp.recovery_pk,
            vkek_kid,
            &vkek,
            [7u8; 16],
            [8u8; 24],
            [9u8; 32],
            [10u8; 24],
            1_795_521_600_000,
        )
        .unwrap();

        // 1. Passphrase unlocks exact VKEK; wrong passphrase fails with AuthRequired
        let unlocked_pw = unlock_vault_with_passphrase(b"strong-vault-passphrase-2026", &hdr1).unwrap();
        assert_eq!(*unlocked_pw.active_vkek, vkek);
        let wrong_err = unlock_vault_with_passphrase(b"wrong-passphrase", &hdr1)
            .err()
            .unwrap();
        assert_eq!(wrong_err.code(), ErrorCode::AuthRequired);

        // 2. 24-word unified recovery independently unseals the exact same VKEK
        let kp2 = RecoveryKeypair::from_mnemonic_words(&words).unwrap();
        let unlocked_rec = unseal_vault_with_recovery(&kp2, &hdr1).unwrap();
        assert_eq!(*unlocked_rec.active_vkek, vkek);
        assert_eq!(unlocked_rec.active_kid, vkek_kid);

        // 3. Wrap & unwrap MNW1 BDEK
        let mnw1 = unlocked_pw
            .wrap_bdek(key_id, block_id, &bdek, [11u8; 24])
            .unwrap();
        assert_eq!(*unlocked_rec.unwrap_bdek(key_id, block_id, &mnw1).unwrap(), bdek);

        // 4. Changing passphrase bumps updated_at_ms (gen) while keeping VKEK and MNW1 intact!
        let hdr2 = change_vault_passphrase(
            &hdr1,
            &unlocked_pw,
            b"brand-new-passphrase-2027",
            [12u8; 16],
            [13u8; 24],
            &[],
            1_795_521_600_000, // even same timestamp bumps monotonically
        )
        .unwrap();
        assert!(hdr2.updated_at_ms > hdr1.updated_at_ms);
        assert_eq!(hdr2.vkek_kid, hdr1.vkek_kid);
        assert!(unlock_vault_with_passphrase(b"strong-vault-passphrase-2026", &hdr2).is_err());
        let unlocked_new = unlock_vault_with_passphrase(b"brand-new-passphrase-2027", &hdr2).unwrap();
        assert_eq!(*unlocked_new.active_vkek, vkek);
        assert_eq!(*unlocked_new.unwrap_bdek(key_id, block_id, &mnw1).unwrap(), bdek);

        // 24-word recovery still unseals hdr2 identically
        let unlocked_rec2 = unseal_vault_with_recovery(&kp2, &hdr2).unwrap();
        assert_eq!(*unlocked_rec2.active_vkek, vkek);
    }

    #[test]
    fn secret_pattern_detector_identifies_high_risk_credentials_without_false_positives() {
        assert_eq!(
            detect_secret_pattern("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
            Some("aws_access_key")
        );
        assert_eq!(
            detect_secret_pattern("token: ghp_1234567890abcdefghijklmnopQRSTUV"),
            Some("github_token")
        );
        assert_eq!(
            detect_secret_pattern("github_pat_11ABCDEFGH0123456789_abcdefghij0123456789"),
            Some("github_token")
        );
        assert_eq!(
            detect_secret_pattern("OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnop"),
            Some("api_key")
        );
        assert_eq!(
            detect_secret_pattern("SLACK=xoxb-123456789012-123456789012-abcdefABCDEF"),
            Some("slack_token")
        );
        assert_eq!(
            detect_secret_pattern(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
            ),
            Some("pem_private_key")
        );
        assert_eq!(
            detect_secret_pattern("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
            Some("jwt_token")
        );
        // Normal developer text must not trigger false positives
        assert_eq!(detect_secret_pattern("SELECT * FROM users WHERE id = 42;"), None);
        assert_eq!(
            detect_secret_pattern("{\"hello\": \"world\", \"sk\": \"short\"}"),
            None
        );
    }
}
