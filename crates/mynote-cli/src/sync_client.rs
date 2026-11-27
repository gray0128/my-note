//! Cloudflare blind sync HTTP + WebSocket Hibernation client (`#14 [M1-11]`).
//!
//! Enforces anti-302 captive-portal / CF-Access defense (`redirect: manual`, strict `HTTP 200` +
//! `Content-Type: application/json` + `body.ok === true` before advancing any local cursor).

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use mynote_core::clip::CLIP_BLOB_ENVELOPE_MAX_BYTES;
use mynote_core::crypto::{
    decrypt_pairing_ticket, encrypt_pairing_ticket, PairingPayloadV1, SmkGenerationBytes,
};
use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::ids::{ClipKid, DeviceId, JournalEpoch, KeyId, MarkId, OpId};
use mynote_core::model::{DeviceScope, KeyRecordRow, ShredMarkRow, ShredMarkState};
use mynote_core::sync::{
    step, AckedOp, KeyTableSyncDto, PushRequestDto, RemoteEnvelopeRow, ShredResultDto, SyncCommand, SyncEvent,
};
use mynote_store::store::SyncApplySummary;
use mynote_store::{DeviceCredentials, LocalStore};
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use url::Url;
use zeroize::Zeroizing;

pub const PAIRING_CODE_PREFIX: &str = "mynote-pair:v1:";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
}

fn rand_bytes<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("OS CSPRNG error: {e}"),
            "Check system entropy",
        )
    })?;
    Ok(b)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex_encode(&h.finalize())
}

fn build_http_client() -> Result<Client, CoreError> {
    // HARD INVARIANT: NEVER follow 302 redirects (anti-Access / captive-portal silent data drop).
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| {
            CoreError::new(
                ErrorCode::SyncOffline,
                format!("failed to initialize HTTP sync client: {e}"),
                "Check TLS/network configuration",
            )
        })
}

fn map_error_code(code: &str) -> ErrorCode {
    match code {
        "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
        "NOT_FOUND" => ErrorCode::NotFound,
        "CAS_MISMATCH" => ErrorCode::CasMismatch,
        "KEY_SHREDDED" => ErrorCode::KeyShredded,
        "KEY_UNKNOWN" => ErrorCode::KeyUnknown,
        "KEY_PENDING_SHRED" => ErrorCode::KeyPendingShred,
        "SHRED_STALE" => ErrorCode::ShredStale,
        "GRACE_TOO_SHORT" => ErrorCode::GraceTooShort,
        "AUTH_REQUIRED" => ErrorCode::AuthRequired,
        "DEVICE_REVOKED" => ErrorCode::DeviceRevoked,
        "TOKEN_SCOPE_FORBIDDEN" => ErrorCode::TokenScopeForbidden,
        "NO_ONLINE_DESKTOP" => ErrorCode::NoOnlineDesktop,
        "RATE_LIMITED" => ErrorCode::RateLimited,
        "INTEGRITY_ERROR" => ErrorCode::IntegrityError,
        _ => ErrorCode::SyncOffline,
    }
}

/// Strictly validates relay response: rejects 3xx redirects, non-JSON Content-Type, or `ok != true`.
async fn parse_relay_json(res: reqwest::Response) -> Result<serde_json::Value, CoreError> {
    let status = res.status();
    if status.is_redirection() {
        return Err(CoreError::new(
            ErrorCode::SyncOffline,
            format!(
                "relay returned redirect HTTP {}; refusing to follow to prevent silent data loss",
                status.as_u16()
            ),
            "Ensure sync URL does not sit behind a 302 login/Access redirect; local outbox preserved intact",
        ));
    }
    let ct = res
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let media_type = ct.split(';').next().unwrap_or("").trim();
    if media_type != "application/json" {
        return Err(CoreError::new(
            ErrorCode::SyncOffline,
            format!(
                "relay returned non-JSON Content-Type '{ct}' (HTTP {}); refusing ack",
                status.as_u16()
            ),
            "Check sync URL or proxy/captive portal; local outbox preserved",
        ));
    }
    let text = res.text().await.map_err(|e| {
        CoreError::new(
            ErrorCode::SyncOffline,
            format!("failed reading relay response body: {e}"),
            "Retry once network stabilizes; local outbox preserved",
        )
    })?;
    let val: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        CoreError::new(
            ErrorCode::SyncOffline,
            format!("relay returned malformed JSON (HTTP {}): {e}", status.as_u16()),
            "Local outbox preserved; retry later",
        )
    })?;
    if status != StatusCode::OK || val.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err_obj = val.get("error");
        let code_str = err_obj
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str())
            .unwrap_or("SYNC_OFFLINE");
        let msg = err_obj
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("sync relay rejected request");
        let mut ce = CoreError::new(
            map_error_code(code_str),
            format!("relay HTTP {}: {msg}", status.as_u16()),
            "Check sync status and retry",
        );
        if let Some(details) = err_obj.and_then(|e| e.get("details")).cloned() {
            ce = ce.with_details(details);
        }
        return Err(ce);
    }
    Ok(val)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PairingCodeInner {
    u: String, // sync_url
    p: String, // pair_id
    k: String, // base64url(K_pair 32B)
}

pub fn encode_pairing_code(sync_url: &str, pair_id: &str, k_pair: &[u8; 32]) -> Result<String, CoreError> {
    let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let inner = PairingCodeInner {
        u: sync_url.trim_end_matches('/').to_string(),
        p: pair_id.to_string(),
        k: b64u.encode(k_pair),
    };
    let json = serde_json::to_vec(&inner)
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode pairing code"))?;
    Ok(format!("{PAIRING_CODE_PREFIX}{}", b64u.encode(json)))
}

pub fn decode_pairing_code(code: &str) -> Result<(String, String, Zeroizing<[u8; 32]>), CoreError> {
    let trimmed = code.trim();
    let encoded = trimmed.strip_prefix(PAIRING_CODE_PREFIX).ok_or_else(|| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            "pairing code must start with 'mynote-pair:v1:'",
            "Paste the exact pairing code output by 'mynote device add' or 'mynote device refresh'",
        )
    })?;
    let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let json = b64u.decode(encoded).map_err(|e| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            format!("invalid base64url in pairing code: {e}"),
            "Check the full pairing code was pasted without truncation",
        )
    })?;
    let inner: PairingCodeInner = serde_json::from_slice(&json).map_err(|e| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            format!("malformed pairing code JSON: {e}"),
            "Re-copy the pairing code",
        )
    })?;
    let k_raw = b64u.decode(&inner.k).map_err(|_| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            "invalid K_pair encoding",
            "Re-copy the pairing code",
        )
    })?;
    if k_raw.len() != 32 {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "invalid K_pair length (expected 32 bytes)",
            "Re-copy the pairing code",
        ));
    }
    let mut k_pair = Zeroizing::new([0u8; 32]);
    k_pair.copy_from_slice(&k_raw);
    Ok((inner.u, inner.p, k_pair))
}

pub fn render_terminal_qr(payload: &str) -> String {
    match qrcode::QrCode::new(payload.as_bytes()) {
        Ok(qr) => qr
            .render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapReceipt {
    pub device_id: String,
    pub scope: String,
    pub epoch: String,
    pub sync_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingTicketReceipt {
    pub device_id: String,
    pub pair_id: String,
    pub scope: String,
    pub expires_at_ms: i64,
    pub pairing_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimReceipt {
    pub kind: String,
    pub device_id: String,
    pub scope: String,
    pub sync_url: String,
    pub smk_generations: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteDeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub scope: String,
    pub last_pulled_seq: i64,
    pub last_seen_at_ms: i64,
    pub created_at_ms: i64,
    pub claimed_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncRoundReport {
    pub epoch: Option<String>,
    pub head_seq: i64,
    pub pulled_ops: usize,
    pub pushed_ops: usize,
    pub keys_synced: bool,
    pub reconciled_epoch_change: bool,
    #[serde(skip)]
    pub apply_summary: SyncApplySummary,
}

pub struct RelayClient {
    http: Client,
    base_url: String,
    bearer_token: Option<String>,
}

impl RelayClient {
    pub fn new(base_url: &str, bearer_token: Option<String>) -> Result<Self, CoreError> {
        Ok(Self {
            http: build_http_client()?,
            base_url: base_url.trim_end_matches('/').to_string(),
            bearer_token,
        })
    }

    pub fn from_credentials(creds: &DeviceCredentials) -> Result<Self, CoreError> {
        Self::new(&creds.sync_url, Some(creds.device_token.clone()))
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn add_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut r = req.header("X-Mynote-Protocol", "1");
        if let Some(tok) = &self.bearer_token {
            r = r.header(AUTHORIZATION, format!("Bearer {tok}"));
        }
        r
    }

    /// `POST /v1/devices/bootstrap` without requiring an already-initialized `LocalStore`.
    /// Generates random 256-bit `device_token` locally and sends ONLY `SHA-256(device_token)`.
    pub async fn bootstrap_register(
        url: &str,
        bootstrap_token: &str,
        device_id: &DeviceId,
        device_name: &str,
        revoke_existing: bool,
    ) -> Result<(BootstrapReceipt, DeviceCredentials), CoreError> {
        let client = Self::new(url, Some(bootstrap_token.to_string()))?;
        let raw_token = Zeroizing::new(rand_bytes::<32>()?);
        let device_token = format!("mnt_{}", hex_encode(raw_token.as_ref()));
        let token_hash = sha256_hex(&device_token);
        let body = serde_json::json!({
            "device_id": device_id.as_str(),
            "device_name": device_name,
            "token_sha256_hex": token_hash,
            "revoke_existing": revoke_existing,
        });
        let res = client
            .add_headers(
                client
                    .http
                    .post(client.endpoint("/v1/devices/bootstrap"))
                    .json(&body),
            )
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("bootstrap request failed: {e}"),
                    "Check Cloudflare Worker URL and network connectivity",
                )
            })?;
        let val = parse_relay_json(res).await?;
        let resp_device_id = val["device_id"]
            .as_str()
            .unwrap_or(device_id.as_str())
            .to_string();
        let scope = val["scope"].as_str().unwrap_or("read-write").to_string();
        let epoch = val["epoch"].as_str().unwrap_or_default().to_string();
        let creds = DeviceCredentials {
            sync_url: client.base_url.clone(),
            device_token,
            scope: scope.clone(),
        };
        Ok((
            BootstrapReceipt {
                device_id: resp_device_id,
                scope,
                epoch,
                sync_url: client.base_url,
            },
            creds,
        ))
    }

    /// `POST /v1/devices/bootstrap`: registers an already-initialized desktop with `BOOTSTRAP_TOKEN`.
    pub async fn bootstrap_device(
        url: &str,
        bootstrap_token: &str,
        store: &LocalStore,
        device_name: &str,
        revoke_existing: bool,
    ) -> Result<BootstrapReceipt, CoreError> {
        let (receipt, creds) = Self::bootstrap_register(
            url,
            bootstrap_token,
            store.device_id(),
            device_name,
            revoke_existing,
        )
        .await?;
        store.save_credentials(&creds)?;
        Ok(receipt)
    }

    /// `POST /v1/devices`: pre-register a new device and upload `K_pair`-encrypted one-time ticket.
    /// Server NEVER sees plaintext `device_token` or `K_pair`.
    /// Enforces four-state scope isolation (`read`, `read+clip`, `clip-write`, `read-write`):
    /// `clip-write` tickets ALWAYS carry ZERO SMKs and ONLY `(clip_kid, clip_key)`.
    pub async fn create_pairing_ticket(
        &self,
        device_name: &str,
        scope: &str,
        smks: Vec<SmkGenerationBytes>,
        clip_key: Option<(ClipKid, Zeroizing<[u8; 32]>)>,
    ) -> Result<PairingTicketReceipt, CoreError> {
        let parsed_scope = DeviceScope::from_str(scope)?;
        let (ticket_smks, ticket_clip_kid, ticket_clip_key) = match parsed_scope {
            DeviceScope::ClipWrite => {
                let (ck, key) = clip_key.ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::KeyMissing,
                        "clip-write pairing ticket requires an initialized ClipKey",
                        "Initialize ClipKey before creating a clip-write pairing ticket",
                    )
                })?;
                // HARD INVARIANT: clip-write tickets NEVER contain any SMK!
                (Vec::new(), Some(ck), Some(*key))
            }
            DeviceScope::ReadClip => {
                if smks.is_empty() {
                    return Err(CoreError::new(
                        ErrorCode::KeyMissing,
                        "read+clip pairing ticket requires SMK generations",
                        "Unlock keyring before pairing",
                    ));
                }
                let (ck, key) = clip_key.ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::KeyMissing,
                        "read+clip pairing ticket requires an initialized ClipKey",
                        "Initialize ClipKey before creating a read+clip pairing ticket",
                    )
                })?;
                (smks, Some(ck), Some(*key))
            }
            DeviceScope::Read => {
                if smks.is_empty() {
                    return Err(CoreError::new(
                        ErrorCode::KeyMissing,
                        "read pairing ticket requires SMK generations",
                        "Unlock keyring before pairing",
                    ));
                }
                (smks, None, None)
            }
            DeviceScope::ReadWrite => {
                if smks.is_empty() {
                    return Err(CoreError::new(
                        ErrorCode::KeyMissing,
                        "read-write pairing ticket requires SMK generations",
                        "Unlock keyring before pairing",
                    ));
                }
                match clip_key {
                    Some((ck, key)) => (smks, Some(ck), Some(*key)),
                    None => (smks, None, None),
                }
            }
        };
        let new_device_id = DeviceId::from_random_bytes(rand_bytes::<10>()?);
        let raw_token = Zeroizing::new(rand_bytes::<32>()?);
        let new_device_token = format!("mnt_{}", hex_encode(raw_token.as_ref()));
        let token_hash = sha256_hex(&new_device_token);
        let pair_id = hex_encode(&rand_bytes::<16>()?);
        let k_pair = Zeroizing::new(rand_bytes::<32>()?);
        let payload = PairingPayloadV1 {
            smks: ticket_smks,
            device_token: Some(new_device_token),
            device_id: new_device_id.clone(),
            sync_url: self.base_url.clone(),
            clip_kid: ticket_clip_kid,
            clip_key: ticket_clip_key,
        };
        let ct = encrypt_pairing_ticket(&pair_id, &k_pair, &payload, rand_bytes::<24>()?)?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "device_id": new_device_id.as_str(),
            "pair_id": pair_id,
            "device_name": device_name,
            "scope": parsed_scope.as_str(),
            "token_sha256_hex": token_hash,
            "ciphertext_b64": b64.encode(&ct),
        });
        let res = self
            .add_headers(self.http.post(self.endpoint("/v1/devices")).json(&body))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("device add failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        let expires_at_ms = val["expires_at_ms"].as_i64().unwrap_or(0);
        let pairing_code = encode_pairing_code(&self.base_url, &pair_id, &k_pair)?;
        Ok(PairingTicketReceipt {
            device_id: new_device_id.to_string(),
            pair_id,
            scope: parsed_scope.as_str().to_string(),
            expires_at_ms,
            pairing_code,
        })
    }

    /// `POST /v1/devices/:id/refresh`: create 10-min one-time SMK refresh ticket for an existing active device.
    pub async fn create_refresh_ticket(
        &self,
        target_device_id: &str,
        smks: Vec<SmkGenerationBytes>,
    ) -> Result<PairingTicketReceipt, CoreError> {
        let dev_id = DeviceId::parse(target_device_id)?;
        let pair_id = hex_encode(&rand_bytes::<16>()?);
        let k_pair = Zeroizing::new(rand_bytes::<32>()?);
        let payload = PairingPayloadV1 {
            smks,
            device_token: None,
            device_id: dev_id.clone(),
            sync_url: self.base_url.clone(),
            clip_kid: None,
            clip_key: None,
        };
        let ct = encrypt_pairing_ticket(&pair_id, &k_pair, &payload, rand_bytes::<24>()?)?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "pair_id": pair_id,
            "ciphertext_b64": b64.encode(&ct),
        });
        let path = format!("/v1/devices/{}/refresh", target_device_id);
        let res = self
            .add_headers(self.http.post(self.endpoint(&path)).json(&body))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("device refresh failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        let expires_at_ms = val["expires_at_ms"].as_i64().unwrap_or(0);
        let pairing_code = encode_pairing_code(&self.base_url, &pair_id, &k_pair)?;
        Ok(PairingTicketReceipt {
            device_id: dev_id.to_string(),
            pair_id,
            scope: "existing".to_string(),
            expires_at_ms,
            pairing_code,
        })
    }

    /// `POST /v1/devices/pair-claim`: claim a pairing or refresh code on target device (unauthenticated).
    pub async fn claim_pairing_code(
        code: &str,
        data_dir: &std::path::Path,
    ) -> Result<ClaimReceipt, CoreError> {
        let (sync_url, pair_id, k_pair) = decode_pairing_code(code)?;
        let client = Self::new(&sync_url, None)?;
        let res = client
            .add_headers(
                client
                    .http
                    .post(client.endpoint("/v1/devices/pair-claim"))
                    .json(&serde_json::json!({ "pair_id": pair_id })),
            )
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("pair-claim request failed: {e}"),
                    "Check connectivity",
                )
            })?;
        let val = parse_relay_json(res).await?;
        let kind = val["kind"].as_str().unwrap_or("add").to_string();
        let scope = val["scope"].as_str().unwrap_or("read-write").to_string();
        let ct_b64 = val["ciphertext_b64"].as_str().ok_or_else(|| {
            CoreError::new(
                ErrorCode::IntegrityError,
                "pair-claim response missing ciphertext_b64",
                "Verify relay version",
            )
        })?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let ct = b64.decode(ct_b64).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("invalid ciphertext_b64: {e}"),
                "Retry pairing",
            )
        })?;
        let payload = decrypt_pairing_ticket(&pair_id, &k_pair, &ct)?;
        let smk_count = payload.smks.len();

        if kind == "refresh" {
            let mut store = LocalStore::open(data_dir)?;
            store.install_refreshed_smks(&payload.smks)?;
        } else {
            let token = payload.device_token.as_deref().ok_or_else(|| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    "pairing payload missing device_token",
                    "Generate a fresh pairing code",
                )
            })?;
            let _store = LocalStore::open_for_claim(
                data_dir,
                payload.device_id.clone(),
                &payload.smks,
                &payload.sync_url,
                token,
                &scope,
            )?;
        }
        Ok(ClaimReceipt {
            kind,
            device_id: payload.device_id.to_string(),
            scope,
            sync_url: payload.sync_url,
            smk_generations: smk_count,
        })
    }

    pub async fn list_devices(&self) -> Result<Vec<RemoteDeviceInfo>, CoreError> {
        let res = self
            .add_headers(self.http.get(self.endpoint("/v1/devices")))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("list devices failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        serde_json::from_value(val["devices"].clone()).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("invalid devices response: {e}"),
                "Verify relay",
            )
        })
    }

    pub async fn revoke_device(&self, device_id: &str) -> Result<i64, CoreError> {
        let path = format!("/v1/devices/{}", device_id);
        let res = self
            .add_headers(self.http.delete(self.endpoint(&path)))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("revoke device failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        Ok(val["revoked_at_ms"].as_i64().unwrap_or(now_ms() as i64))
    }
}

#[derive(Clone, Debug)]
pub enum PushOutcome {
    Acked {
        epoch: JournalEpoch,
        acked: Vec<AckedOp>,
        shred_results: Vec<ShredResultDto>,
        cancelled_keys: Vec<KeyId>,
        head_seq: i64,
    },
    EpochMismatch(JournalEpoch),
    KeyRace {
        code: ErrorCode,
    },
}

fn parse_shred_state(s: &str) -> ShredMarkState {
    match s {
        "scheduled" => ShredMarkState::Scheduled,
        "cancelled" => ShredMarkState::Cancelled,
        "executed" => ShredMarkState::Executed,
        _ => ShredMarkState::PendingConfirm,
    }
}

fn parse_shred_mark_json(item: &serde_json::Value) -> Result<ShredMarkRow, CoreError> {
    let mark_id = MarkId::parse(item["mark_id"].as_str().unwrap_or_default())?;
    let key_id = KeyId::parse(item["key_id"].as_str().unwrap_or_default())?;
    let requested_by = DeviceId::parse(item["requested_by"].as_str().unwrap_or_default())?;
    let cancelled_by = item["cancelled_by"].as_str().map(DeviceId::parse).transpose()?;
    Ok(ShredMarkRow {
        mark_id,
        key_id,
        seen_seq: item["seen_seq"].as_i64().unwrap_or(0),
        requested_by,
        requested_at_ms: item["requested_at_ms"].as_i64().unwrap_or(0),
        grace_ms: item["grace_ms"]
            .as_i64()
            .unwrap_or(mynote_core::vault::T_GRACE_DEFAULT_MS),
        not_before_ms: item["not_before_ms"].as_i64(),
        state: parse_shred_state(item["state"].as_str().unwrap_or("pending_confirm")),
        confirmed_at_ms: item["confirmed_at_ms"].as_i64(),
        cancelled_by,
        executed_at_ms: item["executed_at_ms"].as_i64(),
    })
}

fn parse_shred_results(val: &serde_json::Value) -> Result<Vec<ShredResultDto>, CoreError> {
    let mut out = Vec::new();
    let arr_opt = val["shred_results"]
        .as_array()
        .or_else(|| val["results"].as_array());
    if let Some(arr) = arr_opt {
        for r in arr {
            let key_id = KeyId::parse(r["key_id"].as_str().unwrap_or_default())?;
            out.push(ShredResultDto {
                key_id,
                state: parse_shred_state(r["state"].as_str().unwrap_or("pending_confirm")),
                not_before_ms: r["not_before_ms"].as_i64(),
            });
        }
    }
    Ok(out)
}

impl RelayClient {
    pub async fn pull_page_for_daemon(
        &self,
        since_seq: i64,
        limit: u16,
    ) -> Result<(JournalEpoch, Vec<RemoteEnvelopeRow>, String, i64, bool), CoreError> {
        self.http_pull(since_seq, limit).await
    }

    pub async fn push_batch_for_daemon(&self, req: &PushRequestDto) -> Result<PushOutcome, CoreError> {
        self.http_push(req).await
    }

    async fn http_pull(
        &self,
        since_seq: i64,
        limit: u16,
    ) -> Result<(JournalEpoch, Vec<RemoteEnvelopeRow>, String, i64, bool), CoreError> {
        let url = format!("{}/v1/sync/pull?since={since_seq}&limit={limit}", self.base_url);
        let res = self.add_headers(self.http.get(url)).send().await.map_err(|e| {
            CoreError::new(
                ErrorCode::SyncOffline,
                format!("pull failed: {e}"),
                "Retry online",
            )
        })?;
        let val = parse_relay_json(res).await?;
        let epoch = JournalEpoch::parse(val["epoch"].as_str().unwrap_or_default())?;
        let keys_digest = val["keys_digest"].as_str().unwrap_or_default().to_string();
        let head_seq = val["head_seq"].as_i64().unwrap_or(0);
        let has_more = val["has_more"].as_bool().unwrap_or(false);
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut ops = Vec::new();
        if let Some(arr) = val["ops"].as_array() {
            for item in arr {
                let env_b64 = item["envelope_b64"].as_str().unwrap_or_default();
                let envelope = b64.decode(env_b64).map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        format!("bad envelope_b64: {e}"),
                        "Check relay",
                    )
                })?;
                ops.push(RemoteEnvelopeRow {
                    seq: item["seq"].as_i64().unwrap_or(0),
                    op_id: OpId::parse(item["op_id"].as_str().unwrap_or_default())?,
                    key_id: item["key_id"].as_str().map(KeyId::parse).transpose()?,
                    device_id: DeviceId::parse(item["device_id"].as_str().unwrap_or_default())?,
                    created_at: item["created_at"].as_i64().unwrap_or(0),
                    envelope,
                });
            }
        }
        Ok((epoch, ops, keys_digest, head_seq, has_more))
    }

    async fn http_push(&self, req: &PushRequestDto) -> Result<PushOutcome, CoreError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let key_records: Vec<serde_json::Value> = req
            .key_records
            .iter()
            .filter_map(|k| {
                let raw = k.key_record.as_ref()?;
                Some(serde_json::json!({
                    "key_id": k.key_id.to_string(),
                    "wrap_gen": k.wrap_gen,
                    "key_record_b64": b64.encode(raw),
                }))
            })
            .collect();
        let cancel_key_ids: Vec<String> = req.cancel_key_ids.iter().map(ToString::to_string).collect();
        let ops: Vec<serde_json::Value> = req
            .ops
            .iter()
            .map(|o| {
                serde_json::json!({
                    "op_id": o.op_id.to_string(),
                    "key_id": o.key_id.map(|k| k.to_string()),
                    "device_id": o.device_id.as_str(),
                    "envelope_b64": b64.encode(&o.envelope),
                })
            })
            .collect();
        let shred_marks: Vec<serde_json::Value> = req
            .shred_marks
            .iter()
            .map(|m| {
                serde_json::json!({
                    "mark_id": m.mark_id.to_string(),
                    "key_id": m.key_id.to_string(),
                    "grace_ms": m.grace_ms,
                })
            })
            .collect();
        let body = serde_json::json!({
            "expected_epoch": req.expected_epoch.to_string(),
            "seen_seq": req.seen_seq,
            "key_records": key_records,
            "cancel_key_ids": cancel_key_ids,
            "ops": ops,
            "shred_marks": shred_marks,
        });
        let res = self
            .add_headers(self.http.post(self.endpoint("/v1/sync/push")).json(&body))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("push failed: {e}"),
                    "Retry online",
                )
            })?;
        match parse_relay_json(res).await {
            Ok(val) => {
                let epoch = JournalEpoch::parse(val["epoch"].as_str().unwrap_or_default())?;
                let head_seq = val["head_seq"].as_i64().unwrap_or(0);
                let mut acked = Vec::new();
                if let Some(arr) = val["acked"].as_array() {
                    for a in arr {
                        acked.push(AckedOp {
                            op_id: OpId::parse(a["op_id"].as_str().unwrap_or_default())?,
                            seq: a["seq"].as_i64().unwrap_or(0),
                        });
                    }
                }
                let shred_results = parse_shred_results(&val)?;
                Ok(PushOutcome::Acked {
                    epoch,
                    acked,
                    shred_results,
                    cancelled_keys: req.cancel_key_ids.clone(),
                    head_seq,
                })
            }
            Err(err) if err.code() == ErrorCode::CasMismatch => {
                if let Some(remote_ep) = err
                    .details()
                    .and_then(|d| d.get("remote_epoch"))
                    .and_then(|v| v.as_str())
                {
                    let ep = JournalEpoch::parse(remote_ep)?;
                    return Ok(PushOutcome::EpochMismatch(ep));
                }
                Err(err)
            }
            Err(err)
                if matches!(
                    err.code(),
                    ErrorCode::ShredStale | ErrorCode::KeyPendingShred | ErrorCode::KeyShredded
                ) =>
            {
                Ok(PushOutcome::KeyRace { code: err.code() })
            }
            Err(err) => Err(err),
        }
    }

    /// `POST /v1/keys/shred`: register or expedite shred marks on the relay (M2).
    pub async fn post_keys_shred(
        &self,
        seen_seq: i64,
        expedite: bool,
        migration_exempt: bool,
        marks: &[ShredMarkRow],
    ) -> Result<Vec<ShredResultDto>, CoreError> {
        let marks_json: Vec<serde_json::Value> = marks
            .iter()
            .map(|m| {
                serde_json::json!({
                    "mark_id": m.mark_id.to_string(),
                    "key_id": m.key_id.to_string(),
                    "grace_ms": m.grace_ms,
                })
            })
            .collect();
        let body = serde_json::json!({
            "seen_seq": seen_seq,
            "expedite": expedite,
            "migration_exempt": migration_exempt,
            "marks": marks_json,
        });
        let res = self
            .add_headers(self.http.post(self.endpoint("/v1/keys/shred")).json(&body))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("POST /v1/keys/shred failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        parse_shred_results(&val)
    }

    /// `POST /v1/keys/cancel`: cancel active shred marks on the relay (`410 KEY_SHREDDED` if already executed).
    pub async fn post_keys_cancel(&self, key_ids: &[KeyId]) -> Result<Vec<KeyId>, CoreError> {
        let ids: Vec<String> = key_ids.iter().map(ToString::to_string).collect();
        let body = serde_json::json!({ "key_ids": ids });
        let res = self
            .add_headers(self.http.post(self.endpoint("/v1/keys/cancel")).json(&body))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("POST /v1/keys/cancel failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        let mut out = Vec::new();
        if let Some(arr) = val["cancelled"].as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    out.push(KeyId::parse(s)?);
                }
            }
        }
        Ok(out)
    }

    /// `POST /v1/keys/confirm`: confirm `pending_confirm` shred marks into `scheduled` with `T_grace_min`.
    pub async fn post_keys_confirm(
        &self,
        key_ids: &[KeyId],
        grace_ms: Option<i64>,
    ) -> Result<Vec<ShredResultDto>, CoreError> {
        let ids: Vec<String> = key_ids.iter().map(ToString::to_string).collect();
        let mut body = serde_json::json!({ "key_ids": ids });
        if let Some(g) = grace_ms {
            body["grace_ms"] = serde_json::json!(g);
        }
        let res = self
            .add_headers(self.http.post(self.endpoint("/v1/keys/confirm")).json(&body))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("POST /v1/keys/confirm failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        parse_shred_results(&val)
    }

    /// `PUT /v1/snapshots/state`: upload encrypted `MNP1` mobile state snapshot (monotonic `covers_seq`).
    pub async fn put_state_snapshot(
        &self,
        epoch: &str,
        covers_seq: i64,
        snapshot_id: &str,
        mnp1_bytes: &[u8],
    ) -> Result<serde_json::Value, CoreError> {
        let res = self
            .add_headers(
                self.http
                    .put(self.endpoint("/v1/snapshots/state"))
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header("X-Journal-Epoch", epoch)
                    .header("X-Covers-Seq", covers_seq.to_string())
                    .header("X-Snapshot-Id", snapshot_id)
                    .body(mnp1_bytes.to_vec()),
            )
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("PUT /v1/snapshots/state failed: {e}"),
                    "Retry online",
                )
            })?;
        parse_relay_json(res).await
    }

    /// `GET /v1/snapshots/state`: download latest `MNP1` mobile state snapshot (returns `Ok(None)` on 404).
    pub async fn get_state_snapshot(&self) -> Result<Option<(String, i64, String, Vec<u8>)>, CoreError> {
        let res = self
            .add_headers(self.http.get(self.endpoint("/v1/snapshots/state")))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("GET /v1/snapshots/state failed: {e}"),
                    "Retry online",
                )
            })?;
        let status = res.status();
        if status.is_redirection() {
            return Err(CoreError::new(
                ErrorCode::SyncOffline,
                format!("snapshot endpoint returned redirect HTTP {}", status.as_u16()),
                "Check sync URL",
            ));
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status != StatusCode::OK {
            let _ = parse_relay_json(res).await?;
            return Ok(None);
        }
        let epoch = res
            .headers()
            .get("X-Journal-Epoch")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let covers_seq = res
            .headers()
            .get("X-Covers-Seq")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let snapshot_id = res
            .headers()
            .get("X-Snapshot-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = res.bytes().await.map_err(|e| {
            CoreError::new(
                ErrorCode::SyncOffline,
                format!("reading snapshot body failed: {e}"),
                "Retry online",
            )
        })?;
        Ok(Some((epoch, covers_seq, snapshot_id, bytes.to_vec())))
    }

    /// Publish an encrypted `MNP1` mobile state snapshot if due (first bootstrap, >= 1000 ops, daily,
    /// or immediately after ExecuteShred when `last_seq > last_snapshot_seq`).
    /// Resets watermark whenever `journal_epoch` changes (H22).
    pub async fn maybe_publish_state_snapshot(
        &self,
        store: &mut LocalStore,
        force_after_shred: bool,
    ) -> Result<bool, CoreError> {
        let snap_info = {
            if store.get_local_meta("bootstrap_completed").as_deref() != Some("1")
                || store.get_local_meta("reconciling_epoch").is_some()
            {
                return Ok(false);
            }
            let Some(cur_epoch) = store.get_local_meta("journal_epoch") else {
                return Ok(false);
            };
            let last_seq = store
                .get_local_meta("last_seq")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            if last_seq <= 0 {
                return Ok(false);
            }
            let same_epoch =
                store.get_local_meta("last_snapshot_epoch").as_deref() == Some(cur_epoch.as_str());
            let last_snap_seq = if same_epoch {
                store
                    .get_local_meta("last_snapshot_seq")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(-1)
            } else {
                -1
            };
            let last_snap_at = if same_epoch {
                store
                    .get_local_meta("last_snapshot_at_ms")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0)
            } else {
                0
            };
            if last_seq <= last_snap_seq {
                return Ok(false);
            }
            let now = now_ms() as i64;
            let due = force_after_shred
                || last_snap_seq < 0
                || last_seq.saturating_sub(last_snap_seq) >= 1000
                || now.saturating_sub(last_snap_at) >= 86_400_000;
            if !due {
                return Ok(false);
            }
            store.build_state_snapshot()?
        };
        let (hdr, bytes) = snap_info;
        let epoch_s = hdr.journal_epoch.to_string();
        match self
            .put_state_snapshot(&epoch_s, hdr.covers_seq, &hdr.snapshot_id.to_string(), &bytes)
            .await
        {
            Ok(_) => {
                let _ = store.set_local_meta("last_snapshot_epoch", &epoch_s);
                let _ = store.set_local_meta("last_snapshot_seq", &hdr.covers_seq.to_string());
                let _ = store.set_local_meta("last_snapshot_at_ms", &(now_ms() as i64).to_string());
                Ok(true)
            }
            Err(e) if e.code() == ErrorCode::CasMismatch => {
                // Only advance watermark if CAS rejected covers_seq (not an epoch mismatch).
                let is_epoch_mismatch = e
                    .details()
                    .and_then(|d| d.get("remote_epoch"))
                    .and_then(|v| v.as_str())
                    .is_some_and(|re| re != epoch_s);
                if !is_epoch_mismatch {
                    let _ = store.set_local_meta("last_snapshot_epoch", &epoch_s);
                    let _ = store.set_local_meta("last_snapshot_seq", &hdr.covers_seq.to_string());
                    let _ = store.set_local_meta("last_snapshot_at_ms", &(now_ms() as i64).to_string());
                }
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Fetch authoritative remote key table (`GET /v1/keys`) without mutating server state.
    pub async fn fetch_remote_keys(
        &self,
    ) -> Result<
        (
            Vec<KeyRecordRow>,
            Vec<ShredMarkRow>,
            Option<(u32, Vec<u8>)>,
            Option<(i64, Vec<u8>)>,
        ),
        CoreError,
    > {
        let b64 = base64::engine::general_purpose::STANDARD;
        let res = self
            .add_headers(self.http.get(self.endpoint("/v1/keys")))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("GET /v1/keys failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        let mut records = Vec::new();
        if let Some(arr) = val["key_records"].as_array() {
            for r in arr {
                let key_record = match r["key_record_b64"].as_str() {
                    Some(s) => Some(b64.decode(s).map_err(|e| {
                        CoreError::new(
                            ErrorCode::IntegrityError,
                            format!("bad key_record_b64: {e}"),
                            "Check relay",
                        )
                    })?),
                    None => None,
                };
                records.push(KeyRecordRow {
                    key_id: KeyId::parse(r["key_id"].as_str().unwrap_or_default())?,
                    wrap_gen: r["wrap_gen"].as_u64().unwrap_or(1) as u32,
                    key_record,
                    created_at_ms: r["created_at_ms"].as_i64().unwrap_or(0),
                });
            }
        }
        let mut marks = Vec::new();
        if let Some(arr) = val["shred_marks"].as_array() {
            for item in arr {
                marks.push(parse_shred_mark_json(item)?);
            }
        }
        let keyring = match val["key_material"]["keyring"].as_object() {
            Some(o) => {
                let gen = o.get("gen").and_then(|v| v.as_u64()).ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        "remote keyring missing valid 'gen'",
                        "Check relay key_material",
                    )
                })? as u32;
                let blob_s = o.get("blob_b64").and_then(|v| v.as_str()).ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        "remote keyring missing 'blob_b64'",
                        "Check relay key_material",
                    )
                })?;
                let blob = b64.decode(blob_s).map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        format!("bad keyring blob_b64: {e}"),
                        "Check relay key_material",
                    )
                })?;
                Some((gen, blob))
            }
            None => None,
        };
        let vault_header = match val["key_material"]["vault_header"].as_object() {
            Some(o) => {
                let gen = o.get("gen").and_then(|v| v.as_i64()).ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        "remote vault_header missing valid 'gen'",
                        "Check relay key_material",
                    )
                })?;
                let blob_s = o.get("blob_b64").and_then(|v| v.as_str()).ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        "remote vault_header missing 'blob_b64'",
                        "Check relay key_material",
                    )
                })?;
                let blob = b64.decode(blob_s).map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        format!("bad vault_header blob_b64: {e}"),
                        "Check relay key_material",
                    )
                })?;
                Some((gen, blob))
            }
            None => None,
        };
        Ok((records, marks, keyring, vault_header))
    }

    /// Synchronize key table using GET-before-POST diffing so a stale local `keyring`/`vault_header`
    /// generation NEVER triggers an atomic `409 CAS_MISMATCH` rollback of new local `key_records`.
    pub async fn sync_key_table(
        &self,
        dto: &KeyTableSyncDto,
        read_only: bool,
    ) -> Result<
        (
            Vec<KeyRecordRow>,
            Vec<ShredMarkRow>,
            Option<(u32, Vec<u8>)>,
            Option<(i64, Vec<u8>)>,
        ),
        CoreError,
    > {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut remote = self.fetch_remote_keys().await?;
        if read_only {
            return Ok(remote);
        }

        // Up to 2 attempts in case a peer bumps keyring/vault_header concurrently between GET and POST.
        for attempt in 0..2 {
            let mut remote_map: std::collections::BTreeMap<KeyId, (u32, bool)> =
                std::collections::BTreeMap::new();
            for r in &remote.0 {
                remote_map.insert(r.key_id, (r.wrap_gen, r.key_record.is_none()));
            }

            let key_records: Vec<serde_json::Value> = dto
                .push_records
                .iter()
                .filter_map(|k| {
                    let raw = k.key_record.as_ref()?;
                    let should_upload = match remote_map.get(&k.key_id) {
                        None => true,
                        Some((_, true)) => false, // Terminal shred on server
                        Some((r_gen, false)) => k.wrap_gen > *r_gen,
                    };
                    if !should_upload {
                        return None;
                    }
                    Some(serde_json::json!({
                        "key_id": k.key_id.to_string(),
                        "wrap_gen": k.wrap_gen,
                        "key_record_b64": b64.encode(raw),
                    }))
                })
                .collect();

            let mut km = serde_json::Map::new();
            if let Some((l_gen, l_blob)) = &dto.keyring_material {
                if remote.2.as_ref().is_none_or(|(r_gen, _)| l_gen > r_gen) {
                    km.insert(
                        "keyring".into(),
                        serde_json::json!({ "gen": l_gen, "blob_b64": b64.encode(l_blob) }),
                    );
                }
            }
            if let Some((l_gen, l_blob)) = &dto.vault_header_material {
                if remote.3.as_ref().is_none_or(|(r_gen, _)| l_gen > r_gen) {
                    km.insert(
                        "vault_header".into(),
                        serde_json::json!({ "gen": l_gen, "blob_b64": b64.encode(l_blob) }),
                    );
                }
            }

            if key_records.is_empty() && km.is_empty() {
                return Ok(remote);
            }

            let body = serde_json::json!({
                "key_records": key_records,
                "key_material": km,
            });
            let res = self
                .add_headers(self.http.post(self.endpoint("/v1/keys")).json(&body))
                .send()
                .await
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::SyncOffline,
                        format!("POST /v1/keys failed: {e}"),
                        "Retry online",
                    )
                })?;
            match parse_relay_json(res).await {
                Ok(_) => {
                    return self.fetch_remote_keys().await;
                }
                Err(err) if err.code() == ErrorCode::CasMismatch && attempt == 0 => {
                    remote = self.fetch_remote_keys().await?;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(remote)
    }

    /// Execute a full Sans-I/O sync round against Cloudflare relay (pull -> key diff -> push -> PITR reconcile -> MNP1 snapshot).
    pub async fn run_sync_round(
        &self,
        store: &mut LocalStore,
        read_only: bool,
    ) -> Result<SyncRoundReport, CoreError> {
        const MAX_SYNC_STEPS: usize = 10_000;
        const MAX_STALLED_STEPS: usize = 8;

        let mut report = SyncRoundReport::default();
        let mut queue: Vec<SyncCommand> = {
            let snap = store.export_engine_snapshot()?;
            let (muts, cmds) = step(&snap, SyncEvent::StartSync)?;
            merge_summary(&mut report.apply_summary, store.apply_store_mutations(&muts)?);
            cmds
        };

        let mut steps = 0usize;
        let mut stalled_steps = 0usize;
        let mut shred_acks = 0usize;
        let mut prev_progress = (
            store.get_local_meta("last_seq"),
            store.get_local_meta("bootstrap_completed"),
            store.get_local_meta("reconciling_epoch"),
            report.pulled_ops,
            report.pushed_ops,
            report.keys_synced,
            shred_acks,
            report.apply_summary.rekeyed_tier1_ops,
        );

        while !queue.is_empty() && steps < MAX_SYNC_STEPS {
            steps += 1;
            let cmd = queue.remove(0);
            match cmd {
                SyncCommand::HttpPull { since_seq, limit } => {
                    let (epoch, ops, keys_digest, head_seq, has_more) =
                        self.http_pull(since_seq, limit).await?;
                    report.epoch = Some(epoch.to_string());
                    report.head_seq = head_seq;
                    report.pulled_ops += ops.len();
                    let snap = store.export_engine_snapshot()?;
                    let (muts, next_cmds) = step(
                        &snap,
                        SyncEvent::PullResponse {
                            now_ms: now_ms(),
                            epoch,
                            ops,
                            keys_digest,
                            head_seq,
                            has_more,
                        },
                    )?;
                    if muts.iter().any(|m| {
                        matches!(
                            m,
                            mynote_core::sync::StoreMutation::ClearServerSeqsForReconcile { .. }
                        )
                    }) {
                        report.reconciled_epoch_change = true;
                    }
                    let applied = store.apply_store_mutations(&muts)?;
                    let rekeyed_now = applied.rekeyed_tier1_ops;
                    merge_summary(&mut report.apply_summary, applied);
                    for c in next_cmds {
                        if matches!(c, SyncCommand::SyncKeyTable(_)) {
                            queue.insert(0, c);
                        } else {
                            queue.push(c);
                        }
                    }
                    if rekeyed_now > 0
                        && !read_only
                        && !queue.iter().any(|c| matches!(c, SyncCommand::HttpPush(_)))
                    {
                        let post_snap = store.export_engine_snapshot()?;
                        if post_snap.bootstrap_completed && post_snap.reconciling_epoch.is_none() {
                            if let Some(req) = post_snap.build_pending_push() {
                                queue.push(SyncCommand::HttpPush(req));
                            }
                        }
                    }
                }
                SyncCommand::SyncKeyTable(dto) => {
                    let (records, marks, keyring, vault_header) =
                        self.sync_key_table(&dto, read_only).await?;
                    report.keys_synced = true;
                    let snap = store.export_engine_snapshot()?;
                    let (muts, next_cmds) = step(
                        &snap,
                        SyncEvent::KeyTableResponse {
                            records,
                            marks,
                            keyring,
                            vault_header,
                            server_now_ms: now_ms() as i64,
                        },
                    )?;
                    let applied = store.apply_store_mutations(&muts)?;
                    let rekeyed_now = applied.rekeyed_tier1_ops;
                    merge_summary(&mut report.apply_summary, applied);
                    queue.extend(next_cmds);
                    if rekeyed_now > 0
                        && !read_only
                        && !queue.iter().any(|c| matches!(c, SyncCommand::HttpPush(_)))
                    {
                        let post_snap = store.export_engine_snapshot()?;
                        if post_snap.bootstrap_completed && post_snap.reconciling_epoch.is_none() {
                            if let Some(req) = post_snap.build_pending_push() {
                                queue.push(SyncCommand::HttpPush(req));
                            }
                        }
                    }
                }
                SyncCommand::HttpPush(push_req) => {
                    if read_only {
                        continue;
                    }
                    match self.http_push(&push_req).await? {
                        PushOutcome::Acked {
                            epoch,
                            acked,
                            shred_results,
                            cancelled_keys,
                            head_seq,
                        } => {
                            report.epoch = Some(epoch.to_string());
                            report.head_seq = head_seq;
                            report.pushed_ops += acked.len();
                            shred_acks += shred_results.len() + cancelled_keys.len();
                            let snap = store.export_engine_snapshot()?;
                            let (muts, next_cmds) = step(
                                &snap,
                                SyncEvent::PushAcked {
                                    epoch,
                                    acked,
                                    shred_results,
                                    cancelled_keys,
                                    head_seq,
                                },
                            )?;
                            merge_summary(&mut report.apply_summary, store.apply_store_mutations(&muts)?);
                            queue.extend(next_cmds);
                        }
                        PushOutcome::EpochMismatch(remote_epoch) => {
                            report.reconciled_epoch_change = true;
                            let snap = store.export_engine_snapshot()?;
                            let (muts, next_cmds) =
                                step(&snap, SyncEvent::PushEpochMismatch { remote_epoch })?;
                            merge_summary(&mut report.apply_summary, store.apply_store_mutations(&muts)?);
                            queue.clear();
                            queue.extend(next_cmds);
                        }
                        PushOutcome::KeyRace { code } => {
                            let snap = store.export_engine_snapshot()?;
                            let (muts, next_cmds) =
                                step(&snap, SyncEvent::PushKeyRaceError { code, key_id: None })?;
                            merge_summary(&mut report.apply_summary, store.apply_store_mutations(&muts)?);
                            queue.clear();
                            queue.extend(next_cmds);
                        }
                    }
                }
            }

            let cur_progress = (
                store.get_local_meta("last_seq"),
                store.get_local_meta("bootstrap_completed"),
                store.get_local_meta("reconciling_epoch"),
                report.pulled_ops,
                report.pushed_ops,
                report.keys_synced,
                shred_acks,
                report.apply_summary.rekeyed_tier1_ops,
            );
            if cur_progress == prev_progress {
                stalled_steps += 1;
                if stalled_steps >= MAX_STALLED_STEPS && !queue.is_empty() {
                    return Err(CoreError::new(
                        ErrorCode::SyncOffline,
                        "sync round stopped making progress (stalled loop detected)",
                        "Inspect relay status and retry 'mynote sync pull'",
                    ));
                }
            } else {
                stalled_steps = 0;
                prev_progress = cur_progress;
            }
        }

        if !queue.is_empty() {
            return Err(CoreError::new(
                ErrorCode::SyncOffline,
                "sync round reached step safety limit before draining all pending operations",
                "Re-run 'mynote sync pull' to continue syncing remaining operations",
            ));
        }

        // One-time M1 -> M2 trash migration (`sync-protocol.md` §5.9): submit pre-existing trashed items
        // with `migration_exempt: true` and persist `m2_trash_migrated = 1` ONLY after HTTP success!
        if !read_only && store.get_local_meta("bootstrap_completed").as_deref() == Some("1") {
            if let Ok((self_check_ok, mig_marks)) = store.collect_m1_trashed_migration_marks() {
                if self_check_ok {
                    if mig_marks.is_empty() {
                        let _ = store.mark_m1_trash_migrated();
                    } else {
                        let seen_seq = store
                            .get_local_meta("last_seq")
                            .and_then(|s| s.parse::<i64>().ok())
                            .unwrap_or(0);
                        if let Ok(results) = self.post_keys_shred(seen_seq, false, true, &mig_marks).await {
                            let _ = store.apply_store_mutations(&[
                                mynote_core::sync::StoreMutation::MarkShredMarksAcked {
                                    results,
                                    cancelled_keys: Vec::new(),
                                },
                            ]);
                            let _ = store.mark_m1_trash_migrated();
                        }
                    }
                }
            }
            // Auto-publish mobile MNP1 state snapshot when due or immediately after ExecuteShred
            let force_snap = !report.apply_summary.executed_shreds.is_empty();
            let _ = self.maybe_publish_state_snapshot(store, force_snap).await;
        }

        Ok(report)
    }
}

fn merge_summary(dst: &mut SyncApplySummary, src: SyncApplySummary) {
    dst.upserted_block_ids.extend(src.upserted_block_ids);
    dst.deleted_block_ids.extend(src.deleted_block_ids);
    dst.upserted_buffer_ids.extend(src.upserted_buffer_ids);
    dst.deleted_buffer_ids.extend(src.deleted_buffer_ids);
    dst.trash_changed |= src.trash_changed;
    if src.clock_skew_ms.is_some() {
        dst.clock_skew_ms = src.clock_skew_ms;
    }
    dst.integrity_alerts.extend(src.integrity_alerts);
    dst.executed_shreds.extend(src.executed_shreds);
    dst.needs_vault_rekey.extend(src.needs_vault_rekey);
    dst.pending_confirm_count += src.pending_confirm_count;
    dst.vault_header_changed |= src.vault_header_changed;
    dst.rekeyed_tier1_ops += src.rekeyed_tier1_ops;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteClipItem {
    pub clip_id: String,
    pub clip_kid: String,
    pub device_id: String,
    pub kind: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub meta_envelope_b64: String,
    pub has_blob: bool,
    pub blob_bytes: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClipMetaPushReceipt {
    pub clip_id: String,
    pub created_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
    pub delivered_to: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClipBlobPushReceipt {
    pub clip_id: String,
    pub blob_bytes: i64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct RemoteClipBlob {
    pub clip_id: String,
    pub clip_kid: String,
    pub device_id: String,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum CloudWsEvent {
    Wake {
        head_seq: Option<i64>,
    },
    DeviceRevoked,
    ClipWake {
        clip_id: String,
        kind: String,
        created_at_ms: i64,
    },
    ClipEphemeral {
        clip_id: String,
        clip_kid: String,
        device_id: String,
        envelope_b64: String,
    },
    ClipCleared {
        clip_id: Option<String>,
    },
}

/// Long-running WebSocket Hibernation wakeup listener (`GET /v1/sync/ws`).
/// Sends `"ping"` every 30s (Cloudflare edge auto-responds `"pong"` without waking DO) and notifies
/// `on_event` whenever `wake`, `clip_wake`, `clip_ephemeral`, `clip_cleared`, or `device_revoked`
/// arrives; backs off exponentially (`1s -> 60s`) on disconnect and stops immediately on HTTP 401 / WS 4401.
pub async fn run_cloud_ws_loop<F>(creds: DeviceCredentials, mut on_event: F)
where
    F: FnMut(CloudWsEvent) + Send + 'static,
{
    let mut backoff_secs = 1u64;
    loop {
        let ws_url = match build_ws_url(&creds.sync_url) {
            Ok(u) => u,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        let Ok(mut req) = ws_url.into_client_request() else {
            tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
            backoff_secs = (backoff_secs * 2).min(60);
            continue;
        };
        if let Ok(val) = format!("Bearer {}", creds.device_token).parse() {
            req.headers_mut().insert("Authorization", val);
        }
        if let Ok(proto) = "1".parse() {
            req.headers_mut().insert("X-Mynote-Protocol", proto);
        }

        match tokio_tungstenite::connect_async(req).await {
            Ok((ws_stream, _)) => {
                backoff_secs = 1;
                let (mut sink, mut stream) = ws_stream.split();
                let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
                ping_interval.tick().await;
                loop {
                    tokio::select! {
                        _ = ping_interval.tick() => {
                            if sink.send(Message::Text("ping".into())).await.is_err() {
                                break;
                            }
                        }
                        maybe_msg = stream.next() => {
                            match maybe_msg {
                                Some(Ok(Message::Text(txt))) => {
                                    if txt == "pong" {
                                        continue;
                                    }
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                                        match v["type"].as_str() {
                                            Some("wake") => {
                                                on_event(CloudWsEvent::Wake {
                                                    head_seq: v["head_seq"].as_i64(),
                                                });
                                            }
                                            Some("device_revoked") => {
                                                on_event(CloudWsEvent::DeviceRevoked);
                                                return;
                                            }
                                            Some("clip_wake") => {
                                                if let (Some(clip_id), Some(kind)) = (
                                                    v["clip_id"].as_str(),
                                                    v["kind"].as_str(),
                                                ) {
                                                    on_event(CloudWsEvent::ClipWake {
                                                        clip_id: clip_id.to_string(),
                                                        kind: kind.to_string(),
                                                        created_at_ms: v["created_at_ms"].as_i64().unwrap_or(0),
                                                    });
                                                }
                                            }
                                            Some("clip_ephemeral") => {
                                                if let (
                                                    Some(clip_id),
                                                    Some(clip_kid),
                                                    Some(device_id),
                                                    Some(envelope_b64),
                                                ) = (
                                                    v["clip_id"].as_str(),
                                                    v["clip_kid"].as_str(),
                                                    v["device_id"].as_str(),
                                                    v["envelope_b64"].as_str(),
                                                ) {
                                                    on_event(CloudWsEvent::ClipEphemeral {
                                                        clip_id: clip_id.to_string(),
                                                        clip_kid: clip_kid.to_string(),
                                                        device_id: device_id.to_string(),
                                                        envelope_b64: envelope_b64.to_string(),
                                                    });
                                                }
                                            }
                                            Some("clip_cleared") => {
                                                on_event(CloudWsEvent::ClipCleared {
                                                    clip_id: v["clip_id"].as_str().map(ToString::to_string),
                                                });
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                Some(Ok(Message::Close(frame))) => {
                                    if frame.as_ref().is_some_and(|f| u16::from(f.code) == 4401) {
                                        on_event(CloudWsEvent::DeviceRevoked);
                                        return;
                                    }
                                    break;
                                }
                                Some(Ok(_)) => {}
                                _ => break,
                            }
                        }
                    }
                }
            }
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) if resp.status().as_u16() == 401 => {
                // Device revoked or unauthenticated: stop hammering the relay until credentials update.
                on_event(CloudWsEvent::DeviceRevoked);
                return;
            }
            Err(_) => {}
        }

        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(60);
    }
}

impl RelayClient {
    /// Fetch remote `key_material.clip_key` (`GET /v1/keys`) if present on relay.
    pub async fn fetch_remote_clip_key(&self) -> Result<Option<(i64, Vec<u8>)>, CoreError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let res = self
            .add_headers(self.http.get(self.endpoint("/v1/keys")))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("GET /v1/keys failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        let Some(o) = val["key_material"]["clip_key"].as_object() else {
            return Ok(None);
        };
        let gen = o.get("gen").and_then(|v| v.as_i64()).ok_or_else(|| {
            CoreError::new(
                ErrorCode::IntegrityError,
                "remote clip_key missing valid 'gen'",
                "Check relay key_material",
            )
        })?;
        let blob_s = o.get("blob_b64").and_then(|v| v.as_str()).ok_or_else(|| {
            CoreError::new(
                ErrorCode::IntegrityError,
                "remote clip_key missing 'blob_b64'",
                "Check relay key_material",
            )
        })?;
        let blob = b64.decode(blob_s).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("bad clip_key blob_b64: {e}"),
                "Check relay key_material",
            )
        })?;
        Ok(Some((gen, blob)))
    }

    /// Upload `key_material.clip_key` (`POST /v1/keys`) with optional `clear_clips: true`.
    pub async fn push_clip_key_material(
        &self,
        gen: i64,
        blob: &[u8],
        clear_clips: bool,
    ) -> Result<i64, CoreError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "key_records": [],
            "key_material": {
                "clip_key": {
                    "gen": gen,
                    "blob_b64": b64.encode(blob),
                }
            },
            "clear_clips": clear_clips,
        });
        let res = self
            .add_headers(self.http.post(self.endpoint("/v1/keys")).json(&body))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("POST /v1/keys (clip_key) failed: {e}"),
                    "Retry online",
                )
            })?;
        let val = parse_relay_json(res).await?;
        Ok(val["key_material_gens"]["clip_key"].as_i64().unwrap_or(gen))
    }

    /// `POST /v1/clip`: push inline text `MNC1` metadata envelope or ephemeral WS direct push.
    pub async fn clip_push_meta(
        &self,
        clip_id: &str,
        clip_kid: &str,
        kind: &str,
        ephemeral: bool,
        meta_envelope: &[u8],
    ) -> Result<ClipMetaPushReceipt, CoreError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "clip_id": clip_id,
            "clip_kid": clip_kid,
            "kind": kind,
            "ephemeral": ephemeral,
            "meta_envelope_b64": b64.encode(meta_envelope),
        });
        let res = self
            .add_headers(self.http.post(self.endpoint("/v1/clip")).json(&body))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("POST /v1/clip failed: {e}"),
                    "Check network connectivity and retry",
                )
            })?;
        let val = parse_relay_json(res).await?;
        Ok(ClipMetaPushReceipt {
            clip_id: val["clip_id"].as_str().unwrap_or(clip_id).to_string(),
            created_at_ms: val["created_at_ms"].as_i64(),
            expires_at_ms: val["expires_at_ms"].as_i64(),
            delivered_to: val["delivered_to"].as_u64().map(|n| n as usize),
        })
    }

    /// `PUT /v1/clip/blob`: stream-upload `MNC1` raw binary blob (`payload_type=1`) with exact
    /// `Content-Length` and `X-Clip-*` headers directly to R2 via Worker.
    pub async fn clip_push_blob(
        &self,
        clip_id: &str,
        clip_kid: &str,
        kind: &str,
        meta_envelope: &[u8],
        blob_envelope: &[u8],
    ) -> Result<ClipBlobPushReceipt, CoreError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let res = self
            .add_headers(
                self.http
                    .put(self.endpoint("/v1/clip/blob"))
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header(CONTENT_LENGTH, blob_envelope.len())
                    .header("X-Clip-Id", clip_id)
                    .header("X-Clip-Kid", clip_kid)
                    .header("X-Clip-Kind", kind)
                    .header("X-Clip-Meta-B64", b64.encode(meta_envelope))
                    .body(blob_envelope.to_vec()),
            )
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("PUT /v1/clip/blob failed: {e}"),
                    "Check network connectivity and retry",
                )
            })?;
        let val = parse_relay_json(res).await?;
        Ok(ClipBlobPushReceipt {
            clip_id: val["clip_id"].as_str().unwrap_or(clip_id).to_string(),
            blob_bytes: val["blob_bytes"].as_i64().unwrap_or(blob_envelope.len() as i64),
            created_at_ms: val["created_at_ms"].as_i64().unwrap_or(now_ms() as i64),
            expires_at_ms: val["expires_at_ms"].as_i64().unwrap_or(0),
        })
    }

    /// `GET /v1/clip?since_id=&limit=`: fetch encrypted clip metadata envelopes.
    pub async fn clip_list(
        &self,
        since_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RemoteClipItem>, CoreError> {
        let lim = limit.clamp(1, 100);
        let url = match since_id.filter(|s| !s.is_empty()) {
            Some(since) => format!("{}/v1/clip?since_id={since}&limit={lim}", self.base_url),
            None => format!("{}/v1/clip?limit={lim}", self.base_url),
        };
        let res = self.add_headers(self.http.get(url)).send().await.map_err(|e| {
            CoreError::new(
                ErrorCode::SyncOffline,
                format!("GET /v1/clip failed: {e}"),
                "Check network connectivity and retry",
            )
        })?;
        let val = parse_relay_json(res).await?;
        serde_json::from_value(val["items"].clone()).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("invalid GET /v1/clip items payload: {e}"),
                "Verify relay version",
            )
        })
    }

    /// `GET /v1/clip/:clip_id/blob`: fetch raw `MNC1` (`payload_type=1`) blob from R2 via Worker.
    pub async fn clip_get_blob(&self, clip_id: &str) -> Result<RemoteClipBlob, CoreError> {
        let path = format!("/v1/clip/{clip_id}/blob");
        let res = self
            .add_headers(self.http.get(self.endpoint(&path)))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("GET /v1/clip/{clip_id}/blob failed: {e}"),
                    "Check network connectivity and retry",
                )
            })?;
        let status = res.status();
        if status.is_redirection() {
            return Err(CoreError::new(
                ErrorCode::SyncOffline,
                format!("clip blob endpoint returned redirect HTTP {}", status.as_u16()),
                "Check sync URL",
            ));
        }
        if status == StatusCode::NOT_FOUND {
            return Err(CoreError::new(
                ErrorCode::NotFound,
                format!("clip blob '{clip_id}' not found or expired on relay"),
                "Refresh clip history with 'mynote clip history'",
            ));
        }
        if status != StatusCode::OK {
            let _ = parse_relay_json(res).await?;
            return Err(CoreError::new(
                ErrorCode::SyncOffline,
                format!("clip blob request failed with HTTP {}", status.as_u16()),
                "Retry online",
            ));
        }
        let resp_clip_id = res
            .headers()
            .get("X-Clip-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(clip_id)
            .to_string();
        let resp_clip_kid = res
            .headers()
            .get("X-Clip-Kid")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let resp_device_id = res
            .headers()
            .get("X-Clip-Device-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = res.bytes().await.map_err(|e| {
            CoreError::new(
                ErrorCode::SyncOffline,
                format!("reading clip blob body failed: {e}"),
                "Retry online",
            )
        })?;
        if bytes.len() > CLIP_BLOB_ENVELOPE_MAX_BYTES {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!(
                    "downloaded clip blob ({} bytes) exceeds 10.5 MiB envelope cap",
                    bytes.len()
                ),
                "Refusing oversized blob",
            ));
        }
        Ok(RemoteClipBlob {
            clip_id: resp_clip_id,
            clip_kid: resp_clip_kid,
            device_id: resp_device_id,
            envelope: bytes.to_vec(),
        })
    }

    /// `DELETE /v1/clip` or `DELETE /v1/clip/:clip_id`.
    pub async fn clip_delete(&self, clip_id: Option<&str>) -> Result<usize, CoreError> {
        let path = match clip_id {
            Some(id) => format!("/v1/clip/{id}"),
            None => "/v1/clip".to_string(),
        };
        let res = self
            .add_headers(self.http.delete(self.endpoint(&path)))
            .send()
            .await
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::SyncOffline,
                    format!("DELETE {path} failed: {e}"),
                    "Check network connectivity and retry",
                )
            })?;
        let val = parse_relay_json(res).await?;
        Ok(val["deleted_count"].as_u64().unwrap_or(0) as usize)
    }
}

/// Ensure a valid `(ClipKid, ClipKey, gen)` exists locally and on the relay.
/// Syncs from remote `GET /v1/keys` if already published by another desktop, otherwise mints
/// a fresh `gen = 1` `ClipKey`, wraps it with current SMK, pushes to `POST /v1/keys`, and persists locally.
pub async fn ensure_clip_key(
    store: &mut LocalStore,
    client: &RelayClient,
) -> Result<mynote_store::UnwrappedClipKey, CoreError> {
    if let Some(local) = store.unwrap_local_clip_key()? {
        return Ok(local);
    }
    if let Some((gen, blob)) = client.fetch_remote_clip_key().await? {
        store.upsert_clip_key_material(gen, &blob, now_ms() as i64)?;
        if let Some(local) = store.unwrap_local_clip_key()? {
            return Ok(local);
        }
    }
    let now = now_ms();
    let (clip_kid, clip_key, blob) = store.generate_wrapped_clip_key(now)?;
    match client.push_clip_key_material(1, &blob, false).await {
        Ok(gen) => {
            store.upsert_clip_key_material(gen, &blob, now as i64)?;
            Ok((clip_kid, clip_key, gen))
        }
        Err(err) if err.code() == ErrorCode::CasMismatch => {
            if let Some((gen, r_blob)) = client.fetch_remote_clip_key().await? {
                store.upsert_clip_key_material(gen, &r_blob, now_ms() as i64)?;
                if let Some(local) = store.unwrap_local_clip_key()? {
                    return Ok(local);
                }
            }
            Err(err)
        }
        Err(err) => Err(err),
    }
}

/// Mutex-safe `ensure_clip_key` for Daemon async handlers (NEVER holds `std::sync::Mutex` across `.await`).
pub async fn ensure_clip_key_with_mutex(
    store_mutex: &Mutex<LocalStore>,
    client: &RelayClient,
) -> Result<mynote_store::UnwrappedClipKey, CoreError> {
    if let Some(local) = store_mutex.lock().unwrap().unwrap_local_clip_key()? {
        return Ok(local);
    }
    if let Some((gen, blob)) = client.fetch_remote_clip_key().await? {
        let store = store_mutex.lock().unwrap();
        store.upsert_clip_key_material(gen, &blob, now_ms() as i64)?;
        if let Some(local) = store.unwrap_local_clip_key()? {
            return Ok(local);
        }
    }
    let now = now_ms();
    let (clip_kid, clip_key, blob) = store_mutex.lock().unwrap().generate_wrapped_clip_key(now)?;
    match client.push_clip_key_material(1, &blob, false).await {
        Ok(gen) => {
            store_mutex
                .lock()
                .unwrap()
                .upsert_clip_key_material(gen, &blob, now as i64)?;
            Ok((clip_kid, clip_key, gen))
        }
        Err(err) if err.code() == ErrorCode::CasMismatch => {
            if let Some((gen, r_blob)) = client.fetch_remote_clip_key().await? {
                let store = store_mutex.lock().unwrap();
                store.upsert_clip_key_material(gen, &r_blob, now_ms() as i64)?;
                if let Some(local) = store.unwrap_local_clip_key()? {
                    return Ok(local);
                }
            }
            Err(err)
        }
        Err(err) => Err(err),
    }
}

/// Refresh local `ClipKey` from remote `GET /v1/keys` (e.g., after a peer rotated `ClipKey`).
pub async fn refresh_clip_key_from_remote(
    store: &mut LocalStore,
    client: &RelayClient,
) -> Result<Option<mynote_store::UnwrappedClipKey>, CoreError> {
    if let Some((gen, blob)) = client.fetch_remote_clip_key().await? {
        let local_gen = store.get_clip_key_material()?.map(|m| m.gen).unwrap_or(0);
        if gen > local_gen {
            store.upsert_clip_key_material(gen, &blob, now_ms() as i64)?;
        }
    }
    store.unwrap_local_clip_key()
}

/// Mutex-safe `refresh_clip_key_from_remote` for Daemon async handlers.
pub async fn refresh_clip_key_from_remote_with_mutex(
    store_mutex: &Mutex<LocalStore>,
    client: &RelayClient,
) -> Result<Option<mynote_store::UnwrappedClipKey>, CoreError> {
    if let Some((gen, blob)) = client.fetch_remote_clip_key().await? {
        let store = store_mutex.lock().unwrap();
        let local_gen = store.get_clip_key_material()?.map(|m| m.gen).unwrap_or(0);
        if gen > local_gen {
            store.upsert_clip_key_material(gen, &blob, now_ms() as i64)?;
        }
    }
    store_mutex.lock().unwrap().unwrap_local_clip_key()
}

/// Rotate `ClipKey` to a brand-new generation, instruct the relay to wipe `clip_items` & `clip/blobs/*`
/// (`clear_clips: true`), destructively overwrite local `key_material(kind='clip_key')`, and clear
/// local `clip_items` & `clip_cache/`.
pub async fn rotate_clip_key(
    store: &mut LocalStore,
    client: &RelayClient,
) -> Result<(ClipKid, i64), CoreError> {
    let remote_gen = client.fetch_remote_clip_key().await?.map(|(g, _)| g).unwrap_or(0);
    let local_gen = store.get_clip_key_material()?.map(|m| m.gen).unwrap_or(0);
    let next_gen = remote_gen.max(local_gen) + 1;
    let now = now_ms();
    let (new_kid, _new_key, blob) = store.generate_wrapped_clip_key(now)?;
    let acked_gen = client.push_clip_key_material(next_gen, &blob, true).await?;
    store.upsert_clip_key_material(acked_gen, &blob, now as i64)?;
    let _ = store.clear_clip_items()?;
    let _ = store.clip_cache().clear();
    Ok((new_kid, acked_gen))
}

fn build_ws_url(sync_url: &str) -> Result<String, CoreError> {
    let mut u = Url::parse(sync_url).map_err(|e| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            format!("invalid sync_url '{sync_url}': {e}"),
            "Provide http:// or https:// sync URL",
        )
    })?;
    let ws_scheme: String = match u.scheme() {
        "https" => "wss".to_string(),
        "http" => "ws".to_string(),
        other => other.to_string(),
    };
    let _ = u.set_scheme(&ws_scheme);
    u.set_path("/v1/sync/ws");
    Ok(u.to_string())
}
