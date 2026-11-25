//! Cloudflare blind sync HTTP + WebSocket Hibernation client (`#14 [M1-11]`).
//!
//! Enforces anti-302 captive-portal / CF-Access defense (`redirect: manual`, strict `HTTP 200` +
//! `Content-Type: application/json` + `body.ok === true` before advancing any local cursor).

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use mynote_core::crypto::{
    decrypt_pairing_ticket, encrypt_pairing_ticket, PairingPayloadV1, SmkGenerationBytes,
};
use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::ids::{DeviceId, JournalEpoch, KeyId, OpId};
use mynote_core::model::{KeyRecordRow, ShredMarkRow};
use mynote_core::sync::{
    step, AckedOp, KeyTableSyncDto, PushRequestDto, RemoteEnvelopeRow, SyncCommand, SyncEvent,
};
use mynote_store::store::SyncApplySummary;
use mynote_store::{DeviceCredentials, LocalStore};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    pub async fn create_pairing_ticket(
        &self,
        device_name: &str,
        scope: &str,
        smks: Vec<SmkGenerationBytes>,
    ) -> Result<PairingTicketReceipt, CoreError> {
        if scope != "read" && scope != "read-write" {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid scope '{scope}': expected 'read' or 'read-write'"),
                "Use --scope read (mobile) or --scope read-write (desktop)",
            ));
        }
        let new_device_id = DeviceId::from_random_bytes(rand_bytes::<10>()?);
        let raw_token = Zeroizing::new(rand_bytes::<32>()?);
        let new_device_token = format!("mnt_{}", hex_encode(raw_token.as_ref()));
        let token_hash = sha256_hex(&new_device_token);
        let pair_id = hex_encode(&rand_bytes::<16>()?);
        let k_pair = Zeroizing::new(rand_bytes::<32>()?);
        let payload = PairingPayloadV1 {
            smks,
            device_token: Some(new_device_token),
            device_id: new_device_id.clone(),
            sync_url: self.base_url.clone(),
        };
        let ct = encrypt_pairing_ticket(&pair_id, &k_pair, &payload, rand_bytes::<24>()?)?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "device_id": new_device_id.as_str(),
            "pair_id": pair_id,
            "device_name": device_name,
            "scope": scope,
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
            scope: scope.to_string(),
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

    pub async fn pull_page_for_daemon(
        &self,
        since_seq: i64,
        limit: u16,
    ) -> Result<(JournalEpoch, Vec<RemoteEnvelopeRow>, String, i64, bool), CoreError> {
        self.http_pull(since_seq, limit).await
    }

    pub async fn push_batch_for_daemon(
        &self,
        req: &PushRequestDto,
    ) -> Result<Result<(JournalEpoch, Vec<AckedOp>, i64), JournalEpoch>, CoreError> {
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

    async fn http_push(
        &self,
        req: &PushRequestDto,
    ) -> Result<Result<(JournalEpoch, Vec<AckedOp>, i64), JournalEpoch>, CoreError> {
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
        let body = serde_json::json!({
            "expected_epoch": req.expected_epoch.to_string(),
            "seen_seq": req.seen_seq,
            "key_records": key_records,
            "ops": ops,
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
                Ok(Ok((epoch, acked, head_seq)))
            }
            Err(err) if err.code() == ErrorCode::CasMismatch => {
                if let Some(remote_ep) = err
                    .details()
                    .and_then(|d| d.get("remote_epoch"))
                    .and_then(|v| v.as_str())
                {
                    let ep = JournalEpoch::parse(remote_ep)?;
                    return Ok(Err(ep));
                }
                Err(err)
            }
            Err(err) => Err(err),
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
        let keyring = val["key_material"]["keyring"].as_object().and_then(|o| {
            let gen = o.get("gen")?.as_u64()? as u32;
            let blob = b64.decode(o.get("blob_b64")?.as_str()?).ok()?;
            Some((gen, blob))
        });
        let vault_header = val["key_material"]["vault_header"].as_object().and_then(|o| {
            let gen = o.get("gen")?.as_i64()?;
            let blob = b64.decode(o.get("blob_b64")?.as_str()?).ok()?;
            Some((gen, blob))
        });
        Ok((records, Vec::new(), keyring, vault_header))
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

    /// Execute a full Sans-I/O sync round against Cloudflare relay (pull -> key diff -> push -> PITR reconcile).
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
        let mut prev_progress = (
            store.get_local_meta("last_seq"),
            store.get_local_meta("bootstrap_completed"),
            store.get_local_meta("reconciling_epoch"),
            report.pulled_ops,
            report.pushed_ops,
            report.keys_synced,
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
                    merge_summary(&mut report.apply_summary, store.apply_store_mutations(&muts)?);
                    // Prioritize SyncKeyTable before HttpPush so key_material & keys settle first
                    for c in next_cmds {
                        if matches!(c, SyncCommand::SyncKeyTable(_)) {
                            queue.insert(0, c);
                        } else {
                            queue.push(c);
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
                    merge_summary(&mut report.apply_summary, store.apply_store_mutations(&muts)?);
                    queue.extend(next_cmds);
                }
                SyncCommand::HttpPush(push_req) => {
                    if read_only {
                        continue;
                    }
                    match self.http_push(&push_req).await? {
                        Ok((epoch, acked, head_seq)) => {
                            report.epoch = Some(epoch.to_string());
                            report.head_seq = head_seq;
                            report.pushed_ops += acked.len();
                            let snap = store.export_engine_snapshot()?;
                            let (muts, next_cmds) = step(
                                &snap,
                                SyncEvent::PushAcked {
                                    epoch,
                                    acked,
                                    head_seq,
                                },
                            )?;
                            merge_summary(&mut report.apply_summary, store.apply_store_mutations(&muts)?);
                            queue.extend(next_cmds);
                        }
                        Err(remote_epoch) => {
                            report.reconciled_epoch_change = true;
                            let snap = store.export_engine_snapshot()?;
                            let (muts, next_cmds) =
                                step(&snap, SyncEvent::PushEpochMismatch { remote_epoch })?;
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
}

/// Long-running WebSocket Hibernation wakeup listener (`GET /v1/sync/ws`).
/// Sends `"ping"` every 30s (Cloudflare edge auto-responds `"pong"` without waking DO) and notifies
/// `on_wake` whenever `{ type: "wake" }` arrives; backs off exponentially (`1s -> 60s`) on disconnect,
/// and stops immediately on HTTP 401 / WS 4401 revocation.
pub async fn run_cloud_ws_loop<F>(creds: DeviceCredentials, mut on_wake: F)
where
    F: FnMut(Option<i64>) + Send + 'static,
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
                                                on_wake(v["head_seq"].as_i64());
                                            }
                                            Some("device_revoked") => {
                                                return;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                Some(Ok(Message::Close(frame))) => {
                                    if frame.as_ref().is_some_and(|f| u16::from(f.code) == 4401) {
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
                return;
            }
            Err(_) => {}
        }

        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(60);
    }
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
