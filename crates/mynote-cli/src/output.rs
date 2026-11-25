//! Unified CLI JSON envelope, JSONL streaming, and human output formatting
//! (`docs/interface-contracts.md` §2.1 & §2.6).

use mynote_core::error::CoreError;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Clone, Debug, Serialize)]
pub struct CliErrorBody {
    pub code: &'static str,
    pub message: String,
    pub hint: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CliMeta {
    pub local_op_count_pending: usize,
    pub sync_state: String,
    pub redacted_locked_count: usize,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CliEnvelope<T: Serialize> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<CliErrorBody>,
    pub meta: CliMeta,
}

impl<T: Serialize> CliEnvelope<T> {
    pub fn ok(data: T, meta: CliMeta) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            meta,
        }
    }
}

impl CliEnvelope<serde_json::Value> {
    pub fn err(err: &CoreError, meta: CliMeta) -> Self {
        let code = err.code();
        Self {
            ok: false,
            data: None,
            error: Some(CliErrorBody {
                code: code.as_str(),
                message: err.message().to_string(),
                hint: err.hint().to_string(),
                retryable: code.retryable(),
                details: err.details().cloned(),
            }),
            meta,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
    Jsonl,
}

pub fn emit_json<T: Serialize>(data: T, meta: CliMeta) {
    let env = CliEnvelope::ok(data, meta);
    let line = serde_json::to_string(&env).expect("envelope serialization must not fail");
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{line}");
}

pub fn emit_jsonl<T: Serialize>(items: &[T]) {
    let mut out = io::stdout().lock();
    for item in items {
        let line = serde_json::to_string(item).expect("jsonl item serialization must not fail");
        let _ = writeln!(out, "{line}");
    }
}

pub fn emit_error(err: &CoreError, mode: OutputMode, meta: CliMeta, quiet: bool) -> i32 {
    let code = err.code();
    match mode {
        OutputMode::Json | OutputMode::Jsonl => {
            let env = CliEnvelope::err(err, meta);
            let line = serde_json::to_string(&env).expect("error envelope serialization");
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{line}");
        }
        OutputMode::Human => {
            if !quiet {
                let mut err_out = io::stderr().lock();
                let _ = writeln!(err_out, "error [{}]: {}", code.as_str(), err.message());
                if !err.hint().is_empty() {
                    let _ = writeln!(err_out, "hint: {}", err.hint());
                }
            }
        }
    }
    code.exit_code()
}
