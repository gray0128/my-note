use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Global machine-readable error code registry (`docs/interface-contracts.md` §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArgument,
    EmptyStdinRefused,
    InteractionRequired,
    UiConfirmationRequired,
    NotFound,
    InTrash,
    HeadMismatch,
    ConflictPresent,
    CasMismatch,
    BlockLocked,
    KeyShredded,
    KeyUnknown,
    KeyPendingShred,
    ShredStale,
    GraceTooShort,
    AuthRequired,
    DeviceRevoked,
    TokenScopeForbidden,
    SyncOffline,
    RateLimited,
    FormatSyntaxError,
    KeyMissing,
    IntegrityError,
}

impl ErrorCode {
    /// Stable CLI exit code (`docs/interface-contracts.md` §1).
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::InvalidArgument
            | Self::EmptyStdinRefused
            | Self::InteractionRequired
            | Self::UiConfirmationRequired => 2,
            Self::NotFound | Self::InTrash => 3,
            Self::HeadMismatch
            | Self::ConflictPresent
            | Self::CasMismatch
            | Self::KeyPendingShred
            | Self::ShredStale => 4,
            Self::BlockLocked
            | Self::KeyShredded
            | Self::KeyUnknown
            | Self::GraceTooShort
            | Self::AuthRequired
            | Self::DeviceRevoked
            | Self::TokenScopeForbidden => 5,
            Self::SyncOffline | Self::RateLimited => 6,
            Self::FormatSyntaxError => 7,
            Self::KeyMissing | Self::IntegrityError => 8,
        }
    }

    /// Canonical HTTP status code (`docs/interface-contracts.md` §1).
    pub const fn http_status(self) -> u16 {
        match self {
            Self::InvalidArgument | Self::EmptyStdinRefused | Self::InteractionRequired => 400,
            Self::UiConfirmationRequired => 428,
            Self::NotFound | Self::InTrash => 404,
            Self::HeadMismatch
            | Self::ConflictPresent
            | Self::CasMismatch
            | Self::KeyUnknown
            | Self::KeyPendingShred
            | Self::ShredStale => 409,
            Self::BlockLocked => 423,
            Self::KeyShredded => 410,
            Self::GraceTooShort | Self::FormatSyntaxError => 422,
            Self::AuthRequired | Self::DeviceRevoked => 401,
            Self::TokenScopeForbidden => 403,
            Self::SyncOffline => 503,
            Self::RateLimited => 429,
            Self::KeyMissing | Self::IntegrityError => 500,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::HeadMismatch
                | Self::CasMismatch
                | Self::KeyPendingShred
                | Self::ShredStale
                | Self::SyncOffline
                | Self::RateLimited
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::EmptyStdinRefused => "EMPTY_STDIN_REFUSED",
            Self::InteractionRequired => "INTERACTION_REQUIRED",
            Self::UiConfirmationRequired => "UI_CONFIRMATION_REQUIRED",
            Self::NotFound => "NOT_FOUND",
            Self::InTrash => "IN_TRASH",
            Self::HeadMismatch => "HEAD_MISMATCH",
            Self::ConflictPresent => "CONFLICT_PRESENT",
            Self::CasMismatch => "CAS_MISMATCH",
            Self::BlockLocked => "BLOCK_LOCKED",
            Self::KeyShredded => "KEY_SHREDDED",
            Self::KeyUnknown => "KEY_UNKNOWN",
            Self::KeyPendingShred => "KEY_PENDING_SHRED",
            Self::ShredStale => "SHRED_STALE",
            Self::GraceTooShort => "GRACE_TOO_SHORT",
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::DeviceRevoked => "DEVICE_REVOKED",
            Self::TokenScopeForbidden => "TOKEN_SCOPE_FORBIDDEN",
            Self::SyncOffline => "SYNC_OFFLINE",
            Self::RateLimited => "RATE_LIMITED",
            Self::FormatSyntaxError => "FORMAT_SYNTAX_ERROR",
            Self::KeyMissing => "KEY_MISSING",
            Self::IntegrityError => "INTEGRITY_ERROR",
        }
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{code:?}: {message}")]
    Coded {
        code: ErrorCode,
        message: String,
        hint: String,
        details: Option<serde_json::Value>,
    },
}

impl CoreError {
    pub fn new(code: ErrorCode, message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::Coded {
            code,
            message: message.into(),
            hint: hint.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, value: serde_json::Value) -> Self {
        match &mut self {
            Self::Coded { details, .. } => *details = Some(value),
        }
        self
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Coded { code, .. } => *code,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Coded { message, .. } => message,
        }
    }

    pub fn hint(&self) -> &str {
        match self {
            Self::Coded { hint, .. } => hint,
        }
    }

    pub fn details(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Coded { details, .. } => details.as_ref(),
        }
    }
}
