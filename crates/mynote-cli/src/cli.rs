//! Clap CLI command tree (`docs/interface-contracts.md` §2.3, `docs/architecture-proposal.md` §5.5).

use crate::help::{ADD_AFTER_HELP, BLOCK_AFTER_HELP, FORMAT_AFTER_HELP, TOP_LEVEL_HELP, TRASH_AFTER_HELP};
use clap::{Args, CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "mynote",
    version,
    about = "Local-first block scratchpad with E2EE sync & formatting",
    override_help = TOP_LEVEL_HELP,
    disable_help_subcommand = true,
    propagate_version = true
)]
pub struct Cli {
    /// Structured JSON output envelope {ok, data, error, meta}
    #[arg(long, global = true)]
    pub json: bool,

    /// Line-delimited JSON stream for list/search/trash/history
    #[arg(long, global = true)]
    pub jsonl: bool,

    /// Suppress non-data stderr notices
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Never prompt; fail fast with exit code 2 or 5
    #[arg(long, global = true)]
    pub non_interactive: bool,

    /// Override local data directory (defaults to MYNOTE_DATA_DIR or ~/.local/share/mynote)
    #[arg(long, global = true, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Actor tag recorded in op metadata (defaults to MYNOTE_ACTOR or "human")
    #[arg(long, global = true, value_name = "ACTOR")]
    pub actor: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create a new block (supports stdin pipe & --format)
    #[command(after_help = ADD_AFTER_HELP)]
    Add(AddArgs),

    /// List recent active blocks (summary-first, token-budget safe)
    Ls(LsArgs),

    /// Full-text search across unlocked active blocks (FTS5)
    Search(SearchArgs),

    /// Read, update, append, move, resolve, history, revert, or delete (to trash) a block
    #[command(after_help = BLOCK_AFTER_HELP)]
    Block {
        #[command(subcommand)]
        action: BlockCommand,
    },

    /// List, create, rename, or delete buffers
    Buf {
        #[command(subcommand)]
        action: BufCommand,
    },

    /// List or restore blocks in the recycle bin
    #[command(after_help = TRASH_AFTER_HELP)]
    Trash {
        #[command(subcommand)]
        action: TrashCommand,
    },

    /// Format a block in-place or act as a pure stdin->stdout filter
    #[command(after_help = FORMAT_AFTER_HELP)]
    Format(FormatArgs),

    /// Import notes from external tools (Heynote ∞∞∞ migration)
    Import {
        #[command(subcommand)]
        source: ImportCommand,
    },

    /// Inspect sync status or explicitly trigger push/pull
    Sync {
        #[command(subcommand)]
        action: SyncCommand,
    },

    /// Lock/unlock sensitive Tier 2 blocks (TTY required)
    Vault {
        #[command(subcommand)]
        action: VaultCommand,
    },

    /// Manage device pairing, refresh codes, listing, and revocation
    Device {
        #[command(subcommand)]
        action: DeviceCommand,
    },

    /// Rotate SMK generation or unlock synced keyring with 24 recovery words
    Keyring {
        #[command(subcommand)]
        action: KeyringCommand,
    },

    /// Show recovery bundle (first init) or run offline recovery drill
    Recovery {
        #[command(subcommand)]
        action: RecoveryCommand,
    },

    /// Pure offline disaster recovery from local R2 archive directory (--from-archive)
    Restore(RestoreArgs),

    /// Run the local desktop HTTP/WS/UDS daemon with embedded Web UI and background sync
    Daemon(DaemonArgs),

    /// Open the local desktop UI
    Open,

    /// Deep offline help topics: agent, formatting, conflict, locking, upgrade
    Help {
        /// Topic name (agent, formatting, conflict, locking, upgrade) or subcommand name
        topic: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Loopback port for http://localhost:<port> (default: 19876)
    #[arg(long, default_value_t = 19876)]
    pub port: u16,

    /// Disable background cloud sync loop (local-only mode)
    #[arg(long)]
    pub no_cloud_sync: bool,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Text content (reads stdin when omitted)
    pub text: Option<String>,

    /// Target buffer name or ULID (default: "scratch")
    #[arg(long, default_value = "scratch")]
    pub buf: String,

    /// Language tag (auto-detected for JSON/SQL/Markdown or "text" when omitted)
    #[arg(long)]
    pub lang: Option<String>,

    /// Format input before writing (fails with exit 7 and zero writes on syntax error)
    #[arg(long)]
    pub format: bool,

    /// Insert immediately after the given block ID
    #[arg(long, value_name = "BLOCK_ID")]
    pub after: Option<String>,

    /// Client idempotency key (replay returns original block_id/op_id with idempotent_replay: true)
    #[arg(long, value_name = "KEY")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
pub struct LsArgs {
    /// Filter by buffer name or ULID
    #[arg(long)]
    pub buf: Option<String>,

    /// Maximum number of blocks to return
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    /// SQLite FTS5 query string
    pub query: String,

    /// Filter by buffer name or ULID
    #[arg(long)]
    pub buf: Option<String>,

    /// Maximum number of results to return
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

#[derive(Debug, Subcommand)]
pub enum BlockCommand {
    /// Read full details or raw bytes of a single block
    Get {
        /// Target block ULID
        id: String,

        /// Emit exact display content bytes to stdout with no trailing decorations
        #[arg(long)]
        raw: bool,

        /// Truncate displayed content to at most N Unicode scalar values
        #[arg(long, value_name = "N")]
        max_chars: Option<usize>,

        /// Interactively decrypt a locked Tier 2 block (requires real /dev/tty)
        #[arg(long)]
        decrypt: bool,
    },

    /// Replace block content (also used to merge multi-leaf conflicts)
    Update {
        /// Target block ULID
        id: String,

        /// New block text (reads stdin when omitted)
        text: Option<String>,

        /// Expected current head op_id (repeatable; must equal full leaf set)
        #[arg(long = "expected-head", value_name = "OP_ID")]
        expected_heads: Vec<String>,

        /// Bypass expected-head check in interactive TTY only (refused non-TTY)
        #[arg(long)]
        force: bool,

        /// Explicitly allow writing 0-byte content over a non-empty block
        #[arg(long)]
        allow_empty: bool,
    },

    /// Append text to a single-leaf block
    Append {
        /// Target block ULID
        id: String,

        /// Text to append (reads stdin when omitted)
        text: Option<String>,

        /// Optional expected head op_id for optimistic concurrency
        #[arg(long = "expected-head", value_name = "OP_ID")]
        expected_heads: Vec<String>,
    },

    /// Move block across buffers, reorder position, or update language metadata (LWW)
    Move {
        /// Target block ULID
        id: String,

        /// Destination buffer name or ULID
        #[arg(long, value_name = "BUF")]
        to_buf: Option<String>,

        /// Place after this block ID
        #[arg(long, value_name = "BLOCK_ID")]
        after: Option<String>,

        /// Place before this block ID
        #[arg(long, value_name = "BLOCK_ID")]
        before: Option<String>,

        /// Update language tag
        #[arg(long)]
        lang: Option<String>,
    },

    /// Alias of 'block update' for merging multi-leaf conflicts (supports --keep <op_id>)
    Resolve {
        /// Target block ULID
        id: String,

        /// Merged text (reads stdin when omitted unless --keep is given)
        text: Option<String>,

        /// Expected current head op_ids (repeatable; must equal full leaf set)
        #[arg(long = "expected-head", value_name = "OP_ID")]
        expected_heads: Vec<String>,

        /// Keep the exact content of an existing unlocked leaf op_id
        #[arg(long, value_name = "OP_ID")]
        keep: Option<String>,

        /// Bypass expected-head check in interactive TTY only
        #[arg(long)]
        force: bool,

        /// Explicitly allow empty merged content
        #[arg(long)]
        allow_empty: bool,
    },

    /// List historical full-payload op metadata for a block
    History {
        /// Target block ULID
        id: String,

        /// Maximum history entries to show
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Write a new UPDATE reverting a single-leaf block to a previous version
    Revert {
        /// Target block ULID
        id: String,

        /// Revert to the exact content of this op_id
        #[arg(long, value_name = "OP_ID")]
        to_op: Option<String>,

        /// Revert to the latest version not authored by this actor
        #[arg(long, value_name = "ACTOR")]
        undo_actor: Option<String>,

        /// Validate and preview the revert target without modifying the database
        #[arg(long)]
        dry_run: bool,
    },

    /// Move a block into the recycle bin (soft delete only; recoverable via 'trash restore')
    Delete {
        /// Target block ULID
        id: String,

        /// Optional expected head op_ids (repeatable)
        #[arg(long = "expected-head", value_name = "OP_ID")]
        expected_heads: Vec<String>,

        /// Validate and preview deletion without modifying the database
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum BufCommand {
    /// List active buffers in fractional-index order
    Ls,

    /// Create a new buffer
    Create {
        /// Buffer display name
        name: String,

        /// Insert after this buffer name or ULID
        #[arg(long, value_name = "BUF")]
        after: Option<String>,
    },

    /// Rename an existing buffer
    Rename {
        /// Buffer name or ULID
        buf: String,

        /// New display name
        new_name: String,
    },

    /// Soft-delete a buffer and its active blocks into trash
    Delete {
        /// Buffer name or ULID
        buf: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum TrashCommand {
    /// List all trashed (unshredded) blocks across devices
    Ls,

    /// Restore a block from the recycle bin back to its buffer
    Restore {
        /// Trashed block ULID
        id: String,

        /// Preview restoration without modifying the database
        #[arg(long)]
        dry_run: bool,
    },

    /// Desktop UI only — always returns UI_CONFIRMATION_REQUIRED (exit 2)
    Empty,

    /// Desktop UI only — always returns UI_CONFIRMATION_REQUIRED (exit 2)
    Expedite {
        /// Optional block ID
        id: Option<String>,
    },

    /// Desktop UI only — always returns UI_CONFIRMATION_REQUIRED (exit 2)
    Confirm {
        /// Optional block ID
        id: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct FormatArgs {
    /// Optional block ULID to format in-place (omit to filter stdin -> stdout)
    pub id: Option<String>,

    /// Language tag (required for stdin mode unless implied by --action)
    #[arg(long)]
    pub lang: Option<String>,

    /// Transform action (unescape-json, compact, to-yaml, to-toml, to-json, jwt-decode, ...)
    #[arg(long)]
    pub action: Option<String>,

    /// Expected head op_id when formatting a block in-place
    #[arg(long = "expected-head", value_name = "OP_ID")]
    pub expected_heads: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    /// Import a Heynote .txt buffer file or directory of .txt buffers
    Heynote {
        /// Path to Heynote .txt file or directory
        path: PathBuf,

        /// Override destination buffer name (single-file mode)
        #[arg(long)]
        buf: Option<String>,

        /// Parse and report block counts without writing to the database
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    /// Inspect local sync state, key liveness self-check, and trash summary
    Status,

    /// Explicitly push pending ops to configured Cloudflare relay (exits 6 if offline)
    Push,

    /// Explicitly pull ops and key table from configured Cloudflare relay (exits 6 if offline)
    Pull,
}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Initialize Tier 2 Vault VKEK with Argon2id passphrase and 24-word recovery backup (TTY required)
    Init,
    /// Lock an active block into Tier 2 Vault (TTY required)
    Lock {
        id: String,
        #[arg(long)]
        hint: Option<String>,
        #[arg(long = "expected-head", value_name = "OP_ID")]
        expected_heads: Vec<String>,
    },
    /// Unlock a Tier 2 Vault block back to Tier 1 (TTY required)
    Unlock {
        id: String,
        #[arg(long)]
        shred_old_key: bool,
        #[arg(long = "expected-head", value_name = "OP_ID")]
        expected_heads: Vec<String>,
    },
    /// Change Vault passphrase (use --recover to reset via 24-word recovery bundle; TTY required)
    Passwd {
        #[arg(long)]
        recover: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    /// Bootstrap first desktop device with BOOTSTRAP_TOKEN (TTY required)
    Bootstrap {
        #[arg(long)]
        url: String,
        #[arg(long)]
        revoke_existing: bool,
    },
    /// Generate a 10-minute one-time pairing ticket for a new device (TTY required)
    Add {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "read-write")]
        scope: String,
    },
    /// Generate a 10-minute one-time SMK refresh code for an existing device (TTY required)
    Refresh { device_id: String },
    /// Claim a pairing or refresh code on this device (TTY required)
    Claim,
    /// List registered devices
    Ls,
    /// Revoke a registered device
    Revoke { device_id: String },
}

#[derive(Debug, Subcommand)]
pub enum KeyringCommand {
    /// Append a new SMK generation and re-wrap active key records (TTY required)
    Rotate,
    /// Unseal missing SMK generations from synced keyring using 24 recovery words (TTY required)
    Unlock,
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    /// Display 24-word recovery bundle during initial bootstrap session (TTY required)
    Show,
    /// Offline read-only verification that 24 words unseal all SMK generations (TTY required)
    Drill,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// Local directory containing exported R2 archives/ops/*.mna1 and archives/keys/latest.mnks
    #[arg(long, value_name = "LOCAL_DIR")]
    pub from_archive: PathBuf,

    /// Empty or non-existent target data directory (never overwrites non-empty directories)
    #[arg(long, value_name = "EMPTY_DATA_DIR")]
    pub to: PathBuf,

    /// Key snapshot path or "latest"
    #[arg(long, default_value = "latest")]
    pub key_snapshot: String,

    /// Verify archives & recovery words without writing target directory
    #[arg(long)]
    pub dry_run: bool,
}

pub fn build_cli() -> clap::Command {
    Cli::command()
}
