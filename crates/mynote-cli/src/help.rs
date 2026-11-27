//! L1–L3a progressive help templates and offline topic guides
//! (`docs/architecture-proposal.md` §5.5, `docs/interface-contracts.md` §2.4).

pub const TOP_LEVEL_HELP: &str = "\
mynote — Local-first block scratchpad with E2EE sync & formatting

CAPTURE & BLOCKS:
  add         Create a new block (supports stdin pipe & --format)
  block       Read, update, append, move, resolve, revert, or delete (to trash)
  buf         List, create, rename, or delete buffers
  trash       List or restore blocks in the recycle bin
  import      Import existing Heynote buffers (∞∞∞ delimiter migration)

QUERY:
  ls          List recent blocks (summary-first, token-budget safe)
  search      Full-text search across unlocked blocks (FTS5)

TRANSFORM & OPS:
  format      Format a block or stdin (json/sql/yaml/xml/md + external CLIs)
  sync        Inspect sync status or explicitly push/pull
  vault       Lock/unlock sensitive blocks (TTY / client-side decryption)
  device      Bootstrap, pair/refresh (one-time claim code), list, or revoke
  keyring     Rotate SMK generation or unlock synced keyring with 24 words
  recovery    Show recovery bundle on init or run offline recovery drill
  restore     Rebuild offline from local R2 archive directory (--from-archive)
  daemon      Run local desktop HTTP/WS/UDS daemon with embedded Web UI
  open        Open the local desktop UI
  help        Deep topics: agent, formatting, conflict, locking, upgrade

GLOBAL FLAGS:
  --json              Structured JSON output envelope {ok, data, error, meta}
  --jsonl             Line-delimited JSON stream for list/search
  --quiet             Suppress non-data stderr notices
  --non-interactive   Never prompt; fail fast with exit code 2 or 5
  --data-dir <PATH>   Override data directory (or MYNOTE_DATA_DIR env)

NEXT STEP:
  Run 'mynote <cmd> --help' for flags, IO contract, exit codes & examples.
  Run 'mynote help agent' for AI agent integration contract & exit codes.";

pub const ADD_AFTER_HELP: &str = "\
STDIN & STDOUT:
  Reads positional [TEXT], or reads UTF-8 bytes from stdin when omitted.
  With --json, stdout emits {ok, data: {block_id, op_id, head_op_ids, buffer_id}, error, meta}.

EXIT CODES:
  0  Written locally (offline writes succeed with meta.sync_state = \"pending_offline\")
  2  INVALID_ARGUMENT
  3  NOT_FOUND (target buffer does not exist when passed by ID)
  7  FORMAT_SYNTAX_ERROR (when --format fails; zero writes performed)

EXAMPLES:
  mynote add \"quick note\" --buf scratch --json
  pbpaste | mynote add --lang json --format --json
  mynote add --buf work --idempotency-key req-42 --json < payload.json";

pub const BLOCK_AFTER_HELP: &str = "\
STDIN & STDOUT:
  'block get <id> --raw' writes exact display content bytes to stdout (no trailing decorations).
  'block update' / 'block resolve' read positional [TEXT] or stdin; 0-byte non-TTY stdin on a
  non-empty block fails with EMPTY_STDIN_REFUSED (exit 2) unless --allow-empty is passed.

EXIT CODES:
  0  Success (offline writes return pending_offline)
  2  INVALID_ARGUMENT | EMPTY_STDIN_REFUSED | INTERACTION_REQUIRED
  3  NOT_FOUND | IN_TRASH
  4  HEAD_MISMATCH (retry with details.actual_heads) | CONFLICT_PRESENT
  5  BLOCK_LOCKED | KEY_SHREDDED

EXAMPLES:
  mynote block get <id> --json
  mynote block get <id> --raw | jq .
  mynote block update <id> --expected-head <op_id> --json < new.txt
  mynote block revert <id> --undo-actor agent:claude-code --dry-run --json
  mynote block delete <id> --expected-head <op_id> --json";

pub const TRASH_AFTER_HELP: &str = "\
DELETE BOUNDARY:
  'block delete' moves blocks to the recycle bin only (recoverable via 'trash restore').
  'trash empty', 'trash expedite', and 'trash confirm' ALWAYS exit 2 (UI_CONFIRMATION_REQUIRED)
  regardless of TTY; irreversible trash actions require confirmation in the desktop UI.

EXIT CODES:
  0  Success
  2  UI_CONFIRMATION_REQUIRED (for empty / expedite / confirm)
  3  NOT_FOUND
  5  KEY_SHREDDED (grace period expired; content permanently unrecoverable)

EXAMPLES:
  mynote trash ls --json
  mynote trash restore <id> --json";

pub const FORMAT_AFTER_HELP: &str = "\
STDIN & STDOUT:
  With <id>: formats the block in-place (requires --expected-head; rejects multi-leaf blocks).
  Without <id>: pure filter reading stdin and writing formatted output to stdout.
  Syntax errors or empty external formatter output exit 7 with zero database writes.

EXIT CODES:
  0  Formatted successfully
  4  HEAD_MISMATCH | CONFLICT_PRESENT
  5  BLOCK_LOCKED
  7  FORMAT_SYNTAX_ERROR (original block untouched)

EXAMPLES:
  echo '{\"b\":1,\"a\":2}' | mynote format --lang json
  mynote format --lang json --action unescape-json < raw.txt
  mynote format <id> --expected-head <op_id> --json";

pub const CLIP_AFTER_HELP: &str = "\
CHANNEL ISOLATION:
  'mynote clip' uses an independent 100-item / 7-day encrypted channel (ClipKey / MNC1)
  physically isolated from note ops, FTS5 search, Markdown mirrors, and recovery keyrings.
  Bitmap images allow png/jpeg/webp/gif (<= 10 MiB); image/svg+xml is rejected as image.

EXIT CODES:
  0  Success
  2  INVALID_ARGUMENT (e.g., SVG image, >10 MiB, promote image) | INTERACTION_REQUIRED
  3  NOT_FOUND (clip_id not found or history empty)
  6  SYNC_OFFLINE | NO_ONLINE_DESKTOP (for --ephemeral when no desktop is online)

EXAMPLES:
  mynote clip push --text \"hello\" --json
  mynote clip push --file screenshot.png --json
  mynote clip push --text \"one-time-otp\" --ephemeral --json
  mynote clip pull --apply --json
  mynote clip history --limit 20 --kind text --json
  mynote clip promote --buf scratch --json
  mynote clip undo --json
  mynote clip watch --enable --auto-apply inbox-only --json
  mynote clip rotate-key";

pub fn render_topic(topic: &str) -> Option<&'static str> {
    match topic.to_ascii_lowercase().as_str() {
        "agent" => Some(TOPIC_AGENT),
        "formatting" | "format" => Some(TOPIC_FORMATTING),
        "conflict" | "conflicts" => Some(TOPIC_CONFLICT),
        "locking" | "lock" | "vault" => Some(TOPIC_LOCKING),
        "upgrade" | "downgrade" | "migration" => Some(TOPIC_UPGRADE),
        _ => None,
    }
}

const TOPIC_AGENT: &str = "\
# mynote help agent — AI Agent Integration Contract

## Output Discipline
- Pass `--json` on every programmatic call. `stdout` emits exactly ONE valid UTF-8 JSON object
  ending with `\\n`: `{ ok, data, error, meta }`. Diagnostics go to `stderr` only.
- Pass `--jsonl` on `ls` / `search` / `trash ls` for one JSON object per line.
- Offline local writes (`add`, `block update/append/move/delete`, `trash restore`, `import`)
  ALWAYS succeed locally with exit code `0` and `meta.sync_state = \"pending_offline\"`.
- Explicit network commands (`sync push`, `sync pull`, `device *`, `keyring rotate`) exit `6`
  (`SYNC_OFFLINE`, `retryable: true`) when offline or unconfigured.

## Stable Exit Codes
  0  Success (including offline local writes)
  2  INVALID_ARGUMENT | EMPTY_STDIN_REFUSED | INTERACTION_REQUIRED | UI_CONFIRMATION_REQUIRED
  3  NOT_FOUND | IN_TRASH (check details.deleted_at_ms; undo via `mynote trash restore <id>`)
  4  HEAD_MISMATCH (retryable; read error.details.actual_heads) | CONFLICT_PRESENT | CAS_MISMATCH
  5  BLOCK_LOCKED | KEY_SHREDDED | AUTH_REQUIRED | DEVICE_REVOKED | TOKEN_SCOPE_FORBIDDEN
  6  SYNC_OFFLINE | RATE_LIMITED (retryable)
  7  FORMAT_SYNTAX_ERROR (zero writes; original block untouched)
  8  KEY_MISSING | INTEGRITY_ERROR (e.g., SCHEMA_TOO_NEW)

## Optimistic Locking & Safety Fuses
1. Updates MUST declare every current leaf via repeatable `--expected-head <op_id>`.
   Never use `--force` in non-interactive shells (exits 2 `INTERACTION_REQUIRED`).
2. Empty non-TTY stdin on a non-empty block exits 2 (`EMPTY_STDIN_REFUSED`) unless `--allow-empty`.
3. `block delete` moves blocks to trash only (`shred_state: \"unscheduled\"` in M1).
   `trash empty` / `trash expedite` / `trash confirm` ALWAYS exit 2 (`UI_CONFIRMATION_REQUIRED`).
4. Locked blocks (`is_locked: true`, `redacted: true`) never expose plaintext to CLI/FTS5/mirror.
5. Time travel & rollback: inspect `mynote block history <id> --json`, preview with
   `mynote block revert <id> --undo-actor <actor> --dry-run --json`, then execute without `--dry-run`.
";

const TOPIC_FORMATTING: &str = "\
# mynote help formatting — Offline Layer 1 & External Layer 2 Pipelines

## Layer 1 (Built-in Offline Rust Core, Zero Subprocess)
- Languages: `json`, `json5`, `yaml`, `toml`, `sql`, `xml`, `markdown` (GFM CJK/Emoji table aligner)
- Actions (`--action`):
  - `unescape-json`, `compact`, `json5`
  - `to-json`, `to-yaml`, `to-toml`
  - `base64-encode`, `base64-decode`, `base64url-encode`, `base64url-decode`
  - `query-to-json`, `json-to-query`
  - `jwt-decode` (header & payload inspection only; does not verify signatures)
  - `ts-to-iso`, `iso-to-ts`

## Layer 2 (Optional External CLI Pipeline: ~/.config/mynote/formatters.toml)
Example configuration (array `cmd` or string `cmd` + `args` are both supported):
  [formatters.typescript]
  cmd = [\"biome\", \"format\", \"--stdin-file-path=scratch.ts\"]
  timeout_ms = 2000

  [formatters.python]
  cmd = \"ruff\"
  args = [\"format\", \"-\"]
  timeout_ms = 2000

Safety Fuse:
- Non-zero exit code, timeout kill, non-UTF-8 stdout, or 0-byte stdout for non-empty input
  ALWAYS returns `FORMAT_SYNTAX_ERROR` (exit 7) and leaves the target block unmodified.
- Child process runs with cleared environment (`PATH` and `LC_ALL=C.UTF-8` only).
- Unlocked Tier 2 blocks are NEVER sent to external Layer 2 subprocesses.
";

const TOPIC_CONFLICT: &str = "\
# mynote help conflict — Multi-Leaf (Path γ) Conflict Resolution

## How Conflicts Work
- Each block maintains a causal DAG of full-payload ops. Concurrent offline edits create
  multiple maximal leaves (`head_op_ids.length > 1`, `has_conflict: true`).
- `display_op_id` is the deterministic highest `(hlc, op_id)` live leaf.
- Single-version commands (`block append`, `format <id>`, `block revert`) refuse multi-leaf
  blocks with exit 4 (`CONFLICT_PRESENT`).

## Inspect & Merge Recipe
1. Inspect all versions (display version is always `versions[0]`):
     mynote block get <id> --json
2. Merge by passing EVERY leaf in `head_op_ids`:
     mynote block update <id> --expected-head <h1> --expected-head <h2> --json < merged.txt
   Or pick one existing version verbatim:
     mynote block resolve <id> --keep <h1> --expected-head <h1> --expected-head <h2> --json
3. Once merged, `head_op_ids` collapses back to 1 leaf (`has_conflict: false`).
";

const TOPIC_LOCKING: &str = "\
# mynote help locking — Tier 2 Vault Locked Blocks

- If ANY live leaf of a block is Tier 2 encrypted, the entire block is rendered as locked:
  `is_locked: true`, `redacted: true`, `content: null`, `preview: null`, `byte_size: null`.
- Locked blocks are strictly excluded from SQLite FTS5 search and `mirror/*.md` exports.
- If another device concurrently edited an unlocked version, `has_unlocked_concurrent_version: true`
  is reported; merging must happen after unlocking in the desktop UI.
- `mynote block get <id> --raw` on a locked block writes 0 bytes to stdout and exits 5 (`BLOCK_LOCKED`).
- `mynote block get <id> --decrypt` requires a real interactive TTY (exits 5 non-TTY).
";

const TOPIC_UPGRADE: &str = "\
# mynote help upgrade — Upgrades, Backups & Safe Downgrade Rollback

## Distribution & Auto-Backup
- `mynote` is distributed via package managers (Homebrew tap / AUR / cargo). It never self-updates
  or phones home in the background.
- Before any SQLite `PRAGMA user_version` schema migration, `mynote` automatically creates a `0600`
  snapshot at `<data_dir>/backups/mynote-pre-schema-v<old>.db` via `VACUUM INTO`.

## Downgrade (`SCHEMA_TOO_NEW`, Exit 8)
If an older binary opens a newer database (`min_reader_schema_version > supported`), it exits 8
(`INTEGRITY_ERROR`) without writing anything. To roll back manually:
1. Stop the daemon (if running).
2. Reinstall the target older version via your package manager.
3. Back up current `<data_dir>/mynote.db*` and restore `<data_dir>/backups/mynote-pre-schema-v<old>.db`
   to `<data_dir>/mynote.db`.
";
