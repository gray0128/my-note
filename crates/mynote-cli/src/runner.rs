//! CLI command execution engine implementing `docs/interface-contracts.md` §1 & §2.

use crate::cli::{
    build_cli, AddArgs, BlockCommand, BufCommand, Cli, Commands, DaemonArgs, DeviceCommand, FormatArgs,
    ImportCommand, KeyringCommand, LsArgs, RecoveryCommand, RestoreArgs, SearchArgs, SyncCommand,
    TrashCommand, VaultCommand,
};
use crate::daemon::{run_daemon_foreground, DaemonConfig};
use crate::formatters::format_content;
use crate::help::render_topic;
use crate::output::{emit_error, emit_json, emit_jsonl, CliMeta, OutputMode};
use crate::sync_client::{render_terminal_qr, RelayClient};
use crate::uds::{try_send_uds, ApplyMeta, ApplyRequest, UdsRequest, UdsResponse};
use clap::Parser;
use mynote_core::error::{CoreError, ErrorCode};
use mynote_store::store::{DeleteReceipt, LocalStore, WriteReceipt};
use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn run_async<F, T>(fut: F) -> Result<T, CoreError>
where
    F: std::future::Future<Output = Result<T, CoreError>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, format!("tokio runtime: {e}"), "Retry"))?;
    rt.block_on(fut)
}

fn try_daemon_apply(
    data_dir: &Path,
    meta: ApplyMeta,
    request: ApplyRequest,
    quiet: bool,
) -> Result<Option<UdsResponse>, CoreError> {
    let resp = try_send_uds(
        data_dir,
        &UdsRequest::Apply { meta, request },
        Duration::from_secs(10),
    )?;
    let Some(r) = resp else {
        return Ok(None);
    };
    if !quiet {
        if let Some(ver) = &r.version {
            if ver != env!("CARGO_PKG_VERSION") {
                eprintln!(
                    "warning: running mynote daemon version ({ver}) differs from CLI ({}); restart daemon",
                    env!("CARGO_PKG_VERSION")
                );
            }
        }
    }
    if !r.ok {
        return Err(r.into_core_error());
    }
    Ok(Some(r))
}

/// Entrypoint accepting arbitrary argv (makes in-process testing ergonomic).
pub fn run_from<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let raw_args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    let wants_json = raw_args.iter().any(|a| a == "--json" || a == "--jsonl");
    let wants_quiet = raw_args.iter().any(|a| a == "--quiet" || a == "-q");
    let started = Instant::now();

    let cli = match Cli::try_parse_from(&raw_args) {
        Ok(parsed) => parsed,
        Err(err) => {
            use clap::error::ErrorKind;
            match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    let _ = err.print();
                    return 0;
                }
                _ => {
                    if wants_json {
                        let ce = CoreError::new(
                            ErrorCode::InvalidArgument,
                            err.to_string().trim().to_string(),
                            "Run 'mynote --help' or 'mynote <cmd> --help' for valid usage",
                        );
                        return emit_error(&ce, OutputMode::Json, empty_meta(started), wants_quiet);
                    } else {
                        let _ = err.print();
                        return ErrorCode::InvalidArgument.exit_code();
                    }
                }
            }
        }
    };

    let mode = if cli.json {
        OutputMode::Json
    } else if cli.jsonl {
        OutputMode::Jsonl
    } else {
        OutputMode::Human
    };

    execute(cli, mode, started)
}

fn empty_meta(started: Instant) -> CliMeta {
    CliMeta {
        local_op_count_pending: 0,
        sync_state: "unconfigured".to_string(),
        redacted_locked_count: 0,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

fn store_meta(store: &LocalStore, started: Instant, redacted_override: Option<usize>) -> CliMeta {
    CliMeta {
        local_op_count_pending: store.pending_op_count(),
        sync_state: store.sync_state_label().to_string(),
        redacted_locked_count: redacted_override.unwrap_or_else(|| store.redacted_locked_count()),
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

fn resolve_data_dir(cli_override: Option<PathBuf>) -> PathBuf {
    if let Some(p) = cli_override {
        return p;
    }
    if let Ok(env_dir) = std::env::var("MYNOTE_DATA_DIR") {
        if !env_dir.trim().is_empty() {
            return PathBuf::from(env_dir);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("mynote");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local").join("share").join("mynote");
    }
    PathBuf::from(".mynote")
}

fn resolve_actor(cli_override: Option<String>) -> String {
    if let Some(a) = cli_override {
        return a;
    }
    if let Ok(env_a) = std::env::var("MYNOTE_ACTOR") {
        if !env_a.trim().is_empty() {
            return env_a;
        }
    }
    "human".to_string()
}

fn is_interactive_tty(non_interactive: bool) -> bool {
    !non_interactive && io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn require_tty(non_interactive: bool, op_name: &str) -> Result<(), CoreError> {
    if !is_interactive_tty(non_interactive) {
        return Err(CoreError::new(
            ErrorCode::InteractionRequired,
            format!("'{op_name}' requires an interactive TTY confirmation"),
            "Run this command directly in an interactive terminal without --non-interactive",
        ));
    }
    Ok(())
}

fn ui_confirmation_error(action: &str) -> CoreError {
    CoreError::new(
        ErrorCode::UiConfirmationRequired,
        format!("'mynote trash {action}' can only be confirmed inside the desktop UI"),
        "Open the desktop UI ('mynote open') and confirm there",
    )
}

fn read_text_arg_or_stdin(arg: Option<String>) -> Result<(String, bool), CoreError> {
    if let Some(t) = arg {
        return Ok((t, false));
    }
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf).map_err(|e| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            format!("failed to read UTF-8 content from stdin: {e}"),
            "Provide UTF-8 text as an argument or pipe it on stdin",
        )
    })?;
    Ok((buf, true))
}

fn read_tty_line(prompt: &str) -> Result<String, CoreError> {
    let mut stderr = io::stderr().lock();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(|e| {
        CoreError::new(
            ErrorCode::InteractionRequired,
            format!("failed reading interactive input: {e}"),
            "Retry in an interactive terminal",
        )
    })?;
    Ok(line.trim().to_string())
}

fn execute(cli: Cli, mode: OutputMode, started: Instant) -> i32 {
    let quiet = cli.quiet;
    let non_interactive = cli.non_interactive;
    let data_dir = resolve_data_dir(cli.data_dir);
    let actor = resolve_actor(cli.actor);

    // Handle commands that MUST NOT open or mutate the database first
    match &cli.command {
        Commands::Help { topic } => {
            return handle_help(topic.as_deref(), mode, started, quiet);
        }
        Commands::Trash {
            action: TrashCommand::Empty,
        } => {
            return emit_error(&ui_confirmation_error("empty"), mode, empty_meta(started), quiet);
        }
        Commands::Trash {
            action: TrashCommand::Expedite { .. },
        } => {
            return emit_error(
                &ui_confirmation_error("expedite"),
                mode,
                empty_meta(started),
                quiet,
            );
        }
        Commands::Trash {
            action: TrashCommand::Confirm { .. },
        } => {
            return emit_error(
                &ui_confirmation_error("confirm"),
                mode,
                empty_meta(started),
                quiet,
            );
        }
        Commands::Format(args) if args.id.is_none() => {
            return handle_format_stdin(args, mode, started, quiet);
        }
        Commands::Restore(args) => {
            return handle_restore(args, non_interactive, mode, started, quiet);
        }
        Commands::Vault { action } => {
            return handle_vault(action, non_interactive, mode, started, quiet);
        }
        Commands::Daemon(args) => {
            return handle_daemon(args, data_dir, mode, started, quiet);
        }
        Commands::Open => {
            return handle_open(&data_dir, mode, started, quiet);
        }
        Commands::Device {
            action: DeviceCommand::Claim,
        } => {
            return handle_device_claim(&data_dir, non_interactive, mode, started, quiet);
        }
        _ => {}
    }

    let mut store = match LocalStore::open(&data_dir) {
        Ok(s) => s,
        Err(err) => return emit_error(&err, mode, empty_meta(started), quiet),
    };

    if let Some(words) = &store.initial_recovery_words {
        if !quiet && mode == OutputMode::Human {
            let mut err_out = io::stderr().lock();
            let _ = writeln!(
                err_out,
                "Initialized new vault at {}. Record your 24-word recovery bundle safely:\n  {words}",
                data_dir.display()
            );
        }
    }

    let res = match cli.command {
        Commands::Add(args) => handle_add(&mut store, args, &actor, mode, started, quiet),
        Commands::Ls(args) => handle_ls(&store, args, mode, started),
        Commands::Search(args) => handle_search(&store, args, mode, started),
        Commands::Block { action } => {
            handle_block(&mut store, action, &actor, non_interactive, mode, started, quiet)
        }
        Commands::Buf { action } => handle_buf(&mut store, action, &actor, mode, started, quiet),
        Commands::Trash { action } => handle_trash(&mut store, action, &actor, mode, started, quiet),
        Commands::Format(args) => handle_format_block(&mut store, args, &actor, mode, started, quiet),
        Commands::Import { source } => handle_import(&mut store, source, &actor, mode, started, quiet),
        Commands::Sync { action } => handle_sync(&mut store, action, mode, started),
        Commands::Device { action } => handle_device(&mut store, action, non_interactive, mode, started),
        Commands::Keyring { action } => handle_keyring(&mut store, action, non_interactive, mode, started),
        Commands::Recovery { action } => handle_recovery(&store, action, non_interactive, mode, started),
        Commands::Help { .. }
        | Commands::Restore(_)
        | Commands::Vault { .. }
        | Commands::Daemon(_)
        | Commands::Open => {
            unreachable!("handled prior to opening store")
        }
    };

    match res {
        Ok(code) => code,
        Err(err) => emit_error(&err, mode, store_meta(&store, started, None), quiet),
    }
}

fn handle_daemon(
    args: &DaemonArgs,
    data_dir: PathBuf,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> i32 {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            let err = CoreError::new(ErrorCode::IntegrityError, format!("tokio runtime: {e}"), "Retry");
            return emit_error(&err, mode, empty_meta(started), quiet);
        }
    };
    let cfg = DaemonConfig {
        data_dir,
        port: args.port,
        enable_cloud_sync: !args.no_cloud_sync,
    };
    match rt.block_on(run_daemon_foreground(cfg)) {
        Ok(()) => 0,
        Err(err) => emit_error(&err, mode, empty_meta(started), quiet),
    }
}

fn handle_open(data_dir: &Path, mode: OutputMode, started: Instant, quiet: bool) -> i32 {
    match try_send_uds(data_dir, &UdsRequest::OpenTicket, Duration::from_secs(3)) {
        Ok(Some(resp)) if resp.ok => {
            let url = resp.url.unwrap_or_default();
            let port = resp.port.unwrap_or(19876);
            if mode == OutputMode::Human && std::env::var("MYNOTE_NO_BROWSER").is_err() {
                #[cfg(target_os = "macos")]
                let _ = std::process::Command::new("open").arg(&url).spawn();
                #[cfg(target_os = "linux")]
                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
            }
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(
                    serde_json::json!({ "status": "opened", "url": url, "port": port }),
                    empty_meta(started),
                ),
                OutputMode::Human => println!("{url}"),
            }
            0
        }
        Ok(Some(resp)) => emit_error(&resp.into_core_error(), mode, empty_meta(started), quiet),
        Ok(None) => {
            let msg = serde_json::json!({
                "status": "daemon_not_running",
                "hint": "Start the local daemon via 'mynote daemon' to open http://localhost:<port>"
            });
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(msg, empty_meta(started)),
                OutputMode::Human => {
                    println!("mynote daemon is not running. Start it with: mynote daemon");
                }
            }
            0
        }
        Err(err) => emit_error(&err, mode, empty_meta(started), quiet),
    }
}

fn handle_device_claim(
    data_dir: &Path,
    non_interactive: bool,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> i32 {
    if let Err(err) = require_tty(non_interactive, "device claim") {
        return emit_error(&err, mode, empty_meta(started), quiet);
    }
    let code = match read_tty_line("Paste pairing/refresh code (mynote-pair:v1:...): ") {
        Ok(c) => c,
        Err(err) => return emit_error(&err, mode, empty_meta(started), quiet),
    };
    let receipt = match run_async(RelayClient::claim_pairing_code(&code, data_dir)) {
        Ok(r) => r,
        Err(err) => return emit_error(&err, mode, empty_meta(started), quiet),
    };
    // Perform an immediate pull so synced notes/keys hydrate cleanly right after claim
    if let Ok(mut store) = LocalStore::open(data_dir) {
        if let Ok(Some(creds)) = store.load_credentials() {
            if let Ok(client) = RelayClient::from_credentials(&creds) {
                let _ = run_async(client.run_sync_round(&mut store, creds.scope == "read"));
            }
        }
    }
    match mode {
        OutputMode::Json | OutputMode::Jsonl => emit_json(&receipt, empty_meta(started)),
        OutputMode::Human => println!(
            "claimed {} for device {} (scope={}, smk_generations={})",
            receipt.kind, receipt.device_id, receipt.scope, receipt.smk_generations
        ),
    }
    0
}

fn handle_help(topic: Option<&str>, mode: OutputMode, started: Instant, quiet: bool) -> i32 {
    let Some(t) = topic else {
        let mut cmd = build_cli();
        let _ = cmd.print_help();
        println!();
        return 0;
    };
    if let Some(doc) = render_topic(t) {
        if mode == OutputMode::Json {
            emit_json(
                serde_json::json!({ "topic": t, "content": doc }),
                empty_meta(started),
            );
        } else {
            print!("{doc}");
        }
        return 0;
    }
    let mut cmd = build_cli();
    if let Some(sub) = cmd.find_subcommand_mut(t) {
        let _ = sub.print_help();
        println!();
        return 0;
    }
    let err = CoreError::new(
        ErrorCode::InvalidArgument,
        format!("unknown help topic or command '{t}'"),
        "Available topics: agent, formatting, conflict, locking, upgrade (or any subcommand name)",
    );
    emit_error(&err, mode, empty_meta(started), quiet)
}

fn handle_add(
    store: &mut LocalStore,
    args: AddArgs,
    actor: &str,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> Result<i32, CoreError> {
    let (raw_text, _) = read_text_arg_or_stdin(args.text)?;
    let effective_lang = args
        .lang
        .clone()
        .unwrap_or_else(|| mynote_store::store::sniff_language(&raw_text));
    let final_text = if args.format {
        format_content(&raw_text, &effective_lang, None)?
    } else {
        raw_text
    };

    if let Some(resp) = try_daemon_apply(
        store.data_dir(),
        ApplyMeta {
            actor: actor.to_string(),
            idempotency_key: args.idempotency_key.clone(),
            allow_empty: true,
            force: false,
        },
        ApplyRequest::AddBlock {
            buffer: args.buf.clone(),
            content: final_text.clone(),
            lang: Some(effective_lang.clone()),
            after_id: args.after.clone(),
        },
        quiet,
    )? {
        if let Some(data) = resp.data {
            let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode daemon receipt")
            })?;
            emit_write_receipt(&receipt, store, mode, started);
            return Ok(0);
        }
    }

    let receipt = store.add_block(
        &args.buf,
        &final_text,
        Some(&effective_lang),
        args.after.as_deref(),
        actor,
        args.idempotency_key.as_deref(),
    )?;

    emit_write_receipt(&receipt, store, mode, started);
    Ok(0)
}

fn handle_ls(store: &LocalStore, args: LsArgs, mode: OutputMode, started: Instant) -> Result<i32, CoreError> {
    let items = store.list_blocks(args.buf.as_deref(), args.limit)?;
    let redacted = items.iter().filter(|b| b.redacted).count();
    match mode {
        OutputMode::Json => emit_json(&items, store_meta(store, started, Some(redacted))),
        OutputMode::Jsonl => emit_jsonl(&items),
        OutputMode::Human => {
            if items.is_empty() {
                println!("(no active blocks)");
            } else {
                for item in &items {
                    let badge = if item.is_locked {
                        format!(
                            "[LOCKED{}]",
                            item.public_hint
                                .as_deref()
                                .map(|h| format!(" hint: {h}"))
                                .unwrap_or_default()
                        )
                    } else if item.has_conflict {
                        format!("[CONFLICT {} leaves]", item.head_op_ids.len())
                    } else {
                        String::new()
                    };
                    let preview = item.preview.as_deref().unwrap_or("<redacted>").replace('\n', " ");
                    println!(
                        "{}  {:10} {:10} {} {}",
                        item.id, item.buffer_name, item.lang, badge, preview
                    );
                }
            }
        }
    }
    Ok(0)
}

fn handle_search(
    store: &LocalStore,
    args: SearchArgs,
    mode: OutputMode,
    started: Instant,
) -> Result<i32, CoreError> {
    let items = store.search_blocks(&args.query, args.buf.as_deref(), args.limit)?;
    match mode {
        OutputMode::Json => emit_json(&items, store_meta(store, started, Some(0))),
        OutputMode::Jsonl => emit_jsonl(&items),
        OutputMode::Human => {
            if items.is_empty() {
                println!("(no matching unlocked blocks)");
            } else {
                for item in &items {
                    let preview = item.preview.as_deref().unwrap_or("").replace('\n', " ");
                    println!(
                        "{}  {:10} {:10} {}",
                        item.id, item.buffer_name, item.lang, preview
                    );
                }
            }
        }
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn handle_block(
    store: &mut LocalStore,
    action: BlockCommand,
    actor: &str,
    non_interactive: bool,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> Result<i32, CoreError> {
    match action {
        BlockCommand::Get {
            id,
            raw,
            max_chars,
            decrypt,
        } => {
            if decrypt {
                // `docs/interface-contracts.md` §2.6 #9: --decrypt in non-TTY returns BLOCK_LOCKED (exit 5)
                if !is_interactive_tty(non_interactive) {
                    return Err(CoreError::new(
                        ErrorCode::BlockLocked,
                        "cannot decrypt a locked block in non-TTY mode",
                        "Unlock interactively in a real terminal or desktop UI",
                    ));
                }
                return Err(CoreError::new(
                    ErrorCode::BlockLocked,
                    "Tier 2 Vault interactive decryption lands in Milestone M2",
                    "Use the desktop UI once Tier 2 Vault is enabled",
                ));
            }

            let mut detail = store.get_block(&id)?;

            if raw {
                if detail.is_locked {
                    // `docs/interface-contracts.md` §2.2 #2 & G10: stdout MUST be empty, exit 5
                    if mode == OutputMode::Json {
                        return Err(CoreError::new(
                            ErrorCode::BlockLocked,
                            format!("block '{id}' is locked (Tier 2 Vault)"),
                            "Locked block plaintext cannot be emitted in raw non-TTY mode",
                        ));
                    }
                    return Ok(ErrorCode::BlockLocked.exit_code());
                }
                if detail.versions.len() > 1 && !quiet {
                    let _ = writeln!(io::stderr(), "block has {} versions", detail.versions.len());
                }
                let content = detail.content.unwrap_or_default();
                let out_str = apply_max_chars(&content, max_chars);
                let mut stdout = io::stdout().lock();
                let _ = stdout.write_all(out_str.as_bytes());
                let _ = stdout.flush();
                return Ok(0);
            }

            if detail.is_locked {
                // Non-TTY human/default access to a locked block returns BLOCK_LOCKED (exit 5) with ZERO plaintext (`G10`),
                // while `--json` returns either redacted metadata OR if the user only inspects metadata without --raw:
                // Wait: per `docs/interface-contracts.md` §2.2 #2 & `eval-framework.md` G10:
                // - `block get <id> --json` returns redacted DTO (`content: null`, `versions[*].content: null`, `redacted: true`)
                //   UNLESS `--decrypt` was requested (exit 5).
                // - `block get <id>` (human) or `--raw` on a locked block exits 5 (`BLOCK_LOCKED`) with zero plaintext!
                if mode == OutputMode::Human {
                    return Err(CoreError::new(
                        ErrorCode::BlockLocked,
                        format!("block '{id}' is locked (Tier 2 Vault)"),
                        "Inspect redacted metadata with '--json' or unlock in the desktop UI",
                    ));
                }
            }

            if let Some(limit) = max_chars {
                if let Some(ref mut c) = detail.content {
                    *c = apply_max_chars(c, Some(limit));
                }
                for v in &mut detail.versions {
                    if let Some(ref mut c) = v.content {
                        *c = apply_max_chars(c, Some(limit));
                    }
                }
            }

            let redacted = usize::from(detail.redacted);
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(&detail, store_meta(store, started, Some(redacted)));
                }
                OutputMode::Human => {
                    println!(
                        "block {}  buf={}  lang={}  heads={}",
                        detail.id,
                        detail.buffer_id,
                        detail.lang,
                        detail.head_op_ids.join(",")
                    );
                    if detail.has_conflict {
                        println!(
                            "warning: {} concurrent versions (showing display version first)",
                            detail.versions.len()
                        );
                    }
                    if let Some(c) = &detail.content {
                        println!("---\n{c}");
                    }
                }
            }
            Ok(0)
        }

        BlockCommand::Update {
            id,
            text,
            expected_heads,
            force,
            allow_empty,
        } => {
            if force {
                require_tty(non_interactive, "block update --force")?;
            } else if expected_heads.is_empty() {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "missing required --expected-head <op_id>",
                    format!(
                        "Run 'mynote block get {id} --json' to fetch head_op_ids, then pass --expected-head"
                    ),
                ));
            }
            let (content, from_stdin) = read_text_arg_or_stdin(text)?;
            check_empty_stdin_fuse(store, &id, &content, from_stdin, allow_empty, non_interactive)?;
            if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty,
                    force,
                },
                ApplyRequest::UpdateBlock {
                    id: id.clone(),
                    content: content.clone(),
                    expected_heads: expected_heads.clone(),
                },
                quiet,
            )? {
                if let Some(data) = resp.data {
                    let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode daemon receipt")
                    })?;
                    emit_write_receipt(&receipt, store, mode, started);
                    return Ok(0);
                }
            }
            let receipt = store.update_block(&id, &content, &expected_heads, force, actor)?;
            emit_write_receipt(&receipt, store, mode, started);
            Ok(0)
        }

        BlockCommand::Append {
            id,
            text,
            expected_heads,
        } => {
            let (suffix, _) = read_text_arg_or_stdin(text)?;
            if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::AppendBlock {
                    id: id.clone(),
                    text: suffix.clone(),
                    expected_heads: expected_heads.clone(),
                },
                quiet,
            )? {
                if let Some(data) = resp.data {
                    let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode daemon receipt")
                    })?;
                    emit_write_receipt(&receipt, store, mode, started);
                    return Ok(0);
                }
            }
            let exp_opt = if expected_heads.is_empty() {
                None
            } else {
                Some(expected_heads.as_slice())
            };
            let receipt = store.append_block(&id, &suffix, exp_opt, actor)?;
            emit_write_receipt(&receipt, store, mode, started);
            Ok(0)
        }

        BlockCommand::Move {
            id,
            to_buf,
            after,
            before,
            lang,
        } => {
            if to_buf.is_none() && after.is_none() && before.is_none() && lang.is_none() {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "specify at least one of --to-buf, --after, --before, or --lang",
                    "Run 'mynote block move --help' for examples",
                ));
            }
            if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::MoveBlock {
                    id: id.clone(),
                    to_buf: to_buf.clone(),
                    after_id: after.clone(),
                    before_id: before.clone(),
                    lang: lang.clone(),
                },
                quiet,
            )? {
                if let Some(data) = resp.data {
                    let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode daemon receipt")
                    })?;
                    emit_write_receipt(&receipt, store, mode, started);
                    return Ok(0);
                }
            }
            let receipt = store.move_block(
                &id,
                to_buf.as_deref(),
                after.as_deref(),
                before.as_deref(),
                lang.as_deref(),
                actor,
            )?;
            emit_write_receipt(&receipt, store, mode, started);
            Ok(0)
        }

        BlockCommand::Resolve {
            id,
            text,
            expected_heads,
            keep,
            force,
            allow_empty,
        } => {
            if force {
                require_tty(non_interactive, "block resolve --force")?;
            } else if expected_heads.is_empty() {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "missing required --expected-head <op_id> (must list all current leaves)",
                    format!("Run 'mynote block get {id} --json' and pass every head_op_id"),
                ));
            }

            let content = if let Some(ref keep_op) = keep {
                let detail = store.get_block(&id)?;
                if detail.is_locked {
                    return Err(CoreError::new(
                        ErrorCode::BlockLocked,
                        format!("block '{id}' is locked; resolve in desktop UI after unlocking"),
                        "Unlock the block in desktop UI to merge locked versions",
                    ));
                }
                let ver = detail
                    .versions
                    .iter()
                    .find(|v| v.op_id == *keep_op)
                    .ok_or_else(|| {
                        CoreError::new(
                            ErrorCode::NotFound,
                            format!("leaf op_id '{keep_op}' not found on block '{id}'"),
                            format!("Run 'mynote block get {id} --json' to list active leaf op_ids"),
                        )
                    })?;
                ver.content.clone().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::BlockLocked,
                        format!("version '{keep_op}' has no available plaintext"),
                        "Unlock the block in desktop UI",
                    )
                })?
            } else {
                let (c, from_stdin) = read_text_arg_or_stdin(text)?;
                check_empty_stdin_fuse(store, &id, &c, from_stdin, allow_empty, non_interactive)?;
                c
            };

            if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty,
                    force,
                },
                ApplyRequest::ResolveBlock {
                    id: id.clone(),
                    expected_heads: expected_heads.clone(),
                    content: if keep.is_some() {
                        None
                    } else {
                        Some(content.clone())
                    },
                    keep_op_id: keep.clone(),
                },
                quiet,
            )? {
                if let Some(data) = resp.data {
                    let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode daemon receipt")
                    })?;
                    emit_write_receipt(&receipt, store, mode, started);
                    return Ok(0);
                }
            }

            let receipt = store.update_block(&id, &content, &expected_heads, force, actor)?;
            emit_write_receipt(&receipt, store, mode, started);
            Ok(0)
        }

        BlockCommand::History { id, limit } => {
            let entries = store.block_history(&id, limit)?;
            match mode {
                OutputMode::Json => emit_json(&entries, store_meta(store, started, None)),
                OutputMode::Jsonl => emit_jsonl(&entries),
                OutputMode::Human => {
                    for e in &entries {
                        println!(
                            "{}  {}  {}  actor={}  available={}",
                            e.op_id, e.op_type, e.hlc, e.actor, e.content_available
                        );
                    }
                }
            }
            Ok(0)
        }

        BlockCommand::Revert {
            id,
            to_op,
            undo_actor,
        } => {
            if to_op.is_none() && undo_actor.is_none() {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "specify either --to-op <op_id> or --undo-actor <actor>",
                    format!("Run 'mynote block history {id} --json' to list historical ops"),
                ));
            }
            if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::RevertBlock {
                    id: id.clone(),
                    to_op: to_op.clone(),
                    undo_actor: undo_actor.clone(),
                },
                quiet,
            )? {
                if let Some(data) = resp.data {
                    let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode daemon receipt")
                    })?;
                    emit_write_receipt(&receipt, store, mode, started);
                    return Ok(0);
                }
            }
            let target_op = match (to_op, undo_actor) {
                (Some(op), _) => op,
                (None, Some(bad_actor)) => {
                    let history = store.block_history(&id, 200)?;
                    history
                        .into_iter()
                        .find(|e| e.actor != bad_actor && e.content_available)
                        .map(|e| e.op_id)
                        .ok_or_else(|| {
                            CoreError::new(
                                ErrorCode::NotFound,
                                format!("no earlier available version outside actor '{bad_actor}'"),
                                format!("Run 'mynote block history {id} --json' to pick an op_id explicitly"),
                            )
                        })?
                }
                (None, None) => unreachable!("checked above"),
            };
            let receipt = store.revert_block(&id, &target_op, actor)?;
            emit_write_receipt(&receipt, store, mode, started);
            Ok(0)
        }

        BlockCommand::Delete {
            id,
            expected_heads,
            dry_run,
        } => {
            let exp_opt = if expected_heads.is_empty() {
                None
            } else {
                Some(expected_heads.as_slice())
            };
            if dry_run {
                let detail = store.get_block(&id)?;
                if let Some(exp) = exp_opt {
                    let exp_set: BTreeSet<String> = exp.iter().cloned().collect();
                    let act_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
                    if exp_set != act_set {
                        return Err(CoreError::new(
                            ErrorCode::HeadMismatch,
                            format!("block {id} heads changed concurrently"),
                            format!("Run 'mynote block get {id} --json' and retry"),
                        )
                        .with_details(serde_json::json!({
                            "expected_heads": exp,
                            "actual_heads": detail.head_op_ids,
                        })));
                    }
                }
                let preview = serde_json::json!({
                    "dry_run": true,
                    "block_id": detail.id,
                    "buffer_id": detail.buffer_id,
                    "head_op_ids": detail.head_op_ids,
                    "in_trash": true,
                    "shred_not_before_ms": serde_json::Value::Null,
                    "shred_state": "unscheduled",
                });
                match mode {
                    OutputMode::Json | OutputMode::Jsonl => {
                        emit_json(preview, store_meta(store, started, None));
                    }
                    OutputMode::Human => {
                        println!("dry-run: would move block {} to recycle bin", detail.id);
                    }
                }
                return Ok(0);
            }

            if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::DeleteBlock {
                    id: id.clone(),
                    expected_heads: expected_heads.clone(),
                    dry_run: false,
                },
                quiet,
            )? {
                if let Some(data) = resp.data {
                    let receipt: DeleteReceipt = serde_json::from_value(data).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode delete receipt")
                    })?;
                    emit_delete_receipt(&receipt, store, mode, started);
                    return Ok(0);
                }
            }

            let receipt = store.delete_block(&id, exp_opt, actor)?;
            emit_delete_receipt(&receipt, store, mode, started);
            Ok(0)
        }
    }
}

fn check_empty_stdin_fuse(
    store: &LocalStore,
    id: &str,
    new_content: &str,
    from_stdin: bool,
    allow_empty: bool,
    non_interactive: bool,
) -> Result<(), CoreError> {
    if !new_content.is_empty() || allow_empty {
        return Ok(());
    }
    let non_tty = non_interactive || !io::stdin().is_terminal();
    if from_stdin && non_tty {
        let detail = store.get_block(id)?;
        if detail.is_locked {
            return Err(CoreError::new(
                ErrorCode::BlockLocked,
                format!("block '{id}' is locked (Tier 2 Vault)"),
                "Unlock the block interactively before updating",
            ));
        }
        let currently_non_empty = detail.content.as_deref().is_some_and(|c| !c.is_empty());
        if currently_non_empty {
            return Err(CoreError::new(
                ErrorCode::EmptyStdinRefused,
                "refusing to overwrite non-empty block with 0-byte non-interactive stdin",
                format!(
                    "Pass --allow-empty to clear content, or use 'mynote block delete {id}' (moves it to trash)"
                ),
            ));
        }
    }
    Ok(())
}

fn apply_max_chars(text: &str, max_chars: Option<usize>) -> String {
    match max_chars {
        Some(limit) => text.chars().take(limit).collect(),
        None => text.to_string(),
    }
}

fn handle_buf(
    store: &mut LocalStore,
    action: BufCommand,
    actor: &str,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> Result<i32, CoreError> {
    match action {
        BufCommand::Ls => {
            let bufs = store.list_buffers()?;
            match mode {
                OutputMode::Json => emit_json(&bufs, store_meta(store, started, None)),
                OutputMode::Jsonl => emit_jsonl(&bufs),
                OutputMode::Human => {
                    for b in &bufs {
                        println!("{}  {}  (pos={})", b.id, b.name, b.position);
                    }
                }
            }
        }
        BufCommand::Create { name, after } => {
            let buf: mynote_store::store::BufferDto = if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::CreateBuffer {
                    name: name.clone(),
                    after: after.clone(),
                },
                quiet,
            )? {
                serde_json::from_value(resp.data.unwrap_or_default()).map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode buffer dto")
                })?
            } else {
                store.create_buffer(&name, after.as_deref(), actor)?
            };
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(&buf, store_meta(store, started, None)),
                OutputMode::Human => println!("created buffer {} ({})", buf.name, buf.id),
            }
        }
        BufCommand::Rename { buf, new_name } => {
            let updated: mynote_store::store::BufferDto = if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::RenameBuffer {
                    buf: buf.clone(),
                    new_name: new_name.clone(),
                },
                quiet,
            )? {
                serde_json::from_value(resp.data.unwrap_or_default()).map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode buffer dto")
                })?
            } else {
                store.rename_buffer(&buf, &new_name, actor)?
            };
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(&updated, store_meta(store, started, None));
                }
                OutputMode::Human => println!("renamed buffer {} -> {}", updated.id, updated.name),
            }
        }
        BufCommand::Delete { buf } => {
            let deleted: mynote_store::store::BufferDto = if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::DeleteBuffer { buf: buf.clone() },
                quiet,
            )? {
                serde_json::from_value(resp.data.unwrap_or_default()).map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode buffer dto")
                })?
            } else {
                store.delete_buffer(&buf, actor)?
            };
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(&deleted, store_meta(store, started, None));
                }
                OutputMode::Human => {
                    println!("moved buffer {} ({}) to recycle bin", deleted.name, deleted.id)
                }
            }
        }
    }
    Ok(0)
}

fn handle_trash(
    store: &mut LocalStore,
    action: TrashCommand,
    actor: &str,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> Result<i32, CoreError> {
    match action {
        TrashCommand::Ls => {
            let items = store.list_trash()?;
            let redacted = items.iter().filter(|i| i.is_locked).count();
            match mode {
                OutputMode::Json => emit_json(&items, store_meta(store, started, Some(redacted))),
                OutputMode::Jsonl => emit_jsonl(&items),
                OutputMode::Human => {
                    if items.is_empty() {
                        println!("(recycle bin is empty)");
                    } else {
                        for item in &items {
                            println!(
                                "{}  {:10} state={}  deleted_at_ms={}  {}",
                                item.id,
                                item.buffer_name,
                                item.shred_state,
                                item.deleted_at_ms,
                                item.preview.as_deref().unwrap_or("<redacted>").replace('\n', " ")
                            );
                        }
                    }
                }
            }
        }
        TrashCommand::Restore { id, dry_run } => {
            if dry_run {
                let trash = store.list_trash()?;
                let found = trash.into_iter().find(|t| t.id == id).ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::NotFound,
                        format!("block '{id}' is not in the recycle bin"),
                        "Run 'mynote trash ls --json' to list restorable blocks",
                    )
                })?;
                let preview = serde_json::json!({
                    "dry_run": true,
                    "block_id": found.id,
                    "buffer_id": found.buffer_id,
                    "shred_state": found.shred_state,
                });
                match mode {
                    OutputMode::Json | OutputMode::Jsonl => {
                        emit_json(preview, store_meta(store, started, None));
                    }
                    OutputMode::Human => {
                        println!(
                            "dry-run: would restore block {} to buffer {}",
                            found.id, found.buffer_name
                        );
                    }
                }
                return Ok(0);
            }
            if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::RestoreTrash { id: id.clone() },
                quiet,
            )? {
                if let Some(data) = resp.data {
                    let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode restore receipt")
                    })?;
                    emit_write_receipt(&receipt, store, mode, started);
                    return Ok(0);
                }
            }
            let receipt = store.restore_trash(&id, actor)?;
            emit_write_receipt(&receipt, store, mode, started);
        }
        TrashCommand::Empty | TrashCommand::Expedite { .. } | TrashCommand::Confirm { .. } => {
            unreachable!("handled before opening store")
        }
    }
    Ok(0)
}

fn handle_format_stdin(args: &FormatArgs, mode: OutputMode, started: Instant, quiet: bool) -> i32 {
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        let ce = CoreError::new(
            ErrorCode::InvalidArgument,
            format!("failed to read stdin: {e}"),
            "Pipe UTF-8 content into 'mynote format --lang <lang>'",
        );
        return emit_error(&ce, mode, empty_meta(started), quiet);
    }
    let lang = args.lang.as_deref().unwrap_or("json");
    match format_content(&input, lang, args.action.as_deref()) {
        Ok(formatted) => {
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(
                        serde_json::json!({ "lang": lang, "formatted": formatted }),
                        empty_meta(started),
                    );
                }
                OutputMode::Human => {
                    let mut out = io::stdout().lock();
                    let _ = out.write_all(formatted.as_bytes());
                    let _ = out.flush();
                }
            }
            0
        }
        Err(err) => emit_error(&err, mode, empty_meta(started), quiet),
    }
}

fn handle_format_block(
    store: &mut LocalStore,
    args: FormatArgs,
    actor: &str,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> Result<i32, CoreError> {
    let id = args.id.expect("id checked by caller");
    if args.expected_heads.is_empty() {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "missing required --expected-head <op_id> when formatting a block in-place",
            format!("Run 'mynote block get {id} --json' and pass --expected-head"),
        ));
    }
    let detail = store.get_block(&id)?;
    if detail.is_locked {
        return Err(CoreError::new(
            ErrorCode::BlockLocked,
            format!("block '{id}' is locked; unlocked Tier 2 blocks must be formatted in WASM UI"),
            "Never send locked blocks to CLI/external formatters",
        ));
    }
    if detail.has_conflict {
        return Err(CoreError::new(
            ErrorCode::ConflictPresent,
            format!("block '{id}' has {} concurrent versions", detail.versions.len()),
            format!(
                "Inspect with 'mynote block get {id} --json', then merge via 'mynote block update {id} --expected-head ...'"
            ),
        ));
    }
    let exp_set: BTreeSet<String> = args.expected_heads.iter().cloned().collect();
    let act_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
    if exp_set != act_set {
        return Err(CoreError::new(
            ErrorCode::HeadMismatch,
            format!("block {id} heads changed concurrently"),
            format!("Run 'mynote block get {id} --json' and retry"),
        )
        .with_details(serde_json::json!({
            "expected_heads": args.expected_heads,
            "actual_heads": detail.head_op_ids,
        })));
    }

    let current = detail.content.unwrap_or_default();
    let lang = args.lang.as_deref().unwrap_or(&detail.lang);
    let formatted = format_content(&current, lang, args.action.as_deref())?;
    if let Some(resp) = try_daemon_apply(
        store.data_dir(),
        ApplyMeta {
            actor: actor.to_string(),
            idempotency_key: None,
            allow_empty: true,
            force: false,
        },
        ApplyRequest::UpdateBlock {
            id: id.clone(),
            content: formatted.clone(),
            expected_heads: args.expected_heads.clone(),
        },
        quiet,
    )? {
        if let Some(data) = resp.data {
            let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode daemon receipt")
            })?;
            emit_write_receipt(&receipt, store, mode, started);
            return Ok(0);
        }
    }
    let receipt = store.update_block(&id, &formatted, &args.expected_heads, false, actor)?;
    emit_write_receipt(&receipt, store, mode, started);
    Ok(0)
}

fn handle_import(
    store: &mut LocalStore,
    source: ImportCommand,
    actor: &str,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> Result<i32, CoreError> {
    match source {
        ImportCommand::Heynote { path, buf, dry_run } => {
            let summary: mynote_store::store::ImportSummaryDto = if !dry_run {
                if let Some(resp) = try_daemon_apply(
                    store.data_dir(),
                    ApplyMeta {
                        actor: actor.to_string(),
                        idempotency_key: None,
                        allow_empty: true,
                        force: false,
                    },
                    ApplyRequest::ImportHeynote {
                        path: path.to_string_lossy().to_string(),
                        buf: buf.clone(),
                        dry_run,
                    },
                    quiet,
                )? {
                    serde_json::from_value(resp.data.unwrap_or_default()).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode import summary")
                    })?
                } else {
                    store.import_heynote(&path, buf.as_deref(), dry_run, actor)?
                }
            } else {
                store.import_heynote(&path, buf.as_deref(), dry_run, actor)?
            };
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(&summary, store_meta(store, started, None));
                }
                OutputMode::Human => {
                    println!(
                        "{}imported {} blocks across {} buffer(s)",
                        if summary.dry_run { "[dry-run] " } else { "" },
                        summary.blocks_imported,
                        summary.buffers_imported
                    );
                    if !summary.duplicate_sources.is_empty() {
                        eprintln!(
                            "warning: previously imported source file(s): {}",
                            summary.duplicate_sources.join(", ")
                        );
                    }
                }
            }
            Ok(0)
        }
    }
}

fn handle_sync(
    store: &mut LocalStore,
    action: SyncCommand,
    mode: OutputMode,
    started: Instant,
) -> Result<i32, CoreError> {
    match action {
        SyncCommand::Status => {
            let status = store.sync_status()?;
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(&status, store_meta(store, started, None));
                }
                OutputMode::Human => {
                    println!(
                        "sync_state={}  pending_ops={}  last_seq={}  trash={}  key_self_check_ok={}",
                        status.sync_state,
                        status.pending_ops,
                        status.last_seq,
                        status.trash.count,
                        status.key_self_check.ok
                    );
                }
            }
            Ok(0)
        }
        SyncCommand::Push | SyncCommand::Pull => {
            // If Daemon is running, trigger Single-Flight sync through Daemon so SQLite keeps one writer.
            if let Some(resp) = try_send_uds(
                store.data_dir(),
                &UdsRequest::SyncNow { wait: true },
                Duration::from_secs(30),
            )? {
                if !resp.ok {
                    return Err(resp.into_core_error());
                }
                let data = serde_json::json!({
                    "head_seq": resp.head_seq.unwrap_or(0),
                    "sync_state": resp.sync_state.unwrap_or_else(|| "idle".to_string()),
                    "pending_ops": resp.pending_ops.unwrap_or(0),
                });
                match mode {
                    OutputMode::Json | OutputMode::Jsonl => {
                        emit_json(data, store_meta(store, started, None));
                    }
                    OutputMode::Human => println!(
                        "sync ok (via daemon): head_seq={}  pending_ops={}",
                        resp.head_seq.unwrap_or(0),
                        resp.pending_ops.unwrap_or(0)
                    ),
                }
                return Ok(0);
            }

            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "sync relay is offline or not configured on this device",
                    "Local writes are safely persisted; configure Cloudflare relay via 'mynote device bootstrap' or retry once online",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let read_only = creds.scope == "read" || matches!(action, SyncCommand::Pull);
            let report = run_async(client.run_sync_round(store, read_only))?;
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(&report, store_meta(store, started, None));
                }
                OutputMode::Human => println!(
                    "sync ok: head_seq={}  pulled={}  pushed={}  keys_synced={}",
                    report.head_seq, report.pulled_ops, report.pushed_ops, report.keys_synced
                ),
            }
            Ok(0)
        }
    }
}

fn handle_vault(
    _action: &VaultCommand,
    non_interactive: bool,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> i32 {
    if let Err(err) = require_tty(non_interactive, "vault") {
        return emit_error(&err, mode, empty_meta(started), quiet);
    }
    let err = CoreError::new(
        ErrorCode::InvalidArgument,
        "Tier 2 Vault commands ship in Milestone M2",
        "M1 provides full Tier 1 E2EE sync & unified 24-word recovery",
    );
    emit_error(&err, mode, empty_meta(started), quiet)
}

fn handle_device(
    store: &mut LocalStore,
    action: DeviceCommand,
    non_interactive: bool,
    mode: OutputMode,
    started: Instant,
) -> Result<i32, CoreError> {
    match action {
        DeviceCommand::Bootstrap { url, revoke_existing } => {
            require_tty(non_interactive, "device bootstrap")?;
            let token = match std::env::var("MYNOTE_BOOTSTRAP_TOKEN") {
                Ok(v) if !v.trim().is_empty() => v,
                _ => read_tty_line("Enter Cloudflare BOOTSTRAP_TOKEN: ")?,
            };
            if token.trim().is_empty() {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "BOOTSTRAP_TOKEN cannot be empty",
                    "Provide the secret set via 'wrangler secret put BOOTSTRAP_TOKEN'",
                ));
            }
            let dev_name = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_else(|_| "desktop".to_string());
            let receipt = run_async(RelayClient::bootstrap_device(
                &url,
                &token,
                store,
                &dev_name,
                revoke_existing,
            ))?;
            // Immediately run initial sync round to publish local keys/ops or pull remote history
            if let Ok(Some(creds)) = store.load_credentials() {
                if let Ok(client) = RelayClient::from_credentials(&creds) {
                    let _ = run_async(client.run_sync_round(store, false));
                }
            }
            let _ = try_send_uds(
                store.data_dir(),
                &UdsRequest::Poke { fast_flush: true },
                Duration::from_secs(2),
            );
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(&receipt, store_meta(store, started, None));
                }
                OutputMode::Human => println!(
                    "bootstrapped device {} (scope={}, epoch={}) -> {}",
                    receipt.device_id, receipt.scope, receipt.epoch, receipt.sync_url
                ),
            }
            Ok(0)
        }
        DeviceCommand::Add { name, scope } => {
            require_tty(non_interactive, "device add")?;
            if mode != OutputMode::Human {
                return Err(CoreError::new(
                    ErrorCode::InteractionRequired,
                    "pairing codes contain K_pair and are never emitted into --json/--jsonl output",
                    "Run 'mynote device add' in an interactive terminal without --json",
                ));
            }
            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "sync relay is not configured on this device",
                    "Run 'mynote device bootstrap --url <https://...>' first",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let smks = store.current_smks_for_pairing();
            let ticket = run_async(client.create_pairing_ticket(&name, &scope, smks))?;
            println!(
                "One-time pairing ticket created for device {} (scope={}, valid 10 min):",
                ticket.device_id, ticket.scope
            );
            println!("\n{}\n", render_terminal_qr(&ticket.pairing_code));
            println!("Pairing code:\n  {}\n", ticket.pairing_code);
            println!("Run 'mynote device claim' on the target device and paste the code above.");
            Ok(0)
        }
        DeviceCommand::Refresh { device_id } => {
            require_tty(non_interactive, "device refresh")?;
            if mode != OutputMode::Human {
                return Err(CoreError::new(
                    ErrorCode::InteractionRequired,
                    "refresh pairing codes contain K_pair and are never emitted into --json/--jsonl output",
                    "Run 'mynote device refresh <device_id>' in an interactive terminal without --json",
                ));
            }
            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "sync relay is not configured on this device",
                    "Run 'mynote device bootstrap --url <https://...>' first",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let smks = store.current_smks_for_pairing();
            let ticket = run_async(client.create_refresh_ticket(&device_id, smks))?;
            println!(
                "One-time SMK refresh ticket created for device {} (valid 10 min):",
                ticket.device_id
            );
            println!("\n{}\n", render_terminal_qr(&ticket.pairing_code));
            println!("Refresh code:\n  {}\n", ticket.pairing_code);
            println!(
                "Run 'mynote device claim' on device {} and paste the code above.",
                ticket.device_id
            );
            Ok(0)
        }
        DeviceCommand::Claim => unreachable!("handled prior to opening store"),
        DeviceCommand::Ls => {
            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "sync relay is offline or not configured",
                    "Run 'mynote device bootstrap --url <https://...>' once Cloudflare relay is deployed",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let devices = run_async(client.list_devices())?;
            match mode {
                OutputMode::Json => emit_json(&devices, store_meta(store, started, None)),
                OutputMode::Jsonl => emit_jsonl(&devices),
                OutputMode::Human => {
                    for d in &devices {
                        let st = if d.revoked_at_ms.is_some() {
                            "REVOKED"
                        } else {
                            "active"
                        };
                        println!(
                            "{}  {:14} {:10} {:7} last_seq={}",
                            d.device_id, d.device_name, d.scope, st, d.last_pulled_seq
                        );
                    }
                }
            }
            Ok(0)
        }
        DeviceCommand::Revoke { device_id } => {
            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "sync relay is offline or not configured",
                    "Run 'mynote device bootstrap --url <https://...>' first",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let revoked_at_ms = run_async(client.revoke_device(&device_id))?;
            let data = serde_json::json!({
                "device_id": device_id,
                "revoked_at_ms": revoked_at_ms,
                "hint": "Run 'mynote keyring rotate' to prevent the revoked device from decrypting future notes",
            });
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(data, store_meta(store, started, None));
                }
                OutputMode::Human => {
                    println!("revoked device {device_id} at {revoked_at_ms}");
                    println!("hint: run 'mynote keyring rotate' to rotate SMK for future notes");
                }
            }
            Ok(0)
        }
    }
}

fn handle_keyring(
    store: &mut LocalStore,
    action: KeyringCommand,
    non_interactive: bool,
    mode: OutputMode,
    started: Instant,
) -> Result<i32, CoreError> {
    match action {
        KeyringCommand::Rotate => {
            require_tty(non_interactive, "keyring rotate")?;
            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "keyring rotate requires cloud sync connectivity to publish the new SMK generation",
                    "Configure cloud sync via 'mynote device bootstrap' and re-run 'mynote keyring rotate'",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let (new_gen, new_kid) = store.rotate_smk()?;
            // Push updated block_keys + RecoveryKeyringV1 immediately to the relay
            let report = run_async(client.run_sync_round(store, false))?;
            let _ = try_send_uds(
                store.data_dir(),
                &UdsRequest::Poke { fast_flush: true },
                Duration::from_secs(2),
            );
            let data = serde_json::json!({
                "ok": true,
                "active_smk_kid": new_kid.to_string(),
                "keyring_gen": new_gen,
                "keys_synced": report.keys_synced,
                "hint": "Run 'mynote recovery drill' to verify your 24-word recovery bundle unseals the new SMK generation",
            });
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(data, store_meta(store, started, None)),
                OutputMode::Human => {
                    println!(
                        "rotated SMK to {new_kid} (keyring_gen={new_gen}, keys_synced={})",
                        report.keys_synced
                    );
                    println!("hint: run 'mynote recovery drill' to verify offline recovery; run 'mynote device refresh <id>' or 'mynote keyring unlock' on other trusted devices");
                }
            }
            Ok(0)
        }
        KeyringCommand::Unlock => {
            require_tty(non_interactive, "keyring unlock")?;
            let words = read_tty_line("Enter 24-word recovery bundle: ")?;
            let gens = store.unlock_keyring_with_words(&words)?;
            if let Ok(Some(creds)) = store.load_credentials() {
                if let Ok(client) = RelayClient::from_credentials(&creds) {
                    let _ = run_async(client.run_sync_round(store, creds.scope == "read"));
                }
            }
            let _ = try_send_uds(
                store.data_dir(),
                &UdsRequest::Poke { fast_flush: true },
                Duration::from_secs(2),
            );
            let data = serde_json::json!({ "ok": true, "unsealed_generations": gens });
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(data, store_meta(store, started, None)),
                OutputMode::Human => println!("unsealed {gens} SMK generation(s) into local store"),
            }
            Ok(0)
        }
    }
}

fn handle_recovery(
    store: &LocalStore,
    action: RecoveryCommand,
    non_interactive: bool,
    mode: OutputMode,
    started: Instant,
) -> Result<i32, CoreError> {
    match action {
        RecoveryCommand::Show => {
            require_tty(non_interactive, "recovery show")?;
            // Recovery words are NEVER written into --json output (`docs/interface-contracts.md` §2.3)
            if mode != OutputMode::Human {
                return Err(CoreError::new(
                    ErrorCode::InteractionRequired,
                    "recovery bundle words are never emitted into --json/--jsonl output",
                    "Run 'mynote recovery show' in an interactive terminal without --json",
                ));
            }
            if let Some(words) = &store.initial_recovery_words {
                println!("24-word recovery bundle (record offline now):\n  {words}");
                Ok(0)
            } else {
                Err(CoreError::new(
                    ErrorCode::NotFound,
                    "recovery bundle is only shown during initial bootstrap session and is not stored on disk",
                    "Verify your recorded bundle with 'mynote recovery drill'",
                ))
            }
        }
        RecoveryCommand::Drill => {
            require_tty(non_interactive, "recovery drill")?;
            let words = read_tty_line("Enter 24-word recovery bundle for offline drill: ")?;
            let res = store.recovery_drill(&words)?;
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(&res, store_meta(store, started, None)),
                OutputMode::Human => println!(
                    "recovery drill OK: unsealed {} SMK generation(s) (includes_vkek={})",
                    res.keyring_generations, res.includes_vkek
                ),
            }
            Ok(0)
        }
    }
}

fn handle_restore(
    args: &RestoreArgs,
    non_interactive: bool,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> i32 {
    if let Err(err) = require_tty(non_interactive, "restore --from-archive") {
        return emit_error(&err, mode, empty_meta(started), quiet);
    }
    let words = match read_tty_line("Enter 24-word recovery bundle: ") {
        Ok(w) => w,
        Err(err) => return emit_error(&err, mode, empty_meta(started), quiet),
    };
    let _ = &args.key_snapshot;
    match LocalStore::restore_from_archive_dir(&args.from_archive, &words, &args.to, args.dry_run) {
        Ok(summary) => {
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(&summary, empty_meta(started)),
                OutputMode::Human => println!(
                    "restored {} block(s) ({} shredded skipped) from {} archive segment(s) into {}",
                    summary.restored_blocks,
                    summary.skipped_shredded,
                    summary.archive_segments,
                    summary.data_dir
                ),
            }
            0
        }
        Err(err) => emit_error(&err, mode, empty_meta(started), quiet),
    }
}

fn emit_write_receipt(receipt: &WriteReceipt, store: &LocalStore, mode: OutputMode, started: Instant) {
    match mode {
        OutputMode::Json | OutputMode::Jsonl => emit_json(receipt, store_meta(store, started, None)),
        OutputMode::Human => println!(
            "block={}  op={}  buffer={}{}",
            receipt.block_id,
            receipt.op_id,
            receipt.buffer_id,
            if receipt.idempotent_replay == Some(true) {
                "  (idempotent replay)"
            } else {
                ""
            }
        ),
    }
}

fn emit_delete_receipt(receipt: &DeleteReceipt, store: &LocalStore, mode: OutputMode, started: Instant) {
    match mode {
        OutputMode::Json | OutputMode::Jsonl => emit_json(receipt, store_meta(store, started, None)),
        OutputMode::Human => println!(
            "moved block {} to recycle bin (shred_state={}; restore via 'mynote trash restore {}')",
            receipt.block_id, receipt.shred_state, receipt.block_id
        ),
    }
}
