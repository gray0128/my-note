//! CLI command execution engine implementing `docs/interface-contracts.md` §1 & §2.

use crate::cli::{
    build_cli, AddArgs, BlockCommand, BufCommand, Cli, Commands, DeviceCommand, FormatArgs, ImportCommand,
    KeyringCommand, LsArgs, RecoveryCommand, RestoreArgs, SearchArgs, SyncCommand, TrashCommand,
    VaultCommand,
};
use crate::formatters::format_content;
use crate::help::render_topic;
use crate::output::{emit_error, emit_json, emit_jsonl, CliMeta, OutputMode};
use clap::Parser;
use mynote_core::error::{CoreError, ErrorCode};
use mynote_store::store::{DeleteReceipt, LocalStore, WriteReceipt};
use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

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
        Commands::Open => {
            let msg = serde_json::json!({
                "status": "daemon_not_running",
                "hint": "Start the local mynote daemon to open http://localhost:<port> in your browser"
            });
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(msg, empty_meta(started)),
                OutputMode::Human => {
                    println!("Desktop UI daemon is not running yet (M1-7/M1-8).");
                }
            }
            return 0;
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
        Commands::Add(args) => handle_add(&mut store, args, &actor, mode, started),
        Commands::Ls(args) => handle_ls(&store, args, mode, started),
        Commands::Search(args) => handle_search(&store, args, mode, started),
        Commands::Block { action } => {
            handle_block(&mut store, action, &actor, non_interactive, mode, started, quiet)
        }
        Commands::Buf { action } => handle_buf(&mut store, action, &actor, mode, started),
        Commands::Trash { action } => handle_trash(&mut store, action, &actor, mode, started),
        Commands::Format(args) => handle_format_block(&mut store, args, &actor, mode, started),
        Commands::Import { source } => handle_import(&mut store, source, &actor, mode, started),
        Commands::Sync { action } => handle_sync(&store, action, mode, started),
        Commands::Device { action } => handle_device(action, non_interactive),
        Commands::Keyring { action } => handle_keyring(&mut store, action, non_interactive, mode, started),
        Commands::Recovery { action } => handle_recovery(&store, action, non_interactive, mode, started),
        Commands::Help { .. } | Commands::Restore(_) | Commands::Vault { .. } | Commands::Open => {
            unreachable!("handled prior to opening store")
        }
    };

    match res {
        Ok(code) => code,
        Err(err) => emit_error(&err, mode, store_meta(&store, started, None), quiet),
    }
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

            let content = if let Some(keep_op) = keep {
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
                    .find(|v| v.op_id == keep_op)
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
                (None, None) => {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "specify either --to-op <op_id> or --undo-actor <actor>",
                        format!("Run 'mynote block history {id} --json' to list historical ops"),
                    ));
                }
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
            let buf = store.create_buffer(&name, after.as_deref(), actor)?;
            match mode {
                OutputMode::Json | OutputMode::Jsonl => emit_json(&buf, store_meta(store, started, None)),
                OutputMode::Human => println!("created buffer {} ({})", buf.name, buf.id),
            }
        }
        BufCommand::Rename { buf, new_name } => {
            let updated = store.rename_buffer(&buf, &new_name, actor)?;
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(&updated, store_meta(store, started, None));
                }
                OutputMode::Human => println!("renamed buffer {} -> {}", updated.id, updated.name),
            }
        }
        BufCommand::Delete { buf } => {
            let deleted = store.delete_buffer(&buf, actor)?;
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
) -> Result<i32, CoreError> {
    match source {
        ImportCommand::Heynote { path, buf, dry_run } => {
            let summary = store.import_heynote(&path, buf.as_deref(), dry_run, actor)?;
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
    store: &LocalStore,
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
        SyncCommand::Push | SyncCommand::Pull => Err(CoreError::new(
            ErrorCode::SyncOffline,
            "sync relay is offline or not configured on this device",
            "Local writes are safely persisted; configure Cloudflare relay via 'mynote device bootstrap' or retry once online",
        )),
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

fn handle_device(action: DeviceCommand, non_interactive: bool) -> Result<i32, CoreError> {
    match action {
        DeviceCommand::Bootstrap { .. }
        | DeviceCommand::Add { .. }
        | DeviceCommand::Refresh { .. }
        | DeviceCommand::Claim => {
            require_tty(non_interactive, "device pairing/bootstrap")?;
            Err(CoreError::new(
                ErrorCode::SyncOffline,
                "cannot reach Cloudflare sync relay while offline",
                "Check network connectivity and Cloudflare Worker URL, then retry",
            ))
        }
        DeviceCommand::Ls | DeviceCommand::Revoke { .. } => Err(CoreError::new(
            ErrorCode::SyncOffline,
            "sync relay is offline or not configured",
            "Run 'mynote device bootstrap --url <https://...>' once Cloudflare relay is deployed",
        )),
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
            Err(CoreError::new(
                ErrorCode::SyncOffline,
                "keyring rotate requires cloud sync connectivity to publish the new SMK generation",
                "Reconnect to the Cloudflare sync relay and re-run 'mynote keyring rotate'",
            ))
        }
        KeyringCommand::Unlock => {
            require_tty(non_interactive, "keyring unlock")?;
            let words = read_tty_line("Enter 24-word recovery bundle: ")?;
            let gens = store.unlock_keyring_with_words(&words)?;
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
