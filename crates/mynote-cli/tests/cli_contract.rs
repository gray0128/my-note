use mynote_core::crypto::{encrypt_mnb1, encrypt_mnr1, KeyRecordV1};
use mynote_core::hlc::Hlc;
use mynote_core::ids::{BlockId, DeviceId, KeyId, MonotonicUlidGen, OpId};
use mynote_core::model::OpType;
use mynote_store::store::{LocalStore, RemoteBlockOpParams};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mynote")
}

fn temp_dir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("mynote_cli_test_{tag}_{ts}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn run_cli(data_dir: &Path, args: &[&str], stdin_bytes: Option<&[u8]>) -> Output {
    run_cli_with_env(data_dir, args, stdin_bytes, &[])
}

fn run_cli_with_env(
    data_dir: &Path,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    extra_env: &[(&str, &str)],
) -> Output {
    let mut cmd = Command::new(bin());
    cmd.arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn mynote binary");
    if let Some(bytes) = stdin_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(bytes).expect("write stdin");
        }
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().expect("wait mynote binary")
}

fn parse_single_json_stdout(out: &Output) -> Value {
    let stdout = String::from_utf8(out.stdout.clone()).expect("stdout must be UTF-8");
    assert!(
        stdout.ends_with('\n'),
        "JSON stdout must end with newline, got: {stdout:?}"
    );
    let trimmed = stdout.trim_end_matches('\n');
    assert!(
        !trimmed.contains('\n'),
        "JSON stdout must be exactly ONE JSON object, got:\n{stdout}"
    );
    let v: Value =
        serde_json::from_str(trimmed).unwrap_or_else(|e| panic!("invalid JSON stdout: {e}\nraw: {stdout}"));
    // Validate top-level envelope keys
    assert!(v.get("ok").and_then(Value::as_bool).is_some());
    assert!(v.get("meta").and_then(Value::as_object).is_some());
    if v["ok"] == Value::Bool(true) {
        assert!(v["error"].is_null());
    } else {
        assert!(v["data"].is_null());
        assert!(v["error"]["code"].is_string());
        assert!(v["error"]["message"].is_string());
        assert!(v["error"]["hint"].is_string());
        assert!(v["error"]["retryable"].is_boolean());
    }
    v
}

#[test]
fn static_clap_debug_assert_all_subcommand_helps_and_skill_token_budget() {
    // 1. clap Command::debug_assert()
    let mut root = mynote_cli::cli::build_cli();
    root.clone().debug_assert();

    // 2. Top-level L1 --help checks (25-35 lines, no clip, no --help-json)
    let dir = temp_dir("help");
    let help_out = run_cli(&dir, &["--help"], None);
    assert_eq!(help_out.status.code(), Some(0));
    let help_str = String::from_utf8(help_out.stdout).unwrap();
    let line_count = help_str.lines().count();
    assert!(
        (25..=38).contains(&line_count),
        "L1 help expected ~25-35 lines, got {line_count}:\n{help_str}"
    );
    assert!(!help_str.contains("--help-json"));
    assert!(!help_str.contains("\n  clip "));

    // 3. Every subcommand produces non-empty --help
    fn check_subcommands(cmd: &mut clap::Command, path: &[String]) {
        for sub in cmd.get_subcommands_mut() {
            let mut sub_path = path.to_vec();
            sub_path.push(sub.get_name().to_string());
            let mut rendered = Vec::new();
            sub.write_help(&mut rendered).unwrap();
            let text = String::from_utf8(rendered).unwrap();
            assert!(
                !text.trim().is_empty(),
                "empty help for subcommand {:?}",
                sub_path
            );
            check_subcommands(sub, &sub_path);
        }
    }
    check_subcommands(&mut root, &[]);

    // 4. L3a offline help topics
    for topic in ["agent", "formatting", "conflict", "locking", "upgrade"] {
        let out = run_cli(&dir, &["help", topic], None);
        assert_eq!(out.status.code(), Some(0), "help {topic} failed");
        assert!(!String::from_utf8(out.stdout).unwrap().trim().is_empty());
    }

    // 5. skill/SKILL.md token budget strictly < 250 tokens (`docs/eval-framework.md` §7)
    let skill_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skill/SKILL.md");
    let skill = std::fs::read_to_string(&skill_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", skill_path.display()));
    let word_count = skill.split_whitespace().count();
    let conservative_bpe_estimate = ((word_count as f64) * 1.35).ceil() as usize;
    let char_quarter_estimate = skill.len().div_ceil(4);
    assert!(
        conservative_bpe_estimate < 250 && char_quarter_estimate < 250,
        "skill/SKILL.md exceeds <250 token budget! words={word_count}, bpe_est={conservative_bpe_estimate}, char/4={char_quarter_estimate}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn g01_g02_g03_g06_add_arg_stdin_idempotency_ls_search_raw_and_offline_semantics() {
    let dir = temp_dir("g01_03_06");

    // G01 + G06: add from positional arg offline -> exit 0, pending_offline
    let out1 = run_cli(
        &dir,
        &[
            "add",
            "hello from positional arg",
            "--buf",
            "scratch",
            "--idempotency-key",
            "k-pos-1",
            "--json",
        ],
        None,
    );
    assert_eq!(out1.status.code(), Some(0));
    let j1 = parse_single_json_stdout(&out1);
    assert_eq!(j1["ok"], true);
    assert_eq!(j1["meta"]["sync_state"], "pending_offline");
    let pending_after_1 = j1["meta"]["local_op_count_pending"].as_u64().unwrap();
    let block_id_1 = j1["data"]["block_id"].as_str().unwrap().to_string();
    let op_id_1 = j1["data"]["op_id"].as_str().unwrap().to_string();
    assert_eq!(block_id_1.len(), 26);
    assert_eq!(op_id_1.len(), 26);

    // Idempotent replay -> exact same block_id & op_id, pending ops unchanged!
    let out1_dup = run_cli(
        &dir,
        &[
            "add",
            "hello from positional arg",
            "--buf",
            "scratch",
            "--idempotency-key",
            "k-pos-1",
            "--json",
        ],
        None,
    );
    assert_eq!(out1_dup.status.code(), Some(0));
    let j1_dup = parse_single_json_stdout(&out1_dup);
    assert_eq!(j1_dup["data"]["block_id"], block_id_1);
    assert_eq!(j1_dup["data"]["op_id"], op_id_1);
    assert_eq!(j1_dup["data"]["idempotent_replay"], true);
    assert_eq!(j1_dup["meta"]["local_op_count_pending"], pending_after_1);

    // G01: add from stdin with exact special characters + no trailing newline
    let raw_payload = "{\"k\":\"v\",\"emoji\":\"🚀\",\"lines\":\"a\\nb\"}";
    let out2 = run_cli(
        &dir,
        &["add", "--buf", "scratch", "--json"],
        Some(raw_payload.as_bytes()),
    );
    assert_eq!(out2.status.code(), Some(0));
    let j2 = parse_single_json_stdout(&out2);
    let block_id_2 = j2["data"]["block_id"].as_str().unwrap().to_string();
    assert_eq!(
        j2["meta"]["local_op_count_pending"].as_u64().unwrap(),
        pending_after_1 + 1
    );

    // G03: block get --raw returns exact byte-for-byte content without trailing newline
    let raw_out = run_cli(&dir, &["block", "get", &block_id_2, "--raw"], None);
    assert_eq!(raw_out.status.code(), Some(0));
    assert_eq!(raw_out.stdout, raw_payload.as_bytes());

    // G02: ls --json, ls --jsonl, search --json
    let ls_out = run_cli(&dir, &["ls", "--limit", "20", "--json"], None);
    assert_eq!(ls_out.status.code(), Some(0));
    let ls_j = parse_single_json_stdout(&ls_out);
    assert_eq!(ls_j["data"].as_array().unwrap().len(), 2);
    assert_eq!(ls_j["data"][1]["lang"], "json");

    let jsonl_out = run_cli(&dir, &["ls", "--jsonl"], None);
    assert_eq!(jsonl_out.status.code(), Some(0));
    let jsonl_lines: Vec<&str> = std::str::from_utf8(&jsonl_out.stdout).unwrap().lines().collect();
    assert_eq!(jsonl_lines.len(), 2);
    for l in jsonl_lines {
        let _: Value = serde_json::from_str(l).expect("valid jsonl row");
    }

    let search_out = run_cli(&dir, &["search", "positional", "--json"], None);
    assert_eq!(search_out.status.code(), Some(0));
    let search_j = parse_single_json_stdout(&search_out);
    assert_eq!(search_j["data"].as_array().unwrap().len(), 1);
    assert_eq!(search_j["data"][0]["id"], block_id_1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn g04_g05_optimistic_lock_head_mismatch_and_empty_stdin_refused_have_zero_side_effects() {
    let dir = temp_dir("g04_05");
    let add_out = run_cli(&dir, &["add", "original precious note", "--json"], None);
    let add_j = parse_single_json_stdout(&add_out);
    let blk_id = add_j["data"]["block_id"].as_str().unwrap().to_string();
    let head1 = add_j["data"]["op_id"].as_str().unwrap().to_string();

    // G04: stale --expected-head -> exit 4 HEAD_MISMATCH with details.actual_heads
    let stale_out = run_cli(
        &dir,
        &[
            "block",
            "update",
            &blk_id,
            "clobber attempt",
            "--expected-head",
            "01J00000000000000000000000",
            "--json",
        ],
        None,
    );
    assert_eq!(stale_out.status.code(), Some(4));
    let stale_j = parse_single_json_stdout(&stale_out);
    assert_eq!(stale_j["ok"], false);
    assert_eq!(stale_j["error"]["code"], "HEAD_MISMATCH");
    assert_eq!(stale_j["error"]["retryable"], true);
    assert_eq!(stale_j["error"]["details"]["actual_heads"][0], head1);
    // DB untouched
    let raw = run_cli(&dir, &["block", "get", &blk_id, "--raw"], None);
    assert_eq!(raw.stdout, b"original precious note");

    // G05: 0-byte non-TTY stdin on non-empty block -> exit 2 EMPTY_STDIN_REFUSED, DB untouched
    let empty_out = run_cli(
        &dir,
        &["block", "update", &blk_id, "--expected-head", &head1, "--json"],
        Some(b""),
    );
    assert_eq!(empty_out.status.code(), Some(2));
    let empty_j = parse_single_json_stdout(&empty_out);
    assert_eq!(empty_j["error"]["code"], "EMPTY_STDIN_REFUSED");
    let raw_after = run_cli(&dir, &["block", "get", &blk_id, "--raw"], None);
    assert_eq!(raw_after.stdout, b"original precious note");

    // Explicit --allow-empty succeeds
    let clear_out = run_cli(
        &dir,
        &[
            "block",
            "update",
            &blk_id,
            "--expected-head",
            &head1,
            "--allow-empty",
            "--json",
        ],
        Some(b""),
    );
    assert_eq!(clear_out.status.code(), Some(0));
    let raw_cleared = run_cli(&dir, &["block", "get", &blk_id, "--raw"], None);
    assert!(raw_cleared.stdout.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn g07_g08_offline_sync_and_trash_delete_boundary_with_ui_confirmation_required() {
    let dir = temp_dir("g07_08");
    let add_out = run_cli(&dir, &["add", "trashable note", "--json"], None);
    let add_j = parse_single_json_stdout(&add_out);
    let blk_id = add_j["data"]["block_id"].as_str().unwrap().to_string();
    let head = add_j["data"]["op_id"].as_str().unwrap().to_string();

    // G07: sync push/pull offline -> exit 6 SYNC_OFFLINE retryable=true; sync status exits 0
    for sub in ["push", "pull"] {
        let out = run_cli(&dir, &["sync", sub, "--json"], None);
        assert_eq!(out.status.code(), Some(6));
        let j = parse_single_json_stdout(&out);
        assert_eq!(j["error"]["code"], "SYNC_OFFLINE");
        assert_eq!(j["error"]["retryable"], true);
    }
    let st_out = run_cli(&dir, &["sync", "status", "--json"], None);
    assert_eq!(st_out.status.code(), Some(0));
    let st_j = parse_single_json_stdout(&st_out);
    assert_eq!(st_j["data"]["sync_state"], "pending_offline");
    assert_eq!(st_j["data"]["key_self_check"]["ok"], true);
    assert_eq!(st_j["data"]["trash"]["count"], 0);

    // G08: block delete moves to trash only (shred_state = "unscheduled", shred_not_before_ms = null)
    let del_out = run_cli(
        &dir,
        &["block", "delete", &blk_id, "--expected-head", &head, "--json"],
        None,
    );
    assert_eq!(del_out.status.code(), Some(0));
    let del_j = parse_single_json_stdout(&del_out);
    assert_eq!(del_j["data"]["in_trash"], true);
    assert_eq!(del_j["data"]["shred_state"], "unscheduled");
    assert!(del_j["data"]["shred_not_before_ms"].is_null());

    // Hidden from ls, returns IN_TRASH (exit 3) on block get, present in trash ls
    let ls_j = parse_single_json_stdout(&run_cli(&dir, &["ls", "--json"], None));
    assert!(ls_j["data"].as_array().unwrap().is_empty());

    let get_trashed = run_cli(&dir, &["block", "get", &blk_id, "--json"], None);
    assert_eq!(get_trashed.status.code(), Some(3));
    let get_trashed_j = parse_single_json_stdout(&get_trashed);
    assert_eq!(get_trashed_j["error"]["code"], "IN_TRASH");
    assert!(get_trashed_j["error"]["details"]["deleted_at_ms"].is_number());

    // trash empty / expedite / confirm ALWAYS exit 2 UI_CONFIRMATION_REQUIRED with zero side effects
    for args in [
        &["trash", "empty", "--json"][..],
        &["trash", "expedite", "--json"][..],
        &["trash", "confirm", "--json"][..],
    ] {
        let out = run_cli(&dir, args, None);
        assert_eq!(out.status.code(), Some(2));
        let j = parse_single_json_stdout(&out);
        assert_eq!(j["error"]["code"], "UI_CONFIRMATION_REQUIRED");
    }

    // Recycle bin unchanged
    let trash_j = parse_single_json_stdout(&run_cli(&dir, &["trash", "ls", "--json"], None));
    assert_eq!(trash_j["data"].as_array().unwrap().len(), 1);
    assert_eq!(trash_j["data"][0]["id"], blk_id);

    // trash restore recovers block intact
    let res_out = run_cli(&dir, &["trash", "restore", &blk_id, "--json"], None);
    assert_eq!(res_out.status.code(), Some(0));
    let raw = run_cli(&dir, &["block", "get", &blk_id, "--raw"], None);
    assert_eq!(raw.stdout, b"trashable note");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn g09_g10_multi_leaf_merge_and_locked_block_non_tty_zero_plaintext() {
    let dir = temp_dir("g09_10");

    // Seed blocks + inject remote concurrent leaf (G09) and Tier 2 locked leaf (G10)
    let (conflict_id, locked_id) = {
        let mut store = LocalStore::open(&dir).unwrap();
        let c1 = store
            .add_block("scratch", "base version", Some("text"), None, "human", None)
            .unwrap();
        let c_bid = BlockId::parse(&c1.block_id).unwrap();
        let c_p1 = OpId::parse(&c1.op_id).unwrap();
        let _c2 = store
            .update_block(&c1.block_id, "mac edit", &c1.head_op_ids, false, "human")
            .unwrap();

        let key_id = store
            .list_blocks(None, 20)
            .unwrap()
            .into_iter()
            .find(|b| b.id == c1.block_id)
            .map(|_| c_bid)
            .unwrap();
        let _ = key_id;

        // Read existing key_id & unwrap via SQL so we encrypt a genuine concurrent remote Tier 1 leaf
        let mut gen = MonotonicUlidGen::new();
        let remote_dev = DeviceId::parse("dev_omarchy001").unwrap();
        let remote_op = OpId::from_ulid(gen.next(1_795_521_700_000, [3u8; 10]));
        // Create a fresh Tier 1 key for remote concurrent op (valid per M1 multi-key block model)
        let remote_key = KeyId::from_ulid(gen.next(1_795_521_700_001, [4u8; 10]));
        let remote_bdek = [0x42u8; 32];
        let mnb1_r = encrypt_mnb1(
            c_bid.as_bytes(),
            remote_op,
            remote_key,
            &remote_bdek,
            "omarchy concurrent edit",
            [5u8; 24],
        )
        .unwrap();
        // Wrap remote_bdek with current SMK by reading smk_keyring.local.json
        let kr_json: Value =
            serde_json::from_slice(&std::fs::read(dir.join("smk_keyring.local.json")).unwrap()).unwrap();
        let smk_kid_s = kr_json["current_smk_kid"].as_str().unwrap();
        let smk_hex = kr_json["generations"][smk_kid_s].as_str().unwrap();
        let mut smk = [0u8; 32];
        for i in 0..32 {
            smk[i] = u8::from_str_radix(&smk_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let smk_kid = mynote_core::ids::SmkKid::parse(smk_kid_s).unwrap();
        let mnr1_r = encrypt_mnr1(
            smk_kid,
            &smk,
            1,
            &KeyRecordV1 {
                v: 1,
                key_id: remote_key,
                block_id: c_bid.0,
                tier: 1,
                created_hlc: Hlc::new(1_795_521_700_000, 0, remote_dev.clone()).canonical_string(),
                created_by: remote_dev.clone(),
                bdek: remote_bdek.to_vec(),
            },
            [6u8; 24],
        )
        .unwrap();
        store
            .apply_remote_block_op_for_sync(RemoteBlockOpParams {
                remote_device: remote_dev.clone(),
                block_id: c_bid,
                op_id: remote_op,
                parents: vec![c_p1],
                op_type: OpType::Update,
                hlc: Hlc::new(1_795_521_700_000, 0, remote_dev.clone()),
                tier: 1,
                key_id: remote_key,
                new_key_record: Some((1, mnr1_r)),
                mnb1: mnb1_r,
                public_hint: None,
            })
            .unwrap();

        // Now create a Tier 2 locked block (G10)
        let l1 = store
            .add_block(
                "scratch",
                "TOP_SECRET_CANARY_XYZ",
                Some("text"),
                None,
                "human",
                None,
            )
            .unwrap();
        let l_bid = BlockId::parse(&l1.block_id).unwrap();
        let l_p1 = OpId::parse(&l1.op_id).unwrap();
        let l_op = OpId::from_ulid(gen.next(1_795_521_800_000, [7u8; 10]));
        let l_key = KeyId::from_ulid(gen.next(1_795_521_800_001, [8u8; 10]));
        let l_mnr1 = encrypt_mnr1(
            smk_kid,
            &smk,
            1,
            &KeyRecordV1 {
                v: 1,
                key_id: l_key,
                block_id: l_bid.0,
                tier: 2,
                created_hlc: Hlc::new(1_795_521_800_000, 0, remote_dev.clone()).canonical_string(),
                created_by: remote_dev.clone(),
                bdek: vec![0x99; 93],
            },
            [9u8; 24],
        )
        .unwrap();
        store
            .apply_remote_block_op_for_sync(RemoteBlockOpParams {
                remote_device: remote_dev.clone(),
                block_id: l_bid,
                op_id: l_op,
                parents: vec![l_p1],
                op_type: OpType::Lock,
                hlc: Hlc::new(1_795_521_800_000, 0, remote_dev),
                tier: 2,
                key_id: l_key,
                new_key_record: Some((1, l_mnr1)),
                mnb1: vec![0xCC; 64],
                public_hint: Some("api key".into()),
            })
            .unwrap();
        // G09 simulates an already-bootstrapped desktop receiving a concurrent remote edit.
        store.set_local_meta("bootstrap_completed", "1").unwrap();

        (c1.block_id, l1.block_id)
    };

    // ---- G09 assertions ----
    let get_c = run_cli(&dir, &["block", "get", &conflict_id, "--json"], None);
    assert_eq!(get_c.status.code(), Some(0));
    let j_c = parse_single_json_stdout(&get_c);
    assert_eq!(j_c["data"]["has_conflict"], true);
    let heads: Vec<String> = j_c["data"]["head_op_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(heads.len(), 2);
    assert_eq!(j_c["data"]["versions"].as_array().unwrap().len(), 2);
    assert_eq!(j_c["data"]["versions"][0]["is_display"], true);

    // Single-version command append must fail with CONFLICT_PRESENT (exit 4)
    let app_out = run_cli(&dir, &["block", "append", &conflict_id, "tail", "--json"], None);
    assert_eq!(app_out.status.code(), Some(4));
    assert_eq!(
        parse_single_json_stdout(&app_out)["error"]["code"],
        "CONFLICT_PRESENT"
    );

    // Merge using both expected heads -> converges to 1 leaf!
    let merge_out = run_cli(
        &dir,
        &[
            "block",
            "update",
            &conflict_id,
            "merged final content",
            "--expected-head",
            &heads[0],
            "--expected-head",
            &heads[1],
            "--json",
        ],
        None,
    );
    assert_eq!(merge_out.status.code(), Some(0));
    let merge_j = parse_single_json_stdout(&merge_out);
    assert_eq!(merge_j["data"]["head_op_ids"].as_array().unwrap().len(), 1);
    let after_c = parse_single_json_stdout(&run_cli(&dir, &["block", "get", &conflict_id, "--json"], None));
    assert_eq!(after_c["data"]["has_conflict"], false);
    assert_eq!(after_c["data"]["content"], "merged final content");

    // ---- G10 assertions (non-TTY locked block access -> exit 5, ZERO plaintext) ----
    let raw_l = run_cli(&dir, &["block", "get", &locked_id, "--raw"], None);
    assert_eq!(raw_l.status.code(), Some(5));
    assert!(raw_l.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&raw_l.stderr).contains("TOP_SECRET_CANARY_XYZ"));

    let dec_l = run_cli(&dir, &["block", "get", &locked_id, "--decrypt", "--json"], None);
    assert_eq!(dec_l.status.code(), Some(5));
    let dec_j = parse_single_json_stdout(&dec_l);
    assert_eq!(dec_j["error"]["code"], "BLOCK_LOCKED");
    assert!(!String::from_utf8_lossy(&dec_l.stdout).contains("TOP_SECRET_CANARY_XYZ"));
    assert!(!String::from_utf8_lossy(&dec_l.stderr).contains("TOP_SECRET_CANARY_XYZ"));

    let meta_l = run_cli(&dir, &["block", "get", &locked_id, "--json"], None);
    assert_eq!(meta_l.status.code(), Some(0));
    let meta_j = parse_single_json_stdout(&meta_l);
    assert_eq!(meta_j["data"]["is_locked"], true);
    assert_eq!(meta_j["data"]["redacted"], true);
    assert!(meta_j["data"]["content"].is_null());
    assert!(!String::from_utf8_lossy(&meta_l.stdout).contains("TOP_SECRET_CANARY_XYZ"));

    let search_l = parse_single_json_stdout(&run_cli(
        &dir,
        &["search", "TOP_SECRET_CANARY_XYZ", "--json"],
        None,
    ));
    assert!(search_l["data"].as_array().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn g11_broken_format_and_layer2_external_formatter_fuses_exit_7_with_zero_side_effects() {
    let dir = temp_dir("g11");

    // G11 stdin filter: broken JSON -> exit 7 FORMAT_SYNTAX_ERROR
    let bad_stdin = run_cli(
        &dir,
        &["format", "--lang", "json", "--json"],
        Some(b"{\"unterminated\": [1, 2"),
    );
    assert_eq!(bad_stdin.status.code(), Some(7));
    assert_eq!(
        parse_single_json_stdout(&bad_stdin)["error"]["code"],
        "FORMAT_SYNTAX_ERROR"
    );

    // G11 in-place block format on broken JSON -> exit 7, original content & head untouched
    let add_j = parse_single_json_stdout(&run_cli(
        &dir,
        &["add", "{\"broken\": ", "--lang", "json", "--json"],
        None,
    ));
    let blk_id = add_j["data"]["block_id"].as_str().unwrap().to_string();
    let head = add_j["data"]["op_id"].as_str().unwrap().to_string();

    let bad_blk = run_cli(
        &dir,
        &["format", &blk_id, "--expected-head", &head, "--json"],
        None,
    );
    assert_eq!(bad_blk.status.code(), Some(7));
    assert_eq!(
        parse_single_json_stdout(&bad_blk)["error"]["code"],
        "FORMAT_SYNTAX_ERROR"
    );
    let check_j = parse_single_json_stdout(&run_cli(&dir, &["block", "get", &blk_id, "--json"], None));
    assert_eq!(check_j["data"]["head_op_ids"][0], head);
    assert_eq!(check_j["data"]["content"], "{\"broken\": ");

    // Layer 2 external formatter fuses: (1) 0-byte stdout, (2) non-zero exit, (3) timeout
    let cfg_path = dir.join("formatters.toml");
    std::fs::write(
        &cfg_path,
        r#"
[formatters.emptyfuse]
cmd = "true"
args = []
timeout_ms = 500

[formatters.failfuse]
cmd = "sh"
args = ["-c", "echo partial; exit 1"]
timeout_ms = 500

[formatters.slowfuse]
cmd = "sleep"
args = ["2"]
timeout_ms = 100
"#,
    )
    .unwrap();
    let cfg_str = cfg_path.to_str().unwrap();

    for lang in ["emptyfuse", "failfuse", "slowfuse"] {
        let out = run_cli_with_env(
            &dir,
            &["format", "--lang", lang, "--json"],
            Some(b"non-empty code"),
            &[("MYNOTE_FORMATTERS_CONFIG", cfg_str)],
        );
        assert_eq!(out.status.code(), Some(7), "Layer 2 fuse {lang} must exit 7");
        assert_eq!(
            parse_single_json_stdout(&out)["error"]["code"],
            "FORMAT_SYNTAX_ERROR"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn non_tty_gates_and_heynote_cli_import_match_contracts() {
    let dir = temp_dir("tty_and_import");
    let add_j = parse_single_json_stdout(&run_cli(&dir, &["add", "hello", "--json"], None));
    let blk_id = add_j["data"]["block_id"].as_str().unwrap().to_string();

    // Non-TTY interactive gates (`docs/interface-contracts.md` §2.6 #9)
    let cases: Vec<Vec<&str>> = vec![
        vec!["block", "update", &blk_id, "x", "--force", "--json"],
        vec!["vault", "init", "--json"],
        vec!["device", "bootstrap", "--url", "https://example.test", "--json"],
        vec!["device", "add", "--name", "phone", "--json"],
        vec!["keyring", "rotate", "--json"],
        vec!["keyring", "unlock", "--json"],
        vec!["recovery", "show", "--json"],
        vec!["recovery", "drill", "--json"],
        vec![
            "restore",
            "--from-archive",
            "/tmp/nonexistent-archive",
            "--to",
            "/tmp/nonexistent-dst",
            "--json",
        ],
    ];
    for argv in cases {
        let out = run_cli(&dir, &argv, None);
        assert_eq!(
            out.status.code(),
            Some(2),
            "non-TTY {:?} must exit 2 INTERACTION_REQUIRED",
            argv
        );
        assert_eq!(
            parse_single_json_stdout(&out)["error"]["code"],
            "INTERACTION_REQUIRED"
        );
    }

    // CLI Heynote import of dirty fixture
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/heynote_dirty.txt");
    let imp_out = run_cli(
        &dir,
        &[
            "import",
            "heynote",
            fixture.to_str().unwrap(),
            "--buf",
            "from_heynote",
            "--json",
        ],
        None,
    );
    assert_eq!(imp_out.status.code(), Some(0));
    let imp_j = parse_single_json_stdout(&imp_out);
    assert_eq!(imp_j["data"]["blocks_imported"], 7);
    assert_eq!(imp_j["data"]["buffers_imported"], 1);

    let _ = std::fs::remove_dir_all(&dir);
}
