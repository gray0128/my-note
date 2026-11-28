use mynote_core::error::ErrorCode;
use mynote_store::LocalStore;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("mynote_store_integ_{tag}_{ts}"));
    let _ = std::fs::remove_dir_all(&p);
    p
}

#[test]
fn heynote_dirty_fixture_imports_losslessly_and_is_idempotent() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/heynote_dirty.txt");
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());

    let dir = temp_dir("heynote_fixture");
    let mut store = LocalStore::open(&dir).unwrap();

    // Dry run must create zero blocks
    let dry = store.import_heynote(&fixture, None, true, "human").unwrap();
    assert_eq!(dry.blocks_imported, 7);
    assert!(dry.dry_run);
    assert!(store.list_blocks(None, 50).unwrap().is_empty());

    // Actual import
    let rep = store
        .import_heynote(&fixture, Some("migrated"), false, "human")
        .unwrap();
    assert_eq!(rep.blocks_imported, 7);
    assert_eq!(rep.buffers_imported, 1);
    assert!(rep.duplicate_sources.is_empty());

    let blocks = store.list_blocks(Some("migrated"), 50).unwrap();
    assert_eq!(blocks.len(), 7);
    let langs: Vec<&str> = blocks.iter().map(|b| b.lang.as_str()).collect();
    assert_eq!(
        langs,
        vec!["text", "json", "sql", "text", "markdown", "rust", "text"]
    );

    // Inline ∞∞∞ inside JSON string literal & indented ∞∞∞ stay intact
    let json_blk = store.get_block(&blocks[1].id).unwrap();
    assert!(json_blk
        .content
        .as_deref()
        .unwrap()
        .contains("contains ∞∞∞ inside a string literal"));

    // Mirror file exists and contains imported content
    let mirror = std::fs::read_to_string(dir.join("mirror/migrated.md")).unwrap();
    assert!(mirror.contains("Heynote 2.x -a auto-format flag normalized!"));

    // Re-importing same file flags duplicate_sources
    let rep2 = store
        .import_heynote(&fixture, Some("migrated-2"), false, "human")
        .unwrap();
    assert!(!rep2.duplicate_sources.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wal_concurrent_readers_and_single_writer_have_zero_sqlite_busy_errors() {
    let dir = temp_dir("wal_concurrent");
    let mut writer = LocalStore::open(&dir).unwrap();
    writer
        .add_block(
            "scratch",
            "seed block for wal stress",
            Some("text"),
            None,
            "human",
            None,
        )
        .unwrap();

    let done = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let rdir = dir.clone();
        let rdone = Arc::clone(&done);
        readers.push(thread::spawn(move || {
            let reader = LocalStore::open(&rdir).expect("reader open");
            let mut reads = 0usize;
            while !rdone.load(Ordering::Relaxed) || reads < 10 {
                let list = reader
                    .list_blocks(None, 50)
                    .expect("WAL list must not SQLITE_BUSY");
                assert!(!list.is_empty());
                let hits = reader
                    .search_blocks("seed", None, 20)
                    .expect("WAL FTS5 search must not SQLITE_BUSY");
                assert!(!hits.is_empty());
                reads += 1;
                if reads > 200 {
                    break;
                }
            }
            reads
        }));
    }

    for i in 0..40 {
        writer
            .add_block(
                "scratch",
                &format!("concurrent write item #{i} with seed keyword"),
                Some("text"),
                None,
                "human",
                None,
            )
            .expect("single writer must never fail");
    }
    done.store(true, Ordering::Relaxed);

    for handle in readers {
        let reads = handle.join().expect("reader thread panicked");
        assert!(reads >= 10);
    }

    assert_eq!(writer.list_blocks(None, 100).unwrap().len(), 41);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn schema_too_new_refuses_open_without_writing() {
    let dir = temp_dir("schema_too_new");
    {
        let mut store = LocalStore::open(&dir).unwrap();
        store
            .add_block("scratch", "important data", Some("text"), None, "human", None)
            .unwrap();
    }
    // Simulate a future binary bumping min_reader_schema_version to 99
    {
        let conn = Connection::open(dir.join("mynote.db")).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('min_reader_schema_version', '99')",
            [],
        )
        .unwrap();
    }
    let err = LocalStore::open(&dir)
        .err()
        .expect("must fail with SCHEMA_TOO_NEW");
    assert_eq!(err.code(), ErrorCode::IntegrityError);
    assert!(err.message().contains("SCHEMA_TOO_NEW"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn time_travel_history_undo_actor_shred_and_tier2_daemon_contracts() {
    use base64::Engine;
    use mynote_core::crypto::{decrypt_mnb1, encrypt_mnb1, encrypt_mnr1, KeyRecordV1};
    use mynote_core::hlc::Hlc;
    use mynote_core::ids::{BlockId, DeviceId, KeyId, MonotonicUlidGen, OpId, SmkKid, Ulid, VkekKid};
    use mynote_core::model::OpType;
    use mynote_core::sync::StoreMutation;
    use mynote_core::vault::{create_vault_header, unlock_vault_with_passphrase, T_GRACE_DEFAULT_MS};
    use mynote_store::store::RemoteBlockOpParams;
    use mynote_store::Tier2OpInput;
    use zeroize::Zeroizing;

    let dir = temp_dir("time_travel_m3");
    let mut store = LocalStore::open(&dir).unwrap();

    // 1. Interleaved human edits, SET_META, and agent edits
    let r1 = store
        .add_block(
            "scratch",
            "v1 human original",
            Some("markdown"),
            None,
            "human",
            None,
        )
        .unwrap();
    let blk_id = r1.block_id.clone();
    let op1 = r1.op_id.clone();

    let meta1 = store
        .move_block(&blk_id, None, None, None, Some("text"), "human")
        .unwrap();
    let r2 = store
        .update_block(
            &blk_id,
            "v2 agent draft",
            &r1.head_op_ids,
            false,
            "agent:claude-code",
        )
        .unwrap();
    let r3 = store
        .update_block(
            &blk_id,
            "v3 agent bad edit",
            &r2.head_op_ids,
            false,
            "agent:claude-code",
        )
        .unwrap();
    // Intervening SET_META by human AFTER agent edits MUST NOT hijack --undo-actor!
    let _meta2 = store
        .move_block(&blk_id, None, None, None, Some("markdown"), "human")
        .unwrap();

    let hist = store.block_history(&blk_id, 50).unwrap();
    assert_eq!(hist.len(), 5);
    let meta_entry = hist.iter().find(|e| e.op_id == meta1.op_id).unwrap();
    assert_eq!(meta_entry.op_type, "SET_META");
    assert!(!meta_entry.has_content);
    assert!(!meta_entry.content_available);
    assert!(!meta_entry.shredded);
    assert!(!meta_entry.is_locked);
    assert!(meta_entry.key_id.is_none());

    let content_entry = hist.iter().find(|e| e.op_id == op1).unwrap();
    assert!(content_entry.has_content);
    assert!(content_entry.content_available);
    assert!(!content_entry.shredded);
    assert!(!content_entry.is_locked);
    assert!(content_entry.key_id.is_some());

    // Non-content op -> InvalidArgument (400); missing op -> NotFound (404)
    let meta_err = store
        .get_block_history_op_for_daemon(&blk_id, &meta1.op_id)
        .unwrap_err();
    assert_eq!(meta_err.code(), ErrorCode::InvalidArgument);
    let missing_op = OpId::from_ulid(Ulid::from_parts(1_720_000_000_999, [0xEE; 10])).to_string();
    assert_eq!(
        store
            .get_block_history_op_for_daemon(&blk_id, &missing_op)
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );

    // Tier 1 historical op fetch
    let op1_dto = store.get_block_history_op_for_daemon(&blk_id, &op1).unwrap();
    assert_eq!(op1_dto.content.as_deref(), Some("v1 human original"));
    assert!(!op1_dto.is_locked);
    assert!(op1_dto.mnb1_b64.is_none());
    assert!(op1_dto.mnw1_b64.is_none());
    assert_eq!(op1_dto.lang.as_deref(), Some("markdown"));

    // Preview --undo-actor skips SET_META and skips 2 agent ops with ZERO DB writes
    let preview = store
        .preview_revert_block(&blk_id, None, Some("agent:claude-code"))
        .unwrap();
    assert!(preview.dry_run);
    assert_eq!(preview.current_head_op_id.as_deref(), Some(r3.op_id.as_str()));
    assert_eq!(preview.target_op_id, op1);
    assert_eq!(preview.target_actor, "human");
    assert_eq!(preview.skipped_actor_ops, 2);
    assert!(!preview.is_locked);
    assert_eq!(preview.preview.as_deref(), Some("v1 human original"));
    // Verify zero writes
    assert_eq!(store.block_history(&blk_id, 50).unwrap().len(), 5);
    assert_eq!(
        store.get_block(&blk_id).unwrap().content.as_deref(),
        Some("v3 agent bad edit")
    );

    // Execute revert -> writes a fresh UPDATE without mutating history
    let resolved = store
        .resolve_revert_target(&blk_id, None, Some("agent:claude-code"))
        .unwrap();
    let rev_receipt = store
        .revert_block(&blk_id, &resolved.target.op_id, "human")
        .unwrap();
    assert_ne!(rev_receipt.op_id, op1);
    assert_eq!(
        store.get_block(&blk_id).unwrap().content.as_deref(),
        Some("v1 human original")
    );
    assert_eq!(store.block_history(&blk_id, 50).unwrap().len(), 6);

    // 2. Purge history + ExecuteShred -> shredded ops report shredded=true, content_available=false,
    //    and both get_block_history_op_for_daemon & revert_block return KeyShredded!
    let (_purge_rec, old_keys) = store
        .purge_block_history(&blk_id, None, None, T_GRACE_DEFAULT_MS, "agent:claude-code")
        .unwrap();
    assert!(!old_keys.is_empty());
    let muts: Vec<StoreMutation> = old_keys
        .iter()
        .copied()
        .map(|key_id| StoreMutation::ExecuteShred { key_id })
        .collect();
    store.apply_store_mutations(&muts).unwrap();

    let hist_after_shred = store.block_history(&blk_id, 50).unwrap();
    let op1_after = hist_after_shred.iter().find(|e| e.op_id == op1).unwrap();
    assert!(op1_after.has_content);
    assert!(op1_after.shredded);
    assert!(!op1_after.content_available);

    assert_eq!(
        store
            .get_block_history_op_for_daemon(&blk_id, &op1)
            .unwrap_err()
            .code(),
        ErrorCode::KeyShredded
    );
    assert_eq!(
        store.revert_block(&blk_id, &op1, "human").unwrap_err().code(),
        ErrorCode::KeyShredded
    );
    // CRITICAL: undo_actor MUST fail closed with KeyShredded when the immediate predecessor
    // outside bad_actor was shredded (NEVER silently skip past it!)
    assert_eq!(
        store
            .resolve_revert_target(&blk_id, None, Some("agent:claude-code"))
            .unwrap_err()
            .code(),
        ErrorCode::KeyShredded
    );

    // 3. Multi-leaf conflict block -> ConflictPresent (exit 4 / HTTP 409)
    let c1 = store
        .add_block("scratch", "conflict base", Some("text"), None, "human", None)
        .unwrap();
    let _c2 = store
        .update_block(&c1.block_id, "local branch", &c1.head_op_ids, false, "human")
        .unwrap();
    let kr_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("smk_keyring.local.json")).unwrap()).unwrap();
    let smk_kid_s = kr_json["current_smk_kid"].as_str().unwrap();
    let smk_hex = kr_json["generations"][smk_kid_s].as_str().unwrap();
    let mut smk = [0u8; 32];
    for i in 0..32 {
        smk[i] = u8::from_str_radix(&smk_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let smk_kid = SmkKid::parse(smk_kid_s).unwrap();
    let mut ugen = MonotonicUlidGen::new();
    let remote_dev = DeviceId::parse("dev_remote_tt01").unwrap();
    let c_bid = BlockId::parse(&c1.block_id).unwrap();
    let r_op = OpId::from_ulid(ugen.next(1_795_600_000_000, [1u8; 10]));
    let r_kid = KeyId::from_ulid(ugen.next(1_795_600_000_001, [2u8; 10]));
    let r_bdek = [0x33u8; 32];
    let r_mnb1 = encrypt_mnb1(c_bid.as_bytes(), r_op, r_kid, &r_bdek, "remote branch", [3u8; 24]).unwrap();
    let r_mnr1 = encrypt_mnr1(
        smk_kid,
        &smk,
        1,
        &KeyRecordV1 {
            v: 1,
            key_id: r_kid,
            block_id: c_bid.0,
            tier: 1,
            created_hlc: Hlc::new(1_795_600_000_000, 0, remote_dev.clone()).canonical_string(),
            created_by: remote_dev.clone(),
            bdek: r_bdek.to_vec(),
        },
        [4u8; 24],
    )
    .unwrap();
    store
        .apply_remote_block_op_for_sync(RemoteBlockOpParams {
            remote_device: remote_dev.clone(),
            block_id: c_bid,
            op_id: r_op,
            parents: vec![OpId::parse(&c1.op_id).unwrap()],
            op_type: OpType::Update,
            hlc: Hlc::new(1_795_600_000_000, 0, remote_dev),
            tier: 1,
            key_id: r_kid,
            new_key_record: Some((1, r_mnr1)),
            mnb1: r_mnb1,
            public_hint: None,
        })
        .unwrap();
    store.set_local_meta("bootstrap_completed", "1").unwrap();

    assert_eq!(
        store
            .resolve_revert_target(&c1.block_id, Some(&c1.op_id), None)
            .unwrap_err()
            .code(),
        ErrorCode::ConflictPresent
    );
    assert_eq!(
        store
            .preview_revert_block(&c1.block_id, Some(&c1.op_id), None)
            .unwrap_err()
            .code(),
        ErrorCode::ConflictPresent
    );
    assert_eq!(
        store
            .revert_block(&c1.block_id, &c1.op_id, "human")
            .unwrap_err()
            .code(),
        ErrorCode::ConflictPresent
    );

    // 4. Tier 2 Vault history op -> SEC-03 zero plaintext in Daemon, returns mnb1_b64 + mnw1_b64
    let rpk = store.recovery_pk().unwrap();
    let vkid = VkekKid::from_ulid(Ulid::from_parts(1_720_000_000_000, [0x11; 10]));
    let vh = create_vault_header(
        b"tt-vault-pass",
        &rpk,
        vkid,
        &[0x77; 32],
        [0x12; 16],
        [0x13; 24],
        [0x14; 32],
        [0x15; 24],
        1_720_000_000_000,
    )
    .unwrap();
    let unlocked = unlock_vault_with_passphrase(b"tt-vault-pass", &vh).unwrap();
    store
        .put_vault_header(vh.updated_at_ms, &rmp_serde::to_vec_named(&vh).unwrap())
        .unwrap();

    let t2_blk = BlockId::from_ulid(ugen.next(1_795_600_100_000, [0x21; 10]));
    let t2_op1 = OpId::from_ulid(ugen.next(1_795_600_100_001, [0x22; 10]));
    let t2_kid = KeyId::from_ulid(ugen.next(1_795_600_100_002, [0x23; 10]));
    let t2_bdek = Zeroizing::new([0x88; 32]);
    let t2_mnb1_1 = encrypt_mnb1(
        t2_blk.as_bytes(),
        t2_op1,
        t2_kid,
        &t2_bdek,
        "TIER2_HISTORICAL_SECRET_V1",
        [0x24; 24],
    )
    .unwrap();
    let t2_mnw1 = unlocked.wrap_bdek(t2_kid, t2_blk, &t2_bdek, [0x25; 24]).unwrap();
    let t2_rec1 = store
        .add_tier2_block(
            &t2_blk.to_string(),
            Tier2OpInput {
                op_id: &t2_op1.to_string(),
                key_id: &t2_kid.to_string(),
                mnb1: &t2_mnb1_1,
                mnw1: Some(&t2_mnw1),
            },
            "scratch",
            "text",
            None,
            Some("secret hint"),
            "human",
        )
        .unwrap();

    let t2_op2 = OpId::from_ulid(ugen.next(1_795_600_100_010, [0x26; 10]));
    let t2_mnb1_2 = encrypt_mnb1(
        t2_blk.as_bytes(),
        t2_op2,
        t2_kid,
        &t2_bdek,
        "TIER2_CURRENT_SECRET_V2",
        [0x27; 24],
    )
    .unwrap();
    store
        .update_tier2_block(
            &t2_blk.to_string(),
            Tier2OpInput {
                op_id: &t2_op2.to_string(),
                key_id: &t2_kid.to_string(),
                mnb1: &t2_mnb1_2,
                mnw1: None,
            },
            &t2_rec1.head_op_ids,
            None,
            None,
            "human",
        )
        .unwrap();

    let t2_hist = store.block_history(&t2_blk.to_string(), 10).unwrap();
    assert_eq!(t2_hist.len(), 2);
    assert!(t2_hist
        .iter()
        .all(|e| e.is_locked && e.has_content && e.content_available && !e.shredded));

    let t2_op1_dto = store
        .get_block_history_op_for_daemon(&t2_blk.to_string(), &t2_op1.to_string())
        .unwrap();
    assert!(t2_op1_dto.is_locked);
    assert!(t2_op1_dto.content.is_none());
    let json_s = serde_json::to_string(&t2_op1_dto).unwrap();
    assert!(!json_s.contains("TIER2_HISTORICAL_SECRET_V1"));
    let dec_mnb1 = base64::engine::general_purpose::STANDARD
        .decode(t2_op1_dto.mnb1_b64.as_deref().unwrap())
        .unwrap();
    let dec_mnw1 = base64::engine::general_purpose::STANDARD
        .decode(t2_op1_dto.mnw1_b64.as_deref().unwrap())
        .unwrap();
    let unwrapped_bdek = unlocked.unwrap_bdek(t2_kid, t2_blk, &dec_mnw1).unwrap();
    let recovered = decrypt_mnb1(t2_blk.as_bytes(), t2_op1, t2_kid, &unwrapped_bdek, &dec_mnb1).unwrap();
    assert_eq!(recovered, "TIER2_HISTORICAL_SECRET_V1");

    // Preview on locked op returns is_locked=true, preview=None; Tier 1 revert_block returns BlockLocked
    let t2_prev = store
        .preview_revert_block(&t2_blk.to_string(), Some(&t2_op1.to_string()), None)
        .unwrap();
    assert!(t2_prev.is_locked);
    assert!(t2_prev.preview.is_none());
    assert_eq!(
        store
            .revert_block(&t2_blk.to_string(), &t2_op1.to_string(), "human")
            .unwrap_err()
            .code(),
        ErrorCode::BlockLocked
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sqlite_v1_to_v2_migration_creates_backup_preserves_key_material_and_adds_clip_items() {
    use mynote_core::ids::{Ulid, VkekKid};
    use mynote_core::vault::create_vault_header;
    use mynote_store::{ClipItemRow, CLIP_LOCAL_MAX_ITEMS};

    let dir = temp_dir("v1_to_v2_migration");
    // 1. Bootstrap a real store, populate a note & vault_header, then downgrade DB on disk to genuine v1 schema.
    let block_id;
    let saved_keyring_blob: Vec<u8>;
    let saved_vault_blob: Vec<u8>;
    {
        let mut store = LocalStore::open(&dir).unwrap();
        let rec = store
            .add_block(
                "scratch",
                "pre-migration note content",
                Some("text"),
                None,
                "human",
                None,
            )
            .unwrap();
        block_id = rec.block_id;
        let rpk = store.recovery_pk().unwrap();
        let vh = create_vault_header(
            b"mig-pass",
            &rpk,
            VkekKid::from_ulid(Ulid::from_parts(1_720_000_000_000, [0x41; 10])),
            &[0x55; 32],
            [0x11; 16],
            [0x12; 24],
            [0x13; 32],
            [0x14; 24],
            1_720_000_000_000,
        )
        .unwrap();
        saved_vault_blob = rmp_serde::to_vec_named(&vh).unwrap();
        store
            .put_vault_header(vh.updated_at_ms, &saved_vault_blob)
            .unwrap();
    }
    {
        let conn = Connection::open(dir.join("mynote.db")).unwrap();
        saved_keyring_blob = conn
            .query_row("SELECT blob FROM key_material WHERE kind = 'keyring'", [], |r| {
                r.get(0)
            })
            .unwrap();
        // Rebuild exact v1 DB state: drop clip_items, restore old 2-kind CHECK on key_material, user_version = 1
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TABLE IF EXISTS clip_items;
             CREATE TABLE key_material_old (
                 kind TEXT PRIMARY KEY CHECK (kind IN ('keyring', 'vault_header')),
                 gen INTEGER NOT NULL,
                 blob BLOB NOT NULL,
                 updated_at_ms INTEGER NOT NULL
             ) STRICT;
             INSERT INTO key_material_old SELECT kind, gen, blob, updated_at_ms FROM key_material WHERE kind IN ('keyring', 'vault_header');
             DROP TABLE key_material;
             ALTER TABLE key_material_old RENAME TO key_material;
             UPDATE local_meta SET value = '1' WHERE key IN ('schema_version', 'min_reader_schema_version');
             PRAGMA user_version = 1;
             PRAGMA foreign_keys = ON;",
        )
        .unwrap();
        // Verify old v1 CHECK rejects 'clip_key'
        assert!(conn
            .execute(
                "INSERT INTO key_material (kind, gen, blob, updated_at_ms) VALUES ('clip_key', 1, X'01', 1)",
                [],
            )
            .is_err());
    }

    // 2. Reopen via LocalStore::open -> MUST trigger VACUUM INTO backup + v1->v2 migration!
    let mut store = LocalStore::open(&dir).unwrap();
    let backup_path = dir.join("backups/mynote-pre-schema-v1.db");
    assert!(
        backup_path.is_file(),
        "pre-migration VACUUM INTO backup must exist at {}",
        backup_path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pre-migration backup must be 0600");
    }

    // Verify user_version == 2 and existing note + key_material rows are preserved
    {
        let conn = Connection::open(dir.join("mynote.db")).unwrap();
        let ver: u32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 2);
        let kr: Vec<u8> = conn
            .query_row("SELECT blob FROM key_material WHERE kind = 'keyring'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let vh: Vec<u8> = conn
            .query_row(
                "SELECT blob FROM key_material WHERE kind = 'vault_header'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kr, saved_keyring_blob);
        assert_eq!(vh, saved_vault_blob);
    }
    assert_eq!(
        store.get_block(&block_id).unwrap().content.as_deref(),
        Some("pre-migration note content")
    );

    // 3. ClipKey storage & destructive rotation (no old key retained)
    let (ck1, key1, blob1) = store.generate_wrapped_clip_key(1_795_600_000_000).unwrap();
    store
        .upsert_clip_key_material(1, &blob1, 1_795_600_000_000)
        .unwrap();
    let (unw_kid1, unw_key1, unw_gen1) = store.unwrap_local_clip_key().unwrap().unwrap();
    assert_eq!(unw_kid1, ck1);
    assert_eq!(*unw_key1, *key1);
    assert_eq!(unw_gen1, 1);

    // Rotate to gen 2 -> replaces gen 1 completely; stale gen 1 now fails with CasMismatch
    let (ck2, key2, blob2) = store.generate_wrapped_clip_key(1_795_600_010_000).unwrap();
    store
        .upsert_clip_key_material(2, &blob2, 1_795_600_010_000)
        .unwrap();
    let (unw_kid2, unw_key2, unw_gen2) = store.unwrap_local_clip_key().unwrap().unwrap();
    assert_eq!(unw_kid2, ck2);
    assert_eq!(*unw_key2, *key2);
    assert_eq!(unw_gen2, 2);
    assert_eq!(
        store
            .upsert_clip_key_material(1, &blob1, 1_795_600_010_001)
            .unwrap_err()
            .code(),
        ErrorCode::CasMismatch
    );

    // 4. Insert 105 clip_items -> unbounded local archive retains all 105; explicit trim_clip_items(100) still works
    for i in 0..105u64 {
        let cid = store.next_clip_id(1_795_600_100_000 + i).unwrap();
        let rel = format!("{cid}.png");
        store
            .upsert_clip_item(&ClipItemRow {
                clip_id: cid.to_string(),
                clip_kid: ck2.to_string(),
                device_id: store.device_id().as_str().to_string(),
                kind: "image".to_string(),
                mime: "image/png".to_string(),
                source_mode: "explicit".to_string(),
                created_at_ms: (1_795_600_100_000 + i) as i64,
                expires_at_ms: (1_795_600_100_000 + i + 604_800_000) as i64,
                text_preview: None,
                has_blob: true,
                blob_bytes: Some(128),
                blob_sha256: Some("a".repeat(64)),
                width: Some(16),
                height: Some(16),
                thumb_mime: Some("image/jpeg".to_string()),
                thumb_blob: Some(vec![0xFF, 0xD8, 0xFF]),
                local_blob_path: Some(rel),
            })
            .unwrap();
    }
    assert_eq!(store.count_all_clip_items().unwrap(), 105);
    assert_eq!(store.list_clip_items(200, None).unwrap().len(), 105);
    let evicted = store.trim_clip_items(100).unwrap();
    assert_eq!(evicted.len(), 5);
    assert_eq!(store.list_clip_items(100, None).unwrap().len(), 100);
    let _ = CLIP_LOCAL_MAX_ITEMS;

    // SVG mime must be rejected at store boundary
    let svg_cid = store.next_clip_id(1_795_600_200_000).unwrap().to_string();
    let svg_err = store
        .upsert_clip_item(&ClipItemRow {
            clip_id: svg_cid,
            clip_kid: ck2.to_string(),
            device_id: store.device_id().as_str().to_string(),
            kind: "image".to_string(),
            mime: "image/svg+xml".to_string(),
            source_mode: "explicit".to_string(),
            created_at_ms: 1_795_600_200_000,
            expires_at_ms: 1_795_600_800_000,
            text_preview: None,
            has_blob: true,
            blob_bytes: Some(10),
            blob_sha256: Some("b".repeat(64)),
            width: None,
            height: None,
            thumb_mime: None,
            thumb_blob: None,
            local_blob_path: None,
        })
        .unwrap_err();
    assert_eq!(svg_err.code(), ErrorCode::InvalidArgument);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clip_cache_enforces_lru_file_count_byte_budget_permissions_and_isolation() {
    use mynote_store::ClipItemRow;
    use std::time::Duration;

    let dir = temp_dir("clip_cache_lru_isolation");
    let mut store = LocalStore::open(&dir).unwrap();
    let note = store
        .add_block(
            "scratch",
            "permanent note needle",
            Some("text"),
            None,
            "human",
            None,
        )
        .unwrap();
    let mirror_before = std::fs::read_to_string(dir.join("mirror/scratch.md")).unwrap();

    let count_rows = |table: &str| -> i64 {
        let conn = Connection::open(dir.join("mynote.db")).unwrap();
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    };
    let ops_before = count_rows("sync_ops");
    let blocks_before = count_rows("blocks");
    let bufs_before = count_rows("buffers");
    let keys_before = count_rows("block_keys");
    let marks_before = count_rows("shred_marks");

    // 1. ClipCache LRU: file count cap + read mtime bump + byte budget cap + path traversal guard
    let cache = store.clip_cache();
    assert_eq!(
        cache.write("../escape.png", b"bad").unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        cache.write("sub/file.png", b"bad").unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        cache.write(".hidden", b"bad").unwrap_err().code(),
        ErrorCode::InvalidArgument
    );

    // Write 3 files with small sleeps so mtimes strictly increase; read "a.png" to bump its mtime;
    // writing 4th file with max_files=3 must evict "b.png" (not "a.png"!).
    cache.write_with_limits("a.png", &[1u8; 30], 3, 1000).unwrap();
    thread::sleep(Duration::from_millis(20));
    cache.write_with_limits("b.png", &[2u8; 30], 3, 1000).unwrap();
    thread::sleep(Duration::from_millis(20));
    cache.write_with_limits("c.png", &[3u8; 30], 3, 1000).unwrap();
    thread::sleep(Duration::from_millis(20));
    assert_eq!(cache.read("a.png").unwrap().unwrap(), vec![1u8; 30]);
    thread::sleep(Duration::from_millis(20));
    cache.write_with_limits("d.png", &[4u8; 30], 3, 1000).unwrap();

    assert!(
        cache.exists("a.png"),
        "read hit must protect a.png from LRU eviction"
    );
    assert!(!cache.exists("b.png"), "oldest unread b.png must be evicted");
    assert!(cache.exists("c.png"));
    assert!(cache.exists("d.png"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = std::fs::metadata(cache.root()).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(cache.path_for("a.png").unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    // Byte budget cap: max_bytes = 65 bytes must evict oldest until total <= 65
    let evicted = cache.enforce_lru(10, 65).unwrap();
    assert!(!evicted.is_empty());
    let (files, total_bytes) = cache.stats();
    assert!(files <= 2 && total_bytes <= 65);

    // 2. INV-CLIP-ISOLATION: clip writes/deletes/clears NEVER touch notes, FTS5, sync_ops, block_keys, or mirror/
    let (ck, _, blob) = store.generate_wrapped_clip_key(1_795_600_300_000).unwrap();
    store
        .upsert_clip_key_material(1, &blob, 1_795_600_300_000)
        .unwrap();
    let cid = store.next_clip_id(1_795_600_300_001).unwrap();
    store
        .upsert_clip_item(&ClipItemRow {
            clip_id: cid.to_string(),
            clip_kid: ck.to_string(),
            device_id: store.device_id().as_str().to_string(),
            kind: "text".to_string(),
            mime: "text/plain".to_string(),
            source_mode: "explicit".to_string(),
            created_at_ms: 1_795_600_300_001,
            expires_at_ms: 1_795_600_900_001,
            text_preview: Some("CLIP_ONLY_UNIQUE_TOKEN_999".to_string()),
            has_blob: false,
            blob_bytes: None,
            blob_sha256: None,
            width: None,
            height: None,
            thumb_mime: None,
            thumb_blob: None,
            local_blob_path: None,
        })
        .unwrap();

    // FTS5 search MUST NOT index clip_items!
    assert!(store
        .search_blocks("CLIP_ONLY_UNIQUE_TOKEN_999", None, 20)
        .unwrap()
        .is_empty());
    assert_eq!(count_rows("sync_ops"), ops_before);
    assert_eq!(count_rows("blocks"), blocks_before);
    assert_eq!(count_rows("buffers"), bufs_before);
    assert_eq!(count_rows("block_keys"), keys_before);
    assert_eq!(count_rows("shred_marks"), marks_before);
    assert_eq!(
        std::fs::read_to_string(dir.join("mirror/scratch.md")).unwrap(),
        mirror_before
    );
    assert_eq!(
        store.get_block(&note.block_id).unwrap().content.as_deref(),
        Some("permanent note needle")
    );

    store.clear_clip_items().unwrap();
    cache.clear().unwrap();
    assert_eq!(cache.stats(), (0, 0));
    assert_eq!(count_rows("sync_ops"), ops_before);
    assert_eq!(count_rows("blocks"), blocks_before);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unbounded_local_clip_archive_pagination_search_prune_and_uncached_blobs() {
    use mynote_store::{ClipItemRow, ClipListQuery, ClipPruneFilter};

    let dir = temp_dir("clip_unbounded_d8p");
    let mut store = LocalStore::open(&dir).unwrap();
    let (ck, _, blob) = store.generate_wrapped_clip_key(1_795_600_000_000).unwrap();
    store
        .upsert_clip_key_material(1, &blob, 1_795_600_000_000)
        .unwrap();
    let cache = store.clip_cache();

    // Insert 120 items (exceeding legacy 100-item cap), including expired cloud TTL rows & blobs
    let mut ids = Vec::new();
    for i in 0..120u64 {
        let ts = (1_795_600_000_000 + i * 1_000) as i64;
        let cid = store.next_clip_id(ts as u64).unwrap().to_string();
        let is_img = i % 3 == 0;
        let is_cached = is_img && i < 114;
        let rel = if is_cached {
            let name = format!("{cid}.png");
            cache.write(&name, &vec![0xABu8; 512]).unwrap();
            Some(name)
        } else {
            None
        };
        store
            .upsert_clip_item(&ClipItemRow {
                clip_id: cid.clone(),
                clip_kid: ck.to_string(),
                device_id: store.device_id().as_str().to_string(),
                kind: if is_img { "image" } else { "text" }.to_string(),
                mime: if is_img { "image/png" } else { "text/plain" }.to_string(),
                source_mode: "explicit".to_string(),
                created_at_ms: ts,
                // First 20 items have already passed cloud TTL relative to now = 1_795_600_500_000
                expires_at_ms: if i < 20 { ts + 10_000 } else { ts + 30 * 86_400_000 },
                text_preview: if is_img {
                    None
                } else if i == 55 {
                    Some("100%_exact_needle_alpha".to_string())
                } else {
                    Some(format!("clip item #{i}"))
                },
                has_blob: is_img,
                blob_bytes: if is_img { Some(512) } else { None },
                blob_sha256: if is_img { Some("c".repeat(64)) } else { None },
                width: if is_img { Some(32) } else { None },
                height: if is_img { Some(32) } else { None },
                thumb_mime: None,
                thumb_blob: None,
                local_blob_path: rel,
            })
            .unwrap();
        ids.push(cid);
    }

    // All 120 items and all 38 cached files survive without automatic eviction
    assert_eq!(store.count_all_clip_items().unwrap(), 120);
    let stats = store.clip_storage_stats().unwrap();
    assert_eq!(stats.total_items, 120);
    assert_eq!(stats.image_items, 40);
    assert_eq!(stats.text_items, 80);
    assert_eq!(stats.cached_blob_files, 38);
    assert_eq!(stats.cached_blob_bytes, 38 * 512);
    assert_eq!(stats.uncached_blob_items, 2);

    // Uncached remote blobs only returns the 2 unexpired uncached images (indices 114, 117)
    let uncached = store.list_uncached_remote_blobs(1_795_600_500_000, 10).unwrap();
    assert_eq!(uncached.len(), 2);
    assert_eq!(uncached[0].clip_id, ids[117]);
    assert_eq!(uncached[1].clip_id, ids[114]);

    // Cursor pagination walks all 120 items without duplicates or gaps
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = store
            .list_clip_items_page(&ClipListQuery {
                limit: 35,
                before_id: cursor.as_deref(),
                kind: None,
                query: None,
            })
            .unwrap();
        assert_eq!(page.total_count, 120);
        for row in &page.items {
            seen.push(row.clip_id.clone());
        }
        if !page.has_more {
            break;
        }
        cursor = page.items.last().map(|r| r.clip_id.clone());
    }
    assert_eq!(seen.len(), 120);
    assert_eq!(seen[0], ids[119]);
    assert_eq!(seen[119], ids[0]);

    // Search escapes LIKE wildcards (% and _) accurately
    let search = store
        .list_clip_items_page(&ClipListQuery {
            limit: 50,
            before_id: None,
            kind: None,
            query: Some("100%_EXACT_NEEDLE"),
        })
        .unwrap();
    assert_eq!(search.total_count, 1);
    assert_eq!(search.items[0].clip_id, ids[55]);

    // Manual prune dry-run + execute: delete images keeping newest 10 -> deletes 30 images (all 30 cached -> 30 * 512 bytes)
    let dry = store
        .prune_clip_items(&ClipPruneFilter {
            before_ms: None,
            keep_latest: Some(10),
            kind: Some("image".to_string()),
            dry_run: true,
        })
        .unwrap();
    assert!(dry.dry_run);
    assert_eq!(dry.matched_count, 30);
    assert_eq!(dry.deleted_count, 0);
    assert_eq!(dry.freed_bytes, 30 * 512);
    assert_eq!(store.count_all_clip_items().unwrap(), 120);

    let applied = store
        .prune_clip_items(&ClipPruneFilter {
            before_ms: None,
            keep_latest: Some(10),
            kind: Some("image".to_string()),
            dry_run: false,
        })
        .unwrap();
    assert!(!applied.dry_run);
    assert_eq!(applied.deleted_count, 30);
    assert_eq!(applied.freed_bytes, 30 * 512);
    assert_eq!(store.count_all_clip_items().unwrap(), 90);
    assert_eq!(cache.stats(), (8, 8 * 512));

    let _ = std::fs::remove_dir_all(&dir);
}
