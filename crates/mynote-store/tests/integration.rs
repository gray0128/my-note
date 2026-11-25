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
