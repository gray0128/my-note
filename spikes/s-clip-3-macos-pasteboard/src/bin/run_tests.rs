//! Real macOS `NSPasteboard.generalPasteboard()` verification runner (Tests 1-5 + lazy promise proof).
//! Always snapshots and restores the existing clipboard via RAII `ClipboardRestoreGuard`.

use std::sync::atomic::Ordering;
use std::time::Instant;

use image::ImageFormat;
use s_clip_3_macos_pasteboard::img;
use s_clip_3_macos_pasteboard::typed_objc2::{self as pb, lazy_provider, ClipboardRestoreGuard};
use s_clip_3_macos_pasteboard::types::{
    ClipPayload, ReadOptions, ReadOutcome, SkipReason, WriteMarkers, PNG_MAGIC, UTI_AUTO_GENERATED,
    UTI_CONCEALED, UTI_MYNOTE_SYNCED, UTI_MYNOTE_VAULT_SECRET, UTI_ONEPASSWORD, UTI_PNG,
    UTI_REMOTE_CLIPBOARD, UTI_SVG, UTI_TIFF, UTI_TRANSIENT, UTI_UTF8_PLAIN_TEXT,
};

fn main() {
    if let Err(e) = run_all_real_macos_tests() {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}

fn run_all_real_macos_tests() -> Result<(), String> {
    let guard = ClipboardRestoreGuard::capture();
    println!(
        "[Setup] Captured existing macOS pasteboard ({}); will restore automatically on exit.",
        guard.summary()
    );
    println!(
        "[Env]   NSPasteboard.accessBehavior() raw = {} (2 = AlwaysAllow)",
        pb::access_behavior_raw()
    );

    // -------------------------------------------------------------------------
    // Test 1: UTF-8 Text roundtrip + changeCount increment
    // -------------------------------------------------------------------------
    {
        let before = pb::change_count();
        let sample = "hello my-note 剪贴板 🔐\nline 2 — UTF-8";
        let after = pb::write_text(sample, WriteMarkers::default())?;
        if after <= before {
            return Err(format!(
                "Test 1 failed: changeCount did not increment ({before} -> {after})"
            ));
        }
        let report = pb::read_pasteboard(ReadOptions::default())?;
        match &report.outcome {
            ReadOutcome::Payload(ClipPayload::Text(s)) if s == sample => {}
            other => return Err(format!("Test 1 unexpected outcome: {other:?}")),
        }
        if report.stats.types_queries != 1
            || report.stats.string_for_type_calls != vec![UTI_UTF8_PLAIN_TEXT]
            || !report.stats.data_for_type_calls.is_empty()
        {
            return Err(format!("Test 1 unexpected stats: {:?}", report.stats));
        }
        println!(
            "[PASS] Test 1 (Text): changeCount {before} -> {after} (+{}), {} bytes UTF-8 roundtrip exact, types_queries=1",
            after - before,
            sample.len()
        );
    }

    // -------------------------------------------------------------------------
    // Test 2: PNG + larger TIFF simultaneously -> reads public.png ONLY, skips public.tiff
    // -------------------------------------------------------------------------
    {
        let small_img = img::make_test_rgba(16, 16, 7);
        let large_img = img::make_test_rgba(128, 128, 99);
        let png_bytes = img::encode_rgba_as(&small_img, ImageFormat::Png)?;
        let tiff_bytes = img::encode_rgba_as(&large_img, ImageFormat::Tiff)?;
        if tiff_bytes.len() <= png_bytes.len() * 10 {
            return Err(format!(
                "Test 2 fixture invalid: expected TIFF ({}) >> PNG ({})",
                tiff_bytes.len(),
                png_bytes.len()
            ));
        }

        // Write BOTH public.tiff and public.png onto the same NSPasteboardItem (TIFF first!).
        pb::write_item_representations(&[], &[(UTI_TIFF, &tiff_bytes), (UTI_PNG, &png_bytes)], false)?;
        let observed = pb::read_types();
        if !observed.iter().any(|t| t == UTI_PNG) || !observed.iter().any(|t| t == UTI_TIFF) {
            return Err(format!(
                "Test 2 failed: pasteboard missing PNG or TIFF: {observed:?}"
            ));
        }

        let report = pb::read_pasteboard(ReadOptions::default())?;
        if report.stats.data_for_type_calls != vec![UTI_PNG] {
            return Err(format!(
                "Test 2 failed: expected dataForType([public.png]) only, got {:?}",
                report.stats.data_for_type_calls
            ));
        }
        match &report.outcome {
            ReadOutcome::Payload(ClipPayload::Image {
                mime,
                bytes,
                source_uti,
                transcoded_to_png,
            }) => {
                if *mime != "image/png" || *source_uti != UTI_PNG || *transcoded_to_png || bytes != &png_bytes
                {
                    return Err("Test 2 failed: returned PNG bytes did not match original public.png".into());
                }
            }
            other => return Err(format!("Test 2 unexpected outcome: {other:?}")),
        }

        // OS-level lazy promise proof: eager public.png + promised public.tiff -> 0 provider calls!
        let (_provider, tiff_invocations) = lazy_provider::write_item_with_lazy_promise(
            &[(UTI_PNG, &png_bytes)],
            &[UTI_TIFF],
            tiff_bytes.clone(),
            false,
        )?;
        let lazy_report = pb::read_pasteboard(ReadOptions::default())?;
        let invoked = tiff_invocations.load(Ordering::SeqCst);
        if invoked != 0 || lazy_report.stats.data_for_type_calls != vec![UTI_PNG] {
            return Err(format!(
                "Test 2 lazy proof failed: tiff_provider_invocations={invoked}, calls={:?}",
                lazy_report.stats.data_for_type_calls
            ));
        }
        println!(
            "[PASS] Test 2 (PNG+TIFF priority): PNG={} B vs TIFF={} B; dataForType={:?}; lazy TIFF provider invocations={invoked}",
            png_bytes.len(),
            tiff_bytes.len(),
            report.stats.data_for_type_calls
        );
    }

    // -------------------------------------------------------------------------
    // Test 3: TIFF-only fallback -> reads TIFF and transcodes to valid PNG
    // -------------------------------------------------------------------------
    {
        let src_img = img::make_test_rgba(64, 48, 42);
        let tiff_bytes = img::encode_rgba_as(&src_img, ImageFormat::Tiff)?;

        pb::write_item_representations(&[], &[(UTI_TIFF, &tiff_bytes)], false)?;
        let observed = pb::read_types();
        if observed.iter().any(|t| t == UTI_PNG) || !observed.iter().any(|t| t == UTI_TIFF) {
            return Err(format!(
                "Test 3 fixture invalid: expected TIFF only, got {observed:?}"
            ));
        }

        let t0 = Instant::now();
        let report = pb::read_pasteboard(ReadOptions::default())?;
        let elapsed_small = t0.elapsed();

        if report.stats.data_for_type_calls != vec![UTI_TIFF] {
            return Err(format!(
                "Test 3 failed: expected dataForType([public.tiff]), got {:?}",
                report.stats.data_for_type_calls
            ));
        }
        let png_len = match &report.outcome {
            ReadOutcome::Payload(ClipPayload::Image {
                mime,
                bytes,
                source_uti,
                transcoded_to_png,
            }) => {
                if *mime != "image/png" || *source_uti != UTI_TIFF || !*transcoded_to_png {
                    return Err("Test 3 metadata mismatch".into());
                }
                if !bytes.starts_with(&PNG_MAGIC) {
                    return Err("Test 3 transcoded output missing 8-byte PNG magic".into());
                }
                let decoded = image::load_from_memory_with_format(bytes, ImageFormat::Png)
                    .map_err(|e| format!("Test 3 PNG decode failed: {e}"))?
                    .to_rgba8();
                if decoded.dimensions() != (64, 48) || decoded.as_raw() != src_img.as_raw() {
                    return Err("Test 3 pixel-for-pixel roundtrip mismatch".into());
                }
                bytes.len()
            }
            other => return Err(format!("Test 3 unexpected outcome: {other:?}")),
        };

        // Benchmark realistic 1920x1080 uncompressed RGBA TIFF (~8.1 MiB) -> PNG transcode.
        let hd_img = img::make_test_rgba(1920, 1080, 17);
        let hd_tiff = img::encode_rgba_as(&hd_img, ImageFormat::Tiff)?;
        let t1 = Instant::now();
        let hd_png = img::transcode_tiff_to_png(&hd_tiff)?;
        let hd_elapsed = t1.elapsed();
        println!(
            "[PASS] Test 3 (TIFF-only fallback): 64x48 TIFF={} B -> valid PNG={} B (magic 89 50 4E 47, pixel-exact) in {:.2} ms; 1080p TIFF={} KiB -> PNG={} KiB in {:.1} ms",
            tiff_bytes.len(),
            png_len,
            elapsed_small.as_secs_f64() * 1000.0,
            hd_tiff.len() / 1024,
            hd_png.len() / 1024,
            hd_elapsed.as_secs_f64() * 1000.0
        );
    }

    // -------------------------------------------------------------------------
    // Test 4: All 7 sensitive / remote / echo-guard UTIs skipped via types() ONLY
    // -------------------------------------------------------------------------
    {
        let cases: &[(&str, SkipReason)] = &[
            (UTI_CONCEALED, SkipReason::ConcealedType),
            (UTI_TRANSIENT, SkipReason::TransientType),
            (UTI_AUTO_GENERATED, SkipReason::AutoGeneratedType),
            (UTI_ONEPASSWORD, SkipReason::OnePassword),
            (UTI_REMOTE_CLIPBOARD, SkipReason::UniversalClipboardRemote),
            (UTI_MYNOTE_SYNCED, SkipReason::SyncedByMynote),
            (UTI_MYNOTE_VAULT_SECRET, SkipReason::VaultSecret),
        ];

        for (uti, expected_reason) in cases {
            pb::write_item_representations(
                &[(UTI_UTF8_PLAIN_TEXT, "TOP-SECRET-DO-NOT-READ")],
                &[(uti, &[])],
                false,
            )?;
            let report = pb::read_pasteboard(ReadOptions::default())?;
            if report.outcome != ReadOutcome::Skipped(expected_reason.clone()) {
                return Err(format!(
                    "Test 4 failed for {uti}: expected Skipped({expected_reason:?}), got {:?} (observed types={:?})",
                    report.outcome, report.observed_types
                ));
            }
            if !report.stats.data_for_type_calls.is_empty() || !report.stats.string_for_type_calls.is_empty()
            {
                return Err(format!(
                    "Test 4 VIOLATION for {uti}: dataForType/stringForType called despite skip! stats={:?}",
                    report.stats
                ));
            }
        }

        // OS-level AppKit lazy-promise proof for `com.apple.is-remote-clipboard`.
        let (_provider, remote_invocations) = lazy_provider::write_item_with_lazy_promise(
            &[(UTI_REMOTE_CLIPBOARD, &[])],
            &[UTI_UTF8_PLAIN_TEXT],
            b"lazy-remote-payload".to_vec(),
            true,
        )?;
        let skipped = pb::read_pasteboard(ReadOptions::default())?;
        let count_after_skip = remote_invocations.load(Ordering::SeqCst);
        if skipped.outcome != ReadOutcome::Skipped(SkipReason::UniversalClipboardRemote)
            || count_after_skip != 0
        {
            return Err(format!(
                "Test 4 lazy remote proof failed: outcome={:?}, provider_invocations={count_after_skip}",
                skipped.outcome
            ));
        }

        let opt_in = pb::read_pasteboard(ReadOptions {
            ignore_universal_clipboard: false,
            skip_synced_marker: true,
        })?;
        let count_after_read = remote_invocations.load(Ordering::SeqCst);
        if opt_in.outcome != ReadOutcome::Payload(ClipPayload::Text("lazy-remote-payload".into()))
            || count_after_read != 1
        {
            return Err(format!(
                "Test 4 positive control failed: outcome={:?}, provider_invocations={count_after_read}",
                opt_in.outcome
            ));
        }

        println!(
            "[PASS] Test 4 (Sensitive + Remote UTI pre-check): 7/7 UTIs skipped with 0 dataForType/stringForType calls; AppKit lazy-promise invocations: skipped={count_after_skip}, positive-control={count_after_read}"
        );
    }

    // -------------------------------------------------------------------------
    // Test 5: Write markers (synced text, ephemeral sensitive text, synced PNG)
    // -------------------------------------------------------------------------
    {
        // 5a: Normal synced text (+ dev.mynote.synced-clip)
        pb::write_text(
            "synced from omarchy",
            WriteMarkers {
                synced_by_mynote: true,
                ephemeral_sensitive: false,
                current_host_only: false,
            },
        )?;
        let types_normal = pb::read_types();
        for req in [UTI_UTF8_PLAIN_TEXT, UTI_MYNOTE_SYNCED] {
            if !types_normal.iter().any(|t| t == req) {
                return Err(format!(
                    "Test 5a failed: missing {req} in independent types()={types_normal:?}"
                ));
            }
        }
        let watcher_check = pb::read_pasteboard(ReadOptions::default())?;
        if watcher_check.outcome != ReadOutcome::Skipped(SkipReason::SyncedByMynote) {
            return Err(format!(
                "Test 5a echo-guard failed: got {:?}",
                watcher_check.outcome
            ));
        }

        // 5b: Ephemeral sensitive text (+ synced-clip + TransientType + ConcealedType + CurrentHostOnly)
        pb::write_text(
            "ephemeral-otp-482910",
            WriteMarkers {
                synced_by_mynote: true,
                ephemeral_sensitive: true,
                current_host_only: true,
            },
        )?;
        let types_eph = pb::read_types();
        for req in [
            UTI_UTF8_PLAIN_TEXT,
            UTI_MYNOTE_SYNCED,
            UTI_TRANSIENT,
            UTI_CONCEALED,
        ] {
            if !types_eph.iter().any(|t| t == req) {
                return Err(format!(
                    "Test 5b failed: missing {req} in independent types()={types_eph:?}"
                ));
            }
        }

        // 5c: Synced PNG (+ dev.mynote.synced-clip)
        let png = img::encode_rgba_as(&img::make_test_rgba(24, 24, 3), ImageFormat::Png)?;
        pb::write_png(
            &png,
            WriteMarkers {
                synced_by_mynote: true,
                ephemeral_sensitive: false,
                current_host_only: false,
            },
        )?;
        let types_png = pb::read_types();
        for req in [UTI_PNG, UTI_MYNOTE_SYNCED] {
            if !types_png.iter().any(|t| t == req) {
                return Err(format!(
                    "Test 5c failed: missing {req} in independent types()={types_png:?}"
                ));
            }
        }
        let png_echo = pb::read_pasteboard(ReadOptions::default())?;
        if png_echo.outcome != ReadOutcome::Skipped(SkipReason::SyncedByMynote) {
            return Err(format!(
                "Test 5c PNG echo-guard failed: got {:?}",
                png_echo.outcome
            ));
        }

        // Bonus: SVG-only pasteboard item must never be treated as a bitmap image
        pb::write_item_representations(&[], &[(UTI_SVG, b"<svg><script>alert(1)</script></svg>")], false)?;
        let svg_res = pb::read_pasteboard(ReadOptions::default())?;
        if !matches!(
            svg_res.outcome,
            ReadOutcome::Skipped(SkipReason::UnsupportedTypes(_))
        ) || !svg_res.stats.data_for_type_calls.is_empty()
        {
            return Err(format!(
                "Bonus SVG guard failed: outcome={:?}, stats={:?}",
                svg_res.outcome, svg_res.stats
            ));
        }

        println!(
            "[PASS] Test 5 (Write markers): normal={types_normal:?}; ephemeral(CurrentHostOnly)={types_eph:?}; png={types_png:?}"
        );
        println!("[PASS] Bonus (SVG XSS guard): SVG-only item skipped with 0 dataForType calls");
    }

    drop(guard);
    println!("[Done] Restored original macOS pasteboard cleanly.");
    Ok(())
}
