//! Real macOS `NSPasteboard.generalPasteboard()` integration tests (Spike S-Clip-3).
//!
//! Uses a global Mutex + RAII `ClipboardRestoreGuard` so the host clipboard is always
//! snapshotted before and restored after every test, even under default parallel `cargo test`.

#![cfg(all(target_os = "macos", feature = "backend-objc2-typed", feature = "img-full"))]

use std::sync::atomic::Ordering;
use std::sync::Mutex;

use image::ImageFormat;
use s_clip_3_macos_pasteboard::img;
use s_clip_3_macos_pasteboard::typed_objc2::{self as pb, lazy_provider, ClipboardRestoreGuard};
use s_clip_3_macos_pasteboard::types::{
    ClipPayload, ReadOptions, ReadOutcome, SkipReason, WriteMarkers, PNG_MAGIC, UTI_AUTO_GENERATED,
    UTI_CONCEALED, UTI_MYNOTE_SYNCED, UTI_MYNOTE_VAULT_SECRET, UTI_ONEPASSWORD, UTI_PNG,
    UTI_REMOTE_CLIPBOARD, UTI_SVG, UTI_TIFF, UTI_TRANSIENT, UTI_UTF8_PLAIN_TEXT,
};

static PASTEBOARD_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_1_utf8_text_roundtrip_and_change_count() {
    let _lock = PASTEBOARD_LOCK.lock().unwrap();
    let _guard = ClipboardRestoreGuard::capture();

    let before = pb::change_count();
    let expected = "my-note S-Clip-3 UTF-8 测试 🚀\nline 2";
    let after = pb::write_text(expected, WriteMarkers::default()).expect("write_text");
    assert!(
        after > before,
        "changeCount must increment (before={before}, after={after})"
    );

    let report = pb::read_pasteboard(ReadOptions::default()).expect("read_pasteboard");
    assert_eq!(report.change_count, after);
    assert_eq!(
        report.outcome,
        ReadOutcome::Payload(ClipPayload::Text(expected.into()))
    );
    assert_eq!(report.stats.types_queries, 1);
    assert_eq!(report.stats.string_for_type_calls, vec![UTI_UTF8_PLAIN_TEXT]);
    assert!(report.stats.data_for_type_calls.is_empty());
}

#[test]
fn test_2_png_preferred_over_larger_tiff_without_reading_tiff() {
    let _lock = PASTEBOARD_LOCK.lock().unwrap();
    let _guard = ClipboardRestoreGuard::capture();

    let small_png = img::encode_rgba_as(&img::make_test_rgba(16, 16, 5), ImageFormat::Png).unwrap();
    let large_tiff = img::encode_rgba_as(&img::make_test_rgba(128, 128, 88), ImageFormat::Tiff).unwrap();
    assert!(large_tiff.len() > small_png.len() * 10);

    // Advertise TIFF first AND PNG second on the same NSPasteboardItem.
    pb::write_item_representations(&[], &[(UTI_TIFF, &large_tiff), (UTI_PNG, &small_png)], false).unwrap();

    let types = pb::read_types();
    assert!(types.iter().any(|t| t == UTI_PNG));
    assert!(types.iter().any(|t| t == UTI_TIFF));

    let report = pb::read_pasteboard(ReadOptions::default()).unwrap();
    assert_eq!(
        report.stats.data_for_type_calls,
        vec![UTI_PNG],
        "must read ONLY public.png and never public.tiff"
    );
    assert!(report.stats.string_for_type_calls.is_empty());
    assert_eq!(
        report.outcome,
        ReadOutcome::Payload(ClipPayload::Image {
            mime: "image/png",
            bytes: small_png.clone(),
            source_uti: UTI_PNG,
            transcoded_to_png: false,
        })
    );

    // OS-level lazy promise proof: eager public.png + promised public.tiff -> 0 TIFF provider calls.
    let (_provider, tiff_calls) =
        lazy_provider::write_item_with_lazy_promise(&[(UTI_PNG, &small_png)], &[UTI_TIFF], large_tiff, false)
            .unwrap();
    let lazy_report = pb::read_pasteboard(ReadOptions::default()).unwrap();
    assert_eq!(tiff_calls.load(Ordering::SeqCst), 0);
    assert_eq!(lazy_report.stats.data_for_type_calls, vec![UTI_PNG]);
}

#[test]
fn test_3_tiff_only_fallback_transcodes_to_valid_png() {
    let _lock = PASTEBOARD_LOCK.lock().unwrap();
    let _guard = ClipboardRestoreGuard::capture();

    let src = img::make_test_rgba(64, 48, 21);
    let tiff_bytes = img::encode_rgba_as(&src, ImageFormat::Tiff).unwrap();

    pb::write_item_representations(&[], &[(UTI_TIFF, &tiff_bytes)], false).unwrap();
    let types = pb::read_types();
    assert!(!types.iter().any(|t| t == UTI_PNG));
    assert!(types.iter().any(|t| t == UTI_TIFF));

    let report = pb::read_pasteboard(ReadOptions::default()).unwrap();
    assert_eq!(report.stats.data_for_type_calls, vec![UTI_TIFF]);
    match report.outcome {
        ReadOutcome::Payload(ClipPayload::Image {
            mime,
            bytes,
            source_uti,
            transcoded_to_png,
        }) => {
            assert_eq!(mime, "image/png");
            assert_eq!(source_uti, UTI_TIFF);
            assert!(transcoded_to_png);
            assert!(bytes.starts_with(&PNG_MAGIC), "must start with PNG magic");
            let decoded = image::load_from_memory_with_format(&bytes, ImageFormat::Png)
                .expect("valid PNG")
                .to_rgba8();
            assert_eq!(decoded.dimensions(), (64, 48));
            assert_eq!(decoded.as_raw(), src.as_raw());
        }
        other => panic!("expected transcoded PNG image, got {other:?}"),
    }
}

#[test]
fn test_4_sensitive_and_remote_utis_skipped_without_reading_payload() {
    let _lock = PASTEBOARD_LOCK.lock().unwrap();
    let _guard = ClipboardRestoreGuard::capture();

    let cases = [
        (UTI_CONCEALED, SkipReason::ConcealedType),
        (UTI_TRANSIENT, SkipReason::TransientType),
        (UTI_AUTO_GENERATED, SkipReason::AutoGeneratedType),
        (UTI_ONEPASSWORD, SkipReason::OnePassword),
        (UTI_REMOTE_CLIPBOARD, SkipReason::UniversalClipboardRemote),
        (UTI_MYNOTE_SYNCED, SkipReason::SyncedByMynote),
        (UTI_MYNOTE_VAULT_SECRET, SkipReason::VaultSecret),
    ];

    for (uti, expected) in cases {
        pb::write_item_representations(
            &[(UTI_UTF8_PLAIN_TEXT, "secret-must-not-be-read")],
            &[(uti, &[])],
            false,
        )
        .unwrap();

        let report = pb::read_pasteboard(ReadOptions::default()).unwrap();
        assert_eq!(
            report.outcome,
            ReadOutcome::Skipped(expected),
            "UTI {uti} must be skipped at pre-check"
        );
        assert_eq!(report.stats.types_queries, 1);
        assert!(
            report.stats.data_for_type_calls.is_empty(),
            "UTI {uti} must not invoke dataForType"
        );
        assert!(
            report.stats.string_for_type_calls.is_empty(),
            "UTI {uti} must not invoke stringForType"
        );
    }

    // OS-level AppKit lazy-promise proof for `com.apple.is-remote-clipboard`:
    let (_provider, calls) = lazy_provider::write_item_with_lazy_promise(
        &[(UTI_REMOTE_CLIPBOARD, &[])],
        &[UTI_UTF8_PLAIN_TEXT],
        b"remote-iphone-text".to_vec(),
        true,
    )
    .unwrap();
    let skipped = pb::read_pasteboard(ReadOptions::default()).unwrap();
    assert_eq!(
        skipped.outcome,
        ReadOutcome::Skipped(SkipReason::UniversalClipboardRemote)
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "AppKit must NOT invoke provideDataForType when skipping via types()"
    );

    // Positive control: explicitly opting in DOES trigger provideDataForType once.
    let read_opt_in = pb::read_pasteboard(ReadOptions {
        ignore_universal_clipboard: false,
        skip_synced_marker: true,
    })
    .unwrap();
    assert_eq!(
        read_opt_in.outcome,
        ReadOutcome::Payload(ClipPayload::Text("remote-iphone-text".into()))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn test_5_write_markers_visible_on_independent_read() {
    let _lock = PASTEBOARD_LOCK.lock().unwrap();
    let _guard = ClipboardRestoreGuard::capture();

    // 5a: Normal synced text
    pb::write_text(
        "synced-hello",
        WriteMarkers {
            synced_by_mynote: true,
            ephemeral_sensitive: false,
            current_host_only: false,
        },
    )
    .unwrap();
    let types = pb::read_types();
    assert!(types.iter().any(|t| t == UTI_UTF8_PLAIN_TEXT));
    assert!(types.iter().any(|t| t == UTI_MYNOTE_SYNCED));
    assert_eq!(
        pb::read_pasteboard(ReadOptions::default()).unwrap().outcome,
        ReadOutcome::Skipped(SkipReason::SyncedByMynote)
    );

    // 5b: Ephemeral sensitive text (+ TransientType + ConcealedType + CurrentHostOnly)
    pb::write_text(
        "otp-123456",
        WriteMarkers {
            synced_by_mynote: true,
            ephemeral_sensitive: true,
            current_host_only: true,
        },
    )
    .unwrap();
    let eph_types = pb::read_types();
    assert!(eph_types.iter().any(|t| t == UTI_UTF8_PLAIN_TEXT));
    assert!(eph_types.iter().any(|t| t == UTI_MYNOTE_SYNCED));
    assert!(eph_types.iter().any(|t| t == UTI_TRANSIENT));
    assert!(eph_types.iter().any(|t| t == UTI_CONCEALED));

    // 5c: Synced PNG image
    let png = img::encode_rgba_as(&img::make_test_rgba(20, 20, 9), ImageFormat::Png).unwrap();
    pb::write_png(
        &png,
        WriteMarkers {
            synced_by_mynote: true,
            ephemeral_sensitive: false,
            current_host_only: false,
        },
    )
    .unwrap();
    let png_types = pb::read_types();
    assert!(png_types.iter().any(|t| t == UTI_PNG));
    assert!(png_types.iter().any(|t| t == UTI_MYNOTE_SYNCED));
    assert_eq!(
        pb::read_pasteboard(ReadOptions::default()).unwrap().outcome,
        ReadOutcome::Skipped(SkipReason::SyncedByMynote)
    );
}

#[test]
fn test_bonus_svg_is_never_read_as_bitmap_image() {
    let _lock = PASTEBOARD_LOCK.lock().unwrap();
    let _guard = ClipboardRestoreGuard::capture();

    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
    pb::write_item_representations(&[], &[(UTI_SVG, svg)], false).unwrap();
    let report = pb::read_pasteboard(ReadOptions::default()).unwrap();
    assert!(
        matches!(
            report.outcome,
            ReadOutcome::Skipped(SkipReason::UnsupportedTypes(_))
        ),
        "SVG-only pasteboard item must never be treated as a bitmap image"
    );
    assert!(report.stats.data_for_type_calls.is_empty());

    // Confirm image normalization rejects image/svg+xml explicitly.
    assert!(img::normalize_bitmap_to_png(svg, "image/svg+xml").is_err());
}
