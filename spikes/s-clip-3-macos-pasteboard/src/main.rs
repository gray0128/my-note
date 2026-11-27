//! Production-equivalent apples-to-apples probe binary for Spike S-Clip-3.
//!
//! Exercises the exact same pasteboard and image code paths across `backend-objc2-raw`
//! and `backend-objc2-typed` so stripped `lto = "thin"` release binary sizes have zero
//! dead-code-elimination or test-harness skew.

use std::env;

#[allow(unused_imports)]
use s_clip_3_macos_pasteboard::types::{ReadOptions, WriteMarkers, PNG_MAGIC};

fn main() {
    let cmd = env::args().nth(1).unwrap_or_else(|| "info".to_string());
    match cmd.as_str() {
        "info" => {
            println!("s-clip-3-macos-pasteboard");
            #[cfg(feature = "backend-objc2-typed")]
            println!("  backend: objc2-typed (objc2-app-kit + objc2-foundation surgical)");
            #[cfg(all(feature = "backend-objc2-raw", not(feature = "backend-objc2-typed")))]
            println!("  backend: objc2-raw (minimal objc2 + msg_send!)");
            #[cfg(not(any(feature = "backend-objc2-typed", feature = "backend-objc2-raw")))]
            println!("  backend: none (baseline)");
            #[cfg(feature = "img-full")]
            println!("  image: full (png, jpeg, webp, gif, tiff)");
            #[cfg(all(feature = "img-png-tiff", not(feature = "img-full")))]
            println!("  image: png+tiff only");
            #[cfg(not(any(feature = "img-png-tiff", feature = "img-full")))]
            println!("  image: none");
        }
        "probe" => run_probe(),
        other => {
            eprintln!("usage: s-clip-3-macos-pasteboard [info | probe] (got {other})");
            std::process::exit(2);
        }
    }
}

fn run_probe() {
    #[cfg(feature = "backend-objc2-typed")]
    {
        use s_clip_3_macos_pasteboard::typed_objc2 as pb;
        let cc = pb::change_count();
        let types = pb::read_types();
        let report = pb::read_pasteboard(ReadOptions::default());
        println!(
            "typed probe: changeCount={cc}, types={types:?}, outcome_ok={}",
            report.is_ok()
        );
        if env::var_os("MYNOTE_SPIKE_DO_WRITE").is_some() {
            let _ = pb::write_text(
                "probe",
                WriteMarkers {
                    synced_by_mynote: true,
                    ephemeral_sensitive: true,
                    current_host_only: true,
                },
            );
            let _ = pb::write_png(&PNG_MAGIC, WriteMarkers::default());
        }
    }

    #[cfg(all(feature = "backend-objc2-raw", not(feature = "backend-objc2-typed")))]
    {
        use s_clip_3_macos_pasteboard::raw_objc2 as pb;
        let cc = pb::change_count();
        let types = pb::read_types();
        let report = pb::read_pasteboard(ReadOptions::default());
        println!(
            "raw probe: changeCount={cc}, types={types:?}, outcome_ok={}",
            report.is_ok()
        );
        if env::var_os("MYNOTE_SPIKE_DO_WRITE").is_some() {
            let _ = pb::write_text(
                "probe",
                WriteMarkers {
                    synced_by_mynote: true,
                    ephemeral_sensitive: true,
                    current_host_only: true,
                },
            );
            let _ = pb::write_png(&PNG_MAGIC, WriteMarkers::default());
        }
    }

    #[cfg(any(feature = "img-png-tiff", feature = "img-full"))]
    {
        use image::ImageFormat;
        use s_clip_3_macos_pasteboard::img;

        let rgba = img::make_test_rgba(32, 32, 1);
        let tiff = img::encode_rgba_as(&rgba, ImageFormat::Tiff).expect("encode tiff");
        let png = img::transcode_tiff_to_png(&tiff).expect("tiff->png");
        let decoded = image::load_from_memory_with_format(&png, ImageFormat::Png)
            .expect("decode png")
            .to_rgba8();
        println!(
            "image probe: tiff={}B -> png={}B ({}x{})",
            tiff.len(),
            png.len(),
            decoded.width(),
            decoded.height()
        );

        #[cfg(feature = "img-full")]
        {
            let jpg = img::encode_rgba_as(&rgba, ImageFormat::Jpeg).expect("encode jpeg");
            let webp = img::encode_rgba_as(&rgba, ImageFormat::WebP).expect("encode webp");
            let gif = img::encode_rgba_as(&rgba, ImageFormat::Gif).expect("encode gif");
            let (p1, _, _) = img::normalize_bitmap_to_png(&jpg, "image/jpeg").expect("jpg->png");
            let (p2, _, _) = img::normalize_bitmap_to_png(&webp, "image/webp").expect("webp->png");
            let (p3, _, _) = img::normalize_bitmap_to_png(&gif, "image/gif").expect("gif->png");
            let thumb = img::make_thumbnail_jpeg(&png, 16).expect("thumb");
            println!(
                "image full codecs live: jpg->png={}B, webp->png={}B, gif->png={}B, thumb={}B",
                p1.len(),
                p2.len(),
                p3.len(),
                thumb.len()
            );
        }
    }
}
