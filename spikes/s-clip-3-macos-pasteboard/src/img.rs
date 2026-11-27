//! Image decoding, TIFF->PNG fallback transcoding, and bitmap normalization.
//!
//! Uses `image` crate with `default-features = false` and strictly the 5 bitmap
//! formats required by M4 (`png`, `jpeg`, `webp`, `gif`, `tiff`).

#[cfg(any(feature = "img-png-tiff", feature = "img-full"))]
use std::io::Cursor;

#[cfg(any(feature = "img-png-tiff", feature = "img-full"))]
use image::{ImageFormat, RgbaImage};

/// Transcode raw TIFF bytes into valid PNG bytes (`89 50 4E 47 0D 0A 1A 0A`).
#[cfg(any(feature = "img-png-tiff", feature = "img-full"))]
pub fn transcode_tiff_to_png(tiff_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let img = image::load_from_memory_with_format(tiff_bytes, ImageFormat::Tiff)
        .map_err(|e| format!("decode TIFF failed: {e}"))?;
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .map_err(|e| format!("encode PNG failed: {e}"))?;
    Ok(out)
}

/// Transcode any whitelisted bitmap format (`png`, `jpeg`, `webp`, `gif`, `tiff`) into PNG
/// for uniform desktop pasteboard writes (M4a-3: JPEG/WebP -> PNG before NSPasteboard write).
#[cfg(feature = "img-full")]
pub fn normalize_bitmap_to_png(bytes: &[u8], mime: &str) -> Result<(Vec<u8>, u32, u32), String> {
    let fmt = match mime {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        "image/webp" => ImageFormat::WebP,
        "image/gif" => ImageFormat::Gif,
        "image/tiff" => ImageFormat::Tiff,
        other => return Err(format!("rejected non-whitelisted image MIME: {other}")),
    };
    let img =
        image::load_from_memory_with_format(bytes, fmt).map_err(|e| format!("decode {mime} failed: {e}"))?;
    let (w, h) = (img.width(), img.height());
    if fmt == ImageFormat::Png {
        return Ok((bytes.to_vec(), w, h));
    }
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .map_err(|e| format!("encode PNG failed: {e}"))?;
    Ok((out, w, h))
}

/// Generate a compact JPEG/WebP thumbnail (<= 16 KiB target for DO metadata).
/// Included so LTO size measurement retains the actual M4a-3 encoding paths.
#[cfg(feature = "img-full")]
pub fn make_thumbnail_jpeg(png_or_bitmap: &[u8], max_dim: u32) -> Result<Vec<u8>, String> {
    let img = image::load_from_memory(png_or_bitmap)
        .map_err(|e| format!("decode image for thumbnail failed: {e}"))?;
    let thumb = img.thumbnail(max_dim, max_dim);
    let mut out = Vec::new();
    thumb
        .write_to(&mut Cursor::new(&mut out), ImageFormat::Jpeg)
        .map_err(|e| format!("encode JPEG thumbnail failed: {e}"))?;
    Ok(out)
}

/// Deterministic synthetic RGBA test image builder.
#[cfg(any(feature = "img-png-tiff", feature = "img-full"))]
pub fn make_test_rgba(width: u32, height: u32, seed: u8) -> RgbaImage {
    RgbaImage::from_fn(width, height, |x, y| {
        let r = ((x.wrapping_mul(7) + y.wrapping_mul(3) + seed as u32) & 0xFF) as u8;
        let g = ((x.wrapping_mul(11) ^ y.wrapping_mul(5) ^ (seed as u32 * 13)) & 0xFF) as u8;
        let b = ((x + y + seed as u32 * 29) & 0xFF) as u8;
        image::Rgba([r, g, b, 255])
    })
}

#[cfg(any(feature = "img-png-tiff", feature = "img-full"))]
pub fn encode_rgba_as(img: &RgbaImage, fmt: ImageFormat) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let dyn_img = image::DynamicImage::ImageRgba8(img.clone());
    dyn_img
        .write_to(&mut Cursor::new(&mut out), fmt)
        .map_err(|e| format!("encode {fmt:?} failed: {e}"))?;
    Ok(out)
}
