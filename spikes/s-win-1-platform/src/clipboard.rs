//! Win32 native clipboard & `HWND_MESSAGE` `WM_CLIPBOARDUPDATE` watcher (`SEC-WIN-CLIP`,
//! `docs/architecture-proposal.md` §5.7, `docs/threat-model.md` §10.1, `docs/eval-framework.md` §5):
//! - Event-driven zero-polling `HWND_MESSAGE` + `AddClipboardFormatListener` (`WM_CLIPBOARDUPDATE`);
//! - `OpenClipboard` UTF-16 (`CF_UNICODETEXT`) text read/write;
//! - Registered `"PNG"` format priority over `CF_DIBV5`, with `CF_DIBV5` (`BITMAPV5HEADER`) fallback
//!   lossless conversion to PNG;
//! - Strict SVG (`image/svg+xml` / `<svg` bytes) rejection in image channel;
//! - Hard-filtering `ExcludeClipboardContentFromMonitorProcessing` (presence),
//!   `CanIncludeInClipboardHistory == 0` (`DWORD == 0`), and
//!   `CanUploadClipboardDataToCloud == 0` (`DWORD == 0`) BEFORE reading user text/image payloads.

use image::{ImageFormat, ImageReader, RgbaImage};
use std::io::Cursor;

pub const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Registered Windows clipboard format names.
pub const FMT_NAME_PNG: &str = "PNG";
pub const FMT_NAME_SVG_MIME: &str = "image/svg+xml";
pub const FMT_NAME_SVG_SHORT: &str = "SVG";
pub const FMT_NAME_EXCLUDE_MONITOR: &str = "ExcludeClipboardContentFromMonitorProcessing";
pub const FMT_NAME_CAN_INCLUDE_HISTORY: &str = "CanIncludeInClipboardHistory";
pub const FMT_NAME_CAN_UPLOAD_CLOUD: &str = "CanUploadClipboardDataToCloud";
pub const FMT_NAME_MYNOTE_SYNCED: &str = "dev.mynote.synced-clip";

const BI_RGB_CONST: u32 = 0;
const BI_BITFIELDS_CONST: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WinClipPayload {
    Text(String),
    PngImage {
        png_bytes: Vec<u8>,
        width: u32,
        height: u32,
        from_dibv5_fallback: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WinClipReadOutcome {
    Payload(WinClipPayload),
    Empty,
    SkippedPrivacy(&'static str),
    SkippedEchoMarker,
    RejectedSvg(&'static str),
}

#[derive(Clone, Debug, Default)]
pub struct ClipboardReadTrace {
    pub enumerated_formats: Vec<(u32, String)>,
    pub get_clipboard_data_calls: Vec<u32>,
}

/// Detect whether raw bytes represent an SVG XML document (forbidden in bitmap image channel).
pub fn is_svg_bytes(bytes: &[u8]) -> bool {
    let prefix_len = bytes.len().min(1024);
    let Ok(head) = core::str::from_utf8(&bytes[..prefix_len]) else {
        return false;
    };
    let trimmed = head.trim_start_matches('\u{feff}').trim_start();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("<svg")
        || (lower.starts_with("<?xml") && lower.contains("<svg"))
        || lower.starts_with("<!doctype svg")
}

/// Evaluate a 4-byte Windows clipboard `DWORD` flag (`CanIncludeInClipboardHistory` /
/// `CanUploadClipboardDataToCloud`): returns `true` when `DWORD == 0` OR when the buffer is
/// malformed (`< 4` bytes, fail-closed).
pub fn is_dword_flag_zero_or_malformed(raw_bytes: &[u8]) -> bool {
    if raw_bytes.len() < 4 {
        return true;
    }
    let val = u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
    val == 0
}

/// Validate raw `"PNG"` clipboard bytes: reject SVG spoofing and verify PNG signature + dimensions.
pub fn validate_png_clipboard_bytes(bytes: &[u8]) -> Result<(u32, u32), String> {
    if is_svg_bytes(bytes) {
        return Err("disallowed SVG XML payload disguised inside PNG clipboard format".to_string());
    }
    if bytes.len() < 8 || bytes[..8] != PNG_MAGIC {
        return Err("clipboard PNG payload missing 8-byte PNG signature".to_string());
    }
    let reader = ImageReader::with_format(Cursor::new(bytes), ImageFormat::Png);
    reader
        .into_dimensions()
        .map_err(|e| format!("invalid PNG header dimensions: {e}"))
}

/// Construct a standard Win32 `CF_DIBV5` (`BITMAPV5HEADER`, 124-byte header, bottom-up 32-bpp BGRA)
/// byte buffer from an RGBA8 image for deterministic testing and Win32 clipboard writing.
pub fn rgba_to_dibv5_bytes(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    assert_eq!(rgba.len(), (width as usize) * (height as usize) * 4);
    let header_size = 124usize;
    let pixel_bytes = (width as usize) * (height as usize) * 4;
    let mut out = vec![0u8; header_size + pixel_bytes];

    out[0..4].copy_from_slice(&(header_size as u32).to_le_bytes()); // bV5Size = 124
    out[4..8].copy_from_slice(&(width as i32).to_le_bytes()); // bV5Width
    out[8..12].copy_from_slice(&(height as i32).to_le_bytes()); // bV5Height (>0 = bottom-up)
    out[12..14].copy_from_slice(&1u16.to_le_bytes()); // bV5Planes = 1
    out[14..16].copy_from_slice(&32u16.to_le_bytes()); // bV5BitCount = 32
    out[16..20].copy_from_slice(&BI_BITFIELDS_CONST.to_le_bytes()); // bV5Compression = BI_BITFIELDS
    out[20..24].copy_from_slice(&(pixel_bytes as u32).to_le_bytes()); // bV5SizeImage
    out[40..44].copy_from_slice(&0x00FF_0000u32.to_le_bytes()); // bV5RedMask
    out[44..48].copy_from_slice(&0x0000_FF00u32.to_le_bytes()); // bV5GreenMask
    out[48..52].copy_from_slice(&0x0000_00FFu32.to_le_bytes()); // bV5BlueMask
    out[52..56].copy_from_slice(&0xFF00_0000u32.to_le_bytes()); // bV5AlphaMask
    out[56..60].copy_from_slice(&0x7352_4742u32.to_le_bytes()); // LCS_sRGB ('sRGB')

    // Write bottom-up scanlines in BGRA order
    let row_bytes = (width as usize) * 4;
    for y in 0..(height as usize) {
        let src_row = (height as usize - 1 - y) * row_bytes;
        let dst_row = header_size + y * row_bytes;
        for x in 0..(width as usize) {
            let s = src_row + x * 4;
            let d = dst_row + x * 4;
            out[d] = rgba[s + 2]; // B
            out[d + 1] = rgba[s + 1]; // G
            out[d + 2] = rgba[s]; // R
            out[d + 3] = rgba[s + 3]; // A
        }
    }
    out
}

/// Convert raw Win32 `CF_DIBV5` (or `BITMAPINFOHEADER` / `BITMAPV4HEADER` DIB) memory into valid
/// PNG bytes `(png_bytes, width, height)`. Handles both bottom-up (`height > 0`) and top-down
/// (`height < 0`), 24-bpp & 32-bpp `BI_RGB` / `BI_BITFIELDS`, extra 12-byte GDI bitfield tables,
/// and legacy GDI all-zero alpha (`alpha_mask == 0` -> opaque `0xFF`).
pub fn dibv5_to_png(dib: &[u8]) -> Result<(Vec<u8>, u32, u32), String> {
    if is_svg_bytes(dib) {
        return Err("SVG XML rejected in DIB decoder".to_string());
    }
    if dib.len() < 40 {
        return Err(format!("DIB buffer too short ({} bytes < 40)", dib.len()));
    }
    let bi_size = u32::from_le_bytes(dib[0..4].try_into().unwrap()) as usize;
    if bi_size < 40 || dib.len() < bi_size {
        return Err(format!(
            "invalid DIB header size {bi_size} for buffer len {}",
            dib.len()
        ));
    }

    let width_i32 = i32::from_le_bytes(dib[4..8].try_into().unwrap());
    let height_i32 = i32::from_le_bytes(dib[8..12].try_into().unwrap());
    if width_i32 <= 0 || height_i32 == 0 || height_i32 == i32::MIN {
        return Err(format!("invalid DIB dimensions {width_i32}x{height_i32}"));
    }
    let width = width_i32 as u32;
    let bottom_up = height_i32 > 0;
    let height = height_i32.unsigned_abs();

    let planes = u16::from_le_bytes(dib[12..14].try_into().unwrap());
    let bit_count = u16::from_le_bytes(dib[14..16].try_into().unwrap());
    let compression = u32::from_le_bytes(dib[16..20].try_into().unwrap());
    let clr_used = u32::from_le_bytes(dib[32..36].try_into().unwrap()) as usize;

    if planes != 1 {
        return Err(format!("unsupported DIB planes={planes}"));
    }
    if !matches!(bit_count, 24 | 32) {
        return Err(format!(
            "unsupported DIB bit_count={bit_count} (expected 24 or 32)"
        ));
    }
    if !matches!(compression, BI_RGB_CONST | BI_BITFIELDS_CONST) {
        return Err(format!("unsupported DIB compression={compression}"));
    }

    let stride = ((width as usize) * (bit_count as usize)).div_ceil(32) * 4;
    let pixel_bytes = stride
        .checked_mul(height as usize)
        .ok_or_else(|| "DIB pixel buffer size overflow".to_string())?;

    let (r_mask, g_mask, b_mask, a_mask, pixel_offset) = if compression == BI_BITFIELDS_CONST {
        if bi_size >= 108 {
            let rm = u32::from_le_bytes(dib[40..44].try_into().unwrap());
            let gm = u32::from_le_bytes(dib[44..48].try_into().unwrap());
            let bm = u32::from_le_bytes(dib[48..52].try_into().unwrap());
            let am = u32::from_le_bytes(dib[52..56].try_into().unwrap());
            // Win32 GDI synthesized CF_DIBV5 sometimes appends a redundant 12-byte bmiColors mask
            // table after the 124-byte BITMAPV5HEADER (even with GlobalAlloc trailing padding).
            let base = bi_size + clr_used * 4;
            let off = if dib.len() >= base + 12 + pixel_bytes && dib[base..base + 12] == dib[40..52] {
                base + 12
            } else {
                base
            };
            (rm, gm, bm, am, off)
        } else {
            if dib.len() < bi_size + 12 {
                return Err("BITMAPINFOHEADER BI_BITFIELDS missing 12-byte masks".to_string());
            }
            let rm = u32::from_le_bytes(dib[bi_size..bi_size + 4].try_into().unwrap());
            let gm = u32::from_le_bytes(dib[bi_size + 4..bi_size + 8].try_into().unwrap());
            let bm = u32::from_le_bytes(dib[bi_size + 8..bi_size + 12].try_into().unwrap());
            (rm, gm, bm, 0, bi_size + 12 + clr_used * 4)
        }
    } else {
        let am = if bit_count == 32 && bi_size >= 108 {
            u32::from_le_bytes(dib[52..56].try_into().unwrap())
        } else {
            0
        };
        (0x00FF_0000, 0x0000_FF00, 0x0000_00FF, am, bi_size + clr_used * 4)
    };

    if dib.len() < pixel_offset + pixel_bytes {
        return Err(format!(
            "DIB truncated: len={} < offset({pixel_offset}) + pixels({pixel_bytes})",
            dib.len()
        ));
    }

    let pixels = &dib[pixel_offset..pixel_offset + pixel_bytes];
    let mut rgba = vec![0u8; (width as usize) * (height as usize) * 4];
    let mut any_nonzero_alpha = false;

    for out_y in 0..(height as usize) {
        let src_y = if bottom_up {
            height as usize - 1 - out_y
        } else {
            out_y
        };
        let row = &pixels[src_y * stride..(src_y + 1) * stride];
        let dst_row = out_y * (width as usize) * 4;
        if bit_count == 32 {
            for x in 0..(width as usize) {
                let px = u32::from_le_bytes(row[x * 4..x * 4 + 4].try_into().unwrap());
                let r = extract_masked_channel(px, r_mask);
                let g = extract_masked_channel(px, g_mask);
                let b = extract_masked_channel(px, b_mask);
                let a = if a_mask != 0 {
                    extract_masked_channel(px, a_mask)
                } else {
                    (px >> 24) as u8
                };
                if a != 0 {
                    any_nonzero_alpha = true;
                }
                let d = dst_row + x * 4;
                rgba[d] = r;
                rgba[d + 1] = g;
                rgba[d + 2] = b;
                rgba[d + 3] = a;
            }
        } else {
            for x in 0..(width as usize) {
                let s = x * 3;
                let d = dst_row + x * 4;
                rgba[d] = row[s + 2];
                rgba[d + 1] = row[s + 1];
                rgba[d + 2] = row[s];
                rgba[d + 3] = 0xFF;
            }
            any_nonzero_alpha = true;
        }
    }

    // Legacy GDI 32-bpp BI_RGB writers leave alpha byte 0x00 across all pixels when opaque.
    if bit_count == 32 && a_mask == 0 && !any_nonzero_alpha {
        for [_, _, _, a] in rgba.as_chunks_mut::<4>().0 {
            *a = 0xFF;
        }
    }

    let img = RgbaImage::from_raw(width, height, rgba)
        .ok_or_else(|| "failed constructing RgbaImage".to_string())?;
    let mut png_out = Vec::new();
    img.write_to(&mut Cursor::new(&mut png_out), ImageFormat::Png)
        .map_err(|e| format!("PNG encode failed: {e}"))?;
    Ok((png_out, width, height))
}

fn extract_masked_channel(pixel: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let max_val = mask >> shift;
    let raw = (pixel & mask) >> shift;
    if max_val == 0xFF {
        raw as u8
    } else {
        ((raw as u64 * 255 + (max_val as u64 / 2)) / (max_val as u64)) as u8
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::cell::RefCell;
    use std::io;
    use std::ptr;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot};
    use windows_sys::Win32::Foundation::{
        GetLastError, GlobalFree, ERROR_CLASS_ALREADY_EXISTS, HANDLE, HGLOBAL, HINSTANCE, HWND, LPARAM,
        LRESULT, WPARAM,
    };
    use windows_sys::Win32::System::DataExchange::{
        AddClipboardFormatListener, CloseClipboard, EmptyClipboard, EnumClipboardFormats, GetClipboardData,
        GetClipboardFormatNameW, GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW,
        RemoveClipboardFormatListener, SetClipboardData,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT,
    };
    use windows_sys::Win32::System::Ole::{CF_DIBV5, CF_UNICODETEXT};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostMessageW,
        PostQuitMessage, RegisterClassExW, TranslateMessage, HWND_MESSAGE, MSG, WM_CLIPBOARDUPDATE, WM_USER,
        WNDCLASSEXW,
    };

    const WM_APP_SHUTDOWN: u32 = WM_USER + 0x4D;

    #[derive(Clone, Copy, Debug)]
    pub struct RegisteredClipFormats {
        pub png: u32,
        pub svg_mime: u32,
        pub svg_short: u32,
        pub exclude_monitor: u32,
        pub can_include_history: u32,
        pub can_upload_cloud: u32,
        pub mynote_synced: u32,
    }

    pub fn register_clip_formats() -> io::Result<RegisteredClipFormats> {
        Ok(RegisteredClipFormats {
            png: register_format(FMT_NAME_PNG)?,
            svg_mime: register_format(FMT_NAME_SVG_MIME)?,
            svg_short: register_format(FMT_NAME_SVG_SHORT)?,
            exclude_monitor: register_format(FMT_NAME_EXCLUDE_MONITOR)?,
            can_include_history: register_format(FMT_NAME_CAN_INCLUDE_HISTORY)?,
            can_upload_cloud: register_format(FMT_NAME_CAN_UPLOAD_CLOUD)?,
            mynote_synced: register_format(FMT_NAME_MYNOTE_SYNCED)?,
        })
    }

    fn register_format(name: &str) -> io::Result<u32> {
        let wide: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        let id = unsafe { RegisterClipboardFormatW(wide.as_ptr()) };
        if id == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(id)
        }
    }

    struct OpenClipboardGuard;

    impl OpenClipboardGuard {
        fn open_with_retry() -> io::Result<Self> {
            let mut last_err = io::Error::other("OpenClipboard failed");
            for attempt in 0..15 {
                let ok = unsafe { OpenClipboard(ptr::null_mut()) };
                if ok != 0 {
                    return Ok(Self);
                }
                last_err = io::Error::last_os_error();
                if attempt < 14 {
                    thread::sleep(Duration::from_millis(5));
                }
            }
            Err(last_err)
        }
    }

    impl Drop for OpenClipboardGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }

    unsafe fn set_raw_clipboard_bytes(format: u32, bytes: &[u8]) -> io::Result<()> {
        let alloc_len = bytes.len().max(1);
        let hmem: HGLOBAL = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, alloc_len) };
        if hmem.is_null() {
            return Err(io::Error::last_os_error());
        }
        if !bytes.is_empty() {
            let dst = unsafe { GlobalLock(hmem) };
            if dst.is_null() {
                let err = io::Error::last_os_error();
                unsafe {
                    let _ = GlobalFree(hmem);
                }
                return Err(err);
            }
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), dst.cast::<u8>(), bytes.len());
                let _ = GlobalUnlock(hmem);
            }
        }
        let placed = unsafe { SetClipboardData(format, hmem as HANDLE) };
        if placed.is_null() {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = GlobalFree(hmem);
            }
            return Err(err);
        }
        // Ownership of `hmem` transferred to the system upon successful SetClipboardData.
        Ok(())
    }

    unsafe fn get_raw_clipboard_bytes(format: u32, trace: &mut ClipboardReadTrace) -> io::Result<Vec<u8>> {
        trace.get_clipboard_data_calls.push(format);
        let hdata = unsafe { GetClipboardData(format) };
        if hdata.is_null() {
            return Err(io::Error::last_os_error());
        }
        let hmem = hdata as HGLOBAL;
        let size = unsafe { GlobalSize(hmem) };
        if size == 0 {
            return Ok(Vec::new());
        }
        let ptr = unsafe { GlobalLock(hmem) };
        if ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        let out = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), size).to_vec() };
        unsafe {
            let _ = GlobalUnlock(hmem);
        }
        Ok(out)
    }

    fn format_debug_name(fmt: u32) -> String {
        if fmt == CF_UNICODETEXT as u32 {
            return "CF_UNICODETEXT".to_string();
        }
        if fmt == CF_DIBV5 as u32 {
            return "CF_DIBV5".to_string();
        }
        let mut buf = [0u16; 128];
        let len = unsafe { GetClipboardFormatNameW(fmt, buf.as_mut_ptr(), buf.len() as i32) };
        if len > 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            format!("CF_{fmt}")
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct WinClipWriteSpec {
        pub unicode_text: Option<String>,
        pub png_bytes: Option<Vec<u8>>,
        pub dibv5_bytes: Option<Vec<u8>>,
        pub svg_xml_bytes: Option<Vec<u8>>,
        pub exclude_from_monitor: bool,
        pub can_include_in_history: Option<u32>,
        pub can_upload_to_cloud: Option<u32>,
        pub mynote_synced_marker: bool,
    }

    /// Atomically clear and write multiple formats in a single `OpenClipboard` .. `CloseClipboard`
    /// transaction (matching macOS single `NSPasteboardItem` atomicity so clipboard monitors never
    /// observe unmarked intermediate state).
    pub fn write_win32_clipboard(spec: &WinClipWriteSpec) -> io::Result<()> {
        let fmts = register_clip_formats()?;
        let _guard = OpenClipboardGuard::open_with_retry()?;
        let ok = unsafe { EmptyClipboard() };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        // Place privacy / echo markers FIRST inside the atomic OpenClipboard transaction.
        if spec.mynote_synced_marker {
            unsafe { set_raw_clipboard_bytes(fmts.mynote_synced, &[1u8])? };
        }
        if spec.exclude_from_monitor {
            unsafe { set_raw_clipboard_bytes(fmts.exclude_monitor, &1u32.to_le_bytes())? };
        }
        if let Some(flag) = spec.can_include_in_history {
            unsafe { set_raw_clipboard_bytes(fmts.can_include_history, &flag.to_le_bytes())? };
        }
        if let Some(flag) = spec.can_upload_to_cloud {
            unsafe { set_raw_clipboard_bytes(fmts.can_upload_cloud, &flag.to_le_bytes())? };
        }
        if let Some(text) = &spec.unicode_text {
            let utf16: Vec<u16> = text.encode_utf16().chain(core::iter::once(0)).collect();
            let raw_bytes: &[u8] =
                unsafe { core::slice::from_raw_parts(utf16.as_ptr().cast::<u8>(), utf16.len() * 2) };
            unsafe { set_raw_clipboard_bytes(CF_UNICODETEXT as u32, raw_bytes)? };
        }
        if let Some(dib) = &spec.dibv5_bytes {
            unsafe { set_raw_clipboard_bytes(CF_DIBV5 as u32, dib)? };
        }
        if let Some(png) = &spec.png_bytes {
            unsafe { set_raw_clipboard_bytes(fmts.png, png)? };
        }
        if let Some(svg) = &spec.svg_xml_bytes {
            unsafe { set_raw_clipboard_bytes(fmts.svg_mime, svg)? };
        }
        Ok(())
    }

    /// Read the Win32 clipboard with full format-inspection trace:
    /// 1. Enumerate formats first (`EnumClipboardFormats`) without reading user payloads;
    /// 2. Hard-filter `dev.mynote.synced-clip`, `ExcludeClipboardContentFromMonitorProcessing`,
    ///    `CanIncludeInClipboardHistory == 0`, and `CanUploadClipboardDataToCloud == 0` BEFORE
    ///    touching `CF_UNICODETEXT`, `"PNG"`, or `CF_DIBV5`;
    /// 3. Prefer `"PNG"` over `CF_DIBV5`, fall back to `CF_DIBV5 -> PNG`, reject SVG, and read
    ///    `CF_UNICODETEXT` UTF-16 text.
    pub fn read_win32_clipboard_with_trace() -> io::Result<(WinClipReadOutcome, ClipboardReadTrace)> {
        let fmts = register_clip_formats()?;
        let _guard = OpenClipboardGuard::open_with_retry()?;
        let mut trace = ClipboardReadTrace::default();

        let mut cur = 0u32;
        loop {
            cur = unsafe { EnumClipboardFormats(cur) };
            if cur == 0 {
                break;
            }
            trace.enumerated_formats.push((cur, format_debug_name(cur)));
        }

        if trace.enumerated_formats.is_empty() {
            return Ok((WinClipReadOutcome::Empty, trace));
        }

        fn has_fmt(trace: &ClipboardReadTrace, target: u32) -> bool {
            trace.enumerated_formats.iter().any(|(id, _)| *id == target)
        }

        // 1. Echo guard marker check (zero user payload read)
        if has_fmt(&trace, fmts.mynote_synced) {
            return Ok((WinClipReadOutcome::SkippedEchoMarker, trace));
        }

        // 2. Presence-based privacy hard filter (zero GetClipboardData calls!)
        if has_fmt(&trace, fmts.exclude_monitor) {
            return Ok((
                WinClipReadOutcome::SkippedPrivacy("ExcludeClipboardContentFromMonitorProcessing"),
                trace,
            ));
        }

        // 3. DWORD == 0 privacy hard filters (reads ONLY the 4-byte flag, never user text/image!)
        if has_fmt(&trace, fmts.can_include_history) {
            let raw = unsafe { get_raw_clipboard_bytes(fmts.can_include_history, &mut trace)? };
            if is_dword_flag_zero_or_malformed(&raw) {
                return Ok((
                    WinClipReadOutcome::SkippedPrivacy("CanIncludeInClipboardHistory == 0"),
                    trace,
                ));
            }
        }
        if has_fmt(&trace, fmts.can_upload_cloud) {
            let raw = unsafe { get_raw_clipboard_bytes(fmts.can_upload_cloud, &mut trace)? };
            if is_dword_flag_zero_or_malformed(&raw) {
                return Ok((
                    WinClipReadOutcome::SkippedPrivacy("CanUploadClipboardDataToCloud == 0"),
                    trace,
                ));
            }
        }

        // 4. Image channel: strict `"PNG"` priority -> `CF_DIBV5` fallback -> SVG rejection
        if has_fmt(&trace, fmts.png) {
            let png_bytes = unsafe { get_raw_clipboard_bytes(fmts.png, &mut trace)? };
            if is_svg_bytes(&png_bytes) {
                return Ok((
                    WinClipReadOutcome::RejectedSvg("spoofed SVG XML inside PNG format"),
                    trace,
                ));
            }
            let (width, height) = validate_png_clipboard_bytes(&png_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok((
                WinClipReadOutcome::Payload(WinClipPayload::PngImage {
                    png_bytes,
                    width,
                    height,
                    from_dibv5_fallback: false,
                }),
                trace,
            ));
        }

        if has_fmt(&trace, CF_DIBV5 as u32) && !has_fmt(&trace, CF_UNICODETEXT as u32) {
            let dib_bytes = unsafe { get_raw_clipboard_bytes(CF_DIBV5 as u32, &mut trace)? };
            let (png_bytes, width, height) =
                dibv5_to_png(&dib_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok((
                WinClipReadOutcome::Payload(WinClipPayload::PngImage {
                    png_bytes,
                    width,
                    height,
                    from_dibv5_fallback: true,
                }),
                trace,
            ));
        }

        if (has_fmt(&trace, fmts.svg_mime) || has_fmt(&trace, fmts.svg_short))
            && !has_fmt(&trace, CF_UNICODETEXT as u32)
        {
            return Ok((WinClipReadOutcome::RejectedSvg("image/svg+xml"), trace));
        }

        // 5. Unicode text (`CF_UNICODETEXT`, UTF-16LE)
        if has_fmt(&trace, CF_UNICODETEXT as u32) {
            let raw = unsafe { get_raw_clipboard_bytes(CF_UNICODETEXT as u32, &mut trace)? };
            let u16_len = raw.len() / 2;
            let mut u16_buf = Vec::with_capacity(u16_len);
            for &[lo, hi] in raw.as_chunks::<2>().0 {
                let unit = u16::from_le_bytes([lo, hi]);
                if unit == 0 {
                    break;
                }
                u16_buf.push(unit);
            }
            let decoded =
                String::from_utf16(&u16_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok((WinClipReadOutcome::Payload(WinClipPayload::Text(decoded)), trace));
        }

        Ok((WinClipReadOutcome::Empty, trace))
    }

    #[derive(Clone, Copy, Debug)]
    pub struct ClipboardUpdateEvent {
        pub sequence_number: u32,
    }

    thread_local! {
        static THREAD_WATCHER_TX: RefCell<Option<mpsc::UnboundedSender<ClipboardUpdateEvent>>> =
            const { RefCell::new(None) };
    }

    unsafe extern "system" fn watcher_wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_CLIPBOARDUPDATE => {
                let seq = unsafe { GetClipboardSequenceNumber() };
                THREAD_WATCHER_TX.with(|slot| {
                    if let Some(tx) = slot.borrow().as_ref() {
                        let _ = tx.send(ClipboardUpdateEvent { sequence_number: seq });
                    }
                });
                0
            }
            WM_APP_SHUTDOWN => {
                unsafe {
                    let _ = RemoveClipboardFormatListener(hwnd);
                    let _ = DestroyWindow(hwnd);
                    PostQuitMessage(0);
                }
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    /// Event-driven zero-polling Win32 clipboard listener backed by a dedicated `HWND_MESSAGE`
    /// thread and `AddClipboardFormatListener` (`WM_CLIPBOARDUPDATE`).
    pub struct Win32ClipboardWatcher {
        hwnd_raw: usize,
        rx: mpsc::UnboundedReceiver<ClipboardUpdateEvent>,
        join: Option<JoinHandle<()>>,
    }

    impl Win32ClipboardWatcher {
        pub async fn start() -> io::Result<Self> {
            let (tx, rx) = mpsc::unbounded_channel();
            let (ready_tx, ready_rx) = oneshot::channel::<io::Result<usize>>();

            let join = thread::Builder::new()
                .name("mynote-win32-clip-watcher".to_string())
                .spawn(move || {
                    let hinstance: HINSTANCE = unsafe { GetModuleHandleW(ptr::null()) };
                    let class_name: Vec<u16> = "MyNoteSpikeClipWatcherClass\0".encode_utf16().collect();

                    let wc = WNDCLASSEXW {
                        cbSize: core::mem::size_of::<WNDCLASSEXW>() as u32,
                        lpfnWndProc: Some(watcher_wndproc),
                        hInstance: hinstance,
                        lpszClassName: class_name.as_ptr(),
                        ..Default::default()
                    };
                    let atom = unsafe { RegisterClassExW(&wc) };
                    if atom == 0 {
                        let err = unsafe { GetLastError() };
                        if err != ERROR_CLASS_ALREADY_EXISTS {
                            let _ = ready_tx.send(Err(io::Error::from_raw_os_error(err as i32)));
                            return;
                        }
                    }

                    THREAD_WATCHER_TX.with(|slot| {
                        *slot.borrow_mut() = Some(tx);
                    });

                    let hwnd = unsafe {
                        CreateWindowExW(
                            0,
                            class_name.as_ptr(),
                            ptr::null(),
                            0,
                            0,
                            0,
                            0,
                            0,
                            HWND_MESSAGE,
                            ptr::null_mut(),
                            hinstance,
                            ptr::null(),
                        )
                    };
                    if hwnd.is_null() {
                        let _ = ready_tx.send(Err(io::Error::last_os_error()));
                        return;
                    }

                    let added = unsafe { AddClipboardFormatListener(hwnd) };
                    if added == 0 {
                        let err = io::Error::last_os_error();
                        unsafe {
                            let _ = DestroyWindow(hwnd);
                        }
                        let _ = ready_tx.send(Err(err));
                        return;
                    }

                    let _ = ready_tx.send(Ok(hwnd as usize));

                    let mut msg: MSG = unsafe { core::mem::zeroed() };
                    loop {
                        let ret = unsafe { GetMessageW(&mut msg, ptr::null_mut(), 0, 0) };
                        if ret <= 0 {
                            break;
                        }
                        unsafe {
                            let _ = TranslateMessage(&msg);
                            DispatchMessageW(&msg);
                        }
                    }

                    THREAD_WATCHER_TX.with(|slot| {
                        *slot.borrow_mut() = None;
                    });
                })?;

            let hwnd_raw = ready_rx
                .await
                .map_err(|_| io::Error::other("watcher thread exited before ready"))??;

            Ok(Self {
                hwnd_raw,
                rx,
                join: Some(join),
            })
        }

        pub async fn next_event(&mut self) -> Option<ClipboardUpdateEvent> {
            self.rx.recv().await
        }

        pub fn stop(&mut self) {
            if let Some(join) = self.join.take() {
                unsafe {
                    let _ = PostMessageW(self.hwnd_raw as HWND, WM_APP_SHUTDOWN, 0, 0);
                }
                let _ = join.join();
            }
        }
    }

    impl Drop for Win32ClipboardWatcher {
        fn drop(&mut self) {
            self.stop();
        }
    }
}

#[cfg(windows)]
pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_dibv5_roundtrip_and_svg_privacy_guards() {
        // 4x3 RGBA pattern with translucent + opaque pixels
        let mut orig_rgba = Vec::with_capacity(4 * 3 * 4);
        for y in 0..3u8 {
            for x in 0..4u8 {
                orig_rgba.extend_from_slice(&[x * 60, y * 90, 200 - x * 30, 80 + y * 70]);
            }
        }
        let dib = rgba_to_dibv5_bytes(4, 3, &orig_rgba);
        let (png, w, h) = dibv5_to_png(&dib).expect("dibv5_to_png must succeed");
        assert_eq!((w, h), (4, 3));
        assert_eq!(&png[..8], &PNG_MAGIC);

        let decoded = ImageReader::with_format(Cursor::new(&png), ImageFormat::Png)
            .decode()
            .unwrap()
            .to_rgba8();
        assert_eq!(
            decoded.as_raw(),
            &orig_rgba,
            "RGBA pixels must roundtrip 100% losslessly"
        );

        assert!(is_svg_bytes(
            b"  <svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"
        ));
        assert!(is_svg_bytes(b"<?xml version='1.0'?><svg></svg>"));
        assert!(!is_svg_bytes(&png));

        assert!(is_dword_flag_zero_or_malformed(&0u32.to_le_bytes()));
        assert!(is_dword_flag_zero_or_malformed(&[0, 0])); // malformed < 4B fails closed
        assert!(!is_dword_flag_zero_or_malformed(&1u32.to_le_bytes()));
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn win_sec_clip_watcher_formats_and_privacy_filters() {
        use std::time::Instant;
        use tokio::sync::Mutex;

        static CLIP_LOCK: Mutex<()> = Mutex::const_new(());
        let _serial = CLIP_LOCK.lock().await;

        let mut watcher = Win32ClipboardWatcher::start()
            .await
            .expect("start HWND_MESSAGE WM_CLIPBOARDUPDATE watcher");

        // Drain any stale startup notifications
        while tokio::time::timeout(std::time::Duration::from_millis(20), watcher.next_event())
            .await
            .is_ok()
        {}

        // 1. UTF-16 text write + WM_CLIPBOARDUPDATE event + lossless readback
        let sample_text = "Hello Windows 剪贴板 🚀🔒 — line 1\n第二行 UTF-16 无损测试";
        let t_write = Instant::now();
        write_win32_clipboard(&WinClipWriteSpec {
            unicode_text: Some(sample_text.to_string()),
            ..Default::default()
        })
        .expect("write UTF-16 text to clipboard");

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), watcher.next_event())
            .await
            .expect("WM_CLIPBOARDUPDATE must fire within 2s")
            .expect("watcher channel open");
        let notify_us = t_write.elapsed().as_secs_f64() * 1_000_000.0;
        let (outcome, trace) = read_win32_clipboard_with_trace().expect("read UTF-16 text");
        println!(
            "[S-Win-1][CLIP] UTF-16 text + WM_CLIPBOARDUPDATE: seq={} notify_latency={:.1}us formats={:?}",
            ev.sequence_number, notify_us, trace.enumerated_formats
        );
        assert_eq!(
            outcome,
            WinClipReadOutcome::Payload(WinClipPayload::Text(sample_text.to_string()))
        );

        // 2. `"PNG"` priority over larger `CF_DIBV5` (0 reads of CF_DIBV5!)
        let small_red_rgba = vec![
            255, 0, 0, 255, 0, 255, 0, 255, // row 0
            0, 0, 255, 255, 255, 255, 0, 128, // row 1
        ];
        let mut png_2x2 = Vec::new();
        RgbaImage::from_raw(2, 2, small_red_rgba.clone())
            .unwrap()
            .write_to(&mut Cursor::new(&mut png_2x2), ImageFormat::Png)
            .unwrap();
        let larger_blue_dib = rgba_to_dibv5_bytes(16, 16, &[10u8; 16 * 16 * 4]);

        write_win32_clipboard(&WinClipWriteSpec {
            png_bytes: Some(png_2x2.clone()),
            dibv5_bytes: Some(larger_blue_dib),
            ..Default::default()
        })
        .expect("write PNG + CF_DIBV5");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), watcher.next_event())
            .await
            .expect("WM_CLIPBOARDUPDATE for PNG");

        let fmts = register_clip_formats().unwrap();
        let (outcome_png, trace_png) = read_win32_clipboard_with_trace().expect("read PNG");
        println!(
            "[S-Win-1][CLIP] PNG + CF_DIBV5 priority: get_data_calls={:?} enumerated={:?}",
            trace_png.get_clipboard_data_calls, trace_png.enumerated_formats
        );
        assert_eq!(
            trace_png.get_clipboard_data_calls,
            vec![fmts.png],
            "reader MUST fetch only registered 'PNG' format and NEVER read CF_DIBV5 when PNG is present"
        );
        assert_eq!(
            outcome_png,
            WinClipReadOutcome::Payload(WinClipPayload::PngImage {
                png_bytes: png_2x2,
                width: 2,
                height: 2,
                from_dibv5_fallback: false,
            })
        );

        // 3. `CF_DIBV5` fallback conversion to PNG (when `"PNG"` is absent) + 1080p transcode timing
        let fallback_rgba: Vec<u8> = (0..(8 * 6))
            .flat_map(|i| [(i * 5) as u8, (255 - i * 4) as u8, (i * 3 + 17) as u8, 255u8])
            .collect();
        let fallback_dib = rgba_to_dibv5_bytes(8, 6, &fallback_rgba);
        write_win32_clipboard(&WinClipWriteSpec {
            dibv5_bytes: Some(fallback_dib),
            ..Default::default()
        })
        .expect("write CF_DIBV5 only");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), watcher.next_event())
            .await
            .expect("WM_CLIPBOARDUPDATE for CF_DIBV5");

        let (outcome_dib, trace_dib) = read_win32_clipboard_with_trace().expect("read CF_DIBV5 fallback");
        println!(
            "[S-Win-1][CLIP] CF_DIBV5 fallback: enumerated={:?} get_data_calls={:?}",
            trace_dib.enumerated_formats, trace_dib.get_clipboard_data_calls
        );
        match outcome_dib {
            WinClipReadOutcome::Payload(WinClipPayload::PngImage {
                png_bytes,
                width,
                height,
                from_dibv5_fallback,
            }) => {
                assert_eq!((width, height), (8, 6));
                assert!(from_dibv5_fallback);
                let decoded = ImageReader::with_format(Cursor::new(&png_bytes), ImageFormat::Png)
                    .decode()
                    .unwrap()
                    .to_rgba8();
                assert_eq!(decoded.as_raw(), &fallback_rgba);
            }
            other => panic!("expected PngImage fallback, got {other:?}"),
        }

        // Measure 1920x1080 (~8.29 MiB) CF_DIBV5 -> PNG transcode across 5 runs
        let hd_rgba: Vec<u8> = (0..(1920 * 1080 * 4)).map(|i| (i & 0xFF) as u8).collect();
        let hd_dib = rgba_to_dibv5_bytes(1920, 1080, &hd_rgba);
        let mut hd_ms = Vec::new();
        let mut hd_png_len = 0usize;
        for _ in 0..5 {
            let t0 = Instant::now();
            let (p, w, h) = dibv5_to_png(&hd_dib).unwrap();
            hd_ms.push(t0.elapsed().as_secs_f64() * 1_000.0);
            hd_png_len = p.len();
            assert_eq!((w, h), (1920, 1080));
        }
        hd_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "[S-Win-1][CLIP] 1920x1080 CF_DIBV5 ({} B) -> PNG ({} B) 5-run median={:.2}ms (range {:.2}..{:.2}ms)",
            hd_dib.len(),
            hd_png_len,
            hd_ms[2],
            hd_ms[0],
            hd_ms[4]
        );

        // 4. SVG rejection (`image/svg+xml` format AND spoofed SVG bytes inside `"PNG"`)
        let malicious_svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"></svg>".to_vec();
        write_win32_clipboard(&WinClipWriteSpec {
            svg_xml_bytes: Some(malicious_svg.clone()),
            ..Default::default()
        })
        .expect("write SVG format");
        let (svg_out1, svg_trace1) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(svg_out1, WinClipReadOutcome::RejectedSvg("image/svg+xml"));
        assert!(
            svg_trace1.get_clipboard_data_calls.is_empty(),
            "image/svg+xml format must be rejected at format check with 0 GetClipboardData calls"
        );

        write_win32_clipboard(&WinClipWriteSpec {
            png_bytes: Some(malicious_svg),
            ..Default::default()
        })
        .expect("write spoofed SVG inside PNG slot");
        let (svg_out2, _) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(
            svg_out2,
            WinClipReadOutcome::RejectedSvg("spoofed SVG XML inside PNG format")
        );
        println!("[S-Win-1][CLIP] SVG rejection PASS (both image/svg+xml and spoofed PNG slot)");

        // 5. Privacy hard-filtering: ExcludeClipboardContentFromMonitorProcessing,
        //    CanIncludeInClipboardHistory == 0, CanUploadClipboardDataToCloud == 0
        //    (plus positive control == 1 and mynote echo marker)
        write_win32_clipboard(&WinClipWriteSpec {
            unicode_text: Some("1password-master-secret".to_string()),
            exclude_from_monitor: true,
            ..Default::default()
        })
        .unwrap();
        let (priv1, ptrace1) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(
            priv1,
            WinClipReadOutcome::SkippedPrivacy("ExcludeClipboardContentFromMonitorProcessing")
        );
        assert!(
            ptrace1.get_clipboard_data_calls.is_empty(),
            "ExcludeClipboardContentFromMonitorProcessing MUST do 0 GetClipboardData calls"
        );

        write_win32_clipboard(&WinClipWriteSpec {
            unicode_text: Some("bitwarden-totp-000000".to_string()),
            can_include_in_history: Some(0),
            ..Default::default()
        })
        .unwrap();
        let (priv2, ptrace2) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(
            priv2,
            WinClipReadOutcome::SkippedPrivacy("CanIncludeInClipboardHistory == 0")
        );
        assert_eq!(
            ptrace2.get_clipboard_data_calls,
            vec![fmts.can_include_history],
            "must NOT touch CF_UNICODETEXT when CanIncludeInClipboardHistory == 0"
        );

        write_win32_clipboard(&WinClipWriteSpec {
            unicode_text: Some("local-only-token".to_string()),
            can_upload_to_cloud: Some(0),
            ..Default::default()
        })
        .unwrap();
        let (priv3, ptrace3) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(
            priv3,
            WinClipReadOutcome::SkippedPrivacy("CanUploadClipboardDataToCloud == 0")
        );
        assert_eq!(
            ptrace3.get_clipboard_data_calls,
            vec![fmts.can_upload_cloud],
            "must NOT touch CF_UNICODETEXT when CanUploadClipboardDataToCloud == 0"
        );

        // Positive control: DWORD == 1 explicitly allows history & cloud sync
        write_win32_clipboard(&WinClipWriteSpec {
            unicode_text: Some("explicitly-allowed-note".to_string()),
            can_include_in_history: Some(1),
            can_upload_to_cloud: Some(1),
            ..Default::default()
        })
        .unwrap();
        let (allowed_out, _) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(
            allowed_out,
            WinClipReadOutcome::Payload(WinClipPayload::Text("explicitly-allowed-note".to_string()))
        );

        // Echo marker `dev.mynote.synced-clip` skips with 0 payload reads
        write_win32_clipboard(&WinClipWriteSpec {
            unicode_text: Some("synced-from-mac".to_string()),
            mynote_synced_marker: true,
            ..Default::default()
        })
        .unwrap();
        let (echo_out, echo_trace) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(echo_out, WinClipReadOutcome::SkippedEchoMarker);
        assert!(echo_trace.get_clipboard_data_calls.is_empty());

        println!(
            "[S-Win-1][CLIP] All 3 Windows privacy formats + positive DWORD=1 control + echo marker PASS"
        );
        watcher.stop();
    }
}
