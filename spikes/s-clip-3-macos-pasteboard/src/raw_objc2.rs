//! Minimal `objc2`-only backend (no `objc2-app-kit` / `objc2-foundation` wrapper crates).
//! Used strictly to quantify the binary-size and compile-time delta against `objc2-app-kit`
//! with surgical feature gates.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::AnyObject;
use objc2::{class, msg_send};

use crate::types::{
    precheck_sensitive_uti, select_source_uti, ClipPayload, ReadOptions, ReadOutcome, ReadReport, ReadStats,
    SelectedSource, SkipReason, WriteMarkers, UTI_CONCEALED, UTI_GIF, UTI_JPEG, UTI_MYNOTE_SYNCED, UTI_PNG,
    UTI_TIFF, UTI_TRANSIENT, UTI_UTF8_PLAIN_TEXT, UTI_WEBP,
};

#[link(name = "Foundation", kind = "framework")]
extern "C" {}

#[link(name = "AppKit", kind = "framework")]
extern "C" {}

unsafe fn nsstring_from_str(s: &str) -> Retained<AnyObject> {
    let c = CString::new(s).expect("UTI/text contains interior NUL");
    let obj: Option<Retained<AnyObject>> = msg_send![class!(NSString), stringWithUTF8String: c.as_ptr()];
    obj.expect("NSString stringWithUTF8String returned nil")
}

unsafe fn nsstring_to_string(obj: &AnyObject) -> String {
    let ptr: *const c_char = msg_send![obj, UTF8String];
    if ptr.is_null() {
        String::new()
    } else {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

unsafe fn nsdata_from_bytes(bytes: &[u8]) -> Retained<AnyObject> {
    let obj: Option<Retained<AnyObject>> =
        msg_send![class!(NSData), dataWithBytes: bytes.as_ptr(), length: bytes.len()];
    obj.expect("NSData dataWithBytes:length: returned nil")
}

unsafe fn nsdata_to_vec(obj: &AnyObject) -> Vec<u8> {
    let len: usize = msg_send![obj, length];
    if len == 0 {
        return Vec::new();
    }
    let ptr: *const u8 = msg_send![obj, bytes];
    std::slice::from_raw_parts(ptr, len).to_vec()
}

pub fn change_count() -> isize {
    autoreleasepool(|_| unsafe {
        let pb: *mut AnyObject = msg_send![class!(NSPasteboard), generalPasteboard];
        msg_send![pb, changeCount]
    })
}

pub fn read_types() -> Vec<String> {
    autoreleasepool(|_| unsafe {
        let pb: *mut AnyObject = msg_send![class!(NSPasteboard), generalPasteboard];
        let arr: *mut AnyObject = msg_send![pb, types];
        if arr.is_null() {
            return Vec::new();
        }
        let count: usize = msg_send![arr, count];
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let elem: *mut AnyObject = msg_send![arr, objectAtIndex: i];
            if !elem.is_null() {
                out.push(nsstring_to_string(&*elem));
            }
        }
        out
    })
}

pub fn read_pasteboard(opts: ReadOptions) -> Result<ReadReport, String> {
    autoreleasepool(|_| unsafe {
        let pb: *mut AnyObject = msg_send![class!(NSPasteboard), generalPasteboard];
        let cc: isize = msg_send![pb, changeCount];
        let mut stats = ReadStats::default();

        stats.types_queries += 1;
        let observed_types = read_types();

        if let Some(reason) = precheck_sensitive_uti(&observed_types, opts) {
            return Ok(ReadReport {
                change_count: cc,
                observed_types,
                outcome: ReadOutcome::Skipped(reason),
                stats,
            });
        }

        let Some(selected) = select_source_uti(&observed_types) else {
            return Ok(ReadReport {
                change_count: cc,
                observed_types: observed_types.clone(),
                outcome: ReadOutcome::Skipped(SkipReason::UnsupportedTypes(observed_types)),
                stats,
            });
        };

        let fetch_data = |uti: &str, stats: &mut ReadStats| -> Result<Vec<u8>, String> {
            stats.data_for_type_calls.push(uti.to_string());
            let key = nsstring_from_str(uti);
            let data: *mut AnyObject = msg_send![pb, dataForType: &*key];
            if data.is_null() {
                return Err(format!("dataForType({uti}) returned nil"));
            }
            Ok(nsdata_to_vec(&*data))
        };

        let outcome = match selected {
            SelectedSource::Png => ReadOutcome::Payload(ClipPayload::Image {
                mime: "image/png",
                bytes: fetch_data(UTI_PNG, &mut stats)?,
                source_uti: UTI_PNG,
                transcoded_to_png: false,
            }),
            SelectedSource::Jpeg => ReadOutcome::Payload(ClipPayload::Image {
                mime: "image/jpeg",
                bytes: fetch_data(UTI_JPEG, &mut stats)?,
                source_uti: UTI_JPEG,
                transcoded_to_png: false,
            }),
            SelectedSource::Webp => ReadOutcome::Payload(ClipPayload::Image {
                mime: "image/webp",
                bytes: fetch_data(UTI_WEBP, &mut stats)?,
                source_uti: UTI_WEBP,
                transcoded_to_png: false,
            }),
            SelectedSource::Gif => ReadOutcome::Payload(ClipPayload::Image {
                mime: "image/gif",
                bytes: fetch_data(UTI_GIF, &mut stats)?,
                source_uti: UTI_GIF,
                transcoded_to_png: false,
            }),
            SelectedSource::TiffFallback => {
                let tiff_bytes = fetch_data(UTI_TIFF, &mut stats)?;
                #[cfg(any(feature = "img-png-tiff", feature = "img-full"))]
                {
                    let png_bytes = crate::img::transcode_tiff_to_png(&tiff_bytes)?;
                    ReadOutcome::Payload(ClipPayload::Image {
                        mime: "image/png",
                        bytes: png_bytes,
                        source_uti: UTI_TIFF,
                        transcoded_to_png: true,
                    })
                }
                #[cfg(not(any(feature = "img-png-tiff", feature = "img-full")))]
                {
                    let _ = tiff_bytes;
                    return Err("TIFF fallback requires image feature".into());
                }
            }
            SelectedSource::Utf8Text => {
                stats.string_for_type_calls.push(UTI_UTF8_PLAIN_TEXT.to_string());
                let key = nsstring_from_str(UTI_UTF8_PLAIN_TEXT);
                let s: *mut AnyObject = msg_send![pb, stringForType: &*key];
                if s.is_null() {
                    return Err("stringForType returned nil".into());
                }
                ReadOutcome::Payload(ClipPayload::Text(nsstring_to_string(&*s)))
            }
        };

        Ok(ReadReport {
            change_count: cc,
            observed_types,
            outcome,
            stats,
        })
    })
}

pub fn write_item_representations(
    string_reps: &[(&str, &str)],
    data_reps: &[(&str, &[u8])],
    current_host_only: bool,
) -> Result<isize, String> {
    autoreleasepool(|_| unsafe {
        let pb: *mut AnyObject = msg_send![class!(NSPasteboard), generalPasteboard];
        let item: Retained<AnyObject> = msg_send![class!(NSPasteboardItem), new];

        for (uti, text) in string_reps {
            let key = nsstring_from_str(uti);
            let val = nsstring_from_str(text);
            let ok: bool = msg_send![&*item, setString: &*val, forType: &*key];
            if !ok {
                return Err(format!("setString:forType:({uti}) failed"));
            }
        }

        for (uti, bytes) in data_reps {
            let key = nsstring_from_str(uti);
            let val = nsdata_from_bytes(bytes);
            let ok: bool = msg_send![&*item, setData: &*val, forType: &*key];
            if !ok {
                return Err(format!("setData:forType:({uti}) failed"));
            }
        }

        if current_host_only {
            let opts: usize = 1 << 0; // NSPasteboardContentsCurrentHostOnly
            let _: isize = msg_send![pb, prepareForNewContentsWithOptions: opts];
        } else {
            let _: isize = msg_send![pb, clearContents];
        }

        let arr: Retained<AnyObject> = msg_send![class!(NSArray), arrayWithObject: &*item];
        let ok: bool = msg_send![pb, writeObjects: &*arr];
        if !ok {
            return Err("writeObjects: failed".into());
        }
        let cc: isize = msg_send![pb, changeCount];
        Ok(cc)
    })
}

pub fn write_text(text: &str, markers: WriteMarkers) -> Result<isize, String> {
    let mut data_reps: Vec<(&str, &[u8])> = Vec::new();
    if markers.synced_by_mynote {
        data_reps.push((UTI_MYNOTE_SYNCED, &[]));
    }
    if markers.ephemeral_sensitive {
        data_reps.push((UTI_TRANSIENT, &[]));
        data_reps.push((UTI_CONCEALED, &[]));
    }
    write_item_representations(
        &[(UTI_UTF8_PLAIN_TEXT, text)],
        &data_reps,
        markers.current_host_only,
    )
}

pub fn write_png(png_bytes: &[u8], markers: WriteMarkers) -> Result<isize, String> {
    let mut data_reps: Vec<(&str, &[u8])> = vec![(UTI_PNG, png_bytes)];
    if markers.synced_by_mynote {
        data_reps.push((UTI_MYNOTE_SYNCED, &[]));
    }
    if markers.ephemeral_sensitive {
        data_reps.push((UTI_TRANSIENT, &[]));
        data_reps.push((UTI_CONCEALED, &[]));
    }
    write_item_representations(&[], &data_reps, markers.current_host_only)
}
