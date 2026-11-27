//! Safe typed macOS `NSPasteboard` backend built on `objc2-app-kit` + `objc2-foundation`
//! with surgical per-class feature gates (`NSPasteboard`, `NSPasteboardItem`,
//! `NSArray`, `NSData`, `NSString`).
//!
//! Notice that the entire production read/write surface uses **zero `unsafe` blocks**.

use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::ProtocolObject;
use objc2_app_kit::{NSPasteboard, NSPasteboardContentsOptions, NSPasteboardItem, NSPasteboardWriting};
use objc2_foundation::{NSArray, NSData, NSString};

use crate::types::{
    precheck_sensitive_uti, select_source_uti, ClipPayload, ReadOptions, ReadOutcome, ReadReport, ReadStats,
    SelectedSource, SkipReason, WriteMarkers, UTI_CONCEALED, UTI_GIF, UTI_JPEG, UTI_MYNOTE_SYNCED, UTI_PNG,
    UTI_TIFF, UTI_TRANSIENT, UTI_UTF8_PLAIN_TEXT, UTI_WEBP,
};

/// Return the current `NSPasteboard.generalPasteboard().changeCount()`.
pub fn change_count() -> isize {
    autoreleasepool(|_| {
        let pb = NSPasteboard::generalPasteboard();
        pb.changeCount()
    })
}

/// Inspect `NSPasteboard.generalPasteboard().types()` WITHOUT reading any payload data.
pub fn read_types() -> Vec<String> {
    autoreleasepool(|_| {
        let pb = NSPasteboard::generalPasteboard();
        match pb.types() {
            Some(arr) => arr.iter().map(|s| s.to_string()).collect(),
            None => Vec::new(),
        }
    })
}

/// Report the raw macOS 15.4+ `NSPasteboardAccessBehavior` integer (0=Default, 1=Ask, 2=AlwaysAllow, 3=AlwaysDeny).
pub fn access_behavior_raw() -> isize {
    autoreleasepool(|_| {
        let pb = NSPasteboard::generalPasteboard();
        pb.accessBehavior().0
    })
}

/// Read the system pasteboard following `my-note` M4 safety and priority rules:
/// 1. Query `types()` first (inside an `autoreleasepool`).
/// 2. Reject sensitive / transient / remote Universal Clipboard / echo-loop UTIs
///    BEFORE any `dataForType` or `stringForType` call.
/// 3. Prefer `public.png` (and other compressed bitmaps) strictly BEFORE `public.tiff`
///    so macOS screenshots never trigger reading 20-40 MiB uncompressed TIFF.
/// 4. Fall back to `public.tiff` and transcode to PNG only when no compressed bitmap exists.
pub fn read_pasteboard(opts: ReadOptions) -> Result<ReadReport, String> {
    autoreleasepool(|_| {
        let pb = NSPasteboard::generalPasteboard();
        let cc = pb.changeCount();
        let mut stats = ReadStats::default();

        stats.types_queries += 1;
        let observed_types: Vec<String> = match pb.types() {
            Some(arr) => arr.iter().map(|s| s.to_string()).collect(),
            None => Vec::new(),
        };

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

        let outcome = match selected {
            SelectedSource::Png => {
                let bytes = fetch_data(&pb, UTI_PNG, &mut stats)?;
                ReadOutcome::Payload(ClipPayload::Image {
                    mime: "image/png",
                    bytes,
                    source_uti: UTI_PNG,
                    transcoded_to_png: false,
                })
            }
            SelectedSource::Jpeg => {
                let bytes = fetch_data(&pb, UTI_JPEG, &mut stats)?;
                ReadOutcome::Payload(ClipPayload::Image {
                    mime: "image/jpeg",
                    bytes,
                    source_uti: UTI_JPEG,
                    transcoded_to_png: false,
                })
            }
            SelectedSource::Webp => {
                let bytes = fetch_data(&pb, UTI_WEBP, &mut stats)?;
                ReadOutcome::Payload(ClipPayload::Image {
                    mime: "image/webp",
                    bytes,
                    source_uti: UTI_WEBP,
                    transcoded_to_png: false,
                })
            }
            SelectedSource::Gif => {
                let bytes = fetch_data(&pb, UTI_GIF, &mut stats)?;
                ReadOutcome::Payload(ClipPayload::Image {
                    mime: "image/gif",
                    bytes,
                    source_uti: UTI_GIF,
                    transcoded_to_png: false,
                })
            }
            SelectedSource::TiffFallback => {
                let tiff_bytes = fetch_data(&pb, UTI_TIFF, &mut stats)?;
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
                    return Err("TIFF fallback requires an image feature (img-png-tiff or img-full)".into());
                }
            }
            SelectedSource::Utf8Text => {
                let text = fetch_string(&pb, UTI_UTF8_PLAIN_TEXT, &mut stats)?;
                ReadOutcome::Payload(ClipPayload::Text(text))
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

fn fetch_data(pb: &NSPasteboard, uti: &str, stats: &mut ReadStats) -> Result<Vec<u8>, String> {
    stats.data_for_type_calls.push(uti.to_string());
    let key = NSString::from_str(uti);
    let data = pb
        .dataForType(&key)
        .ok_or_else(|| format!("NSPasteboard::dataForType({uti}) returned None"))?;
    Ok(data.to_vec())
}

fn fetch_string(pb: &NSPasteboard, uti: &str, stats: &mut ReadStats) -> Result<String, String> {
    stats.string_for_type_calls.push(uti.to_string());
    let key = NSString::from_str(uti);
    let s = pb
        .stringForType(&key)
        .ok_or_else(|| format!("NSPasteboard::stringForType({uti}) returned None"))?;
    Ok(s.to_string())
}

/// Atomically write one `NSPasteboardItem` carrying arbitrary `(uti, payload)` pairs.
/// All representations are committed in a single `writeObjects:` IPC call so clipboard
/// managers (Maccy, 1Password, our own watcher) never observe text before its marker UTIs.
pub fn write_item_representations(
    string_reps: &[(&str, &str)],
    data_reps: &[(&str, &[u8])],
    current_host_only: bool,
) -> Result<isize, String> {
    autoreleasepool(|_| {
        let pb = NSPasteboard::generalPasteboard();
        let item = NSPasteboardItem::new();

        for (uti, text) in string_reps {
            let key = NSString::from_str(uti);
            let val = NSString::from_str(text);
            if !item.setString_forType(&val, &key) {
                return Err(format!("NSPasteboardItem::setString_forType({uti}) failed"));
            }
        }

        for (uti, bytes) in data_reps {
            let key = NSString::from_str(uti);
            let val = NSData::with_bytes(bytes);
            if !item.setData_forType(&val, &key) {
                return Err(format!("NSPasteboardItem::setData_forType({uti}) failed"));
            }
        }

        if current_host_only {
            pb.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
        } else {
            pb.clearContents();
        }

        let obj: Retained<ProtocolObject<dyn NSPasteboardWriting>> = ProtocolObject::from_retained(item);
        let arr = NSArray::from_retained_slice(&[obj]);
        if !pb.writeObjects(&arr) {
            return Err("NSPasteboard::writeObjects failed".into());
        }
        Ok(pb.changeCount())
    })
}

/// Write UTF-8 plain text with optional `my-note` echo-guard and ephemeral privacy markers.
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

/// Write PNG bytes with optional `my-note` echo-guard and ephemeral privacy markers.
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

/// Clear the general pasteboard completely.
pub fn clear_pasteboard() -> isize {
    autoreleasepool(|_| {
        let pb = NSPasteboard::generalPasteboard();
        pb.clearContents()
    })
}

/// RAII guard that snapshots the user's current text/PNG pasteboard before tests
/// and restores it unconditionally on drop (including on panic).
pub struct ClipboardRestoreGuard {
    saved: SavedClipboard,
}

enum SavedClipboard {
    Empty,
    Text(String),
    Png(Vec<u8>),
    SkippedPreserve,
}

impl ClipboardRestoreGuard {
    pub fn capture() -> Self {
        let types = read_types();
        if types.is_empty() {
            return Self {
                saved: SavedClipboard::Empty,
            };
        }
        // Never force-read remote Universal Clipboard or sensitive password-manager items.
        if precheck_sensitive_uti(
            &types,
            ReadOptions {
                ignore_universal_clipboard: true,
                skip_synced_marker: false,
            },
        )
        .is_some()
        {
            return Self {
                saved: SavedClipboard::SkippedPreserve,
            };
        }

        let saved = autoreleasepool(|_| {
            let pb = NSPasteboard::generalPasteboard();
            if types.iter().any(|t| t == UTI_UTF8_PLAIN_TEXT) {
                if let Some(s) = pb.stringForType(&NSString::from_str(UTI_UTF8_PLAIN_TEXT)) {
                    return SavedClipboard::Text(s.to_string());
                }
            }
            if types.iter().any(|t| t == UTI_PNG) {
                if let Some(d) = pb.dataForType(&NSString::from_str(UTI_PNG)) {
                    return SavedClipboard::Png(d.to_vec());
                }
            }
            SavedClipboard::SkippedPreserve
        });
        Self { saved }
    }

    pub fn summary(&self) -> &'static str {
        match &self.saved {
            SavedClipboard::Empty => "empty",
            SavedClipboard::Text(_) => "utf8-text",
            SavedClipboard::Png(_) => "png-image",
            SavedClipboard::SkippedPreserve => "non-text/sensitive (not read)",
        }
    }
}

impl Drop for ClipboardRestoreGuard {
    fn drop(&mut self) {
        match &self.saved {
            SavedClipboard::Empty => {
                clear_pasteboard();
            }
            SavedClipboard::Text(text) => {
                let _ = write_text(text, WriteMarkers::default());
            }
            SavedClipboard::Png(png) => {
                let _ = write_png(png, WriteMarkers::default());
            }
            SavedClipboard::SkippedPreserve => {
                // Nothing safe was captured; leave clipboard cleared rather than leaving test fixture.
                clear_pasteboard();
            }
        }
    }
}

/// Real AppKit lazy data provider (`NSPasteboardItemDataProvider`) used by tests to prove
/// at the OS/AppKit level that `pb.types()` NEVER triggers lazy data materialization
/// (the exact mechanism behind `com.apple.is-remote-clipboard` and lazy TIFF rendering),
/// whereas calling `dataForType:` / `stringForType:` DOES invoke `provideDataForType:`.
pub mod lazy_provider {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use objc2::rc::{autoreleasepool, Retained};
    use objc2::runtime::ProtocolObject;
    use objc2::{define_class, msg_send, AnyThread, DefinedClass};
    use objc2_app_kit::{
        NSPasteboard, NSPasteboardItem, NSPasteboardItemDataProvider, NSPasteboardType, NSPasteboardWriting,
    };
    use objc2_foundation::{NSArray, NSData, NSObject, NSObjectProtocol, NSString};

    pub struct ProviderIvars {
        pub invocations: Arc<AtomicUsize>,
        pub payload_bytes: Vec<u8>,
        pub payload_is_string: bool,
    }

    define_class!(
        #[unsafe(super(NSObject))]
        #[name = "MynoteSpikeLazyProvider"]
        #[ivars = ProviderIvars]
        pub struct LazyProvider;

        unsafe impl NSObjectProtocol for LazyProvider {}

        unsafe impl NSPasteboardItemDataProvider for LazyProvider {
            #[unsafe(method(pasteboard:item:provideDataForType:))]
            fn pasteboard_item_provide_data_for_type(
                &self,
                _pasteboard: Option<&NSPasteboard>,
                item: &NSPasteboardItem,
                r#type: &NSPasteboardType,
            ) {
                let ivars = self.ivars();
                ivars.invocations.fetch_add(1, Ordering::SeqCst);
                if ivars.payload_is_string {
                    let s = String::from_utf8_lossy(&ivars.payload_bytes);
                    let ns = NSString::from_str(&s);
                    let _ = item.setString_forType(&ns, r#type);
                } else {
                    let data = NSData::with_bytes(&ivars.payload_bytes);
                    let _ = item.setData_forType(&data, r#type);
                }
            }
        }
    );

    impl LazyProvider {
        pub fn new(
            invocations: Arc<AtomicUsize>,
            payload_bytes: Vec<u8>,
            payload_is_string: bool,
        ) -> Retained<Self> {
            let this = Self::alloc().set_ivars(ProviderIvars {
                invocations,
                payload_bytes,
                payload_is_string,
            });
            unsafe { msg_send![super(this), init] }
        }
    }

    /// Keep the returned `Retained<LazyProvider>` alive while the pasteboard holds the promise.
    pub fn write_item_with_lazy_promise(
        eager_data: &[(&str, &[u8])],
        promised_utis: &[&str],
        lazy_payload: Vec<u8>,
        lazy_is_string: bool,
    ) -> Result<(Retained<LazyProvider>, Arc<AtomicUsize>), String> {
        autoreleasepool(|_| {
            let invocations = Arc::new(AtomicUsize::new(0));
            let provider = LazyProvider::new(invocations.clone(), lazy_payload, lazy_is_string);

            let item = NSPasteboardItem::new();
            for (uti, bytes) in eager_data {
                let key = NSString::from_str(uti);
                let val = NSData::with_bytes(bytes);
                if !item.setData_forType(&val, &key) {
                    return Err(format!("setData_forType({uti}) failed"));
                }
            }

            let promised_ns: Vec<Retained<NSString>> =
                promised_utis.iter().map(|u| NSString::from_str(u)).collect();
            let promised_arr = NSArray::from_retained_slice(&promised_ns);
            let proto: &ProtocolObject<dyn NSPasteboardItemDataProvider> =
                ProtocolObject::from_ref(&*provider);
            if !item.setDataProvider_forTypes(proto, &promised_arr) {
                return Err("setDataProvider_forTypes failed".into());
            }

            let pb = NSPasteboard::generalPasteboard();
            pb.clearContents();
            let obj: Retained<ProtocolObject<dyn NSPasteboardWriting>> = ProtocolObject::from_retained(item);
            if !pb.writeObjects(&NSArray::from_retained_slice(&[obj])) {
                return Err("writeObjects with lazy provider failed".into());
            }
            Ok((provider, invocations))
        })
    }
}
