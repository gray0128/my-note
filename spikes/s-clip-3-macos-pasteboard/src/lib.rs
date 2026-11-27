//! Spike S-Clip-3: macOS native `NSPasteboard` prototype & dependency evaluation.

pub mod img;
pub mod types;

#[cfg(feature = "backend-objc2-typed")]
pub mod typed_objc2;

#[cfg(feature = "backend-objc2-raw")]
pub mod raw_objc2;
