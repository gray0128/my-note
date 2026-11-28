//! M5 Phase 0 Spike `S-Win-1` (Issue #77): isolated verification of the three D9 Windows
//! security and platform primitives before `M5-W1..W3`:
//!
//! 1. [`named_pipe`]: `tokio::net::windows::named_pipe` with `first_pipe_instance(true)`,
//!    `reject_remote_clients(true)`, explicit `SECURITY_ATTRIBUTES` SDDL `D:P(A;;GA;;;OW)`,
//!    kernel DACL readback (`GetSecurityInfo`), and NDJSON roundtrip latency.
//! 2. [`subprocess`]: `CREATE_NO_WINDOW | CREATE_SUSPENDED` + `CreateJobObjectW`
//!    (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) + `AssignProcessToJobObject` + `ResumeThread`
//!    zero-orphan process-tree teardown, minimal Windows environment allowlist, UTF-8
//!    Chinese/Emoji `stdin -> stdout` roundtrip, and `.bat`/`.cmd` rejection.
//! 3. [`clipboard`]: Win32 `HWND_MESSAGE` + `AddClipboardFormatListener` (`WM_CLIPBOARDUPDATE`)
//!    zero-polling watcher, `OpenClipboard` UTF-16 text, `"PNG"` priority with `CF_DIBV5`
//!    fallback conversion to PNG, SVG rejection, and Windows privacy format hard-filtering.

pub mod clipboard;
pub mod named_pipe;
pub mod subprocess;
