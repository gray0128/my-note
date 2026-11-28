# S-Win-1: Windows Named Pipe SDDL, Job Object, and Win32 Clipboard Spike (Issue #77)

Isolated M5 Phase 0 prototype verifying D9 Windows security and platform primitives prior to `M5-W1..W3`:

1. **Named Pipe local isolation (`SEC-WIN-PIPE`)**: `tokio::net::windows::named_pipe` with `first_pipe_instance(true)`, `reject_remote_clients(true)`, explicit `SECURITY_ATTRIBUTES` SDDL `D:P(A;;GA;;;OW)`, kernel DACL readback (`GetSecurityInfo` + `ConvertSecurityDescriptorToStringSecurityDescriptorW`), and NDJSON roundtrip latency.
2. **Hardened subprocess & zero-orphan Job Object tree teardown**: `CREATE_NO_WINDOW | CREATE_SUSPENDED` + `CreateJobObjectW` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) + `AssignProcessToJobObject` + `ResumeThread`, minimal Windows environment allowlist (`SYSTEMROOT` + `PYTHONUTF8=1`), UTF-8 Chinese/Emoji `stdin -> stdout` roundtrip, and `.bat`/`.cmd` rejection.
3. **Win32 clipboard & zero-polling watcher (`SEC-WIN-CLIP`)**: `HWND_MESSAGE` + `AddClipboardFormatListener` (`WM_CLIPBOARDUPDATE`), `OpenClipboard` UTF-16 text, `"PNG"` priority over `CF_DIBV5` with lossless `CF_DIBV5 -> PNG` fallback, SVG rejection, and hard-filtering `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory == 0`, and `CanUploadClipboardDataToCloud == 0`.

## Reproduce

```bash
cargo clippy --manifest-path spikes/s-win-1-platform/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path spikes/s-win-1-platform/Cargo.toml -- --nocapture
cargo run --manifest-path spikes/s-win-1-platform/Cargo.toml --release -- --bench
```
