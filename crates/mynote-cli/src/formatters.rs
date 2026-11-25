//! Combined Layer 1 (built-in Rust core) + Layer 2 (`~/.config/mynote/formatters.toml`)
//! external formatter pipeline with strict timeout & zero-byte fuse
//! (`docs/interface-contracts.md` §2.4).

use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::format::format_snippet;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_MS: u64 = 2_000;

#[derive(Clone, Debug, Deserialize)]
struct FormattersConfig {
    #[serde(default)]
    formatters: BTreeMap<String, ExternalFormatterSpec>,
}

#[derive(Clone, Debug, Deserialize)]
struct ExternalFormatterSpec {
    cmd: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn config_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("MYNOTE_FORMATTERS_CONFIG") {
        if !explicit.trim().is_empty() {
            return Some(PathBuf::from(explicit));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return Some(PathBuf::from(xdg).join("mynote").join("formatters.toml"));
        }
    }
    std::env::var("HOME").ok().map(|h| {
        PathBuf::from(h)
            .join(".config")
            .join("mynote")
            .join("formatters.toml")
    })
}

fn load_external_spec(lang: &str) -> Result<Option<ExternalFormatterSpec>, CoreError> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("failed to read '{}': {e}", path.display()),
            "Check permissions and TOML syntax of formatters.toml",
        )
    })?;
    let cfg: FormattersConfig = toml::from_str(&raw).map_err(|e| {
        CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("invalid formatters.toml: {e}"),
            "Fix TOML syntax in ~/.config/mynote/formatters.toml",
        )
    })?;
    Ok(cfg.formatters.get(&lang.to_ascii_lowercase()).cloned())
}

/// Format snippet via Layer 1 built-in core, falling back to Layer 2 external formatter
/// ONLY when no `--action` is specified and a matching entry exists in `formatters.toml`.
pub fn format_content(input: &str, lang: &str, action: Option<&str>) -> Result<String, CoreError> {
    if action.is_none() {
        if let Some(spec) = load_external_spec(lang)? {
            return run_external_formatter(&spec, input);
        }
    }
    format_snippet(input, lang, action)
}

fn run_external_formatter(spec: &ExternalFormatterSpec, input: &str) -> Result<String, CoreError> {
    let mut cmd = Command::new(&spec.cmd);
    cmd.args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Restrict environment to minimal PATH/LANG for safer subprocess execution
        .env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("LC_ALL", "C.UTF-8");

    let mut child = cmd.spawn().map_err(|e| {
        CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("failed to spawn external formatter '{}': {e}", spec.cmd),
            "Verify the formatter binary exists on PATH in ~/.config/mynote/formatters.toml",
        )
    })?;

    if let Some(mut stdin) = child.stdin.take() {
        let bytes = input.as_bytes().to_vec();
        thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }

    let mut stdout_pipe = child.stdout.take();
    let stdout_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stdout_pipe.take() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let mut stderr_pipe = child.stderr.take();
    let stderr_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stderr_pipe.take() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + Duration::from_millis(spec.timeout_ms.max(50));
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CoreError::new(
                        ErrorCode::FormatSyntaxError,
                        format!(
                            "external formatter '{}' timed out after {} ms",
                            spec.cmd, spec.timeout_ms
                        ),
                        "Original block left untouched; check input or increase timeout_ms",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(CoreError::new(
                    ErrorCode::FormatSyntaxError,
                    format!("error waiting on formatter '{}': {e}", spec.cmd),
                    "Original block left untouched",
                ));
            }
        }
    };

    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr_bytes);
        return Err(CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!(
                "external formatter '{}' exited with {}: {}",
                spec.cmd,
                status,
                stderr_str.trim()
            ),
            "Fix input syntax; original block was NOT modified",
        ));
    }

    // Zero-byte fuse (`docs/interface-contracts.md` §2.4): non-empty input + 0-byte stdout => exit 7
    if !input.is_empty() && stdout_bytes.is_empty() {
        return Err(CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!(
                "external formatter '{}' returned 0 bytes for non-empty input",
                spec.cmd
            ),
            "Refusing to overwrite block with empty output; inspect formatter configuration",
        ));
    }

    String::from_utf8(stdout_bytes).map_err(|_| {
        CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("external formatter '{}' emitted non-UTF-8 output", spec.cmd),
            "Original block left untouched",
        )
    })
}
