//! Heynote 1.x / 2.x lossless `∞∞∞<lang>` buffer parser & importer (`M1-5`, Issue #6).

use mynote_core::error::{CoreError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const HEYNOTE_DELIMITER: &str = "∞∞∞";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedHeynoteBlock {
    pub lang: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedHeynoteBuffer {
    pub buffer_name: String,
    pub source_hash: String,
    pub blocks: Vec<ParsedHeynoteBlock>,
}

/// Normalize Heynote language identifiers (including Heynote 2.x `-a` auto-format flags).
pub fn normalize_heynote_lang(raw: &str) -> String {
    let token = raw.split_whitespace().next().unwrap_or("");
    let cleaned = token
        .strip_suffix("-a")
        .or_else(|| token.strip_suffix(":auto"))
        .unwrap_or(token)
        .to_ascii_lowercase();
    match cleaned.as_str() {
        "" | "plain" | "plaintext" | "txt" => "text".to_string(),
        "js" | "javascript" | "jsx" => "javascript".to_string(),
        "ts" | "typescript" | "tsx" => "typescript".to_string(),
        "md" | "markdown" => "markdown".to_string(),
        "py" | "python" => "python".to_string(),
        "rs" | "rust" => "rust".to_string(),
        "sh" | "bash" | "zsh" | "shell" => "shell".to_string(),
        "yml" | "yaml" => "yaml".to_string(),
        "json" | "jsonc" | "json5" | "sql" | "xml" | "html" | "css" | "toml" | "go" | "java" | "c"
        | "cpp" | "mermaid" | "math" => cleaned,
        _ => "text".to_string(),
    }
}

/// Losslessly parse a Heynote `.txt` buffer preserving every character, indentation, blank line,
/// empty block, and in-code `"∞∞∞..."` literals (only line-start `∞∞∞` starts a new block).
pub fn parse_heynote_text(raw: &str) -> Vec<ParsedHeynoteBlock> {
    // Strip optional UTF-8 BOM at byte 0
    let stripped = raw.strip_prefix('\u{FEFF}').unwrap_or(raw);
    // Normalize CRLF to LF without losing trailing empty lines
    let normalized = stripped.replace("\r\n", "\n");

    let mut blocks: Vec<ParsedHeynoteBlock> = Vec::new();
    let mut current_lang: Option<String> = None;
    let mut current_lines: Vec<&str> = Vec::new();
    let mut saw_delimiter = false;

    for line in normalized.split('\n') {
        if let Some(rest) = line.strip_prefix(HEYNOTE_DELIMITER) {
            if saw_delimiter || !current_lines.is_empty() {
                blocks.push(ParsedHeynoteBlock {
                    lang: current_lang.take().unwrap_or_else(|| "text".to_string()),
                    content: current_lines.join("\n"),
                });
                current_lines.clear();
            }
            saw_delimiter = true;
            current_lang = Some(normalize_heynote_lang(rest));
        } else {
            current_lines.push(line);
        }
    }

    if saw_delimiter || !current_lines.is_empty() {
        blocks.push(ParsedHeynoteBlock {
            lang: current_lang.unwrap_or_else(|| "text".to_string()),
            content: current_lines.join("\n"),
        });
    }

    blocks
}

/// Read either a single Heynote 1.x `.txt` file or a Heynote 2.x directory of `.txt` files.
pub fn load_heynote_path(
    path: &Path,
    override_buffer_name: Option<&str>,
) -> Result<Vec<ParsedHeynoteBuffer>, CoreError> {
    if !path.exists() {
        return Err(CoreError::new(
            ErrorCode::NotFound,
            format!("Heynote path '{}' does not exist", path.display()),
            "Pass a valid Heynote .txt file or buffer directory path",
        ));
    }
    if path.is_file() {
        let bytes = std::fs::read(path).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("failed to read '{}': {e}", path.display()),
                "Ensure the file is readable",
            )
        })?;
        let text = String::from_utf8(bytes.clone()).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("Heynote file '{}' is not valid UTF-8: {e}", path.display()),
                "Convert the Heynote buffer file to UTF-8 before importing",
            )
        })?;
        let name = override_buffer_name
            .map(str::to_string)
            .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "heynote".to_string());
        let hash = blake3::hash(&bytes).to_hex().to_string();
        return Ok(vec![ParsedHeynoteBuffer {
            buffer_name: name,
            source_hash: hash,
            blocks: parse_heynote_text(&text),
        }]);
    }

    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(path)
        .map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("failed to read directory '{}': {e}", path.display()),
                "Ensure the Heynote directory is readable",
            )
        })?
        .filter_map(|e| e.ok().map(|x| x.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    files.sort();

    let mut out = Vec::with_capacity(files.len());
    for file in files {
        let mut parsed = load_heynote_path(&file, None)?;
        out.append(&mut parsed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_heynote_corpus_diff_preserves_every_block_and_byte() {
        // Covers: UTF-8 BOM, leading block without delimiter, string literal "∞∞∞json" inside code,
        // CRLF + LF mix, empty blocks, consecutive delimiters, unknown lang fallback, CJK/Emoji.
        let dirty = "\u{FEFF}leading block line 1\r\nleading line 2\r\n\
∞∞∞javascript\r\nconst s = \"∞∞∞json\";\nconsole.log('中文🚀');\r\n\
∞∞∞json-a\n\
∞∞∞unknown_xyz_lang\nfallback content\n\
∞∞∞sql\nSELECT 1;\n";

        let blocks = parse_heynote_text(dirty);
        assert_eq!(blocks.len(), 5);

        assert_eq!(blocks[0].lang, "text");
        assert_eq!(blocks[0].content, "leading block line 1\nleading line 2");

        assert_eq!(blocks[1].lang, "javascript");
        assert_eq!(
            blocks[1].content,
            "const s = \"∞∞∞json\";\nconsole.log('中文🚀');"
        );

        assert_eq!(blocks[2].lang, "json");
        assert_eq!(blocks[2].content, "");

        assert_eq!(blocks[3].lang, "text");
        assert_eq!(blocks[3].content, "fallback content");

        assert_eq!(blocks[4].lang, "sql");
        assert_eq!(blocks[4].content, "SELECT 1;\n");
    }
}
