use crate::error::{CoreError, ErrorCode};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::{Reader, Writer};
use std::collections::BTreeMap;
use std::io::Cursor;
use unicode_width::UnicodeWidthStr;

fn syntax_err(msg: impl Into<String>) -> CoreError {
    CoreError::new(
        ErrorCode::FormatSyntaxError,
        msg,
        "Fix the syntax error in the snippet; original block content was left untouched",
    )
}

/// Layer 1 pure-Rust offline formatting & structural transformations (`docs/architecture-proposal.md` §5.3).
/// NEVER returns an empty string on invalid input; returns `FORMAT_SYNTAX_ERROR` instead.
pub fn format_snippet(input: &str, lang: &str, action: Option<&str>) -> Result<String, CoreError> {
    if let Some(act) = action {
        return run_action(input, act);
    }
    match lang.to_ascii_lowercase().as_str() {
        "json" | "jsonc" | "json5" => format_json(input, 2),
        "json-4" => format_json(input, 4),
        "json-compact" => format_json_compact(input),
        "yaml" | "yml" => format_yaml(input),
        "toml" => format_toml(input),
        "sql" => format_sql(input),
        "xml" | "html" | "svg" => format_xml(input),
        "markdown" | "md" => Ok(format_markdown(input)),
        other => Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("unsupported Layer 1 language '{other}'"),
            "Supported Layer 1 languages: json, json5, yaml, toml, sql, xml, markdown",
        )),
    }
}

fn run_action(input: &str, action: &str) -> Result<String, CoreError> {
    match action.to_ascii_lowercase().as_str() {
        "unescape-json" => unescape_and_format_json(input),
        "compact-json" => format_json_compact(input),
        "json-4" => format_json(input, 4),
        "to-yaml" => {
            let val = parse_json_or_json5(input)?;
            serde_yaml_ng::to_string(&val).map_err(|e| syntax_err(format!("YAML encode error: {e}")))
        }
        "to-toml" => {
            let val = parse_json_or_json5(input)?;
            toml::to_string_pretty(&val).map_err(|e| syntax_err(format!("TOML encode error: {e}")))
        }
        "to-json" => {
            if let Ok(v) = parse_json_or_json5(input) {
                return serde_json::to_string_pretty(&v).map_err(|e| syntax_err(e.to_string()));
            }
            if let Ok(v) = toml::from_str::<toml::Value>(input) {
                return serde_json::to_string_pretty(&v).map_err(|e| syntax_err(e.to_string()));
            }
            let v: serde_yaml_ng::Value =
                serde_yaml_ng::from_str(input).map_err(|e| syntax_err(format!("YAML/TOML parse error: {e}")))?;
            serde_json::to_string_pretty(&v).map_err(|e| syntax_err(e.to_string()))
        }
        "base64-encode" => Ok(B64.encode(input.as_bytes())),
        "base64-decode" => {
            let bytes = B64
                .decode(input.trim())
                .map_err(|e| syntax_err(format!("invalid base64: {e}")))?;
            String::from_utf8(bytes).map_err(|e| syntax_err(format!("decoded base64 is not UTF-8: {e}")))
        }
        "base64url-encode" => Ok(B64URL.encode(input.as_bytes())),
        "base64url-decode" => {
            let bytes = B64URL
                .decode(input.trim())
                .map_err(|e| syntax_err(format!("invalid base64url: {e}")))?;
            String::from_utf8(bytes).map_err(|e| syntax_err(format!("decoded base64url is not UTF-8: {e}")))
        }
        "query-to-json" => query_to_json(input),
        "json-to-query" => json_to_query(input),
        "jwt-decode" => decode_jwt(input),
        "ts-to-iso" => timestamp_to_iso(input),
        "iso-to-ts" => iso_to_timestamp(input),
        other => Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("unknown format action '{other}'"),
            "Supported actions: unescape-json, compact-json, to-yaml, to-toml, to-json, base64-encode, base64-decode, base64url-encode, base64url-decode, query-to-json, json-to-query, jwt-decode, ts-to-iso, iso-to-ts",
        )),
    }
}

fn parse_json_or_json5(input: &str) -> Result<serde_json::Value, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(syntax_err("empty JSON input"));
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Ok(v);
    }
    json5::from_str::<serde_json::Value>(trimmed)
        .map_err(|e| syntax_err(format!("JSON/JSON5 syntax error: {e}")))
}

pub fn format_json(input: &str, indent_spaces: usize) -> Result<String, CoreError> {
    let val = parse_json_or_json5(input)?;
    if indent_spaces == 2 {
        serde_json::to_string_pretty(&val).map_err(|e| syntax_err(e.to_string()))
    } else {
        let indent = vec![b' '; indent_spaces];
        let formatter = serde_json::ser::PrettyFormatter::with_indent(&indent);
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        serde::Serialize::serialize(&val, &mut ser).map_err(|e| syntax_err(e.to_string()))?;
        String::from_utf8(buf).map_err(|e| syntax_err(e.to_string()))
    }
}

pub fn format_json_compact(input: &str) -> Result<String, CoreError> {
    let val = parse_json_or_json5(input)?;
    serde_json::to_string(&val).map_err(|e| syntax_err(e.to_string()))
}

/// Unwrap log-escaped JSON strings (e.g. `"{\"a\":1,\"b\":\"{\\\"c\\\":2}\"}"`) and pretty-print.
pub fn unescape_and_format_json(input: &str) -> Result<String, CoreError> {
    let mut current = input.trim().to_string();
    if current.is_empty() {
        return Err(syntax_err("empty JSON input"));
    }
    // Unwrap up to 4 layers of JSON string escaping
    for _ in 0..4 {
        if let Ok(serde_json::Value::String(inner)) = serde_json::from_str::<serde_json::Value>(&current) {
            current = inner;
            continue;
        }
        // Handle bare unquoted escaped JSON from logs like `{\"a\": 1}`
        if current.contains("\\\"") && !current.starts_with('"') {
            let wrapped = format!("\"{current}\"");
            if let Ok(serde_json::Value::String(inner)) = serde_json::from_str::<serde_json::Value>(&wrapped)
            {
                current = inner;
                continue;
            }
        }
        break;
    }
    let val = parse_json_or_json5(&current)?;
    serde_json::to_string_pretty(&val).map_err(|e| syntax_err(e.to_string()))
}

pub fn format_yaml(input: &str) -> Result<String, CoreError> {
    if input.trim().is_empty() {
        return Err(syntax_err("empty YAML input"));
    }
    let val: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(input).map_err(|e| syntax_err(format!("YAML syntax error: {e}")))?;
    let mut out = serde_yaml_ng::to_string(&val).map_err(|e| syntax_err(e.to_string()))?;
    while out.ends_with('\n') {
        out.pop();
    }
    Ok(out)
}

pub fn format_toml(input: &str) -> Result<String, CoreError> {
    if input.trim().is_empty() {
        return Err(syntax_err("empty TOML input"));
    }
    let val: toml::Value =
        toml::from_str(input).map_err(|e| syntax_err(format!("TOML syntax error: {e}")))?;
    let mut out = toml::to_string_pretty(&val).map_err(|e| syntax_err(e.to_string()))?;
    while out.ends_with('\n') {
        out.pop();
    }
    Ok(out)
}

pub fn format_sql(input: &str) -> Result<String, CoreError> {
    if input.trim().is_empty() {
        return Err(syntax_err("empty SQL input"));
    }
    let opts = sqlformat::FormatOptions {
        indent: sqlformat::Indent::Spaces(2),
        uppercase: Some(true),
        lines_between_queries: 1,
        ..Default::default()
    };
    Ok(sqlformat::format(
        input.trim(),
        &sqlformat::QueryParams::None,
        &opts,
    ))
}

pub fn format_xml(input: &str) -> Result<String, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || !trimmed.starts_with('<') {
        return Err(syntax_err("invalid XML: must start with '<'"));
    }
    let mut reader = Reader::from_str(trimmed);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;

    let mut writer = Writer::new_with_indent(Cursor::new(Vec::new()), b' ', 2);
    let mut buf = Vec::new();
    let mut saw_element = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(ev) => {
                if matches!(ev, Event::Start(_) | Event::Empty(_)) {
                    saw_element = true;
                }
                writer
                    .write_event(ev)
                    .map_err(|e| syntax_err(format!("XML write error: {e}")))?;
            }
            Err(e) => {
                return Err(syntax_err(format!(
                    "XML syntax error at byte {}: {e}",
                    reader.error_position()
                )));
            }
        }
        buf.clear();
    }

    if !saw_element {
        return Err(syntax_err("XML contains no element nodes"));
    }
    String::from_utf8(writer.into_inner().into_inner()).map_err(|e| syntax_err(e.to_string()))
}

/// Format Markdown: align GFM pipe tables (CJK/Emoji display-width aware) & collapse excessive blank lines.
pub fn format_markdown(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;

    while i < lines.len() {
        if i + 1 < lines.len() && is_table_row(lines[i]) && is_table_separator(lines[i + 1]) {
            let start = i;
            i += 2;
            while i < lines.len() && is_table_row(lines[i]) {
                i += 1;
            }
            out.extend(format_gfm_table(&lines[start..i]));
            continue;
        }
        let line = lines[i].trim_end();
        if line.is_empty() && out.last().is_some_and(String::is_empty) {
            i += 1;
            continue;
        }
        out.push(line.to_string());
        i += 1;
    }
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out.join("\n")
}

fn is_table_row(line: &str) -> bool {
    let t = line.trim();
    t.starts_with('|') && t.ends_with('|') && t.len() >= 2
}

fn is_table_separator(line: &str) -> bool {
    if !is_table_row(line) {
        return false;
    }
    let cells = split_table_cells(line);
    !cells.is_empty()
        && cells.iter().all(|c| {
            let s = c.trim();
            !s.is_empty() && s.bytes().all(|b| b == b'-' || b == b':') && s.contains('-')
        })
}

fn split_table_cells(line: &str) -> Vec<String> {
    let t = line.trim();
    let inner = t.strip_prefix('|').unwrap_or(t);
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    inner.split('|').map(|c| c.trim().to_string()).collect()
}

fn format_gfm_table(rows: &[&str]) -> Vec<String> {
    let parsed: Vec<Vec<String>> = rows.iter().map(|r| split_table_cells(r)).collect();
    let cols = parsed.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![3usize; cols];

    for (r_idx, row) in parsed.iter().enumerate() {
        if r_idx == 1 {
            continue;
        }
        for (c_idx, cell) in row.iter().enumerate() {
            widths[c_idx] = widths[c_idx].max(UnicodeWidthStr::width(cell.as_str()));
        }
    }

    let mut formatted = Vec::with_capacity(parsed.len());
    for (r_idx, row) in parsed.iter().enumerate() {
        let mut line = String::from("|");
        for (c_idx, &w) in widths.iter().enumerate() {
            let cell = row.get(c_idx).map(String::as_str).unwrap_or("");
            if r_idx == 1 {
                let left = cell.starts_with(':');
                let right = cell.ends_with(':');
                let dashes = match (left, right) {
                    (true, true) => format!(":{}:", "-".repeat(w.saturating_sub(2).max(1))),
                    (true, false) => format!(":{}", "-".repeat(w.saturating_sub(1).max(2))),
                    (false, true) => format!("{}:", "-".repeat(w.saturating_sub(1).max(2))),
                    (false, false) => "-".repeat(w),
                };
                line.push(' ');
                line.push_str(&dashes);
                line.push_str(" |");
            } else {
                let cell_w = UnicodeWidthStr::width(cell);
                let pad = w.saturating_sub(cell_w);
                line.push(' ');
                line.push_str(cell);
                for _ in 0..pad {
                    line.push(' ');
                }
                line.push_str(" |");
            }
        }
        formatted.push(line);
    }
    formatted
}

fn query_to_json(input: &str) -> Result<String, CoreError> {
    let trimmed = input.trim();
    let qs = if let Some((_, q)) = trimmed.split_once('?') {
        q
    } else {
        trimmed
    };
    let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
        let key = k.into_owned();
        let val = serde_json::Value::String(v.into_owned());
        map.entry(key)
            .and_modify(|existing| match existing {
                serde_json::Value::Array(arr) => arr.push(val.clone()),
                prev => *prev = serde_json::Value::Array(vec![prev.clone(), val.clone()]),
            })
            .or_insert(val);
    }
    serde_json::to_string_pretty(&map).map_err(|e| syntax_err(e.to_string()))
}

fn json_to_query(input: &str) -> Result<String, CoreError> {
    let val = parse_json_or_json5(input)?;
    let obj = val
        .as_object()
        .ok_or_else(|| syntax_err("json-to-query requires a top-level JSON object"))?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in obj {
        match v {
            serde_json::Value::String(s) => {
                serializer.append_pair(k, s);
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    let s = item
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| item.to_string());
                    serializer.append_pair(k, &s);
                }
            }
            other => {
                serializer.append_pair(k, &other.to_string());
            }
        }
    }
    Ok(serializer.finish())
}

fn decode_jwt(input: &str) -> Result<String, CoreError> {
    let parts: Vec<&str> = input.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(syntax_err("JWT must have exactly 3 dot-separated segments"));
    }
    let hdr_bytes = B64URL
        .decode(parts[0])
        .map_err(|e| syntax_err(format!("invalid JWT header base64url: {e}")))?;
    let pay_bytes = B64URL
        .decode(parts[1])
        .map_err(|e| syntax_err(format!("invalid JWT payload base64url: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&hdr_bytes)
        .map_err(|e| syntax_err(format!("invalid JWT header JSON: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&pay_bytes)
        .map_err(|e| syntax_err(format!("invalid JWT payload JSON: {e}")))?;
    serde_json::to_string_pretty(&serde_json::json!({
        "header": header,
        "payload": payload,
        "signature_present": !parts[2].is_empty(),
    }))
    .map_err(|e| syntax_err(e.to_string()))
}

fn timestamp_to_iso(input: &str) -> Result<String, CoreError> {
    let n = input
        .trim()
        .parse::<i64>()
        .map_err(|e| syntax_err(format!("invalid unix timestamp: {e}")))?;
    let dt = if n.abs() >= 1_000_000_000_000 {
        DateTime::<Utc>::from_timestamp_millis(n)
    } else {
        DateTime::<Utc>::from_timestamp(n, 0)
    }
    .ok_or_else(|| syntax_err("timestamp out of range"))?;
    Ok(dt.to_rfc3339())
}

fn iso_to_timestamp(input: &str) -> Result<String, CoreError> {
    let dt = DateTime::parse_from_rfc3339(input.trim())
        .map_err(|e| syntax_err(format!("invalid RFC3339/ISO-8601 timestamp: {e}")))?;
    Ok(format!(
        "{{\"unix_s\": {}, \"unix_ms\": {}}}",
        dt.timestamp(),
        dt.timestamp_millis()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dirty_json_unescape_and_json5_work() {
        let escaped = r#""{\"service\":\"my-note\",\"ok\":true}""#;
        let out = format_snippet(escaped, "json", Some("unescape-json")).unwrap();
        assert_eq!(out, "{\n  \"ok\": true,\n  \"service\": \"my-note\"\n}");

        let json5_in = "{ /* comment */ 'a': 1, b: [2, 3,], }";
        let out5 = format_snippet(json5_in, "json5", None).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&out5).unwrap(),
            serde_json::json!({"a": 1, "b": [2, 3]})
        );
    }

    #[test]
    fn markdown_gfm_table_aligns_cjk_and_emoji_idempotently() {
        let md = "| 名称 | 状态 | Notes |\n|---|---:|:---:|\n| 中文列 | ✅ | ok |\n| a | 🚀 | long cell |\n\n\n\nEnd";
        let f1 = format_snippet(md, "markdown", None).unwrap();
        let f2 = format_snippet(&f1, "markdown", None).unwrap();
        assert_eq!(f1, f2);
        assert!(f1.contains("| 中文列 |"));
        assert!(!f1.contains("\n\n\n"));
    }

    #[test]
    fn jwt_query_and_timestamp_transforms_work() {
        let hdr = B64URL.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let pay = B64URL.encode(br#"{"sub":"u1","exp":1800000000}"#);
        let jwt = format!("{hdr}.{pay}.sig");
        let dec = format_snippet(&jwt, "text", Some("jwt-decode")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&dec).unwrap();
        assert_eq!(v["header"]["alg"], "HS256");
        assert_eq!(v["payload"]["sub"], "u1");

        let qj = format_snippet("https://a.test/?b=2&a=1&a=3", "text", Some("query-to-json")).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&qj).unwrap(),
            serde_json::json!({"a": ["1", "3"], "b": "2"})
        );

        let iso = format_snippet("1795521600", "text", Some("ts-to-iso")).unwrap();
        assert!(iso.starts_with("2026-"));
    }

    #[test]
    fn broken_inputs_return_format_syntax_error_never_empty() {
        for (lang, bad) in [
            ("json", "{broken: "),
            ("yaml", "a: [1, 2"),
            ("toml", "a = [1, "),
            ("xml", "<root><unclosed></root>"),
        ] {
            let err = format_snippet(bad, lang, None).unwrap_err();
            assert_eq!(err.code(), ErrorCode::FormatSyntaxError);
        }
    }

    proptest! {
        #[test]
        fn json_format_is_idempotent_and_semantically_equivalent(
            pairs in prop::collection::vec(("[a-z]{1,8}", -1000i64..1000i64), 1..8)
        ) {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                map.insert(k, serde_json::Value::from(v));
            }
            let raw = serde_json::Value::Object(map).to_string();
            let f1 = format_snippet(&raw, "json", None).unwrap();
            let f2 = format_snippet(&f1, "json", None).unwrap();
            prop_assert_eq!(&f1, &f2);
            let p_raw: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let p_f1: serde_json::Value = serde_json::from_str(&f1).unwrap();
            prop_assert_eq!(p_raw, p_f1);
        }

        #[test]
        fn toml_and_yaml_format_are_idempotent_and_semantically_equivalent(
            pairs in prop::collection::vec(("[a-z]{1,8}", 0i64..500i64), 1..6)
        ) {
            let mut tbl = toml::map::Map::new();
            for (k, v) in pairs {
                tbl.insert(k, toml::Value::Integer(v));
            }
            let raw_toml = toml::to_string(&toml::Value::Table(tbl)).unwrap();
            let t1 = format_snippet(&raw_toml, "toml", None).unwrap();
            let t2 = format_snippet(&t1, "toml", None).unwrap();
            prop_assert_eq!(&t1, &t2);
            prop_assert_eq!(
                toml::from_str::<toml::Value>(&raw_toml).unwrap(),
                toml::from_str::<toml::Value>(&t1).unwrap()
            );

            let y1 = format_snippet(&raw_toml.replace(" = ", ": "), "yaml", None).unwrap();
            let y2 = format_snippet(&y1, "yaml", None).unwrap();
            prop_assert_eq!(&y1, &y2);
            prop_assert_eq!(
                serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&y1).unwrap(),
                serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&y2).unwrap()
            );
        }

        #[test]
        fn xml_format_is_idempotent_and_semantically_equivalent(
            tag in "[a-z]{2,6}",
            child in "[a-z]{2,6}",
            text in "[a-zA-Z0-9]{1,12}"
        ) {
            let raw = format!("<{tag}><{child}>{text}</{child}></{tag}>");
            let x1 = format_snippet(&raw, "xml", None).unwrap();
            let x2 = format_snippet(&x1, "xml", None).unwrap();
            prop_assert_eq!(&x1, &x2);
            let d1 = roxmltree::Document::parse(&raw).unwrap();
            let d2 = roxmltree::Document::parse(&x1).unwrap();
            prop_assert_eq!(d1.root_element().tag_name().name(), d2.root_element().tag_name().name());
            prop_assert_eq!(
                d1.root_element().first_element_child().unwrap().text(),
                d2.root_element().first_element_child().unwrap().text()
            );
        }
    }
}
