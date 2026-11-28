//! Zero-import Core WASM 3-Export (+ optional dealloc) guest plugin for S-Plugin-1.
//!
//! Exports (`docs/data-structures.md` §2.3):
//! - `mynote_abi_version() -> u32` (returns `1`)
//! - `mynote_alloc(len: u32) -> u32`
//! - `mynote_invoke(ptr: u32, len: u32) -> u64` (`(resp_ptr << 32) | resp_len`)
//! - `mynote_dealloc(ptr: u32, len: u32)`
//!
//! Built as `#![no_std]` + `alloc` for `wasm32-unknown-unknown` (`cdylib`, `< 50 KiB`,
//! zero `wasm-bindgen`, zero WASI/host imports) with an O(1) power-of-two segregated
//! free-list allocator so repeated warm invocations reuse linear memory with zero growth.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

pub const PLUGIN_WASM_ABI_VERSION: u32 = 1;
const ZERO_LEN_SENTINEL_PTR: u32 = 1;
const WASM_PAGE_BYTES: usize = 65_536;
const NUM_SIZE_CLASSES: usize = 22; // 16 B .. 32 MiB

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

unsafe extern "C" {
    static __heap_base: u8;
}

struct WasmSlabAlloc {
    state: UnsafeCell<AllocState>,
}

struct AllocState {
    initialized: bool,
    bump_ptr: usize,
    bump_end: usize,
    free_lists: [usize; NUM_SIZE_CLASSES],
}

// SAFETY: Core WASM guest modules are strictly single-threaded (`threads` proposal disabled).
unsafe impl Sync for WasmSlabAlloc {}

#[global_allocator]
static ALLOCATOR: WasmSlabAlloc = WasmSlabAlloc {
    state: UnsafeCell::new(AllocState {
        initialized: false,
        bump_ptr: 0,
        bump_end: 0,
        free_lists: [0; NUM_SIZE_CLASSES],
    }),
};

fn size_class_and_bytes(layout: Layout) -> Option<(usize, usize)> {
    let min_bytes = layout.size().max(layout.align()).max(16);
    let block_bytes = min_bytes.checked_next_power_of_two()?;
    let class = (block_bytes.trailing_zeros() as usize).saturating_sub(4);
    if class >= NUM_SIZE_CLASSES {
        return None;
    }
    Some((class, block_bytes))
}

#[cfg(target_arch = "wasm32")]
fn current_memory_bytes() -> usize {
    core::arch::wasm32::memory_size(0) * WASM_PAGE_BYTES
}

#[cfg(not(target_arch = "wasm32"))]
fn current_memory_bytes() -> usize {
    0
}

#[cfg(target_arch = "wasm32")]
fn grow_memory_pages(pages: usize) -> bool {
    core::arch::wasm32::memory_grow(0, pages) != usize::MAX
}

#[cfg(not(target_arch = "wasm32"))]
fn grow_memory_pages(_pages: usize) -> bool {
    false
}

unsafe impl GlobalAlloc for WasmSlabAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some((class, block_bytes)) = size_class_and_bytes(layout) else {
            return core::ptr::null_mut();
        };
        let st = unsafe { &mut *self.state.get() };
        if !st.initialized {
            let base = (&raw const __heap_base) as usize;
            st.bump_ptr = (base + 15) & !15;
            st.bump_end = current_memory_bytes();
            st.initialized = true;
        }

        let head = st.free_lists[class];
        if head != 0 {
            st.free_lists[class] = unsafe { *(head as *const usize) };
            return head as *mut u8;
        }

        let aligned_ptr = (st.bump_ptr + (block_bytes - 1)) & !(block_bytes - 1);
        let Some(new_bump) = aligned_ptr.checked_add(block_bytes) else {
            return core::ptr::null_mut();
        };
        if new_bump > st.bump_end {
            let needed_bytes = new_bump - st.bump_end;
            let needed_pages = needed_bytes.div_ceil(WASM_PAGE_BYTES);
            if !grow_memory_pages(needed_pages) {
                return core::ptr::null_mut();
            }
            st.bump_end = current_memory_bytes();
        }
        st.bump_ptr = new_bump;
        aligned_ptr as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let Some((class, _)) = size_class_and_bytes(layout) else {
            return;
        };
        let st = unsafe { &mut *self.state.get() };
        let addr = ptr as usize;
        unsafe {
            *(addr as *mut usize) = st.free_lists[class];
        }
        st.free_lists[class] = addr;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mynote_abi_version() -> u32 {
    PLUGIN_WASM_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn mynote_alloc(len: u32) -> u32 {
    if len == 0 {
        return ZERO_LEN_SENTINEL_PTR;
    }
    let Ok(layout) = Layout::from_size_align(len as usize, 1) else {
        return 0;
    };
    let ptr = unsafe { alloc::alloc::alloc(layout) };
    ptr as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn mynote_dealloc(ptr: u32, len: u32) {
    if len == 0 || ptr <= ZERO_LEN_SENTINEL_PTR {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(len as usize, 1) {
        unsafe { alloc::alloc::dealloc(ptr as *mut u8, layout) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mynote_invoke(ptr: u32, len: u32) -> u64 {
    let input_bytes: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
    };

    let response_json = match core::str::from_utf8(input_bytes) {
        Ok(req_str) => handle_request_str(req_str),
        Err(_) => toast_error_json("invalid UTF-8 request payload"),
    };

    pack_response(response_json.into_bytes())
}

fn pack_response(bytes: Vec<u8>) -> u64 {
    if bytes.is_empty() {
        return (ZERO_LEN_SENTINEL_PTR as u64) << 32;
    }
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    let len = boxed.len() as u32;
    let ptr = Box::into_raw(boxed) as *mut u8 as u32;
    ((ptr as u64) << 32) | (len as u64)
}

fn handle_request_str(req_str: &str) -> String {
    let parsed = match JsonVal::parse(req_str) {
        Ok(v) => v,
        Err(msg) => return toast_error_json_prefix("invalid request JSON: ", msg),
    };
    let JsonVal::Object(map) = parsed else {
        return toast_error_json("request root must be a JSON object");
    };

    let action = map
        .get("action")
        .and_then(JsonVal::as_str)
        .unwrap_or("eval_lines");
    let content = map.get("content").and_then(JsonVal::as_str).unwrap_or("");

    match action {
        "eval_lines" => eval_lines_gutter(content),
        "eval_replace" => eval_lines_replace(content),
        "json_canonicalize" => canonicalize_content_json(content),
        other => toast_error_json_prefix("unknown action: ", other),
    }
}

fn eval_lines_gutter(content: &str) -> String {
    let mut vars: BTreeMap<String, f64> = BTreeMap::new();
    let mut annotations = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = strip_line_comment(raw_line).trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((var_opt, expr_src)) = split_assignment(trimmed) {
            if let Ok(val) = eval_expr(expr_src, &vars) {
                if val.is_finite() {
                    if let Some(name) = var_opt {
                        vars.insert(String::from(name), val);
                    }
                    let formatted = format_f64(val);
                    let mut text = String::with_capacity(2 + formatted.len());
                    text.push_str("= ");
                    text.push_str(&formatted);

                    let mut ann = BTreeMap::new();
                    ann.insert(String::from("line"), JsonVal::Number(line_no as f64));
                    ann.insert(String::from("text"), JsonVal::Str(text));
                    ann.insert(String::from("copy"), JsonVal::Str(formatted));
                    annotations.push(JsonVal::Object(ann));
                }
            }
        }
    }

    let mut out = BTreeMap::new();
    out.insert(String::from("kind"), JsonVal::Str(String::from("gutter")));
    out.insert(String::from("annotations"), JsonVal::Array(annotations));
    JsonVal::Object(out).to_compact_json()
}

fn eval_lines_replace(content: &str) -> String {
    let mut vars: BTreeMap<String, f64> = BTreeMap::new();
    let mut joined = String::with_capacity(content.len() + 32);

    for (i, raw_line) in content.lines().enumerate() {
        if i > 0 {
            joined.push('\n');
        }
        let trimmed = strip_line_comment(raw_line).trim();
        if trimmed.is_empty() {
            joined.push_str(raw_line);
            continue;
        }
        let clean = trimmed.strip_suffix('=').map(str::trim).unwrap_or(trimmed);
        if let Some((var_opt, expr_src)) = split_assignment(clean) {
            if let Ok(val) = eval_expr(expr_src, &vars) {
                if val.is_finite() {
                    if let Some(name) = var_opt {
                        vars.insert(String::from(name), val);
                    }
                    let formatted = format_f64(val);
                    joined.push_str(clean);
                    joined.push_str(" = ");
                    joined.push_str(&formatted);
                    continue;
                }
            }
        }
        joined.push_str(raw_line);
    }

    let mut out = BTreeMap::new();
    out.insert(
        String::from("kind"),
        JsonVal::Str(String::from("replace_content")),
    );
    out.insert(String::from("content"), JsonVal::Str(joined));
    out.insert(String::from("lang"), JsonVal::Str(String::from("text")));
    JsonVal::Object(out).to_compact_json()
}

fn canonicalize_content_json(content: &str) -> String {
    match JsonVal::parse(content) {
        Ok(val) => {
            let pretty = val.to_pretty_json(0);
            let mut out = BTreeMap::new();
            out.insert(
                String::from("kind"),
                JsonVal::Str(String::from("replace_content")),
            );
            out.insert(String::from("content"), JsonVal::Str(pretty));
            out.insert(String::from("lang"), JsonVal::Str(String::from("json")));
            JsonVal::Object(out).to_compact_json()
        }
        Err(err) => toast_error_json_prefix("JSON syntax error: ", err),
    }
}

fn toast_error_json(msg: &str) -> String {
    let mut out = BTreeMap::new();
    out.insert(String::from("kind"), JsonVal::Str(String::from("toast")));
    out.insert(String::from("level"), JsonVal::Str(String::from("error")));
    out.insert(String::from("message"), JsonVal::Str(String::from(msg)));
    JsonVal::Object(out).to_compact_json()
}

fn toast_error_json_prefix(prefix: &str, detail: &str) -> String {
    let mut s = String::with_capacity(prefix.len() + detail.len());
    s.push_str(prefix);
    s.push_str(detail);
    toast_error_json(&s)
}

fn strip_line_comment(line: &str) -> &str {
    match line.find('#').or_else(|| line.find("//")) {
        Some(idx) => &line[..idx],
        None => line,
    }
}

fn split_assignment(s: &str) -> Option<(Option<&str>, &str)> {
    if let Some(eq_idx) = s.find('=') {
        let lhs = s[..eq_idx].trim();
        let rhs = s[eq_idx + 1..].trim();
        if !lhs.is_empty() && is_ident(lhs) && !rhs.starts_with('=') {
            return Some((Some(lhs), rhs));
        }
    }
    Some((None, s))
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// --- Zero-flt2dec / zero-dec2flt decimal number codec ---

fn push_u64_dec(out: &mut String, mut n: u64) {
    if n == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut len = 0;
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        out.push(buf[len] as char);
    }
}

fn format_f64(v: f64) -> String {
    if !v.is_finite() {
        return String::from("0");
    }
    let mut out = String::with_capacity(24);
    let abs_v = wasm_abs(v);
    if abs_v == 0.0 {
        out.push('0');
        return out;
    }
    if v < 0.0 {
        out.push('-');
    }
    // Scale by 10^8 for clean scratchpad decimal display without core::fmt::float (`flt2dec`).
    const SCALE: f64 = 100_000_000.0;
    if abs_v < 9e10 {
        let scaled = wasm_nearest(abs_v * SCALE) as u128;
        let int_part = (scaled / 100_000_000) as u64;
        let mut frac_part = (scaled % 100_000_000) as u64;
        push_u64_dec(&mut out, int_part);
        if frac_part > 0 {
            out.push('.');
            let mut digits = [b'0'; 8];
            for i in (0..8).rev() {
                digits[i] = b'0' + (frac_part % 10) as u8;
                frac_part /= 10;
            }
            let mut end = 8;
            while end > 0 && digits[end - 1] == b'0' {
                end -= 1;
            }
            for &d in &digits[..end] {
                out.push(d as char);
            }
        }
    } else if abs_v < (u64::MAX as f64) {
        push_u64_dec(&mut out, wasm_nearest(abs_v) as u64);
    } else {
        out.push_str("overflow");
    }
    out
}

fn parse_decimal_f64(bytes: &[u8]) -> Result<f64, &'static str> {
    if bytes.is_empty() {
        return Err("empty number");
    }
    let mut i = 0;
    let mut neg = false;
    if bytes[i] == b'-' {
        neg = true;
        i += 1;
    } else if bytes[i] == b'+' {
        i += 1;
    }
    let mut mantissa: f64 = 0.0;
    let mut any_digit = false;
    while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
        if bytes[i] != b'_' {
            mantissa = mantissa * 10.0 + (bytes[i] - b'0') as f64;
            any_digit = true;
        }
        i += 1;
    }
    let mut frac_exp: i32 = 0;
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
            if bytes[i] != b'_' {
                mantissa = mantissa * 10.0 + (bytes[i] - b'0') as f64;
                frac_exp -= 1;
                any_digit = true;
            }
            i += 1;
        }
    }
    if !any_digit {
        return Err("missing digits");
    }
    let mut sci_exp: i32 = 0;
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        i += 1;
        let mut exp_neg = false;
        if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
            exp_neg = bytes[i] == b'-';
            i += 1;
        }
        let mut exp_digits = false;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            sci_exp = sci_exp
                .saturating_mul(10)
                .saturating_add((bytes[i] - b'0') as i32);
            exp_digits = true;
            i += 1;
        }
        if !exp_digits {
            return Err("invalid exponent");
        }
        if exp_neg {
            sci_exp = -sci_exp;
        }
    }
    if i != bytes.len() {
        return Err("invalid number token");
    }
    let total_exp = frac_exp.saturating_add(sci_exp);
    let val = apply_pow10(mantissa, total_exp);
    if !val.is_finite() {
        return Err("number overflow");
    }
    Ok(if neg { -val } else { val })
}

fn apply_pow10(mut v: f64, exp: i32) -> f64 {
    if exp >= 0 {
        let mut e = exp as u32;
        let mut base = 10.0_f64;
        while e > 0 {
            if e & 1 == 1 {
                v *= base;
            }
            base *= base;
            e >>= 1;
        }
        v
    } else {
        let mut e = (-exp) as u32;
        let mut base = 10.0_f64;
        let mut div = 1.0_f64;
        while e > 0 {
            if e & 1 == 1 {
                div *= base;
            }
            base *= base;
            e >>= 1;
        }
        v / div
    }
}

fn int_pow(mut base: f64, mut exp: i32) -> f64 {
    if exp == 0 {
        return 1.0;
    }
    let inv = exp < 0;
    if inv {
        exp = -exp;
    }
    let mut e = exp as u32;
    let mut acc = 1.0_f64;
    while e > 0 {
        if e & 1 == 1 {
            acc *= base;
        }
        base *= base;
        e >>= 1;
    }
    if inv {
        1.0 / acc
    } else {
        acc
    }
}

// Pure stable `no_std` IEEE-754 `f64` math helpers (zero `libm` / nightly intrinsics)
#[inline]
fn wasm_sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut g = f64::from_bits((x.to_bits() >> 1) + (0x3ff0_0000_0000_0000 >> 1));
    for _ in 0..6 {
        g = 0.5 * (g + x / g);
    }
    g
}

#[inline]
fn wasm_abs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & 0x7fff_ffff_ffff_ffff)
}

#[inline]
fn wasm_floor(x: f64) -> f64 {
    const TWO_POW_52: f64 = 4_503_599_627_370_496.0;
    if wasm_abs(x) >= TWO_POW_52 {
        return x;
    }
    let t = (x as i64) as f64;
    if t > x {
        t - 1.0
    } else {
        t
    }
}

#[inline]
fn wasm_ceil(x: f64) -> f64 {
    const TWO_POW_52: f64 = 4_503_599_627_370_496.0;
    if wasm_abs(x) >= TWO_POW_52 {
        return x;
    }
    let t = (x as i64) as f64;
    if t < x {
        t + 1.0
    } else {
        t
    }
}

#[inline]
fn wasm_nearest(x: f64) -> f64 {
    if x >= 0.0 {
        wasm_floor(x + 0.5)
    } else {
        wasm_ceil(x - 0.5)
    }
}

// --- Recursive-descent arithmetic evaluator ---

struct ExprParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    vars: &'a BTreeMap<String, f64>,
}

fn eval_expr(src: &str, vars: &BTreeMap<String, f64>) -> Result<f64, &'static str> {
    let mut p = ExprParser {
        bytes: src.as_bytes(),
        pos: 0,
        vars,
    };
    let val = p.parse_add_sub()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err("unexpected trailing token");
    }
    Ok(val)
}

impl<'a> ExprParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    fn parse_add_sub(&mut self) -> Result<f64, &'static str> {
        let mut acc = self.parse_mul_div()?;
        while let Some(op) = self.peek() {
            if op == b'+' || op == b'-' {
                self.pos += 1;
                let rhs = self.parse_mul_div()?;
                acc = if op == b'+' { acc + rhs } else { acc - rhs };
            } else {
                break;
            }
        }
        Ok(acc)
    }

    fn parse_mul_div(&mut self) -> Result<f64, &'static str> {
        let mut acc = self.parse_pow()?;
        while let Some(op) = self.peek() {
            if op == b'*' || op == b'/' || op == b'%' {
                self.pos += 1;
                let rhs = self.parse_pow()?;
                if (op == b'/' || op == b'%') && rhs == 0.0 {
                    return Err("division by zero");
                }
                acc = match op {
                    b'*' => acc * rhs,
                    b'/' => acc / rhs,
                    _ => acc - wasm_floor(acc / rhs) * rhs,
                };
            } else {
                break;
            }
        }
        Ok(acc)
    }

    fn parse_pow(&mut self) -> Result<f64, &'static str> {
        let base = self.parse_unary()?;
        if self.peek() == Some(b'^') {
            self.pos += 1;
            let exp = self.parse_pow()?;
            let rounded = wasm_nearest(exp);
            if wasm_abs(exp - rounded) < 1e-9 && wasm_abs(rounded) <= 1024.0 {
                Ok(int_pow(base, rounded as i32))
            } else if wasm_abs(exp - 0.5) < 1e-9 && base >= 0.0 {
                Ok(wasm_sqrt(base))
            } else {
                Err("fractional exponent unsupported")
            }
        } else {
            Ok(base)
        }
    }

    fn parse_unary(&mut self) -> Result<f64, &'static str> {
        match self.peek() {
            Some(b'+') => {
                self.pos += 1;
                self.parse_unary()
            }
            Some(b'-') => {
                self.pos += 1;
                Ok(-self.parse_unary()?)
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<f64, &'static str> {
        self.skip_ws();
        let Some(ch) = self.bytes.get(self.pos).copied() else {
            return Err("unexpected end of expression");
        };
        if ch == b'(' {
            self.pos += 1;
            let val = self.parse_add_sub()?;
            if self.peek() != Some(b')') {
                return Err("missing closing parenthesis");
            }
            self.pos += 1;
            return Ok(val);
        }
        if ch.is_ascii_digit() || ch == b'.' {
            let start = self.pos;
            while self.pos < self.bytes.len()
                && (self.bytes[self.pos].is_ascii_digit()
                    || self.bytes[self.pos] == b'.'
                    || self.bytes[self.pos] == b'_')
            {
                self.pos += 1;
            }
            return parse_decimal_f64(&self.bytes[start..self.pos]);
        }
        if ch.is_ascii_alphabetic() || ch == b'_' {
            let start = self.pos;
            while self.pos < self.bytes.len()
                && (self.bytes[self.pos].is_ascii_alphanumeric() || self.bytes[self.pos] == b'_')
            {
                self.pos += 1;
            }
            let ident = core::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| "utf8")?;
            if self.peek() == Some(b'(') {
                self.pos += 1;
                let mut args = Vec::new();
                if self.peek() != Some(b')') {
                    loop {
                        args.push(self.parse_add_sub()?);
                        if self.peek() == Some(b',') {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                }
                if self.peek() != Some(b')') {
                    return Err("unclosed function call");
                }
                self.pos += 1;
                return eval_builtin_fn(ident, &args);
            }
            return match ident {
                "pi" | "PI" => Ok(core::f64::consts::PI),
                "e" | "E" => Ok(core::f64::consts::E),
                _ => self.vars.get(ident).copied().ok_or("unknown variable"),
            };
        }
        Err("unexpected character")
    }
}

fn eval_builtin_fn(name: &str, args: &[f64]) -> Result<f64, &'static str> {
    match (name, args) {
        ("sqrt", [x]) if *x >= 0.0 => Ok(wasm_sqrt(*x)),
        ("abs", [x]) => Ok(wasm_abs(*x)),
        ("round", [x]) => Ok(wasm_nearest(*x)),
        ("floor", [x]) => Ok(wasm_floor(*x)),
        ("ceil", [x]) => Ok(wasm_ceil(*x)),
        ("min", [first, rest @ ..]) => Ok(rest.iter().copied().fold(*first, f64::min)),
        ("max", [first, rest @ ..]) => Ok(rest.iter().copied().fold(*first, f64::max)),
        _ => Err("unsupported function or arity"),
    }
}

// --- Zero-dependency RFC 8259 JSON value parser & canonical serializer ---

#[derive(Clone)]
enum JsonVal {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Array(Vec<JsonVal>),
    Object(BTreeMap<String, JsonVal>),
}

impl JsonVal {
    fn as_str(&self) -> Option<&str> {
        match self {
            JsonVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn parse(src: &str) -> Result<Self, &'static str> {
        let mut p = JsonParser {
            bytes: src.as_bytes(),
            pos: 0,
            depth: 0,
        };
        let val = p.parse_value()?;
        p.skip_ws();
        if p.pos != p.bytes.len() {
            return Err("trailing characters");
        }
        Ok(val)
    }

    fn to_compact_json(&self) -> String {
        let mut out = String::new();
        self.write_compact(&mut out);
        out
    }

    fn to_pretty_json(&self, indent: usize) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, indent);
        out
    }

    fn write_compact(&self, out: &mut String) {
        match self {
            JsonVal::Null => out.push_str("null"),
            JsonVal::Bool(true) => out.push_str("true"),
            JsonVal::Bool(false) => out.push_str("false"),
            JsonVal::Number(n) => out.push_str(&format_f64(*n)),
            JsonVal::Str(s) => write_escaped_str(out, s),
            JsonVal::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_compact(out);
                }
                out.push(']');
            }
            JsonVal::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped_str(out, k);
                    out.push(':');
                    v.write_compact(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, indent: usize) {
        match self {
            JsonVal::Array(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    for _ in 0..(indent + 2) {
                        out.push(' ');
                    }
                    item.write_pretty(out, indent + 2);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                for _ in 0..indent {
                    out.push(' ');
                }
                out.push(']');
            }
            JsonVal::Object(map) if !map.is_empty() => {
                out.push_str("{\n");
                for (i, (k, v)) in map.iter().enumerate() {
                    for _ in 0..(indent + 2) {
                        out.push(' ');
                    }
                    write_escaped_str(out, k);
                    out.push_str(": ");
                    v.write_pretty(out, indent + 2);
                    if i + 1 < map.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                for _ in 0..indent {
                    out.push(' ');
                }
                out.push('}');
            }
            _ => self.write_compact(out),
        }
    }
}

fn push_hex4(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[((code >> 12) & 0xf) as usize] as char);
    out.push(HEX[((code >> 8) & 0xf) as usize] as char);
    out.push(HEX[((code >> 4) & 0xf) as usize] as char);
    out.push(HEX[(code & 0xf) as usize] as char);
}

fn write_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                push_hex4(out, c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> Result<JsonVal, &'static str> {
        if self.depth > 64 {
            return Err("nesting depth exceeded");
        }
        self.skip_ws();
        let Some(b) = self.bytes.get(self.pos).copied() else {
            return Err("unexpected EOF");
        };
        match b {
            b'n' => {
                if self.bytes[self.pos..].starts_with(b"null") {
                    self.pos += 4;
                    Ok(JsonVal::Null)
                } else {
                    Err("invalid literal")
                }
            }
            b't' => {
                if self.bytes[self.pos..].starts_with(b"true") {
                    self.pos += 4;
                    Ok(JsonVal::Bool(true))
                } else {
                    Err("invalid literal")
                }
            }
            b'f' => {
                if self.bytes[self.pos..].starts_with(b"false") {
                    self.pos += 5;
                    Ok(JsonVal::Bool(false))
                } else {
                    Err("invalid literal")
                }
            }
            b'"' => Ok(JsonVal::Str(self.parse_string()?)),
            b'[' => {
                self.pos += 1;
                self.depth += 1;
                let mut arr = Vec::new();
                self.skip_ws();
                if self.bytes.get(self.pos) == Some(&b']') {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(JsonVal::Array(arr));
                }
                loop {
                    arr.push(self.parse_value()?);
                    self.skip_ws();
                    match self.bytes.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            self.depth -= 1;
                            return Ok(JsonVal::Array(arr));
                        }
                        _ => return Err("expected ',' or ']'"),
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                self.depth += 1;
                let mut map = BTreeMap::new();
                self.skip_ws();
                if self.bytes.get(self.pos) == Some(&b'}') {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(JsonVal::Object(map));
                }
                loop {
                    self.skip_ws();
                    let key = self.parse_string()?;
                    self.skip_ws();
                    if self.bytes.get(self.pos) != Some(&b':') {
                        return Err("expected ':'");
                    }
                    self.pos += 1;
                    let val = self.parse_value()?;
                    map.insert(key, val);
                    self.skip_ws();
                    match self.bytes.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            self.depth -= 1;
                            return Ok(JsonVal::Object(map));
                        }
                        _ => return Err("expected ',' or '}'"),
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                if b == b'-' {
                    self.pos += 1;
                }
                while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b'.' {
                    self.pos += 1;
                    while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                        self.pos += 1;
                    }
                }
                if self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b'e' | b'E') {
                    self.pos += 1;
                    if self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b'+' | b'-') {
                        self.pos += 1;
                    }
                    while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                        self.pos += 1;
                    }
                }
                Ok(JsonVal::Number(parse_decimal_f64(&self.bytes[start..self.pos])?))
            }
            _ => Err("unexpected token"),
        }
    }

    fn parse_string(&mut self) -> Result<String, &'static str> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err("expected '\"'");
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            if b == b'"' {
                return Ok(out);
            }
            if b == b'\\' {
                let Some(esc) = self.bytes.get(self.pos).copied() else {
                    return Err("unterminated escape");
                };
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        if self.pos + 4 > self.bytes.len() {
                            return Err("short unicode escape");
                        }
                        let mut code = 0u32;
                        for &hb in &self.bytes[self.pos..self.pos + 4] {
                            let digit = match hb {
                                b'0'..=b'9' => (hb - b'0') as u32,
                                b'a'..=b'f' => (hb - b'a' + 10) as u32,
                                b'A'..=b'F' => (hb - b'A' + 10) as u32,
                                _ => return Err("invalid hex"),
                            };
                            code = (code << 4) | digit;
                        }
                        self.pos += 4;
                        let ch = char::from_u32(code).ok_or("invalid surrogate")?;
                        out.push(ch);
                    }
                    _ => return Err("unknown escape"),
                }
            } else if b < 0x80 {
                if b < 0x20 {
                    return Err("unescaped control char");
                }
                out.push(b as char);
            } else {
                let rem = &self.bytes[self.pos - 1..];
                let window = &rem[..rem.len().min(4)];
                let s = match core::str::from_utf8(window) {
                    Ok(valid) => valid,
                    Err(e) => core::str::from_utf8(&window[..e.valid_up_to()]).unwrap_or(""),
                };
                let Some(ch) = s.chars().next() else {
                    return Err("invalid UTF-8 in string");
                };
                self.pos += ch.len_utf8() - 1;
                out.push(ch);
            }
        }
        Err("unterminated string")
    }
}
