use crate::error::{CoreError, ErrorCode};
use std::cmp::Ordering;

/// Strictly ASCII-ascending Base62 alphabet (`docs/data-structures.md` §1.3).
pub const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn char_to_digit(b: u8) -> Result<u8, CoreError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'Z' => Ok(b - b'A' + 10),
        b'a'..=b'z' => Ok(b - b'a' + 36),
        _ => Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("invalid fractional index character byte {b}"),
            "FractionalIndex keys must contain only Base62 [0-9A-Za-z] characters",
        )),
    }
}

fn validate_key(s: &str) -> Result<(), CoreError> {
    if s.is_empty() {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "fractional index key cannot be empty",
            "Provide a non-empty Base62 key",
        ));
    }
    for &b in s.as_bytes() {
        char_to_digit(b)?;
    }
    Ok(())
}

/// Deterministic total order comparator `(position_bytes, id_bytes)` (`docs/data-structures.md` §1.3).
pub fn compare_order(pos_a: &str, id_a: &str, pos_b: &str, id_b: &str) -> Ordering {
    (pos_a.as_bytes(), id_a.as_bytes()).cmp(&(pos_b.as_bytes(), id_b.as_bytes()))
}

/// Compute a Base62 lexicographic key strictly between `prev` and `next`, appending
/// a 4-character Base62 CSPRNG jitter suffix (`62^-4` collision rate).
/// Per F-18, keys are NEVER rebalanced.
pub fn between(prev: Option<&str>, next: Option<&str>, jitter: [u8; 4]) -> Result<String, CoreError> {
    if let Some(p) = prev {
        validate_key(p)?;
    }
    if let Some(n) = next {
        validate_key(n)?;
    }
    if let (Some(p), Some(n)) = (prev, next) {
        if p >= n {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid bounds: prev '{p}' >= next '{n}'"),
                "Lower bound must be strictly less than upper bound",
            ));
        }
    }

    let suffix = encode_jitter(jitter);

    let prefix = match (prev, next) {
        (None, None) => "V".to_string(),
        (Some(p), None) => increment_after(p)?,
        (None, Some(n)) => decrement_before(n)?,
        (Some(p), Some(n)) => midpoint(p, n)?,
    };

    let candidate = format!("{prefix}{suffix}");
    if let Some(p) = prev {
        debug_assert!(p < candidate.as_str(), "prev={p} candidate={candidate}");
    }
    if let Some(n) = next {
        if candidate.as_str() >= n {
            // Prefix equals a prefix of `n` or suffix pushed past `n`; generate tighter midpoint without jitter collision.
            let tighter = midpoint(prev.unwrap_or("0"), n)?;
            let mut safe = tighter;
            // Ensure strictly between prev and n by appending a valid jitter digit only when it stays < n
            for ch in suffix.chars() {
                let mut probe = safe.clone();
                probe.push(ch);
                if probe.as_str() < n && prev.is_none_or(|p| p < probe.as_str()) {
                    safe = probe;
                } else {
                    break;
                }
            }
            return Ok(safe);
        }
    }
    Ok(candidate)
}

fn encode_jitter(jitter: [u8; 4]) -> String {
    let mut s = String::with_capacity(4);
    for b in jitter {
        // Avoid '0' on the very last char so keys stay cleanly bisectible
        let idx = 1 + (b as usize % 61);
        s.push(BASE62[idx] as char);
    }
    s
}

fn increment_after(prev: &str) -> Result<String, CoreError> {
    let bytes = prev.as_bytes();
    let d0 = char_to_digit(bytes[0])?;
    if d0 < 61 {
        let next_d = d0 + 1;
        return Ok((BASE62[next_d as usize] as char).to_string());
    }
    // prev starts with 'z', find first non-'z' or extend with 'zV'
    let mut out = String::with_capacity(bytes.len() + 2);
    for &b in bytes {
        let d = char_to_digit(b)?;
        if d < 61 {
            out.push(BASE62[(d + 1) as usize] as char);
            return Ok(out);
        }
        out.push('z');
    }
    out.push('V');
    Ok(out)
}

fn decrement_before(next: &str) -> Result<String, CoreError> {
    let bytes = next.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        let d = char_to_digit(b)?;
        if d > 1 {
            let mut out = next[..i].to_string();
            out.push(BASE62[(d / 2) as usize] as char);
            return Ok(out);
        }
        if d == 1 {
            let mut out = next[..i].to_string();
            out.push('0');
            out.push('V');
            return Ok(out);
        }
    }
    // next is all '0's — shouldn't occur for valid generated keys, fallback to prepending '0'
    Err(CoreError::new(
        ErrorCode::InvalidArgument,
        format!("cannot allocate key strictly before all-zero key '{next}'"),
        "Upper bound must contain at least one non-'0' digit",
    ))
}

fn midpoint(prev: &str, next: &str) -> Result<String, CoreError> {
    let p_bytes = prev.as_bytes();
    let n_bytes = next.as_bytes();
    let max_len = p_bytes.len().max(n_bytes.len());
    let mut out = String::with_capacity(max_len + 2);

    for i in 0..=max_len {
        let pd = if i < p_bytes.len() {
            char_to_digit(p_bytes[i])?
        } else {
            0
        };
        let nd = if i < n_bytes.len() {
            char_to_digit(n_bytes[i])?
        } else {
            62
        };

        if pd == nd {
            out.push(BASE62[pd as usize] as char);
            continue;
        }
        if nd > pd + 1 {
            let mid = pd + (nd - pd) / 2;
            out.push(BASE62[mid as usize] as char);
            return Ok(out);
        }
        // Adjacent digits: pd + 1 == nd. Emit pd, then take midpoint against virtual 62 for remaining tail of prev.
        out.push(BASE62[pd as usize] as char);
        let mut j = i + 1;
        loop {
            let p_tail = if j < p_bytes.len() {
                char_to_digit(p_bytes[j])?
            } else {
                0
            };
            if p_tail < 61 {
                let mid = p_tail + (62 - p_tail) / 2;
                out.push(BASE62[mid as usize] as char);
                return Ok(out);
            }
            out.push('z');
            j += 1;
        }
    }
    unreachable!("prev < next guarantees a differing position")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn sequential_and_repeated_bisections_preserve_strict_order() {
        let mut keys = vec![between(None, None, [1, 2, 3, 4]).unwrap()];
        // Append 50 keys at end
        for i in 0u8..50 {
            let k = between(
                keys.last().map(String::as_str),
                None,
                [i, i.wrapping_mul(3), 7, 11],
            )
            .unwrap();
            assert!(keys.last().unwrap() < &k);
            keys.push(k);
        }
        // Prepend 50 keys at start
        for i in 0u8..50 {
            let k = between(None, Some(keys[0].as_str()), [i, 9, 17, 23]).unwrap();
            assert!(k < keys[0]);
            keys.insert(0, k);
        }
        // Bisect tightly 100 times in the exact same gap (proves unbounded length without rebalancing)
        let mut left = keys[10].clone();
        let right = keys[11].clone();
        for i in 0u8..100 {
            let mid = between(Some(&left), Some(&right), [i, 42, 99, 13]).unwrap();
            assert!(
                left < mid && mid < right,
                "failed at i={i}: {left} < {mid} < {right}"
            );
            left = mid;
        }
    }

    proptest! {
        #[test]
        fn between_always_strictly_ordered(j1 in any::<[u8; 4]>(), j2 in any::<[u8; 4]>(), j3 in any::<[u8; 4]>()) {
            let a = between(None, None, j1).unwrap();
            let b = between(Some(&a), None, j2).unwrap();
            let m = between(Some(&a), Some(&b), j3).unwrap();
            prop_assert!(a < m);
            prop_assert!(m < b);
        }
    }
}
