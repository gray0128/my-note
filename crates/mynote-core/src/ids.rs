use crate::error::{CoreError, ErrorCode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'H' => Some(b - b'A' + 10),
        b'J'..=b'K' => Some(b - b'J' + 18),
        b'M'..=b'N' => Some(b - b'M' + 20),
        b'P'..=b'T' => Some(b - b'P' + 22),
        b'V'..=b'Z' => Some(b - b'V' + 27),
        _ => None,
    }
}

/// Canonical 128-bit ULID stored as big-endian `[u8; 16]`.
/// Crockford Base32 uppercase 26-char encoding preserves exact lexicographical order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ulid([u8; 16]);

impl Ulid {
    pub const ZERO: Self = Self([0u8; 16]);

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn from_parts(timestamp_ms: u64, rand_80: [u8; 10]) -> Self {
        let mut bytes = [0u8; 16];
        let ts = timestamp_ms & 0x0000_FFFF_FFFF_FFFF;
        bytes[0] = (ts >> 40) as u8;
        bytes[1] = (ts >> 32) as u8;
        bytes[2] = (ts >> 24) as u8;
        bytes[3] = (ts >> 16) as u8;
        bytes[4] = (ts >> 8) as u8;
        bytes[5] = ts as u8;
        bytes[6..16].copy_from_slice(&rand_80);
        Self(bytes)
    }

    pub fn timestamp_ms(&self) -> u64 {
        ((self.0[0] as u64) << 40)
            | ((self.0[1] as u64) << 32)
            | ((self.0[2] as u64) << 24)
            | ((self.0[3] as u64) << 16)
            | ((self.0[4] as u64) << 8)
            | (self.0[5] as u64)
    }

    pub fn encode(&self) -> String {
        let val = u128::from_be_bytes(self.0);
        let mut out = [0u8; 26];
        for (i, slot) in out.iter_mut().enumerate() {
            let shift = (25 - i) * 5;
            *slot = CROCKFORD[((val >> shift) & 0x1F) as usize];
        }
        // SAFETY: CROCKFORD is strictly ASCII
        String::from_utf8(out.to_vec()).expect("ASCII")
    }

    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let bytes = s.as_bytes();
        if bytes.len() != 26 {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid ULID length {}: expected 26", bytes.len()),
                "Provide a valid 26-character uppercase Crockford Base32 ULID",
            ));
        }
        let first = crockford_val(bytes[0]).ok_or_else(|| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid ULID character in '{s}'"),
                "Provide a valid uppercase Crockford Base32 ULID",
            )
        })?;
        if first > 7 {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("ULID overflow in '{s}'"),
                "First ULID character must be in 0..=7",
            ));
        }
        let mut val: u128 = first as u128;
        for &b in &bytes[1..] {
            let v = crockford_val(b).ok_or_else(|| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid ULID character in '{s}'"),
                    "Provide a valid uppercase Crockford Base32 ULID",
                )
            })?;
            val = (val << 5) | (v as u128);
        }
        Ok(Self(val.to_be_bytes()))
    }
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl fmt::Debug for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ulid({})", self.encode())
    }
}

impl FromStr for Ulid {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Ulid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for Ulid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Sans-I/O monotonic ULID generator (`docs/data-structures.md` §1.1).
/// Within the same millisecond (or backward wall clock), increments the 80-bit low random part.
#[derive(Clone, Debug, Default)]
pub struct MonotonicUlidGen {
    last: Option<Ulid>,
}

impl MonotonicUlidGen {
    pub fn new() -> Self {
        Self { last: None }
    }

    pub fn next(&mut self, now_ms: u64, rand_80: [u8; 10]) -> Ulid {
        let candidate = match self.last {
            Some(prev) if now_ms <= prev.timestamp_ms() => {
                let mut val = u128::from_be_bytes(prev.0);
                val = val.saturating_add(1);
                Ulid(val.to_be_bytes())
            }
            _ => Ulid::from_parts(now_ms, rand_80),
        };
        self.last = Some(candidate);
        candidate
    }
}

macro_rules! define_ulid_newtype {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Ulid);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(Ulid::from_bytes(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            pub fn from_ulid(u: Ulid) -> Self {
                Self(u)
            }

            pub fn parse(s: &str) -> Result<Self, CoreError> {
                Ulid::parse(s).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl FromStr for $name {
            type Err = CoreError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }
    };
}

define_ulid_newtype!(BufferId);
define_ulid_newtype!(BlockId);
define_ulid_newtype!(OpId);
define_ulid_newtype!(KeyId);
define_ulid_newtype!(SmkKid);
define_ulid_newtype!(VkekKid);
define_ulid_newtype!(MarkId);
define_ulid_newtype!(SnapshotId);
define_ulid_newtype!(ClipId);
define_ulid_newtype!(ClipKid);

/// Device identifier (`dev_` + lowercase alphanumeric/underscore, strictly no hyphens `-`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn parse(s: impl Into<String>) -> Result<Self, CoreError> {
        let s = s.into();
        if !s.starts_with("dev_")
            || s.len() < 8
            || s.len() > 48
            || !s
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid DeviceId '{s}'"),
                "DeviceId must match 'dev_[a-z0-9_]+' without hyphens",
            ));
        }
        Ok(Self(s))
    }

    pub fn from_random_bytes(bytes: [u8; 10]) -> Self {
        const LOWER_B32: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
        let mut s = String::with_capacity(20);
        s.push_str("dev_");
        let mut val: u128 = 0;
        for b in bytes {
            val = (val << 8) | (b as u128);
        }
        for i in 0..16 {
            let idx = ((val >> ((15 - i) * 5)) & 0x1F) as usize;
            s.push(LOWER_B32[idx] as char);
        }
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for DeviceId {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(s).map_err(serde::de::Error::custom)
    }
}

/// Cloud DO journal epoch identifier (UUIDv4, `docs/data-structures.md` §1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JournalEpoch(uuid::Uuid);

impl JournalEpoch {
    pub fn from_random_bytes(mut bytes: [u8; 16]) -> Self {
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
        Self(uuid::Uuid::from_bytes(bytes))
    }

    pub fn parse(s: &str) -> Result<Self, CoreError> {
        uuid::Uuid::parse_str(s).map(Self).map_err(|_| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid JournalEpoch UUID '{s}'"),
                "Provide a canonical 36-character UUID string",
            )
        })
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for JournalEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for JournalEpoch {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_roundtrip_and_monotonic_order() {
        let mut g = MonotonicUlidGen::new();
        let u1 = g.next(1_795_521_600_123, [0x11; 10]);
        let u2 = g.next(1_795_521_600_123, [0x00; 10]); // same ms
        let u3 = g.next(1_795_521_600_100, [0x00; 10]); // backward ms
        let u4 = g.next(1_795_521_600_200, [0x00; 10]); // forward ms

        assert!(u1 < u2 && u2 < u3 && u3 < u4);
        assert!(u1.encode() < u2.encode());
        assert!(u2.encode() < u3.encode());
        assert!(u3.encode() < u4.encode());
        assert_eq!(Ulid::parse(&u1.encode()).unwrap(), u1);
        assert_eq!(u1.timestamp_ms(), 1_795_521_600_123);
    }

    #[test]
    fn device_id_rejects_hyphens() {
        assert!(DeviceId::parse("dev_01jdf8z9x4k7m2n5").is_ok());
        assert!(DeviceId::parse("dev_bad-hyphen").is_err());
        assert!(DeviceId::parse("mac_01234567").is_err());
    }

    #[test]
    fn clip_ids_roundtrip_and_preserve_order() {
        let mut g = MonotonicUlidGen::new();
        let c1 = ClipId::from_ulid(g.next(1_795_600_000_000, [0x11; 10]));
        let c2 = ClipId::from_ulid(g.next(1_795_600_000_000, [0x00; 10]));
        assert!(c1 < c2);
        assert_eq!(ClipId::parse(&c1.to_string()).unwrap(), c1);
        assert_eq!(ClipId::from_bytes(*c1.as_bytes()), c1);

        let k1 = ClipKid::parse("01JDF8Z9X4K7M2N5P8Q1R3S6T9").unwrap();
        assert_eq!(k1.to_string(), "01JDF8Z9X4K7M2N5P8Q1R3S6T9");
        assert_eq!(
            serde_json::to_string(&k1).unwrap(),
            "\"01JDF8Z9X4K7M2N5P8Q1R3S6T9\""
        );
        assert_eq!(
            serde_json::from_str::<ClipKid>("\"01JDF8Z9X4K7M2N5P8Q1R3S6T9\"").unwrap(),
            k1
        );
    }
}
