use crate::error::{CoreError, ErrorCode};
use crate::ids::DeviceId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Local UI warning threshold for remote clock skew (5 minutes, `docs/data-structures.md` §1.2).
/// Per F-03 / D3, remote ops are NEVER rejected or clamped regardless of skew.
pub const CLOCK_SKEW_WARN_MS: u64 = 300_000;

/// Fixed-width canonical Hybrid Logical Clock (`docs/data-structures.md` §1.2).
/// String form `"{wall_ms:015}-{counter:05}-{device_id}"` has byte order isomorphic to tuple order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u16,
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockSkewWarning {
    pub skew_ms: i64,
    pub remote_device_id: DeviceId,
}

impl Hlc {
    pub fn new(wall_ms: u64, counter: u16, device_id: DeviceId) -> Self {
        Self {
            wall_ms,
            counter,
            device_id,
        }
    }

    pub fn canonical_string(&self) -> String {
        format!(
            "{:015}-{:05}-{}",
            self.wall_ms,
            self.counter,
            self.device_id.as_str()
        )
    }

    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let mut parts = s.splitn(3, '-');
        let wall_str = parts.next().unwrap_or("");
        let cnt_str = parts.next().unwrap_or("");
        let dev_str = parts.next().unwrap_or("");
        if wall_str.len() != 15 || cnt_str.len() != 5 || dev_str.is_empty() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid canonical HLC '{s}'"),
                "Expected fixed-width HLC '<15-digit wall_ms>-<5-digit counter>-<device_id>'",
            ));
        }
        let wall_ms = wall_str.parse::<u64>().map_err(|_| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid HLC wall_ms in '{s}'"),
                "wall_ms must be a 15-digit unsigned integer",
            )
        })?;
        let counter = cnt_str.parse::<u16>().map_err(|_| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid HLC counter in '{s}'"),
                "counter must be a 5-digit u16",
            )
        })?;
        let device_id = DeviceId::parse(dev_str)?;
        Ok(Self {
            wall_ms,
            counter,
            device_id,
        })
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:015}-{:05}-{}",
            self.wall_ms,
            self.counter,
            self.device_id.as_str()
        )
    }
}

impl FromStr for Hlc {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Hlc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.canonical_string())
    }
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Sans-I/O HLC clock state for a single device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HlcClock {
    device_id: DeviceId,
    last_wall_ms: u64,
    last_counter: u16,
}

impl HlcClock {
    pub fn new(device_id: DeviceId, initial_wall_ms: u64) -> Self {
        Self {
            device_id,
            last_wall_ms: initial_wall_ms,
            last_counter: 0,
        }
    }

    pub fn from_last(hlc: Hlc) -> Self {
        Self {
            device_id: hlc.device_id,
            last_wall_ms: hlc.wall_ms,
            last_counter: hlc.counter,
        }
    }

    pub fn current(&self) -> Hlc {
        Hlc::new(self.last_wall_ms, self.last_counter, self.device_id.clone())
    }

    /// Generate the next strictly greater local HLC timestamp.
    pub fn tick(&mut self, now_ms: u64) -> Hlc {
        if now_ms > self.last_wall_ms {
            self.last_wall_ms = now_ms;
            self.last_counter = 0;
        } else if let Some(next_cnt) = self.last_counter.checked_add(1) {
            self.last_counter = next_cnt;
        } else {
            self.last_wall_ms = self.last_wall_ms.saturating_add(1);
            self.last_counter = 0;
        }
        self.current()
    }

    /// Merge a remote HLC into local clock without EVER clamping or rejecting (`F-03`).
    /// Emits `Some(ClockSkewWarning)` if remote clock exceeds local wall clock by > 5 minutes.
    pub fn receive(&mut self, now_ms: u64, remote: &Hlc) -> (Hlc, Option<ClockSkewWarning>) {
        let skew_warning = if remote.wall_ms > now_ms.saturating_add(CLOCK_SKEW_WARN_MS) {
            Some(ClockSkewWarning {
                skew_ms: (remote.wall_ms - now_ms) as i64,
                remote_device_id: remote.device_id.clone(),
            })
        } else {
            None
        };

        let next_wall = now_ms.max(self.last_wall_ms).max(remote.wall_ms);
        let next_counter = if next_wall == self.last_wall_ms && next_wall == remote.wall_ms {
            self.last_counter.max(remote.counter).saturating_add(1)
        } else if next_wall == self.last_wall_ms {
            self.last_counter.saturating_add(1)
        } else if next_wall == remote.wall_ms {
            remote.counter.saturating_add(1)
        } else {
            0
        };

        if next_counter == u16::MAX {
            self.last_wall_ms = next_wall.saturating_add(1);
            self.last_counter = 0;
        } else {
            self.last_wall_ms = next_wall;
            self.last_counter = next_counter;
        }

        (self.current(), skew_warning)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn receive_never_rejects_large_clock_skew_and_warns() {
        let d_local = DeviceId::parse("dev_local00001").unwrap();
        let d_fast = DeviceId::parse("dev_fast000002").unwrap();
        let mut clock = HlcClock::new(d_local, 1_000_000);
        // Remote device is 2 hours ahead
        let remote = Hlc::new(1_000_000 + 7_200_000, 5, d_fast.clone());
        let (merged, warn) = clock.receive(1_000_000, &remote);
        assert!(merged > remote);
        let w = warn.expect("must emit ClockSkewWarning");
        assert_eq!(w.skew_ms, 7_200_000);
        assert_eq!(w.remote_device_id, d_fast);
    }

    proptest! {
        #[test]
        fn canonical_string_order_isomorphic_to_struct_order(
            w1 in 0u64..10_000_000_000_000u64,
            c1 in 0u16..65535u16,
            w2 in 0u64..10_000_000_000_000u64,
            c2 in 0u16..65535u16,
            same_dev in any::<bool>()
        ) {
            let d1 = DeviceId::parse("dev_aaaa00001").unwrap();
            let d2 = if same_dev { d1.clone() } else { DeviceId::parse("dev_bbbb00002").unwrap() };
            let h1 = Hlc::new(w1, c1, d1);
            let h2 = Hlc::new(w2, c2, d2);
            prop_assert_eq!(h1.cmp(&h2), h1.canonical_string().cmp(&h2.canonical_string()));
            prop_assert_eq!(Hlc::parse(&h1.canonical_string()).unwrap(), h1);
        }
    }
}
