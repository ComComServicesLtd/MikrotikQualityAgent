//! The probe data plane: sender, reflector, and the sockets underneath them.

pub mod reflector;
pub mod sender;
pub mod socket;
pub mod twamp;

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::proto::twamp::NtpTimestamp;

/// Monotonic nanosecond clock for probe timestamps.
///
/// The origin is arbitrary and differs per process, which is fine and in fact
/// intended: every value MQP puts on the wire is only ever used in a difference
/// against another value from *the same* clock. See `docs/protocol.md` for why
/// that removes the need to synchronise agents.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    origin: Instant,
    /// Wall-clock reading taken once, at the same moment as `origin`.
    ///
    /// TWAMP puts wall-clock timestamps on the wire, but reading the system
    /// clock per packet would let an NTP step land in the middle of a
    /// measurement and produce a large, plausible, wrong RTT. Anchoring once
    /// and advancing by monotonic elapsed time keeps every reading consistent
    /// with every other for the life of the process.
    wall_origin_nanos: u128,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            wall_origin_nanos: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                // A system clock before 1970 means the RTC is unset, which is
                // common on a router that has not reached NTP yet. Zero is
                // wrong in absolute terms but still monotonic, and only
                // differences are ever used.
                .unwrap_or(0),
        }
    }

    /// Nanoseconds since this clock's origin.
    #[inline]
    pub fn now_ns(&self) -> u64 {
        // u64 nanoseconds covers 584 years of uptime; saturating rather than
        // wrapping means a pathological value can never present as a negative
        // or absurdly small latency.
        self.origin.elapsed().as_nanos().min(u64::MAX as u128) as u64
    }
}

impl Clock {
    /// Current time as a TWAMP/NTP timestamp, advanced monotonically from the
    /// anchor taken at construction.
    #[inline]
    pub fn now_ntp(&self) -> NtpTimestamp {
        NtpTimestamp::from_unix_nanos(self.wall_origin_nanos + self.origin.elapsed().as_nanos())
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_is_monotonic() {
        let c = Clock::new();
        let a = c.now_ns();
        let b = c.now_ns();
        assert!(b >= a, "monotonic clock went backwards: {a} then {b}");
    }

    #[test]
    fn clock_measures_elapsed_time() {
        let c = Clock::new();
        let start = c.now_ns();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let elapsed = c.now_ns() - start;
        assert!(elapsed >= 4_000_000, "expected >=4ms, measured {elapsed}ns");
    }
}
