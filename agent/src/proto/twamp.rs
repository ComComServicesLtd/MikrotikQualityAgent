//! TWAMP-Light — RFC 5357 unauthenticated mode.
//!
//! This exists for interop. MQP is better suited to our own mesh, but a great
//! many things that are not our agents speak TWAMP: carrier and transit
//! providers run responders, and test sets expect one. RouterOS does **not** —
//! there is no TWAMP menu on RouterOS 7.x and no package provides one — so
//! where a MikroTik needs to answer TWAMP, this agent is what answers.
//!
//! # Unauthenticated mode only
//!
//! RFC 5357 also defines authenticated and encrypted modes, which need
//! TWAMP-Control to negotiate keys. Light mode skips the control protocol
//! entirely: the responder is simply configured to reflect on a port. That is
//! what makes it deployable, and it has a consequence worth stating plainly —
//! **there is no session identifier**. MQP's admission control is an
//! unguessable `session_id`; TWAMP-Light has nothing equivalent, so the only
//! thing standing between the reflector and the internet is the source-address
//! filter and the firewall in front of it.
//!
//! # Why RTT still needs no clock synchronisation
//!
//! The four timestamps are `T1` (sender TX), `T2` (reflector RX), `T3`
//! (reflector TX) and `T4` (sender RX). RTT is
//!
//! ```text
//! (T4 - T1) - (T3 - T2)
//! ```
//!
//! Each bracket is a difference between two readings of *one* host's clock, so
//! the result holds even when the two hosts disagree completely about the time.
//! Only one-way delay needs synchronisation, and we do not claim it: the error
//! estimate goes out with its synchronised bit clear.
//!
//! The wire format is NTP wall-clock, but the values we put in it are derived
//! from a monotonic source. A host whose NTP client steps the clock in the
//! middle of a measurement would otherwise produce a wildly wrong — and
//! plausible-looking — RTT.

use std::time::Duration;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
/// Includes the 17 leap days in that span.
pub const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// Minimum Session-Sender test packet: seq(4) + timestamp(8) + error(2).
pub const SENDER_MIN_LEN: usize = 14;

/// Minimum Session-Reflector test packet, per RFC 5357 §4.2.1.
pub const REFLECTOR_MIN_LEN: usize = 41;

/// Default size for both directions.
///
/// Padded so a sender packet is the same size as the reflector packet it
/// provokes. Unequal sizes make the two directions traverse the path
/// differently, and a path that polices or fragments by size would then be
/// measured asymmetrically for reasons that have nothing to do with the
/// network.
pub const DEFAULT_PACKET_LEN: usize = REFLECTOR_MIN_LEN;

/// Largest packet accepted, matching the MQP limit so neither protocol
/// fragments on a 1500-byte path.
pub const MAX_PACKET_LEN: usize = 1400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwampError {
    TooShort { got: usize, need: usize },
    TooLong { got: usize },
}

impl std::fmt::Display for TwampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { got, need } => {
                write!(f, "TWAMP packet too short: {got} bytes, need at least {need}")
            }
            Self::TooLong { got } => write!(f, "TWAMP packet too long: {got} bytes"),
        }
    }
}

impl std::error::Error for TwampError {}

/// An NTP 64-bit timestamp: seconds since 1900 plus a binary fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct NtpTimestamp {
    pub seconds: u32,
    /// Fraction of a second in units of 2⁻³² s (about 233 picoseconds).
    pub fraction: u32,
}

impl NtpTimestamp {
    pub const ZERO: Self = Self { seconds: 0, fraction: 0 };

    pub fn from_bytes(b: [u8; 8]) -> Self {
        Self {
            seconds: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            fraction: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.seconds.to_be_bytes());
        out[4..8].copy_from_slice(&self.fraction.to_be_bytes());
        out
    }

    /// Build from nanoseconds since the Unix epoch.
    pub fn from_unix_nanos(ns: u128) -> Self {
        let secs = (ns / 1_000_000_000) as u64;
        let sub_ns = (ns % 1_000_000_000) as u64;
        Self {
            // Wraps in 2036 when the NTP era rolls over. Era handling is out of
            // scope: every value here is used in a difference against another
            // reading taken seconds earlier, and a difference is unaffected
            // unless the rollover falls between the two.
            seconds: secs.wrapping_add(NTP_UNIX_OFFSET) as u32,
            fraction: ((sub_ns << 32) / 1_000_000_000) as u32,
        }
    }

    /// Nanoseconds since the Unix epoch.
    pub fn to_unix_nanos(self) -> u128 {
        let secs = (self.seconds as u64).wrapping_sub(NTP_UNIX_OFFSET);
        let sub_ns = ((self.fraction as u64) * 1_000_000_000) >> 32;
        secs as u128 * 1_000_000_000 + sub_ns as u128
    }

    /// Difference between two timestamps from the *same* clock.
    ///
    /// Returns `None` when `self` precedes `earlier`, which for two readings of
    /// one clock means something is wrong — a stepped clock, or fields read in
    /// the wrong order — and is better surfaced than folded into a zero.
    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        let a = self.as_units();
        let b = earlier.as_units();
        if a < b {
            return None;
        }
        let diff = a - b;
        let secs = diff >> 32;
        let frac_ns = ((diff & 0xFFFF_FFFF) * 1_000_000_000) >> 32;
        Some(Duration::new(secs as u64, frac_ns as u32))
    }

    fn as_units(self) -> u64 {
        ((self.seconds as u64) << 32) | self.fraction as u64
    }
}

/// The 2-byte Error Estimate field (RFC 4656 §4.1.2).
///
/// ```text
///  0                   1
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |S|Z|   Scale   |   Multiplier  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The estimate is `Multiplier · 2^(Scale−32)` seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorEstimate {
    /// Set only when the clock is disciplined to an external reference.
    pub synchronized: bool,
    pub scale: u8,
    pub multiplier: u8,
}

impl ErrorEstimate {
    /// What this agent claims about its own timestamps.
    ///
    /// The synchronised bit is clear, deliberately. Agents run in containers on
    /// customer routers whose NTP state we neither control nor verify, and a
    /// receiver that believes the bit may compute a one-way delay from our
    /// timestamps. Claiming synchronisation we cannot demonstrate would make
    /// that number confidently wrong rather than obviously unavailable.
    ///
    /// The magnitude describes timestamp resolution — roughly a microsecond —
    /// not agreement with UTC, which is unbounded while unsynchronised.
    pub const UNSYNCHRONIZED: Self = Self { synchronized: false, scale: 12, multiplier: 1 };

    pub fn from_u16(v: u16) -> Self {
        Self {
            synchronized: v & 0x8000 != 0,
            // Bit 14 is Z (must be zero); mask it out rather than folding it
            // into the scale, where it would multiply the estimate by 2^32.
            scale: ((v >> 8) & 0x3F) as u8,
            multiplier: (v & 0xFF) as u8,
        }
    }

    pub fn to_u16(self) -> u16 {
        let s = if self.synchronized { 0x8000u16 } else { 0 };
        s | (((self.scale & 0x3F) as u16) << 8) | self.multiplier as u16
    }

    /// The estimate as a duration.
    pub fn as_duration(self) -> Duration {
        if self.multiplier == 0 {
            return Duration::ZERO;
        }
        let exp = self.scale as i32 - 32;
        let secs = self.multiplier as f64 * 2f64.powi(exp);
        Duration::from_secs_f64(secs.clamp(0.0, 3600.0))
    }
}

/// A Session-Sender test packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderPacket {
    pub sequence: u32,
    pub timestamp: NtpTimestamp,
    pub error_estimate: ErrorEstimate,
}

impl SenderPacket {
    /// Write into `buf`, which must be at least [`SENDER_MIN_LEN`]. Padding
    /// beyond the header is left as the caller set it.
    pub fn encode(&self, buf: &mut [u8]) -> Result<(), TwampError> {
        if buf.len() < SENDER_MIN_LEN {
            return Err(TwampError::TooShort { got: buf.len(), need: SENDER_MIN_LEN });
        }
        buf[0..4].copy_from_slice(&self.sequence.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp.to_bytes());
        buf[12..14].copy_from_slice(&self.error_estimate.to_u16().to_be_bytes());
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, TwampError> {
        if buf.len() < SENDER_MIN_LEN {
            return Err(TwampError::TooShort { got: buf.len(), need: SENDER_MIN_LEN });
        }
        if buf.len() > MAX_PACKET_LEN {
            return Err(TwampError::TooLong { got: buf.len() });
        }
        Ok(Self {
            sequence: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            timestamp: NtpTimestamp::from_bytes(buf[4..12].try_into().unwrap()),
            error_estimate: ErrorEstimate::from_u16(u16::from_be_bytes([buf[12], buf[13]])),
        })
    }
}

/// A Session-Reflector test packet (RFC 5357 §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectorPacket {
    /// The reflector's own counter, which advances per reply it generates.
    pub sequence: u32,
    /// T3 — when the reflector sent this.
    pub timestamp: NtpTimestamp,
    pub error_estimate: ErrorEstimate,
    /// T2 — when the reflector received the request.
    pub receive_timestamp: NtpTimestamp,
    /// The sequence number from the request, echoed.
    pub sender_sequence: u32,
    /// T1 — the sender's own transmit timestamp, echoed.
    pub sender_timestamp: NtpTimestamp,
    pub sender_error_estimate: ErrorEstimate,
    /// TTL of the request as it arrived, so the sender can derive hop count.
    pub sender_ttl: u8,
}

impl ReflectorPacket {
    pub fn encode(&self, buf: &mut [u8]) -> Result<(), TwampError> {
        if buf.len() < REFLECTOR_MIN_LEN {
            return Err(TwampError::TooShort { got: buf.len(), need: REFLECTOR_MIN_LEN });
        }
        buf[0..4].copy_from_slice(&self.sequence.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp.to_bytes());
        buf[12..14].copy_from_slice(&self.error_estimate.to_u16().to_be_bytes());
        buf[14..16].copy_from_slice(&[0, 0]); // MBZ
        buf[16..24].copy_from_slice(&self.receive_timestamp.to_bytes());
        buf[24..28].copy_from_slice(&self.sender_sequence.to_be_bytes());
        buf[28..36].copy_from_slice(&self.sender_timestamp.to_bytes());
        buf[36..38].copy_from_slice(&self.sender_error_estimate.to_u16().to_be_bytes());
        buf[38..40].copy_from_slice(&[0, 0]); // MBZ
        buf[40] = self.sender_ttl;
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, TwampError> {
        if buf.len() < REFLECTOR_MIN_LEN {
            return Err(TwampError::TooShort { got: buf.len(), need: REFLECTOR_MIN_LEN });
        }
        if buf.len() > MAX_PACKET_LEN {
            return Err(TwampError::TooLong { got: buf.len() });
        }
        Ok(Self {
            sequence: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            timestamp: NtpTimestamp::from_bytes(buf[4..12].try_into().unwrap()),
            error_estimate: ErrorEstimate::from_u16(u16::from_be_bytes([buf[12], buf[13]])),
            receive_timestamp: NtpTimestamp::from_bytes(buf[16..24].try_into().unwrap()),
            sender_sequence: u32::from_be_bytes(buf[24..28].try_into().unwrap()),
            sender_timestamp: NtpTimestamp::from_bytes(buf[28..36].try_into().unwrap()),
            sender_error_estimate: ErrorEstimate::from_u16(u16::from_be_bytes([buf[36], buf[37]])),
            sender_ttl: buf[40],
        })
    }

    /// Build a reply to a received request.
    ///
    /// `t3` is filled by the caller immediately before the send, so the
    /// reflector's own processing time is measured rather than guessed.
    pub fn reply_to(
        request: &SenderPacket,
        own_sequence: u32,
        t2: NtpTimestamp,
        sender_ttl: u8,
    ) -> Self {
        Self {
            sequence: own_sequence,
            timestamp: NtpTimestamp::ZERO,
            error_estimate: ErrorEstimate::UNSYNCHRONIZED,
            receive_timestamp: t2,
            sender_sequence: request.sequence,
            sender_timestamp: request.timestamp,
            sender_error_estimate: request.error_estimate,
            sender_ttl,
        }
    }
}

/// Overwrite T3 in an encoded reply, immediately before transmission.
///
/// Encoding then stamping keeps the window between reading the clock and the
/// syscall as small as possible. Anything in that window is charged to the
/// network by whoever is measuring us.
pub fn stamp_reflector_tx(buf: &mut [u8], t3: NtpTimestamp) -> Result<(), TwampError> {
    if buf.len() < REFLECTOR_MIN_LEN {
        return Err(TwampError::TooShort { got: buf.len(), need: REFLECTOR_MIN_LEN });
    }
    buf[4..12].copy_from_slice(&t3.to_bytes());
    Ok(())
}

/// Overwrite T1 in an encoded request, immediately before transmission.
pub fn stamp_sender_tx(buf: &mut [u8], t1: NtpTimestamp) -> Result<(), TwampError> {
    if buf.len() < SENDER_MIN_LEN {
        return Err(TwampError::TooShort { got: buf.len(), need: SENDER_MIN_LEN });
    }
    buf[4..12].copy_from_slice(&t1.to_bytes());
    Ok(())
}

/// Round-trip time from the four timestamps, with the reflector's own
/// turnaround removed.
///
/// `t1`/`t4` come from the sender's clock and `t2`/`t3` from the reflector's;
/// each pair is subtracted only within its own clock, so no synchronisation is
/// required. A reflector reporting a turnaround longer than the whole round
/// trip is not credible, so its contribution is ignored rather than allowed to
/// produce a negative result.
pub fn round_trip(
    t1: NtpTimestamp,
    t2: NtpTimestamp,
    t3: NtpTimestamp,
    t4: NtpTimestamp,
) -> Option<Duration> {
    let total = t4.duration_since(t1)?;
    let turnaround = t3.duration_since(t2).unwrap_or(Duration::ZERO);
    Some(total.saturating_sub(turnaround))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u32, frac: u32) -> NtpTimestamp {
        NtpTimestamp { seconds: secs, fraction: frac }
    }

    #[test]
    fn packet_sizes_match_the_rfc() {
        // These are wire constants; a change silently breaks interop with
        // every third-party responder.
        assert_eq!(SENDER_MIN_LEN, 14);
        assert_eq!(REFLECTOR_MIN_LEN, 41);
    }

    #[test]
    fn ntp_epoch_offset_is_correct() {
        // 1900-01-01 to 1970-01-01 is 70 years with 17 leap days.
        assert_eq!(NTP_UNIX_OFFSET, (70 * 365 + 17) * 86_400);
    }

    #[test]
    fn unix_time_round_trips_through_ntp_format() {
        // 2026-09-22T00:00:00Z
        let unix_ns: u128 = 1_790_035_200_000_000_000;
        let t = NtpTimestamp::from_unix_nanos(unix_ns);
        assert_eq!(t.seconds as u64, 1_790_035_200 + NTP_UNIX_OFFSET);
        assert_eq!(t.fraction, 0);
        assert_eq!(t.to_unix_nanos(), unix_ns);
    }

    #[test]
    fn fractional_seconds_survive_to_the_microsecond() {
        // The fraction is in units of 2^-32 s, so exact nanosecond round trips
        // are not possible; a microsecond is what the protocol can carry.
        for ns in [1_000u128, 500_000, 123_456_000, 999_999_000] {
            let t = NtpTimestamp::from_unix_nanos(1_790_035_200_000_000_000 + ns);
            let back = t.to_unix_nanos() - 1_790_035_200_000_000_000;
            assert!(
                (back as i128 - ns as i128).abs() < 1_000,
                "ns {ns} came back as {back}"
            );
        }
    }

    #[test]
    fn half_a_second_is_the_top_fraction_bit() {
        let t = NtpTimestamp::from_unix_nanos(500_000_000);
        assert_eq!(t.fraction, 0x8000_0000);
    }

    #[test]
    fn timestamps_serialise_big_endian() {
        let t = ts(0xAABB_CCDD, 0x1122_3344);
        assert_eq!(t.to_bytes(), [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(NtpTimestamp::from_bytes(t.to_bytes()), t);
    }

    #[test]
    fn duration_between_two_readings_is_exact_enough() {
        let a = ts(100, 0);
        let b = ts(100, 0x8000_0000); // +0.5 s
        let d = b.duration_since(a).unwrap();
        assert_eq!(d.as_millis(), 500);
        assert_eq!(ts(101, 0).duration_since(a).unwrap(), Duration::from_secs(1));
    }

    #[test]
    fn a_backwards_pair_is_reported_rather_than_folded_to_zero() {
        // Two readings of one clock cannot go backwards; if they do, something
        // stepped the clock and the measurement is not salvageable.
        assert!(ts(100, 0).duration_since(ts(101, 0)).is_none());
    }

    #[test]
    fn error_estimate_round_trips_every_field() {
        for sync in [true, false] {
            for scale in [0u8, 1, 31, 63] {
                for mult in [0u8, 1, 200, 255] {
                    let e = ErrorEstimate { synchronized: sync, scale, multiplier: mult };
                    assert_eq!(ErrorEstimate::from_u16(e.to_u16()), e, "{e:?}");
                }
            }
        }
    }

    #[test]
    fn the_must_be_zero_bit_is_masked_out_of_the_scale() {
        // Folding Z into the scale would multiply the reported estimate by
        // 2^32 — turning microseconds into over a century.
        let with_z = 0x4000u16 | (5 << 8) | 7;
        let e = ErrorEstimate::from_u16(with_z);
        assert_eq!(e.scale, 5);
        assert_eq!(e.multiplier, 7);
        assert!(!e.synchronized);
    }

    #[test]
    fn our_error_estimate_does_not_claim_synchronisation() {
        // Agents run on customer routers whose NTP state we do not control. A
        // receiver that trusts this bit will compute one-way delay from our
        // timestamps.
        let e = ErrorEstimate::UNSYNCHRONIZED;
        assert!(!e.synchronized);
        assert_eq!(e.to_u16() & 0x8000, 0);
        let d = e.as_duration();
        assert!(d < Duration::from_millis(1), "claimed error {d:?} is implausibly large");
    }

    #[test]
    fn sender_packet_round_trips() {
        let p = SenderPacket {
            sequence: 0xDEAD_BEEF,
            timestamp: ts(0x1234_5678, 0x9ABC_DEF0),
            error_estimate: ErrorEstimate::UNSYNCHRONIZED,
        };
        let mut buf = vec![0u8; DEFAULT_PACKET_LEN];
        p.encode(&mut buf).unwrap();
        assert_eq!(SenderPacket::decode(&buf).unwrap(), p);
    }

    #[test]
    fn sender_fields_land_at_the_offsets_the_rfc_specifies() {
        // A third-party responder reads by offset, so these are the contract.
        let p = SenderPacket {
            sequence: 0x0102_0304,
            timestamp: ts(0x1112_1314, 0x2122_2324),
            error_estimate: ErrorEstimate { synchronized: true, scale: 1, multiplier: 2 },
        };
        let mut buf = vec![0u8; SENDER_MIN_LEN];
        p.encode(&mut buf).unwrap();
        assert_eq!(&buf[0..4], &[1, 2, 3, 4]);
        assert_eq!(&buf[4..12], &[0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24]);
        assert_eq!(&buf[12..14], &[0x81, 0x02]);
    }

    #[test]
    fn reflector_packet_round_trips() {
        let p = ReflectorPacket {
            sequence: 7,
            timestamp: ts(300, 3),
            error_estimate: ErrorEstimate::UNSYNCHRONIZED,
            receive_timestamp: ts(200, 2),
            sender_sequence: 42,
            sender_timestamp: ts(100, 1),
            sender_error_estimate: ErrorEstimate { synchronized: true, scale: 9, multiplier: 5 },
            sender_ttl: 64,
        };
        let mut buf = vec![0u8; REFLECTOR_MIN_LEN];
        p.encode(&mut buf).unwrap();
        assert_eq!(ReflectorPacket::decode(&buf).unwrap(), p);
    }

    #[test]
    fn reflector_fields_land_at_the_offsets_the_rfc_specifies() {
        let p = ReflectorPacket {
            sequence: 0x0102_0304,
            timestamp: ts(0x1111_1111, 0x2222_2222),
            error_estimate: ErrorEstimate { synchronized: false, scale: 0, multiplier: 1 },
            receive_timestamp: ts(0x3333_3333, 0x4444_4444),
            sender_sequence: 0x0506_0708,
            sender_timestamp: ts(0x5555_5555, 0x6666_6666),
            sender_error_estimate: ErrorEstimate { synchronized: false, scale: 0, multiplier: 2 },
            sender_ttl: 0xFE,
        };
        let mut buf = vec![0u8; REFLECTOR_MIN_LEN];
        p.encode(&mut buf).unwrap();

        assert_eq!(&buf[0..4], &[1, 2, 3, 4], "reflector sequence");
        assert_eq!(&buf[14..16], &[0, 0], "MBZ after the error estimate");
        assert_eq!(&buf[16..20], &[0x33, 0x33, 0x33, 0x33], "receive timestamp");
        assert_eq!(&buf[24..28], &[5, 6, 7, 8], "sender sequence echoed");
        assert_eq!(&buf[38..40], &[0, 0], "second MBZ");
        assert_eq!(buf[40], 0xFE, "sender TTL is the last header byte");
    }

    #[test]
    fn a_reply_echoes_everything_the_sender_needs_to_match_it() {
        let req = SenderPacket {
            sequence: 99,
            timestamp: ts(1000, 500),
            error_estimate: ErrorEstimate { synchronized: true, scale: 3, multiplier: 4 },
        };
        let r = ReflectorPacket::reply_to(&req, 5, ts(1001, 0), 61);

        // Without these the sender cannot pair a reply with the packet it sent.
        assert_eq!(r.sender_sequence, 99);
        assert_eq!(r.sender_timestamp, req.timestamp);
        assert_eq!(r.sender_error_estimate, req.error_estimate);
        assert_eq!(r.receive_timestamp, ts(1001, 0));
        assert_eq!(r.sender_ttl, 61);
        assert_eq!(r.timestamp, NtpTimestamp::ZERO, "T3 is stamped at send time");
    }

    #[test]
    fn stamping_does_not_disturb_neighbouring_fields() {
        let req = SenderPacket {
            sequence: 1,
            timestamp: ts(10, 0),
            error_estimate: ErrorEstimate::UNSYNCHRONIZED,
        };
        let r = ReflectorPacket::reply_to(&req, 2, ts(11, 0), 64);
        let mut buf = vec![0u8; REFLECTOR_MIN_LEN];
        r.encode(&mut buf).unwrap();

        stamp_reflector_tx(&mut buf, ts(12, 34)).unwrap();
        let back = ReflectorPacket::decode(&buf).unwrap();
        assert_eq!(back.timestamp, ts(12, 34));
        assert_eq!(back.sequence, 2);
        assert_eq!(back.receive_timestamp, ts(11, 0));
        assert_eq!(back.sender_sequence, 1);
    }

    #[test]
    fn round_trip_removes_the_reflector_turnaround() {
        // Sender sees 100 ms wall to wall; the reflector held the packet for
        // 40 ms of it. The path cost 60 ms.
        let t1 = ts(1000, 0);
        let t4 = NtpTimestamp::from_unix_nanos(
            t1.to_unix_nanos() + Duration::from_millis(100).as_nanos(),
        );
        // The reflector's clock is deliberately far from the sender's, which
        // must not matter.
        let t2 = ts(9_000_000, 0);
        let t3 = NtpTimestamp::from_unix_nanos(
            t2.to_unix_nanos() + Duration::from_millis(40).as_nanos(),
        );

        let rtt = round_trip(t1, t2, t3, t4).unwrap();
        assert!(
            (rtt.as_millis() as i64 - 60).abs() <= 1,
            "expected about 60 ms, got {rtt:?}"
        );
    }

    #[test]
    fn a_wildly_wrong_reflector_clock_cannot_produce_a_negative_rtt() {
        // A reflector claiming a turnaround longer than the whole round trip
        // is not credible; the result must stay a real duration.
        let t1 = ts(1000, 0);
        let t4 = NtpTimestamp::from_unix_nanos(
            t1.to_unix_nanos() + Duration::from_millis(10).as_nanos(),
        );
        let t2 = ts(500, 0);
        let t3 = ts(900, 0); // claims a 400-second turnaround
        assert_eq!(round_trip(t1, t2, t3, t4), Some(Duration::ZERO));
    }

    #[test]
    fn a_backwards_sender_pair_yields_no_measurement() {
        assert!(round_trip(ts(100, 0), ts(1, 0), ts(2, 0), ts(99, 0)).is_none());
    }

    #[test]
    fn short_packets_are_rejected_with_the_size_they_needed() {
        assert_eq!(
            SenderPacket::decode(&[0u8; 13]),
            Err(TwampError::TooShort { got: 13, need: SENDER_MIN_LEN })
        );
        assert_eq!(
            ReflectorPacket::decode(&[0u8; 40]),
            Err(TwampError::TooShort { got: 40, need: REFLECTOR_MIN_LEN })
        );
        // A 14-byte sender packet is valid but is not a reflector packet.
        assert!(SenderPacket::decode(&[0u8; 14]).is_ok());
        assert!(ReflectorPacket::decode(&[0u8; 14]).is_err());
    }

    #[test]
    fn oversized_packets_are_refused() {
        assert!(matches!(
            SenderPacket::decode(&vec![0u8; MAX_PACKET_LEN + 1]),
            Err(TwampError::TooLong { .. })
        ));
    }

    #[test]
    fn default_size_makes_both_directions_equal() {
        // Unequal sizes would let a path that polices by size measure the two
        // directions differently for reasons unrelated to the network.
        assert_eq!(DEFAULT_PACKET_LEN, REFLECTOR_MIN_LEN);
        assert!(DEFAULT_PACKET_LEN >= SENDER_MIN_LEN);
    }
}
