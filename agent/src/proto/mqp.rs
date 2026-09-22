//! MQP wire codec — see `docs/protocol.md`.
//!
//! Fixed 56-byte header, big-endian, no allocation on the hot path. Encoding
//! writes into a caller-owned buffer; decoding borrows one. The reflector
//! mutates a received buffer in place and sends it straight back.

use std::fmt;

pub const MAGIC: u16 = 0x4D51; // "MQ"
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 56;

/// Default probe size: a 20 ms G.711 frame over RTP/UDP/IP is 172 bytes on the
/// wire, so the default probe stresses the path like the traffic we care about.
pub const DEFAULT_PACKET_LEN: usize = 172;

/// Largest packet we will send or accept. Keeps the reflector's per-session
/// buffer bounded and avoids IP fragmentation on a 1500-byte path.
pub const MAX_PACKET_LEN: usize = 1400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Request = 1,
    Reply = 2,
}

impl PacketType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Request),
            2 => Some(Self::Reply),
            _ => None,
        }
    }
}

pub mod flags {
    pub const ECHO_PAYLOAD: u16 = 1 << 0;
    pub const LAST_PACKET: u16 = 1 << 1;
    pub const NO_REFLECT: u16 = 1 << 2;
    pub const REQUEST_DSCP_ECHO: u16 = 1 << 3;

    /// Bits we understand. Anything else set means the peer is speaking a
    /// dialect we don't, and we say so rather than guessing.
    pub const KNOWN: u16 = ECHO_PAYLOAD | LAST_PACKET | NO_REFLECT | REQUEST_DSCP_ECHO;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TooShort { got: usize },
    BadMagic { got: u16 },
    UnsupportedVersion { got: u8 },
    UnknownType { got: u8 },
    UnknownFlags { got: u16 },
    LengthMismatch { declared: usize, actual: usize },
    BadChecksum { expected: u16, got: u16 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got } => {
                write!(f, "packet too short: {got} bytes, need at least {HEADER_LEN}")
            }
            Self::BadMagic { got } => write!(f, "bad magic 0x{got:04X}, expected 0x{MAGIC:04X}"),
            Self::UnsupportedVersion { got } => {
                write!(f, "unsupported protocol version {got}, this agent speaks {VERSION}")
            }
            Self::UnknownType { got } => write!(f, "unknown packet type {got}"),
            Self::UnknownFlags { got } => write!(f, "unknown flag bits set: 0x{got:04X}"),
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "payload_len declares {declared} bytes but packet carries {actual}"
            ),
            Self::BadChecksum { expected, got } => {
                write!(f, "checksum mismatch: computed 0x{expected:04X}, header says 0x{got:04X}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// A decoded MQP header. Padding is not copied — the caller still holds the
/// buffer if it needs to inspect or echo it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub pkt_type: PacketType,
    pub flags: u16,
    pub session_id: u64,
    pub seq: u32,
    pub reflector_seq: u32,
    /// Sender TX, ns on the *sender's* clock.
    pub t1: u64,
    /// Reflector RX, ns on the *reflector's* clock.
    pub t2: u64,
    /// Reflector TX, ns on the *reflector's* clock.
    pub t3: u64,
    pub tx_dscp: u8,
    pub rx_dscp: u8,
    pub ttl_fwd: u8,
    pub ttl_rev: u8,
    pub payload_len: u16,
}

impl Header {
    /// A fresh Request header. Timestamps and reflector fields are zero; the
    /// sender fills `t1` immediately before the socket write.
    pub fn request(session_id: u64, seq: u32, tx_dscp: u8, payload_len: u16) -> Self {
        Self {
            version: VERSION,
            pkt_type: PacketType::Request,
            flags: flags::REQUEST_DSCP_ECHO,
            session_id,
            seq,
            reflector_seq: 0,
            t1: 0,
            t2: 0,
            t3: 0,
            tx_dscp,
            rx_dscp: 0,
            ttl_fwd: 0,
            ttl_rev: 0,
            payload_len,
        }
    }

    pub fn has_flag(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }

    /// Total wire size of a packet carrying this header.
    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.payload_len as usize
    }

    /// Write the header into the first [`HEADER_LEN`] bytes of `buf`, including
    /// the checksum. Padding beyond the header is left untouched.
    pub fn encode(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort { got: buf.len() });
        }
        buf[0..2].copy_from_slice(&MAGIC.to_be_bytes());
        buf[2] = self.version;
        buf[3] = self.pkt_type as u8;
        buf[4..6].copy_from_slice(&self.flags.to_be_bytes());
        buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // reserved
        buf[8..16].copy_from_slice(&self.session_id.to_be_bytes());
        buf[16..20].copy_from_slice(&self.seq.to_be_bytes());
        buf[20..24].copy_from_slice(&self.reflector_seq.to_be_bytes());
        buf[24..32].copy_from_slice(&self.t1.to_be_bytes());
        buf[32..40].copy_from_slice(&self.t2.to_be_bytes());
        buf[40..48].copy_from_slice(&self.t3.to_be_bytes());
        buf[48] = self.tx_dscp;
        buf[49] = self.rx_dscp;
        buf[50] = self.ttl_fwd;
        buf[51] = self.ttl_rev;
        buf[52..54].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[54..56].copy_from_slice(&0u16.to_be_bytes()); // checksum field zeroed first

        let crc = crc16_ccitt(&buf[0..54]);
        buf[54..56].copy_from_slice(&crc.to_be_bytes());
        Ok(())
    }

    /// Parse and validate a header from the front of `buf`.
    ///
    /// Validation is ordered cheapest-first so that stray traffic hitting the
    /// probe port is rejected in a few instructions.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort { got: buf.len() });
        }

        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != MAGIC {
            return Err(DecodeError::BadMagic { got: magic });
        }

        let version = buf[2];
        if version != VERSION {
            return Err(DecodeError::UnsupportedVersion { got: version });
        }

        let pkt_type =
            PacketType::from_u8(buf[3]).ok_or(DecodeError::UnknownType { got: buf[3] })?;

        let flags = u16::from_be_bytes([buf[4], buf[5]]);
        if flags & !flags::KNOWN != 0 {
            return Err(DecodeError::UnknownFlags { got: flags & !flags::KNOWN });
        }

        let stated_crc = u16::from_be_bytes([buf[54], buf[55]]);
        let computed = {
            let mut head = [0u8; 54];
            head.copy_from_slice(&buf[0..54]);
            crc16_ccitt(&head)
        };
        if stated_crc != computed {
            return Err(DecodeError::BadChecksum { expected: computed, got: stated_crc });
        }

        let payload_len = u16::from_be_bytes([buf[52], buf[53]]);
        let actual_payload = buf.len() - HEADER_LEN;
        if payload_len as usize != actual_payload {
            return Err(DecodeError::LengthMismatch {
                declared: payload_len as usize,
                actual: actual_payload,
            });
        }

        Ok(Self {
            version,
            pkt_type,
            flags,
            session_id: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
            seq: u32::from_be_bytes(buf[16..20].try_into().unwrap()),
            reflector_seq: u32::from_be_bytes(buf[20..24].try_into().unwrap()),
            t1: u64::from_be_bytes(buf[24..32].try_into().unwrap()),
            t2: u64::from_be_bytes(buf[32..40].try_into().unwrap()),
            t3: u64::from_be_bytes(buf[40..48].try_into().unwrap()),
            tx_dscp: buf[48],
            rx_dscp: buf[49],
            ttl_fwd: buf[50],
            ttl_rev: buf[51],
            payload_len,
        })
    }
}

/// Patch `t1` in an already-encoded buffer and fix the checksum.
///
/// The sender encodes the packet once, then stamps the clock as late as
/// possible — after the buffer is built, immediately before `send_to`. Anything
/// between the stamp and the write is counted as network latency, so this
/// window is kept as small as it can be.
pub fn stamp_t1(buf: &mut [u8], t1: u64) -> Result<(), DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::TooShort { got: buf.len() });
    }
    buf[24..32].copy_from_slice(&t1.to_be_bytes());
    buf[54..56].copy_from_slice(&0u16.to_be_bytes());
    let crc = crc16_ccitt(&buf[0..54]);
    buf[54..56].copy_from_slice(&crc.to_be_bytes());
    Ok(())
}

/// Turn a received Request buffer into a Reply, in place.
///
/// `t3` is stamped by the caller via [`stamp_t3`] just before the send, for the
/// same reason [`stamp_t1`] exists.
pub fn make_reply_in_place(
    buf: &mut [u8],
    t2: u64,
    reflector_seq: u32,
    rx_dscp: u8,
    ttl_fwd: u8,
    ttl_rev: u8,
) -> Result<(), DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::TooShort { got: buf.len() });
    }
    buf[3] = PacketType::Reply as u8;
    buf[20..24].copy_from_slice(&reflector_seq.to_be_bytes());
    buf[32..40].copy_from_slice(&t2.to_be_bytes());
    buf[49] = rx_dscp;
    buf[50] = ttl_fwd;
    buf[51] = ttl_rev;
    Ok(())
}

/// Stamp `t3` and recompute the checksum. Call immediately before sending.
pub fn stamp_t3(buf: &mut [u8], t3: u64) -> Result<(), DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::TooShort { got: buf.len() });
    }
    buf[40..48].copy_from_slice(&t3.to_be_bytes());
    buf[54..56].copy_from_slice(&0u16.to_be_bytes());
    let crc = crc16_ccitt(&buf[0..54]);
    buf[54..56].copy_from_slice(&crc.to_be_bytes());
    Ok(())
}

/// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final xor.
///
/// This guards against a corrupt header being silently parsed as plausible
/// values — a truncated timestamp would otherwise show up as a wild RTT rather
/// than as a dropped packet. It is not a security mechanism.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header {
            version: VERSION,
            pkt_type: PacketType::Request,
            flags: flags::REQUEST_DSCP_ECHO | flags::ECHO_PAYLOAD,
            session_id: 0x7F3A_9C2B_1D4E_8A60,
            seq: 12345,
            reflector_seq: 0,
            t1: 1_234_567_890_123,
            t2: 0,
            t3: 0,
            tx_dscp: 46,
            rx_dscp: 0,
            ttl_fwd: 0,
            ttl_rev: 0,
            payload_len: (DEFAULT_PACKET_LEN - HEADER_LEN) as u16,
        }
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let h = sample_header();
        let mut buf = vec![0u8; h.wire_len()];
        h.encode(&mut buf).unwrap();
        assert_eq!(Header::decode(&buf).unwrap(), h);
    }

    #[test]
    fn header_is_exactly_56_bytes() {
        // The layout is a wire contract; a silent change here desynchronises
        // every deployed agent.
        assert_eq!(HEADER_LEN, 56);
        let h = sample_header();
        assert_eq!(h.wire_len(), DEFAULT_PACKET_LEN);
    }

    #[test]
    fn rejects_foreign_traffic() {
        let mut buf = vec![0u8; DEFAULT_PACKET_LEN];
        buf[0..2].copy_from_slice(&0xDEADu16.to_be_bytes());
        assert!(matches!(Header::decode(&buf), Err(DecodeError::BadMagic { .. })));
    }

    #[test]
    fn rejects_short_packet() {
        let buf = vec![0u8; 20];
        assert!(matches!(Header::decode(&buf), Err(DecodeError::TooShort { got: 20 })));
    }

    #[test]
    fn rejects_future_version() {
        let h = sample_header();
        let mut buf = vec![0u8; h.wire_len()];
        h.encode(&mut buf).unwrap();
        buf[2] = 99;
        assert!(matches!(
            Header::decode(&buf),
            Err(DecodeError::UnsupportedVersion { got: 99 })
        ));
    }

    #[test]
    fn rejects_unknown_flags() {
        let mut h = sample_header();
        h.flags = 0x8000; // reserved bit
        let mut buf = vec![0u8; h.wire_len()];
        h.encode(&mut buf).unwrap();
        assert!(matches!(Header::decode(&buf), Err(DecodeError::UnknownFlags { .. })));
    }

    #[test]
    fn detects_corrupted_timestamp() {
        // The case the checksum exists for: a flipped byte in t1 would
        // otherwise decode as a plausible-looking but wrong latency.
        let h = sample_header();
        let mut buf = vec![0u8; h.wire_len()];
        h.encode(&mut buf).unwrap();
        buf[27] ^= 0x01;
        assert!(matches!(Header::decode(&buf), Err(DecodeError::BadChecksum { .. })));
    }

    #[test]
    fn detects_truncated_payload() {
        let h = sample_header();
        let mut buf = vec![0u8; h.wire_len()];
        h.encode(&mut buf).unwrap();
        buf.truncate(h.wire_len() - 10);
        assert!(matches!(Header::decode(&buf), Err(DecodeError::LengthMismatch { .. })));
    }

    #[test]
    fn stamping_t1_keeps_packet_valid() {
        let h = sample_header();
        let mut buf = vec![0u8; h.wire_len()];
        h.encode(&mut buf).unwrap();
        stamp_t1(&mut buf, 999_999_999).unwrap();
        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(decoded.t1, 999_999_999);
        assert_eq!(decoded.seq, h.seq, "stamping must not disturb other fields");
    }

    #[test]
    fn reflection_sets_reply_fields_and_stays_valid() {
        let h = sample_header();
        let mut buf = vec![0u8; h.wire_len()];
        h.encode(&mut buf).unwrap();

        make_reply_in_place(&mut buf, 5_000, 77, 46, 62, 64).unwrap();
        stamp_t3(&mut buf, 5_120).unwrap();

        let r = Header::decode(&buf).unwrap();
        assert_eq!(r.pkt_type, PacketType::Reply);
        assert_eq!(r.t2, 5_000);
        assert_eq!(r.t3, 5_120);
        assert_eq!(r.reflector_seq, 77);
        assert_eq!(r.rx_dscp, 46);
        assert_eq!(r.ttl_fwd, 62);
        // Sender-side fields must survive reflection untouched — the sender
        // matches the reply to its sample by seq and t1.
        assert_eq!(r.seq, h.seq);
        assert_eq!(r.t1, h.t1);
        assert_eq!(r.session_id, h.session_id);
    }

    #[test]
    fn crc_matches_known_vector() {
        // CRC-16/CCITT-FALSE check value for "123456789" is 0x29B1.
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
    }
}
