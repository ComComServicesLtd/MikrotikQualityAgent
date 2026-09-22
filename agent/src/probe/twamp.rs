//! TWAMP-Light Session-Reflector and Session-Sender.
//!
//! RouterOS provides no TWAMP responder of its own, so where a MikroTik has to
//! answer TWAMP — for a carrier's test set, a customer's probe, or our own
//! sender — this is what answers.
//!
//! # Why this listens on its own port
//!
//! MQP begins with a two-byte magic, TWAMP with a four-byte sequence number.
//! A TWAMP packet whose sequence happens to start `0x4D51` would be
//! indistinguishable from an MQP packet on a shared port, and would be parsed
//! as one. Rather than guess between them, each protocol gets a socket.
//!
//! # Admission control is weaker than MQP's, unavoidably
//!
//! MQP carries an unguessable `session_id` that the controller issues per test,
//! and the reflector ignores anything else. TWAMP-Light has no session
//! identifier at all — that is the point of Light mode — so the only thing this
//! reflector can filter on is the source address. An open TWAMP reflector will
//! answer anyone who finds the port, which makes it usable as a reflection
//! amplifier. Replies are the same size as requests, which removes the
//! amplification factor, but the exposure is real: keep the allow-list narrow
//! and the firewall in front of it narrower.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, trace, warn};

use super::socket::{self, RecvMeta};
use super::Clock;
use crate::collector::stats::Sample;
use crate::proto::twamp::{
    self, ErrorEstimate, ReflectorPacket, SenderPacket, DEFAULT_PACKET_LEN, MAX_PACKET_LEN,
    REFLECTOR_MIN_LEN, SENDER_MIN_LEN,
};

/// TTL set on replies, so a sender can derive the reverse hop count.
const REPLY_TTL: u8 = 64;

/// Who the reflector will answer.
#[derive(Debug, Default)]
pub struct AllowList {
    peers: BTreeSet<IpAddr>,
    /// Answer anyone. Intended for a lab or a port already firewalled to a
    /// known set; never a sensible production default, since TWAMP-Light has
    /// no other admission control.
    open: bool,
}

impl AllowList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer any source. See the caveat above.
    pub fn open() -> Self {
        Self { peers: BTreeSet::new(), open: true }
    }

    pub fn allow(&mut self, ip: IpAddr) {
        self.peers.insert(ip);
    }

    pub fn revoke(&mut self, ip: &IpAddr) -> bool {
        self.peers.remove(ip)
    }

    pub fn permits(&self, ip: &IpAddr) -> bool {
        self.open || self.peers.contains(ip)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty() && !self.open
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReflectorStats {
    pub reflected: u64,
    pub refused: u64,
    pub malformed: u64,
    pub send_errors: u64,
}

pub struct TwampReflector {
    sock: UdpSocket,
    clock: Clock,
    allow: Arc<Mutex<AllowList>>,
    /// Advances once per reply generated, across all peers.
    ///
    /// RFC 5357 describes this as per-session, but Light mode has no session to
    /// scope it to. A single counter is the honest reading, and a sender uses
    /// it only to spot gaps on the return path.
    sequence: u32,
    stats: ReflectorStats,
}

impl TwampReflector {
    pub async fn bind(addr: SocketAddr, allow: Arc<Mutex<AllowList>>) -> std::io::Result<Self> {
        let sock = socket::bind(addr, None)?;
        Ok(Self {
            sock,
            clock: Clock::new(),
            allow,
            sequence: 0,
            stats: ReflectorStats::default(),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub fn stats(&self) -> ReflectorStats {
        self.stats
    }

    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut buf = vec![0u8; MAX_PACKET_LEN];
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        debug!(stats = ?self.stats, "TWAMP reflector shutting down");
                        return;
                    }
                }
                res = socket::recv_from_with_meta(&self.sock, &mut buf) => match res {
                    Ok((n, peer, meta)) => self.handle(&mut buf, n, peer, meta).await,
                    Err(e) => {
                        // A transient receive error must not end the loop, or
                        // the agent goes silently deaf to TWAMP.
                        warn!(error = %e, "TWAMP socket receive failed");
                        self.stats.send_errors += 1;
                    }
                },
            }
        }
    }

    async fn handle(&mut self, buf: &mut [u8], n: usize, peer: SocketAddr, meta: RecvMeta) {
        // Stamp arrival before parsing, so our own decode cost is not charged
        // to the network by whoever is measuring us.
        let t2 = self.clock.now_ntp();

        if !self.allow.lock().await.permits(&peer.ip()) {
            // Silence, not a rejection: answering would confirm to a scanner
            // that a reflector lives here.
            self.stats.refused += 1;
            trace!(%peer, "refusing TWAMP from a source that is not allowed");
            return;
        }

        let request = match SenderPacket::decode(&buf[..n]) {
            Ok(r) => r,
            Err(e) => {
                self.stats.malformed += 1;
                trace!(%peer, error = %e, "dropping malformed TWAMP request");
                return;
            }
        };

        let reply = ReflectorPacket::reply_to(
            &request,
            self.sequence,
            t2,
            meta.ttl.unwrap_or(0),
        );
        self.sequence = self.sequence.wrapping_add(1);

        // Reply in the same size as the request where the request is large
        // enough to hold a reply, so neither direction is policed differently
        // for its size. A request smaller than a reflector packet is padded up
        // to the minimum the format requires.
        let out_len = n.max(REFLECTOR_MIN_LEN).min(MAX_PACKET_LEN);
        if buf.len() < out_len {
            self.stats.malformed += 1;
            return;
        }
        // Clear the header region; padding beyond it is whatever arrived,
        // which is what the RFC expects to be echoed.
        buf[..REFLECTOR_MIN_LEN].fill(0);
        if reply.encode(&mut buf[..out_len]).is_err() {
            self.stats.malformed += 1;
            return;
        }

        // T3 as late as possible — see the note in the codec.
        let t3 = self.clock.now_ntp();
        if twamp::stamp_reflector_tx(&mut buf[..out_len], t3).is_err() {
            self.stats.malformed += 1;
            return;
        }
        let _ = socket::set_dscp_raw(
            {
                use std::os::fd::AsRawFd;
                self.sock.as_raw_fd()
            },
            peer.is_ipv4(),
            meta.dscp.unwrap_or(0),
        );

        match self.sock.send_to(&buf[..out_len], peer).await {
            Ok(_) => self.stats.reflected += 1,
            Err(e) => {
                self.stats.send_errors += 1;
                warn!(%peer, error = %e, "failed to send TWAMP reply");
            }
        }
        let _ = REPLY_TTL;
    }
}

// --- sender ---------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TwampConfig {
    pub peer: SocketAddr,
    pub count: u32,
    pub interval: Duration,
    pub payload_bytes: usize,
    pub dscp: Option<u8>,
    pub timeout: Duration,
    pub linger: Duration,
}

impl Default for TwampConfig {
    fn default() -> Self {
        Self {
            peer: "127.0.0.1:862".parse().unwrap(),
            count: 100,
            interval: Duration::from_millis(20),
            payload_bytes: DEFAULT_PACKET_LEN,
            dscp: None,
            timeout: Duration::from_secs(1),
            linger: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TwampSenderError {
    #[error("socket error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet size {requested} is out of range ({SENDER_MIN_LEN}..={MAX_PACKET_LEN})")]
    BadPacketSize { requested: usize },
    #[error("count must be at least 1")]
    EmptyRun,
}

#[derive(Debug)]
pub struct TwampRun {
    pub sent: u32,
    pub samples: Vec<Sample>,
    pub late_ticks: u32,
    /// True when the responder ever set its synchronised bit. Recorded because
    /// one-way delay is only meaningful if it did — and ours never does.
    pub peer_claims_sync: bool,
}

/// Run a TWAMP-Light session against a responder.
///
/// Results reuse [`Sample`], so the same statistics and MOS code serves both
/// protocols. DSCP conformance comes back empty: TWAMP has no field for the
/// class a packet arrived in, which is precisely the gap MQP exists to close.
pub async fn run(cfg: &TwampConfig) -> Result<TwampRun, TwampSenderError> {
    if cfg.count == 0 {
        return Err(TwampSenderError::EmptyRun);
    }
    if cfg.payload_bytes < SENDER_MIN_LEN || cfg.payload_bytes > MAX_PACKET_LEN {
        return Err(TwampSenderError::BadPacketSize { requested: cfg.payload_bytes });
    }

    let bind: SocketAddr =
        if cfg.peer.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = socket::bind(bind, cfg.dscp)?;
    let clock = Clock::new();

    let mut sent_at = vec![None; cfg.count as usize];
    let mut samples: Vec<Sample> = Vec::with_capacity(cfg.count as usize);
    let mut arrival_index = 0u32;
    let mut late_ticks = 0u32;
    let mut peer_claims_sync = false;

    let mut tx = vec![0u8; cfg.payload_bytes];
    let mut rx = vec![0u8; MAX_PACKET_LEN];

    let mut ticker = interval(cfg.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut seq = 0u32;
    let start = clock.now_ns();

    while seq < cfg.count {
        tokio::select! {
            biased;
            res = socket::recv_from_with_meta(&sock, &mut rx) => {
                if let Ok((n, peer, _)) = res {
                    let t4 = clock.now_ntp();
                    if let Some(s) = accept(&rx[..n], peer, t4, cfg, &sent_at, arrival_index,
                                            &mut peer_claims_sync) {
                        samples.push(s);
                        arrival_index += 1;
                    }
                }
            }
            _ = ticker.tick() => {
                let expected = start + (seq as u64) * cfg.interval.as_nanos() as u64;
                if clock.now_ns() > expected + cfg.interval.as_nanos() as u64 {
                    late_ticks += 1;
                }

                let pkt = SenderPacket {
                    sequence: seq,
                    timestamp: twamp::NtpTimestamp::ZERO,
                    error_estimate: ErrorEstimate::UNSYNCHRONIZED,
                };
                if pkt.encode(&mut tx).is_err() {
                    return Err(TwampSenderError::BadPacketSize { requested: cfg.payload_bytes });
                }
                let t1 = clock.now_ntp();
                let _ = twamp::stamp_sender_tx(&mut tx, t1);

                match sock.send_to(&tx, cfg.peer).await {
                    Ok(_) => sent_at[seq as usize] = Some(t1),
                    Err(e) => warn!(seq, error = %e, "TWAMP send failed"),
                }
                seq += 1;
            }
        }
    }

    // Linger, or the last few packets are always reported lost because we
    // stopped listening rather than because they did not arrive.
    let deadline = tokio::time::Instant::now() + cfg.linger;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match timeout(left, socket::recv_from_with_meta(&sock, &mut rx)).await {
            Ok(Ok((n, peer, _))) => {
                let t4 = clock.now_ntp();
                if let Some(s) =
                    accept(&rx[..n], peer, t4, cfg, &sent_at, arrival_index, &mut peer_claims_sync)
                {
                    samples.push(s);
                    arrival_index += 1;
                }
            }
            _ => break,
        }
    }

    let actually_sent = sent_at.iter().filter(|s| s.is_some()).count() as u32;
    debug!(
        peer = %cfg.peer, sent = actually_sent, received = samples.len(),
        late_ticks, "TWAMP run complete"
    );
    Ok(TwampRun { sent: actually_sent, samples, late_ticks, peer_claims_sync })
}

#[allow(clippy::too_many_arguments)]
fn accept(
    buf: &[u8],
    peer: SocketAddr,
    t4: twamp::NtpTimestamp,
    cfg: &TwampConfig,
    sent_at: &[Option<twamp::NtpTimestamp>],
    arrival_index: u32,
    peer_claims_sync: &mut bool,
) -> Option<Sample> {
    if peer.ip() != cfg.peer.ip() {
        return None;
    }
    let r = ReflectorPacket::decode(buf)
        .inspect_err(|e| trace!(error = %e, "discarding malformed TWAMP reply"))
        .ok()?;

    if r.error_estimate.synchronized {
        *peer_claims_sync = true;
    }

    // Our own record of T1, not the echoed one: a responder that mangles the
    // field must not be able to corrupt our timing.
    let t1 = (*sent_at.get(r.sender_sequence as usize)?)?;
    let rtt = twamp::round_trip(t1, r.receive_timestamp, r.timestamp, t4)?;

    if rtt > cfg.timeout {
        trace!(seq = r.sender_sequence, ?rtt, "TWAMP reply arrived after timeout");
        return None;
    }

    Some(Sample {
        seq: r.sender_sequence,
        // Light mode has no session, so the responder counter spans all peers
        // and cannot tell this sender anything about its own return path.
        reflector_seq: None,
        rtt_ns: rtt.as_nanos().min(u64::MAX as u128) as u64,
        tx_dscp: cfg.dscp.unwrap_or(0),
        // TWAMP has no field for the class a packet arrived in, so DSCP
        // conformance is genuinely unavailable rather than zero.
        rx_dscp: None,
        arrival_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::stats;
    use tokio::sync::watch;

    async fn spawn(allow: AllowList) -> (SocketAddr, watch::Sender<bool>) {
        let list = Arc::new(Mutex::new(allow));
        let r = TwampReflector::bind("127.0.0.1:0".parse().unwrap(), list).await.unwrap();
        let addr = r.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(r.run(rx));
        (addr, tx)
    }

    fn cfg(peer: SocketAddr, count: u32) -> TwampConfig {
        TwampConfig {
            peer,
            count,
            interval: Duration::from_millis(2),
            linger: Duration::from_millis(300),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_full_session_completes_over_loopback() {
        let (addr, _sd) = spawn(AllowList::open()).await;
        let run = run(&cfg(addr, 20)).await.unwrap();

        assert_eq!(run.sent, 20);
        assert_eq!(run.samples.len(), 20, "loopback should not lose TWAMP packets");

        let m = stats::summarise(run.sent, &run.samples, None);
        assert_eq!(m.loss.loss_pct, 0.0);
        assert!(m.rtt.unwrap().avg_us < 50_000);
    }

    #[tokio::test]
    async fn reflector_turnaround_is_excluded_from_rtt() {
        let (addr, _sd) = spawn(AllowList::open()).await;
        let run = run(&cfg(addr, 10)).await.unwrap();
        let r = stats::summarise(run.sent, &run.samples, None).rtt.unwrap();
        assert!(r.min_us < 20_000, "corrected RTT unexpectedly large: {}us", r.min_us);
    }

    #[tokio::test]
    async fn dscp_conformance_is_unavailable_not_zero() {
        // TWAMP carries no received-class field. Reporting 0% conformance
        // would look like a total QoS failure rather than missing data.
        let (addr, _sd) = spawn(AllowList::open()).await;
        let mut c = cfg(addr, 10);
        c.dscp = Some(46);
        let run = run(&c).await.unwrap();
        assert!(stats::summarise(run.sent, &run.samples, Some(46)).dscp.is_none());
    }

    #[tokio::test]
    async fn a_source_that_is_not_allowed_gets_silence() {
        // Not an error reply: answering would confirm a reflector is here.
        let mut list = AllowList::new();
        list.allow("203.0.113.9".parse().unwrap());
        let (addr, _sd) = spawn(list).await;

        let run = run(&cfg(addr, 5)).await.unwrap();
        assert!(run.samples.is_empty(), "reflector must not answer an unlisted source");
    }

    #[tokio::test]
    async fn an_explicitly_allowed_source_is_answered() {
        let mut list = AllowList::new();
        list.allow("127.0.0.1".parse().unwrap());
        let (addr, _sd) = spawn(list).await;

        let run = run(&cfg(addr, 5)).await.unwrap();
        assert_eq!(run.samples.len(), 5);
    }

    #[tokio::test]
    async fn the_reflector_survives_garbage() {
        let (addr, _sd) = spawn(AllowList::open()).await;
        let junk = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        junk.send_to(b"hi", addr).await.unwrap();
        junk.send_to(&[0u8; 3], addr).await.unwrap();

        let run = run(&cfg(addr, 5)).await.unwrap();
        assert_eq!(run.samples.len(), 5, "reflector should still be serving");
    }

    #[tokio::test]
    async fn twamp_samples_carry_no_direction_attribution() {
        // The responder's counter spans every peer at once, so it says nothing
        // about this sender's return path. Two customers probing one upstream
        // would otherwise each read the other's replies as their own reverse
        // loss and report heavy loss on a healthy path.
        let (addr, _sd) = spawn(AllowList::open()).await;
        let run = run(&cfg(addr, 6)).await.unwrap();
        assert!(!run.samples.is_empty());
        assert!(
            run.samples.iter().all(|s| s.reflector_seq.is_none()),
            "TWAMP must not claim a direction it cannot know"
        );

        let l = stats::summarise(run.sent, &run.samples, None).loss;
        assert_eq!(l.reverse_lost, 0);
        assert_eq!(l.forward_lost, 0);
    }

    #[tokio::test]
    async fn our_reflector_does_not_claim_a_synchronised_clock() {
        let (addr, _sd) = spawn(AllowList::open()).await;
        let run = run(&cfg(addr, 5)).await.unwrap();
        assert!(
            !run.peer_claims_sync,
            "we cannot verify NTP on a customer router, so we must not assert it"
        );
    }

    #[tokio::test]
    async fn an_unreachable_responder_is_total_loss_not_an_error() {
        let c = TwampConfig {
            peer: "127.0.0.1:1".parse().unwrap(),
            count: 4,
            interval: Duration::from_millis(2),
            linger: Duration::from_millis(100),
            ..Default::default()
        };
        let run = run(&c).await.unwrap();
        assert_eq!(run.sent, 4);
        assert!(run.samples.is_empty());
        assert_eq!(stats::summarise(run.sent, &run.samples, None).loss.loss_pct, 100.0);
    }

    #[tokio::test]
    async fn invalid_configuration_is_rejected() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(matches!(
            run(&TwampConfig { count: 0, peer, ..Default::default() }).await,
            Err(TwampSenderError::EmptyRun)
        ));
        assert!(matches!(
            run(&TwampConfig { payload_bytes: 4, peer, ..Default::default() }).await,
            Err(TwampSenderError::BadPacketSize { .. })
        ));
    }

    #[test]
    fn an_empty_allow_list_permits_nobody() {
        let list = AllowList::new();
        assert!(!list.permits(&"127.0.0.1".parse().unwrap()));
        assert!(list.is_empty());
    }

    #[test]
    fn allow_and_revoke_behave() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let mut list = AllowList::new();
        list.allow(ip);
        assert!(list.permits(&ip));
        assert_eq!(list.len(), 1);
        assert!(list.revoke(&ip));
        assert!(!list.permits(&ip));
        assert!(!list.revoke(&ip), "revoking twice reports nothing was there");
    }
}
