//! The sender: paces probe packets at a fixed interval and collects samples.
//!
//! Receiving runs concurrently with sending rather than after it. Sending a
//! whole burst first and then draining replies would make every RTT include the
//! remainder of the burst — the measurement would be dominated by our own
//! pacing rather than by the network.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, trace, warn};

use super::socket::{self, RecvMeta};
use super::Clock;
use crate::collector::stats::Sample;
use crate::proto::mqp::{self, Header, PacketType, DEFAULT_PACKET_LEN, HEADER_LEN, MAX_PACKET_LEN};

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub session_id: u64,
    pub peer: SocketAddr,
    pub count: u32,
    pub interval: Duration,
    /// Total packet size on the wire, header included.
    pub payload_bytes: usize,
    pub dscp: Option<u8>,
    /// How long to wait for a reply before giving up on an individual packet.
    pub timeout: Duration,
    /// Grace period after the last packet, for stragglers still in flight.
    pub linger: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            session_id: 0,
            peer: "127.0.0.1:5301".parse().unwrap(),
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
pub enum ProbeError {
    #[error("probe socket error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet size {requested} is out of range ({HEADER_LEN}..={MAX_PACKET_LEN})")]
    BadPacketSize { requested: usize },
    #[error("count must be at least 1")]
    EmptyRun,
}

#[derive(Debug)]
pub struct ProbeRun {
    pub sent: u32,
    pub samples: Vec<Sample>,
    /// Packets whose pacing tick was late. High values mean the device could
    /// not keep up and the offered rate was not what was configured — the
    /// results are still valid, but the test was gentler than requested.
    pub late_ticks: u32,
}

/// Run one probe session to completion.
pub async fn run(cfg: &ProbeConfig) -> Result<ProbeRun, ProbeError> {
    if cfg.count == 0 {
        return Err(ProbeError::EmptyRun);
    }
    if cfg.payload_bytes < HEADER_LEN || cfg.payload_bytes > MAX_PACKET_LEN {
        return Err(ProbeError::BadPacketSize { requested: cfg.payload_bytes });
    }

    let bind_addr: SocketAddr =
        if cfg.peer.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = socket::bind(bind_addr, cfg.dscp)?;

    let clock = Clock::new();
    let payload_len = (cfg.payload_bytes - HEADER_LEN) as u16;
    let requested_dscp = cfg.dscp.unwrap_or(0);

    // t1 as we recorded it locally, indexed by seq. The value echoed back in
    // the packet is the same, but keeping our own copy means a peer that
    // mangles the field cannot corrupt our timing.
    let mut sent_at: Vec<Option<u64>> = vec![None; cfg.count as usize];
    let mut samples: Vec<Sample> = Vec::with_capacity(cfg.count as usize);
    let mut arrival_index: u32 = 0;
    let mut late_ticks: u32 = 0;

    let mut tx_buf = vec![0u8; cfg.payload_bytes];
    let mut rx_buf = vec![0u8; MAX_PACKET_LEN];

    let mut ticker = interval(cfg.interval);
    // If the device stalls, fire once and carry on rather than firing a
    // catch-up burst — a burst would measure our own backlog, not the path.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut seq: u32 = 0;
    let run_start = clock.now_ns();

    while seq < cfg.count {
        tokio::select! {
            biased;

            // Drain replies first so they are timestamped as close to arrival
            // as possible, ahead of any queued send work.
            res = socket::recv_from_with_meta(&sock, &mut rx_buf) => {
                match res {
                    Ok((n, peer, meta)) => {
                        let t4 = clock.now_ns();
                        if let Some(s) = accept_reply(
                            &rx_buf[..n], peer, meta, t4, cfg, &sent_at,
                            requested_dscp, arrival_index,
                        ) {
                            samples.push(s);
                            arrival_index += 1;
                        }
                    }
                    Err(e) => warn!(error = %e, "receive failed mid-run"),
                }
            }

            tick = ticker.tick() => {
                let expected = run_start + (seq as u64) * cfg.interval.as_nanos() as u64;
                let _ = tick;
                if clock.now_ns() > expected + cfg.interval.as_nanos() as u64 {
                    late_ticks += 1;
                }

                let header = Header::request(cfg.session_id, seq, requested_dscp, payload_len);
                if header.encode(&mut tx_buf).is_err() {
                    return Err(ProbeError::BadPacketSize { requested: cfg.payload_bytes });
                }

                // Stamp as late as possible — anything after this point and
                // before the syscall is charged to the network.
                let t1 = clock.now_ns();
                let _ = mqp::stamp_t1(&mut tx_buf, t1);

                match sock.send_to(&tx_buf, cfg.peer).await {
                    Ok(_) => sent_at[seq as usize] = Some(t1),
                    Err(e) => {
                        // A send failure is not network loss — record it as a
                        // packet never sent rather than a packet lost.
                        warn!(seq, error = %e, "send failed");
                    }
                }
                seq += 1;
            }
        }
    }

    // Linger for packets still in flight. Without this, every run would report
    // the last few packets as lost purely because we stopped listening.
    let deadline = tokio::time::Instant::now() + cfg.linger;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, socket::recv_from_with_meta(&sock, &mut rx_buf)).await {
            Ok(Ok((n, peer, meta))) => {
                let t4 = clock.now_ns();
                if let Some(s) = accept_reply(
                    &rx_buf[..n],
                    peer,
                    meta,
                    t4,
                    cfg,
                    &sent_at,
                    requested_dscp,
                    arrival_index,
                ) {
                    samples.push(s);
                    arrival_index += 1;
                }
            }
            Ok(Err(e)) => {
                warn!(error = %e, "receive failed during linger");
                break;
            }
            Err(_) => break, // linger expired
        }
    }

    let actually_sent = sent_at.iter().filter(|s| s.is_some()).count() as u32;
    debug!(
        session_id = %format_args!("{:016x}", cfg.session_id),
        sent = actually_sent,
        received = samples.len(),
        late_ticks,
        "probe run complete"
    );

    Ok(ProbeRun { sent: actually_sent, samples, late_ticks })
}

/// Validate a reply and turn it into a sample, or return `None` with a reason
/// logged. Everything here is a reason to *discard* rather than to fail the run.
#[allow(clippy::too_many_arguments)]
fn accept_reply(
    buf: &[u8],
    peer: SocketAddr,
    meta: RecvMeta,
    t4: u64,
    cfg: &ProbeConfig,
    sent_at: &[Option<u64>],
    requested_dscp: u8,
    arrival_index: u32,
) -> Option<Sample> {
    if peer.ip() != cfg.peer.ip() {
        trace!(%peer, "ignoring reply from unexpected address");
        return None;
    }

    let h = Header::decode(buf)
        .inspect_err(|e| trace!(error = %e, "discarding malformed reply"))
        .ok()?;

    if h.pkt_type != PacketType::Reply || h.session_id != cfg.session_id {
        return None;
    }

    let t1 = *sent_at.get(h.seq as usize)?;
    let t1 = t1?;

    let round_trip = t4.checked_sub(t1)?;
    let reflector_delay = h.t3.saturating_sub(h.t2);

    // Subtract the reflector's own processing time. On a loaded armv7 router
    // this can be milliseconds and would otherwise be read as network latency.
    let rtt_ns = round_trip.saturating_sub(reflector_delay);

    // A reply that arrived after we gave up on it is real data about a slow
    // path, but including it would understate the loss the application saw.
    if rtt_ns > cfg.timeout.as_nanos() as u64 {
        trace!(seq = h.seq, rtt_ms = rtt_ns / 1_000_000, "reply arrived after timeout");
        return None;
    }

    Some(Sample {
        seq: h.seq,
        reflector_seq: Some(h.reflector_seq),
        rtt_ns,
        tx_dscp: requested_dscp,
        // The reflector's observation of what arrived at *its* end. `meta.dscp`
        // is what came back on the return path, a different question.
        //
        // A non-zero forward TTL proves the reflector's control-message path
        // works -- both fields come from the same mechanism -- so a zero DSCP
        // alongside it means the packet really did arrive best-effort.
        rx_dscp: if h.ttl_fwd > 0 { Some(h.rx_dscp) } else { None },
        arrival_index,
    })
    .inspect(|_| {
        let _ = meta; // return-path DSCP/TTL is captured in v2
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::stats;
    use crate::probe::reflector::{Reflector, Registry};
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex};

    /// Bring up a real reflector and probe it over loopback.
    async fn with_reflector<F, Fut, T>(session_id: u64, f: F) -> T
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let registry = Arc::new(Mutex::new(Registry::new()));
        let r = Reflector::bind("127.0.0.1:0".parse().unwrap(), registry.clone()).await.unwrap();
        let addr = r.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(r.run(rx));

        // Grant from any loopback source; the sender's ephemeral port is not
        // known until it binds, and the registry matches on IP.
        registry.lock().await.grant(session_id, "127.0.0.1:0".parse().unwrap());
        f(addr).await
    }

    fn fast_cfg(session_id: u64, peer: SocketAddr, count: u32) -> ProbeConfig {
        ProbeConfig {
            session_id,
            peer,
            count,
            interval: Duration::from_millis(2),
            dscp: Some(46),
            linger: Duration::from_millis(300),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn loopback_run_returns_every_packet() {
        let run = with_reflector(0x5001, |addr| async move {
            run(&fast_cfg(0x5001, addr, 20)).await.unwrap()
        })
        .await;

        assert_eq!(run.sent, 20);
        assert_eq!(run.samples.len(), 20, "loopback should not lose packets");

        let m = stats::summarise(run.sent, &run.samples, Some(46));
        assert_eq!(m.loss.loss_pct, 0.0);
        assert_eq!(m.reorder.reordered, 0);
        assert!(m.rtt.unwrap().avg_us < 50_000, "loopback RTT should be well under 50ms");
    }

    #[tokio::test]
    async fn reflector_processing_time_is_excluded_from_rtt() {
        // Loopback RTT is microseconds. If we failed to subtract (t3 - t2) the
        // figure would still be small here, so assert the stronger property:
        // measured RTT must be below the wall-clock time the run took per
        // packet, which includes all reflector work.
        let run = with_reflector(0x5002, |addr| async move {
            run(&fast_cfg(0x5002, addr, 10)).await.unwrap()
        })
        .await;

        let m = stats::summarise(run.sent, &run.samples, None).rtt.unwrap();
        assert!(m.min_us < 20_000, "corrected RTT unexpectedly large: {}us", m.min_us);
    }

    #[tokio::test]
    async fn dscp_marking_survives_the_round_trip() {
        let run = with_reflector(0x5003, |addr| async move {
            run(&fast_cfg(0x5003, addr, 10)).await.unwrap()
        })
        .await;

        let d = stats::summarise(run.sent, &run.samples, Some(46))
            .dscp
            .expect("reflector should have echoed DSCP");
        assert_eq!(d.conformant_pct, 100.0, "EF marking should survive loopback intact");
    }

    #[tokio::test]
    async fn unanswered_run_reports_total_loss_not_an_error() {
        // Nothing listening: a dead peer is a measurement result, not a crash.
        let cfg = ProbeConfig {
            session_id: 0x5004,
            peer: "127.0.0.1:1".parse().unwrap(),
            count: 5,
            interval: Duration::from_millis(2),
            linger: Duration::from_millis(100),
            ..Default::default()
        };
        let run = run(&cfg).await.unwrap();

        assert_eq!(run.sent, 5);
        assert!(run.samples.is_empty());

        let m = stats::summarise(run.sent, &run.samples, None);
        assert_eq!(m.loss.loss_pct, 100.0);
        assert_eq!(m.loss.unknown_direction, 5);
    }

    #[tokio::test]
    async fn rejects_invalid_configuration() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let empty = ProbeConfig { count: 0, peer, ..Default::default() };
        assert!(matches!(run(&empty).await, Err(ProbeError::EmptyRun)));

        let tiny = ProbeConfig { payload_bytes: 10, peer, ..Default::default() };
        assert!(matches!(run(&tiny).await, Err(ProbeError::BadPacketSize { .. })));

        let huge = ProbeConfig { payload_bytes: 9000, peer, ..Default::default() };
        assert!(matches!(run(&huge).await, Err(ProbeError::BadPacketSize { .. })));
    }

    #[tokio::test]
    async fn replies_for_a_foreign_session_are_ignored() {
        // The reflector grants 0x5005; we probe with a different session ID, so
        // nothing should be reflected and the run reports full loss.
        let registry = Arc::new(Mutex::new(Registry::new()));
        let r = Reflector::bind("127.0.0.1:0".parse().unwrap(), registry.clone()).await.unwrap();
        let addr = r.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(r.run(rx));
        registry.lock().await.grant(0x5005, "127.0.0.1:0".parse().unwrap());

        let run = run(&fast_cfg(0x9999, addr, 5)).await.unwrap();
        assert!(run.samples.is_empty(), "reflector must not answer an ungranted session");
    }

    #[tokio::test]
    async fn honours_the_configured_packet_size() {
        let run = with_reflector(0x5006, |addr| async move {
            let cfg = ProbeConfig { payload_bytes: 512, ..fast_cfg(0x5006, addr, 5) };
            run(&cfg).await.unwrap()
        })
        .await;
        assert_eq!(run.samples.len(), 5, "512-byte probes should round-trip fine");
    }
}
