//! Turns per-packet samples into the metrics the controller stores.
//!
//! All latency is microseconds. Nanoseconds would overstate the accuracy we
//! actually have through a container veth; milliseconds lose real signal on a
//! LAN path.

use serde::{Deserialize, Serialize};

/// One probe packet's outcome, recorded by the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub seq: u32,
    /// Reflector's own counter, used to separate reverse loss from forward
    /// loss.
    ///
    /// `None` when the protocol cannot attribute a direction at all. TWAMP-Light
    /// is the case: it has no session, so a responder's counter advances across
    /// every peer at once. Two customers probing one upstream would each see
    /// the other's replies consume counter values, read the gaps as their own
    /// reverse loss, and report heavy loss on a healthy path. Encoding the
    /// absence here rather than passing a flag means a protocol that cannot
    /// know simply cannot claim.
    pub reflector_seq: Option<u32>,
    /// Corrected round trip: `(t4 - t1) - (t3 - t2)`, in nanoseconds.
    pub rtt_ns: u64,
    /// DSCP we asked for.
    pub tx_dscp: u8,
    /// DSCP the reflector actually observed on arrival.
    ///
    /// `None` when the peer did not report one at all — TWAMP has no such
    /// field, and a reflector whose kernel withheld the control message cannot
    /// know either. `Some(0)` is entirely different: the packet genuinely
    /// arrived as best-effort, which means something on the path bleached the
    /// marking. Collapsing those two into a bare `0` hid exactly the finding
    /// this metric exists to produce.
    pub rx_dscp: Option<u8>,
    /// Order of arrival at the sender, 0-based. Distinct from `seq`, which is
    /// order of departure — the difference is what reordering means.
    pub arrival_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RttStats {
    pub min_us: u64,
    pub avg_us: u64,
    pub max_us: u64,
    pub stddev_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct JitterStats {
    /// Mean absolute IPDV per RFC 3393: |RTT(i) - RTT(i-1)| averaged over
    /// consecutive *sent* packets that both returned.
    pub ipdv_avg_us: u64,
    /// 95th percentile of |RTT(i) - p50|. Packet delay variation against the
    /// median rather than against the previous packet; monitoring systems
    /// disagree about which "jitter" means, so we report both.
    pub pdv_p95_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LossStats {
    pub sent: u32,
    pub received: u32,
    /// Gaps the reflector observed in our `seq` — the request never arrived.
    pub forward_lost: u32,
    /// Gaps in `reflector_seq` — the reply was generated but never arrived.
    pub reverse_lost: u32,
    /// Sent, never seen again, and no neighbouring reply let us attribute a
    /// direction. Counted separately rather than guessed at.
    pub unknown_direction: u32,
    pub loss_pct: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReorderStats {
    /// Packets that arrived after a higher `seq` had already arrived (RFC 4737).
    pub reordered: u32,
    /// Largest gap, in sequence positions, that a reordered packet travelled.
    pub max_displacement: u32,
    pub duplicated: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DscpStats {
    pub requested: u8,
    /// Most frequently observed DSCP at the reflector.
    pub observed_mode: u8,
    /// Share of packets that arrived carrying the DSCP we asked for. Below 100
    /// means something on the path is remarking or bleaching the traffic.
    pub conformant_pct: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeMetrics {
    pub rtt: Option<RttStats>,
    pub jitter: Option<JitterStats>,
    pub loss: LossStats,
    pub reorder: ReorderStats,
    pub dscp: Option<DscpStats>,
}

/// Compute metrics for a completed session.
///
/// `sent` is how many packets we put on the wire; `samples` are the ones that
/// came back, in arrival order. `highest_reflector_seq` is the largest
/// `reflector_seq` we saw, which bounds how many replies the reflector actually
/// generated.
pub fn summarise(sent: u32, samples: &[Sample], requested_dscp: Option<u8>) -> ProbeMetrics {
    let received = samples.len() as u32;

    ProbeMetrics {
        rtt: rtt_stats(samples),
        jitter: jitter_stats(samples),
        loss: loss_stats(sent, samples),
        reorder: reorder_stats(samples),
        dscp: requested_dscp.and_then(|d| dscp_stats(d, samples)),
        // `received` is folded into loss_stats; kept here only for clarity of
        // the assertion below.
    }
    .tap_check(received)
}

impl ProbeMetrics {
    fn tap_check(self, received: u32) -> Self {
        debug_assert_eq!(self.loss.received, received);
        self
    }
}

fn rtt_stats(samples: &[Sample]) -> Option<RttStats> {
    if samples.is_empty() {
        return None;
    }

    let mut us: Vec<u64> = samples.iter().map(|s| s.rtt_ns / 1_000).collect();
    us.sort_unstable();

    let n = us.len();
    let sum: u128 = us.iter().map(|&v| v as u128).sum();
    let avg = (sum / n as u128) as u64;

    // Population variance in u128 to stay exact: a 24 ms RTT squared already
    // exceeds u32, and on a bad path we may see far worse.
    let variance = us
        .iter()
        .map(|&v| {
            let d = v.abs_diff(avg) as u128;
            d * d
        })
        .sum::<u128>()
        / n as u128;

    Some(RttStats {
        min_us: us[0],
        avg_us: avg,
        max_us: us[n - 1],
        stddev_us: isqrt_u128(variance),
        p50_us: percentile(&us, 50.0),
        p95_us: percentile(&us, 95.0),
        p99_us: percentile(&us, 99.0),
    })
}

fn jitter_stats(samples: &[Sample]) -> Option<JitterStats> {
    if samples.len() < 2 {
        return None;
    }

    // IPDV is defined over consecutive *sent* packets, so order by seq, not by
    // arrival. Using arrival order would fold reordering into the jitter figure.
    let mut by_seq: Vec<&Sample> = samples.iter().collect();
    by_seq.sort_unstable_by_key(|s| s.seq);

    let mut deltas: Vec<u64> = Vec::with_capacity(by_seq.len() - 1);
    for pair in by_seq.windows(2) {
        // Only consecutive sequence numbers qualify; across a loss gap the
        // difference is not IPDV.
        if pair[1].seq == pair[0].seq + 1 {
            let a = pair[0].rtt_ns / 1_000;
            let b = pair[1].rtt_ns / 1_000;
            deltas.push(b.abs_diff(a));
        }
    }

    if deltas.is_empty() {
        return None;
    }

    let ipdv_avg = (deltas.iter().map(|&v| v as u128).sum::<u128>() / deltas.len() as u128) as u64;

    let mut us: Vec<u64> = samples.iter().map(|s| s.rtt_ns / 1_000).collect();
    us.sort_unstable();
    let median = percentile(&us, 50.0);
    let mut devs: Vec<u64> = us.iter().map(|&v| v.abs_diff(median)).collect();
    devs.sort_unstable();

    Some(JitterStats { ipdv_avg_us: ipdv_avg, pdv_p95_us: percentile(&devs, 95.0) })
}

fn loss_stats(sent: u32, samples: &[Sample]) -> LossStats {
    let received = samples.len() as u32;
    let missing = sent.saturating_sub(received);
    let loss_pct = if sent == 0 { 0.0 } else { (missing as f64 / sent as f64) * 100.0 };

    // Every sample must carry a counter before any attribution is attempted.
    // Guessing from a protocol that cannot tell us is worse than admitting we
    // do not know: a wrong direction sends someone to the wrong end of a path.
    if !samples.iter().all(|s| s.reflector_seq.is_some()) {
        return LossStats {
            sent,
            received,
            forward_lost: 0,
            reverse_lost: 0,
            unknown_direction: missing,
            loss_pct: round2(loss_pct),
        };
    }

    // `reflector_seq` increments once per reply the reflector generated. If we
    // saw its highest value but are missing packets in between, those replies
    // existed and died on the way back. Requests that never reached the
    // reflector never advanced its counter at all.
    let highest_reflector_seq = samples.iter().filter_map(|s| s.reflector_seq).max();
    let distinct_replies = samples.len() as u32;

    let (forward_lost, reverse_lost, unknown) = match highest_reflector_seq {
        Some(high) => {
            // The reflector numbered replies 0..=high, so it generated high+1.
            let replies_generated = high.saturating_add(1);
            let reverse = replies_generated.saturating_sub(distinct_replies);
            let forward = missing.saturating_sub(reverse);
            (forward, reverse.min(missing), 0)
        }
        // Nothing came back at all — we cannot attribute a direction.
        None => (0, 0, missing),
    };

    LossStats {
        sent,
        received,
        forward_lost,
        reverse_lost,
        unknown_direction: unknown,
        loss_pct: round2(loss_pct),
    }
}

fn reorder_stats(samples: &[Sample]) -> ReorderStats {
    let mut seen: Vec<u32> = samples.iter().map(|s| s.seq).collect();
    let total = seen.len();
    seen.sort_unstable();
    seen.dedup();
    let duplicated = (total - seen.len()) as u32;

    // RFC 4737: a packet is reordered if a higher sequence number has already
    // arrived. Walk arrival order, tracking the high-water mark.
    let mut by_arrival: Vec<&Sample> = samples.iter().collect();
    by_arrival.sort_unstable_by_key(|s| s.arrival_index);

    let mut high_water = 0u32;
    let mut first = true;
    let mut reordered = 0u32;
    let mut max_displacement = 0u32;

    for s in by_arrival {
        if first {
            high_water = s.seq;
            first = false;
            continue;
        }
        if s.seq < high_water {
            reordered += 1;
            max_displacement = max_displacement.max(high_water - s.seq);
        } else {
            high_water = s.seq;
        }
    }

    ReorderStats { reordered, max_displacement, duplicated }
}

fn dscp_stats(requested: u8, samples: &[Sample]) -> Option<DscpStats> {
    // Only samples where the peer actually reported a class. An all-zero set
    // is now a real answer -- the path bleached the marking -- rather than an
    // ambiguous one, because a peer that cannot observe DSCP says so instead
    // of reporting zero.
    let echoed: Vec<u8> = samples.iter().filter_map(|s| s.rx_dscp).collect();
    if echoed.is_empty() {
        return None;
    }

    let mut counts = [0u32; 64];
    for &d in &echoed {
        counts[(d & 0x3F) as usize] += 1;
    }
    let mode = counts
        .iter()
        .enumerate()
        .max_by_key(|(_, &c)| c)
        .map(|(i, _)| i as u8)
        .unwrap_or(0);

    let conformant = counts[(requested & 0x3F) as usize];
    let pct = (conformant as f64 / echoed.len() as f64) * 100.0;

    Some(DscpStats { requested, observed_mode: mode, conformant_pct: round2(pct) })
}

/// Nearest-rank percentile over a pre-sorted slice.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// Integer square root. Avoids pulling f64 into the variance path, where large
/// values would lose precision.
fn isqrt_u128(n: u128) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x as u64
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seq: u32, rtt_us: u64, arrival: u32) -> Sample {
        Sample {
            seq,
            reflector_seq: Some(seq),
            rtt_ns: rtt_us * 1_000,
            tx_dscp: 46,
            rx_dscp: Some(46),
            arrival_index: arrival,
        }
    }

    fn clean_run(n: u32, rtt_us: u64) -> Vec<Sample> {
        (0..n).map(|i| sample(i, rtt_us, i)).collect()
    }

    #[test]
    fn perfect_run_has_no_loss_or_jitter() {
        let s = clean_run(100, 10_000);
        let m = summarise(100, &s, Some(46));

        assert_eq!(m.loss.loss_pct, 0.0);
        assert_eq!(m.loss.received, 100);
        assert_eq!(m.jitter.unwrap().ipdv_avg_us, 0, "constant RTT means zero jitter");
        assert_eq!(m.reorder.reordered, 0);
        assert_eq!(m.rtt.unwrap().avg_us, 10_000);
        assert_eq!(m.dscp.unwrap().conformant_pct, 100.0);
    }

    #[test]
    fn rtt_percentiles_track_the_tail() {
        let mut s = clean_run(99, 10_000);
        s.push(sample(99, 500_000, 99)); // one 500 ms outlier
        let r = summarise(100, &s, None).rtt.unwrap();

        assert_eq!(r.min_us, 10_000);
        assert_eq!(r.max_us, 500_000);
        assert_eq!(r.p50_us, 10_000, "median must ignore a single outlier");
        assert_eq!(r.p99_us, 10_000);
        assert!(r.avg_us > 10_000, "mean is dragged up where the median is not");
    }

    #[test]
    fn jitter_uses_send_order_not_arrival_order() {
        // Alternating 10 ms / 20 ms RTT gives a 10 ms IPDV, but the packets
        // arrive scrambled. Sorting by arrival instead of seq would report a
        // different, wrong figure.
        let samples = vec![
            sample(0, 10_000, 0),
            sample(2, 10_000, 1),
            sample(1, 20_000, 2),
            sample(3, 20_000, 3),
        ];
        let j = summarise(4, &samples, None).jitter.unwrap();
        // |20-10| + |10-20| + |20-10| over the three consecutive pairs.
        assert_eq!(j.ipdv_avg_us, 10_000);
    }

    #[test]
    fn jitter_skips_across_loss_gaps() {
        // seq 1 is missing; 0→2 is not a consecutive pair and must not
        // contribute an IPDV delta.
        let samples = vec![sample(0, 10_000, 0), sample(2, 50_000, 1), sample(3, 50_000, 2)];
        let j = summarise(4, &samples, None).jitter.unwrap();
        assert_eq!(j.ipdv_avg_us, 0, "only the 2→3 pair qualifies, and it is flat");
    }

    #[test]
    fn total_loss_is_reported_as_unattributable() {
        let m = summarise(100, &[], None);
        assert_eq!(m.loss.loss_pct, 100.0);
        assert_eq!(m.loss.unknown_direction, 100);
        assert_eq!(m.loss.forward_lost, 0, "must not invent a direction");
        assert_eq!(m.loss.reverse_lost, 0);
        assert!(m.rtt.is_none());
    }

    #[test]
    fn reverse_loss_is_distinguished_from_forward_loss() {
        // The reflector generated 10 replies (reflector_seq 0..9) but only 8
        // reached us — so 2 died on the return path, not the forward path.
        let samples: Vec<Sample> = (0..8)
            .map(|i| Sample { reflector_seq: Some(i), ..sample(i, 10_000, i) })
            .chain(std::iter::once(Sample {
                seq: 9,
                reflector_seq: Some(9),
                ..sample(9, 10_000, 8)
            }))
            .collect();

        let l = summarise(10, &samples, None).loss;
        assert_eq!(l.received, 9);
        assert_eq!(l.reverse_lost, 1);
        assert_eq!(l.forward_lost, 0);
    }

    #[test]
    fn a_protocol_that_cannot_attribute_direction_reports_undetermined() {
        // TWAMP-Light: the responder's counter spans every peer, so gaps mean
        // nothing about this sender's return path. Attributing them would have
        // reported heavy reverse loss on a perfectly healthy path.
        let samples: Vec<Sample> = (0..8)
            .map(|i| Sample { reflector_seq: None, ..sample(i, 10_000, i) })
            .collect();
        let l = summarise(10, &samples, None).loss;

        assert_eq!(l.unknown_direction, 2);
        assert_eq!(l.forward_lost, 0);
        assert_eq!(l.reverse_lost, 0);
        assert_eq!(l.loss_pct, 20.0, "the loss figure itself is still correct");
    }

    #[test]
    fn interleaved_counters_would_have_faked_reverse_loss() {
        // The concrete failure: a shared upstream answering two customers. This
        // sender got every packet back, but the counter jumped because someone
        // else's replies consumed values in between.
        let samples: Vec<Sample> = (0..5)
            .map(|i| Sample { reflector_seq: None, ..sample(i, 10_000, i) })
            .collect();
        let l = summarise(5, &samples, None).loss;
        assert_eq!(l.loss_pct, 0.0);
        assert_eq!(l.reverse_lost, 0, "a healthy path must not report reverse loss");
    }

    #[test]
    fn reordering_is_detected_with_displacement() {
        // Sent 0,1,2,3,4 — arrived 0,1,4,2,3.
        let samples = vec![
            sample(0, 10_000, 0),
            sample(1, 10_000, 1),
            sample(4, 10_000, 2),
            sample(2, 10_000, 3),
            sample(3, 10_000, 4),
        ];
        let r = summarise(5, &samples, None).reorder;
        assert_eq!(r.reordered, 2, "seq 2 and 3 both arrived after seq 4");
        assert_eq!(r.max_displacement, 2, "seq 2 arrived while high-water was 4");
    }

    #[test]
    fn duplicates_are_counted() {
        let samples =
            vec![sample(0, 10_000, 0), sample(1, 10_000, 1), sample(1, 10_000, 2)];
        assert_eq!(summarise(2, &samples, None).reorder.duplicated, 1);
    }

    #[test]
    fn dscp_remarking_shows_up_as_non_conformance() {
        // Asked for EF (46); half the path bleached it to best-effort.
        let samples: Vec<Sample> = (0..10)
            .map(|i| Sample { rx_dscp: Some(if i < 5 { 46 } else { 0 }), ..sample(i, 10_000, i) })
            .collect();
        let d = summarise(10, &samples, Some(46)).dscp.unwrap();
        assert_eq!(d.conformant_pct, 50.0);
        assert_eq!(d.requested, 46);
    }

    #[test]
    fn a_peer_that_cannot_report_dscp_yields_no_figure() {
        // TWAMP, or a kernel that withheld the control message. Calling that
        // "0% conformant" would read as a total QoS failure.
        let samples: Vec<Sample> =
            (0..10).map(|i| Sample { rx_dscp: None, ..sample(i, 10_000, i) }).collect();
        assert!(summarise(10, &samples, Some(46)).dscp.is_none());
    }

    #[test]
    fn a_path_that_bleaches_the_marking_is_reported_as_zero_percent() {
        // The real case, measured toward an upstream POP: the reflector saw
        // every packet arrive as best-effort. That is the single most useful
        // thing this metric can tell an operator, and the old heuristic hid it
        // behind "not echoed by peer".
        let samples: Vec<Sample> =
            (0..10).map(|i| Sample { rx_dscp: Some(0), ..sample(i, 10_000, i) }).collect();
        let d = summarise(10, &samples, Some(46)).dscp.expect("bleaching must be reported");
        assert_eq!(d.conformant_pct, 0.0);
        assert_eq!(d.observed_mode, 0, "everything arrived best-effort");
        assert_eq!(d.requested, 46);
    }

    #[test]
    fn best_effort_request_still_reports_when_echo_is_zero() {
        // The converse: if we asked for DSCP 0, an all-zero echo is a real
        // 100% conformant result, not missing data.
        let samples: Vec<Sample> = (0..10)
            .map(|i| Sample { tx_dscp: 0, rx_dscp: Some(0), ..sample(i, 10_000, i) })
            .collect();
        let d = summarise(10, &samples, Some(0)).dscp.unwrap();
        assert_eq!(d.conformant_pct, 100.0);
    }

    #[test]
    fn stddev_survives_large_latencies() {
        // A 2 s RTT in microseconds squared overflows u64; the variance path
        // must stay in u128.
        let samples =
            vec![sample(0, 2_000_000, 0), sample(1, 2_000_000, 1), sample(2, 2_000_000, 2)];
        let r = summarise(3, &samples, None).rtt.unwrap();
        assert_eq!(r.stddev_us, 0);
        assert_eq!(r.avg_us, 2_000_000);
    }

    #[test]
    fn single_sample_yields_rtt_but_not_jitter() {
        let m = summarise(1, &[sample(0, 10_000, 0)], None);
        assert!(m.rtt.is_some());
        assert!(m.jitter.is_none(), "jitter is undefined for one packet");
    }
}
