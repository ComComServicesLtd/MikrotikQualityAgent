//! ITU-T G.107 E-model — R-factor and MOS from measured latency, jitter and
//! loss.
//!
//! A MOS score without its codec is meaningless: the same path scores very
//! differently for G.711 and G.729. The codec is therefore a required input and
//! is recorded alongside every score.

use serde::{Deserialize, Serialize};

/// Codec-specific E-model parameters.
///
/// `ie` is the equipment impairment at zero loss; `bpl` is the packet-loss
/// robustness factor — higher means the codec degrades more gracefully.
/// Values are the G.113 Appendix I provisional figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    /// G.711 A-law/µ-law, 64 kbit/s. The reference codec: no compression
    /// impairment, but least tolerant of loss.
    G711,
    /// G.711 with packet loss concealment.
    G711Plc,
    /// G.729A, 8 kbit/s.
    G729,
    /// G.722.2 / AMR-WB wideband.
    G722,
    /// Opus at wideband settings.
    Opus,
}

impl Codec {
    /// `(Ie, Bpl)` — equipment impairment and loss robustness.
    const fn params(self) -> (f64, f64) {
        match self {
            Self::G711 => (0.0, 4.3),
            Self::G711Plc => (0.0, 25.1),
            Self::G729 => (11.0, 19.0),
            Self::G722 => (8.0, 18.0),
            Self::Opus => (7.0, 22.0),
        }
    }

    /// Base (and maximum) transmission rating for this codec's scale.
    ///
    /// Narrowband G.107 tops out at 93.2; the wideband E-model of G.107.1
    /// widens the scale to 129. This is both the starting value of `R0` and the
    /// clamp ceiling — a codec must be scored entirely on one scale or the
    /// other, never with one scale's base and the other's ceiling.
    const fn r_max(self) -> f64 {
        match self {
            Self::G722 | Self::Opus => 129.0,
            _ => 93.2,
        }
    }

    const fn is_wideband(self) -> bool {
        matches!(self, Self::G722 | Self::Opus)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MosScore {
    pub codec: Codec,
    /// Transmission rating factor, 0–93.2 narrowband or 0–129 wideband.
    pub r_factor: f64,
    /// Mean Opinion Score, 1.0–4.5 narrowband (up to ~4.8 wideband).
    pub mos: f64,
    /// Effective one-way delay used in the calculation, ms. Derived, not
    /// measured — v1 has no synchronised clocks. Reported so a consumer can see
    /// what the score was actually based on.
    pub effective_delay_ms: f64,
}

/// Inputs to the E-model, taken from a completed probe session.
#[derive(Debug, Clone, Copy)]
pub struct MosInput {
    pub rtt_us: u64,
    /// Mean absolute IPDV.
    pub jitter_us: u64,
    pub loss_pct: f64,
    pub codec: Codec,
    /// De-jitter buffer depth in ms. A larger buffer absorbs more jitter at the
    /// cost of delay; 60 ms is a common default for a fixed buffer.
    pub jitter_buffer_ms: f64,
}

impl MosInput {
    pub fn new(rtt_us: u64, jitter_us: u64, loss_pct: f64, codec: Codec) -> Self {
        Self { rtt_us, jitter_us, loss_pct, codec, jitter_buffer_ms: 60.0 }
    }
}

/// Advantage factor. Zero for wireline — users grant no tolerance for
/// inconvenience, unlike mobile or satellite.
const A: f64 = 0.0;

/// Best and worst MOS on the narrowband curve, used to stretch wideband scores
/// onto their wider scale without lifting the floor off 1.0.
const MOS_FLOOR: f64 = 1.0;
const MOS_CEIL_NB: f64 = 4.5;
const MOS_CEIL_WB: f64 = 4.8;

/// Compute R-factor and MOS.
///
/// ```text
/// R = R0 - Is - Id - Ie_eff + A
/// ```
///
/// `Is` (simultaneous impairment: loudness, sidetone, quantisation) is zero
/// here — those are properties of the endpoints, which an in-network probe
/// cannot see and should not invent.
pub fn score(input: MosInput) -> MosScore {
    let (ie, bpl) = input.codec.params();

    // One-way delay is approximated as half the round trip. Without
    // synchronised clocks this assumes a symmetric path; asymmetric routing
    // makes it optimistic for the slow direction.
    let owd_ms = (input.rtt_us as f64 / 1_000.0) / 2.0;

    // Jitter costs delay twice: the de-jitter buffer adds its own depth, and
    // jitter beyond what the buffer absorbs becomes discarded packets, which
    // the loss term below accounts for.
    let jitter_ms = input.jitter_us as f64 / 1_000.0;
    let effective_delay_ms = owd_ms + input.jitter_buffer_ms;

    let id = delay_impairment(effective_delay_ms);

    // Jitter exceeding the buffer arrives too late to play out. Treat the
    // excess as additional loss — a path with low average loss but heavy
    // jitter genuinely does sound bad.
    let late_loss_pct = if jitter_ms > input.jitter_buffer_ms {
        ((jitter_ms - input.jitter_buffer_ms) / jitter_ms * 100.0).min(100.0)
    } else {
        0.0
    };
    let total_loss = (input.loss_pct + late_loss_pct).clamp(0.0, 100.0);

    // Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl/BurstR + Bpl)   [G.107 eq. 7-27]
    // BurstR = 1 assumes random (Bernoulli) loss. Real loss is bursty, which
    // is worse; we do not have burst statistics here, so this is optimistic.
    let ie_eff = ie + (95.0 - ie) * total_loss / (total_loss + bpl);

    // R0 is the top of this codec's scale: 93.2 narrowband, 129 wideband. Using
    // the narrowband base for a wideband codec would make a perfect wideband
    // path score *worse* than a perfect narrowband one.
    let r0 = input.codec.r_max();
    let r_raw = r0 - id - ie_eff + A;
    let r = r_raw.clamp(0.0, r0);

    MosScore {
        codec: input.codec,
        r_factor: round2(r),
        mos: round2(r_to_mos(r, input.codec)),
        effective_delay_ms: round2(effective_delay_ms),
    }
}

/// Delay impairment `Id` — the ITU-T G.107 Annex B simplified approximation.
///
/// Flat below 100 ms, then rising; the knee near 177 ms is where conversation
/// starts to break down because talkers begin colliding.
fn delay_impairment(delay_ms: f64) -> f64 {
    if delay_ms < 100.0 {
        return 0.0;
    }
    let h = if delay_ms - 177.3 < 0.0 { 0.0 } else { 1.0 };
    0.024 * delay_ms + 0.11 * (delay_ms - 177.3) * h
}

/// Map R to MOS using the G.107 §B.4 piecewise curve.
///
/// Narrowband R feeds the curve directly, so a perfect narrowband path yields
/// the standard 4.41 at R = 93.2. Wideband R is first normalised onto the same
/// 0–100 curve input, then the resulting score is stretched from the narrowband
/// ceiling to the wideband one — stretching only the range above the floor, so
/// a totally broken wideband path still scores 1.0 rather than something above
/// it.
fn r_to_mos(r: f64, codec: Codec) -> f64 {
    let curve_input = if codec.is_wideband() { r / codec.r_max() * 100.0 } else { r };

    let mos_nb = if curve_input <= 0.0 {
        MOS_FLOOR
    } else if curve_input >= 100.0 {
        MOS_CEIL_NB
    } else {
        1.0 + 0.035 * curve_input
            + curve_input * (curve_input - 60.0) * (100.0 - curve_input) * 7.0e-6
    };

    if codec.is_wideband() {
        let stretch = (MOS_CEIL_WB - MOS_FLOOR) / (MOS_CEIL_NB - MOS_FLOOR);
        (MOS_FLOOR + (mos_nb - MOS_FLOOR) * stretch).clamp(MOS_FLOOR, MOS_CEIL_WB)
    } else {
        mos_nb.clamp(MOS_FLOOR, MOS_CEIL_NB)
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 0.05;

    #[test]
    fn pristine_g711_path_scores_toll_quality() {
        // 10 ms RTT, no jitter, no loss — the best a G.711 call can be.
        let s = score(MosInput::new(10_000, 0, 0.0, Codec::G711));
        assert!(s.mos >= 4.3, "expected toll quality, got MOS {}", s.mos);
        assert!(s.r_factor >= 90.0, "expected R >= 90, got {}", s.r_factor);
    }

    #[test]
    fn loss_degrades_g711_faster_than_g711_with_plc() {
        let plain = score(MosInput::new(10_000, 0, 3.0, Codec::G711));
        let plc = score(MosInput::new(10_000, 0, 3.0, Codec::G711Plc));
        assert!(
            plc.mos > plain.mos,
            "packet loss concealment must help: plc {} vs plain {}",
            plc.mos,
            plain.mos
        );
    }

    #[test]
    fn mos_decreases_monotonically_with_loss() {
        let mut last = f64::MAX;
        for loss in [0.0, 1.0, 2.0, 5.0, 10.0, 20.0] {
            let m = score(MosInput::new(20_000, 0, loss, Codec::G711)).mos;
            assert!(m <= last, "MOS rose from {last} to {m} as loss increased to {loss}%");
            last = m;
        }
    }

    #[test]
    fn mos_decreases_monotonically_with_delay() {
        let mut last = f64::MAX;
        for rtt_ms in [10u64, 100, 200, 400, 800, 1600] {
            let m = score(MosInput::new(rtt_ms * 1_000, 0, 0.0, Codec::G711)).mos;
            assert!(m <= last, "MOS rose from {last} to {m} at {rtt_ms} ms RTT");
            last = m;
        }
    }

    #[test]
    fn satellite_grade_delay_is_penalised() {
        // 600 ms RTT → 300 ms one-way plus buffer. Well past the point where
        // talkers collide; should be clearly sub-toll even with zero loss.
        let s = score(MosInput::new(600_000, 0, 0.0, Codec::G711));
        assert!(s.mos < 3.6, "600 ms RTT should hurt, got MOS {}", s.mos);
    }

    #[test]
    fn jitter_beyond_the_buffer_counts_as_loss() {
        // 100 ms of jitter against a 60 ms buffer: packets arrive too late to
        // play, so the score must fall even though measured loss is zero.
        let calm = score(MosInput::new(20_000, 1_000, 0.0, Codec::G711));
        let wild = score(MosInput::new(20_000, 100_000, 0.0, Codec::G711));
        assert!(
            wild.mos < calm.mos - 0.5,
            "excess jitter must degrade MOS: calm {} vs wild {}",
            calm.mos,
            wild.mos
        );
    }

    #[test]
    fn jitter_within_the_buffer_is_absorbed() {
        let none = score(MosInput::new(20_000, 0, 0.0, Codec::G711));
        let some = score(MosInput::new(20_000, 30_000, 0.0, Codec::G711));
        assert!(
            (none.mos - some.mos).abs() < EPS,
            "30 ms jitter fits a 60 ms buffer and should be absorbed"
        );
    }

    #[test]
    fn g729_is_penalised_against_g711_on_an_identical_path() {
        let g711 = score(MosInput::new(10_000, 0, 0.0, Codec::G711));
        let g729 = score(MosInput::new(10_000, 0, 0.0, Codec::G729));
        assert!(
            g729.mos < g711.mos,
            "compression impairment must show: g729 {} vs g711 {}",
            g729.mos,
            g711.mos
        );
    }

    #[test]
    fn wideband_can_exceed_the_narrowband_ceiling() {
        let opus = score(MosInput::new(10_000, 0, 0.0, Codec::Opus));
        assert!(opus.mos > 4.5, "wideband should beat narrowband toll, got {}", opus.mos);
        assert!(opus.mos <= 4.8);
    }

    #[test]
    fn scores_stay_in_range_under_total_failure() {
        let s = score(MosInput::new(5_000_000, 500_000, 100.0, Codec::G711));
        assert!(s.mos >= 1.0, "MOS floor is 1.0, got {}", s.mos);
        assert!(s.r_factor >= 0.0, "R floor is 0, got {}", s.r_factor);
    }

    #[test]
    fn score_records_the_delay_it_used() {
        // The consumer must be able to see that effective delay is derived
        // from RTT/2 plus buffer, not measured one-way.
        let s = score(MosInput::new(100_000, 0, 0.0, Codec::G711));
        assert!((s.effective_delay_ms - (50.0 + 60.0)).abs() < EPS);
    }

    #[test]
    fn codec_is_carried_through_to_the_result() {
        assert_eq!(score(MosInput::new(10_000, 0, 0.0, Codec::G729)).codec, Codec::G729);
    }
}
