//! Packet capture, for naming the host behind a problem.
//!
//! Interface counters tell you *which interface* is carrying a storm. They
//! cannot tell you which host is generating it, and that is the only fact that
//! lets anyone act. A short capture closes that gap.
//!
//! Two different instruments, for two different questions:
//!
//! - [`run_packet_capture`] drives `/tool/sniffer`, which captures IP traffic
//!   on an interface. This is the one that answers "who is flooding the LAN".
//! - [`run_wireless_capture`] drives `/interface/wireless/sniffer`, which
//!   captures 802.11 frames off the air — management and control frames a
//!   normal capture never sees. It answers RF questions: deauth floods, a
//!   client retrying endlessly, a neighbouring network on the channel.
//!
//! The wireless sniffer exists **only on the legacy `wireless` stack**. The
//! newer `/interface/wifi` used by ax-generation boards has no sniffer at all
//! (verified: `/interface/wifi/sniffer` returns 400), so on those devices this
//! degrades to the packet sniffer and says why.
//!
//! # Both are disruptive, in different ways
//!
//! `/tool/sniffer` costs CPU on a device that may have little to spare. The
//! wireless sniffer is worse: putting the radio into monitor mode, and
//! especially letting it hop channels, interrupts service for associated
//! clients. Neither belongs in a continuous plan — they are one-shot
//! diagnostics with a bounded duration, and the duration is capped here rather
//! than trusted from a caller.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, warn};

use super::findings::{Finding, Severity};
use crate::routeros::{RouterOs, RouterOsError};

/// Longest capture permitted. A sniffer left running on a small router is a
/// denial of service against its own control plane.
pub const MAX_CAPTURE: Duration = Duration::from_secs(60);

/// A host seen during a capture, with what it sent and received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostTraffic {
    pub address: String,
    /// Bytes per second, transmitted and received, as RouterOS reports them.
    pub tx_rate_bps: u64,
    pub rx_rate_bps: u64,
    pub peak_tx_bps: u64,
    pub peak_rx_bps: u64,
    pub total_bytes: u64,
}

impl HostTraffic {
    fn busiest(&self) -> u64 {
        self.tx_rate_bps.max(self.rx_rate_bps)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolTraffic {
    pub protocol: String,
    pub bytes: u64,
    pub packets: u64,
    /// Percentage of captured bytes, as RouterOS computes it.
    pub share_pct: f64,
}

/// One 802.11 frame as the wireless sniffer saw it.
///
/// This is the layer a normal capture cannot reach: management and control
/// frames, the rate each was actually sent at, and whether it arrived intact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WirelessFrame {
    pub src: String,
    pub dst: String,
    /// RouterOS reports this as `2412/20/gn(17dBm)`.
    pub channel: String,
    pub signal_dbm: i32,
    /// Rate the frame was transmitted at, Mbit/s.
    pub rate_mbps: f64,
    /// A frame that failed its checksum. A high share means interference or a
    /// signal too weak to decode reliably — the receiver still spent the
    /// airtime.
    pub crc_error: bool,
    pub frame_type: String,
}

impl WirelessFrame {
    fn is_broadcast(&self) -> bool {
        self.dst.eq_ignore_ascii_case("FF:FF:FF:FF:FF:FF")
    }

    /// Whether this frame's transmit rate says anything about a client's health.
    ///
    /// Only data frames. Beacons, probe responses and acknowledgements are sent
    /// at basic rates *by design* — a beacon at 5.5 Mbit/s on 2.4 GHz is
    /// correct behaviour, not a symptom. On a real capture beacons outnumbered
    /// data frames six to one, so judging every frame by its rate reported 92%
    /// "low rate" on a channel whose data frames were a small minority.
    fn rate_is_diagnostic(&self) -> bool {
        self.frame_type.eq_ignore_ascii_case("data")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capture {
    pub interface: String,
    pub duration_s: u64,
    pub hosts: Vec<HostTraffic>,
    pub protocols: Vec<ProtocolTraffic>,
    /// Frames the wireless sniffer saw, when that instrument was used.
    pub wireless_frames: u64,
    pub frames: Vec<WirelessFrame>,
    pub used_wireless_sniffer: bool,
    pub notes: Vec<String>,
}

/// Capture IP traffic with `/tool/sniffer` and summarise who was talking.
///
/// `interface` empty means every interface, which is usually what you want
/// when hunting a storm you cannot yet localise.
pub async fn run_packet_capture(
    ros: &RouterOs,
    interface: &str,
    duration: Duration,
) -> Result<Capture, RouterOsError> {
    let (secs, mut notes) = clamp(duration);

    // Memory-only. Writing a capture file to a router's flash for a diagnostic
    // that is about to be summarised and discarded is gratuitous wear.
    let mut cfg = json!({ "file-name": "", "memory-limit": "10" });
    if !interface.is_empty() {
        cfg["filter-interface"] = Value::String(interface.to_string());
    }
    // Best-effort: an older RouterOS may not accept every key, and a capture
    // with default settings is far better than no capture.
    if let Err(e) = ros.post("/tool/sniffer/set", &cfg).await {
        debug!(error = %e, "could not apply sniffer settings; using existing ones");
        notes.push("sniffer settings could not be applied; existing configuration used".into());
    }

    ros.post("/tool/sniffer/start", &json!({})).await?;
    tokio::time::sleep(Duration::from_secs(secs)).await;

    // Stop before reading. A running sniffer's tables move under you, and a
    // failure to stop leaves it consuming CPU indefinitely, so this is
    // attempted even if the read below fails.
    if let Err(e) = ros.post("/tool/sniffer/stop", &json!({})).await {
        warn!(error = %e, "could not stop the sniffer — it may still be running");
        notes.push("the sniffer could not be stopped; check /tool/sniffer on the device".into());
    }

    let hosts = match ros.get("/tool/sniffer/host").await {
        Ok(v) => parse_hosts(&v),
        Err(e) => {
            warn!(error = %e, "could not read the sniffer host table");
            vec![]
        }
    };
    let protocols = match ros.get("/tool/sniffer/protocol").await {
        Ok(v) => parse_protocols(&v),
        Err(_) => vec![],
    };

    Ok(Capture {
        interface: interface.to_string(),
        duration_s: secs,
        hosts,
        protocols,
        wireless_frames: 0,
        frames: vec![],
        used_wireless_sniffer: false,
        notes,
    })
}

/// Capture 802.11 frames with `/interface/wireless/sniffer`.
///
/// Falls back to the packet sniffer when the device has no legacy wireless
/// stack, rather than failing: the caller asked to see traffic, and returning
/// the traffic we *can* see with an explanation beats returning nothing.
pub async fn run_wireless_capture(
    ros: &RouterOs,
    interface: &str,
    duration: Duration,
    hop_channels: bool,
) -> Result<Capture, RouterOsError> {
    // The ax-generation `/interface/wifi` has no sniffer at all, so on those
    // boards there is nothing to drive.
    if ros.get("/interface/wireless/sniffer").await.is_err() {
        let mut cap = run_packet_capture(ros, interface, duration).await?;
        cap.notes.push(
            "this device has no wireless sniffer — the newer /interface/wifi stack provides \
             none — so IP traffic was captured instead. RF-level frames are not available here."
                .into(),
        );
        return Ok(cap);
    }

    let (secs, mut notes) = clamp(duration);

    // `sniff` requires an interface; it will not pick one itself.
    let iface = if interface.is_empty() {
        match first_wireless_interface(ros).await {
            Some(i) => i,
            None => {
                return Err(RouterOsError::Decode(
                    "this device has a wireless sniffer but no wireless interface to run it on"
                        .into(),
                ))
            }
        }
    } else {
        interface.to_string()
    };

    notes.push(format!(
        "radio {iface} was placed in monitor mode, which interrupts service for any client \
         associated to it"
    ));
    if hop_channels {
        notes.push(
            "channel hopping was enabled: this sees neighbouring networks, but leaves our own \
             channel repeatedly for the duration"
                .into(),
        );
    }

    let cfg = json!({
        "file-name": "",
        "memory-limit": "10",
        "multiple-channels": if hop_channels { "yes" } else { "no" },
        // Headers only: payload is not needed to answer an RF question and
        // fills the memory limit far faster.
        "only-headers": "yes",
    });
    if let Err(e) = ros.post("/interface/wireless/sniffer/set", &cfg).await {
        debug!(error = %e, "could not apply wireless sniffer settings");
        notes.push("wireless sniffer settings could not be applied".into());
    }

    // `sniff` is a continuous command that blocks for `duration`, so there is
    // no separate start/stop — unlike /tool/sniffer, which does need both.
    ros.post(
        "/interface/wireless/sniffer/sniff",
        &json!({ "interface": iface, "duration": secs.to_string() }),
    )
    .await?;

    let frames = match ros.get("/interface/wireless/sniffer/packet").await {
        Ok(v) => parse_frames(&v),
        Err(e) => {
            warn!(error = %e, "could not read captured frames");
            vec![]
        }
    };

    Ok(Capture {
        interface: iface,
        duration_s: secs,
        hosts: vec![],
        protocols: vec![],
        wireless_frames: frames.len() as u64,
        frames,
        used_wireless_sniffer: true,
        notes,
    })
}

async fn first_wireless_interface(ros: &RouterOs) -> Option<String> {
    let v = ros.get("/interface/wireless").await.ok()?;
    let rows = v.as_array()?;
    // Prefer one that is actually up; fall back to any, since a disabled radio
    // can still sniff and that is often exactly what a spare radio is for.
    rows.iter()
        .find(|r| s(r, "running") == "true")
        .or_else(|| rows.first())
        .map(|r| s(r, "name"))
        .filter(|n| !n.is_empty())
}

/// Parse `signal-at-rate`, which RouterOS formats as `-58@5.5Mbps`.
fn parse_signal_at_rate(v: &str) -> (i32, f64) {
    let mut parts = v.splitn(2, '@');
    let sig = parts.next().unwrap_or("").trim().parse().unwrap_or(0);
    let rate = parts
        .next()
        .map(|r| {
            let digits: String =
                r.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            digits.parse().unwrap_or(0.0)
        })
        .unwrap_or(0.0);
    (sig, rate)
}

pub fn parse_frames(v: &Value) -> Vec<WirelessFrame> {
    v.as_array()
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|r| {
            let (signal, rate) = parse_signal_at_rate(&s(r, "signal-at-rate"));
            WirelessFrame {
                src: s(r, "src"),
                dst: s(r, "dst"),
                channel: s(r, "channel"),
                signal_dbm: signal,
                rate_mbps: rate,
                crc_error: s(r, "crc-error") == "true",
                frame_type: s(r, "type"),
            }
        })
        .filter(|f| !f.src.is_empty() || !f.dst.is_empty())
        .collect()
}

fn clamp(d: Duration) -> (u64, Vec<String>) {
    let want = d.as_secs().max(1);
    if want > MAX_CAPTURE.as_secs() {
        (
            MAX_CAPTURE.as_secs(),
            vec![format!(
                "capture shortened from {}s to {}s: a sniffer left running costs the router CPU \
                 it may not have to spare",
                want,
                MAX_CAPTURE.as_secs()
            )],
        )
    } else {
        (want, vec![])
    }
}

// --- parsing --------------------------------------------------------------

/// RouterOS reports host rates as `"tx/rx"`, e.g. `"0/2736"`.
fn split_rate(s: &str) -> (u64, u64) {
    let mut it = s.split('/');
    let tx = it.next().unwrap_or("").trim().parse().unwrap_or(0);
    let rx = it.next().unwrap_or("").trim().parse().unwrap_or(0);
    (tx, rx)
}

pub fn parse_hosts(v: &Value) -> Vec<HostTraffic> {
    let mut out: Vec<HostTraffic> = v
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|r| {
            let (tx, rx) = split_rate(&s(r, "rate"));
            let (ptx, prx) = split_rate(&s(r, "peak-rate"));
            let (ttx, trx) = split_rate(&s(r, "total"));
            HostTraffic {
                address: s(r, "address"),
                tx_rate_bps: tx,
                rx_rate_bps: rx,
                peak_tx_bps: ptx,
                peak_rx_bps: prx,
                total_bytes: ttx.saturating_add(trx),
            }
        })
        .filter(|h| !h.address.is_empty())
        .collect();

    // Busiest first: the whole point is to name the top talker.
    out.sort_by(|a, b| b.busiest().cmp(&a.busiest()).then(b.total_bytes.cmp(&a.total_bytes)));
    out
}

pub fn parse_protocols(v: &Value) -> Vec<ProtocolTraffic> {
    let mut out: Vec<ProtocolTraffic> = v
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|r| ProtocolTraffic {
            // `ip-protocol` (tcp, udp, icmp) is the useful label where it
            // exists; `protocol` is the layer below it and reads "ip" for
            // nearly every row, which tells nobody anything.
            protocol: first_non_empty(r, &["ip-protocol", "protocol", "mac-protocol"]),
            bytes: n(r, "bytes"),
            packets: n(r, "packets"),
            share_pct: s(r, "share").parse().unwrap_or(0.0),
        })
        .filter(|p| !p.protocol.is_empty())
        .collect();
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    out
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(x)) => x.to_string(),
        _ => String::new(),
    }
}

fn first_non_empty(v: &Value, keys: &[&str]) -> String {
    keys.iter().map(|k| s(v, k)).find(|x| !x.is_empty()).unwrap_or_default()
}

fn n(v: &Value, k: &str) -> u64 {
    s(v, k).split(',').next().unwrap_or("").trim().parse().unwrap_or(0)
}

// --- analysis -------------------------------------------------------------

/// A host above this share of all captured traffic is worth naming.
const DOMINANT_SHARE: f64 = 0.5;
/// Broadcast traffic above this share suggests a storm rather than chatter.
const BROADCAST_SHARE: f64 = 0.3;

/// Turn a capture into findings, naming hosts rather than interfaces.
pub fn analyse(cap: &Capture) -> Vec<Finding> {
    let mut out = Vec::new();

    if cap.used_wireless_sniffer {
        return analyse_wireless(cap);
    }

    if cap.hosts.is_empty() {
        return out;
    }

    let total: u64 = cap.hosts.iter().map(|h| h.busiest()).sum();
    if total == 0 {
        return out;
    }

    // The finding interface counters cannot produce: which host.
    let top = &cap.hosts[0];
    let share = top.busiest() as f64 / total as f64;
    if share >= DOMINANT_SHARE && cap.hosts.len() > 1 {
        out.push(Finding {
            code: "capture.dominant_host",
            severity: if share >= 0.8 { Severity::Warning } else { Severity::Info },
            summary: format!(
                "{} accounted for {:.0}% of captured traffic — interface counters can show \
                 which link is busy, but only a capture names the host",
                top.address,
                share * 100.0
            ),
            evidence: cap
                .hosts
                .iter()
                .take(5)
                .map(|h| {
                    format!(
                        "{} tx {} B/s, rx {} B/s (peak {}/{})",
                        h.address, h.tx_rate_bps, h.rx_rate_bps, h.peak_tx_bps, h.peak_rx_bps
                    )
                })
                .collect(),
        });
    }

    // Broadcast and multicast destinations, which is what a storm looks like
    // from the host table.
    let bum: u64 = cap
        .hosts
        .iter()
        .filter(|h| is_broadcastish(&h.address))
        .map(|h| h.busiest())
        .sum();
    if bum > 0 {
        let bshare = bum as f64 / total as f64;
        if bshare >= BROADCAST_SHARE {
            out.push(Finding {
                code: "capture.broadcast_storm_source",
                severity: Severity::Critical,
                summary: format!(
                    "{:.0}% of captured traffic went to broadcast or multicast addresses; on \
                     wifi these are sent at the lowest basic rate and cost far more airtime \
                     than their bit rate suggests",
                    bshare * 100.0
                ),
                evidence: cap
                    .hosts
                    .iter()
                    .filter(|h| is_broadcastish(&h.address))
                    .take(5)
                    .map(|h| format!("{} at {} B/s", h.address, h.busiest()))
                    .collect(),
            });
        }
    }

    out
}

/// Share of frames failing CRC that indicates a real RF problem.
const CRC_ERROR_SHARE: f64 = 0.15;
/// 802.11 rates at or below this drag shared airtime badly.
const LOW_RATE_MBPS: f64 = 12.0;
/// Share of frames at a low rate before it is worth naming.
const LOW_RATE_SHARE: f64 = 0.4;
/// Too few data frames and the share is noise rather than a measurement.
const MIN_DATA_FRAMES: usize = 20;

/// Findings from an 802.11 capture — the RF layer a packet capture cannot see.
fn analyse_wireless(cap: &Capture) -> Vec<Finding> {
    let mut out = Vec::new();
    let n = cap.frames.len();
    if n == 0 {
        out.push(Finding {
            code: "capture.wireless_silent",
            severity: Severity::Info,
            summary: format!(
                "no 802.11 frames were captured on {} in {}s",
                cap.interface, cap.duration_s
            ),
            evidence: cap.notes.clone(),
        });
        return out;
    }

    // CRC failures are frames the radio spent airtime receiving and then threw
    // away. A packet capture never sees them at all.
    let crc = cap.frames.iter().filter(|f| f.crc_error).count();
    let crc_share = crc as f64 / n as f64;
    if crc_share >= CRC_ERROR_SHARE {
        out.push(Finding {
            code: "capture.wifi_crc_errors",
            severity: if crc_share >= 0.3 { Severity::Critical } else { Severity::Warning },
            summary: format!(
                "{:.0}% of captured frames failed CRC ({crc} of {n}) — the radio spent airtime \
                 receiving them and discarded them. Suspect interference or a signal too weak \
                 to decode.",
                crc_share * 100.0
            ),
            evidence: vec![format!("channel {}", cap.frames[0].channel)],
        });
    }

    // Low-rate *data* frames occupy the channel far longer than their size
    // suggests. Management and control frames are excluded: they are supposed
    // to be slow, and including them drowns the signal entirely.
    let data: Vec<&WirelessFrame> = cap.frames.iter().filter(|f| f.rate_is_diagnostic()).collect();
    let low: Vec<&&WirelessFrame> =
        data.iter().filter(|f| f.rate_mbps > 0.0 && f.rate_mbps <= LOW_RATE_MBPS).collect();
    let low_share =
        if data.is_empty() { 0.0 } else { low.len() as f64 / data.len() as f64 };
    if data.len() >= MIN_DATA_FRAMES && low_share >= LOW_RATE_SHARE {
        let mut by_src: std::collections::BTreeMap<&str, usize> = Default::default();
        for f in &low {
            *by_src.entry(f.src.as_str()).or_default() += 1;
        }
        let mut worst: Vec<(&&str, &usize)> = by_src.iter().collect();
        worst.sort_by(|a, b| b.1.cmp(a.1));

        out.push(Finding {
            code: "capture.wifi_low_rate_frames",
            severity: Severity::Warning,
            summary: format!(
                "{:.0}% of data frames ({} of {}) were sent at {LOW_RATE_MBPS} Mbit/s or below, \
                 which holds the channel far longer than the same data at a high rate and slows \
                 every other client",
                low_share * 100.0,
                low.len(),
                data.len()
            ),
            evidence: worst
                .iter()
                .take(5)
                .map(|(src, count)| format!("{src} sent {count} low-rate frames"))
                .collect(),
        });
    }

    // Who is on the air, by frame count rather than bytes — management and
    // control frames are small but still consume airtime.
    let mut by_src: std::collections::BTreeMap<&str, usize> = Default::default();
    for f in &cap.frames {
        if !f.src.is_empty() {
            *by_src.entry(f.src.as_str()).or_default() += 1;
        }
    }
    let mut talkers: Vec<(&&str, &usize)> = by_src.iter().collect();
    talkers.sort_by(|a, b| b.1.cmp(a.1));
    if let Some((src, count)) = talkers.first() {
        let share = **count as f64 / n as f64;
        if share >= DOMINANT_SHARE && talkers.len() > 1 {
            out.push(Finding {
                code: "capture.wifi_dominant_transmitter",
                severity: Severity::Info,
                summary: format!(
                    "{src} sent {:.0}% of the frames on this channel",
                    share * 100.0
                ),
                evidence: talkers
                    .iter()
                    .take(5)
                    .map(|(s, c)| format!("{s}: {c} frames"))
                    .collect(),
            });
        }
    }

    let mut by_type: std::collections::BTreeMap<&str, usize> = Default::default();
    for f in &cap.frames {
        if !f.frame_type.is_empty() {
            *by_type.entry(f.frame_type.as_str()).or_default() += 1;
        }
    }
    if !by_type.is_empty() {
        let mut kinds: Vec<(&&str, &usize)> = by_type.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1));
        out.push(Finding {
            code: "capture.wifi_frame_mix",
            severity: Severity::Info,
            summary: format!(
                "{n} frames on {}: {}",
                cap.interface,
                kinds
                    .iter()
                    .take(4)
                    .map(|(t, c)| format!("{c} {t}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence: kinds.iter().map(|(t, c)| format!("{t}: {c}")).collect(),
        });
    }

    // Broadcast *data* frames only, for the same reason the rate rule ignores
    // management: every beacon is addressed to the broadcast MAC by
    // definition, so counting them reports a storm on every healthy channel.
    // On a real capture 52 of 88 frames were beacons and this rule fired at
    // 61% against an idle radio.
    let bcast = data.iter().filter(|f| f.is_broadcast()).count();
    if data.len() >= MIN_DATA_FRAMES && bcast as f64 / data.len() as f64 >= BROADCAST_SHARE {
        out.push(Finding {
            code: "capture.wifi_broadcast_heavy",
            severity: Severity::Warning,
            summary: format!(
                "{:.0}% of data frames ({bcast} of {}) were broadcast, which 802.11 sends at \
                 the lowest basic rate so every client must stay awake to receive them",
                bcast as f64 / data.len() as f64 * 100.0,
                data.len()
            ),
            evidence: vec![format!("{bcast} broadcast data frames of {} total captured", n)],
        });
    }

    out
}

/// Whether an address is a broadcast or multicast destination.
fn is_broadcastish(addr: &str) -> bool {
    if addr == "255.255.255.255" || addr == "0.0.0.0" {
        return true;
    }
    // IPv4 multicast is 224.0.0.0/4; IPv6 multicast begins ff00::/8.
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        return v4.is_multicast() || v4.is_broadcast();
    }
    if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
        return v6.is_multicast();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(addr: &str, tx: u64, rx: u64) -> HostTraffic {
        HostTraffic {
            address: addr.into(),
            tx_rate_bps: tx,
            rx_rate_bps: rx,
            peak_tx_bps: tx,
            peak_rx_bps: rx,
            total_bytes: tx + rx,
        }
    }

    fn cap(hosts: Vec<HostTraffic>) -> Capture {
        Capture { duration_s: 10, hosts, ..Default::default() }
    }

    fn find(f: &[Finding], code: &str) -> Option<Finding> {
        f.iter().find(|x| x.code == code).cloned()
    }

    #[test]
    fn parses_a_real_host_table() {
        // Captured verbatim from a hAP ac³ running RouterOS 7.24.2, where the
        // rate field is "tx/rx".
        let v = json!([
            {".id":"*1","address":"162.216.185.241","rate":"0/2736","peak-rate":"0/8192","total":"0/54720"},
            {".id":"*2","address":"172.16.220.4","rate":"0/0","peak-rate":"0/0","total":"0/0"}
        ]);
        let hosts = parse_hosts(&v);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].address, "162.216.185.241");
        assert_eq!(hosts[0].rx_rate_bps, 2736, "the second field is rx");
        assert_eq!(hosts[0].tx_rate_bps, 0);
        assert_eq!(hosts[0].peak_rx_bps, 8192);
        assert_eq!(hosts[0].total_bytes, 54_720);
    }

    #[test]
    fn hosts_come_back_busiest_first() {
        // The entire point is to name the top talker, so ordering is not
        // cosmetic.
        let v = json!([
            {"address":"10.0.0.1","rate":"10/10"},
            {"address":"10.0.0.2","rate":"9000/0"},
            {"address":"10.0.0.3","rate":"0/500"}
        ]);
        let hosts = parse_hosts(&v);
        assert_eq!(hosts[0].address, "10.0.0.2");
        assert_eq!(hosts[1].address, "10.0.0.3");
    }

    #[test]
    fn malformed_rows_do_not_sink_the_capture() {
        let v = json!([
            {"address":"10.0.0.1","rate":"not-a-rate"},
            {"rate":"1/2"},
            {"address":"10.0.0.2","rate":"5"}
        ]);
        let hosts = parse_hosts(&v);
        assert_eq!(hosts.len(), 2, "the row with no address is unusable");
        // "5" with no slash is a tx figure with no rx.
        assert!(hosts.iter().any(|h| h.address == "10.0.0.2" && h.tx_rate_bps == 5));
    }

    #[test]
    fn a_dominant_host_is_named() {
        let f = analyse(&cap(vec![
            host("10.0.0.99", 900_000, 0),
            host("10.0.0.1", 1_000, 1_000),
            host("10.0.0.2", 500, 500),
        ]));
        let hit = find(&f, "capture.dominant_host").expect("should name the talker");
        assert!(hit.summary.contains("10.0.0.99"), "{}", hit.summary);
        assert_eq!(hit.severity, Severity::Warning);
    }

    #[test]
    fn evenly_shared_traffic_names_nobody() {
        let f = analyse(&cap(vec![
            host("10.0.0.1", 1000, 1000),
            host("10.0.0.2", 1000, 1000),
            host("10.0.0.3", 1000, 1000),
        ]));
        assert!(find(&f, "capture.dominant_host").is_none());
    }

    #[test]
    fn a_single_host_is_not_called_dominant() {
        // With one host it is trivially 100% and says nothing.
        let f = analyse(&cap(vec![host("10.0.0.1", 9999, 0)]));
        assert!(find(&f, "capture.dominant_host").is_none());
    }

    #[test]
    fn broadcast_heavy_traffic_is_flagged_critical() {
        let f = analyse(&cap(vec![
            host("255.255.255.255", 800_000, 0),
            host("10.0.0.1", 1_000, 1_000),
        ]));
        let hit = find(&f, "capture.broadcast_storm_source").expect("should flag the storm");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.summary.contains("airtime"), "must explain the wifi cost: {}", hit.summary);
    }

    #[test]
    fn multicast_counts_towards_the_storm_share() {
        let f = analyse(&cap(vec![
            host("224.0.0.251", 500_000, 0), // mDNS
            host("239.255.255.250", 300_000, 0), // SSDP
            host("10.0.0.1", 1_000, 0),
        ]));
        assert!(find(&f, "capture.broadcast_storm_source").is_some());
    }

    #[test]
    fn ordinary_unicast_traffic_is_not_a_storm() {
        let f = analyse(&cap(vec![host("10.0.0.1", 900_000, 0), host("10.0.0.2", 100_000, 0)]));
        assert!(find(&f, "capture.broadcast_storm_source").is_none());
    }

    #[test]
    fn broadcast_classification_covers_the_real_cases() {
        for a in ["255.255.255.255", "224.0.0.1", "239.255.255.250", "ff02::1", "0.0.0.0"] {
            assert!(is_broadcastish(a), "{a} should count as broadcast/multicast");
        }
        for a in ["10.0.0.1", "192.168.1.255", "2001:db8::1", "not-an-address"] {
            assert!(!is_broadcastish(a), "{a} should not");
        }
    }

    #[test]
    fn protocol_rows_prefer_the_informative_label() {
        // Captured verbatim: every IP row also carries protocol="ip", so
        // preferring that field labels the whole table "ip".
        let v = json!([
            {"bytes":"8453","ip-protocol":"tcp","packets":"11","protocol":"ip","share":"88.54"},
            {"bytes":"914","ip-protocol":"udp","packets":"3","protocol":"ip","share":"9.57"},
            {"bytes":"180","packets":"3","protocol":"arp","share":"1.88"}
        ]);
        let ps = parse_protocols(&v);
        assert_eq!(ps[0].protocol, "tcp");
        assert_eq!(ps[0].share_pct, 88.54);
        assert_eq!(ps[1].protocol, "udp");
        assert_eq!(ps[2].protocol, "arp", "a row with no ip-protocol keeps its own label");
    }

    #[test]
    fn an_empty_capture_is_safe() {
        assert!(analyse(&Capture::default()).is_empty());
        assert!(parse_hosts(&json!(null)).is_empty());
        assert!(parse_protocols(&json!("nonsense")).is_empty());
    }

    fn frame(src: &str, dst: &str, sig: i32, rate: f64, crc: bool) -> WirelessFrame {
        WirelessFrame {
            src: src.into(),
            dst: dst.into(),
            channel: "2412/20/gn(17dBm)".into(),
            signal_dbm: sig,
            rate_mbps: rate,
            crc_error: crc,
            frame_type: "data".into(),
        }
    }

    fn typed(mut f: WirelessFrame, t: &str) -> WirelessFrame {
        f.frame_type = t.into();
        f
    }

    fn wcap(frames: Vec<WirelessFrame>) -> Capture {
        Capture {
            interface: "wlan1".into(),
            duration_s: 5,
            wireless_frames: frames.len() as u64,
            frames,
            used_wireless_sniffer: true,
            ..Default::default()
        }
    }

    #[test]
    fn parses_a_real_sniffed_frame() {
        // Captured verbatim from a hAP ac³ on RouterOS 7.24.2.
        let v = json!([{
            "channel":"2412/20/gn(17dBm)","crc-error":"false","dst":"FF:FF:FF:FF:FF:FF",
            "interface":"wlan1","signal-at-rate":"-58@5.5Mbps","src":"B8:69:F4:CC:48:27",
            "type":"data"
        }]);
        let f = &parse_frames(&v)[0];
        assert_eq!(f.src, "B8:69:F4:CC:48:27");
        assert_eq!(f.signal_dbm, -58);
        assert_eq!(f.rate_mbps, 5.5, "the rate rides in the same field as the signal");
        assert!(!f.crc_error);
        assert!(f.is_broadcast());
    }

    #[test]
    fn signal_at_rate_parses_defensively() {
        assert_eq!(parse_signal_at_rate("-58@5.5Mbps"), (-58, 5.5));
        assert_eq!(parse_signal_at_rate("-70@130Mbps"), (-70, 130.0));
        assert_eq!(parse_signal_at_rate("-64"), (-64, 0.0));
        assert_eq!(parse_signal_at_rate(""), (0, 0.0));
    }

    #[test]
    fn crc_failures_are_flagged_because_a_packet_capture_never_sees_them() {
        let mut frames: Vec<WirelessFrame> =
            (0..6).map(|_| frame("AA:BB:CC:00:00:01", "DD:..", -70, 54.0, true)).collect();
        frames.extend((0..14).map(|_| frame("AA:BB:CC:00:00:01", "DD:..", -70, 54.0, false)));

        let hit = find(&analyse(&wcap(frames)), "capture.wifi_crc_errors").expect("should flag");
        assert!(hit.summary.contains("30%"), "{}", hit.summary);
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn a_clean_channel_raises_no_crc_finding() {
        let frames: Vec<WirelessFrame> =
            (0..20).map(|_| frame("AA:BB:CC:00:00:01", "DD:..", -50, 130.0, false)).collect();
        assert!(find(&analyse(&wcap(frames)), "capture.wifi_crc_errors").is_none());
    }

    #[test]
    fn low_rate_data_frames_name_the_transmitters_responsible() {
        let mut frames: Vec<WirelessFrame> =
            (0..25).map(|_| frame("AA:BB:CC:00:00:99", "DD:..", -80, 5.5, false)).collect();
        frames.extend((0..10).map(|_| frame("AA:BB:CC:00:00:01", "DD:..", -45, 130.0, false)));

        let hit = find(&analyse(&wcap(frames)), "capture.wifi_low_rate_frames").expect("flag");
        assert!(hit.summary.contains("data frames"), "{}", hit.summary);
        assert!(hit.evidence[0].contains("AA:BB:CC:00:00:99"), "{:?}", hit.evidence);
    }

    #[test]
    fn beacons_are_not_counted_as_slow_clients() {
        // The real distribution from a hAP ac3: 51 beacons and 8 data frames,
        // every beacon at 5.5 Mbit/s because that is what beacons do. Counting
        // them reported "92% of frames low rate" on a healthy channel.
        let mut frames: Vec<WirelessFrame> = (0..51)
            .map(|_| typed(frame("B8:69:F4:CC:48:27", "FF:FF:FF:FF:FF:FF", -63, 5.5, false), "beacon"))
            .collect();
        frames.extend((0..8).map(|_| typed(frame("D4:01:C3:C8:EF:D2", "AA:..", -75, 5.5, false), "probe-resp")));
        frames.extend((0..17).map(|_| typed(frame("24:A4:3C:70:27:F8", "AA:..", -85, 12.0, false), "ack")));

        let f = analyse(&wcap(frames));
        assert!(
            find(&f, "capture.wifi_low_rate_frames").is_none(),
            "management and control frames are low-rate by design: {f:?}"
        );
    }

    #[test]
    fn too_few_data_frames_is_not_a_measurement() {
        // Three slow data frames in a capture is noise, not a finding.
        let mut frames: Vec<WirelessFrame> =
            (0..3).map(|_| frame("AA:BB:CC:00:00:99", "DD:..", -80, 5.5, false)).collect();
        frames.extend((0..40).map(|_| typed(frame("BB:..", "FF:FF:FF:FF:FF:FF", -60, 5.5, false), "beacon")));
        assert!(find(&analyse(&wcap(frames)), "capture.wifi_low_rate_frames").is_none());
    }

    #[test]
    fn the_frame_mix_is_reported_because_it_is_informative_on_its_own() {
        let mut frames: Vec<WirelessFrame> =
            (0..10).map(|_| typed(frame("AA:..", "FF:FF:FF:FF:FF:FF", -60, 5.5, false), "beacon")).collect();
        frames.extend((0..4).map(|_| typed(frame("BB:..", "AA:..", -60, 54.0, false), "probe-req")));
        let hit = find(&analyse(&wcap(frames)), "capture.wifi_frame_mix").expect("should report");
        assert!(hit.summary.contains("beacon"), "{}", hit.summary);
    }

    #[test]
    fn a_broadcast_heavy_channel_is_flagged_on_data_frames() {
        let frames: Vec<WirelessFrame> = (0..25)
            .map(|_| frame("AA:BB:CC:00:00:01", "FF:FF:FF:FF:FF:FF", -50, 130.0, false))
            .collect();
        let hit = find(&analyse(&wcap(frames)), "capture.wifi_broadcast_heavy").expect("flag");
        assert!(hit.summary.contains("data frames"), "{}", hit.summary);
    }

    #[test]
    fn beacons_do_not_make_an_idle_channel_look_broadcast_heavy() {
        // Every beacon is addressed to the broadcast MAC by definition. The
        // real capture was 52 beacons of 88 frames and this fired at 61% on a
        // radio carrying no user traffic at all.
        let mut frames: Vec<WirelessFrame> = (0..52)
            .map(|_| typed(frame("AA:..", "FF:FF:FF:FF:FF:FF", -60, 5.5, false), "beacon"))
            .collect();
        frames.extend((0..22).map(|_| typed(frame("BB:..", "CC:..", -60, 24.0, false), "ack")));
        frames.extend((0..4).map(|_| frame("CC:..", "DD:..", -60, 54.0, false)));

        let f = analyse(&wcap(frames));
        assert!(
            find(&f, "capture.wifi_broadcast_heavy").is_none(),
            "beacons are broadcast by design: {f:?}"
        );
    }

    #[test]
    fn a_silent_channel_says_so_rather_than_nothing() {
        let hit = find(&analyse(&wcap(vec![])), "capture.wireless_silent").expect("should report");
        assert!(hit.summary.contains("wlan1"));
    }

    #[test]
    fn an_overlong_capture_is_shortened_and_explained() {
        // A sniffer left running is a denial of service against the router's
        // own control plane.
        let (secs, notes) = clamp(Duration::from_secs(600));
        assert_eq!(secs, MAX_CAPTURE.as_secs());
        assert!(notes[0].contains("shortened"), "{notes:?}");

        let (secs, notes) = clamp(Duration::from_secs(10));
        assert_eq!(secs, 10);
        assert!(notes.is_empty());
    }

    #[test]
    fn rate_pairs_parse_defensively() {
        assert_eq!(split_rate("0/2736"), (0, 2736));
        assert_eq!(split_rate("100/200"), (100, 200));
        assert_eq!(split_rate("42"), (42, 0));
        assert_eq!(split_rate(""), (0, 0));
        assert_eq!(split_rate("junk/more"), (0, 0));
    }
}
