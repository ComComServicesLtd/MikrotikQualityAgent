//! Turning a router's local state into explanations.
//!
//! The point of discovery is not an inventory. An operator asking "why is this
//! site slow" is not helped by a list of ARP entries; they need the one or two
//! facts that explain the complaint. So the collectors gather raw state and
//! this module reduces it to [`Finding`]s, each with a severity and enough
//! evidence to act on.
//!
//! The analysis is pure, so every rule can be tested against constructed state
//! rather than by waiting for a real network to misbehave.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, not currently hurting anyone.
    Info,
    /// Degrading some users now, or will soon.
    Warning,
    /// Actively degrading the whole site.
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable machine-readable identifier, e.g. `wifi.slow_client_airtime`.
    pub code: &'static str,
    pub severity: Severity,
    /// One line an operator can act on.
    pub summary: String,
    /// What was observed, so the conclusion can be checked rather than trusted.
    pub evidence: Vec<String>,
}

// --- inputs ---------------------------------------------------------------
//
// Deliberately narrow structs rather than raw JSON: the two RouterOS wireless
// stacks report the same facts under different field names, and normalising at
// the collector boundary keeps that mess out of the analysis.

/// One associated wireless client.
#[derive(Debug, Clone, PartialEq)]
pub struct WifiClient {
    pub mac: String,
    pub interface: String,
    pub ssid: String,
    /// dBm as reported by the AP. Closer to zero is stronger.
    pub signal_dbm: i32,
    /// Negotiated rates, bits per second.
    pub tx_rate_bps: u64,
    pub rx_rate_bps: u64,
    pub band: String,
    pub uptime_s: u64,
    /// Seconds since this client last sent or received a frame.
    pub last_activity_s: u64,
}

impl WifiClient {
    fn is_2ghz(&self) -> bool {
        self.band.contains("2ghz") || self.band.starts_with('2')
    }

    /// Whether this client's negotiated rate means anything right now.
    ///
    /// An idle 802.11 client's tx-rate reflects whatever it last transmitted,
    /// which for a device that has been quiet is the lowest basic rate. Judging
    /// an idle client by that figure reports a problem on every healthy network --
    /// so rate-based rules only consider clients that are actually passing
    /// traffic.
    fn rate_is_meaningful(&self) -> bool {
        self.last_activity_s <= IDLE_AFTER_S
    }
}

/// A radio and the channel it is on.
#[derive(Debug, Clone, PartialEq)]
pub struct Radio {
    pub name: String,
    pub band: String,
    /// Centre frequency in MHz, when known.
    pub frequency_mhz: Option<u32>,
    pub width: String,
    pub country: String,
}

/// An AP heard during a scan — ours or a neighbour's.
#[derive(Debug, Clone, PartialEq)]
pub struct NeighbourAp {
    pub ssid: String,
    pub frequency_mhz: u32,
    pub signal_dbm: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArpEntry {
    pub address: String,
    pub mac: String,
    pub interface: String,
    /// True when the entry came from DHCP rather than being learned or static.
    pub from_dhcp: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DhcpLease {
    pub address: String,
    pub mac: String,
    pub hostname: String,
    pub active: bool,
}

/// Interface counters, used to spot storms.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_packets_per_s: u64,
    pub tx_packets_per_s: u64,
    /// Broadcast and multicast frames per second received.
    pub rx_broadcast_per_s: u64,
    pub rx_multicast_per_s: u64,
    pub running: bool,
}

/// Everything a discovery run gathered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub clients: Vec<WifiClient>,
    pub radios: Vec<Radio>,
    pub neighbour_aps: Vec<NeighbourAp>,
    pub arp: Vec<ArpEntry>,
    pub leases: Vec<DhcpLease>,
    pub interfaces: Vec<InterfaceStats>,
    /// Size of the DHCP pool, when it could be determined.
    pub dhcp_pool_size: Option<usize>,
}

// --- thresholds -----------------------------------------------------------

/// Below this, a client is at the edge of usable coverage.
const WEAK_SIGNAL_DBM: i32 = -75;
/// Signal strong enough that a low rate cannot be explained by distance.
const STRONG_SIGNAL_DBM: i32 = -60;
/// Rates at or below this drag shared airtime badly.
const SLOW_RATE_BPS: u64 = 24_000_000;
/// Share of a radio's clients that must be slow before the radio is a problem.
const SLOW_CLIENT_SHARE: f64 = 0.25;
/// Broadcast frames per second that indicate a storm rather than normal chatter.
const BROADCAST_STORM_PPS: u64 = 500;
/// Co-channel neighbours this strong genuinely contend with us.
const SIGNIFICANT_AP_DBM: i32 = -82;
/// Past this, a client is idle and its negotiated rate is stale.
const IDLE_AFTER_S: u64 = 30;
/// Airtime contention needs at least this many clients to be contention at all.
const MIN_CLIENTS_FOR_CONTENTION: usize = 2;

/// Run every rule over a snapshot, most severe first.
pub fn analyse(s: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();

    out.extend(slow_client_airtime(s));
    out.extend(weak_signal_clients(s));
    out.extend(rate_signal_mismatch(s));
    out.extend(band_steering_opportunity(s));
    out.extend(co_channel_contention(s));
    out.extend(broadcast_storm(s));
    out.extend(duplicate_addresses(s));
    out.extend(unleased_devices(s));
    out.extend(dhcp_pool_pressure(s));

    // Most severe first, so the thing ruining the site is the first thing read.
    out.sort_by(|a, b| b.severity.cmp(&a.severity));
    out
}

/// The classic cause of "everyone's wifi is slow".
///
/// 802.11 shares airtime, not bandwidth. A client transmitting at 6 Mbit/s
/// occupies the channel roughly fifty times longer than one at 300 Mbit/s to
/// move the same bytes, and every other client waits. One badly-connected
/// device can therefore flatten a whole SSID while looking, on its own, merely
/// slow. This is the finding most likely to explain a site-wide complaint, so
/// it runs first and quantifies the cost rather than just naming the device.
fn slow_client_airtime(s: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut by_iface: std::collections::BTreeMap<&str, Vec<&WifiClient>> = Default::default();
    for c in &s.clients {
        by_iface.entry(c.interface.as_str()).or_default().push(c);
    }

    for (iface, all) in by_iface {
        // Only clients actually passing traffic contend for airtime, and only
        // their rates are current. An idle client neither harms anyone nor
        // reports a rate worth judging.
        let clients: Vec<&&WifiClient> =
            all.iter().filter(|c| c.rate_is_meaningful()).collect();

        // With a single client there is nobody to slow down. That is a
        // per-client problem, covered by the weak-signal and rate-mismatch
        // rules, not contention.
        if clients.len() < MIN_CLIENTS_FOR_CONTENTION {
            continue;
        }

        let slow: Vec<&&&WifiClient> =
            clients.iter().filter(|c| c.tx_rate_bps <= SLOW_RATE_BPS).collect();
        if slow.is_empty() {
            continue;
        }

        let share = slow.len() as f64 / clients.len() as f64;
        let fastest = clients.iter().map(|c| c.tx_rate_bps).max().unwrap_or(0);
        let slowest = slow.iter().map(|c| c.tx_rate_bps).min().unwrap_or(0);

        // How much longer the slowest client holds the channel than the
        // fastest, for the same amount of data.
        let airtime_ratio =
            if slowest > 0 { fastest as f64 / slowest as f64 } else { f64::INFINITY };

        let severity = if share >= SLOW_CLIENT_SHARE || airtime_ratio >= 20.0 {
            Severity::Critical
        } else {
            Severity::Warning
        };

        let mut evidence: Vec<String> = slow
            .iter()
            .map(|c| {
                format!(
                    "{} on {} at {} Mbit/s, signal {} dBm",
                    c.mac,
                    c.ssid,
                    c.tx_rate_bps / 1_000_000,
                    c.signal_dbm
                )
            })
            .collect();
        evidence.push(format!(
            "fastest client on this radio negotiates {} Mbit/s",
            fastest / 1_000_000
        ));
        if airtime_ratio.is_finite() {
            evidence.push(format!(
                "slowest client consumes roughly {:.0}x the airtime of the fastest for the same data",
                airtime_ratio
            ));
        }

        out.push(Finding {
            code: "wifi.slow_client_airtime",
            severity,
            summary: format!(
                "{} of {} active clients on {} are at or below {} Mbit/s, which slows every \
                 other client on that radio because 802.11 shares airtime rather than bandwidth",
                slow.len(),
                clients.len(),
                iface,
                SLOW_RATE_BPS / 1_000_000
            ),
            evidence,
        });
    }
    out
}

/// Clients at the edge of coverage. Distinct from the airtime finding: these
/// are slow *because* they are far away, which is a coverage problem rather
/// than a client problem.
fn weak_signal_clients(s: &Snapshot) -> Vec<Finding> {
    let weak: Vec<&WifiClient> =
        s.clients.iter().filter(|c| c.signal_dbm < WEAK_SIGNAL_DBM).collect();
    if weak.is_empty() {
        return vec![];
    }
    vec![Finding {
        code: "wifi.weak_signal",
        severity: Severity::Warning,
        summary: format!(
            "{} client(s) are below {} dBm and are at the edge of usable coverage",
            weak.len(),
            WEAK_SIGNAL_DBM
        ),
        evidence: weak
            .iter()
            .map(|c| format!("{} at {} dBm on {}", c.mac, c.signal_dbm, c.interface))
            .collect(),
    }]
}

/// A strong signal with a low rate cannot be explained by distance, so
/// something else is wrong: interference, a legacy client, or a device that has
/// given up on rate adaptation.
fn rate_signal_mismatch(s: &Snapshot) -> Vec<Finding> {
    let odd: Vec<&WifiClient> = s
        .clients
        .iter()
        .filter(|c| {
            c.rate_is_meaningful() && c.signal_dbm >= STRONG_SIGNAL_DBM
                && c.tx_rate_bps <= SLOW_RATE_BPS
        })
        .collect();
    if odd.is_empty() {
        return vec![];
    }
    vec![Finding {
        code: "wifi.rate_signal_mismatch",
        severity: Severity::Warning,
        summary: format!(
            "{} client(s) have a strong signal but a low negotiated rate, which distance \
             cannot explain — suspect interference, a legacy device, or a stuck rate",
            odd.len()
        ),
        evidence: odd
            .iter()
            .map(|c| {
                format!(
                    "{} at {} dBm but only {} Mbit/s ({})",
                    c.mac,
                    c.signal_dbm,
                    c.tx_rate_bps / 1_000_000,
                    c.band
                )
            })
            .collect(),
    }]
}

/// Clients sitting on 2.4 GHz with a strong signal would usually do better on
/// 5 GHz, and would stop consuming the more congested band's airtime.
fn band_steering_opportunity(s: &Snapshot) -> Vec<Finding> {
    let has_5ghz = s.radios.iter().any(|r| r.band.contains("5ghz"));
    if !has_5ghz {
        return vec![];
    }
    let candidates: Vec<&WifiClient> = s
        .clients
        .iter()
        .filter(|c| c.is_2ghz() && c.signal_dbm >= STRONG_SIGNAL_DBM)
        .collect();
    if candidates.is_empty() {
        return vec![];
    }
    vec![Finding {
        code: "wifi.band_steering_opportunity",
        severity: Severity::Info,
        summary: format!(
            "{} client(s) with a strong signal are on 2.4 GHz while 5 GHz is available",
            candidates.len()
        ),
        evidence: candidates
            .iter()
            .map(|c| format!("{} at {} dBm on {}", c.mac, c.signal_dbm, c.ssid))
            .collect(),
    }]
}

/// Other APs sharing our channel. Co-channel neighbours do not merely add
/// noise: they take turns with us, so each one directly reduces the airtime
/// available to our clients.
fn co_channel_contention(s: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in &s.radios {
        let Some(freq) = r.frequency_mhz else { continue };
        let contenders: Vec<&NeighbourAp> = s
            .neighbour_aps
            .iter()
            .filter(|n| n.frequency_mhz == freq && n.signal_dbm >= SIGNIFICANT_AP_DBM)
            .collect();
        if contenders.len() < 2 {
            continue;
        }
        out.push(Finding {
            code: "wifi.co_channel_contention",
            severity: if contenders.len() >= 4 { Severity::Critical } else { Severity::Warning },
            summary: format!(
                "{} other access points share {}'s channel ({} MHz); they take turns with us, \
                 so each one directly reduces the airtime our clients can use",
                contenders.len(),
                r.name,
                freq
            ),
            evidence: contenders
                .iter()
                .map(|n| format!("{} at {} dBm", if n.ssid.is_empty() { "<hidden>" } else { &n.ssid }, n.signal_dbm))
                .collect(),
        });
    }
    out
}

/// Broadcast and multicast storms. On wifi these are especially damaging
/// because broadcast frames are sent at the lowest basic rate to reach every
/// client, so a storm consumes far more airtime than its bit rate suggests.
fn broadcast_storm(s: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    for i in &s.interfaces {
        if !i.running {
            continue;
        }
        let bum = i.rx_broadcast_per_s + i.rx_multicast_per_s;
        if bum < BROADCAST_STORM_PPS {
            continue;
        }
        let share = if i.rx_packets_per_s > 0 {
            bum as f64 / i.rx_packets_per_s as f64 * 100.0
        } else {
            100.0
        };
        out.push(Finding {
            code: "network.broadcast_storm",
            severity: Severity::Critical,
            summary: format!(
                "{} is receiving {} broadcast/multicast frames per second ({:.0}% of its traffic), \
                 which on wifi is sent at the lowest basic rate and consumes disproportionate airtime",
                i.name, bum, share
            ),
            evidence: vec![
                format!("broadcast {}/s, multicast {}/s", i.rx_broadcast_per_s, i.rx_multicast_per_s),
                format!("total rx {} packets/s", i.rx_packets_per_s),
            ],
        });
    }
    out
}

/// Two MACs claiming one address, which breaks connectivity intermittently and
/// is almost impossible to diagnose from the client side.
fn duplicate_addresses(s: &Snapshot) -> Vec<Finding> {
    let mut by_addr: std::collections::BTreeMap<&str, Vec<&ArpEntry>> = Default::default();
    for e in s.arp.iter().filter(|e| e.complete) {
        by_addr.entry(e.address.as_str()).or_default().push(e);
    }

    let mut out = Vec::new();
    for (addr, entries) in by_addr {
        let macs: std::collections::BTreeSet<&str> =
            entries.iter().map(|e| e.mac.as_str()).collect();
        if macs.len() > 1 {
            out.push(Finding {
                code: "network.duplicate_address",
                severity: Severity::Critical,
                summary: format!(
                    "{addr} is claimed by {} different MAC addresses, which causes intermittent \
                     connectivity that is very hard to diagnose from the client side",
                    macs.len()
                ),
                evidence: entries
                    .iter()
                    .map(|e| format!("{} via {} on {}", e.address, e.mac, e.interface))
                    .collect(),
            });
        }
    }
    out
}

/// Devices present on the network with no DHCP lease: statics, rogues, or
/// something that has outlived its lease record.
fn unleased_devices(s: &Snapshot) -> Vec<Finding> {
    if s.leases.is_empty() {
        // With no lease data at all this rule would flag the entire network.
        return vec![];
    }
    let leased: std::collections::BTreeSet<String> =
        s.leases.iter().map(|l| l.mac.to_ascii_uppercase()).collect();

    let strays: Vec<&ArpEntry> = s
        .arp
        .iter()
        .filter(|e| e.complete && !e.from_dhcp && !leased.contains(&e.mac.to_ascii_uppercase()))
        .collect();
    if strays.is_empty() {
        return vec![];
    }
    vec![Finding {
        code: "network.unleased_device",
        severity: Severity::Info,
        summary: format!(
            "{} device(s) are active but hold no DHCP lease — statically addressed, or not \
             managed by this router",
            strays.len()
        ),
        evidence: strays
            .iter()
            .map(|e| format!("{} ({}) on {}", e.address, e.mac, e.interface))
            .collect(),
    }]
}

/// A pool close to exhaustion hands out no more addresses, which presents to
/// users as "the wifi connects but there's no internet".
fn dhcp_pool_pressure(s: &Snapshot) -> Vec<Finding> {
    let Some(size) = s.dhcp_pool_size else { return vec![] };
    if size == 0 {
        return vec![];
    }
    let active = s.leases.iter().filter(|l| l.active).count();
    let used = active as f64 / size as f64;
    if used < 0.85 {
        return vec![];
    }
    vec![Finding {
        code: "network.dhcp_pool_pressure",
        severity: if used >= 0.95 { Severity::Critical } else { Severity::Warning },
        summary: format!(
            "DHCP pool is {:.0}% used ({} of {}); once it is exhausted new devices associate \
             but get no address, which users report as \"connected, no internet\"",
            used * 100.0,
            active,
            size
        ),
        evidence: vec![format!("{active} active leases in a pool of {size}")],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(mac: &str, signal: i32, tx_mbps: u64) -> WifiClient {
        WifiClient {
            mac: mac.into(),
            interface: "wifi1".into(),
            ssid: "Site".into(),
            signal_dbm: signal,
            tx_rate_bps: tx_mbps * 1_000_000,
            rx_rate_bps: tx_mbps * 1_000_000,
            band: "5ghz-ac".into(),
            uptime_s: 600,
            last_activity_s: 1,
        }
    }

    fn idle(mut c: WifiClient) -> WifiClient {
        c.last_activity_s = 600;
        c
    }

    fn codes(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.code).collect()
    }

    /// Returns an owned copy so callers can write `find(&analyse(&s), ..)`
    /// without borrowing from a temporary.
    fn find(f: &[Finding], code: &str) -> Option<Finding> {
        f.iter().find(|x| x.code == code).cloned()
    }

    #[test]
    fn a_healthy_snapshot_produces_no_findings() {
        let s = Snapshot {
            clients: vec![client("aa", -45, 300), client("bb", -50, 400)],
            radios: vec![Radio {
                name: "wifi1".into(),
                band: "5ghz-ax".into(),
                frequency_mhz: Some(5180),
                width: "80mhz".into(),
                country: "Canada".into(),
            }],
            ..Default::default()
        };
        assert!(analyse(&s).is_empty(), "got {:?}", analyse(&s));
    }

    #[test]
    fn one_slow_client_is_flagged_as_hurting_the_whole_radio() {
        // The headline case: a single 6 Mbit/s device flattening an SSID.
        let s = Snapshot {
            clients: vec![client("slow", -70, 6), client("a", -45, 300), client("b", -50, 300)],
            ..Default::default()
        };
        let f = analyse(&s);
        let hit = find(&f, "wifi.slow_client_airtime").expect("should flag airtime");
        assert_eq!(hit.severity, Severity::Critical, "50x airtime cost is critical");
        assert!(
            hit.summary.contains("shares airtime"),
            "the explanation is the useful part: {}",
            hit.summary
        );
        assert!(hit.evidence.iter().any(|e| e.contains("50x")), "{:?}", hit.evidence);
    }

    #[test]
    fn a_uniformly_fast_radio_is_not_flagged() {
        let s = Snapshot {
            clients: vec![client("a", -45, 300), client("b", -50, 400)],
            ..Default::default()
        };
        assert!(find(&analyse(&s), "wifi.slow_client_airtime").is_none());
    }

    #[test]
    fn airtime_findings_are_per_radio() {
        // wifi1 is healthy; wifi2 has a slow client contending with a fast one.
        // Only wifi2 should be named, and contention is judged per radio rather
        // than across the whole device.
        let on = |c: WifiClient, iface: &str| WifiClient { interface: iface.into(), ..c };
        let s = Snapshot {
            clients: vec![
                on(client("a", -45, 300), "wifi1"),
                on(client("b", -46, 300), "wifi1"),
                on(client("slow", -70, 6), "wifi2"),
                on(client("c", -45, 300), "wifi2"),
            ],
            ..Default::default()
        };
        let f = analyse(&s);
        let hits: Vec<&Finding> =
            f.iter().filter(|x| x.code == "wifi.slow_client_airtime").collect();
        assert_eq!(hits.len(), 1, "only the affected radio should be flagged");
        assert!(hits[0].summary.contains("wifi2"), "should name it: {}", hits[0].summary);
    }

    #[test]
    fn strong_signal_with_a_low_rate_is_called_out_separately() {
        // The anomaly seen on the real sandbox router: -17 dBm at 6 Mbit/s.
        // Distance cannot explain it, so it needs a different diagnosis from a
        // weak-signal client.
        let s = Snapshot { clients: vec![client("odd", -17, 6)], ..Default::default() };
        let f = analyse(&s);
        let hit = find(&f, "wifi.rate_signal_mismatch").expect("should flag the mismatch");
        assert!(hit.evidence[0].contains("-17"), "{:?}", hit.evidence);
        assert!(
            find(&f, "wifi.weak_signal").is_none(),
            "a -17 dBm client is not a coverage problem"
        );
    }

    #[test]
    fn a_distant_client_is_a_coverage_problem_not_a_mismatch() {
        let s = Snapshot { clients: vec![client("far", -85, 6)], ..Default::default() };
        let f = analyse(&s);
        assert!(find(&f, "wifi.weak_signal").is_some());
        assert!(
            find(&f, "wifi.rate_signal_mismatch").is_none(),
            "distance explains this rate, so it is not an anomaly"
        );
    }

    #[test]
    fn band_steering_is_only_suggested_when_5ghz_exists() {
        let mut c = client("dualband", -50, 100);
        c.band = "2ghz-n".into();

        let without = Snapshot { clients: vec![c.clone()], ..Default::default() };
        assert!(find(&analyse(&without), "wifi.band_steering_opportunity").is_none());

        let with = Snapshot {
            clients: vec![c],
            radios: vec![Radio {
                name: "wifi1".into(),
                band: "5ghz-ax".into(),
                frequency_mhz: Some(5180),
                width: "80mhz".into(),
                country: "Canada".into(),
            }],
            ..Default::default()
        };
        assert!(find(&analyse(&with), "wifi.band_steering_opportunity").is_some());
    }

    #[test]
    fn co_channel_neighbours_are_counted_only_on_our_own_channel() {
        let radio = Radio {
            name: "wifi1".into(),
            band: "5ghz-ax".into(),
            frequency_mhz: Some(5180),
            width: "80mhz".into(),
            country: "Canada".into(),
        };
        let s = Snapshot {
            radios: vec![radio],
            neighbour_aps: vec![
                NeighbourAp { ssid: "NeighbourA".into(), frequency_mhz: 5180, signal_dbm: -60 },
                NeighbourAp { ssid: "NeighbourB".into(), frequency_mhz: 5180, signal_dbm: -70 },
                // Different channel: not contending.
                NeighbourAp { ssid: "Elsewhere".into(), frequency_mhz: 5745, signal_dbm: -50 },
                // Same channel but too weak to matter.
                NeighbourAp { ssid: "Distant".into(), frequency_mhz: 5180, signal_dbm: -95 },
            ],
            ..Default::default()
        };
        let hit = find(&analyse(&s), "wifi.co_channel_contention").expect("should flag");
        assert!(hit.summary.contains('2'), "only two genuine contenders: {}", hit.summary);
        assert_eq!(hit.evidence.len(), 2);
    }

    #[test]
    fn a_crowded_channel_is_critical() {
        let s = Snapshot {
            radios: vec![Radio {
                name: "wifi2".into(),
                band: "2ghz".into(),
                frequency_mhz: Some(2412),
                width: "20mhz".into(),
                country: "Canada".into(),
            }],
            neighbour_aps: (0..5)
                .map(|i| NeighbourAp {
                    ssid: format!("AP{i}"),
                    frequency_mhz: 2412,
                    signal_dbm: -55,
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            find(&analyse(&s), "wifi.co_channel_contention").unwrap().severity,
            Severity::Critical
        );
    }

    #[test]
    fn broadcast_storms_are_critical_and_explain_the_wifi_impact() {
        let s = Snapshot {
            interfaces: vec![InterfaceStats {
                name: "bridge".into(),
                rx_packets_per_s: 2_000,
                tx_packets_per_s: 100,
                rx_broadcast_per_s: 1_500,
                rx_multicast_per_s: 200,
                running: true,
            }],
            ..Default::default()
        };
        let hit = find(&analyse(&s), "network.broadcast_storm").expect("should flag");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.summary.contains("airtime"), "must explain the wifi cost: {}", hit.summary);
    }

    #[test]
    fn normal_broadcast_chatter_is_not_a_storm() {
        let s = Snapshot {
            interfaces: vec![InterfaceStats {
                name: "bridge".into(),
                rx_packets_per_s: 900,
                tx_packets_per_s: 800,
                rx_broadcast_per_s: 12,
                rx_multicast_per_s: 30,
                running: true,
            }],
            ..Default::default()
        };
        assert!(find(&analyse(&s), "network.broadcast_storm").is_none());
    }

    #[test]
    fn a_down_interface_is_not_inspected() {
        let s = Snapshot {
            interfaces: vec![InterfaceStats {
                name: "ether5".into(),
                rx_packets_per_s: 5_000,
                tx_packets_per_s: 0,
                rx_broadcast_per_s: 5_000,
                rx_multicast_per_s: 0,
                running: false,
            }],
            ..Default::default()
        };
        assert!(find(&analyse(&s), "network.broadcast_storm").is_none());
    }

    #[test]
    fn two_macs_on_one_address_is_critical() {
        let s = Snapshot {
            arp: vec![
                ArpEntry {
                    address: "192.168.5.10".into(),
                    mac: "AA:BB:CC:00:00:01".into(),
                    interface: "bridge".into(),
                    from_dhcp: false,
                    complete: true,
                },
                ArpEntry {
                    address: "192.168.5.10".into(),
                    mac: "AA:BB:CC:00:00:02".into(),
                    interface: "bridge".into(),
                    from_dhcp: false,
                    complete: true,
                },
            ],
            leases: vec![DhcpLease {
                address: "192.168.5.99".into(),
                mac: "AA:BB:CC:00:00:01".into(),
                hostname: "x".into(),
                active: true,
            }],
            ..Default::default()
        };
        let hit = find(&analyse(&s), "network.duplicate_address").expect("should flag");
        assert_eq!(hit.severity, Severity::Critical);
        assert_eq!(analyse(&s)[0].code, "network.duplicate_address", "critical sorts first");
    }

    #[test]
    fn incomplete_arp_entries_do_not_fake_a_duplicate() {
        // An incomplete entry has no resolved MAC and must not be compared.
        let s = Snapshot {
            arp: vec![
                ArpEntry {
                    address: "192.168.5.10".into(),
                    mac: "AA:BB:CC:00:00:01".into(),
                    interface: "bridge".into(),
                    from_dhcp: true,
                    complete: true,
                },
                ArpEntry {
                    address: "192.168.5.10".into(),
                    mac: String::new(),
                    interface: "bridge".into(),
                    from_dhcp: false,
                    complete: false,
                },
            ],
            ..Default::default()
        };
        assert!(find(&analyse(&s), "network.duplicate_address").is_none());
    }

    #[test]
    fn unleased_devices_are_reported_when_lease_data_exists() {
        let s = Snapshot {
            arp: vec![
                ArpEntry {
                    address: "192.168.5.20".into(),
                    mac: "DE:AD:BE:EF:00:01".into(),
                    interface: "bridge".into(),
                    from_dhcp: false,
                    complete: true,
                },
                ArpEntry {
                    address: "192.168.5.21".into(),
                    mac: "AA:BB:CC:00:00:01".into(),
                    interface: "bridge".into(),
                    from_dhcp: true,
                    complete: true,
                },
            ],
            leases: vec![DhcpLease {
                address: "192.168.5.21".into(),
                mac: "aa:bb:cc:00:00:01".into(), // lowercase: matching must be case-insensitive
                hostname: "laptop".into(),
                active: true,
            }],
            ..Default::default()
        };
        let hit = find(&analyse(&s), "network.unleased_device").expect("should flag the stray");
        assert_eq!(hit.evidence.len(), 1);
        assert!(hit.evidence[0].contains("192.168.5.20"));
    }

    #[test]
    fn without_lease_data_no_device_is_called_unleased() {
        // Otherwise a router that simply is not the DHCP server would report
        // every device on the network as a rogue.
        let s = Snapshot {
            arp: vec![ArpEntry {
                address: "192.168.5.20".into(),
                mac: "DE:AD:BE:EF:00:01".into(),
                interface: "bridge".into(),
                from_dhcp: false,
                complete: true,
            }],
            ..Default::default()
        };
        assert!(find(&analyse(&s), "network.unleased_device").is_none());
    }

    #[test]
    fn dhcp_pool_pressure_escalates_as_it_fills() {
        let lease = |i: usize| DhcpLease {
            address: format!("192.168.5.{}", 10 + i),
            mac: format!("AA:BB:CC:00:00:{i:02X}"),
            hostname: format!("d{i}"),
            active: true,
        };

        let comfortable = Snapshot {
            leases: (0..50).map(lease).collect(),
            dhcp_pool_size: Some(100),
            ..Default::default()
        };
        assert!(find(&analyse(&comfortable), "network.dhcp_pool_pressure").is_none());

        let tight = Snapshot {
            leases: (0..88).map(lease).collect(),
            dhcp_pool_size: Some(100),
            ..Default::default()
        };
        assert_eq!(
            find(&analyse(&tight), "network.dhcp_pool_pressure").unwrap().severity,
            Severity::Warning
        );

        let critical = Snapshot {
            leases: (0..97).map(lease).collect(),
            dhcp_pool_size: Some(100),
            ..Default::default()
        };
        let hit = find(&analyse(&critical), "network.dhcp_pool_pressure").unwrap();
        assert_eq!(hit.severity, Severity::Critical);
        assert!(
            hit.summary.contains("connected, no internet"),
            "should name the user-visible symptom: {}",
            hit.summary
        );
    }

    #[test]
    fn inactive_leases_do_not_count_towards_pool_pressure() {
        let s = Snapshot {
            leases: (0..95)
                .map(|i| DhcpLease {
                    address: format!("192.168.5.{i}"),
                    mac: format!("AA:BB:CC:00:00:{i:02X}"),
                    hostname: String::new(),
                    active: false,
                })
                .collect(),
            dhcp_pool_size: Some(100),
            ..Default::default()
        };
        assert!(find(&analyse(&s), "network.dhcp_pool_pressure").is_none());
    }

    #[test]
    fn findings_are_ordered_most_severe_first() {
        // An operator reads the top of the list; the thing ruining the site
        // must be there.
        let s = Snapshot {
            clients: vec![client("slow", -70, 6), client("a", -45, 300)],
            interfaces: vec![InterfaceStats {
                name: "bridge".into(),
                rx_packets_per_s: 3_000,
                tx_packets_per_s: 100,
                rx_broadcast_per_s: 2_500,
                rx_multicast_per_s: 100,
                running: true,
            }],
            arp: vec![ArpEntry {
                address: "192.168.5.7".into(),
                mac: "AA:BB:CC:00:00:09".into(),
                interface: "bridge".into(),
                from_dhcp: false,
                complete: true,
            }],
            leases: vec![DhcpLease {
                address: "192.168.5.8".into(),
                mac: "AA:BB:CC:00:00:10".into(),
                hostname: "x".into(),
                active: true,
            }],
            ..Default::default()
        };
        let f = analyse(&s);
        assert_eq!(f[0].severity, Severity::Critical);
        let last = f.last().unwrap().severity;
        assert!(last <= f[0].severity, "codes: {:?}", codes(&f));
    }

    #[test]
    fn a_lone_slow_client_is_not_an_airtime_problem() {
        // Real routers surfaced this: with one client the summary read "1 of 1
        // clients ... slows every other client", and the airtime ratio was a
        // meaningless 1x. There is nobody to contend with.
        let s = Snapshot { clients: vec![client("only", -40, 6)], ..Default::default() };
        assert!(
            find(&analyse(&s), "wifi.slow_client_airtime").is_none(),
            "one client cannot contend with itself"
        );
    }

    #[test]
    fn idle_clients_are_excluded_from_rate_based_rules() {
        // An idle 802.11 client reports whatever rate it last transmitted at,
        // which is the lowest basic rate. Judging it by that would raise a
        // critical finding on every quiet, healthy network.
        let s = Snapshot {
            clients: vec![idle(client("quiet1", -40, 6)), idle(client("quiet2", -45, 6))],
            ..Default::default()
        };
        let f = analyse(&s);
        assert!(find(&f, "wifi.slow_client_airtime").is_none(), "{f:?}");
        assert!(find(&f, "wifi.rate_signal_mismatch").is_none(), "{f:?}");
    }

    #[test]
    fn an_active_slow_client_among_active_peers_is_still_caught() {
        // The guard must not have disabled the rule it protects.
        let s = Snapshot {
            clients: vec![client("slow", -50, 6), client("fast", -45, 300)],
            ..Default::default()
        };
        assert!(find(&analyse(&s), "wifi.slow_client_airtime").is_some());
    }

    #[test]
    fn idle_peers_do_not_count_towards_contention() {
        // One active slow client plus idle neighbours is not contention: the
        // idle ones are not using airtime.
        let s = Snapshot {
            clients: vec![client("slow", -50, 6), idle(client("asleep", -45, 300))],
            ..Default::default()
        };
        assert!(find(&analyse(&s), "wifi.slow_client_airtime").is_none());
    }

    #[test]
    fn weak_signal_is_reported_even_when_idle() {
        // Coverage is a property of where the device is, not whether it is
        // currently transmitting, so this rule deliberately ignores activity.
        let s = Snapshot { clients: vec![idle(client("far", -88, 6))], ..Default::default() };
        assert!(find(&analyse(&s), "wifi.weak_signal").is_some());
    }

    #[test]
    fn an_empty_snapshot_is_safe() {
        assert!(analyse(&Snapshot::default()).is_empty());
    }
}
