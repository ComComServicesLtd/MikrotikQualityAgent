//! Gathering local state from the host RouterOS device.
//!
//! Every value in a RouterOS REST response is a JSON *string*, including
//! numbers and booleans, so all parsing here is defensive: a field that is
//! missing, empty or unparseable yields a default rather than failing the whole
//! run. A discovery pass that returns nine of ten collectors is far more useful
//! than one that aborts because a device lacks a wireless card.
//!
//! RouterOS 7 ships two incompatible wireless stacks — legacy
//! `/interface/wireless` and the newer `/interface/wifi` — and a given device
//! has one or the other. The hAP ac³ answers on `wireless`; the hAP ax³ returns
//! 400 for it and answers on `wifi`. Both are tried and whichever responds is
//! used, so one build covers a mixed fleet.

use std::time::Duration;

use serde_json::Value;
use tracing::{debug, warn};

use super::findings::{ArpEntry, DhcpLease, InterfaceStats, NeighbourAp, Radio, Snapshot, WifiClient};
use crate::routeros::RouterOs;

/// Interval between the two interface samples used to derive packet rates.
/// RouterOS exposes counters, not rates, so a rate needs two reads.
const RATE_SAMPLE: Duration = Duration::from_secs(2);

/// Collect everything, tolerating individual failures.
pub async fn run(ros: &RouterOs) -> Snapshot {
    let mut s = Snapshot::default();

    match ros.get("/ip/arp").await {
        Ok(v) => s.arp = parse_arp(&v),
        Err(e) => warn!(error = %e, "could not read ARP table"),
    }
    match ros.get("/ip/dhcp-server/lease").await {
        Ok(v) => s.leases = parse_leases(&v),
        Err(e) => debug!(error = %e, "no DHCP lease data (this router may not serve DHCP)"),
    }

    let (clients, radios) = collect_wireless(ros).await;
    s.clients = clients;
    s.radios = radios;

    s.interfaces = collect_interface_rates(ros).await;
    s.dhcp_pool_size = collect_pool_size(ros).await;

    debug!(
        arp = s.arp.len(), leases = s.leases.len(), clients = s.clients.len(),
        radios = s.radios.len(), interfaces = s.interfaces.len(),
        "discovery snapshot collected"
    );
    s
}

/// Try the modern stack, then the legacy one.
async fn collect_wireless(ros: &RouterOs) -> (Vec<WifiClient>, Vec<Radio>) {
    if let Ok(v) = ros.get("/interface/wifi/registration-table").await {
        let clients = parse_wifi_clients(&v);
        let radios = match ros.get("/interface/wifi").await {
            Ok(r) => parse_wifi_radios(&r),
            Err(_) => vec![],
        };
        debug!(stack = "wifi", clients = clients.len(), "using the modern wireless stack");
        return (clients, radios);
    }

    if let Ok(v) = ros.get("/interface/wireless/registration-table").await {
        let clients = parse_legacy_clients(&v);
        let radios = match ros.get("/interface/wireless").await {
            Ok(r) => parse_legacy_radios(&r),
            Err(_) => vec![],
        };
        debug!(stack = "wireless", clients = clients.len(), "using the legacy wireless stack");
        return (clients, radios);
    }

    debug!("no wireless interfaces on this device");
    (vec![], vec![])
}

/// Two samples, so counters become rates.
async fn collect_interface_rates(ros: &RouterOs) -> Vec<InterfaceStats> {
    let first = match ros.get("/interface").await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "could not read interfaces");
            return vec![];
        }
    };
    tokio::time::sleep(RATE_SAMPLE).await;
    let second = match ros.get("/interface").await {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let secs = RATE_SAMPLE.as_secs().max(1);
    let mut out = Vec::new();

    for b in second.as_array().map(|a| a.as_slice()).unwrap_or_default() {
        let name = str_of(b, "name");
        if name.is_empty() {
            continue;
        }
        let Some(a) = first
            .as_array()
            .and_then(|arr| arr.iter().find(|x| str_of(x, "name") == name))
        else {
            continue;
        };

        // Counters wrap and can reset when an interface bounces; saturating
        // subtraction turns that into a zero rate rather than an absurd spike
        // that would be reported as a storm.
        let delta = |k: &str| num_of(b, k).saturating_sub(num_of(a, k)) / secs;

        out.push(InterfaceStats {
            name,
            rx_packets_per_s: delta("rx-packet"),
            tx_packets_per_s: delta("tx-packet"),
            rx_broadcast_per_s: delta("rx-broadcast"),
            rx_multicast_per_s: delta("rx-multicast"),
            running: bool_of(b, "running"),
        });
    }
    out
}

async fn collect_pool_size(ros: &RouterOs) -> Option<usize> {
    let pools = ros.get("/ip/pool").await.ok()?;
    let mut total = 0usize;
    for p in pools.as_array()? {
        total += count_range(&str_of(p, "ranges"));
    }
    (total > 0).then_some(total)
}

/// Count addresses in a RouterOS pool range list, e.g.
/// `192.168.5.10-192.168.5.254,192.168.6.10-192.168.6.20`.
fn count_range(ranges: &str) -> usize {
    let mut total = 0usize;
    for part in ranges.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let Some((lo, hi)) = part.split_once('-') else {
            total += 1; // a bare address is a pool of one
            continue;
        };
        if let (Some(a), Some(b)) = (ipv4_to_u32(lo.trim()), ipv4_to_u32(hi.trim())) {
            if b >= a {
                total += (b - a + 1) as usize;
            }
        }
    }
    total
}

fn ipv4_to_u32(s: &str) -> Option<u32> {
    let v: std::net::Ipv4Addr = s.parse().ok()?;
    Some(u32::from_be_bytes(v.octets()))
}

// --- parsers --------------------------------------------------------------

fn parse_arp(v: &Value) -> Vec<ArpEntry> {
    rows(v)
        .map(|r| ArpEntry {
            address: str_of(r, "address"),
            mac: str_of(r, "mac-address"),
            interface: str_of(r, "interface"),
            from_dhcp: bool_of(r, "dhcp"),
            complete: bool_of(r, "complete"),
        })
        .filter(|e| !e.address.is_empty())
        .collect()
}

/// Public wrapper so one-shot tools can reuse lease parsing without the whole
/// collection pass.
pub fn parse_leases_public(v: &Value) -> Vec<DhcpLease> {
    parse_leases(v)
}

fn parse_leases(v: &Value) -> Vec<DhcpLease> {
    rows(v)
        .map(|r| {
            // Active fields reflect the live binding; the static ones are the
            // configured reservation and can differ.
            let addr = first_non_empty(r, &["active-address", "address"]);
            let mac = first_non_empty(r, &["active-mac-address", "mac-address"]);
            DhcpLease {
                address: addr,
                mac,
                hostname: first_non_empty(r, &["host-name", "comment"]),
                active: str_of(r, "status") == "bound" || !str_of(r, "active-address").is_empty(),
            }
        })
        .filter(|l| !l.mac.is_empty())
        .collect()
}

fn parse_wifi_clients(v: &Value) -> Vec<WifiClient> {
    rows(v)
        .map(|r| WifiClient {
            mac: str_of(r, "mac-address"),
            interface: str_of(r, "interface"),
            ssid: str_of(r, "ssid"),
            signal_dbm: signed_of(r, "signal"),
            tx_rate_bps: num_of(r, "tx-rate"),
            rx_rate_bps: num_of(r, "rx-rate"),
            band: str_of(r, "band"),
            uptime_s: parse_uptime(&str_of(r, "uptime")),
            last_activity_s: parse_uptime(&str_of(r, "last-activity")),
        })
        .filter(|c| !c.mac.is_empty())
        .collect()
}

fn parse_wifi_radios(v: &Value) -> Vec<Radio> {
    rows(v)
        .map(|r| Radio {
            name: str_of(r, "name"),
            band: first_non_empty(r, &["channel.band", "band"]),
            frequency_mhz: {
                let f = num_of(r, "channel.frequency");
                if f > 0 {
                    Some(f as u32)
                } else {
                    None
                }
            },
            width: first_non_empty(r, &["channel.width", "width"]),
            country: first_non_empty(r, &["configuration.country", "country"]),
        })
        .filter(|r| !r.name.is_empty())
        .collect()
}

fn parse_legacy_clients(v: &Value) -> Vec<WifiClient> {
    rows(v)
        .map(|r| WifiClient {
            mac: str_of(r, "mac-address"),
            interface: str_of(r, "interface"),
            ssid: str_of(r, "ssid"),
            // Legacy reports e.g. "-64@6mbps" or plain "-64".
            signal_dbm: parse_legacy_signal(&first_non_empty(
                r,
                &["signal-strength", "signal-strength-ch0", "signal"],
            )),
            tx_rate_bps: parse_legacy_rate(&str_of(r, "tx-rate")),
            rx_rate_bps: parse_legacy_rate(&str_of(r, "rx-rate")),
            band: str_of(r, "band"),
            uptime_s: parse_uptime(&str_of(r, "uptime")),
            last_activity_s: parse_uptime(&first_non_empty(r, &["last-activity", "last-ip"])),
        })
        .filter(|c| !c.mac.is_empty())
        .collect()
}

fn parse_legacy_radios(v: &Value) -> Vec<Radio> {
    rows(v)
        .map(|r| Radio {
            name: str_of(r, "name"),
            band: str_of(r, "band"),
            frequency_mhz: {
                let f = num_of(r, "frequency");
                if f > 0 {
                    Some(f as u32)
                } else {
                    None
                }
            },
            width: first_non_empty(r, &["channel-width", "width"]),
            country: str_of(r, "country"),
        })
        .filter(|r| !r.name.is_empty())
        .collect()
}

/// Parse a scan result into neighbouring APs. Shared by both stacks, which
/// happen to agree on these field names.
pub fn parse_scan(v: &Value) -> Vec<NeighbourAp> {
    rows(v)
        .map(|r| NeighbourAp {
            ssid: str_of(r, "ssid"),
            frequency_mhz: {
                let f = num_of(r, "frequency");
                if f > 0 {
                    f as u32
                } else {
                    num_of(r, "channel") as u32
                }
            },
            signal_dbm: signed_of(r, "signal"),
        })
        .filter(|a| a.frequency_mhz > 0)
        .collect()
}

// --- field helpers --------------------------------------------------------

fn rows(v: &Value) -> impl Iterator<Item = &Value> {
    v.as_array().map(|a| a.iter()).unwrap_or_else(|| [].iter())
}

fn str_of(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn first_non_empty(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        let s = str_of(v, k);
        if !s.is_empty() {
            return s;
        }
    }
    String::new()
}

/// Unsigned number from a RouterOS string field. A value like "4108,60349"
/// (rx,tx byte pairs) takes the first component rather than failing.
fn num_of(v: &Value, key: &str) -> u64 {
    let s = str_of(v, key);
    let head = s.split(',').next().unwrap_or("").trim();
    head.parse().unwrap_or(0)
}

fn signed_of(v: &Value, key: &str) -> i32 {
    let s = str_of(v, key);
    let head = s.split(',').next().unwrap_or("").trim();
    head.parse().unwrap_or(0)
}

fn bool_of(v: &Value, key: &str) -> bool {
    matches!(str_of(v, key).as_str(), "true" | "yes")
}

/// Legacy signal strength: `-64@6mbps` or `-64`.
fn parse_legacy_signal(s: &str) -> i32 {
    s.split('@').next().unwrap_or("").trim().parse().unwrap_or(0)
}

/// Legacy rate: `54Mbps`, `6Mbps-40MHz/1S`, or a bare bits-per-second value.
fn parse_legacy_rate(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    if let Ok(n) = s.parse::<u64>() {
        return n; // already bits per second
    }
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let value: f64 = digits.parse().unwrap_or(0.0);
    let lower = s.to_ascii_lowercase();
    let scale = if lower.contains("gbps") {
        1e9
    } else if lower.contains("mbps") {
        1e6
    } else if lower.contains("kbps") {
        1e3
    } else {
        1.0
    };
    (value * scale) as u64
}

/// RouterOS durations: `1h22m56s`, `3d17h58m3s`, `6s`.
fn parse_uptime(s: &str) -> u64 {
    let mut total = 0u64;
    let mut num = 0u64;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            num = num * 10 + d as u64;
        } else {
            total += num
                * match c {
                    'w' => 604_800,
                    'd' => 86_400,
                    'h' => 3_600,
                    'm' => 60,
                    's' => 1,
                    _ => 0,
                };
            num = 0;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_real_wifi_registration_row() {
        // Captured verbatim from a hAP ax³ running RouterOS 7.24.2.
        let v = json!([{
            "mac-address": "08:55:31:E2:89:7C", "interface": "wifi1",
            "ssid": "Lyttonnet 0", "signal": "-17", "band": "5ghz-ac",
            "tx-rate": "6000000", "rx-rate": "300000000",
            "uptime": "1h22m56s", "bytes": "4108,60349", "last-activity": "6s"
        }]);
        let c = &parse_wifi_clients(&v)[0];
        assert_eq!(c.mac, "08:55:31:E2:89:7C");
        assert_eq!(c.signal_dbm, -17);
        assert_eq!(c.tx_rate_bps, 6_000_000);
        assert_eq!(c.rx_rate_bps, 300_000_000);
        assert_eq!(c.uptime_s, 4976);
        assert_eq!(c.last_activity_s, 6, "activity drives whether the rate is trusted");
    }

    #[test]
    fn parses_legacy_signal_and_rate_formats() {
        let v = json!([{
            "mac-address": "AA:BB:CC:00:00:01", "interface": "wlan1",
            "signal-strength": "-64@6mbps", "tx-rate": "54Mbps",
            "rx-rate": "6Mbps-40MHz/1S", "uptime": "2d3h4m5s"
        }]);
        let c = &parse_legacy_clients(&v)[0];
        assert_eq!(c.signal_dbm, -64, "must strip the @rate suffix");
        assert_eq!(c.tx_rate_bps, 54_000_000);
        assert_eq!(c.rx_rate_bps, 6_000_000, "must stop at the first unit");
        assert_eq!(c.uptime_s, 2 * 86_400 + 3 * 3_600 + 4 * 60 + 5);
    }

    #[test]
    fn comma_separated_counters_take_the_first_component() {
        // RouterOS reports "bytes":"4108,60349" as an rx,tx pair. Parsing the
        // whole string would yield zero and silently lose the value.
        let v = json!({"packets": "34,533"});
        assert_eq!(num_of(&v, "packets"), 34);
    }

    #[test]
    fn missing_and_malformed_fields_degrade_to_defaults() {
        // A collector that panics on one odd row loses the other nine.
        let v = json!([{"mac-address": "AA:BB:CC:00:00:01"}]);
        let c = &parse_wifi_clients(&v)[0];
        assert_eq!(c.signal_dbm, 0);
        assert_eq!(c.tx_rate_bps, 0);
        assert_eq!(c.uptime_s, 0);

        assert!(parse_wifi_clients(&json!("not an array")).is_empty());
        assert!(parse_arp(&json!(null)).is_empty());
    }

    #[test]
    fn arp_booleans_come_back_as_strings() {
        let v = json!([{
            "address": "192.168.5.10", "mac-address": "AA:BB:CC:00:00:01",
            "interface": "bridge", "dhcp": "true", "complete": "true"
        }]);
        let e = &parse_arp(&v)[0];
        assert!(e.from_dhcp);
        assert!(e.complete);

        let v2 = json!([{"address": "1.2.3.4", "complete": "false", "dhcp": "false"}]);
        assert!(!parse_arp(&v2)[0].complete);
    }

    #[test]
    fn leases_prefer_the_live_binding_over_the_reservation() {
        let v = json!([{
            "address": "192.168.5.50", "active-address": "192.168.5.51",
            "mac-address": "AA:BB:CC:00:00:01", "active-mac-address": "AA:BB:CC:00:00:02",
            "host-name": "laptop", "status": "bound"
        }]);
        let l = &parse_leases(&v)[0];
        assert_eq!(l.address, "192.168.5.51");
        assert_eq!(l.mac, "AA:BB:CC:00:00:02");
        assert!(l.active);
    }

    #[test]
    fn counts_addresses_across_pool_ranges() {
        assert_eq!(count_range("192.168.5.10-192.168.5.254"), 245);
        assert_eq!(count_range("192.168.5.10-192.168.5.20,192.168.6.1-192.168.6.10"), 21);
        assert_eq!(count_range("192.168.5.7"), 1);
        assert_eq!(count_range(""), 0);
        // A reversed range is nonsense; count nothing rather than underflow.
        assert_eq!(count_range("192.168.5.20-192.168.5.10"), 0);
    }

    #[test]
    fn scan_results_become_neighbour_aps() {
        let v = json!([
            {"ssid": "Neighbour", "frequency": "5180", "signal": "-62"},
            {"ssid": "", "channel": "2412", "signal": "-70"},
            {"ssid": "NoFreq", "signal": "-50"}
        ]);
        let aps = parse_scan(&v);
        assert_eq!(aps.len(), 2, "a scan row with no frequency is unusable");
        assert_eq!(aps[0].frequency_mhz, 5180);
        assert_eq!(aps[1].frequency_mhz, 2412, "falls back to the channel field");
    }

    #[test]
    fn uptime_handles_every_unit() {
        assert_eq!(parse_uptime("6s"), 6);
        assert_eq!(parse_uptime("1h22m56s"), 4976);
        assert_eq!(parse_uptime("3d17h58m3s"), 3 * 86_400 + 17 * 3_600 + 58 * 60 + 3);
        assert_eq!(parse_uptime("1w2d"), 604_800 + 2 * 86_400);
        assert_eq!(parse_uptime(""), 0);
    }
}
