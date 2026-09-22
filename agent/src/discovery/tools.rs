//! Active diagnostics: traceroute and IP scan.
//!
//! Both are one-shot tools rather than continuous measurements — a traceroute
//! run hours late answers a question nobody is still asking, and an IP scan
//! puts real traffic on the network.
//!
//! # Reading RouterOS tool output
//!
//! Both commands are *continuous*: they emit a fresh batch of rows on every
//! round, tagged with a `.section` number, and REST returns every batch. A
//! two-round traceroute over nine hops returns eighteen rows, not nine. The
//! last section is the cumulative result, so that is the only one worth
//! parsing — treating the whole response as a hop list would report each hop
//! several times.

use serde_json::Value;

use super::findings::{DhcpLease, Finding, Severity};

/// One traceroute hop, as of the final round.
#[derive(Debug, Clone, PartialEq)]
pub struct Hop {
    /// 1-based distance from us.
    pub ttl: usize,
    /// Empty when the hop did not answer.
    pub address: String,
    pub sent: u32,
    pub loss_pct: f64,
    pub avg_ms: f64,
    pub best_ms: f64,
    pub worst_ms: f64,
}

impl Hop {
    pub fn responded(&self) -> bool {
        !self.address.is_empty() && self.loss_pct < 100.0
    }
}

/// A host found by an IP scan.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanHost {
    pub address: String,
    pub mac: String,
    pub dns: String,
    pub netbios: String,
}

/// Keep only the rows belonging to the highest `.section`.
///
/// Each section is a complete cumulative snapshot, so the last one supersedes
/// every earlier one.
fn last_section(v: &Value) -> Vec<&Value> {
    let Some(rows) = v.as_array() else { return vec![] };
    let section_of = |r: &Value| -> i64 {
        r.get(".section")
            .and_then(|s| s.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    let Some(max) = rows.iter().map(section_of).max() else { return vec![] };
    rows.iter().filter(|r| section_of(r) == max).collect()
}

pub fn parse_traceroute(v: &Value) -> Vec<Hop> {
    last_section(v)
        .into_iter()
        .enumerate()
        .map(|(i, r)| Hop {
            // Position within the final section is the TTL; RouterOS does not
            // label hops explicitly.
            ttl: i + 1,
            address: s(r, "address"),
            sent: f(r, "sent") as u32,
            loss_pct: f(r, "loss"),
            avg_ms: f(r, "avg"),
            best_ms: f(r, "best"),
            worst_ms: f(r, "worst"),
        })
        .collect()
}

pub fn parse_ip_scan(v: &Value) -> Vec<ScanHost> {
    last_section(v)
        .into_iter()
        .map(|r| ScanHost {
            address: s(r, "address"),
            mac: s(r, "mac-address"),
            dns: s(r, "dns").trim_end_matches('.').to_string(),
            netbios: s(r, "netbios"),
        })
        .filter(|h| !h.address.is_empty())
        .collect()
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) if x != "-" => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn f(v: &Value, k: &str) -> f64 {
    s(v, k).trim().parse().unwrap_or(0.0)
}

// --- thresholds -----------------------------------------------------------

/// A latency increase at one hop worth naming, in milliseconds.
const LATENCY_STEP_MS: f64 = 30.0;
/// Loss at the destination that counts as real.
const REAL_LOSS_PCT: f64 = 2.0;
/// Carrier-grade NAT range (RFC 6598). Its presence changes what the customer
/// can be sold and whether inbound services can ever work.
const CGNAT: (u32, u32) = (0x6440_0000, 0x647F_FFFF); // 100.64.0.0/10

/// Analyse a completed traceroute.
pub fn analyse_path(hops: &[Hop], target: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if hops.is_empty() {
        return out;
    }

    let responding: Vec<&Hop> = hops.iter().filter(|h| h.responded()).collect();
    let Some(last) = responding.last() else {
        out.push(Finding {
            code: "path.no_response",
            severity: Severity::Critical,
            summary: format!("no hop on the way to {target} answered at all"),
            evidence: vec![format!("{} hops probed, none responded", hops.len())],
        });
        return out;
    };

    let reached = last.address == target;
    if !reached {
        out.push(Finding {
            code: "path.unreachable",
            severity: Severity::Critical,
            summary: format!(
                "{target} was not reached; the path stops responding after hop {} ({})",
                last.ttl, last.address
            ),
            evidence: hops
                .iter()
                .map(|h| describe(h))
                .collect(),
        });
    }

    out.extend(latency_step(&responding, target, reached));
    out.extend(path_loss(&responding, target, reached));
    out.extend(routing_loop(&responding));
    out.extend(cgnat(&responding));
    out
}

/// Find where latency actually enters the path.
///
/// Only a step that *persists to the destination* matters. A single hop
/// reporting high RTT while later hops are fast is a router deprioritising
/// ICMP to its own control plane — extremely common, and the single most
/// misread thing in a traceroute. Reporting it would send an engineer chasing
/// a device that is forwarding perfectly.
fn latency_step(responding: &[&Hop], target: &str, reached: bool) -> Vec<Finding> {
    if !reached || responding.len() < 2 {
        return vec![];
    }
    let final_rtt = responding.last().map(|h| h.avg_ms).unwrap_or(0.0);

    let mut worst: Option<(&Hop, &Hop, f64)> = None;
    for pair in responding.windows(2) {
        let step = pair[1].avg_ms - pair[0].avg_ms;
        if step < LATENCY_STEP_MS {
            continue;
        }
        // The step must still be present at the destination; otherwise the
        // elevated hop was answering slowly, not forwarding slowly.
        if pair[1].avg_ms > final_rtt + LATENCY_STEP_MS {
            continue;
        }
        if worst.map(|(_, _, s)| step > s).unwrap_or(true) {
            worst = Some((pair[0], pair[1], step));
        }
    }

    let Some((before, after, step)) = worst else { return vec![] };
    vec![Finding {
        code: "path.latency_step",
        severity: if step >= 100.0 { Severity::Warning } else { Severity::Info },
        summary: format!(
            "latency to {target} rises by {step:.0} ms between hop {} and hop {} — that link \
             is where the delay is introduced, not anything before it",
            before.ttl, after.ttl
        ),
        evidence: vec![
            describe(before),
            describe(after),
            format!("end-to-end average {final_rtt:.1} ms"),
        ],
    }]
}

/// Loss that reaches the destination. Loss at an intermediate hop which
/// disappears further along is ICMP rate limiting on that router, not packet
/// loss on the path.
fn path_loss(responding: &[&Hop], target: &str, reached: bool) -> Vec<Finding> {
    if !reached {
        return vec![];
    }
    let Some(last) = responding.last() else { return vec![] };
    if last.loss_pct < REAL_LOSS_PCT {
        return vec![];
    }

    // Walk back to the first hop where this loss appears and stays.
    let onset = responding
        .iter()
        .find(|h| h.loss_pct >= REAL_LOSS_PCT)
        .map(|h| (h.ttl, h.address.clone()));

    let mut evidence: Vec<String> =
        responding.iter().filter(|h| h.loss_pct > 0.0).map(|h| describe(h)).collect();
    evidence.push(format!("{:.0}% loss reaches {target}", last.loss_pct));

    vec![Finding {
        code: "path.loss",
        severity: if last.loss_pct >= 10.0 { Severity::Critical } else { Severity::Warning },
        summary: match onset {
            Some((ttl, addr)) if ttl < last.ttl => format!(
                "{:.0}% loss to {target}, first appearing at hop {ttl} ({addr}) and persisting \
                 to the destination",
                last.loss_pct
            ),
            _ => format!("{:.0}% loss to {target}", last.loss_pct),
        },
        evidence,
    }]
}

/// The same address appearing twice means the packet is going in circles.
fn routing_loop(responding: &[&Hop]) -> Vec<Finding> {
    let mut seen: std::collections::BTreeMap<&str, Vec<usize>> = Default::default();
    for h in responding {
        seen.entry(h.address.as_str()).or_default().push(h.ttl);
    }
    let loops: Vec<(&&str, &Vec<usize>)> =
        seen.iter().filter(|(_, ttls)| ttls.len() > 1).collect();
    if loops.is_empty() {
        return vec![];
    }
    vec![Finding {
        code: "path.routing_loop",
        severity: Severity::Critical,
        summary: format!(
            "{} address(es) appear more than once in the path, which means traffic is looping",
            loops.len()
        ),
        evidence: loops
            .iter()
            .map(|(addr, ttls)| {
                format!("{addr} appears at hops {}",
                    ttls.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(", "))
            })
            .collect(),
    }]
}

/// Carrier-grade NAT on the path. Not a fault, but it explains a whole class
/// of complaints — inbound connections, VPNs and port forwarding cannot work
/// through it — and it is invisible from the customer's own router.
fn cgnat(responding: &[&Hop]) -> Vec<Finding> {
    let hits: Vec<&&Hop> = responding
        .iter()
        .filter(|h| ipv4(&h.address).map(in_cgnat).unwrap_or(false))
        .collect();
    if hits.is_empty() {
        return vec![];
    }
    vec![Finding {
        code: "path.cgnat",
        severity: Severity::Info,
        summary: "the path traverses carrier-grade NAT (100.64.0.0/10), so inbound connections, \
                  port forwarding and some VPNs cannot work regardless of local configuration"
            .to_string(),
        evidence: hits.iter().map(|h| describe(h)).collect(),
    }]
}

fn describe(h: &Hop) -> String {
    if h.responded() {
        format!(
            "hop {}: {} avg {:.1} ms (best {:.1}, worst {:.1}), {:.0}% loss",
            h.ttl, h.address, h.avg_ms, h.best_ms, h.worst_ms, h.loss_pct
        )
    } else {
        format!("hop {}: no response", h.ttl)
    }
}

fn ipv4(s: &str) -> Option<u32> {
    let a: std::net::Ipv4Addr = s.parse().ok()?;
    Some(u32::from_be_bytes(a.octets()))
}

fn in_cgnat(a: u32) -> bool {
    a >= CGNAT.0 && a <= CGNAT.1
}

/// Analyse an IP scan against what DHCP knows about.
pub fn analyse_scan(hosts: &[ScanHost], leases: &[DhcpLease]) -> Vec<Finding> {
    let mut out = Vec::new();
    if hosts.is_empty() {
        return out;
    }

    // One MAC on several addresses is usually a device that changed address
    // without releasing, and it makes lease accounting and per-device policy
    // wrong until it ages out.
    let mut by_mac: std::collections::BTreeMap<&str, Vec<&ScanHost>> = Default::default();
    for h in hosts.iter().filter(|h| !h.mac.is_empty()) {
        by_mac.entry(h.mac.as_str()).or_default().push(h);
    }
    let multi: Vec<(&&str, &Vec<&ScanHost>)> =
        by_mac.iter().filter(|(_, v)| v.len() > 1).collect();
    if !multi.is_empty() {
        out.push(Finding {
            code: "scan.mac_multiple_addresses",
            severity: Severity::Warning,
            summary: format!(
                "{} device(s) are answering on more than one address, which makes lease \
                 accounting and any per-device policy unreliable",
                multi.len()
            ),
            evidence: multi
                .iter()
                .map(|(mac, hs)| {
                    format!(
                        "{mac} at {}",
                        hs.iter().map(|h| h.address.as_str()).collect::<Vec<_>>().join(", ")
                    )
                })
                .collect(),
        });
    }

    if !leases.is_empty() {
        let leased: std::collections::BTreeSet<String> =
            leases.iter().map(|l| l.mac.to_ascii_uppercase()).collect();
        let unknown: Vec<&ScanHost> = hosts
            .iter()
            .filter(|h| !h.mac.is_empty() && !leased.contains(&h.mac.to_ascii_uppercase()))
            .collect();
        if !unknown.is_empty() {
            out.push(Finding {
                code: "scan.unmanaged_host",
                severity: Severity::Info,
                summary: format!(
                    "{} host(s) are live on the network but hold no DHCP lease from this router",
                    unknown.len()
                ),
                evidence: unknown
                    .iter()
                    .map(|h| {
                        let label = if !h.dns.is_empty() {
                            h.dns.clone()
                        } else if !h.netbios.is_empty() {
                            h.netbios.clone()
                        } else {
                            "unidentified".to_string()
                        };
                        format!("{} ({}) — {}", h.address, h.mac, label)
                    })
                    .collect(),
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hop(ttl: usize, addr: &str, avg: f64, loss: f64) -> Hop {
        Hop {
            ttl,
            address: addr.into(),
            sent: 3,
            loss_pct: loss,
            avg_ms: avg,
            best_ms: avg * 0.9,
            worst_ms: avg * 1.2,
        }
    }

    fn find(f: &[Finding], code: &str) -> Option<Finding> {
        f.iter().find(|x| x.code == code).cloned()
    }

    #[test]
    fn only_the_last_section_is_parsed() {
        // Captured shape from a real RouterOS run: two rounds over two hops
        // returns four rows. Treating them all as hops would double the path.
        let v = json!([
            {".section":"0","address":"10.0.0.1","sent":"1","loss":"0","avg":"0.5","best":"0.4","worst":"0.6"},
            {".section":"0","address":"10.0.1.1","sent":"1","loss":"0","avg":"2.0","best":"1.9","worst":"2.1"},
            {".section":"1","address":"10.0.0.1","sent":"2","loss":"0","avg":"0.4","best":"0.3","worst":"0.6"},
            {".section":"1","address":"10.0.1.1","sent":"2","loss":"0","avg":"1.8","best":"1.7","worst":"2.0"}
        ]);
        let hops = parse_traceroute(&v);
        assert_eq!(hops.len(), 2, "two hops, not four");
        assert_eq!(hops[0].ttl, 1);
        assert_eq!(hops[1].ttl, 2);
        assert_eq!(hops[1].sent, 2, "the last section carries cumulative counts");
        assert!((hops[1].avg_ms - 1.8).abs() < 0.01);
    }

    #[test]
    fn a_clean_path_produces_no_findings() {
        let hops = vec![
            hop(1, "172.16.220.1", 0.4, 0.0),
            hop(2, "172.16.100.52", 1.1, 0.0),
            hop(3, "1.1.1.1", 8.7, 0.0),
        ];
        assert!(analyse_path(&hops, "1.1.1.1").is_empty());
    }

    #[test]
    fn a_latency_step_names_the_link_that_introduced_it() {
        let hops = vec![
            hop(1, "192.168.1.1", 1.0, 0.0),
            hop(2, "10.0.0.1", 3.0, 0.0),
            hop(3, "203.0.113.1", 95.0, 0.0), // satellite or congested uplink
            hop(4, "1.1.1.1", 98.0, 0.0),
        ];
        let f = analyse_path(&hops, "1.1.1.1");
        let hit = find(&f, "path.latency_step").expect("should locate the step");
        assert!(hit.summary.contains("hop 2"), "{}", hit.summary);
        assert!(hit.summary.contains("hop 3"), "{}", hit.summary);
    }

    #[test]
    fn an_icmp_deprioritising_hop_is_not_reported_as_latency() {
        // The most misread thing in a traceroute: one router answers its own
        // ICMP slowly while forwarding perfectly. Reporting it would send an
        // engineer after a device that is working fine.
        let hops = vec![
            hop(1, "192.168.1.1", 1.0, 0.0),
            hop(2, "10.0.0.1", 250.0, 0.0), // slow to answer, fast to forward
            hop(3, "203.0.113.1", 9.0, 0.0),
            hop(4, "1.1.1.1", 10.0, 0.0),
        ];
        assert!(
            find(&analyse_path(&hops, "1.1.1.1"), "path.latency_step").is_none(),
            "a spike that does not persist to the destination is not path latency"
        );
    }

    #[test]
    fn intermediate_loss_that_does_not_persist_is_ignored() {
        // Same reasoning for loss: routers rate-limit ICMP to themselves.
        let hops = vec![
            hop(1, "192.168.1.1", 1.0, 0.0),
            hop(2, "10.0.0.1", 3.0, 60.0), // rate-limited, still forwarding
            hop(3, "1.1.1.1", 9.0, 0.0),
        ];
        assert!(find(&analyse_path(&hops, "1.1.1.1"), "path.loss").is_none());
    }

    #[test]
    fn loss_reaching_the_destination_is_reported_with_its_onset() {
        let hops = vec![
            hop(1, "192.168.1.1", 1.0, 0.0),
            hop(2, "10.0.0.1", 3.0, 12.0),
            hop(3, "1.1.1.1", 9.0, 14.0),
        ];
        let hit = find(&analyse_path(&hops, "1.1.1.1"), "path.loss").expect("should report");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.summary.contains("hop 2"), "should name the onset: {}", hit.summary);
    }

    #[test]
    fn an_unreached_destination_is_critical_and_shows_the_whole_path() {
        let hops = vec![
            hop(1, "192.168.1.1", 1.0, 0.0),
            hop(2, "10.0.0.1", 3.0, 0.0),
            Hop { address: String::new(), ..hop(3, "", 0.0, 100.0) },
        ];
        let hit = find(&analyse_path(&hops, "1.1.1.1"), "path.unreachable").expect("should flag");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.evidence.iter().any(|e| e.contains("no response")));
    }

    #[test]
    fn a_totally_silent_path_is_distinguished_from_an_incomplete_one() {
        let hops = vec![
            Hop { address: String::new(), ..hop(1, "", 0.0, 100.0) },
            Hop { address: String::new(), ..hop(2, "", 0.0, 100.0) },
        ];
        let f = analyse_path(&hops, "1.1.1.1");
        assert!(find(&f, "path.no_response").is_some());
        assert!(find(&f, "path.unreachable").is_none(), "only one diagnosis, not two");
    }

    #[test]
    fn a_repeated_address_is_a_routing_loop() {
        let hops = vec![
            hop(1, "10.0.0.1", 1.0, 0.0),
            hop(2, "10.0.0.2", 2.0, 0.0),
            hop(3, "10.0.0.1", 3.0, 0.0),
            hop(4, "10.0.0.2", 4.0, 0.0),
        ];
        let hit = find(&analyse_path(&hops, "9.9.9.9"), "path.routing_loop").expect("should flag");
        assert_eq!(hit.severity, Severity::Critical);
        assert_eq!(hit.evidence.len(), 2);
    }

    #[test]
    fn cgnat_on_the_path_is_surfaced() {
        // Invisible from the customer's own router, and explains why port
        // forwarding "does not work" no matter what they configure.
        let hops = vec![
            hop(1, "192.168.1.1", 1.0, 0.0),
            hop(2, "100.64.12.1", 4.0, 0.0),
            hop(3, "1.1.1.1", 9.0, 0.0),
        ];
        let hit = find(&analyse_path(&hops, "1.1.1.1"), "path.cgnat").expect("should flag");
        assert!(hit.summary.contains("port forwarding"), "{}", hit.summary);
    }

    #[test]
    fn ordinary_private_ranges_are_not_mistaken_for_cgnat() {
        // 100.64/10 is easy to confuse with 10/8 and 172.16/12 when checking
        // by prefix rather than by range.
        for addr in ["10.0.0.1", "172.16.220.1", "192.168.1.1", "100.128.0.1", "100.63.255.255"] {
            let hops = vec![hop(1, addr, 1.0, 0.0), hop(2, "1.1.1.1", 9.0, 0.0)];
            assert!(
                find(&analyse_path(&hops, "1.1.1.1"), "path.cgnat").is_none(),
                "{addr} is not CGNAT"
            );
        }
        // Both ends of the real range are.
        for addr in ["100.64.0.0", "100.127.255.255"] {
            let hops = vec![hop(1, addr, 1.0, 0.0), hop(2, "1.1.1.1", 9.0, 0.0)];
            assert!(find(&analyse_path(&hops, "1.1.1.1"), "path.cgnat").is_some(), "{addr}");
        }
    }

    // --- ip scan ---------------------------------------------------------

    #[test]
    fn scan_parses_the_last_section_and_strips_trailing_dots() {
        let v = json!([
            {".section":"0","address":"10.0.0.1","mac-address":"AA:BB:CC:00:00:01"},
            {".section":"1","address":"10.0.0.1","mac-address":"AA:BB:CC:00:00:01","dns":"router.lan."},
            {".section":"1","address":"10.0.0.2","mac-address":"AA:BB:CC:00:00:02","netbios":"DESKTOP"}
        ]);
        let hosts = parse_ip_scan(&v);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].dns, "router.lan", "trailing dot is noise in a report");
        assert_eq!(hosts[1].netbios, "DESKTOP");
    }

    #[test]
    fn a_dash_placeholder_is_treated_as_absent() {
        // RouterOS prints "-" for a field it has no value for; carrying that
        // into a report as if it were a MAC address would be misleading.
        let v = json!([{".section":"0","address":"10.0.0.1","mac-address":"-"}]);
        assert_eq!(parse_ip_scan(&v)[0].mac, "");
    }

    #[test]
    fn one_mac_on_several_addresses_is_flagged() {
        let hosts = vec![
            ScanHost { address: "10.0.0.5".into(), mac: "AA:BB:CC:00:00:01".into(), dns: String::new(), netbios: String::new() },
            ScanHost { address: "10.0.0.9".into(), mac: "AA:BB:CC:00:00:01".into(), dns: String::new(), netbios: String::new() },
        ];
        let hit = find(&analyse_scan(&hosts, &[]), "scan.mac_multiple_addresses").expect("flag");
        assert_eq!(hit.severity, Severity::Warning);
        assert!(hit.evidence[0].contains("10.0.0.5"));
    }

    #[test]
    fn hosts_without_a_lease_are_listed_with_whatever_identifies_them() {
        let hosts = vec![
            ScanHost { address: "10.0.0.5".into(), mac: "AA:BB:CC:00:00:01".into(), dns: "nas.lan".into(), netbios: String::new() },
            ScanHost { address: "10.0.0.6".into(), mac: "AA:BB:CC:00:00:02".into(), dns: String::new(), netbios: String::new() },
        ];
        let leases = vec![DhcpLease {
            address: "10.0.0.5".into(),
            mac: "aa:bb:cc:00:00:01".into(),
            hostname: "nas".into(),
            active: true,
        }];
        let hit = find(&analyse_scan(&hosts, &leases), "scan.unmanaged_host").expect("flag");
        assert_eq!(hit.evidence.len(), 1, "the leased host must not be listed");
        assert!(hit.evidence[0].contains("unidentified"), "{:?}", hit.evidence);
    }

    #[test]
    fn without_lease_data_no_host_is_called_unmanaged() {
        let hosts = vec![ScanHost {
            address: "10.0.0.6".into(),
            mac: "AA:BB:CC:00:00:02".into(),
            dns: String::new(),
            netbios: String::new(),
        }];
        assert!(find(&analyse_scan(&hosts, &[]), "scan.unmanaged_host").is_none());
    }

    #[test]
    fn empty_input_is_safe() {
        assert!(analyse_path(&[], "1.1.1.1").is_empty());
        assert!(analyse_scan(&[], &[]).is_empty());
        assert!(parse_traceroute(&json!(null)).is_empty());
        assert!(parse_ip_scan(&json!("nonsense")).is_empty());
    }
}
