//! Throughput testing via the host router's `/tool/bandwidth-test`.
//!
//! Running a throughput test inside the container would measure the container's
//! veth and the router's CPU scheduling, not the path. Driving the router's own
//! tool exercises its forwarding hardware instead, which is what the link
//! actually delivers.
//!
//! # The number is only as good as the CPU behind it
//!
//! On small MikroTik hardware the router's CPU is very often the limit rather
//! than the link. A measured 621 Mbit/s at 64% CPU means something quite
//! different from 621 Mbit/s at 8%, and at 100% the figure is a measurement of
//! the router, not the network. RouterOS reports `local-cpu-load` and (for
//! transmit) `remote-cpu-load`, so every result carries them and says so when
//! they are high enough to matter.
//!
//! # REST cannot stream
//!
//! `/tool/bandwidth-test` is a continuous command. Over REST there is no
//! streaming and a hard 60-second ceiling, so a duration must always be given
//! and kept below it. Like the other RouterOS tools, the response is a series
//! of cumulative `.section` batches; only the last is the result.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{RouterOs, RouterOsError};

/// RouterOS terminates any REST command at 60 seconds. Staying clear of the
/// edge leaves room for the connection setup either side of the test itself.
pub const MAX_REST_DURATION: Duration = Duration::from_secs(45);

/// Above this, the result describes the router rather than the link.
const CPU_SATURATED_PCT: u8 = 90;
/// Above this, the router is contributing materially to the ceiling.
const CPU_BUSY_PCT: u8 = 70;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Which way the data flows, from this router's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Pull from the far end: measures download.
    Receive,
    /// Push to the far end: measures upload.
    Transmit,
    /// Both at once. Note this is not the same as running each separately —
    /// the two streams contend, so each figure is lower than it would be alone.
    Both,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Transmit => "transmit",
            Self::Both => "both",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rx" | "receive" | "download" => Some(Self::Receive),
            "tx" | "transmit" | "upload" => Some(Self::Transmit),
            "both" | "bidirectional" => Some(Self::Both),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BtestConfig {
    /// The far end, which must be running `/tool/bandwidth-server`.
    pub address: String,
    pub direction: Direction,
    pub protocol: Protocol,
    pub duration: Duration,
    /// Credentials for a user on the *far* router holding the `test` policy.
    pub user: String,
    pub password: String,
    /// TCP only. More connections can fill a high-latency path that a single
    /// stream cannot, but each one costs the router CPU.
    pub connection_count: Option<u32>,
    /// Ceilings in bits per second, to stop a test saturating a live link.
    pub local_tx_speed: Option<u64>,
    pub remote_tx_speed: Option<u64>,
}

impl BtestConfig {
    pub fn new(address: impl Into<String>, direction: Direction, protocol: Protocol) -> Self {
        Self {
            address: address.into(),
            direction,
            protocol,
            duration: Duration::from_secs(10),
            user: String::new(),
            password: String::new(),
            connection_count: None,
            local_tx_speed: None,
            remote_tx_speed: None,
        }
    }

    /// Build the request body, clamping anything RouterOS would reject.
    pub fn to_request(&self) -> (Value, Option<String>) {
        let mut note = None;
        let mut secs = self.duration.as_secs().max(1);
        if secs > MAX_REST_DURATION.as_secs() {
            note = Some(format!(
                "duration reduced from {}s to {}s: RouterOS terminates any REST command at 60s",
                secs,
                MAX_REST_DURATION.as_secs()
            ));
            secs = MAX_REST_DURATION.as_secs();
        }

        let mut body = serde_json::json!({
            "address": self.address,
            "duration": format!("{secs}s"),
            "direction": self.direction.as_str(),
            "protocol": self.protocol.as_str(),
            "user": self.user,
            "password": self.password,
        });
        if let Some(n) = self.connection_count {
            if self.protocol == Protocol::Tcp {
                body["connection-count"] = Value::String(n.to_string());
            }
        }
        if let Some(v) = self.local_tx_speed {
            body["local-tx-speed"] = Value::String(v.to_string());
        }
        if let Some(v) = self.remote_tx_speed {
            body["remote-tx-speed"] = Value::String(v.to_string());
        }
        (body, note)
    }
}

/// How much the router's own CPU limited the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuVerdict {
    /// The router had headroom; the figure describes the link.
    LinkLimited,
    /// The router was working hard; treat the figure as a floor.
    RouterContributing,
    /// The router was saturated; this measures the router, not the link.
    RouterLimited,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BtestResult {
    pub protocol: Protocol,
    pub direction: Direction,
    /// Bits per second averaged over the whole run. Absent for a direction
    /// that was not measured.
    pub tx_bps: Option<u64>,
    pub rx_bps: Option<u64>,
    pub duration_s: u64,
    pub local_cpu_load: Option<u8>,
    pub remote_cpu_load: Option<u8>,
    /// UDP only: RouterOS sends faster than the path can carry and counts what
    /// did not arrive. Meaningless for TCP, which never offers more than the
    /// path accepts.
    pub lost_packets: Option<u64>,
    pub connection_count: Option<u32>,
    pub status: String,
    pub cpu_verdict: CpuVerdict,
    /// Plain-language caveats worth printing beside the number.
    pub notes: Vec<String>,
    /// Where the measurement was taken. Recorded because a figure from the
    /// router's forwarding path and one from inside a container are not
    /// comparable.
    pub source: &'static str,
}

/// Run a bandwidth test from this router against `cfg.address`.
pub async fn run(ros: &RouterOs, cfg: &BtestConfig) -> Result<BtestResult, RouterOsError> {
    let (body, clamp_note) = cfg.to_request();
    let raw = ros.post("/tool/bandwidth-test", &body).await?;
    let mut result = parse(&raw, cfg)?;
    if let Some(n) = clamp_note {
        result.notes.insert(0, n);
    }
    Ok(result)
}

/// Parse a `/tool/bandwidth-test` response.
pub fn parse(raw: &Value, cfg: &BtestConfig) -> Result<BtestResult, RouterOsError> {
    // Cumulative `.section` batches, same as traceroute and ip-scan. Only the
    // last one is the result; earlier ones are progress.
    let rows = raw.as_array().ok_or_else(|| {
        RouterOsError::Decode("bandwidth-test did not return a list of results".into())
    })?;
    let last = rows.last().ok_or_else(|| {
        RouterOsError::Decode("bandwidth-test returned no results at all".into())
    })?;

    let status = s(last, "status");
    // RouterOS reports a refusal in the same shape as a result.
    if status.contains("connect") && !status.contains("done") && rows.len() == 1 {
        return Err(RouterOsError::Decode(format!(
            "bandwidth-test did not run: {status}. Check that the far end has \
             /tool/bandwidth-server enabled and that the credentials hold the `test` policy"
        )));
    }

    let local_cpu = u8_of(last, "local-cpu-load");
    let remote_cpu = u8_of(last, "remote-cpu-load");
    let worst_cpu = local_cpu.into_iter().chain(remote_cpu).max();

    let cpu_verdict = match worst_cpu {
        Some(c) if c >= CPU_SATURATED_PCT => CpuVerdict::RouterLimited,
        Some(c) if c >= CPU_BUSY_PCT => CpuVerdict::RouterContributing,
        _ => CpuVerdict::LinkLimited,
    };

    let mut notes = Vec::new();
    match cpu_verdict {
        CpuVerdict::RouterLimited => notes.push(format!(
            "CPU reached {}%, so this measures the router rather than the link — the link \
             may well be faster",
            worst_cpu.unwrap_or(0)
        )),
        CpuVerdict::RouterContributing => notes.push(format!(
            "CPU reached {}%, so the router contributed to the ceiling; treat the figure as \
             a floor",
            worst_cpu.unwrap_or(0)
        )),
        CpuVerdict::LinkLimited => {}
    }
    if cfg.direction == Direction::Both {
        notes.push(
            "both directions ran at once and contend with each other, so each figure is lower \
             than it would be measured alone"
                .into(),
        );
    }
    if cfg.protocol == Protocol::Udp {
        notes.push(
            "UDP offers more than the path can carry and counts what does not arrive, so loss \
             here is expected and is how the ceiling is found"
                .into(),
        );
    }

    Ok(BtestResult {
        protocol: cfg.protocol,
        direction: cfg.direction,
        tx_bps: u64_of(last, "tx-total-average"),
        rx_bps: u64_of(last, "rx-total-average"),
        duration_s: parse_secs(&s(last, "duration")),
        local_cpu_load: local_cpu,
        remote_cpu_load: remote_cpu,
        lost_packets: if cfg.protocol == Protocol::Udp {
            u64_of(last, "lost-packets")
        } else {
            None
        },
        connection_count: u64_of(last, "connection-count").map(|v| v as u32),
        status,
        cpu_verdict,
        notes,
        source: "routeros_host",
    })
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn u64_of(v: &Value, k: &str) -> Option<u64> {
    let raw = s(v, k);
    if raw.is_empty() {
        return None;
    }
    raw.trim().parse().ok()
}

fn u8_of(v: &Value, k: &str) -> Option<u8> {
    u64_of(v, k).map(|n| n.min(100) as u8)
}

/// RouterOS echoes the duration as `6s`, or occasionally with larger units.
fn parse_secs(s: &str) -> u64 {
    let mut total = 0u64;
    let mut num = 0u64;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            num = num * 10 + d as u64;
        } else {
            total += num
                * match c {
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

    fn cfg(dir: Direction, proto: Protocol) -> BtestConfig {
        BtestConfig::new("10.0.0.1", dir, proto)
    }

    #[test]
    fn direction_and_protocol_accept_the_obvious_spellings() {
        for s in ["rx", "receive", "RX", "download"] {
            assert_eq!(Direction::parse(s), Some(Direction::Receive), "{s}");
        }
        for s in ["tx", "transmit", "upload"] {
            assert_eq!(Direction::parse(s), Some(Direction::Transmit), "{s}");
        }
        assert_eq!(Direction::parse("both"), Some(Direction::Both));
        assert_eq!(Direction::parse("sideways"), None);
        assert_eq!(Protocol::parse("TCP"), Some(Protocol::Tcp));
        assert_eq!(Protocol::parse("udp"), Some(Protocol::Udp));
        assert_eq!(Protocol::parse("sctp"), None);
    }

    #[test]
    fn the_request_carries_what_routeros_expects() {
        let mut c = cfg(Direction::Receive, Protocol::Tcp);
        c.user = "bt".into();
        c.password = "secret".into();
        c.duration = Duration::from_secs(10);
        let (body, note) = c.to_request();

        assert_eq!(body["direction"], "receive");
        assert_eq!(body["protocol"], "tcp");
        assert_eq!(body["duration"], "10s");
        assert_eq!(body["user"], "bt");
        assert!(note.is_none());
    }

    #[test]
    fn a_duration_past_the_rest_ceiling_is_clamped_and_explained() {
        // RouterOS kills any REST command at 60s. Sending 120 would produce a
        // confusing timeout rather than a short test.
        let mut c = cfg(Direction::Receive, Protocol::Tcp);
        c.duration = Duration::from_secs(120);
        let (body, note) = c.to_request();

        assert_eq!(body["duration"], format!("{}s", MAX_REST_DURATION.as_secs()));
        assert!(note.unwrap().contains("60s"));
    }

    #[test]
    fn connection_count_is_tcp_only() {
        // RouterOS rejects it for UDP, which would fail the whole test.
        let mut c = cfg(Direction::Receive, Protocol::Udp);
        c.connection_count = Some(8);
        assert!(c.to_request().0.get("connection-count").is_none());

        let mut t = cfg(Direction::Receive, Protocol::Tcp);
        t.connection_count = Some(8);
        assert_eq!(t.to_request().0["connection-count"], "8");
    }

    #[test]
    fn speed_ceilings_are_passed_through_when_set() {
        let mut c = cfg(Direction::Both, Protocol::Tcp);
        c.local_tx_speed = Some(50_000_000);
        c.remote_tx_speed = Some(25_000_000);
        let (body, _) = c.to_request();
        assert_eq!(body["local-tx-speed"], "50000000");
        assert_eq!(body["remote-tx-speed"], "25000000");
    }

    /// Captured verbatim from a hAP ac³, RouterOS 7.24.2, TCP receive.
    fn real_receive_response() -> Value {
        json!([
            {".section":"0","status":"connecting","direction":"receive"},
            {".section":"6","connection-count":"20","direction":"receive","duration":"6s",
             "local-cpu-load":"64","random-data":"false","rx-10-second-average":"621022992",
             "rx-current":"628332032","rx-total-average":"621022992","status":"done testing"}
        ])
    }

    #[test]
    fn parses_a_real_receive_response() {
        let r = parse(&real_receive_response(), &cfg(Direction::Receive, Protocol::Tcp)).unwrap();
        assert_eq!(r.rx_bps, Some(621_022_992));
        assert_eq!(r.tx_bps, None, "a receive test measures only one direction");
        assert_eq!(r.local_cpu_load, Some(64));
        assert_eq!(r.duration_s, 6);
        assert_eq!(r.connection_count, Some(20));
        assert_eq!(r.status, "done testing");
        assert_eq!(r.source, "routeros_host");
    }

    #[test]
    fn parses_a_real_transmit_response_including_the_far_end_cpu() {
        // Captured from the same pair, UDP transmit.
        let raw = json!([
            {".section":"0","status":"connecting"},
            {".section":"4","direction":"transmit","duration":"4s","local-cpu-load":"64",
             "remote-cpu-load":"36","tx-total-average":"954335872","tx-current":"960000000",
             "lost-packets":"1423","status":"done testing"}
        ]);
        let r = parse(&raw, &cfg(Direction::Transmit, Protocol::Udp)).unwrap();
        assert_eq!(r.tx_bps, Some(954_335_872));
        assert_eq!(r.remote_cpu_load, Some(36), "transmit reports the far end too");
        assert_eq!(r.lost_packets, Some(1423));
    }

    #[test]
    fn only_the_last_section_counts() {
        // Earlier sections are progress, not results. Reading the first would
        // report the speed during connection setup.
        let raw = json!([
            {".section":"0","status":"running","rx-total-average":"1000"},
            {".section":"1","status":"running","rx-total-average":"50000"},
            {".section":"2","status":"done testing","rx-total-average":"621022992"}
        ]);
        let r = parse(&raw, &cfg(Direction::Receive, Protocol::Tcp)).unwrap();
        assert_eq!(r.rx_bps, Some(621_022_992));
    }

    #[test]
    fn a_saturated_cpu_says_the_number_measures_the_router() {
        let raw = json!([{".section":"0","status":"done testing",
                          "rx-total-average":"300000000","local-cpu-load":"99"}]);
        let r = parse(&raw, &cfg(Direction::Receive, Protocol::Tcp)).unwrap();
        assert_eq!(r.cpu_verdict, CpuVerdict::RouterLimited);
        assert!(r.notes.iter().any(|n| n.contains("measures the router")), "{:?}", r.notes);
    }

    #[test]
    fn a_busy_cpu_says_treat_the_figure_as_a_floor() {
        let raw = json!([{".section":"0","status":"done testing",
                          "rx-total-average":"621022992","local-cpu-load":"75"}]);
        let r = parse(&raw, &cfg(Direction::Receive, Protocol::Tcp)).unwrap();
        assert_eq!(r.cpu_verdict, CpuVerdict::RouterContributing);
        assert!(r.notes.iter().any(|n| n.contains("floor")), "{:?}", r.notes);
    }

    #[test]
    fn an_idle_cpu_gets_no_caveat() {
        let raw = json!([{".section":"0","status":"done testing",
                          "rx-total-average":"100000000","local-cpu-load":"12"}]);
        let r = parse(&raw, &cfg(Direction::Receive, Protocol::Tcp)).unwrap();
        assert_eq!(r.cpu_verdict, CpuVerdict::LinkLimited);
        assert!(r.notes.is_empty(), "{:?}", r.notes);
    }

    #[test]
    fn the_worse_of_the_two_cpus_decides_the_verdict() {
        // A far end at 95% limits the test just as surely as a local one.
        let raw = json!([{".section":"0","status":"done testing","tx-total-average":"1000",
                          "local-cpu-load":"20","remote-cpu-load":"95"}]);
        let r = parse(&raw, &cfg(Direction::Transmit, Protocol::Tcp)).unwrap();
        assert_eq!(r.cpu_verdict, CpuVerdict::RouterLimited);
    }

    #[test]
    fn bidirectional_results_warn_that_the_streams_contend() {
        let raw = json!([{".section":"0","status":"done testing",
                          "tx-total-average":"400000000","rx-total-average":"380000000",
                          "local-cpu-load":"30"}]);
        let r = parse(&raw, &cfg(Direction::Both, Protocol::Tcp)).unwrap();
        assert!(r.tx_bps.is_some() && r.rx_bps.is_some());
        assert!(r.notes.iter().any(|n| n.contains("contend")), "{:?}", r.notes);
    }

    #[test]
    fn udp_loss_is_reported_and_explained_but_tcp_loss_is_not() {
        let raw = json!([{".section":"0","status":"done testing","tx-total-average":"1000",
                          "lost-packets":"500","local-cpu-load":"10"}]);

        let udp = parse(&raw, &cfg(Direction::Transmit, Protocol::Udp)).unwrap();
        assert_eq!(udp.lost_packets, Some(500));
        assert!(udp.notes.iter().any(|n| n.contains("expected")), "{:?}", udp.notes);

        // TCP never offers more than the path accepts, so a loss figure there
        // would be meaningless even if RouterOS emitted one.
        let tcp = parse(&raw, &cfg(Direction::Transmit, Protocol::Tcp)).unwrap();
        assert_eq!(tcp.lost_packets, None);
    }

    #[test]
    fn a_refusal_becomes_an_error_naming_the_likely_cause() {
        // RouterOS reports "cannot connect" in the same shape as a result, so
        // without this the caller would record 0 bps as a measurement.
        let raw = json!([{".section":"0","status":"connecting"}]);
        let err = parse(&raw, &cfg(Direction::Receive, Protocol::Tcp)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bandwidth-server"), "{msg}");
        assert!(msg.contains("test"), "should name the policy needed: {msg}");
    }

    #[test]
    fn malformed_responses_are_rejected() {
        let c = cfg(Direction::Receive, Protocol::Tcp);
        assert!(parse(&json!({}), &c).is_err());
        assert!(parse(&json!([]), &c).is_err());
    }

    #[test]
    fn duration_parses_every_unit_routeros_uses() {
        assert_eq!(parse_secs("6s"), 6);
        assert_eq!(parse_secs("1m30s"), 90);
        assert_eq!(parse_secs("1h"), 3600);
        assert_eq!(parse_secs(""), 0);
    }
}
