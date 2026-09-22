//! Standalone sub-commands for testing against real hardware.
//!
//! The agent's normal mode needs a controller to grant sessions before the
//! reflector will answer anything. That is correct for production — an
//! unsolicited-packet responder is a liability — but it makes the data plane
//! impossible to exercise until the whole control plane exists.
//!
//! `reflect` and `probe` short-circuit that: both take an explicit session ID,
//! so a pair of them can measure a real path with no controller involved.
//!
//! Arguments are parsed by hand rather than with clap. The agent ships to
//! devices with 128 MB of flash, and an argument parser is not worth a few
//! hundred kilobytes of the budget.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};

use crate::collector::mos::{self, Codec, MosInput};
use crate::collector::stats;
use crate::probe::reflector::{Reflector, Registry};
use crate::probe::sender::{self, ProbeConfig};
use crate::proto::mqp::DEFAULT_PACKET_LEN;

pub const USAGE: &str = "\
mqagent — MikroTik network quality agent

USAGE:
    mqagent                        Run as a managed agent (requires MQ_* env vars)
    mqagent reflect [OPTIONS]      Standalone reflector, no controller needed
    mqagent probe   [OPTIONS]      Standalone sender, no controller needed
    mqagent discover [OPTIONS]     Survey the local network via a RouterOS device
    mqagent trace    [OPTIONS]     Traceroute from a RouterOS device, with analysis
    mqagent scan     [OPTIONS]     IP-scan a range from a RouterOS device
    mqagent twamp-reflect [OPTIONS]  TWAMP-Light responder (RouterOS has none)
    mqagent twamp-probe   [OPTIONS]  Measure against any TWAMP-Light responder
    mqagent btest    [OPTIONS]     Throughput test via the router's own hardware
    mqagent capture  [OPTIONS]     Packet or 802.11 capture, to name a talker
    mqagent --help

REFLECT OPTIONS:
    --port <PORT>        MQP listen port                    [default: 5301]
    --session <HEX>      Session ID to accept               [default: 1]
    --peer <IP>          Only accept from this address      [default: any]
    --twamp-port <PORT>  Also answer TWAMP-Light here (separate socket)
    --twamp-peer <IP>    Source permitted to TWAMP; repeatable

PROBE OPTIONS:
    --peer <IP[:PORT]>   Target reflector                   [required]
    --session <HEX>      Session ID, must match the peer    [default: 1]
    --count <N>          Packets to send                    [default: 100]
    --interval <MS>      Gap between packets                [default: 20]
    --size <BYTES>       Total packet size, 56..1400        [default: 172]
    --dscp <0-63>        DSCP to mark, e.g. 46 for EF       [default: none]
    --timeout <MS>       Per-packet reply timeout           [default: 1000]
    --codec <NAME>       g711|g711plc|g729|g722|opus for MOS [default: g711]
    --json               Emit JSON instead of a text report

DISCOVER OPTIONS:
    --host <IP>          RouterOS device to survey             [required]
    --port <PORT>        REST port                  [default: 80, or 443 with --tls]
    --user <NAME>        RouterOS username                     [default: admin]
    --pass <SECRET>      RouterOS password                     [default: empty]
    --tls                Use HTTPS (accepts self-signed certs)
    --json               Emit JSON instead of a report

EXAMPLE — measure the path to a router running `mqagent reflect`:
    mqagent probe --peer 172.16.220.138 --session cafe --count 300 --dscp 46

TRACE OPTIONS:   (plus the RouterOS options above)
    --target <IP>        Where to trace to                     [required]
    --count <N>          Probes per hop                        [default: 3]

SCAN OPTIONS:    (plus the RouterOS options above)
    --range <CIDR|RANGE> What to scan, e.g. 192.168.88.0/24    [required]
    --duration <S>       How long to scan                      [default: 10]

EXAMPLE — find out why a site is slow:
    mqagent discover --host 172.16.220.1 --user claude

TWAMP-REFLECT OPTIONS:
    --port <PORT>        Listen port (862 is the registered one)  [default: 862]
    --peer <IP>          Permit this source; repeatable. Omit to answer anyone,
                         which is safe only behind a restrictive firewall.

TWAMP-PROBE OPTIONS:
    --peer <IP[:PORT]>   Responder to measure                     [required]
    --count <N>          Packets to send                          [default: 100]
    --interval <MS>      Gap between packets                      [default: 20]
    --size <BYTES>       Total packet size, 14..1400              [default: 41]
    --dscp <0-63>        DSCP to mark
    --timeout <MS>       Per-packet reply timeout                 [default: 1000]
    --codec <NAME>       Codec for MOS scoring                    [default: g711]
    --json               Emit JSON instead of a report

EXAMPLE — find where the latency is introduced:
    mqagent trace --host 172.16.220.1 --user claude --target 1.1.1.1

BTEST OPTIONS:   (plus the RouterOS options above)
    --target <IP>        Far end, running /tool/bandwidth-server   [required]
    --direction <DIR>    rx | tx | both                            [default: rx]
    --protocol <PROTO>   tcp | udp                                 [default: tcp]
    --duration <S>       Seconds, capped at 45 by the REST limit   [default: 10]
    --bt-user <NAME>     User on the FAR router, needs `test` policy
    --bt-pass <SECRET>   Its password
    --connections <N>    TCP streams
    --limit <BPS>        Cap the offered rate, to spare a live link

CAPTURE OPTIONS: (plus the RouterOS options above)
    --interface <NAME>   Capture here; omit for all interfaces
    --duration <S>       Seconds, capped at 60                     [default: 10]
    --wireless           Capture 802.11 frames (legacy wireless stack only)
    --hop                Hop channels during a wireless capture — disruptive

EXAMPLE — let a MikroTik answer TWAMP, which RouterOS cannot do itself:
    mqagent twamp-reflect --port 862 --peer 203.0.113.7

EXAMPLE — find which host is flooding a LAN:
    mqagent capture --host 172.16.220.1 --user claude --duration 15
";

#[derive(Debug, PartialEq)]
pub enum Command {
    Agent,
    Help,
    Reflect(ReflectArgs),
    Probe(Box<ProbeArgs>),
    Discover(Box<DiscoverArgs>),
    Trace(Box<TraceArgs>),
    Scan(Box<ScanArgs>),
    TwampReflect(TwampReflectArgs),
    TwampProbe(Box<TwampProbeArgs>),
    Btest(Box<BtestArgs>),
    Capture(Box<CaptureArgs>),
}

#[derive(Debug, PartialEq)]
pub struct BtestArgs {
    pub ros: DiscoverArgs,
    pub target: String,
    pub direction: crate::routeros::btest::Direction,
    pub protocol: crate::routeros::btest::Protocol,
    pub duration_s: u64,
    pub bt_user: String,
    pub bt_pass: String,
    pub connections: Option<u32>,
    pub limit_bps: Option<u64>,
}

#[derive(Debug, PartialEq)]
pub struct CaptureArgs {
    pub ros: DiscoverArgs,
    pub interface: String,
    pub duration_s: u64,
    /// Capture 802.11 frames instead of IP traffic. Legacy wireless stack only.
    pub wireless: bool,
    /// Hop channels during a wireless capture. Sees neighbours, but leaves our
    /// own channel repeatedly and so interrupts associated clients.
    pub hop: bool,
}

#[derive(Debug, PartialEq)]
pub struct TwampReflectArgs {
    pub port: u16,
    /// Sources permitted to be answered. Empty means answer anyone, which is
    /// only appropriate behind a firewall that already restricts the port.
    pub peers: Vec<std::net::IpAddr>,
}

#[derive(Debug, PartialEq)]
pub struct TwampProbeArgs {
    pub peer: SocketAddr,
    pub count: u32,
    pub interval_ms: u64,
    pub size: usize,
    pub dscp: Option<u8>,
    pub timeout_ms: u64,
    pub codec: Codec,
    pub json: bool,
}

#[derive(Debug, PartialEq)]
pub struct TraceArgs {
    pub ros: DiscoverArgs,
    pub target: String,
    pub count: u32,
}

#[derive(Debug, PartialEq)]
pub struct ScanArgs {
    pub ros: DiscoverArgs,
    /// Address range or CIDR, e.g. `192.168.88.0/24`.
    pub range: String,
    pub duration_s: u32,
}

#[derive(Debug, PartialEq)]
pub struct DiscoverArgs {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub tls: bool,
    pub json: bool,
}

#[derive(Debug, PartialEq)]
pub struct ReflectArgs {
    pub port: u16,
    pub session: u64,
    pub peer: Option<std::net::IpAddr>,
    /// When set, a TWAMP-Light responder runs alongside the MQP reflector on
    /// this port.
    ///
    /// One container then answers both our own mesh and third parties. They
    /// cannot share a socket: MQP's magic and a TWAMP sequence number can
    /// collide, and a packet matching both would be parsed as whichever was
    /// tried first.
    pub twamp_port: Option<u16>,
    pub twamp_peers: Vec<std::net::IpAddr>,
}

#[derive(Debug, PartialEq)]
pub struct ProbeArgs {
    pub peer: SocketAddr,
    pub session: u64,
    pub count: u32,
    pub interval_ms: u64,
    pub size: usize,
    pub dscp: Option<u8>,
    pub timeout_ms: u64,
    pub codec: Codec,
    pub json: bool,
}

/// Build a standalone command from environment variables.
///
/// RouterOS parameterises containers through `/container/envs` envlists and
/// does not reliably forward the `cmd` property into the container's argv — a
/// container created with `cmd="reflect --session cafe"` starts with an empty
/// argv and silently falls through to managed mode. Environment variables are
/// the native and dependable mechanism on that platform, so the standalone
/// modes accept them too.
///
/// Returns `None` when `MQ_MODE` is unset or names the managed agent.
pub fn from_env<F>(get: F) -> Option<Result<Command, String>>
where
    F: Fn(&str) -> Option<String>,
{
    let mode = get("MQ_MODE")?.trim().to_ascii_lowercase();

    let sess = |d: u64| -> Result<u64, String> {
        match get("MQ_SESSION") {
            Some(s) => u64::from_str_radix(s.trim().trim_start_matches("0x"), 16)
                .map_err(|_| format!("MQ_SESSION {s:?} is not hexadecimal")),
            None => Ok(d),
        }
    };
    let port = || -> Result<u16, String> { num(get("MQ_PROBE_PORT").as_deref(), 5301, "MQ_PROBE_PORT") };
    let dscp = || -> Result<Option<u8>, String> {
        match get("MQ_DSCP") {
            Some(d) if !d.trim().is_empty() => {
                let v: u8 = d.trim().parse().map_err(|_| format!("MQ_DSCP {d:?} is not a number"))?;
                if v > 63 {
                    return Err(format!("MQ_DSCP {v} is out of range (0-63)"));
                }
                Ok(Some(v))
            }
            _ => Ok(None),
        }
    };

    Some((|| match mode.as_str() {
        "agent" => Ok(Command::Agent),
        "reflect" => Ok(Command::Reflect(ReflectArgs {
            port: port()?,
            session: sess(1)?,
            peer: match get("MQ_PEER_IP") {
                Some(p) if !p.trim().is_empty() => {
                    Some(p.trim().parse().map_err(|_| format!("MQ_PEER_IP {p:?} is not an IP"))?)
                }
                _ => None,
            },
            // Setting MQ_TWAMP_PORT alongside reflect mode is how one
            // container comes to answer both protocols on a router.
            twamp_port: match get("MQ_TWAMP_PORT") {
                Some(v) if !v.trim().is_empty() => Some(
                    v.trim().parse().map_err(|_| format!("MQ_TWAMP_PORT {v:?} is not a port"))?,
                ),
                _ => None,
            },
            twamp_peers: twamp_peers(&get)?,
        })),
        "probe" => {
            let peer = get("MQ_PEER").ok_or("MQ_MODE=probe requires MQ_PEER")?;
            let peer = peer.trim();
            let peer: SocketAddr = if peer.contains(':') {
                peer.parse().map_err(|_| format!("MQ_PEER {peer:?} is not addr:port"))?
            } else {
                format!("{peer}:{}", port()?)
                    .parse()
                    .map_err(|_| format!("MQ_PEER {peer:?} is not an IP"))?
            };
            Ok(Command::Probe(Box::new(ProbeArgs {
                peer,
                session: sess(1)?,
                count: num(get("MQ_COUNT").as_deref(), 100, "MQ_COUNT")?,
                interval_ms: num(get("MQ_INTERVAL_MS").as_deref(), 20, "MQ_INTERVAL_MS")?,
                size: num(get("MQ_SIZE").as_deref(), DEFAULT_PACKET_LEN, "MQ_SIZE")?,
                dscp: dscp()?,
                timeout_ms: num(get("MQ_TIMEOUT_MS").as_deref(), 1000, "MQ_TIMEOUT_MS")?,
                codec: codec(get("MQ_CODEC").as_deref())?,
                json: matches!(
                    get("MQ_JSON").as_deref().map(str::trim),
                    Some("1" | "true" | "yes" | "on")
                ),
            })))
        }
        // RouterOS does not forward a container's cmd into argv, so every mode
        // that might run on a router has to be reachable from the environment.
        "twamp-reflect" => Ok(Command::TwampReflect(TwampReflectArgs {
            port: num(get("MQ_TWAMP_PORT").as_deref(), 862, "MQ_TWAMP_PORT")?,
            peers: twamp_peers(&get)?,
        })),
        other => Err(format!(
            "MQ_MODE {other:?} is not one of: agent, reflect, probe, twamp-reflect"
        )),
    })())
}

/// Parse the comma-separated TWAMP allow-list from the environment.
fn twamp_peers<F>(get: &F) -> Result<Vec<std::net::IpAddr>, String>
where
    F: Fn(&str) -> Option<String>,
{
    match get("MQ_TWAMP_PEERS") {
        Some(v) if !v.trim().is_empty() => v
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| {
                p.parse::<std::net::IpAddr>()
                    .map_err(|_| format!("MQ_TWAMP_PEERS entry {p:?} is not an IP"))
            })
            .collect(),
        _ => Ok(vec![]),
    }
}

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Command, String> {
    let mut it = args.into_iter().skip(1).peekable();

    let sub = match it.next() {
        None => return Ok(Command::Agent),
        Some(s) if s == "--help" || s == "-h" || s == "help" => return Ok(Command::Help),
        Some(s) => s,
    };

    // Collect --key value pairs plus bare flags.
    let mut flags: Vec<String> = Vec::new();
    let mut kv: Vec<(String, String)> = Vec::new();
    while let Some(tok) = it.next() {
        let Some(key) = tok.strip_prefix("--") else {
            return Err(format!("unexpected argument {tok:?}"));
        };
        if matches!(key, "json" | "tls" | "wireless" | "hop") {
            flags.push(key.to_string());
            continue;
        }
        let val = it.next().ok_or_else(|| format!("--{key} needs a value"))?;
        kv.push((key.to_string(), val));
    }
    let get = |name: &str| kv.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());

    match sub.as_str() {
        "reflect" => Ok(Command::Reflect(ReflectArgs {
            port: num(get("port"), 5301, "port")?,
            session: session_id(get("session"))?,
            peer: match get("peer") {
                Some(p) => Some(p.parse().map_err(|_| format!("--peer {p:?} is not an IP"))?),
                None => None,
            },
            twamp_port: match get("twamp-port") {
                Some(v) => Some(
                    v.parse().map_err(|_| format!("--twamp-port {v:?} is not a port"))?,
                ),
                None => None,
            },
            twamp_peers: kv
                .iter()
                .filter(|(k, _)| k == "twamp-peer")
                .map(|(_, v)| {
                    v.parse::<std::net::IpAddr>()
                        .map_err(|_| format!("--twamp-peer {v:?} is not an IP"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        })),
        "probe" => {
            let peer = get("peer").ok_or("probe requires --peer")?;
            // Accept a bare IP and supply the default port, since the port is
            // the same on both ends in every normal deployment.
            let peer: SocketAddr = if peer.contains(':') {
                peer.parse().map_err(|_| format!("--peer {peer:?} is not addr:port"))?
            } else {
                format!("{peer}:5301")
                    .parse()
                    .map_err(|_| format!("--peer {peer:?} is not an IP"))?
            };

            let dscp = match get("dscp") {
                Some(d) => {
                    let v: u8 = d.parse().map_err(|_| format!("--dscp {d:?} is not a number"))?;
                    if v > 63 {
                        return Err(format!("--dscp {v} is out of range (0-63)"));
                    }
                    Some(v)
                }
                None => None,
            };

            Ok(Command::Probe(Box::new(ProbeArgs {
                peer,
                session: session_id(get("session"))?,
                count: num(get("count"), 100, "count")?,
                interval_ms: num(get("interval"), 20, "interval")?,
                size: num(get("size"), DEFAULT_PACKET_LEN, "size")?,
                dscp,
                timeout_ms: num(get("timeout"), 1000, "timeout")?,
                codec: codec(get("codec"))?,
                json: flags.iter().any(|f| f == "json"),
            })))
        }
        "twamp-reflect" => Ok(Command::TwampReflect(TwampReflectArgs {
            port: num(get("port"), 862, "port")?,
            peers: kv
                .iter()
                .filter(|(k, _)| k == "peer")
                .map(|(_, v)| {
                    v.parse::<std::net::IpAddr>()
                        .map_err(|_| format!("--peer {v:?} is not an IP address"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        })),
        "twamp-probe" => {
            let peer = get("peer").ok_or("twamp-probe requires --peer")?;
            let peer: SocketAddr = if peer.contains(':') {
                peer.parse().map_err(|_| format!("--peer {peer:?} is not addr:port"))?
            } else {
                // 862 is the registered TWAMP port; a bare IP means that.
                format!("{peer}:862").parse().map_err(|_| format!("--peer {peer:?} is not an IP"))?
            };
            let dscp = match get("dscp") {
                Some(d) => {
                    let v: u8 = d.parse().map_err(|_| format!("--dscp {d:?} is not a number"))?;
                    if v > 63 {
                        return Err(format!("--dscp {v} is out of range (0-63)"));
                    }
                    Some(v)
                }
                None => None,
            };
            Ok(Command::TwampProbe(Box::new(TwampProbeArgs {
                peer,
                count: num(get("count"), 100, "count")?,
                interval_ms: num(get("interval"), 20, "interval")?,
                size: num(get("size"), crate::proto::twamp::DEFAULT_PACKET_LEN, "size")?,
                dscp,
                timeout_ms: num(get("timeout"), 1000, "timeout")?,
                codec: codec(get("codec"))?,
                json: flags.iter().any(|f| f == "json"),
            })))
        }
        "btest" => {
            use crate::routeros::btest::{Direction, Protocol};
            let ros = ros_args(&get, &flags)?;
            Ok(Command::Btest(Box::new(BtestArgs {
                target: get("target").ok_or("btest requires --target")?.to_string(),
                direction: Direction::parse(get("direction").unwrap_or("rx"))
                    .ok_or("--direction must be rx, tx or both")?,
                protocol: Protocol::parse(get("protocol").unwrap_or("tcp"))
                    .ok_or("--protocol must be tcp or udp")?,
                duration_s: num(get("duration"), 10, "duration")?,
                bt_user: get("bt-user").unwrap_or("").to_string(),
                bt_pass: get("bt-pass").unwrap_or("").to_string(),
                connections: match get("connections") {
                    Some(v) => Some(v.parse().map_err(|_| "--connections is not a number")?),
                    None => None,
                },
                limit_bps: match get("limit") {
                    Some(v) => Some(v.parse().map_err(|_| "--limit is not a number")?),
                    None => None,
                },
                ros,
            })))
        }
        "capture" => {
            let ros = ros_args(&get, &flags)?;
            Ok(Command::Capture(Box::new(CaptureArgs {
                interface: get("interface").unwrap_or("").to_string(),
                duration_s: num(get("duration"), 10, "duration")?,
                wireless: flags.iter().any(|f| f == "wireless"),
                hop: flags.iter().any(|f| f == "hop"),
                ros,
            })))
        }
        "trace" => {
            let ros = ros_args(&get, &flags)?;
            Ok(Command::Trace(Box::new(TraceArgs {
                target: get("target").ok_or("trace requires --target")?.to_string(),
                count: num(get("count"), 3, "count")?,
                ros,
            })))
        }
        "scan" => {
            let ros = ros_args(&get, &flags)?;
            Ok(Command::Scan(Box::new(ScanArgs {
                range: get("range").ok_or("scan requires --range")?.to_string(),
                duration_s: num(get("duration"), 10, "duration")?,
                ros,
            })))
        }
        "discover" => {
            let tls = flags.iter().any(|f| f == "tls");
            Ok(Command::Discover(Box::new(DiscoverArgs {
                host: get("host").ok_or("discover requires --host")?.to_string(),
                port: num(get("port"), if tls { 443 } else { 80 }, "port")?,
                user: get("user").unwrap_or("admin").to_string(),
                // A blank password is normal on lab and factory-default
                // routers, so an absent --pass means empty, not an error.
                pass: get("pass").unwrap_or("").to_string(),
                tls,
                json: flags.iter().any(|f| f == "json"),
            })))
        }
        other => Err(format!("unknown command {other:?} — try --help")),
    }
}

/// Shared RouterOS connection options, used by discover, trace and scan.
fn ros_args<'a, F>(get: &F, flags: &[String]) -> Result<DiscoverArgs, String>
where
    F: Fn(&str) -> Option<&'a str>,
{
    let tls = flags.iter().any(|f| f == "tls");
    Ok(DiscoverArgs {
        host: get("host").ok_or("--host is required")?.to_string(),
        port: num(get("port"), if tls { 443 } else { 80 }, "port")?,
        user: get("user").unwrap_or("admin").to_string(),
        pass: get("pass").unwrap_or("").to_string(),
        tls,
        json: flags.iter().any(|f| f == "json"),
    })
}

fn num<T: std::str::FromStr>(v: Option<&str>, default: T, name: &str) -> Result<T, String> {
    match v {
        Some(s) => s.parse().map_err(|_| format!("--{name} {s:?} is not a number")),
        None => Ok(default),
    }
}

/// Session IDs are hex, to match how they appear in logs and on the wire.
fn session_id(v: Option<&str>) -> Result<u64, String> {
    match v {
        None => Ok(1),
        Some(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|_| format!("--session {s:?} is not hexadecimal")),
    }
}

fn codec(v: Option<&str>) -> Result<Codec, String> {
    Ok(match v.unwrap_or("g711").to_ascii_lowercase().as_str() {
        "g711" => Codec::G711,
        "g711plc" => Codec::G711Plc,
        "g729" => Codec::G729,
        "g722" => Codec::G722,
        "opus" => Codec::Opus,
        other => return Err(format!("unknown codec {other:?}")),
    })
}

// --- runners -------------------------------------------------------------

pub async fn run_reflect(args: ReflectArgs) -> anyhow::Result<()> {
    let registry = Arc::new(Mutex::new(Registry::new()));
    let bind: SocketAddr = ([0, 0, 0, 0], args.port).into();
    let reflector = Reflector::bind(bind, registry.clone()).await?;
    let actual = reflector.local_addr()?;

    // The registry matches a grant by IP. Without --peer, accept any source:
    // this is a test mode, and requiring the sender's ephemeral port up front
    // would make it unusable.
    let peer_filter: SocketAddr = match args.peer {
        Some(ip) => (ip, 0).into(),
        None => ([0, 0, 0, 0], 0).into(),
    };
    registry.lock().await.grant(args.session, peer_filter);

    eprintln!("MQP reflector listening on {actual}");
    eprintln!("session {:016x} granted to {}", args.session,
        args.peer.map(|p| p.to_string()).unwrap_or_else(|| "any address".into()));

    let (tx, rx) = watch::channel(false);
    let mut tasks = vec![tokio::spawn(reflector.run(rx.clone()))];

    // A second socket, not a second process: MQP's magic and a TWAMP sequence
    // number can collide, so they cannot share a port.
    if let Some(tport) = args.twamp_port {
        use crate::probe::twamp::{AllowList, TwampReflector};

        let mut allow =
            if args.twamp_peers.is_empty() { AllowList::open() } else { AllowList::new() };
        for p in &args.twamp_peers {
            allow.allow(*p);
        }
        let tbind: SocketAddr = ([0, 0, 0, 0], tport).into();
        let tr = TwampReflector::bind(tbind, Arc::new(Mutex::new(allow)))
            .await
            .map_err(|e| anyhow::anyhow!("could not bind {tbind}: {e}{}", port_hint(tport)))?;
        eprintln!("TWAMP-Light responder listening on {}", tr.local_addr()?);
        if args.twamp_peers.is_empty() {
            eprintln!("WARNING: TWAMP answering any source — restrict with --twamp-peer");
        } else {
            eprintln!("TWAMP answering: {}", args.twamp_peers.iter().map(|p| p.to_string())
                .collect::<Vec<_>>().join(", "));
        }
        tasks.push(tokio::spawn(tr.run(rx)));
    }

    eprintln!("press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    let _ = tx.send(true);
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

pub async fn run_probe(args: ProbeArgs) -> anyhow::Result<()> {
    let cfg = ProbeConfig {
        session_id: args.session,
        peer: args.peer,
        count: args.count,
        interval: Duration::from_millis(args.interval_ms),
        payload_bytes: args.size,
        dscp: args.dscp,
        timeout: Duration::from_millis(args.timeout_ms),
        linger: Duration::from_secs(2),
    };

    if !args.json {
        eprintln!(
            "probing {} — {} packets, {} ms apart, {} bytes{}",
            cfg.peer,
            cfg.count,
            args.interval_ms,
            cfg.payload_bytes,
            args.dscp.map(|d| format!(", DSCP {d}")).unwrap_or_default()
        );
    }

    let run = sender::run(&cfg).await?;
    let m = stats::summarise(run.sent, &run.samples, args.dscp);

    let score = m.rtt.zip(m.jitter).map(|(r, j)| {
        mos::score(MosInput::new(r.avg_us, j.ipdv_avg_us, m.loss.loss_pct, args.codec))
    });

    if args.json {
        let out = serde_json::json!({
            "peer": cfg.peer.to_string(),
            "session_id": format!("{:016x}", args.session),
            "metrics": m,
            "mos": score,
            "late_ticks": run.late_ticks,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_report(&m, score.as_ref(), run.late_ticks);
    }

    // A run where nothing came back is a successful measurement of a broken
    // path, but scripts need to tell it from a healthy one.
    if m.loss.received == 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn print_report(m: &stats::ProbeMetrics, score: Option<&mos::MosScore>, late: u32) {
    println!();
    match &m.rtt {
        Some(r) => {
            println!("RTT       min {:.3} ms  avg {:.3} ms  max {:.3} ms  stddev {:.3} ms",
                ms(r.min_us), ms(r.avg_us), ms(r.max_us), ms(r.stddev_us));
            println!("          p50 {:.3} ms  p95 {:.3} ms  p99 {:.3} ms",
                ms(r.p50_us), ms(r.p95_us), ms(r.p99_us));
        }
        None => println!("RTT       no replies"),
    }

    match &m.jitter {
        Some(j) => println!("Jitter    IPDV avg {:.3} ms  PDV p95 {:.3} ms",
            ms(j.ipdv_avg_us), ms(j.pdv_p95_us)),
        None => println!("Jitter    insufficient data"),
    }

    let l = &m.loss;
    print!("Loss      {}/{} lost ({:.2}%)", l.sent - l.received, l.sent, l.loss_pct);
    if l.forward_lost > 0 || l.reverse_lost > 0 {
        print!("  [forward {} · reverse {}]", l.forward_lost, l.reverse_lost);
    }
    if l.unknown_direction > 0 {
        print!("  [{} undetermined]", l.unknown_direction);
    }
    println!();

    let r = &m.reorder;
    println!("Order     {} reordered (max displacement {})  {} duplicated",
        r.reordered, r.max_displacement, r.duplicated);

    match &m.dscp {
        Some(d) => println!("DSCP      requested {}  observed {}  conformant {:.1}%",
            d.requested, d.observed_mode, d.conformant_pct),
        None => println!("DSCP      not echoed by peer"),
    }

    if let Some(s) = score {
        println!("Voice     MOS {:.2}  R-factor {:.1}  ({:?}, {:.0} ms effective delay)",
            s.mos, s.r_factor, s.codec, s.effective_delay_ms);
    }

    if late > 0 {
        // Without this the operator would read a gentler-than-requested test
        // as if it had run at the configured rate.
        println!("\nNote: {late} send ticks were late — this device could not sustain the");
        println!("      requested rate, so the offered load was lower than configured.");
    }
}

fn ms(us: u64) -> f64 {
    us as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &[&str]) -> Vec<String> {
        std::iter::once("mqagent".to_string()).chain(s.iter().map(|x| x.to_string())).collect()
    }

    #[test]
    fn no_arguments_runs_the_managed_agent() {
        assert_eq!(parse(argv(&[])).unwrap(), Command::Agent);
    }

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn unset_mq_mode_leaves_the_agent_in_managed_mode() {
        assert!(from_env(env(&[])).is_none());
    }

    #[test]
    fn env_can_select_reflect_mode() {
        // The case that matters on RouterOS: `cmd` is not forwarded into argv,
        // so without this the container silently falls through to managed mode
        // and dies asking for MQ_CONTROLLER_URL.
        let c = from_env(env(&[("MQ_MODE", "reflect"), ("MQ_SESSION", "cafe"), ("MQ_PROBE_PORT", "5301")]))
            .unwrap()
            .unwrap();
        let Command::Reflect(r) = c else { panic!("expected reflect") };
        assert_eq!(r.session, 0xcafe);
        assert_eq!(r.port, 5301);
        assert!(r.peer.is_none());
    }

    #[test]
    fn env_can_select_probe_mode_with_a_bare_peer_ip() {
        let c = from_env(env(&[
            ("MQ_MODE", "probe"),
            ("MQ_PEER", "172.16.220.138"),
            ("MQ_SESSION", "cafe"),
            ("MQ_COUNT", "300"),
            ("MQ_DSCP", "46"),
        ]))
        .unwrap()
        .unwrap();
        let Command::Probe(p) = c else { panic!("expected probe") };
        assert_eq!(p.peer, "172.16.220.138:5301".parse::<SocketAddr>().unwrap());
        assert_eq!(p.count, 300);
        assert_eq!(p.dscp, Some(46));
        assert_eq!(p.session, 0xcafe);
    }

    #[test]
    fn env_probe_without_a_peer_is_rejected() {
        let err = from_env(env(&[("MQ_MODE", "probe")])).unwrap().unwrap_err();
        assert!(err.contains("MQ_PEER"), "got {err}");
    }

    #[test]
    fn env_rejects_an_unknown_mode_rather_than_defaulting() {
        // Defaulting a typo'd MQ_MODE to managed mode would be a silent
        // misconfiguration that only shows up as "no measurements".
        let err = from_env(env(&[("MQ_MODE", "reflct")])).unwrap().unwrap_err();
        assert!(err.contains("not one of"), "got {err}");
    }

    #[test]
    fn reflect_mode_can_run_both_protocols_from_the_environment() {
        // One container answering our own mesh and third parties at once, which
        // is what restores DSCP conformance toward a shared upstream.
        let c = from_env(env(&[
            ("MQ_MODE", "reflect"),
            ("MQ_PROBE_PORT", "5401"),
            ("MQ_SESSION", "cafe"),
            ("MQ_TWAMP_PORT", "862"),
            ("MQ_TWAMP_PEERS", "162.216.190.1"),
        ]))
        .unwrap()
        .unwrap();
        let Command::Reflect(r) = c else { panic!("expected reflect") };
        assert_eq!(r.port, 5401);
        assert_eq!(r.twamp_port, Some(862), "TWAMP should run alongside MQP");
        assert_eq!(r.twamp_peers.len(), 1);
        assert_ne!(r.port, r.twamp_port.unwrap(), "they cannot share a socket");
    }

    #[test]
    fn reflect_without_a_twamp_port_stays_mqp_only() {
        let c = from_env(env(&[("MQ_MODE", "reflect")])).unwrap().unwrap();
        let Command::Reflect(r) = c else { panic!("expected reflect") };
        assert!(r.twamp_port.is_none());
    }

    #[test]
    fn reflect_accepts_both_protocols_on_the_command_line() {
        let Command::Reflect(r) = parse(argv(&[
            "reflect", "--port", "5401", "--twamp-port", "862",
            "--twamp-peer", "10.0.0.1", "--twamp-peer", "10.0.0.2",
        ]))
        .unwrap() else {
            panic!("expected reflect")
        };
        assert_eq!(r.twamp_port, Some(862));
        assert_eq!(r.twamp_peers.len(), 2, "--twamp-peer must be repeatable");
    }

    #[test]
    fn env_can_select_the_twamp_responder() {
        // The mode most likely to run on a router, since RouterOS has no TWAMP
        // of its own — and argv is not delivered there.
        let c = from_env(env(&[
            ("MQ_MODE", "twamp-reflect"),
            ("MQ_TWAMP_PORT", "862"),
            ("MQ_TWAMP_PEERS", "203.0.113.7, 198.51.100.9"),
        ]))
        .unwrap()
        .unwrap();
        let Command::TwampReflect(r) = c else { panic!("expected twamp-reflect") };
        assert_eq!(r.port, 862);
        assert_eq!(r.peers.len(), 2);
        assert_eq!(r.peers[0], "203.0.113.7".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn env_twamp_peers_may_be_omitted_for_an_open_responder() {
        let c = from_env(env(&[("MQ_MODE", "twamp-reflect")])).unwrap().unwrap();
        let Command::TwampReflect(r) = c else { panic!("expected twamp-reflect") };
        assert!(r.peers.is_empty());
        assert_eq!(r.port, 862, "the registered TWAMP port is the default");
    }

    #[test]
    fn env_twamp_peers_rejects_a_bad_entry_rather_than_skipping_it() {
        // Silently dropping a malformed peer would leave the responder
        // answering fewer sources than configured, with no indication why.
        let err = from_env(env(&[("MQ_MODE", "twamp-reflect"), ("MQ_TWAMP_PEERS", "10.0.0.1,nope")]))
            .unwrap()
            .unwrap_err();
        assert!(err.contains("nope"), "got {err}");
    }

    #[test]
    fn env_mode_agent_is_explicit_and_valid() {
        assert_eq!(from_env(env(&[("MQ_MODE", "agent")])).unwrap().unwrap(), Command::Agent);
    }

    #[test]
    fn env_validates_dscp_range() {
        let err = from_env(env(&[("MQ_MODE", "probe"), ("MQ_PEER", "10.0.0.1"), ("MQ_DSCP", "99")]))
            .unwrap()
            .unwrap_err();
        assert!(err.contains("out of range"), "got {err}");
    }

    #[test]
    fn help_is_recognised() {
        for f in ["--help", "-h", "help"] {
            assert_eq!(parse(argv(&[f])).unwrap(), Command::Help);
        }
    }

    #[test]
    fn probe_accepts_a_bare_ip_and_supplies_the_default_port() {
        let Command::Probe(p) = parse(argv(&["probe", "--peer", "172.16.220.138"])).unwrap()
        else {
            panic!("expected probe");
        };
        assert_eq!(p.peer, "172.16.220.138:5301".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn probe_accepts_an_explicit_port() {
        let Command::Probe(p) = parse(argv(&["probe", "--peer", "10.0.0.1:9999"])).unwrap()
        else {
            panic!("expected probe");
        };
        assert_eq!(p.peer.port(), 9999);
    }

    #[test]
    fn session_ids_are_parsed_as_hex() {
        // They are printed as hex everywhere else; parsing them as decimal
        // would silently target a different session than the one granted.
        let Command::Reflect(r) = parse(argv(&["reflect", "--session", "cafe"])).unwrap()
        else {
            panic!("expected reflect");
        };
        assert_eq!(r.session, 0xcafe);

        let Command::Reflect(r) = parse(argv(&["reflect", "--session", "0xdeadbeef"])).unwrap()
        else {
            panic!("expected reflect");
        };
        assert_eq!(r.session, 0xdeadbeef);
    }

    #[test]
    fn probe_defaults_match_the_documented_values() {
        let Command::Probe(p) = parse(argv(&["probe", "--peer", "10.0.0.1"])).unwrap() else {
            panic!("expected probe");
        };
        assert_eq!(p.count, 100);
        assert_eq!(p.interval_ms, 20);
        assert_eq!(p.size, DEFAULT_PACKET_LEN);
        assert_eq!(p.session, 1);
        assert_eq!(p.codec, Codec::G711);
        assert!(p.dscp.is_none());
        assert!(!p.json);
    }

    #[test]
    fn json_is_a_bare_flag_not_a_key_value() {
        let Command::Probe(p) =
            parse(argv(&["probe", "--peer", "10.0.0.1", "--json"])).unwrap()
        else {
            panic!("expected probe");
        };
        assert!(p.json);
    }

    #[test]
    fn dscp_out_of_range_is_rejected() {
        // 6-bit field: 64 would silently truncate to 0 (best effort) and the
        // run would report a QoS class it never actually requested.
        let err = parse(argv(&["probe", "--peer", "10.0.0.1", "--dscp", "64"])).unwrap_err();
        assert!(err.contains("out of range"), "got {err}");
    }

    #[test]
    fn missing_peer_is_rejected() {
        assert!(parse(argv(&["probe"])).unwrap_err().contains("--peer"));
    }

    #[test]
    fn a_flag_without_its_value_is_rejected() {
        assert!(parse(argv(&["probe", "--peer"])).unwrap_err().contains("needs a value"));
    }

    #[test]
    fn unknown_command_and_codec_are_rejected() {
        assert!(parse(argv(&["frobnicate"])).unwrap_err().contains("unknown command"));
        assert!(parse(argv(&["probe", "--peer", "10.0.0.1", "--codec", "mp3"]))
            .unwrap_err()
            .contains("unknown codec"));
    }

    #[test]
    fn every_codec_name_resolves() {
        for (name, want) in [
            ("g711", Codec::G711),
            ("g711plc", Codec::G711Plc),
            ("g729", Codec::G729),
            ("g722", Codec::G722),
            ("OPUS", Codec::Opus),
        ] {
            let Command::Probe(p) =
                parse(argv(&["probe", "--peer", "10.0.0.1", "--codec", name])).unwrap()
            else {
                panic!("expected probe");
            };
            assert_eq!(p.codec, want, "codec {name}");
        }
    }
}

/// Survey a RouterOS device and report what is wrong with the local network.
pub async fn run_discover(args: DiscoverArgs) -> anyhow::Result<()> {
    use crate::discovery::{collect, findings};
    use crate::routeros::RouterOs;

    let ros = RouterOs::new(
        &args.host,
        args.port,
        &args.user,
        &args.pass,
        args.tls,
        Duration::from_secs(20),
    )?;

    let identity = ros.check().await?;
    if !args.json {
        eprintln!("surveying {} ({}:{})", identity, args.host, args.port);
    }

    let snap = collect::run(&ros).await;
    let found = findings::analyse(&snap);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "router": identity,
                "host": args.host,
                "inventory": {
                    "wifi_clients": snap.clients.len(),
                    "radios": snap.radios.len(),
                    "arp_entries": snap.arp.len(),
                    "dhcp_leases": snap.leases.len(),
                    "interfaces": snap.interfaces.len(),
                    "dhcp_pool_size": snap.dhcp_pool_size,
                },
                "findings": found,
            }))?
        );
        return Ok(());
    }

    println!();
    println!("Inventory");
    println!("  wifi clients   {}", snap.clients.len());
    println!("  radios         {}", snap.radios.len());
    println!("  ARP entries    {}", snap.arp.len());
    println!("  DHCP leases    {}{}", snap.leases.len(),
        snap.dhcp_pool_size.map(|p| format!(" of {p} pool addresses")).unwrap_or_default());
    println!("  interfaces     {}", snap.interfaces.len());

    for r in &snap.radios {
        println!("  radio {:8} {} {} {}", r.name, r.band, r.width,
            r.frequency_mhz.map(|f| format!("{f} MHz")).unwrap_or_default());
    }
    for c in &snap.clients {
        println!(
            "  client {} {:>5} dBm  tx {:>4} Mbit/s  rx {:>4} Mbit/s  {}",
            c.mac, c.signal_dbm, c.tx_rate_bps / 1_000_000, c.rx_rate_bps / 1_000_000, c.ssid
        );
    }

    println!();
    if found.is_empty() {
        println!("No problems found.");
        return Ok(());
    }

    println!("Findings ({})", found.len());
    for f in &found {
        let tag = match f.severity {
            findings::Severity::Critical => "CRITICAL",
            findings::Severity::Warning => "WARNING ",
            findings::Severity::Info => "INFO    ",
        };
        println!("\n  [{tag}] {}", f.code);
        println!("  {}", f.summary);
        for e in &f.evidence {
            println!("    · {e}");
        }
    }
    Ok(())
}

/// Connect to a RouterOS device using the shared options.
fn connect(a: &DiscoverArgs) -> anyhow::Result<crate::routeros::RouterOs> {
    Ok(crate::routeros::RouterOs::new(
        &a.host,
        a.port,
        &a.user,
        &a.pass,
        a.tls,
        // Generous: a traceroute across a slow path, or a scan of a /24, takes
        // a while and the router streams results for the whole duration.
        Duration::from_secs(180),
    )?)
}

/// Traceroute from the router, then explain where the path degrades.
pub async fn run_trace(args: TraceArgs) -> anyhow::Result<()> {
    use crate::discovery::tools;

    let ros = connect(&args.ros)?;
    let identity = ros.check().await?;
    if !args.ros.json {
        eprintln!("tracing {} from {} ({})", args.target, identity, args.ros.host);
    }

    let raw = ros
        .post(
            "/tool/traceroute",
            &serde_json::json!({
                "address": args.target,
                "count": args.count.to_string(),
                "timeout": "1",
            }),
        )
        .await?;
    let hops = tools::parse_traceroute(&raw);
    let found = tools::analyse_path(&hops, &args.target);

    if args.ros.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "router": identity,
                "target": args.target,
                "hops": hops.iter().map(|h| serde_json::json!({
                    "ttl": h.ttl, "address": h.address, "sent": h.sent,
                    "loss_pct": h.loss_pct, "avg_ms": h.avg_ms,
                    "best_ms": h.best_ms, "worst_ms": h.worst_ms,
                })).collect::<Vec<_>>(),
                "findings": found,
            }))?
        );
        return Ok(());
    }

    println!();
    for h in &hops {
        if h.responded() {
            println!(
                "  {:>2}  {:<16} {:>7.1} ms  (best {:.1}, worst {:.1})  {:.0}% loss",
                h.ttl, h.address, h.avg_ms, h.best_ms, h.worst_ms, h.loss_pct
            );
        } else {
            println!("  {:>2}  {:<16} no response", h.ttl, "*");
        }
    }
    print_findings(&found);
    Ok(())
}

/// Scan a range from the router and compare it with what DHCP knows.
pub async fn run_scan(args: ScanArgs) -> anyhow::Result<()> {
    use crate::discovery::{collect, tools};

    let ros = connect(&args.ros)?;
    let identity = ros.check().await?;
    if !args.ros.json {
        eprintln!(
            "scanning {} from {} ({}) for {}s",
            args.range, identity, args.ros.host, args.duration_s
        );
    }

    let raw = ros
        .post(
            "/tool/ip-scan",
            &serde_json::json!({
                "address-range": args.range,
                "duration": args.duration_s.to_string(),
            }),
        )
        .await?;
    let hosts = tools::parse_ip_scan(&raw);

    // Lease data turns a bare host list into "which of these should be here".
    let leases = match ros.get("/ip/dhcp-server/lease").await {
        Ok(v) => collect::parse_leases_public(&v),
        Err(_) => vec![],
    };
    let found = tools::analyse_scan(&hosts, &leases);

    if args.ros.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "router": identity,
                "range": args.range,
                "hosts": hosts.iter().map(|h| serde_json::json!({
                    "address": h.address, "mac": h.mac,
                    "dns": h.dns, "netbios": h.netbios,
                })).collect::<Vec<_>>(),
                "findings": found,
            }))?
        );
        return Ok(());
    }

    println!("\n{} host(s) responding", hosts.len());
    for h in &hosts {
        let label = if !h.dns.is_empty() {
            h.dns.clone()
        } else if !h.netbios.is_empty() {
            h.netbios.clone()
        } else {
            String::new()
        };
        println!("  {:<16} {:<18} {}", h.address, if h.mac.is_empty() { "-" } else { &h.mac }, label);
    }
    print_findings(&found);
    Ok(())
}

fn print_findings(found: &[crate::discovery::findings::Finding]) {
    use crate::discovery::findings::Severity;
    println!();
    if found.is_empty() {
        println!("No problems found.");
        return;
    }
    println!("Findings ({})", found.len());
    for f in found {
        let tag = match f.severity {
            Severity::Critical => "CRITICAL",
            Severity::Warning => "WARNING ",
            Severity::Info => "INFO    ",
        };
        println!("\n  [{tag}] {}", f.code);
        println!("  {}", f.summary);
        for e in &f.evidence {
            println!("    · {e}");
        }
    }
}

/// Answer TWAMP-Light on behalf of a router that cannot.
pub async fn run_twamp_reflect(args: TwampReflectArgs) -> anyhow::Result<()> {
    use crate::probe::twamp::{AllowList, TwampReflector};

    let mut allow = if args.peers.is_empty() { AllowList::open() } else { AllowList::new() };
    for p in &args.peers {
        allow.allow(*p);
    }
    let open = args.peers.is_empty();

    let bind: SocketAddr = ([0, 0, 0, 0], args.port).into();
    let reflector = TwampReflector::bind(bind, Arc::new(Mutex::new(allow)))
        .await
        .map_err(|e| anyhow::anyhow!("could not bind {bind}: {e}{}", port_hint(args.port)))?;

    eprintln!("TWAMP-Light responder on {}", reflector.local_addr()?);
    if open {
        // TWAMP-Light has no session identifier, so an open responder answers
        // whoever finds it. Saying so beats discovering it later.
        eprintln!("WARNING: answering any source — restrict with --peer, or firewall the port");
    } else {
        eprintln!("answering: {}", args.peers.iter().map(|p| p.to_string())
            .collect::<Vec<_>>().join(", "));
    }
    eprintln!("press Ctrl-C to stop");

    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(reflector.run(rx));
    tokio::signal::ctrl_c().await?;
    let _ = tx.send(true);
    let _ = task.await;
    Ok(())
}

fn port_hint(port: u16) -> &'static str {
    if port < 1024 {
        " (ports below 1024 need elevated privileges)"
    } else {
        ""
    }
}

/// Measure against any TWAMP-Light responder.
pub async fn run_twamp_probe(args: TwampProbeArgs) -> anyhow::Result<()> {
    use crate::probe::twamp::{self, TwampConfig};

    let cfg = TwampConfig {
        peer: args.peer,
        count: args.count,
        interval: Duration::from_millis(args.interval_ms),
        payload_bytes: args.size,
        dscp: args.dscp,
        timeout: Duration::from_millis(args.timeout_ms),
        linger: Duration::from_secs(2),
    };

    if !args.json {
        eprintln!(
            "TWAMP-Light to {} — {} packets, {} ms apart, {} bytes",
            cfg.peer, cfg.count, args.interval_ms, cfg.payload_bytes
        );
    }

    let run = twamp::run(&cfg).await?;
    let m = stats::summarise(run.sent, &run.samples, args.dscp);
    let score = m.rtt.zip(m.jitter).map(|(r, j)| {
        mos::score(MosInput::new(r.avg_us, j.ipdv_avg_us, m.loss.loss_pct, args.codec))
    });

    if args.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "protocol": "twamp-light",
            "peer": cfg.peer.to_string(),
            "metrics": m,
            "mos": score,
            "late_ticks": run.late_ticks,
            "responder_claims_synchronised_clock": run.peer_claims_sync,
        }))?);
    } else {
        print_report(&m, score.as_ref(), run.late_ticks);
        if !run.peer_claims_sync {
            println!("\nNote: the responder does not claim a synchronised clock, so one-way");
            println!("      delay is not available. Round-trip figures are unaffected.");
        }
    }

    if m.loss.received == 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Throughput test driven by the router's own hardware.
pub async fn run_btest(args: BtestArgs) -> anyhow::Result<()> {
    use crate::routeros::btest::{self, BtestConfig, CpuVerdict};

    let ros = connect(&args.ros)?;
    let identity = ros.check().await?;
    if !args.ros.json {
        eprintln!(
            "bandwidth test from {} ({}) to {} — {:?} {:?}, {}s",
            identity, args.ros.host, args.target, args.protocol, args.direction, args.duration_s
        );
    }

    let mut cfg = BtestConfig::new(args.target.clone(), args.direction, args.protocol);
    cfg.duration = Duration::from_secs(args.duration_s);
    cfg.user = args.bt_user;
    cfg.password = args.bt_pass;
    cfg.connection_count = args.connections;
    cfg.local_tx_speed = args.limit_bps;
    cfg.remote_tx_speed = args.limit_bps;

    let r = btest::run(&ros, &cfg).await?;

    if args.ros.json {
        println!("{}", serde_json::to_string_pretty(&r)?);
        return Ok(());
    }

    let mbps = |v: Option<u64>| v.map(|b| format!("{:.1} Mbit/s", b as f64 / 1e6));
    println!();
    if let Some(v) = mbps(r.rx_bps) {
        println!("  download (rx)  {v}");
    }
    if let Some(v) = mbps(r.tx_bps) {
        println!("  upload   (tx)  {v}");
    }
    println!("  duration       {}s", r.duration_s);
    if let Some(c) = r.local_cpu_load {
        print!("  CPU            local {c}%");
        match r.remote_cpu_load {
            Some(rc) => println!(", remote {rc}%"),
            None => println!(),
        }
    }
    if let Some(l) = r.lost_packets {
        println!("  lost packets   {l}");
    }
    if let Some(n) = r.connection_count {
        println!("  connections    {n}");
    }
    println!("  measured by    {}", r.source);

    // The verdict is the part that stops a CPU-bound number being read as a
    // link speed.
    let verdict = match r.cpu_verdict {
        CpuVerdict::LinkLimited => "link-limited — the router had headroom",
        CpuVerdict::RouterContributing => "router contributed to the ceiling",
        CpuVerdict::RouterLimited => "ROUTER-LIMITED — this measures the router, not the link",
    };
    println!("  verdict        {verdict}");

    for n in &r.notes {
        println!("\n  note: {n}");
    }
    Ok(())
}

/// Capture traffic and name the host behind it.
pub async fn run_capture(args: CaptureArgs) -> anyhow::Result<()> {
    use crate::discovery::capture;

    let ros = connect(&args.ros)?;
    let identity = ros.check().await?;
    let d = Duration::from_secs(args.duration_s);

    if !args.ros.json {
        eprintln!(
            "capturing {} on {} for {}s{}",
            if args.wireless { "802.11 frames" } else { "IP traffic" },
            identity,
            args.duration_s,
            if args.interface.is_empty() { String::new() } else { format!(" ({})", args.interface) }
        );
        if args.wireless {
            eprintln!("NOTE: monitor mode interrupts service for associated clients");
        }
    }

    let cap = if args.wireless {
        capture::run_wireless_capture(&ros, &args.interface, d, args.hop).await?
    } else {
        capture::run_packet_capture(&ros, &args.interface, d).await?
    };
    let found = capture::analyse(&cap);

    if args.ros.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "router": identity, "capture": cap, "findings": found,
        }))?);
        return Ok(());
    }

    println!();
    if cap.used_wireless_sniffer {
        println!(
            "{} 802.11 frames captured on {} in {}s",
            cap.wireless_frames, cap.interface, cap.duration_s
        );
        let crc = cap.frames.iter().filter(|f| f.crc_error).count();
        if !cap.frames.is_empty() {
            println!("  channel        {}", cap.frames[0].channel);
            println!("  CRC failures   {crc} of {}", cap.frames.len());
        }
        let mut by_src: std::collections::BTreeMap<&str, usize> = Default::default();
        for f in &cap.frames {
            if !f.src.is_empty() {
                *by_src.entry(f.src.as_str()).or_default() += 1;
            }
        }
        let mut t: Vec<_> = by_src.into_iter().collect();
        t.sort_by(|a, b| b.1.cmp(&a.1));
        if !t.is_empty() {
            println!("\n  transmitters (by frame count)");
            for (src, n) in t.iter().take(8) {
                let sig: Vec<i32> = cap.frames.iter()
                    .filter(|f| f.src == *src).map(|f| f.signal_dbm).collect();
                let avg = if sig.is_empty() { 0 } else { sig.iter().sum::<i32>() / sig.len() as i32 };
                println!("    {src}  {n:>5} frames  avg {avg} dBm");
            }
        }
    } else {
        println!("{} hosts seen in {}s — busiest first", cap.hosts.len(), cap.duration_s);
        for h in cap.hosts.iter().take(12) {
            println!(
                "  {:<40} tx {:>10} B/s   rx {:>10} B/s",
                h.address, h.tx_rate_bps, h.rx_rate_bps
            );
        }
        if !cap.protocols.is_empty() {
            println!("\nprotocols");
            for p in cap.protocols.iter().take(6) {
                println!(
                    "  {:<16} {:>12} bytes  {:>6.1}%  ({} packets)",
                    p.protocol, p.bytes, p.share_pct, p.packets
                );
            }
        }
    }
    for n in &cap.notes {
        println!("\n  note: {n}");
    }
    print_findings(&found);
    Ok(())
}
