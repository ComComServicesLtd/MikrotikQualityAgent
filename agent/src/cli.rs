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
    mqagent --help

REFLECT OPTIONS:
    --port <PORT>        Listen port                        [default: 5301]
    --session <HEX>      Session ID to accept               [default: 1]
    --peer <IP>          Only accept from this address      [default: any]

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

EXAMPLE — measure the path to a router running `mqagent reflect`:
    mqagent probe --peer 172.16.220.138 --session cafe --count 300 --dscp 46
";

#[derive(Debug, PartialEq)]
pub enum Command {
    Agent,
    Help,
    Reflect(ReflectArgs),
    Probe(Box<ProbeArgs>),
}

#[derive(Debug, PartialEq)]
pub struct ReflectArgs {
    pub port: u16,
    pub session: u64,
    pub peer: Option<std::net::IpAddr>,
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
        other => Err(format!("MQ_MODE {other:?} is not one of: agent, reflect, probe")),
    })())
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
        if key == "json" {
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
        other => Err(format!("unknown command {other:?} — try --help")),
    }
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

    eprintln!("reflector listening on {actual}");
    eprintln!("session {:016x} granted to {}", args.session,
        args.peer.map(|p| p.to_string()).unwrap_or_else(|| "any address".into()));
    eprintln!("press Ctrl-C to stop");

    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(reflector.run(rx));
    tokio::signal::ctrl_c().await?;
    let _ = tx.send(true);
    let _ = task.await;
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
