//! Agent configuration.
//!
//! Everything comes from environment variables. A `scratch` image has no shell
//! and no convenient way to manage a config file, and RouterOS parameterises
//! containers through `/container/envs` envlists — so environment variables are
//! both the simplest and the native mechanism here.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Controller base URL, e.g. `https://controller.example.net`.
    pub controller_url: String,
    /// Pre-shared enrolment token, used once at first registration.
    pub enrolment_token: String,
    /// Human-chosen unique name, e.g. `yvr-branch-01`.
    pub name: String,
    /// Mesh unit. Agents in the same group are scheduled to probe each other.
    pub group: String,
    /// Where the reflector listens.
    pub probe_bind: SocketAddr,
    /// Address peers should reach this agent on. Usually discovered by the
    /// controller from the source address of our registration, but it can be
    /// pinned when the agent sits behind a static DNAT.
    pub advertise_addr: Option<IpAddr>,
    /// Where agent state (the assigned ID and token) is persisted, so a
    /// container restart is not a new agent.
    pub state_dir: String,
    /// RouterOS host API, for the bandwidth-test offload. Absent means
    /// throughput tasks are skipped with a reason rather than failed.
    pub routeros: Option<RouterOsConfig>,
    pub log_filter: String,
    pub heartbeat_interval: Duration,
    pub poll_interval: Duration,
    /// Bounds on the offline result queue. See [`crate::spool`].
    pub spool: crate::spool::SpoolConfig,
    /// When set, a TWAMP-Light responder runs alongside the managed agent.
    ///
    /// A managed agent already reflects MQP for its peers; answering TWAMP as
    /// well costs one more socket and lets the same device serve carriers and
    /// test sets that will never run an agent of ours. Without this, switching
    /// a standalone responder over to managed mode would silently take its
    /// TWAMP service away.
    pub twamp_port: Option<u16>,
    pub twamp_peers: Vec<IpAddr>,
}

/// Credentials for the RouterOS device hosting this container.
///
/// The host is reachable at the container's default gateway — the address
/// assigned to the RouterOS side of the veth or its bridge. There is no
/// `host.docker.internal` equivalent on RouterOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterOsConfig {
    pub host: IpAddr,
    /// Binary API port. 8728 plaintext, 8729 TLS.
    ///
    /// The binary API is used rather than REST because `/tool/bandwidth-test`
    /// is a continuous-output command: the binary API streams `!re` sentences
    /// and supports cancellation by tag, whereas REST cannot stream and caps
    /// commands at 60 seconds.
    pub port: u16,
    pub username: String,
    pub password: String,
    pub use_tls: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is required but not set")]
    Missing(&'static str),
    #[error("{var} is not valid: {value:?} ({reason})")]
    Invalid { var: &'static str, value: String, reason: &'static str },
    #[error(
        "MQ_ROUTEROS_HOST is set but {0} is not — a partial RouterOS \
         configuration would fail silently at the first bandwidth test"
    )]
    PartialRouterOs(&'static str),
}

impl Config {
    /// Load from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(|k| std::env::var(k).ok())
    }

    /// Load from an arbitrary lookup, so the parsing rules can be tested
    /// without mutating global process state.
    pub fn from_source<F>(get: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let required = |var: &'static str| -> Result<String, ConfigError> {
            get(var).filter(|v| !v.trim().is_empty()).ok_or(ConfigError::Missing(var))
        };

        let controller_url = required("MQ_CONTROLLER_URL")?;
        if !controller_url.starts_with("http://") && !controller_url.starts_with("https://") {
            return Err(ConfigError::Invalid {
                var: "MQ_CONTROLLER_URL",
                value: controller_url,
                reason: "must start with http:// or https://",
            });
        }

        let name = required("MQ_AGENT_NAME")?;
        let group = required("MQ_AGENT_GROUP")?;
        let enrolment_token = required("MQ_ENROLMENT_TOKEN")?;

        let probe_port = parse_or("MQ_PROBE_PORT", &get, 5301u16, "expected a port number")?;
        let probe_bind = SocketAddr::from(([0, 0, 0, 0], probe_port));

        let advertise_addr = match get("MQ_ADVERTISE_ADDR") {
            Some(v) if !v.trim().is_empty() => Some(v.trim().parse::<IpAddr>().map_err(|_| {
                ConfigError::Invalid {
                    var: "MQ_ADVERTISE_ADDR",
                    value: v,
                    reason: "expected an IP address",
                }
            })?),
            _ => None,
        };

        let routeros = Self::routeros_from(&get)?;

        Ok(Self {
            controller_url: controller_url.trim_end_matches('/').to_string(),
            enrolment_token,
            name,
            group,
            probe_bind,
            advertise_addr,
            state_dir: get("MQ_STATE_DIR").unwrap_or_else(|| "/var/lib/mqagent".into()),
            routeros,
            log_filter: get("MQ_LOG").unwrap_or_else(|| "info".into()),
            heartbeat_interval: Duration::from_secs(parse_or(
                "MQ_HEARTBEAT_SECS",
                &get,
                30u64,
                "expected a number of seconds",
            )?),
            poll_interval: Duration::from_secs(parse_or(
                "MQ_POLL_SECS",
                &get,
                10u64,
                "expected a number of seconds",
            )?),
            twamp_port: match get("MQ_TWAMP_PORT") {
                Some(v) if !v.trim().is_empty() => Some(v.trim().parse::<u16>().map_err(|_| {
                    ConfigError::Invalid {
                        var: "MQ_TWAMP_PORT",
                        value: v,
                        reason: "expected a port number",
                    }
                })?),
                _ => None,
            },
            twamp_peers: match get("MQ_TWAMP_PEERS") {
                Some(v) if !v.trim().is_empty() => v
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(|p| {
                        p.parse::<IpAddr>().map_err(|_| ConfigError::Invalid {
                            var: "MQ_TWAMP_PEERS",
                            value: p.to_string(),
                            reason: "expected a comma-separated list of IP addresses",
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => vec![],
            },
            spool: crate::spool::SpoolConfig::new(
                parse_or(
                    "MQ_SPOOL_MAX_ENTRIES",
                    &get,
                    crate::spool::DEFAULT_MAX_ENTRIES,
                    "expected a number of results",
                )?,
                parse_or(
                    "MQ_SPOOL_MAX_BYTES",
                    &get,
                    crate::spool::DEFAULT_MAX_BYTES,
                    "expected a number of bytes",
                )?,
                // Expressed as a percentage rather than a fraction: an envlist
                // value of "20" is harder to misread than "0.2".
                parse_or(
                    "MQ_SPOOL_ONSET_PCT",
                    &get,
                    (crate::spool::DEFAULT_ONSET_FRACTION * 100.0) as u32,
                    "expected a percentage (0-90)",
                )? as f64
                    / 100.0,
            ),
        })
    }

    fn routeros_from<F>(get: &F) -> Result<Option<RouterOsConfig>, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let Some(host) = get("MQ_ROUTEROS_HOST").filter(|v| !v.trim().is_empty()) else {
            return Ok(None);
        };

        let host = host.trim().parse::<IpAddr>().map_err(|_| ConfigError::Invalid {
            var: "MQ_ROUTEROS_HOST",
            value: host.clone(),
            reason: "expected an IP address — usually the container's default gateway",
        })?;

        // Half-configured credentials are worse than none: the agent would
        // advertise the bandwidth-test capability, be scheduled throughput
        // work, and fail every task at run time.
        let username = get("MQ_ROUTEROS_USER")
            .filter(|v| !v.trim().is_empty())
            .ok_or(ConfigError::PartialRouterOs("MQ_ROUTEROS_USER"))?;
        // Presence, not non-emptiness. A blank RouterOS password is normal on
        // lab and factory-default routers -- which is exactly where this tool
        // is most needed -- and the environment distinguishes "unset" from
        // "set to empty" for us. Requiring a non-empty value made the agent
        // refuse to start against the very devices it was written for.
        let password = get("MQ_ROUTEROS_PASS")
            .ok_or(ConfigError::PartialRouterOs("MQ_ROUTEROS_PASS"))?;

        let use_tls = parse_bool(get("MQ_ROUTEROS_TLS").as_deref(), false);
        let default_port = if use_tls { 8729 } else { 8728 };
        let port = parse_or("MQ_ROUTEROS_PORT", get, default_port, "expected a port number")?;

        Ok(Some(RouterOsConfig { host, port, username, password, use_tls }))
    }

    /// Whether this agent can offload throughput tests to its host router.
    pub fn can_bandwidth_test(&self) -> bool {
        self.routeros.is_some()
    }
}

fn parse_or<T, F>(var: &'static str, get: &F, default: T, reason: &'static str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    F: Fn(&str) -> Option<String>,
{
    match get(var) {
        Some(v) if !v.trim().is_empty() => v
            .trim()
            .parse::<T>()
            .map_err(|_| ConfigError::Invalid { var, value: v, reason }),
        _ => Ok(default),
    }
}

fn parse_bool(v: Option<&str>, default: bool) -> bool {
    match v.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("1" | "true" | "yes" | "on") => true,
        Some("0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("MQ_CONTROLLER_URL", "https://controller.example.net"),
            ("MQ_AGENT_NAME", "yvr-branch-01"),
            ("MQ_AGENT_GROUP", "west-wan"),
            ("MQ_ENROLMENT_TOKEN", "enrol-secret"),
        ])
    }

    fn load(map: &HashMap<&'static str, &'static str>) -> Result<Config, ConfigError> {
        Config::from_source(|k| map.get(k).map(|v| v.to_string()))
    }

    #[test]
    fn minimal_configuration_loads_with_sane_defaults() {
        let c = load(&base()).unwrap();
        assert_eq!(c.name, "yvr-branch-01");
        assert_eq!(c.group, "west-wan");
        assert_eq!(c.probe_bind.port(), 5301);
        assert_eq!(c.state_dir, "/var/lib/mqagent");
        assert_eq!(c.heartbeat_interval, Duration::from_secs(30));
        assert!(!c.can_bandwidth_test(), "no RouterOS config means no throughput offload");
    }

    #[test]
    fn every_required_variable_is_enforced() {
        for missing in
            ["MQ_CONTROLLER_URL", "MQ_AGENT_NAME", "MQ_AGENT_GROUP", "MQ_ENROLMENT_TOKEN"]
        {
            let mut m = base();
            m.remove(missing);
            match load(&m) {
                Err(ConfigError::Missing(var)) => assert_eq!(var, missing),
                other => panic!("expected {missing} to be required, got {other:?}"),
            }
        }
    }

    #[test]
    fn blank_values_count_as_missing() {
        // RouterOS envlists make it easy to define a key with an empty value;
        // treating that as "set" would produce confusing downstream failures.
        let mut m = base();
        m.insert("MQ_AGENT_NAME", "   ");
        assert!(matches!(load(&m), Err(ConfigError::Missing("MQ_AGENT_NAME"))));
    }

    #[test]
    fn controller_url_must_carry_a_scheme() {
        let mut m = base();
        m.insert("MQ_CONTROLLER_URL", "controller.example.net");
        assert!(matches!(
            load(&m),
            Err(ConfigError::Invalid { var: "MQ_CONTROLLER_URL", .. })
        ));
    }

    #[test]
    fn trailing_slash_on_controller_url_is_normalised() {
        // Otherwise every request path would come out doubled-up.
        let mut m = base();
        m.insert("MQ_CONTROLLER_URL", "https://controller.example.net/");
        assert_eq!(load(&m).unwrap().controller_url, "https://controller.example.net");
    }

    #[test]
    fn routeros_defaults_to_the_plaintext_binary_api_port() {
        let mut m = base();
        m.insert("MQ_ROUTEROS_HOST", "172.17.0.1");
        m.insert("MQ_ROUTEROS_USER", "btagent");
        m.insert("MQ_ROUTEROS_PASS", "secret");

        let ros = load(&m).unwrap().routeros.unwrap();
        assert_eq!(ros.port, 8728);
        assert!(!ros.use_tls);
        assert_eq!(ros.host, "172.17.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn enabling_tls_moves_the_default_routeros_port() {
        let mut m = base();
        m.insert("MQ_ROUTEROS_HOST", "172.17.0.1");
        m.insert("MQ_ROUTEROS_USER", "btagent");
        m.insert("MQ_ROUTEROS_PASS", "secret");
        m.insert("MQ_ROUTEROS_TLS", "yes");

        let ros = load(&m).unwrap().routeros.unwrap();
        assert!(ros.use_tls);
        assert_eq!(ros.port, 8729);
    }

    #[test]
    fn a_blank_routeros_password_is_accepted() {
        // Lab and factory-default MikroTiks ship with one. Rejecting it made
        // the agent refuse to start against the devices it exists to measure,
        // while routeros.rs simultaneously asserted blank passwords work.
        let mut m = base();
        m.insert("MQ_ROUTEROS_HOST", "172.16.220.138");
        m.insert("MQ_ROUTEROS_USER", "admin");
        m.insert("MQ_ROUTEROS_PASS", "");

        let ros = load(&m).unwrap().routeros.expect("blank password is a valid choice");
        assert_eq!(ros.username, "admin");
        assert!(ros.password.is_empty());
    }

    #[test]
    fn partial_routeros_credentials_are_rejected_loudly() {
        // The failure mode this prevents: the agent advertises the
        // bandwidth-test capability, gets scheduled throughput work, and then
        // fails every single task at run time.
        let mut m = base();
        m.insert("MQ_ROUTEROS_HOST", "172.17.0.1");
        assert!(matches!(load(&m), Err(ConfigError::PartialRouterOs("MQ_ROUTEROS_USER"))));

        // Omitting the variable entirely is still a mistake -- that is the
        // half-configured case worth catching.
        m.insert("MQ_ROUTEROS_USER", "btagent");
        assert!(matches!(load(&m), Err(ConfigError::PartialRouterOs("MQ_ROUTEROS_PASS"))));
    }

    #[test]
    fn routeros_host_must_be_an_ip_not_a_hostname() {
        // A scratch image has no resolver configured by default, so a hostname
        // here would fail at connect time with a much less obvious error.
        let mut m = base();
        m.insert("MQ_ROUTEROS_HOST", "my-router.lan");
        m.insert("MQ_ROUTEROS_USER", "btagent");
        m.insert("MQ_ROUTEROS_PASS", "secret");
        assert!(matches!(load(&m), Err(ConfigError::Invalid { var: "MQ_ROUTEROS_HOST", .. })));
    }

    #[test]
    fn numeric_fields_reject_garbage_rather_than_defaulting() {
        let mut m = base();
        m.insert("MQ_PROBE_PORT", "not-a-port");
        assert!(matches!(load(&m), Err(ConfigError::Invalid { var: "MQ_PROBE_PORT", .. })));
    }

    #[test]
    fn advertise_address_is_optional_but_validated() {
        let mut m = base();
        assert!(load(&m).unwrap().advertise_addr.is_none());

        m.insert("MQ_ADVERTISE_ADDR", "203.0.113.24");
        assert_eq!(
            load(&m).unwrap().advertise_addr,
            Some("203.0.113.24".parse::<IpAddr>().unwrap())
        );

        m.insert("MQ_ADVERTISE_ADDR", "definitely not an ip");
        assert!(matches!(load(&m), Err(ConfigError::Invalid { var: "MQ_ADVERTISE_ADDR", .. })));
    }

    #[test]
    fn a_managed_agent_can_also_answer_twamp() {
        // Otherwise switching a standalone responder to managed mode silently
        // removes the TWAMP service it was deployed for.
        let mut m = base();
        m.insert("MQ_TWAMP_PORT", "862");
        m.insert("MQ_TWAMP_PEERS", "162.216.190.1, 10.0.0.5");

        let c = load(&m).unwrap();
        assert_eq!(c.twamp_port, Some(862));
        assert_eq!(c.twamp_peers.len(), 2);
    }

    #[test]
    fn twamp_is_off_unless_a_port_is_given() {
        let c = load(&base()).unwrap();
        assert!(c.twamp_port.is_none());
        assert!(c.twamp_peers.is_empty());
    }

    #[test]
    fn a_malformed_twamp_peer_is_rejected_not_skipped() {
        let mut m = base();
        m.insert("MQ_TWAMP_PORT", "862");
        m.insert("MQ_TWAMP_PEERS", "10.0.0.1,nonsense");
        assert!(matches!(load(&m), Err(ConfigError::Invalid { var: "MQ_TWAMP_PEERS", .. })));
    }

    #[test]
    fn spool_defaults_protect_the_onset() {
        let c = load(&base()).unwrap();
        assert_eq!(c.spool.max_entries, crate::spool::DEFAULT_MAX_ENTRIES);
        assert!(c.spool.onset_reserve > 0, "onset protection must be on by default");
        assert!(c.spool.onset_reserve < c.spool.max_entries);
    }

    #[test]
    fn spool_limits_are_tunable_for_tighter_devices() {
        let mut m = base();
        m.insert("MQ_SPOOL_MAX_ENTRIES", "500");
        m.insert("MQ_SPOOL_MAX_BYTES", "262144");
        m.insert("MQ_SPOOL_ONSET_PCT", "40");

        let c = load(&m).unwrap();
        assert_eq!(c.spool.max_entries, 500);
        assert_eq!(c.spool.max_bytes, 262_144);
        assert_eq!(c.spool.onset_reserve, 200);
    }

    #[test]
    fn spool_onset_percentage_cannot_consume_the_whole_spool() {
        // 100% would leave nothing evictable and the spool would jam.
        let mut m = base();
        m.insert("MQ_SPOOL_MAX_ENTRIES", "100");
        m.insert("MQ_SPOOL_ONSET_PCT", "100");
        let c = load(&m).unwrap();
        assert!(c.spool.onset_reserve < c.spool.max_entries);
    }

    #[test]
    fn boolean_parsing_accepts_the_usual_spellings() {
        assert!(parse_bool(Some("yes"), false));
        assert!(parse_bool(Some("TRUE"), false));
        assert!(parse_bool(Some("1"), false));
        assert!(parse_bool(Some(" on "), false));
        assert!(!parse_bool(Some("no"), true));
        assert!(!parse_bool(Some("0"), true));
        assert!(parse_bool(None, true), "absent falls back to the default");
        assert!(parse_bool(Some("banana"), true), "unrecognised falls back too");
    }
}

impl RouterOsConfig {
    /// Port for the REST API.
    ///
    /// `port` configures the *binary* API, which the throughput offload wants
    /// for its streaming. Discovery and one-shot diagnostics use REST, which
    /// lives on the web service instead — a different port entirely, and
    /// reusing 8728 there fails with a confusing connection error.
    pub fn port_rest(&self) -> u16 {
        if self.use_tls {
            443
        } else {
            80
        }
    }
}
