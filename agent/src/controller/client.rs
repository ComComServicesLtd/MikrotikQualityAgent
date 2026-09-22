//! HTTP transport for the controller API.
//!
//! The wire shapes here mirror `docs/api.md`. They are kept separate from the
//! agent's internal types so a controller adding a field cannot break an older
//! agent, and so the internal model is free to differ from the contract.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{endpoint, ControllerError, Identity};
use crate::tasks::plan;

/// Request body for `POST /agents/register`.
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub name: String,
    pub group: String,
    pub version: String,
    pub capabilities: Capabilities,
    pub host: HostInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_addr: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub mqp: bool,
    pub twamp_light: bool,
    pub routeros_btest: bool,
    pub probe_port: u16,
}

#[derive(Debug, Default, Serialize)]
pub struct HostInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routeros_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    pub agent_id: String,
    pub token: String,
    pub group: String,
    #[serde(default)]
    pub poll_interval_s: Option<u64>,
    #[serde(default)]
    pub heartbeat_interval_s: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest {
    pub uptime_s: u64,
    pub active_sessions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Results discarded since the last successful submission. Surfaced so a
    /// gap in the time series is visible rather than silent.
    pub spool_dropped: u64,
    pub spool_depth: usize,
}

/// A task as the controller sends it.
#[derive(Debug, Deserialize)]
pub struct TaskDto {
    pub task_id: String,
    /// Carried as a string: JSON numbers are f64 in most parsers and would lose
    /// precision above 2^53, yielding a session the reflector never granted.
    pub session_id: String,
    pub kind: String,
    pub role: String,
    #[serde(default)]
    pub peer: Option<PeerDto>,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(default)]
    pub recurring: bool,
    #[serde(default)]
    pub interval_s: Option<u64>,
    #[serde(default)]
    pub expires_in_s: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct PeerDto {
    pub agent_id: String,
    pub name: String,
    pub address: String,
    pub probe_port: u16,
}

impl TaskDto {
    /// Convert to the agent's internal task, along with how long a one-shot
    /// stays worth running.
    ///
    /// An unrecognised `kind` is an error rather than a default: guessing would
    /// run the wrong measurement and report it under the controller's label.
    pub fn into_plan(self) -> Result<(plan::Task, Option<Duration>), ControllerError> {
        let kind = match self.kind.as_str() {
            "mqp_probe" => plan::Kind::MqpProbe,
            "twamp_probe" => plan::Kind::TwampProbe,
            "tcp_connect" => plan::Kind::TcpConnect,
            "routeros_btest" => plan::Kind::RouterOsBtest,
            "path_trace" => plan::Kind::PathTrace,
            "wifi_signal" => plan::Kind::WifiSignal,
            "packet_capture" => plan::Kind::PacketCapture,
            other => {
                return Err(ControllerError::Decode(format!("unknown task kind {other:?}")))
            }
        };
        let role = match self.role.as_str() {
            "sender" => plan::Role::Sender,
            "reflector" => plan::Role::Reflector,
            other => return Err(ControllerError::Decode(format!("unknown role {other:?}"))),
        };
        // Decimal first: the controller sends `json:",string"`, which is decimal,
        // and every decimal string is also valid hex -- so trying hex first
        // would silently mis-read "255" as 0x255 and target a session the
        // reflector never granted. Only an explicit 0x prefix means hex.
        let raw = self.session_id.trim();
        let session_id = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => raw.parse::<u64>(),
        }
        .map_err(|_| ControllerError::Decode(format!("bad session_id {:?}", self.session_id)))?;

        Ok((
            plan::Task {
                task_id: self.task_id,
                session_id,
                kind,
                role,
                peer: self.peer.map(|p| plan::Peer {
                    agent_id: p.agent_id,
                    name: p.name,
                    address: p.address,
                    probe_port: p.probe_port,
                }),
                params: self.params,
                recurring: self.recurring,
                interval: self.interval_s.map(Duration::from_secs),
            },
            self.expires_in_s.map(Duration::from_secs),
        ))
    }
}

#[derive(Debug, Serialize)]
pub struct ResultsRequest<'a> {
    pub results: &'a [serde_json::Value],
    /// Results the agent had to discard because the spool filled.
    pub dropped: u64,
}

#[derive(Debug, Deserialize)]
pub struct ResultsResponse {
    #[serde(default)]
    pub accepted: usize,
}

pub struct Client {
    http: reqwest::Client,
    base: String,
}

impl Client {
    pub fn new(base: impl Into<String>, timeout: Duration) -> Result<Self, ControllerError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            // Agents poll frequently; reusing connections avoids a TLS
            // handshake per poll on a CPU that has better things to do.
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| ControllerError::Transport(e.to_string()))?;
        Ok(Self { http, base: base.into() })
    }

    pub async fn register(
        &self,
        enrolment_token: &str,
        req: &RegisterRequest,
    ) -> Result<RegisterResponse, ControllerError> {
        let resp = self
            .http
            .post(endpoint(&self.base, "agents/register"))
            .bearer_auth(enrolment_token)
            .json(req)
            .send()
            .await
            .map_err(transport)?;
        decode(resp).await
    }

    pub async fn heartbeat(
        &self,
        id: &Identity,
        req: &HeartbeatRequest,
    ) -> Result<(), ControllerError> {
        let resp = self
            .http
            .post(endpoint(&self.base, &format!("agents/{}/heartbeat", id.agent_id)))
            .bearer_auth(&id.token)
            .json(req)
            .send()
            .await
            .map_err(transport)?;
        check(resp).await
    }

    pub async fn lease_tasks(&self, id: &Identity) -> Result<Vec<TaskDto>, ControllerError> {
        let resp = self
            .http
            .get(endpoint(&self.base, &format!("agents/{}/tasks", id.agent_id)))
            .bearer_auth(&id.token)
            .send()
            .await
            .map_err(transport)?;
        decode(resp).await
    }

    pub async fn submit_results(
        &self,
        id: &Identity,
        results: &[serde_json::Value],
        dropped: u64,
    ) -> Result<ResultsResponse, ControllerError> {
        let resp = self
            .http
            .post(endpoint(&self.base, &format!("agents/{}/results", id.agent_id)))
            .bearer_auth(&id.token)
            .json(&ResultsRequest { results, dropped })
            .send()
            .await
            .map_err(transport)?;
        decode(resp).await
    }
}

fn transport(e: reqwest::Error) -> ControllerError {
    ControllerError::Transport(e.to_string())
}

async fn check(resp: reqwest::Response) -> Result<(), ControllerError> {
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ControllerError::Unauthorized);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ControllerError::Http { status: status.as_u16(), body: truncate(&body) });
    }
    Ok(())
}

async fn decode<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, ControllerError> {
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ControllerError::Unauthorized);
    }
    let body = resp.text().await.map_err(transport)?;
    if !status.is_success() {
        return Err(ControllerError::Http { status: status.as_u16(), body: truncate(&body) });
    }
    serde_json::from_str(&body)
        .map_err(|e| ControllerError::Decode(format!("{e} (body: {})", truncate(&body))))
}

/// Keep error bodies out of the device's small log buffer.
fn truncate(s: &str) -> String {
    const MAX: usize = 300;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}…", &s[..MAX])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dto(kind: &str, role: &str, session: &str) -> TaskDto {
        TaskDto {
            task_id: "t1".into(),
            session_id: session.into(),
            kind: kind.into(),
            role: role.into(),
            peer: None,
            params: serde_json::json!({"count": 100}),
            recurring: true,
            interval_s: Some(30),
            expires_in_s: None,
        }
    }

    #[test]
    fn converts_every_documented_task_kind() {
        for (k, want) in [
            ("mqp_probe", plan::Kind::MqpProbe),
            ("twamp_probe", plan::Kind::TwampProbe),
            ("tcp_connect", plan::Kind::TcpConnect),
            ("routeros_btest", plan::Kind::RouterOsBtest),
            ("path_trace", plan::Kind::PathTrace),
            ("wifi_signal", plan::Kind::WifiSignal),
            ("packet_capture", plan::Kind::PacketCapture),
        ] {
            let (t, _) = dto(k, "sender", "51966").into_plan().unwrap();
            assert_eq!(t.kind, want, "kind {k}");
        }
    }

    #[test]
    fn an_unknown_kind_is_an_error_not_a_default() {
        // Guessing would run the wrong measurement and file it under the
        // controller's label for something else.
        let err = dto("quantum_ping", "sender", "1").into_plan().unwrap_err();
        assert!(matches!(err, ControllerError::Decode(_)));
        assert!(!err.is_retryable(), "a malformed task will not become valid on retry");
    }

    #[test]
    fn an_unknown_role_is_rejected() {
        assert!(dto("mqp_probe", "bystander", "1").into_plan().is_err());
    }

    #[test]
    fn session_ids_survive_at_full_64_bit_width() {
        // The reason session_id crosses the wire as a string at all: as a JSON
        // number this would be rounded by any f64-based parser.
        let (t, _) = dto("mqp_probe", "sender", "18446744073709551615").into_plan().unwrap();
        assert_eq!(t.session_id, u64::MAX);
    }

    #[test]
    fn bare_digits_are_decimal_not_hex() {
        // The controller sends Go's `json:",string"`, which is decimal. Every
        // decimal string is also valid hex, so guessing hex first would read
        // "255" as 597 and target a session the reflector never granted --
        // silently, as 100% packet loss on a healthy path.
        let (t, _) = dto("mqp_probe", "sender", "255").into_plan().unwrap();
        assert_eq!(t.session_id, 255);
    }

    #[test]
    fn an_explicit_prefix_still_selects_hex() {
        let (t, _) = dto("mqp_probe", "sender", "0xcafe").into_plan().unwrap();
        assert_eq!(t.session_id, 0xcafe);
    }

    #[test]
    fn a_malformed_session_id_is_rejected() {
        assert!(dto("mqp_probe", "sender", "not-a-session").into_plan().is_err());
    }

    #[test]
    fn expiry_and_interval_are_carried_through() {
        let mut d = dto("path_trace", "sender", "1");
        d.recurring = false;
        d.expires_in_s = Some(300);
        d.interval_s = None;

        let (t, expires) = d.into_plan().unwrap();
        assert!(!t.recurring);
        assert_eq!(expires, Some(Duration::from_secs(300)));
        assert_eq!(t.interval, None);
    }

    #[test]
    fn unknown_response_fields_are_ignored() {
        // A newer controller must be able to add fields without breaking
        // agents already in the field, which cannot easily be upgraded.
        let raw = r#"{"task_id":"t1","session_id":"51966","kind":"mqp_probe",
                      "role":"sender","brand_new_field":42}"#;
        let d: TaskDto = serde_json::from_str(raw).unwrap();
        assert_eq!(d.task_id, "t1");
        assert!(!d.recurring, "absent boolean defaults rather than failing");
    }

    #[test]
    fn long_error_bodies_are_truncated() {
        // A controller returning an HTML error page must not evict the
        // device's whole log buffer.
        let long = "x".repeat(5_000);
        let t = truncate(&long);
        assert!(t.len() < 400, "got {} chars", t.len());
        assert!(t.ends_with('…'));
    }
}
