//! The managed agent loop.
//!
//! Registers, then runs measurement and communication as two concerns that do
//! not block each other. Measurement is driven entirely by the local
//! [`plan`](crate::tasks::plan), so a controller outage slows reporting but
//! never stops measuring — which is the point, since the controller link is
//! often down because of the fault being measured.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::{watch, Mutex};
use tracing::{debug, error, info, warn};

use crate::collector::mos::{self, Codec, MosInput};
use crate::collector::stats;
use crate::config::Config;
use crate::controller::client::{
    Capabilities, Client, HeartbeatRequest, HostInfo, RegisterRequest,
};
use crate::controller::{load_identity, save_identity, Backoff, Identity};
use crate::probe::reflector::Registry;
use crate::probe::sender::{self, ProbeConfig};
use crate::spool::{Accepted, Spool};
use crate::tasks::plan::{self, Plan};

/// Largest batch of results to submit at once. Bounded so a deep spool drains
/// steadily rather than in one request the controller may reject for size.
const SUBMIT_BATCH: usize = 100;

/// How long a single measurement may run before we give up on it. Prevents one
/// wedged task from stalling the whole loop.
const TASK_TIMEOUT: Duration = Duration::from_secs(120);

/// Which host-router diagnostic a task is asking for.
///
/// All four run through the RouterOS API rather than from inside the
/// container, because what they inspect — the path from the router, the
/// router's forwarding hardware, the wire, the radio — is not visible from a
/// veth.
#[derive(Debug, Clone, Copy)]
enum HostTask {
    Trace,
    Btest,
    Capture,
    WifiSignal,
}

impl HostTask {
    fn label(self) -> &'static str {
        match self {
            Self::Trace => "traceroute",
            Self::Btest => "bandwidth test",
            Self::Capture => "packet capture",
            Self::WifiSignal => "wireless snapshot",
        }
    }
}

/// Outcome of checking a persisted identity against the controller.
enum Verified {
    /// The stored credential still works.
    Usable,
    /// The controller rejected it; enrol again.
    Revoked,
    ShuttingDown,
}

pub struct Agent {
    cfg: Config,
    client: Client,
    identity: Identity,
    plan: Plan,
    spool: Spool<serde_json::Value>,
    registry: Arc<Mutex<Registry>>,
    /// Client for the *host* router, when credentials are configured. One-shot
    /// diagnostics run through it; without it they are skipped with a reason
    /// rather than failing silently.
    ros: Option<crate::routeros::RouterOs>,
    started: Instant,
    last_error: Option<String>,
}

impl Agent {
    /// Register with the controller, reusing a persisted identity if present.
    ///
    /// Retries indefinitely on transport failures: an agent that gives up
    /// because the controller was down at boot would need a human to restart
    /// it, on a device that may be in a locked cabinet in another city.
    pub async fn enrol(
        cfg: Config,
        registry: Arc<Mutex<Registry>>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> anyhow::Result<Self> {
        let client = Client::new(cfg.controller_url.clone(), Duration::from_secs(30))?;
        let existing = load_identity(&cfg.state_dir);

        // Reuse a persisted identity rather than registering again.
        //
        // Enrolment tokens are single-use and burned on first registration, so
        // re-registering on every start would fail permanently the moment the
        // agent restarts once — and with `restart-policy=on-failure` that is a
        // crash loop on a device nobody can easily reach. Registration is for
        // bootstrapping; the agent token it returns is the long-lived
        // credential.
        if let Some(id) = existing.clone() {
            info!(agent_id = %id.agent_id, "found a persisted identity; verifying it");
            match Self::verify(&client, &id, &registry, shutdown).await {
                Verified::Usable => {
                    info!(agent_id = %id.agent_id, "resumed as the same agent");
                    return Ok(Self::assemble(cfg, client, id, registry));
                }
                Verified::Revoked => {
                    warn!("stored credentials were rejected; enrolling afresh");
                }
                Verified::ShuttingDown => anyhow::bail!("shut down before enrolment completed"),
            }
        }

        let req = RegisterRequest {
            agent_id: existing.as_ref().map(|i| i.agent_id.clone()),
            name: cfg.name.clone(),
            group: cfg.group.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: Self::caps_from(&cfg),
            host: HostInfo::default(),
            advertise_addr: cfg.advertise_addr.map(|a| a.to_string()),
        };

        let mut backoff = Backoff::default();
        loop {
            match client.register(&cfg.enrolment_token, &req).await {
                Ok(resp) => {
                    let identity = Identity {
                        agent_id: resp.agent_id,
                        token: resp.token,
                        group: resp.group,
                    };
                    if let Err(e) = save_identity(&cfg.state_dir, &identity) {
                        // Not fatal: the agent works fine this run, it just
                        // re-enrols after a restart. Better than refusing to
                        // start because a mount is missing.
                        warn!(error = %e, "could not persist identity; a restart will re-enrol");
                    }
                    info!(agent_id = %identity.agent_id, group = %identity.group, "registered");
                    return Ok(Self::assemble(cfg, client, identity, registry));
                }
                Err(e) if e.is_retryable() => {
                    let delay = backoff.next_delay(rand::thread_rng().gen());
                    warn!(error = %e, attempt = backoff.attempt(), ?delay, "registration failed, retrying");
                    if wait_or_shutdown(shutdown, delay).await {
                        anyhow::bail!("shut down before registration completed");
                    }
                }
                Err(e) => {
                    // A bad enrolment token will never become good. Failing
                    // loudly beats retrying forever against a controller that
                    // keeps saying no.
                    anyhow::bail!("registration rejected: {e}");
                }
            }
        }
    }

    /// What this agent can currently do, derived from configuration.
    fn caps_from(cfg: &Config) -> Capabilities {
        Capabilities {
            mqp: true,
            // Reported from configuration rather than hardcoded. Claiming
            // false while a responder is listening makes the controller refuse
            // TWAMP tests against a device that can serve them.
            twamp_light: cfg.twamp_port.is_some(),
            routeros_btest: cfg.can_bandwidth_test(),
            probe_port: cfg.probe_bind.port(),
            // A peer cannot reach our responder without knowing its port, and
            // it is not the MQP one.
            twamp_port: cfg.twamp_port,
        }
    }

    fn capabilities(&self) -> Capabilities {
        Self::caps_from(&self.cfg)
    }

    fn assemble(
        cfg: Config,
        client: Client,
        identity: Identity,
        registry: Arc<Mutex<Registry>>,
    ) -> Self {
        let ros = cfg.routeros.as_ref().and_then(|r| {
            crate::routeros::RouterOs::new(
                &r.host.to_string(),
                r.port_rest(),
                &r.username,
                &r.password,
                r.use_tls,
                Duration::from_secs(90),
            )
            .map_err(|e| warn!(error = %e, "could not build a RouterOS client"))
            .ok()
        });

        Self {
            plan: Plan::new(Duration::from_secs(60)),
            spool: Spool::new(cfg.spool),
            cfg,
            client,
            identity,
            registry,
            ros,
            started: Instant::now(),
            last_error: None,
        }
    }

    /// Check whether a stored identity still works, by heartbeating with it.
    ///
    /// A transport failure proves nothing about the credential, so it is
    /// retried rather than treated as revocation — discarding a working
    /// identity because the controller happened to be down would burn the
    /// agent's one enrolment token for nothing.
    async fn verify(
        client: &Client,
        id: &Identity,
        registry: &Arc<Mutex<Registry>>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Verified {
        let mut backoff = Backoff::default();
        loop {
            let req = HeartbeatRequest {
                capabilities: None,
                uptime_s: 0,
                active_sessions: registry.lock().await.active_count(),
                last_error: None,
                spool_dropped: 0,
                spool_depth: 0,
            };
            match client.heartbeat(id, &req).await {
                Ok(()) => return Verified::Usable,
                Err(e) if e.needs_reregistration() => return Verified::Revoked,
                Err(e) if e.is_retryable() => {
                    let delay = backoff.next_delay(rand::thread_rng().gen());
                    warn!(error = %e, ?delay, "controller unreachable while verifying identity");
                    if wait_or_shutdown(shutdown, delay).await {
                        return Verified::ShuttingDown;
                    }
                }
                Err(e) => {
                    // Something we do not understand. Prefer the stored
                    // identity over burning the enrolment token on a guess.
                    warn!(error = %e, "unexpected response verifying identity; keeping it");
                    return Verified::Usable;
                }
            }
        }
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut comms = Backoff::default();
        let mut next_poll = Instant::now();
        let mut next_heartbeat = Instant::now();

        loop {
            if *shutdown.borrow() {
                break;
            }
            let now = Instant::now();

            // A one-shot past its deadline is reported skipped, never run late.
            for skipped in self.plan.reap_expired(now) {
                info!(task = %skipped.task.task_id, reason = skipped.reason, "abandoning one-shot");
                self.enqueue_skipped(&skipped.task, skipped.reason);
            }

            if now >= next_poll {
                let ok = self.poll_tasks().await;
                next_poll = now
                    + if ok {
                        comms.reset();
                        self.cfg.poll_interval
                    } else {
                        comms.next_delay(rand::thread_rng().gen())
                    };
            }

            if now >= next_heartbeat {
                if self.heartbeat().await {
                    self.spool.clear_dropped();
                }
                next_heartbeat = now + self.cfg.heartbeat_interval;
            }

            // Measurement is driven purely by local state, so it continues at
            // full cadence regardless of how the calls above went.
            if let Some(task) = self.plan.next_due(Instant::now()) {
                self.execute(task).await;
                // Submit before looping back for more work. Draining only when
                // the queue is empty would starve submission entirely whenever
                // there is a backlog -- results would accumulate until the
                // spool overflowed, on an agent that looked perfectly healthy.
                self.drain_spool().await;
                continue;
            }

            self.drain_spool().await;

            let sleep = self
                .plan
                .time_until_due(Instant::now())
                .unwrap_or(self.cfg.poll_interval)
                .min(next_poll.saturating_duration_since(Instant::now()))
                .min(Duration::from_secs(5))
                .max(Duration::from_millis(50));

            if wait_or_shutdown(&mut shutdown, sleep).await {
                break;
            }
        }

        info!(spooled = self.spool.len(), "agent loop stopped");
        // Best-effort final flush so a graceful stop does not discard results
        // the spool is holding. The spool is memory-only, so this is the last
        // chance they have.
        self.drain_spool().await;
    }

    async fn poll_tasks(&mut self) -> bool {
        match self.client.lease_tasks(&self.identity).await {
            Ok(dtos) => {
                let now = Instant::now();
                let mut recurring_ids = Vec::new();
                for dto in dtos {
                    match dto.into_plan() {
                        Ok((task, expires_in)) => {
                            if task.recurring {
                                recurring_ids.push(task.task_id.clone());
                            }
                            if task.role == plan::Role::Reflector {
                                self.grant_reflector(&task).await;
                            }
                            self.plan.accept(task, expires_in, now);
                        }
                        Err(e) => warn!(error = %e, "ignoring task we cannot interpret"),
                    }
                }
                // Only reconcile on a *successful* poll. Doing it after a
                // failure would cancel every measurement the agent has and turn
                // a controller outage into a monitoring outage.
                if !recurring_ids.is_empty() {
                    let dropped = self.plan.reconcile_recurring(&recurring_ids);
                    if dropped > 0 {
                        debug!(dropped, "controller withdrew recurring assignments");
                    }
                }
                self.last_error = None;
                true
            }
            Err(e) => {
                if e.needs_reregistration() {
                    error!("controller rejected our token; identity may have been revoked");
                }
                warn!(error = %e, plan = self.plan.recurring_len(), "task poll failed; continuing on the cached plan");
                self.last_error = Some(e.to_string());
                false
            }
        }
    }

    async fn grant_reflector(&self, task: &plan::Task) {
        let Some(peer) = &task.peer else { return };
        let Ok(ip) = peer.address.parse::<std::net::IpAddr>() else {
            warn!(addr = %peer.address, "reflector grant has an unusable peer address");
            return;
        };
        self.registry
            .lock()
            .await
            .grant(task.session_id, std::net::SocketAddr::new(ip, peer.probe_port));
    }

    async fn heartbeat(&mut self) -> bool {
        let s = self.spool.stats();
        let req = HeartbeatRequest {
            capabilities: Some(self.capabilities()),
            uptime_s: self.started.elapsed().as_secs(),
            active_sessions: self.registry.lock().await.active_count(),
            last_error: self.last_error.clone(),
            spool_dropped: s.dropped,
            spool_depth: s.entries,
        };
        match self.client.heartbeat(&self.identity, &req).await {
            Ok(()) => true,
            Err(e) => {
                debug!(error = %e, "heartbeat failed");
                false
            }
        }
    }

    async fn execute(&mut self, task: plan::Task) {
        match task.kind {
            plan::Kind::MqpProbe if task.role == plan::Role::Sender => {
                self.run_mqp_probe(task).await
            }
            // A reflector task is an authorisation, not an action: the grant
            // was installed at poll time and the reflector serves it.
            plan::Kind::MqpProbe => {}

            plan::Kind::PathTrace => self.run_host_task(task, HostTask::Trace).await,
            plan::Kind::RouterOsBtest => self.run_host_task(task, HostTask::Btest).await,
            plan::Kind::PacketCapture => self.run_host_task(task, HostTask::Capture).await,
            plan::Kind::WifiSignal => self.run_host_task(task, HostTask::WifiSignal).await,

            other => {
                debug!(?other, task = %task.task_id, "task kind not implemented yet; skipping");
                self.enqueue_skipped(&task, "task kind not implemented in this agent version");
            }
        }
    }

    async fn run_mqp_probe(&mut self, task: plan::Task) {
        let Some(peer) = task.peer.clone() else {
            self.enqueue_skipped(&task, "probe task has no peer");
            return;
        };
        let Ok(ip) = peer.address.parse::<std::net::IpAddr>() else {
            self.enqueue_skipped(&task, "peer address is not an IP");
            return;
        };

        let p = &task.params;
        let dscp = p.get("dscp").and_then(|v| v.as_u64()).map(|v| v as u8);
        let cfg = ProbeConfig {
            session_id: task.session_id,
            peer: std::net::SocketAddr::new(ip, peer.probe_port),
            count: p.get("count").and_then(|v| v.as_u64()).unwrap_or(100) as u32,
            interval: Duration::from_millis(
                p.get("interval_ms").and_then(|v| v.as_u64()).unwrap_or(20),
            ),
            payload_bytes: p.get("payload_bytes").and_then(|v| v.as_u64()).unwrap_or(172) as usize,
            dscp,
            timeout: Duration::from_millis(
                p.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(1000),
            ),
            linger: Duration::from_secs(2),
        };
        let codec = match p.get("codec").and_then(|v| v.as_str()).unwrap_or("g711") {
            "g711plc" => Codec::G711Plc,
            "g729" => Codec::G729,
            "g722" => Codec::G722,
            "opus" => Codec::Opus,
            _ => Codec::G711,
        };

        let started = time::OffsetDateTime::now_utc();
        let outcome = tokio::time::timeout(TASK_TIMEOUT, sender::run(&cfg)).await;
        let ended = time::OffsetDateTime::now_utc();

        let body = match outcome {
            Ok(Ok(run)) => {
                let m = stats::summarise(run.sent, &run.samples, dscp);
                let score = m.rtt.zip(m.jitter).map(|(r, j)| {
                    mos::score(MosInput::new(r.avg_us, j.ipdv_avg_us, m.loss.loss_pct, codec))
                });
                debug!(
                    task = %task.task_id, peer = %peer.name,
                    loss = m.loss.loss_pct, rtt_us = m.rtt.map(|r| r.avg_us).unwrap_or(0),
                    "probe complete"
                );
                serde_json::json!({
                    "task_id": task.task_id,
                    "session_id": task.session_id.to_string(),
                    "started_at": rfc3339(started),
                    "ended_at": rfc3339(ended),
                    // A run where nothing came back is a valid measurement of a
                    // broken path, not a failed task.
                    "status": if m.loss.received == 0 { "partial" } else { "ok" },
                    "rtt": m.rtt, "jitter": m.jitter, "loss": m.loss,
                    "reorder": m.reorder, "dscp": m.dscp, "mos": score,
                })
            }
            Ok(Err(e)) => self.failure_body(&task, started, ended, &e.to_string()),
            Err(_) => self.failure_body(&task, started, ended, "task exceeded its time limit"),
        };

        self.enqueue(body);
    }

    /// Run a one-shot diagnostic through the host router and spool the result.
    async fn run_host_task(&mut self, task: plan::Task, which: HostTask) {
        let Some(ros) = self.ros.as_ref() else {
            // Configured absence, not a failure: the agent simply has no
            // credentials for its host. Saying which ones are missing is more
            // use than a generic error.
            self.enqueue_skipped(
                &task,
                "no RouterOS credentials configured; set MQ_ROUTEROS_HOST/USER/PASS",
            );
            return;
        };

        let started = time::OffsetDateTime::now_utc();
        // Annotated because the arms build their errors from several sources;
        // without it the block's error type is ambiguous.
        let outcome: Result<Result<serde_json::Value, String>, _> =
            tokio::time::timeout(TASK_TIMEOUT, async {
            match which {
                HostTask::Trace => {
                    let target = task
                        .params
                        .get("target")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "traceroute task carries no target".to_string())?;
                    let count = task.params.get("count").and_then(|v| v.as_u64()).unwrap_or(3);
                    let raw = ros
                        .post(
                            "/tool/traceroute",
                            &serde_json::json!({
                                "address": target, "count": count.to_string(), "timeout": "1",
                            }),
                        )
                        .await
                        .map_err(|e| e.to_string())?;

                    let hops = crate::discovery::tools::parse_traceroute(&raw);
                    let findings = crate::discovery::tools::analyse_path(&hops, target);
                    Ok(serde_json::json!({
                        "target": target,
                        "hops": hops.iter().map(|h| serde_json::json!({
                            "ttl": h.ttl, "address": h.address, "avg_ms": h.avg_ms,
                            "best_ms": h.best_ms, "worst_ms": h.worst_ms, "loss_pct": h.loss_pct,
                        })).collect::<Vec<_>>(),
                        "findings": findings,
                    }))
                }

                HostTask::Btest => {
                    use crate::routeros::btest::{self, BtestConfig, Direction, Protocol};
                    let p = &task.params;
                    let target = p
                        .get("target")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "bandwidth test carries no target".to_string())?;
                    let dir = Direction::parse(p.get("direction").and_then(|v| v.as_str()).unwrap_or("rx"))
                        .ok_or_else(|| "direction must be rx, tx or both".to_string())?;
                    let proto = Protocol::parse(p.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp"))
                        .ok_or_else(|| "protocol must be tcp or udp".to_string())?;

                    let mut cfg = BtestConfig::new(target, dir, proto);
                    cfg.duration = Duration::from_secs(
                        p.get("duration_s").and_then(|v| v.as_u64()).unwrap_or(10),
                    );
                    cfg.user = p.get("bt_user").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    cfg.password =
                        p.get("bt_pass").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    let r = btest::run(ros, &cfg).await.map_err(|e| e.to_string())?;
                    Ok(serde_json::to_value(&r).unwrap_or_default())
                }

                HostTask::Capture => {
                    use crate::discovery::capture;
                    let iface =
                        task.params.get("interface").and_then(|v| v.as_str()).unwrap_or("");
                    let secs =
                        task.params.get("duration_s").and_then(|v| v.as_u64()).unwrap_or(10);
                    let wireless =
                        task.params.get("wireless").and_then(|v| v.as_bool()).unwrap_or(false);

                    let cap = if wireless {
                        capture::run_wireless_capture(ros, iface, Duration::from_secs(secs), false)
                            .await
                    } else {
                        capture::run_packet_capture(ros, iface, Duration::from_secs(secs)).await
                    }
                    .map_err(|e| e.to_string())?;

                    let findings = capture::analyse(&cap);
                    Ok(serde_json::json!({ "capture": cap, "findings": findings }))
                }

                HostTask::WifiSignal => {
                    let snap = crate::discovery::collect::run(ros).await;
                    let findings = crate::discovery::findings::analyse(&snap);
                    Ok(serde_json::json!({
                        "clients": snap.clients.len(),
                        "radios": snap.radios.len(),
                        "findings": findings,
                    }))
                }
            }
        })
        .await;

        let ended = time::OffsetDateTime::now_utc();
        let body = match outcome {
            Ok(Ok(extra)) => {
                debug!(task = %task.task_id, kind = which.label(), "one-shot complete");
                serde_json::json!({
                    "task_id": task.task_id,
                    "session_id": task.session_id.to_string(),
                    "started_at": rfc3339(started),
                    "ended_at": rfc3339(ended),
                    "status": "ok",
                    "extra": extra,
                })
            }
            Ok(Err(e)) => self.failure_body(&task, started, ended, &e),
            Err(_) => self.failure_body(
                &task,
                started,
                ended,
                &format!("{} exceeded its time limit", which.label()),
            ),
        };
        self.enqueue(body);
    }

    fn failure_body(
        &self,
        task: &plan::Task,
        started: time::OffsetDateTime,
        ended: time::OffsetDateTime,
        err: &str,
    ) -> serde_json::Value {
        warn!(task = %task.task_id, error = err, "task failed");
        serde_json::json!({
            "task_id": task.task_id,
            "session_id": task.session_id.to_string(),
            "started_at": rfc3339(started),
            "ended_at": rfc3339(ended),
            "status": "failed",
            "error": err,
        })
    }

    fn enqueue_skipped(&mut self, task: &plan::Task, reason: &str) {
        let now = time::OffsetDateTime::now_utc();
        self.enqueue(serde_json::json!({
            "task_id": task.task_id,
            "session_id": task.session_id.to_string(),
            "started_at": rfc3339(now),
            "ended_at": rfc3339(now),
            "status": "skipped",
            "error": reason,
        }));
    }

    fn enqueue(&mut self, body: serde_json::Value) {
        let bytes = body.to_string().len();
        match self.spool.push(body, bytes) {
            Accepted::Queued => {}
            Accepted::QueuedEvicting(n) => {
                warn!(evicted = n, depth = self.spool.len(), "spool full; discarded older results")
            }
            Accepted::Rejected => warn!("spool full of protected results; discarded this one"),
        }
    }

    async fn drain_spool(&mut self) {
        while !self.spool.is_empty() {
            let batch = self.spool.take(SUBMIT_BATCH);
            let dropped = self.spool.stats().dropped;
            let n = batch.len();

            match self.client.submit_results(&self.identity, &batch, dropped).await {
                Ok(resp) => {
                    debug!(sent = n, accepted = resp.accepted, "results submitted");
                    self.spool.clear_dropped();
                    if n < SUBMIT_BATCH {
                        break; // spool drained
                    }
                }
                Err(e) => {
                    // Put the batch back rather than losing it to a transient
                    // error during the POST.
                    let restored: Vec<_> =
                        batch.into_iter().map(|v| { let b = v.to_string().len(); (v, b) }).collect();
                    self.spool.return_unsent(restored);
                    debug!(error = %e, depth = self.spool.len(), "submission failed; results retained");
                    break;
                }
            }
        }
    }
}

fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

/// Sleep, returning true if we were told to shut down instead.
async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, d: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}
