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
            capabilities: Capabilities {
                mqp: true,
                twamp_light: false,
                routeros_btest: cfg.can_bandwidth_test(),
                probe_port: cfg.probe_bind.port(),
            },
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

    fn assemble(
        cfg: Config,
        client: Client,
        identity: Identity,
        registry: Arc<Mutex<Registry>>,
    ) -> Self {
        Self {
            plan: Plan::new(Duration::from_secs(60)),
            spool: Spool::new(cfg.spool),
            cfg,
            client,
            identity,
            registry,
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
                continue; // check for more due work before sleeping
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
                    "session_id": format!("{:016x}", task.session_id),
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
            "session_id": format!("{:016x}", task.session_id),
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
            "session_id": format!("{:016x}", task.session_id),
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
