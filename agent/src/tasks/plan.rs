//! The agent's local view of what it should be measuring.
//!
//! The controller assigns work, but the agent must not depend on the controller
//! to keep working. The link to the controller is frequently down *because* of
//! the fault being measured, so an agent that stops measuring when it cannot
//! poll is blind exactly when it matters.
//!
//! So the plan is authoritative locally: recurring work is cached and keeps
//! firing on its own schedule indefinitely, and a successful poll refreshes it
//! rather than being required to produce it.
//!
//! One-shot diagnostics get the opposite treatment. They carry a deadline and
//! are abandoned once past it, because a traceroute executed hours late answers
//! a question nobody is still asking about a moment that has passed. Reporting
//! `skipped` is both more honest and more useful than reporting a stale result.
//!
//! All scheduling uses [`Instant`], never the wall clock. A container whose NTP
//! steps the system clock mid-outage must not thereby fire every cached task at
//! once, or stop firing them entirely.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// What kind of measurement a task asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    MqpProbe,
    TwampProbe,
    TcpConnect,
    RouterOsBtest,
    PathTrace,
    WifiSignal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Reflector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub agent_id: String,
    pub name: String,
    pub address: String,
    pub probe_port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub task_id: String,
    pub session_id: u64,
    pub kind: Kind,
    pub role: Role,
    pub peer: Option<Peer>,
    /// Opaque measurement parameters, passed through to the runner.
    pub params: serde_json::Value,
    /// Continuous-plan work: cached and kept running when offline.
    pub recurring: bool,
    /// How often recurring work repeats. Ignored for one-shots.
    pub interval: Option<Duration>,
}

/// A task held by the plan, with its local scheduling state.
#[derive(Debug, Clone)]
struct Scheduled {
    task: Task,
    /// When a one-shot stops being worth running. Converted from the wall-clock
    /// `expires_at` at accept time so later clock steps cannot disturb it.
    deadline: Option<Instant>,
    /// When this task should next fire.
    due_at: Instant,
}

/// Why a task was dropped without running.
#[derive(Debug, Clone, PartialEq)]
pub struct Skipped {
    pub task: Task,
    pub reason: &'static str,
}

pub const REASON_EXPIRED: &str = "one-shot expired before it could run";

#[derive(Debug)]
pub struct Plan {
    /// Cached continuous work, keyed by task id so a refresh updates in place
    /// rather than accumulating duplicates.
    recurring: HashMap<String, Scheduled>,
    /// Pending one-shots, oldest first.
    oneshot: Vec<Scheduled>,
    /// Fallback cadence for recurring work that arrives without one.
    default_interval: Duration,
}

impl Plan {
    pub fn new(default_interval: Duration) -> Self {
        Self {
            recurring: HashMap::new(),
            oneshot: Vec::new(),
            default_interval,
        }
    }

    pub fn recurring_len(&self) -> usize {
        self.recurring.len()
    }

    pub fn oneshot_len(&self) -> usize {
        self.oneshot.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recurring.is_empty() && self.oneshot.is_empty()
    }

    /// Merge freshly leased tasks into the plan.
    ///
    /// `expires_in` is how long a one-shot remains worth running, measured from
    /// now. Recurring tasks ignore it — continuous work never expires, which is
    /// the whole point of caching it.
    pub fn accept(&mut self, task: Task, expires_in: Option<Duration>, now: Instant) {
        if task.recurring {
            let interval = task.interval.unwrap_or(self.default_interval);
            match self.recurring.get_mut(&task.task_id) {
                // Refreshing an existing assignment must not reset its
                // schedule, or an agent polling faster than its measurement
                // interval would never actually fire.
                Some(existing) => {
                    existing.task = task;
                    existing.deadline = None;
                }
                None => {
                    let id = task.task_id.clone();
                    self.recurring.insert(
                        id,
                        Scheduled { task, deadline: None, due_at: now },
                    );
                    let _ = interval;
                }
            }
        } else {
            if self.oneshot.iter().any(|s| s.task.task_id == task.task_id) {
                return; // already queued; a repeated lease is not a second run
            }
            self.oneshot.push(Scheduled {
                task,
                deadline: expires_in.map(|d| now + d),
                due_at: now,
            });
        }
    }

    /// Remove one-shots that are past their deadline.
    ///
    /// Returned so the caller can report them as `skipped` — silently dropping
    /// them would leave an operator waiting forever for an answer.
    pub fn reap_expired(&mut self, now: Instant) -> Vec<Skipped> {
        let mut out = Vec::new();
        self.oneshot.retain(|s| match s.deadline {
            Some(d) if now >= d => {
                out.push(Skipped { task: s.task.clone(), reason: REASON_EXPIRED });
                false
            }
            _ => true,
        });
        out
    }

    /// Take the next task that is due to run, if any.
    ///
    /// One-shots win over recurring work: somebody is actively waiting on a
    /// diagnostic, whereas a continuous probe that slips by one cycle is
    /// unremarkable.
    ///
    /// This consults only local state, so it keeps returning work while the
    /// controller is unreachable.
    pub fn next_due(&mut self, now: Instant) -> Option<Task> {
        if !self.oneshot.is_empty() {
            let s = self.oneshot.remove(0);
            return Some(s.task);
        }

        let next = self
            .recurring
            .values()
            .filter(|s| s.due_at <= now)
            .min_by_key(|s| s.due_at)
            .map(|s| s.task.task_id.clone())?;

        let s = self.recurring.get_mut(&next)?;
        let interval = s.task.interval.unwrap_or(self.default_interval);

        // Schedule from the previous due time, not from now, so a slow run
        // does not make the cadence drift. If we have fallen more than a whole
        // interval behind, skip ahead instead of trying to catch up with a
        // burst — a burst would measure our own backlog rather than the path.
        s.due_at = if now.duration_since(s.due_at) > interval {
            now + interval
        } else {
            s.due_at + interval
        };

        Some(s.task.clone())
    }

    /// How long until the next recurring task is due, for sizing a sleep.
    pub fn time_until_due(&self, now: Instant) -> Option<Duration> {
        if !self.oneshot.is_empty() {
            return Some(Duration::ZERO);
        }
        self.recurring
            .values()
            .map(|s| s.due_at.saturating_duration_since(now))
            .min()
    }

    /// Drop a recurring assignment the controller has withdrawn.
    pub fn remove(&mut self, task_id: &str) -> bool {
        self.recurring.remove(task_id).is_some()
    }

    /// Replace the whole recurring set with what the controller just sent.
    ///
    /// Only safe after a *successful* poll. Applying it to an empty result from
    /// a failed poll would silently cancel every measurement the agent has —
    /// turning a controller outage into a monitoring outage, which is the exact
    /// failure this module exists to prevent.
    pub fn reconcile_recurring(&mut self, keep: &[String]) -> usize {
        let before = self.recurring.len();
        self.recurring.retain(|id, _| keep.iter().any(|k| k == id));
        before - self.recurring.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, recurring: bool, interval_s: u64) -> Task {
        Task {
            task_id: id.to_string(),
            session_id: 0xCAFE,
            kind: if recurring { Kind::MqpProbe } else { Kind::PathTrace },
            role: Role::Sender,
            peer: Some(Peer {
                agent_id: "peer".into(),
                name: "probe-a".into(),
                address: "172.16.220.138".into(),
                probe_port: 5401,
            }),
            params: serde_json::json!({}),
            recurring,
            interval: Some(Duration::from_secs(interval_s)),
        }
    }

    fn plan() -> (Plan, Instant) {
        (Plan::new(Duration::from_secs(60)), Instant::now())
    }

    #[test]
    fn empty_plan_has_nothing_due() {
        let (mut p, t0) = plan();
        assert!(p.is_empty());
        assert!(p.next_due(t0).is_none());
        assert!(p.time_until_due(t0).is_none());
    }

    #[test]
    fn recurring_task_fires_immediately_then_on_its_interval() {
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 10), None, t0);

        assert_eq!(p.next_due(t0).unwrap().task_id, "r1");
        assert!(p.next_due(t0).is_none(), "must not fire twice in one instant");
        assert!(p.next_due(t0 + Duration::from_secs(9)).is_none());
        assert_eq!(p.next_due(t0 + Duration::from_secs(10)).unwrap().task_id, "r1");
    }

    #[test]
    fn recurring_work_keeps_firing_with_no_controller_contact() {
        // The core requirement: measurement continues through an outage.
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 10), None, t0);

        let mut fired = 0;
        for i in 0..100 {
            if p.next_due(t0 + Duration::from_secs(i * 10)).is_some() {
                fired += 1;
            }
        }
        assert_eq!(fired, 100, "cached plan must run indefinitely while offline");
    }

    #[test]
    fn refreshing_an_assignment_does_not_reset_its_schedule() {
        // An agent polling every 10s for a task measured every 60s would never
        // fire if each poll pushed the due time back.
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 60), None, t0);
        assert!(p.next_due(t0).is_some());

        for i in 1..6 {
            p.accept(task("r1", true, 60), None, t0 + Duration::from_secs(i * 10));
        }
        assert_eq!(p.recurring_len(), 1, "refresh must update in place, not duplicate");
        assert_eq!(
            p.next_due(t0 + Duration::from_secs(60)).unwrap().task_id,
            "r1",
            "schedule survived repeated refreshes"
        );
    }

    #[test]
    fn cadence_does_not_drift_after_a_slow_run() {
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 10), None, t0);
        p.next_due(t0);

        // Fires 2s late; the next one should still land on the original grid
        // at t+20, not at t+22.
        assert!(p.next_due(t0 + Duration::from_secs(12)).is_some());
        assert!(p.next_due(t0 + Duration::from_secs(20)).is_some());
    }

    #[test]
    fn a_long_stall_skips_ahead_instead_of_bursting() {
        // After a 10-minute stall a catch-up burst would measure our own
        // backlog rather than the network.
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 10), None, t0);
        p.next_due(t0);

        let late = t0 + Duration::from_secs(600);
        assert!(p.next_due(late).is_some(), "one run at the stall");
        assert!(p.next_due(late).is_none(), "but not a burst of the 60 missed ones");
    }

    #[test]
    fn one_shot_runs_once_and_is_gone() {
        let (mut p, t0) = plan();
        p.accept(task("o1", false, 0), Some(Duration::from_secs(300)), t0);

        assert_eq!(p.next_due(t0).unwrap().task_id, "o1");
        assert!(p.next_due(t0).is_none());
        assert_eq!(p.oneshot_len(), 0);
    }

    #[test]
    fn expired_one_shot_is_reported_skipped_rather_than_run() {
        // A traceroute executed hours late answers a question nobody is still
        // asking, about a moment that has passed.
        let (mut p, t0) = plan();
        p.accept(task("o1", false, 0), Some(Duration::from_secs(300)), t0);

        let later = t0 + Duration::from_secs(301);
        let reaped = p.reap_expired(later);
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].task.task_id, "o1");
        assert_eq!(reaped[0].reason, REASON_EXPIRED);

        assert!(p.next_due(later).is_none(), "must not run after being reaped");
    }

    #[test]
    fn unexpired_one_shot_survives_reaping() {
        let (mut p, t0) = plan();
        p.accept(task("o1", false, 0), Some(Duration::from_secs(300)), t0);
        assert!(p.reap_expired(t0 + Duration::from_secs(299)).is_empty());
        assert_eq!(p.oneshot_len(), 1);
    }

    #[test]
    fn recurring_work_never_expires() {
        // Continuous work is cached precisely so an outage cannot stop it.
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 10), Some(Duration::from_secs(1)), t0);

        let much_later = t0 + Duration::from_secs(86_400);
        assert!(p.reap_expired(much_later).is_empty());
        assert!(p.next_due(much_later).is_some());
    }

    #[test]
    fn one_shots_take_priority_over_recurring_work() {
        // Someone is actively waiting on a diagnostic; a probe that slips one
        // cycle is unremarkable.
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 10), None, t0);
        p.accept(task("o1", false, 0), None, t0);

        assert_eq!(p.next_due(t0).unwrap().task_id, "o1");
        assert_eq!(p.next_due(t0).unwrap().task_id, "r1");
    }

    #[test]
    fn duplicate_lease_of_a_one_shot_runs_it_only_once() {
        // Re-leasing after a lease expiry must not double-execute a diagnostic.
        let (mut p, t0) = plan();
        p.accept(task("o1", false, 0), None, t0);
        p.accept(task("o1", false, 0), None, t0);
        assert_eq!(p.oneshot_len(), 1);
    }

    #[test]
    fn time_until_due_sizes_the_sleep() {
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 30), None, t0);
        assert_eq!(p.time_until_due(t0), Some(Duration::ZERO));

        p.next_due(t0);
        assert_eq!(p.time_until_due(t0), Some(Duration::from_secs(30)));
        assert_eq!(p.time_until_due(t0 + Duration::from_secs(10)), Some(Duration::from_secs(20)));
    }

    #[test]
    fn a_pending_one_shot_makes_the_sleep_zero() {
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 300), None, t0);
        p.next_due(t0);
        p.accept(task("o1", false, 0), None, t0);
        assert_eq!(p.time_until_due(t0), Some(Duration::ZERO));
    }

    #[test]
    fn reconcile_drops_withdrawn_assignments_only() {
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 10), None, t0);
        p.accept(task("r2", true, 10), None, t0);
        p.accept(task("r3", true, 10), None, t0);

        let removed = p.reconcile_recurring(&["r1".into(), "r3".into()]);
        assert_eq!(removed, 1);
        assert_eq!(p.recurring_len(), 2);
        assert!(p.remove("r1"));
        assert!(!p.remove("nope"));
    }

    #[test]
    fn reconciling_against_nothing_clears_everything() {
        // Documents the hazard: this must only ever follow a *successful* poll.
        // Applying it to a failed poll's empty result would turn a controller
        // outage into a monitoring outage.
        let (mut p, t0) = plan();
        p.accept(task("r1", true, 10), None, t0);
        assert_eq!(p.reconcile_recurring(&[]), 1);
        assert_eq!(p.recurring_len(), 0);
    }

    #[test]
    fn several_recurring_tasks_fire_oldest_due_first() {
        let (mut p, t0) = plan();
        p.accept(task("slow", true, 100), None, t0);
        p.accept(task("fast", true, 10), None, t0);

        // Both are due at t0; drain them.
        let mut first = vec![p.next_due(t0).unwrap().task_id, p.next_due(t0).unwrap().task_id];
        first.sort();
        assert_eq!(first, vec!["fast", "slow"]);

        // Only the fast one comes back inside the next 10 seconds.
        let t = t0 + Duration::from_secs(10);
        assert_eq!(p.next_due(t).unwrap().task_id, "fast");
        assert!(p.next_due(t).is_none());
    }

    #[test]
    fn interval_defaults_when_the_controller_omits_one() {
        let (mut p, t0) = plan(); // default 60s
        let mut t = task("r1", true, 0);
        t.interval = None;
        p.accept(t, None, t0);

        p.next_due(t0);
        assert!(p.next_due(t0 + Duration::from_secs(59)).is_none());
        assert!(p.next_due(t0 + Duration::from_secs(60)).is_some());
    }
}
