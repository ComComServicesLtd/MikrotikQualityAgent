//! Client for the controller REST API (see `docs/api.md`).
//!
//! Two behaviours here matter more than the HTTP plumbing.
//!
//! **Identity persists.** The controller-assigned `agent_id` and token are
//! written to the state directory, so a container restart re-registers as the
//! same agent rather than appearing as a new one and orphaning its history.
//! This is one small write at enrolment, not a per-result write, so it costs
//! the device's NAND essentially nothing.
//!
//! **Reconnection is jittered.** When a controller comes back after an outage,
//! every agent in the fleet has been failing on the same cadence and is poised
//! to retry at the same moment. Un-jittered backoff would have them arrive
//! together and knock it over again.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Persisted agent identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub agent_id: String,
    pub token: String,
    pub group: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("controller rejected our credentials")]
    Unauthorized,
    #[error("controller returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("could not parse controller response: {0}")]
    Decode(String),
    #[error("state directory error: {0}")]
    State(String),
}

impl ControllerError {
    /// Whether retrying could plausibly succeed.
    ///
    /// The distinction drives the retry loop: a network blip should be retried
    /// forever, but a rejected token will never succeed and retrying it just
    /// hammers the controller with requests that cannot work.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            // 5xx is the controller's problem and may pass; 4xx is ours.
            Self::Http { status, .. } => *status >= 500 || *status == 429,
            Self::Unauthorized => false,
            Self::Decode(_) => false,
            Self::State(_) => false,
        }
    }

    /// Whether this should make the agent re-enrol from scratch.
    pub fn needs_reregistration(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }
}

/// Exponential backoff with full jitter, bounded.
///
/// Full jitter (a uniform draw over `[0, backoff]`) rather than a fixed
/// multiplier: it spreads a recovering fleet across the whole window instead of
/// merely delaying the stampede.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self { base, max, attempt: 0 }
    }

    /// Next delay to wait. Advances the attempt counter.
    pub fn next_delay(&mut self, rand_unit: f64) -> Duration {
        // Cap the exponent before it reaches the width of the type, or the
        // shift overflows and the delay collapses to nothing.
        let shift = self.attempt.min(20);
        let ceiling = self
            .base
            .saturating_mul(1u32 << shift)
            .min(self.max);
        self.attempt = self.attempt.saturating_add(1);

        let unit = rand_unit.clamp(0.0, 1.0);
        // Never return zero: a "retry immediately" loop is a busy-wait against
        // a controller that is already struggling.
        let jittered = ceiling.mul_f64(unit).max(self.base.min(ceiling));
        jittered
    }

    /// Reset after a success.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(300))
    }
}

/// Where the agent's identity lives on disk.
pub fn identity_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("identity.json")
}

/// Load a previously persisted identity, if any.
///
/// A missing or unreadable file is not an error: it simply means this agent has
/// not enrolled yet, or its state mount was not provisioned. Both are recovered
/// by registering again.
pub fn load_identity(state_dir: &str) -> Option<Identity> {
    let path = identity_path(state_dir);
    let raw = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str(&raw) {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "ignoring unreadable identity file");
            None
        }
    }
}

/// Persist the identity so a restart is not a new agent.
pub fn save_identity(state_dir: &str, id: &Identity) -> Result<(), ControllerError> {
    let dir = Path::new(state_dir);
    std::fs::create_dir_all(dir)
        .map_err(|e| ControllerError::State(format!("creating {}: {e}", dir.display())))?;

    let path = identity_path(state_dir);
    let body = serde_json::to_string_pretty(id)
        .map_err(|e| ControllerError::State(format!("serialising identity: {e}")))?;

    // Write-then-rename, so a power cut mid-write cannot leave a truncated
    // identity that would silently re-enrol the agent under a new id.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body)
        .map_err(|e| ControllerError::State(format!("writing {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| ControllerError::State(format!("renaming into {}: {e}", path.display())))?;
    Ok(())
}

/// Build the URL for an API path, tolerating a base with or without a trailing
/// slash.
pub fn endpoint(base: &str, path: &str) -> String {
    format!("{}/api/v1/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_built_without_doubled_slashes() {
        for base in ["https://c.example.net", "https://c.example.net/"] {
            assert_eq!(
                endpoint(base, "agents/register"),
                "https://c.example.net/api/v1/agents/register"
            );
            assert_eq!(
                endpoint(base, "/agents/register"),
                "https://c.example.net/api/v1/agents/register"
            );
        }
    }

    #[test]
    fn transport_and_server_errors_are_retryable() {
        assert!(ControllerError::Transport("reset".into()).is_retryable());
        assert!(ControllerError::Http { status: 503, body: String::new() }.is_retryable());
        assert!(ControllerError::Http { status: 429, body: String::new() }.is_retryable());
    }

    #[test]
    fn client_errors_are_not_retried() {
        // Retrying a rejected token forever just hammers the controller with
        // requests that can never succeed.
        assert!(!ControllerError::Unauthorized.is_retryable());
        assert!(!ControllerError::Http { status: 400, body: String::new() }.is_retryable());
        assert!(!ControllerError::Decode("bad json".into()).is_retryable());
    }

    #[test]
    fn only_unauthorized_triggers_reregistration() {
        assert!(ControllerError::Unauthorized.needs_reregistration());
        assert!(!ControllerError::Transport("x".into()).needs_reregistration());
        assert!(!ControllerError::Http { status: 500, body: String::new() }.needs_reregistration());
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        // rand_unit = 1.0 gives the top of the jitter window, i.e. the ceiling.
        let delays: Vec<u64> =
            (0..10).map(|_| b.next_delay(1.0).as_secs()).collect();

        assert_eq!(&delays[..4], &[1, 2, 4, 8]);
        assert!(delays.iter().all(|d| *d <= 60), "must never exceed the cap: {delays:?}");
        assert_eq!(delays[9], 60, "should be pinned at the cap by then");
    }

    #[test]
    fn backoff_does_not_overflow_after_many_failures() {
        // A multi-day outage must not shift the exponent past the type width
        // and collapse the delay back to zero.
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(300));
        for _ in 0..10_000 {
            b.next_delay(1.0);
        }
        let d = b.next_delay(1.0);
        assert_eq!(d, Duration::from_secs(300), "stays pinned at the cap, got {d:?}");
    }

    #[test]
    fn full_jitter_spreads_retries_across_the_window() {
        // The point of jitter: a recovering fleet must not arrive together.
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(64));
        for _ in 0..6 {
            b.next_delay(0.5);
        }

        let mut low = Backoff::new(Duration::from_secs(1), Duration::from_secs(64));
        for _ in 0..6 {
            low.next_delay(0.0);
        }
        let small = low.next_delay(0.0);
        let large = b.next_delay(1.0);
        assert!(small < large, "different draws must produce different delays");
    }

    #[test]
    fn backoff_never_returns_zero() {
        // Otherwise a rand_unit of 0 becomes a busy-wait against a controller
        // that is already in trouble.
        let mut b = Backoff::new(Duration::from_millis(500), Duration::from_secs(60));
        for _ in 0..20 {
            assert!(b.next_delay(0.0) > Duration::ZERO);
        }
    }

    #[test]
    fn reset_returns_to_the_base_delay() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        for _ in 0..5 {
            b.next_delay(1.0);
        }
        assert!(b.attempt() > 0);
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.next_delay(1.0), Duration::from_secs(1));
    }

    #[test]
    fn identity_survives_a_save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("mqagent-id-{}", std::process::id()));
        let dir_s = dir.to_string_lossy().to_string();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(load_identity(&dir_s).is_none(), "nothing enrolled yet");

        let id = Identity {
            agent_id: "b2c3".into(),
            token: "secret-token".into(),
            group: "west-wan".into(),
        };
        save_identity(&dir_s, &id).unwrap();
        assert_eq!(load_identity(&dir_s).unwrap(), id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_identity_file_is_ignored_rather_than_fatal() {
        // A truncated file must degrade to "re-enrol", not crash-loop the
        // container on a device nobody can easily get a shell on.
        let dir = std::env::temp_dir().join(format!("mqagent-bad-{}", std::process::id()));
        let dir_s = dir.to_string_lossy().to_string();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(identity_path(&dir_s), b"{ not json").unwrap();

        assert!(load_identity(&dir_s).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
