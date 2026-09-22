//! Bounded in-memory result spool.
//!
//! Measurement must not stop when the controller is unreachable — the link to
//! the controller is often down *because* of the fault being measured, so that
//! window is the most valuable data the agent will ever hold. Results are
//! therefore queued locally and submitted when comms return.
//!
//! The spool is memory-only by design. The target devices store their container
//! on NAND with limited write endurance, and writing every result through to
//! flash would wear it for data that is, by definition, about to be uploaded.
//! The cost is that a container restart loses whatever is queued.
//!
//! # What gets dropped
//!
//! A plain ring buffer keeps the most recent results and silently discards the
//! onset of the incident — usually the part that explains it. This spool
//! instead protects the oldest [`SpoolConfig::onset_reserve`] entries and
//! evicts from immediately after them, so a long outage retains:
//!
//! ```text
//!   [ onset: how it broke ][ ...thinned middle... ][ recent: current state ]
//! ```
//!
//! Because a successful drain empties the spool, "oldest entries" is always
//! "the first results after the last successful submission" — the onset needs
//! no outage tracking to identify.
//!
//! Every discard is counted. A gap that is not reported is a time series that
//! lies about its own completeness, so [`SpoolStats::dropped`] is surfaced to
//! the controller rather than kept as a local curiosity.

use std::collections::VecDeque;

/// Default ceiling on queued results.
///
/// At roughly 800 bytes of JSON per result this is about 8 MB — affordable in a
/// 64 MB container budget, and around 13 hours of a 5-second cadence against
/// one peer.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Hard ceiling on spool memory, whichever limit is reached first.
pub const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Share of the spool reserved for the onset of an outage.
pub const DEFAULT_ONSET_FRACTION: f64 = 0.2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    /// Number of oldest entries that are never evicted while the spool is full.
    pub onset_reserve: usize,
}

impl SpoolConfig {
    pub fn new(max_entries: usize, max_bytes: usize, onset_fraction: f64) -> Self {
        let reserve = (max_entries as f64 * onset_fraction.clamp(0.0, 0.9)) as usize;
        Self {
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            // The reserve must stay strictly below capacity, or a full spool
            // would have nothing evictable and could never accept a new result.
            onset_reserve: reserve.min(max_entries.saturating_sub(1)),
        }
    }
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BYTES, DEFAULT_ONSET_FRACTION)
    }
}

/// What happened to a pushed result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// Queued with room to spare.
    Queued,
    /// Queued, but older results were discarded to make room.
    QueuedEvicting(usize),
    /// Rejected: the spool is full of protected entries and this result is too
    /// large to fit. Only reachable via the byte ceiling.
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpoolStats {
    pub entries: usize,
    pub bytes: usize,
    /// Results discarded since the last successful submission. Reported
    /// upstream so the resulting gap is visible rather than silent.
    pub dropped: u64,
    /// Discards over the agent's whole lifetime, for health reporting.
    pub dropped_total: u64,
}

#[derive(Debug)]
struct Entry<T> {
    item: T,
    bytes: usize,
}

#[derive(Debug)]
pub struct Spool<T> {
    cfg: SpoolConfig,
    entries: VecDeque<Entry<T>>,
    bytes: usize,
    dropped: u64,
    dropped_total: u64,
}

impl<T> Spool<T> {
    pub fn new(cfg: SpoolConfig) -> Self {
        Self {
            cfg,
            entries: VecDeque::with_capacity(cfg.max_entries.min(1024)),
            bytes: 0,
            dropped: 0,
            dropped_total: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn stats(&self) -> SpoolStats {
        SpoolStats {
            entries: self.entries.len(),
            bytes: self.bytes,
            dropped: self.dropped,
            dropped_total: self.dropped_total,
        }
    }

    /// Queue a result. `bytes` is its serialised size, used for the memory
    /// ceiling.
    pub fn push(&mut self, item: T, bytes: usize) -> Accepted {
        let mut evicted = 0usize;

        while self.would_exceed(bytes) {
            // Everything present is protected — the only way out is to refuse
            // the newcomer. Preferring the onset over one fresh sample is the
            // right trade: the onset is irreplaceable, one more recent sample
            // is not.
            if self.entries.len() <= self.cfg.onset_reserve {
                self.dropped += 1;
                self.dropped_total += 1;
                return Accepted::Rejected;
            }
            // Evict the oldest *unprotected* entry: just past the reserve.
            if let Some(e) = self.entries.remove(self.cfg.onset_reserve) {
                self.bytes -= e.bytes;
                evicted += 1;
                self.dropped += 1;
                self.dropped_total += 1;
            } else {
                break;
            }
        }

        self.bytes += bytes;
        self.entries.push_back(Entry { item, bytes });

        if evicted == 0 {
            Accepted::Queued
        } else {
            Accepted::QueuedEvicting(evicted)
        }
    }

    fn would_exceed(&self, incoming: usize) -> bool {
        self.entries.len() >= self.cfg.max_entries
            || self.bytes + incoming > self.cfg.max_bytes
    }

    /// Take up to `max` of the oldest results for submission.
    ///
    /// Oldest-first matters: it means a submission that only partly succeeds
    /// still makes progress through the backlog in chronological order, and the
    /// onset is delivered before anything else.
    pub fn take(&mut self, max: usize) -> Vec<T> {
        let n = max.min(self.entries.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(e) = self.entries.pop_front() {
                self.bytes -= e.bytes;
                out.push(e.item);
            }
        }
        out
    }

    /// Put results back at the front after a failed submission, preserving
    /// order.
    ///
    /// Without this a transient network error during the POST would destroy the
    /// batch it was trying to save.
    pub fn return_unsent(&mut self, items: Vec<(T, usize)>) {
        for (item, bytes) in items.into_iter().rev() {
            // Re-admitting must not push the spool past its ceiling, so evict
            // from the back — these returned entries are older and outrank the
            // newest arrivals.
            while self.entries.len() >= self.cfg.max_entries
                || self.bytes + bytes > self.cfg.max_bytes
            {
                match self.entries.pop_back() {
                    Some(e) => {
                        self.bytes -= e.bytes;
                        self.dropped += 1;
                        self.dropped_total += 1;
                    }
                    None => break,
                }
            }
            self.bytes += bytes;
            self.entries.push_front(Entry { item, bytes });
        }
    }

    /// Clear the per-outage drop counter after it has been reported upstream.
    pub fn clear_dropped(&mut self) {
        self.dropped = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spool of 10 with a reserve of 2, so boundaries are easy to reason
    /// about. Each entry counts as 1 byte unless stated otherwise.
    fn small() -> Spool<u32> {
        Spool::new(SpoolConfig { max_entries: 10, max_bytes: 1_000, onset_reserve: 2 })
    }

    fn contents(s: &Spool<u32>) -> Vec<u32> {
        s.entries.iter().map(|e| e.item).collect()
    }

    #[test]
    fn empty_spool_reports_nothing() {
        let s = small();
        assert!(s.is_empty());
        assert_eq!(s.stats(), SpoolStats::default());
    }

    #[test]
    fn queues_and_takes_in_order() {
        let mut s = small();
        for i in 0..5 {
            assert_eq!(s.push(i, 1), Accepted::Queued);
        }
        assert_eq!(s.take(10), vec![0, 1, 2, 3, 4], "oldest first");
        assert!(s.is_empty());
        assert_eq!(s.stats().bytes, 0);
    }

    #[test]
    fn take_respects_the_batch_limit() {
        let mut s = small();
        for i in 0..6 {
            s.push(i, 1);
        }
        assert_eq!(s.take(3), vec![0, 1, 2]);
        assert_eq!(contents(&s), vec![3, 4, 5], "remainder stays queued, in order");
    }

    #[test]
    fn overflow_preserves_the_onset_and_the_recent() {
        // The headline behaviour: after a long outage we still hold how it
        // started and what is happening now, with the middle thinned.
        let mut s = small(); // cap 10, reserve 2
        for i in 0..30 {
            s.push(i, 1);
        }

        let held = contents(&s);
        assert_eq!(held.len(), 10);
        assert_eq!(&held[..2], &[0, 1], "onset must survive");
        assert_eq!(
            &held[held.len() - 3..],
            &[27, 28, 29],
            "most recent must survive"
        );
        assert_eq!(s.stats().dropped, 20);
    }

    #[test]
    fn a_plain_ring_buffer_would_have_lost_the_onset() {
        // Guards the design decision itself: if eviction ever reverts to
        // dropping the true front, this fails.
        let mut s = small();
        for i in 0..100 {
            s.push(i, 1);
        }
        assert!(contents(&s).contains(&0), "entry 0 is the onset and is protected");
        assert!(!contents(&s).contains(&50), "middle is what gets thinned");
    }

    #[test]
    fn eviction_is_reported_on_the_push_that_caused_it() {
        let mut s = small();
        for i in 0..10 {
            assert_eq!(s.push(i, 1), Accepted::Queued);
        }
        assert_eq!(s.push(10, 1), Accepted::QueuedEvicting(1));
    }

    #[test]
    fn byte_ceiling_is_enforced_independently_of_count() {
        // 100 bytes total, 10 entries max: the byte cap must bite first.
        let mut s = Spool::new(SpoolConfig { max_entries: 10, max_bytes: 100, onset_reserve: 2 });
        for i in 0..4 {
            s.push(i, 30);
        }
        assert!(s.stats().bytes <= 100, "bytes {} exceeded cap", s.stats().bytes);
        assert!(s.len() < 4, "byte cap should have evicted before the count cap");
    }

    #[test]
    fn an_oversized_result_is_rejected_rather_than_evicting_the_onset() {
        // Degenerate case reachable only through the byte ceiling. Losing one
        // fresh sample beats losing irreplaceable onset data.
        let mut s = Spool::new(SpoolConfig { max_entries: 10, max_bytes: 100, onset_reserve: 2 });
        s.push(1, 40);
        s.push(2, 40);
        assert_eq!(s.push(3, 90), Accepted::Rejected);
        assert_eq!(contents(&s), vec![1, 2], "protected entries untouched");
        assert_eq!(s.stats().dropped, 1);
    }

    #[test]
    fn config_keeps_the_reserve_below_capacity() {
        // A reserve equal to capacity would make a full spool unable to accept
        // anything ever again.
        let cfg = SpoolConfig::new(10, 1000, 1.0);
        assert!(cfg.onset_reserve < cfg.max_entries);

        let mut s: Spool<u32> = Spool::new(cfg);
        for i in 0..40 {
            s.push(i, 1);
        }
        assert_eq!(s.len(), 10);
        assert!(contents(&s).contains(&39), "newest must still be accepted");
    }

    #[test]
    fn draining_resets_what_counts_as_the_onset() {
        // After a successful submission the spool is empty, so the next
        // outage's first results become the new protected onset. No explicit
        // outage tracking required.
        let mut s = small();
        for i in 0..30 {
            s.push(i, 1);
        }
        let _ = s.take(100);
        assert!(s.is_empty());

        for i in 100..130 {
            s.push(i, 1);
        }
        assert_eq!(&contents(&s)[..2], &[100, 101], "new onset, not the old one");
    }

    #[test]
    fn failed_submission_returns_the_batch_in_order() {
        // A transient error during the POST must not destroy the batch it was
        // trying to save.
        let mut s = small();
        for i in 0..5 {
            s.push(i, 1);
        }
        let batch = s.take(3);
        assert_eq!(batch, vec![0, 1, 2]);

        s.return_unsent(batch.into_iter().map(|i| (i, 1)).collect());
        assert_eq!(contents(&s), vec![0, 1, 2, 3, 4], "order fully restored");
    }

    #[test]
    fn returned_batch_respects_capacity_by_dropping_the_newest() {
        // Returned entries are older than what arrived while the POST was in
        // flight, and the onset outranks recent samples.
        let mut s = small(); // cap 10
        for i in 0..3 {
            s.push(i, 1);
        }
        let batch = s.take(3);
        for i in 50..60 {
            s.push(i, 1);
        }
        assert_eq!(s.len(), 10);

        s.return_unsent(batch.into_iter().map(|i| (i, 1)).collect());
        let held = contents(&s);
        assert_eq!(s.len(), 10, "never exceeds capacity");
        assert_eq!(&held[..3], &[0, 1, 2], "returned entries are at the front");
        assert!(!held.contains(&59), "newest were sacrificed instead");
    }

    #[test]
    fn dropped_counter_separates_this_outage_from_lifetime() {
        let mut s = small();
        for i in 0..20 {
            s.push(i, 1);
        }
        assert_eq!(s.stats().dropped, 10);
        assert_eq!(s.stats().dropped_total, 10);

        // Reported upstream, so the per-outage counter resets; the lifetime
        // figure must not.
        s.clear_dropped();
        assert_eq!(s.stats().dropped, 0);
        assert_eq!(s.stats().dropped_total, 10);
    }

    #[test]
    fn byte_accounting_stays_exact_across_churn() {
        // A leak here silently shrinks effective capacity until the spool
        // refuses everything.
        let mut s = Spool::new(SpoolConfig { max_entries: 50, max_bytes: 10_000, onset_reserve: 5 });
        for round in 0..10 {
            for i in 0..20 {
                s.push(round * 100 + i, 7);
            }
            let _ = s.take(8);
        }
        let expected = s.entries.iter().map(|e| e.bytes).sum::<usize>();
        assert_eq!(s.stats().bytes, expected);

        let _ = s.take(usize::MAX);
        assert_eq!(s.stats().bytes, 0, "fully drained spool must report zero bytes");
    }

    #[test]
    fn default_config_is_sane_for_the_target_device() {
        let c = SpoolConfig::default();
        assert_eq!(c.max_entries, DEFAULT_MAX_ENTRIES);
        assert!(c.onset_reserve > 0, "onset protection must actually be on");
        assert!(c.onset_reserve < c.max_entries);
        // 8 MB must stay comfortably inside a 64 MB container budget.
        assert!(c.max_bytes <= 16 * 1024 * 1024);
    }
}
