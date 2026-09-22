package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func baseResult() Result {
	now := time.Now()
	return Result{
		TaskID:    "t_01J",
		SessionID: 0x7F3A9C2B1D4E8A60,
		StartedAt: now,
		EndedAt:   now.Add(6 * time.Second),
		Status:    StatusOK,
	}
}

func TestValidAcceptsAWellFormedResult(t *testing.T) {
	if err := baseResult().Valid(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidRejectsInvertedTimestamps(t *testing.T) {
	r := baseResult()
	r.EndedAt = r.StartedAt.Add(-time.Second)
	if err := r.Valid(); err == nil {
		t.Fatal("a result that ended before it started must be rejected")
	}
}

func TestValidRejectsReceivedExceedingSent(t *testing.T) {
	// The failure this guards: one impossible row skews every rollup that
	// touches its bucket, and the raw sample is long gone by the time anyone
	// notices the graph is wrong.
	r := baseResult()
	r.Loss = &LossStats{Sent: 100, Received: 150}
	if err := r.Valid(); err == nil {
		t.Fatal("received > sent must be rejected")
	}
}

func TestValidRejectsOutOfRangeLoss(t *testing.T) {
	for _, pct := range []float64{-1, 100.5} {
		r := baseResult()
		r.Loss = &LossStats{Sent: 10, Received: 5, LossPct: pct}
		if err := r.Valid(); err == nil {
			t.Fatalf("loss_pct %v must be rejected", pct)
		}
	}
}

func TestValidRequiresACodecWithMOS(t *testing.T) {
	// A MOS without its codec is meaningless — the same path scores very
	// differently for G.711 and G.729.
	r := baseResult()
	r.MOS = &MOSStats{RFactor: 88.4, MOS: 4.32}
	err := r.Valid()
	if err == nil {
		t.Fatal("MOS without a codec must be rejected")
	}
	if !strings.Contains(err.Error(), "codec") {
		t.Fatalf("error should name the missing codec, got %q", err)
	}
}

func TestValidAcceptsWidebandMOSAboveTheNarrowbandCeiling(t *testing.T) {
	// Wideband codecs legitimately exceed 4.5; clamping at 4.5 here would
	// reject every valid Opus result.
	r := baseResult()
	r.MOS = &MOSStats{Codec: "opus", RFactor: 122, MOS: 4.72}
	if err := r.Valid(); err != nil {
		t.Fatalf("wideband MOS 4.72 should be accepted, got %v", err)
	}
}

func TestValidRejectsImpossibleMOS(t *testing.T) {
	for _, m := range []float64{0.5, 5.2} {
		r := baseResult()
		r.MOS = &MOSStats{Codec: "g711", MOS: m}
		if err := r.Valid(); err == nil {
			t.Fatalf("MOS %v must be rejected", m)
		}
	}
}

func TestValidRejectsOutOfRangeDSCP(t *testing.T) {
	r := baseResult()
	r.DSCP = &DSCPStats{Requested: 64} // DSCP is 6 bits: 0-63
	if err := r.Valid(); err == nil {
		t.Fatal("DSCP 64 must be rejected")
	}
}

func TestValidRejectsUnknownStatus(t *testing.T) {
	r := baseResult()
	r.Status = "weird"
	if err := r.Valid(); err == nil {
		t.Fatal("unknown status must be rejected")
	}
}

func TestSessionIDSurvivesJSONRoundTripAtFullWidth(t *testing.T) {
	// session_id is a uint64 and is serialised as a string: JSON numbers are
	// float64 in most parsers, which silently loses precision above 2^53 and
	// would produce a session ID the reflector never granted.
	const want uint64 = 0xFFFFFFFFFFFFFFFF
	task := Task{TaskID: "t1", SessionID: want, Kind: TaskMQPProbe, Role: RoleSender}

	blob, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"18446744073709551615"`) {
		t.Fatalf("session_id must serialise as a string, got %s", blob)
	}

	var back Task
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back.SessionID != want {
		t.Fatalf("session_id lost precision: want %d, got %d", want, back.SessionID)
	}
}

func TestAgentStateIsDerivedFromLastSeen(t *testing.T) {
	now := time.Now()
	recent := now.Add(-10 * time.Second)
	old := now.Add(-10 * time.Minute)

	cases := []struct {
		name string
		a    Agent
		want string
	}{
		{"never heard from", Agent{}, "pending"},
		{"recently seen", Agent{LastSeenAt: &recent}, "online"},
		{"long silent", Agent{LastSeenAt: &old}, "stale"},
		{"disabled wins over liveness", Agent{LastSeenAt: &recent, Disabled: true}, "disabled"},
	}
	for _, c := range cases {
		if got := c.a.State(now); got != c.want {
			t.Errorf("%s: want %q, got %q", c.name, c.want, got)
		}
	}
}

func TestStaleThresholdAllowsThreeMissedHeartbeats(t *testing.T) {
	// Agents heartbeat every 30s. Marking one stale after a single missed beat
	// would flap the mesh on any transient hiccup.
	if StaleAfter < 90*time.Second {
		t.Fatalf("StaleAfter %v is too aggressive for a 30s heartbeat", StaleAfter)
	}
}

func TestOmittedStatsSectionsStayAbsentInJSON(t *testing.T) {
	// "no jitter data" and "zero jitter" are different facts. If absent
	// sections serialised as zero-valued objects, the controller would store
	// zeros and every average over them would be wrong.
	blob, err := json.Marshal(baseResult())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"rtt", "jitter", "loss", "mos", "throughput"} {
		if strings.Contains(string(blob), `"`+field+`"`) {
			t.Errorf("absent %s should be omitted, got %s", field, blob)
		}
	}
}

func TestContinuousKindsAreRecurringAndDiagnosticsAreNot(t *testing.T) {
	// The split decides what survives a controller outage, so it is worth
	// pinning rather than leaving to the reader of a switch statement.
	for _, k := range []TaskKind{TaskMQPProbe, TaskTwampProbe, TaskTCPConnect} {
		if !k.Recurring() {
			t.Errorf("%s is continuous measurement and should be recurring", k)
		}
	}
	for _, k := range []TaskKind{TaskPathTrace, TaskWifiSignal, TaskRouterOSBtest} {
		if k.Recurring() {
			t.Errorf("%s is a diagnostic and should not default to recurring", k)
		}
	}
}

func TestOneShotGoesStaleButContinuousNeverDoes(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)

	oneShot := Task{Kind: TaskPathTrace, ExpiresAt: past}
	if !oneShot.Stale(now) {
		t.Fatal("an expired traceroute must be skipped, not run late")
	}

	fresh := Task{Kind: TaskPathTrace, ExpiresAt: now.Add(time.Hour)}
	if fresh.Stale(now) {
		t.Fatal("an unexpired one-shot should still run")
	}

	// The continuous plan is cached precisely so it keeps running through an
	// outage; it must never be discarded for age.
	continuous := Task{Kind: TaskMQPProbe, Recurring: true, ExpiresAt: past}
	if continuous.Stale(now) {
		t.Fatal("continuous plan work must never go stale")
	}

	noExpiry := Task{Kind: TaskWifiSignal}
	if noExpiry.Stale(now) {
		t.Fatal("a one-shot with no expiry set should not be considered stale")
	}
}
