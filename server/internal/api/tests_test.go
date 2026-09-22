package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
)

func online(caps model.Capabilities) model.Agent {
	now := time.Now()
	return model.Agent{Name: "a", Capabilities: caps, LastSeenAt: &now}
}

func TestKindsDeclareWhatTheyNeed(t *testing.T) {
	// The distinction that decides what a test request must supply: some kinds
	// measure between two agents, others aim at an arbitrary address.
	if !model.TaskMQPProbe.NeedsPeer() || !model.TaskTwampProbe.NeedsPeer() {
		t.Error("probe kinds measure between agents")
	}
	if model.TaskPathTrace.NeedsPeer() {
		t.Error("a traceroute needs a target, not a peer agent — that is the point of it")
	}
	if !model.TaskPathTrace.NeedsTarget() || !model.TaskRouterOSBtest.NeedsTarget() {
		t.Error("these aim at an address")
	}
	if model.TaskPacketCapture.NeedsTarget() || model.TaskPacketCapture.NeedsPeer() {
		t.Error("a capture needs neither: it looks at the local wire")
	}
}

func TestRouterOSDependentKindsAreIdentified(t *testing.T) {
	for _, k := range []model.TaskKind{
		model.TaskRouterOSBtest, model.TaskPathTrace,
		model.TaskWifiSignal, model.TaskPacketCapture,
	} {
		if !k.NeedsRouterOS() {
			t.Errorf("%s runs through the host router's API", k)
		}
	}
	if model.TaskMQPProbe.NeedsRouterOS() {
		t.Error("an MQP probe runs from the container itself")
	}
}

func TestAnAgentWithoutRouterOSIsRefusedUpFront(t *testing.T) {
	// Queueing this would waste the operator's time: they would wait for a
	// result that arrives minutes later saying "skipped".
	a := online(model.Capabilities{MQP: true, RouterOSBtest: false})
	reason := agentCanRun(a, model.TaskRouterOSBtest)
	if reason == "" {
		t.Fatal("should refuse")
	}
	if !contains(reason, "MQ_ROUTEROS_HOST") {
		t.Errorf("the reason should say how to fix it, got %q", reason)
	}
}

func TestACapableAgentIsAccepted(t *testing.T) {
	a := online(model.Capabilities{MQP: true, RouterOSBtest: true, TwampLight: true})
	for _, k := range []model.TaskKind{
		model.TaskMQPProbe, model.TaskTwampProbe,
		model.TaskRouterOSBtest, model.TaskPacketCapture,
	} {
		if r := agentCanRun(a, k); r != "" {
			t.Errorf("%s should be accepted, got %q", k, r)
		}
	}
}

func TestStaleAndDisabledAgentsAreRefused(t *testing.T) {
	old := time.Now().Add(-10 * time.Minute)
	stale := model.Agent{Capabilities: model.Capabilities{MQP: true}, LastSeenAt: &old}
	if agentCanRun(stale, model.TaskMQPProbe) == "" {
		t.Error("a stale agent would never pick the task up")
	}

	now := time.Now()
	disabled := model.Agent{
		Capabilities: model.Capabilities{MQP: true}, LastSeenAt: &now, Disabled: true,
	}
	if agentCanRun(disabled, model.TaskMQPProbe) == "" {
		t.Error("a disabled agent must be refused")
	}
}

func TestKnownKindsAreExactlyTheImplementedSet(t *testing.T) {
	for _, k := range []model.TaskKind{
		model.TaskMQPProbe, model.TaskTwampProbe, model.TaskTCPConnect,
		model.TaskRouterOSBtest, model.TaskPathTrace, model.TaskWifiSignal,
		model.TaskPacketCapture,
	} {
		if !knownKind(k) {
			t.Errorf("%s should be accepted", k)
		}
	}
	for _, k := range []model.TaskKind{"", "ping", "mqp-probe", "MQP_PROBE"} {
		if knownKind(k) {
			t.Errorf("%q should be rejected", k)
		}
	}
}

func TestTargetValidationRejectsOnlyRealNonsense(t *testing.T) {
	for _, ok := range []string{"1.1.1.1", "192.168.1.1", "2001:db8::1", "example.com", "a.b.c.d"} {
		if err := validTarget(ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "   ", "http://example.com", "has space", "a/b"} {
		if err := validTarget(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestTaskParamsSurviveUnknownFields(t *testing.T) {
	// The regression that produced "traceroute task carries no target": a
	// typed params struct dropped every field it did not declare, so a
	// one-shot reached the agent with no destination.
	raw := `{"task_id":"t1","session_id":"1","kind":"path_trace","role":"sender",
	         "params":{"target":"1.1.1.1","count":2,"anything_else":"kept"}}`
	var task model.Task
	if err := json.Unmarshal([]byte(raw), &task); err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(task.Params, &p); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"target", "count", "anything_else"} {
		if _, ok := p[k]; !ok {
			t.Errorf("params lost %q on the way through the controller", k)
		}
	}

	// And it must survive a round trip back out to the agent.
	out, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(out), `"target":"1.1.1.1"`) {
		t.Fatalf("target did not survive re-marshalling: %s", out)
	}
}
