package scheduler

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
)

func agent(name string, opts ...func(*Candidate)) Candidate {
	c := Candidate{
		AgentID:          uuid.NewSHA1(uuid.Nil, []byte(name)),
		Name:             name,
		Address:          "10.0.0.1",
		ProbePort:        5301,
		InboundReachable: true,
		Online:           true,
		Caps:             model.Capabilities{MQP: true},
	}
	for _, o := range opts {
		o(&c)
	}
	return c
}

func behindNAT(c *Candidate)  { c.InboundReachable = false }
func offline(c *Candidate)    { c.Online = false }
func isHub(c *Candidate)      { c.Hub = true }
func noMQP(c *Candidate)      { c.Caps.MQP = false }
func noAddress(c *Candidate)  { c.Address = "" }

func agents(names ...string) []Candidate {
	out := make([]Candidate, 0, len(names))
	for _, n := range names {
		out = append(out, agent(n))
	}
	return out
}

func pairNames(ps []Pairing) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s->%s", p.Sender.Name, p.Reflector.Name))
	}
	sort.Strings(out)
	return out
}

func hasReason(ex []Exclusion, reason string) bool {
	for _, e := range ex {
		if e.Reason == reason {
			return true
		}
	}
	return false
}

func TestFullMeshCoversEveryOrderedPair(t *testing.T) {
	ps, _ := PlanMesh(model.MeshFull, 0, agents("a", "b", "c"), 0)
	want := []string{"a->b", "a->c", "b->a", "b->c", "c->a", "c->b"}
	if got := pairNames(ps); !equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestFullMeshGrowsQuadratically(t *testing.T) {
	// Documents the cost that motivates the other plans existing at all.
	for _, n := range []int{2, 4, 8} {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("a%02d", i)
		}
		ps, _ := PlanMesh(model.MeshFull, 0, agents(names...), 0)
		if len(ps) != n*(n-1) {
			t.Errorf("n=%d: want %d pairs, got %d", n, n*(n-1), len(ps))
		}
	}
}

func TestRingGivesEachAgentExactlyOneSend(t *testing.T) {
	ps, _ := PlanMesh(model.MeshRing, 0, agents("a", "b", "c", "d"), 0)
	if len(ps) != 4 {
		t.Fatalf("ring over 4 agents should be 4 pairs, got %d", len(ps))
	}
	sends := map[string]int{}
	for _, p := range ps {
		sends[p.Sender.Name]++
	}
	for name, n := range sends {
		if n != 1 {
			t.Errorf("%s sends %d times, want 1 — ring must be constant cost", name, n)
		}
	}
}

func TestPartialRespectsFanout(t *testing.T) {
	ps, _ := PlanMesh(model.MeshPartial, 2, agents("a", "b", "c", "d", "e"), 0)
	sends := map[string]int{}
	for _, p := range ps {
		sends[p.Sender.Name]++
	}
	for name, n := range sends {
		if n != 2 {
			t.Errorf("%s sends %d times, want fanout of 2", name, n)
		}
	}
}

func TestPartialRotationEventuallyCoversTheWholeMesh(t *testing.T) {
	// The point of the partial plan: bounded concurrent cost, full coverage
	// across a window. If rotation were broken it would probe the same peers
	// forever and silently never test the rest.
	group := agents("a", "b", "c", "d", "e")
	seen := map[string]bool{}
	for cycle := 0; cycle < 4; cycle++ {
		ps, _ := PlanMesh(model.MeshPartial, 1, group, cycle)
		for _, n := range pairNames(ps) {
			seen[n] = true
		}
	}
	// 5 agents, fanout 1, 4 cycles => every ordered pair should have appeared.
	if len(seen) != 20 {
		t.Fatalf("expected all 20 ordered pairs across 4 cycles, got %d: %v", len(seen), keys(seen))
	}
}

func TestPartialFanoutIsClampedToAvailablePeers(t *testing.T) {
	// A fanout larger than the group would wrap and schedule duplicates.
	ps, _ := PlanMesh(model.MeshPartial, 99, agents("a", "b", "c"), 0)
	if got := pairNames(ps); len(got) != 6 {
		t.Fatalf("want 6 distinct pairs, got %d: %v", len(got), got)
	}
}

func TestNATdAgentIsNeverAReflector(t *testing.T) {
	// The rule the lab deployment proved: an agent behind NAT can complete a
	// measurement as the sender, but cannot be probed.
	group := []Candidate{agent("reachable"), agent("natted", behindNAT)}
	ps, _ := PlanMesh(model.MeshFull, 0, group, 0)

	if len(ps) == 0 {
		t.Fatal("a reachable/NAT pair should still be measurable in one direction")
	}
	for _, p := range ps {
		if p.Reflector.Name == "natted" {
			t.Fatalf("scheduled %s as reflector, but it cannot be reached inbound", p.Reflector.Name)
		}
	}
}

func TestPairBehindNATIsFlippedNotDropped(t *testing.T) {
	// Measuring the reverse direction beats measuring nothing.
	group := []Candidate{agent("hub"), agent("branch", behindNAT)}
	ps, _ := PlanMesh(model.MeshRing, 0, group, 0)
	if got := pairNames(ps); !equal(got, []string{"branch->hub"}) {
		t.Fatalf("want the pair flipped to branch->hub, got %v", got)
	}
}

func TestTwoNATdAgentsAreExcludedWithAReason(t *testing.T) {
	// Neither can accept a session, so no measurement is possible. It must be
	// reported, not silently dropped -- an operator staring at a gap needs to
	// know whether the path is broken or simply never tested.
	group := []Candidate{agent("a", behindNAT), agent("b", behindNAT)}
	ps, ex := PlanMesh(model.MeshFull, 0, group, 0)

	if len(ps) != 0 {
		t.Fatalf("expected no pairings, got %v", pairNames(ps))
	}
	if !hasReason(ex, ReasonBothBehindNAT) {
		t.Fatalf("exclusion must explain why: %+v", ex)
	}
}

func TestOfflineAgentsAreExcludedWithAReason(t *testing.T) {
	group := []Candidate{agent("a"), agent("b"), agent("gone", offline)}
	ps, ex := PlanMesh(model.MeshFull, 0, group, 0)

	for _, p := range ps {
		if p.Sender.Name == "gone" || p.Reflector.Name == "gone" {
			t.Fatal("a stale agent must not be scheduled")
		}
	}
	if !hasReason(ex, ReasonOffline) {
		t.Fatalf("want an offline exclusion, got %+v", ex)
	}
}

func TestAgentsWithoutTheProbeProtocolAreExcluded(t *testing.T) {
	group := []Candidate{agent("a"), agent("b"), agent("legacy", noMQP)}
	ps, ex := PlanMesh(model.MeshFull, 0, group, 0)
	for _, p := range ps {
		if p.Sender.Name == "legacy" || p.Reflector.Name == "legacy" {
			t.Fatal("scheduled work an agent cannot perform")
		}
	}
	if !hasReason(ex, ReasonNoMQP) {
		t.Fatalf("want a capability exclusion, got %+v", ex)
	}
}

func TestAgentWithNoAddressIsExcluded(t *testing.T) {
	// The controller has nothing to hand a peer, so the pair could only fail.
	group := []Candidate{agent("a"), agent("b"), agent("addressless", noAddress)}
	_, ex := PlanMesh(model.MeshFull, 0, group, 0)
	if !hasReason(ex, ReasonNoAddress) {
		t.Fatalf("want an address exclusion, got %+v", ex)
	}
}

func TestSingleUsableAgentProducesNoMeshButSaysSo(t *testing.T) {
	ps, ex := PlanMesh(model.MeshFull, 0, []Candidate{agent("lonely")}, 0)
	if len(ps) != 0 {
		t.Fatal("one agent cannot form a mesh")
	}
	if !hasReason(ex, ReasonSingleAgent) {
		t.Fatalf("the reason must be reported, got %+v", ex)
	}
}

func TestEmptyGroupIsHandled(t *testing.T) {
	ps, _ := PlanMesh(model.MeshFull, 0, nil, 0)
	if len(ps) != 0 {
		t.Fatal("empty group should yield nothing")
	}
}

func TestHubPlanMeasuresSpokesToHubsAndHubsToEachOther(t *testing.T) {
	group := []Candidate{agent("h1", isHub), agent("h2", isHub), agent("s1"), agent("s2")}
	ps, _ := PlanMesh(model.MeshHub, 0, group, 0)

	got := pairNames(ps)
	want := []string{"h1->h2", "h2->h1", "s1->h1", "s1->h2", "s2->h1", "s2->h2"}
	if !equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for _, n := range got {
		if strings.HasSuffix(n, "->s1") || strings.HasSuffix(n, "->s2") {
			t.Errorf("hub plan should not probe spokes: %s", n)
		}
	}
}


func TestHubPlanWithNoHubDesignatedFallsBackToRing(t *testing.T) {
	// Silently measuring nothing would be the worst outcome here.
	ps, ex := PlanMesh(model.MeshHub, 0, agents("a", "b", "c"), 0)
	if len(ps) != 3 {
		t.Fatalf("expected a 3-pair ring fallback, got %v", pairNames(ps))
	}
	found := false
	for _, e := range ex {
		if strings.Contains(e.Reason, "no agent is marked as a hub") {
			found = true
		}
	}
	if !found {
		t.Fatalf("fallback must be reported, got %+v", ex)
	}
}

func TestNoSelfPairsAreEverScheduled(t *testing.T) {
	// Probing yourself measures the container's loopback and tells nobody
	// anything about the network.
	for _, plan := range []model.MeshPlan{model.MeshFull, model.MeshRing, model.MeshPartial} {
		ps, _ := PlanMesh(plan, 2, agents("a", "b", "c"), 0)
		for _, p := range ps {
			if p.Sender.AgentID == p.Reflector.AgentID {
				t.Errorf("%s scheduled a self-pair", plan)
			}
		}
	}
}

func TestPlanIsDeterministicForAGivenCycle(t *testing.T) {
	// Rotation is meaningless if the same inputs can produce different plans.
	group := agents("d", "a", "c", "b")
	first, _ := PlanMesh(model.MeshPartial, 2, group, 3)
	for i := 0; i < 5; i++ {
		again, _ := PlanMesh(model.MeshPartial, 2, group, 3)
		if !equal(pairNames(first), pairNames(again)) {
			t.Fatal("same inputs must produce the same plan")
		}
	}
}

func TestInputOrderDoesNotChangeThePlan(t *testing.T) {
	a := agents("a", "b", "c", "d")
	b := agents("d", "c", "b", "a")
	pa, _ := PlanMesh(model.MeshRing, 0, a, 0)
	pb, _ := PlanMesh(model.MeshRing, 0, b, 0)
	if !equal(pairNames(pa), pairNames(pb)) {
		t.Fatalf("plan depends on input order: %v vs %v", pairNames(pa), pairNames(pb))
	}
}

func TestUnknownPlanFallsBackToRingRatherThanNothing(t *testing.T) {
	ps, _ := PlanMesh(model.MeshPlan("nonsense"), 0, agents("a", "b", "c"), 0)
	if len(ps) != 3 {
		t.Fatalf("unknown plan should degrade to a ring, got %d pairs", len(ps))
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
