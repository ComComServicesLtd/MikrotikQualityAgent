// Package scheduler decides which agents probe which, and how often.
//
// The planning logic here is deliberately pure: it takes a snapshot of a
// group's agents and returns pairings, with no database or clock involved. Mesh
// planning has enough edge cases -- NAT, stale agents, capability mismatches --
// that being able to test it exhaustively matters more than the small amount of
// plumbing it costs.
package scheduler

import (
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
)

// Candidate is an agent as the scheduler sees it.
type Candidate struct {
	AgentID   uuid.UUID
	Name      string
	Address   string
	ProbePort int

	// InboundReachable reports whether peers can open a session *to* this
	// agent. An agent behind NAT can complete a full measurement as the sender
	// -- the reflector's reply rides the same UDP flow and conntrack carries it
	// home -- but it cannot be probed. Such an agent must never be cast as a
	// reflector.
	InboundReachable bool

	// Hub marks an agent as a hub for the hub plan.
	Hub bool

	Online bool
	Caps   model.Capabilities
}

// Pairing is one directed measurement: Sender probes Reflector.
type Pairing struct {
	Sender    Candidate
	Reflector Candidate
}

// Exclusion records a pair or agent the scheduler declined to schedule.
//
// These are returned rather than silently dropped. A mesh that quietly covers
// less than it appears to is worse than one that reports its own gaps: an
// operator looking at a sparse graph needs to know whether the network is
// healthy or the scheduler simply never tested that path.
type Exclusion struct {
	Sender    string
	Reflector string
	Reason    string
}

const (
	ReasonOffline       = "agent has not heartbeated recently"
	ReasonNoMQP         = "agent does not support the probe protocol"
	ReasonBothBehindNAT = "neither agent is reachable inbound, so no session can be established"
	ReasonNoAddress     = "agent has no probe address the controller can hand to a peer"
	ReasonSingleAgent   = "a group needs at least two usable agents to form a mesh"
)

// PlanMesh returns the ordered pairs to schedule for one cycle.
//
// cycle advances once per scheduling round and is used by the partial plan to
// rotate which peers each agent probes, so the whole mesh is covered over a
// window without any agent exceeding its fanout at once.
func PlanMesh(plan model.MeshPlan, fanout int, agents []Candidate, cycle int) ([]Pairing, []Exclusion) {
	var excluded []Exclusion

	// Deterministic order, so a given cycle always produces the same plan.
	// Without this, rotation in the partial plan would be meaningless and the
	// same pair could be scheduled twice in a row by accident.
	sorted := append([]Candidate(nil), agents...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var usable []Candidate
	for _, a := range sorted {
		switch {
		case !a.Online:
			excluded = append(excluded, Exclusion{Sender: a.Name, Reason: ReasonOffline})
		case !a.Caps.MQP:
			excluded = append(excluded, Exclusion{Sender: a.Name, Reason: ReasonNoMQP})
		case a.Address == "":
			excluded = append(excluded, Exclusion{Sender: a.Name, Reason: ReasonNoAddress})
		default:
			usable = append(usable, a)
		}
	}

	if len(usable) < 2 {
		if len(usable) == 1 {
			excluded = append(excluded, Exclusion{Sender: usable[0].Name, Reason: ReasonSingleAgent})
		}
		return nil, excluded
	}

	var candidates []Pairing
	switch plan {
	case model.MeshFull:
		candidates = fullMesh(usable)
	case model.MeshRing:
		candidates = ring(usable)
	case model.MeshHub:
		candidates = hub(usable, &excluded)
	case model.MeshPartial:
		candidates = partial(usable, fanout, cycle)
	default:
		candidates = ring(usable)
	}

	// Enforce the NAT rule last, uniformly, rather than inside each plan.
	pairings := make([]Pairing, 0, len(candidates))
	for _, p := range candidates {
		switch {
		case p.Reflector.InboundReachable:
			pairings = append(pairings, p)
		case p.Sender.InboundReachable:
			// The reflector cannot be probed, but the sender can. Measuring
			// the reverse direction is far better than measuring nothing, and
			// for a symmetric path it answers the same question.
			pairings = append(pairings, Pairing{Sender: p.Reflector, Reflector: p.Sender})
		default:
			excluded = append(excluded, Exclusion{
				Sender:    p.Sender.Name,
				Reflector: p.Reflector.Name,
				Reason:    ReasonBothBehindNAT,
			})
		}
	}

	return dedupe(pairings), excluded
}

// fullMesh is every ordered pair: n*(n-1). Grows quadratically and will
// saturate small routers past a handful of agents.
func fullMesh(a []Candidate) []Pairing {
	out := make([]Pairing, 0, len(a)*(len(a)-1))
	for i := range a {
		for j := range a {
			if i != j {
				out = append(out, Pairing{Sender: a[i], Reflector: a[j]})
			}
		}
	}
	return out
}

// ring has each agent probe the next, wrapping. n pairs, constant cost per
// agent regardless of group size.
func ring(a []Candidate) []Pairing {
	out := make([]Pairing, 0, len(a))
	for i := range a {
		out = append(out, Pairing{Sender: a[i], Reflector: a[(i+1)%len(a)]})
	}
	return out
}

// hub has every non-hub agent probe every hub. For hub-and-spoke WANs, where
// spoke-to-spoke paths are not what anyone is actually using.
func hub(a []Candidate, excluded *[]Exclusion) []Pairing {
	var hubs, spokes []Candidate
	for _, c := range a {
		if c.Hub {
			hubs = append(hubs, c)
		} else {
			spokes = append(spokes, c)
		}
	}
	// A hub plan with no hub designated would silently measure nothing. Fall
	// back to a ring so the group is still covered, and say so.
	if len(hubs) == 0 {
		*excluded = append(*excluded, Exclusion{
			Reason: "hub plan selected but no agent is marked as a hub; falling back to a ring",
		})
		return ring(a)
	}

	out := make([]Pairing, 0, len(spokes)*len(hubs))
	for _, s := range spokes {
		for _, h := range hubs {
			out = append(out, Pairing{Sender: s, Reflector: h})
		}
	}
	// With several hubs, measure between them too -- the hub-to-hub path
	// usually carries the most traffic in the group.
	for i := range hubs {
		for j := range hubs {
			if i != j {
				out = append(out, Pairing{Sender: hubs[i], Reflector: hubs[j]})
			}
		}
	}
	return out
}

// partial has each agent probe `fanout` peers, rotating by cycle so the full
// mesh is covered over time without any agent exceeding its fanout at once.
func partial(a []Candidate, fanout, cycle int) []Pairing {
	n := len(a)
	if fanout < 1 {
		fanout = 1
	}
	// Each agent can reach at most n-1 distinct peers; beyond that the offsets
	// wrap and would schedule the same pair twice in one cycle.
	if fanout > n-1 {
		fanout = n - 1
	}

	out := make([]Pairing, 0, n*fanout)
	for i := range a {
		for k := 0; k < fanout; k++ {
			// Advancing the offset by cycle*fanout walks the whole ring of
			// peers across successive cycles.
			offset := (cycle*fanout + k) % (n - 1)
			j := (i + 1 + offset) % n
			out = append(out, Pairing{Sender: a[i], Reflector: a[j]})
		}
	}
	return out
}

// dedupe removes duplicate directed pairs, which the NAT flip can introduce
// when both directions of a pair were originally scheduled.
func dedupe(in []Pairing) []Pairing {
	seen := make(map[string]struct{}, len(in))
	out := make([]Pairing, 0, len(in))
	for _, p := range in {
		key := fmt.Sprintf("%s->%s", p.Sender.AgentID, p.Reflector.AgentID)
		if _, dup := seen[key]; dup {
			continue
		}
		// A self-pair measures the loopback inside a container, which tells
		// nobody anything about the network.
		if p.Sender.AgentID == p.Reflector.AgentID {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}
