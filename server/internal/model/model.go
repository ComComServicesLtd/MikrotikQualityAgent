// Package model holds the domain types shared between the API surface and the
// store. Field names and JSON tags mirror docs/api.md — that document is the
// contract, and these structs are its Go expression.
package model

import (
	"time"

	"github.com/google/uuid"
)

// MeshPlan decides which ordered pairs in a group probe each other.
//
// Full mesh is n*(n-1) sessions and grows quadratically, which will saturate
// small routers; the other plans bound the per-agent cost.
type MeshPlan string

const (
	// MeshFull has every agent probe every other. Fine for small groups.
	MeshFull MeshPlan = "full"
	// MeshRing has each agent probe the next. n pairs, constant per-agent cost.
	MeshRing MeshPlan = "ring"
	// MeshHub has designated hubs probe all others. For hub-and-spoke WANs.
	MeshHub MeshPlan = "hub"
	// MeshPartial has each agent probe k peers, rotating so the whole mesh is
	// covered across a window without exceeding k concurrent sessions.
	MeshPartial MeshPlan = "partial"
)

type Group struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MeshPlan    MeshPlan  `json:"mesh_plan"`
	MeshFanout  int       `json:"mesh_fanout"`
	IntervalS   int       `json:"interval_s"`
	CreatedAt   time.Time `json:"created_at"`
}

// Capabilities is what an agent reports it can do. The scheduler uses this to
// avoid handing an agent work it will only skip.
type Capabilities struct {
	MQP            bool `json:"mqp"`
	TwampLight     bool `json:"twamp_light"`
	RouterOSBtest  bool `json:"routeros_btest"`
	ProbePort      int  `json:"probe_port"`
}

type HostInfo struct {
	RouterOSVersion string `json:"routeros_version,omitempty"`
	Board           string `json:"board,omitempty"`
	Arch            string `json:"arch,omitempty"`
}

type Agent struct {
	AgentID      uuid.UUID    `json:"agent_id"`
	Name         string       `json:"name"`
	Group        string       `json:"group"`
	Version      string       `json:"version"`
	ProbeAddr    string       `json:"probe_addr,omitempty"`
	ProbePort    int          `json:"probe_port"`
	Capabilities Capabilities `json:"capabilities"`
	Host         HostInfo     `json:"host"`
	RegisteredAt time.Time    `json:"registered_at"`
	LastSeenAt   *time.Time   `json:"last_seen_at,omitempty"`
	Disabled     bool         `json:"disabled"`
}

// StaleAfter is how long an agent may go unheard-from before the scheduler
// stops pairing it. Three missed 30-second heartbeats.
const StaleAfter = 95 * time.Second

// State reports liveness, derived rather than stored — a status column that
// drifts from last_seen_at is worse than no status column.
func (a Agent) State(now time.Time) string {
	switch {
	case a.Disabled:
		return "disabled"
	case a.LastSeenAt == nil:
		return "pending"
	case now.Sub(*a.LastSeenAt) > StaleAfter:
		return "stale"
	default:
		return "online"
	}
}

type TaskKind string

const (
	TaskMQPProbe      TaskKind = "mqp_probe"
	TaskTwampProbe    TaskKind = "twamp_probe"
	TaskTCPConnect    TaskKind = "tcp_connect"
	TaskRouterOSBtest TaskKind = "routeros_btest"
	TaskPathTrace     TaskKind = "path_trace"
	// TaskWifiSignal reads wireless signal strength and registration data from
	// the host router. Host telemetry, not a path measurement.
	TaskWifiSignal TaskKind = "wifi_signal"
)

// Recurring reports whether this kind belongs to a group's continuous plan
// rather than being an operator-issued one-shot.
//
// The distinction decides behaviour during a controller outage: continuous
// work is cached and keeps running, one-shots expire. Executing a stale
// diagnostic would answer a question nobody is still asking, about a moment
// that has passed.
func (k TaskKind) Recurring() bool {
	switch k {
	case TaskMQPProbe, TaskTwampProbe, TaskTCPConnect:
		return true
	default:
		// Throughput, traceroute and wifi sampling can each be scheduled
		// continuously, but only when a plan says so -- they are expensive or
		// disruptive enough that recurring is not their default.
		return false
	}
}

type TaskRole string

const (
	RoleSender    TaskRole = "sender"
	RoleReflector TaskRole = "reflector"
)

// ProbeParams are the knobs for one measurement.
type ProbeParams struct {
	Count        int    `json:"count,omitempty"`
	IntervalMS   int    `json:"interval_ms,omitempty"`
	PayloadBytes int    `json:"payload_bytes,omitempty"`
	DSCP         *int   `json:"dscp,omitempty"`
	TimeoutMS    int    `json:"timeout_ms,omitempty"`
	Codec        string `json:"codec,omitempty"`
	DurationS    int    `json:"duration_s,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
}

// PeerRef is everything the agent needs to reach its counterpart.
type PeerRef struct {
	AgentID   uuid.UUID `json:"agent_id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	ProbePort int       `json:"probe_port"`
}

type Task struct {
	TaskID string `json:"task_id"`
	// SessionID is shared by the sender task and its reflector grant, and goes
	// on the wire as MQP's session_id. It is the reflector's only admission
	// control, so it must come from a CSPRNG.
	SessionID      uint64      `json:"session_id,string"`
	Kind           TaskKind    `json:"kind"`
	Role           TaskRole    `json:"role"`
	Peer           *PeerRef    `json:"peer,omitempty"`
	Params         ProbeParams `json:"params"`
	LeaseExpiresAt time.Time   `json:"lease_expires_at"`
	// Recurring marks this as part of the group's continuous plan, which the
	// agent caches and keeps running when the controller is unreachable.
	Recurring bool `json:"recurring"`
	// ExpiresAt bounds a one-shot's usefulness. An agent that receives or
	// reaches it after this point reports `skipped` instead of running it.
	// Zero means no expiry.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Stale reports whether a one-shot has outlived its usefulness.
func (t Task) Stale(now time.Time) bool {
	return !t.Recurring && !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)
}

// --- results -------------------------------------------------------------

type RTTStats struct {
	MinUS    int64 `json:"min_us"`
	AvgUS    int64 `json:"avg_us"`
	MaxUS    int64 `json:"max_us"`
	StddevUS int64 `json:"stddev_us"`
	P50US    int64 `json:"p50_us"`
	P95US    int64 `json:"p95_us"`
	P99US    int64 `json:"p99_us"`
}

type JitterStats struct {
	IPDVAvgUS int64 `json:"ipdv_avg_us"`
	PDVP95US  int64 `json:"pdv_p95_us"`
}

type LossStats struct {
	Sent             int     `json:"sent"`
	Received         int     `json:"received"`
	ForwardLost      int     `json:"forward_lost"`
	ReverseLost      int     `json:"reverse_lost"`
	UnknownDirection int     `json:"unknown_direction"`
	LossPct          float64 `json:"loss_pct"`
}

type ReorderStats struct {
	Reordered       int `json:"reordered"`
	MaxDisplacement int `json:"max_displacement"`
	Duplicated      int `json:"duplicated"`
}

type DSCPStats struct {
	Requested      int     `json:"requested"`
	ObservedMode   int     `json:"observed_mode"`
	ConformantPct  float64 `json:"conformant_pct"`
}

type MOSStats struct {
	Codec    string  `json:"codec"`
	RFactor  float64 `json:"r_factor"`
	MOS      float64 `json:"mos"`
}

type ThroughputStats struct {
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
	TxBps     int64  `json:"tx_bps"`
	RxBps     int64  `json:"rx_bps"`
	DurationS int    `json:"duration_s"`
	// Source distinguishes a number measured by the host router's forwarding
	// path from one measured inside the container. They are not comparable, so
	// a result without this is ambiguous.
	Source        string `json:"source"`
	LocalCPULoad  int    `json:"local_cpu_load,omitempty"`
	RemoteCPULoad int    `json:"remote_cpu_load,omitempty"`
}

type ResultStatus string

const (
	StatusOK      ResultStatus = "ok"
	StatusPartial ResultStatus = "partial"
	StatusFailed  ResultStatus = "failed"
	StatusSkipped ResultStatus = "skipped"
)

type Result struct {
	TaskID    string       `json:"task_id"`
	SessionID uint64       `json:"session_id,string"`
	StartedAt time.Time    `json:"started_at"`
	EndedAt   time.Time    `json:"ended_at"`
	Status    ResultStatus `json:"status"`
	Error     *string      `json:"error,omitempty"`

	RTT        *RTTStats        `json:"rtt,omitempty"`
	Jitter     *JitterStats     `json:"jitter,omitempty"`
	Loss       *LossStats       `json:"loss,omitempty"`
	Reorder    *ReorderStats    `json:"reorder,omitempty"`
	DSCP       *DSCPStats       `json:"dscp,omitempty"`
	MOS        *MOSStats        `json:"mos,omitempty"`
	Throughput *ThroughputStats `json:"throughput,omitempty"`
}

// Valid reports whether a submitted result is self-consistent. Rejecting
// nonsense at the edge keeps it out of the time series, where a single
// impossible row will skew every rollup that touches it.
func (r Result) Valid() error {
	if r.TaskID == "" {
		return errField("task_id is required")
	}
	if r.EndedAt.Before(r.StartedAt) {
		return errField("ended_at precedes started_at")
	}
	switch r.Status {
	case StatusOK, StatusPartial, StatusFailed, StatusSkipped:
	default:
		return errField("unknown status " + string(r.Status))
	}
	if l := r.Loss; l != nil {
		if l.Received > l.Sent {
			return errField("received exceeds sent")
		}
		if l.LossPct < 0 || l.LossPct > 100 {
			return errField("loss_pct out of range")
		}
	}
	if m := r.MOS; m != nil {
		// Narrowband tops out at 4.5, wideband at 4.8.
		if m.MOS < 1 || m.MOS > 4.8 {
			return errField("mos out of range")
		}
		if m.Codec == "" {
			return errField("mos requires a codec — a score without one is meaningless")
		}
	}
	if d := r.DSCP; d != nil {
		if d.Requested < 0 || d.Requested > 63 {
			return errField("dscp requested out of range")
		}
	}
	return nil
}

type fieldError string

func (e fieldError) Error() string { return string(e) }

func errField(s string) error { return fieldError(s) }
