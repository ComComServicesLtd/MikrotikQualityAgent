package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/store"
)

// How long a one-shot stays worth running if the agent has not picked it up.
//
// Short on purpose. A diagnostic answers a question someone is asking now; run
// an hour late it describes a moment that has passed and nobody is still
// waiting for it.
const (
	DefaultTestExpiry = 5 * time.Minute
	MaxTestExpiry     = 1 * time.Hour
)

type testRequest struct {
	/// Agent name or UUID. Names are accepted because that is what an operator
	/// has in front of them.
	Agent string `json:"agent"`
	Kind  string `json:"kind"`
	/// Peer agent, for kinds that measure between two agents.
	Peer string `json:"peer"`
	/// Destination address, for kinds that aim at an arbitrary target.
	Target     string         `json:"target"`
	Params     map[string]any `json:"params"`
	ExpiresInS int            `json:"expires_in_s"`
}

func (s *Server) testRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/tests", s.operatorAuth(s.handleCreateTest))
	mux.Handle("GET /api/v1/tests/{id}", s.operatorAuth(s.handleGetTest))
}

func (s *Server) handleCreateTest(w http.ResponseWriter, r *http.Request) {
	var req testRequest
	if !decode(w, r, &req) {
		return
	}

	kind := model.TaskKind(strings.TrimSpace(req.Kind))
	if !knownKind(kind) {
		problem(w, http.StatusBadRequest, "unknown kind",
			"expected one of: mqp_probe, twamp_probe, tcp_connect, routeros_btest, "+
				"path_trace, wifi_signal, packet_capture")
		return
	}

	agent, err := s.resolveAgent(r.Context(), req.Agent)
	if err != nil {
		problem(w, http.StatusBadRequest, "unknown agent", err.Error())
		return
	}

	// Refuse work the agent cannot do, rather than queueing something it will
	// only report as skipped minutes later. The operator finds out now, with a
	// reason, instead of waiting for a non-answer.
	if reason := agentCanRun(agent, kind); reason != "" {
		problem(w, http.StatusConflict, "agent cannot run this test", reason)
		return
	}

	params := req.Params
	if params == nil {
		params = map[string]any{}
	}

	var peerID *uuid.UUID
	switch {
	case kind.NeedsPeer():
		if req.Peer == "" {
			problem(w, http.StatusBadRequest, "peer is required",
				fmt.Sprintf("%s measures between two agents; name the far end with \"peer\"", kind))
			return
		}
		peer, err := s.resolveAgent(r.Context(), req.Peer)
		if err != nil {
			problem(w, http.StatusBadRequest, "unknown peer", err.Error())
			return
		}
		if peer.AgentID == agent.AgentID {
			problem(w, http.StatusBadRequest, "agent and peer are the same",
				"probing itself measures the container's loopback, not the network")
			return
		}
		if peer.ProbeAddr == "" {
			problem(w, http.StatusConflict, "peer has no probe address",
				"the controller has nothing to hand the sender; the peer has not registered one")
			return
		}
		peerID = &peer.AgentID

	case kind.NeedsTarget():
		if req.Target == "" {
			problem(w, http.StatusBadRequest, "target is required",
				fmt.Sprintf("%s aims at an address rather than a peer agent", kind))
			return
		}
		if err := validTarget(req.Target); err != nil {
			problem(w, http.StatusBadRequest, "invalid target", err.Error())
			return
		}
		params["target"] = req.Target
	}

	expiry := DefaultTestExpiry
	if req.ExpiresInS > 0 {
		expiry = time.Duration(req.ExpiresInS) * time.Second
		if expiry > MaxTestExpiry {
			problem(w, http.StatusBadRequest, "expires_in_s too large",
				fmt.Sprintf("the maximum is %.0f seconds: a diagnostic run later than that "+
					"describes a moment that has passed", MaxTestExpiry.Seconds()))
			return
		}
	}

	taskID, expiresAt, err := s.st.CreateOneShot(r.Context(), store.OneShotRequest{
		AgentID:   agent.AgentID,
		PeerID:    peerID,
		Kind:      kind,
		Params:    params,
		Group:     agent.Group,
		ExpiresIn: expiry,
	})
	if err != nil {
		s.fail(w, "create one-shot test", err)
		return
	}

	s.log.Info("one-shot test queued",
		"task", taskID, "kind", kind, "agent", agent.Name,
		"peer", req.Peer, "target", req.Target)

	w.Header().Set("Location", "/api/v1/tests/"+taskID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"task_id":    taskID,
		"kind":       kind,
		"agent":      agent.Name,
		"state":      "pending",
		"expires_at": expiresAt,
		// The agent polls; it does not get pushed to. Saying so stops anyone
		// reading an immediate empty result as a failure.
		"note": fmt.Sprintf("the agent will pick this up on its next poll, within about %ds",
			pollHintSeconds),
	})
}

func (s *Server) handleGetTest(w http.ResponseWriter, r *http.Request) {
	t, err := s.st.TestByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		problem(w, http.StatusNotFound, "no such test", "")
		return
	}
	if err != nil {
		s.fail(w, "get test", err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// pollHintSeconds mirrors what registration tells agents to use.
const pollHintSeconds = 10

func knownKind(k model.TaskKind) bool {
	switch k {
	case model.TaskMQPProbe, model.TaskTwampProbe, model.TaskTCPConnect,
		model.TaskRouterOSBtest, model.TaskPathTrace, model.TaskWifiSignal,
		model.TaskPacketCapture:
		return true
	default:
		return false
	}
}

// agentCanRun returns an empty string when the agent can perform the kind, or
// the reason it cannot.
func agentCanRun(a model.Agent, k model.TaskKind) string {
	if a.Disabled {
		return "the agent is disabled"
	}
	if a.State(time.Now()) == "stale" {
		return "the agent has not heartbeated recently, so it would not pick this up"
	}
	if k.NeedsRouterOS() && !a.Capabilities.RouterOSBtest {
		return "this test runs through the host router's API, which the agent reports it " +
			"cannot reach; set MQ_ROUTEROS_HOST/USER/PASS on the agent"
	}
	if (k == model.TaskMQPProbe) && !a.Capabilities.MQP {
		return "the agent does not support the probe protocol"
	}
	if k == model.TaskTwampProbe && !a.Capabilities.TwampLight {
		return "the agent does not report TWAMP-Light support"
	}
	return ""
}

// validTarget accepts an IP or a hostname, rejecting things that cannot be one.
func validTarget(t string) error {
	t = strings.TrimSpace(t)
	if t == "" {
		return errors.New("empty")
	}
	if net.ParseIP(t) != nil {
		return nil
	}
	// A hostname is fine — the agent resolves it — but reject obvious
	// nonsense so the failure surfaces here rather than as a skipped task.
	if len(t) > 253 || strings.ContainsAny(t, " \t/\\?#") {
		return fmt.Errorf("%q is neither an IP address nor a plausible hostname", t)
	}
	return nil
}

// resolveAgent accepts a UUID or a name.
func (s *Server) resolveAgent(ctx contextLike, ref string) (model.Agent, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return model.Agent{}, errors.New("no agent given")
	}
	if id, err := uuid.Parse(ref); err == nil {
		a, err := s.st.AgentByID(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return model.Agent{}, fmt.Errorf("no agent with id %s", ref)
		}
		return a, err
	}

	agents, err := s.st.ListAgents(ctx, "")
	if err != nil {
		return model.Agent{}, err
	}
	for _, a := range agents {
		if a.Name == ref {
			return a, nil
		}
	}
	return model.Agent{}, fmt.Errorf("no agent named %q", ref)
}

// contextLike keeps the signature readable without importing context twice.
type contextLike = interface {
	Deadline() (time.Time, bool)
	Done() <-chan struct{}
	Err() error
	Value(any) any
}
