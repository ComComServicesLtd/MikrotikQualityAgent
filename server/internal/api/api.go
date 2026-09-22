// Package api is the controller's HTTP surface. The contract is docs/api.md.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/store"
)

// TaskLease is how long a leased task is held before the sweeper returns it to
// the pending pool. Generous relative to any single test so a slow run is not
// reassigned underneath the agent still working on it.
const TaskLease = 10 * time.Minute

type Server struct {
	st  *store.Store
	log *slog.Logger
	// operatorToken guards the management endpoints. Empty disables them
	// outright, which is safer than defaulting to a well-known value.
	operatorToken string
	ui            bool
}

func New(st *store.Store, log *slog.Logger, operatorToken string, serveUI bool) *Server {
	return &Server{st: st, log: log, operatorToken: operatorToken, ui: serveUI}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated health endpoints, for container and load-balancer probes.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.handleReady)

	mux.HandleFunc("POST /api/v1/agents/register", s.handleRegister)
	mux.Handle("POST /api/v1/agents/{id}/heartbeat", s.agentAuth(s.handleHeartbeat))
	mux.Handle("GET /api/v1/agents/{id}/tasks", s.agentAuth(s.handleTasks))
	mux.Handle("POST /api/v1/agents/{id}/results", s.agentAuth(s.handleResults))

	mux.Handle("GET /api/v1/agents", s.operatorAuth(s.handleListAgents))
	s.operatorRoutes(mux)
	s.testRoutes(mux)
	if s.ui {
		s.uiRoutes(mux)
	}

	return cors(logging(s.log, mux))
}

// --- handlers ------------------------------------------------------------

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.st.Ping(r.Context()); err != nil {
		problem(w, http.StatusServiceUnavailable, "database unreachable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

type registerRequest struct {
	AgentID      *uuid.UUID         `json:"agent_id"`
	Name         string             `json:"name"`
	Group        string             `json:"group"`
	Version      string             `json:"version"`
	Capabilities model.Capabilities `json:"capabilities"`
	Host         model.HostInfo     `json:"host"`
	Advertise    string             `json:"advertise_addr"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		problem(w, http.StatusUnauthorized, "missing enrolment token", "")
		return
	}

	var req registerRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || req.Group == "" {
		problem(w, http.StatusBadRequest, "name and group are required", "")
		return
	}

	group, err := s.st.RedeemEnrolment(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrBadToken) {
			problem(w, http.StatusUnauthorized, "invalid or expired enrolment token", "")
			return
		}
		s.fail(w, "redeem enrolment", err)
		return
	}

	// The token's group wins over whatever the agent claimed. An enrolment
	// token is scoped to a group precisely so a misconfigured agent cannot
	// insert itself into someone else's mesh.
	if req.Group != group {
		s.log.Warn("agent claimed a group its token does not grant",
			"name", req.Name, "claimed", req.Group, "granted", group)
	}

	res, err := s.st.Register(r.Context(), store.RegisterRequest{
		AgentID:       req.AgentID,
		Name:          req.Name,
		Group:         group,
		Version:       req.Version,
		Capabilities:  req.Capabilities,
		Host:          req.Host,
		ObservedAddr:  clientIP(r),
		AdvertiseAddr: req.Advertise,
	})
	if err != nil {
		if errors.Is(err, store.ErrNameConflict) {
			problem(w, http.StatusConflict, "name already registered to a different agent",
				"choose a unique MQ_AGENT_NAME, or supply the original agent_id")
			return
		}
		s.fail(w, "register agent", err)
		return
	}

	if err := s.st.MarkEnrolmentUsed(r.Context(), token, res.AgentID); err != nil {
		// The agent is registered and usable; failing the request now would
		// make it retry and hit the name-conflict path instead.
		s.log.Error("could not burn enrolment token", "error", err, "agent", res.AgentID)
	}

	if res.Reclaimed {
		s.log.Warn("agent reclaimed an existing name with a fresh enrolment token",
			"name", req.Name, "group", group, "id", res.AgentID,
			"note", "expected after a re-flash or a recreated container; investigate otherwise")
	} else {
		s.log.Info("agent registered", "name", req.Name, "group", group, "id", res.AgentID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id":             res.AgentID,
		"token":                res.Token,
		"group":                res.Group,
		"heartbeat_interval_s": 30,
		"poll_interval_s":      10,
	})
}

type heartbeatRequest struct {
	// Optional: older agents do not send it, and a heartbeat that fails to
	// decode would mark a healthy agent stale.
	Capabilities *model.Capabilities `json:"capabilities"`
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, a model.Agent) {
	var req heartbeatRequest
	// Ignore a malformed body rather than failing the beat: liveness matters
	// more than the optional payload riding along with it.
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)

	if err := s.st.Heartbeat(r.Context(), a.AgentID); err != nil {
		s.fail(w, "heartbeat", err)
		return
	}
	// An agent that keeps its identity never registers again, so this is the
	// only route by which a newly gained capability reaches us.
	if req.Capabilities != nil {
		if err := s.st.UpdateCapabilities(r.Context(), a.AgentID, *req.Capabilities); err != nil {
			s.log.Error("could not update capabilities", "agent", a.AgentID, "error", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"poll_interval_s": 10,
		"reregister":      false,
	})
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request, a model.Agent) {
	tasks, err := s.st.LeaseTasks(r.Context(), a.AgentID, TaskLease)
	if err != nil {
		s.fail(w, "lease tasks", err)
		return
	}
	if tasks == nil {
		// An explicit empty array, never null — a polling client should not
		// have to special-case JSON null on its hot path.
		tasks = []model.Task{}
	}
	writeJSON(w, http.StatusOK, tasks)
}

type resultsRequest struct {
	Results []model.Result `json:"results"`
}

type rejected struct {
	TaskID string `json:"task_id"`
	Reason string `json:"reason"`
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request, a model.Agent) {
	var req resultsRequest
	if !decode(w, r, &req) {
		return
	}

	accepted := 0
	rejects := []rejected{}

	for _, res := range req.Results {
		if err := res.Valid(); err != nil {
			rejects = append(rejects, rejected{res.TaskID, err.Error()})
			continue
		}
		inserted, err := s.st.SaveResult(r.Context(), a.AgentID, a.Group, res)
		switch {
		case errors.Is(err, store.ErrNotFound):
			rejects = append(rejects, rejected{res.TaskID, "unknown task"})
		case err != nil:
			// One bad row must not discard the rest of a drained spool.
			s.log.Error("could not save result", "task", res.TaskID, "error", err)
			rejects = append(rejects, rejected{res.TaskID, "internal error"})
		case !inserted:
			rejects = append(rejects, rejected{res.TaskID, "duplicate"})
		default:
			accepted++
		}
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted": accepted,
		"rejected": rejects,
	})
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.st.ListAgents(r.Context(), r.URL.Query().Get("group"))
	if err != nil {
		s.fail(w, "list agents", err)
		return
	}

	now := time.Now()
	out := make([]map[string]any, 0, len(agents))
	for _, a := range agents {
		out = append(out, map[string]any{
			"agent_id":     a.AgentID,
			"name":         a.Name,
			"group":        a.Group,
			"version":      a.Version,
			"probe_addr":   a.ProbeAddr,
			"probe_port":   a.ProbePort,
			"capabilities": a.Capabilities,
			"host":         a.Host,
			"state":        a.State(now),
			"last_seen_at": a.LastSeenAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- middleware ----------------------------------------------------------

type agentHandler func(http.ResponseWriter, *http.Request, model.Agent)

// agentAuth resolves the bearer token to an agent and checks the path ID
// matches it, so a valid token cannot be used to act as a different agent.
func (s *Server) agentAuth(next agentHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		if !ok {
			problem(w, http.StatusUnauthorized, "missing bearer token", "")
			return
		}
		agent, err := s.st.AuthenticateAgent(r.Context(), token)
		if err != nil {
			if errors.Is(err, store.ErrBadToken) {
				problem(w, http.StatusUnauthorized, "invalid token", "")
				return
			}
			s.fail(w, "authenticate", err)
			return
		}
		if id := r.PathValue("id"); id != "" && id != agent.AgentID.String() {
			problem(w, http.StatusForbidden, "token does not match the agent in the path", "")
			return
		}
		next(w, r, agent)
	})
}

func (s *Server) operatorAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.operatorToken == "" {
			problem(w, http.StatusForbidden, "operator API disabled",
				"set MQ_OPERATOR_TOKEN to enable management endpoints")
			return
		}
		token, ok := bearer(r)
		if !ok || subtleCompare(token, s.operatorToken) != 1 {
			problem(w, http.StatusUnauthorized, "invalid operator token", "")
			return
		}
		next(w, r)
	})
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// Health checks would otherwise dominate the log at the poll rates
		// agents and orchestrators use.
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			log.Info("request",
				"method", r.Method, "path", r.URL.Path,
				"status", rec.status, "duration_ms", time.Since(start).Milliseconds())
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// --- helpers -------------------------------------------------------------

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	t := strings.TrimSpace(h[7:])
	return t, t != ""
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	// Bound the body: an agent is not expected to send megabytes, and an
	// unbounded decode is a trivial memory-exhaustion vector.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := dec.Decode(dst); err != nil {
		problem(w, http.StatusBadRequest, "malformed JSON body", err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// problem emits RFC 7807 application/problem+json.
func problem(w http.ResponseWriter, code int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  title,
		"status": code,
		"detail": detail,
	})
}

// fail logs the real error and returns a generic one — internal details do not
// belong in a response body.
func (s *Server) fail(w http.ResponseWriter, op string, err error) {
	s.log.Error("request failed", "op", op, "error", err)
	problem(w, http.StatusInternalServerError, "internal error", "")
}

func clientIP(r *http.Request) string {
	// X-Forwarded-For is attacker-controlled unless a trusted proxy sets it, so
	// it is deliberately ignored here. If the controller is ever fronted by a
	// proxy, that proxy must be made to rewrite RemoteAddr instead.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	if diff == 0 {
		return 1
	}
	return 0
}
