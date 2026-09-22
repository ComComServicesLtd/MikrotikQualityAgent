package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/store"
)

// Longest window a single chart query may cover. An unbounded range over a
// hypertable is an easy way for one dashboard tab to saturate the database.
const maxWindow = 90 * 24 * time.Hour

// Bucket widths the series endpoint accepts. Restricted rather than free-form
// because the value reaches the query as an interval, and because an
// unbounded bucket count is a denial-of-service in a chart.
var allowedBuckets = map[string]time.Duration{
	"1m":  time.Minute,
	"5m":  5 * time.Minute,
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"1d":  24 * time.Hour,
}

func (s *Server) operatorRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/groups", s.operatorAuth(s.handleListGroups))
	mux.Handle("POST /api/v1/groups", s.operatorAuth(s.handleUpsertGroup))
	mux.Handle("PUT /api/v1/groups/{name}", s.operatorAuth(s.handleUpsertGroup))
	mux.Handle("DELETE /api/v1/groups/{name}", s.operatorAuth(s.handleDeleteGroup))

	mux.Handle("POST /api/v1/groups/{name}/enrolment-tokens", s.operatorAuth(s.handleCreateToken))
	mux.Handle("GET /api/v1/enrolment-tokens", s.operatorAuth(s.handleListTokens))

	mux.Handle("GET /api/v1/agents/{id}", s.operatorAuth(s.handleGetAgent))
	mux.Handle("PATCH /api/v1/agents/{id}", s.operatorAuth(s.handlePatchAgent))
	mux.Handle("DELETE /api/v1/agents/{id}", s.operatorAuth(s.handleDeleteAgent))

	mux.Handle("GET /api/v1/pairs", s.operatorAuth(s.handlePairs))
	mux.Handle("GET /api/v1/series", s.operatorAuth(s.handleSeries))
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.st.Groups(r.Context())
	if err != nil {
		s.fail(w, "list groups", err)
		return
	}
	// An explicit empty array, never null: the UI should not have to
	// special-case JSON null before it can iterate.
	if groups == nil {
		groups = []model.Group{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *Server) handleUpsertGroup(w http.ResponseWriter, r *http.Request) {
	var in store.GroupInput
	if !decode(w, r, &in) {
		return
	}
	// PUT /groups/{name} takes the name from the path, so the body cannot
	// rename a group by accident.
	if n := r.PathValue("name"); n != "" {
		in.Name = n
	}
	if err := in.Validate(); err != nil {
		problem(w, http.StatusBadRequest, "invalid group", err.Error())
		return
	}
	g, err := s.st.UpsertGroup(r.Context(), in)
	if err != nil {
		s.fail(w, "upsert group", err)
		return
	}
	s.log.Info("group saved", "name", g.Name, "plan", g.MeshPlan, "interval_s", g.IntervalS)
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	err := s.st.DeleteGroup(r.Context(), r.PathValue("name"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		problem(w, http.StatusNotFound, "no such group", "")
	case err != nil:
		// A group with agents still in it is the caller's problem to fix, and
		// the message says how.
		problem(w, http.StatusConflict, "cannot delete group", err.Error())
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("name")
	ttl := 24 * time.Hour
	if v := r.URL.Query().Get("ttl_hours"); v != "" {
		h, err := strconv.Atoi(v)
		if err != nil || h <= 0 || h > 24*365 {
			problem(w, http.StatusBadRequest, "invalid ttl_hours", "expected 1..8760")
			return
		}
		ttl = time.Duration(h) * time.Hour
	}

	tok, err := s.st.CreateEnrolmentToken(r.Context(), group, ttl)
	if err != nil {
		s.fail(w, "create enrolment token", err)
		return
	}
	// Logged without the token itself: it is a credential, and the point of
	// storing only its hash is defeated if it lands in the log.
	s.log.Info("enrolment token issued", "group", group, "expires_at", tok.ExpiresAt)
	writeJSON(w, http.StatusCreated, tok)
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.st.ListEnrolmentTokens(r.Context(), r.URL.Query().Get("group"))
	if err != nil {
		s.fail(w, "list enrolment tokens", err)
		return
	}
	writeJSON(w, http.StatusOK, toks)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r)
	if !ok {
		return
	}
	a, err := s.st.AgentByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		problem(w, http.StatusNotFound, "no such agent", "")
		return
	}
	if err != nil {
		s.fail(w, "get agent", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id": a.AgentID, "name": a.Name, "group": a.Group,
		"version": a.Version, "probe_addr": a.ProbeAddr, "probe_port": a.ProbePort,
		"capabilities": a.Capabilities, "host": a.Host,
		"state": a.State(time.Now()), "last_seen_at": a.LastSeenAt,
		"registered_at": a.RegisteredAt,
	})
}

func (s *Server) handlePatchAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r)
	if !ok {
		return
	}
	var p store.AgentPatch
	if !decode(w, r, &p) {
		return
	}
	err := s.st.PatchAgent(r.Context(), id, p)
	if errors.Is(err, store.ErrNotFound) {
		problem(w, http.StatusNotFound, "no such agent", "")
		return
	}
	if err != nil {
		s.fail(w, "patch agent", err)
		return
	}
	s.log.Info("agent updated", "agent", id,
		"inbound_reachable", p.InboundReachable, "is_hub", p.IsHub, "disabled", p.Disabled)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r)
	if !ok {
		return
	}
	err := s.st.DeleteAgent(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		problem(w, http.StatusNotFound, "no such agent", "")
		return
	}
	if err != nil {
		s.fail(w, "delete agent", err)
		return
	}
	s.log.Info("agent deleted", "agent", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePairs(w http.ResponseWriter, r *http.Request) {
	from, _, ok := timeWindow(w, r)
	if !ok {
		return
	}
	pairs, err := s.st.Pairs(r.Context(), r.URL.Query().Get("group"), from)
	if err != nil {
		s.fail(w, "summarise pairs", err)
		return
	}
	writeJSON(w, http.StatusOK, pairs)
}

func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request) {
	from, to, ok := timeWindow(w, r)
	if !ok {
		return
	}

	bucketName := r.URL.Query().Get("bucket")
	if bucketName == "" {
		bucketName = autoBucket(to.Sub(from))
	}
	bucket, valid := allowedBuckets[bucketName]
	if !valid {
		problem(w, http.StatusBadRequest, "invalid bucket", "expected one of 1m, 5m, 15m, 1h, 6h, 1d")
		return
	}

	q := store.SeriesQuery{
		Group:  r.URL.Query().Get("group"),
		From:   from,
		To:     to,
		Bucket: bucket,
	}
	if v := r.URL.Query().Get("agent"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid agent id", "")
			return
		}
		q.Agent = &id
	}
	if v := r.URL.Query().Get("peer"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid peer id", "")
			return
		}
		q.Peer = &id
	}

	points, err := s.st.Series(r.Context(), q)
	if err != nil {
		s.fail(w, "series query", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bucket": bucketName,
		"from":   from,
		"to":     to,
		"points": points,
	})
}

// autoBucket keeps the point count sane for a chart without the caller having
// to think about it: roughly 100-300 buckets across any window.
func autoBucket(window time.Duration) string {
	switch {
	case window <= 2*time.Hour:
		return "1m"
	case window <= 12*time.Hour:
		return "5m"
	case window <= 2*24*time.Hour:
		return "15m"
	case window <= 14*24*time.Hour:
		return "1h"
	case window <= 60*24*time.Hour:
		return "6h"
	default:
		return "1d"
	}
}

// timeWindow parses from/to, defaulting to the last hour and refusing a range
// wide enough to hurt the database.
func timeWindow(w http.ResponseWriter, r *http.Request) (time.Time, time.Time, bool) {
	now := time.Now()
	to := now
	from := now.Add(-time.Hour)

	if v := r.URL.Query().Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid to", "expected RFC 3339")
			return time.Time{}, time.Time{}, false
		}
		to = t
	}
	if v := r.URL.Query().Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid from", "expected RFC 3339")
			return time.Time{}, time.Time{}, false
		}
		from = t
	} else if v := r.URL.Query().Get("window"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			problem(w, http.StatusBadRequest, "invalid window", "expected a duration like 6h or 7d")
			return time.Time{}, time.Time{}, false
		}
		from = to.Add(-d)
	}

	if !from.Before(to) {
		problem(w, http.StatusBadRequest, "invalid range", "from must be before to")
		return time.Time{}, time.Time{}, false
	}
	if to.Sub(from) > maxWindow {
		problem(w, http.StatusBadRequest, "range too wide",
			"the maximum window is 90 days")
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

func pathUUID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid agent id", "expected a UUID")
		return uuid.Nil, false
	}
	return id, true
}
