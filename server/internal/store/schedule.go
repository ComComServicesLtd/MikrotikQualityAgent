package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/scheduler"
)

// Groups returns every group with its mesh configuration.
func (s *Store) Groups(ctx context.Context) ([]model.Group, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT name, description, mesh_plan, mesh_fanout, interval_s, created_at
		FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Group
	for rows.Next() {
		var g model.Group
		if err := rows.Scan(&g.Name, &g.Description, &g.MeshPlan,
			&g.MeshFanout, &g.IntervalS, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Candidates returns a group's agents as the scheduler sees them.
//
// Liveness is computed in SQL from last_seen_at rather than read from a stored
// status column, so it cannot drift out of step with reality.
func (s *Store) Candidates(ctx context.Context, group string) ([]scheduler.Candidate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.agent_id, a.name, COALESCE(host(a.probe_addr), ''), a.probe_port,
		       a.inbound_reachable, a.is_hub, a.capabilities,
		       (NOT a.disabled AND a.last_seen_at IS NOT NULL
		        AND a.last_seen_at > now() - $2::interval),
		       (ag.role = 'reflector')
		FROM agent_groups ag
		JOIN agents a ON a.agent_id = ag.agent_id
		WHERE ag.group_name = $1`, group, model.StaleAfter.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []scheduler.Candidate
	for rows.Next() {
		var c scheduler.Candidate
		if err := rows.Scan(&c.AgentID, &c.Name, &c.Address, &c.ProbePort,
			&c.InboundReachable, &c.Hub, &c.Caps, &c.Online, &c.ReflectorOnly); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateMeshTasks writes one cycle of scheduled work.
//
// Each pairing becomes two rows sharing a session id: a sender task and the
// matching reflector grant. Both are needed -- the reflector drops packets for
// any session it has not been told about.
//
// Task ids are derived from the group, pair and cycle so re-running a cycle is
// idempotent. A scheduler that ran twice after a restart would otherwise double
// the load on every router in the group.
func (s *Store) CreateMeshTasks(
	ctx context.Context,
	group string,
	pairs []scheduler.Pairing,
	cycle int,
	interval time.Duration,
	params map[string]any,
) (int, error) {
	if len(pairs) == 0 {
		return 0, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	created := 0
	for i, p := range pairs {
		sessionID, err := NewSessionID()
		if err != nil {
			return created, err
		}

		// Spread start times across the cycle. Without this the whole group
		// fires at once, and the resulting self-inflicted burst is measured as
		// if it were network congestion.
		offset := time.Duration(0)
		if len(pairs) > 1 {
			offset = time.Duration(int64(interval) * int64(i) / int64(len(pairs)))
		}
		startAt := time.Now().Add(offset)

		base := fmt.Sprintf("%s:%s:%s:%d", group, p.Sender.AgentID, p.Reflector.AgentID, cycle)

		n, err := insertTask(ctx, tx, taskRow{
			taskID:    "s:" + base,
			sessionID: int64(sessionID),
			kind:      string(model.TaskMQPProbe),
			role:      string(model.RoleSender),
			agentID:   p.Sender.AgentID,
			peerID:    &p.Reflector.AgentID,
			params:    params,
			recurring: true,
			startAt:   startAt,
			group:     group,
		})
		if err != nil {
			return created, err
		}
		created += n

		// The reflector grant carries no measurement parameters: it only
		// authorises this session from this peer.
		m, err := insertTask(ctx, tx, taskRow{
			taskID:    "r:" + base,
			sessionID: int64(sessionID),
			kind:      string(model.TaskMQPProbe),
			role:      string(model.RoleReflector),
			agentID:   p.Reflector.AgentID,
			peerID:    &p.Sender.AgentID,
			params:    map[string]any{},
			recurring: true,
			startAt:   startAt,
			group:     group,
		})
		if err != nil {
			return created, err
		}
		created += m
	}

	if err := tx.Commit(ctx); err != nil {
		return created, err
	}
	return created, nil
}

type taskRow struct {
	taskID    string
	sessionID int64
	kind      string
	role      string
	agentID   uuid.UUID
	peerID    *uuid.UUID
	params    map[string]any
	recurring bool
	startAt   time.Time
	group     string
}

func insertTask(ctx context.Context, tx pgx.Tx, r taskRow) (int, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO tasks (task_id, session_id, kind, role, agent_id, peer_id,
		                   params, recurring, scheduled_for, group_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (task_id) DO NOTHING`,
		r.taskID, r.sessionID, r.kind, r.role, r.agentID, r.peerID,
		r.params, r.recurring, r.startAt, r.group)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// PurgeCompletedTasks removes finished task rows older than the cutoff.
//
// Recurring mesh work creates rows continuously; without this the table grows
// without bound and the pending-task index degrades for every agent poll.
func (s *Store) PurgeCompletedTasks(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM tasks
		WHERE state IN ('done','expired') AND created_at < now() - $1::interval`,
		olderThan.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- one-shot tests -------------------------------------------------------

// OneShotRequest is an operator-issued diagnostic.
type OneShotRequest struct {
	AgentID   uuid.UUID
	PeerID    *uuid.UUID
	Kind      model.TaskKind
	Params    map[string]any
	Group     string
	ExpiresIn time.Duration
}

// CreateOneShot writes a single non-recurring task, plus the matching
// reflector grant when the kind measures between two agents.
//
// The id carries a random suffix rather than being derived from the pair and a
// cycle like mesh work: two operators asking for the same traceroute a minute
// apart both want an answer, so these must not collide and silently become one.
func (s *Store) CreateOneShot(ctx context.Context, req OneShotRequest) (string, time.Time, error) {
	sessionID, err := NewSessionID()
	if err != nil {
		return "", time.Time{}, err
	}
	suffix, err := NewSessionID()
	if err != nil {
		return "", time.Time{}, err
	}
	taskID := fmt.Sprintf("o:%s:%016x", req.Kind, suffix)
	expiresAt := time.Now().Add(req.ExpiresIn)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := insertOneShot(ctx, tx, oneShotRow{
		taskID:    taskID,
		sessionID: int64(sessionID),
		kind:      string(req.Kind),
		role:      string(model.RoleSender),
		agentID:   req.AgentID,
		peerID:    req.PeerID,
		params:    req.Params,
		group:     req.Group,
		expiresAt: expiresAt,
	}); err != nil {
		return "", time.Time{}, err
	}

	// A probe between agents needs the far end told about the session, or it
	// drops every packet and the test reports total loss.
	if req.Kind.NeedsPeer() && req.PeerID != nil {
		if _, err := insertOneShot(ctx, tx, oneShotRow{
			taskID:    "or:" + taskID,
			sessionID: int64(sessionID),
			kind:      string(req.Kind),
			role:      string(model.RoleReflector),
			agentID:   *req.PeerID,
			peerID:    &req.AgentID,
			params:    map[string]any{},
			group:     req.Group,
			expiresAt: expiresAt,
		}); err != nil {
			return "", time.Time{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return taskID, expiresAt, nil
}

type oneShotRow struct {
	taskID    string
	sessionID int64
	kind      string
	role      string
	agentID   uuid.UUID
	peerID    *uuid.UUID
	params    map[string]any
	group     string
	expiresAt time.Time
}

func insertOneShot(ctx context.Context, tx pgx.Tx, r oneShotRow) (int, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO tasks (task_id, session_id, kind, role, agent_id, peer_id,
		                   params, recurring, scheduled_for, group_name, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, false, now(), $8, $9)`,
		r.taskID, r.sessionID, r.kind, r.role, r.agentID, r.peerID,
		r.params, r.group, r.expiresAt)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// TestStatus is a one-shot and its result, if it has one yet.
type TestStatus struct {
	TaskID    string          `json:"task_id"`
	Kind      string          `json:"kind"`
	State     string          `json:"state"`
	Agent     string          `json:"agent"`
	Peer      string          `json:"peer,omitempty"`
	Group     string          `json:"group,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
	Result    *TestResultView `json:"result,omitempty"`
}

// TestResultView is the reported outcome. Absent until the agent submits.
type TestResultView struct {
	Time     time.Time       `json:"time"`
	Status   string          `json:"status"`
	Error    *string         `json:"error,omitempty"`
	RTTAvgUS *int64          `json:"rtt_avg_us,omitempty"`
	LossPct  *float64        `json:"loss_pct,omitempty"`
	TxBps    *int64          `json:"tx_bps,omitempty"`
	RxBps    *int64          `json:"rx_bps,omitempty"`
	Extra    json.RawMessage `json:"extra,omitempty"`
}

// TestByID returns a one-shot's state and its result if one has arrived.
func (s *Store) TestByID(ctx context.Context, taskID string) (TestStatus, error) {
	var t TestStatus
	var peer, group *string
	err := s.pool.QueryRow(ctx, `
		SELECT t.task_id, t.kind, t.state, a.name, p.name, t.group_name,
		       t.created_at, t.expires_at
		FROM tasks t
		JOIN agents a ON a.agent_id = t.agent_id
		LEFT JOIN agents p ON p.agent_id = t.peer_id
		WHERE t.task_id = $1`, taskID).
		Scan(&t.TaskID, &t.Kind, &t.State, &t.Agent, &peer, &group,
			&t.CreatedAt, &t.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TestStatus{}, ErrNotFound
	}
	if err != nil {
		return TestStatus{}, err
	}
	if peer != nil {
		t.Peer = *peer
	}
	if group != nil {
		t.Group = *group
	}

	var r TestResultView
	var extra []byte
	err = s.pool.QueryRow(ctx, `
		SELECT time, status, error, rtt_avg_us, loss_pct, tx_bps, rx_bps, extra
		FROM results WHERE task_id = $1 ORDER BY time DESC LIMIT 1`, taskID).
		Scan(&r.Time, &r.Status, &r.Error, &r.RTTAvgUS, &r.LossPct, &r.TxBps, &r.RxBps, &extra)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Not an error: the agent has simply not reported yet.
	case err != nil:
		return TestStatus{}, err
	default:
		r.Extra = extra
		t.Result = &r
	}
	return t, nil
}
