package store

import (
	"context"
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
