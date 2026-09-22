// Package store is the TimescaleDB access layer.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrBadToken     = errors.New("invalid or expired token")
	ErrNameConflict = errors.New("name already registered to a different agent")
)

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	// Agents poll on a short interval, so connections churn. A modest ceiling
	// keeps Postgres from being swamped as the fleet grows.
	cfg.MaxConns = 16
	cfg.MinConns = 2
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate applies the schema. Idempotent — every statement is IF NOT EXISTS.
func (s *Store) Migrate(ctx context.Context, sql string) error {
	_, err := s.pool.Exec(ctx, sql)
	return err
}

// --- tokens --------------------------------------------------------------

// NewToken returns a fresh token and its hash. Only the hash is stored, so a
// leaked database yields no working credentials.
func NewToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	return token, h[:], nil
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// NewSessionID returns an unguessable MQP session identifier.
//
// This is the reflector's only admission control, so it must come from a
// CSPRNG — a counter or timestamp here would let anyone who can reach the probe
// port inject samples.
func NewSessionID() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// --- agents --------------------------------------------------------------

type RegisterRequest struct {
	AgentID      *uuid.UUID
	Name         string
	Group        string
	Version      string
	Capabilities model.Capabilities
	Host         model.HostInfo
	// ObservedAddr is the source address the registration arrived from. Used
	// as the probe address unless the agent pinned one.
	ObservedAddr  string
	AdvertiseAddr string
}

type RegisterResult struct {
	AgentID uuid.UUID
	Token   string
	Group   string
}

// RedeemEnrolment validates a group-scoped, single-use enrolment token.
func (s *Store) RedeemEnrolment(ctx context.Context, token string) (string, error) {
	var group string
	err := s.pool.QueryRow(ctx, `
		SELECT group_name FROM enrolment_tokens
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`,
		hashToken(token)).Scan(&group)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrBadToken
	}
	return group, err
}

// Register creates or refreshes an agent.
//
// Re-registering an existing name with a matching agent_id refreshes metadata
// and issues a new token, so a container restart is the same agent rather than
// a new one. A name arriving with a *different* agent_id is a conflict, not a
// silent takeover.
func (s *Store) Register(ctx context.Context, req RegisterRequest) (RegisterResult, error) {
	token, hash, err := NewToken()
	if err != nil {
		return RegisterResult{}, err
	}

	probeAddr := req.AdvertiseAddr
	if probeAddr == "" {
		probeAddr = req.ObservedAddr
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RegisterResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT agent_id FROM agents WHERE name = $1`, req.Name).Scan(&existingID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// New agent.
	case err != nil:
		return RegisterResult{}, err
	case req.AgentID != nil && *req.AgentID == existingID:
		// Known agent coming back.
	default:
		return RegisterResult{}, ErrNameConflict
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO groups (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`,
		req.Group); err != nil {
		return RegisterResult{}, err
	}

	var id uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO agents (name, group_name, token_hash, version,
		                    probe_addr, probe_port, capabilities, host_info, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (name) DO UPDATE SET
			group_name   = EXCLUDED.group_name,
			token_hash   = EXCLUDED.token_hash,
			version      = EXCLUDED.version,
			probe_addr   = EXCLUDED.probe_addr,
			probe_port   = EXCLUDED.probe_port,
			capabilities = EXCLUDED.capabilities,
			host_info    = EXCLUDED.host_info,
			last_seen_at = now()
		RETURNING agent_id`,
		req.Name, req.Group, hash, req.Version,
		nullIfEmpty(probeAddr), req.Capabilities.ProbePort,
		req.Capabilities, req.Host).Scan(&id)
	if err != nil {
		return RegisterResult{}, err
	}

	// The home group is a membership like any other, so the scheduler -- which
	// plans from agent_groups -- sees a freshly enrolled agent immediately.
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_groups (agent_id, group_name) VALUES ($1, $2)
		ON CONFLICT (agent_id, group_name) DO NOTHING`, id, req.Group); err != nil {
		return RegisterResult{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{AgentID: id, Token: token, Group: req.Group}, nil
}

// MarkEnrolmentUsed burns a single-use token. Called after a successful
// registration so a failed one does not consume it.
func (s *Store) MarkEnrolmentUsed(ctx context.Context, token string, agentID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE enrolment_tokens SET used_at = now(), used_by = $2
		WHERE token_hash = $1 AND used_at IS NULL`, hashToken(token), agentID)
	return err
}

// AuthenticateAgent resolves a bearer token to an agent.
func (s *Store) AuthenticateAgent(ctx context.Context, token string) (model.Agent, error) {
	var a model.Agent
	var stored []byte
	var probeAddr string

	err := s.pool.QueryRow(ctx, `
		SELECT agent_id, name, group_name, version, token_hash,
		       COALESCE(host(probe_addr), ''), probe_port, capabilities, host_info,
		       registered_at, last_seen_at, disabled
		FROM agents WHERE token_hash = $1`, hashToken(token)).
		Scan(&a.AgentID, &a.Name, &a.Group, &a.Version, &stored,
			&probeAddr, &a.ProbePort, &a.Capabilities, &a.Host,
			&a.RegisteredAt, &a.LastSeenAt, &a.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Agent{}, ErrBadToken
	}
	if err != nil {
		return model.Agent{}, err
	}

	// The lookup above already matched on the hash, but compare in constant
	// time anyway so this stays correct if the query ever changes shape.
	if subtle.ConstantTimeCompare(stored, hashToken(token)) != 1 {
		return model.Agent{}, ErrBadToken
	}
	if a.Disabled {
		return model.Agent{}, ErrBadToken
	}
	a.ProbeAddr = probeAddr
	return a, nil
}

func (s *Store) Heartbeat(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE agents SET last_seen_at = now() WHERE agent_id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListAgents(ctx context.Context, group string) ([]model.Agent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, name, group_name, version, COALESCE(host(probe_addr), ''), probe_port,
		       capabilities, host_info, registered_at, last_seen_at, disabled
		FROM agents
		WHERE ($1 = '' OR group_name = $1)
		ORDER BY group_name, name`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Agent
	for rows.Next() {
		var a model.Agent
		var probeAddr string
		if err := rows.Scan(&a.AgentID, &a.Name, &a.Group, &a.Version,
			&probeAddr, &a.ProbePort, &a.Capabilities, &a.Host,
			&a.RegisteredAt, &a.LastSeenAt, &a.Disabled); err != nil {
			return nil, err
		}
		a.ProbeAddr = probeAddr
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- tasks ---------------------------------------------------------------

// LeaseTasks claims pending work for an agent.
//
// FOR UPDATE SKIP LOCKED means two concurrent polls never hand out the same
// task, without either blocking the other.
func (s *Store) LeaseTasks(ctx context.Context, agentID uuid.UUID, lease time.Duration) ([]model.Task, error) {
	rows, err := s.pool.Query(ctx, `
		WITH claimed AS (
			SELECT task_id FROM tasks
			WHERE agent_id = $1 AND state = 'pending' AND scheduled_for <= now()
			ORDER BY scheduled_for
			LIMIT 16
			FOR UPDATE SKIP LOCKED
		)
		UPDATE tasks t
		SET state = 'leased', leased_at = now(), lease_expires_at = now() + $2::interval
		FROM claimed c
		WHERE t.task_id = c.task_id
		RETURNING t.task_id, t.session_id, t.kind, t.role, t.peer_id, t.params, t.lease_expires_at`,
		agentID, lease.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []model.Task
	peerIDs := map[uuid.UUID]*model.PeerRef{}
	for rows.Next() {
		var t model.Task
		var sessionID int64
		var peerID *uuid.UUID
		if err := rows.Scan(&t.TaskID, &sessionID, &t.Kind, &t.Role,
			&peerID, &t.Params, &t.LeaseExpiresAt); err != nil {
			return nil, err
		}
		// session_id is stored signed because Postgres has no unsigned 64-bit
		// integer; the bit pattern is what matters and round-trips exactly.
		t.SessionID = uint64(sessionID)
		if peerID != nil {
			ref := &model.PeerRef{AgentID: *peerID}
			t.Peer = ref
			peerIDs[*peerID] = ref
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(peerIDs) > 0 {
		if err := s.fillPeers(ctx, peerIDs); err != nil {
			return nil, err
		}
	}
	return tasks, nil
}

func (s *Store) fillPeers(ctx context.Context, peers map[uuid.UUID]*model.PeerRef) error {
	ids := make([]uuid.UUID, 0, len(peers))
	for id := range peers {
		ids = append(ids, id)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, name, COALESCE(host(probe_addr), ''), probe_port
		FROM agents WHERE agent_id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		var name, addr string
		var port int
		if err := rows.Scan(&id, &name, &addr, &port); err != nil {
			return err
		}
		if ref, ok := peers[id]; ok {
			ref.Name = name
			ref.ProbePort = port
			ref.Address = addr
		}
	}
	return rows.Err()
}

// ExpireLeases returns tasks whose agent never reported back to the pending
// pool. Without this, a container that dies mid-task strands its work forever.
func (s *Store) ExpireLeases(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE tasks SET state = 'pending', leased_at = NULL, lease_expires_at = NULL
		WHERE state = 'leased' AND lease_expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- results -------------------------------------------------------------

// SaveResult stores one result and closes out its task.
//
// Idempotent on task_id: an agent draining a spool after an outage must not
// double-count. A repeat submission returns (false, nil).
func (s *Store) SaveResult(ctx context.Context, agentID uuid.UUID, group string, r model.Result) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var peerID *uuid.UUID
	var kind string
	var taskGroup *string
	err = tx.QueryRow(ctx,
		`SELECT peer_id, kind, group_name FROM tasks WHERE task_id = $1`, r.TaskID).
		Scan(&peerID, &kind, &taskGroup)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}

	// The task's group wins over the submitting agent's own. A shared upstream
	// agent answers for many customers; filing its results under its home group
	// would make them disappear from the customer view they belong to.
	if taskGroup != nil && *taskGroup != "" {
		group = *taskGroup
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO results (
			time, task_id, session_id, agent_id, peer_id, group_name, kind,
			status, error, started_at, ended_at,
			rtt_min_us, rtt_avg_us, rtt_max_us, rtt_stddev_us, rtt_p50_us, rtt_p95_us, rtt_p99_us,
			ipdv_avg_us, pdv_p95_us,
			sent, received, forward_lost, reverse_lost, unknown_direction, loss_pct,
			reordered, max_displacement, duplicated,
			dscp_requested, dscp_observed, dscp_conformant_pct,
			mos_codec, r_factor, mos,
			tx_bps, rx_bps, throughput_source, local_cpu_load, remote_cpu_load)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11,
			$12, $13, $14, $15, $16, $17, $18,
			$19, $20,
			$21, $22, $23, $24, $25, $26,
			$27, $28, $29,
			$30, $31, $32,
			$33, $34, $35,
			$36, $37, $38, $39, $40)
		ON CONFLICT (task_id, time) DO NOTHING`,
		r.EndedAt, r.TaskID, int64(r.SessionID), agentID, peerID, group, kind,
		string(r.Status), r.Error, r.StartedAt, r.EndedAt,
		v(r.RTT, func(x model.RTTStats) any { return x.MinUS }),
		v(r.RTT, func(x model.RTTStats) any { return x.AvgUS }),
		v(r.RTT, func(x model.RTTStats) any { return x.MaxUS }),
		v(r.RTT, func(x model.RTTStats) any { return x.StddevUS }),
		v(r.RTT, func(x model.RTTStats) any { return x.P50US }),
		v(r.RTT, func(x model.RTTStats) any { return x.P95US }),
		v(r.RTT, func(x model.RTTStats) any { return x.P99US }),
		v(r.Jitter, func(x model.JitterStats) any { return x.IPDVAvgUS }),
		v(r.Jitter, func(x model.JitterStats) any { return x.PDVP95US }),
		v(r.Loss, func(x model.LossStats) any { return x.Sent }),
		v(r.Loss, func(x model.LossStats) any { return x.Received }),
		v(r.Loss, func(x model.LossStats) any { return x.ForwardLost }),
		v(r.Loss, func(x model.LossStats) any { return x.ReverseLost }),
		v(r.Loss, func(x model.LossStats) any { return x.UnknownDirection }),
		v(r.Loss, func(x model.LossStats) any { return x.LossPct }),
		v(r.Reorder, func(x model.ReorderStats) any { return x.Reordered }),
		v(r.Reorder, func(x model.ReorderStats) any { return x.MaxDisplacement }),
		v(r.Reorder, func(x model.ReorderStats) any { return x.Duplicated }),
		v(r.DSCP, func(x model.DSCPStats) any { return x.Requested }),
		v(r.DSCP, func(x model.DSCPStats) any { return x.ObservedMode }),
		v(r.DSCP, func(x model.DSCPStats) any { return x.ConformantPct }),
		v(r.MOS, func(x model.MOSStats) any { return x.Codec }),
		v(r.MOS, func(x model.MOSStats) any { return x.RFactor }),
		v(r.MOS, func(x model.MOSStats) any { return x.MOS }),
		v(r.Throughput, func(x model.ThroughputStats) any { return x.TxBps }),
		v(r.Throughput, func(x model.ThroughputStats) any { return x.RxBps }),
		v(r.Throughput, func(x model.ThroughputStats) any { return x.Source }),
		v(r.Throughput, func(x model.ThroughputStats) any { return x.LocalCPULoad }),
		v(r.Throughput, func(x model.ThroughputStats) any { return x.RemoteCPULoad }),
	)
	if err != nil {
		return false, err
	}

	if _, err := tx.Exec(ctx, `UPDATE tasks SET state = 'done' WHERE task_id = $1`, r.TaskID); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// v extracts a field from an optional stats struct, yielding SQL NULL when the
// struct is absent. Writing a zero instead would be a lie: "no jitter data" and
// "zero jitter" are different facts, and averaging them together is wrong.
func v[T any](p *T, f func(T) any) any {
	if p == nil {
		return nil
	}
	return f(*p)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
