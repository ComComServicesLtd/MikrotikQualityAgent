package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/model"
)

// --- groups ---------------------------------------------------------------

// Tags are required, not decorative: Go's JSON decoder matches field names
// case-insensitively but does not bridge snake_case, so without them a request
// body of {"mesh_plan":"full"} decodes to the zero value and Validate quietly
// substitutes the default — returning 200 with settings the caller never asked
// for.
type GroupInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	MeshPlan    string `json:"mesh_plan"`
	MeshFanout  int    `json:"mesh_fanout"`
	IntervalS   int    `json:"interval_s"`
}

var validPlans = map[string]bool{"full": true, "ring": true, "hub": true, "partial": true}

// Validate rejects input at the edge, where a clear message can be returned,
// rather than letting a CHECK constraint surface as an opaque 500.
func (g *GroupInput) Validate() error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return errors.New("name is required")
	}
	if g.MeshPlan == "" {
		g.MeshPlan = "ring"
	}
	if !validPlans[g.MeshPlan] {
		return fmt.Errorf("mesh_plan %q is not one of full, ring, hub, partial", g.MeshPlan)
	}
	if g.MeshFanout <= 0 {
		g.MeshFanout = 3
	}
	if g.IntervalS == 0 {
		g.IntervalS = 300
	}
	// A cadence below the length of a probe run would queue work faster than
	// agents can complete it, and the backlog would look like agent failure.
	if g.IntervalS < 10 {
		return errors.New("interval_s must be at least 10")
	}
	return nil
}

func (s *Store) UpsertGroup(ctx context.Context, in GroupInput) (model.Group, error) {
	var g model.Group
	err := s.pool.QueryRow(ctx, `
		INSERT INTO groups (name, description, mesh_plan, mesh_fanout, interval_s)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (name) DO UPDATE SET
			description = EXCLUDED.description,
			mesh_plan   = EXCLUDED.mesh_plan,
			mesh_fanout = EXCLUDED.mesh_fanout,
			interval_s  = EXCLUDED.interval_s
		RETURNING name, description, mesh_plan, mesh_fanout, interval_s, created_at`,
		in.Name, in.Description, in.MeshPlan, in.MeshFanout, in.IntervalS).
		Scan(&g.Name, &g.Description, &g.MeshPlan, &g.MeshFanout, &g.IntervalS, &g.CreatedAt)
	return g, err
}

// DeleteGroup refuses while agents still belong to it. The foreign key would
// reject it anyway, but a clear message beats a constraint-violation 500.
func (s *Store) DeleteGroup(ctx context.Context, name string) error {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM agents WHERE group_name = $1`, name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("group %q still has %d agent(s); move or delete them first", name, n)
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- enrolment tokens -----------------------------------------------------

type EnrolmentToken struct {
	Token     string     `json:"token,omitempty"`
	Group     string     `json:"group"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	UsedBy    *uuid.UUID `json:"used_by,omitempty"`
}

// CreateEnrolmentToken mints a single-use, group-scoped token.
//
// The plaintext is returned exactly once and never stored — only its hash is
// kept, so the token cannot be recovered from the database afterwards.
func (s *Store) CreateEnrolmentToken(ctx context.Context, group string, ttl time.Duration) (EnrolmentToken, error) {
	token, hash, err := NewToken()
	if err != nil {
		return EnrolmentToken{}, err
	}
	var out EnrolmentToken
	err = s.pool.QueryRow(ctx, `
		INSERT INTO enrolment_tokens (token_hash, group_name, expires_at)
		VALUES ($1, $2, now() + $3::interval)
		RETURNING group_name, expires_at, created_at`,
		hash, group, ttl.String()).Scan(&out.Group, &out.ExpiresAt, &out.CreatedAt)
	if err != nil {
		return EnrolmentToken{}, err
	}
	out.Token = token
	return out, nil
}

// ListEnrolmentTokens never returns plaintext — it cannot, since only hashes
// are stored. It exists so an operator can see what is outstanding.
func (s *Store) ListEnrolmentTokens(ctx context.Context, group string) ([]EnrolmentToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT group_name, expires_at, created_at, used_at, used_by
		FROM enrolment_tokens
		WHERE ($1 = '' OR group_name = $1)
		ORDER BY created_at DESC LIMIT 100`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []EnrolmentToken{}
	for rows.Next() {
		var t EnrolmentToken
		if err := rows.Scan(&t.Group, &t.ExpiresAt, &t.CreatedAt, &t.UsedAt, &t.UsedBy); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- agents ---------------------------------------------------------------

// AgentPatch carries only the fields an operator may change. Pointers so an
// omitted field is distinguishable from one deliberately set to false.
type AgentPatch struct {
	InboundReachable *bool `json:"inbound_reachable,omitempty"`
	IsHub            *bool `json:"is_hub,omitempty"`
	Disabled         *bool `json:"disabled,omitempty"`
}

func (s *Store) PatchAgent(ctx context.Context, id uuid.UUID, p AgentPatch) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE agents SET
			inbound_reachable = COALESCE($2, inbound_reachable),
			is_hub            = COALESCE($3, is_hub),
			disabled          = COALESCE($4, disabled)
		WHERE agent_id = $1`, id, p.InboundReachable, p.IsHub, p.Disabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAgent(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM agents WHERE agent_id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- results --------------------------------------------------------------

type SeriesQuery struct {
	Group  string
	Agent  *uuid.UUID
	Peer   *uuid.UUID
	From   time.Time
	To     time.Time
	Bucket time.Duration
}

// SeriesPoint is one time bucket of aggregated measurements.
type SeriesPoint struct {
	Time     time.Time `json:"time"`
	Samples  int       `json:"samples"`
	RTTAvgUS *float64  `json:"rtt_avg_us,omitempty"`
	RTTP95US *float64  `json:"rtt_p95_us,omitempty"`
	RTTMaxUS *float64  `json:"rtt_max_us,omitempty"`
	JitterUS *float64  `json:"jitter_us,omitempty"`
	LossPct  *float64  `json:"loss_pct,omitempty"`
	MOS      *float64  `json:"mos,omitempty"`
	DSCPPct  *float64  `json:"dscp_conformant_pct,omitempty"`
	Failures int       `json:"failures"`
}

// Series returns bucketed measurements for charting.
//
// time_bucket is TimescaleDB's; bucket width is validated by the caller rather
// than interpolated blindly, since it lands in the query text.
func (s *Store) Series(ctx context.Context, q SeriesQuery) ([]SeriesPoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT time_bucket($1::interval, time) AS bucket,
		       count(*),
		       avg(rtt_avg_us), avg(rtt_p95_us), max(rtt_max_us),
		       avg(ipdv_avg_us), avg(loss_pct), avg(mos), avg(dscp_conformant_pct),
		       sum(CASE WHEN status <> 'ok' THEN 1 ELSE 0 END)
		FROM results
		WHERE time >= $2 AND time < $3
		  AND ($4 = '' OR group_name = $4)
		  AND ($5::uuid IS NULL OR agent_id = $5)
		  AND ($6::uuid IS NULL OR peer_id = $6)
		GROUP BY bucket
		ORDER BY bucket`,
		q.Bucket.String(), q.From, q.To, q.Group, q.Agent, q.Peer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SeriesPoint{}
	for rows.Next() {
		var p SeriesPoint
		var failures int64
		if err := rows.Scan(&p.Time, &p.Samples, &p.RTTAvgUS, &p.RTTP95US, &p.RTTMaxUS,
			&p.JitterUS, &p.LossPct, &p.MOS, &p.DSCPPct, &failures); err != nil {
			return nil, err
		}
		p.Failures = int(failures)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PairSummary is the current state of one directed agent pair.
type PairSummary struct {
	AgentID  uuid.UUID  `json:"agent_id"`
	Agent    string     `json:"agent"`
	PeerID   *uuid.UUID `json:"peer_id,omitempty"`
	Peer     string     `json:"peer,omitempty"`
	Group    string     `json:"group"`
	LastSeen time.Time  `json:"last_result_at"`
	Samples  int        `json:"samples"`
	RTTAvgUS *float64   `json:"rtt_avg_us,omitempty"`
	JitterUS *float64   `json:"jitter_us,omitempty"`
	LossPct  *float64   `json:"loss_pct,omitempty"`
	MOS      *float64   `json:"mos,omitempty"`
	DSCPPct  *float64   `json:"dscp_conformant_pct,omitempty"`
	Failures int        `json:"failures"`
}

// Pairs summarises every measured path over a window — the overview a
// dashboard opens on.
func (s *Store) Pairs(ctx context.Context, group string, since time.Time) ([]PairSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.agent_id, a.name, r.peer_id, COALESCE(p.name, ''), r.group_name,
		       max(r.time), count(*),
		       avg(r.rtt_avg_us), avg(r.ipdv_avg_us), avg(r.loss_pct),
		       avg(r.mos), avg(r.dscp_conformant_pct),
		       sum(CASE WHEN r.status <> 'ok' THEN 1 ELSE 0 END)
		FROM results r
		JOIN agents a ON a.agent_id = r.agent_id
		LEFT JOIN agents p ON p.agent_id = r.peer_id
		WHERE r.time >= $1 AND ($2 = '' OR r.group_name = $2)
		GROUP BY r.agent_id, a.name, r.peer_id, p.name, r.group_name
		ORDER BY avg(r.loss_pct) DESC NULLS LAST, avg(r.rtt_avg_us) DESC NULLS LAST`,
		since, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []PairSummary{}
	for rows.Next() {
		var p PairSummary
		var failures int64
		if err := rows.Scan(&p.AgentID, &p.Agent, &p.PeerID, &p.Peer, &p.Group,
			&p.LastSeen, &p.Samples, &p.RTTAvgUS, &p.JitterUS, &p.LossPct,
			&p.MOS, &p.DSCPPct, &failures); err != nil {
			return nil, err
		}
		p.Failures = int(failures)
		out = append(out, p)
	}
	return out, rows.Err()
}

// AgentByID is used by the detail view.
func (s *Store) AgentByID(ctx context.Context, id uuid.UUID) (model.Agent, error) {
	var a model.Agent
	var probeAddr string
	err := s.pool.QueryRow(ctx, `
		SELECT agent_id, name, group_name, version, COALESCE(host(probe_addr), ''),
		       probe_port, capabilities, host_info, registered_at, last_seen_at, disabled
		FROM agents WHERE agent_id = $1`, id).
		Scan(&a.AgentID, &a.Name, &a.Group, &a.Version, &probeAddr,
			&a.ProbePort, &a.Capabilities, &a.Host, &a.RegisteredAt, &a.LastSeenAt, &a.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Agent{}, ErrNotFound
	}
	a.ProbeAddr = probeAddr
	return a, err
}

// --- group membership -----------------------------------------------------

// Membership is one agent's place in one group.
type Membership struct {
	AgentID uuid.UUID `json:"agent_id"`
	Name    string    `json:"name"`
	Group   string    `json:"group"`
	// "member" takes part in the mesh normally; "reflector" answers probes but
	// never originates them.
	Role    string    `json:"role"`
	AddedAt time.Time `json:"added_at"`
}

var validRoles = map[string]bool{"member": true, "reflector": true}

// AddMember places an agent in a group, or changes the role it holds there.
func (s *Store) AddMember(ctx context.Context, group string, id uuid.UUID, role string) error {
	if role == "" {
		role = "member"
	}
	if !validRoles[role] {
		return fmt.Errorf("role %q is not one of member, reflector", role)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_groups (agent_id, group_name, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (agent_id, group_name) DO UPDATE SET role = EXCLUDED.role`,
		id, group, role)
	return err
}

// RemoveMember takes an agent out of a group.
//
// An agent's home group cannot be removed this way: it is where the agent
// enrolled and what it reports as its own, and dropping it would leave the
// agent registered but in no mesh at all, which looks like a scheduler fault
// rather than a configuration choice.
func (s *Store) RemoveMember(ctx context.Context, group string, id uuid.UUID) error {
	var home string
	if err := s.pool.QueryRow(ctx,
		`SELECT group_name FROM agents WHERE agent_id = $1`, id).Scan(&home); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if home == group {
		return fmt.Errorf("%q is this agent's home group; delete the agent instead", group)
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM agent_groups WHERE agent_id = $1 AND group_name = $2`, id, group)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Members lists a group's agents and the role each holds.
func (s *Store) Members(ctx context.Context, group string) ([]Membership, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ag.agent_id, a.name, ag.group_name, ag.role, ag.added_at
		FROM agent_groups ag JOIN agents a ON a.agent_id = ag.agent_id
		WHERE ag.group_name = $1 ORDER BY a.name`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Membership{}
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.AgentID, &m.Name, &m.Group, &m.Role, &m.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GroupsOf lists every group an agent belongs to — the view that matters for a
// shared upstream agent, where the home group is the least interesting one.
func (s *Store) GroupsOf(ctx context.Context, id uuid.UUID) ([]Membership, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ag.agent_id, a.name, ag.group_name, ag.role, ag.added_at
		FROM agent_groups ag JOIN agents a ON a.agent_id = ag.agent_id
		WHERE ag.agent_id = $1 ORDER BY ag.group_name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Membership{}
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.AgentID, &m.Name, &m.Group, &m.Role, &m.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
