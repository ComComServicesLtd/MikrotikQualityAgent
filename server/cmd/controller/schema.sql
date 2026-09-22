-- Controller schema.
--
-- Relational inventory (agents, groups, tasks) and time-series results live in
-- the same database. TimescaleDB is a Postgres extension, so probe results get
-- hypertable partitioning and retention while still joining against agents with
-- real foreign keys.

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------- groups

CREATE TABLE IF NOT EXISTS groups (
    name         TEXT PRIMARY KEY,
    description  TEXT NOT NULL DEFAULT '',
    -- How the mesh is planned. 'full' is n*(n-1) ordered pairs and will
    -- saturate small routers past a handful of members; the others bound the
    -- per-agent cost. See internal/scheduler.
    mesh_plan    TEXT NOT NULL DEFAULT 'ring'
                 CHECK (mesh_plan IN ('full', 'ring', 'hub', 'partial')),
    -- For 'partial': how many peers each agent probes per cycle.
    mesh_fanout  INT NOT NULL DEFAULT 3 CHECK (mesh_fanout > 0),
    -- Seconds between test cycles for this group.
    interval_s   INT NOT NULL DEFAULT 300 CHECK (interval_s >= 10),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- agents

CREATE TABLE IF NOT EXISTS agents (
    agent_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL UNIQUE,
    group_name    TEXT NOT NULL REFERENCES groups(name) ON DELETE RESTRICT,

    -- Bearer token, stored hashed. A leaked database should not yield working
    -- agent credentials.
    token_hash    BYTEA NOT NULL,

    version       TEXT NOT NULL DEFAULT '',
    -- Address peers should probe this agent on. Normally learned from the
    -- source address of registration; can be pinned for static DNAT.
    probe_addr    INET,
    probe_port    INT NOT NULL DEFAULT 5301,

    capabilities  JSONB NOT NULL DEFAULT '{}'::jsonb,
    host_info     JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Whether peers can open a session *to* this agent. An agent behind NAT
    -- can complete a measurement as the sender -- the reflector's reply rides
    -- the same UDP flow and conntrack carries it home -- but it cannot be
    -- probed, so it must never be scheduled as a reflector.
    inbound_reachable BOOLEAN NOT NULL DEFAULT true,
    -- Designates a hub for the 'hub' mesh plan.
    is_hub        BOOLEAN NOT NULL DEFAULT false,

    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ,
    -- 'stale' is derived from last_seen_at rather than stored, except for
    -- explicit disable — a state column that drifts from reality is worse
    -- than no state column.
    disabled      BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS agents_group_idx ON agents (group_name);
CREATE INDEX IF NOT EXISTS agents_last_seen_idx ON agents (last_seen_at DESC);

-- An agent's group memberships.
--
-- Many-to-many, because a shared upstream agent belongs to every customer
-- group it serves. agents.group_name remains the agent's *home* group -- the
-- one it enrolled into and reports as its own -- while this table is what the
-- scheduler actually plans from.
CREATE TABLE IF NOT EXISTS agent_groups (
    agent_id   UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
    -- 'member' takes part in the mesh normally. 'reflector' may answer probes
    -- but never originate them: a shared upstream agent in fifty customer
    -- groups would otherwise have its send load grow with the customer count,
    -- while answering costs it one socket regardless.
    role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'reflector')),
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, group_name)
);

CREATE INDEX IF NOT EXISTS agent_groups_group_idx ON agent_groups (group_name);

-- Single-use, group-scoped registration tokens.
CREATE TABLE IF NOT EXISTS enrolment_tokens (
    token_hash  BYTEA PRIMARY KEY,
    group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    used_by     UUID REFERENCES agents(agent_id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- tasks

CREATE TABLE IF NOT EXISTS tasks (
    task_id      TEXT PRIMARY KEY,
    -- Shared by the sender task and its matching reflector grant, and used on
    -- the wire as MQP's session_id. Generated from a CSPRNG: it is the
    -- reflector's only admission control.
    session_id   BIGINT NOT NULL,

    kind         TEXT NOT NULL
                 CHECK (kind IN ('mqp_probe', 'twamp_probe', 'tcp_connect',
                                 'routeros_btest', 'path_trace', 'wifi_signal',
                                 'packet_capture')),

    -- Continuous plan work is cached by the agent and keeps running through a
    -- controller outage. One-shots expire instead: a stale diagnostic answers
    -- a question nobody is still asking.
    recurring    BOOLEAN NOT NULL DEFAULT false,
    expires_at   TIMESTAMPTZ,
    role         TEXT NOT NULL CHECK (role IN ('sender', 'reflector')),

    agent_id     UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    peer_id      UUID REFERENCES agents(agent_id) ON DELETE CASCADE,

    params       JSONB NOT NULL DEFAULT '{}'::jsonb,

    state        TEXT NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending', 'leased', 'done', 'expired')),
    leased_at    TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,

    -- Which group this task was scheduled for. Results are filed under it
    -- rather than under the submitting agent's own group: a shared upstream
    -- agent answers for many customers, and attributing its results to itself
    -- would make them vanish from the customer's view entirely.
    group_name   TEXT,

    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    scheduled_for TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The hot query: "what work is waiting for this agent right now".
CREATE INDEX IF NOT EXISTS tasks_pending_idx
    ON tasks (agent_id, scheduled_for)
    WHERE state = 'pending';

-- Sweeping leases that were never reported.
CREATE INDEX IF NOT EXISTS tasks_lease_idx
    ON tasks (lease_expires_at)
    WHERE state = 'leased';

-- Existing deployments predate the columns above; adding them is idempotent.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS group_name TEXT;

-- Every agent belongs to its home group, so seed that membership for any
-- agent registered before this table existed.
INSERT INTO agent_groups (agent_id, group_name)
SELECT agent_id, group_name FROM agents
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------- results

CREATE TABLE IF NOT EXISTS results (
    time          TIMESTAMPTZ NOT NULL,
    task_id       TEXT NOT NULL,
    session_id    BIGINT NOT NULL,

    agent_id      UUID NOT NULL,
    peer_id       UUID,
    group_name    TEXT NOT NULL,
    kind          TEXT NOT NULL,

    status        TEXT NOT NULL CHECK (status IN ('ok','partial','failed','skipped')),
    error         TEXT,

    started_at    TIMESTAMPTZ NOT NULL,
    ended_at      TIMESTAMPTZ NOT NULL,

    -- Latency, microseconds throughout. Milliseconds lose real signal on a LAN
    -- path; nanoseconds overstate the accuracy available through a veth.
    rtt_min_us    BIGINT,
    rtt_avg_us    BIGINT,
    rtt_max_us    BIGINT,
    rtt_stddev_us BIGINT,
    rtt_p50_us    BIGINT,
    rtt_p95_us    BIGINT,
    rtt_p99_us    BIGINT,

    ipdv_avg_us   BIGINT,
    pdv_p95_us    BIGINT,

    sent              INT,
    received          INT,
    forward_lost      INT,
    reverse_lost      INT,
    unknown_direction INT,
    loss_pct          DOUBLE PRECISION,

    reordered         INT,
    max_displacement  INT,
    duplicated        INT,

    dscp_requested    SMALLINT,
    dscp_observed     SMALLINT,
    dscp_conformant_pct DOUBLE PRECISION,

    mos_codec     TEXT,
    r_factor      DOUBLE PRECISION,
    mos           DOUBLE PRECISION,

    -- Populated by routeros_btest. `throughput_source` records whether the
    -- number came from the host router's forwarding path or from inside the
    -- container — they are not comparable.
    tx_bps            BIGINT,
    rx_bps            BIGINT,
    throughput_source TEXT,
    remote_cpu_load   SMALLINT,
    local_cpu_load    SMALLINT,

    -- Anything not worth a column yet (path traces, raw counters).
    extra         JSONB NOT NULL DEFAULT '{}'::jsonb
);

SELECT create_hypertable('results', 'time', if_not_exists => TRUE);

-- Submission is idempotent on task_id: an agent draining a spool after an
-- outage must not double-count. The unique index must include `time` because
-- TimescaleDB requires the partitioning column in every unique constraint.
CREATE UNIQUE INDEX IF NOT EXISTS results_task_unique ON results (task_id, time);

CREATE INDEX IF NOT EXISTS results_agent_time_idx ON results (agent_id, time DESC);
CREATE INDEX IF NOT EXISTS results_group_time_idx ON results (group_name, time DESC);
CREATE INDEX IF NOT EXISTS results_pair_time_idx  ON results (agent_id, peer_id, time DESC);

-- ---------------------------------------------------------------- rollups

-- Dashboards asking for a month of data must not scan raw probe rows.
-- Percentiles are averaged across buckets rather than recomputed, which is an
-- approximation — the raw table remains the source of truth for exact figures.
CREATE MATERIALIZED VIEW IF NOT EXISTS results_5m
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('5 minutes', time) AS bucket,
    agent_id,
    peer_id,
    group_name,
    kind,
    count(*)                        AS samples,
    avg(rtt_avg_us)                 AS rtt_avg_us,
    max(rtt_max_us)                 AS rtt_max_us,
    avg(rtt_p95_us)                 AS rtt_p95_us,
    avg(ipdv_avg_us)                AS ipdv_avg_us,
    avg(loss_pct)                   AS loss_pct,
    avg(mos)                        AS mos,
    avg(dscp_conformant_pct)        AS dscp_conformant_pct,
    sum(CASE WHEN status <> 'ok' THEN 1 ELSE 0 END) AS failures
FROM results
GROUP BY bucket, agent_id, peer_id, group_name, kind
WITH NO DATA;

SELECT add_continuous_aggregate_policy('results_5m',
    start_offset => INTERVAL '1 day',
    end_offset   => INTERVAL '5 minutes',
    schedule_interval => INTERVAL '5 minutes',
    if_not_exists => TRUE);

-- Raw samples age out; the 5-minute rollup is kept far longer. Adjust to taste.
SELECT add_retention_policy('results', INTERVAL '30 days', if_not_exists => TRUE);
