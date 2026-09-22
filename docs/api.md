# Controller REST API

Base path `/api/v1`. All bodies are JSON. All timestamps are RFC 3339 UTC.

Authentication is `Authorization: Bearer <token>`:

- **Enrolment token** — pre-shared, group-scoped, single-use. Only valid on
  `POST /agents/register`.
- **Agent token** — returned by registration, long-lived, used for every other
  agent endpoint.
- **Operator token** — for the management endpoints (`/groups`, `/tests`,
  queries). Separate from agent tokens.

Errors use RFC 7807 `application/problem+json`.

---

## Agent endpoints

### `POST /agents/register`

Called at startup. Idempotent on `name` — re-registering an existing name with a
matching `agent_id` refreshes metadata and returns the same identity, so a
container restart is not a new agent.

```jsonc
// Request
{
  "agent_id": "b2c3…",           // null on very first registration
  "name": "yvr-branch-01",
  "group": "west-wan",
  "version": "0.1.0",
  "capabilities": {
    "mqp": true,
    "twamp_light": true,
    "routeros_btest": true,      // host RouterOS API reachable & authorised
    "probe_port": 5301
  },
  "host": {
    "routeros_version": "7.16.2",
    "board": "RB4011iGS+",
    "arch": "arm"
  }
}

// 200
{
  "agent_id": "b2c3…",
  "token": "…",                  // agent token; store it
  "group": "west-wan",
  "heartbeat_interval_s": 30,
  "poll_interval_s": 10
}
```

### `POST /agents/{agent_id}/heartbeat`

Liveness plus lightweight local state. The controller marks an agent `stale`
after 3 missed intervals and stops scheduling it as a peer.

```jsonc
// Request
{ "uptime_s": 8412, "active_sessions": 2, "last_error": null }

// 200 — the controller can retune polling or ask the agent to re-register
{ "poll_interval_s": 10, "reregister": false }
```

### `GET /agents/{agent_id}/tasks`

Leases pending work. Returns an empty array when idle. Each task is leased for
`lease_expires_at`; if the agent does not report by then the controller may
reassign it.

```jsonc
// 200
[
  {
    "task_id": "t_01J…",
    "session_id": "9166399904847513184",  // u64 as a DECIMAL string
    "kind": "mqp_probe",                 // mqp_probe | twamp_probe | tcp_connect
                                         // | routeros_btest | path_trace
    "role": "sender",                    // sender | reflector
    "peer": {
      "agent_id": "c3d4…",
      "name": "cal-branch-02",
      "address": "203.0.113.24",
      "probe_port": 5301
    },
    "params": {
      "count": 300,
      "interval_ms": 20,
      "payload_bytes": 172,
      "dscp": 46,                        // EF
      "timeout_ms": 1000,
      "codec": "g711"                    // for MOS scoring
    },
    "lease_expires_at": "2026-09-21T18:04:00Z"
  }
]
```

A `reflector` task carries no `params.count` — it simply authorises the given
`session_id` from the given peer until `lease_expires_at`.

### `POST /agents/{agent_id}/results`

Submits one completed task. Accepts a batch so an agent that was offline can
drain its spool.

```jsonc
// Request
{
  "results": [
    {
      "task_id": "t_01J…",
      "session_id": "9166399904847513184",
      "started_at": "2026-09-21T18:00:00Z",
      "ended_at":   "2026-09-21T18:00:06Z",
      "status": "ok",                    // ok | partial | failed | skipped
      "error": null,
      "rtt": {
        "min_us": 8420, "avg_us": 9130, "max_us": 24880,
        "stddev_us": 1840, "p50_us": 8900, "p95_us": 12400, "p99_us": 19800
      },
      "jitter": { "ipdv_avg_us": 640, "pdv_p95_us": 3500 },
      "loss": {
        "sent": 300, "received": 297,
        "forward_lost": 1, "reverse_lost": 2, "unknown_direction": 0,
        "loss_pct": 1.0
      },
      "reorder": { "reordered": 0, "max_displacement": 0, "duplicated": 0 },
      "dscp":    { "requested": 46, "observed_mode": 46, "conformant_pct": 98.7 },
      "mos":     { "codec": "g711", "r_factor": 88.4, "mos": 4.32 },
      "throughput": null,                // populated by routeros_btest
      "path": null                       // populated by path_trace
    }
  ]
}

// 202
{ "accepted": 1, "rejected": [] }
```

`routeros_btest` results populate `throughput`:

```jsonc
"throughput": {
  "protocol": "tcp",
  "direction": "both",
  "tx_bps": 486000000,
  "rx_bps": 471000000,
  "duration_s": 10,
  "source": "routeros_host"    // measured by the router, not the container
}
```

---

## Operator endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/agents` | List agents, filterable by `group`, `state`. |
| `GET`  | `/agents/{id}` | Agent detail incl. last heartbeat and capabilities. |
| `DELETE` | `/agents/{id}` | Deregister; revokes the agent token. |
| `GET`/`POST` | `/groups` | List / create groups. |
| `PUT`  | `/groups/{name}/plan` | Set the mesh plan (`full`, `ring`, `hub`, `partial`) and cadence. |
| `POST` | `/tests` | Schedule a one-off test between named agents. |
| `GET`  | `/results` | Query results. `group`, `agent`, `peer`, `from`, `to`, `kind`, plus `rollup=raw\|1m\|5m\|1h`. |
| `GET`  | `/healthz` · `/readyz` | Liveness and readiness. Unauthenticated. |

## Conventions

- `session_id` is a u64 rendered as a **decimal** string, never hex and never
  a JSON number. A number would be parsed as f64 by most clients and silently
  rounded above 2^53; bare hex is ambiguous because every decimal string is
  also valid hex, so `"255"` would be read as 597 and target a session the
  reflector never granted — surfacing as 100% loss on a healthy path.
- Durations in field names carry their unit (`_ms`, `_us`, `_s`, `_bps`).
  Latency is microseconds throughout — milliseconds lose too much resolution on
  a LAN, nanoseconds overstate the accuracy we actually have.
- The agent retries `results` with exponential backoff and spools to disk
  meanwhile. Submission is idempotent on `task_id`; a duplicate returns `202`
  and is counted in `rejected` with reason `duplicate`.
- Unknown JSON fields are ignored by both sides, so a newer controller can add
  fields without breaking older agents.
