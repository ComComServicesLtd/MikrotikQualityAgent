# Architecture

## Components

```
                         ┌──────────────────────────────┐
                         │  Controller (Go)             │
                         │  ├─ REST API                 │
                         │  ├─ Mesh scheduler           │
                         │  └─ TimescaleDB (results)    │
                         └──────────────┬───────────────┘
                                        │ HTTPS/REST
                                        │ register · lease tasks · submit results
                 ┌──────────────────────┼──────────────────────┐
                 │                      │                      │
        ┌────────┴────────┐    ┌────────┴────────┐    ┌────────┴────────┐
        │ Agent (Rust)    │    │ Agent (Rust)    │    │ Agent (Rust)    │
        │ on MikroTik A   │    │ on MikroTik B   │    │ on MikroTik C   │
        └────────┬────────┘    └────────┬────────┘    └────────┬────────┘
                 │                      │                      │
                 └──────── MQP/UDP probe mesh (agent-to-agent) ─┘
                 └──────── RouterOS API → /tool bandwidth-test ─┘
                                (to the host router it runs on)
```

- **Agent** — Rust, static musl binary in a `scratch` image. Runs as a RouterOS
  container on each MikroTik. Acts as both probe **sender** and **reflector**.
- **Controller** — Go + TimescaleDB. Owns agent inventory, group membership,
  test scheduling, and result storage. Single static binary in Docker.
- **MQP** — the UDP probe protocol, specified in [`protocol.md`](protocol.md).

## Why these choices

**Rust + static musl + scratch** — the binding constraint is the deployment
target: armv7 MikroTik devices with 256 MB RAM and, on several models, very
little free flash. A `scratch` image containing one statically linked binary
lands in single-digit megabytes with no libc, no shell, and no package manager
to keep patched. It also gives predictable latency: no GC pause lands in the
middle of a timestamp.

**Go for the controller** — it is not latency-critical, so the agent's
constraints do not apply. What matters is sustained ingest from many agents and
easy operation, which Go handles with a single static binary and good
concurrency primitives.

**TimescaleDB** — probe results are append-heavy time-series with a natural
retention policy. Hypertables plus continuous aggregates give rollups without a
second system. It is a Postgres extension, so relational data (agents, groups,
tasks) lives in the same database with real foreign keys.

**Pull, not push** — agents poll the controller for work rather than the
controller connecting inward. MikroTik devices sit behind NAT at customer sites;
requiring inbound reachability to the *controller* would be a non-starter.
Agents still need inbound UDP reachability *from each other* for the mesh, which
is a deliberate and much smaller requirement.

## Agent internals

```
main
├── config          load TOML + env overrides, resolve identity
├── controller      REST client: register, heartbeat, lease tasks, submit results
├── probe
│   ├── sender      paces packets, records per-packet samples
│   ├── reflector   single UDP socket, serves all inbound sessions
│   ├── mqp         MQP wire codec (docs/protocol.md)
│   └── twamp       TWAMP-Light codec (RFC 5357 unauthenticated)
├── collector       sample set → RTT/jitter/loss/reorder/DSCP/MOS
├── routeros        API client to the *host* router (bandwidth-test offload)
└── tasks           executor: dispatch a leased task to the right runner
```

### Identity

Each agent has:

- **`agent_id`** — UUID, assigned by the controller at first registration and
  persisted to disk. Survives container restarts and re-images.
- **`name`** — human-chosen, unique, e.g. `yvr-branch-01`.
- **`group`** — the mesh unit. Agents in the same group are scheduled to probe
  each other. An agent belongs to exactly one group.

Registration is bootstrapped with a pre-shared enrolment token; the controller
returns a long-lived agent token used for all subsequent calls.

### Bandwidth testing via the host router

Running a throughput test *inside* the container would measure the container's
veth and the router's CPU, not the path. Instead the agent calls the RouterOS
API on the router hosting it and drives `/tool bandwidth-test` against the peer
agent's host router, which exercises the router's own forwarding path. The agent
supplies credentials from config, starts the test, reads results, and reports
them upstream like any other metric.

This is the one place the agent depends on its host. It is optional per task,
and a task requiring it is skipped with a clear reason if RouterOS credentials
are absent.

### MOS / R-factor

The ITU-T G.107 E-model, using the common simplified form:

```
R = R0 - Is - Id - Ie_eff + A
```

With default assumptions for a modern codec path, the agent reduces this to the
delay impairment `Id` (from RTT and jitter, via an effective one-way delay of
`RTT/2 + 2·jitter`) and the equipment impairment `Ie_eff` (from the codec's
packet-loss robustness factor and measured loss). MOS is then mapped from R by
the standard piecewise formula. The codec assumption is a task parameter and is
recorded alongside the score — a MOS without its codec is meaningless.

## Controller internals

```
cmd/controller       entrypoint, config, graceful shutdown
internal/api         HTTP handlers, auth middleware, OpenAPI
internal/model       shared domain types (Agent, Group, Task, Result)
internal/scheduler   mesh planning: which pairs test what, how often
internal/store       TimescaleDB access, migrations
```

### Mesh scheduling

For a group of *n* agents a full mesh is *n·(n-1)* ordered pairs, which grows
quadratically and will saturate small routers. The scheduler therefore supports:

- **full** — every ordered pair. Fine for small groups.
- **ring** — each agent probes the next; *n* pairs, constant cost per agent.
- **hub** — designated hub agents probe all others; for hub-and-spoke WANs.
- **partial(k)** — each agent probes *k* peers, rotating over time so the whole
  mesh is covered across a window without any agent exceeding *k* concurrent
  sessions.

The scheduler also staggers start times within an interval so a group does not
synchronise into a thundering herd — which would itself distort the measurement.

## Security posture

- Agent→controller is HTTPS with a bearer token per agent.
- Enrolment tokens are single-use and scoped to a group.
- MQP has no authentication; its admission control is the unguessable
  `session_id` issued by the controller. This is adequate for a probe protocol
  carrying no secrets, but it means **an attacker who can reach the UDP port and
  guess a session ID can inject samples**. Reflector ports should be firewalled
  to known peer addresses; the deployment guide covers the required rules.
- The agent holds RouterOS credentials for its host. These should belong to a
  dedicated user restricted to the `test` policy, not `admin`.

## Deployment shape during development

The controller and TimescaleDB run in Docker on the developer workstation. Agents
run as real containers on real MikroTik hardware, reaching the workstation over
the LAN. This keeps the agent side honest — armv7 performance and RouterOS
container quirks show up immediately rather than at the end.

See [`deployment-mikrotik.md`](deployment-mikrotik.md).
