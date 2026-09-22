# MikroTik Quality Agent

A distributed network quality measurement system. Rust agents run as RouterOS
containers on MikroTik routers, probe each other in a mesh, and report latency,
jitter, loss, reordering, DSCP conformance, voice MOS and throughput to a
central Go controller.

## What it measures

| Metric | How |
|---|---|
| **RTT** min/avg/max/stddev, p50/p95/p99 | UDP probes, reflector processing time subtracted out |
| **Jitter** | IPDV (RFC 3393) and PDV — both, because monitoring systems disagree on which "jitter" means |
| **Loss**, split forward vs reverse | The reflector's own counter reveals which direction dropped the packet |
| **Reordering** and duplication | RFC 4737, with displacement |
| **DSCP conformance** | The reflector reports the DSCP it actually received, exposing remarking and bleaching along the path |
| **MOS / R-factor** | ITU-T G.107 E-model, per codec |
| **Throughput** | Offloaded to the host router's `/tool/bandwidth-test`, so it measures the router's forwarding path rather than the container's veth |

One-way delay is deliberately **not** reported in v1 — it needs clock
synchronisation whose error would exceed the jitter we are trying to measure.
See [`docs/protocol.md`](docs/protocol.md).

## Layout

```
agent/      Rust agent — static musl binary in a scratch image
server/     Go controller + TimescaleDB
docs/       Architecture, wire protocol, REST API, deployment
deploy/     docker-compose for local dev, MikroTik helper scripts
```

## Documentation

- [Architecture](docs/architecture.md) — components, decisions, and why
- [Wire protocol](docs/protocol.md) — the MQP packet format
- [REST API](docs/api.md) — the agent ↔ controller contract
- [MikroTik deployment](docs/deployment-mikrotik.md) — the part with the sharp edges

## Quick start

### Controller (local dev)

```bash
make server-up
```

Brings up the controller and TimescaleDB on `localhost:8080`.

### Agent

Build the image for your router's architecture:

```bash
make agent-image-armv7
```

Then follow [the deployment guide](docs/deployment-mikrotik.md). Two things
catch everyone out:

1. RouterOS needs **both** `container=yes` and `bandwidth-test=yes` in
   device-mode. Devices shipping with 7.17+ default to `home` mode, where
   bandwidth-test is disabled.
2. The image must be a `docker save` archive built with
   `--output=type=docker`. `docker export` output will not import.

### Measuring a path without a controller

The agent's managed mode only answers sessions a controller has granted. To
exercise a real path before the control plane exists, both halves can run
standalone with a shared session ID.

On the far end:

```bash
mqagent reflect --session cafe --port 5301
```

From the near end:

```bash
mqagent probe --peer 172.16.220.138 --session cafe --count 300 --dscp 46
```

```
RTT       min 0.041 ms  avg 0.120 ms  max 1.058 ms  stddev 0.136 ms
          p50 0.086 ms  p95 0.226 ms  p99 1.058 ms
Jitter    IPDV avg 0.060 ms  PDV p95 0.140 ms
Loss      0/60 lost (0.00%)
Order     0 reordered (max displacement 0)  0 duplicated
DSCP      requested 46  observed 46  conformant 100.0%
Voice     MOS 4.41  R-factor 93.2  (G711, 60 ms effective delay)
```

`--json` emits the same data as machine-readable output. The process exits
non-zero when nothing came back, so it drops into a monitoring script.

### Tests

```bash
make test
```

The agent's tests run a real reflector and sender over loopback, including DSCP
echo through actual `recvmsg` control messages — no mocking of the data plane.

## Status

| Component | State |
|---|---|
| MQP wire protocol | Implemented, tested |
| Probe sender / reflector | Implemented, tested |
| Statistics (RTT, jitter, loss, reorder, DSCP) | Implemented, tested |
| MOS / R-factor | Implemented, tested |
| Agent config | Implemented, tested |
| armv7 / arm64 container image | Implemented — 880 KB static binary, 488 KB tar |
| Controller: schema, agent endpoints, auth | Implemented |
| Controller: mesh scheduler | Not yet — no tasks are generated, so agents lease nothing |
| Agent controller client | Not yet — agent runs reflector-only |
| RouterOS bandwidth-test offload | Not yet |
| TWAMP-Light interop | Not yet |

The two gaps that matter for an end-to-end run are the **mesh scheduler** (the
controller stores and hands out tasks, but nothing creates them yet) and the
**agent's controller client** (the agent reflects for peers but does not
register or poll). Until both land, the agent is usable only as a reflector
driven by a sender you invoke directly.
