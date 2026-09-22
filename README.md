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

### Controller and dashboard (local dev)

```bash
MQ_OPERATOR_TOKEN=some-secret make server-up
```

Brings up the controller and TimescaleDB, serves the API on `localhost:8080`
and the dashboard at the same address. Set `MQ_PORT` if 8080 is taken.

The dashboard is a single self-contained HTML file embedded in the controller
binary — no build step, no CDN, no separate deployment. It also runs standalone:
copy `server/internal/api/ui/index.html` anywhere, open it, and point it at a
controller under **Controller…**. The API sends permissive CORS headers for
exactly this, which is safe because every endpoint authenticates with a bearer
token and none uses cookies.

Enrol an agent without touching the database:

```bash
curl -X POST localhost:8080/api/v1/groups -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"name":"west-wan","mesh_plan":"full","interval_s":60}'

curl -X POST localhost:8080/api/v1/groups/west-wan/enrolment-tokens \
     -H "Authorization: Bearer $TOKEN"
```

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

### TWAMP-Light

RouterOS provides no TWAMP responder, so the agent supplies one:

```bash
mqagent twamp-reflect --port 862 --peer 203.0.113.7
mqagent twamp-probe   --peer 203.0.113.7
```

Useful for measuring toward carriers and transit providers that run a responder
but will never host an agent. Note that TWAMP-Light has **no session
identifier** — the source allow-list is the only admission control, so firewall
the port. It also carries no DSCP echo, so QoS conformance is unavailable over
TWAMP; that gap is why MQP exists.

### Throughput and capture

Throughput runs on the router's own forwarding hardware, not in the container:

```bash
mqagent btest --host 172.16.220.1 --user claude \
    --target 10.0.0.2 --direction rx --protocol tcp --duration 10
```

Every result carries a CPU verdict. On small MikroTik hardware the router is
very often the limit rather than the link, and 621 Mbit/s at 64% CPU means
something quite different from the same figure at 8%.

Capture names the host behind a problem, which interface counters cannot:

```bash
mqagent capture --host 172.16.220.1 --user claude --duration 15
mqagent capture --host 172.16.220.1 --user claude --wireless --duration 10
```

`--wireless` drives `/interface/wireless/sniffer` for 802.11 frames — beacons,
acks, probe requests, CRC failures, and the rate each frame was sent at. That
layer is invisible to a packet capture. It exists only on the legacy `wireless`
stack; on ax-generation boards the command degrades to a packet capture and
says so.

### Network discovery

The agent can survey a RouterOS device and explain what is wrong with the local
network, rather than just inventorying it:

```bash
mqagent discover --host 172.16.220.1 --user claude
```

It reads ARP, DHCP leases, wireless registrations, radios and interface
counters, then reduces them to ranked findings — slow clients eating shared
airtime, coverage gaps, co-channel contention, broadcast storms, duplicate
addresses, DHCP pool pressure. `--json` for machine consumption.

Both RouterOS wireless stacks are handled: the hAP ac³ answers on legacy
`/interface/wireless`, the hAP ax³ returns 400 for it and answers on
`/interface/wifi`. One build covers a mixed fleet.

Two active diagnostics run from the router as well:

```bash
mqagent trace --host 172.16.220.1 --user claude --target 1.1.1.1
mqagent scan  --host 172.16.220.1 --user claude --range 192.168.88.0/24
```

`trace` reports **where** the path degrades rather than listing hops. It
deliberately ignores loss and latency at an intermediate hop that does not
persist to the destination — that is a router rate-limiting ICMP to its own
control plane while forwarding perfectly, and it is the single most misread
thing in a traceroute. It also surfaces routing loops and carrier-grade NAT,
which explains why port forwarding cannot work no matter how it is configured.

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
| Controller: mesh scheduler | Implemented, tested (full/ring/hub/partial, NAT-aware) |
| Agent controller client + cached plan | Implemented, verified end to end |
| Offline result spool | Implemented, tested |
| Network discovery (wifi, ARP, DHCP, storms) | Implemented, verified against a live router |
| RouterOS bandwidth-test offload | Implemented — tcp/udp, rx/tx/both, with a CPU verdict |
| Discovery: traceroute + ip-scan | Implemented, verified against a live router |
| Discovery: packet + 802.11 capture | Implemented — names the host, not just the interface |
| Operator API (groups, tokens, agents, membership, queries) | Implemented, tested |
| One-shot tests (`POST /tests`) + agent executors | Implemented, verified end to end |
| Many-to-many group membership with roles | Implemented, verified with a shared upstream agent |
| Dashboard (embedded + standalone) | Implemented, verified with live data |
| TWAMP-Light (responder + sender) | Implemented, verified on armv7 and arm64 hardware |
| Combined MQP + TWAMP reflector | Implemented — one container answers both, on separate ports |

The measurement loop is complete: the scheduler plans a group's mesh, agents
lease paired sender/reflector tasks, run them, and results land in TimescaleDB.
Verified end to end with two agents against a live controller.

Groups, enrolment tokens and agent settings are all managed over the API now;
`psql` is no longer needed to run the system.
