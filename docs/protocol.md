# MQP — Mikrotik Quality Probe wire protocol

Version 1. All multi-byte fields are **big-endian** (network byte order).

MQP is the custom UDP probe format used for agent-to-agent measurement. It is
deliberately small and fixed-layout so the hot path needs no allocation and no
parsing beyond fixed-offset reads — important on armv7 where we have little CPU
to spare.

Agents can alternatively speak TWAMP-Light (RFC 5357 unauthenticated mode) for
interop with third-party responders; see [TWAMP-Light mode](#twamp-light-mode).

---

## 1. Packet layout

Every MQP packet — request and reply — uses the same 56-byte header, followed by
optional padding. Using one layout in both directions means the reflector can
mutate the buffer in place and send it straight back.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------+-------+-------+-------+-------+-------+-------+-------+
|    magic 0x4D51       | ver   | type  |     flags     | resv  |   0
+-------+-------+-------+-------+-------+-------+-------+-------+
|                        session_id (u64)                       |   8
+-------+-------+-------+-------+-------+-------+-------+-------+
|          seq (u32)            |      reflector_seq (u32)      |  16
+-------+-------+-------+-------+-------+-------+-------+-------+
|                    t1 — sender TX (u64 ns)                    |  24
+-------+-------+-------+-------+-------+-------+-------+-------+
|                 t2 — reflector RX (u64 ns)                    |  32
+-------+-------+-------+-------+-------+-------+-------+-------+
|                 t3 — reflector TX (u64 ns)                    |  40
+-------+-------+-------+-------+-------+-------+-------+-------+
|tx_dscp|rx_dscp|ttl_fwd|ttl_rev|  payload_len  |    crc16      |  48
+-------+-------+-------+-------+-------+-------+-------+-------+
|                      padding (payload_len bytes)              |  56
```

| Offset | Size | Field           | Meaning |
|-------:|-----:|-----------------|---------|
| 0      | 2    | `magic`         | Always `0x4D51` (ASCII `MQ`). Cheap rejection of stray traffic. |
| 2      | 1    | `ver`           | Protocol version. Currently `1`. |
| 3      | 1    | `type`          | `1` = Request (sender→reflector), `2` = Reply (reflector→sender). |
| 4      | 2    | `flags`         | See [flags](#flags). |
| 6      | 2    | `reserved`      | Must be zero on send; ignored on receive. |
| 8      | 8    | `session_id`    | Opaque session identifier, assigned by the controller per test. |
| 16     | 4    | `seq`           | Sender's sequence number, starts at 0, increments per packet. |
| 20     | 4    | `reflector_seq` | Reflector's own counter for this session. Lets the sender tell reverse-path loss from forward-path loss. Zero in a Request. |
| 24     | 8    | `t1`            | Sender's TX timestamp, nanoseconds. |
| 32     | 8    | `t2`            | Reflector's RX timestamp, ns. Zero in a Request. |
| 40     | 8    | `t3`            | Reflector's TX timestamp, ns. Zero in a Request. |
| 48     | 1    | `tx_dscp`       | DSCP the sender *asked for* (6-bit value in the low bits). |
| 49     | 1    | `rx_dscp`       | DSCP the reflector actually *observed* on arrival. Zero in a Request. |
| 50     | 1    | `ttl_fwd`       | IP TTL observed by the reflector. Zero in a Request. |
| 51     | 1    | `ttl_rev`       | IP TTL the reflector set on the reply. |
| 52     | 2    | `payload_len`   | Bytes of padding following the header. |
| 54     | 2    | `crc16`         | CRC-16/CCITT-FALSE over bytes 0..54 with this field taken as zero. |

Minimum packet: **56 bytes**. Default padded size is **172 bytes**, matching a
20 ms G.711 voice frame over RTP/UDP/IP — so the default probe stresses the path
the same way the traffic we care about does.

### Flags

| Bit | Name              | Meaning |
|----:|-------------------|---------|
| 0   | `ECHO_PAYLOAD`    | Reflector must return padding unchanged (detects payload corruption). |
| 1   | `LAST_PACKET`     | Final packet of the session; reflector may retire state after reply. |
| 2   | `NO_REFLECT`      | One-way test: reflector records but does not reply. |
| 3   | `REQUEST_DSCP_ECHO` | Reflector should populate `rx_dscp`. |
| 4–15| reserved          | Must be zero. |

---

## 2. Timestamps and why v1 is RTT-only

Timestamps are `u64` nanoseconds. **They are not comparable across hosts.** Each
agent stamps from its own `CLOCK_MONOTONIC`-derived source, which has an
arbitrary origin.

This is deliberate. Round-trip time is computed as:

```
RTT = (t4 - t1) - (t3 - t2)
```

where `t4` is the sender's RX timestamp (never transmitted — it stays local).
Both `(t4 - t1)` and `(t3 - t2)` are *deltas measured on a single clock*, so the
result is correct with **no clock synchronisation between agents at all**. The
`(t3 - t2)` subtraction removes the reflector's own processing and scheduling
delay, which on a loaded armv7 router can easily be several milliseconds and
would otherwise be misread as network latency.

One-way delay is intentionally **not** reported in v1. Deriving it needs either
synchronised clocks or an offset estimate whose error would frequently exceed
the sub-millisecond jitter we are trying to measure. The header reserves the
fields to add it later without a version bump.

---

## 3. Derived metrics

Computed by the agent from the per-packet record set, then submitted to the
controller. Definitions follow the relevant RFCs so results are comparable with
other tooling.

| Metric | Definition |
|---|---|
| **RTT** min/avg/max/stddev, p50/p95/p99 | From the formula above, over all replied packets. |
| **Jitter** | IPDV per **RFC 3393**: the difference in RTT between *consecutive* packets, reported as mean absolute value. Also reported as PDV (variation from the p50) since monitoring systems differ on which they expect. |
| **Loss** | Forward loss and reverse loss separated using `reflector_seq`: a gap in `seq` seen by the reflector is forward loss; a gap in `reflector_seq` seen by the sender is reverse loss. A plain "no reply" is ambiguous and is counted separately as `unknown_direction`. |
| **Reordering** | Per **RFC 4737** — a packet is reordered if its `seq` is lower than the highest `seq` already received. Reported as a ratio plus max displacement. |
| **Duplication** | Count of `seq` values received more than once. |
| **DSCP conformance** | `tx_dscp` vs `rx_dscp` per packet. A mismatch means something on the path remarked or bleached the traffic — the single most useful signal for verifying QoS actually survives end to end. |
| **MOS / R-factor** | ITU-T **G.107** E-model, computed from avg RTT, jitter and loss. See [`docs/architecture.md`](architecture.md). |

---

## 4. Session lifecycle

MQP has no handshake. The controller is the coordinator, which keeps the data
plane stateless and cheap.

1. Controller issues a task to sender A and a matching reflector grant to agent
   B, both carrying the same `session_id`.
2. B's reflector accepts packets bearing that `session_id`. Unknown session IDs
   are dropped silently — this is the only admission control on the UDP port, so
   `session_id` must be unguessable (the controller generates it from a CSPRNG).
3. A sends `count` packets at `interval`, then a final packet with `LAST_PACKET`.
4. A waits `linger` (default 2 s) for stragglers, computes statistics, POSTs the
   result to the controller.
5. B retires session state after `LAST_PACKET` + linger, or on idle timeout.

Because state is per-session and small, a reflector can serve many concurrent
sessions. The reflector never initiates anything.

---

## 5. TWAMP-Light mode

When a task specifies `protocol: twamp-light`, the agent speaks RFC 5357
unauthenticated mode instead. This exists for interop: carriers and transit
providers run responders, and test sets expect one.

**RouterOS has no TWAMP of its own.** There is no `/tool/twamp` menu on
RouterOS 7.x and no package supplies one — verified on 7.24.2. So where a
MikroTik needs to answer TWAMP, this agent is what answers, and
`mqagent twamp-reflect` is how.

| | Sender packet | Reflector packet |
|---|---|---|
| Minimum size | 14 bytes | 41 bytes |
| Contents | seq, timestamp, error estimate | own seq + T3 + error, T2, sender's seq/T1/error, sender TTL |

Both directions default to 41 bytes so neither is policed differently for its
size.

### Timestamps

TWAMP uses **NTP 64-bit** format — seconds since 1900 plus a binary fraction —
not the nanosecond counter MQP carries. The values are nevertheless derived
from a *monotonic* source and converted at the boundary. Reading the system
clock per packet would let an NTP step land mid-measurement and produce a
large, plausible, wrong RTT.

RTT is `(T4−T1) − (T3−T2)`, so as with MQP each bracket stays within one host's
clock and **no synchronisation is required**. One-way delay would need it, and
the agent does not claim it: the error estimate goes out with its synchronised
bit clear, because an agent runs on a customer router whose NTP state we
neither control nor verify.

### What TWAMP-Light cannot do

- **No session identifier.** MQP's admission control is an unguessable
  `session_id`; Light mode has nothing equivalent, so the only filter available
  is the source address. An open responder answers anyone who finds the port.
  Replies are the same size as requests, so there is no amplification factor,
  but keep the allow-list narrow and the firewall narrower.
- **No DSCP echo.** There is no field for the class a packet arrived in, so
  QoS conformance is unavailable — reported as missing rather than as zero.
  Closing that gap is why MQP exists.
- **No forward/reverse loss split beyond the reflector counter**, and that
  counter is per-responder rather than per-session, since there are no
  sessions.

MQP therefore remains the default between our own agents. TWAMP-Light is for
everything that is not one.

## 6. Version negotiation

There is none, by design. The controller knows each agent's protocol version
from registration and only schedules a session between two agents that share
one. An agent receiving a packet whose `ver` it does not implement drops it and
increments a counter, rather than guessing at the layout.
