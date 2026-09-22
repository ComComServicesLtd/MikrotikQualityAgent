# Deploying the agent on MikroTik RouterOS

Target: **ARM 32-bit (armv7), 256 MB RAM** — hAP ac³, RB4011 and similar.
RouterOS 7.x. Current stable at time of writing is the 7.24 branch.

> RouterOS 7.24.x was current when this was written. Commands are stable across
> 7.x, but check `/system/device-mode/print` output against your build.

---

## 0. Before you start — the two things that bite

**1. You need `bandwidth-test` enabled in device-mode, not just `container`.**
They are independent flags. Devices shipping with RouterOS 7.17+ come in
`home` device-mode, where `bandwidth-test` is **disabled**. Enable both in one
update so you only need a single physical button press.

**2. Import a `docker save` tar — not `docker export`.** RouterOS expects an OCI
archive with `manifest.json` and layers. `docker export` produces a flattened
rootfs with no manifest and will not import. The build must also use
`--output=type=docker`; BuildKit's default OCI layout has failed to import.

---

## 1. Enable the container feature

The `container` package is not in the base bundle.

```
# System > Packages > Check For Updates > tick "container" > Apply Changes
# (RouterOS 7.18+ can fetch extra packages directly from the router)
```

Or download the ARM "Extra packages" archive matching your exact RouterOS
version from <https://mikrotik.com/download?architecture=arm>, upload
`container-<version>-arm.npk`, and reboot.

Then enable both device-mode flags:

```bash
/system/device-mode/update container=yes bandwidth-test=yes
```

RouterOS prints:

```
update: please activate by turning power off or pressing reset or mode button in 5m00s
```

Within that window, **press the reset/mode button** or cold power-cycle. The
router reboots itself once confirmed. Update attempts are limited to three
before a power cycle is needed just to reset the counter.

Verify:

```bash
/system/device-mode/print
```

Both `container: yes` and `bandwidth-test: yes` must appear.

> If `flagged: yes` shows up, RouterOS detected suspicious configuration at boot
> and will block creating new containers until you clear it with
> `/system/device-mode/update flagged=no` — which needs another button press.

---

## 2. Storage

On 128 MB NAND (hAP ac³) or 16 MB flash (hAP ac²), **use a USB disk**. The
agent image is small, but RouterOS needs headroom and NAND write endurance is
poor. On a 16 MB board external storage is mandatory.

```bash
/disk/format-drive usb1 file-system=ext4 label=cstore
/disk/print detail
```

ext4 — not FAT32/exFAT, which lack POSIX permissions and symlinks.

Point the layer-extraction scratch directory at the disk too. Leaving `tmpdir`
unset makes RouterOS extract to internal storage, which is the documented cause
of "no space to extract layer" failures:

```bash
/container/config/set tmpdir=usb1/pull-tmp
```

---

## 3. Networking

The container gets a veth pair. `address=` and `gateway=` describe the
**container's** side.

```bash
/interface/veth/add name=veth-mq address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=containers
/ip/address/add address=172.17.0.1/24 interface=containers
/interface/bridge/port/add bridge=containers interface=veth-mq
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24
```

**`172.17.0.1` is the RouterOS host** as seen from inside the container. There
is no `host.docker.internal` equivalent — the host is simply the container's
default gateway.

### Let peers reach the reflector

The mesh needs inbound UDP to the agent's probe port. Forward it and restrict
the source to your known peers — MQP's only admission control is the session ID
the controller issues, so do not leave this open to the internet:

```bash
/ip/firewall/nat/add chain=dstnat action=dst-nat protocol=udp dst-port=5301 \
    to-addresses=172.17.0.2 to-ports=5301 comment="MQP probe reflector"

/ip/firewall/address-list/add list=mq-peers address=203.0.113.24 comment="cal-branch-02"
/ip/firewall/filter/add chain=forward action=accept protocol=udp dst-port=5301 \
    src-address-list=mq-peers place-before=0 comment="MQP from known peers"
```

### Let the container reach the router's API

The default firewall contains `drop all not coming from LAN` on the `input`
chain, and a new `containers` bridge is **not** in the `LAN` interface list — so
container-to-router traffic is dropped by default. This is the single most
common cause of "the agent cannot reach RouterOS".

Add a narrow accept rule rather than adding the bridge to `LAN`:

```bash
/ip/firewall/filter/add chain=input action=accept protocol=tcp \
    in-interface=containers src-address=172.17.0.2 dst-address=172.17.0.1 \
    dst-port=8728,8729 comment="mqagent -> RouterOS API" \
    place-before=[find comment~"drop all not coming from LAN"]
```

---

## 4. RouterOS API user for bandwidth-test

The agent drives `/tool/bandwidth-test` on the host router so throughput is
measured by the router's forwarding path, not through the container's veth.

Use the **binary API (8728/8729)**, which the agent defaults to.
`bandwidth-test` is a continuous-output command: the binary API streams results
and supports cancel-by-tag, whereas REST cannot stream and terminates any
command at 60 seconds.

```bash
/ip/service/set api disabled=no port=8728 address=172.17.0.2/32

/user/group/add name=mqagent policy=read,test,api
/user/add name=mqagent group=mqagent password=<strong-secret> \
    address=172.17.0.2/32 comment="quality agent container"
```

- **`test`** policy is what permits ping, traceroute and bandwidth-test.
- **`api`** and **`rest-api`** are *separate* policies. The agent uses `api`.
- Do **not** use `admin`. The `address=` restriction means this account can only
  authenticate from the container's veth address.

Plaintext on 8728 is defensible only because the traffic never leaves the
device. For 8729 you need a certificate on the service and TLS enabled in the
agent config (`MQ_ROUTEROS_TLS=yes`).

### On the far-end router

Each peer's router needs a bandwidth server and a matching user, and its own
`device-mode` must allow bandwidth-test:

```bash
/system/device-mode/update bandwidth-test=yes
/tool/bandwidth-server/set enabled=yes authenticate=yes max-sessions=10
/user/group/add name=btserver policy=read,test
/user/add name=bt group=btserver password=<secret>
```

The far end must be reachable on TCP 2000 (control) plus the allocated UDP port
range (from 2000 by default).

> On a 4-core 448–896 MHz IPQ-4019, the router's CPU will often be the
> bottleneck rather than the link. The agent records `local-cpu-load` with every
> throughput result — if it is near 100, you measured the CPU, not the path.

---

## 5. Build and load the image

On your workstation:

```bash
make agent-image-armv7
```

Which is:

```bash
docker buildx build --platform linux/arm/v7 --output=type=docker \
    -t mqagent:armv7 agent/
docker save mqagent:armv7 -o dist/mqagent-armv7.tar
```

`--output=type=docker` is load-bearing — it produces a classic Docker archive.
BuildKit's default OCI output has failed to import into RouterOS.

Copy to the router's USB disk:

```bash
scp dist/mqagent-armv7.tar admin@192.168.88.1:usb1/
```

---

## 6. Create and start the container

```bash
/container/envs/add list=mqenv key=MQ_CONTROLLER_URL value="http://192.168.88.10:8080"
/container/envs/add list=mqenv key=MQ_AGENT_NAME     value="yvr-branch-01"
/container/envs/add list=mqenv key=MQ_AGENT_GROUP    value="west-wan"
/container/envs/add list=mqenv key=MQ_ENROLMENT_TOKEN value="<enrolment-token>"
/container/envs/add list=mqenv key=MQ_PROBE_PORT     value="5301"
/container/envs/add list=mqenv key=MQ_ROUTEROS_HOST  value="172.17.0.1"
/container/envs/add list=mqenv key=MQ_ROUTEROS_USER  value="mqagent"
/container/envs/add list=mqenv key=MQ_ROUTEROS_PASS  value="<strong-secret>"
/container/envs/add list=mqenv key=MQ_LOG            value="info"

/container/mounts/add name=mqstate src=usb1/data/mqagent dst=/var/lib/mqagent

/container/add file=usb1/mqagent-armv7.tar name=mqagent \
    interface=veth-mq root-dir=usb1/containers/mqagent \
    envlist=mqenv mountlists=mqstate dns=172.17.0.1 \
    logging=yes start-on-boot=yes restart-policy=on-failure

/container/start mqagent
/container/print detail
/log/print where topics~"container"
```

The `mqstate` mount matters: the agent persists its controller-assigned ID and
token there, so a container restart re-registers as the *same* agent rather than
appearing as a new one.

`start-on-boot=yes` is off by default — set it or the agent will not come back
after a reboot. `logging=yes` is also off by default, which makes a
crash-looping container completely silent.

---

## 7. Memory limits — an important caveat

**Do not set `memory-high`.** On hAP ac³ (and RB5009, RB450Gx4), containers
with `memory-high` set come back after a reboot shell-accessible but with their
networking broken — services unreachable, DNS dead. Community-reported and
resolved by clearing the setting; not documented by MikroTik.

Use `memory-max` alone if you need a cap:

```bash
/container/set mqagent memory-max=67108864     # 64 MB hard cap
```

On 256 MB total, with RouterOS itself using roughly 80–130 MB, budget no more
than ~60–80 MB for the container. The agent's steady-state footprint is a few
megabytes; the cap is a backstop, not a target.

Optionally pin the container away from cores handling forwarding:

```bash
/container/set mqagent cpu-list=2,3
```

---

## 8. Verifying

```bash
/container/print detail                        # status should be "running"
/log/print where topics~"container"            # agent's own log lines
/ping 172.17.0.2                               # container reachable from router
```

From another host on the LAN, confirm the probe port is answering — the
reflector stays silent for sessions it has not been granted, so the useful
signal is the agent's log, not a reply.

To verify the API path independently of the agent:

```bash
/tool/bandwidth-test address=<peer-router> duration=5s direction=both \
    protocol=tcp user=bt password=<secret>
```

If that fails from the CLI, it will fail from the agent too — fix it here first.

---

## 9. ARM64 devices

For RB5009, CCR2004, cAP ax and other ARM64 boards, everything above applies
except the build target:

```bash
make agent-image-arm64
```

Check with `/system/resource/print` — `architecture-name` reads `arm` for
32-bit and `arm64` for 64-bit. Loading the wrong architecture gives a container
that starts and immediately dies with no useful message.

> MIPS-based boards (hEX, hAP lite, older RB9xx/RB7xx) have **no container
> package at all** — only arm, arm64 and x86 are supported.

---

## Lessons from a real deployment

Verified on hAP ac³ / RouterOS 7.24.2. Each of these cost real debugging time.

### `docker save` alone is not enough on Docker 28+

Docker's containerd image store emits the **OCI layout** — `blobs/sha256/<digest>`
with gzipped layers — even for `docker save` and
`buildx --output=type=docker`. RouterOS only understands the **legacy** layout,
`<layer-id>/layer.tar`, uncompressed. Importing an OCI archive fails with:

```
download/extract error: could not load next layer
```

which names neither the cause nor the fix. `make agent-image-armv7` now runs
[`deploy/mikrotik/oci-to-docker-archive.py`](../deploy/mikrotik/oci-to-docker-archive.py)
and emits a `-ros.tar` — **import that one.** The script verifies each
decompressed layer against the config's `diff_id`, so a silent corruption
becomes a build failure rather than a container that will not start.

### RouterOS does not pass `cmd` into the container's argv

A container created with `cmd="reflect --session cafe"` logs

```
*** started /mqagent reflect --session cafe --port 5301
```

and then starts the binary with an **empty argv**. The agent therefore selects
its mode from `MQ_MODE` as well as from the command line — envlists are the
mechanism RouterOS actually delivers.

### The REST property is `envlists`, not `envlist`

The CLI spells it `envlist=`; REST rejects that with
`unknown parameter envlist`. Also, `root-dir` wants a leading slash.

### dst-nat rule order decides everything

Rules are evaluated top to bottom and **the first match wins**. A new rule for a
port some earlier rule already claims will sit at the bottom matching nothing:

```
*3 dst-nat udp dport=5301 -> 172.30.1.2:5301   "lab: testhost w24"   pkts=11
*8 dst-nat udp dport=5301 -> 172.30.2.2:5301   "ours"                pkts=0
```

Check with `/ip/firewall/nat/print stats` before assuming the container is at
fault — a reflector that is running perfectly looks identical to a dead one when
its traffic is being redirected somewhere else. Pick a free port rather than
reordering someone else's rules.

### Agents behind NAT must be senders, not reflectors

A NAT'd agent can complete a full measurement because the reflector's reply
rides the same UDP flow and conntrack carries it home. It cannot be *probed*
without an inbound forward. The scheduler must therefore always cast a NAT'd
agent as the sender. Measured across such a boundary:

```
Loss  5/300 lost (1.67%)  [forward 0 · reverse 5]
```

All five losses were on the return path — the expected signature of UDP
conntrack eviction, and the directional split is what makes it legible.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Container starts then immediately exits | Wrong architecture image, or a required env var missing. Check `/log/print` — the agent prints which variable it needs and exits 2. |
| `no space to extract layer` | `/container/config tmpdir` not set to external storage. |
| Agent logs "RouterOS API not configured" | `MQ_ROUTEROS_HOST`/`USER`/`PASS` not all set. Throughput tasks are skipped, probes still run. |
| Agent cannot reach the RouterOS API | The default `drop all not coming from LAN` input rule. See §3. |
| Bandwidth-test rejected | User lacks the `test` policy, or device-mode has `bandwidth-test=no`, or the far end's `bandwidth-server` is disabled. |
| Container networking dead after reboot | `memory-high` is set. Clear it — see §7. |
| Image will not import | Built with `docker export`, or BuildKit's default OCI output. Use `docker save` from a `--output=type=docker` build. |
| Peers report 100% loss to this agent | Probe port not forwarded (§3), or the peer is not in `mq-peers`. |
