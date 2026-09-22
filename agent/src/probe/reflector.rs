//! The reflector: one UDP socket serving every inbound probe session.
//!
//! It never initiates anything and holds only a small counter per session, so a
//! single armv7 device can reflect for many peers at once. Admission control is
//! the `session_id` the controller granted — see the security note in
//! `docs/architecture.md`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use super::socket::{self, RecvMeta};
use super::Clock;
use crate::proto::mqp::{self, Header, PacketType, MAX_PACKET_LEN};

/// TTL we set on replies. Fixed so the sender can derive the reverse hop count
/// by subtraction.
const REPLY_TTL: u8 = 64;

/// Per-session state. Deliberately tiny — this is multiplied by every concurrent
/// session the device is serving.
#[derive(Debug)]
struct Session {
    /// Increments once per reply generated. The sender uses gaps in this to
    /// tell reverse-path loss from forward-path loss.
    reflector_seq: u32,
    /// Only this peer may use this session ID. An unspecified address
    /// (`0.0.0.0` / `::`) is a wildcard — see [`Session::accepts`].
    peer: SocketAddr,
    packets: u64,
}

impl Session {
    /// Whether a packet from `from` may use this session.
    ///
    /// Matching is on address only, never port: the sender's source port is
    /// ephemeral and the controller cannot know it when it issues the grant.
    ///
    /// An unspecified bind address is treated as "any source". The controller
    /// always names a real peer, so this only applies to the standalone
    /// `reflect` test mode, where the sender's address is not known up front.
    /// The session ID remains required either way.
    fn accepts(&self, from: SocketAddr) -> bool {
        self.peer.ip().is_unspecified() || self.peer.ip() == from.ip()
    }
}

/// Grants issued by the controller, keyed by session ID.
#[derive(Debug, Default)]
pub struct Registry {
    sessions: HashMap<u64, Session>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorise a session ID from a given peer until it is revoked.
    pub fn grant(&mut self, session_id: u64, peer: SocketAddr) {
        debug!(session_id = %format_args!("{session_id:016x}"), %peer, "session granted");
        self.sessions.insert(session_id, Session { reflector_seq: 0, peer, packets: 0 });
    }

    /// Revoke a session and report how many packets it reflected.
    pub fn revoke(&mut self, session_id: u64) -> Option<u64> {
        self.sessions.remove(&session_id).map(|s| s.packets)
    }

    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }
}

/// Counters for the agent's own health reporting. A reflector that is quietly
/// dropping everything should be visible as such, not look idle.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReflectorStats {
    pub reflected: u64,
    pub unknown_session: u64,
    pub wrong_peer: u64,
    pub malformed: u64,
    pub send_errors: u64,
}

pub struct Reflector {
    sock: UdpSocket,
    clock: Clock,
    registry: Arc<Mutex<Registry>>,
    stats: ReflectorStats,
}

impl Reflector {
    pub async fn bind(addr: SocketAddr, registry: Arc<Mutex<Registry>>) -> std::io::Result<Self> {
        // No default DSCP: replies are marked to match what arrived, so the
        // return path is measured under the same class as the forward path.
        let sock = socket::bind(addr, None)?;
        Ok(Self { sock, clock: Clock::new(), registry, stats: ReflectorStats::default() })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub fn stats(&self) -> ReflectorStats {
        self.stats
    }

    /// Serve until cancelled.
    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut buf = vec![0u8; MAX_PACKET_LEN];

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        debug!(stats = ?self.stats, "reflector shutting down");
                        return;
                    }
                }
                res = socket::recv_from_with_meta(&self.sock, &mut buf) => {
                    match res {
                        Ok((n, peer, meta)) => self.handle(&mut buf, n, peer, meta).await,
                        Err(e) => {
                            // A transient receive error must not kill the
                            // reflector — the agent would go silently deaf.
                            warn!(error = %e, "probe socket receive failed");
                            self.stats.send_errors += 1;
                        }
                    }
                }
            }
        }
    }

    async fn handle(&mut self, buf: &mut [u8], n: usize, peer: SocketAddr, meta: RecvMeta) {
        // Stamp arrival first, before any parsing, so our own decode cost is
        // not attributed to the network.
        let t2 = self.clock.now_ns();

        let header = match Header::decode(&buf[..n]) {
            Ok(h) => h,
            Err(e) => {
                self.stats.malformed += 1;
                trace!(%peer, error = %e, "dropping malformed packet");
                return;
            }
        };

        // Only reflect requests. A reply arriving here means a misconfiguration
        // (or a loop) and must not be reflected again.
        if header.pkt_type != PacketType::Request {
            self.stats.malformed += 1;
            return;
        }

        let (reflector_seq, authorised) = {
            let mut reg = self.registry.lock().await;
            match reg.sessions.get_mut(&header.session_id) {
                Some(s) if s.accepts(peer) => {
                    let seq = s.reflector_seq;
                    s.reflector_seq = s.reflector_seq.wrapping_add(1);
                    s.packets += 1;
                    (seq, true)
                }
                Some(_) => (0, false),
                None => (0, false),
            }
        };

        if !authorised {
            // Silence is the correct response: replying would confirm to a
            // scanner that this port is live and that the session ID space is
            // worth probing.
            self.stats.unknown_session += 1;
            trace!(
                %peer,
                session_id = %format_args!("{:016x}", header.session_id),
                "dropping packet for unknown or mismatched session"
            );
            return;
        }

        if header.has_flag(mqp::flags::NO_REFLECT) {
            return;
        }

        let rx_dscp = meta.dscp.unwrap_or(0);

        // Mark the reply with the DSCP that arrived, so the return path is
        // measured in the same traffic class. Best-effort: if the socket
        // refuses, the measurement is still valid, just unmarked.
        if let Err(e) = self.set_reply_dscp(rx_dscp) {
            trace!(error = %e, "could not set reply DSCP");
        }

        if let Err(e) = mqp::make_reply_in_place(
            buf,
            t2,
            reflector_seq,
            rx_dscp,
            meta.ttl.unwrap_or(0),
            REPLY_TTL,
        ) {
            self.stats.malformed += 1;
            warn!(error = %e, "failed to build reply");
            return;
        }

        // Stamp departure as late as possible: everything between here and the
        // syscall would otherwise be charged to the network. `(t3 - t2)` is
        // subtracted out by the sender, so this window is exactly what we are
        // excluding from the measurement.
        let t3 = self.clock.now_ns();
        if mqp::stamp_t3(buf, t3).is_err() {
            self.stats.malformed += 1;
            return;
        }

        match self.sock.send_to(&buf[..n], peer).await {
            Ok(_) => self.stats.reflected += 1,
            Err(e) => {
                self.stats.send_errors += 1;
                warn!(%peer, error = %e, "failed to send reply");
            }
        }
    }

    fn set_reply_dscp(&self, dscp: u8) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let is_v4 = self.sock.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
        socket::set_dscp_raw(self.sock.as_raw_fd(), is_v4, dscp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::mqp::{Header, DEFAULT_PACKET_LEN};
    use std::time::Duration;
    use tokio::sync::watch;

    /// Start a reflector on loopback and return its address plus a handle to
    /// its registry.
    async fn spawn_reflector() -> (SocketAddr, Arc<Mutex<Registry>>, watch::Sender<bool>) {
        let registry = Arc::new(Mutex::new(Registry::new()));
        let r = Reflector::bind("127.0.0.1:0".parse().unwrap(), registry.clone()).await.unwrap();
        let addr = r.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(r.run(rx));
        (addr, registry, tx)
    }

    fn request(session_id: u64, seq: u32) -> Vec<u8> {
        let h = Header::request(session_id, seq, 46, (DEFAULT_PACKET_LEN - 56) as u16);
        let mut buf = vec![0u8; h.wire_len()];
        h.encode(&mut buf).unwrap();
        buf
    }

    #[tokio::test]
    async fn reflects_a_granted_session() {
        let (addr, registry, _sd) = spawn_reflector().await;
        let client = socket::bind("127.0.0.1:0".parse().unwrap(), Some(46)).unwrap();
        registry.lock().await.grant(0xAAAA, client.local_addr().unwrap());

        client.send_to(&request(0xAAAA, 7), addr).await.unwrap();

        let mut buf = [0u8; MAX_PACKET_LEN];
        let (n, _, _) = tokio::time::timeout(
            Duration::from_secs(2),
            socket::recv_from_with_meta(&client, &mut buf),
        )
        .await
        .expect("reflector did not reply in time")
        .unwrap();

        let reply = Header::decode(&buf[..n]).unwrap();
        assert_eq!(reply.pkt_type, PacketType::Reply);
        assert_eq!(reply.seq, 7, "sender's seq must survive reflection");
        assert_eq!(reply.session_id, 0xAAAA);
        assert!(reply.t2 > 0, "reflector must stamp arrival");
        assert!(reply.t3 >= reply.t2, "departure cannot precede arrival");
        assert_eq!(reply.rx_dscp, 46, "reflector must echo the DSCP it observed");
    }

    #[tokio::test]
    async fn wildcard_grant_accepts_any_source_address() {
        // The standalone `reflect` mode cannot know the sender's address in
        // advance, so it grants 0.0.0.0. Without wildcard handling the
        // reflector compares 0.0.0.0 against the real source, rejects every
        // packet, and the run reports 100% loss on a perfectly healthy path.
        let (addr, registry, _sd) = spawn_reflector().await;
        let client = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        registry.lock().await.grant(0xF00D, "0.0.0.0:0".parse().unwrap());

        client.send_to(&request(0xF00D, 1), addr).await.unwrap();

        let mut buf = [0u8; MAX_PACKET_LEN];
        let (n, _, _) = tokio::time::timeout(
            Duration::from_secs(2),
            socket::recv_from_with_meta(&client, &mut buf),
        )
        .await
        .expect("wildcard grant should have been reflected")
        .unwrap();
        assert_eq!(Header::decode(&buf[..n]).unwrap().seq, 1);
    }

    #[tokio::test]
    async fn specific_grant_still_rejects_a_different_source() {
        // The wildcard must not have weakened normal admission control.
        let (addr, registry, _sd) = spawn_reflector().await;
        let client = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        // Grant a different address than the one we will send from.
        registry.lock().await.grant(0xBEEF, "203.0.113.99:5301".parse().unwrap());

        client.send_to(&request(0xBEEF, 0), addr).await.unwrap();

        let mut buf = [0u8; MAX_PACKET_LEN];
        let res = tokio::time::timeout(
            Duration::from_millis(300),
            socket::recv_from_with_meta(&client, &mut buf),
        )
        .await;
        assert!(res.is_err(), "a grant for another address must not be usable");
    }

    #[tokio::test]
    async fn ignores_ungranted_sessions_silently() {
        let (addr, _registry, _sd) = spawn_reflector().await;
        let client = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();

        // No grant issued for this session ID.
        client.send_to(&request(0xDEAD_BEEF, 0), addr).await.unwrap();

        let mut buf = [0u8; MAX_PACKET_LEN];
        let res = tokio::time::timeout(
            Duration::from_millis(300),
            socket::recv_from_with_meta(&client, &mut buf),
        )
        .await;
        assert!(res.is_err(), "must not reply to an ungranted session, not even an error");
    }

    #[tokio::test]
    async fn reflector_seq_increments_to_expose_reverse_loss() {
        let (addr, registry, _sd) = spawn_reflector().await;
        let client = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        registry.lock().await.grant(0xBBBB, client.local_addr().unwrap());

        let mut buf = [0u8; MAX_PACKET_LEN];
        for i in 0..3u32 {
            client.send_to(&request(0xBBBB, i), addr).await.unwrap();
            let (n, _, _) = tokio::time::timeout(
                Duration::from_secs(2),
                socket::recv_from_with_meta(&client, &mut buf),
            )
            .await
            .expect("timed out")
            .unwrap();
            let reply = Header::decode(&buf[..n]).unwrap();
            assert_eq!(reply.reflector_seq, i, "reflector counter must advance once per reply");
        }
    }

    #[tokio::test]
    async fn malformed_packets_do_not_kill_the_reflector() {
        let (addr, registry, _sd) = spawn_reflector().await;
        let client = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        registry.lock().await.grant(0xCCCC, client.local_addr().unwrap());

        // Garbage, then a valid probe. The reflector must survive the first and
        // still answer the second.
        client.send_to(b"not an mqp packet at all", addr).await.unwrap();
        client.send_to(&[0u8; 200], addr).await.unwrap();
        client.send_to(&request(0xCCCC, 1), addr).await.unwrap();

        let mut buf = [0u8; MAX_PACKET_LEN];
        let (n, _, _) = tokio::time::timeout(
            Duration::from_secs(2),
            socket::recv_from_with_meta(&client, &mut buf),
        )
        .await
        .expect("reflector died on malformed input")
        .unwrap();
        assert_eq!(Header::decode(&buf[..n]).unwrap().seq, 1);
    }

    #[tokio::test]
    async fn revoked_session_stops_being_reflected() {
        let (addr, registry, _sd) = spawn_reflector().await;
        let client = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        registry.lock().await.grant(0xEEEE, client.local_addr().unwrap());

        client.send_to(&request(0xEEEE, 0), addr).await.unwrap();
        let mut buf = [0u8; MAX_PACKET_LEN];
        tokio::time::timeout(
            Duration::from_secs(2),
            socket::recv_from_with_meta(&client, &mut buf),
        )
        .await
        .expect("first packet should reflect")
        .unwrap();

        let packets = registry.lock().await.revoke(0xEEEE);
        assert_eq!(packets, Some(1), "revoke should report packets served");

        client.send_to(&request(0xEEEE, 1), addr).await.unwrap();
        let res = tokio::time::timeout(
            Duration::from_millis(300),
            socket::recv_from_with_meta(&client, &mut buf),
        )
        .await;
        assert!(res.is_err(), "revoked session must no longer be reflected");
    }

    #[tokio::test]
    async fn serves_multiple_concurrent_sessions() {
        let (addr, registry, _sd) = spawn_reflector().await;
        let a = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let b = socket::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        {
            let mut reg = registry.lock().await;
            reg.grant(0x1111, a.local_addr().unwrap());
            reg.grant(0x2222, b.local_addr().unwrap());
            assert_eq!(reg.active_count(), 2);
        }

        a.send_to(&request(0x1111, 0), addr).await.unwrap();
        b.send_to(&request(0x2222, 0), addr).await.unwrap();

        let mut buf = [0u8; MAX_PACKET_LEN];
        for sock in [&a, &b] {
            let (n, _, _) = tokio::time::timeout(
                Duration::from_secs(2),
                socket::recv_from_with_meta(sock, &mut buf),
            )
            .await
            .expect("both sessions should be served")
            .unwrap();
            let h = Header::decode(&buf[..n]).unwrap();
            assert!(h.session_id == 0x1111 || h.session_id == 0x2222);
        }
    }
}
