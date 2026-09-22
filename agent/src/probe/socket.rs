//! Probe sockets, and the control-message plumbing the DSCP feature needs.
//!
//! Neither `std` nor `tokio` can tell you the TOS byte or TTL a datagram
//! arrived with — that only comes back through `recvmsg` control messages,
//! which must be requested per-socket first. Verifying that QoS marking
//! survives a path is one of this agent's headline jobs, so the extra plumbing
//! earns its keep. All the `unsafe` in the agent lives here.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// What a datagram arrived with, beyond its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecvMeta {
    /// DSCP extracted from the received TOS byte (its upper 6 bits).
    /// `None` when the kernel supplied no TOS control message.
    pub dscp: Option<u8>,
    /// IP TTL / IPv6 hop limit on arrival. Subtracting from the sender's
    /// initial TTL gives the forward hop count.
    pub ttl: Option<u8>,
}

/// Bind a UDP socket for probe traffic.
///
/// `dscp` marks *outbound* packets. Requesting the TOS/TTL control messages is
/// best-effort: a kernel or container that refuses simply means DSCP
/// conformance goes unreported, which beats failing to start.
pub fn bind(addr: SocketAddr, dscp: Option<u8>) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;

    // Probe bursts can outpace the receive path on a loaded armv7 CPU. A
    // generous buffer means a scheduling hiccup shows up as jitter, which is
    // true, rather than as loss, which would be a lie about the network.
    let _ = sock.set_recv_buffer_size(1 << 20);
    let _ = sock.set_send_buffer_size(1 << 20);

    if let Some(d) = dscp {
        set_dscp(&sock, addr.is_ipv4(), d)?;
    }

    let fd = sock.as_raw_fd();
    let is_v4 = addr.is_ipv4();
    let (tos_level, tos_name) = if is_v4 {
        (libc::IPPROTO_IP, libc::IP_RECVTOS)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)
    };
    let (ttl_level, ttl_name) = if is_v4 {
        (libc::IPPROTO_IP, libc::IP_RECVTTL)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
    };
    let _ = setsockopt_int(fd, tos_level, tos_name, 1);
    let _ = setsockopt_int(fd, ttl_level, ttl_name, 1);

    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Set the DSCP on outbound packets.
///
/// DSCP occupies the upper 6 bits of the 8-bit TOS field, so the value is
/// shifted left by 2. Passing 46 (EF) unshifted would set TOS 46, which is
/// DSCP 11 — a silent, plausible-looking mismarking.
pub fn set_dscp(sock: &Socket, is_ipv4: bool, dscp: u8) -> io::Result<()> {
    let tos = ((dscp & 0x3F) as i32) << 2;
    if is_ipv4 {
        sock.set_tos(tos as u32)
    } else {
        setsockopt_int(sock.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_TCLASS, tos)
    }
}

/// Set the DSCP on an already-bound tokio socket. Used by the reflector, which
/// marks each reply to match what arrived.
pub fn set_dscp_raw(fd: RawFd, is_ipv4: bool, dscp: u8) -> io::Result<()> {
    let tos = ((dscp & 0x3F) as i32) << 2;
    let (level, name) =
        if is_ipv4 { (libc::IPPROTO_IP, libc::IP_TOS) } else { (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) };
    setsockopt_int(fd, level, name, tos)
}

fn setsockopt_int(fd: RawFd, level: i32, name: i32, value: i32) -> io::Result<()> {
    // SAFETY: `fd` is a live socket owned by the caller for the duration of the
    // call, and we pass a correctly sized pointer to a local `c_int`, which is
    // what every option used here expects.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const i32 as *const libc::c_void,
            mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Control buffer, over-aligned to `cmsghdr` via the union.
///
/// A bare `[u8; N]` is only byte-aligned; the kernel's `CMSG_*` macros assume
/// `cmsghdr` alignment, so walking a misaligned buffer is undefined behaviour.
/// 128 bytes comfortably holds the two messages we ask for.
const CMSG_BUF_LEN: usize = 128;

#[repr(C)]
union CmsgBuf {
    _align: libc::cmsghdr,
    bytes: [u8; CMSG_BUF_LEN],
}

/// Receive one datagram along with its TOS and TTL.
///
/// Waits for readiness through tokio, then performs the `recvmsg` itself so the
/// control messages are not discarded. Returns the same `(len, peer)` pair as
/// `recv_from`, plus the metadata.
pub async fn recv_from_with_meta(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, RecvMeta)> {
    loop {
        sock.readable().await?;

        // `try_io` tells tokio that a WouldBlock result means the readiness we
        // were handed is stale and must be re-armed — without it we would spin.
        match sock.try_io(Interest::READABLE, || recvmsg_once(sock.as_raw_fd(), buf)) {
            Ok(res) => return Ok(res),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn recvmsg_once(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, RecvMeta)> {
    // SAFETY: every pointer handed to the kernel below refers to a local that
    // outlives the `recvmsg` call, and each length is the true size of its
    // buffer. `msghdr`, `iovec` and `sockaddr_storage` are all POD, so a
    // zeroed value is valid. Control messages are read with unaligned reads,
    // and the control buffer is `cmsghdr`-aligned by construction.
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut src: libc::sockaddr_storage = mem::zeroed();
        let mut cmsg = CmsgBuf { bytes: [0u8; CMSG_BUF_LEN] };

        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = &mut src as *mut _ as *mut libc::c_void;
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.bytes.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = CMSG_BUF_LEN as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut meta = RecvMeta::default();
        let mut hdr = libc::CMSG_FIRSTHDR(&msg);
        while !hdr.is_null() {
            let level = (*hdr).cmsg_level;
            let ctype = (*hdr).cmsg_type;
            let data = libc::CMSG_DATA(hdr);

            match (level, ctype) {
                // Linux delivers IP_TOS as a single byte: the whole 8-bit TOS
                // field, so shift down to recover the 6-bit DSCP.
                (libc::IPPROTO_IP, libc::IP_TOS) => {
                    meta.dscp = Some(std::ptr::read_unaligned(data) >> 2);
                }
                // The remaining three arrive as `int`.
                (libc::IPPROTO_IP, libc::IP_TTL) => {
                    let v = std::ptr::read_unaligned(data as *const libc::c_int);
                    meta.ttl = Some(v as u8);
                }
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => {
                    let v = std::ptr::read_unaligned(data as *const libc::c_int);
                    meta.dscp = Some(((v as u8) >> 2) & 0x3F);
                }
                (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
                    let v = std::ptr::read_unaligned(data as *const libc::c_int);
                    meta.ttl = Some(v as u8);
                }
                _ => {}
            }

            hdr = libc::CMSG_NXTHDR(&msg, hdr);
        }

        let peer = sockaddr_to_std(&src).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "recvmsg returned an unusable peer address")
        })?;

        Ok((n as usize, peer, meta))
    }
}

/// Convert a kernel `sockaddr_storage` into a `SocketAddr`.
///
/// # Safety
/// `storage` must have been populated by the kernel, so that its `ss_family`
/// correctly describes the union member in use.
unsafe fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let a = &*(storage as *const _ as *const libc::sockaddr_in);
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let a = &*(storage as *const _ as *const libc::sockaddr_in6);
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                u32::from_be(a.sin6_flowinfo),
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_the_dscp_a_packet_arrived_with() {
        let rx = bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let rx_addr = rx.local_addr().unwrap();

        let tx = bind("127.0.0.1:0".parse().unwrap(), Some(46)).unwrap();
        tx.send_to(b"probe", rx_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, peer, meta) = recv_from_with_meta(&rx, &mut buf).await.unwrap();

        assert_eq!(&buf[..n], b"probe");
        assert_eq!(peer.ip(), tx.local_addr().unwrap().ip());
        assert_eq!(peer.port(), tx.local_addr().unwrap().port());
        assert_eq!(
            meta.dscp,
            Some(46),
            "DSCP must survive loopback; a value of 11 here means the TOS shift is wrong"
        );
        assert!(meta.ttl.is_some(), "TTL control message should be present on Linux");
    }

    #[tokio::test]
    async fn unmarked_traffic_reports_best_effort() {
        let rx = bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = bind("127.0.0.1:0".parse().unwrap(), None).unwrap();

        tx.send_to(b"x", rx_addr).await.unwrap();

        let mut buf = [0u8; 16];
        let (_, _, meta) = recv_from_with_meta(&rx, &mut buf).await.unwrap();
        assert_eq!(meta.dscp, Some(0));
    }

    #[tokio::test]
    async fn distinguishes_several_dscp_classes() {
        // EF (46), AF41 (34) and CS1 (8) must each survive intact — a broken
        // shift would collapse them into indistinguishable low values.
        let rx = bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let rx_addr = rx.local_addr().unwrap();

        for want in [46u8, 34, 8, 0] {
            let tx = bind("127.0.0.1:0".parse().unwrap(), Some(want)).unwrap();
            tx.send_to(b"q", rx_addr).await.unwrap();

            let mut buf = [0u8; 16];
            let (_, _, meta) = recv_from_with_meta(&rx, &mut buf).await.unwrap();
            assert_eq!(meta.dscp, Some(want), "DSCP {want} did not survive");
        }
    }

    #[test]
    fn dscp_is_shifted_into_the_upper_six_bits() {
        // Guards the likeliest silent bug here: DSCP 46 (EF) must become TOS
        // 0xB8, not TOS 46.
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        set_dscp(&sock, true, 46).unwrap();
        assert_eq!(sock.tos().unwrap(), (46u32) << 2);
    }

    #[tokio::test]
    async fn preserves_payload_across_the_size_range() {
        let rx = bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = bind("127.0.0.1:0".parse().unwrap(), None).unwrap();

        for len in [1usize, 56, 172, 1400] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            tx.send_to(&payload, rx_addr).await.unwrap();

            let mut buf = vec![0u8; 2048];
            let (n, _, _) = recv_from_with_meta(&rx, &mut buf).await.unwrap();
            assert_eq!(n, len);
            assert_eq!(&buf[..n], &payload[..], "payload corrupted at {len} bytes");
        }
    }
}
