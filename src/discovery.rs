//! LAN discovery via UDP broadcast.
//!
//! Packets are authenticated with an HMAC derived from the pairing code, so
//! devices only react to announcements from their own group. They carry no
//! secrets; the TCP connection is authenticated separately by Noise.

use crate::crypto;
use crate::node::Node;
use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC: &[u8; 8] = b"CLPSHR01";
const KIND_ANNOUNCE: u8 = 0;
const KIND_REPLY: u8 = 1;
const BODY_LEN: usize = 8 + 1 + 16 + 2;
const PACKET_LEN: usize = BODY_LEN + 16;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);

fn build(key: &[u8; 32], kind: u8, id: &[u8; 16], tcp_port: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(PACKET_LEN);
    p.extend_from_slice(MAGIC);
    p.push(kind);
    p.extend_from_slice(id);
    p.extend_from_slice(&tcp_port.to_be_bytes());
    let tag = crypto::mac(key, &p);
    p.extend_from_slice(&tag);
    p
}

fn parse(key: &[u8; 32], p: &[u8]) -> Option<(u8, [u8; 16], u16)> {
    if p.len() != PACKET_LEN || &p[..8] != MAGIC {
        return None;
    }
    if !crypto::ct_eq(&crypto::mac(key, &p[..BODY_LEN]), &p[BODY_LEN..]) {
        return None; // a device paired with a different code
    }
    let kind = p[8];
    let id: [u8; 16] = p[9..25].try_into().ok()?;
    let port = u16::from_be_bytes([p[25], p[26]]);
    Some((kind, id, port))
}

/// Broadcast addresses of every IPv4 interface, plus the limited broadcast.
fn broadcast_targets(port: u16) -> Vec<SocketAddr> {
    let mut targets = vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, port))];
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if let if_addrs::IfAddr::V4(v4) = iface.addr
                && !v4.ip.is_loopback()
                && let Some(b) = v4.broadcast
            {
                let t = SocketAddr::V4(SocketAddrV4::new(b, port));
                if !targets.contains(&t) {
                    targets.push(t);
                }
            }
        }
    }
    targets
}

pub async fn run(node: Arc<Node>, key: [u8; 32], udp_port: u16, tcp_port: u16) -> Result<()> {
    let id: [u8; 16] = hex::decode(node.id())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad device id"))?;
    let std_sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, udp_port))?;
    std_sock.set_broadcast(true)?;
    std_sock.set_nonblocking(true)?;
    let sock = Arc::new(UdpSocket::from_std(std_sock)?);
    log::info!("LAN discovery on UDP {udp_port}");

    let announce = build(&key, KIND_ANNOUNCE, &id, tcp_port);
    let reply = build(&key, KIND_REPLY, &id, tcp_port);

    let sender = sock.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(ANNOUNCE_INTERVAL);
        loop {
            tick.tick().await;
            for target in broadcast_targets(udp_port) {
                if let Err(e) = sender.send_to(&announce, target).await {
                    log::trace!("broadcast to {target} failed: {e}");
                }
            }
        }
    });

    let mut buf = [0u8; 512];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                // Windows reports ICMP "port unreachable" from earlier sends
                // as an error on the next receive; it's harmless.
                log::trace!("udp receive error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some((kind, peer, port)) = parse(&key, &buf[..n]) else {
            continue;
        };
        if peer == id {
            continue; // our own broadcast
        }
        let peer_id = hex::encode(peer);
        let connected = node.is_connected(&peer_id);
        node.on_discovered(peer_id, SocketAddr::new(src.ip(), port));
        // Answer directly so the other device learns about us immediately
        // rather than waiting for our next broadcast.
        if kind == KIND_ANNOUNCE && !connected {
            let _ = sock.send_to(&reply, src).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_roundtrip_and_auth() {
        let key = [7u8; 32];
        let id = [3u8; 16];
        let p = build(&key, KIND_REPLY, &id, 1234);
        assert_eq!(parse(&key, &p), Some((KIND_REPLY, id, 1234)));
        assert_eq!(parse(&[8u8; 32], &p), None);
        let mut tampered = p.clone();
        tampered[26] ^= 1;
        assert_eq!(parse(&key, &tampered), None);
    }
}
