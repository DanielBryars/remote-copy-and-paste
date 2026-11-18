//! Sync state and peer connections.

use crate::crypto::Keys;
use crate::proto::{self, Channel, Clip, Message, PROTOCOL_VERSION};
use anyhow::{Result, anyhow, bail};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const PING_INTERVAL: Duration = Duration::from_secs(15);
const PEER_TIMEOUT: Duration = Duration::from_secs(45);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SEND_TIMEOUT: Duration = Duration::from_secs(60);
/// Normally only the device with the lower id dials a discovered peer. If
/// that hasn't produced a connection after this long (for example the other
/// side's firewall blocks inbound TCP), the higher-id side dials too.
const FALLBACK_DIAL_AFTER: Duration = Duration::from_secs(12);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct Node {
    id: String,
    name: String,
    keys: Keys,
    /// Text to write to the local clipboard.
    clipboard: std::sync::mpsc::Sender<String>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Lamport clock: max of every clock value seen.
    clock: u64,
    /// The latest clip known to this device.
    current: Option<Clip>,
    peers: HashMap<String, Peer>,
    dialing: HashSet<String>,
    unconnected_since: HashMap<String, Instant>,
    next_conn_id: u64,
}

struct Peer {
    conn_id: u64,
    /// Device id of whoever opened this connection.
    dialer: String,
    name: String,
    tx: mpsc::UnboundedSender<Message>,
}

impl Node {
    pub fn new(
        id: String,
        name: String,
        keys: Keys,
        clipboard: std::sync::mpsc::Sender<String>,
    ) -> Arc<Self> {
        Arc::new(Node {
            id,
            name,
            keys,
            clipboard,
            state: Mutex::new(State::default()),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn is_connected(&self, peer_id: &str) -> bool {
        self.state.lock().unwrap().peers.contains_key(peer_id)
    }

    pub fn peer_names(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .peers
            .values()
            .map(|p| p.name.clone())
            .collect()
    }

    /// The user copied something on this machine.
    pub fn on_local_clip(&self, text: String) {
        let mut st = self.state.lock().unwrap();
        if st
            .current
            .as_ref()
            .is_some_and(|c| same_text(&c.text, &text))
        {
            return; // e.g. the clip we just received from a peer
        }
        st.clock += 1;
        let clip = Clip {
            clock: st.clock,
            origin: self.id.clone(),
            text,
        };
        log::info!(
            "copied {} — sending to {} peer(s)",
            describe(&clip.text),
            st.peers.len()
        );
        for p in st.peers.values() {
            let _ = p.tx.send(Message::Clip(clip.clone()));
        }
        st.current = Some(clip);
    }

    fn on_remote_clip(&self, from_conn: u64, from_name: &str, clip: Clip) {
        let mut st = self.state.lock().unwrap();
        st.clock = st.clock.max(clip.clock);
        if !clip.is_newer_than(st.current.as_ref()) {
            log::debug!("ignoring older clip from {from_name}");
            return;
        }
        log::info!("received {} from {from_name}", describe(&clip.text));
        // Relay so devices that aren't directly connected still converge.
        for p in st.peers.values().filter(|p| p.conn_id != from_conn) {
            let _ = p.tx.send(Message::Clip(clip.clone()));
        }
        let _ = self.clipboard.send(clip.text.clone());
        st.current = Some(clip);
    }

    /// Returns the connection id and the clip to bring the peer up to date,
    /// or `None` if an existing connection to this peer takes precedence.
    fn register(
        &self,
        peer_id: &str,
        name: &str,
        dialer: &str,
        addr: SocketAddr,
        tx: mpsc::UnboundedSender<Message>,
    ) -> Option<(u64, Option<Clip>)> {
        let mut st = self.state.lock().unwrap();
        // If both sides dial each other at once, both must keep the same
        // connection: the one opened by the lower device id wins.
        let preferred = std::cmp::min(self.id.as_str(), peer_id);
        if let Some(existing) = st.peers.get(peer_id)
            && existing.dialer == preferred
            && dialer != preferred
        {
            log::debug!("dropping duplicate connection to {name}");
            return None;
        }
        st.next_conn_id += 1;
        let conn_id = st.next_conn_id;
        st.unconnected_since.remove(peer_id);
        let replaced = st
            .peers
            .insert(
                peer_id.to_string(),
                Peer {
                    conn_id,
                    dialer: dialer.to_string(),
                    name: name.to_string(),
                    tx,
                },
            )
            .is_some();
        if !replaced {
            log::info!("connected to {name} ({})", addr.ip());
        }
        Some((conn_id, st.current.clone()))
    }

    fn unregister(&self, peer_id: &str, conn_id: u64) {
        let mut st = self.state.lock().unwrap();
        if st.peers.get(peer_id).map(|p| p.conn_id) == Some(conn_id) {
            let p = st.peers.remove(peer_id).unwrap();
            log::info!("disconnected from {}", p.name);
        }
    }

    pub async fn listen(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let node = self.clone();
                    tokio::spawn(async move {
                        if let (_, Err(e)) = node.run_conn(stream, false).await {
                            log::warn!("connection from {}: {e:#}", addr.ip());
                        }
                    });
                }
                Err(e) => {
                    log::warn!("accept failed: {e}");
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Keep a connection open to a manually configured peer address.
    pub async fn dial_loop(self: Arc<Self>, target: String) {
        let mut backoff = Duration::from_secs(1);
        let mut known_id: Option<String> = None;
        loop {
            if let Some(id) = &known_id
                && self.is_connected(id)
            {
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(target.as_str())).await {
                Ok(Ok(stream)) => {
                    let (peer, result) = self.clone().run_conn(stream, true).await;
                    if peer.is_some() {
                        known_id = peer;
                        backoff = Duration::from_secs(1);
                    }
                    if let Err(e) = result {
                        log::warn!("{target}: {e:#}");
                    }
                }
                Ok(Err(e)) => log::debug!("{target}: {e}"),
                Err(_) => log::debug!("{target}: connect timed out"),
            }
            sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// A paired device announced itself on the LAN.
    pub fn on_discovered(self: &Arc<Self>, peer_id: String, addr: SocketAddr) {
        let mut st = self.state.lock().unwrap();
        if st.peers.contains_key(&peer_id) || st.dialing.contains(&peer_id) {
            return;
        }
        let since = *st
            .unconnected_since
            .entry(peer_id.clone())
            .or_insert_with(Instant::now);
        if self.id.as_str() > peer_id.as_str() && since.elapsed() < FALLBACK_DIAL_AFTER {
            return; // the other side will dial us
        }
        st.dialing.insert(peer_id.clone());
        drop(st);

        log::debug!("discovered peer at {addr}, connecting");
        let node = self.clone();
        tokio::spawn(async move {
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    if let (_, Err(e)) = node.clone().run_conn(stream, true).await {
                        log::warn!("{}: {e:#}", addr.ip());
                    }
                }
                Ok(Err(e)) => log::debug!("{addr}: {e}"),
                Err(_) => log::debug!("{addr}: connect timed out"),
            }
            node.state.lock().unwrap().dialing.remove(&peer_id);
        });
    }

    /// Run one connection to completion. Returns the peer's device id if the
    /// handshake got that far.
    async fn run_conn(
        self: Arc<Self>,
        stream: TcpStream,
        initiator: bool,
    ) -> (Option<String>, Result<()>) {
        let addr = match stream.peer_addr() {
            Ok(a) => a,
            Err(e) => return (None, Err(e.into())),
        };
        let _ = stream.set_nodelay(true);
        let (mut chan, peer_id, peer_name) =
            match timeout(HANDSHAKE_TIMEOUT, self.establish(stream, initiator)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return (None, Err(e)),
                Err(_) => return (None, Err(anyhow!("handshake timed out"))),
            };

        let dialer = if initiator {
            self.id.clone()
        } else {
            peer_id.clone()
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let Some((conn_id, current)) = self.register(&peer_id, &peer_name, &dialer, addr, tx)
        else {
            return (Some(peer_id), Ok(()));
        };
        let result = self
            .conn_loop(&mut chan, &mut rx, conn_id, &peer_name, current)
            .await;
        self.unregister(&peer_id, conn_id);
        (Some(peer_id), result)
    }

    async fn establish(
        &self,
        stream: TcpStream,
        initiator: bool,
    ) -> Result<(Channel, String, String)> {
        let mut chan = proto::handshake(stream, &self.keys.psk, initiator).await?;
        chan.send(&Message::Hello {
            id: self.id.clone(),
            name: self.name.clone(),
            version: PROTOCOL_VERSION,
        })
        .await?;
        loop {
            let frame = chan
                .recv_frame()
                .await
                .ok_or_else(|| anyhow!("connection closed before hello"))??;
            for msg in chan.open(&frame)? {
                if let Message::Hello { id, name, version } = msg {
                    if id == self.id {
                        bail!("connected to myself");
                    }
                    if version != PROTOCOL_VERSION {
                        bail!(
                            "{name} runs protocol v{version}, this device runs v{PROTOCOL_VERSION}; update both"
                        );
                    }
                    return Ok((chan, id, name));
                }
            }
        }
    }

    async fn conn_loop(
        &self,
        chan: &mut Channel,
        rx: &mut mpsc::UnboundedReceiver<Message>,
        conn_id: u64,
        peer_name: &str,
        current: Option<Clip>,
    ) -> Result<()> {
        // Bring the peer up to date; it keeps the clip only if it is newer.
        if let Some(clip) = current {
            send(chan, &Message::Clip(clip)).await?;
        }
        let mut ping =
            tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
        let mut last_heard = Instant::now();
        loop {
            tokio::select! {
                frame = chan.recv_frame() => {
                    let Some(frame) = frame else { return Ok(()) };
                    let frame = frame?;
                    last_heard = Instant::now();
                    for msg in chan.open(&frame)? {
                        match msg {
                            Message::Clip(clip) => self.on_remote_clip(conn_id, peer_name, clip),
                            Message::Ping => send(chan, &Message::Pong).await?,
                            Message::Pong | Message::Hello { .. } => {}
                        }
                    }
                }
                out = rx.recv() => match out {
                    Some(msg) => send(chan, &msg).await?,
                    None => return Ok(()), // superseded by a newer connection
                },
                _ = ping.tick() => {
                    if last_heard.elapsed() > PEER_TIMEOUT {
                        bail!("{peer_name} stopped responding");
                    }
                    send(chan, &Message::Ping).await?;
                }
            }
        }
    }
}

async fn send(chan: &mut Channel, msg: &Message) -> Result<()> {
    timeout(SEND_TIMEOUT, chan.send(msg))
        .await
        .map_err(|_| anyhow!("send timed out"))?
}

fn same_text(a: &str, b: &str) -> bool {
    a == b || a.replace("\r\n", "\n") == b.replace("\r\n", "\n")
}

fn describe(text: &str) -> String {
    let n = text.chars().count();
    if n == 1 {
        "1 character".into()
    } else {
        format!("{n} characters")
    }
}
