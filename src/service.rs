//! Wires the clipboard, node, listener and discovery together.

use crate::clipboard::{self, BackendFactory};
use crate::crypto::{Keys, Secret};
use crate::discovery;
use crate::node::Node;
use anyhow::{Context, Result, bail};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpListener;

pub struct Options {
    pub device_id: String,
    pub device_name: String,
    pub secret: Secret,
    pub port: u16,
    /// Addresses to always connect to, as `host:port`.
    pub peers: Vec<String>,
    pub discovery: bool,
    pub poll_interval: Duration,
}

pub async fn run(opts: Options, clipboard: BackendFactory) -> Result<()> {
    let keys = Keys::derive(&opts.secret);

    let (apply_tx, apply_rx) = std::sync::mpsc::channel();
    let (change_tx, mut change_rx) = tokio::sync::mpsc::unbounded_channel();
    clipboard::spawn(clipboard, apply_rx, change_tx, opts.poll_interval)
        .context("could not access the clipboard")?;

    let node = Node::new(
        opts.device_id,
        opts.device_name.clone(),
        keys.clone(),
        apply_tx,
    );

    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, opts.port))
        .await
        .with_context(|| format!("could not listen on TCP port {} (is clipshare already running, or is the port reserved by another program? try --port)", opts.port))?;
    log::info!("\"{}\" listening on TCP {}", opts.device_name, opts.port);
    tokio::spawn(node.clone().listen(listener));

    if opts.discovery {
        let node = node.clone();
        let port = opts.port;
        tokio::spawn(async move {
            if let Err(e) = discovery::run(node, keys.discovery, port, port).await {
                log::warn!("LAN discovery unavailable ({e:#}); use --peer to connect manually");
            }
        });
    }
    for peer in opts.peers {
        tokio::spawn(node.clone().dial_loop(peer));
    }

    while let Some(text) = change_rx.recv().await {
        node.on_local_clip(text);
    }
    bail!("clipboard monitor stopped unexpectedly")
}
