//! clipshare: peer-to-peer clipboard sharing between computers.
//!
//! Architecture:
//! - [`clipboard`] runs a dedicated OS thread that watches the local clipboard
//!   and applies text received from peers.
//! - [`node`] owns the sync state (a Lamport clock so "last copy wins" is
//!   decided identically on every machine) and the peer connections.
//! - [`proto`] is the wire protocol: a Noise `NNpsk0` handshake keyed by the
//!   pairing code, then encrypted, length-framed JSON messages.
//! - [`discovery`] finds paired peers on the LAN with authenticated UDP
//!   broadcasts.

pub mod clipboard;
pub mod config;
pub mod crypto;
pub mod discovery;
pub mod node;
pub mod proto;
pub mod service;
