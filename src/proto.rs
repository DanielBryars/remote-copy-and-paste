//! Wire protocol.
//!
//! TCP stream → 2-byte length-delimited frames → Noise transport messages
//! (ChaCha20-Poly1305) → a plaintext byte stream carrying u32-length-prefixed
//! JSON [`Message`]s. Large messages are split across several Noise frames.

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub const PROTOCOL_VERSION: u32 = 1;

/// PSK-authenticated, forward-secret handshake. Anyone without the pairing
/// code fails the handshake and learns nothing.
const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"clipshare/1";
const MAX_NOISE_MSG: usize = 65535;
const TAG_LEN: usize = 16;
const MAX_PLAINTEXT: usize = MAX_NOISE_MSG - TAG_LEN;

/// Largest clipboard text we will send.
pub const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;
/// Largest encoded message we will accept (JSON escaping can inflate text).
const MAX_MESSAGE_BYTES: usize = 8 * MAX_TEXT_BYTES;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Clip {
    /// Lamport clock value at the time of the copy.
    pub clock: u64,
    /// Device id of the machine the text was copied on.
    pub origin: String,
    pub text: String,
}

impl Clip {
    /// Total order used to decide which copy is the latest. Every node
    /// applies the same rule, so they all converge on the same clip.
    pub fn is_newer_than(&self, other: Option<&Clip>) -> bool {
        match other {
            None => true,
            Some(o) => (self.clock, &self.origin) > (o.clock, &o.origin),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Hello {
        id: String,
        name: String,
        version: u32,
    },
    Clip(Clip),
    Ping,
    Pong,
}

/// An established, encrypted connection to a peer.
pub struct Channel {
    framed: Framed<TcpStream, LengthDelimitedCodec>,
    noise: snow::TransportState,
    plain: Vec<u8>,
}

pub async fn handshake(stream: TcpStream, psk: &[u8; 32], initiator: bool) -> Result<Channel> {
    let codec = LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(MAX_NOISE_MSG)
        .new_codec();
    let mut framed = Framed::new(stream, codec);
    let builder = snow::Builder::new(NOISE_PARAMS.parse()?)
        .psk(0, psk)?
        .prologue(PROLOGUE)?;
    let mut buf = vec![0u8; MAX_NOISE_MSG];

    let noise = if initiator {
        let mut hs = builder.build_initiator()?;
        let n = hs.write_message(&[], &mut buf)?;
        framed.send(Bytes::copy_from_slice(&buf[..n])).await?;
        let reply = next_frame(&mut framed).await?;
        hs.read_message(&reply, &mut buf).map_err(|_| {
            anyhow!("handshake rejected: the other device has a different pairing code")
        })?;
        hs.into_transport_mode()?
    } else {
        let mut hs = builder.build_responder()?;
        let hello = next_frame(&mut framed).await?;
        hs.read_message(&hello, &mut buf).map_err(|_| {
            anyhow!("handshake rejected: the other device has a different pairing code")
        })?;
        let n = hs.write_message(&[], &mut buf)?;
        framed.send(Bytes::copy_from_slice(&buf[..n])).await?;
        hs.into_transport_mode()?
    };

    Ok(Channel {
        framed,
        noise,
        plain: Vec::new(),
    })
}

async fn next_frame(framed: &mut Framed<TcpStream, LengthDelimitedCodec>) -> Result<BytesMut> {
    framed
        .next()
        .await
        .ok_or_else(|| {
            anyhow!(
                "connection closed during handshake (do both devices have the same pairing code?)"
            )
        })?
        .context("reading handshake")
}

impl Channel {
    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        let body = serde_json::to_vec(msg)?;
        let mut data = Vec::with_capacity(body.len() + 4);
        data.extend_from_slice(&(body.len() as u32).to_be_bytes());
        data.extend_from_slice(&body);
        let mut out = vec![0u8; MAX_NOISE_MSG];
        for chunk in data.chunks(MAX_PLAINTEXT) {
            let n = self.noise.write_message(chunk, &mut out)?;
            self.framed.feed(Bytes::copy_from_slice(&out[..n])).await?;
        }
        SinkExt::<Bytes>::flush(&mut self.framed).await?;
        Ok(())
    }

    /// Wait for the next encrypted frame. Cancel-safe, so it can be used in
    /// `tokio::select!`. Returns `None` when the peer closes the connection.
    pub async fn recv_frame(&mut self) -> Option<Result<BytesMut>> {
        self.framed.next().await.map(|r| r.map_err(Into::into))
    }

    /// Decrypt a frame and return any messages it completed.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<Message>> {
        let mut buf = vec![0u8; frame.len()];
        let n = self
            .noise
            .read_message(frame, &mut buf)
            .map_err(|_| anyhow!("failed to decrypt message from peer"))?;
        self.plain.extend_from_slice(&buf[..n]);

        let mut msgs = Vec::new();
        loop {
            if self.plain.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes(self.plain[..4].try_into().unwrap()) as usize;
            if len > MAX_MESSAGE_BYTES {
                bail!("peer sent an oversized message ({len} bytes)");
            }
            if self.plain.len() < 4 + len {
                break;
            }
            let msg = serde_json::from_slice(&self.plain[4..4 + len])
                .context("malformed message from peer");
            self.plain.drain(..4 + len);
            match msg {
                Ok(m) => msgs.push(m),
                // Unknown message types from newer versions are skipped.
                Err(e) => log::debug!("{e:#}"),
            }
        }
        Ok(msgs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clip(clock: u64, origin: &str) -> Clip {
        Clip {
            clock,
            origin: origin.into(),
            text: String::new(),
        }
    }

    #[test]
    fn ordering() {
        assert!(clip(1, "a").is_newer_than(None));
        assert!(clip(2, "a").is_newer_than(Some(&clip(1, "b"))));
        assert!(!clip(1, "a").is_newer_than(Some(&clip(2, "b"))));
        // Concurrent copies with the same clock: device id breaks the tie.
        assert!(clip(3, "b").is_newer_than(Some(&clip(3, "a"))));
        assert!(!clip(3, "a").is_newer_than(Some(&clip(3, "b"))));
        assert!(!clip(3, "a").is_newer_than(Some(&clip(3, "a"))));
    }
}
