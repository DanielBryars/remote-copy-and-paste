//! Pairing codes and key derivation.

use anyhow::{Result, anyhow, bail};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// 15 bytes = 120 bits of entropy = exactly 24 base32 characters.
pub const SECRET_LEN: usize = 15;
pub type Secret = [u8; SECRET_LEN];

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn new_secret() -> Secret {
    rand::random()
}

/// Encode a secret as a human-friendly code like `ABCD-EFGH-IJKL-MNOP-QRST-UVWX`.
pub fn encode_code(secret: &Secret) -> String {
    let mut chars = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in secret {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            chars.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    debug_assert_eq!(bits, 0);
    chars
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a pairing code. Case, dashes and whitespace are ignored, and the
/// commonly-confused digits 0/1/8 are read as O/I/B.
pub fn decode_code(code: &str) -> Result<Secret> {
    let mut out = Vec::with_capacity(SECRET_LEN);
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in code.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        let c = match c.to_ascii_uppercase() {
            '0' => 'O',
            '1' => 'I',
            '8' => 'B',
            c => c,
        };
        let v = ALPHABET
            .iter()
            .position(|&a| a as char == c)
            .ok_or_else(|| anyhow!("invalid character '{c}' in pairing code"))?;
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if out.len() != SECRET_LEN || bits != 0 {
        bail!(
            "pairing code should be {} letters/digits (got something else)",
            SECRET_LEN * 8 / 5
        );
    }
    Ok(out.try_into().unwrap())
}

/// Keys derived from the shared pairing secret.
#[derive(Clone)]
pub struct Keys {
    /// Pre-shared key for the Noise handshake.
    pub psk: [u8; 32],
    /// HMAC key for authenticating LAN discovery packets.
    pub discovery: [u8; 32],
}

impl Keys {
    pub fn derive(secret: &Secret) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"clipshare/v1"), secret);
        let mut psk = [0u8; 32];
        let mut discovery = [0u8; 32];
        hk.expand(b"noise-psk", &mut psk).expect("hkdf length");
        hk.expand(b"lan-discovery", &mut discovery)
            .expect("hkdf length");
        Keys { psk, discovery }
    }
}

/// Truncated HMAC-SHA256 tag.
pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut m =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    let full = m.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_roundtrip() {
        for _ in 0..100 {
            let s = new_secret();
            let code = encode_code(&s);
            assert_eq!(code.len(), 24 + 5);
            assert_eq!(decode_code(&code).unwrap(), s);
        }
    }

    #[test]
    fn code_is_forgiving() {
        let s = new_secret();
        let code = encode_code(&s);
        let sloppy = code.to_lowercase().replace('-', " ").replace('O', "0");
        assert_eq!(decode_code(&sloppy).unwrap(), s);
    }

    #[test]
    fn bad_codes_rejected() {
        assert!(decode_code("ABCD").is_err());
        assert!(decode_code("ABCD-EFGH-IJKL-MNOP-QRST-UVW!").is_err());
    }

    #[test]
    fn keys_differ_per_secret() {
        let a = Keys::derive(&new_secret());
        let b = Keys::derive(&new_secret());
        assert_ne!(a.psk, b.psk);
        assert_ne!(a.psk, a.discovery);
    }
}
