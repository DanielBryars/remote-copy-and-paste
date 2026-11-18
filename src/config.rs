//! Persistent per-device configuration.

use crate::crypto::{self, Secret};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Deliberately below the 32768+ ephemeral ranges used by Linux and by WSL's
/// mirrored networking mode, which reserves them on the Windows host.
pub const DEFAULT_PORT: u16 = 29873;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    /// Random, stable identifier for this device (hex).
    pub device_id: String,
    /// Friendly name shown to peers.
    pub device_name: String,
    /// Shared secret for the group of devices, as a pairing code.
    pub pairing_code: String,
    /// TCP port to listen on (UDP discovery uses the same number).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Extra peers to always connect to (`host` or `host:port`), for networks
    /// where LAN broadcast discovery does not work.
    #[serde(default)]
    pub peers: Vec<String>,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

pub fn default_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("CLIPSHARE_CONFIG") {
        return Ok(p.into());
    }
    let dir = dirs::config_dir().context("could not determine the user config directory")?;
    Ok(dir.join("clipshare").join("config.json"))
}

impl Config {
    pub fn new(secret: &Secret) -> Self {
        Config {
            device_id: hex::encode(rand::random::<[u8; 16]>()),
            device_name: gethostname::gethostname().to_string_lossy().into_owned(),
            pairing_code: crypto::encode_code(secret),
            port: DEFAULT_PORT,
            peers: Vec::new(),
        }
    }

    pub fn secret(&self) -> Result<Secret> {
        crypto::decode_code(&self.pairing_code).context("pairing code in config file is invalid")
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(Some(
                serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        write_private(path, json.as_bytes()).with_context(|| format!("writing {}", path.display()))
    }
}

/// The config holds the group secret, so keep it readable only by the user.
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // %APPDATA% is already private to the user on Windows.
    std::fs::write(path, data)
}
