# clipshare

Share your clipboard between computers. Copy on one machine, paste on the
other — whichever machine copied last wins. Windows and Linux (X11 and
Wayland), text only for now, peer-to-peer with no server or account.

## Quick start

On the first computer:

```
clipshare init
```

This prints a pairing code like `SEU4-YN57-YFQY-XVXM-MEYH-7E4D`. On the other
computer:

```
clipshare pair SEU4-YN57-YFQY-XVXM-MEYH-7E4D
```

(Case, spaces and dashes don't matter.) Then run `clipshare` on both. They find
each other on the local network automatically, usually within a few seconds.

If automatic discovery doesn't work (VPN, different subnets, broadcast blocked):

```
clipshare add-peer 192.168.1.20      # remembered in config
clipshare run --peer 192.168.1.20    # just this run
```

Only one side needs to know the other's address.

### Commands

| Command | |
|---|---|
| `clipshare` / `clipshare run` | Start sharing (`--peer`, `--port`, `--no-discovery`, `-v`) |
| `clipshare init` | Create a new pairing code |
| `clipshare pair <CODE>` | Join a group using another device's code |
| `clipshare code` | Show the pairing code |
| `clipshare add-peer <HOST[:PORT]>` | Always connect to this address |

Config lives in `%APPDATA%\clipshare\config.json` (Windows) or
`~/.config/clipshare/config.json` (Linux, mode 0600). Override with `--config`.

### Firewall

clipshare uses **TCP and UDP port 29873**. Windows asks to allow it the first
time it runs — allow it on private networks. On Linux with `ufw`:
`sudo ufw allow 29873`.

## How it works

- **Clipboard watching.** A dedicated thread polls every 250 ms. On Windows it
  checks the clipboard sequence number first, so idle polling is essentially
  free. Linux uses Wayland's data-control protocol where the compositor
  supports it (KDE, Sway, Hyprland) and falls back to X11 otherwise (GNOME runs
  X11 apps through XWayland, which shares the clipboard).
- **Password managers.** On Windows, clipboard content flagged with
  `ExcludeClipboardContentFromMonitorProcessing` (KeePass, 1Password, etc.)
  is never sent.
- **Security.** Devices connect over TCP using the
  [Noise](https://noiseprotocol.org/) `NNpsk0` handshake (the framework
  WireGuard is built on) keyed from the pairing code: ChaCha20-Poly1305
  encryption, forward secrecy, and devices without the code can't connect or
  read anything. LAN discovery packets are HMAC-authenticated with a separate
  key derived from the code.
- **Last copy wins.** Each copy carries a Lamport clock value plus the device
  id. Every machine orders copies the same way, so simultaneous copies
  converge on the same result without relying on synchronized system clocks,
  and text never bounces back and forth.
- **Catch-up.** When two devices connect, each sends its latest copy; the
  newer one wins. Copies are relayed, so three or more devices converge even
  without a direct connection between every pair.
- Line endings are converted to the native form (CRLF on Windows, LF on Linux).
  Text up to 16 MB.

## Development

```
cargo test                        # unit + end-to-end tests (in-memory clipboards)
cargo run -- -v                   # run with debug logging
cargo run --example clip -- get   # read the system clipboard directly
.\build-release.ps1               # Windows + static Linux binaries into dist\
```

Windows builds use the `x86_64-pc-windows-gnu` toolchain with MinGW (WinLibs)
on PATH. Linux builds target `x86_64-unknown-linux-musl` for a fully static
binary that runs on any distro.

Source layout: `clipboard.rs` (OS clipboard thread), `node.rs` (sync state,
connections), `proto.rs` (Noise + framing), `discovery.rs` (UDP broadcast),
`crypto.rs` (pairing codes, key derivation), `service.rs` (wiring), `main.rs`
(CLI).

## Roadmap

- Tray icon + autostart (Windows startup entry, systemd user unit / XDG autostart)
- Honour `x-kde-passwordManagerHint` on Linux (KeePassXC)
- Event-driven change detection instead of polling (Windows clipboard listener,
  X11 XFixes, `ext-data-control` watch)
- Per-device keys (Noise `XX`) so a single device can be removed from a group
- Relay server for machines on different networks
- Images and files
- macOS
