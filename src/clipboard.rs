//! Local clipboard access.
//!
//! All clipboard work happens on one dedicated OS thread: some platform
//! clipboard handles are not thread-safe, and on X11/Wayland the owning
//! object must stay alive to keep serving the text we pasted.

use anyhow::Result;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

use crate::proto::MAX_TEXT_BYTES;

pub trait Backend {
    /// Cheap pre-check: could the clipboard have changed since the last call?
    fn maybe_changed(&mut self) -> bool {
        true
    }
    /// `Ok(None)` means there is no text to share (empty, an image, or content
    /// a password manager marked private). `Err` is a transient failure.
    fn get_text(&mut self) -> Result<Option<String>>;
    fn set_text(&mut self, text: &str) -> Result<()>;
}

pub type BackendFactory = Box<dyn FnOnce() -> Result<Box<dyn Backend>> + Send>;

/// Start the clipboard thread.
///
/// Text received on `apply` is written to the clipboard. Text the user
/// copies is sent on `changes`. Text that was already on the clipboard at
/// startup is not sent, since only new copies should propagate.
pub fn spawn(
    factory: BackendFactory,
    apply: Receiver<String>,
    changes: UnboundedSender<String>,
    poll: Duration,
) -> Result<()> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("clipboard".into())
        .spawn(move || {
            let mut cb = match factory() {
                Ok(cb) => {
                    let _ = ready_tx.send(Ok(()));
                    cb
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            watch(cb.as_mut(), apply, changes, poll);
        })?;
    ready_rx.recv()?
}

fn watch(
    cb: &mut dyn Backend,
    apply: Receiver<String>,
    changes: UnboundedSender<String>,
    poll: Duration,
) {
    cb.maybe_changed();
    let mut last = cb.get_text().ok().flatten();
    loop {
        match apply.recv_timeout(poll) {
            Ok(text) => {
                let text = native_line_endings(&text);
                if last.as_deref() != Some(&text) {
                    match cb.set_text(&text) {
                        Ok(()) => {
                            // Remember what the platform reports back so we don't echo it.
                            cb.maybe_changed();
                            last = cb.get_text().ok().flatten().or(Some(text));
                        }
                        Err(e) => log::warn!("could not write to clipboard: {e:#}"),
                    }
                }
                continue;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }

        if !cb.maybe_changed() {
            continue;
        }
        match cb.get_text() {
            Ok(Some(text)) => {
                if last.as_deref() == Some(&text) {
                    continue;
                }
                last = Some(text.clone());
                if text.len() > MAX_TEXT_BYTES {
                    log::warn!(
                        "copied text is {} MB, too large to share",
                        text.len() / 1_000_000
                    );
                    continue;
                }
                if changes.send(text).is_err() {
                    return;
                }
            }
            Ok(None) => last = None,
            Err(e) => log::debug!("clipboard read failed (will retry): {e:#}"),
        }
    }
}

/// Convert text from a peer to this platform's line endings.
pub fn native_line_endings(s: &str) -> String {
    let lf = s.replace("\r\n", "\n");
    if cfg!(windows) {
        lf.replace('\n', "\r\n")
    } else {
        lf
    }
}

/// The real system clipboard.
pub fn system() -> BackendFactory {
    Box::new(|| Ok(Box::new(SystemClipboard::new()?) as Box<dyn Backend>))
}

struct SystemClipboard {
    cb: arboard::Clipboard,
    #[cfg(windows)]
    win: win::Watcher,
}

impl SystemClipboard {
    fn new() -> Result<Self> {
        Ok(SystemClipboard {
            cb: arboard::Clipboard::new()?,
            #[cfg(windows)]
            win: win::Watcher::new(),
        })
    }
}

impl Backend for SystemClipboard {
    fn maybe_changed(&mut self) -> bool {
        #[cfg(windows)]
        return self.win.changed();
        #[cfg(not(windows))]
        true
    }

    fn get_text(&mut self) -> Result<Option<String>> {
        #[cfg(windows)]
        if self.win.is_private() {
            log::debug!("skipping clipboard content marked private (password manager)");
            return Ok(None);
        }
        match self.cb.get_text() {
            Ok(t) if t.is_empty() => Ok(None),
            Ok(t) => Ok(Some(t)),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => {
                #[cfg(windows)]
                self.win.force_recheck();
                Err(e.into())
            }
        }
    }

    fn set_text(&mut self, text: &str) -> Result<()> {
        self.cb.set_text(text)?;
        Ok(())
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::DataExchange::{
        GetClipboardSequenceNumber, IsClipboardFormatAvailable, RegisterClipboardFormatW,
    };

    /// Uses the clipboard sequence number so polling costs almost nothing,
    /// and honours the formats password managers use to mark secrets.
    pub struct Watcher {
        seq: Option<u32>,
        private_formats: Vec<u32>,
    }

    impl Watcher {
        pub fn new() -> Self {
            let private_formats = [
                "ExcludeClipboardContentFromMonitorProcessing",
                "Clipboard Viewer Ignore",
            ]
            .iter()
            .map(|name| {
                let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                unsafe { RegisterClipboardFormatW(wide.as_ptr()) }
            })
            .filter(|&f| f != 0)
            .collect();
            Watcher {
                seq: None,
                private_formats,
            }
        }

        pub fn changed(&mut self) -> bool {
            let seq = unsafe { GetClipboardSequenceNumber() };
            let changed = self.seq != Some(seq);
            self.seq = Some(seq);
            changed
        }

        pub fn force_recheck(&mut self) {
            self.seq = None;
        }

        pub fn is_private(&self) -> bool {
            self.private_formats
                .iter()
                .any(|&f| unsafe { IsClipboardFormatAvailable(f) } != 0)
        }
    }
}

/// In-memory clipboard, for tests.
#[derive(Clone, Default)]
pub struct MemoryClipboard(pub Arc<Mutex<Option<String>>>);

impl MemoryClipboard {
    pub fn get(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    pub fn set(&self, text: &str) {
        *self.0.lock().unwrap() = Some(text.to_string());
    }
    pub fn factory(&self) -> BackendFactory {
        let me = self.clone();
        Box::new(move || Ok(Box::new(me) as Box<dyn Backend>))
    }
}

impl Backend for MemoryClipboard {
    fn get_text(&mut self) -> Result<Option<String>> {
        Ok(self.get())
    }
    fn set_text(&mut self, text: &str) -> Result<()> {
        self.set(text);
        Ok(())
    }
}
