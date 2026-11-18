//! Diagnostic helper: read or write the system clipboard directly.
//!
//!   cargo run --example clip -- get
//!   cargo run --example clip -- set "some text"

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cb = arboard::Clipboard::new()?;
    match args.first().map(String::as_str) {
        Some("get") => println!("{:?}", cb.get_text()?),
        Some("set") => {
            let text = args.get(1).cloned().unwrap_or_default();
            #[cfg(target_os = "linux")]
            {
                // X11/Wayland clipboards are served by the owning process, so stay
                // alive briefly for clipboard watchers to pick the text up.
                use arboard::SetExtLinux;
                let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
                cb.set().wait_until(until).text(text)?;
            }
            #[cfg(not(target_os = "linux"))]
            cb.set_text(text)?;
        }
        _ => anyhow::bail!("usage: clip get | clip set <text>"),
    }
    Ok(())
}
