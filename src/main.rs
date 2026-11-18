use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use clipshare::config::{self, Config};
use clipshare::{clipboard, crypto, service};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Share your clipboard between computers.
///
/// Run `clipshare init` on one computer, `clipshare pair <CODE>` on the
/// others, then run `clipshare` on each. Whatever you copy last on any
/// of them is ready to paste on all of them.
#[derive(Parser)]
#[command(name = "clipshare", version)]
struct Cli {
    /// Path to the config file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// More logging (-v debug, -vv trace).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new pairing code on this computer.
    Init {
        /// Replace an existing pairing code.
        #[arg(long)]
        force: bool,
    },
    /// Join another computer's group using its pairing code.
    Pair { code: String },
    /// Show this computer's pairing code.
    Code,
    /// Always connect to this address, for networks where automatic
    /// discovery doesn't work (e.g. VPNs or separate subnets).
    AddPeer { address: String },
    /// Start sharing the clipboard (the default).
    Run(RunArgs),
}

#[derive(Args, Default)]
struct RunArgs {
    /// Also connect to this address (host or host:port). Repeatable.
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Port to listen on (TCP and UDP).
    #[arg(long)]
    port: Option<u16>,
    /// Don't use LAN broadcast discovery.
    #[arg(long)]
    no_discovery: bool,
}

fn main() {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_target(false)
        .format_timestamp_secs()
        .init();
    if let Err(e) = real_main(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main(cli: Cli) -> Result<()> {
    let path = match cli.config {
        Some(p) => p,
        None => config::default_path()?,
    };
    match cli.command.unwrap_or(Command::Run(RunArgs::default())) {
        Command::Init { force } => {
            if Config::load(&path)?.is_some() && !force {
                bail!(
                    "already set up ({}). Use `clipshare code` to see the pairing code, or `init --force` to make a new one",
                    path.display()
                );
            }
            let cfg = Config::new(&crypto::new_secret());
            cfg.save(&path)?;
            print_pairing_instructions(&cfg);
        }
        Command::Pair { code } => {
            let secret = crypto::decode_code(&code)?;
            let cfg = match Config::load(&path)? {
                Some(mut c) => {
                    c.pairing_code = crypto::encode_code(&secret);
                    c
                }
                None => Config::new(&secret),
            };
            cfg.save(&path)?;
            println!("Paired. Run `clipshare` on this computer to start sharing.");
        }
        Command::Code => {
            let cfg = load_existing(&path)?;
            print_pairing_instructions(&cfg);
        }
        Command::AddPeer { address } => {
            let mut cfg = load_existing(&path)?;
            if !cfg.peers.contains(&address) {
                cfg.peers.push(address.clone());
                cfg.save(&path)?;
            }
            println!("Will always connect to {address}.");
        }
        Command::Run(args) => run(&path, args)?,
    }
    Ok(())
}

fn run(path: &Path, args: RunArgs) -> Result<()> {
    let cfg = match Config::load(path)? {
        Some(c) => c,
        None => {
            let c = Config::new(&crypto::new_secret());
            c.save(path)?;
            println!("First run: created a new pairing code.");
            print_pairing_instructions(&c);
            println!();
            c
        }
    };
    let port = args.port.unwrap_or(cfg.port);
    let peers = cfg
        .peers
        .iter()
        .chain(&args.peers)
        .map(|p| with_default_port(p, port))
        .collect();
    let opts = service::Options {
        device_id: cfg.device_id.clone(),
        device_name: cfg.device_name.clone(),
        secret: cfg.secret()?,
        port,
        peers,
        discovery: !args.no_discovery,
        poll_interval: Duration::from_millis(250),
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async {
        tokio::select! {
            r = service::run(opts, clipboard::system()) => r,
            _ = tokio::signal::ctrl_c() => {
                log::info!("stopping");
                Ok(())
            }
        }
    })
}

fn load_existing(path: &Path) -> Result<Config> {
    Config::load(path)?.ok_or_else(|| {
        anyhow::anyhow!("not set up yet: run `clipshare init` or `clipshare pair <CODE>`")
    })
}

fn with_default_port(addr: &str, port: u16) -> String {
    let has_port = match addr.rsplit_once(':') {
        Some((host, p)) => p.parse::<u16>().is_ok() && (!host.contains(':') || host.ends_with(']')),
        None => false,
    };
    if has_port {
        addr.to_string()
    } else {
        format!("{addr}:{port}")
    }
}

fn print_pairing_instructions(cfg: &Config) {
    println!("Pairing code: {}", cfg.pairing_code);
    println!(
        "On your other computer run:  clipshare pair {}",
        cfg.pairing_code
    );
}
