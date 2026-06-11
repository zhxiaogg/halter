//! `halter-agent` — the consumer-side setup CLI (thin wrapper over [`cli::agent`]).
//!
//! A sandboxed consumer runs one command to configure its stock tools (`gh`/`kubectl`/
//! `aws`/SDKs) to reach upstreams through halter. It fetches a provision doc from the
//! reserved `/.halter/provision` path on the proxy listener (`--halter-url`) — the only
//! address a sandbox can reach — and renders native config from it. `--admin-url` is a
//! back-compat alias that fetches the legacy `/provision` from the admin API instead.

use clap::{Parser, Subcommand};
use cli::agent::ProvisionEndpoint;

#[derive(Parser)]
#[command(name = "halter-agent", about = "Configure stock tools to reach halter")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch and pretty-print the raw provision doc.
    Show(Common),
    /// Print shell `export` lines (for `eval "$(halter-agent env ...)"`).
    Env(Common),
    /// Print a human-readable summary of what the token can reach.
    Status(Common),
    /// Write native tool config (kubeconfig / ~/.aws / git) into a home directory.
    Setup(SetupArgs),
    /// Remove the native tool config halter previously wrote (per its manifest).
    Teardown(TeardownArgs),
}

#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("halter").required(true).multiple(false)))]
struct Common {
    /// Base URL of the halter proxy listener, e.g. http://127.0.0.1:9090 (provision is
    /// fetched from the reserved /.halter/provision path).
    #[arg(long, group = "halter")]
    halter_url: Option<String>,
    /// Back-compat alias: base URL of the halter admin API, e.g. http://127.0.0.1:9091
    /// (fetches the legacy /provision path).
    #[arg(long, group = "halter")]
    admin_url: Option<String>,
    /// The halter token to provision for.
    #[arg(long)]
    token: String,
}

impl Common {
    /// Resolve the provision endpoint from the URL flags. The required, single-member
    /// clap group `halter` already enforces exactly-one-of at parse time; this match
    /// validates fail-closed regardless, so a future flag-wiring mistake yields a clear
    /// error rather than a silent pick.
    fn endpoint(&self) -> Result<ProvisionEndpoint, String> {
        match (&self.halter_url, &self.admin_url) {
            (Some(url), None) => Ok(ProvisionEndpoint::Proxy(url.clone())),
            (None, Some(url)) => Ok(ProvisionEndpoint::Admin(url.clone())),
            (None, None) => Err("one of --halter-url or --admin-url is required".to_string()),
            (Some(_), Some(_)) => {
                Err("--halter-url and --admin-url are mutually exclusive".to_string())
            }
        }
    }
}

#[derive(clap::Args)]
struct SetupArgs {
    #[command(flatten)]
    common: Common,
    /// Home directory to write native config into (defaults to $HOME).
    #[arg(long)]
    home: Option<std::path::PathBuf>,
}

#[derive(clap::Args)]
struct TeardownArgs {
    /// Home directory to remove halter-written config from (defaults to $HOME).
    #[arg(long)]
    home: Option<std::path::PathBuf>,
}

/// Resolve a `--home` override or fall back to `$HOME`.
fn resolve_home(
    explicit: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    explicit
        .or_else(|| std::env::var_os("HOME").map(Into::into))
        .ok_or_else(|| "no --home and $HOME is unset".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Show(c) => {
            let doc = cli::agent::fetch_provision(&c.endpoint()?, &c.token).await?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        Command::Env(c) => {
            let doc = cli::agent::fetch_provision(&c.endpoint()?, &c.token).await?;
            print!("{}", cli::agent::render_env(&doc));
        }
        Command::Status(c) => {
            let doc = cli::agent::fetch_provision(&c.endpoint()?, &c.token).await?;
            print!("{}", cli::agent::render_status(&doc));
        }
        Command::Setup(args) => {
            let doc =
                cli::agent::fetch_provision(&args.common.endpoint()?, &args.common.token).await?;
            let home = resolve_home(args.home)?;
            let written = cli::agent::write_configs(&home, &doc)?;
            for p in &written {
                println!("wrote {}", p.display());
            }
        }
        Command::Teardown(args) => {
            let home = resolve_home(args.home)?;
            let removed = cli::agent::teardown(&home)?;
            for p in &removed {
                println!("removed {}", p.display());
            }
        }
    }
    Ok(())
}
