//! `halter-agent` — the consumer-side setup CLI.
//!
//! A sandboxed consumer runs one command to configure its stock tools (`gh`/`kubectl`/
//! `aws`/SDKs) to reach upstreams through halter. It fetches a [`ProvisionDoc`] from
//! `/provision` with its halter token and renders native config from it — so the
//! endpoint-override model is automated rather than hand-wired.
//!
//! Phase-2 subcommands: `show` (dump the doc), `env` (shell exports), `status` (human
//! summary), `setup` (write an env file + summary into a target dir). Native per-tool
//! config writers (kubeconfig/aws/git) build on the same rendered doc.

use clap::{Parser, Subcommand};
use models::provision::{ProvisionDoc, ProvisionMode};

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
    /// Write an env file and summary into a directory (the sandbox home).
    Setup(SetupArgs),
}

#[derive(clap::Args)]
struct Common {
    /// Base URL of the halter admin API, e.g. http://127.0.0.1:9091
    #[arg(long)]
    admin_url: String,
    /// The halter token to provision for.
    #[arg(long)]
    token: String,
}

#[derive(clap::Args)]
struct SetupArgs {
    #[command(flatten)]
    common: Common,
    /// Directory to write `halter.env` and `halter-status.txt` into.
    #[arg(long, default_value = ".")]
    dir: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Show(c) => {
            let doc = fetch_provision(&c).await?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        Command::Env(c) => {
            let doc = fetch_provision(&c).await?;
            print!("{}", render_env(&doc));
        }
        Command::Status(c) => {
            let doc = fetch_provision(&c).await?;
            print!("{}", render_status(&doc));
        }
        Command::Setup(args) => {
            let doc = fetch_provision(&args.common).await?;
            std::fs::create_dir_all(&args.dir)?;
            let env_path = args.dir.join("halter.env");
            let status_path = args.dir.join("halter-status.txt");
            std::fs::write(&env_path, render_env(&doc))?;
            std::fs::write(&status_path, render_status(&doc))?;
            println!("wrote {} and {}", env_path.display(), status_path.display());
        }
    }
    Ok(())
}

/// Fetch the provision doc, presenting the token via `X-Halter-Token`.
async fn fetch_provision(c: &Common) -> Result<ProvisionDoc, Box<dyn std::error::Error>> {
    let url = format!("{}/provision", c.admin_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-Halter-Token", &c.token)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(format!("provision failed: HTTP {}", resp.status()).into());
    }
    Ok(resp.json().await?)
}

/// Render shell `export` lines from a provision doc. Pure — unit-tested.
fn render_env(doc: &ProvisionDoc) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# halter-agent env (token expires at {} ms)\n",
        doc.expires_at_ms
    ));
    out.push_str(&format!("export HALTER_TOKEN='{}'\n", doc.halter_token));
    out.push_str("export HALTER_TOKEN_HEADER='X-Halter-Token'\n");
    for s in &doc.services {
        out.push_str(&format!(
            "# service '{}' [{}] {}\n",
            s.target,
            s.flavor,
            mode_hint(&s.mode)
        ));
        if !s.address.is_empty() {
            out.push_str(&format!("#   point your tool at: {}\n", s.address));
        }
    }
    out
}

/// Render a human-readable summary. Pure — unit-tested.
fn render_status(doc: &ProvisionDoc) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "halter token valid until {} ms; {} service(s) reachable:\n",
        doc.expires_at_ms,
        doc.services.len()
    ));
    for s in &doc.services {
        let addr = if s.address.is_empty() {
            "(via halter proxy)".to_string()
        } else {
            s.address.clone()
        };
        out.push_str(&format!(
            "  - {} [{}] {} → {}\n",
            s.target,
            s.flavor,
            mode_hint(&s.mode),
            addr
        ));
    }
    out
}

fn mode_hint(mode: &ProvisionMode) -> &'static str {
    match mode {
        ProvisionMode::Inject => "inject (halter supplies the credential)",
        ProvisionMode::Passthrough => "passthrough (bring your own credential)",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use models::provision::ProvisionService;

    fn doc() -> ProvisionDoc {
        ProvisionDoc {
            halter_token: "tok-abc".into(),
            halter_ca: String::new(),
            expires_at_ms: 12345,
            services: vec![
                ProvisionService {
                    target: "github".into(),
                    flavor: "github".into(),
                    address: "https://gh.halter.local".into(),
                    mode: ProvisionMode::Inject,
                },
                ProvisionService {
                    target: "openai".into(),
                    flavor: "generic".into(),
                    address: String::new(),
                    mode: ProvisionMode::Passthrough,
                },
            ],
        }
    }

    #[test]
    fn env_exports_token_and_lists_services() {
        let env = render_env(&doc());
        assert!(env.contains("export HALTER_TOKEN='tok-abc'"));
        assert!(env.contains("X-Halter-Token"));
        assert!(env.contains("service 'github'"));
        assert!(env.contains("https://gh.halter.local"));
        assert!(env.contains("service 'openai'"));
    }

    #[test]
    fn status_describes_modes() {
        let status = render_status(&doc());
        assert!(status.contains("2 service(s) reachable"));
        assert!(status.contains("github"));
        assert!(status.contains("inject"));
        assert!(status.contains("passthrough"));
    }
}
