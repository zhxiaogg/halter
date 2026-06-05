//! `halter` — the CLI entry point.
//!
//! `halter serve --config <file>` starts the reverse proxy + admin API from a config
//! file. `halter mint --admin-url <url> --agent <id> --ttl <secs>` calls a running
//! server's admin API to issue a launch token (handy for manual testing; in production
//! the orchestrator calls the admin API directly).

mod config;

use clap::{Parser, Subcommand};
use config::Config;
use control::{ControlPlane, InMemoryCredentials, Secret, TracingAudit};
use gateway::{Flavor, Gateway, Service, ServiceRouter};
use models::control::{MintRequest, MintResponse};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "halter",
    about = "JIT, policy-scoped access for untrusted agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the reverse proxy and admin API.
    Serve(ServeArgs),
    /// Mint a launch token for an agent via a running server's admin API.
    Mint(MintArgs),
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Path to the JSON config file.
    #[arg(long)]
    config: std::path::PathBuf,
}

#[derive(clap::Args)]
struct MintArgs {
    /// Base URL of the admin API, e.g. http://127.0.0.1:9091
    #[arg(long)]
    admin_url: String,
    /// Agent id to mint a token for.
    #[arg(long)]
    agent: String,
    /// Token lifetime in seconds.
    #[arg(long, default_value_t = 3600)]
    ttl: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Mint(args) => mint(args).await,
    }
}

/// Build the control plane and gateway from config, then serve until shutdown.
async fn serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(&args.config)?;

    let credentials = Arc::new(InMemoryCredentials::new());
    for (id, secret) in &cfg.credentials {
        credentials.insert(id.clone(), Secret::new(secret.clone()));
    }
    let control = Arc::new(ControlPlane::new(credentials, Arc::new(TracingAudit)));
    for agent in &cfg.agents {
        control
            .registry
            .register(agent.id.clone(), agent.policy.clone());
    }
    let services: Vec<Service> = cfg
        .services
        .iter()
        .map(|s| Service {
            name: s.name.clone(),
            host: s.host.clone(),
            upstream_base: s.upstream_base.clone(),
            flavor: Flavor::parse(s.flavor.as_deref()),
        })
        .collect();
    tracing::info!(
        agents = cfg.agents.len(),
        credentials = cfg.credentials.len(),
        services = services.len(),
        "loaded config"
    );

    let gateway = Gateway::new(control, ServiceRouter::new(services));

    let proxy_addr = cfg.proxy_addr.parse()?;
    let admin_addr = cfg.admin_addr.parse()?;
    gateway::serve(proxy_addr, admin_addr, gateway).await?;
    Ok(())
}

/// Call a running server's admin API to mint a token, and print the response as JSON.
async fn mint(args: MintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/mint", args.admin_url.trim_end_matches('/'));
    let body = MintRequest {
        agent: args.agent,
        ttl_seconds: args.ttl,
    };
    let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
    if !resp.status().is_success() {
        return Err(format!("mint failed: HTTP {}", resp.status()).into());
    }
    let minted: MintResponse = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&minted)?);
    Ok(())
}
