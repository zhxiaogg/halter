//! `halter` — the CLI entry point.
//!
//! `halter serve --config <file>` starts the reverse proxy + admin API from a config
//! file. `halter mint --admin-url <url> --policy <file> --ttl <secs>` calls a running
//! server's admin API to issue a launch token bound to that policy (handy for manual
//! testing; in production the orchestrator calls the admin API directly).

mod config;

use clap::{Parser, Subcommand};
use config::{Config, OutboundConfig};
use control::{ControlPlane, InMemoryCredentials, Secret, TracingAudit};
use gateway::{Catalog, Extract, Flavor, Gateway, Outbound, Protocol, Service, ServiceRouter};
use models::control::{MintRequest, MintResponse};
use models::policy::Policy;
use std::collections::HashMap;
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
    /// Mint a launch token bound to a policy file, via a running server's admin API.
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
    /// Path to a JSON policy document to bind the token to.
    #[arg(long)]
    policy: std::path::PathBuf,
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
    for (key, targets) in &cfg.tenants {
        control.tenants.insert(key.clone(), targets.iter().cloned());
    }
    let services: Vec<Service> = cfg
        .services
        .iter()
        .map(|s| Service {
            name: s.name.clone(),
            host: s.host.clone(),
            upstream_base: s.upstream_base.clone(),
            flavor: Flavor::parse(s.flavor.as_deref()),
            outbound: match &s.outbound {
                OutboundConfig::Passthrough => Outbound::Passthrough,
                OutboundConfig::Bearer(id) => Outbound::Bearer {
                    credential: id.clone(),
                },
                OutboundConfig::Header { name, credential } => Outbound::Header {
                    name: name.clone(),
                    credential: credential.clone(),
                },
                OutboundConfig::Sigv4 {
                    credential,
                    access_key_id,
                    region,
                    service,
                } => Outbound::SigV4 {
                    credential: credential.clone(),
                    access_key_id: access_key_id.clone(),
                    region: region.clone(),
                    service: service.clone(),
                },
            },
            address: s.consumer_address.clone().unwrap_or_default(),
            extract: Extract {
                protocol: Protocol::parse(s.protocol.as_deref()),
                path_template: s.path_template.clone(),
            },
        })
        .collect();
    tracing::info!(
        credentials = cfg.credentials.len(),
        services = services.len(),
        "loaded config"
    );

    let mut catalogs: HashMap<String, Catalog> = HashMap::new();
    for s in &cfg.services {
        if !s.catalog.is_empty() {
            catalogs.insert(s.name.clone(), Catalog::of(s.catalog.iter().cloned()));
        }
    }
    let gateway = Gateway::new(control, ServiceRouter::new(services)).with_catalogs(catalogs);

    let proxy_addr = cfg.proxy_addr.parse()?;
    let admin_addr = cfg.admin_addr.parse()?;
    gateway::serve(proxy_addr, admin_addr, gateway).await?;
    Ok(())
}

/// Call a running server's admin API to mint a token bound to a policy file, and print
/// the response as JSON.
async fn mint(args: MintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(&args.policy)
        .map_err(|e| format!("read policy {}: {e}", args.policy.display()))?;
    let policy: Policy = serde_json::from_str(&text)
        .map_err(|e| format!("parse policy {}: {e}", args.policy.display()))?;
    let url = format!("{}/mint", args.admin_url.trim_end_matches('/'));
    let body = MintRequest {
        policy,
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
