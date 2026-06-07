//! Consumer-side provisioning: fetch the [`ProvisionDoc`] from halter's `/provision` and
//! render it into native tool config. [`write_configs`] writes everything **under a
//! caller-supplied home directory** — nothing outside it is touched, so a sandbox (or a
//! test) can configure stock tools without polluting the host's real `~/.kube`, `~/.aws`,
//! or git config.

use models::provision::{ProvisionAuth, ProvisionDoc, ProvisionMode, ProvisionService};
use std::path::{Path, PathBuf};

/// Fetch the provision doc, presenting the token via `X-Halter-Token`.
pub async fn fetch_provision(admin_url: &str, token: &str) -> Result<ProvisionDoc, String> {
    let url = format!("{}/provision", admin_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-Halter-Token", token)
        .send()
        .await
        .map_err(|e| format!("provision request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("provision failed: HTTP {}", resp.status()));
    }
    resp.json()
        .await
        .map_err(|e| format!("provision decode failed: {e}"))
}

/// Render shell `export` lines from a provision doc.
pub fn render_env(doc: &ProvisionDoc) -> String {
    let mut out = format!(
        "# halter-agent env (token expires at {} ms)\nexport HALTER_TOKEN='{}'\n\
         export HALTER_TOKEN_HEADER='X-Halter-Token'\n",
        doc.expires_at_ms, doc.halter_token
    );
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

/// Render a human-readable summary.
pub fn render_status(doc: &ProvisionDoc) -> String {
    let mut out = format!(
        "halter token valid until {} ms; {} service(s) reachable:\n",
        doc.expires_at_ms,
        doc.services.len()
    );
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

/// Write native tool config for every service into `home` (an isolated directory).
/// Returns the files written. Always writes `halter.env`; per service it writes a
/// kubeconfig (k8s), git credentials (github), or an AWS profile (SigV4).
pub fn write_configs(home: &Path, doc: &ProvisionDoc) -> std::io::Result<Vec<PathBuf>> {
    let mut written = vec![write(&home.join("halter.env"), &render_env(doc))?];
    for s in &doc.services {
        match s.flavor.as_str() {
            "github" => written.push(write_github(home, s)?),
            "k8s" => written.push(write_kubeconfig(home, s)?),
            _ => {}
        }
        if let ProvisionAuth::SigV4(a) = &s.auth {
            written.extend(write_aws(home, s, a)?);
        }
    }
    Ok(written)
}

/// The bearer (halter) token a service presents, if its auth is bearer.
fn bearer_token(s: &ProvisionService) -> Option<&str> {
    match &s.auth {
        ProvisionAuth::Bearer(b) => Some(&b.token),
        ProvisionAuth::SigV4(_) => None,
    }
}

fn endpoint(s: &ProvisionService) -> &str {
    if s.address.is_empty() {
        "https://halter.local"
    } else {
        &s.address
    }
}

/// Write a kubeconfig with a static token (no `exec` plugin) pointing at halter.
fn write_kubeconfig(home: &Path, s: &ProvisionService) -> std::io::Result<PathBuf> {
    let token = bearer_token(s).unwrap_or_default();
    let name = &s.target;
    let body = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: {name}\n\
         clusters:\n- name: {name}\n  cluster:\n    server: {server}\n\
         contexts:\n- name: {name}\n  context:\n    cluster: {name}\n    user: {name}\n\
         users:\n- name: {name}\n  user:\n    token: {token}\n",
        server = endpoint(s),
    );
    write(&home.join(".kube").join("config"), &body)
}

/// Write git credentials (store helper) so `git`/`gh` use the halter token.
fn write_github(home: &Path, s: &ProvisionService) -> std::io::Result<PathBuf> {
    let token = bearer_token(s).unwrap_or_default();
    // `git`'s store-helper format. The host comes from the consumer-facing address.
    let host = endpoint(s)
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let body = format!("https://x-access-token:{token}@{host}\n");
    write(&home.join(".git-credentials"), &body)
}

/// Write an AWS profile (dummy credential + halter endpoint) for the `aws` CLI / SDKs:
/// `~/.aws/credentials` (the dummy key pair) and `~/.aws/config` (region + endpoint).
fn write_aws(
    home: &Path,
    s: &ProvisionService,
    a: &models::provision::SigV4Auth,
) -> std::io::Result<Vec<PathBuf>> {
    let creds = format!(
        "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n",
        a.access_key_id, a.secret_access_key
    );
    let config = format!(
        "[default]\nregion = {}\nendpoint_url = {}\n",
        a.region,
        endpoint(s)
    );
    Ok(vec![
        write(&home.join(".aws").join("credentials"), &creds)?,
        write(&home.join(".aws").join("config"), &config)?,
    ])
}

/// Write `contents` to `path`, creating parent directories. Returns `path`.
fn write(path: &Path, contents: &str) -> std::io::Result<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use models::provision::{BearerAuth, SigV4Auth};

    fn svc(
        target: &str,
        flavor: &str,
        auth: ProvisionAuth,
        mode: ProvisionMode,
    ) -> ProvisionService {
        ProvisionService {
            target: target.into(),
            flavor: flavor.into(),
            address: String::new(),
            mode,
            auth,
        }
    }

    fn doc() -> ProvisionDoc {
        ProvisionDoc {
            halter_token: "tok-abc".into(),
            halter_ca: String::new(),
            expires_at_ms: 12345,
            services: vec![
                svc(
                    "github",
                    "github",
                    ProvisionAuth::Bearer(BearerAuth {
                        token: "tok-abc".into(),
                    }),
                    ProvisionMode::Inject,
                ),
                svc(
                    "eks-prod",
                    "k8s",
                    ProvisionAuth::Bearer(BearerAuth {
                        token: "tok-abc".into(),
                    }),
                    ProvisionMode::Inject,
                ),
                svc(
                    "aws-acct-a",
                    "generic",
                    ProvisionAuth::SigV4(SigV4Auth {
                        access_key_id: "AKIADUMMY".into(),
                        secret_access_key: "dummy-secret".into(),
                        region: "us-east-1".into(),
                    }),
                    ProvisionMode::Inject,
                ),
            ],
        }
    }

    #[test]
    fn env_exports_token_and_lists_services() {
        let env = render_env(&doc());
        assert!(env.contains("export HALTER_TOKEN='tok-abc'"));
        assert!(env.contains("service 'github'"));
        assert!(env.contains("service 'aws-acct-a'"));
    }

    #[test]
    fn write_configs_writes_native_files_into_home() {
        let dir = std::env::temp_dir().join(format!("halter-agent-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let written = write_configs(&dir, &doc()).unwrap();
        assert!(written.iter().any(|p| p.ends_with("halter.env")));

        let kube = std::fs::read_to_string(dir.join(".kube").join("config")).unwrap();
        assert!(kube.contains("token: tok-abc"));
        assert!(kube.contains("kind: Config"));

        let creds = std::fs::read_to_string(dir.join(".aws").join("credentials")).unwrap();
        assert!(creds.contains("aws_access_key_id = AKIADUMMY"));
        assert!(creds.contains("aws_secret_access_key = dummy-secret"));

        let git = std::fs::read_to_string(dir.join(".git-credentials")).unwrap();
        assert!(git.contains("x-access-token:tok-abc@"));

        // Everything stayed under the isolated home.
        assert!(written.iter().all(|p| p.starts_with(&dir)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
