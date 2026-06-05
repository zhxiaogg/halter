# Examples

## `config.json`

A worked halter server config:

- **proxy_addr / admin_addr** — the agent-facing reverse proxy and the
  operator/orchestrator admin API. Bind the admin API to localhost only.
- **route** — the single upstream (v1): GitHub's API.
- **credentials** — logical id → real secret. Provision a real **GitHub App
  installation token** (short-lived, repo-scoped, revocable) and put it here; it never
  leaves halter. The placeholder value must be replaced before the proxy can forward.
- **agents** — each agent's id and its standing policy.

The example `reviewer-bot` may:

1. **read** anything under `octocat`'s repos (`Read` on `repos/octocat/*/**`), and
2. **open pull requests** in `octocat`'s repos, but only against the `develop` base
   branch.

Everything else is denied (default-deny).

Run it:

```bash
cargo run -p cli --bin halter -- serve --config examples/config.json
```

Then mint a token and drive it as a sandboxed agent would:

```bash
TOKEN=$(cargo run -q -p cli --bin halter -- \
  mint --admin-url http://127.0.0.1:9091 --agent reviewer-bot --ttl 3600 \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

# Allowed (read):
curl -s http://127.0.0.1:9090/repos/octocat/hello/contents/README.md \
  -H "Authorization: Bearer $TOKEN"

# Denied (create PR to main → 403):
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:9090/repos/octocat/hello/pulls \
  -H "Authorization: Bearer $TOKEN" -d '{"base":"main"}'
```
