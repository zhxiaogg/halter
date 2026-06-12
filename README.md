# hackamore

**JIT, policy-scoped access for untrusted AI agents.**

An agent runs in a sandbox whose only network egress is the hackamore proxy. It is given a
short-lived **hackamore token** — never a real credential. When it calls a configured
service — GitHub, OpenAI, any HTTPS API (via `gh`, `git`, an SDK, or raw HTTP) — hackamore
routes by Host, normalizes the request, evaluates the agent's standing policy, and —
only if allowed — swaps the hackamore token for the **real** upstream credential and
forwards it. The agent never sees a secret, can't exceed its policy, and every decision
is audited.

**Any HTTPS service, any HTTP transport.** Upstreams are a configured allowlist routed
by `Host` (unknown host → denied, fail closed). Responses are **streamed**, so plain
request/response, Server-Sent Events, and long-polls all flow through transparently.

This is the companion to [horsie](../horsie): horsie sandboxes the agent runtime (via
[nono](https://github.com/always-further/nono): Landlock/Seatbelt) and points its egress
at hackamore; hackamore decides what that egress is allowed to do.

## Why a reverse proxy + sandbox, not MITM

The agent is **untrusted** (it may be prompt-injected or go rogue). Two invariants hold:

1. The agent never holds a real upstream credential.
2. The sandbox guarantees hackamore is the *only* reachable destination, so the agent
   cannot bypass policy — whether it uses `gh`, `git`, or `curl`.

Because confinement is the sandbox's job (nono/Seatbelt/Landlock + a netns/nftables
redirect on Linux), hackamore can be a plain **reverse proxy** and skip TLS interception
and CA distribution entirely.

## Architecture

Three planes, with the policy engine deliberately decoupled from the data plane so it
can be reused by any proxy (an Envoy `ext_authz` adapter, a hudsucker MITM, …) later.

```
 sandboxed agent ──(only egress)──▶ hackamore reverse proxy ──▶ any configured HTTPS service
   gh / git / sdk / curl             │  route by Host → service        (GitHub, OpenAI, …)
   Authorization: <hackamore token>     │  normalize → Action
                                     │  policy::decide(Action) → Verdict
                                     │  inject real credential, strip hackamore token
                                     │  stream response (HTTP / SSE)
                                     ▼
                          audit every decision
```

| Crate | Role |
|-------|------|
| `models` | fluorite-generated contract types: `Action`, `Verdict`, `Policy`, audit + mint wire types |
| `policy` | the **reusable engine** — pure `decide(&Action, &Policy) -> Verdict`, no I/O |
| `control` | control plane: agent→policy registry, token minting, credential vault, audit sink |
| `gateway` | data plane: Host router + service allowlist, request→`Action` normalizer (generic + flavors), decision/enforcement core, streaming reverse proxy |
| `cli` | the `hackamore` binary: `serve` + `mint` |
| `tests` | full-stack e2e tests (mock GitHub upstream + live server) |

The `Action`/`Verdict` contract is the portability boundary: the engine never sees HTTP,
only a normalized `Action`, so a future K8s or Envoy adapter reuses it unchanged.

## Policy model

A **token is minted from a policy document** (there is no agent identity). Rules are
evaluated **first-match-wins**, **default-deny**. `verb` is an open tagged union — a CRUD
arm for RESTful services, a named-action arm (`{"type":"Action","value":{"id":"…"}}`) for
RPC services:

```json
{ "effect": "Allow",
  "matches": {
    "verbs": [ { "type": "Crud", "value": { "kind": "Create" } } ],
    "resources": ["repos/*/*/pulls"],
    "conditions": [ { "type": "Equals", "value": { "field": "base", "value": "develop" } } ]
  } }
```

That rule means: *may open pull requests in any repo, but only against the `develop`
base branch* — finer-grained than GitHub's native permissions. **Credentials are not
named in the policy**: each service instance owns its credential and outbound stance
(`passthrough` to forward the consumer's own credential, or `{ "inject": "<id>" }` to swap
in the real one).

## Quickstart

```bash
make build
# edit examples/config.json: set a real credential and your agents' policies
make run                      # serves proxy on :9090, admin API on :9091

# mint a launch token from a policy document (the orchestrator does this at launch)
cargo run -p cli --bin hackamore -- mint --admin-url http://127.0.0.1:9091 \
  --policy examples/policy.reviewer-bot.json --ttl 3600

# the consumer then points gh/git at the proxy and presents the token
GH_HOST=127.0.0.1:9090 GITHUB_TOKEN=<minted-token> gh ...
```

## Development

```bash
make check     # cargo fmt --check + clippy -D warnings + test  (the CI gate)
```

Production code denies `unwrap`/`expect`/`panic`/wildcard match arms; see `CLAUDE.md`
for the full design philosophy and fluorite conventions.

## License

MIT.
