# CLAUDE.md — Vault Agentic Identity Broker

## What This Project Is

A reference implementation for secure AI agent identity and delegated database access. The system ensures that when an AI agent queries a database on behalf of a human, there is cryptographic proof of **which human authorized the action**, **which agent performed it**, and **what permissions were granted** — with a full audit trail.

The core flow: Human (Alice) logs in via Keycloak -> Agent gets SPIFFE identity from SPIRE -> Token Exchange validates both and mints fused delegation JWT -> Agent authenticates to Vault via SPIFFE + fused JWT (two-login pattern) -> Vault Sentinel EGPs enforce policy -> Vault issues dynamic PostgreSQL credentials -> Agent queries database with time-limited, scoped credentials that auto-expire.

See `ARCHITECTURE.md` for detailed component diagrams and `DEMO-STORY.md` for a narrative walkthrough.

## Quick Reference

### Deployment

This project runs in Docker. There are two network modes:

**Host network mode** (required in sandboxed/CI environments like this one):
```bash
docker compose -f docker-compose.host.yml up -d
./scripts/bootstrap.sh --host
docker compose -f docker-compose.host.yml --profile test run --rm test-runner
```

**Bridge network mode** (standard Docker networking):
```bash
docker compose up -d
./scripts/bootstrap.sh
docker compose --profile test run --rm test-runner
```

The bootstrap script is idempotent — it detects already-initialized services and skips them. The test runner validates the deployment (exit code 0 = all tests pass).

### Cleanup

```bash
./scripts/cleanup.sh          # bridge mode
./scripts/cleanup.sh --host   # host mode
```

This removes all containers, volumes, and generated credential files (`.vault-unseal-key`, `.vault-root-token`, `.gateway.env`).

### Running the Demo

```bash
./scripts/demo.sh                      # Device Auth Flow (recommended)
AUTH_MODE=token ./scripts/demo.sh      # Pre-supplied token
AUTH_MODE=password ./scripts/demo.sh   # Password grant (demo only)
```

### Running the AI Agent Manually

After bootstrap, the agent can be invoked directly:
```bash
docker compose -f docker-compose.host.yml exec \
  -e AGENT_MODE=demo ai-agent python agent.py
```

## Architecture at a Glance

9 services across 4 trust boundaries:

| Service | Port | Role |
|---|---|---|
| **Keycloak** | :8080 | Human OIDC identity provider (admin/admin) |
| **SPIRE Server** | :8081 | SPIFFE trust domain root (`demo.local`) |
| **SPIRE Agent** | (socket) | Workload attestation, SVID distribution |
| **SPIRE OIDC** | :8082 | JWKS endpoint for JWT-SVID verification |
| **Vault** | :8200 | Dynamic secrets, JWT auth, Sentinel EGPs, audit logging |
| **Token Exchange** | :8090 | Stateless fused JWT minter (Python, RFC 8693) |
| **AgentGateway** | :9080 (API), :9090 (MCP, host mode) | Rust MCP/A2A proxy with RBAC |
| **PostgreSQL** | :5432 | Target database (appdb, schema: app) |
| **AI Agent** | (no port) | Python agent with sub-agent delegation |

In host mode, AgentGateway MCP listens on **:9090** (not :8080) to avoid conflict with Keycloak.

### Identity Delegation Flow

```
Human (Alice) --[OIDC token]--> Agent --[SPIFFE SVID]--> Token Exchange
  Token Exchange: validate human token (Keycloak userinfo)
                  validate agent identity (SPIFFE JWKS verification)
                  mint fused delegation JWT with nested act{} claim
                  (stateless — no Vault dependency, no credential brokering)
Agent --[SPIFFE JWT]--> Vault (JWT auth login 1: workload identity)
Agent --[fused delegation JWT]--> Vault (JWT auth login 2: delegation token)
  Vault Sentinel EGPs: require-delegation, enforce-scope,
                       enforce-chain-depth, enforce-may-act
Agent --[Vault-issued credentials]--> PostgreSQL (SELECT only, auto-expires)
```

Sub-agents extend the chain via a second RFC 8693 exchange using the parent's delegation token. Max depth: 3. Scope can only narrow, never widen.

## Project Structure

```
docker-compose.yml              # Bridge network orchestration
docker-compose.host.yml         # Host network orchestration (sandboxed/CI)
scripts/
  bootstrap.sh                  # Initialize Vault, SPIRE, configure integrations
  demo.sh                       # Run the full delegation demo
  cleanup.sh                    # Tear down everything
  run-tests.sh                  # Three-phase test orchestrator (offline → wait → E2E)
token-exchange/
  token_exchange.py             # RFC 8693 Token Exchange Service (Python)
  Dockerfile
ai-agent/
  agent.py                      # AI agent with SPIFFE, RFC 8693, sub-agents
  subagents/sql_executor.py     # SQL executor sub-agent
  tests/test_agent.py
  Dockerfile
agentgateway/config/
  gateway.yaml                  # AgentGateway config (bridge mode)
  gateway-host.yaml             # AgentGateway config (host mode, localhost addrs)
spire/
  server/server.conf            # SPIRE server (trust domain: demo.local)
  agent/agent.conf              # SPIRE agent (bridge mode)
  agent/agent-host.conf         # SPIRE agent (host mode, discover_workload_path=false)
  oidc/oidc-discovery-provider.conf  # OIDC JWKS endpoint config
  entries/registration-entries.sh    # SPIRE workload registration script
keycloak/realm/demo-realm.json  # Realm: demo, users: alice/bob, clients, mappers
vault/
  config/vault.hcl              # Vault server config (file storage, no TLS)
  policies/*.hcl                # ACL policies (gateway, ai-agent-db-read, ai-agent-db-readwrite)
sentinel-policies/
  require-delegation.sentinel   # Vault Sentinel EGP: delegation metadata must exist
  enforce-scope.sentinel        # Vault Sentinel EGP: scope matches requested role
  enforce-chain-depth.sentinel  # Vault Sentinel EGP: chain depth <= 3
  enforce-may-act.sentinel      # Vault Sentinel EGP: human authorized this agent
postgres/init/
  00-vault-user.sql             # Vault admin user for dynamic credential management
  01-init.sql                   # Sample schema (orders, customers, products)
tests/
  Dockerfile                    # Test runner container (python:3.12-slim + curl/jq/psql)
  requirements.txt              # Python test dependencies
  config-validation/            # Offline config validation tests (pytest)
  e2e/                          # End-to-end integration tests (bash + pytest)
  test_token_exchange.py        # Token Exchange unit tests
```

## Key Implementation Details

### SPIRE (Host Mode Specifics)

- SPIRE server image runs as **UID 1000:1000**. The compose files include a `spire-init` alpine container that `chown`s the data volume before SPIRE starts.
- The host-mode agent config (`agent-host.conf`) has `discover_workload_path = false` because cross-container `/proc/<PID>/exe` readlink fails due to PID/mount namespace boundaries. UID-based attestation (`unix:uid:N`) still works.
- SPIRE 1.11.0 uses `-x509SVIDTTL` and `-jwtSVIDTTL` flags (not the removed `-ttl` flag).
- The OIDC discovery provider is a distroless image (no shell, no wget, no curl). Its healthcheck is disabled; the bootstrap script verifies it externally via `curl http://localhost:8082/keys`.
- The OIDC provider needs its own SPIRE registration entry (`unix:uid:1000`, SPIFFE ID: `spiffe://demo.local/oidc-provider`).
- The `acme {}` block and `insecure_addr` are mutually exclusive in the OIDC config. For HTTP-only demo, use only `insecure_addr`.

### Bootstrap Script (`scripts/bootstrap.sh`)

The bootstrap runs 10 steps in order:
1. Wait for infrastructure services (Vault, PostgreSQL, Keycloak)
2. Initialize and unseal Vault (1 key share, threshold 1 for demo)
3. Write Vault ACL policies
4. Enable Vault audit logging (file device)
5. Configure Vault database secrets engine (PostgreSQL connection, rotate root creds, create readonly/readwrite roles with 5-min TTL)
6. (Skipped — Token Exchange is now stateless, no Vault token needed)
7. Enable Vault JWT auth method and create JWT auth roles (spiffe-agent, agent-readonly, agent-readwrite)
8. Register SPIRE entries (generate join token, start agent, register workloads including OIDC provider, start OIDC, configure Vault JWT JWKS URL). On Vault Enterprise, load Sentinel EGP policies (Step 8d).
9. Health check (verify Token Exchange, SPIRE OIDC are reachable)
10. Verify setup (test Keycloak auth, Vault dynamic credentials)

**Important ordering**: JWT auth roles (Step 7) are created before SPIRE OIDC starts. The JWKS URL configuration happens in Step 8b after the OIDC provider is running and serving keys.

Credentials saved by bootstrap:
- `.vault-unseal-key` — Vault unseal key (chmod 600)
- `.vault-root-token` — Vault root token (chmod 600)
- `.gateway.env` — Legacy file (may be empty; Token Exchange no longer needs a Vault token)

### Token Exchange Service

- Python service on port 8090 — **stateless fused JWT minter** (no Vault dependency)
- Key endpoints: `POST /v1/token/exchange` (RFC 8693), `POST /v1/delegate` (legacy), `GET /v1/delegation/chain`, `GET /v1/audit`, `GET /health`
- Validates human tokens via Keycloak userinfo endpoint
- Validates agent identity via cryptographic SPIFFE JWT-SVID verification against SPIRE OIDC JWKS
- Signs fused delegation tokens with RS256 (in-memory RSA keypair or loaded from `SIGNING_KEY_PATH`)
- Serves delegation token JWKS at `GET /.well-known/jwks.json`
- Builds delegation tokens with nested `act{}` claims per RFC 8693 Section 4.1
- Supports sub-agent chain extension with scope narrowing and depth limits
- Does NOT broker Vault credentials — agents authenticate to Vault directly
- Fail-closed: rejects requests when Keycloak or SPIRE OIDC are unavailable

### AgentGateway

- Rust-based open-source MCP/A2A proxy ([agentgateway/agentgateway](https://github.com/agentgateway/agentgateway))
- Two configs: `gateway.yaml` (bridge mode, Docker DNS names) and `gateway-host.yaml` (host mode, `127.0.0.1` addresses)
- In host mode, MCP listener is on port **9090** (not 8080, which conflicts with Keycloak)
- OIDC auth via Keycloak, rate limiting (60 req/min), CORS, routes to Token Exchange

### Vault Sentinel EGPs (Enterprise)

- Sentinel Endpoint Governing Policies replace OPA as the policy engine
- Policies are applied to `database/creds/*` with `hard-mandatory` enforcement
- `require-delegation.sentinel` — delegation metadata must exist on requesting entity
- `enforce-scope.sentinel` — delegation scope must match requested credential role
- `enforce-chain-depth.sentinel` — chain depth must be <= 3
- `enforce-may-act.sentinel` — human must have authorized this specific agent
- Entity metadata populated via JWT/SPIFFE auth `claim_mappings` (human_user, agent_identity, delegation_scope, chain_depth, may_act)
- On Vault OSS, Sentinel step is skipped with a warning
- Policies live in `sentinel-policies/` directory

### Vault

- File storage backend (no TLS for demo)
- Database secrets engine with PostgreSQL plugin
- Dynamic roles: `ai-agent-readonly` (SELECT on schema app, 5-min TTL), `ai-agent-readwrite` (CRUD on schema app, 5-min TTL)
- JWT auth method backed by SPIRE OIDC JWKS endpoint
- Root credentials rotated after initial config (original password invalidated)

### Keycloak

- Realm: `demo`
- Users: `alice` (password: `alice-demo-password`, groups: data-analysts, trading-team), `bob` (password: `bob-demo-password`, group: engineering)
- Clients: `demo-cli` (public, supports device auth + direct access), `ai-agent-service` (confidential, token exchange enabled)
- Custom protocol mappers: `groups` claim, `may_act` claim (hardcoded for demo)
- Health on management port 9000, realm API on port 8080

### PostgreSQL

- Database: `appdb`, Schema: `app`
- Tables: `orders`, `customers`, `products`; View: `order_summary`
- Vault admin user (`vault_admin`) created in `00-vault-user.sql` with `CREATEROLE` privilege
- Logging: `log_statement=all`, `log_connections=on`, `log_disconnections=on`

## Testing

### Run All Tests via Docker (Recommended)

The `test-runner` service runs the full test suite (offline + E2E) in a single command. It uses the `test` profile so it won't start during normal `docker compose up`.

```bash
# Host network mode (after deploy + bootstrap):
docker compose -f docker-compose.host.yml --profile test run --rm test-runner

# Bridge network mode:
docker compose --profile test run --rm test-runner

# CI mode (auto-exit on completion):
docker compose -f docker-compose.host.yml --profile test up --abort-on-container-exit test-runner
```

The test runner executes three phases:
1. **Offline** — Config validation, token exchange unit tests, agent unit tests (no services needed)
2. **Wait** — Polls for bootstrap completion (120s timeout)
3. **E2E** — Full integration tests (only if bootstrap detected)

Exit code 0 means all suites passed.

### Run Individual Test Suites Manually

#### Config Validation Tests (Offline)

```bash
cd /workspace && python -m pytest tests/config-validation/ -v
```

These validate configuration files without running services: Keycloak realm JSON, Sentinel policies, SPIRE configs, Vault policies, Docker Compose structure, PostgreSQL schema.

#### End-to-End Tests (Require Running Services)

```bash
# After bootstrap:
bash tests/e2e/test_e2e_flow.sh
bash tests/e2e/test_token_exchange_e2e.sh
bash tests/e2e/test_native_e2e.sh
```

#### Token Exchange Unit Tests

```bash
cd /workspace && python -m pytest tests/test_token_exchange.py -v
```

#### AI Agent Tests

```bash
cd /workspace && python -m pytest ai-agent/tests/test_agent.py -v
```

## Common Issues and Fixes

| Symptom | Root Cause | Fix |
|---|---|---|
| SPIRE server crashes with "unable to open database file" | Volume owned by root, SPIRE runs as UID 1000 | The `spire-init` container handles this; if persists, `docker volume rm` and redeploy |
| SPIRE entries silently fail to register | Using `-ttl` flag (removed in SPIRE 1.11) | Use `-x509SVIDTTL` and `-jwtSVIDTTL` instead |
| OIDC provider crashes with "insecure_addr and acme mutually exclusive" | Config has both `acme {}` block and `insecure_addr` | Remove the `acme {}` block for HTTP-only mode |
| SPIRE agent "no identity issued" for OIDC provider | Missing SPIRE registration entry for UID 1000 | Register entry with `-selector unix:uid:1000 -spiffeID spiffe://demo.local/oidc-provider` |
| SPIRE agent "readlink /proc/PID/exe: permission denied" | `discover_workload_path = true` fails across container namespaces | Set `discover_workload_path = false` in `agent-host.conf` |
| AgentGateway crashes with "failed to load JWKS: fetch keycloak:8080" | Host mode uses Docker DNS names that don't resolve | Use `gateway-host.yaml` with `127.0.0.1` addresses |
| AgentGateway port conflict with Keycloak on 8080 | Both bind port 8080 in host mode | Host-mode gateway uses port 9090 for MCP listener |
| SPIRE OIDC healthcheck always unhealthy | Distroless image has no wget/curl/shell | Healthcheck is disabled; bootstrap verifies externally |
| Vault JWT auth config fails | SPIRE OIDC not running yet when JWT config runs | Bootstrap configures JWKS URL after OIDC is started (Step 8b) |
| "PostgreSQL failed to start" during bootstrap | HTTP probe against PostgreSQL (doesn't speak HTTP) | Expected — bootstrap falls through to `pg_isready` check via docker exec |

## Environment Variables

| Variable | Default | Used By | Purpose |
|---|---|---|---|
| `AUTH_MODE` | `device` | ai-agent, demo.sh | Human auth mode: `device`, `token`, or `password` |
| `HUMAN_ACCESS_TOKEN` | (none) | ai-agent | Pre-supplied OIDC token (for `AUTH_MODE=token`) |
| `DEMO_USERNAME` | `alice` | ai-agent | Demo user for password grant mode |
| `DEMO_PASSWORD` | (none) | ai-agent | Demo password for password grant mode |
| `GATEWAY_VAULT_TOKEN` | (set by bootstrap) | (legacy) | No longer used — Token Exchange is stateless |
| `SPIRE_JOIN_TOKEN` | (set by bootstrap) | spire-agent | SPIRE agent join token |
| `HOST_NETWORK` | (unset) | bootstrap.sh, cleanup.sh, test-runner, E2E tests | Set to `true` as alternative to `--host` flag |
| `TOKEN_SIGNING_SECRET` | `token-exchange-secret-change-in-production` | token-exchange | Deprecated: HMAC secret (RS256 keypair used by default) |
| `SIGNING_KEY_PATH` | (none) | token-exchange | Path to PEM private key for RS256 signing (generates in-memory if empty) |
| `SPIRE_OIDC_URL` | `http://spire-oidc:8082` | token-exchange | SPIRE OIDC Discovery Provider URL for JWKS verification |
| `MAX_DELEGATION_DEPTH` | `3` | token-exchange | Maximum delegation chain depth |
| `DEFAULT_TTL` | `300` | token-exchange | Default credential TTL in seconds |
| `MAX_TTL` | `1800` | token-exchange | Maximum credential TTL in seconds |
