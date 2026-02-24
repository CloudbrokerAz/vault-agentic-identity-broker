# Vault Agentic Identity Broker

A reference implementation for secure AI agent identity and delegated database access, combining SPIFFE/SPIRE workload identity, OAuth 2.0 token exchange, HashiCorp Vault dynamic secrets, and OPA policy enforcement.

## Architecture

When an AI agent queries a database on behalf of a human, the system must know **which human authorized the action**, **which agent performed it**, and **what permissions were granted** — with cryptographic proof at every step.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY 1: Identity Infrastructure                                  │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐                  │
│  │ Keycloak │    │ SPIRE Server │    │ OPA Policy Store │                  │
│  │ (OIDC)   │    │ (Trust Root) │    │ (Rego Policies)  │                  │
│  └────┬─────┘    └──────┬───────┘    └────────┬─────────┘                  │
├───────┼─────────────────┼─────────────────────┼────────────────────────────┤
│  TRUST BOUNDARY 2: Proxy + Credential Broker                                │
│  ┌──────────────────────────────────────────────────────────────┐           │
│  │  AgentGateway (Rust, open-source MCP/A2A proxy)              │           │
│  │  - OIDC authentication (Keycloak)                             │           │
│  │  - RBAC with group-to-role mapping                            │           │
│  │  - Rate limiting (60 req/min per identity)                    │           │
│  │  - Routes to Token Exchange Service                           │           │
│  └───────────────────────┬──────────────────────────────────────┘           │
│                          │                                                  │
│  ┌───────────────────────┴──────────────────────────────────────┐           │
│  │  Token Exchange Service (Python, RFC 8693)                    │           │
│  │  1. Validates human OIDC token (Keycloak userinfo)            │           │
│  │  2. Validates agent SPIFFE identity (trust domain check)      │           │
│  │  3. Evaluates OPA delegation policy                           │           │
│  │  4. Builds delegation chain with nested `act` claim           │           │
│  │  5. Brokers Vault dynamic credentials                         │           │
│  │  6. Supports sub-agent chain extension (configurable depth)   │           │
│  └───────────────────────┬──────────────────────────────────────┘           │
│                          │                                                  │
│  ┌───────────────────────┴──────────────────────────────────────┐           │
│  │            HashiCorp Vault                                    │           │
│  │  - JWT auth (SPIRE OIDC) / Token auth                        │           │
│  │  - Database secrets engine (PostgreSQL)                       │           │
│  │  - Dynamic credentials with 5-min TTL                        │           │
│  │  - Full audit logging                                         │           │
│  └──────────────────────────────────────────────────────────────┘           │
├─────────────────────────────────────────────────────────────────────────────┤
│  TRUST BOUNDARY 3: Agent Workload                                           │
│  ┌──────────────────────────────────────────────┐                          │
│  │  AI Agent (Python)                            │                          │
│  │  - SPIFFE identity via SPIRE Workload API     │                          │
│  │  - RFC 8693 token exchange for delegation     │                          │
│  │  - Dynamic DB credentials from Vault          │                          │
│  │  - Sub-agent delegation (sql-executor, etc.)  │                          │
│  └──────────────────────┬───────────────────────┘                          │
├─────────────────────────┼───────────────────────────────────────────────────┤
│  TRUST BOUNDARY 4: Protected Resources                                      │
│  ┌──────────────────────┴───────────────────────┐                          │
│  │  PostgreSQL 16                                │                          │
│  │  - pgaudit extension for query logging        │                          │
│  │  - Unique Vault-managed roles per session     │                          │
│  │  - SELECT-only for readonly delegations       │                          │
│  └──────────────────────────────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Identity Delegation Flow (RFC 8693)

```
 Human (Alice)    Keycloak     AI Agent     SPIRE    Token Exchange    OPA       Vault      PostgreSQL
     │               │            │           │            │            │          │             │
     │ 1. OIDC Login │            │           │            │            │          │             │
     │──────────────>│            │           │            │            │          │             │
     │  access_token │            │           │            │            │          │             │
     │  {sub, email, │            │           │            │            │          │             │
     │   groups,     │            │           │            │            │          │             │
     │   may_act}    │            │           │            │            │          │             │
     │<──────────────│            │           │            │            │          │             │
     │               │            │           │            │            │          │             │
     │──(token)────────────────>│           │            │            │          │             │
     │               │            │           │            │            │          │             │
     │               │            │ 2. SVID   │            │            │          │             │
     │               │            │──────────>│            │            │          │             │
     │               │            │<──────────│            │            │          │             │
     │               │            │  JWT-SVID              │            │          │             │
     │               │            │  {sub: spiffe://       │            │          │             │
     │               │            │   demo.local/agent/    │            │          │             │
     │               │            │   query-agent}         │            │          │             │
     │               │            │           │            │            │          │             │
     │               │  3. RFC 8693 Token Exchange         │            │          │             │
     │               │            │──────────────────────>│            │          │             │
     │               │            │  grant_type:           │            │          │             │
     │               │            │   token-exchange       │            │          │             │
     │               │            │  subject_token:        │            │          │             │
     │               │            │   human_jwt            │            │          │             │
     │               │            │  actor_token:          │            │          │             │
     │               │            │   agent_svid           │            │          │             │
     │               │            │  scope: readonly       │            │          │             │
     │               │            │           │            │            │          │             │
     │               │            │           │  4. Validate human token │          │             │
     │               │<───────────────────────────(userinfo)│           │          │             │
     │               │────────────────────────────(claims)>│           │          │             │
     │               │            │           │            │            │          │             │
     │               │            │           │  5. Evaluate OPA policy  │          │             │
     │               │            │           │            │───────────>│          │             │
     │               │            │           │            │<───────────│          │             │
     │               │            │           │            │  allow/deny│          │             │
     │               │            │           │            │            │          │             │
     │               │            │           │  6. Build delegation chain         │             │
     │               │            │           │     act: {sub: agent,   │          │             │
     │               │            │           │       act: {sub: alice}}│          │             │
     │               │            │           │            │            │          │             │
     │               │            │           │  7. Broker Vault creds  │          │             │
     │               │            │           │            │──────────────────────>│             │
     │               │            │           │            │  dynamic creds       │             │
     │               │            │           │            │  (5-min TTL)         │             │
     │               │            │           │            │<──────────────────────│             │
     │               │            │           │            │            │          │  CREATE ROLE│
     │               │            │           │            │            │          │────────────>│
     │               │            │           │            │            │          │             │
     │               │            │<──────────────────────│            │          │             │
     │               │            │  {delegation_token,    │            │          │             │
     │               │            │   db_credential,       │            │          │             │
     │               │            │   delegation_chain}    │            │          │             │
     │               │            │           │            │            │          │             │
     │               │            │ 8. SQL query with dynamic credentials         │             │
     │               │            │────────────────────────────────────────────────────────────>│
     │               │            │                                     results                │
     │               │            │<──────────────────────────────────────────────────────────│
     │  results      │            │           │            │            │          │             │
     │<──────────────────────────│           │            │            │          │             │
     │               │            │           │            │            │          │             │
     │               │            │           9. Credentials auto-expire (5 min)  │             │
```

### Sub-Agent Delegation (Chain Extension)

When an agent needs to delegate further to a sub-agent, the same token exchange
repeats at a deeper level. The parent's **delegation token** (not the original
human token) becomes the `subject_token`:

```
 Parent Agent       Sub-Agent (sql-executor)    Token Exchange     Vault      PostgreSQL
     │                         │                      │              │             │
     │  delegation_token       │                      │              │             │
     │────────────────────────>│                      │              │             │
     │                         │                      │              │             │
     │                         │  RFC 8693 Exchange   │              │             │
     │                         │  subject_token =     │              │             │
     │                         │   parent's deleg_jwt │              │             │
     │                         │  actor_token =       │              │             │
     │                         │   subagent's SVID    │              │             │
     │                         │─────────────────────>│              │             │
     │                         │                      │              │             │
     │                         │              Validates chain depth  │             │
     │                         │              (must be < max of 3)   │             │
     │                         │              Enforces scope narrow  │             │
     │                         │              Extends act{} claim    │             │
     │                         │                      │              │             │
     │                         │                      │──(GET creds)>│             │
     │                         │                      │<─────────────│             │
     │                         │                      │              │             │
     │                         │<─────────────────────│              │             │
     │                         │  {sub-delegation_token,             │             │
     │                         │   db_credential,                    │             │
     │                         │   extended_chain}                   │             │
     │                         │                      │              │             │
     │                         │  SQL query with own credentials     │             │
     │                         │─────────────────────────────────────────────────>│
     │                         │                                    results       │
     │                         │<────────────────────────────────────────────────│
```

## Quick Start

### Prerequisites

- Docker and Docker Compose v2
- `curl`, `python3`, `jq` (for bootstrap/demo scripts)

### Launch

```bash
# 1. Start all services
docker compose up -d

# 2. Wait for services to be healthy, then bootstrap
./scripts/bootstrap.sh

# 3. Verify the deployment
docker compose --profile test run --rm test-runner

# 4a. Interactive demo UI (recommended — browser-based walkthrough)
#     Open http://localhost:8500 after bootstrap
#     Supports Device Flow (RFC 8628) and Authorization Code Flow

# 4b. CLI demo (headless)
./scripts/demo.sh

# Or choose an auth mode:
AUTH_MODE=device   ./scripts/demo.sh   # (recommended) Agent never sees password
AUTH_MODE=token    ./scripts/demo.sh   # Pre-supplied token from upstream app
AUTH_MODE=password ./scripts/demo.sh   # Demo/test only — agent has password
```

### Human Authentication Modes

The agent supports three modes for obtaining the human's OIDC token, controlled by the `AUTH_MODE` environment variable:

| Mode | `AUTH_MODE=` | Agent sees password? | Production ready? | How it works |
|---|---|---|---|---|
| **Device Flow** | `device` (default) | **No** | Yes | Agent displays a URL + code. Human opens browser, authenticates directly with Keycloak (with MFA if configured), and approves. Agent polls for the token. |
| **Pre-supplied Token** | `token` | **No** | Yes | An upstream app (chat UI, IDE, orchestrator) already authenticated the human and passes the access token via `HUMAN_ACCESS_TOKEN` env var. |
| **Authorization Code Flow** | (demo UI only) | **No** | Yes | Standard OAuth 2.0 redirect flow — user is redirected to Keycloak, authenticates, and is redirected back with an authorization code exchanged for tokens server-side. Used by the interactive demo UI. |

> **Security note:** In all three modes, the agent **never possesses the human's password**. It only receives a scoped, time-limited access token after the human explicitly consents. This is the correct pattern for production AI agent deployments.

### What the demo does

1. **Alice authorizes** the agent via one of the auth modes above (Device Flow recommended)
2. **AI agent obtains SPIFFE identity** from SPIRE (JWT-SVID: `spiffe://demo.local/agent/query-agent`)
3. **RFC 8693 Token Exchange** — agent sends Alice's OIDC token + its own SPIFFE SVID to the Token Exchange Service
4. **Token Exchange validates** both tokens, then consults **OPA** for policy evaluation
5. **OPA evaluates** delegation policy (Alice's groups permit `readonly` scope, `may_act` authorizes delegation)
6. **Vault generates** dynamic PostgreSQL credentials (5-minute TTL, read-only role)
7. **Delegation token minted** with nested `act` claim preserving the full identity chain
8. **Agent queries** database using Vault-issued credentials
9. **(Optional) Sub-agent delegation** — agent delegates to `sql-executor` sub-agent via a second token exchange, extending the `act` chain
10. **Credentials auto-revoke** after TTL expiry (or immediate revocation via `/v1/token/revoke`)

## Project Structure

```
├── docker-compose.yml           # 10-service container orchestration
├── ARCHITECTURE.md              # Detailed architecture documentation
├── demo-ui/                     # Interactive educational demo (browser-based)
│   ├── server.py                # Python backend with Keycloak reverse proxy
│   ├── static/index.html        # Single-page UI walking through the delegation flow
│   ├── requirements.txt
│   └── Dockerfile
├── agentgateway/                # AgentGateway proxy configuration (NEW)
│   └── config/
│       └── gateway.yaml         # MCP/A2A proxy config (OIDC, RBAC, routing)
├── token-exchange/              # RFC 8693 Token Exchange Service (NEW)
│   ├── token_exchange.py        # Token exchange, delegation chains, Vault brokering
│   ├── requirements.txt
│   └── Dockerfile
├── ai-agent/                    # Python AI agent with sub-agent support
│   ├── agent.py                 # SPIFFE identity, RFC 8693 exchange, DB queries
│   ├── subagents/               # Sub-agent modules (NEW)
│   │   ├── __init__.py
│   │   └── sql_executor.py      # SQL executor sub-agent with chain extension
│   ├── tests/
│   │   └── test_agent.py
│   ├── requirements.txt
│   └── Dockerfile
├── spire/
│   ├── server/server.conf       # SPIRE server config (trust domain root)
│   ├── agent/agent.conf         # SPIRE agent config (workload attestation)
│   └── entries/                 # SPIRE registration entry scripts
├── keycloak/
│   └── realm/demo-realm.json    # Keycloak realm with users, clients, mappers
├── vault/
│   ├── config/vault.hcl         # Vault server configuration
│   └── policies/                # Vault ACL policies
│       ├── ai-agent-db-read.hcl # Agent: database/creds/readonly only
│       ├── gateway-policy.hcl   # Gateway: token create + entity metadata
│       └── admin-policy.hcl     # Admin: full access (bootstrap only)
├── opa/
│   └── policies/
│       ├── delegation.rego      # OPA delegation policy (Rego) — with chain validation
│       └── data.json            # Policy data (trusted issuers, agents, sub-agents,
│                                #   group permissions, scope hierarchy, max depth)
├── postgres/
│   └── init/                    # Database initialization
│       ├── 00-vault-user.sql    # Vault admin user
│       └── 01-init.sql          # Sample schema + data (orders, customers, products)
├── tests/
│   ├── Dockerfile               # Test runner container image
│   ├── requirements.txt         # Python test dependencies
│   ├── config-validation/       # Offline config validation tests (pytest)
│   ├── e2e/                     # End-to-end integration tests (bash)
│   └── test_token_exchange.py   # Token Exchange unit tests
└── scripts/
    ├── bootstrap.sh             # Initialize Vault, configure all engines
    ├── demo.sh                  # Run the full delegation demo
    ├── run-tests.sh             # Three-phase test orchestrator
    └── cleanup.sh               # Tear down everything
```

## Components

### AgentGateway (MCP/A2A Proxy)

- **Runtime**: Rust ([agentgateway/agentgateway](https://github.com/agentgateway/agentgateway))
- **Port**: `:9080` (MCP/HTTP), `:19000` (Admin API)
- **Features**: OIDC authentication, RBAC with group-to-role mapping, rate limiting (60 req/min), observability
- **Role**: Front-door proxy for AI agents; routes requests to the Token Exchange Service

### Token Exchange Service (RFC 8693)

- **Language**: Python
- **Port**: `:8090`
- **Endpoints**:
  - `POST /v1/token/exchange` — RFC 8693 token exchange with delegation semantics
  - `POST /v1/delegate` — Legacy delegation API (backward-compatible)
  - `POST /v1/token/revoke` — Revoke delegation token and Vault credentials
  - `GET /v1/delegation/chain` — Query full delegation chain for a session
  - `GET /v1/audit` — Audit trail
- **Flow**: Validate subject token (Keycloak) → Validate actor token (SPIFFE) → Check chain depth → Enforce scope narrowing → Evaluate OPA policy → Build `act` claim → Broker Vault credentials → Issue delegation token

### SPIRE (SPIFFE Runtime Environment)

- **Trust domain**: `demo.local`
- **Node attestation**: Join token (for demo; Kubernetes/AWS in production)
- **Workload attestation**: Unix UID (for demo; K8s pod selectors in production)
- **Registered SPIFFE IDs**:
  - `spiffe://demo.local/agent/query-agent` (primary agent)
  - `spiffe://demo.local/agent/analysis-agent` (analysis agent)
  - `spiffe://demo.local/agent/write-agent` (write agent)
  - `spiffe://demo.local/subagent/sql-executor` (sub-agent)
  - `spiffe://demo.local/subagent/result-formatter` (sub-agent)
### Demo UI (Interactive Walkthrough)

- **Language**: Python + vanilla HTML/JS
- **Port**: `:8500`
- **Purpose**: Browser-based educational tool that walks through the identity delegation flow step by step, with live API calls, decoded JWTs, and annotated responses
- **Auth flows**: Device Flow (RFC 8628) and Authorization Code Flow via Keycloak reverse proxy
- **Steps**: Health Check → Human Auth → Agent Identity (SPIFFE) → Policy Check (OPA) → Token Exchange (RFC 8693) → Database Query → Revocation → Audit Trail

### Keycloak (Human Identity Provider)

- **Realm**: `demo`
- **Users**: `alice` (data-analyst, groups: data-analysts, trading-team), `bob` (data-engineer, group: engineering)
- **Clients**: `demo-cli` (public, device auth + authorization code + direct access), `ai-agent-service` (confidential, token exchange enabled)
- **Auth flows**: Device Authorization Grant (RFC 8628, recommended for agents), Authorization Code Flow (demo UI)
- **Custom claims**: `groups` membership, `may_act` delegation authorization (hardcoded protocol mapper)

### HashiCorp Vault

- **Auth**: JWT auth (SPIRE OIDC) for production; token auth for demo
- **Secrets engine**: PostgreSQL database with dynamic credential generation
- **Policies**: Templated ACL using identity entity metadata
- **Roles**: `ai-agent-readonly` (SELECT only, 5-min TTL), `ai-agent-readwrite`
- **Audit**: File audit device with full request/response logging

### OPA (Open Policy Agent)

- **Policy**: `delegation.rego` — evaluates human token, agent SPIFFE ID, scope, delegation chain depth, and scope narrowing
- **Data**: Trusted issuers, registered agents, registered sub-agents, group-to-scope permissions, scope hierarchy, max delegation depth
- **Decision**: Allow/deny with reason (for audit trail)
- **Delegation chain rules**: Validates chain extension for sub-agents, enforces max depth (3), scope narrowing

### AI Agent (with Sub-Agent Delegation)

- **Language**: Python
- **SPIFFE**: spiffe library (falls back to demo mode without SPIRE)
- **Human auth**: Supports Device Flow (RFC 8628, recommended), pre-supplied token, or password grant (CLI demo only)
- **Token exchange**: RFC 8693 client for delegation via Token Exchange Service
- **Sub-agents**: `sql-executor` — can receive delegation from parent agent and extend the chain
- **Queries**: Pre-mapped natural language → SQL for demo
- **Agent modes**: `demo` (single query), `interactive` (REPL), `wait` (container standby)
- **Auth modes**: `device` (default), `token`, `password` — controlled by `AUTH_MODE` env var

## Security Properties

| Property | Implementation |
|---|---|
| **Agent never sees password** | Device Authorization Flow (RFC 8628) or pre-supplied token mode — agent only receives a scoped, time-limited access token after explicit human consent |
| **No static credentials** | All DB credentials are dynamic, 5-min TTL, auto-revoked |
| **Human attribution** | `sub` claim preserved through entire delegation chain via RFC 8693 `act` claim |
| **Agent attestation** | SPIFFE SVID proves agent workload identity cryptographically |
| **RFC 8693 delegation** | Standard OAuth 2.0 token exchange with `subject_token` + `actor_token` |
| **Delegation chains** | Nested `act` claims per RFC 8693 Section 4.1; Human → Agent → Sub-Agent traceable |
| **Scope narrowing** | Each delegation level can only narrow scope, never widen it |
| **Max chain depth** | Configurable limit (default: 3) prevents infinite delegation |
| **Least privilege** | Agents get SELECT-only on specific schemas; scoped by group membership |
| **Policy enforcement** | OPA evaluates group membership, scope, `may_act` claims, chain depth, and scope narrowing |
| **Audit trail** | 7-layer correlation: IdP → AgentGateway → Token Exchange → OPA → Vault → Lease → PostgreSQL |
| **Credential lifecycle** | Vault auto-revokes after TTL; immediate revocation via `/v1/token/revoke` |
| **Zero trust** | Every request validated end-to-end; no implicit trust from network position |

## Service Endpoints (Local)

| Service | URL | Credentials |
|---|---|---|
| **Demo UI** | http://localhost:8500 | (no auth — educational walkthrough) |
| Keycloak Admin | http://localhost:8080 | admin / admin |
| SPIRE Server | localhost:8081 | (internal) |
| SPIRE OIDC | http://localhost:8082 | (JWKS endpoint) |
| Token Exchange | http://localhost:8090 | (no auth for demo) |
| OPA | http://localhost:8181 | (no auth) |
| Vault UI | http://localhost:8200 | Root token from `.vault-root-token` |
| PostgreSQL | localhost:5432 | postgres / postgres-root-password |
| AgentGateway | http://localhost:9080 | (OIDC auth) |
| AgentGateway Admin | http://localhost:19000 | (no auth) |

## Testing

Run the full test suite (offline config validation + E2E integration) via the `test-runner` container:

```bash
# After deploy + bootstrap:
docker compose -f docker-compose.host.yml --profile test run --rm test-runner

# Bridge network mode:
docker compose --profile test run --rm test-runner
```

The test runner uses the `test` profile and won't start during normal `docker compose up`. It executes three phases:

1. **Offline** — Config validation, token exchange unit tests, agent unit tests
2. **Wait** — Polls for bootstrap completion (120s timeout)
3. **E2E** — Full integration tests against running services

Exit code 0 = all suites passed. See `CLAUDE.md` for individual test suite commands.

## Cleanup

```bash
./scripts/cleanup.sh
```

This removes all containers, volumes, and generated credential files.
