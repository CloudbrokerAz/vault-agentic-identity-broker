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
│  TRUST BOUNDARY 2: Credential Broker                                        │
│  ┌──────────────────────────────────────────────────────────────┐           │
│  │            Identity Gateway (Go service)                     │           │
│  │  1. Validates human OIDC token (Keycloak JWKS)              │           │
│  │  2. Validates agent SPIFFE ID (trust domain check)          │           │
│  │  3. Evaluates OPA delegation policy                         │           │
│  │  4. Brokers Vault access with delegation metadata           │           │
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
│  │  - Delegation request to gateway              │                          │
│  │  - Dynamic DB credentials from Vault          │                          │
│  │  - Natural language → SQL query mapping        │                          │
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

## Identity Delegation Flow

```
 Human (Alice)         AI Agent         Identity Gateway      OPA       Vault      PostgreSQL
     │                    │                    │                │          │             │
     │ 1. OIDC Login      │                    │                │          │             │
     │───────────────────>│                    │                │          │             │
     │   access_token     │                    │                │          │             │
     │<───────────────────│                    │                │          │             │
     │                    │ 2. SPIRE SVID      │                │          │             │
     │                    │  (Workload API)    │                │          │             │
     │                    │                    │                │          │             │
     │                    │ 3. Delegate        │                │          │             │
     │                    │  human_token +     │                │          │             │
     │                    │  agent_spiffe_id   │                │          │             │
     │                    │───────────────────>│                │          │             │
     │                    │                    │ 4. Evaluate    │          │             │
     │                    │                    │───────────────>│          │             │
     │                    │                    │   allow/deny   │          │             │
     │                    │                    │<───────────────│          │             │
     │                    │                    │                │          │             │
     │                    │                    │ 5. Get DB creds│          │             │
     │                    │                    │  + delegation  │          │             │
     │                    │                    │  metadata      │          │             │
     │                    │                    │───────────────────────────>│             │
     │                    │                    │  dynamic creds (5-min TTL)│             │
     │                    │                    │<─────────────────────────│             │
     │                    │                    │                │          │             │
     │                    │ 6. DB credentials  │                │          │             │
     │                    │<───────────────────│                │          │             │
     │                    │                                                │             │
     │                    │ 7. SQL query with dynamic credentials          │             │
     │                    │───────────────────────────────────────────────>│             │
     │                    │                           results             │             │
     │                    │<──────────────────────────────────────────────│             │
     │  results           │                                                │             │
     │<───────────────────│                                                │             │
     │                    │                                                │             │
     │                    │           8. Credentials auto-expire (5 min)   │             │
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

# 3. Run the demo
./scripts/demo.sh
```

### What the demo does

1. **Alice authenticates** via Keycloak OIDC (direct access grant)
2. **AI agent obtains SPIFFE identity** from SPIRE (JWT-SVID)
3. **Identity Gateway** validates both tokens, consults OPA
4. **OPA evaluates** delegation policy (alice's groups permit readonly scope)
5. **Vault generates** dynamic PostgreSQL credentials (5-minute TTL)
6. **Agent queries** database: "Show me all orders over $1000 from last month"
7. **Credentials auto-revoke** after TTL expiry
8. **Full audit trail** visible in Vault audit log

## Project Structure

```
├── docker-compose.yml           # 8-container orchestration
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
│       ├── delegation.rego      # OPA delegation policy (Rego)
│       └── data.json            # Policy data (trusted issuers, groups, scopes)
├── identity-gateway/            # Go service: token validation + Vault brokering
│   ├── main.go                  # HTTP server, delegation endpoint, audit log
│   ├── token_verifier.go        # Keycloak OIDC token validation
│   ├── opa_client.go            # OPA policy evaluation client
│   ├── vault_broker.go          # Vault API client for dynamic credentials
│   ├── Dockerfile
│   └── go.mod
├── ai-agent/                    # Python demo agent
│   ├── agent.py                 # SPIFFE identity, delegation flow, DB queries
│   ├── requirements.txt
│   └── Dockerfile
├── postgres/
│   └── init/                    # Database initialization
│       ├── 00-vault-user.sql    # Vault admin user
│       └── 01-init.sql          # Sample schema + data (orders, customers, products)
└── scripts/
    ├── bootstrap.sh             # Initialize Vault, configure all engines
    ├── demo.sh                  # Run the full delegation demo
    └── cleanup.sh               # Tear down everything
```

## Components

### SPIRE (SPIFFE Runtime Environment)

- **Trust domain**: `demo.local`
- **Node attestation**: Join token (for demo; Kubernetes/AWS in production)
- **Workload attestation**: Unix UID (for demo; K8s pod selectors in production)
- **Agent SPIFFE IDs**:
  - `spiffe://demo.local/gateway/identity-gateway`
  - `spiffe://demo.local/agent/query-agent`

### Keycloak (Human Identity Provider)

- **Realm**: `demo`
- **Users**: `alice` (data-analyst), `bob` (data-engineer)
- **Clients**: `demo-cli` (public, direct access), `ai-agent-service` (confidential)
- **Custom claims**: `groups` membership, `may_act` delegation authorization

### HashiCorp Vault

- **Auth**: JWT auth (SPIRE OIDC) for production; token auth for demo gateway
- **Secrets engine**: PostgreSQL database with dynamic credential generation
- **Policies**: Templated ACL using identity entity metadata
- **Roles**: `ai-agent-readonly` (SELECT only, 5-min TTL), `ai-agent-readwrite`
- **Audit**: File audit device with full request/response logging

### OPA (Open Policy Agent)

- **Policy**: `delegation.rego` — evaluates human token, agent SPIFFE ID, scope
- **Data**: Trusted issuers, registered agents, group-to-scope permissions
- **Decision**: Allow/deny with reason (for audit trail)

### Identity Gateway

- **Language**: Go
- **Endpoint**: `POST /v1/delegate`
- **Flow**: Validate human token → Validate agent SPIFFE ID → Evaluate OPA → Broker Vault → Return DB credentials
- **Audit**: In-memory log at `GET /v1/audit`

### AI Agent

- **Language**: Python
- **SPIFFE**: py-spiffe library (falls back to demo mode without SPIRE)
- **Queries**: Pre-mapped natural language → SQL for demo
- **Modes**: `demo` (single query), `interactive` (REPL), `wait` (container standby)

## Security Properties

| Property | Implementation |
|---|---|
| **No static credentials** | All DB credentials are dynamic, 5-min TTL, auto-revoked |
| **Human attribution** | Delegation metadata attached to Vault entity, logged at every layer |
| **Agent attestation** | SPIFFE SVID proves agent workload identity cryptographically |
| **Least privilege** | Agents get SELECT-only on specific schemas |
| **Policy enforcement** | OPA evaluates group membership, scope, and may_act claims |
| **Audit trail** | 6-layer correlation: IdP → Gateway → OPA → Vault → Lease → PostgreSQL |
| **Credential lifecycle** | Vault auto-revokes; immediate manual revocation available |
| **Zero trust** | Every request validated; no implicit trust based on network position |

## Service Endpoints (Local)

| Service | URL | Credentials |
|---|---|---|
| Vault UI | http://localhost:8200 | Root token from `.vault-root-token` |
| Keycloak Admin | http://localhost:8080 | admin / admin |
| OPA | http://localhost:8181 | (no auth) |
| Identity Gateway | http://localhost:9080 | (no auth for demo) |
| PostgreSQL | localhost:5432 | postgres / postgres-root-password |

## Cleanup

```bash
./scripts/cleanup.sh
```

This removes all containers, volumes, and generated credential files.
