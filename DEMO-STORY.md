# How Do You Trust an AI Agent With Your Database?

**A walkthrough of secure, auditable AI agent delegation — from human approval to database query and back.**

---

## The Problem

Your company has AI agents that help employees get answers from databases. An analyst named Alice asks her AI assistant: *"Show me all orders over $1,000 from the last 30 days."*

Simple question. But behind the scenes, a chain of deeply uncomfortable questions emerges:

- **Who gave the agent permission** to touch the database?
- **Which human is responsible** if the agent reads something it shouldn't?
- **How do you prove** — six months from now during an audit — exactly what happened?
- **What stops the agent** from accessing data beyond what Alice is allowed to see?
- **What if the agent delegates** to a *sub-agent* — does the chain of trust break?
- **Do the credentials ever expire**, or do they sit around waiting to be stolen?

Today, most teams answer these questions with shared database passwords, long-lived API keys, or "we trust the agent." None of that survives a compliance audit. None of it scales.

This project solves all of it. Here's how.

---

## The Cast of Characters

Before we walk through the story, here's who's involved:

| Who / What | Role | Analogy |
|---|---|---|
| **Alice** | A data analyst at Acme Corp | The employee who needs answers |
| **Query Agent** | An AI agent that runs database queries | Alice's AI assistant |
| **SQL Executor** | A sub-agent that specializes in running SQL | A specialist the assistant delegates to |
| **Keycloak** | The company's identity provider | The corporate login page |
| **SPIRE** | The workload identity system | A passport office, but for software |
| **Token Exchange Service** | The delegation JWT minter | A notary who verifies both parties and stamps a delegation letter |
| **Vault** | The secrets manager + policy enforcer | A bank vault that issues temporary keys and enforces the rules |
| **PostgreSQL** | The database | The filing cabinet with the actual data |

---

## Phase 1: Alice Logs In (The Agent Never Sees Her Password)

Alice opens her chat interface and types: *"Show me high-value orders from the last month."*

The AI agent needs to query a database to answer this. But first, it needs Alice to prove who she is — and to consent to the agent acting on her behalf.

Here's what Alice sees:

```
╔══════════════════════════════════════════════════════╗
║  HUMAN AUTHORIZATION REQUIRED                        ║
║                                                      ║
║  Open this URL in your browser:                      ║
║  https://login.acme.com/device?code=ABCD-EFGH        ║
║                                                      ║
║  Enter code: ABCD-EFGH                               ║
║                                                      ║
║  (The agent does NOT have your password)              ║
╚══════════════════════════════════════════════════════╝
```

Alice opens that link on her own machine — her own browser, her own password manager, her own multi-factor authenticator. She logs in, sees a consent screen, and clicks "Approve."

The agent never touches her credentials. It just waits.

### What's Happening Technically

This is the **OAuth 2.0 Device Authorization Grant** ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)), the same flow your smart TV uses when it asks you to visit a URL and enter a code.

```
  Alice's Browser                    Keycloak                       AI Agent
       │                                │                              │
       │                                │  1. POST /auth/device        │
       │                                │<─────────────────────────────│
       │                                │  {client_id: "demo-cli"}     │
       │                                │                              │
       │                                │  device_code + user_code     │
       │                                │─────────────────────────────>│
       │                                │                              │
       │                                │           Display URL + code to Alice
       │                                │                              │
       │  2. Alice opens URL            │                              │
       │───────────────────────────────>│                              │
       │  Logs in with password + MFA   │                              │
       │  Clicks "Approve"              │                              │
       │<───────────────────────────────│                              │
       │                                │                              │
       │                                │  3. Agent polls POST /token  │
       │                                │<─────────────────────────────│
       │                                │  (every 5 seconds)           │
       │                                │                              │
       │                                │  4. access_token             │
       │                                │─────────────────────────────>│
```

The agent receives a **scoped, time-limited access token** — not a password. The token contains claims that describe Alice:

```json
{
  "sub": "alice@acme.com",
  "email": "alice@acme.com",
  "groups": ["data-analysts", "trading-team"],
  "may_act": {
    "sub": "agent:query-agent-v2",
    "client_id": "ai-agent-service"
  },
  "exp": 1740268800,
  "iss": "https://login.acme.com/realms/demo"
}
```

Two things to notice:

1. **`groups`** — Alice belongs to `data-analysts` and `trading-team`. These groups will determine what she's allowed to delegate.
2. **`may_act`** — This claim, set by Alice's administrator, explicitly says "this user is authorized to delegate to an AI agent." Without it, the entire flow stops here.

---

## Phase 2: The Agent Proves Its Own Identity

Alice has proven who she is. Now the agent needs to prove who *it* is.

In a world of containers, microservices, and cloud workloads, a software process can't just say "I'm the query agent — trust me." It needs a **cryptographic identity** that's verifiable by anyone, tied to the specific workload running on a specific machine.

This is what **SPIFFE** (Secure Production Identity Framework for Everyone) provides. Think of it as a passport system for software: every workload gets a globally unique identity (a **SPIFFE ID**) and a short-lived, signed certificate (a **SVID**) that proves it.

The agent contacts its local SPIRE agent — a process running on the same host — and requests a JWT-SVID:

```
  AI Agent                      SPIRE Agent                  SPIRE Server
     │                              │                             │
     │  1. "Give me my identity"    │                             │
     │  (via Unix domain socket)    │                             │
     │─────────────────────────────>│                             │
     │                              │                             │
     │                              │  2. Attests the workload    │
     │                              │  (checks process UID,       │
     │                              │   container labels, etc.)   │
     │                              │                             │
     │                              │  3. Signs JWT-SVID          │
     │                              │────────────────────────────>│
     │                              │<────────────────────────────│
     │                              │                             │
     │  4. JWT-SVID returned        │                             │
     │<─────────────────────────────│                             │
```

The agent now holds a signed JWT that says:

```
SPIFFE ID: spiffe://demo.local/agent/query-agent
```

This identity is:
- **Cryptographically signed** by the SPIRE server's certificate authority
- **Short-lived** — it expires and must be refreshed
- **Tied to the actual workload** — not just a name anyone can claim
- **Verifiable by anyone** who trusts the `demo.local` trust domain

---

## Phase 3: The Delegation Exchange

The agent now has two things:
1. **Alice's OIDC token** — proving a human authorized this action
2. **Its own SPIFFE identity** — proving which agent is performing it

It bundles both together and sends them to the **Token Exchange Service**, following [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) (OAuth 2.0 Token Exchange):

```
POST /v1/token/exchange

{
  "grant_type":          "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token":       "<Alice's OIDC JWT>",
  "subject_token_type":  "urn:ietf:params:oauth:token-type:access_token",
  "actor_token":         "<Agent's SPIFFE JWT-SVID>",
  "actor_token_type":    "urn:ietf:params:oauth:token-type:jwt",
  "scope":               "readonly",
  "audience":            "database"
}
```

In plain English: *"I am agent `query-agent`, acting on behalf of Alice, and I need `readonly` access to the database."*

The Token Exchange Service validates both identities and mints a **fused delegation JWT**. Then the agent authenticates directly to Vault to get database credentials.

```
  AI Agent          Token Exchange       Keycloak       Vault       PostgreSQL
     │                    │                  │           │              │
     │  RFC 8693 request  │                  │           │              │
     │───────────────────>│                  │           │              │
     │                    │                  │           │              │
     │                    │  Validate Alice  │           │              │
     │                    │─────────────────>│           │              │
     │                    │  claims verified │           │              │
     │                    │<─────────────────│           │              │
     │                    │                  │           │              │
     │                    │  Validate agent  │           │              │
     │                    │  SPIFFE trust    │           │              │
     │                    │  domain check    │           │              │
     │                    │  (SPIRE OIDC     │           │              │
     │                    │   JWKS verify)   │           │              │
     │                    │                  │           │              │
     │                    │  Mint fused JWT  │           │              │
     │                    │  with act{} claim│           │              │
     │                    │                  │           │              │
     │  fused deleg. JWT  │                  │           │              │
     │<───────────────────│                  │           │              │
     │                    │                  │           │              │
     │  Two-login Vault auth:               │           │              │
     │  1) SPIFFE JWT auth → workload token │           │              │
     │──────────────────────────────────────────────────>│              │
     │<──────────────────────────────────────────────────│              │
     │  2) Fused JWT auth → delegation token│           │              │
     │──────────────────────────────────────────────────>│              │
     │<──────────────────────────────────────────────────│              │
     │                    │                  │           │              │
     │  Request DB credentials              │           │              │
     │  GET /v1/database/creds/readonly     │           │              │
     │──────────────────────────────────────────────────>│              │
     │                    │                  │  Sentinel │              │
     │                    │                  │  EGPs     │              │
     │                    │                  │  enforce  │              │
     │                    │                  │  policy   │              │
     │  dynamic creds (5-min TTL)           │           │              │
     │<──────────────────────────────────────────────────│  CREATE ROLE │
     │                    │                  │           │─────────────>│
```

Let's look at each step.

### Step 3a: Is Alice's Token Legitimate?

The Token Exchange Service calls Keycloak's **userinfo endpoint** with Alice's token. Keycloak either confirms the token is valid and returns Alice's claims, or rejects it. This catches expired tokens, revoked tokens, and forgeries.

### Step 3b: Is This Agent Who It Claims to Be?

The service cryptographically verifies the agent's JWT-SVID against the SPIRE OIDC JWKS endpoint:
- Is the signature valid (RS256, verified against SPIRE's published keys)?
- Does the SPIFFE ID (`spiffe://demo.local/agent/query-agent`) belong to the `demo.local` trust domain?

### Step 3c: The Fused Delegation JWT

With both identities validated, the Token Exchange Service mints a **fused delegation JWT** — a signed token that binds Alice's identity to the agent's identity with a nested `act` claim per RFC 8693 Section 4.1. This JWT is stateless — the Token Exchange Service has no Vault dependency and does not broker credentials.

### Step 3d: The Agent Authenticates to Vault (Two-Login Pattern)

The agent now authenticates directly to Vault using two separate JWT auth logins:

1. **SPIFFE JWT auth** — The agent presents its SPIFFE JWT-SVID. Vault verifies it against SPIRE's JWKS and issues a workload token that identifies the agent.

2. **Fused delegation JWT auth** — The agent presents the fused delegation JWT from Token Exchange. Vault verifies it and populates entity metadata from the JWT claims (human user, agent identity, delegation scope, chain depth, may_act).

### Step 3e: Vault Enforces Policy and Issues Credentials

The agent requests database credentials using its Vault delegation token:

```
GET /v1/database/creds/ai-agent-readonly
```

Before issuing credentials, Vault's **Sentinel Endpoint Governing Policies (EGPs)** evaluate four hard-mandatory rules:

| Policy | Question | Result |
|---|---|---|
| `require-delegation` | Does delegation metadata exist? | human_user, agent_identity, delegation_scope all present |
| `enforce-scope` | Does the scope match the requested role? | `readonly` scope matches `readonly` credential role |
| `enforce-chain-depth` | Is the chain within limits? | depth 0 (human -> agent) is within max of 3 |
| `enforce-may-act` | Did Alice authorize this agent? | `may_act` pattern matches agent's SPIFFE ID |

If *any* of these policies fail, Vault returns a hard denial and no credentials are issued. This enforcement happens inside Vault itself — there is no external policy engine to bypass.

Vault then creates a **brand new PostgreSQL user** specifically for this session:

```sql
CREATE ROLE "v-token-readonly-3ee8b521"
  WITH LOGIN PASSWORD 'rV9z4k7xWpQ9mZ2L6vN3...'
  VALID UNTIL '2026-02-22 10:50:23'     -- 5 minutes from now
  INHERIT;

GRANT USAGE ON SCHEMA app TO "v-token-readonly-3ee8b521";
GRANT SELECT ON ALL TABLES IN SCHEMA app TO "v-token-readonly-3ee8b521";
```

Notice what this achieves:
- **Unique per session** — every delegation gets its own database user
- **Read-only** — this role can only `SELECT`, never `INSERT`, `UPDATE`, or `DELETE`
- **Time-limited** — the role expires in 5 minutes, even if nobody revokes it
- **Traceable** — any query from `v-token-readonly-3ee8b521` can be tied back to this specific delegation by Alice to this specific agent

Vault natively records **entity metadata** linking this credential to the delegation — both the human and the agent identity are visible in a single audit log entry:

```json
{
  "human_user": "alice@acme.com",
  "agent_identity": "spiffe://demo.local/agent/query-agent",
  "delegation_scope": "readonly",
  "chain_depth": "0"
}
```

### Step 3f: The Delegation Token

The fused delegation JWT minted by the Token Exchange Service is a JWT with a nested `act` (actor) claim defined by RFC 8693 Section 4.1:

```json
{
  "iss": "http://token-exchange:8090",
  "sub": "alice@acme.com",
  "aud": "database",
  "scope": "readonly",
  "exp": 1740265500,
  "act": {
    "sub": "spiffe://demo.local/agent/query-agent"
  },
  "delegation_chain": [
    {
      "subject": "alice@acme.com",
      "actor": "spiffe://demo.local/agent/query-agent",
      "scope": "readonly",
      "depth": 0
    }
  ],
  "session_id": "sess-3ee8b521a1b2c3d4"
}
```

This token is the **receipt** for the delegation. Anyone who inspects it can answer: *who authorized this?* (Alice), *who is acting?* (query-agent), *what can they do?* (readonly), and *when does it expire?*

---

## Phase 4: The Agent Queries the Database

The agent now has Vault-issued dynamic database credentials. It connects to PostgreSQL using the Vault-generated username and password, and executes Alice's query:

```sql
SELECT customer_name, product, quantity, unit_price,
       (quantity * unit_price) AS total_amount,
       order_date, status
FROM   app.orders
WHERE  (quantity * unit_price) > 1000
  AND  order_date >= NOW() - INTERVAL '30 days'
ORDER  BY total_amount DESC;
```

Alice sees the results:

```
 customer_name     | product             | quantity | unit_price | total_amount | order_date | status
───────────────────┼─────────────────────┼──────────┼────────────┼──────────────┼────────────┼──────────
 Acme Corp         | AI Processing Unit  |       10 |    1299.99 |     12999.90 | 2026-02-16 | confirmed
 Wayne Enterprises | Security Scanner    |       25 |     599.99 |     14999.75 | 2026-02-13 | shipped
 Umbrella Corp     | Data Analyzer Suite |       50 |     299.99 |     14999.50 | 2026-02-09 | confirmed
(3 rows)
```

From Alice's perspective, she asked a question and got an answer. She didn't know — and didn't need to know — about SPIFFE, token exchange, Vault Sentinel policies, or lease management. That's the point.

---

## Phase 5: Sub-Agent Delegation (The Chain Extends)

Sometimes an agent needs help. The query agent might delegate the actual SQL execution to a specialized **sub-agent** — a smaller, purpose-built agent that only knows how to run SQL.

This is where delegation chains come in. The query agent doesn't hand the sub-agent Alice's original token. Instead, it performs *another* RFC 8693 token exchange, using its own delegation token as the `subject_token`:

```
  Query Agent           SQL Executor          Token Exchange        Vault
      │                      │                      │                │
      │  "Run this SQL"      │                      │                │
      │─────────────────────>│                      │                │
      │                      │                      │                │
      │                      │  RFC 8693 Exchange    │                │
      │                      │  subject = parent's   │                │
      │                      │    delegation token   │                │
      │                      │  actor = sub-agent's  │                │
      │                      │    SPIFFE SVID        │                │
      │                      │─────────────────────>│                │
      │                      │                      │                │
      │                      │                      │  Validate &    │
      │                      │                      │  mint fused    │
      │                      │                      │  sub-delegation│
      │                      │                      │  JWT           │
      │                      │                      │                │
      │                      │  sub-delegation JWT   │                │
      │                      │<─────────────────────│                │
      │                      │                      │                │
      │                      │  Two-login Vault auth │                │
      │                      │  + request DB creds   │                │
      │                      │  (Sentinel EGPs       │                │
      │                      │   enforce policy)     │                │
      │                      │──────────────────────────────────────>│
      │                      │  DB credentials       │                │
      │                      │<──────────────────────────────────────│
      │                      │                      │                │
      │  query results       │                      │                │
      │<─────────────────────│                      │                │
```

### How Policy Prevents Abuse

Vault Sentinel EGPs enforce two critical rules during chain extension:

**1. Scope Narrowing** — A sub-agent can never gain *more* access than its parent. If the query agent has `readonly`, the sub-agent can request `readonly` or something narrower (like `db:read`), but never `readwrite`. The scope hierarchy is explicit:

```
readwrite ──> readonly ──> db:read
    │                       db:query
    └──────> db:write ──> db:read
```

An arrow means "implies." Having `readwrite` implies `readonly`, which implies `db:read`. But `db:read` never implies `readwrite` — you can't escalate upward.

**2. Chain Depth Limit** — The system enforces a maximum delegation depth (default: 3). Human → Agent is depth 0. Agent → Sub-Agent is depth 1. This prevents infinite delegation chains.

### The Nested `act` Claim

The sub-agent's delegation token now contains a **nested** `act` claim showing the full chain:

```json
{
  "sub": "alice@acme.com",
  "act": {
    "sub": "spiffe://demo.local/subagent/sql-executor",
    "act": {
      "sub": "spiffe://demo.local/agent/query-agent",
      "act": {
        "sub": "alice@acme.com"
      }
    }
  }
}
```

Read it from the inside out: **Alice** authorized **query-agent**, which delegated to **sql-executor**, which is now acting as **Alice**. The complete chain of trust is embedded in the token itself.

---

## Phase 6: The Credentials Disappear

Five minutes after issuance, Vault automatically revokes the database credentials:

```sql
DROP ROLE IF EXISTS "v-token-readonly-3ee8b521";
```

Any attempt to connect with those credentials fails:

```
FATAL: role "v-token-readonly-3ee8b521" does not exist
```

If the agent (or anyone who intercepted the credentials) tries to use them after expiry, they get nothing. There's no password to rotate, no key to revoke manually, no "forgot to clean up" scenario. The credentials simply cease to exist.

For sensitive operations, the system also supports **immediate revocation** — the agent (or an administrator) can revoke the Vault lease directly:

```
PUT /v1/sys/leases/revoke
{ "lease_id": "<vault_lease_id>" }
```

This revokes the Vault lease instantly, dropping the database role before the TTL expires.

---

## Phase 7: The Audit Trail

After the interaction is complete, every layer has logged what happened — independently, with correlated identifiers. An auditor can trace the full story across six layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                         AUDIT TRAIL                             │
├──────────────┬──────────────────────────────────────────────────┤
│              │                                                  │
│  Keycloak    │  alice@acme.com authenticated via Device Flow    │
│              │  Granted: groups [data-analysts, trading-team]   │
│              │  Token issued at 10:45:00, expires 10:50:00      │
│              │                                                  │
├──────────────┼──────────────────────────────────────────────────┤
│              │                                                  │
│  SPIRE       │  SVID issued to spiffe://demo.local/agent/       │
│              │  query-agent (workload attested via UID match)   │
│              │                                                  │
├──────────────┼──────────────────────────────────────────────────┤
│              │                                                  │
│  Token       │  Session: sess-3ee8b521a1b2c3d4                  │
│  Exchange    │  Human: alice@acme.com                            │
│              │  Agent: spiffe://demo.local/agent/query-agent    │
│              │  Scope: readonly                                  │
│              │  Fused delegation JWT minted                      │
│              │                                                  │
├──────────────┼──────────────────────────────────────────────────┤
│              │                                                  │
│  Vault       │  Lease: database/creds/ai-agent-readonly/hvs...  │
│  (audit +    │  Entity metadata:                                 │
│   Sentinel)  │    human_user = alice@acme.com                    │
│              │    agent_identity = spiffe://.../query-agent      │
│              │    delegation_scope = readonly                    │
│              │  Sentinel EGP results: all 4 policies passed     │
│              │  TTL: 300s                                        │
│              │                                                  │
├──────────────┼──────────────────────────────────────────────────┤
│              │                                                  │
│  Vault       │  Lease created: 10:45:31                          │
│  Lease       │  Lease expires: 10:50:31                          │
│              │  Role: v-token-readonly-3ee8b521                  │
│              │  Revoked: 10:50:31 (TTL expiry)                  │
│              │                                                  │
├──────────────┼──────────────────────────────────────────────────┤
│              │                                                  │
│  PostgreSQL  │  [pgaudit] user=v-token-readonly-3ee8b521        │
│              │  SELECT customer_name, product FROM app.orders    │
│              │  WHERE total_amount > 1000                        │
│              │                                                  │
└──────────────┴──────────────────────────────────────────────────┘
```

Vault's audit log natively records both the human and agent identity on every credential request, plus Sentinel policy decisions. This eliminates the need for a separate policy engine log — the enforcement and audit happen in a single system.

An auditor can start at any layer and trace forward or backward. The **session ID** (`sess-3ee8b521a1b2c3d4`) and the **Vault-generated username** (`v-token-readonly-3ee8b521`) serve as correlation keys across all systems.

---

## The Complete Picture

Here's the full architecture at a glance — four trust boundaries, each with its own verification:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY 1: Identity Infrastructure                              │
│                                                                         │
│   ┌──────────┐     ┌───────────────┐                                   │
│   │ Keycloak │     │ SPIRE Server  │                                   │
│   │          │     │               │                                   │
│   │ "Who is  │     │ "Who is this  │                                   │
│   │  the     │     │  software     │                                   │
│   │  human?" │     │  workload?"   │                                   │
│   └──────────┘     └───────────────┘                                   │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│  TRUST BOUNDARY 2: Proxy + Identity Broker                              │
│                                                                         │
│   ┌──────────────────────────────────────────────────────────┐         │
│   │  AgentGateway                                             │         │
│   │  "Front door — authenticate, rate-limit, route"           │         │
│   └─────────────────────────┬────────────────────────────────┘         │
│                              │                                          │
│   ┌─────────────────────────┴────────────────────────────────┐         │
│   │  Token Exchange Service                                   │         │
│   │  "Validate both identities, mint fused delegation JWT"    │         │
│   └──────────────────────────────────────────────────────────┘         │
│                                                                         │
│   ┌──────────────────────────────────────────────────────────┐         │
│   │  HashiCorp Vault (Enterprise)                             │         │
│   │  "Authenticate agents, enforce Sentinel policy,           │         │
│   │   mint unique, time-limited database credentials"         │         │
│   └──────────────────────────────────────────────────────────┘         │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│  TRUST BOUNDARY 3: Agent Workloads                                      │
│                                                                         │
│   ┌────────────────────────┐    ┌────────────────────────┐             │
│   │  Query Agent           │───>│  SQL Executor           │             │
│   │  SPIFFE: .../agent/    │    │  SPIFFE: .../subagent/  │             │
│   │  query-agent           │    │  sql-executor           │             │
│   └────────────────────────┘    └────────────────────────┘             │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│  TRUST BOUNDARY 4: Protected Resources                                  │
│                                                                         │
│   ┌──────────────────────────────────────────────────────────┐         │
│   │  PostgreSQL                                               │         │
│   │  "Every query logged. Every role unique. Every            │         │
│   │   credential expires."                                    │         │
│   └──────────────────────────────────────────────────────────┘         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## What Makes This Different

| Traditional Approach | This System |
|---|---|
| Shared database password in config file | Unique credentials per delegation, per session |
| Credentials live forever until rotated | Credentials auto-expire in 5 minutes |
| Agent has a service account with broad access | Agent gets exactly the permissions Alice's groups allow |
| "Who ran this query?" — Nobody knows | Every query traces back to a specific human through a cryptographic chain |
| Agent can do anything once authenticated | Vault Sentinel EGPs evaluate every credential request in real time |
| Sub-agent gets parent's full credentials | Sub-agent can only narrow scope, never widen it |
| Audit = application logs (maybe) | 6-layer correlated audit trail across every component |
| Agent stores human's password | Agent never sees human's password (Device Flow) |

---

## Try It Yourself

```bash
# Start all services
docker compose up -d

# Bootstrap Vault, SPIRE, and database
./scripts/bootstrap.sh

# Run the full demo (Device Flow — recommended)
./scripts/demo.sh
```

The demo walks through every phase described above with a real Keycloak login, real SPIRE identities, real Vault Sentinel policy enforcement, real Vault dynamic credentials, and a real PostgreSQL query — all running locally in containers.

---

*Every query traces back to a human, through a chain of delegated identities, each validated by policy, with cryptographic proof at every step.*
