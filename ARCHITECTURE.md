# Architecture: Secure Agentic AI Identity & Database Access (v3)

## System Overview (v3 — Production-Hardened)

```
+=========================================================================+
|               IDENTITY DELEGATION CHAIN (v3)                            |
|   Human (Alice) --> Agent --> [Sub-Agent] --> PostgreSQL Database        |
|                                                                         |
|  "Every query traces back to a human, through a chain of delegated      |
|   identities, each validated by policy with cryptographic proof."       |
|                                                                         |
|  v3 security hardening:                                                 |
|   - Dynamic per-user agent consent (may_act via Keycloak attributes)   |
|   - Vault periodic token with auto-renewal and policy restrictions     |
|   - Optional mTLS via SPIFFE X.509-SVIDs on critical path             |
|   - Cryptographic SPIFFE SVID verification (SPIRE OIDC JWKS)          |
|   - RS256 delegation token signing with JWKS endpoint                  |
|   - Fail-closed defaults (Keycloak, SPIRE unavailable → deny)         |
|   - No synthetic/demo identities — real SPIRE SVIDs required           |
+=========================================================================+

                    +-------------------+
                    |   Human (Alice)   |
                    | alice@acme.com    |
                    | groups:           |
                    |  - data-analysts  |
                    |  - trading-team   |
                    +--------+----------+
                             |
                    (1) Device Auth Flow (RFC 8628)
                    Human opens browser, logs in
                    directly with Keycloak.
                    Agent NEVER sees password.
                    (Or: token from upstream app)
                             |
                             v
                  +---------------------+
                  |      Keycloak       |
                  |   (OIDC Provider)   |
                  |    :8080            |
                  +----------+----------+
                             |
                   (2) JWT Access Token
                   Claims: sub, email,
                   groups[], may_act{}
                   may_act sourced from user's
                   agent_consent attribute
                   (dynamic, per-user consent)
                             |
                             v
              +--------------+--------------+
              |        AI Agent             |
              |  (Python Workload)          |
              |                             |
              |  Has:                       |
              |  - Human's OIDC token       |
              |    (NOT the password)       |
              |  - Own SPIFFE identity      |
              +----+-------------------+----+
                   |                   |
          (3) SPIFFE SVID       (4) RFC 8693 Token Exchange
          from SPIRE            POST /v1/token/exchange
                   |             {subject_token: human_jwt,
                   v              actor_token: agent_svid}
          +----------------+           |
          |  SPIRE Agent   |           |
          | (Workload API) |           |
          +-------+--------+           |
                  |                    |
                  v                    v
          +----------------+  +=====================+
          |  SPIRE Server  |  |   AgentGateway      |
          | (Trust Root)   |  | (Rust MCP/A2A Proxy)|
          |   :8081        |  |   :9080             |
          +----------------+  |                     |
                              | - OIDC auth         |
                              | - RBAC policies     |
                              | - Rate limiting     |
                              | - Observability     |
                              +==========+==========+
                                         |
                               routes to |
                                         v
                              +=====================+
                              | Token Exchange Svc  |
                              | (Python, RFC 8693)  |
                              |   :8090             |
                              |                     |
                              | - subject_token     |
                              | - actor_token       |
                              | - SPIFFE JWKS verify|
                              |   (SPIRE OIDC)     |
                              | - RS256 delegation  |
                              |   token signing     |
                              | - delegation chain  |
                              | - act{} claim       |
                              | - scope narrowing   |
                              | - fail-closed       |
                              | - mTLS (optional)   |
                              | - stateless (no     |
                              |   Vault dependency) |
                              +==========+==========+
                                         |
                              +----------+----------+
                              |                     |
                     (5) Validate              (6) Mint fused
                     Tokens (Keycloak          delegation JWT
                     userinfo + SPIFFE         (RS256, act{} claim)
                     JWKS verification)              |
                              |                      |
                              v                      v
                    +-----------+            +----------+
                    | Keycloak  |            |  Agent   |
                    | userinfo  |            | receives |
                    +-----------+            | fused JWT|
                                             +----+-----+
                                                  |
                                    (7) Agent authenticates
                                    to Vault directly:
                                    a) SPIFFE JWT auth → workload token
                                    b) Fused JWT auth → delegation token
                                    (Vault Sentinel EGPs enforce policy)
                                                  |
                                                  v
                                             +----------+
                                             |  Vault   |
                                             |  :8200   |
                                             +----+-----+
                                                   |
                                          (8) CREATE ROLE
                                          v-token-readonly-xxx
                                          TTL: 5 minutes
                                                   |
                                                   v
                                          +-------------------+
                                          |   PostgreSQL      |
                                          |   (appdb) :5432   |
                                          +-------------------+
                                                   ^
                                                   |
                                         (9) SQL queries
                                         using dynamic creds
                                                   |
                                          +--------+--------+
                                          |    AI Agent /   |
                                          |    Sub-Agent    |
                                          +-----------------+
```

## Identity Delegation Flow (Vault Enterprise Model)

```
 Human      Keycloak    Agent     SPIRE    AgentGW    TokenExchange    Vault     PostgreSQL  SPIRE OIDC
   |            |          |        |         |             |            |           |          |
   |-(login)--->|          |        |         |             |            |           |          |
   |<--(JWT)----|          |        |         |             |            |           |          |
   |  {sub, email,         |        |         |             |            |           |          |
   |   groups, may_act}    |        |         |             |            |           |          |
   |            |          |        |         |             |            |           |          |
   |---(token)->| (task)   |        |         |             |            |           |          |
   |            |          |        |         |             |            |           |          |
   |            |          |-(SVID)->|        |             |            |           |          |
   |            |          |<(SVID)--|        |             |            |           |          |
   |            |          |        |         |             |            |           |          |
   |            |  RFC 8693 Token Exchange    |             |            |           |          |
   |            |          |----(POST /v1/token/exchange)-->|            |           |          |
   |            |          |  grant_type: token-exchange    |            |           |          |
   |            |          |  subject_token: human_jwt      |            |           |          |
   |            |          |  actor_token: agent_svid       |            |           |          |
   |            |          |  scope: readonly               |            |           |          |
   |            |          |        |         |             |            |           |          |
   |            |          |        |         |   [Validate subject_token]           |          |
   |            |<----------------------------------(userinfo)          |           |          |
   |            |-----------------------------------(claims)>|          |           |          |
   |            |          |        |         |             |            |           |          |
   |            |          |        |         |   [Validate actor_token (SPIFFE JWT-SVID)]     |
   |            |          |        |         |             |------(GET /keys)------|--------->|
   |            |          |        |         |             |<-----(JWKS)-----------|----------|
   |            |          |        |         |   Signature verified (RS256) via SPIRE JWKS    |
   |            |          |        |         |             |            |           |          |
   |            |          |        |         |   [Mint fused delegation JWT]        |          |
   |            |          |        |         |   act: {sub: agent,     |           |          |
   |            |          |        |         |     act: {sub: alice}}  |           |          |
   |            |          |        |         |   Sign delegation token (RS256, in-memory RSA keypair)
   |            |          |        |         |             |            |           |          |
   |            |          |<-----(fused delegation JWT)----|            |           |          |
   |            |          |        |         |             |            |           |          |
   |            |          |  [Two-login Vault auth]        |            |           |          |
   |            |          |  a) SPIFFE JWT auth → workload token        |           |          |
   |            |          |----(POST /v1/auth/jwt/login, role=spiffe)-->|           |          |
   |            |          |<---(Vault workload token)------|------------|           |          |
   |            |          |  b) Fused JWT auth → delegation token       |           |          |
   |            |          |----(POST /v1/auth/jwt/login, role=deleg)--->|           |          |
   |            |          |<---(Vault delegation token, scoped policy)--|           |          |
   |            |          |        |         |             |            |           |          |
   |            |          |  [Request DB credentials from Vault]        |           |          |
   |            |          |----(GET /v1/database/creds/ai-agent-readonly)---------->|          |
   |            |          |<---(username, password, lease_id)-----------|           |          |
   |            |          |        |         |             |  (CREATE ROLE)-------->|          |
   |            |          |        |         |             |            |           |          |
   |            |          |  [Vault Sentinel EGPs enforce delegation policy]        |          |
   |            |          |  - require-delegation: metadata must exist  |           |          |
   |            |          |  - enforce-scope: scope matches role        |           |          |
   |            |          |  - enforce-chain-depth: depth <= 3          |           |          |
   |            |          |  - enforce-may-act: human authorized agent  |           |          |
   |            |          |        |         |             |            |           |          |
   |            |          |--------(SQL query with dynamic creds)-------|---------->|          |
   |            |          |<-------(results)----------------------------------------|          |
   |            |          |        |         |             |            |           |          |
   |            |          |  [Revoke credentials]          |            |           |          |
   |            |          |----(PUT /v1/sys/leases/revoke)------------->|           |          |
   |            |          |        |         |             |            |  (DROP ROLE)-------->|
   |            |          |        |         |             |            |           |          |
```

## Sub-Agent Delegation Chain Extension

```
                    +------------------+
                    |  Human (Alice)   |
                    |  alice@acme.com  |
                    +--------+---------+
                             |
                    OIDC Token (subject_token)
                    {sub, email, groups, may_act}
                             |
                    +--------v---------+
                    |  Parent Agent    |  Depth 0: Human -> Agent
                    |  spiffe://demo.  |
                    |  local/agent/    |
                    |  query-agent     |
                    +--------+---------+
                             |
                    RFC 8693 Token Exchange
                    subject_token = human_jwt
                    actor_token = agent_svid
                             |
                    +--------v---------+
                    | Delegation Token |
                    | sub: alice@acme  |
                    | act: {           |
                    |   sub: agent,    |
                    |   act: {         |
                    |     sub: alice   |
                    |   }              |
                    | }                |
                    | scope: readonly  |
                    +--------+---------+
                             |
            +----------------+----------------+
            |                                 |
   (Can use directly)              (Can delegate further)
            |                                 |
   +--------v---------+             +--------v---------+
   |  Query Database  |             |  Sub-Agent       |  Depth 1: Agent -> Sub-Agent
   |  SELECT * FROM   |             |  spiffe://demo.  |
   |  app.orders ...  |             |  local/subagent/ |
   +------------------+             |  sql-executor    |
                                    +--------+---------+
                                             |
                                    RFC 8693 Token Exchange
                                    subject_token = delegation_jwt
                                    actor_token = subagent_svid
                                    scope: readonly (narrowed)
                                             |
                                    +--------v---------+
                                    | Sub-Delegation   |
                                    | sub: alice@acme  |
                                    | act: {           |
                                    |   sub: subagent, |
                                    |   act: {         |
                                    |     sub: agent,  |
                                    |     act: {       |
                                    |       sub: alice |
                                    |     }            |
                                    |   }              |
                                    | }                |
                                    | scope: readonly  |
                                    +--------+---------+
                                             |
                                    Query with sub-agent's
                                    own Vault credentials
                                             |
                                    +--------v---------+
                                    |   PostgreSQL     |
                                    |   (via Vault     |
                                    |    dynamic creds)|
                                    +------------------+

  Delegation Chain Constraints:
  +----------------------------+-------+
  | Max depth                  |   3   |
  | Scope narrowing            | Only  |
  | Sub-agent can request      | same  |
  | same or narrower scope     | or <  |
  | TTL inheritance            | Min   |
  | Each level gets min(parent,| of    |
  |  configured) TTL           | both  |
  +----------------------------+-------+
```

## Dynamic Agent Consent (may_act)

```
  +-------------------------------------------------------------------+
  |  User-Controlled Agent Authorization                              |
  |                                                                    |
  |  Each Keycloak user has an "agent_consent" attribute that          |
  |  controls which AI agents may act on their behalf. The OIDC       |
  |  mapper reads this attribute at token issuance and emits it as    |
  |  the may_act claim in the JWT. No hardcoded consent values.       |
  +-------------------------------------------------------------------+

  +-----------------+              +-------------------+
  |  Demo UI (:8500)|              |  Keycloak (:8080) |
  |                 |              |                   |
  | Consent Step    |  Admin API   | User Attributes:  |
  | [x] query-agent |----(PUT)--->| alice:            |
  | [x] analysis-*  |             |   agent_consent:  |
  | [ ] write-agent |             |   {"sub":"spiffe: |
  |                 |             |    .../query-agent|
  | [Update] [Revoke]             |    ","aud":[...]} |
  +-----------------+              +--------+----------+
                                            |
                                   Token issuance
                                   (oidc-usermodel-
                                    attribute-mapper)
                                            |
                                            v
                                   +-------------------+
                                   | JWT Access Token  |
                                   | {                 |
                                   |   "sub": "alice", |
                                   |   "may_act": {    |
                                   |     "sub": "spiffe|
                                   |       ://demo.    |
                                   |       local/agent/|
                                   |       query-agent"|
                                   |     ,"aud": [...] |
                                   |   }               |
                                   | }                 |
                                   +-------------------+

  Consent Flow:
  1. Human logs in via Device Auth or Auth Code flow
  2. Demo UI loads current consent via Keycloak Admin API
     GET /admin/realms/demo/users/{id} → attributes.agent_consent
  3. Human selects which agents to authorize (checkboxes)
  4. Demo UI updates consent via Keycloak Admin API
     PUT /admin/realms/demo/users/{id} {attributes: {agent_consent: ...}}
  5. Next token issuance includes updated may_act claim
  6. Vault Sentinel enforce-may-act validates agent is authorized

  Pre-seeded Defaults:
  +--------+-----------------------------------------------------------+
  | User   | Consented Agents                                          |
  +--------+-----------------------------------------------------------+
  | alice  | query-agent, analysis-agent, write-agent (all 3)          |
  | bob    | query-agent only                                          |
  +--------+-----------------------------------------------------------+
```

## Component Architecture (v3)

```
+-------------------------------------------------------------------------+
|                        Docker Network: identity-net                      |
|                                                                         |
|  +========================+    +=========================+              |
|  | IDENTITY LAYER         |    | VERIFICATION LAYER      |              |
|  |                        |    |                         |              |
|  | +--------------------+ |    | +---------------------+ |              |
|  | | SPIRE Server :8081 | |    | | SPIRE OIDC :8082    | |              |
|  | | Trust Domain Root  | |    | | JWKS for JWT-SVID   | |              |
|  | | - CA certificates  | |    | | verification        | |              |
|  | | - SVID issuer      | |    | +---------------------+ |              |
|  | +--------+-----------+ |    |                         |              |
|  |          |              |    | +---------------------+ |              |
|  |    (attestation)        |    | | Vault Sentinel EGPs | |              |
|  |          |              |    | | (Enterprise)        | |              |
|  | +--------v-----------+ |    | |                     | |              |
|  | | SPIRE Agent        | |    | | require-delegation  | |              |
|  | | Workload Attestor  | |    | | enforce-scope       | |              |
|  | +--------------------+ |    | | enforce-chain-depth | |              |
|  |                        |    | | enforce-may-act     | |              |
|  | +--------------------+ |    | |                     | |              |
|  | | Keycloak :8080     | |    | | Applied to:         | |              |
|  | | OIDC Identity Prov | |    | |  database/creds/*   | |              |
|  | |                    | |    | |  hard-mandatory      | |              |
|  | | Realm: demo        | |    | +---------------------+ |              |
|  | | Users:             | |    |                         |              |
|  | |  alice (analyst)   | |    +=========================+              |
|  | |  bob   (engineer)  | |                                             |
|  | |                    | |                                             |
|  | | may_act mapper:    | |                                             |
|  | |  usermodel-attrib  | |                                             |
|  | |  reads per-user    | |                                             |
|  | |  agent_consent     | |                                             |
|  | +--------------------+ |                                             |
|  +========================+                                             |
|                                                                         |
|  +===================================================================+ |
|  | PROXY LAYER                                                       | |
|  |                                                                    | |
|  | +----------------------------------------------------------------+| |
|  | | AgentGateway :9080 (Rust, open-source)                          || |
|  | |   https://github.com/agentgateway/agentgateway                 || |
|  | |                                                                  || |
|  | |  MCP Listener  -- AI agents connect via MCP (SSE/HTTP)         || |
|  | |  HTTP Listener -- REST API for backward compatibility           || |
|  | |  Admin API     -- Health, metrics (:19000)                      || |
|  | |                                                                  || |
|  | |  Features:                                                       || |
|  | |   - OIDC authentication (Keycloak)                              || |
|  | |   - SPIFFE workload identity                                     || |
|  | |   - RBAC with group-to-role mapping                             || |
|  | |   - Rate limiting (60 req/min per identity)                     || |
|  | |   - Observability (JSON logging, metrics)                       || |
|  | |                                                                  || |
|  | |  Routes to: Token Exchange Service                              || |
|  | +----------------------------------------------------------------+| |
|  +===================================================================+ |
|                                                                         |
|  +===================================================================+ |
|  | TOKEN EXCHANGE LAYER (Stateless JWT Minter, RFC 8693)            | |
|  |                                                                    | |
|  | +----------------------------------------------------------------+| |
|  | | Token Exchange Service :8090 (Python)                           || |
|  | |                                                                  || |
|  | |  POST /v1/token/exchange  -- RFC 8693 Token Exchange            || |
|  | |  POST /v1/delegate        -- Legacy delegation API              || |
|  | |  POST /v1/token/revoke    -- (Legacy) delegation audit           || |
|  | |  GET  /v1/delegation/chain -- Query delegation chain            || |
|  | |  GET  /health             -- Service health                     || |
|  | |  GET  /v1/audit           -- Audit trail                        || |
|  | |  GET  /.well-known/jwks.json -- Delegation token JWKS           || |
|  | |                                                                  || |
|  | |  Token Signing: RS256 (in-memory RSA-2048 keypair)              || |
|  | |    Key can be loaded from SIGNING_KEY_PATH env var              || |
|  | |    Public key exposed at /.well-known/jwks.json                 || |
|  | |                                                                  || |
|  | |  SPIFFE Verification: Cryptographic (not string prefix)         || |
|  | |    Fetches JWKS from SPIRE OIDC (GET /keys)                    || |
|  | |    Validates JWT-SVID signature (RS256)                         || |
|  | |                                                                  || |
|  | |  Fail-Closed Behavior:                                           || |
|  | |    Keycloak unavailable ---> reject token (not accept)          || |
|  | |    SPIRE OIDC unavailable -> reject actor (not accept)          || |
|  | |                                                                  || |
|  | |  mTLS (optional, via SPIFFE X.509-SVIDs):                       || |
|  | |    Enabled with MTLS_ENABLED=true                               || |
|  | |    Fetches X.509-SVID from SPIRE Workload API                   || |
|  | |    TLSv1.2+ with mutual certificate verification                || |
|  | |    Graceful fallback to HTTP if SPIRE unavailable               || |
|  | |                                                                  || |
|  | |  Stateless — no Vault dependency, no credential brokering        || |
|  | |  Mints fused delegation JWTs only                               || |
|  | |                                                                  || |
|  | |  Connects to:                                                    || |
|  | |   Keycloak ----> validate subject_token (human OIDC)            || |
|  | |   SPIRE OIDC --> fetch JWKS for JWT-SVID verification           || |
|  | |                                                                  || |
|  | |  Token Exchange Parameters (RFC 8693):                          || |
|  | |   grant_type:        urn:ietf:params:oauth:grant-type:          || |
|  | |                      token-exchange                              || |
|  | |   subject_token:     Human's OIDC JWT                           || |
|  | |   subject_token_type: access_token                              || |
|  | |   actor_token:       Agent's SPIFFE JWT-SVID                    || |
|  | |   actor_token_type:  jwt                                        || |
|  | |   scope:             readonly | readwrite                       || |
|  | |   audience:          database | other-service                   || |
|  | +----------------------------------------------------------------+| |
|  +===================================================================+ |
|                                                                         |
|  +===================================================================+ |
|  | WORKLOAD LAYER                    DATA LAYER                       | |
|  |                                                                    | |
|  | +---------------------------+   +-------------------------------+  | |
|  | | AI Agent (Python)         |   | PostgreSQL :5432              |  | |
|  | |                           |   |                               |  | |
|  | | 1. Get SPIFFE SVID        |   | Database: appdb               |  | |
|  | | 2. Authenticate human     |   | Schema: app                   |  | |
|  | | 3. RFC 8693 exchange      |   | Tables: orders, customers,    |  | |
|  | | 4. Receive delegation tok |   |         products              |  | |
|  | | 5. [Delegate to sub-agent]|   | Views: order_summary          |  | |
|  | | 6. Query database         |   |                               |  | |
|  | | 7. Creds auto-expire      |   | Vault-managed roles:          |  | |
|  | |                           |   |  v-token-readonly-{uuid}      |  | |
|  | | Sub-Agents:               |   |  v-token-readwrite-{uuid}     |  | |
|  | |  - sql-executor           |   |                               |  | |
|  | |  - result-formatter       |   | Audit: pgaudit + log_stmt=all |  | |
|  | +---------------------------+   +-------------------------------+  | |
|  +===================================================================+ |
+-------------------------------------------------------------------------+
```

## Vault Sentinel EGP Policy Enforcement

```
  Vault Sentinel Endpoint Governing Policies (EGPs) replace OPA as the
  policy engine. Policies are applied to database/creds/* with
  hard-mandatory enforcement. They execute inside Vault at credential
  request time, using entity metadata populated by JWT/SPIFFE auth.

                    Agent requests DB credentials
                    GET /v1/database/creds/ai-agent-readonly
                                |
                    +-----------v-----------+
                    | require-delegation    |
                    | - human_user present  |
                    | - agent_identity set  |
                    | - delegation_scope set|
                    | - agent in trust      |
                    |   domain (spiffe://   |
                    |   demo.local/*)       |
                    +-----------+-----------+
                         pass   |   fail
                        +-------+--------+
                        |                |
                        v                v
              +-----------------+   DENY: "missing
              | enforce-scope   |    delegation metadata"
              | - readonly path |
              |   requires      |
              |   readonly scope|
              | - readwrite path|
              |   requires      |
              |   readwrite     |
              |   scope         |
              +--------+--------+
                  pass |   fail
                 +-----+------+
                 |            |
                 v            v
        +----------------+ DENY: "scope
        | enforce-chain- |  mismatch"
        | depth          |
        | - chain_depth  |
        |   <= 3         |
        +-------+--------+
           pass |   fail
          +-----+------+
          |            |
          v            v
  +---------------+ DENY: "max depth
  | enforce-may-  |  exceeded"
  | act           |
  | - may_act     |
  |   matches     |
  |   agent_id    |
  | - exact or    |
  |   wildcard    |
  +------+--------+
    pass |   fail
   +-----+------+
   |            |
   v            v
 ALLOW       DENY: "agent not
 (issue       authorized by
  creds)      human"

  Registered Identities (SPIRE entries):
  +---------------------------------------------+-----------+
  | SPIFFE ID                                   | Type      |
  +---------------------------------------------+-----------+
  | spiffe://demo.local/agent/query-agent       | Agent     |
  | spiffe://demo.local/agent/analysis-agent    | Agent     |
  | spiffe://demo.local/agent/write-agent       | Agent     |
  | spiffe://demo.local/service/token-exchange  | Service   |
  | spiffe://demo.local/subagent/sql-executor   | Sub-Agent |
  | spiffe://demo.local/subagent/result-format* | Sub-Agent |
  +---------------------------------------------+-----------+
```

## Vault Credential Lifecycle

```
  Time
   |
   |  T=0  Agent authenticates to Vault (two-login pattern)
   |   |
   |   |   Agent requests credentials directly:
   |   |   GET /v1/database/creds/ai-agent-readonly
   |   |
   |   v
   |  +------------------------------------------------------------------+
   |  | Vault creates PostgreSQL role:                                    |
   |  |                                                                   |
   |  |   CREATE ROLE "v-token-readonly-3ee8b521"                        |
   |  |     WITH LOGIN PASSWORD 'rV9z4k...'                              |
   |  |     VALID UNTIL '2026-02-21 10:50:23'                            |
   |  |     INHERIT;                                                      |
   |  |   GRANT USAGE ON SCHEMA app TO "v-token-readonly-3ee8b521";      |
   |  |   GRANT SELECT ON ALL TABLES IN SCHEMA app                       |
   |  |     TO "v-token-readonly-3ee8b521";                              |
   |  +------------------------------------------------------------------+
   |
   |  T=0..300s  Agent (or sub-agent) uses credentials
   |   |
   |   |   SELECT * FROM app.order_summary
   |   |   WHERE total_amount > 1000
   |   |
   |   |   [pgaudit logs every query with user = v-token-readonly-3ee8b521]
   |   |
   |  T=300s  Lease expires (TTL = 5 minutes)
   |   |
   |   v
   |  +------------------------------------------------------------------+
   |  | Vault auto-revokes:                                               |
   |  |                                                                   |
   |  |   DROP ROLE IF EXISTS "v-token-readonly-3ee8b521";               |
   |  |                                                                   |
   |  | Result: All new connection attempts fail                          |
   |  |         Existing connections closed on next query                 |
   |  +------------------------------------------------------------------+
   |
   v

  Manual revocation via Vault API:
    PUT /v1/sys/leases/revoke {"lease_id": "<vault_lease_id>"}
    --> Revokes Vault lease
    --> Immediately drops the PostgreSQL role
```

## Agent Two-Login Vault Authentication

```
  Agents authenticate directly to Vault using a two-login pattern.
  This replaces the previous model where Token Exchange brokered
  Vault credentials on behalf of agents.

  Login 1: SPIFFE JWT Auth (workload identity)
  +-------------------------------------------------------------------+
  | POST /v1/auth/jwt/login                                           |
  |   role: "spiffe-agent"                                            |
  |   jwt: <agent's SPIFFE JWT-SVID>                                  |
  |                                                                   |
  | Result: Vault workload token                                      |
  |   - Proves which agent is making the request                      |
  |   - Entity metadata: agent_identity, trust_domain                 |
  +-------------------------------------------------------------------+

  Login 2: Fused Delegation JWT Auth (human + agent identity)
  +-------------------------------------------------------------------+
  | POST /v1/auth/jwt/login                                           |
  |   role: "agent-readonly" or "agent-readwrite"                     |
  |   jwt: <fused delegation JWT from Token Exchange>                 |
  |                                                                   |
  | Result: Vault delegation token with scoped policies               |
  |   - Entity metadata populated from JWT claims:                    |
  |     human_user, agent_identity, delegation_scope,                 |
  |     chain_depth, may_act                                          |
  |   - Policies: ai-agent-db-read or ai-agent-db-readwrite          |
  |   - Sentinel EGPs enforce delegation constraints                  |
  +-------------------------------------------------------------------+

  Credential Request (with delegation token):
  +-------------------------------------------------------------------+
  | GET /v1/database/creds/ai-agent-readonly                          |
  |   Authorization: Bearer <Vault delegation token>                  |
  |                                                                   |
  | Sentinel EGPs evaluate at request time:                           |
  |   require-delegation  --> metadata exists?                        |
  |   enforce-scope       --> scope matches role?                     |
  |   enforce-chain-depth --> depth <= 3?                             |
  |   enforce-may-act     --> human authorized this agent?            |
  |                                                                   |
  | Result: Dynamic PostgreSQL credentials (5-min TTL)                |
  +-------------------------------------------------------------------+
```

## mTLS Transport Security

```
  The Token Exchange Service optionally supports mutual TLS using
  SPIFFE X.509-SVIDs from the SPIRE Workload API. This provides
  transport-layer identity verification on the critical path where
  identity tokens are exchanged.

  +-------------------------------------------------------------------+
  |  AI Agent                         Token Exchange Service          |
  |                                                                   |
  |  Connects via HTTPS              MTLS_ENABLED=true                |
  |  with client X.509-SVID          Server X.509-SVID:              |
  |                                   spiffe://demo.local/            |
  |   +------------------+            service/token-exchange          |
  |   | SPIRE Agent      |                                           |
  |   | Workload API     |   +----------------------------------+    |
  |   |                  |   | _setup_mtls_context():            |    |
  |   | fetch_x509_      |   |   1. Fetch X.509-SVID from SPIRE |    |
  |   | context()        |   |   2. Create ssl.SSLContext         |    |
  |   +------------------+   |   3. Load cert chain + private key |    |
  |                          |   4. Load trust bundle as CA       |    |
  |                          |   5. verify_mode = CERT_REQUIRED   |    |
  |                          |   6. min version = TLSv1.2         |    |
  |                          |   7. Wrap server socket            |    |
  |                          +----------------------------------+    |
  +-------------------------------------------------------------------+

  SPIRE Registration Entries:
  +-----------------------------------------------+--------------------+
  | SPIFFE ID                                     | DNS / Selector     |
  +-----------------------------------------------+--------------------+
  | spiffe://demo.local/agent/query-agent         | ai-agent, uid:0    |
  | spiffe://demo.local/agent/analysis-agent      | ai-agent, uid:0    |
  | spiffe://demo.local/agent/write-agent         | ai-agent, uid:0    |
  | spiffe://demo.local/service/token-exchange     | token-exchange,    |
  |                                               | uid:0              |
  | spiffe://demo.local/subagent/sql-executor     | ai-agent, uid:0    |
  | spiffe://demo.local/subagent/result-formatter | ai-agent, uid:0    |
  +-----------------------------------------------+--------------------+

  Fallback behavior:
  - SPIRE agent socket not found    --> HTTP (warning logged)
  - spiffe library not installed    --> HTTP (warning logged)
  - No X.509-SVIDs received        --> HTTP (warning logged)
  - MTLS_ENABLED not set to "true" --> HTTP (default)

  Note: Third-party services (Keycloak, Vault, PostgreSQL) don't
  natively consume SPIRE Workload API SVIDs. Full mTLS coverage would
  require sidecar cert injection (spiffe-helper) or an Envoy service
  mesh. The current implementation covers the critical path where
  identity tokens are exchanged.
```

## 6-Layer Audit Correlation Chain

```
  +--------+   +----------+   +----------+   +---------+   +---------+   +----------+
  |   1    |   |    2     |   |    3     |   |    4    |   |    5    |   |    6     |
  |Keycloak|-->|AgentGW   |-->|  Token   |-->|  Vault  |-->|  Lease  |-->|PostgreSQL|
  | Token  |   | Access   |   |Exchange  |   |Metadata |   | Record  |   | pgaudit  |
  | (OIDC) |   |  Log     |   | Audit    |   |+ Sentinel   |         |   |          |
  +--------+   +----------+   +----------+   +---------+   +---------+   +----------+
       |            |              |              |             |              |
       v            v              v              v             v              v
  +---------+  +---------+   +-----------+  +----------+ +-----------+ +----------+
  | JWT     |  |identity |   |session_id |  | entity   | | lease_id  | | user:    |
  | sub:    |  |OIDC auth|   |request_id |  | metadata:| | lease_ttl | | v-token- |
  |  alice  |  |SPIFFE id|   |human:     |  |  human   | | renewable | |  readonly|
  | email:  |  |RBAC role|   | alice@    |  |  scope   | |           | |  -xxx    |
  |  alice@ |  |rate     |   |actor:     |  |  agent   | |           | |          |
  | groups: |  | limit   |   | agent/    |  |  chain   | |           | | query:   |
  | may_act:|  |scope    |   | subagent  |  |  session | |           | |  SELECT  |
  |  {sub}  |  |         |   |chain:     |  |  depth   | |           | |  FROM    |
  | exp:    |  |         |   | [links]   |  | Sentinel | |           | |  app.*   |
  +---------+  +---------+   |act: {...} |  | EGP logs | +-----------+ +----------+
                              +-----------+  +----------+

  Vault audit log natively records both human and agent identity via
  entity metadata, plus Sentinel EGP policy decisions. This replaces
  the separate OPA decision log, consolidating policy enforcement
  and audit into a single system.
```

## Port Map & Network Topology (v3)

```
  Host Machine
  +-----------------------------------------------------------------------+
  |                                                                       |
  |  Exposed Ports:                                                       |
  |                                                                       |
  |  :8080   Keycloak       (OIDC login, admin UI at /admin)             |
  |  :8081   SPIRE          (internal trust infrastructure)              |
  |  :8082   SPIRE OIDC     (JWKS endpoint for JWT-SVID verification)   |
  |  :8090   Token Exchange (RFC 8693 API)                 <-- NEW       |
  |                         (Vault Sentinel EGPs replace OPA)            |
  |  :8200   Vault          (secrets API & UI)                           |
  |  :8500   Demo UI        (interactive educational walkthrough)        |
  |  :5432   PostgreSQL     (database connections)                       |
  |  :9080   AgentGateway   (MCP/HTTP proxy for agents)    <-- CHANGED  |
  |  :19000  AgentGateway   (Admin API: health, metrics)   <-- NEW      |
  |                                                                       |
  +---------------------------+-------------------------------------------+
                              |
                     Docker Bridge Network
                       (identity-net)
                              |
          +-------------------+-------------------+
          |                   |                   |
  +-------v------+   +-------v------+   +--------v-----+
  | spire-server |   |   keycloak   |   |     vault    |
  |    :8081     |   |    :8080     |   |    :8200     |
  +-------+------+   +--------------+   +------+-------+
          |                                     |
  +-------v------+                         |
  | spire-agent  |                 +-------v------+
  | (socket API) |                 |  postgresql  |
  +-------+------+                 |    :5432     |
          |                        +---------+----+
          |                                  ^
          |                                  |
  +-------v-------------+                          |
  |   AgentGateway      |                          |
  |  :9080 (MCP/HTTP)   |                          |
  |  :19000 (Admin)     |                          |
  +-------+-------------+                          |
          |                                        |
  +-------v-------------+                          |
  | Token Exchange Svc  |   (stateless JWT minter)  |
  |  :8090              |                          |
  |  (optional mTLS)    |                          |
  +---------+-----------+                          |
            |                                      |
  +---------v-----------+                          |
  |    ai-agent         |
  |  + sub-agents       |   <-- NEW
  | (no listen port)    |
  +---------+-----------+
            |
            +----(SQL queries with dynamic creds)--+
                                                    |
                                           +--------v-----+
                                           |  postgresql   |
                                           +--------------+

  Dependency Order:
  1. spire-server    (no deps)
  2. postgresql      (no deps)
  3. vault           (no deps)
  4. keycloak        (no deps)
  5. spire-agent     (depends: spire-server healthy)
  6. token-exchange  (depends: keycloak healthy)
  7. agentgateway    (depends: keycloak, token-exchange)
  8. ai-agent        (depends: vault, token-exchange healthy, postgresql)
```

## Key Security Properties (v3)

```
  +-----------------------------+------------------------------------------+
  | Property                    | How It's Achieved                        |
  +-----------------------------+------------------------------------------+
  | No static DB credentials    | Vault generates unique creds per request |
  |                             | TTL: 300s, auto-revoked                  |
  +-----------------------------+------------------------------------------+
  | Human attribution           | OIDC token with sub, email, groups       |
  |                             | Preserved through entire delegation chain|
  +-----------------------------+------------------------------------------+
  | Agent attestation           | SPIFFE JWT-SVID proves workload identity |
  |                             | Cryptographically verified via SPIRE     |
  |                             | OIDC JWKS endpoint (RS256 signature)     |
  +-----------------------------+------------------------------------------+
  | RFC 8693 Token Exchange     | Standard OAuth 2.0 delegation flow       |   <-- NEW
  |                             | subject_token + actor_token -> delegated |
  +-----------------------------+------------------------------------------+
  | Delegation chains           | Nested `act` claims per RFC 8693 Sec 4.1 |   <-- NEW
  |                             | Human -> Agent -> Sub-Agent traceable    |
  +-----------------------------+------------------------------------------+
  | Scope narrowing             | Each delegation level can only narrow    |
  |                             | scope, never widen it                    |
  |                             | Vault Sentinel enforce-scope policy      |
  |                             | validates at credential request time     |
  +-----------------------------+------------------------------------------+
  | Max chain depth             | Configurable limit (default: 3)          |   <-- NEW
  |                             | Prevents infinite delegation             |
  +-----------------------------+------------------------------------------+
  | AgentGateway proxy          | RBAC, rate limiting, observability       |   <-- NEW
  |                             | MCP/A2A protocol support                 |
  +-----------------------------+------------------------------------------+
  | Least privilege             | Vault policies + Sentinel EGPs enforce   |
  |                             | group-to-scope mapping via entity        |
  |                             | metadata from JWT auth claims            |
  +-----------------------------+------------------------------------------+
  | Deny by default             | Vault Sentinel EGPs are hard-mandatory   |
  |                             | All policies must pass for cred issuance |
  +-----------------------------+------------------------------------------+
  | Complete audit trail        | 6-layer correlation from human to query  |
  |                             | Every decision logged with chain context |
  +-----------------------------+------------------------------------------+
  | Zero trust                  | Every request validated end-to-end       |
  |                             | No implicit trust from network position  |
  |                             | Fail-closed when dependencies unavailable|
  +-----------------------------+------------------------------------------+
  | Credential lifecycle        | Auto-revocation after TTL                |
  |                             | Manual revocation via Vault lease API    |
  |                             | PostgreSQL role dropped on expiry        |
  +-----------------------------+------------------------------------------+
  | Asymmetric token signing    | Delegation tokens signed with RS256      |
  |                             | In-memory RSA-2048 keypair (or from env) |
  |                             | Public key at /.well-known/jwks.json     |
  +-----------------------------+------------------------------------------+
  | Fail-closed defaults        | Vault Sentinel -> hard-mandatory deny    |
  |                             | Keycloak unavailable -> reject token     |
  |                             | SPIRE OIDC unavailable -> reject actor   |
  +-----------------------------+------------------------------------------+
  | No synthetic identities     | Agents require real SPIFFE JWT-SVIDs     |
  |                             | from SPIRE; no demo/synthetic fallback   |
  |                             | SPIRE unavailable -> agent fails clearly |
  +-----------------------------+------------------------------------------+
  | SPIFFE-based authorization  | may_act claim uses SPIFFE IDs            |
  |                             | (spiffe://demo.local/agent/...) not      |
  |                             | descriptive names; aud[] list supported  |
  |                             | No legacy bypass for non-SPIFFE values   |
  +-----------------------------+------------------------------------------+
  | Dynamic agent consent       | Per-user agent_consent attribute in      |
  |                             | Keycloak controls which agents may act   |
  |                             | on behalf of the user. Updated via Admin |
  |                             | API. Emitted as may_act via usermodel-   |
  |                             | attribute-mapper (not hardcoded)         |
  +-----------------------------+------------------------------------------+
  | Direct Vault auth           | Agents authenticate directly to Vault    |
  |                             | via two-login pattern (SPIFFE + fused    |
  |                             | JWT). No intermediate credential broker. |
  |                             | Token Exchange is stateless — no Vault   |
  |                             | token, no credential brokering.          |
  +-----------------------------+------------------------------------------+
  | Transport security (mTLS)   | Token Exchange optionally serves over    |
  |                             | mTLS using SPIFFE X.509-SVIDs from      |
  |                             | SPIRE Workload API. TLSv1.2+ with       |
  |                             | mutual cert verification. Graceful       |
  |                             | fallback to HTTP if SPIRE unavailable.   |
  +-----------------------------+------------------------------------------+
```
