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
|   - Fail-closed defaults (OPA, Keycloak, SPIRE unavailable → deny)    |
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
                              | - Vault token       |
                              |   auto-renewal      |
                              +==========+==========+
                                         |
                              +----------+----------+
                              |          |          |
                     (5) Validate  (6) Evaluate  (7) Broker
                     Tokens        OPA Policy    Vault Creds
                              |          |          |
                              v          v          v
                    +-----------+ +---------+ +----------+
                    | Keycloak  | |   OPA   | |  Vault   |
                    | userinfo  | | :8181   | |  :8200   |
                    +-----------+ +---------+ +----+-----+
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

## RFC 8693 Token Exchange Flow

```
 Human      Keycloak    Agent     SPIRE    AgentGW    TokenExchange    OPA       Vault     PostgreSQL  SPIRE OIDC
   |            |          |        |         |             |            |          |           |          |
   |-(login)--->|          |        |         |             |            |          |           |          |
   |<--(JWT)----|          |        |         |             |            |          |           |          |
   |  {sub, email,         |        |         |             |            |          |           |          |
   |   groups, may_act}    |        |         |             |            |          |           |          |
   |            |          |        |         |             |            |          |           |          |
   |---(token)->| (task)   |        |         |             |            |          |           |          |
   |            |          |        |         |             |            |          |           |          |
   |            |          |-(SVID)->|        |             |            |          |           |          |
   |            |          |<(SVID)--|        |             |            |          |           |          |
   |            |          |        |         |             |            |          |           |          |
   |            |  RFC 8693 Token Exchange    |             |            |          |           |          |
   |            |          |----(POST /v1/token/exchange)-->|            |          |           |          |
   |            |          |  grant_type: token-exchange    |            |          |           |          |
   |            |          |  subject_token: human_jwt      |            |          |           |          |
   |            |          |  actor_token: agent_svid       |            |          |           |          |
   |            |          |  scope: readonly               |            |          |           |          |
   |            |          |        |         |             |            |          |           |          |
   |            |          |        |         |   [Validate subject_token]          |           |          |
   |            |<----------------------------------(userinfo)          |          |           |          |
   |            |-----------------------------------(claims)>|          |          |           |          |
   |            |          |        |         |             |            |          |           |          |
   |            |          |        |         |   [Validate actor_token (SPIFFE JWT-SVID)]     |          |
   |            |          |        |         |             |------(GET /keys)-----|---------->|          |
   |            |          |        |         |             |<-----(JWKS)----------|-----------|          |
   |            |          |        |         |   Signature verified (RS256) via SPIRE JWKS    |          |
   |            |          |        |         |             |            |          |           |          |
   |            |          |        |         |   [OPA Policy]          |          |           |          |
   |            |          |        |         |             |-(evaluate)->|         |           |          |
   |            |          |        |         |             |<-(allow)---|         |           |          |
   |            |          |        |         |             |            |          |           |          |
   |            |          |        |         |   [Build delegation chain]          |           |          |
   |            |          |        |         |   act: {sub: agent,     |          |           |          |
   |            |          |        |         |     act: {sub: alice}}  |          |           |          |
   |            |          |        |         |   Sign delegation token (RS256, in-memory RSA keypair)    |
   |            |          |        |         |             |            |          |           |          |
   |            |          |        |         |   [Broker Vault creds]  |          |           |          |
   |            |          |        |         |             |----------(GET creds)->|           |          |
   |            |          |        |         |             |<-(username,password)--|           |          |
   |            |          |        |         |             |            |   (CREATE ROLE)----->|          |
   |            |          |        |         |             |            |          |           |          |
   |            |          |<-----(Token Exchange Response)-|            |          |           |          |
   |            |          |  {access_token: delegation_jwt,|            |          |           |          |
   |            |          |   issued_token_type: delegation|            |          |           |          |
   |            |          |   expires_in: 300,             |            |          |           |          |
   |            |          |   db_credential: {user,pass},  |            |          |           |          |
   |            |          |   delegation_chain: [...]}     |            |          |           |          |
   |            |          |        |         |             |            |          |           |          |
   |            |          |--------(SQL query with dynamic creds)------|--------->|           |          |
   |            |          |<-------(results)-----------------------------------------------|          |
   |            |          |        |         |             |            |          |           |          |
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
  6. OPA validates may_act.sub is a SPIFFE ID and agent is in aud[]

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
|  | IDENTITY LAYER         |    | POLICY LAYER            |              |
|  |                        |    |                         |              |
|  | +--------------------+ |    | +---------------------+ |              |
|  | | SPIRE Server :8081 | |    | |   OPA :8181         | |              |
|  | | Trust Domain Root  | |    | |   Policy Engine     | |              |
|  | | - CA certificates  | |    | |                     | |              |
|  | | - SVID issuer      | |    | | delegation.rego:    | |              |
|  | +--------+-----------+ |    | | - valid_human_token | |              |
|  |          |              |    | | - valid_agent_id    | |              |
|  |    (attestation)        |    | | - authorized_deleg  | |              |
|  |          |              |    | | - scope_permitted   | |              |
|  | +--------v-----------+ |    | | - delegation_chain  | |  <-- NEW    |
|  | | SPIRE Agent        | |    | | - chain_depth_limit | |  <-- NEW    |
|  | | Workload Attestor  | |    | | - scope_narrowing   | |  <-- NEW    |
|  | +--------------------+ |    | |                     | |              |
|  |                        |    | | data.json:          | |              |
|  | +--------------------+ |    | | - trusted_issuers   | |              |
|  | | Keycloak :8080     | |    | | - registered_agents | |              |
|  | | OIDC Identity Prov | |    | | - registered_sub-   | |  <-- NEW    |
|  | |                    | |    | |   agents             | |              |
|  | | Realm: demo        | |    | | - group_permissions | |              |
|  | | Users:             | |    | | - max_delegation_   | |  <-- NEW    |
|  | |  alice (analyst)   | |    | |   depth              | |              |
|  | |  bob   (engineer)  | |    | | - scope_hierarchy   | |  <-- NEW    |
|  | |                    | |    | +---------------------+ |              |
|  | | may_act mapper:    | |    |                         |              |
|  | |  usermodel-attrib  | |    | +---------------------+ |              |
|  | |  reads per-user    | |    | | SPIRE OIDC :8082    | |              |
|  | |  agent_consent     | |    | | JWKS for JWT-SVID   | |              |
|  | +--------------------+ |    | | verification        | |              |
|  +========================+    | +---------------------+ |              |
|                                +=========================+              |
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
|  | TOKEN EXCHANGE LAYER (NEW - RFC 8693)                             | |
|  |                                                                    | |
|  | +----------------------------------------------------------------+| |
|  | | Token Exchange Service :8090 (Python)                           || |
|  | |                                                                  || |
|  | |  POST /v1/token/exchange  -- RFC 8693 Token Exchange            || |
|  | |  POST /v1/delegate        -- Legacy delegation API              || |
|  | |  POST /v1/token/revoke    -- Revoke delegation token            || |
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
|  | |    OPA unavailable --------> deny (not allow)                   || |
|  | |    Keycloak unavailable ---> reject token (not accept)          || |
|  | |    SPIRE OIDC unavailable -> reject actor (not accept)          || |
|  | |                                                                  || |
|  | |  mTLS (optional, via SPIFFE X.509-SVIDs):                       || |
|  | |    Enabled with MTLS_ENABLED=true                               || |
|  | |    Fetches X.509-SVID from SPIRE Workload API                   || |
|  | |    TLSv1.2+ with mutual certificate verification                || |
|  | |    Graceful fallback to HTTP if SPIRE unavailable               || |
|  | |                                                                  || |
|  | |  Vault Token Management:                                         || |
|  | |    Periodic token (1h period, 24h max TTL)                      || |
|  | |    Background daemon auto-renews every 45 minutes               || |
|  | |    Child tokens restricted to DB credential policies            || |
|  | |                                                                  || |
|  | |  Connects to:                                                    || |
|  | |   Keycloak ----> validate subject_token (human OIDC)            || |
|  | |   SPIRE OIDC --> fetch JWKS for JWT-SVID verification           || |
|  | |   OPA ---------> evaluate delegation policy                     || |
|  | |   Vault -------> broker dynamic DB credentials                  || |
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

## OPA Policy Decision Tree (v3)

```
                     Delegation Request
                            |
               +------------+------------+
               |                         |
      Initial Delegation          Chain Extension
      (depth == 0)               (depth > 0)
               |                         |
               v                         v
     +-------------------+     +--------------------+
     | valid_human_token |     | valid_deleg_chain  |
     | - sub != ""       |     | - depth > 0        |
     | - exp > now       |     | - sub != ""        |
     | - iss trusted     |     | - exp > now        |
     +--------+----------+     +--------+-----------+
              |                         |
       yes    |    no            yes    |    no
      +-------+--------+       +-------+--------+
      |                |       |                |
      v                v       v                v
+------------------+ DENY  +------------------+ DENY
| valid_agent_id   |       | valid_agent_id   |
| - spiffe://      |       | - spiffe://      |
|   demo.local/*   |       |   demo.local/*   |
| - registered     |       | - registered     |
|   agent OR       |       |   agent OR       |
|   subagent       |       |   subagent       |
+--------+---------+       +--------+---------+
         |                          |
  yes    |    no             yes    |    no
 +-------+--------+        +-------+--------+
 |                |        |                |
 v                v        v                v
+-----------+   DENY   +------------------+ DENY
| authorized|          | chain_depth_ok   |
| delegation|          | depth < max (3)  |
| may_act{} |          +--------+---------+
| - sub must|                  |
|   be SPIFFE ID        yes    |    no
|   (exact match)      +-------+--------+
| - OR aud[] list      |                |
|   contains agent     v                v
|   SPIFFE ID    +------------------+ DENY: "max_depth_exceeded"
| (no legacy     | scope_narrowing  |
|  bypass)       | - parent_scope   |
+-----+-----+   |   passed to OPA  |
      |          |   for enforcement |
yes   |  no      | - scope <=       |
+-----+-----+   |   parent scope   |
|           |    +--------+---------+
v           v            |
+---------+ DENY   yes   |    no
| scope   |       +------+--------+
| permitted       |               |
| group   |       v               v
| check   |    ALLOW           DENY: "scope_narrowing_violation"
+----+----+    "allowed"
     |
yes  | no
+----+----+
|        |
v        v
ALLOW   DENY
"ok"    "scope_not_permitted"

  Registered Identities:
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
   |  T=0  Token Exchange approves delegation
   |   |
   |   |   Token Exchange Service requests:
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

  Manual revocation via Token Exchange Service:
    POST /v1/token/revoke {"token": "<delegation_jwt>"}
    --> Revokes Vault lease
    --> Immediately drops the PostgreSQL role
    --> Marks session as revoked
```

## Vault Token Lifecycle (Token Exchange Service)

```
  Token Exchange Service's own Vault token is a periodic token with
  restricted child token policies. This prevents privilege escalation
  and ensures the service token stays alive through automatic renewal.

  Bootstrap creates the token:
  +-------------------------------------------------------------------+
  | vault token create                                                |
  |   -policy=gateway-policy                                          |
  |   -period=1h            <-- renewable every hour                  |
  |   -explicit-max-ttl=24h <-- hard ceiling, must re-bootstrap after |
  |   -allowed-policies=ai-agent-db-read,ai-agent-db-readwrite       |
  +-------------------------------------------------------------------+

  Token Renewal (background daemon thread):
  +-------------------------------------------------------------------+
  |                                                                   |
  |  T=0       Service starts, token is valid (period=1h)             |
  |  T=45m     Renewal thread: POST /v1/auth/token/renew-self         |
  |            {increment: "2700s"} --> new TTL = 1h                  |
  |  T=90m     Renewal thread fires again --> new TTL = 1h            |
  |  ...       Repeats every 45 minutes                               |
  |  T=24h     explicit_max_ttl reached: renewal fails                |
  |            Service must be re-bootstrapped                        |
  |                                                                   |
  +-------------------------------------------------------------------+

  Child Token Restrictions (allowed_policies):
  +-------------------------------------------------------------------+
  |  The gateway token can ONLY create child tokens with these         |
  |  policies (prevents privilege escalation):                         |
  |                                                                   |
  |  - ai-agent-db-read      (SELECT on schema app)                   |
  |  - ai-agent-db-readwrite (CRUD on schema app)                     |
  |                                                                   |
  |  Cannot create tokens with gateway-policy or any other policy.    |
  |  Cannot create orphan tokens (path removed from policy).          |
  +-------------------------------------------------------------------+

  Vault Policy (gateway-policy.hcl):
  +-------------------------------+------------------------------------+
  | Path                          | Capability                         |
  +-------------------------------+------------------------------------+
  | auth/token/create             | create, update (child tokens)      |
  | auth/token/lookup             | update                             |
  | auth/token/lookup-self        | read                               |
  | auth/token/renew-self         | update (periodic renewal)          |
  | identity/entity/id/*          | read, update                       |
  | identity/entity/name/*        | read, update, create               |
  | identity/lookup/entity        | update                             |
  | identity/entity-alias/id/*    | read, update                       |
  | database/creds/ai-agent-*     | read (broker DB creds)             |
  | sys/leases/renew              | update                             |
  | sys/leases/revoke             | update                             |
  | sys/seal                      | DENY                               |
  | sys/step-down                 | DENY                               |
  +-------------------------------+------------------------------------+
```

## mTLS Transport Security

```
  The Token Exchange Service optionally supports mutual TLS using
  SPIFFE X.509-SVIDs from the SPIRE Workload API. This provides
  transport-layer identity verification on the critical path where
  identity tokens are exchanged and credentials are brokered.

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

  Note: Third-party services (Keycloak, Vault, OPA, PostgreSQL) don't
  natively consume SPIRE Workload API SVIDs. Full mTLS coverage would
  require sidecar cert injection (spiffe-helper) or an Envoy service
  mesh. The current implementation covers the critical path where
  identity tokens are exchanged and credentials are brokered.
```

## 7-Layer Audit Correlation Chain (v3)

```
  +--------+   +----------+   +----------+   +-------+   +---------+   +---------+   +----------+
  |   1    |   |    2     |   |    3     |   |   4   |   |    5    |   |    6    |   |    7     |
  |Keycloak|-->|AgentGW   |-->|  Token   |-->|  OPA  |-->|  Vault  |-->|  Lease  |-->|PostgreSQL|
  | Token  |   | Access   |   |Exchange  |   |Decision|  |Metadata |   | Record  |   | pgaudit  |
  | (OIDC) |   |  Log     |   | Audit    |   |        |  |         |   |         |   |          |
  +--------+   +----------+   +----------+   +-------+   +---------+   +---------+   +----------+
       |            |              |              |            |             |              |
       v            v              v              v            v             v              v
  +---------+  +---------+   +-----------+  +----------+ +----------+ +-----------+ +----------+
  | JWT     |  |identity |   |session_id |  | allow/   | | entity   | | lease_id  | | user:    |
  | sub:    |  |OIDC auth|   |request_id |  | deny     | | metadata:| | lease_ttl | | v-token- |
  |  alice  |  |SPIFFE id|   |human:     |  | reason:  | |  human   | | renewable | |  readonly|
  | email:  |  |RBAC role|   | alice@    |  |  allowed/| |  scope   | |           | |  -xxx    |
  |  alice@ |  |rate     |   |actor:     |  |  chain_  | |  agent   | |           | |          |
  | groups: |  | limit   |   | agent/    |  |  depth   | |  chain   | |           | | query:   |
  | may_act:|  |scope    |   | subagent  |  |          | |  session | |           | |  SELECT  |
  |  {sub}  |  |         |   |chain:     |  |          | |  depth   | |           | |  FROM    |
  | exp:    |  |         |   | [links]   |  |          | |          | |           | |  app.*   |
  +---------+  +---------+   |act: {...} |  +----------+ +----------+ +-----------+ +----------+
                              +-----------+
  NEW: delegation chain fully traceable through `act` claim nesting
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
  |  :8181   OPA            (policy API)                                 |
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
  +-------v------+   +--------------+           |
  | spire-agent  |   |     opa      |   +-------v------+
  | (socket API) |   |    :8181     |   |  postgresql  |
  +-------+------+   +------+-------+   |    :5432     |
          |                  |           +---------+----+
          |    +-------------+                     ^
          |    |                                   |
  +-------v----v--------+                          |
  |   AgentGateway      |                          |
  |  :9080 (MCP/HTTP)   |                          |
  |  :19000 (Admin)     |                          |
  +-------+-------------+                          |
          |                                        |
  +-------v-------------+                          |
  | Token Exchange Svc  |   <-- NEW (RFC 8693)     |
  |  :8090              |                          |
  |  (optional mTLS)    |                          |
  +---------+-----------+                          |
            |                                      |
            +----(Vault creds: CREATE ROLE)--------+
            |
  +---------v-----------+
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
  4. opa             (no deps)
  5. keycloak        (no deps)
  6. spire-agent     (depends: spire-server healthy)
  7. token-exchange  (depends: vault, keycloak, opa healthy)       <-- NEW
  8. agentgateway    (depends: keycloak, opa, token-exchange)      <-- NEW
  9. ai-agent        (depends: token-exchange healthy, postgresql)  <-- CHANGED
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
  | Scope narrowing             | Each delegation level can only narrow    |   <-- NEW
  |                             | scope, never widen it                    |
  |                             | parent_scope passed to OPA for enforce-  |
  |                             | ment (not just general scope check)      |
  +-----------------------------+------------------------------------------+
  | Max chain depth             | Configurable limit (default: 3)          |   <-- NEW
  |                             | Prevents infinite delegation             |
  +-----------------------------+------------------------------------------+
  | AgentGateway proxy          | RBAC, rate limiting, observability       |   <-- NEW
  |                             | MCP/A2A protocol support                 |
  +-----------------------------+------------------------------------------+
  | Least privilege             | OPA enforces group-to-scope mapping      |
  |                             | data-analysts: readonly only             |
  |                             | engineering: readonly + readwrite        |
  +-----------------------------+------------------------------------------+
  | Deny by default             | OPA default allow := false               |
  |                             | All rules must pass                      |
  +-----------------------------+------------------------------------------+
  | Complete audit trail        | 7-layer correlation from human to query  |
  |                             | Every decision logged with chain context |
  +-----------------------------+------------------------------------------+
  | Zero trust                  | Every request validated end-to-end       |
  |                             | No implicit trust from network position  |
  |                             | Fail-closed when dependencies unavailable|
  +-----------------------------+------------------------------------------+
  | Credential lifecycle        | Auto-revocation after TTL                |
  |                             | Manual revocation via token revoke API   |
  |                             | PostgreSQL role dropped on expiry        |
  +-----------------------------+------------------------------------------+
  | Asymmetric token signing    | Delegation tokens signed with RS256      |
  |                             | In-memory RSA-2048 keypair (or from env) |
  |                             | Public key at /.well-known/jwks.json     |
  +-----------------------------+------------------------------------------+
  | Fail-closed defaults        | OPA unavailable -> deny (not allow)      |
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
  | Vault token least privilege | Token Exchange Service uses periodic     |
  |                             | Vault token (1h period, 24h max TTL)     |
  |                             | with allowed_policies restricting child  |
  |                             | tokens to DB credential policies only.   |
  |                             | Background thread auto-renews every 45m. |
  |                             | No orphan token creation capability.     |
  +-----------------------------+------------------------------------------+
  | Transport security (mTLS)   | Token Exchange optionally serves over    |
  |                             | mTLS using SPIFFE X.509-SVIDs from      |
  |                             | SPIRE Workload API. TLSv1.2+ with       |
  |                             | mutual cert verification. Graceful       |
  |                             | fallback to HTTP if SPIRE unavailable.   |
  +-----------------------------+------------------------------------------+
```
