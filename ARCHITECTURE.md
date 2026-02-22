# Architecture: Secure Agentic AI Identity & Database Access (v2)

## System Overview (v2 with AgentGateway + Token Exchange)

```
+=========================================================================+
|               IDENTITY DELEGATION CHAIN (v2)                            |
|   Human (Alice) --> Agent --> [Sub-Agent] --> PostgreSQL Database        |
|                                                                         |
|  "Every query traces back to a human, through a chain of delegated      |
|   identities, each validated by policy with cryptographic proof."       |
|                                                                         |
|  New in v2:                                                             |
|   - AgentGateway (Rust) as MCP/A2A proxy                              |
|   - RFC 8693 Token Exchange for delegation                             |
|   - Sub-agent delegation chains (configurable depth)                   |
|   - MCP/A2A protocol support                                           |
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
                   (agent receives token
                    only after human consents)
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
                              | - delegation chain  |
                              | - act{} claim       |
                              | - scope narrowing   |
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
 Human      Keycloak    Agent     SPIRE    AgentGW    TokenExchange    OPA       Vault     PostgreSQL
   |            |          |        |         |             |            |          |           |
   |-(login)--->|          |        |         |             |            |          |           |
   |<--(JWT)----|          |        |         |             |            |          |           |
   |  {sub, email,         |        |         |             |            |          |           |
   |   groups, may_act}    |        |         |             |            |          |           |
   |            |          |        |         |             |            |          |           |
   |---(token)->| (task)   |        |         |             |            |          |           |
   |            |          |        |         |             |            |          |           |
   |            |          |-(SVID)->|        |             |            |          |           |
   |            |          |<(SVID)--|        |             |            |          |           |
   |            |          |        |         |             |            |          |           |
   |            |  RFC 8693 Token Exchange    |             |            |          |           |
   |            |          |----(POST /v1/token/exchange)-->|            |          |           |
   |            |          |  grant_type: token-exchange    |            |          |           |
   |            |          |  subject_token: human_jwt      |            |          |           |
   |            |          |  actor_token: agent_svid       |            |          |           |
   |            |          |  scope: readonly               |            |          |           |
   |            |          |        |         |             |            |          |           |
   |            |          |        |         |   [Validate subject_token]          |           |
   |            |<----------------------------------(userinfo)          |          |           |
   |            |-----------------------------------(claims)>|          |          |           |
   |            |          |        |         |             |            |          |           |
   |            |          |        |         |   [Validate actor_token]            |           |
   |            |          |        |         |   SPIFFE trust domain OK            |          |           |
   |            |          |        |         |             |            |          |           |
   |            |          |        |         |   [OPA Policy]          |          |           |
   |            |          |        |         |             |-(evaluate)->|         |           |
   |            |          |        |         |             |<-(allow)---|         |           |
   |            |          |        |         |             |            |          |           |
   |            |          |        |         |   [Build delegation chain]          |           |
   |            |          |        |         |   act: {sub: agent,     |          |           |
   |            |          |        |         |     act: {sub: alice}}  |          |           |
   |            |          |        |         |             |            |          |           |
   |            |          |        |         |   [Broker Vault creds]  |          |           |
   |            |          |        |         |             |----------(GET creds)->|           |
   |            |          |        |         |             |<-(username,password)--|           |
   |            |          |        |         |             |            |   (CREATE ROLE)----->|
   |            |          |        |         |             |            |          |           |
   |            |          |<-----(Token Exchange Response)-|            |          |           |
   |            |          |  {access_token: delegation_jwt,|            |          |           |
   |            |          |   issued_token_type: delegation|            |          |           |
   |            |          |   expires_in: 300,             |            |          |           |
   |            |          |   db_credential: {user,pass},  |            |          |           |
   |            |          |   delegation_chain: [...]}     |            |          |           |
   |            |          |        |         |             |            |          |           |
   |            |          |--------(SQL query with dynamic creds)------|--------->|           |
   |            |          |<-------(results)-----------------------------------------------|
   |            |          |        |         |             |            |          |           |
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

## Component Architecture (v2)

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
|  | +--------------------+ |    | +---------------------+ |              |
|  +========================+    +=========================+              |
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
|  | |                                                                  || |
|  | |  Connects to:                                                    || |
|  | |   Keycloak ----> validate subject_token (human OIDC)            || |
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

## OPA Policy Decision Tree (v2 with Delegation Chains)

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
+-----+-----+                  |
      |                 yes    |    no
yes   |  no            +-------+--------+
+-----+-----+         |                |
|           |         v                v
v           v    +------------------+ DENY: "max_depth_exceeded"
+---------+ DENY | scope_narrowing  |
| scope   |      | - scope <=       |
| permitted      |   parent scope   |
| group   |      +--------+---------+
| check   |              |
+----+----+        yes    |    no
     |            +-------+--------+
yes  | no        |                |
+----+----+     v                v
|        |   ALLOW            DENY: "scope_narrowing_violation"
v        v   "allowed"
ALLOW   DENY
"ok"    "scope_not_permitted"

  Registered Identities:
  +----------------------------------------+-----------+
  | SPIFFE ID                              | Type      |
  +----------------------------------------+-----------+
  | spiffe://demo.local/agent/query-agent  | Agent     |
  | spiffe://demo.local/agent/analysis-*   | Agent     |
  | spiffe://demo.local/agent/write-agent  | Agent     |
  | spiffe://demo.local/subagent/sql-exec  | Sub-Agent |
  | spiffe://demo.local/subagent/result-*  | Sub-Agent |
  +----------------------------------------+-----------+
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

## 7-Layer Audit Correlation Chain (v2)

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

## Port Map & Network Topology (v2)

```
  Host Machine
  +-----------------------------------------------------------------------+
  |                                                                       |
  |  Exposed Ports:                                                       |
  |                                                                       |
  |  :8080   Keycloak       (OIDC login, admin UI at /admin)             |
  |  :8081   SPIRE          (internal trust infrastructure)              |
  |  :8090   Token Exchange (RFC 8693 API)                 <-- NEW       |
  |  :8181   OPA            (policy API)                                 |
  |  :8200   Vault          (secrets API & UI)                           |
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

## Key Security Properties (v2)

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
  | Agent attestation           | SPIFFE SVID proves workload identity     |
  |                             | Cryptographically verified by SPIRE      |
  +-----------------------------+------------------------------------------+
  | RFC 8693 Token Exchange     | Standard OAuth 2.0 delegation flow       |   <-- NEW
  |                             | subject_token + actor_token -> delegated |
  +-----------------------------+------------------------------------------+
  | Delegation chains           | Nested `act` claims per RFC 8693 Sec 4.1 |   <-- NEW
  |                             | Human -> Agent -> Sub-Agent traceable    |
  +-----------------------------+------------------------------------------+
  | Scope narrowing             | Each delegation level can only narrow    |   <-- NEW
  |                             | scope, never widen it                    |
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
  +-----------------------------+------------------------------------------+
  | Credential lifecycle        | Auto-revocation after TTL                |
  |                             | Manual revocation via token revoke API   |
  |                             | PostgreSQL role dropped on expiry        |
  +-----------------------------+------------------------------------------+
```
