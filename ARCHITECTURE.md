# Architecture: Secure Agentic AI Identity & Database Access

## System Overview

```
+=====================================================================+
|                     IDENTITY DELEGATION CHAIN                       |
|        Human (Alice) --> AI Agent --> PostgreSQL Database            |
|                                                                     |
|  "Every query traces back to a human, an agent, a policy decision,  |
|   and a short-lived credential -- with cryptographic proof."        |
+=====================================================================+

                    +-------------------+
                    |   Human (Alice)   |
                    | alice@acme.com    |
                    | groups:           |
                    |  - data-analysts  |
                    |  - trading-team   |
                    +--------+----------+
                             |
                    (1) OIDC Login
                    username + password
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
                             |
                             v
              +--------------+--------------+
              |        AI Agent             |
              |  (Python Workload)          |
              |                             |
              |  Has:                       |
              |  - Human's OIDC token       |
              |  - Own SPIFFE identity      |
              +----+-------------------+----+
                   |                   |
          (3) Fetch JWT-SVID    (4) POST /v1/delegate
          from SPIRE socket     {human_token,
                   |             agent_spiffe_id,
                   v             requested_scope}
          +----------------+           |
          |  SPIRE Agent   |           |
          | (Workload API) |           |
          | socket://...   |           |
          +-------+--------+           |
                  |                    |
          (attests via)                |
                  v                    v
          +----------------+  +------------------+
          |  SPIRE Server  |  | Identity Gateway |
          | (Trust Root)   |  |   (Go Service)   |
          |   :8081        |  |     :9080        |
          +----------------+  +--------+---------+
                                       |
                              +--------+--------+
                              |                 |
                     (5) Validate        (6) Evaluate
                     Human Token         OPA Policy
                              |                 |
                              v                 v
                    +-----------+     +-----------+
                    | Keycloak  |     |    OPA    |
                    | userinfo  |     |  :8181   |
                    | endpoint  |     +-----------+
                    +-----------+           |
                                    (7) allow/deny
                                    + reason
                                            |
                              +-------------+
                              |
                     (8) Request Dynamic
                     DB Credentials
                              |
                              v
                    +-------------------+
                    |   HashiCorp Vault |
                    | (Secrets Manager) |
                    |      :8200        |
                    +---------+---------+
                              |
                    (9) CREATE ROLE
                    "v-token-readonly-xxx"
                    TTL: 5 minutes
                              |
                              v
                    +-------------------+
                    |   PostgreSQL      |
                    |   (appdb)         |
                    |     :5432         |
                    +-------------------+
                              ^
                              |
                   (10) SELECT queries
                   using dynamic creds
                              |
                    +---------+---------+
                    |     AI Agent      |
                    | connects with     |
                    | short-lived creds |
                    +-------------------+
```

## Delegation Flow (Step by Step)

```
 Human        Keycloak     AI Agent      SPIRE       Gateway       OPA         Vault       PostgreSQL
   |              |            |           |            |            |            |             |
   |---(login)--->|            |           |            |            |            |             |
   |   username   |            |           |            |            |            |             |
   |   password   |            |           |            |            |            |             |
   |<---(JWT)-----|            |           |            |            |            |             |
   |  access_token|            |           |            |            |            |             |
   |  [sub,email, |            |           |            |            |            |             |
   |   groups,    |            |           |            |            |            |             |
   |   may_act]   |            |           |            |            |            |             |
   |              |            |           |            |            |            |             |
   |----(token)-->|  (delegate)|           |            |            |            |             |
   |              |    task    |           |            |            |            |             |
   |              |            |           |            |            |            |             |
   |              |            |---(fetch  |            |            |            |             |
   |              |            |   SVID)-->|            |            |            |             |
   |              |            |<-(JWT-SVID)|           |            |            |             |
   |              |            |   [spiffe:|            |            |            |             |
   |              |            |    //demo.|            |            |            |             |
   |              |            |    local/ |            |            |            |             |
   |              |            |    agent/ |            |            |            |             |
   |              |            |    query] |            |            |            |             |
   |              |            |           |            |            |            |             |
   |              |            |---------(POST /v1/delegate)-------->|            |             |
   |              |            |  {human_token, agent_spiffe_id,     |            |             |
   |              |            |   agent_jwt_svid, requested_scope}  |            |             |
   |              |            |           |            |            |            |             |
   |              |            |           |      [Step 1: Validate Human Token]  |             |
   |              |<---------------------------(userinfo)|            |            |             |
   |              |----(claims)------------------------>|            |            |             |
   |              |  {sub, email, groups, may_act}      |            |            |             |
   |              |            |           |            |            |            |             |
   |              |            |           |      [Step 2: Validate SPIFFE ID]    |             |
   |              |            |           |       trust_domain OK?  |            |             |
   |              |            |           |       registered agent? |            |             |
   |              |            |           |            |            |            |             |
   |              |            |           |      [Step 3: Evaluate Policy]       |             |
   |              |            |           |            |---(POST)-->|            |             |
   |              |            |           |            | {input:    |            |             |
   |              |            |           |            |  human_token,           |             |
   |              |            |           |            |  agent_id, |            |             |
   |              |            |           |            |  scope}    |            |             |
   |              |            |           |            |<-(allow/-->|            |             |
   |              |            |           |            |   deny +   |            |             |
   |              |            |           |            |   reason)  |            |             |
   |              |            |           |            |            |            |             |
   |              |            |           |      [Step 4: Broker Vault Creds]    |             |
   |              |            |           |            |----------(GET creds)--->|             |
   |              |            |           |            | database/creds/         |             |
   |              |            |           |            | ai-agent-readonly       |             |
   |              |            |           |            |<-(username,password,----|             |
   |              |            |           |            |   lease_id, ttl=300s)   |             |
   |              |            |           |            |            |            |             |
   |              |            |           |            |            |  (CREATE ROLE)---------->|
   |              |            |           |            |            |  v-token-readonly-xxx    |
   |              |            |           |            |            |  VALID UNTIL +5min       |
   |              |            |           |            |            |  GRANT SELECT ON app.*   |
   |              |            |           |            |            |            |             |
   |              |            |<-------(DelegationResponse)---------|            |             |
   |              |            |  {session_id, db_credential:        |            |             |
   |              |            |   {username, password, host,        |            |             |
   |              |            |    port, ttl, lease_id},            |            |             |
   |              |            |   metadata: {delegating_human,      |            |             |
   |              |            |    delegation_scope, ...}}          |            |             |
   |              |            |           |            |            |            |             |
   |              |            |----------(SQL query via dynamic creds)---------->|             |
   |              |            |  SELECT * FROM app.order_summary    |            |             |
   |              |            |  WHERE total_amount > 1000          |            |             |
   |              |            |<---------(query results)-------------------------|             |
   |              |            |           |            |            |            |             |
   |              |            |           |            |            | (after 5min)|            |
   |              |            |           |            |            | DROP ROLE   |            |
   |              |            |           |            |            | v-token-*   |----------->|
   |              |            |           |            |            |            |             |
```

## Component Architecture

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
|  | | - SQLite3 store    | |    | | - valid_human_token | |              |
|  | | - Join token auth  | |    | | - valid_agent_id    | |              |
|  | +--------+-----------+ |    | | - authorized_deleg  | |              |
|  |          |              |    | | - scope_permitted   | |              |
|  |    (attestation)        |    | |                     | |              |
|  |          |              |    | | data.json:          | |              |
|  | +--------v-----------+ |    | | - trusted_issuers   | |              |
|  | | SPIRE Agent        | |    | | - registered_agents | |              |
|  | | Workload Attestor  | |    | | - group_permissions | |              |
|  | | - Unix UID match   | |    | +---------------------+ |              |
|  | | - Socket API       | |    +=========================+              |
|  | +--------------------+ |                                             |
|  |                        |    +=========================+              |
|  | +--------------------+ |    | SECRETS LAYER           |              |
|  | | Keycloak :8080     | |    |                         |              |
|  | | OIDC Identity Prov | |    | +---------------------+ |              |
|  | |                    | |    | | Vault :8200          | |              |
|  | | Realm: demo        | |    | | Dynamic Secrets Mgr | |              |
|  | | Users:             | |    | |                     | |              |
|  | |  alice (analyst)   | |    | | Engines:            | |              |
|  | |  bob   (engineer)  | |    | |  database/postgres  | |              |
|  | |                    | |    | |                     | |              |
|  | | Clients:           | |    | | Roles:              | |              |
|  | |  demo-cli (public) | |    | |  ai-agent-readonly  | |              |
|  | |  ai-agent-service  | |    | |  ai-agent-readwrite | |              |
|  | |  identity-gateway  | |    | |                     | |              |
|  | |                    | |    | | TTL: 5 min (300s)   | |              |
|  | | Claims:            | |    | | Max TTL: 30 min     | |              |
|  | |  groups[]          | |    | |                     | |              |
|  | |  may_act{}         | |    | | Audit: file backend | |              |
|  | +--------------------+ |    | +---------------------+ |              |
|  +========================+    +=========================+              |
|                                                                         |
|  +===================================================================+ |
|  | ORCHESTRATION LAYER                                                | |
|  |                                                                    | |
|  | +----------------------------------------------------------------+| |
|  | | Identity Gateway :9080 (Go)                                     || |
|  | |                                                                  || |
|  | |  POST /v1/delegate  -- Full delegation flow                     || |
|  | |  GET  /v1/health    -- Service health                           || |
|  | |  GET  /v1/audit     -- Audit trail entries                      || |
|  | |                                                                  || |
|  | |  Connects to:                                                    || |
|  | |   Keycloak ----> validate human OIDC token                      || |
|  | |   OPA ---------> evaluate delegation policy                     || |
|  | |   Vault -------> broker dynamic DB credentials                  || |
|  | |   SPIRE -------> verify agent SPIFFE ID trust domain            || |
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
|  | | 3. Request delegation     |   |                               |  | |
|  | | 4. Receive dynamic creds  |   | Tables:                       |  | |
|  | | 5. Query database         |   |  - app.orders (15 rows)       |  | |
|  | | 6. Creds auto-expire      |   |  - app.customers (8 rows)     |  | |
|  | |                           |   |  - app.products (8 rows)      |  | |
|  | | NL-to-SQL mapping:        |   |                               |  | |
|  | |  "show orders" -> SELECT  |   | Views:                        |  | |
|  | |  "top customers" -> ...   |   |  - app.order_summary          |  | |
|  | |  "low stock" -> ...       |   |    (with value_tier)          |  | |
|  | +---------------------------+   |                               |  | |
|  |                                 | Vault-managed roles:          |  | |
|  |                                 |  v-token-readonly-{uuid}      |  | |
|  |                                 |  v-token-readwrite-{uuid}     |  | |
|  |                                 |                               |  | |
|  |                                 | Audit: pgaudit extension      |  | |
|  |                                 |  log_statement=all            |  | |
|  |                                 |  log_connections=on           |  | |
|  |                                 +-------------------------------+  | |
|  +===================================================================+ |
+-------------------------------------------------------------------------+
```

## OPA Policy Decision Tree

```
                     Delegation Request
                            |
                            v
                  +-------------------+
                  | valid_human_token |
                  | - sub != ""       |
                  | - exp > now       |
                  | - iss trusted     |
                  +--------+----------+
                           |
                    yes    |    no
                   +-------+--------+
                   |                |
                   v                v
          +------------------+  DENY: "invalid_human_token"
          | valid_agent_id   |
          | - spiffe://      |
          |   demo.local/*   |
          | - registered     |
          +--------+---------+
                   |
            yes    |    no
           +-------+--------+
           |                |
           v                v
  +--------------------+  DENY: "invalid_agent_identity"
  | authorized_deleg   |
  | - may_act.sub != ""|
  +--------+-----------+
           |
    yes    |    no
   +-------+--------+
   |                |
   v                v
+------------------+  DENY: "unauthorized_delegation"
| scope_permitted  |
| group_permissions|
|   [group] has    |
|   requested_scope|
+--------+---------+
         |
  yes    |    no
 +-------+--------+
 |                |
 v                v
ALLOW           DENY: "scope_not_permitted"
"allowed"


  Group Permissions Matrix:
  +----------------+----------+-----------+--------+----------+----------+
  | Group          | readonly | readwrite | db:read| db:write | db:query |
  +----------------+----------+-----------+--------+----------+----------+
  | data-analysts  |    Y     |           |   Y    |          |    Y     |
  | trading-team   |    Y     |           |   Y    |          |    Y     |
  | engineering    |    Y     |     Y     |   Y    |    Y     |    Y     |
  +----------------+----------+-----------+--------+----------+----------+
```

## Vault Credential Lifecycle

```
  Time
   |
   |  T=0  Delegation approved by OPA
   |   |
   |   |   Gateway requests: GET /v1/database/creds/ai-agent-readonly
   |   |
   |   v
   |  +------------------------------------------------------------------+
   |  | Vault creates PostgreSQL role:                                    |
   |  |                                                                   |
   |  |   CREATE ROLE "v-token-readonly-3ee8b521"                        |
   |  |     WITH LOGIN PASSWORD 'rV9z4k...'                              |
   |  |     VALID UNTIL '2025-02-21 10:50:23'                            |
   |  |     INHERIT;                                                      |
   |  |   GRANT USAGE ON SCHEMA app TO "v-token-readonly-3ee8b521";      |
   |  |   GRANT SELECT ON ALL TABLES IN SCHEMA app                       |
   |  |     TO "v-token-readonly-3ee8b521";                              |
   |  +------------------------------------------------------------------+
   |
   |  T=0..300s  Agent uses credentials
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

  Manual revocation also possible:
    PUT /v1/sys/leases/revoke {"lease_id": "database/creds/.../xxx"}
    --> Immediately drops the PostgreSQL role
```

## 6-Layer Audit Correlation Chain

```
  +--------+    +----------+    +-------+    +---------+    +---------+    +------------+
  |   1    |    |    2     |    |   3   |    |    4    |    |    5    |    |     6      |
  |Keycloak|--->| Gateway  |--->|  OPA  |--->|  Vault  |--->|  Lease  |--->| PostgreSQL |
  | Token  |    | Audit Log|    |Decision|   | Metadata|    |  Record |    | pgaudit    |
  +--------+    +----------+    +-------+    +---------+    +---------+    +------------+
       |              |              |             |              |              |
       v              v              v             v              v              v
  +---------+   +-----------+  +----------+  +----------+  +-----------+  +----------+
  | JWT     |   | session_id|  | allow/   |  | entity   |  | lease_id  |  | user:    |
  | sub:    |   | request_id|  | deny     |  | metadata:|  | lease_ttl |  | v-token- |
  |  alice  |   | human:    |  | reason:  |  |  human   |  | renewable |  |  readonly|
  | email:  |   |  alice@   |  |  allowed/|  |  scope   |  |           |  |  -xxx    |
  |  alice@ |   | agent:    |  |  invalid_|  |  agent   |  |           |  |          |
  | groups: |   |  spiffe://|  |  token/  |  |  groups  |  |           |  | query:   |
  |  [data- |   | scope:    |  |  scope_  |  |  session |  |           |  |  SELECT  |
  |   analysts]|  readonly |  |  not_    |  |  time    |  |           |  |  FROM    |
  | may_act:|   | decision: |  |  permitted| |          |  |           |  |  app.*   |
  |  {sub:  |   |  allow    |  |          |  |          |  |           |  |          |
  |   agent}|   | result:   |  |          |  |          |  |           |  | status:  |
  | exp:    |   |  success  |  |          |  |          |  |           |  |  OK      |
  | iss:    |   |           |  |          |  |          |  |           |  |          |
  |  keycloak|  |           |  |          |  |          |  |           |  | time:    |
  +---------+   +-----------+  +----------+  +----------+  +-----------+  +----------+

  Correlation Path:
  session_id --> lease_id --> db_username --> pgaudit query log
       |                          |
       +--> human identity        +--> OPA decision reason
       +--> agent SPIFFE ID
       +--> delegation scope
```

## Security Boundaries

```
  +=========================================================================+
  | BOUNDARY 1: Identity Infrastructure (trusted root)                      |
  |                                                                         |
  |   Keycloak         SPIRE Server         OPA                             |
  |   (RS256 keys)     (CA certs)           (Rego policies)                 |
  |   (user DB)        (trust domain)       (group permissions)             |
  |                                                                         |
  |   Trust assumption: These components are not compromised                |
  +====================================+====================================+
                                       |
                            validates all requests
                                       |
  +====================================v====================================+
  | BOUNDARY 2: Credential Broker (mediator)                                |
  |                                                                         |
  |   Identity Gateway                                                      |
  |   - Holds Vault token (24h TTL, renewable)                              |
  |   - Validates human tokens via Keycloak                                 |
  |   - Evaluates policy via OPA                                            |
  |   - Brokers Vault credentials                                           |
  |   - Records full audit trail                                            |
  |                                                                         |
  |   Vault Policies:                                                       |
  |   +-------------------+--------------------------------------------+   |
  |   | gateway-policy    | database/creds/* (read)                    |   |
  |   |                   | identity/entity/* (read/write metadata)    |   |
  |   |                   | auth/token/create (create child tokens)    |   |
  |   |                   | sys/leases/* (manage leases)               |   |
  |   |                   | DENY: sys/seal, sys/step-down              |   |
  |   +-------------------+--------------------------------------------+   |
  |   | ai-agent-db-read  | database/creds/ai-agent-readonly (read)    |   |
  |   |                   | auth/token/lookup-self, renew-self         |   |
  |   |                   | DENY: sys/*, secret/*                      |   |
  |   +-------------------+--------------------------------------------+   |
  +====================================+====================================+
                                       |
                          issues short-lived creds
                                       |
  +====================================v====================================+
  | BOUNDARY 3: Agent Workload (consumer)                                   |
  |                                                                         |
  |   AI Agent                                                              |
  |   - Proves identity via SPIFFE SVID                                     |
  |   - Receives credentials only through Gateway                           |
  |   - Cannot forge tokens or escalate privileges                          |
  |   - Cannot access Vault directly (policy-limited)                       |
  |   - Credentials expire in 5 minutes                                     |
  +====================================+====================================+
                                       |
                          queries with temp credentials
                                       |
  +====================================v====================================+
  | BOUNDARY 4: Protected Resource (target)                                 |
  |                                                                         |
  |   PostgreSQL                                                            |
  |   - Vault-managed roles only (no static passwords)                      |
  |   - SELECT-only for readonly scope                                      |
  |   - Roles auto-dropped after TTL                                        |
  |   - pgaudit logs every query with username                              |
  |   - Cannot execute DDL (no CREATE/ALTER/DROP)                           |
  +=========================================================================+
```

## Port Map & Network Topology

```
  Host Machine
  +-----------------------------------------------------------------------+
  |                                                                       |
  |  Exposed Ports:                                                       |
  |                                                                       |
  |  :8080  Keycloak   (OIDC login, admin UI at /admin)                   |
  |  :8081  SPIRE      (internal trust infrastructure)                    |
  |  :8181  OPA        (policy API, /v1/data/delegation/allow)            |
  |  :8200  Vault      (secrets API & UI)                                 |
  |  :5432  PostgreSQL (database connections)                             |
  |  :9080  Gateway    (delegation API: /v1/delegate, /v1/health)         |
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
          |                  |           +--------------+
          |    +-------------+                  ^
          |    |                                |
  +-------v----v-----+                          |
  | identity-gateway |  (broker)                |
  |  :8080 --> :9080 |--------------------------+
  +-------+----------+     (Vault creates roles)
          ^
          |
  +-------+----------+
  |    ai-agent      |
  | (no listen port) |
  +------------------+

  Dependency Order:
  1. spire-server  (no deps)
  2. postgresql    (no deps)
  3. vault         (no deps)
  4. opa           (no deps)
  5. keycloak      (no deps)
  6. spire-agent   (depends: spire-server healthy)
  7. identity-gw   (depends: vault, keycloak, opa healthy)
  8. ai-agent      (depends: identity-gw started, postgresql healthy)
```

## Key Security Properties

```
  +-----------------------------+------------------------------------------+
  | Property                    | How It's Achieved                        |
  +-----------------------------+------------------------------------------+
  | No static DB credentials    | Vault generates unique creds per request |
  |                             | TTL: 300s, auto-revoked                  |
  +-----------------------------+------------------------------------------+
  | Human attribution           | OIDC token with sub, email, groups       |
  |                             | Preserved through entire chain           |
  +-----------------------------+------------------------------------------+
  | Agent attestation           | SPIFFE SVID proves workload identity     |
  |                             | Cryptographically verified by SPIRE      |
  +-----------------------------+------------------------------------------+
  | Least privilege             | OPA enforces group-to-scope mapping      |
  |                             | data-analysts: readonly only             |
  |                             | engineering: readonly + readwrite        |
  +-----------------------------+------------------------------------------+
  | Deny by default             | OPA default allow := false               |
  |                             | All 4 rules must pass                    |
  +-----------------------------+------------------------------------------+
  | Complete audit trail        | 6-layer correlation from human to query  |
  |                             | Every decision logged with reason        |
  +-----------------------------+------------------------------------------+
  | Zero trust                  | Every request validated end-to-end       |
  |                             | No implicit trust from network position  |
  +-----------------------------+------------------------------------------+
  | Credential lifecycle        | Auto-revocation after TTL                |
  |                             | Manual revocation via Vault API          |
  |                             | PostgreSQL role dropped on expiry        |
  +-----------------------------+------------------------------------------+
```
