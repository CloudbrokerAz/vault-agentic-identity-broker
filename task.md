# Task Tracker: Assessment Remediation

## Priority Order

Issues #3 (mTLS) and #5 (Vault token) are deferred to last per user request.

## Status Key
- [ ] Not started
- [~] In progress
- [x] Completed

---

## 1. SPIFFE SVIDs: Enable Cryptographic Verification
**Status:** [x] Completed
**Files:** `token-exchange/token_exchange.py`, `ai-agent/agent.py`, `ai-agent/subagents/sql_executor.py`
**Problem:** `verify_signature: False` everywhere. SPIRE OIDC provider serves JWKS at :8082/keys but nobody fetches or uses them. The entire SPIFFE trust model is decorative.
**Changes made:**
- [x] Added `spire_oidc_url` config (env: `SPIRE_OIDC_URL`) to ServiceConfig
- [x] Added `_fetch_spire_jwks()` with caching (configurable TTL, default 300s)
- [x] `_validate_actor_token()` now verifies JWT-SVID signatures against SPIRE JWKS using `PyJWKSet`
- [x] Only SPIFFE IDs accepted as actor tokens — non-SPIFFE subs rejected
- [x] Fail-closed when JWKS unavailable (rejects token, doesn't silently accept)
- [x] Removed `_create_spiffe_token()` from token_exchange.py
- [x] Removed `_generate_demo_svid()` from agent.py — raises RuntimeError if SPIRE unavailable
- [x] Replaced `_create_identity_token()` in sql_executor.py with `_fetch_jwt_svid()` (real SPIRE)
- [x] Legacy `delegate()` now requires `agent_jwt_svid` parameter
- [x] Added `SPIRE_OIDC_URL` to both docker-compose files

## 2. Fail-Closed Defaults (OPA + Keycloak)
**Status:** [x] Completed
**Files:** `token-exchange/token_exchange.py`
**Changes made:**
- [x] OPA unavailable → `{"allowed": False, "reason": "policy_engine_unavailable"}`
- [x] Keycloak unavailable (RequestException) → error: "temporarily_unavailable"
- [x] Keycloak non-200 response → error: "invalid_request" with HTTP status code
- [x] Removed entire "Fallback: parse unverified (demo mode)" block

## 3. Asymmetric Token Signing (RS256)
**Status:** [x] Completed
**Files:** `token-exchange/token_exchange.py`, `token-exchange/requirements.txt`
**Changes made:**
- [x] Added `cryptography>=42.0.0` to requirements.txt
- [x] RSA-2048 keypair generated at service startup (or loaded from `SIGNING_KEY_PATH`)
- [x] Delegation tokens signed with RS256 (private key) + `kid` header
- [x] `_validate_subject_token()` verifies delegation tokens with RS256 public key
- [x] Added `/.well-known/jwks.json` endpoint serving the delegation token public key
- [x] Service version bumped to 3.0.0

## 4. Dynamic `may_act` Consent
**Status:** [x] Completed
**Files:** `keycloak/realm/demo-realm.json`, `opa/policies/delegation.rego`, `demo-ui/server.py`, `demo-ui/static/index.html`, `tests/config-validation/test_keycloak_realm.py`
**Changes made:**
- [x] Updated `may_act.sub` to use SPIFFE ID: `spiffe://demo.local/agent/query-agent`
- [x] Added `aud` list to `may_act` claim with all registered agent SPIFFE IDs
- [x] Removed OPA legacy bypass rule (the one that accepted any non-SPIFFE may_act.sub)
- [x] Replaced `oidc-hardcoded-claim-mapper` with `oidc-usermodel-attribute-mapper` on both clients
- [x] Added `agent_consent` user attribute to alice and bob in realm JSON (pre-seeded defaults)
- [x] Added `/api/consent/get` and `/api/consent/update` endpoints to demo-ui server (Keycloak Admin API)
- [x] Added consent step (Step 2) to demo UI with agent selection checkboxes, update/revoke buttons
- [x] Refactored logout handler to use shared admin token/user lookup helpers
- [x] Renumbered all subsequent steps (old 2→3, 3→4, etc.) in HTML panels and JavaScript
- [x] Updated test_keycloak_realm.py: checks for `oidc-usermodel-attribute-mapper` + user attribute validation

**How it works:** Each user's `agent_consent` attribute in Keycloak stores which agents they authorize (as a JSON string). The `oidc-usermodel-attribute-mapper` reads this attribute at token issuance and emits it as the `may_act` claim. The demo UI can update the attribute via the Keycloak Admin API. OPA and Token Exchange require no changes — they already validate `may_act` generically.

## 5. OPA Policy: Fix Scope Narrowing Enforcement
**Status:** [x] Completed
**Files:** `opa/policies/delegation.rego`, `token-exchange/token_exchange.py`
**Changes made:**
- [x] Token exchange now passes `parent_scope` in OPA input during chain extensions (delegation_depth > 0)
- [x] OPA `scope_narrowing_valid` rules already handle parent_scope correctly — they were just never receiving the data

## 6. Remove Synthetic SVID / Demo-Secret Patterns
**Status:** [x] Completed
**Files:** `ai-agent/agent.py`, `ai-agent/subagents/sql_executor.py`, `token-exchange/token_exchange.py`
**Changes made:**
- [x] Removed `_generate_demo_svid()` from agent.py
- [x] Removed `_create_identity_token()` from sql_executor.py (replaced with `_fetch_jwt_svid()`)
- [x] Removed `_create_spiffe_token()` from token_exchange.py
- [x] Removed default readonly scope fallback in `_get_permitted_scopes()` (no implicit permissions)

## Tests Updated
- [x] `tests/test_token_exchange.py` — 80 tests pass (updated for RS256, JWKS mocks, fail-closed, no default readonly)
- [x] `tests/config-validation/test_keycloak_realm.py` — 27 tests pass (updated mapper type, added agent_consent attribute test)
- [x] `tests/config-validation/test_opa_*.py` — 49 tests pass (no changes needed)
- [x] `ai-agent/tests/test_agent.py` — 63 tests pass (removed demo SVID tests, added RuntimeError test)
- [x] `tests/config-validation/test_vault_policies.py` — 25 tests pass (added self-renewal, no orphan tests)
- **Total: 382 tests passing**

---

## DEFERRED (Last Priority)

## 7. Mutual TLS (Zero-Trust Network)
**Status:** [x] Completed (Token Exchange + AI Agent path; third-party services documented)
**Files:** `token-exchange/token_exchange.py`, `token-exchange/requirements.txt`, `docker-compose.yml`, `docker-compose.host.yml`, `scripts/bootstrap.sh`, `spire/entries/registration-entries.sh`
**Changes made:**
- [x] Added `spiffe>=0.2.3` to token-exchange requirements.txt
- [x] Added `mtls_enabled` and `spire_agent_socket` config options (env: `MTLS_ENABLED`, `SPIRE_AGENT_SOCKET`)
- [x] Added `_setup_mtls_context()` function: fetches X.509-SVIDs from SPIRE Workload API, creates ssl.SSLContext with client cert verification
- [x] Server wraps socket with TLS when `MTLS_ENABLED=true` and SPIRE is available
- [x] Graceful fallback: if SPIRE unavailable or spiffe lib missing, falls back to HTTP with warning
- [x] Mounted SPIRE agent socket into token-exchange container (both docker-compose files)
- [x] Added `MTLS_ENABLED` and `SPIRE_AGENT_SOCKET` env vars to token-exchange service
- [x] Registered `spiffe://demo.local/service/token-exchange` SPIRE entry in bootstrap.sh and registration-entries.sh
- [x] Added `ssl` import for TLS support

**Note:** Full mTLS for third-party services (Keycloak, Vault, OPA, PostgreSQL) would require either sidecar cert injection via `spiffe-helper` or an Envoy service mesh. These services don't natively consume SPIRE Workload API SVIDs. The current implementation covers the critical path (AI Agent → Token Exchange) which is where identity tokens are exchanged and credentials are brokered. Production deployment should use a service mesh for full coverage.

## 8. Vault Token Over-Privileged and Long-Lived
**Status:** [x] Completed
**Files:** `vault/policies/gateway-policy.hcl`, `scripts/bootstrap.sh`, `token-exchange/token_exchange.py`, `tests/config-validation/test_vault_policies.py`
**Changes made:**
- [x] Changed token from 24h TTL to periodic 1h token with 24h explicit max TTL
- [x] Added `allowed_policies` to restrict child token creation to `ai-agent-db-read` and `ai-agent-db-readwrite`
- [x] Added `auth/token/renew-self` to gateway-policy.hcl for token self-renewal
- [x] Removed `auth/token/create-orphan` from gateway-policy.hcl (unused, unnecessary attack surface)
- [x] Added background daemon thread in token_exchange.py that renews Vault token every 45 minutes
- [x] Added `vault_token_renewal_interval` config (env: `VAULT_TOKEN_RENEWAL_INTERVAL`, default 2700s)
- [x] Added `import threading` for renewal thread
- [x] Added vault policy tests: self-renewal capability, no orphan token creation

---

## IBM Verify Assessment
**Decision:** Keep Keycloak. IBM Verify has native RFC 8693 with `may_act` but is SaaS-only (no free self-hosted Docker option). Not viable for a self-contained Docker Compose demo.

---

## Files Changed (Summary)

| File | Changes |
|------|---------|
| `token-exchange/token_exchange.py` | SPIFFE JWKS verification, RS256 signing, fail-closed, JWKS endpoint, removed synthetic tokens |
| `token-exchange/requirements.txt` | Added `cryptography>=42.0.0` |
| `ai-agent/agent.py` | Removed `_generate_demo_svid()`, fail-hard on SPIRE unavailable |
| `ai-agent/subagents/sql_executor.py` | Replaced `_create_identity_token()` with `_fetch_jwt_svid()` |
| `opa/policies/delegation.rego` | Removed legacy bypass rule for non-SPIFFE may_act |
| `keycloak/realm/demo-realm.json` | Updated may_act to use SPIFFE IDs + aud list |
| `docker-compose.yml` | Added `SPIRE_OIDC_URL` env var |
| `docker-compose.host.yml` | Added `SPIRE_OIDC_URL` env var |
| `tests/test_token_exchange.py` | Updated for RS256, JWKS, fail-closed behavior |
| `tests/config-validation/test_keycloak_realm.py` | Updated may_act assertion |
| `ai-agent/tests/test_agent.py` | Updated SPIFFE identity tests |

---

## Session Log
- **2026-02-24:** Created task tracker. Completed codebase exploration and IBM Verify research.
- **2026-02-24:** Completed tasks 1-6. All 312 tests passing. Deferred tasks 7-8 per user request.
- **2026-02-24:** Completed task 4 (dynamic may_act consent). Replaced hardcoded mapper with user-attribute mapper, added consent UI step, added Keycloak Admin API endpoints. 380 tests passing.
- **2026-02-24:** Completed task 8 (Vault token scoping). Periodic 1h token, self-renewal thread, restricted child policies, removed create-orphan. 382 tests passing.
- **2026-02-24:** Completed task 7 (mTLS). Token Exchange mTLS server support via SPIFFE X.509-SVIDs, SPIRE entry registration, graceful fallback. 382 tests passing.
