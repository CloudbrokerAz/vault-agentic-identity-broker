"""
Automated end-to-end tests for the Demo UI flow.

Tests the full user journey through the demo UI server API:
  Step 0: Health check
  Step 1: Human authentication (password grant)
  Step 2: Agent consent update
  Step 3: SPIFFE SVID fetch
  Step 4: OPA policy evaluation
  Step 5: Token exchange (RFC 8693) — delegation token only
  Step 6: Vault credential brokering (delegation-gated via Token Exchange)
  Step 7: Database query with dynamic credentials
  Step 8: Credential revocation + verification
  Step 9: Audit trail

Requires all services to be running (bootstrap completed).
Run with: python -m pytest tests/test_demo_ui_flow.py -v
"""

import os
import json
import pytest
import requests

DEMO_UI_URL = os.environ.get("DEMO_UI_URL", "http://localhost:8500")
TIMEOUT = 15


def api(method, path, body=None):
    """Call the demo UI server API."""
    url = f"{DEMO_UI_URL}{path}"
    if method == "GET":
        r = requests.get(url, timeout=TIMEOUT)
    else:
        r = requests.post(url, json=body, timeout=TIMEOUT)
    return r.status_code, r.json()


@pytest.fixture(scope="module")
def flow_state():
    """Shared state across the sequential flow tests."""
    return {}


class TestDemoUIFlow:
    """Test the full demo UI flow end-to-end, in order."""

    def test_step0_health(self, flow_state):
        """Step 0: All services must be healthy."""
        status, data = api("GET", "/api/health")
        assert status == 200, f"Health check failed: {data}"
        assert data["overall"] == "healthy", f"Services not healthy: {data}"

        for name, info in data["services"].items():
            assert info["status"] == "healthy", f"Service {name} is {info['status']}"

    def test_step1_auth_login(self, flow_state):
        """Step 1: Authenticate as alice via password grant."""
        status, data = api("POST", "/api/auth/login", {
            "username": "alice",
            "password": "alice-demo-password",
        })
        assert status == 200, f"Auth failed: {data}"
        assert "access_token" in data, "No access_token in response"
        assert data.get("username"), "Server should return resolved username"
        assert data["username"] == "alice", f"Expected username 'alice', got '{data['username']}'"

        flow_state["access_token"] = data["access_token"]
        flow_state["decoded_token"] = data.get("decoded", {})
        flow_state["username"] = data["username"]

        # Verify decoded token has essential claims
        decoded = data.get("decoded", {})
        assert "email" in decoded or "preferred_username" in decoded, \
            f"Token missing identity claims: {list(decoded.keys())}"

    def test_step1_auth_returns_username(self, flow_state):
        """Step 1b: Verify server resolves the Keycloak username correctly."""
        # The server should return 'alice' even though the token contains
        # email 'alice@acme.com' and not preferred_username
        assert flow_state["username"] == "alice"

    def test_step2_consent_update(self, flow_state):
        """Step 2: Update agent consent for alice."""
        status, data = api("POST", "/api/consent/update", {
            "username": flow_state["username"],
            "agents": ["spiffe://demo.local/agent/query-agent"],
        })
        assert status == 200, f"Consent update failed (status {status}): {data}"
        assert not data.get("error"), f"Consent update error: {data.get('message')}"
        assert data.get("consent") is not None, "Consent should not be null on success"
        assert data["consent"]["aud"] == ["spiffe://demo.local/agent/query-agent"]

    def test_step2_consent_get(self, flow_state):
        """Step 2b: Verify consent is readable."""
        status, data = api("POST", "/api/consent/get", {
            "username": flow_state["username"],
        })
        assert status == 200, f"Consent get failed: {data}"
        assert data.get("consent"), "Expected active consent"

    def test_step2_consent_with_email_fallback(self, flow_state):
        """Step 2c: Consent should work even with email as username."""
        # This tests the email fallback in _get_user_by_name
        status, data = api("POST", "/api/consent/get", {
            "username": "alice@acme.com",
        })
        assert status == 200, f"Email-based consent get failed: {data}"
        assert data.get("consent"), "Consent lookup by email should work"

    def test_step3_svid(self, flow_state):
        """Step 3: Fetch SPIFFE SVID for query-agent."""
        status, data = api("POST", "/api/spiffe/svid", {
            "agent_id": "query-agent",
            "agent_type": "agent",
        })
        assert status == 200, f"SVID fetch failed: {data}"
        assert data.get("svid_token"), "No SVID token returned"
        assert data.get("spiffe_id") == "spiffe://demo.local/agent/query-agent"

        flow_state["svid_token"] = data["svid_token"]
        flow_state["svid_decoded"] = data.get("decoded", {})

    def test_step4_opa(self, flow_state):
        """Step 4: OPA policy evaluation should allow the delegation."""
        decoded = flow_state["decoded_token"]
        opa_input = {
            "human_token": {
                "sub": decoded.get("email") or decoded.get("preferred_username", "alice"),
                "groups": decoded.get("groups", []),
                "may_act": decoded.get("may_act", {}),
                "exp": decoded.get("exp", 0),
                "iss": decoded.get("iss", ""),
            },
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "requested_scope": "readonly",
            "current_time": int(__import__("time").time()),
            "delegation_depth": 0,
        }
        status, data = api("POST", "/api/opa/evaluate", {"input": opa_input})
        assert status == 200, f"OPA eval failed: {data}"
        result = data.get("result", data)
        assert result.get("allow") is True, f"OPA denied: {result}"

    def test_step5_token_exchange(self, flow_state):
        """Step 5: Token exchange should return delegation token (no db_credential)."""
        status, data = api("POST", "/api/token-exchange", {
            "subject_token": flow_state["access_token"],
            "actor_token": flow_state["svid_token"],
            "scope": "readonly",
        })
        assert status == 200, f"Token exchange failed (status {status}): {data}"
        assert data.get("access_token"), "No delegation token returned"
        assert data.get("session_id"), "No session_id returned"

        # Delegation-only: db_credential should NOT be present
        assert data.get("db_credential") is None, \
            "db_credential should not be returned when audience is 'delegation'"

        flow_state["delegation_token"] = data["access_token"]
        flow_state["session_id"] = data["session_id"]

        # Verify decoded input tokens are present
        assert "subject_token_decoded" in data, \
            "Response should include decoded subject token"
        assert "actor_token_decoded" in data, \
            "Response should include decoded actor token"
        assert "delegation_token_decoded" in data, \
            "Response should include decoded delegation token"

        # Verify subject token has expected claims
        st = data["subject_token_decoded"]
        assert st is not None, "subject_token_decoded should not be null"
        assert "groups" in st, f"Subject token missing groups: {list(st.keys())}"

        # Verify actor token has SPIFFE ID
        at = data["actor_token_decoded"]
        assert at is not None, "actor_token_decoded should not be null"
        assert "spiffe://demo.local/agent/query-agent" in (at.get("sub", "")), \
            f"Actor token sub doesn't match: {at.get('sub')}"

        # Verify delegation token has act{} claim
        dt = data["delegation_token_decoded"]
        assert dt is not None, "delegation_token_decoded should not be null"
        assert "act" in dt, f"Delegation token missing act claim: {list(dt.keys())}"
        assert dt["act"].get("sub"), "act.sub should contain the agent SPIFFE ID"
        assert "scope" in dt, "Delegation token should have scope claim"

    def test_step6_vault_credentials(self, flow_state):
        """Step 6: Broker credentials via delegation token through Token Exchange."""
        delegation_token = flow_state.get("delegation_token")
        if not delegation_token:
            pytest.skip("No delegation token from step 5")

        status, data = api("POST", "/api/vault/credentials", {
            "delegation_token": delegation_token,
        })
        assert status == 200, f"Credential brokering failed (status {status}): {data}"
        assert data.get("username"), "DB credential missing username"
        assert data.get("password"), "DB credential missing password"
        assert data.get("host"), "DB credential missing host"
        assert data.get("database") == "appdb", f"Expected database 'appdb', got '{data.get('database')}'"
        assert data.get("ttl_seconds", 0) > 0, "TTL should be positive"
        assert data.get("lease_id"), "DB credential missing lease_id"
        assert data.get("delegation_verified") is True, \
            "delegation_verified should be True — delegation token was checked"
        assert data.get("steps"), "Educational step trace should be present"

        flow_state["db_credential"] = data
        flow_state["vault_lease_id"] = data.get("lease_id")

    def test_step7_db_query(self, flow_state):
        """Step 7: Execute a SQL query with dynamic credentials."""
        db = flow_state.get("db_credential")
        if not db:
            pytest.skip("No DB credentials (Vault token may be expired)")

        status, data = api("POST", "/api/db/query", {
            "host": db["host"],
            "port": db["port"],
            "database": db["database"],
            "username": db["username"],
            "password": db["password"],
            "sql": "SELECT * FROM app.orders LIMIT 3",
        })
        assert status == 200, f"DB query failed: {data}"
        assert not data.get("error"), f"DB query error: {data}"
        assert "columns" in data, "Response missing columns"
        assert "rows" in data, "Response missing rows"
        assert data.get("row_count", 0) > 0, "Expected at least 1 row"

    def test_step8_revoke(self, flow_state):
        """Step 8: Revoke the delegation token and credentials."""
        status, data = api("POST", "/api/revoke", {
            "session_id": flow_state["session_id"],
            "delegation_token": flow_state["delegation_token"],
            "lease_id": flow_state.get("vault_lease_id", ""),
        })
        assert status == 200, f"Revocation failed: {data}"
        flow_state["revoked"] = True

    def test_step8_verify_revocation(self, flow_state):
        """Step 8b: Verify credentials are no longer valid after revocation."""
        db = flow_state.get("db_credential")
        if not db:
            pytest.skip("No DB credentials to verify")

        status, data = api("POST", "/api/db/verify-revoked", {
            "username": db["username"],
            "password": db["password"],
        })
        assert status == 200, f"Verify-revoked failed: {data}"
        assert data.get("revoked") is True, f"Credentials should be revoked: {data}"

    def test_step9_audit(self, flow_state):
        """Step 9: Audit trail should contain entries for this session."""
        status, data = api("GET", "/api/audit")
        assert status == 200, f"Audit fetch failed: {data}"

        entries = data.get("entries", data)
        assert isinstance(entries, list), f"Expected list of entries, got {type(entries)}"
        assert len(entries) > 0, "Audit trail should not be empty"

        # Verify entries have expected fields
        for entry in entries:
            assert "timestamp" in entry, f"Audit entry missing timestamp: {entry}"
            assert "action" in entry, f"Audit entry missing action: {entry}"
            assert "session_id" in entry, f"Audit entry missing session_id: {entry}"

        # Verify current session appears in audit
        session_id = flow_state.get("session_id")
        if session_id:
            session_entries = [e for e in entries if e.get("session_id") == session_id]
            assert len(session_entries) >= 1, \
                f"Expected at least 1 audit entry for session {session_id}, found {len(session_entries)}"

            # Should have exchange + revocation
            actions = [e.get("action") for e in session_entries]
            assert "token_exchange" in actions, \
                f"Expected 'token_exchange' in session audit, got: {actions}"

    def test_step9_audit_entry_structure(self, flow_state):
        """Step 9b: Verify audit entries have the fields the UI timeline expects."""
        status, data = api("GET", "/api/audit")
        entries = data.get("entries", data)

        for entry in entries:
            # These are the fields the timeline renderer uses
            assert "action" in entry, "Timeline needs 'action' field"
            assert "result" in entry, "Timeline needs 'result' field"
            assert "session_id" in entry, "Timeline needs 'session_id' field"
            # Exchange entries should have identity fields; revocation may not
            action = entry.get("action", "")
            if "exchange" in action:
                has_who = entry.get("subject") or entry.get("human") or entry.get("actor") or entry.get("agent")
                assert has_who, f"Exchange entry missing identity fields: {entry}"


class TestDemoUIEdgeCases:
    """Test edge cases and error handling in the demo UI."""

    def test_consent_with_email_lookup(self):
        """Consent update should work when username is an email."""
        status, data = api("POST", "/api/consent/update", {
            "username": "alice@acme.com",
            "agents": ["spiffe://demo.local/agent/query-agent"],
        })
        assert status == 200, f"Email-based consent should work: {data}"
        assert not data.get("error"), f"Consent error with email: {data}"

    def test_consent_missing_user(self):
        """Consent update should fail gracefully for unknown users."""
        status, data = api("POST", "/api/consent/update", {
            "username": "nonexistent-user",
            "agents": ["spiffe://demo.local/agent/query-agent"],
        })
        assert status == 404

    def test_consent_empty_username(self):
        """Consent update should reject empty username."""
        status, data = api("POST", "/api/consent/update", {
            "username": "",
            "agents": [],
        })
        assert status == 400

    def test_token_exchange_missing_tokens(self):
        """Token exchange should fail gracefully with missing tokens."""
        status, data = api("POST", "/api/token-exchange", {
            "subject_token": "",
            "actor_token": "",
            "scope": "readonly",
        })
        # Should not crash — may return 4xx or 502
        assert status >= 400

    def test_vault_credentials_missing_delegation_token(self):
        """Vault credentials should fail without a delegation_token."""
        status, data = api("POST", "/api/vault/credentials", {
            "delegation_token": "",
        })
        assert status == 400

    def test_vault_credentials_invalid_delegation_token(self):
        """Vault credentials should fail with an invalid delegation token."""
        status, data = api("POST", "/api/vault/credentials", {
            "delegation_token": "not-a-valid-jwt-token",
        })
        assert status >= 400

    def test_health_response_structure(self):
        """Health response should have expected structure for the UI."""
        status, data = api("GET", "/api/health")
        assert "overall" in data
        assert "services" in data
        expected_services = {"keycloak", "opa", "token_exchange", "vault", "postgresql", "spire"}
        actual_services = set(data["services"].keys())
        assert expected_services == actual_services, \
            f"Missing services: {expected_services - actual_services}"

    def test_audit_empty_is_ok(self):
        """Audit endpoint should return a valid response even if empty."""
        status, data = api("GET", "/api/audit")
        assert status == 200
        entries = data.get("entries", data)
        assert isinstance(entries, list)

    def test_svid_unregistered_agent(self):
        """SVID fetch for unregistered agent should still return something."""
        status, data = api("POST", "/api/spiffe/svid", {
            "agent_id": "rogue-agent",
            "agent_type": "agent",
        })
        # May succeed with demo SVID or fail — should not crash
        assert status in (200, 400, 404, 502)


class TestResolveUsername:
    """Test the resolve_username function indirectly via auth endpoints."""

    def test_password_grant_returns_username(self):
        """Password grant should return the exact Keycloak username."""
        status, data = api("POST", "/api/auth/login", {
            "username": "alice",
            "password": "alice-demo-password",
        })
        assert status == 200
        assert data.get("username") == "alice"

    def test_password_grant_bob(self):
        """Password grant for bob should return 'bob'."""
        status, data = api("POST", "/api/auth/login", {
            "username": "bob",
            "password": "bob-demo-password",
        })
        assert status == 200
        assert data.get("username") == "bob"
