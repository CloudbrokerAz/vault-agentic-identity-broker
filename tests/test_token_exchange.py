"""
Comprehensive unit tests for the Token Exchange Service.

Tests cover:
- TokenExchangeService unit tests (direct invocation, no HTTP)
- DelegationChainLink data model tests
- RFC 8693 `act` claim building
- Scope validation and group-based resolution
- HTTP handler integration-style tests
- Token revocation
- Delegation chain querying
- SPIFFE trust domain validation

All external services (Keycloak, OPA, Vault) are mocked.
"""

import hashlib
import io
import json
import os
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
from unittest.mock import MagicMock, patch, PropertyMock

import jwt as pyjwt

# Ensure the token-exchange module is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "token-exchange"))

from token_exchange import (
    DelegationChainLink,
    DelegationSession,
    GRANT_TYPE_TOKEN_EXCHANGE,
    ServiceConfig,
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_AGENT_DELEGATION,
    TOKEN_TYPE_DELEGATION,
    TOKEN_TYPE_JWT,
    TOKEN_TYPE_SPIFFE,
    TokenExchangeHandler,
    TokenExchangeService,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SIGNING_SECRET = "test-signing-secret"
TRUST_DOMAIN = "demo.local"
ISSUER_PORT = 8090


def _make_config(**overrides) -> ServiceConfig:
    """Create a ServiceConfig with test defaults."""
    defaults = dict(
        listen_port=ISSUER_PORT,
        keycloak_url="http://keycloak:8080",
        keycloak_realm="demo",
        opa_endpoint="http://opa:8181",
        vault_addr="http://vault:8200",
        vault_token="s.test-vault-token",
        trust_domain=TRUST_DOMAIN,
        signing_secret=SIGNING_SECRET,
        max_delegation_depth=3,
        default_ttl=300,
        max_ttl=1800,
    )
    defaults.update(overrides)
    return ServiceConfig(**defaults)


def _make_service(**overrides) -> TokenExchangeService:
    return TokenExchangeService(_make_config(**overrides))


def _human_jwt(
    sub="alice@acme.com",
    groups=None,
    may_act=None,
    exp_offset=3600,
    extra_claims=None,
) -> str:
    """Create a fake human OIDC JWT (unsigned for test purposes)."""
    now = int(time.time())
    claims = {
        "sub": sub,
        "email": sub,
        "groups": groups or ["data-analysts"],
        "may_act": may_act or {},
        "exp": now + exp_offset,
        "iat": now,
        "iss": "http://keycloak:8080/realms/demo",
    }
    if extra_claims:
        claims.update(extra_claims)
    return pyjwt.encode(claims, "keycloak-secret", algorithm="HS256")


def _agent_jwt(
    sub=None,
    trust_domain=TRUST_DOMAIN,
    extra_claims=None,
) -> str:
    """Create a fake agent SPIFFE JWT-SVID."""
    sub = sub or f"spiffe://{trust_domain}/agent/query-agent"
    now = int(time.time())
    claims = {
        "sub": sub,
        "aud": ["token-exchange"],
        "exp": now + 3600,
        "iat": now,
        "client_type": "ai_agent",
    }
    if extra_claims:
        claims.update(extra_claims)
    return pyjwt.encode(claims, "demo-secret", algorithm="HS256")


def _valid_exchange_params(
    subject_token=None,
    actor_token=None,
    scope="readonly",
    audience="database",
) -> dict:
    """Build a valid RFC 8693 token exchange parameter dict."""
    return {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "subject_token": subject_token or _human_jwt(),
        "subject_token_type": TOKEN_TYPE_ACCESS,
        "actor_token": actor_token or _agent_jwt(),
        "actor_token_type": TOKEN_TYPE_JWT,
        "scope": scope,
        "audience": audience,
    }


def _mock_keycloak_success(human_claims=None):
    """Return a mock for requests.get that simulates Keycloak userinfo 200."""
    resp = MagicMock()
    resp.status_code = 200
    claims = human_claims or {
        "sub": "alice-uuid",
        "email": "alice@acme.com",
        "groups": ["data-analysts"],
    }
    resp.json.return_value = claims
    return resp


def _mock_opa_allow():
    """Return a mock for requests.post that simulates OPA allow."""
    def _side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "decision" in url:
            resp.json.return_value = {"result": {"allowed": True, "reason": "all_checks_passed"}}
        else:
            resp.json.return_value = {"result": True}
        return resp
    return _side_effect


def _mock_opa_deny(reason="policy_denied"):
    """Return a mock for requests.post that simulates OPA deny."""
    def _side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "decision" in url:
            resp.json.return_value = {"result": {"allowed": False, "reason": reason}}
        else:
            resp.json.return_value = {"result": False}
        return resp
    return _side_effect


def _mock_vault_creds():
    """Return a mock for requests.get/post that simulates Vault credential issuance."""
    def _side_effect(url, **kwargs):
        resp = MagicMock()
        if "database/creds" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "data": {
                    "username": "v-spiffe-readonly-abc123",
                    "password": "dynamic-test-pw",
                },
                "lease_id": "database/creds/ai-agent-readonly/lease-xyz",
                "lease_duration": 300,
            }
        else:
            # token/lookup-self
            resp.status_code = 200
            resp.json.return_value = {}
        return resp
    return _side_effect


def _mock_get_keycloak_and_vault(human_claims=None):
    """
    Return a side_effect for requests.get that handles both Keycloak userinfo
    and Vault credential requests by dispatching on URL.
    """
    kc_claims = human_claims or {
        "sub": "alice-uuid",
        "email": "alice@acme.com",
        "groups": ["data-analysts"],
    }

    def _side_effect(url, **kwargs):
        resp = MagicMock()
        if "userinfo" in url:
            resp.status_code = 200
            resp.json.return_value = kc_claims
        elif "database/creds" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "data": {
                    "username": "v-spiffe-readonly-abc123",
                    "password": "dynamic-test-pw",
                },
                "lease_id": "database/creds/ai-agent-readonly/lease-xyz",
                "lease_duration": 300,
            }
        else:
            resp.status_code = 200
            resp.json.return_value = {}
        return resp
    return _side_effect


# ═══════════════════════════════════════════════════════════════════════════════
# 1. DelegationChainLink Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDelegationChainLink(unittest.TestCase):
    """Tests for the DelegationChainLink dataclass."""

    def test_link_creation_with_all_fields(self):
        link = DelegationChainLink(
            subject="alice@acme.com",
            actor="spiffe://demo.local/agent/query-agent",
            actor_type="agent",
            scope="readonly",
            timestamp="2026-01-01T00:00:00+00:00",
            session_id="sess-abc123",
            depth=0,
        )
        self.assertEqual(link.subject, "alice@acme.com")
        self.assertEqual(link.actor, "spiffe://demo.local/agent/query-agent")
        self.assertEqual(link.actor_type, "agent")
        self.assertEqual(link.scope, "readonly")
        self.assertEqual(link.session_id, "sess-abc123")
        self.assertEqual(link.depth, 0)

    def test_chain_depth_tracking(self):
        links = [
            DelegationChainLink(
                subject="alice@acme.com",
                actor="spiffe://demo.local/agent/query-agent",
                actor_type="agent",
                scope="readonly",
                timestamp="",
                session_id="sess-1",
                depth=0,
            ),
            DelegationChainLink(
                subject="spiffe://demo.local/agent/query-agent",
                actor="spiffe://demo.local/subagent/sql-executor",
                actor_type="sub-agent",
                scope="readonly",
                timestamp="",
                session_id="sess-1",
                depth=1,
            ),
        ]
        self.assertEqual(links[0].depth, 0)
        self.assertEqual(links[1].depth, 1)
        self.assertEqual(len(links), 2)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. DelegationSession Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDelegationSession(unittest.TestCase):
    """Tests for the DelegationSession dataclass."""

    def test_session_defaults(self):
        session = DelegationSession(session_id="sess-1")
        self.assertEqual(session.session_id, "sess-1")
        self.assertEqual(session.chain, [])
        self.assertIsNone(session.db_credentials)
        self.assertIsNone(session.vault_lease_id)
        self.assertIsNone(session.delegated_token)
        self.assertFalse(session.revoked)
        self.assertNotEqual(session.created_at, "")

    def test_session_created_at_auto_set(self):
        session = DelegationSession(session_id="sess-auto")
        self.assertIn("T", session.created_at)  # ISO format has a T
        self.assertIn("+", session.created_at)   # UTC offset present


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Act Claim Building Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestActClaimBuilding(unittest.TestCase):
    """Tests for _build_act_claim which produces the RFC 8693 nested act claim."""

    def setUp(self):
        self.service = _make_service()

    def test_empty_chain_returns_empty_dict(self):
        result = self.service._build_act_claim([])
        self.assertEqual(result, {})

    def test_single_link_human_to_agent(self):
        """human -> agent should produce: {sub: agent, act: {sub: human}}"""
        chain = [
            DelegationChainLink(
                subject="alice@acme.com",
                actor="spiffe://demo.local/agent/query-agent",
                actor_type="agent",
                scope="readonly",
                timestamp="",
                session_id="sess-1",
                depth=0,
            ),
        ]
        result = self.service._build_act_claim(chain)
        self.assertEqual(result["sub"], "spiffe://demo.local/agent/query-agent")
        self.assertIn("act", result)
        self.assertEqual(result["act"]["sub"], "alice@acme.com")
        # Only two levels of nesting
        self.assertNotIn("act", result["act"])

    def test_double_link_human_to_agent_to_subagent(self):
        """
        human -> agent -> sub-agent should produce:
        {sub: sub-agent, act: {sub: agent, act: {sub: human}}}
        """
        chain = [
            DelegationChainLink(
                subject="alice@acme.com",
                actor="spiffe://demo.local/agent/query-agent",
                actor_type="agent",
                scope="readonly",
                timestamp="",
                session_id="sess-1",
                depth=0,
            ),
            DelegationChainLink(
                subject="spiffe://demo.local/agent/query-agent",
                actor="spiffe://demo.local/subagent/sql-executor",
                actor_type="sub-agent",
                scope="readonly",
                timestamp="",
                session_id="sess-1",
                depth=1,
            ),
        ]
        result = self.service._build_act_claim(chain)
        # Outermost is the most recent actor (sub-agent)
        self.assertEqual(result["sub"], "spiffe://demo.local/subagent/sql-executor")
        # Next layer is the agent
        self.assertEqual(result["act"]["sub"], "spiffe://demo.local/agent/query-agent")
        # Innermost is the human
        self.assertEqual(result["act"]["act"]["sub"], "alice@acme.com")
        self.assertNotIn("act", result["act"]["act"])

    def test_triple_link_max_depth(self):
        """
        human -> agent -> sub-agent -> sub-sub-agent with three chain links.
        """
        chain = [
            DelegationChainLink(
                subject="alice@acme.com",
                actor="spiffe://demo.local/agent/query-agent",
                actor_type="agent",
                scope="readonly",
                timestamp="",
                session_id="sess-1",
                depth=0,
            ),
            DelegationChainLink(
                subject="spiffe://demo.local/agent/query-agent",
                actor="spiffe://demo.local/subagent/sql-executor",
                actor_type="sub-agent",
                scope="readonly",
                timestamp="",
                session_id="sess-1",
                depth=1,
            ),
            DelegationChainLink(
                subject="spiffe://demo.local/subagent/sql-executor",
                actor="spiffe://demo.local/subagent/formatter",
                actor_type="sub-agent",
                scope="readonly",
                timestamp="",
                session_id="sess-1",
                depth=2,
            ),
        ]
        result = self.service._build_act_claim(chain)
        # Outermost: formatter
        self.assertEqual(result["sub"], "spiffe://demo.local/subagent/formatter")
        # Next: sql-executor
        self.assertEqual(result["act"]["sub"], "spiffe://demo.local/subagent/sql-executor")
        # Next: query-agent
        self.assertEqual(result["act"]["act"]["sub"], "spiffe://demo.local/agent/query-agent")
        # Innermost: human
        self.assertEqual(result["act"]["act"]["act"]["sub"], "alice@acme.com")
        self.assertNotIn("act", result["act"]["act"]["act"])


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Scope Validation Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScopeValidation(unittest.TestCase):
    """Tests for _get_permitted_scopes and scope narrowing."""

    def setUp(self):
        self.service = _make_service()

    def test_data_analysts_group_scopes(self):
        claims = {"groups": ["data-analysts"]}
        scopes = self.service._get_permitted_scopes(claims)
        self.assertIn("readonly", scopes)
        self.assertIn("db:read", scopes)
        self.assertIn("db:query", scopes)
        self.assertNotIn("readwrite", scopes)
        self.assertNotIn("db:write", scopes)

    def test_engineering_group_scopes(self):
        claims = {"groups": ["engineering"]}
        scopes = self.service._get_permitted_scopes(claims)
        self.assertIn("readonly", scopes)
        self.assertIn("readwrite", scopes)
        self.assertIn("db:read", scopes)
        self.assertIn("db:write", scopes)
        self.assertIn("db:query", scopes)

    def test_trading_team_group_scopes(self):
        claims = {"groups": ["trading-team"]}
        scopes = self.service._get_permitted_scopes(claims)
        self.assertIn("readonly", scopes)
        self.assertIn("db:read", scopes)
        self.assertIn("db:query", scopes)
        self.assertNotIn("readwrite", scopes)

    def test_unknown_group_defaults_to_readonly(self):
        claims = {"groups": ["unknown-group"]}
        scopes = self.service._get_permitted_scopes(claims)
        self.assertEqual(scopes, ["readonly"])

    def test_no_groups_defaults_to_readonly(self):
        claims = {"groups": []}
        scopes = self.service._get_permitted_scopes(claims)
        self.assertEqual(scopes, ["readonly"])

    def test_delegation_token_scope_inheritance(self):
        """A delegation token should return only its own scope."""
        claims = {
            "iss": self.service.issuer,
            "scope": "db:read",
            "groups": ["engineering"],  # should be ignored
        }
        scopes = self.service._get_permitted_scopes(claims)
        self.assertEqual(scopes, ["db:read"])

    def test_multiple_groups_union_scopes(self):
        claims = {"groups": ["data-analysts", "engineering"]}
        scopes = self.service._get_permitted_scopes(claims)
        # Engineering is superset so all should be present
        self.assertIn("readwrite", scopes)
        self.assertIn("db:write", scopes)
        self.assertIn("readonly", scopes)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. TokenExchangeService Unit Tests (direct, no HTTP)
# ═══════════════════════════════════════════════════════════════════════════════


class TestTokenExchangeService(unittest.TestCase):
    """Direct unit tests for exchange_token, revoke_token, get_delegation_chain."""

    def setUp(self):
        self.service = _make_service()

    # ── Valid exchange ───────────────────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_valid_token_exchange_all_required_fields(self, mock_post, mock_get):
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertIn("access_token", result)
        self.assertEqual(result["issued_token_type"], TOKEN_TYPE_AGENT_DELEGATION)
        self.assertEqual(result["token_type"], "Bearer")
        self.assertEqual(result["scope"], "readonly")
        self.assertIn("session_id", result)
        self.assertIn("expires_in", result)
        self.assertIn("delegation_chain", result)
        self.assertEqual(len(result["delegation_chain"]), 1)

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_exchange_returns_valid_jwt(self, mock_post, mock_get):
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        token = result["access_token"]

        decoded = pyjwt.decode(token, SIGNING_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        self.assertIn("sub", decoded)
        self.assertIn("act", decoded)
        self.assertIn("scope", decoded)
        self.assertIn("session_id", decoded)
        self.assertEqual(decoded["scope"], "readonly")
        self.assertEqual(decoded["iss"], f"http://token-exchange:{ISSUER_PORT}")

    @patch("token_exchange.requests.get", side_effect=_mock_get_keycloak_and_vault())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_exchange_act_claim_structure(self, mock_post, mock_get):
        """Verify act claim in the JWT is correctly nested per RFC 8693."""
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        token = result["access_token"]

        decoded = pyjwt.decode(token, SIGNING_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        act = decoded["act"]
        # Outermost act.sub should be the agent
        self.assertTrue(act["sub"].startswith("spiffe://"))
        # Innermost should be the human
        self.assertEqual(act["act"]["sub"], "alice@acme.com")

    # ── Missing fields ──────────────────────────────────────────────────

    def test_missing_subject_token_returns_error(self):
        params = _valid_exchange_params()
        del params["subject_token"]
        result = self.service.exchange_token(params)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "invalid_request")
        self.assertIn("subject_token", result["error_description"])

    def test_missing_actor_token_returns_error(self):
        params = _valid_exchange_params()
        del params["actor_token"]
        result = self.service.exchange_token(params)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "invalid_request")
        self.assertIn("actor_token", result["error_description"])

    def test_invalid_grant_type_returns_error(self):
        params = _valid_exchange_params()
        params["grant_type"] = "authorization_code"
        result = self.service.exchange_token(params)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "unsupported_grant_type")

    def test_missing_grant_type_returns_error(self):
        params = _valid_exchange_params()
        del params["grant_type"]
        result = self.service.exchange_token(params)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "unsupported_grant_type")

    # ── Scope narrowing validation ──────────────────────────────────────

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_scope_narrowing_denies_wider_scope(self, mock_post, mock_get):
        """A data-analyst cannot request readwrite scope."""
        mock_get.return_value = _mock_keycloak_success()
        params = _valid_exchange_params(scope="readwrite")
        result = self.service.exchange_token(params)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "invalid_scope")
        self.assertIn("readwrite", result["error_description"])

    @patch("token_exchange.requests.get", side_effect=_mock_get_keycloak_and_vault(
        human_claims={"sub": "eng-user", "email": "eng@acme.com", "groups": ["engineering"]}
    ))
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_engineering_can_request_readwrite(self, mock_post, mock_get):
        """An engineering user can request readwrite scope."""
        human_token = _human_jwt(groups=["engineering"])
        params = _valid_exchange_params(subject_token=human_token, scope="readwrite")
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertEqual(result["scope"], "readwrite")

    # ── Maximum delegation chain depth ──────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_max_delegation_chain_depth_enforcement(self, mock_post, mock_get):
        """Exceeding max_delegation_depth should return an error."""
        # Configure service with max depth 1
        service = _make_service(max_delegation_depth=1)

        # First delegation: human -> agent (depth 0, chain length becomes 1)
        params = _valid_exchange_params()
        result1 = service.exchange_token(params)
        self.assertNotIn("error", result1)

        # Use the delegation token as subject for chain extension
        delegation_token = result1["access_token"]
        sub_agent_jwt = _agent_jwt(sub=f"spiffe://{TRUST_DOMAIN}/subagent/sql-executor")

        params2 = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": delegation_token,
            "subject_token_type": TOKEN_TYPE_DELEGATION,
            "actor_token": sub_agent_jwt,
            "actor_token_type": TOKEN_TYPE_JWT,
            "scope": "readonly",
            "audience": "database",
        }
        result2 = service.exchange_token(params2)

        self.assertIn("error", result2)
        self.assertEqual(result2["error"], "invalid_request")
        self.assertIn("depth", result2["error_description"].lower())

    # ── Delegation chain building ───────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_get_keycloak_and_vault())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_delegation_chain_human_to_agent(self, mock_post, mock_get):
        """Initial delegation should create a chain of depth 1."""
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        chain = result["delegation_chain"]
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["actor_type"], "agent")
        self.assertEqual(chain[0]["depth"], 0)
        self.assertEqual(chain[0]["subject"], "alice@acme.com")

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_delegation_chain_extension_agent_to_subagent(self, mock_post, mock_get):
        """Chain extension should add a sub-agent link."""
        # First: human -> agent
        params = _valid_exchange_params()
        result1 = self.service.exchange_token(params)
        self.assertNotIn("error", result1)

        # Second: agent -> sub-agent
        delegation_token = result1["access_token"]
        sub_agent_jwt = _agent_jwt(sub=f"spiffe://{TRUST_DOMAIN}/subagent/sql-executor")

        params2 = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": delegation_token,
            "subject_token_type": TOKEN_TYPE_DELEGATION,
            "actor_token": sub_agent_jwt,
            "actor_token_type": TOKEN_TYPE_JWT,
            "scope": "readonly",
            "audience": "database",
        }
        result2 = self.service.exchange_token(params2)

        self.assertNotIn("error", result2)
        chain = result2["delegation_chain"]
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0]["actor_type"], "agent")
        self.assertEqual(chain[0]["depth"], 0)
        self.assertEqual(chain[1]["actor_type"], "sub-agent")
        self.assertEqual(chain[1]["depth"], 1)

    # ── Token revocation ────────────────────────────────────────────────

    @patch("token_exchange.requests.put")
    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_token_revocation_marks_session_revoked(self, mock_post, mock_get, mock_put):
        mock_put.return_value = MagicMock(status_code=204)

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        token = result["access_token"]
        session_id = result["session_id"]

        revoke_result = self.service.revoke_token(token)
        self.assertEqual(revoke_result["status"], "revoked")
        self.assertEqual(revoke_result["session_id"], session_id)

        # Verify session is marked revoked
        session = self.service.sessions[session_id]
        self.assertTrue(session.revoked)

    def test_revoke_unknown_token_returns_not_found(self):
        result = self.service.revoke_token("nonexistent-token")
        self.assertEqual(result["status"], "not_found")

    @patch("token_exchange.requests.put")
    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_revocation_calls_vault_lease_revoke(self, mock_post, mock_get, mock_put):
        mock_put.return_value = MagicMock(status_code=204)

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        token = result["access_token"]

        self.service.revoke_token(token)

        # Vault revoke should have been called
        mock_put.assert_called_once()
        call_kwargs = mock_put.call_args
        self.assertIn("sys/leases/revoke", call_kwargs[0][0])

    # ── Delegation chain query ──────────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_delegation_chain_query_returns_correct_data(self, mock_post, mock_get):
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        session_id = result["session_id"]

        chain_data = self.service.get_delegation_chain(session_id)
        self.assertEqual(chain_data["session_id"], session_id)
        self.assertFalse(chain_data["revoked"])
        self.assertEqual(chain_data["chain_depth"], 1)
        self.assertTrue(chain_data["has_credentials"])
        self.assertIn("chain", chain_data)
        self.assertEqual(len(chain_data["chain"]), 1)

    def test_delegation_chain_query_unknown_session(self):
        result = self.service.get_delegation_chain("sess-nonexistent")
        self.assertIn("error", result)
        self.assertEqual(result["error"], "session_not_found")

    # ── SPIFFE trust domain validation ──────────────────────────────────

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_spiffe_wrong_trust_domain_rejected(self, mock_post, mock_get):
        """Actor with wrong SPIFFE trust domain should be rejected."""
        mock_get.return_value = _mock_keycloak_success()
        bad_agent = _agent_jwt(sub="spiffe://evil.domain/agent/bad-agent", trust_domain="evil.domain")
        params = _valid_exchange_params(actor_token=bad_agent)
        result = self.service.exchange_token(params)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "invalid_request")
        self.assertIn("trust domain", result["error_description"].lower())

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_spiffe_correct_trust_domain_accepted(self, mock_post, mock_get):
        """Actor with correct SPIFFE trust domain should be accepted."""
        good_agent = _agent_jwt(sub=f"spiffe://{TRUST_DOMAIN}/agent/good-agent")
        params = _valid_exchange_params(actor_token=good_agent)
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)

    # ── OPA policy integration ──────────────────────────────────────────

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_deny("unauthorized_delegation"))
    def test_opa_deny_blocks_exchange(self, mock_post, mock_get):
        mock_get.return_value = _mock_keycloak_success()
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "access_denied")
        self.assertIn("unauthorized_delegation", result["error_description"])

    # ── Session storage ─────────────────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_session_stored_after_exchange(self, mock_post, mock_get):
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        session_id = result["session_id"]

        self.assertIn(session_id, self.service.sessions)
        session = self.service.sessions[session_id]
        self.assertEqual(len(session.chain), 1)
        self.assertIsNotNone(session.delegated_token)
        self.assertFalse(session.revoked)

    # ── Audit log ───────────────────────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_audit_log_recorded_on_success(self, mock_post, mock_get):
        params = _valid_exchange_params()
        self.service.exchange_token(params)

        self.assertTrue(len(self.service.audit_log) > 0)
        entry = self.service.audit_log[-1]
        self.assertEqual(entry["action"], "token_exchange")
        self.assertEqual(entry["result"], "success")
        self.assertIn("session_id", entry)

    # ── Vault credential brokering ──────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_vault_credentials_included_when_audience_database(self, mock_post, mock_get):
        params = _valid_exchange_params(audience="database")
        result = self.service.exchange_token(params)

        self.assertIn("db_credential", result)
        cred = result["db_credential"]
        self.assertIn("username", cred)
        self.assertIn("password", cred)

    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_no_vault_credentials_without_vault_token(self, mock_post):
        """When vault_token is empty, no DB credentials should be brokered."""
        service = _make_service(vault_token="")
        params = _valid_exchange_params()
        result = service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertNotIn("db_credential", result)

    # ── Scope to Vault role mapping ─────────────────────────────────────

    def test_scope_to_vault_role_readonly(self):
        self.assertEqual(self.service._scope_to_vault_role("readonly"), "ai-agent-readonly")
        self.assertEqual(self.service._scope_to_vault_role("db:read"), "ai-agent-readonly")

    def test_scope_to_vault_role_readwrite(self):
        self.assertEqual(self.service._scope_to_vault_role("readwrite"), "ai-agent-readwrite")
        self.assertEqual(self.service._scope_to_vault_role("db:write"), "ai-agent-readwrite")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Legacy Delegate Endpoint Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLegacyDelegate(unittest.TestCase):
    """Tests for the backward-compatible delegate() method."""

    def setUp(self):
        self.service = _make_service()

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_delegate_returns_legacy_format(self, mock_post, mock_get):
        request = {
            "human_token": _human_jwt(),
            "agent_spiffe_id": f"spiffe://{TRUST_DOMAIN}/agent/query-agent",
            "agent_jwt_svid": _agent_jwt(),
            "requested_scope": "readonly",
        }
        result = self.service.delegate(request)

        self.assertNotIn("error", result)
        self.assertIn("session_id", result)
        self.assertIn("delegation_token", result)
        self.assertIn("metadata", result)
        self.assertIn("expires_at", result)

        meta = result["metadata"]
        self.assertEqual(meta["token_exchange_flow"], "rfc8693")
        self.assertEqual(meta["delegation_scope"], "readonly")

    @patch("token_exchange.requests.get", side_effect=_mock_get_keycloak_and_vault())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_delegate_without_svid_creates_spiffe_token(self, mock_post, mock_get):
        """When agent_jwt_svid is empty, _create_spiffe_token is used."""
        request = {
            "human_token": _human_jwt(),
            "agent_spiffe_id": f"spiffe://{TRUST_DOMAIN}/agent/query-agent",
            "agent_jwt_svid": "",
            "requested_scope": "readonly",
        }
        result = self.service.delegate(request)
        # Should not error because _create_spiffe_token generates a valid JWT
        self.assertNotIn("error", result)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. ServiceConfig Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestServiceConfig(unittest.TestCase):
    """Tests for ServiceConfig and from_env."""

    def test_defaults(self):
        config = ServiceConfig()
        self.assertEqual(config.listen_port, 8090)
        self.assertEqual(config.max_delegation_depth, 3)
        self.assertEqual(config.default_ttl, 300)
        self.assertEqual(config.max_ttl, 1800)
        self.assertEqual(config.trust_domain, "demo.local")

    def test_from_env(self):
        env = {
            "KEYCLOAK_URL": "http://custom-keycloak:9090",
            "OPA_ENDPOINT": "http://custom-opa:9191",
            "VAULT_ADDR": "http://custom-vault:9200",
            "VAULT_TOKEN": "s.custom-token",
            "TRUST_DOMAIN": "prod.example.com",
            "SIGNING_SECRET": "prod-secret",
            "MAX_DELEGATION_DEPTH": "5",
        }
        saved = {}
        for k, v in env.items():
            saved[k] = os.environ.get(k)
            os.environ[k] = v
        try:
            config = ServiceConfig.from_env()
            self.assertEqual(config.keycloak_url, "http://custom-keycloak:9090")
            self.assertEqual(config.opa_endpoint, "http://custom-opa:9191")
            self.assertEqual(config.vault_addr, "http://custom-vault:9200")
            self.assertEqual(config.vault_token, "s.custom-token")
            self.assertEqual(config.trust_domain, "prod.example.com")
            self.assertEqual(config.signing_secret, "prod-secret")
            self.assertEqual(config.max_delegation_depth, 5)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


# ═══════════════════════════════════════════════════════════════════════════════
# 8. HTTP Handler Integration-Style Tests
# ═══════════════════════════════════════════════════════════════════════════════


class _FakeSocket:
    """Minimal socket-like object for constructing a BaseHTTPRequestHandler."""

    def __init__(self, request_bytes):
        self._input = io.BytesIO(request_bytes)
        self._output = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if "r" in mode:
            return self._input
        return self._output

    def sendall(self, data):
        self._output.write(data)

    def getpeername(self):
        return ("127.0.0.1", 12345)


def _make_handler(method, path, body=None, service=None):
    """
    Create a TokenExchangeHandler to process a single request.
    Returns (status_code, response_body_dict).
    """
    if service is None:
        service = _make_service()

    body_bytes = json.dumps(body).encode() if body else b""
    content_length = len(body_bytes)

    request_line = f"{method} {path} HTTP/1.1\r\n"
    headers = f"Host: localhost\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\n\r\n"
    raw = (request_line + headers).encode() + body_bytes

    # Monkey-patch the class-level service reference
    TokenExchangeHandler.service = service

    sock = _FakeSocket(raw)
    handler = TokenExchangeHandler(sock, ("127.0.0.1", 12345), None)

    # Parse the output
    output = sock._output.getvalue().decode("utf-8", errors="replace")

    # Split status line from body
    parts = output.split("\r\n\r\n", 1)
    status_line = parts[0].split("\r\n")[0] if parts else ""
    status_code = int(status_line.split(" ")[1]) if " " in status_line else 0
    response_body = parts[1] if len(parts) > 1 else ""

    try:
        response_json = json.loads(response_body)
    except (json.JSONDecodeError, ValueError):
        response_json = {"_raw": response_body}

    return status_code, response_json


class TestHTTPHandler(unittest.TestCase):
    """Integration-style tests exercising the HTTP handler."""

    def setUp(self):
        self.service = _make_service()

    # ── GET /health ─────────────────────────────────────────────────────

    def test_health_endpoint(self):
        status, body = _make_handler("GET", "/health", service=self.service)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "healthy")
        self.assertEqual(body["service"], "token-exchange")
        self.assertEqual(body["version"], "2.0.0")
        self.assertIn("rfc8693", body["features"])

    # ── POST /v1/token/exchange ─────────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_post_token_exchange_valid(self, mock_post, mock_get):
        params = _valid_exchange_params()
        status, body = _make_handler("POST", "/v1/token/exchange", body=params, service=self.service)

        self.assertEqual(status, 200)
        self.assertIn("access_token", body)
        self.assertEqual(body["token_type"], "Bearer")

    def test_post_token_exchange_invalid_grant_type(self):
        params = _valid_exchange_params()
        params["grant_type"] = "client_credentials"
        status, body = _make_handler("POST", "/v1/token/exchange", body=params, service=self.service)

        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "unsupported_grant_type")

    def test_post_token_exchange_empty_body(self):
        status, body = _make_handler("POST", "/v1/token/exchange", body={}, service=self.service)
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    # ── POST /v1/delegate ───────────────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_post_delegate_legacy_api(self, mock_post, mock_get):
        request_body = {
            "human_token": _human_jwt(),
            "agent_spiffe_id": f"spiffe://{TRUST_DOMAIN}/agent/query-agent",
            "agent_jwt_svid": _agent_jwt(),
            "requested_scope": "readonly",
        }
        status, body = _make_handler("POST", "/v1/delegate", body=request_body, service=self.service)

        self.assertEqual(status, 200)
        self.assertIn("session_id", body)
        self.assertIn("delegation_token", body)

    # ── POST /v1/token/revoke ───────────────────────────────────────────

    @patch("token_exchange.requests.put")
    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_post_token_revoke(self, mock_post, mock_get, mock_put):
        mock_put.return_value = MagicMock(status_code=204)

        # First, create a token
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        token = result["access_token"]

        # Now revoke via HTTP
        status, body = _make_handler(
            "POST", "/v1/token/revoke",
            body={"token": token},
            service=self.service,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "revoked")

    def test_post_token_revoke_missing_token(self):
        status, body = _make_handler(
            "POST", "/v1/token/revoke",
            body={},
            service=self.service,
        )
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    # ── GET /v1/delegation/chain ────────────────────────────────────────

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_get_delegation_chain(self, mock_post, mock_get):
        # Create a session first
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        session_id = result["session_id"]

        status, body = _make_handler(
            "GET", f"/v1/delegation/chain?session_id={session_id}",
            service=self.service,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["session_id"], session_id)
        self.assertEqual(body["chain_depth"], 1)
        self.assertFalse(body["revoked"])

    def test_get_delegation_chain_missing_session_id(self):
        status, body = _make_handler(
            "GET", "/v1/delegation/chain",
            service=self.service,
        )
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_get_delegation_chain_unknown_session(self):
        status, body = _make_handler(
            "GET", "/v1/delegation/chain?session_id=sess-doesnotexist",
            service=self.service,
        )
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    # ── 404 for unknown paths ───────────────────────────────────────────

    def test_get_unknown_path_returns_404(self):
        status, body = _make_handler("GET", "/unknown", service=self.service)
        self.assertEqual(status, 404)

    def test_post_unknown_path_returns_404(self):
        status, body = _make_handler("POST", "/unknown", body={}, service=self.service)
        self.assertEqual(status, 404)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Token Validation Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestTokenValidation(unittest.TestCase):
    """Tests for edge cases in token validation."""

    def setUp(self):
        self.service = _make_service()

    def test_invalid_actor_token_returns_error(self):
        """A completely invalid actor token string should fail."""
        result = self.service._validate_actor_token("not-a-jwt", TOKEN_TYPE_JWT)
        self.assertIn("error", result)

    def test_valid_non_spiffe_actor_token_accepted(self):
        """An actor token without spiffe:// prefix in sub is still accepted."""
        token = pyjwt.encode(
            {"sub": "service-account-123", "exp": int(time.time()) + 3600},
            "some-secret",
            algorithm="HS256",
        )
        result = self.service._validate_actor_token(token, TOKEN_TYPE_JWT)
        self.assertNotIn("error", result)
        self.assertEqual(result["sub"], "service-account-123")

    @patch("token_exchange.requests.get")
    def test_keycloak_fallback_to_unverified_decode(self, mock_get):
        """When Keycloak is down, token is parsed unverified (demo mode)."""
        import requests as real_requests
        mock_get.side_effect = real_requests.exceptions.ConnectionError("refused")

        human_token = _human_jwt(sub="bob@acme.com")
        result = self.service._validate_subject_token(human_token, TOKEN_TYPE_ACCESS)
        # Should parse the JWT unverified as fallback
        self.assertNotIn("error", result)
        self.assertEqual(result["sub"], "bob@acme.com")

    def test_delegation_token_recognized_as_subject(self):
        """A delegation token signed with our secret should be recognized."""
        claims = {
            "iss": self.service.issuer,
            "sub": "alice@acme.com",
            "scope": "readonly",
            "delegation_chain": [],
            "exp": int(time.time()) + 300,
        }
        token = pyjwt.encode(claims, SIGNING_SECRET, algorithm="HS256")
        result = self.service._validate_subject_token(token, TOKEN_TYPE_DELEGATION)
        self.assertNotIn("error", result)
        self.assertEqual(result["iss"], self.service.issuer)


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Error Response Format Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorResponseFormat(unittest.TestCase):
    """Tests for _error_response helper."""

    def setUp(self):
        self.service = _make_service()

    def test_error_response_structure(self):
        result = self.service._error_response("invalid_request", "Something went wrong")
        self.assertEqual(result["error"], "invalid_request")
        self.assertEqual(result["error_description"], "Something went wrong")
        self.assertEqual(len(result), 2)


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Security Boundary Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSecurityBoundaries(unittest.TestCase):
    """Tests for security boundary behaviors: Keycloak fallback, OPA fail-open, Vault failures."""

    def setUp(self):
        self.service = _make_service()

    # ── Keycloak fallback bypass (6 tests) ─────────────────────────────────

    @patch("token_exchange.requests.get")
    def test_keycloak_401_falls_back_to_unverified_decode(self, mock_get):
        """When Keycloak returns 401, the service falls back to unverified JWT decode."""
        resp = MagicMock()
        resp.status_code = 401
        mock_get.return_value = resp

        human_token = _human_jwt(sub="alice@acme.com")
        result = self.service._validate_keycloak_token(human_token)

        self.assertNotIn("error", result)
        self.assertEqual(result["sub"], "alice@acme.com")

    @patch("token_exchange.requests.get")
    def test_keycloak_timeout_rejects_forged_token(self, mock_get):
        """When Keycloak times out and the token is not a valid JWT, an error is returned."""
        import requests as real_requests
        mock_get.side_effect = real_requests.exceptions.Timeout("timed out")

        result = self.service._validate_keycloak_token("not-a-jwt-token")

        self.assertIn("error", result)

    @patch("token_exchange.requests.get")
    def test_keycloak_down_rejects_corrupted_base64(self, mock_get):
        """When Keycloak is down and the token looks like a JWT but has bad base64, an error is returned."""
        import requests as real_requests
        mock_get.side_effect = real_requests.exceptions.ConnectionError("refused")

        result = self.service._validate_keycloak_token("aaa.bbb.ccc")

        self.assertIn("error", result)

    @patch("token_exchange.requests.get")
    def test_keycloak_down_rejects_empty_token(self, mock_get):
        """When Keycloak is down and token is empty, fallback decode also fails."""
        import requests as real_requests
        mock_get.side_effect = real_requests.exceptions.ConnectionError("refused")

        result = self.service._validate_keycloak_token("")

        self.assertIn("error", result)

    @patch("token_exchange.requests.get")
    def test_keycloak_500_with_valid_jwt_extracts_claims(self, mock_get):
        """When Keycloak returns 500, a valid JWT is still decoded via fallback."""
        resp = MagicMock()
        resp.status_code = 500
        mock_get.return_value = resp

        human_token = _human_jwt(sub="bob@acme.com", groups=["engineering"])
        result = self.service._validate_keycloak_token(human_token)

        self.assertNotIn("error", result)
        self.assertEqual(result["sub"], "bob@acme.com")
        self.assertIn("engineering", result["groups"])

    @patch("token_exchange.requests.get")
    def test_keycloak_unavailable_accepts_expired_jwt_in_fallback(self, mock_get):
        """When Keycloak is unavailable, expired JWTs pass through unverified fallback (known gap).

        Documents that pyjwt.decode with verify_signature=False also skips exp
        verification, so expired tokens are accepted in fallback/demo mode.
        """
        import requests as real_requests
        mock_get.side_effect = real_requests.exceptions.ConnectionError("refused")

        # Create a JWT that expired 1 hour ago
        expired_token = _human_jwt(exp_offset=-3600)
        result = self.service._validate_keycloak_token(expired_token)

        # Known gap: pyjwt with verify_signature=False skips exp check too,
        # so expired tokens are silently accepted in fallback mode.
        self.assertNotIn("error", result)
        self.assertEqual(result["sub"], "alice@acme.com")

    # ── OPA fail-open (4 tests) ────────────────────────────────────────────

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post")
    def test_opa_connection_error_fails_open(self, mock_post, mock_get):
        """When OPA is unreachable (ConnectionError), the exchange fails open and succeeds."""
        import requests as real_requests
        mock_get.side_effect = _mock_get_keycloak_and_vault()
        mock_post.side_effect = real_requests.exceptions.ConnectionError("refused")

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertIn("access_token", result)

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post")
    def test_opa_timeout_fails_open(self, mock_post, mock_get):
        """When OPA times out, the exchange fails open and succeeds."""
        import requests as real_requests
        mock_get.side_effect = _mock_get_keycloak_and_vault()
        mock_post.side_effect = real_requests.exceptions.Timeout("timed out")

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertIn("access_token", result)

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post")
    def test_opa_500_fails_open(self, mock_post, mock_get):
        """When OPA returns HTTP 500, the non-200 path falls through to fail-open."""
        mock_get.side_effect = _mock_get_keycloak_and_vault()
        opa_resp = MagicMock()
        opa_resp.status_code = 500
        mock_post.return_value = opa_resp

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertIn("access_token", result)

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_deny("unauthorized_delegation"))
    def test_opa_deny_blocks_exchange(self, mock_post, mock_get):
        """When OPA explicitly denies, the exchange returns access_denied."""
        mock_get.return_value = _mock_keycloak_success()

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "access_denied")
        self.assertIn("unauthorized_delegation", result["error_description"])

    # ── Vault credential failures (4 tests) ────────────────────────────────

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_vault_returns_403_no_credentials(self, mock_post, mock_get):
        """When Vault returns 403, exchange succeeds but without db_credential."""
        def _get_side_effect(url, **kwargs):
            resp = MagicMock()
            if "userinfo" in url:
                resp.status_code = 200
                resp.json.return_value = {
                    "sub": "alice-uuid",
                    "email": "alice@acme.com",
                    "groups": ["data-analysts"],
                }
            elif "database/creds" in url:
                resp.status_code = 403
                resp.text = "permission denied"
            else:
                resp.status_code = 200
                resp.json.return_value = {}
            return resp

        mock_get.side_effect = _get_side_effect

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertIn("access_token", result)
        self.assertNotIn("db_credential", result)

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_vault_connection_error_no_credentials(self, mock_post, mock_get):
        """When Vault raises ConnectionError for creds, exchange succeeds without db_credential."""
        import requests as real_requests

        def _get_side_effect(url, **kwargs):
            if "userinfo" in url:
                resp = MagicMock()
                resp.status_code = 200
                resp.json.return_value = {
                    "sub": "alice-uuid",
                    "email": "alice@acme.com",
                    "groups": ["data-analysts"],
                }
                return resp
            elif "database/creds" in url:
                raise real_requests.exceptions.ConnectionError("vault down")
            else:
                resp = MagicMock()
                resp.status_code = 200
                resp.json.return_value = {}
                return resp

        mock_get.side_effect = _get_side_effect

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertIn("access_token", result)
        self.assertNotIn("db_credential", result)

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_vault_missing_data_fields_raises(self, mock_post, mock_get):
        """When Vault returns 200 with empty data dict, KeyError is raised (documents bug)."""
        def _get_side_effect(url, **kwargs):
            resp = MagicMock()
            if "userinfo" in url:
                resp.status_code = 200
                resp.json.return_value = {
                    "sub": "alice-uuid",
                    "email": "alice@acme.com",
                    "groups": ["data-analysts"],
                }
            elif "database/creds" in url:
                resp.status_code = 200
                resp.json.return_value = {"data": {}}
            else:
                resp.status_code = 200
                resp.json.return_value = {}
            return resp

        mock_get.side_effect = _get_side_effect

        params = _valid_exchange_params()
        with self.assertRaises(KeyError):
            self.service.exchange_token(params)

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_vault_no_lease_id(self, mock_post, mock_get):
        """When Vault returns creds without a lease_id, exchange succeeds with empty lease_id."""
        def _get_side_effect(url, **kwargs):
            resp = MagicMock()
            if "userinfo" in url:
                resp.status_code = 200
                resp.json.return_value = {
                    "sub": "alice-uuid",
                    "email": "alice@acme.com",
                    "groups": ["data-analysts"],
                }
            elif "database/creds" in url:
                resp.status_code = 200
                resp.json.return_value = {
                    "data": {
                        "username": "v-test-user",
                        "password": "v-test-pass",
                    },
                    # No lease_id key at all
                    "lease_duration": 300,
                }
            else:
                resp.status_code = 200
                resp.json.return_value = {}
            return resp

        mock_get.side_effect = _get_side_effect

        params = _valid_exchange_params()
        result = self.service.exchange_token(params)

        self.assertNotIn("error", result)
        self.assertIn("db_credential", result)
        self.assertEqual(result["db_credential"]["lease_id"], "")
        self.assertEqual(result["db_credential"]["username"], "v-test-user")

    # ── Revocation edge cases (2 tests) ────────────────────────────────────

    @patch("token_exchange.requests.put")
    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_vault_revocation_failure_still_marks_revoked(self, mock_post, mock_get, mock_put):
        """When Vault lease revocation raises an exception, the session is still marked revoked."""
        mock_put.side_effect = Exception("vault connection lost")

        # Create a valid session with vault credentials
        params = _valid_exchange_params()
        result = self.service.exchange_token(params)
        self.assertNotIn("error", result)
        token = result["access_token"]
        session_id = result["session_id"]

        # Revoke should succeed despite Vault failure
        revoke_result = self.service.revoke_token(token)

        self.assertEqual(revoke_result["status"], "revoked")
        self.assertEqual(revoke_result["session_id"], session_id)
        session = self.service.sessions[session_id]
        self.assertTrue(session.revoked)

    def test_revoke_nonexistent_token(self):
        """Revoking a token that was never issued returns not_found."""
        result = self.service.revoke_token("completely-random-nonexistent-token")
        self.assertEqual(result["status"], "not_found")

    # ── Expired delegation chain extension (2 tests) ───────────────────────

    @patch("token_exchange.requests.get")
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_expired_delegation_token_accepted_in_chain(self, mock_post, mock_get):
        """An expired delegation token is accepted via unverified fallback (known gap).

        The expired delegation token fails pyjwt.decode with verify_exp (signed path),
        then falls through to _validate_keycloak_token. Keycloak is down, so the
        unverified fallback is used. Since pyjwt with verify_signature=False skips
        exp verification, the expired token is silently accepted and the chain is extended.
        """
        import requests as real_requests

        # Keycloak is unreachable so the fallback path is exercised
        mock_get.side_effect = real_requests.exceptions.ConnectionError("refused")

        # Create an expired delegation token signed with the service's signing secret
        now = int(time.time())
        expired_claims = {
            "iss": self.service.issuer,
            "sub": "alice@acme.com",
            "scope": "readonly",
            "delegation_chain": [
                {
                    "subject": "alice@acme.com",
                    "actor": f"spiffe://{TRUST_DOMAIN}/agent/query-agent",
                    "actor_type": "agent",
                    "scope": "readonly",
                    "depth": 0,
                }
            ],
            "exp": now - 3600,  # Expired 1 hour ago
            "iat": now - 7200,
            "groups": ["data-analysts"],
        }
        expired_token = pyjwt.encode(expired_claims, SIGNING_SECRET, algorithm="HS256")

        sub_agent_jwt = _agent_jwt(sub=f"spiffe://{TRUST_DOMAIN}/subagent/sql-executor")
        params = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": expired_token,
            "subject_token_type": TOKEN_TYPE_DELEGATION,
            "actor_token": sub_agent_jwt,
            "actor_token_type": TOKEN_TYPE_JWT,
            "scope": "readonly",
            "audience": "database",
        }
        result = self.service.exchange_token(params)

        # Known gap: expired delegation token passes through unverified fallback.
        # The chain is extended as if the token were valid.
        self.assertNotIn("error", result)
        self.assertIn("access_token", result)
        # The chain should include both the original link and the new sub-agent link
        self.assertEqual(len(result["delegation_chain"]), 2)

    @patch("token_exchange.requests.get", side_effect=_mock_vault_creds())
    @patch("token_exchange.requests.post", side_effect=_mock_opa_allow())
    def test_max_depth_enforced_on_chain_extension(self, mock_post, mock_get):
        """A delegation token at max chain depth cannot be extended further."""
        service = _make_service(max_delegation_depth=2)

        # Step 1: human -> agent (depth 0, chain length 1)
        params1 = _valid_exchange_params()
        result1 = service.exchange_token(params1)
        self.assertNotIn("error", result1)

        # Step 2: agent -> sub-agent (depth 1, chain length 2)
        delegation_token_1 = result1["access_token"]
        sub_agent_jwt = _agent_jwt(sub=f"spiffe://{TRUST_DOMAIN}/subagent/sql-executor")
        params2 = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": delegation_token_1,
            "subject_token_type": TOKEN_TYPE_DELEGATION,
            "actor_token": sub_agent_jwt,
            "actor_token_type": TOKEN_TYPE_JWT,
            "scope": "readonly",
            "audience": "database",
        }
        result2 = service.exchange_token(params2)
        self.assertNotIn("error", result2)

        # Step 3: sub-agent -> sub-sub-agent (depth 2, chain length would be 3, exceeds max of 2)
        delegation_token_2 = result2["access_token"]
        sub_sub_agent_jwt = _agent_jwt(sub=f"spiffe://{TRUST_DOMAIN}/subagent/formatter")
        params3 = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": delegation_token_2,
            "subject_token_type": TOKEN_TYPE_DELEGATION,
            "actor_token": sub_sub_agent_jwt,
            "actor_token_type": TOKEN_TYPE_JWT,
            "scope": "readonly",
            "audience": "database",
        }
        result3 = service.exchange_token(params3)

        self.assertIn("error", result3)
        self.assertEqual(result3["error"], "invalid_request")
        self.assertIn("depth", result3["error_description"].lower())


if __name__ == "__main__":
    unittest.main()
