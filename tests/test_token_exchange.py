"""
Unit tests for the slim Token Exchange Service (stateless fused JWT minter).

Tests cover:
- Fused JWT minting with correct claims (sub, act, groups, scope, may_act)
- Nested act{} claim building for delegation chains
- Scope validation and group-based resolution
- Human token JWKS validation (offline, not userinfo)
- Agent SPIFFE JWT-SVID JWKS validation
- Delegation depth enforcement
- JWKS endpoint serving
- Health endpoint
- HTTP handler integration
"""

import base64
import json
import os
import sys
import time
import unittest
from unittest.mock import patch, MagicMock

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "token-exchange"))

from token_exchange import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    GROUP_PERMISSIONS,
    TOKEN_TYPE_AGENT_DELEGATION,
    TokenExchangeHandler,
    TokenExchangeService,
)

# ---------------------------------------------------------------------------
# Test keypairs — one for SPIRE, one for Keycloak
# ---------------------------------------------------------------------------

_SPIRE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KEYCLOAK_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks_from_key(private_key, kid="test-kid"):
    pub = private_key.public_key().public_numbers()
    def _b64(n):
        b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                      "n": _b64(pub.n), "e": _b64(pub.e)}]}


SPIRE_JWKS = _jwks_from_key(_SPIRE_KEY, "spire-kid")
KEYCLOAK_JWKS = _jwks_from_key(_KEYCLOAK_KEY, "kc-kid")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service(**overrides) -> TokenExchangeService:
    defaults = dict(
        keycloak_jwks_url="http://keycloak:8080/realms/demo/protocol/openid-connect/certs",
        spire_oidc_url="http://spire-oidc:8082",
        issuer="token-exchange.demo.local",
        max_delegation_depth=3,
        default_ttl=300,
        listen_port=8090,
    )
    defaults.update(overrides)
    svc = TokenExchangeService(**defaults)
    # Pre-fill JWKS caches so tests don't make real HTTP calls
    svc._jwks_cache["http://keycloak:8080/realms/demo/protocol/openid-connect/certs"] = (KEYCLOAK_JWKS, time.time())
    svc._jwks_cache["http://spire-oidc:8082/keys"] = (SPIRE_JWKS, time.time())
    return svc


def _human_jwt(sub="alice@acme.com", groups=None, may_act=None, exp_offset=3600):
    now = int(time.time())
    claims = {
        "sub": sub,
        "email": sub,
        "groups": ["data-analysts"] if groups is None else groups,
        "may_act": may_act if may_act is not None else {},
        "exp": now + exp_offset,
        "iat": now,
        "iss": "http://keycloak:8080/realms/demo",
    }
    return pyjwt.encode(claims, _KEYCLOAK_KEY, algorithm="RS256", headers={"kid": "kc-kid"})


def _agent_jwt(sub=None, extra_claims=None):
    sub = sub or "spiffe://demo.local/agent/query-agent"
    now = int(time.time())
    claims = {"sub": sub, "aud": ["token-exchange"], "exp": now + 3600, "iat": now}
    if extra_claims:
        claims.update(extra_claims)
    return pyjwt.encode(claims, _SPIRE_KEY, algorithm="RS256", headers={"kid": "spire-kid"})


def _exchange_params(subject_token=None, actor_token=None, scope="readonly"):
    return {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "subject_token": subject_token or _human_jwt(),
        "actor_token": actor_token or _agent_jwt(),
        "scope": scope,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Fused JWT Minting
# ═══════════════════════════════════════════════════════════════════════════════


class TestFusedJwtMinting(unittest.TestCase):

    def setUp(self):
        self.svc = _make_service()

    def test_valid_exchange_returns_jwt(self):
        result = self.svc.exchange_token(_exchange_params())
        self.assertNotIn("error", result)
        self.assertIn("access_token", result)
        self.assertEqual(result["issued_token_type"], TOKEN_TYPE_AGENT_DELEGATION)
        self.assertEqual(result["token_type"], "Bearer")
        self.assertEqual(result["scope"], "readonly")
        self.assertEqual(result["expires_in"], 300)

    def test_fused_jwt_has_required_claims(self):
        result = self.svc.exchange_token(_exchange_params())
        token = result["access_token"]
        decoded = pyjwt.decode(token, self.svc._public_key, algorithms=["RS256"], options={"verify_aud": False})

        self.assertEqual(decoded["iss"], "token-exchange.demo.local")
        self.assertEqual(decoded["sub"], "alice@acme.com")
        self.assertEqual(decoded["aud"], "vault")
        self.assertEqual(decoded["scope"], "readonly")
        self.assertIn("data-analysts", decoded["groups"])
        self.assertIn("act", decoded)
        self.assertIn("may_act", decoded)
        self.assertIn("exp", decoded)
        self.assertIn("iat", decoded)
        self.assertIn("jti", decoded)
        self.assertEqual(decoded["delegation_depth"], 1)

    def test_act_claim_structure(self):
        result = self.svc.exchange_token(_exchange_params())
        decoded = pyjwt.decode(result["access_token"], self.svc._public_key, algorithms=["RS256"], options={"verify_aud": False})
        act = decoded["act"]
        self.assertEqual(act["sub"], "spiffe://demo.local/agent/query-agent")
        self.assertEqual(act["act"]["sub"], "alice@acme.com")
        self.assertNotIn("act", act["act"])

    def test_no_vault_or_opa_dependencies(self):
        """The service must have zero Vault/OPA env vars or network calls."""
        svc = TokenExchangeService()
        # No vault_token, vault_addr, opa_endpoint attributes
        self.assertFalse(hasattr(svc, "vault_token"))
        self.assertFalse(hasattr(svc, "opa_endpoint"))


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Nested Act Claims (Sub-agent Chains)
# ═══════════════════════════════════════════════════════════════════════════════


class TestNestedActClaims(unittest.TestCase):

    def setUp(self):
        self.svc = _make_service()

    def test_chain_extension_nests_act(self):
        """human -> agent -> sub-agent produces doubly-nested act{}."""
        # First exchange: human -> agent
        r1 = self.svc.exchange_token(_exchange_params())
        self.assertNotIn("error", r1, r1)
        delegation_token = r1["access_token"]

        # Second exchange: delegation_token as subject, sub-agent as actor
        sub_agent = _agent_jwt(sub="spiffe://demo.local/subagent/sql-executor")
        r2 = self.svc.exchange_token(_exchange_params(
            subject_token=delegation_token, actor_token=sub_agent,
        ))
        self.assertNotIn("error", r2, r2)

        decoded = pyjwt.decode(r2["access_token"], self.svc._public_key, algorithms=["RS256"], options={"verify_aud": False})
        act = decoded["act"]
        # Outermost: sub-agent
        self.assertEqual(act["sub"], "spiffe://demo.local/subagent/sql-executor")
        # Middle: agent
        self.assertEqual(act["act"]["sub"], "spiffe://demo.local/agent/query-agent")
        # Innermost: human
        self.assertEqual(act["act"]["act"]["sub"], "alice@acme.com")
        self.assertEqual(decoded["delegation_depth"], 2)

    def test_max_depth_exceeded(self):
        svc = _make_service(max_delegation_depth=1)
        r1 = svc.exchange_token(_exchange_params())
        self.assertNotIn("error", r1, r1)

        sub_agent = _agent_jwt(sub="spiffe://demo.local/subagent/sql-executor")
        r2 = svc.exchange_token(_exchange_params(
            subject_token=r1["access_token"], actor_token=sub_agent,
        ))
        self.assertIn("error", r2)
        self.assertIn("depth", r2["error_description"].lower())


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Scope Validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestScopeValidation(unittest.TestCase):

    def setUp(self):
        self.svc = _make_service()

    def test_data_analysts_readonly_allowed(self):
        result = self.svc.exchange_token(_exchange_params(scope="readonly"))
        self.assertNotIn("error", result)

    def test_data_analysts_readwrite_denied(self):
        result = self.svc.exchange_token(_exchange_params(scope="readwrite"))
        self.assertIn("error", result)
        self.assertEqual(result["error"], "invalid_scope")

    def test_engineering_readwrite_allowed(self):
        eng_token = _human_jwt(sub="bob@acme.com", groups=["engineering"])
        result = self.svc.exchange_token(_exchange_params(subject_token=eng_token, scope="readwrite"))
        self.assertNotIn("error", result)
        self.assertEqual(result["scope"], "readwrite")

    def test_no_groups_denied(self):
        token = _human_jwt(groups=[])
        result = self.svc.exchange_token(_exchange_params(subject_token=token))
        self.assertIn("error", result)
        self.assertEqual(result["error"], "invalid_scope")

    def test_unknown_group_denied(self):
        token = _human_jwt(groups=["unknown-group"])
        result = self.svc.exchange_token(_exchange_params(subject_token=token))
        self.assertIn("error", result)

    def test_scope_narrowing_in_chain(self):
        """Chain extension can only keep the same scope, not widen."""
        r1 = self.svc.exchange_token(_exchange_params(scope="readonly"))
        self.assertNotIn("error", r1, r1)

        sub_agent = _agent_jwt(sub="spiffe://demo.local/subagent/sql-executor")
        r2 = self.svc.exchange_token(_exchange_params(
            subject_token=r1["access_token"], actor_token=sub_agent, scope="readwrite",
        ))
        self.assertIn("error", r2)
        self.assertEqual(r2["error"], "invalid_scope")

    def test_group_permissions_mapping(self):
        self.assertIn("readonly", GROUP_PERMISSIONS["data-analysts"])
        self.assertIn("readwrite", GROUP_PERMISSIONS["engineering"])
        self.assertNotIn("readwrite", GROUP_PERMISSIONS["trading-team"])


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Human Token Validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestHumanTokenValidation(unittest.TestCase):

    def setUp(self):
        self.svc = _make_service()

    def test_valid_keycloak_token_accepted(self):
        result = self.svc.exchange_token(_exchange_params())
        self.assertNotIn("error", result)

    def test_keycloak_jwks_unavailable_fails_closed(self):
        svc = _make_service()
        svc._jwks_cache.clear()  # Force cache miss
        with patch("token_exchange.requests.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=500)
            result = svc.exchange_token(_exchange_params())
        self.assertIn("error", result)
        self.assertEqual(result["error"], "temporarily_unavailable")

    def test_invalid_signature_rejected(self):
        """Token signed with wrong key is rejected."""
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bad_token = pyjwt.encode(
            {"sub": "alice@acme.com", "groups": ["data-analysts"], "exp": int(time.time()) + 3600,
             "iat": int(time.time()), "iss": "http://keycloak:8080/realms/demo"},
            wrong_key, algorithm="RS256", headers={"kid": "kc-kid"},
        )
        result = self.svc.exchange_token(_exchange_params(subject_token=bad_token))
        self.assertIn("error", result)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Agent SPIFFE SVID Validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentTokenValidation(unittest.TestCase):

    def setUp(self):
        self.svc = _make_service()

    def test_valid_spiffe_svid_accepted(self):
        result = self.svc.exchange_token(_exchange_params())
        self.assertNotIn("error", result)

    def test_non_spiffe_subject_rejected(self):
        bad_agent = pyjwt.encode(
            {"sub": "not-a-spiffe-id", "aud": ["token-exchange"],
             "exp": int(time.time()) + 3600, "iat": int(time.time())},
            _SPIRE_KEY, algorithm="RS256", headers={"kid": "spire-kid"},
        )
        result = self.svc.exchange_token(_exchange_params(actor_token=bad_agent))
        self.assertIn("error", result)
        self.assertIn("SPIFFE", result["error_description"])

    def test_spire_jwks_unavailable_fails_closed(self):
        svc = _make_service()
        svc._jwks_cache.pop("http://spire-oidc:8082/keys", None)
        with patch("token_exchange.requests.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=503)
            result = svc.exchange_token(_exchange_params())
        self.assertIn("error", result)
        self.assertEqual(result["error"], "temporarily_unavailable")

    def test_wrong_signature_rejected(self):
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bad_svid = pyjwt.encode(
            {"sub": "spiffe://demo.local/agent/rogue", "aud": ["token-exchange"],
             "exp": int(time.time()) + 3600, "iat": int(time.time())},
            wrong_key, algorithm="RS256", headers={"kid": "spire-kid"},
        )
        result = self.svc.exchange_token(_exchange_params(actor_token=bad_svid))
        self.assertIn("error", result)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Request Validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestRequestValidation(unittest.TestCase):

    def setUp(self):
        self.svc = _make_service()

    def test_missing_grant_type(self):
        params = _exchange_params()
        del params["grant_type"]
        result = self.svc.exchange_token(params)
        self.assertEqual(result["error"], "unsupported_grant_type")

    def test_wrong_grant_type(self):
        params = _exchange_params()
        params["grant_type"] = "authorization_code"
        result = self.svc.exchange_token(params)
        self.assertEqual(result["error"], "unsupported_grant_type")

    def test_missing_subject_token(self):
        params = _exchange_params()
        del params["subject_token"]
        result = self.svc.exchange_token(params)
        self.assertIn("subject_token", result["error_description"])

    def test_missing_actor_token(self):
        params = _exchange_params()
        del params["actor_token"]
        result = self.svc.exchange_token(params)
        self.assertIn("actor_token", result["error_description"])


# ═══════════════════════════════════════════════════════════════════════════════
# 7. JWKS Endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestJwksEndpoint(unittest.TestCase):

    def test_jwks_returns_rsa_key(self):
        svc = _make_service()
        jwks = svc.jwks()
        self.assertIn("keys", jwks)
        self.assertEqual(len(jwks["keys"]), 1)
        key = jwks["keys"][0]
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["alg"], "RS256")
        self.assertEqual(key["use"], "sig")
        self.assertEqual(key["kid"], svc._kid)
        self.assertIn("n", key)
        self.assertIn("e", key)

    def test_jwks_key_can_verify_fused_jwt(self):
        svc = _make_service()
        result = svc.exchange_token(_exchange_params())
        token = result["access_token"]

        # Build a verifier from the JWKS
        from jwt import PyJWKSet
        jwk_set = PyJWKSet.from_dict(svc.jwks())
        key = jwk_set.keys[0].key
        decoded = pyjwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
        self.assertEqual(decoded["sub"], "alice@acme.com")


# ═══════════════════════════════════════════════════════════════════════════════
# 8. HTTP Handler
# ═══════════════════════════════════════════════════════════════════════════════


class TestHttpHandler(unittest.TestCase):

    def setUp(self):
        self.svc = _make_service()
        TokenExchangeHandler.service = self.svc

    def _make_request(self, method, path, body=None):
        import io
        handler = MagicMock(spec=TokenExchangeHandler)
        handler.service = self.svc
        handler.headers = {"Content-Length": str(len(body)) if body else "0"}
        handler.rfile = io.BytesIO(body if body else b"")
        handler.wfile = io.BytesIO()
        handler.path = path
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        # Bind _json as the real method
        import types
        handler._json = types.MethodType(TokenExchangeHandler._json, handler)

        if method == "GET":
            TokenExchangeHandler.do_GET(handler)
        elif method == "POST":
            TokenExchangeHandler.do_POST(handler)
        return handler

    def test_health_endpoint(self):
        handler = self._make_request("GET", "/health")
        handler.send_response.assert_called_with(200)
        output = handler.wfile.getvalue()
        data = json.loads(output)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["version"], "4.0.0")

    def test_jwks_endpoint(self):
        handler = self._make_request("GET", "/.well-known/jwks.json")
        handler.send_response.assert_called_with(200)
        data = json.loads(handler.wfile.getvalue())
        self.assertIn("keys", data)

    def test_exchange_endpoint(self):
        body = json.dumps(_exchange_params()).encode()
        handler = self._make_request("POST", "/v1/token/exchange", body)
        handler.send_response.assert_called_with(200)
        data = json.loads(handler.wfile.getvalue())
        self.assertIn("access_token", data)

    def test_unknown_get_returns_404(self):
        handler = self._make_request("GET", "/v1/audit")
        handler.send_response.assert_called_with(404)

    def test_unknown_post_returns_404(self):
        handler = self._make_request("POST", "/v1/delegate", b"{}")
        handler.send_response.assert_called_with(404)

    def test_removed_endpoints_return_404(self):
        """Endpoints removed in the slim version should 404."""
        for path in ["/v1/token/revoke", "/v1/token/credentials", "/v1/delegation/chain"]:
            handler = self._make_request("POST" if "revoke" in path or "credentials" in path else "GET", path, b"{}")
            handler.send_response.assert_called_with(404), f"{path} should return 404"


if __name__ == "__main__":
    unittest.main()
