"""
Unit tests for the AI Agent application.

Tests cover:
- AgentConfig defaults and environment loading
- DelegationSession lifecycle and expiry
- SPIFFEIdentity demo SVID generation
- HumanAuthenticator auth modes (device, token, password)
- TokenExchangeClient delegation requests (JWT-only, no DB creds)
- TokenExchangeClient local JWT decoding and chain extraction
- VaultClient SPIFFE auth, JWT auth, DB credential requests
- DatabaseQuerier session validation
- Natural language to SQL mapping
"""

import json
import os
import time
import uuid
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import jwt as pyjwt

# Import the module under test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agent import (
    AgentConfig,
    DelegationSession,
    SPIFFEIdentity,
    HumanAuthenticator,
    TokenExchangeClient,
    VaultClient,
    DatabaseQuerier,
    map_natural_language_to_sql,
    QUERY_MAPPINGS,
    DEFAULT_QUERY,
)


class TestAgentConfig(unittest.TestCase):
    """Tests for AgentConfig dataclass."""

    def test_default_values(self):
        config = AgentConfig()
        self.assertEqual(config.spire_socket_path, "/tmp/spire-agent/public/api.sock")
        self.assertEqual(config.gateway_url, "http://token-exchange:8090")
        self.assertEqual(config.vault_addr, "http://vault:8200")
        self.assertEqual(config.keycloak_url, "http://keycloak:8080")
        self.assertEqual(config.keycloak_realm, "demo")
        self.assertEqual(config.trust_domain, "demo.local")
        self.assertEqual(config.agent_spiffe_id, "spiffe://demo.local/agent/query-agent")
        self.assertEqual(config.db_host, "postgresql")
        self.assertEqual(config.db_port, 5432)
        self.assertEqual(config.db_name, "appdb")

    def test_from_env_defaults(self):
        """from_env should return defaults when no env vars are set."""
        env_vars = [
            "SPIRE_AGENT_SOCKET", "GATEWAY_URL", "TOKEN_EXCHANGE_URL",
            "VAULT_ADDR", "KEYCLOAK_URL", "KEYCLOAK_REALM", "TRUST_DOMAIN",
            "AGENT_SPIFFE_ID", "DB_HOST", "DB_PORT", "DB_NAME",
        ]
        saved = {k: os.environ.pop(k, None) for k in env_vars}
        try:
            config = AgentConfig.from_env()
            self.assertEqual(config.gateway_url, "http://token-exchange:8090")
            self.assertEqual(config.vault_addr, "http://vault:8200")
            self.assertEqual(config.db_port, 5432)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_from_env_custom(self):
        """from_env should read from environment variables."""
        os.environ["GATEWAY_URL"] = "http://custom-gateway:9090"
        os.environ["VAULT_ADDR"] = "http://vault-prod:8200"
        os.environ["DB_PORT"] = "5433"
        os.environ["TRUST_DOMAIN"] = "prod.example.com"
        try:
            config = AgentConfig.from_env()
            self.assertEqual(config.gateway_url, "http://custom-gateway:9090")
            self.assertEqual(config.vault_addr, "http://vault-prod:8200")
            self.assertEqual(config.db_port, 5433)
            self.assertEqual(config.trust_domain, "prod.example.com")
        finally:
            os.environ.pop("GATEWAY_URL", None)
            os.environ.pop("VAULT_ADDR", None)
            os.environ.pop("DB_PORT", None)
            os.environ.pop("TRUST_DOMAIN", None)


class TestDelegationSession(unittest.TestCase):
    """Tests for DelegationSession dataclass and properties."""

    def _make_session(self, ttl=300, created_at=None):
        return DelegationSession(
            session_id="sess-test-123",
            human_subject="alice@acme.com",
            scope="readonly",
            db_username="v-spiffe-readonly-xyz",
            db_password="dynamic-password",
            db_host="postgresql",
            db_port=5432,
            db_name="appdb",
            lease_id="database/creds/ai-agent-readonly/abc123",
            ttl_seconds=ttl,
            created_at=created_at or datetime.now(timezone.utc),
        )

    def test_creation(self):
        session = self._make_session()
        self.assertEqual(session.session_id, "sess-test-123")
        self.assertEqual(session.human_subject, "alice@acme.com")
        self.assertEqual(session.scope, "readonly")
        self.assertEqual(session.db_username, "v-spiffe-readonly-xyz")

    def test_expires_at(self):
        created = datetime(2026, 2, 20, 10, 0, 0, tzinfo=timezone.utc)
        session = self._make_session(ttl=300, created_at=created)
        expected = datetime(2026, 2, 20, 10, 5, 0, tzinfo=timezone.utc)
        self.assertEqual(session.expires_at, expected)

    def test_is_expired_false(self):
        """Freshly created session should not be expired."""
        session = self._make_session(ttl=300)
        self.assertFalse(session.is_expired)

    def test_is_expired_true(self):
        """Session created in the past with short TTL should be expired."""
        past = datetime.now(timezone.utc) - timedelta(seconds=600)
        session = self._make_session(ttl=300, created_at=past)
        self.assertTrue(session.is_expired)

    def test_remaining_seconds_positive(self):
        session = self._make_session(ttl=300)
        remaining = session.remaining_seconds
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 300)

    def test_remaining_seconds_zero_when_expired(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=600)
        session = self._make_session(ttl=300, created_at=past)
        self.assertEqual(session.remaining_seconds, 0)

    def test_zero_ttl_immediately_expired(self):
        """A session with 0 TTL should be expired immediately."""
        session = self._make_session(ttl=0)
        self.assertTrue(session.is_expired)
        self.assertEqual(session.remaining_seconds, 0)


class TestSPIFFEIdentity(unittest.TestCase):
    """Tests for SPIFFEIdentity class."""

    def test_spiffe_id_property(self):
        config = AgentConfig(agent_spiffe_id="spiffe://demo.local/agent/test")
        identity = SPIFFEIdentity(config)
        self.assertEqual(identity.spiffe_id, "spiffe://demo.local/agent/test")

    def test_fetch_jwt_svid_raises_without_spire(self):
        """Without SPIRE, should raise RuntimeError (no silent fallback)."""
        config = AgentConfig(spire_socket_path="/nonexistent/socket")
        identity = SPIFFEIdentity(config)

        with self.assertRaises(RuntimeError) as ctx:
            identity.fetch_jwt_svid(audience="token-exchange")

        self.assertIn("SPIRE Workload API unavailable", str(ctx.exception))

    def test_svid_none_before_fetch(self):
        config = AgentConfig()
        identity = SPIFFEIdentity(config)
        self.assertIsNone(identity._jwt_svid)


class TestHumanAuthenticator(unittest.TestCase):
    """Tests for HumanAuthenticator class with multiple auth modes."""

    def test_token_endpoint_construction(self):
        config = AgentConfig(
            keycloak_url="https://auth.example.com",
            keycloak_realm="production",
        )
        auth = HumanAuthenticator(config)
        self.assertEqual(
            auth.token_endpoint,
            "https://auth.example.com/realms/production/protocol/openid-connect/token",
        )

    def test_device_auth_endpoint_construction(self):
        config = AgentConfig(
            keycloak_url="https://auth.example.com",
            keycloak_realm="production",
        )
        auth = HumanAuthenticator(config)
        self.assertEqual(
            auth.device_auth_endpoint,
            "https://auth.example.com/realms/production/protocol/openid-connect/auth/device",
        )

    def test_invalid_auth_mode_raises(self):
        config = AgentConfig()
        auth = HumanAuthenticator(config)
        with self.assertRaises(ValueError) as ctx:
            auth.authenticate(auth_mode="invalid")
        self.assertIn("invalid", str(ctx.exception))

    # ── Password grant tests ──────────────────────────────────────────

    @patch("agent.requests.post")
    def test_password_grant_success(self, mock_post):
        """Test successful authentication via password grant."""
        fake_token = pyjwt.encode(
            {
                "sub": "alice-uuid",
                "email": "alice@acme.com",
                "groups": ["data-analysts"],
                "exp": int(time.time()) + 300,
            },
            "secret",
            algorithm="HS256",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": fake_token}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        config = AgentConfig()
        auth = HumanAuthenticator(config)
        token = auth.authenticate(
            auth_mode="password",
            username="alice",
            password="alice-demo-password",
        )

        self.assertEqual(token, fake_token)
        mock_post.assert_called_once()

    @patch("agent.requests.post")
    def test_password_grant_failure(self, mock_post):
        """Test password grant failure raises RuntimeError."""
        import requests as real_requests
        mock_post.side_effect = real_requests.exceptions.ConnectionError("Connection refused")

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError) as ctx:
            auth.authenticate(auth_mode="password", username="alice", password="wrong")

        self.assertIn("Human authentication failed", str(ctx.exception))

    @patch("agent.requests.post")
    def test_password_grant_http_error(self, mock_post):
        """Test HTTP error from Keycloak during password grant."""
        import requests as real_requests

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = real_requests.exceptions.HTTPError("401")
        mock_post.return_value = mock_response

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError):
            auth.authenticate(auth_mode="password", username="alice", password="bad")

    # ── Pre-supplied token tests ──────────────────────────────────────

    def test_token_mode_with_argument(self):
        """Token mode should accept a pre-supplied access token."""
        fake_token = pyjwt.encode(
            {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "exp": int(time.time()) + 300,
            },
            "secret",
            algorithm="HS256",
        )

        config = AgentConfig()
        auth = HumanAuthenticator(config)
        result = auth.authenticate(auth_mode="token", access_token=fake_token)
        self.assertEqual(result, fake_token)

    def test_token_mode_from_env(self):
        """Token mode should read from HUMAN_ACCESS_TOKEN env var."""
        fake_token = pyjwt.encode(
            {
                "sub": "bob@acme.com",
                "groups": ["engineering"],
                "exp": int(time.time()) + 300,
            },
            "secret",
            algorithm="HS256",
        )

        os.environ["HUMAN_ACCESS_TOKEN"] = fake_token
        try:
            config = AgentConfig()
            auth = HumanAuthenticator(config)
            result = auth.authenticate(auth_mode="token")
            self.assertEqual(result, fake_token)
        finally:
            os.environ.pop("HUMAN_ACCESS_TOKEN", None)

    def test_token_mode_missing_token_raises(self):
        """Token mode without a token should raise RuntimeError."""
        os.environ.pop("HUMAN_ACCESS_TOKEN", None)
        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError) as ctx:
            auth.authenticate(auth_mode="token")
        self.assertIn("No access token", str(ctx.exception))

    # ── Device flow tests ─────────────────────────────────────────────

    @patch("agent.time.sleep")  # Don't actually sleep in tests
    @patch("agent.requests.post")
    def test_device_flow_success(self, mock_post, mock_sleep):
        """Test the device authorization flow happy path."""
        fake_token = pyjwt.encode(
            {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "exp": int(time.time()) + 300,
            },
            "secret",
            algorithm="HS256",
        )

        # First call: device auth endpoint returns codes
        device_response = MagicMock()
        device_response.status_code = 200
        device_response.json.return_value = {
            "device_code": "DEVICE-CODE-123",
            "user_code": "ABCD-1234",
            "verification_uri": "http://localhost:8080/device",
            "verification_uri_complete": "http://localhost:8080/device?user_code=ABCD-1234",
            "interval": 1,
            "expires_in": 600,
        }
        device_response.raise_for_status = MagicMock()

        # Second call: poll returns authorization_pending
        pending_response = MagicMock()
        pending_response.json.return_value = {
            "error": "authorization_pending",
        }

        # Third call: poll returns the token
        token_response = MagicMock()
        token_response.json.return_value = {
            "access_token": fake_token,
        }

        mock_post.side_effect = [device_response, pending_response, token_response]

        config = AgentConfig()
        auth = HumanAuthenticator(config)
        result = auth.authenticate(auth_mode="device")

        self.assertEqual(result, fake_token)
        self.assertEqual(mock_post.call_count, 3)

    @patch("agent.requests.post")
    def test_device_flow_request_failure(self, mock_post):
        """Test device flow when initial request fails."""
        import requests as real_requests
        mock_post.side_effect = real_requests.exceptions.ConnectionError("refused")

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError) as ctx:
            auth.authenticate(auth_mode="device")
        self.assertIn("Device authorization request failed", str(ctx.exception))

    @patch("agent.time.sleep")
    @patch("agent.requests.post")
    def test_device_flow_access_denied(self, mock_post, mock_sleep):
        """Test device flow when user denies authorization."""
        device_response = MagicMock()
        device_response.status_code = 200
        device_response.json.return_value = {
            "device_code": "DEVICE-CODE-123",
            "user_code": "ABCD-1234",
            "verification_uri": "http://localhost:8080/device",
            "interval": 1,
            "expires_in": 600,
        }
        device_response.raise_for_status = MagicMock()

        denied_response = MagicMock()
        denied_response.json.return_value = {
            "error": "access_denied",
            "error_description": "User denied the request",
        }

        mock_post.side_effect = [device_response, denied_response]

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError) as ctx:
            auth.authenticate(auth_mode="device")
        self.assertIn("access_denied", str(ctx.exception))


class TestTokenExchangeClient(unittest.TestCase):
    """Tests for TokenExchangeClient class (JWT-only, no DB creds)."""

    def _make_fused_jwt(self, claims: dict, secret: str = "test-secret") -> str:
        """Create a fused delegation JWT for testing."""
        defaults = {
            "iss": "token-exchange.demo.local",
            "sub": "alice@acme.com",
            "aud": "vault",
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "jti": str(uuid.uuid4()),
            "scope": "readonly",
            "act": {
                "sub": "spiffe://demo.local/agent/query-agent",
                "act": {"sub": "alice@acme.com"},
            },
            "groups": ["data-analysts"],
            "delegation_depth": 1,
        }
        defaults.update(claims)
        return pyjwt.encode(defaults, secret, algorithm="HS256")

    def test_url_construction(self):
        config = AgentConfig(token_exchange_url="http://exchange:9090")
        client = TokenExchangeClient(config)
        self.assertEqual(client.exchange_url, "http://exchange:9090/v1/token/exchange")
        self.assertEqual(client.health_url, "http://exchange:9090/health")

    @patch("agent.requests.post")
    def test_exchange_token_success(self, mock_post):
        """Token exchange returns fused delegation JWT; agent decodes locally."""
        jti = "test-jti-abc123"
        fused_jwt = self._make_fused_jwt({
            "jti": jti,
            "sub": "alice@acme.com",
            "scope": "readonly",
            "act": {
                "sub": "spiffe://demo.local/agent/query-agent",
                "act": {"sub": "alice@acme.com"},
            },
        })

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": fused_jwt,
            "issued_token_type": "urn:agentic:token-type:agent-delegation",
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "readonly",
        }
        mock_post.return_value = mock_response

        config = AgentConfig()
        client = TokenExchangeClient(config)
        result = client.exchange_token(
            human_token="fake-token",
            agent_jwt_svid="fake-svid",
            requested_scope="readonly",
        )

        self.assertIsInstance(result, dict)
        # session_id is extracted from the JWT jti claim
        self.assertEqual(result["session_id"], jti)
        self.assertEqual(result["delegation_token"], fused_jwt)
        # human_subject is extracted from the JWT sub claim
        self.assertEqual(result["human_subject"], "alice@acme.com")
        self.assertEqual(result["expires_in"], 300)
        self.assertEqual(result["scope"], "readonly")
        # delegation_chain is built from the JWT act{} claims
        self.assertGreater(len(result["delegation_chain"]), 0)
        self.assertEqual(result["delegation_chain"][0]["subject"], "alice@acme.com")
        self.assertEqual(
            result["delegation_chain"][0]["actor"],
            "spiffe://demo.local/agent/query-agent",
        )
        # Verify no DB credentials are returned
        self.assertNotIn("db_credential", result)
        self.assertNotIn("username", result)
        self.assertNotIn("password", result)

    @patch("agent.requests.post")
    def test_exchange_token_no_act_claims(self, mock_post):
        """JWT without act{} claims should produce empty chain, sub from JWT."""
        fused_jwt = self._make_fused_jwt({
            "sub": "bob@acme.com",
            "jti": "jti-no-act",
        })
        # Remove the act claim by re-encoding without it
        fused_jwt = pyjwt.encode({
            "sub": "bob@acme.com",
            "jti": "jti-no-act",
            "exp": int(time.time()) + 300,
        }, "secret", algorithm="HS256")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": fused_jwt,
            "expires_in": 300,
            "scope": "readonly",
        }
        mock_post.return_value = mock_response

        config = AgentConfig()
        client = TokenExchangeClient(config)
        result = client.exchange_token("human-tok", "agent-svid")

        self.assertEqual(result["human_subject"], "bob@acme.com")
        self.assertEqual(result["delegation_chain"], [])
        self.assertEqual(result["session_id"], "jti-no-act")

    @patch("agent.requests.post")
    def test_exchange_token_generates_session_id_when_no_jti(self, mock_post):
        """When JWT has no jti claim, a UUID should be generated for session_id."""
        fused_jwt = pyjwt.encode({
            "sub": "alice@acme.com",
            "exp": int(time.time()) + 300,
            "scope": "readonly",
        }, "secret", algorithm="HS256")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": fused_jwt,
            "expires_in": 300,
            "scope": "readonly",
        }
        mock_post.return_value = mock_response

        config = AgentConfig()
        client = TokenExchangeClient(config)
        result = client.exchange_token("human-tok", "agent-svid")

        # session_id should be a valid UUID since there's no jti
        session_id = result["session_id"]
        try:
            uuid.UUID(session_id)
            valid_uuid = True
        except ValueError:
            valid_uuid = False
        self.assertTrue(valid_uuid, f"Expected UUID, got: {session_id}")

    @patch("agent.requests.post")
    def test_exchange_token_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "error": "access_denied",
            "error_description": "Policy denied",
        }
        mock_post.return_value = mock_response

        config = AgentConfig()
        client = TokenExchangeClient(config)

        with self.assertRaises(RuntimeError) as ctx:
            client.exchange_token("tok", "svid")
        self.assertIn("Token exchange failed", str(ctx.exception))

    @patch("agent.requests.post")
    def test_exchange_token_connection_error(self, mock_post):
        import requests as real_requests
        mock_post.side_effect = real_requests.exceptions.ConnectionError("refused")

        config = AgentConfig()
        client = TokenExchangeClient(config)

        with self.assertRaises(RuntimeError) as ctx:
            client.exchange_token("tok", "svid")
        self.assertIn("Token exchange request failed", str(ctx.exception))

    @patch("agent.requests.get")
    def test_check_health_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "healthy"}
        mock_get.return_value = mock_response

        config = AgentConfig()
        client = TokenExchangeClient(config)
        health = client.check_health()

        self.assertEqual(health["status"], "healthy")

    @patch("agent.requests.get")
    def test_check_health_failure(self, mock_get):
        mock_get.side_effect = Exception("connection refused")

        config = AgentConfig()
        client = TokenExchangeClient(config)
        health = client.check_health()

        self.assertEqual(health["status"], "unhealthy")
        self.assertIn("connection refused", health["error"])


class TestTokenExchangeJWTDecoding(unittest.TestCase):
    """Tests for TokenExchangeClient JWT payload decoding and chain building."""

    def test_decode_jwt_payload_valid(self):
        """Valid JWT should decode to claims dict."""
        token = pyjwt.encode(
            {"sub": "alice@acme.com", "scope": "readonly"},
            "secret",
            algorithm="HS256",
        )
        claims = TokenExchangeClient._decode_jwt_payload(token)
        self.assertEqual(claims["sub"], "alice@acme.com")
        self.assertEqual(claims["scope"], "readonly")

    def test_decode_jwt_payload_invalid(self):
        """Invalid token should return empty dict."""
        claims = TokenExchangeClient._decode_jwt_payload("not-a-jwt")
        self.assertEqual(claims, {})

    def test_decode_jwt_payload_empty(self):
        """Empty string should return empty dict."""
        claims = TokenExchangeClient._decode_jwt_payload("")
        self.assertEqual(claims, {})

    def test_build_delegation_chain_with_act(self):
        """Claims with nested act{} should produce a delegation chain."""
        claims = {
            "sub": "alice@acme.com",
            "scope": "readonly",
            "act": {
                "sub": "spiffe://demo.local/agent/query-agent",
                "act": {"sub": "alice@acme.com"},
            },
        }
        chain = TokenExchangeClient._build_delegation_chain(claims)
        self.assertEqual(len(chain), 2)
        # First link: alice -> agent
        self.assertEqual(chain[0]["subject"], "alice@acme.com")
        self.assertEqual(chain[0]["actor"], "spiffe://demo.local/agent/query-agent")
        self.assertEqual(chain[0]["actor_type"], "agent")
        self.assertEqual(chain[0]["depth"], 0)
        # Second link: agent -> alice (inner act)
        self.assertEqual(chain[1]["subject"], "spiffe://demo.local/agent/query-agent")
        self.assertEqual(chain[1]["actor"], "alice@acme.com")
        self.assertEqual(chain[1]["actor_type"], "human")
        self.assertEqual(chain[1]["depth"], 1)

    def test_build_delegation_chain_no_act(self):
        """Claims without act{} should produce empty chain."""
        claims = {"sub": "alice@acme.com", "scope": "readonly"}
        chain = TokenExchangeClient._build_delegation_chain(claims)
        self.assertEqual(chain, [])

    def test_build_delegation_chain_single_act(self):
        """Claims with single-level act{} (no nested act) produce one link."""
        claims = {
            "sub": "alice@acme.com",
            "scope": "readonly",
            "act": {"sub": "spiffe://demo.local/agent/query-agent"},
        }
        chain = TokenExchangeClient._build_delegation_chain(claims)
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["subject"], "alice@acme.com")
        self.assertEqual(chain[0]["actor"], "spiffe://demo.local/agent/query-agent")



class TestDatabaseQuerier(unittest.TestCase):
    """Tests for DatabaseQuerier class."""

    def _make_active_session(self):
        return DelegationSession(
            session_id="sess-test",
            human_subject="alice@acme.com",
            scope="readonly",
            db_username="v-test-user",
            db_password="test-pw",
            db_host="localhost",
            db_port=5432,
            db_name="testdb",
            lease_id="lease-123",
            ttl_seconds=300,
        )

    def _make_expired_session(self):
        return DelegationSession(
            session_id="sess-expired",
            human_subject="alice@acme.com",
            scope="readonly",
            db_username="v-expired-user",
            db_password="expired-pw",
            db_host="localhost",
            db_port=5432,
            db_name="testdb",
            lease_id="lease-expired",
            ttl_seconds=0,
            created_at=datetime.now(timezone.utc) - timedelta(seconds=600),
        )

    def test_connect_expired_session(self):
        """Connecting with expired session should raise RuntimeError."""
        session = self._make_expired_session()
        querier = DatabaseQuerier(session)

        with self.assertRaises(RuntimeError) as ctx:
            querier.connect()

        self.assertIn("expired", str(ctx.exception))

    def test_query_auto_connects(self):
        """query() should call connect() if not connected."""
        session = self._make_active_session()
        querier = DatabaseQuerier(session)

        with patch.object(querier, "connect") as mock_connect:
            mock_connect.side_effect = RuntimeError("no db in test")
            with self.assertRaises(RuntimeError):
                querier.query("SELECT 1")

            mock_connect.assert_called_once()

    def test_query_expired_during_execution(self):
        """query() should check expiry even if already connected."""
        session = self._make_expired_session()
        querier = DatabaseQuerier(session)
        querier._conn = MagicMock()  # Pretend we're connected

        with self.assertRaises(RuntimeError) as ctx:
            querier.query("SELECT 1")

        self.assertIn("expired", str(ctx.exception))

    def test_close_with_connection(self):
        session = self._make_active_session()
        querier = DatabaseQuerier(session)
        mock_conn = MagicMock()
        querier._conn = mock_conn

        querier.close()

        mock_conn.close.assert_called_once()
        self.assertIsNone(querier._conn)

    def test_close_without_connection(self):
        """close() should be safe to call when not connected."""
        session = self._make_active_session()
        querier = DatabaseQuerier(session)
        querier.close()  # Should not raise


class TestNaturalLanguageMapping(unittest.TestCase):
    """Tests for the natural language to SQL mapping."""

    def test_exact_match(self):
        sql = map_natural_language_to_sql("show me all orders over $1000 from last month")
        self.assertIn("total_amount > 1000", sql)
        self.assertIn("order_summary", sql)

    def test_case_insensitive(self):
        sql = map_natural_language_to_sql("SHOW ME ALL ORDERS OVER $1000 FROM LAST MONTH")
        self.assertIn("total_amount > 1000", sql)

    def test_top_customers(self):
        sql = map_natural_language_to_sql("what are the top customers by order value")
        self.assertIn("customer_name", sql)
        self.assertIn("SUM(total_amount)", sql)
        self.assertIn("GROUP BY", sql)

    def test_region_summary(self):
        sql = map_natural_language_to_sql("show order summary by region")
        self.assertIn("region", sql)
        self.assertIn("GROUP BY", sql)

    def test_low_stock(self):
        sql = map_natural_language_to_sql("list all products with low stock")
        self.assertIn("stock_quantity < 100", sql)

    def test_high_value_orders(self):
        sql = map_natural_language_to_sql("show recent high-value orders")
        self.assertIn("value_tier", sql)
        self.assertIn("LIMIT 10", sql)

    def test_unknown_query_returns_default(self):
        sql = map_natural_language_to_sql("tell me something random")
        self.assertEqual(sql, DEFAULT_QUERY)

    def test_empty_query_returns_default(self):
        sql = map_natural_language_to_sql("")
        self.assertEqual(sql, DEFAULT_QUERY)

    def test_whitespace_handling(self):
        sql = map_natural_language_to_sql("  show me all orders over $1000 from last month  ")
        self.assertIn("total_amount > 1000", sql)

    def test_all_mappings_produce_valid_sql_keywords(self):
        """Every mapped query should contain basic SQL structure."""
        for question, sql in QUERY_MAPPINGS.items():
            with self.subTest(question=question):
                self.assertIn("SELECT", sql.upper())
                self.assertIn("FROM", sql.upper())


class TestQueryMappings(unittest.TestCase):
    """Tests for QUERY_MAPPINGS dictionary integrity."""

    def test_all_mappings_exist(self):
        self.assertEqual(len(QUERY_MAPPINGS), 5)

    def test_default_query_has_limit(self):
        self.assertIn("LIMIT", DEFAULT_QUERY)

    def test_all_queries_reference_app_schema(self):
        """All queries should reference the app schema."""
        for question, sql in QUERY_MAPPINGS.items():
            with self.subTest(question=question):
                self.assertIn("app.", sql)


class TestDeviceFlowEdgeCases(unittest.TestCase):
    """Tests for Device Authorization Flow edge cases."""

    @patch("agent.time.sleep")
    @patch("agent.requests.post")
    def test_slow_down_increases_poll_interval(self, mock_post, mock_sleep):
        """Slow_down response should increase poll interval before succeeding."""
        fake_token = pyjwt.encode(
            {"sub": "alice", "exp": int(time.time()) + 300},
            "secret",
            algorithm="HS256",
        )

        device_response = MagicMock()
        device_response.status_code = 200
        device_response.json.return_value = {
            "device_code": "DEV-123",
            "user_code": "ABCD-1234",
            "verification_uri": "http://localhost:8080/device",
            "interval": 5,
            "expires_in": 600,
        }
        device_response.raise_for_status = MagicMock()

        slow_down_response = MagicMock()
        slow_down_response.json.return_value = {"error": "slow_down"}

        token_response = MagicMock()
        token_response.json.return_value = {"access_token": fake_token}

        mock_post.side_effect = [device_response, slow_down_response, token_response]

        config = AgentConfig()
        auth = HumanAuthenticator(config)
        result = auth.authenticate(auth_mode="device")

        self.assertEqual(result, fake_token)
        self.assertEqual(mock_post.call_count, 3)
        # First sleep uses the original interval (5), second should be 6 (5+1)
        sleep_calls = [call.args[0] for call in mock_sleep.call_args_list]
        self.assertEqual(sleep_calls[0], 5)
        self.assertEqual(sleep_calls[1], 6)

    @patch("agent.time.sleep")
    @patch("agent.requests.post")
    def test_expired_token_raises_runtime_error(self, mock_post, mock_sleep):
        """Expired token error from Keycloak should raise RuntimeError."""
        device_response = MagicMock()
        device_response.status_code = 200
        device_response.json.return_value = {
            "device_code": "DEV-123",
            "user_code": "ABCD-1234",
            "verification_uri": "http://localhost:8080/device",
            "interval": 1,
            "expires_in": 600,
        }
        device_response.raise_for_status = MagicMock()

        expired_response = MagicMock()
        expired_response.json.return_value = {
            "error": "expired_token",
            "error_description": "The device code has expired",
        }

        mock_post.side_effect = [device_response, expired_response]

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError) as ctx:
            auth.authenticate(auth_mode="device")
        self.assertIn("expired_token", str(ctx.exception))

    @patch("agent.time.time")
    @patch("agent.time.sleep")
    @patch("agent.requests.post")
    def test_deadline_expiry_raises_timeout(self, mock_post, mock_sleep, mock_time):
        """Should raise RuntimeError when device authorization times out."""
        device_response = MagicMock()
        device_response.status_code = 200
        device_response.json.return_value = {
            "device_code": "DEV-123",
            "user_code": "ABCD-1234",
            "verification_uri": "http://localhost:8080/device",
            "interval": 1,
            "expires_in": 10,
        }
        device_response.raise_for_status = MagicMock()

        pending_response = MagicMock()
        pending_response.json.return_value = {"error": "authorization_pending"}

        mock_post.side_effect = [device_response, pending_response, pending_response]

        # Simulate time progression: first call sets deadline, then exceed it
        # time.time() is called: once for deadline = time.time() + expires_in,
        # then in the while loop condition
        mock_time.side_effect = [
            100.0,   # deadline = 100.0 + 10 = 110.0
            105.0,   # while check: 105 < 110 → enter loop
            115.0,   # while check: 115 < 110 → False, exit loop
        ]

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError) as ctx:
            auth.authenticate(auth_mode="device")
        self.assertIn("timed out", str(ctx.exception))

    @patch("agent.time.sleep")
    @patch("agent.requests.post")
    def test_network_failure_retries(self, mock_post, mock_sleep):
        """Network failure during polling should be retried."""
        import requests as real_requests

        fake_token = pyjwt.encode(
            {"sub": "alice", "exp": int(time.time()) + 300},
            "secret",
            algorithm="HS256",
        )

        device_response = MagicMock()
        device_response.status_code = 200
        device_response.json.return_value = {
            "device_code": "DEV-123",
            "user_code": "ABCD-1234",
            "verification_uri": "http://localhost:8080/device",
            "interval": 1,
            "expires_in": 600,
        }
        device_response.raise_for_status = MagicMock()

        token_response = MagicMock()
        token_response.json.return_value = {"access_token": fake_token}

        mock_post.side_effect = [
            device_response,
            real_requests.exceptions.ConnectionError("Connection refused"),
            token_response,
        ]

        config = AgentConfig()
        auth = HumanAuthenticator(config)
        result = auth.authenticate(auth_mode="device")

        self.assertEqual(result, fake_token)
        self.assertEqual(mock_post.call_count, 3)

    @patch("agent.time.sleep")
    @patch("agent.requests.post")
    def test_access_denied_raises_error(self, mock_post, mock_sleep):
        """Access denied error should raise RuntimeError."""
        device_response = MagicMock()
        device_response.status_code = 200
        device_response.json.return_value = {
            "device_code": "DEV-123",
            "user_code": "ABCD-1234",
            "verification_uri": "http://localhost:8080/device",
            "interval": 1,
            "expires_in": 600,
        }
        device_response.raise_for_status = MagicMock()

        denied_response = MagicMock()
        denied_response.json.return_value = {
            "error": "access_denied",
            "error_description": "User denied the request",
        }

        mock_post.side_effect = [device_response, denied_response]

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError) as ctx:
            auth.authenticate(auth_mode="device")
        self.assertIn("access_denied", str(ctx.exception))


class TestTokenExchangeClientErrors(unittest.TestCase):
    """Tests for TokenExchangeClient error handling."""

    @patch("agent.requests.post")
    def test_http_500_with_error_key_raises(self, mock_post):
        """Response containing 'error' key should raise RuntimeError."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.return_value = {
            "error": "server_error",
            "error_description": "internal failure",
        }
        mock_post.return_value = mock_response

        config = AgentConfig()
        client = TokenExchangeClient(config)

        with self.assertRaises(RuntimeError) as ctx:
            client.exchange_token("human-tok", "agent-svid")
        self.assertIn("Token exchange failed", str(ctx.exception))
        self.assertIn("server_error", str(ctx.exception))


class TestVaultClient(unittest.TestCase):
    """Tests for VaultClient SPIFFE auth, JWT auth, and DB credentials."""

    def _make_config(self):
        return AgentConfig(vault_addr="http://vault:8200")

    # ── SPIFFE auth tests ──

    @patch("agent.requests.post")
    def test_login_spiffe_success(self, mock_post):
        """Successful SPIFFE login returns client token and policies."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "auth": {
                "client_token": "s.vault-spiffe-token-xyz",
                "policies": ["default", "gateway"],
                "lease_duration": 3600,
                "metadata": {"role": "gateway"},
            }
        }
        mock_post.return_value = mock_response

        client = VaultClient(self._make_config())
        result = client.login_spiffe("fake-jwt-svid", role="gateway")

        self.assertEqual(result["client_token"], "s.vault-spiffe-token-xyz")
        self.assertIn("gateway", result["policies"])
        self.assertEqual(result["lease_duration"], 3600)
        mock_post.assert_called_once_with(
            "http://vault:8200/v1/auth/jwt/login",
            json={"jwt": "fake-jwt-svid", "role": "gateway"},
            timeout=10,
        )

    @patch("agent.requests.post")
    def test_login_spiffe_error_response(self, mock_post):
        """Vault error response should raise RuntimeError."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "errors": ["permission denied"]
        }
        mock_post.return_value = mock_response

        client = VaultClient(self._make_config())
        with self.assertRaises(RuntimeError) as ctx:
            client.login_spiffe("bad-svid")
        self.assertIn("Vault SPIFFE auth failed", str(ctx.exception))

    @patch("agent.requests.post")
    def test_login_spiffe_no_token(self, mock_post):
        """Missing client_token in auth response should raise RuntimeError."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "auth": {
                "policies": ["default"],
                "lease_duration": 0,
            }
        }
        mock_post.return_value = mock_response

        client = VaultClient(self._make_config())
        with self.assertRaises(RuntimeError) as ctx:
            client.login_spiffe("svid")
        self.assertIn("no client_token", str(ctx.exception))

    @patch("agent.requests.post")
    def test_login_spiffe_connection_error(self, mock_post):
        """Network failure should raise RuntimeError."""
        import requests as real_requests
        mock_post.side_effect = real_requests.exceptions.ConnectionError("refused")

        client = VaultClient(self._make_config())
        with self.assertRaises(RuntimeError) as ctx:
            client.login_spiffe("svid")
        self.assertIn("Vault SPIFFE auth request failed", str(ctx.exception))

    # ── JWT auth tests ──

    @patch("agent.requests.post")
    def test_login_jwt_success(self, mock_post):
        """Successful JWT login returns client token with delegation identity."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "auth": {
                "client_token": "s.vault-delegation-token-abc",
                "policies": ["default", "ai-agent-db-read"],
                "lease_duration": 300,
                "metadata": {"role": "agent-readonly"},
            }
        }
        mock_post.return_value = mock_response

        client = VaultClient(self._make_config())
        result = client.login_jwt("fused-delegation-jwt", role="agent-readonly")

        self.assertEqual(result["client_token"], "s.vault-delegation-token-abc")
        self.assertIn("ai-agent-db-read", result["policies"])
        mock_post.assert_called_once_with(
            "http://vault:8200/v1/auth/jwt/login",
            json={"jwt": "fused-delegation-jwt", "role": "agent-readonly"},
            timeout=10,
        )

    @patch("agent.requests.post")
    def test_login_jwt_error_response(self, mock_post):
        """Vault error in JWT auth should raise RuntimeError."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "errors": ["role not found"]
        }
        mock_post.return_value = mock_response

        client = VaultClient(self._make_config())
        with self.assertRaises(RuntimeError) as ctx:
            client.login_jwt("bad-jwt", role="nonexistent")
        self.assertIn("Vault JWT auth failed", str(ctx.exception))

    @patch("agent.requests.post")
    def test_login_jwt_connection_error(self, mock_post):
        """Network failure should raise RuntimeError."""
        import requests as real_requests
        mock_post.side_effect = real_requests.exceptions.ConnectionError("refused")

        client = VaultClient(self._make_config())
        with self.assertRaises(RuntimeError) as ctx:
            client.login_jwt("jwt", role="agent-readonly")
        self.assertIn("Vault JWT auth request failed", str(ctx.exception))

    # ── DB credential tests ──

    @patch("agent.requests.get")
    def test_get_database_credentials_success(self, mock_get):
        """Successful DB credential request returns username, password, lease."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "username": "v-spiffe-readonly-xyz",
                "password": "dynamic-pw-123",
            },
            "lease_id": "database/creds/ai-agent-readonly/abc123",
            "lease_duration": 300,
        }
        mock_get.return_value = mock_response

        client = VaultClient(self._make_config())
        result = client.get_database_credentials(
            "s.vault-token", role="ai-agent-readonly"
        )

        self.assertEqual(result["username"], "v-spiffe-readonly-xyz")
        self.assertEqual(result["password"], "dynamic-pw-123")
        self.assertEqual(result["lease_id"], "database/creds/ai-agent-readonly/abc123")
        self.assertEqual(result["lease_duration"], 300)
        mock_get.assert_called_once_with(
            "http://vault:8200/v1/database/creds/ai-agent-readonly",
            headers={"X-Vault-Token": "s.vault-token"},
            timeout=10,
        )

    @patch("agent.requests.get")
    def test_get_database_credentials_error(self, mock_get):
        """Vault error response should raise RuntimeError."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "errors": ["1 error occurred: permission denied"]
        }
        mock_get.return_value = mock_response

        client = VaultClient(self._make_config())
        with self.assertRaises(RuntimeError) as ctx:
            client.get_database_credentials("s.bad-token", role="ai-agent-readonly")
        self.assertIn("Vault DB credential request failed", str(ctx.exception))

    @patch("agent.requests.get")
    def test_get_database_credentials_connection_error(self, mock_get):
        """Network failure should raise RuntimeError."""
        import requests as real_requests
        mock_get.side_effect = real_requests.exceptions.ConnectionError("refused")

        client = VaultClient(self._make_config())
        with self.assertRaises(RuntimeError) as ctx:
            client.get_database_credentials("s.token", role="ai-agent-readonly")
        self.assertIn("Vault DB credential request failed", str(ctx.exception))

    # ── Lease revocation tests ──

    @patch("agent.requests.put")
    def test_revoke_lease_success(self, mock_put):
        """Successful lease revocation should not raise."""
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_put.return_value = mock_response

        client = VaultClient(self._make_config())
        # Should not raise
        client.revoke_lease("s.vault-token", "database/creds/ai-agent-readonly/abc")

        mock_put.assert_called_once_with(
            "http://vault:8200/v1/sys/leases/revoke",
            headers={"X-Vault-Token": "s.vault-token"},
            json={"lease_id": "database/creds/ai-agent-readonly/abc"},
            timeout=10,
        )

    @patch("agent.requests.put")
    def test_revoke_lease_connection_error(self, mock_put):
        """Network failure during revocation should not raise (just warn)."""
        import requests as real_requests
        mock_put.side_effect = real_requests.exceptions.ConnectionError("refused")

        client = VaultClient(self._make_config())
        # Should not raise — revoke_lease is best-effort
        client.revoke_lease("s.token", "lease-id")


class TestNaturalLanguageSecurity(unittest.TestCase):
    """Tests for SQL injection safety in NL-to-SQL mapping."""

    def test_sql_injection_string_returns_default(self):
        """SQL injection attempt should not match any pattern."""
        sql = map_natural_language_to_sql("'; DROP TABLE orders;--")
        self.assertEqual(sql, DEFAULT_QUERY)

    def test_very_long_input_returns_default(self):
        """Extremely long input should return default query."""
        sql = map_natural_language_to_sql("a" * 10000)
        self.assertEqual(sql, DEFAULT_QUERY)

    def test_empty_input_returns_default(self):
        """Whitespace-only input should return default query."""
        sql = map_natural_language_to_sql("   ")
        self.assertEqual(sql, DEFAULT_QUERY)


class TestDatabaseQuerierExpiry(unittest.TestCase):
    """Tests for DatabaseQuerier session expiry handling."""

    def test_connect_with_expired_session_raises(self):
        """Connecting with an expired session should raise RuntimeError."""
        session = DelegationSession(
            session_id="sess-expired",
            human_subject="alice@acme.com",
            scope="readonly",
            db_username="v-expired-user",
            db_password="expired-pw",
            db_host="localhost",
            db_port=5432,
            db_name="testdb",
            lease_id="lease-expired",
            ttl_seconds=300,
            created_at=datetime.now(timezone.utc) - timedelta(seconds=600),
        )
        querier = DatabaseQuerier(session)

        with self.assertRaises(RuntimeError) as ctx:
            querier.connect()
        self.assertIn("expired", str(ctx.exception))

    def test_query_with_expired_session_raises(self):
        """Querying with an expired session should raise RuntimeError even if connected."""
        session = DelegationSession(
            session_id="sess-expired",
            human_subject="alice@acme.com",
            scope="readonly",
            db_username="v-expired-user",
            db_password="expired-pw",
            db_host="localhost",
            db_port=5432,
            db_name="testdb",
            lease_id="lease-expired",
            ttl_seconds=300,
            created_at=datetime.now(timezone.utc) - timedelta(seconds=600),
        )
        querier = DatabaseQuerier(session)
        querier._conn = MagicMock()  # Pretend we're connected

        with self.assertRaises(RuntimeError) as ctx:
            querier.query("SELECT 1")
        self.assertIn("expired", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
