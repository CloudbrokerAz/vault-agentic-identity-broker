"""
Unit tests for the AI Agent application.

Tests cover:
- AgentConfig defaults and environment loading
- DelegationSession lifecycle and expiry
- SPIFFEIdentity demo SVID generation
- HumanAuthenticator Keycloak interaction
- IdentityGatewayClient delegation requests
- DatabaseQuerier session validation
- Natural language to SQL mapping
"""

import json
import os
import time
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
    IdentityGatewayClient,
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
        self.assertEqual(config.gateway_url, "http://identity-gateway:8080")
        self.assertEqual(config.keycloak_url, "http://keycloak:8080")
        self.assertEqual(config.keycloak_realm, "demo")
        self.assertEqual(config.trust_domain, "demo.local")
        self.assertEqual(config.agent_spiffe_id, "spiffe://demo.local/agent/query-agent")
        self.assertEqual(config.db_host, "postgresql")
        self.assertEqual(config.db_port, 5432)
        self.assertEqual(config.db_name, "appdb")

    def test_from_env_defaults(self):
        """from_env should return defaults when no env vars are set."""
        # Clear relevant env vars
        env_vars = [
            "SPIRE_AGENT_SOCKET", "GATEWAY_URL", "KEYCLOAK_URL",
            "KEYCLOAK_REALM", "TRUST_DOMAIN", "AGENT_SPIFFE_ID",
            "DB_HOST", "DB_PORT", "DB_NAME",
        ]
        saved = {k: os.environ.pop(k, None) for k in env_vars}
        try:
            config = AgentConfig.from_env()
            self.assertEqual(config.gateway_url, "http://identity-gateway:8080")
            self.assertEqual(config.db_port, 5432)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_from_env_custom(self):
        """from_env should read from environment variables."""
        os.environ["GATEWAY_URL"] = "http://custom-gateway:9090"
        os.environ["DB_PORT"] = "5433"
        os.environ["TRUST_DOMAIN"] = "prod.example.com"
        try:
            config = AgentConfig.from_env()
            self.assertEqual(config.gateway_url, "http://custom-gateway:9090")
            self.assertEqual(config.db_port, 5433)
            self.assertEqual(config.trust_domain, "prod.example.com")
        finally:
            os.environ.pop("GATEWAY_URL", None)
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

    def test_generate_demo_svid(self):
        config = AgentConfig()
        identity = SPIFFEIdentity(config)
        svid = identity._generate_demo_svid("test-audience")

        self.assertIsNotNone(svid)
        self.assertIsInstance(svid, str)

        # Decode and verify claims
        claims = pyjwt.decode(svid, "demo-secret", algorithms=["HS256"], audience="test-audience")
        self.assertEqual(claims["sub"], config.agent_spiffe_id)
        self.assertEqual(claims["aud"], ["test-audience"])
        self.assertEqual(claims["client_type"], "ai_agent")
        self.assertIn("exp", claims)
        self.assertIn("iat", claims)

    def test_generate_demo_svid_expiry(self):
        config = AgentConfig()
        identity = SPIFFEIdentity(config)
        svid = identity._generate_demo_svid("test-audience")
        claims = pyjwt.decode(svid, "demo-secret", algorithms=["HS256"], audience="test-audience")

        # Should expire in ~1 hour
        now = int(time.time())
        self.assertAlmostEqual(claims["exp"], now + 3600, delta=5)

    def test_fetch_jwt_svid_falls_back_to_demo(self):
        """Without SPIRE, should fall back to demo SVID."""
        config = AgentConfig(spire_socket_path="/nonexistent/socket")
        identity = SPIFFEIdentity(config)
        svid = identity.fetch_jwt_svid(audience="identity-gateway")

        self.assertIsNotNone(svid)
        claims = pyjwt.decode(svid, "demo-secret", algorithms=["HS256"], audience="identity-gateway")
        self.assertEqual(claims["sub"], config.agent_spiffe_id)

    def test_svid_stored_internally(self):
        config = AgentConfig()
        identity = SPIFFEIdentity(config)
        self.assertIsNone(identity._jwt_svid)

        identity._generate_demo_svid("test")
        self.assertIsNotNone(identity._jwt_svid)


class TestHumanAuthenticator(unittest.TestCase):
    """Tests for HumanAuthenticator class."""

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

    @patch("agent.requests.post")
    def test_authenticate_success(self, mock_post):
        """Test successful authentication via Keycloak."""
        # Create a fake access token
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
        token = auth.authenticate("alice", "alice-demo-password")

        self.assertEqual(token, fake_token)
        mock_post.assert_called_once()

        # Verify the request payload
        call_kwargs = mock_post.call_args
        self.assertEqual(call_kwargs.kwargs.get("timeout", call_kwargs[1].get("timeout")), 10)

    @patch("agent.requests.post")
    def test_authenticate_failure(self, mock_post):
        """Test authentication failure raises RuntimeError."""
        import requests as real_requests
        mock_post.side_effect = real_requests.exceptions.ConnectionError("Connection refused")

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError) as ctx:
            auth.authenticate("alice", "wrong-password")

        self.assertIn("Human authentication failed", str(ctx.exception))

    @patch("agent.requests.post")
    def test_authenticate_http_error(self, mock_post):
        """Test HTTP error from Keycloak."""
        import requests as real_requests

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = real_requests.exceptions.HTTPError("401")
        mock_post.return_value = mock_response

        config = AgentConfig()
        auth = HumanAuthenticator(config)

        with self.assertRaises(RuntimeError):
            auth.authenticate("alice", "bad-password")


class TestIdentityGatewayClient(unittest.TestCase):
    """Tests for IdentityGatewayClient class."""

    def test_url_construction(self):
        config = AgentConfig(gateway_url="http://gateway:9080")
        client = IdentityGatewayClient(config)
        self.assertEqual(client.delegate_url, "http://gateway:9080/v1/delegate")
        self.assertEqual(client.health_url, "http://gateway:9080/v1/health")
        self.assertEqual(client.audit_url, "http://gateway:9080/v1/audit")

    @patch("agent.requests.post")
    def test_request_delegation_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "session_id": "sess-abc123",
            "db_credential": {
                "username": "v-spiffe-readonly-xyz",
                "password": "dynamic-pw",
                "host": "postgresql",
                "port": 5432,
                "database": "appdb",
                "ttl_seconds": 300,
                "lease_id": "database/creds/ai-agent-readonly/abc",
            },
            "metadata": {
                "delegating_human": "alice@acme.com",
                "delegation_scope": "readonly",
            },
            "expires_at": "2026-02-20T10:35:00Z",
        }
        mock_post.return_value = mock_response

        config = AgentConfig()
        client = IdentityGatewayClient(config)
        session = client.request_delegation(
            human_token="fake-token",
            agent_spiffe_id="spiffe://demo.local/agent/query-agent",
            agent_jwt_svid="fake-svid",
            requested_scope="readonly",
        )

        self.assertEqual(session.session_id, "sess-abc123")
        self.assertEqual(session.human_subject, "alice@acme.com")
        self.assertEqual(session.db_username, "v-spiffe-readonly-xyz")
        self.assertEqual(session.ttl_seconds, 300)
        self.assertFalse(session.is_expired)

    @patch("agent.requests.post")
    def test_request_delegation_denied(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {
            "error": "Delegation denied by policy: scope_not_permitted",
        }
        mock_post.return_value = mock_response

        config = AgentConfig()
        client = IdentityGatewayClient(config)

        with self.assertRaises(RuntimeError) as ctx:
            client.request_delegation(
                human_token="fake-token",
                agent_spiffe_id="spiffe://demo.local/agent/query-agent",
                agent_jwt_svid="fake-svid",
                requested_scope="readwrite",
            )

        self.assertIn("403", str(ctx.exception))
        self.assertIn("scope_not_permitted", str(ctx.exception))

    @patch("agent.requests.post")
    def test_request_delegation_connection_error(self, mock_post):
        import requests as real_requests
        mock_post.side_effect = real_requests.exceptions.ConnectionError("refused")

        config = AgentConfig()
        client = IdentityGatewayClient(config)

        with self.assertRaises(RuntimeError) as ctx:
            client.request_delegation("tok", "spiffe", "svid")

        self.assertIn("Gateway request failed", str(ctx.exception))

    @patch("agent.requests.get")
    def test_check_health_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "healthy"}
        mock_get.return_value = mock_response

        config = AgentConfig()
        client = IdentityGatewayClient(config)
        health = client.check_health()

        self.assertEqual(health["status"], "healthy")

    @patch("agent.requests.get")
    def test_check_health_failure(self, mock_get):
        mock_get.side_effect = Exception("connection refused")

        config = AgentConfig()
        client = IdentityGatewayClient(config)
        health = client.check_health()

        self.assertEqual(health["status"], "unhealthy")
        self.assertIn("connection refused", health["error"])

    @patch("agent.requests.get")
    def test_get_audit_log_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"session_id": "sess-1", "result": "success"},
            {"session_id": "sess-2", "result": "denied"},
        ]
        mock_get.return_value = mock_response

        config = AgentConfig()
        client = IdentityGatewayClient(config)
        entries = client.get_audit_log()

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["result"], "success")

    @patch("agent.requests.get")
    def test_get_audit_log_failure(self, mock_get):
        mock_get.side_effect = Exception("error")

        config = AgentConfig()
        client = IdentityGatewayClient(config)
        entries = client.get_audit_log()

        self.assertEqual(len(entries), 1)
        self.assertIn("error", entries[0])


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


if __name__ == "__main__":
    unittest.main()
