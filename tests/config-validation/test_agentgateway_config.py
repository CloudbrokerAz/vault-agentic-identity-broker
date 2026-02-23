"""
AgentGateway Configuration Validation Tests

Validates the AgentGateway YAML configurations for both bridge
and host network modes, ensuring correct ports, URLs, auth settings,
rate limiting, and consistency between configs.
"""

import os
import unittest

import yaml

BRIDGE_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "agentgateway", "config", "gateway.yaml"
)
HOST_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "agentgateway", "config", "gateway-host.yaml"
)


def _collect_strings(obj):
    """Recursively collect all string values from a nested dict/list structure."""
    strings = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for value in obj.values():
            strings.extend(_collect_strings(value))
    elif isinstance(obj, list):
        for item in obj:
            strings.extend(_collect_strings(item))
    return strings


class TestGatewayBridgeConfig(unittest.TestCase):
    """Validate bridge-mode AgentGateway configuration."""

    @classmethod
    def setUpClass(cls):
        with open(BRIDGE_CONFIG_PATH) as f:
            cls.config = yaml.safe_load(f)

    # ─── Helpers ──────────────────────────────────────────────────────

    def _get_mcp_route(self):
        """Return the first route from the MCP listener bind."""
        return self.config["binds"][0]["listeners"][0]["routes"][0]

    def _get_rest_route(self):
        """Return the first route from the REST listener bind."""
        return self.config["binds"][1]["listeners"][0]["routes"][0]

    # ─── Tests ────────────────────────────────────────────────────────

    def test_config_section_has_required_addrs(self):
        """config has adminAddr, readinessAddr, statsAddr."""
        cfg = self.config["config"]
        self.assertIn("adminAddr", cfg)
        self.assertIn("readinessAddr", cfg)
        self.assertIn("statsAddr", cfg)

    def test_two_bind_entries(self):
        """There should be exactly two bind entries."""
        self.assertEqual(len(self.config["binds"]), 2)

    def test_mcp_listener_on_port_8080(self):
        """MCP listener should bind to port 8080 in bridge mode."""
        self.assertEqual(self.config["binds"][0]["port"], 8080)

    def test_rest_listener_on_port_9080(self):
        """REST listener should bind to port 9080."""
        self.assertEqual(self.config["binds"][1]["port"], 9080)

    def test_jwt_auth_configured_with_keycloak_issuer(self):
        """MCP route jwtAuth issuer should point to Keycloak via Docker DNS."""
        route = self._get_mcp_route()
        jwt_auth = route["policies"]["jwtAuth"]
        self.assertEqual(jwt_auth["issuer"], "http://keycloak:8080/realms/demo")

    def test_jwks_url_points_to_keycloak(self):
        """JWKS URL should reference keycloak:8080."""
        route = self._get_mcp_route()
        jwks_url = route["policies"]["jwtAuth"]["jwks"]["url"]
        self.assertIn("keycloak:8080", jwks_url)

    def test_mcp_rate_limiting_60_per_minute(self):
        """MCP route rate limit should be 60 requests per minute."""
        route = self._get_mcp_route()
        rate_limit = route["policies"]["localRateLimit"][0]
        self.assertEqual(rate_limit["maxTokens"], 60)

    def test_rest_rate_limiting_120_per_minute(self):
        """REST route rate limit should be 120 requests per minute."""
        route = self._get_rest_route()
        rate_limit = route["policies"]["localRateLimit"][0]
        self.assertEqual(rate_limit["maxTokens"], 120)

    def test_cors_allows_auth_and_content_type(self):
        """CORS allowHeaders should include authorization and content-type."""
        route = self._get_mcp_route()
        allow_headers = route["policies"]["cors"]["allowHeaders"]
        self.assertIn("authorization", allow_headers)
        self.assertIn("content-type", allow_headers)

    def test_mcp_target_url(self):
        """MCP backend target host should point to the Token Exchange MCP endpoint."""
        route = self._get_mcp_route()
        target = route["backends"][0]["mcp"]["targets"][0]
        self.assertEqual(target["mcp"]["host"], "http://token-exchange:8090/mcp/")


class TestGatewayHostConfig(unittest.TestCase):
    """Validate host-mode AgentGateway configuration."""

    @classmethod
    def setUpClass(cls):
        with open(HOST_CONFIG_PATH) as f:
            cls.config = yaml.safe_load(f)

    # ─── Helpers ──────────────────────────────────────────────────────

    def _get_mcp_route(self):
        """Return the first route from the MCP listener bind."""
        return self.config["binds"][0]["listeners"][0]["routes"][0]

    def _get_rest_route(self):
        """Return the first route from the REST listener bind."""
        return self.config["binds"][1]["listeners"][0]["routes"][0]

    # ─── Tests ────────────────────────────────────────────────────────

    def test_mcp_listener_on_port_9090(self):
        """MCP listener should bind to port 9090 to avoid Keycloak conflict."""
        self.assertEqual(self.config["binds"][0]["port"], 9090)

    def test_rest_listener_on_port_9080(self):
        """REST listener should bind to port 9080."""
        self.assertEqual(self.config["binds"][1]["port"], 9080)

    def test_all_urls_use_127_0_0_1(self):
        """All HTTP URLs in host config should use 127.0.0.1, not Docker DNS names."""
        all_strings = _collect_strings(self.config)
        http_urls = [s for s in all_strings if s.startswith("http://")]
        self.assertTrue(len(http_urls) > 0, "Expected at least one HTTP URL in config")
        for url in http_urls:
            self.assertIn(
                "127.0.0.1",
                url,
                f"URL should use 127.0.0.1 in host mode, got: {url}",
            )

    def test_jwt_issuer_uses_localhost(self):
        """JWT issuer should reference 127.0.0.1 in host mode."""
        route = self._get_mcp_route()
        jwt_auth = route["policies"]["jwtAuth"]
        self.assertEqual(jwt_auth["issuer"], "http://127.0.0.1:8080/realms/demo")

    def test_backend_uses_127_0_0_1(self):
        """REST backend host should reference 127.0.0.1."""
        route = self._get_rest_route()
        backend_host = route["backends"][0]["host"]
        self.assertEqual(backend_host, "127.0.0.1:8090")

    def test_rate_limiting_matches_bridge(self):
        """Rate limits should match bridge config: MCP=60, REST=120."""
        mcp_route = self._get_mcp_route()
        rest_route = self._get_rest_route()
        self.assertEqual(mcp_route["policies"]["localRateLimit"][0]["maxTokens"], 60)
        self.assertEqual(rest_route["policies"]["localRateLimit"][0]["maxTokens"], 120)


class TestGatewayConfigConsistency(unittest.TestCase):
    """Validate consistency between bridge and host configurations."""

    @classmethod
    def setUpClass(cls):
        with open(BRIDGE_CONFIG_PATH) as f:
            cls.bridge = yaml.safe_load(f)
        with open(HOST_CONFIG_PATH) as f:
            cls.host = yaml.safe_load(f)

    # ─── Tests ────────────────────────────────────────────────────────

    def test_same_admin_addr(self):
        """Both configs should have the same adminAddr."""
        self.assertEqual(
            self.bridge["config"]["adminAddr"],
            self.host["config"]["adminAddr"],
        )

    def test_same_number_of_binds(self):
        """Both configs should have the same number of bind entries."""
        self.assertEqual(len(self.bridge["binds"]), len(self.host["binds"]))

    def test_same_jwt_audiences(self):
        """JWT audiences in the MCP listener should be identical across configs."""
        bridge_audiences = (
            self.bridge["binds"][0]["listeners"][0]["routes"][0]["policies"]["jwtAuth"][
                "audiences"
            ]
        )
        host_audiences = (
            self.host["binds"][0]["listeners"][0]["routes"][0]["policies"]["jwtAuth"][
                "audiences"
            ]
        )
        self.assertEqual(bridge_audiences, host_audiences)

    def test_host_config_has_no_docker_dns_names(self):
        """Host config should not contain any Docker DNS service names."""
        docker_dns_names = [
            "keycloak:",
            "token-exchange:",
            "opa:",
            "vault:",
            "postgresql:",
        ]
        all_strings = _collect_strings(self.host)
        for s in all_strings:
            for dns_name in docker_dns_names:
                self.assertNotIn(
                    dns_name,
                    s,
                    f"Host config should not reference Docker DNS name '{dns_name}' "
                    f"but found it in value: {s}",
                )

    def test_both_configs_have_identical_cors(self):
        """CORS settings should be identical across bridge and host configs."""
        bridge_cors = (
            self.bridge["binds"][0]["listeners"][0]["routes"][0]["policies"]["cors"]
        )
        host_cors = (
            self.host["binds"][0]["listeners"][0]["routes"][0]["policies"]["cors"]
        )
        self.assertEqual(bridge_cors["allowOrigins"], host_cors["allowOrigins"])
        self.assertEqual(bridge_cors["allowMethods"], host_cors["allowMethods"])
        self.assertEqual(bridge_cors["allowHeaders"], host_cors["allowHeaders"])
        self.assertEqual(bridge_cors["exposeHeaders"], host_cors["exposeHeaders"])


if __name__ == "__main__":
    unittest.main()
