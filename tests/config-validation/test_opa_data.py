"""
OPA Policy Data Validation Tests

Validates the OPA policy data.json for correct structure,
trusted issuers, registered agents, and group permission mappings.
"""

import json
import os
import unittest

DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "opa", "policies", "data.json"
)


class TestOPAData(unittest.TestCase):
    """Validate OPA policy data configuration."""

    @classmethod
    def setUpClass(cls):
        with open(DATA_PATH) as f:
            cls.data = json.load(f)
        cls.config = cls.data["config"]

    # ─── Structure ───────────────────────────────────────────────────

    def test_config_key_exists(self):
        self.assertIn("config", self.data)

    def test_required_config_keys(self):
        expected = {
            "trusted_issuers",
            "registered_agents",
            "group_permissions",
            "max_delegation_ttl_seconds",
            "require_may_act_claim",
        }
        actual = set(self.config.keys())
        self.assertTrue(expected.issubset(actual), f"Missing keys: {expected - actual}")

    # ─── Trusted Issuers ─────────────────────────────────────────────

    def test_trusted_issuers_not_empty(self):
        self.assertTrue(len(self.config["trusted_issuers"]) > 0)

    def test_keycloak_issuer_registered(self):
        self.assertIn(
            "http://keycloak:8080/realms/demo",
            self.config["trusted_issuers"],
        )

    def test_trusted_issuers_are_urls(self):
        for issuer in self.config["trusted_issuers"]:
            self.assertTrue(
                issuer.startswith("http://") or issuer.startswith("https://"),
                f"Issuer '{issuer}' is not a valid URL",
            )

    # ─── Registered Agents ───────────────────────────────────────────

    def test_registered_agents_not_empty(self):
        self.assertTrue(len(self.config["registered_agents"]) > 0)

    def test_query_agent_registered(self):
        self.assertIn(
            "spiffe://demo.local/agent/query-agent",
            self.config["registered_agents"],
        )

    def test_gateway_registered(self):
        self.assertIn(
            "spiffe://demo.local/gateway/identity-gateway",
            self.config["registered_agents"],
        )

    def test_all_agents_have_spiffe_prefix(self):
        for agent in self.config["registered_agents"]:
            self.assertTrue(
                agent.startswith("spiffe://demo.local/"),
                f"Agent '{agent}' not in demo.local trust domain",
            )

    # ─── Group Permissions ───────────────────────────────────────────

    def test_group_permissions_not_empty(self):
        self.assertTrue(len(self.config["group_permissions"]) > 0)

    def test_data_analysts_permissions(self):
        perms = self.config["group_permissions"]["data-analysts"]
        self.assertIn("readonly", perms)
        self.assertIn("db:read", perms)
        self.assertIn("db:query", perms)

    def test_data_analysts_no_write(self):
        perms = self.config["group_permissions"]["data-analysts"]
        self.assertNotIn("readwrite", perms)
        self.assertNotIn("db:write", perms)

    def test_trading_team_permissions(self):
        perms = self.config["group_permissions"]["trading-team"]
        self.assertIn("readonly", perms)
        self.assertNotIn("readwrite", perms)

    def test_engineering_permissions(self):
        perms = self.config["group_permissions"]["engineering"]
        self.assertIn("readonly", perms)
        self.assertIn("readwrite", perms)
        self.assertIn("db:read", perms)
        self.assertIn("db:write", perms)
        self.assertIn("db:query", perms)

    def test_engineering_is_superset_of_analysts(self):
        analyst_perms = set(self.config["group_permissions"]["data-analysts"])
        eng_perms = set(self.config["group_permissions"]["engineering"])
        self.assertTrue(
            analyst_perms.issubset(eng_perms),
            "Engineering should have all data-analyst permissions",
        )

    # ─── Security Settings ───────────────────────────────────────────

    def test_max_delegation_ttl(self):
        ttl = self.config["max_delegation_ttl_seconds"]
        self.assertEqual(ttl, 28800)  # 8 hours
        self.assertIsInstance(ttl, int)

    def test_require_may_act_enabled(self):
        self.assertTrue(self.config["require_may_act_claim"])


class TestOPARegoPolicy(unittest.TestCase):
    """Validate the Rego policy file structure."""

    @classmethod
    def setUpClass(cls):
        rego_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "opa", "policies", "delegation.rego"
        )
        with open(rego_path) as f:
            cls.rego = f.read()

    def test_package_name(self):
        self.assertIn("package delegation", self.rego)

    def test_default_deny(self):
        self.assertIn("default allow := false", self.rego)

    def test_has_allow_rule(self):
        self.assertIn("allow if", self.rego)

    def test_validates_human_token(self):
        self.assertIn("valid_human_token", self.rego)

    def test_validates_agent_identity(self):
        self.assertIn("valid_agent_identity", self.rego)

    def test_checks_delegation(self):
        self.assertIn("authorized_delegation", self.rego)

    def test_checks_scope(self):
        self.assertIn("scope_permitted", self.rego)

    def test_has_decision_output(self):
        self.assertIn("decision :=", self.rego)

    def test_has_reason_outputs(self):
        self.assertIn("reason :=", self.rego)
        self.assertIn("invalid_human_token", self.rego)
        self.assertIn("invalid_agent_identity", self.rego)
        self.assertIn("unauthorized_delegation", self.rego)
        self.assertIn("scope_not_permitted", self.rego)

    def test_uses_rego_v1(self):
        self.assertIn("import rego.v1", self.rego)


if __name__ == "__main__":
    unittest.main()
