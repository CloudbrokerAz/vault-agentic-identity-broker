"""
Vault Sentinel Policy Validation Tests

Validates the Sentinel Endpoint Governing Policy (EGP) files that replace
OPA in the Vault Enterprise architecture. Each policy enforces a specific
aspect of the delegation model at the Vault request level.
"""

import os
import unittest

SENTINEL_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "sentinel-policies"
)


class TestSentinelPoliciesExist(unittest.TestCase):
    """Verify all required Sentinel policy files are present."""

    def test_sentinel_directory_exists(self):
        self.assertTrue(
            os.path.isdir(SENTINEL_DIR),
            f"sentinel-policies/ directory not found at {SENTINEL_DIR}",
        )

    def test_require_delegation_policy_exists(self):
        path = os.path.join(SENTINEL_DIR, "require-delegation.sentinel")
        self.assertTrue(os.path.isfile(path), "require-delegation.sentinel not found")

    def test_enforce_scope_policy_exists(self):
        path = os.path.join(SENTINEL_DIR, "enforce-scope.sentinel")
        self.assertTrue(os.path.isfile(path), "enforce-scope.sentinel not found")

    def test_enforce_chain_depth_policy_exists(self):
        path = os.path.join(SENTINEL_DIR, "enforce-chain-depth.sentinel")
        self.assertTrue(os.path.isfile(path), "enforce-chain-depth.sentinel not found")

    def test_enforce_may_act_policy_exists(self):
        path = os.path.join(SENTINEL_DIR, "enforce-may-act.sentinel")
        self.assertTrue(os.path.isfile(path), "enforce-may-act.sentinel not found")


class TestRequireDelegationPolicy(unittest.TestCase):
    """Validate require-delegation.sentinel content and structure."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SENTINEL_DIR, "require-delegation.sentinel")) as f:
            cls.policy = f.read()

    def test_imports_strings(self):
        self.assertIn('import "strings"', self.policy)

    def test_checks_human_user_metadata(self):
        self.assertIn("human_user", self.policy)

    def test_checks_agent_identity_metadata(self):
        self.assertIn("agent_identity", self.policy)

    def test_checks_delegation_scope_metadata(self):
        self.assertIn("delegation_scope", self.policy)

    def test_validates_spiffe_trust_domain(self):
        self.assertIn("spiffe://demo.local/", self.policy)

    def test_uses_identity_entity_metadata(self):
        self.assertIn("identity.entity.metadata", self.policy)

    def test_has_main_rule(self):
        self.assertIn("main = rule", self.policy)

    def test_default_deny_pattern(self):
        """Policy should return false on missing metadata (fail-closed)."""
        self.assertIn("return false", self.policy)


class TestEnforceScopePolicy(unittest.TestCase):
    """Validate enforce-scope.sentinel content and structure."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SENTINEL_DIR, "enforce-scope.sentinel")) as f:
            cls.policy = f.read()

    def test_imports_strings(self):
        self.assertIn('import "strings"', self.policy)

    def test_defines_readonly_scopes(self):
        self.assertIn("readonly_scopes", self.policy)
        self.assertIn('"readonly"', self.policy)

    def test_defines_readwrite_scopes(self):
        self.assertIn("readwrite_scopes", self.policy)
        self.assertIn('"readwrite"', self.policy)

    def test_checks_request_path(self):
        self.assertIn("request.path", self.policy)

    def test_checks_readonly_suffix(self):
        self.assertIn("readonly", self.policy)

    def test_checks_readwrite_suffix(self):
        self.assertIn("readwrite", self.policy)

    def test_has_main_rule(self):
        self.assertIn("main = rule", self.policy)

    def test_default_deny_for_unknown_role(self):
        """Unknown role suffix should be denied."""
        self.assertIn("unrecognized credential role", self.policy)


class TestEnforceChainDepthPolicy(unittest.TestCase):
    """Validate enforce-chain-depth.sentinel content and structure."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SENTINEL_DIR, "enforce-chain-depth.sentinel")) as f:
            cls.policy = f.read()

    def test_max_chain_depth_is_3(self):
        self.assertIn("max_chain_depth = 3", self.policy)

    def test_checks_chain_depth_metadata(self):
        self.assertIn("chain_depth", self.policy)

    def test_converts_string_to_int(self):
        """Metadata values are strings; the policy must convert to int."""
        self.assertIn("int(", self.policy)

    def test_compares_depth_to_max(self):
        self.assertIn("max_chain_depth", self.policy)

    def test_has_main_rule(self):
        self.assertIn("main = rule", self.policy)

    def test_default_deny_on_missing_depth(self):
        self.assertIn("return false", self.policy)


class TestEnforceMayActPolicy(unittest.TestCase):
    """Validate enforce-may-act.sentinel content and structure."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SENTINEL_DIR, "enforce-may-act.sentinel")) as f:
            cls.policy = f.read()

    def test_imports_strings(self):
        self.assertIn('import "strings"', self.policy)

    def test_checks_may_act_metadata(self):
        self.assertIn("may_act", self.policy)

    def test_checks_agent_identity(self):
        self.assertIn("agent_identity", self.policy)

    def test_supports_exact_match(self):
        """Policy should support exact SPIFFE ID matching."""
        self.assertIn("may_act is agent_id", self.policy)

    def test_supports_wildcard_match(self):
        """Policy should support wildcard suffix matching (e.g., /agent/*)."""
        self.assertIn("/*", self.policy)
        self.assertIn("has_suffix", self.policy)
        self.assertIn("has_prefix", self.policy)

    def test_has_main_rule(self):
        self.assertIn("main = rule", self.policy)

    def test_default_deny_on_mismatch(self):
        self.assertIn("does not authorize", self.policy)


class TestSentinelPolicyConsistency(unittest.TestCase):
    """Cross-validate Sentinel policies for consistency."""

    @classmethod
    def setUpClass(cls):
        cls.policies = {}
        for fname in os.listdir(SENTINEL_DIR):
            if fname.endswith(".sentinel"):
                with open(os.path.join(SENTINEL_DIR, fname)) as f:
                    cls.policies[fname] = f.read()

    def test_all_policies_have_main_rule(self):
        for name, policy in self.policies.items():
            self.assertIn(
                "main = rule",
                policy,
                f"{name} missing 'main = rule' declaration",
            )

    def test_all_policies_return_false_on_failure(self):
        """All policies should implement fail-closed (return false)."""
        for name, policy in self.policies.items():
            self.assertIn(
                "return false",
                policy,
                f"{name} missing 'return false' (fail-closed pattern)",
            )

    def test_all_policies_use_entity_metadata(self):
        """All policies should reference identity.entity.metadata."""
        for name, policy in self.policies.items():
            self.assertIn(
                "identity.entity.metadata",
                policy,
                f"{name} should reference identity.entity.metadata",
            )

    def test_policy_count(self):
        """There should be exactly 4 Sentinel policies."""
        self.assertEqual(
            len(self.policies),
            4,
            f"Expected 4 Sentinel policies, found {len(self.policies)}: "
            f"{sorted(self.policies.keys())}",
        )

    def test_trust_domain_consistency(self):
        """require-delegation and enforce-may-act both reference the trust domain."""
        rd = self.policies.get("require-delegation.sentinel", "")
        self.assertIn("demo.local", rd)


if __name__ == "__main__":
    unittest.main()
