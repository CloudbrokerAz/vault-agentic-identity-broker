"""
Sentinel Policy Logic Validation Tests

Tests the POLICY LOGIC of each Sentinel Endpoint Governing Policy by parsing
the policy files and verifying that the expected rules, field checks,
comparison operators, and deny conditions are present.

These are deeper than the existence/structure tests in test_sentinel_policies.py.
They verify the actual enforcement logic each policy implements.
"""

import os
import re
import unittest

SENTINEL_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "sentinel-policies"
)
SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
BOOTSTRAP_PATH = os.path.join(SCRIPTS_DIR, "bootstrap.sh")


class TestRequireDelegationLogic(unittest.TestCase):
    """Verify require-delegation.sentinel enforces all required metadata fields."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SENTINEL_DIR, "require-delegation.sentinel")) as f:
            cls.policy = f.read()

    def test_checks_human_user_presence(self):
        """Policy must check that human_user is in entity metadata keys."""
        self.assertIn('"human_user" not in keys(meta)', self.policy)

    def test_checks_human_user_non_empty(self):
        """Policy must reject empty human_user values."""
        self.assertIn('meta["human_user"] is ""', self.policy)

    def test_checks_agent_identity_presence(self):
        """Policy must check that agent_identity is in entity metadata keys."""
        self.assertIn('"agent_identity" not in keys(meta)', self.policy)

    def test_checks_agent_identity_non_empty(self):
        """Policy must reject empty agent_identity values."""
        self.assertIn('meta["agent_identity"] is ""', self.policy)

    def test_checks_delegation_scope_presence(self):
        """Policy must check that delegation_scope is in entity metadata keys."""
        self.assertIn('"delegation_scope" not in keys(meta)', self.policy)

    def test_checks_delegation_scope_non_empty(self):
        """Policy must reject empty delegation_scope values."""
        self.assertIn('meta["delegation_scope"] is ""', self.policy)

    def test_denies_missing_human_user(self):
        """Policy must print DENIED message for missing human_user."""
        self.assertIn("DENIED: missing or empty 'human_user'", self.policy)

    def test_denies_missing_agent_identity(self):
        """Policy must print DENIED message for missing agent_identity."""
        self.assertIn("DENIED: missing or empty 'agent_identity'", self.policy)

    def test_denies_missing_delegation_scope(self):
        """Policy must print DENIED message for missing delegation_scope."""
        self.assertIn("DENIED: missing or empty 'delegation_scope'", self.policy)

    def test_validates_spiffe_trust_domain_prefix(self):
        """Policy must validate agent identity starts with spiffe://demo.local/."""
        self.assertIn('has_prefix(meta["agent_identity"], "spiffe://demo.local/")', self.policy)

    def test_denies_wrong_trust_domain(self):
        """Policy must have a deny message for agents outside the trust domain."""
        self.assertIn("agent_identity is not in trust domain", self.policy)

    def test_returns_false_on_each_failure(self):
        """Each metadata check must return false on failure (fail-closed)."""
        # Count the number of 'return false' statements — one per field check
        # plus one for trust domain validation = at least 4
        false_count = self.policy.count("return false")
        self.assertGreaterEqual(
            false_count, 4,
            f"Expected at least 4 'return false' statements, found {false_count}",
        )

    def test_returns_true_on_success(self):
        """Policy must return true when all checks pass."""
        self.assertIn("return true", self.policy)

    def test_three_required_metadata_fields(self):
        """All three required fields must be checked: human_user, agent_identity, delegation_scope."""
        required = ["human_user", "agent_identity", "delegation_scope"]
        for field in required:
            with self.subTest(field=field):
                # Each field must appear in both a 'not in keys' and 'is ""' check
                self.assertIn(f'"{field}" not in keys(meta)', self.policy)
                self.assertIn(f'meta["{field}"] is ""', self.policy)


class TestEnforceScopeLogic(unittest.TestCase):
    """Verify enforce-scope.sentinel maps scopes to credential roles correctly."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SENTINEL_DIR, "enforce-scope.sentinel")) as f:
            cls.policy = f.read()

    def test_readonly_scopes_include_readonly(self):
        """readonly_scopes list must include 'readonly'."""
        self.assertIn('"readonly"', self.policy)
        # Verify it is part of the readonly_scopes list
        match = re.search(r'readonly_scopes\s*=\s*\[([^\]]+)\]', self.policy)
        self.assertIsNotNone(match, "readonly_scopes list not found")
        self.assertIn('"readonly"', match.group(1))

    def test_readonly_scopes_include_db_read(self):
        """readonly_scopes list must include 'db:read'."""
        match = re.search(r'readonly_scopes\s*=\s*\[([^\]]+)\]', self.policy)
        self.assertIsNotNone(match)
        self.assertIn('"db:read"', match.group(1))

    def test_readonly_scopes_include_db_query(self):
        """readonly_scopes list must include 'db:query'."""
        match = re.search(r'readonly_scopes\s*=\s*\[([^\]]+)\]', self.policy)
        self.assertIsNotNone(match)
        self.assertIn('"db:query"', match.group(1))

    def test_readwrite_scopes_include_readwrite(self):
        """readwrite_scopes list must include 'readwrite'."""
        match = re.search(r'readwrite_scopes\s*=\s*\[([^\]]+)\]', self.policy)
        self.assertIsNotNone(match)
        self.assertIn('"readwrite"', match.group(1))

    def test_readwrite_scopes_include_db_write(self):
        """readwrite_scopes list must include 'db:write'."""
        match = re.search(r'readwrite_scopes\s*=\s*\[([^\]]+)\]', self.policy)
        self.assertIsNotNone(match)
        self.assertIn('"db:write"', match.group(1))

    def test_checks_readonly_path_suffix(self):
        """Policy must check if request path ends with 'readonly'."""
        self.assertIn('has_suffix(path, "readonly")', self.policy)

    def test_checks_readwrite_path_suffix(self):
        """Policy must check if request path ends with 'readwrite'."""
        self.assertIn('has_suffix(path, "readwrite")', self.policy)

    def test_readonly_scope_membership_check(self):
        """Policy must check scope membership in readonly_scopes list."""
        self.assertIn("scope not in readonly_scopes", self.policy)

    def test_readwrite_scope_membership_check(self):
        """Policy must check scope membership in readwrite_scopes list."""
        self.assertIn("scope not in readwrite_scopes", self.policy)

    def test_denies_unknown_path_suffix(self):
        """Policy must deny requests with unrecognized role suffix."""
        self.assertIn("unrecognized credential role in path", self.policy)

    def test_denies_scope_mismatch_for_readonly(self):
        """Policy must print DENIED for scope not matching readonly."""
        self.assertIn("not permitted for readonly credentials", self.policy)

    def test_denies_scope_mismatch_for_readwrite(self):
        """Policy must print DENIED for scope not matching readwrite."""
        self.assertIn("not permitted for readwrite credentials", self.policy)

    def test_unknown_suffix_returns_false(self):
        """Unknown role suffix must cause the function to return false."""
        # After the "unrecognized credential role" print, there must be a return false
        idx_unrecognized = self.policy.index("unrecognized credential role")
        remaining = self.policy[idx_unrecognized:]
        self.assertIn("return false", remaining)

    def test_uses_request_path(self):
        """Policy must extract the request path from request.path."""
        self.assertIn("path = request.path", self.policy)

    def test_guards_missing_delegation_scope(self):
        """Policy must guard against missing delegation_scope in metadata."""
        self.assertIn('"delegation_scope" not in keys(meta)', self.policy)


class TestEnforceChainDepthLogic(unittest.TestCase):
    """Verify enforce-chain-depth.sentinel correctly limits delegation depth."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SENTINEL_DIR, "enforce-chain-depth.sentinel")) as f:
            cls.policy = f.read()

    def test_max_depth_is_3(self):
        """Maximum allowed chain depth must be 3."""
        self.assertIn("max_chain_depth = 3", self.policy)

    def test_checks_chain_depth_key_exists(self):
        """Policy must check that chain_depth key exists in metadata."""
        self.assertIn('"chain_depth" not in keys(meta)', self.policy)

    def test_converts_depth_to_integer(self):
        """Policy must convert string metadata to int for comparison."""
        self.assertIn('int(meta["chain_depth"])', self.policy)

    def test_compares_depth_greater_than_max(self):
        """Policy must use > comparison against max_chain_depth."""
        self.assertIn("depth > max_chain_depth", self.policy)

    def test_denies_missing_chain_depth(self):
        """Policy must deny requests with missing chain_depth metadata."""
        self.assertIn("DENIED: missing 'chain_depth'", self.policy)

    def test_denies_excessive_depth(self):
        """Policy must deny requests where depth exceeds maximum."""
        self.assertIn("exceeds maximum of", self.policy)

    def test_allows_depth_at_or_below_max(self):
        """Policy must return true when depth <= max (using > not >=)."""
        # The comparison is 'depth > max_chain_depth', so depth == 3 is allowed
        self.assertIn("depth > max_chain_depth", self.policy)
        # Must NOT use >= which would reject depth==3
        self.assertNotIn("depth >= max_chain_depth", self.policy)

    def test_returns_false_on_missing_depth(self):
        """Missing chain_depth must cause return false."""
        idx_missing = self.policy.index('"chain_depth" not in keys(meta)')
        # Find the return false that follows
        remaining = self.policy[idx_missing:idx_missing + 200]
        self.assertIn("return false", remaining)

    def test_returns_false_on_excessive_depth(self):
        """Excessive depth must cause return false."""
        idx_exceeds = self.policy.index("depth > max_chain_depth")
        remaining = self.policy[idx_exceeds:idx_exceeds + 200]
        self.assertIn("return false", remaining)


class TestEnforceMayActLogic(unittest.TestCase):
    """Verify enforce-may-act.sentinel validates authorization patterns."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SENTINEL_DIR, "enforce-may-act.sentinel")) as f:
            cls.policy = f.read()

    def test_checks_may_act_presence(self):
        """Policy must check that may_act exists in metadata keys."""
        self.assertIn('"may_act" not in keys(meta)', self.policy)

    def test_checks_may_act_non_empty(self):
        """Policy must reject empty may_act values."""
        self.assertIn('meta["may_act"] is ""', self.policy)

    def test_checks_agent_identity_presence(self):
        """Policy must check that agent_identity exists for comparison."""
        self.assertIn('"agent_identity" not in keys(meta)', self.policy)

    def test_checks_agent_identity_non_empty(self):
        """Policy must reject empty agent_identity."""
        self.assertIn('meta["agent_identity"] is ""', self.policy)

    def test_exact_match_comparison(self):
        """Policy must support exact match: may_act == agent_id."""
        self.assertIn("may_act is agent_id", self.policy)

    def test_wildcard_suffix_detection(self):
        """Policy must detect wildcard suffix '/*' in may_act."""
        self.assertIn('has_suffix(may_act, "/*")', self.policy)

    def test_wildcard_prefix_extraction(self):
        """Policy must extract prefix by trimming '*' from may_act."""
        self.assertIn('trim_suffix(may_act, "*")', self.policy)

    def test_wildcard_prefix_matching(self):
        """Policy must check if agent_id starts with the wildcard prefix."""
        self.assertIn("has_prefix(agent_id, prefix)", self.policy)

    def test_denies_missing_may_act(self):
        """Policy must deny requests with missing may_act metadata."""
        self.assertIn("DENIED: missing or empty 'may_act'", self.policy)

    def test_denies_missing_agent_identity_for_comparison(self):
        """Policy must deny when agent_identity is missing for may_act comparison."""
        self.assertIn("DENIED: missing 'agent_identity' for may_act comparison", self.policy)

    def test_denies_unauthorized_agent(self):
        """Policy must deny when may_act does not authorize the agent."""
        self.assertIn("does not authorize agent", self.policy)

    def test_exact_match_returns_true(self):
        """Exact match must return true immediately."""
        idx_exact = self.policy.index("may_act is agent_id")
        remaining = self.policy[idx_exact:idx_exact + 100]
        self.assertIn("return true", remaining)

    def test_wildcard_match_returns_true(self):
        """Wildcard match must return true."""
        idx_prefix = self.policy.index("has_prefix(agent_id, prefix)")
        remaining = self.policy[idx_prefix:idx_prefix + 100]
        self.assertIn("return true", remaining)

    def test_final_deny_returns_false(self):
        """After all match attempts, policy must return false (default deny)."""
        idx_does_not = self.policy.index("does not authorize agent")
        remaining = self.policy[idx_does_not:]
        self.assertIn("return false", remaining)


class TestVaultAuditLoggingInBootstrap(unittest.TestCase):
    """Verify that bootstrap.sh enables Vault audit logging."""

    @classmethod
    def setUpClass(cls):
        with open(BOOTSTRAP_PATH) as f:
            cls.script = f.read()

    def test_bootstrap_enables_audit_device(self):
        """Bootstrap must enable a Vault audit device via sys/audit."""
        self.assertIn("sys/audit", self.script)

    def test_audit_device_is_file_type(self):
        """Bootstrap must configure a file-based audit device."""
        self.assertIn("sys/audit/file", self.script)

    def test_audit_step_exists(self):
        """Bootstrap must have a dedicated step for audit logging."""
        # Step 4 is 'Enabling Vault audit logging'
        self.assertIn("audit", self.script.lower())
        self.assertIn("log_step 4", self.script)

    def test_audit_uses_vault_token(self):
        """Audit logging configuration must authenticate with Vault token."""
        # Find the sys/audit/file call and verify X-Vault-Token is nearby
        idx = self.script.index("sys/audit/file")
        surrounding = self.script[max(0, idx - 200):idx + 400]
        self.assertIn("X-Vault-Token", surrounding)


if __name__ == "__main__":
    unittest.main()
