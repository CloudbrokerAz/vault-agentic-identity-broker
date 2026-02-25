"""
Vault Policy Validation Tests

Validates the HCL policy files for correct structure and security properties.
"""

import os
import re
import unittest

POLICIES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "vault", "policies"
)


class TestVaultPolicies(unittest.TestCase):
    """Validate Vault HCL policy files."""

    @classmethod
    def setUpClass(cls):
        cls.policies = {}
        for fname in os.listdir(POLICIES_DIR):
            if fname.endswith(".hcl"):
                path = os.path.join(POLICIES_DIR, fname)
                with open(path) as f:
                    cls.policies[fname] = f.read()

    # ─── File Existence ──────────────────────────────────────────────

    def test_required_policies_exist(self):
        expected = {"ai-agent-db-read.hcl", "ai-agent-db-readwrite.hcl", "admin-policy.hcl"}
        actual = set(self.policies.keys())
        self.assertTrue(
            expected.issubset(actual),
            f"Missing policies: {expected - actual}",
        )

    def test_gateway_policy_removed(self):
        """gateway-policy.hcl must not exist — no broker token in new architecture."""
        self.assertNotIn(
            "gateway-policy.hcl",
            self.policies,
            "gateway-policy.hcl should be deleted (no broker token in new auth model)",
        )

    # ─── AI Agent Read Policy ────────────────────────────────────────

    def test_agent_read_policy_grants_db_read(self):
        policy = self.policies["ai-agent-db-read.hcl"]
        self.assertIn("database/creds/ai-agent-readonly", policy)
        self.assertIn('"read"', policy)

    def test_agent_read_policy_allows_self_lookup(self):
        policy = self.policies["ai-agent-db-read.hcl"]
        self.assertIn("auth/token/lookup-self", policy)

    def test_agent_read_policy_allows_self_renew(self):
        policy = self.policies["ai-agent-db-read.hcl"]
        self.assertIn("auth/token/renew-self", policy)

    def test_agent_read_policy_allows_lease_management(self):
        policy = self.policies["ai-agent-db-read.hcl"]
        self.assertIn("sys/leases/renew", policy)
        self.assertIn("sys/leases/revoke", policy)

    def test_agent_read_policy_denies_sys(self):
        policy = self.policies["ai-agent-db-read.hcl"]
        self.assertIn('path "sys/*"', policy)
        self.assertIn('"deny"', policy)

    def test_agent_read_policy_denies_secret(self):
        policy = self.policies["ai-agent-db-read.hcl"]
        self.assertIn('path "secret/*"', policy)

    def test_agent_read_policy_denies_identity(self):
        """Agents must not be able to self-attest delegation metadata."""
        policy = self.policies["ai-agent-db-read.hcl"]
        self.assertIn('path "identity/*"', policy)
        # Verify it's a deny rule
        block = self._extract_path_block(policy, "identity/*")
        self.assertIn('"deny"', block, "identity/* must be denied for agents")

    def test_agent_read_policy_no_templated_paths(self):
        """Templated paths removed — Sentinel handles scope enforcement."""
        policy = self.policies["ai-agent-db-read.hcl"]
        self.assertNotIn("{{identity.entity.metadata", policy)

    def test_agent_read_policy_no_write_capabilities(self):
        """Agent should not have write, create, update, delete on database paths."""
        policy = self.policies["ai-agent-db-read.hcl"]
        db_section = self._extract_path_block(policy, "database/creds/ai-agent-readonly")
        if db_section:
            for cap in ["create", "update", "delete", "list"]:
                self.assertNotIn(
                    f'"{cap}"',
                    db_section,
                    f"Agent policy should not have '{cap}' on database/creds path",
                )

    # ─── AI Agent Readwrite Policy ───────────────────────────────────

    def test_agent_readwrite_policy_grants_db_readwrite(self):
        policy = self.policies["ai-agent-db-readwrite.hcl"]
        self.assertIn("database/creds/ai-agent-readwrite", policy)

    def test_agent_readwrite_policy_grants_db_readonly(self):
        """Readwrite implies read access."""
        policy = self.policies["ai-agent-db-readwrite.hcl"]
        self.assertIn("database/creds/ai-agent-readonly", policy)

    def test_agent_readwrite_policy_denies_identity(self):
        """Agents must not be able to self-attest delegation metadata."""
        policy = self.policies["ai-agent-db-readwrite.hcl"]
        self.assertIn('path "identity/*"', policy)
        block = self._extract_path_block(policy, "identity/*")
        self.assertIn('"deny"', block, "identity/* must be denied for agents")

    def test_agent_readwrite_policy_no_templated_paths(self):
        """Templated paths removed — Sentinel handles scope enforcement."""
        policy = self.policies["ai-agent-db-readwrite.hcl"]
        self.assertNotIn("{{identity.entity.metadata", policy)

    def test_agent_readwrite_policy_allows_lease_management(self):
        policy = self.policies["ai-agent-db-readwrite.hcl"]
        self.assertIn("sys/leases/renew", policy)
        self.assertIn("sys/leases/revoke", policy)

    def test_agent_readwrite_policy_denies_sys(self):
        policy = self.policies["ai-agent-db-readwrite.hcl"]
        self.assertIn('path "sys/*"', policy)

    def test_agent_readwrite_policy_denies_secret(self):
        policy = self.policies["ai-agent-db-readwrite.hcl"]
        self.assertIn('path "secret/*"', policy)

    # ─── Admin Policy ────────────────────────────────────────────────

    def test_admin_policy_full_access(self):
        policy = self.policies["admin-policy.hcl"]
        self.assertIn('path "*"', policy)
        self.assertIn('"sudo"', policy)

    # ─── General Security Checks ─────────────────────────────────────

    def test_no_wildcard_in_agent_policies(self):
        """Agent policies should not contain wildcard paths (except deny rules)."""
        for name in ("ai-agent-db-read.hcl", "ai-agent-db-readwrite.hcl"):
            policy = self.policies[name]
            # Remove deny-rule lines for this check (sys/*, secret/*, identity/*)
            lines = [
                l for l in policy.split("\n")
                if "sys/*" not in l and "secret/*" not in l and "identity/*" not in l
            ]
            clean = "\n".join(lines)
            self.assertNotIn(
                'path "*"', clean, f"{name} should not have wildcard path"
            )

    def test_all_policies_have_capabilities(self):
        """Every policy should define at least one capabilities block."""
        for name, policy in self.policies.items():
            self.assertIn(
                "capabilities",
                policy,
                f"Policy {name} missing capabilities definition",
            )

    def test_all_policies_have_path_blocks(self):
        """Every policy should define at least one path block."""
        for name, policy in self.policies.items():
            self.assertIn(
                "path ",
                policy,
                f"Policy {name} missing path definition",
            )

    # ─── Helper ──────────────────────────────────────────────────────

    def _extract_path_block(self, policy: str, path: str) -> str:
        """Extract the HCL block for a given path."""
        pattern = rf'path\s+"{re.escape(path)}"\s*\{{([^}}]*)\}}'
        match = re.search(pattern, policy, re.DOTALL)
        return match.group(1) if match else ""


class TestVaultConfig(unittest.TestCase):
    """Validate Vault server configuration."""

    @classmethod
    def setUpClass(cls):
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "vault", "config", "vault.hcl"
        )
        with open(config_path) as f:
            cls.config = f.read()

    def test_storage_backend(self):
        self.assertIn('storage "file"', self.config)

    def test_listener_config(self):
        self.assertIn('listener "tcp"', self.config)
        self.assertIn("0.0.0.0:8200", self.config)

    def test_tls_disabled_for_demo(self):
        self.assertIn("tls_disable = 1", self.config)

    def test_ui_enabled(self):
        self.assertIn("ui = true", self.config)

    def test_mlock_disabled_for_containers(self):
        self.assertIn("disable_mlock = true", self.config)

    def test_log_level(self):
        self.assertIn('log_level = "debug"', self.config)


if __name__ == "__main__":
    unittest.main()
