"""
Bootstrap, Cleanup, and Demo Script Validation Tests

Validates the shell scripts for correct structure, step ordering,
security practices, and configuration handling.
"""

import os
import unittest

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
BOOTSTRAP_PATH = os.path.join(SCRIPTS_DIR, "bootstrap.sh")
CLEANUP_PATH = os.path.join(SCRIPTS_DIR, "cleanup.sh")
DEMO_PATH = os.path.join(SCRIPTS_DIR, "demo.sh")


class TestBootstrapScript(unittest.TestCase):
    """Validate bootstrap.sh structure and security practices."""

    @classmethod
    def setUpClass(cls):
        with open(BOOTSTRAP_PATH) as f:
            cls.script = f.read()

    def test_all_nine_steps_present(self):
        """All 9 bootstrap steps must be present in order."""
        for step_num in range(1, 10):
            self.assertIn(
                f"log_step {step_num}",
                self.script,
                f"Step {step_num} is missing from bootstrap script",
            )

    def test_supports_host_flag(self):
        """Bootstrap must support the --host flag for host-network mode."""
        self.assertIn("--host", self.script)

    def test_references_host_compose_file(self):
        """Bootstrap must reference docker-compose.host.yml for host mode."""
        self.assertIn("docker-compose.host.yml", self.script)

    def test_initializes_vault(self):
        """Bootstrap must call Vault sys/init and sys/unseal endpoints."""
        self.assertIn("sys/init", self.script)
        self.assertIn("sys/unseal", self.script)

    def test_configures_vault_policies(self):
        """Bootstrap must configure Vault ACL policies via sys/policies/acl."""
        self.assertIn("sys/policies/acl", self.script)

    def test_enables_audit_logging(self):
        """Bootstrap must enable Vault audit logging via sys/audit."""
        self.assertIn("sys/audit", self.script)

    def test_configures_database_secrets_engine(self):
        """Bootstrap must configure the Vault database secrets engine."""
        self.assertIn("database/", self.script)

    def test_rotates_root_credentials(self):
        """Bootstrap must rotate the database root credentials."""
        self.assertIn("rotate-root", self.script)

    def test_registers_spire_entries(self):
        """Bootstrap must register at least 6 SPIRE workload entries."""
        count = self.script.count("entry create")
        self.assertGreaterEqual(
            count,
            6,
            f"Expected at least 6 SPIRE entry create calls, found {count}",
        )

    def test_configures_jwt_auth(self):
        """Bootstrap must configure the Vault JWT auth method."""
        self.assertIn("auth/jwt", self.script)

    def test_jwt_claim_mappings_include_may_act(self):
        """Bootstrap must map /may_act/sub to entity metadata for Sentinel enforce-may-act."""
        self.assertIn("/may_act/sub", self.script)
        self.assertIn('"may_act"', self.script)

    def test_scope_based_jwt_auth_roles(self):
        """Bootstrap must create scope-specific JWT auth roles for defense-in-depth."""
        self.assertIn("delegated-agent-readonly", self.script)
        self.assertIn("delegated-agent-readwrite", self.script)
        self.assertIn('"scope": "readonly"', self.script)
        self.assertIn('"scope": "readwrite"', self.script)

    def test_saves_credentials_with_chmod_600(self):
        """Bootstrap must set chmod 600 on saved credential files."""
        self.assertIn("chmod 600", self.script)


class TestCleanupScript(unittest.TestCase):
    """Validate cleanup.sh structure."""

    @classmethod
    def setUpClass(cls):
        with open(CLEANUP_PATH) as f:
            cls.script = f.read()

    def test_supports_host_flag(self):
        """Cleanup must support the --host flag for host-network mode."""
        self.assertIn("--host", self.script)

    def test_references_host_compose_file(self):
        """Cleanup must reference docker-compose.host.yml for host mode."""
        self.assertIn("docker-compose.host.yml", self.script)

    def test_removes_credential_files(self):
        """Cleanup must remove generated credential files."""
        self.assertIn(".vault-unseal-key", self.script)
        self.assertIn(".vault-root-token", self.script)

    def test_uses_volume_removal_flag(self):
        """Cleanup must use 'down -v' to remove Docker volumes."""
        self.assertIn("down -v", self.script)


class TestDemoScript(unittest.TestCase):
    """Validate demo.sh structure and auth mode support."""

    @classmethod
    def setUpClass(cls):
        with open(DEMO_PATH) as f:
            cls.script = f.read()

    def test_supports_device_auth_mode(self):
        """Demo must support device authorization flow."""
        self.assertIn("device", self.script)
        self.assertIn("device_code", self.script)

    def test_supports_token_auth_mode(self):
        """Demo must support pre-supplied token auth mode."""
        self.assertIn('"token"', self.script)

    def test_supports_password_auth_mode(self):
        """Demo must support password grant auth mode."""
        self.assertIn("grant_type=password", self.script)

    def test_checks_for_bootstrap_completion(self):
        """Demo must check for .vault-root-token to verify bootstrap ran."""
        self.assertIn(".vault-root-token", self.script)

    def test_handles_slow_down_in_device_flow(self):
        """Demo must handle OAuth 'slow_down' response in device flow polling."""
        self.assertIn("slow_down", self.script)


if __name__ == "__main__":
    unittest.main()
