"""
SPIRE Configuration Validation Tests

Validates the SPIRE server and agent configuration files.
"""

import os
import unittest

SPIRE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "spire")


class TestSPIREServerConfig(unittest.TestCase):
    """Validate SPIRE server configuration."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SPIRE_DIR, "server", "server.conf")) as f:
            cls.config = f.read()

    def test_trust_domain(self):
        self.assertIn('trust_domain = "demo.local"', self.config)

    def test_bind_address(self):
        self.assertIn('bind_address = "0.0.0.0"', self.config)

    def test_bind_port(self):
        self.assertIn('bind_port = "8081"', self.config)

    def test_data_dir(self):
        self.assertIn("data_dir", self.config)

    def test_log_level(self):
        self.assertIn('log_level = "DEBUG"', self.config)

    def test_ca_ttl(self):
        self.assertIn('ca_ttl = "24h"', self.config)

    def test_svid_ttl(self):
        self.assertIn('default_x509_svid_ttl = "1h"', self.config)
        self.assertIn('default_jwt_svid_ttl = "1h"', self.config)

    def test_datastore_plugin(self):
        self.assertIn('DataStore "sql"', self.config)
        self.assertIn("sqlite3", self.config)

    def test_node_attestor(self):
        self.assertIn('NodeAttestor "join_token"', self.config)

    def test_key_manager(self):
        self.assertIn('KeyManager "disk"', self.config)

    def test_ca_subject(self):
        self.assertIn("ca_subject", self.config)
        self.assertIn("Demo SPIRE CA", self.config)


class TestSPIREAgentConfig(unittest.TestCase):
    """Validate SPIRE agent configuration."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SPIRE_DIR, "agent", "agent.conf")) as f:
            cls.config = f.read()

    def test_trust_domain(self):
        self.assertIn('trust_domain = "demo.local"', self.config)

    def test_server_address(self):
        self.assertIn('server_address = "spire-server"', self.config)

    def test_server_port(self):
        self.assertIn('server_port = "8081"', self.config)

    def test_socket_path(self):
        self.assertIn("socket_path", self.config)
        self.assertIn("/tmp/spire-agent", self.config)

    def test_node_attestor(self):
        self.assertIn('NodeAttestor "join_token"', self.config)

    def test_workload_attestor(self):
        self.assertIn('WorkloadAttestor "unix"', self.config)

    def test_key_manager(self):
        self.assertIn('KeyManager "disk"', self.config)

    def test_data_dir(self):
        self.assertIn("data_dir", self.config)


class TestSPIREConfigConsistency(unittest.TestCase):
    """Cross-validate SPIRE server and agent configs."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SPIRE_DIR, "server", "server.conf")) as f:
            cls.server_config = f.read()
        with open(os.path.join(SPIRE_DIR, "agent", "agent.conf")) as f:
            cls.agent_config = f.read()

    def test_same_trust_domain(self):
        self.assertIn("demo.local", self.server_config)
        self.assertIn("demo.local", self.agent_config)

    def test_agent_points_to_server_port(self):
        """Agent server_port should match server bind_port."""
        self.assertIn('"8081"', self.server_config)
        self.assertIn('"8081"', self.agent_config)

    def test_matching_node_attestor(self):
        """Both must use the same node attestor type."""
        self.assertIn("join_token", self.server_config)
        self.assertIn("join_token", self.agent_config)


if __name__ == "__main__":
    unittest.main()
