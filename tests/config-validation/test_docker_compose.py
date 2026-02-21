"""
Docker Compose Configuration Validation Tests

Validates the docker-compose.yml structure, service definitions,
volume mounts, network configuration, health checks, and dependency ordering.
"""

import os
import unittest

import yaml

COMPOSE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "docker-compose.yml"
)


class TestDockerCompose(unittest.TestCase):
    """Validate Docker Compose configuration."""

    @classmethod
    def setUpClass(cls):
        with open(COMPOSE_PATH) as f:
            cls.config = yaml.safe_load(f)

    # ─── Service Existence ───────────────────────────────────────────

    def test_all_services_defined(self):
        expected = {
            "spire-server", "spire-agent", "keycloak", "vault",
            "opa", "postgresql", "identity-gateway", "ai-agent",
            "agentgateway", "token-exchange",
        }
        actual = set(self.config["services"].keys())
        self.assertEqual(expected, actual)

    def test_service_count(self):
        self.assertEqual(len(self.config["services"]), 10)

    # ─── Network Configuration ───────────────────────────────────────

    def test_identity_net_defined(self):
        self.assertIn("identity-net", self.config.get("networks", {}))

    def test_all_services_on_identity_net(self):
        for name, svc in self.config["services"].items():
            self.assertIn(
                "identity-net",
                svc.get("networks", []),
                f"Service '{name}' not on identity-net",
            )

    # ─── Volume Definitions ──────────────────────────────────────────

    def test_required_volumes_defined(self):
        expected_volumes = {
            "spire-server-data", "spire-agent-data", "spire-agent-socket",
            "vault-data", "vault-logs", "postgres-data",
        }
        actual = set(self.config.get("volumes", {}).keys())
        self.assertTrue(
            expected_volumes.issubset(actual),
            f"Missing volumes: {expected_volumes - actual}",
        )

    # ─── SPIRE Server ────────────────────────────────────────────────

    def test_spire_server_image(self):
        svc = self.config["services"]["spire-server"]
        self.assertIn("ghcr.io/spiffe/spire-server", svc["image"])

    def test_spire_server_config_mount(self):
        svc = self.config["services"]["spire-server"]
        volume_strs = [str(v) for v in svc.get("volumes", [])]
        has_config = any("server.conf" in v for v in volume_strs)
        self.assertTrue(has_config, "SPIRE server config not mounted")

    def test_spire_server_healthcheck(self):
        svc = self.config["services"]["spire-server"]
        self.assertIn("healthcheck", svc)

    def test_spire_server_port(self):
        svc = self.config["services"]["spire-server"]
        ports = [str(p) for p in svc.get("ports", [])]
        self.assertTrue(any("8081" in p for p in ports))

    # ─── SPIRE Agent ─────────────────────────────────────────────────

    def test_spire_agent_depends_on_server(self):
        svc = self.config["services"]["spire-agent"]
        deps = svc.get("depends_on", {})
        self.assertIn("spire-server", deps)

    def test_spire_agent_socket_volume(self):
        svc = self.config["services"]["spire-agent"]
        volume_strs = [str(v) for v in svc.get("volumes", [])]
        has_socket = any("spire-agent-socket" in v for v in volume_strs)
        self.assertTrue(has_socket, "SPIRE agent socket volume not mounted")

    def test_spire_agent_host_pid(self):
        svc = self.config["services"]["spire-agent"]
        self.assertEqual(svc.get("pid"), "host")

    # ─── Keycloak ────────────────────────────────────────────────────

    def test_keycloak_image(self):
        svc = self.config["services"]["keycloak"]
        self.assertIn("keycloak", svc["image"])

    def test_keycloak_imports_realm(self):
        svc = self.config["services"]["keycloak"]
        command = svc.get("command", [])
        self.assertIn("--import-realm", command)

    def test_keycloak_realm_mount(self):
        svc = self.config["services"]["keycloak"]
        volume_strs = [str(v) for v in svc.get("volumes", [])]
        has_realm = any("demo-realm.json" in v for v in volume_strs)
        self.assertTrue(has_realm, "Keycloak realm config not mounted")

    def test_keycloak_port(self):
        svc = self.config["services"]["keycloak"]
        ports = [str(p) for p in svc.get("ports", [])]
        self.assertTrue(any("8080" in p for p in ports))

    def test_keycloak_healthcheck(self):
        svc = self.config["services"]["keycloak"]
        self.assertIn("healthcheck", svc)

    def test_keycloak_admin_credentials(self):
        svc = self.config["services"]["keycloak"]
        env = svc.get("environment", {})
        self.assertEqual(env.get("KEYCLOAK_ADMIN"), "admin")

    # ─── Vault ───────────────────────────────────────────────────────

    def test_vault_image(self):
        svc = self.config["services"]["vault"]
        self.assertIn("vault", svc["image"])

    def test_vault_ipc_lock(self):
        svc = self.config["services"]["vault"]
        self.assertIn("IPC_LOCK", svc.get("cap_add", []))

    def test_vault_config_mount(self):
        svc = self.config["services"]["vault"]
        volume_strs = [str(v) for v in svc.get("volumes", [])]
        has_config = any("vault.hcl" in v for v in volume_strs)
        self.assertTrue(has_config, "Vault config not mounted")

    def test_vault_policies_mount(self):
        svc = self.config["services"]["vault"]
        volume_strs = [str(v) for v in svc.get("volumes", [])]
        has_policies = any("policies" in v for v in volume_strs)
        self.assertTrue(has_policies, "Vault policies not mounted")

    def test_vault_port(self):
        svc = self.config["services"]["vault"]
        ports = [str(p) for p in svc.get("ports", [])]
        self.assertTrue(any("8200" in p for p in ports))

    def test_vault_healthcheck(self):
        svc = self.config["services"]["vault"]
        self.assertIn("healthcheck", svc)

    # ─── OPA ─────────────────────────────────────────────────────────

    def test_opa_image(self):
        svc = self.config["services"]["opa"]
        self.assertIn("opa", svc["image"])

    def test_opa_loads_delegation_policy(self):
        svc = self.config["services"]["opa"]
        command = svc.get("command", [])
        command_str = " ".join(str(c) for c in command)
        self.assertIn("delegation.rego", command_str)

    def test_opa_loads_data(self):
        svc = self.config["services"]["opa"]
        command = svc.get("command", [])
        command_str = " ".join(str(c) for c in command)
        self.assertIn("data.json", command_str)

    def test_opa_server_mode(self):
        svc = self.config["services"]["opa"]
        command = svc.get("command", [])
        self.assertIn("--server", command)

    def test_opa_port(self):
        svc = self.config["services"]["opa"]
        ports = [str(p) for p in svc.get("ports", [])]
        self.assertTrue(any("8181" in p for p in ports))

    # ─── PostgreSQL ──────────────────────────────────────────────────

    def test_postgresql_image(self):
        svc = self.config["services"]["postgresql"]
        self.assertIn("postgres", svc["image"])

    def test_postgresql_database_name(self):
        svc = self.config["services"]["postgresql"]
        env = svc.get("environment", {})
        self.assertEqual(env.get("POSTGRES_DB"), "appdb")

    def test_postgresql_init_scripts_mount(self):
        svc = self.config["services"]["postgresql"]
        volume_strs = [str(v) for v in svc.get("volumes", [])]
        has_init = any("docker-entrypoint-initdb.d" in v for v in volume_strs)
        self.assertTrue(has_init, "PostgreSQL init scripts not mounted")

    def test_postgresql_pgaudit(self):
        svc = self.config["services"]["postgresql"]
        command = svc.get("command", [])
        command_str = " ".join(str(c) for c in command)
        self.assertIn("pgaudit", command_str)

    def test_postgresql_logging(self):
        svc = self.config["services"]["postgresql"]
        command = svc.get("command", [])
        command_str = " ".join(str(c) for c in command)
        self.assertIn("log_statement=all", command_str)
        self.assertIn("log_connections=on", command_str)

    def test_postgresql_port(self):
        svc = self.config["services"]["postgresql"]
        ports = [str(p) for p in svc.get("ports", [])]
        self.assertTrue(any("5432" in p for p in ports))

    # ─── Identity Gateway ────────────────────────────────────────────

    def test_gateway_build_context(self):
        svc = self.config["services"]["identity-gateway"]
        build = svc.get("build", {})
        self.assertEqual(build.get("context"), "./identity-gateway")

    def test_gateway_depends_on_vault(self):
        svc = self.config["services"]["identity-gateway"]
        deps = svc.get("depends_on", {})
        self.assertIn("vault", deps)

    def test_gateway_depends_on_keycloak(self):
        svc = self.config["services"]["identity-gateway"]
        deps = svc.get("depends_on", {})
        self.assertIn("keycloak", deps)

    def test_gateway_depends_on_opa(self):
        svc = self.config["services"]["identity-gateway"]
        deps = svc.get("depends_on", {})
        self.assertIn("opa", deps)

    def test_gateway_environment(self):
        svc = self.config["services"]["identity-gateway"]
        env = svc.get("environment", {})
        self.assertEqual(env.get("OPA_ENDPOINT"), "http://opa:8181")
        self.assertEqual(env.get("VAULT_ADDR"), "http://vault:8200")
        self.assertEqual(env.get("TRUST_DOMAIN"), "demo.local")

    def test_gateway_spire_socket_mount(self):
        svc = self.config["services"]["identity-gateway"]
        volume_strs = [str(v) for v in svc.get("volumes", [])]
        has_socket = any("spire-agent-socket" in v for v in volume_strs)
        self.assertTrue(has_socket, "Gateway SPIRE socket not mounted")

    # ─── AI Agent ────────────────────────────────────────────────────

    def test_agent_build_context(self):
        svc = self.config["services"]["ai-agent"]
        build = svc.get("build", {})
        self.assertEqual(build.get("context"), "./ai-agent")

    def test_agent_depends_on_gateway(self):
        svc = self.config["services"]["ai-agent"]
        deps = svc.get("depends_on", {})
        self.assertIn("token-exchange", deps)

    def test_agent_depends_on_postgresql(self):
        svc = self.config["services"]["ai-agent"]
        deps = svc.get("depends_on", {})
        self.assertIn("postgresql", deps)

    def test_agent_environment(self):
        svc = self.config["services"]["ai-agent"]
        env = svc.get("environment", {})
        self.assertEqual(env.get("AGENT_MODE"), "wait")
        self.assertEqual(env.get("TRUST_DOMAIN"), "demo.local")
        self.assertEqual(
            env.get("AGENT_SPIFFE_ID"),
            "spiffe://demo.local/agent/query-agent",
        )

    def test_agent_spire_socket_mount(self):
        svc = self.config["services"]["ai-agent"]
        volume_strs = [str(v) for v in svc.get("volumes", [])]
        has_socket = any("spire-agent-socket" in v for v in volume_strs)
        self.assertTrue(has_socket, "Agent SPIRE socket not mounted")

    # ─── Health Check Consistency ────────────────────────────────────

    def test_all_infrastructure_services_have_healthchecks(self):
        """All infrastructure services should have health checks."""
        infra_services = [
            "spire-server", "spire-agent", "keycloak",
            "vault", "opa", "postgresql",
        ]
        for name in infra_services:
            svc = self.config["services"][name]
            self.assertIn(
                "healthcheck",
                svc,
                f"Service '{name}' missing healthcheck",
            )

    # ─── Dependency Graph ────────────────────────────────────────────

    def test_no_circular_dependencies(self):
        """Verify no circular dependencies in the service graph."""
        services = self.config["services"]
        visited = set()
        in_stack = set()

        def has_cycle(service):
            if service in in_stack:
                return True
            if service in visited:
                return False
            visited.add(service)
            in_stack.add(service)
            deps = services.get(service, {}).get("depends_on", {})
            if isinstance(deps, list):
                dep_names = deps
            elif isinstance(deps, dict):
                dep_names = deps.keys()
            else:
                dep_names = []
            for dep in dep_names:
                if has_cycle(dep):
                    return True
            in_stack.discard(service)
            return False

        for svc_name in services:
            self.assertFalse(
                has_cycle(svc_name),
                f"Circular dependency detected involving '{svc_name}'",
            )


if __name__ == "__main__":
    unittest.main()
