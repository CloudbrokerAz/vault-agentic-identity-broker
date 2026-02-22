"""
Keycloak Realm Configuration Validation Tests

Validates the demo-realm.json structure, users, clients, groups,
protocol mappers, and security settings.
"""

import json
import os
import unittest

REALM_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "keycloak", "realm", "demo-realm.json"
)


class TestKeycloakRealmConfig(unittest.TestCase):
    """Validate Keycloak realm configuration."""

    @classmethod
    def setUpClass(cls):
        with open(REALM_PATH) as f:
            cls.realm = json.load(f)

    # ─── Realm Settings ─────────────────────────────────────────────

    def test_realm_name(self):
        self.assertEqual(self.realm["realm"], "demo")

    def test_realm_enabled(self):
        self.assertTrue(self.realm["enabled"])

    def test_ssl_required_for_demo(self):
        self.assertEqual(self.realm["sslRequired"], "none")

    def test_registration_disabled(self):
        self.assertFalse(self.realm["registrationAllowed"])

    def test_brute_force_protection(self):
        self.assertTrue(self.realm["bruteForceProtected"])

    def test_access_token_lifespan(self):
        """Access tokens should be short-lived (5 min for demo)."""
        self.assertEqual(self.realm["accessTokenLifespan"], 300)

    def test_signature_algorithm(self):
        self.assertEqual(self.realm["defaultSignatureAlgorithm"], "RS256")

    # ─── Roles ───────────────────────────────────────────────────────

    def test_realm_roles_exist(self):
        roles = {r["name"] for r in self.realm["roles"]["realm"]}
        self.assertIn("data-analyst", roles)
        self.assertIn("data-engineer", roles)
        self.assertIn("admin", roles)

    def test_role_descriptions(self):
        for role in self.realm["roles"]["realm"]:
            self.assertTrue(
                role.get("description"),
                f"Role '{role['name']}' missing description",
            )

    # ─── Groups ──────────────────────────────────────────────────────

    def test_groups_exist(self):
        groups = {g["name"] for g in self.realm["groups"]}
        self.assertEqual(groups, {"data-analysts", "trading-team", "engineering"})

    def test_groups_have_roles(self):
        for group in self.realm["groups"]:
            self.assertTrue(
                group.get("realmRoles"),
                f"Group '{group['name']}' has no roles assigned",
            )

    def test_data_analysts_group_role(self):
        group = next(g for g in self.realm["groups"] if g["name"] == "data-analysts")
        self.assertIn("data-analyst", group["realmRoles"])

    def test_engineering_group_role(self):
        group = next(g for g in self.realm["groups"] if g["name"] == "engineering")
        self.assertIn("data-engineer", group["realmRoles"])

    # ─── Users ───────────────────────────────────────────────────────

    def test_users_exist(self):
        usernames = {u["username"] for u in self.realm["users"]}
        self.assertIn("alice", usernames)
        self.assertIn("bob", usernames)

    def test_alice_config(self):
        alice = next(u for u in self.realm["users"] if u["username"] == "alice")
        self.assertTrue(alice["enabled"])
        self.assertEqual(alice["email"], "alice@acme.com")
        self.assertTrue(alice["emailVerified"])
        self.assertIn("data-analysts", alice["groups"])
        self.assertIn("trading-team", alice["groups"])
        self.assertIn("data-analyst", alice["realmRoles"])

    def test_bob_config(self):
        bob = next(u for u in self.realm["users"] if u["username"] == "bob")
        self.assertTrue(bob["enabled"])
        self.assertEqual(bob["email"], "bob@acme.com")
        self.assertIn("engineering", bob["groups"])
        self.assertIn("data-engineer", bob["realmRoles"])

    def test_users_have_credentials(self):
        for user in self.realm["users"]:
            self.assertTrue(
                user.get("credentials"),
                f"User '{user['username']}' has no credentials",
            )
            cred = user["credentials"][0]
            self.assertEqual(cred["type"], "password")
            self.assertFalse(cred["temporary"])

    # ─── Clients ─────────────────────────────────────────────────────

    def test_clients_exist(self):
        client_ids = {c["clientId"] for c in self.realm["clients"]}
        self.assertIn("ai-agent-service", client_ids)
        self.assertIn("demo-cli", client_ids)

    def test_ai_agent_service_config(self):
        client = next(
            c for c in self.realm["clients"] if c["clientId"] == "ai-agent-service"
        )
        self.assertTrue(client["enabled"])
        self.assertFalse(client["publicClient"])
        self.assertTrue(client["serviceAccountsEnabled"])
        self.assertTrue(client["directAccessGrantsEnabled"])
        self.assertEqual(client["protocol"], "openid-connect")

    def test_ai_agent_service_token_exchange(self):
        client = next(
            c for c in self.realm["clients"] if c["clientId"] == "ai-agent-service"
        )
        self.assertEqual(
            client["attributes"]["oauth2.token.exchange.grant.enabled"], "true"
        )

    def test_demo_cli_is_public(self):
        client = next(
            c for c in self.realm["clients"] if c["clientId"] == "demo-cli"
        )
        self.assertTrue(client["publicClient"])
        self.assertTrue(client["directAccessGrantsEnabled"])
        self.assertFalse(client["standardFlowEnabled"])

    def test_client_count(self):
        """Should have exactly 2 clients: ai-agent-service and demo-cli."""
        self.assertEqual(len(self.realm["clients"]), 2)

    # ─── Protocol Mappers ────────────────────────────────────────────

    def test_groups_mapper_on_ai_agent_service(self):
        client = next(
            c for c in self.realm["clients"] if c["clientId"] == "ai-agent-service"
        )
        mappers = {m["name"]: m for m in client.get("protocolMappers", [])}
        self.assertIn("groups", mappers)
        groups_mapper = mappers["groups"]
        self.assertEqual(groups_mapper["protocolMapper"], "oidc-group-membership-mapper")
        self.assertEqual(groups_mapper["config"]["claim.name"], "groups")
        self.assertEqual(groups_mapper["config"]["access.token.claim"], "true")

    def test_may_act_mapper_on_ai_agent_service(self):
        client = next(
            c for c in self.realm["clients"] if c["clientId"] == "ai-agent-service"
        )
        mappers = {m["name"]: m for m in client.get("protocolMappers", [])}
        self.assertIn("may_act", mappers)
        may_act_mapper = mappers["may_act"]
        self.assertEqual(may_act_mapper["protocolMapper"], "oidc-hardcoded-claim-mapper")
        self.assertEqual(may_act_mapper["config"]["claim.name"], "may_act")

        # Validate the may_act claim value is valid JSON
        claim_value = json.loads(may_act_mapper["config"]["claim.value"])
        self.assertIn("sub", claim_value)
        self.assertEqual(claim_value["sub"], "agent:query-agent-v2")

    def test_groups_mapper_on_demo_cli(self):
        client = next(
            c for c in self.realm["clients"] if c["clientId"] == "demo-cli"
        )
        mapper_names = {m["name"] for m in client.get("protocolMappers", [])}
        self.assertIn("groups", mapper_names)
        self.assertIn("may_act", mapper_names)

    # ─── Client Scopes ───────────────────────────────────────────────

    def test_agent_delegation_scope(self):
        scope_names = {s["name"] for s in self.realm.get("clientScopes", [])}
        self.assertIn("agent-delegation", scope_names)


if __name__ == "__main__":
    unittest.main()
