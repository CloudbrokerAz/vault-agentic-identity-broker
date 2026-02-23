"""
OPA Policy Logic Validation Tests

Validates the OPA policy logic by analyzing the scope hierarchy,
sub-agent escalation prevention, delegation depth config, registered
agent security, and Rego denial reasons.
"""

import json
import os
import unittest

DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "opa", "policies", "data.json"
)
REGO_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "opa", "policies", "delegation.rego"
)


class TestScopeHierarchy(unittest.TestCase):
    """Validate scope hierarchy relationships in OPA data."""

    @classmethod
    def setUpClass(cls):
        with open(DATA_PATH) as f:
            cls.data = json.load(f)
        cls.config = cls.data["config"]
        cls.hierarchy = cls.config["scope_hierarchy"]

    def test_readonly_does_not_imply_readwrite(self):
        """readwrite must NOT be implied by readonly."""
        self.assertNotIn(
            "readwrite",
            self.hierarchy["readonly"],
            "readonly should not imply readwrite (privilege escalation)",
        )

    def test_readwrite_implies_readonly(self):
        """readwrite must imply readonly."""
        self.assertIn(
            "readonly",
            self.hierarchy["readwrite"],
            "readwrite should imply readonly",
        )

    def test_readwrite_implies_db_read_and_db_write(self):
        """readwrite must imply both db:read and db:write."""
        self.assertIn(
            "db:read",
            self.hierarchy["readwrite"],
            "readwrite should imply db:read",
        )
        self.assertIn(
            "db:write",
            self.hierarchy["readwrite"],
            "readwrite should imply db:write",
        )

    def test_readonly_implies_db_read_not_db_write(self):
        """readonly must imply db:read but NOT db:write."""
        self.assertIn(
            "db:read",
            self.hierarchy["readonly"],
            "readonly should imply db:read",
        )
        self.assertNotIn(
            "db:write",
            self.hierarchy["readonly"],
            "readonly must not imply db:write",
        )

    def test_no_circular_references(self):
        """DFS cycle detection: no scope should transitively imply itself."""

        def has_cycle(node, path):
            """Recursive DFS: detect back-edges (true cycles) in the graph."""
            for child in self.hierarchy.get(node, []):
                if child in path:
                    return True
                if has_cycle(child, path | {child}):
                    return True
            return False

        for scope in self.hierarchy:
            self.assertFalse(
                has_cycle(scope, {scope}),
                f"Cycle detected in scope hierarchy starting from '{scope}'",
            )

    def test_all_group_permission_scopes_exist_in_hierarchy(self):
        """Every scope in group_permissions must be a key in scope_hierarchy."""
        for group, perms in self.config["group_permissions"].items():
            for perm in perms:
                self.assertIn(
                    perm,
                    self.hierarchy,
                    f"Scope '{perm}' in group '{group}' not found in scope_hierarchy",
                )

    def test_leaf_scopes_have_empty_implications(self):
        """db:read and db:query should be leaf scopes with no implications."""
        self.assertEqual(
            self.hierarchy["db:read"],
            [],
            "db:read should have no implications (leaf scope)",
        )
        self.assertEqual(
            self.hierarchy["db:query"],
            [],
            "db:query should have no implications (leaf scope)",
        )

    def test_transitive_readwrite_reaches_db_query_via_readonly(self):
        """readwrite -> readonly -> db:query must be a valid transitive path."""
        self.assertIn(
            "readonly",
            self.hierarchy["readwrite"],
            "readwrite must directly imply readonly",
        )
        self.assertIn(
            "db:query",
            self.hierarchy["readonly"],
            "readonly must directly imply db:query",
        )


class TestSubAgentScopeEscalation(unittest.TestCase):
    """Verify groups cannot escalate beyond their allowed scopes."""

    @classmethod
    def setUpClass(cls):
        with open(DATA_PATH) as f:
            cls.config = json.load(f)["config"]

    def test_data_analysts_cannot_access_readwrite(self):
        """data-analysts group must not have readwrite scope."""
        self.assertNotIn(
            "readwrite",
            self.config["group_permissions"]["data-analysts"],
            "data-analysts should not have readwrite access",
        )

    def test_data_analysts_cannot_access_db_write(self):
        """data-analysts group must not have db:write scope."""
        self.assertNotIn(
            "db:write",
            self.config["group_permissions"]["data-analysts"],
            "data-analysts should not have db:write access",
        )

    def test_trading_team_cannot_access_readwrite(self):
        """trading-team group must not have readwrite scope."""
        self.assertNotIn(
            "readwrite",
            self.config["group_permissions"]["trading-team"],
            "trading-team should not have readwrite access",
        )


class TestDelegationDepthConfig(unittest.TestCase):
    """Validate delegation depth configuration."""

    @classmethod
    def setUpClass(cls):
        with open(DATA_PATH) as f:
            cls.config = json.load(f)["config"]

    def test_max_depth_is_positive_integer(self):
        """max_delegation_depth must be a positive integer."""
        depth = self.config["max_delegation_depth"]
        self.assertIsInstance(depth, int, "max_delegation_depth must be an integer")
        self.assertGreater(depth, 0, "max_delegation_depth must be positive")

    def test_max_depth_is_exactly_three(self):
        """max_delegation_depth must be exactly 3."""
        self.assertEqual(
            self.config["max_delegation_depth"],
            3,
            "max_delegation_depth should be 3",
        )


class TestRegisteredAgentsSecurity(unittest.TestCase):
    """Validate registered agent SPIFFE ID security."""

    @classmethod
    def setUpClass(cls):
        with open(DATA_PATH) as f:
            cls.config = json.load(f)["config"]

    def test_no_wildcard_spiffe_ids_in_agents(self):
        """No registered agent SPIFFE ID should contain wildcards."""
        for agent in self.config["registered_agents"]:
            self.assertNotIn(
                "*",
                agent,
                f"Agent '{agent}' contains wildcard character",
            )
            self.assertNotIn(
                "**",
                agent,
                f"Agent '{agent}' contains double wildcard",
            )

    def test_no_wildcard_spiffe_ids_in_subagents(self):
        """No registered sub-agent SPIFFE ID should contain wildcards."""
        for subagent in self.config["registered_subagents"]:
            self.assertNotIn(
                "*",
                subagent,
                f"Sub-agent '{subagent}' contains wildcard character",
            )
            self.assertNotIn(
                "**",
                subagent,
                f"Sub-agent '{subagent}' contains double wildcard",
            )

    def test_agents_and_subagents_are_disjoint(self):
        """Registered agents and sub-agents must have no overlap."""
        agents = set(self.config["registered_agents"])
        subagents = set(self.config["registered_subagents"])
        overlap = agents & subagents
        self.assertEqual(
            len(overlap),
            0,
            f"Agents and sub-agents overlap: {overlap}",
        )

    def test_agent_path_conventions(self):
        """Agents must use /agent/ path, sub-agents must use /subagent/ path."""
        for agent in self.config["registered_agents"]:
            self.assertIn(
                "/agent/",
                agent,
                f"Agent '{agent}' does not follow /agent/ path convention",
            )
        for subagent in self.config["registered_subagents"]:
            self.assertIn(
                "/subagent/",
                subagent,
                f"Sub-agent '{subagent}' does not follow /subagent/ path convention",
            )


class TestRegoDenialReasons(unittest.TestCase):
    """Validate Rego policy structure and denial reasons."""

    @classmethod
    def setUpClass(cls):
        with open(REGO_PATH) as f:
            cls.rego = f.read()

    def test_all_denial_reasons_present(self):
        """All expected denial reason strings must appear in the Rego policy."""
        expected_reasons = [
            "allowed",
            "invalid_human_token",
            "invalid_agent_identity",
            "unauthorized_delegation",
            "scope_not_permitted",
            "max_delegation_depth_exceeded",
            "scope_narrowing_violation",
        ]
        for reason in expected_reasons:
            self.assertIn(
                reason,
                self.rego,
                f"Expected reason '{reason}' not found in delegation.rego",
            )

    def test_scope_narrowing_valid_rule_exists(self):
        """The scope_narrowing_valid rule must be defined in the Rego policy."""
        self.assertIn(
            "scope_narrowing_valid",
            self.rego,
            "scope_narrowing_valid rule not found in delegation.rego",
        )

    def test_scope_implies_function_exists(self):
        """The scope_implies function must be defined in the Rego policy."""
        self.assertIn(
            "scope_implies",
            self.rego,
            "scope_implies function not found in delegation.rego",
        )

    def test_chain_depth_permitted_rule_exists(self):
        """The chain_depth_permitted rule must be defined in the Rego policy."""
        self.assertIn(
            "chain_depth_permitted",
            self.rego,
            "chain_depth_permitted rule not found in delegation.rego",
        )

    def test_default_deny_is_first_rule(self):
        """'default allow := false' must appear before any 'allow if' rule."""
        default_pos = self.rego.find("default allow := false")
        allow_if_pos = self.rego.find("allow if")
        self.assertNotEqual(
            default_pos,
            -1,
            "'default allow := false' not found in delegation.rego",
        )
        self.assertNotEqual(
            allow_if_pos,
            -1,
            "'allow if' not found in delegation.rego",
        )
        self.assertLess(
            default_pos,
            allow_if_pos,
            "'default allow := false' must appear before any 'allow if' rule",
        )


if __name__ == "__main__":
    unittest.main()
