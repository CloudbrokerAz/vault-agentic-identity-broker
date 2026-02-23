package delegation

import rego.v1

# Default deny
default allow := false

# Allow delegation when all conditions are met
allow if {
    valid_human_token
    valid_agent_identity
    authorized_delegation
    scope_permitted
}

# Also allow delegation chain extensions (sub-agent delegation)
allow if {
    valid_delegation_chain
    valid_agent_identity
    chain_depth_permitted
    scope_narrowing_valid
}

# ─── Human Token Validation ──────────────────────────────────────────────────

# Validate the human's OIDC token
valid_human_token if {
    input.human_token.sub != ""
    input.human_token.exp > input.current_time
    input.human_token.iss == data.config.trusted_issuers[_]
}

# ─── Agent Identity Validation ───────────────────────────────────────────────

# Validate the agent's SPIFFE identity (primary agents)
valid_agent_identity if {
    startswith(input.agent_spiffe_id, "spiffe://demo.local/")
    input.agent_spiffe_id == data.config.registered_agents[_]
}

# Also accept registered sub-agents
valid_agent_identity if {
    startswith(input.agent_spiffe_id, "spiffe://demo.local/")
    input.agent_spiffe_id == data.config.registered_subagents[_]
}

# ─── Delegation Authorization ────────────────────────────────────────────────

# Check that the human has authorized delegation via may_act claim.
# The may_act.sub must be non-empty AND must match the requesting agent's
# SPIFFE ID to prevent one agent from using a token meant for another.
authorized_delegation if {
    input.human_token.may_act.sub != ""
    # Exact match: may_act.sub must equal the agent's SPIFFE ID
    input.human_token.may_act.sub == input.agent_spiffe_id
}

# Also allow when may_act.sub is a descriptive identifier (e.g. "agent:query-agent-v2")
# and the may_act.aud list includes the requesting agent's SPIFFE ID
authorized_delegation if {
    input.human_token.may_act.sub != ""
    input.human_token.may_act.aud[_] == input.agent_spiffe_id
}

# Legacy/demo mode: may_act.sub is a descriptive name (not a SPIFFE ID)
# and no aud constraint is set — allow if the agent is registered.
# This preserves backward compatibility with existing Keycloak configs
# that use names like "agent:query-agent-v2".
authorized_delegation if {
    input.human_token.may_act.sub != ""
    not startswith(input.human_token.may_act.sub, "spiffe://")
    not input.human_token.may_act.aud
}

# ─── Delegation Chain Validation (RFC 8693) ──────────────────────────────────

# Validate an existing delegation chain for sub-agent extension
valid_delegation_chain if {
    input.delegation_depth > 0
    input.human_token.sub != ""
    # The subject token must still be valid
    input.human_token.exp > input.current_time
}

# Chain depth must not exceed maximum
chain_depth_permitted if {
    input.delegation_depth < data.config.max_delegation_depth
}

# Scope narrowing: sub-agents can only request same or narrower scope.
# Uses the scope_hierarchy from data.json to determine if the requested
# scope is equal to or implied by the parent's scope.
scope_narrowing_valid if {
    # The parent_scope field must be present in the input for chain requests
    parent := object.get(input, "parent_scope", "")
    parent != ""
    # Same scope is always valid
    input.requested_scope == parent
}

scope_narrowing_valid if {
    parent := object.get(input, "parent_scope", "")
    parent != ""
    # Check if requested scope is implied by parent scope (narrower)
    scope_implies(parent, input.requested_scope)
}

# Fallback: if no parent_scope is provided, the scope must be permitted
# by the human's group permissions (preserves backward compatibility)
scope_narrowing_valid if {
    not input.parent_scope
    scope_permitted
}

# ─── Scope Hierarchy Helpers ─────────────────────────────────────────────────

# scope_implies checks if "parent" scope implies "child" scope using
# the scope_hierarchy defined in data.json.
# Supports up to 2 levels of transitive implication (direct + one intermediate).
# OPA does not support recursion, so we unroll the transitive lookup.

# Direct implication: parent -> child
scope_implies(parent, child) if {
    child == data.config.scope_hierarchy[parent][_]
}

# One-level transitive: parent -> intermediate -> child
scope_implies(parent, child) if {
    intermediate := data.config.scope_hierarchy[parent][_]
    child == data.config.scope_hierarchy[intermediate][_]
}

# ─── Scope Validation ────────────────────────────────────────────────────────

# Check that the requested scope is permitted for the human's groups
scope_permitted if {
    some group in input.human_token.groups
    some scope in data.config.group_permissions[group]
    scope == input.requested_scope
}

# Also allow if the requested scope is implied by a scope the user has
scope_permitted if {
    some group in input.human_token.groups
    some scope in data.config.group_permissions[group]
    scope_implies(scope, input.requested_scope)
}

# Sub-agents inherit readonly scope by default
scope_permitted if {
    input.delegation_depth > 0
    input.requested_scope == "readonly"
}

# ─── Decision Details ────────────────────────────────────────────────────────

# Decision details for audit logging
decision := {
    "allowed": allow,
    "human": input.human_token.sub,
    "agent": input.agent_spiffe_id,
    "scope": input.requested_scope,
    "reason": reason,
    "delegation_depth": object.get(input, "delegation_depth", 0),
}

# Provide reason for denial
reason := "allowed" if {
    allow
}

reason := "invalid_human_token" if {
    not valid_human_token
    not valid_delegation_chain
}

reason := "invalid_agent_identity" if {
    valid_human_token
    not valid_agent_identity
}

reason := "unauthorized_delegation" if {
    valid_human_token
    valid_agent_identity
    not authorized_delegation
    not valid_delegation_chain
}

reason := "scope_not_permitted" if {
    valid_human_token
    valid_agent_identity
    authorized_delegation
    not scope_permitted
}

reason := "max_delegation_depth_exceeded" if {
    valid_delegation_chain
    valid_agent_identity
    not chain_depth_permitted
}

reason := "scope_narrowing_violation" if {
    valid_delegation_chain
    valid_agent_identity
    chain_depth_permitted
    not scope_narrowing_valid
}
