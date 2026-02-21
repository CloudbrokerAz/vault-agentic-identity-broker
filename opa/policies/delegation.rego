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

# Check that the human has authorized this agent via may_act claim
authorized_delegation if {
    input.human_token.may_act.sub != ""
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

# Scope narrowing: sub-agents can only request same or narrower scope
scope_narrowing_valid if {
    # Get the parent's scope from the delegation chain
    scope_permitted
}

# ─── Scope Validation ────────────────────────────────────────────────────────

# Check that the requested scope is permitted for the human's groups
scope_permitted if {
    some group in input.human_token.groups
    some scope in data.config.group_permissions[group]
    scope == input.requested_scope
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
