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

# Validate the human's OIDC token
valid_human_token if {
    input.human_token.sub != ""
    input.human_token.exp > input.current_time
    input.human_token.iss == data.config.trusted_issuers[_]
}

# Validate the agent's SPIFFE identity
valid_agent_identity if {
    startswith(input.agent_spiffe_id, "spiffe://demo.local/")
    input.agent_spiffe_id == data.config.registered_agents[_]
}

# Check that the human has authorized this agent via may_act claim
authorized_delegation if {
    input.human_token.may_act.sub != ""
}

# Check that the requested scope is permitted for the human's groups
scope_permitted if {
    some group in input.human_token.groups
    some scope in data.config.group_permissions[group]
    scope == input.requested_scope
}

# Decision details for audit logging
decision := {
    "allowed": allow,
    "human": input.human_token.sub,
    "agent": input.agent_spiffe_id,
    "scope": input.requested_scope,
    "reason": reason,
}

# Provide reason for denial
reason := "allowed" if {
    allow
}

reason := "invalid_human_token" if {
    not valid_human_token
}

reason := "invalid_agent_identity" if {
    valid_human_token
    not valid_agent_identity
}

reason := "unauthorized_delegation" if {
    valid_human_token
    valid_agent_identity
    not authorized_delegation
}

reason := "scope_not_permitted" if {
    valid_human_token
    valid_agent_identity
    authorized_delegation
    not scope_permitted
}
