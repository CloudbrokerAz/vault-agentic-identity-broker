package delegation_test

import rego.v1

import data.delegation

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Basic Delegation Tests (existing behavior)
# ═══════════════════════════════════════════════════════════════════════════════

# Test: Valid human token + registered agent + may_act + permitted scope => allow
test_allow_valid_human_token_registered_agent_may_act_permitted_scope if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts", "trading-team"],
            "may_act": {"sub": "agent:query-agent-v2", "client_id": "ai-agent-service"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Invalid human token (empty sub) => deny
test_deny_invalid_human_token_empty_sub if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Expired human token => deny
test_deny_expired_human_token if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 1000000000,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Token expired at exact current_time => deny (exp must be strictly greater)
test_deny_token_expired_at_exact_current_time if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 1700000000,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Unregistered agent SPIFFE ID => deny
test_deny_unregistered_agent_spiffe_id if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/unknown-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Missing may_act claim (empty object) => deny
test_deny_missing_may_act_claim if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: may_act with empty sub => deny
test_deny_may_act_empty_sub if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "", "client_id": "ai-agent-service"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Scope not in group permissions => deny
test_deny_scope_not_in_group_permissions if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readwrite",
        "current_time": 1700000000,
    }
}

# Test: Untrusted issuer => deny
test_deny_untrusted_issuer if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://evil-idp.com/realms/fake",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Agent with wrong trust domain => deny
test_deny_agent_wrong_trust_domain if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://evil.com/agent/malicious",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Empty agent SPIFFE ID => deny
test_deny_empty_agent_spiffe_id if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Gateway SPIFFE ID should be allowed as a registered agent
test_allow_gateway_agent if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/write-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: User with no groups => deny
test_deny_no_groups if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "nobody@acme.com",
            "groups": [],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: Unknown scope should be denied for all groups
test_deny_unknown_scope if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "admin:full",
        "current_time": 1700000000,
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# 2. Delegation Chain Extension Tests (new behavior)
# ═══════════════════════════════════════════════════════════════════════════════

# Test: Sub-agent with valid delegation chain (depth > 0) => allow
test_allow_subagent_valid_delegation_chain if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Registered sub-agent can extend chain at depth 2 => allow
test_allow_registered_subagent_extends_chain if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/result-formatter",
        "requested_scope": "readonly",
        "delegation_depth": 2,
        "current_time": 1700000000,
    }
}

# Test: Max delegation depth exceeded (depth >= 3) => deny
test_deny_max_delegation_depth_exceeded if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 3,
        "current_time": 1700000000,
    }
}

# Test: Delegation depth exactly at max (depth == 3, max == 3) => deny
test_deny_delegation_depth_at_exact_max if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 3,
        "current_time": 1700000000,
    }
}

# Test: Delegation depth well beyond max => deny
test_deny_delegation_depth_far_exceeds_max if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 10,
        "current_time": 1700000000,
    }
}

# Test: Sub-agent with readonly scope (default for sub-agents) => allow
test_allow_subagent_readonly_scope if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Unregistered sub-agent SPIFFE ID => deny
test_deny_unregistered_subagent_spiffe_id if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/unknown-subagent",
        "requested_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Sub-agent delegation with expired human token => deny
test_deny_subagent_expired_token if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 1000000000,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Sub-agent delegation with empty human sub => deny
test_deny_subagent_empty_human_sub if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Primary registered agent can also participate in delegation chain
test_allow_primary_agent_in_delegation_chain if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/analysis-agent",
        "requested_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# 3. Scope Validation Tests
# ═══════════════════════════════════════════════════════════════════════════════

# Test: data-analyst group with readonly scope => allow
test_allow_data_analyst_readonly_scope if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: engineering group with readwrite scope => allow
test_allow_engineering_readwrite_scope if {
    delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readwrite",
        "current_time": 1700000000,
    }
}

# Test: data-analyst group with readwrite scope => deny
test_deny_data_analyst_readwrite_scope if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readwrite",
        "current_time": 1700000000,
    }
}

# Test: Sub-agent inherits readonly scope via delegation chain => allow
test_allow_subagent_inherits_readonly if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: data-analyst group with db:read scope => allow
test_allow_data_analyst_db_read if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "db:read",
        "current_time": 1700000000,
    }
}

# Test: data-analyst group with db:query scope => allow
test_allow_data_analyst_db_query if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "db:query",
        "current_time": 1700000000,
    }
}

# Test: data-analyst group with db:write scope => deny
test_deny_data_analyst_db_write if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "db:write",
        "current_time": 1700000000,
    }
}

# Test: engineering group with db:write scope => allow
test_allow_engineering_db_write if {
    delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "db:write",
        "current_time": 1700000000,
    }
}

# Test: engineering group with readonly scope => allow
test_allow_engineering_readonly if {
    delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: trading-team with db:read scope => allow
test_allow_trading_team_db_read if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["trading-team"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "db:read",
        "current_time": 1700000000,
    }
}

# Test: User in multiple groups gets union of permissions
test_allow_multi_group_union_permissions if {
    delegation.allow with input as {
        "human_token": {
            "sub": "charlie@acme.com",
            "groups": ["data-analysts", "engineering"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readwrite",
        "current_time": 1700000000,
    }
}

# Test: Sub-agent scope permitted via group membership (db:query for data-analysts)
test_allow_subagent_scope_via_group if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "db:query",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# 4. Decision Details Tests
# ═══════════════════════════════════════════════════════════════════════════════

# Test: Decision includes delegation_depth (default 0 for primary delegation)
test_decision_includes_delegation_depth_default if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
    result.delegation_depth == 0
}

# Test: Decision includes delegation_depth from delegation chain
test_decision_includes_delegation_depth_from_chain if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 2,
        "current_time": 1700000000,
    }
    result.delegation_depth == 2
}

# Test: Decision reason is "allowed" for valid requests
test_decision_reason_allowed if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
    result.allowed == true
    result.reason == "allowed"
    result.human == "alice@acme.com"
    result.agent == "spiffe://demo.local/agent/query-agent"
    result.scope == "readonly"
}

# Test: Decision reason is "allowed" for valid delegation chain request
test_decision_reason_allowed_delegation_chain if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
    result.allowed == true
    result.reason == "allowed"
    result.human == "alice@acme.com"
    result.agent == "spiffe://demo.local/subagent/sql-executor"
    result.scope == "readonly"
    result.delegation_depth == 1
}

# Test: Decision reason is "max_delegation_depth_exceeded" for deep chains
test_decision_reason_max_delegation_depth_exceeded if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "delegation_depth": 3,
        "current_time": 1700000000,
    }
    result.allowed == false
    result.reason == "max_delegation_depth_exceeded"
}

# Test: Decision reason is "scope_not_permitted" for unauthorized scope
test_decision_reason_scope_not_permitted if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readwrite",
        "current_time": 1700000000,
    }
    result.allowed == false
    result.reason == "scope_not_permitted"
}

# Test: Decision reason is "invalid_human_token" for expired token
test_decision_reason_invalid_human_token if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 1000000000,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
    result.allowed == false
    result.reason == "invalid_human_token"
}

# Test: Decision reason is "invalid_agent_identity" for bad agent
test_decision_reason_invalid_agent_identity if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://evil.com/agent/bad",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
    result.allowed == false
    result.reason == "invalid_agent_identity"
}

# Test: Decision reason is "unauthorized_delegation" for missing may_act
test_decision_reason_unauthorized_delegation if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
    result.allowed == false
    result.reason == "unauthorized_delegation"
}

# Test: Decision captures all fields correctly
test_decision_captures_all_fields if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "may_act": {"sub": "agent:write-agent-v1"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/write-agent",
        "requested_scope": "readwrite",
        "current_time": 1700000000,
    }
    result.allowed == true
    result.reason == "allowed"
    result.human == "bob@acme.com"
    result.agent == "spiffe://demo.local/agent/write-agent"
    result.scope == "readwrite"
    result.delegation_depth == 0
}

# Test: Decision for delegation chain captures depth
test_decision_delegation_chain_captures_depth if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/result-formatter",
        "requested_scope": "readonly",
        "delegation_depth": 2,
        "current_time": 1700000000,
    }
    result.allowed == true
    result.delegation_depth == 2
    result.agent == "spiffe://demo.local/subagent/result-formatter"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 5. may_act Agent Identity Validation Tests
# ═══════════════════════════════════════════════════════════════════════════════

# Test: may_act.sub matches agent SPIFFE ID exactly => allow
test_allow_may_act_spiffe_id_match if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "spiffe://demo.local/agent/query-agent"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: may_act.sub is SPIFFE ID but doesn't match requesting agent => deny
test_deny_may_act_spiffe_id_mismatch if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "spiffe://demo.local/agent/analysis-agent"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: may_act.aud includes the requesting agent's SPIFFE ID => allow
test_allow_may_act_aud_match if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {
                "sub": "agent:query-agent-v2",
                "aud": ["spiffe://demo.local/agent/query-agent"],
            },
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# Test: may_act.aud does NOT include the requesting agent => deny
test_deny_may_act_aud_mismatch if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {
                "sub": "agent:query-agent-v2",
                "aud": ["spiffe://demo.local/agent/analysis-agent"],
            },
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# 6. Scope Hierarchy Tests
# ═══════════════════════════════════════════════════════════════════════════════

# Test: readwrite implies readonly via scope_hierarchy => allow
test_allow_scope_hierarchy_readwrite_implies_readonly if {
    delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "db:read",
        "current_time": 1700000000,
    }
}

# Test: readwrite implies db:write via scope_hierarchy => allow
test_allow_scope_hierarchy_readwrite_implies_db_write if {
    delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
        "requested_scope": "db:write",
        "current_time": 1700000000,
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# 7. Scope Narrowing Enforcement Tests
# ═══════════════════════════════════════════════════════════════════════════════

# Test: Sub-agent requests same scope as parent => allow
test_allow_scope_narrowing_same_scope if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "parent_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Sub-agent narrows scope from readwrite to readonly => allow
test_allow_scope_narrowing_readwrite_to_readonly if {
    delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readonly",
        "parent_scope": "readwrite",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Sub-agent narrows scope from readwrite to db:read => allow
test_allow_scope_narrowing_readwrite_to_db_read if {
    delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "db:read",
        "parent_scope": "readwrite",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Sub-agent tries to escalate from readonly to readwrite => deny
test_deny_scope_narrowing_escalation_readonly_to_readwrite if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["engineering"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readwrite",
        "parent_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Sub-agent tries to escalate from db:read to db:write => deny
test_deny_scope_narrowing_escalation_db_read_to_db_write if {
    not delegation.allow with input as {
        "human_token": {
            "sub": "bob@acme.com",
            "groups": ["engineering"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "db:write",
        "parent_scope": "db:read",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
}

# Test: Decision reason is "scope_narrowing_violation" for escalation attempt
test_decision_reason_scope_narrowing_violation if {
    result := delegation.decision with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["engineering"],
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/subagent/sql-executor",
        "requested_scope": "readwrite",
        "parent_scope": "readonly",
        "delegation_depth": 1,
        "current_time": 1700000000,
    }
    result.allowed == false
    result.reason == "scope_narrowing_violation"
}
