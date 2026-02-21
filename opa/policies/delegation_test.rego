package delegation_test

import rego.v1

import data.delegation

# ═══════════════════════════════════════════════════════════════
# Basic allow/deny tests
# ═══════════════════════════════════════════════════════════════

# Test: Valid delegation should be allowed
test_valid_delegation_allowed if {
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

# Test: Engineer with readwrite scope should be allowed
test_engineer_readwrite_allowed if {
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

# Test: Engineer with readonly scope should be allowed
test_engineer_readonly_also_allowed if {
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

# Test: trading-team member with db:read scope should be allowed
test_trading_team_db_read if {
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

# Test: data-analysts with db:query scope should be allowed
test_data_analysts_db_query if {
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

# Test: Gateway SPIFFE ID should be allowed
test_gateway_agent_allowed if {
    delegation.allow with input as {
        "human_token": {
            "sub": "alice@acme.com",
            "groups": ["data-analysts"],
            "may_act": {"sub": "agent:query-agent-v2"},
            "exp": 9999999999,
            "iss": "http://keycloak:8080/realms/demo",
        },
        "agent_spiffe_id": "spiffe://demo.local/gateway/identity-gateway",
        "requested_scope": "readonly",
        "current_time": 1700000000,
    }
}

# ═══════════════════════════════════════════════════════════════
# Token validation tests
# ═══════════════════════════════════════════════════════════════

# Test: Expired human token should be denied
test_expired_token_denied if {
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

# Test: Token expiry at exact current_time should be denied
test_token_expired_at_exact_time if {
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

# Test: Empty subject should be denied
test_empty_subject_denied if {
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

# Test: Untrusted issuer should be denied
test_untrusted_issuer_denied if {
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

# ═══════════════════════════════════════════════════════════════
# Agent identity tests
# ═══════════════════════════════════════════════════════════════

# Test: Invalid agent SPIFFE ID (wrong trust domain)
test_invalid_agent_trust_domain if {
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

# Test: Unregistered agent in correct trust domain
test_unregistered_agent_denied if {
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

# Test: Empty agent SPIFFE ID
test_empty_agent_id_denied if {
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

# ═══════════════════════════════════════════════════════════════
# Delegation authorization tests
# ═══════════════════════════════════════════════════════════════

# Test: Human without may_act claim should be denied
test_no_may_act_denied if {
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

# Test: may_act with empty sub should be denied
test_may_act_empty_sub_denied if {
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

# ═══════════════════════════════════════════════════════════════
# Scope permission tests
# ═══════════════════════════════════════════════════════════════

# Test: data-analyst requesting readwrite should be denied
test_data_analyst_readwrite_denied if {
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

# Test: data-analyst requesting db:write should be denied
test_data_analyst_db_write_denied if {
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

# Test: engineer requesting db:write should be allowed
test_engineer_db_write_allowed if {
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

# Test: Unknown scope should be denied for all groups
test_unknown_scope_denied if {
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

# Test: User with no groups should be denied
test_no_groups_denied if {
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

# ═══════════════════════════════════════════════════════════════
# Decision reason tests
# ═══════════════════════════════════════════════════════════════

# Test: Allowed reason
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

# Test: Invalid token reason
test_decision_reason_invalid_token if {
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

# Test: Invalid agent identity reason
test_decision_reason_invalid_agent if {
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

# Test: Unauthorized delegation reason
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

# Test: Scope not permitted reason
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

# ═══════════════════════════════════════════════════════════════
# Multi-group membership tests
# ═══════════════════════════════════════════════════════════════

# Test: User in multiple groups gets union of permissions
test_multi_group_union if {
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
