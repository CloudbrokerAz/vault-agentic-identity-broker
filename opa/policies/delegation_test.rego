package delegation_test

import rego.v1

import data.delegation

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

# Test: Invalid agent SPIFFE ID should be denied
test_invalid_agent_denied if {
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

# Test: Human not in authorized group for scope should be denied
test_unauthorized_scope_denied if {
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

# Test: Engineer should be allowed readwrite scope
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
