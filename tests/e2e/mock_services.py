#!/usr/bin/env python3
"""
Mock services for E2E testing without Docker.

Simulates:
- OPA Policy Engine (port 8181)
- Keycloak OIDC Provider (port 8080)
- Vault Dynamic Secrets (port 8200)

These mock services implement just enough of each API to support
the Identity Gateway's delegation flow.
"""

import json
import os
import signal
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
import jwt as pyjwt
import secrets
import string

# ─── Configuration ──────────────────────────────────────────────────────────

KEYCLOAK_PORT = 8080
OPA_PORT = 8181
VAULT_PORT = 8200

# Demo users and their credentials/groups
USERS = {
    "alice": {
        "password": "alice-demo-password",
        "email": "alice@acme.com",
        "first_name": "Alice",
        "last_name": "Analyst",
        "groups": ["data-analysts", "trading-team"],
        "realm_roles": ["data-analyst"],
    },
    "bob": {
        "password": "bob-demo-password",
        "email": "bob@acme.com",
        "first_name": "Bob",
        "last_name": "Builder",
        "groups": ["engineering"],
        "realm_roles": ["data-engineer"],
    },
}

# OPA delegation policy data (mirrors opa/policies/data.json)
OPA_CONFIG = {
    "trusted_issuers": [
        "http://127.0.0.1:8080/realms/demo",
        "http://localhost:8080/realms/demo",
        "http://keycloak:8080/realms/demo",
    ],
    "registered_agents": [
        "spiffe://demo.local/agent/query-agent",
        "spiffe://demo.local/agent/analysis-agent",
        "spiffe://demo.local/agent/write-agent",
        "spiffe://demo.local/gateway/identity-gateway",
    ],
    "registered_subagents": [
        "spiffe://demo.local/subagent/sql-executor",
        "spiffe://demo.local/subagent/result-formatter",
    ],
    "max_delegation_depth": 3,
    "group_permissions": {
        "data-analysts": ["readonly", "db:read", "db:query"],
        "trading-team": ["readonly", "db:read", "db:query"],
        "engineering": ["readonly", "readwrite", "db:read", "db:write", "db:query"],
    },
    "max_delegation_ttl_seconds": 28800,
    "require_may_act_claim": True,
}

# JWT signing key for mock tokens
KEYCLOAK_SECRET = "mock-keycloak-secret-key-for-testing"

# Vault state
VAULT_ROOT_TOKEN = "hvs.mock-root-token-for-testing"
VAULT_GATEWAY_TOKEN = None
VAULT_LEASES = {}
VAULT_INITIALIZED = True
VAULT_SEALED = False

# PostgreSQL config for dynamic credentials
PG_HOST = os.environ.get("PG_HOST", "127.0.0.1")
PG_PORT = os.environ.get("PG_PORT", "5432")
PG_DB = os.environ.get("PG_DB", "appdb")

# ─── Keycloak Mock ──────────────────────────────────────────────────────────


class KeycloakHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress request logging

    def _issuer_base(self):
        """Return the base URL using the Host header to support both 127.0.0.1 and localhost."""
        host = self.headers.get("Host", f"127.0.0.1:{KEYCLOAK_PORT}")
        return f"http://{host}"

    def do_GET(self):
        if self.path == "/health/ready":
            self._json_response(200, {"status": "UP"})
        elif self.path == "/realms/demo/.well-known/openid-configuration":
            base = self._issuer_base()
            self._json_response(200, {
                "issuer": f"{base}/realms/demo",
                "authorization_endpoint": f"{base}/realms/demo/protocol/openid-connect/auth",
                "token_endpoint": f"{base}/realms/demo/protocol/openid-connect/token",
                "userinfo_endpoint": f"{base}/realms/demo/protocol/openid-connect/userinfo",
                "jwks_uri": f"{base}/realms/demo/protocol/openid-connect/certs",
            })
        elif self.path == "/realms/demo/protocol/openid-connect/userinfo":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self._json_response(401, {"error": "unauthorized"})
                return
            token = auth[7:]
            try:
                claims = pyjwt.decode(token, KEYCLOAK_SECRET, algorithms=["HS256"],
                                      options={"verify_aud": False})
                self._json_response(200, {
                    "sub": claims.get("sub", ""),
                    "email": claims.get("email", ""),
                    "groups": claims.get("groups", []),
                    "may_act": claims.get("may_act", {}),
                    "email_verified": True,
                })
            except Exception:
                self._json_response(401, {"error": "invalid_token"})
        elif self.path == "/realms/demo/protocol/openid-connect/certs":
            # Return empty JWKS since we use HS256
            self._json_response(200, {"keys": []})
        else:
            self._json_response(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/realms/demo/protocol/openid-connect/token":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)

            username = params.get("username", "")
            password = params.get("password", "")
            grant_type = params.get("grant_type", "")

            if grant_type != "password":
                self._json_response(400, {"error": "unsupported_grant_type"})
                return

            user = USERS.get(username)
            if not user or user["password"] != password:
                self._json_response(401, {"error": "invalid_grant", "error_description": "Invalid user credentials"})
                return

            now = int(time.time())
            base = self._issuer_base()
            token_claims = {
                "sub": user["email"].split("@")[0] + "-uuid",
                "email": user["email"],
                "groups": user["groups"],
                "may_act": {"sub": "agent:query-agent-v2", "client_id": "ai-agent-service"},
                "iss": f"{base}/realms/demo",
                "aud": "demo-cli",
                "exp": now + 300,
                "iat": now,
                "realm_access": {"roles": user["realm_roles"]},
                "name": f"{user['first_name']} {user['last_name']}",
                "preferred_username": username,
            }

            access_token = pyjwt.encode(token_claims, KEYCLOAK_SECRET, algorithm="HS256")
            self._json_response(200, {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 300,
            })
        else:
            self._json_response(404, {"error": "not found"})

    def _json_response(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


# ─── OPA Mock ───────────────────────────────────────────────────────────────


def evaluate_opa_policy(input_data):
    """Evaluate delegation policy (mirrors opa/policies/delegation.rego).

    Supports token exchange / sub-agent delegation via:
      - delegation_depth: current depth of the delegation chain
      - parent_agent_spiffe_id: the SPIFFE ID of the delegating (parent) agent
    """
    human_token = input_data.get("human_token", {})
    agent_spiffe_id = input_data.get("agent_spiffe_id", "")
    requested_scope = input_data.get("requested_scope", "")
    current_time = input_data.get("current_time", int(time.time()))
    delegation_depth = input_data.get("delegation_depth", 0)
    parent_agent_spiffe_id = input_data.get("parent_agent_spiffe_id", "")

    # valid_human_token
    if not human_token.get("sub"):
        return False, "invalid_human_token"
    if human_token.get("exp", 0) <= current_time:
        return False, "invalid_human_token"
    if human_token.get("iss") not in OPA_CONFIG["trusted_issuers"]:
        return False, "invalid_human_token"

    # delegation_depth_check — enforce max_delegation_depth
    max_depth = OPA_CONFIG.get("max_delegation_depth", 3)
    if delegation_depth > max_depth:
        return False, "delegation_depth_exceeded"

    # valid_agent_identity — agents and sub-agents have separate registries
    if not agent_spiffe_id.startswith("spiffe://demo.local/"):
        return False, "invalid_agent_identity"

    is_subagent = "/subagent/" in agent_spiffe_id
    if is_subagent:
        # Sub-agents must appear in the registered_subagents list
        if agent_spiffe_id not in OPA_CONFIG.get("registered_subagents", []):
            return False, "invalid_subagent_identity"
        # Sub-agent delegation requires a valid parent agent
        if delegation_depth > 0 and parent_agent_spiffe_id:
            if parent_agent_spiffe_id not in OPA_CONFIG["registered_agents"]:
                return False, "invalid_parent_agent"
    else:
        if agent_spiffe_id not in OPA_CONFIG["registered_agents"]:
            return False, "invalid_agent_identity"

    # authorized_delegation
    may_act = human_token.get("may_act", {})
    if not may_act or not may_act.get("sub"):
        return False, "unauthorized_delegation"

    # scope_permitted
    groups = human_token.get("groups", [])
    scope_ok = False
    for group in groups:
        perms = OPA_CONFIG["group_permissions"].get(group, [])
        if requested_scope in perms:
            scope_ok = True
            break

    if not scope_ok:
        return False, "scope_not_permitted"

    return True, "allowed"


class OPAHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/health":
            self._json_response(200, {"status": "ok"})
        else:
            self._json_response(404, {})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length).decode("utf-8"))
        input_data = body.get("input", {})

        if self.path == "/v1/data/delegation/allow":
            allowed, reason = evaluate_opa_policy(input_data)
            self._json_response(200, {"result": allowed})

        elif self.path == "/v1/data/delegation/decision":
            allowed, reason = evaluate_opa_policy(input_data)
            result = {
                "allowed": allowed,
                "human": input_data.get("human_token", {}).get("sub", ""),
                "agent": input_data.get("agent_spiffe_id", ""),
                "scope": input_data.get("requested_scope", ""),
                "reason": reason,
                "delegation_depth": input_data.get("delegation_depth", 0),
                "max_delegation_depth": OPA_CONFIG.get("max_delegation_depth", 3),
            }
            if input_data.get("parent_agent_spiffe_id"):
                result["parent_agent"] = input_data["parent_agent_spiffe_id"]
            self._json_response(200, {"result": result})
        else:
            self._json_response(404, {"error": "not found"})

    def _json_response(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


# ─── Vault Mock ─────────────────────────────────────────────────────────────


def _random_password(length=20):
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def _create_pg_role(role_name, username, password):
    """Create an actual PostgreSQL role for dynamic credentials."""
    import subprocess
    try:
        # Compute expiry timestamp as a string
        from datetime import datetime, timedelta, timezone
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S+00")

        # Create the role with proper VALID UNTIL string literal
        create_sql = f"""
            CREATE ROLE "{username}" WITH LOGIN PASSWORD '{password}'
            VALID UNTIL '{expiry}' INHERIT;
            GRANT USAGE ON SCHEMA app TO "{username}";
        """
        if "readonly" in role_name:
            create_sql += f"""
                GRANT SELECT ON ALL TABLES IN SCHEMA app TO "{username}";
                GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{username}";
            """
        else:
            create_sql += f"""
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO "{username}";
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO "{username}";
            """
        result = subprocess.run(
            ["sudo", "-u", "postgres", "psql", "-d", PG_DB, "-c", create_sql],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            print(f"[vault-mock] PG role creation stderr: {result.stderr}", file=sys.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"[vault-mock] Warning: Could not create PG role: {e}", file=sys.stderr)
        return False


def _drop_pg_role(username):
    """Drop a PostgreSQL role (revoke privileges first)."""
    import subprocess
    try:
        revoke_sql = f"""
            REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA app FROM "{username}";
            REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "{username}";
            REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA app FROM "{username}";
            REVOKE USAGE ON SCHEMA app FROM "{username}";
            DROP ROLE IF EXISTS "{username}";
        """
        subprocess.run(
            ["sudo", "-u", "postgres", "psql", "-d", PG_DB, "-c", revoke_sql],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        pass


class VaultHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _check_token(self):
        token = self.headers.get("X-Vault-Token", "")
        if token not in (VAULT_ROOT_TOKEN, VAULT_GATEWAY_TOKEN):
            self._json_response(403, {"errors": ["permission denied"]})
            return False
        return True

    def do_GET(self):
        if self.path == "/v1/sys/health":
            self._json_response(200, {
                "initialized": VAULT_INITIALIZED,
                "sealed": VAULT_SEALED,
                "standby": False,
                "server_time_utc": int(time.time()),
            })

        elif self.path == "/v1/sys/init":
            self._json_response(200, {"initialized": VAULT_INITIALIZED})

        elif self.path == "/v1/sys/seal-status":
            self._json_response(200, {"sealed": VAULT_SEALED, "initialized": VAULT_INITIALIZED})

        elif self.path.startswith("/v1/database/creds/"):
            if not self._check_token():
                return
            role = self.path.split("?")[0].split("/")[-1]
            lease_id = f"database/creds/{role}/{''.join(secrets.choice(string.ascii_lowercase) for _ in range(10))}"
            username = f"v-token-{role[:10]}-{''.join(secrets.choice(string.ascii_lowercase) for _ in range(6))}"
            password = _random_password()

            _create_pg_role(role, username, password)

            # Track delegation metadata alongside the lease
            delegation_metadata = {
                "human_sub": self.headers.get("X-Delegation-Human", ""),
                "agent_spiffe_id": self.headers.get("X-Delegation-Agent", ""),
                "delegation_depth": int(self.headers.get("X-Delegation-Depth", "0")),
                "parent_agent": self.headers.get("X-Delegation-Parent-Agent", ""),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            VAULT_LEASES[lease_id] = {
                "username": username,
                "role": role,
                "delegation": delegation_metadata,
            }

            self._json_response(200, {
                "request_id": secrets.token_hex(8),
                "lease_id": lease_id,
                "renewable": True,
                "lease_duration": 300,
                "data": {
                    "username": username,
                    "password": password,
                },
                "wrap_info": None,
                "warnings": None,
                "auth": None,
            })

        elif self.path == "/v1/auth/token/lookup-self":
            if not self._check_token():
                return
            self._json_response(200, {
                "data": {
                    "id": self.headers.get("X-Vault-Token", ""),
                    "entity_id": "mock-entity-id",
                    "policies": ["gateway-policy"],
                    "ttl": 86400,
                },
            })
        else:
            self._json_response(404, {"errors": ["not found"]})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        if self.path == "/v1/auth/token/create":
            if not self._check_token():
                return
            global VAULT_GATEWAY_TOKEN
            VAULT_GATEWAY_TOKEN = f"hvs.mock-gateway-{secrets.token_hex(8)}"
            self._json_response(200, {
                "auth": {
                    "client_token": VAULT_GATEWAY_TOKEN,
                    "policies": ["gateway-policy"],
                    "lease_duration": 86400,
                    "renewable": True,
                },
            })

        elif self.path == "/v1/sys/mounts/database":
            if not self._check_token():
                return
            self._json_response(204, {})

        elif self.path.startswith("/v1/database/config/"):
            if not self._check_token():
                return
            self._json_response(204, {})

        elif self.path.startswith("/v1/database/roles/"):
            if not self._check_token():
                return
            self._json_response(204, {})

        elif self.path.startswith("/v1/database/rotate-root/"):
            if not self._check_token():
                return
            self._json_response(204, {})

        elif self.path.startswith("/v1/sys/policies/acl/"):
            if not self._check_token():
                return
            self._json_response(204, {})

        elif self.path == "/v1/sys/audit/file":
            if not self._check_token():
                return
            self._json_response(204, {})

        elif self.path.startswith("/v1/identity/entity/id/"):
            if not self._check_token():
                return
            self._json_response(200, {"data": {"id": "mock-entity-id"}})

        else:
            self._json_response(404, {"errors": ["not found"]})

    def do_PUT(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length).decode("utf-8")) if content_length > 0 else {}

        if self.path == "/v1/sys/leases/revoke":
            if not self._check_token():
                return
            lease_id = body.get("lease_id", "")
            lease_info = VAULT_LEASES.pop(lease_id, None)
            if lease_info:
                _drop_pg_role(lease_info["username"])
            self._json_response(204, {})

        elif self.path.startswith("/v1/sys/leases/revoke-prefix/"):
            if not self._check_token():
                return
            prefix = self.path.replace("/v1/sys/leases/revoke-prefix/", "")
            to_remove = [k for k in VAULT_LEASES if k.startswith(prefix)]
            for k in to_remove:
                lease_info = VAULT_LEASES.pop(k)
                _drop_pg_role(lease_info["username"])
            self._json_response(204, {})

        elif self.path == "/v1/sys/init":
            self._json_response(200, {
                "keys": ["mock-unseal-key"],
                "root_token": VAULT_ROOT_TOKEN,
            })

        elif self.path == "/v1/sys/unseal":
            self._json_response(200, {"sealed": False})

        else:
            if not self._check_token():
                return
            self._json_response(200, {})

    def _json_response(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if data:
            self.wfile.write(json.dumps(data).encode())


# ─── Server Management ──────────────────────────────────────────────────────


def start_server(handler_class, port, name):
    server = HTTPServer(("127.0.0.1", port), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[mock] {name} started on port {port}")
    return server


def main():
    servers = []
    try:
        servers.append(start_server(KeycloakHandler, KEYCLOAK_PORT, "Keycloak"))
        servers.append(start_server(OPAHandler, OPA_PORT, "OPA"))
        servers.append(start_server(VaultHandler, VAULT_PORT, "Vault"))

        print(f"[mock] All mock services running")
        print(f"[mock] Vault root token: {VAULT_ROOT_TOKEN}")
        print(f"[mock] PID: {os.getpid()}")

        # Write PID and token info for other scripts
        with open("/tmp/mock-services.pid", "w") as f:
            f.write(str(os.getpid()))
        with open("/tmp/mock-vault-root-token", "w") as f:
            f.write(VAULT_ROOT_TOKEN)

        # Block until signal
        signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
        signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
        print("[mock] All services stopped")


if __name__ == "__main__":
    main()
