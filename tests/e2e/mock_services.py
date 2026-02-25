#!/usr/bin/env python3
"""
Mock services for E2E testing without Docker.

Simulates:
- Keycloak OIDC Provider (port 8080)
- Vault Dynamic Secrets (port 8200)

These mock services implement just enough of each API to support
the Token Exchange Service's delegation flow.
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

KEYCLOAK_PORT = int(os.environ.get("MOCK_KEYCLOAK_PORT", "8080"))
VAULT_PORT = int(os.environ.get("MOCK_VAULT_PORT", "8200"))

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


# ─── Vault Mock ─────────────────────────────────────────────────────────────


def _random_password(length=20):
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def _run_psql(sql):
    """Run SQL against PostgreSQL, trying multiple connection methods."""
    import subprocess
    import shutil
    pg_password = os.environ.get("PG_PASSWORD", "postgres-root-password")
    pg_user = os.environ.get("PG_USER", "postgres")

    # Try native psql via TCP first
    if shutil.which("psql"):
        try:
            result = subprocess.run(
                ["psql", "-h", PG_HOST, "-p", PG_PORT, "-U", pg_user, "-d", PG_DB, "-c", sql],
                capture_output=True, text=True, timeout=5,
                env={**os.environ, "PGPASSWORD": pg_password},
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

    # Try docker compose exec (works when PostgreSQL is in Docker)
    for compose_file in ["docker-compose.host.yml", "docker-compose.yml"]:
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", compose_file, "exec", "-T",
                 "-e", f"PGPASSWORD={pg_password}",
                 "postgresql", "psql", "-U", pg_user, "-d", PG_DB, "-c", sql],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

    # Fallback to sudo (works in native environments)
    try:
        result = subprocess.run(
            ["sudo", "-u", "postgres", "psql", "-d", PG_DB, "-c", sql],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return True
        print(f"[vault-mock] PG stderr: {result.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"[vault-mock] Warning: Could not run psql: {e}", file=sys.stderr)

    return False


def _create_pg_role(role_name, username, password):
    """Create an actual PostgreSQL role for dynamic credentials."""
    from datetime import datetime, timedelta, timezone
    try:
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S+00")

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
        return _run_psql(create_sql)
    except Exception as e:
        print(f"[vault-mock] Warning: Could not create PG role: {e}", file=sys.stderr)
        return False


def _drop_pg_role(username):
    """Drop a PostgreSQL role (revoke privileges first)."""
    try:
        revoke_sql = f"""
            REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA app FROM "{username}";
            REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "{username}";
            REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA app FROM "{username}";
            REVOKE USAGE ON SCHEMA app FROM "{username}";
            DROP ROLE IF EXISTS "{username}";
        """
        _run_psql(revoke_sql)
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
