"""
Live-Integrated Interactive Demo UI Server.

Lightweight Python backend that serves the HTML UI and proxies
real API calls to Keycloak, SPIRE, OPA, Token Exchange, Vault, and PostgreSQL.
"""

import html as html_mod
import json
import logging
import os
import re
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

import jwt
import requests
import psycopg2

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8500"))
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://127.0.0.1:8080")
TOKEN_EXCHANGE_URL = os.environ.get("TOKEN_EXCHANGE_URL", "http://127.0.0.1:8090")
OPA_URL = os.environ.get("OPA_URL", "http://127.0.0.1:8181")
VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "appdb")
SPIRE_SOCKET = os.environ.get("SPIRE_SOCKET", "/tmp/spire-agent/public/api.sock")
GATEWAY_VAULT_TOKEN = os.environ.get("GATEWAY_VAULT_TOKEN", "")

KEYCLOAK_REALM = "demo"
KEYCLOAK_CLIENT_ID = "demo-cli"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("demo-ui")

# ---------------------------------------------------------------------------
# Static file serving
# ---------------------------------------------------------------------------

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


def decode_token_safe(token):
    """Decode a JWT without verification — for UI display only.

    Security note: This function intentionally skips signature verification.
    It is used exclusively by the demo UI to show token structure to the user.
    All actual security validation happens in the Token Exchange Service, which
    cryptographically verifies subject tokens (via Keycloak userinfo) and actor
    tokens (via SPIRE OIDC JWKS with RS256).
    """
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None


def resolve_username(decoded):
    """Extract the Keycloak username from a decoded token.

    Tokens may contain preferred_username, email, or only sub (UUID).
    Returns the best available human-readable identifier. Used for display and
    Keycloak admin API lookups (paired with _get_user_by_name's email fallback).
    """
    if not decoded:
        return None
    if decoded.get("preferred_username"):
        return decoded["preferred_username"]
    if decoded.get("email"):
        return decoded["email"].split("@")[0]
    return decoded.get("sub")


# ---------------------------------------------------------------------------
# Request Handler
# ---------------------------------------------------------------------------

class DemoHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        logger.info("%s %s", self.address_string(), format % args)

    # --- CORS ---

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    # --- Response helpers ---

    def _send_json(self, status, obj):
        body = json.dumps(obj, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, service, message):
        self._send_json(status, {"error": True, "service": service, "message": str(message)})

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"Malformed JSON request body: {e}") from e

    # --- Keycloak Reverse Proxy ---

    def _proxy_keycloak(self, method):
        """Reverse-proxy a request to Keycloak, rewriting headers and content
        so the browser can interact with Keycloak through the demo-ui server."""
        parsed = urlparse(self.path)
        target_url = f"{KEYCLOAK_URL}{parsed.path}"
        if parsed.query:
            target_url += f"?{parsed.query}"

        # Read request body for POST
        body = None
        content_type = self.headers.get("Content-Type", "")
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                body = self.rfile.read(length)

        # Forward headers, rewriting Host/Referer/Origin to point at Keycloak
        kc_parsed = urlparse(KEYCLOAK_URL)
        forward_headers = {}
        for hdr in ("Content-Type", "Accept", "Accept-Language", "Accept-Encoding",
                     "Cookie", "Authorization"):
            val = self.headers.get(hdr)
            if val:
                forward_headers[hdr] = val
        forward_headers["Host"] = kc_parsed.netloc
        if self.headers.get("Referer"):
            forward_headers["Referer"] = self.headers["Referer"].replace(
                f"http://{self.headers.get('Host', 'localhost')}", KEYCLOAK_URL
            )
        if self.headers.get("Origin"):
            forward_headers["Origin"] = KEYCLOAK_URL

        try:
            if method == "GET":
                r = requests.get(target_url, headers=forward_headers,
                                 allow_redirects=False, timeout=15)
            else:
                r = requests.post(target_url, data=body, headers=forward_headers,
                                  allow_redirects=False, timeout=15)
        except Exception as e:
            logger.exception("Keycloak proxy error")
            self._send_error(502, "keycloak-proxy", str(e))
            return

        # Send response status
        self.send_response(r.status_code)

        # Rewrite Location header: strip Keycloak origin so redirects go through proxy
        skip_headers = {"transfer-encoding", "content-encoding", "content-length"}
        for hdr, val in r.headers.items():
            lower = hdr.lower()
            if lower in skip_headers:
                continue
            if lower == "location":
                val = val.replace(KEYCLOAK_URL, "")
                self.send_header(hdr, val)
            elif lower == "set-cookie":
                # Remove Secure and SameSite=None for HTTP-only dev mode
                val = re.sub(r';\s*Secure', '', val, flags=re.IGNORECASE)
                val = re.sub(r';\s*SameSite=None', '; SameSite=Lax', val, flags=re.IGNORECASE)
                self.send_header(hdr, val)
            else:
                self.send_header(hdr, val)

        # Rewrite HTML content: replace absolute Keycloak URLs with relative paths
        resp_content_type = r.headers.get("Content-Type", "")
        response_body = r.content
        if "text/html" in resp_content_type:
            text = response_body.decode("utf-8", errors="replace")
            text = text.replace(KEYCLOAK_URL, "")
            response_body = text.encode("utf-8")

        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    # --- Routing ---

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Keycloak reverse proxy
        if path.startswith("/realms/") or path.startswith("/resources/"):
            return self._proxy_keycloak("GET")

        if path == "/api/health":
            return self._handle_health()
        if path == "/api/audit":
            return self._handle_audit()

        # Static files
        if path == "/" or path == "":
            path = "/index.html"
        self._serve_static(path)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Keycloak reverse proxy
        if path.startswith("/realms/") or path.startswith("/resources/"):
            return self._proxy_keycloak("POST")

        routes = {
            "/api/auth/login": self._handle_login,
            "/api/auth/code-exchange": self._handle_code_exchange,
            "/api/auth/device-start": self._handle_device_start,
            "/api/auth/device-poll": self._handle_device_poll,
            "/api/auth/device-approve": self._handle_device_approve,
            "/api/auth/logout": self._handle_logout,
            "/api/consent/get": self._handle_consent_get,
            "/api/consent/update": self._handle_consent_update,
            "/api/spiffe/svid": self._handle_spiffe_svid,
            "/api/opa/evaluate": self._handle_opa_evaluate,
            "/api/token-exchange": self._handle_token_exchange,
            "/api/vault/credentials": self._handle_vault_credentials,
            "/api/db/query": self._handle_db_query,
            "/api/revoke": self._handle_revoke,
            "/api/db/verify-revoked": self._handle_verify_revoked,
        }

        handler = routes.get(path)
        if handler:
            try:
                handler()
            except ValueError as e:
                # Malformed request body or invalid input
                self._send_error(400, "demo-ui", str(e))
            except Exception as e:
                logger.exception("Error in %s", path)
                self._send_error(500, "demo-ui", str(e))
        else:
            self._send_error(404, "demo-ui", f"Unknown endpoint: {path}")

    # --- Static file serving ---

    def _serve_static(self, path):
        # Prevent directory traversal
        safe_path = os.path.normpath(path.lstrip("/"))
        file_path = os.path.join(STATIC_DIR, safe_path)
        if not file_path.startswith(STATIC_DIR):
            self._send_error(403, "demo-ui", "Forbidden")
            return

        if not os.path.isfile(file_path):
            self._send_error(404, "demo-ui", f"Not found: {path}")
            return

        ext = os.path.splitext(file_path)[1].lower()
        content_type = CONTENT_TYPES.get(ext, "application/octet-stream")

        with open(file_path, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self._cors_headers()
        self.end_headers()
        self.wfile.write(content)

    # --- Health Check ---

    def _handle_health(self):
        services = {}

        # Keycloak
        try:
            r = requests.get(f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}", timeout=3)
            services["keycloak"] = {"status": "healthy" if r.status_code == 200 else "unhealthy", "url": KEYCLOAK_URL}
        except Exception as e:
            services["keycloak"] = {"status": "unhealthy", "error": str(e)}

        # OPA
        try:
            r = requests.get(f"{OPA_URL}/health", timeout=3)
            services["opa"] = {"status": "healthy" if r.status_code == 200 else "unhealthy", "url": OPA_URL}
        except Exception as e:
            services["opa"] = {"status": "unhealthy", "error": str(e)}

        # Token Exchange
        try:
            r = requests.get(f"{TOKEN_EXCHANGE_URL}/health", timeout=3)
            services["token_exchange"] = {"status": "healthy" if r.status_code == 200 else "unhealthy", "url": TOKEN_EXCHANGE_URL}
        except Exception as e:
            services["token_exchange"] = {"status": "unhealthy", "error": str(e)}

        # Vault
        try:
            r = requests.get(f"{VAULT_ADDR}/v1/sys/health", timeout=3)
            services["vault"] = {"status": "healthy" if r.status_code == 200 else "unhealthy", "url": VAULT_ADDR}
        except Exception as e:
            services["vault"] = {"status": "unhealthy", "error": str(e)}

        # PostgreSQL
        try:
            conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user="postgres", password="postgres-root-password", connect_timeout=3)
            conn.close()
            services["postgresql"] = {"status": "healthy", "host": DB_HOST, "port": DB_PORT}
        except Exception as e:
            services["postgresql"] = {"status": "unhealthy", "error": str(e)}

        # SPIRE (check socket existence)
        spire_ok = os.path.exists(SPIRE_SOCKET)
        services["spire"] = {"status": "healthy" if spire_ok else "unavailable", "socket": SPIRE_SOCKET, "note": "Socket present" if spire_ok else "Socket not found; will use synthetic SVIDs"}

        all_healthy = all(s.get("status") == "healthy" for name, s in services.items() if name != "spire")
        self._send_json(200, {"overall": "healthy" if all_healthy else "degraded", "services": services})

    # --- Auth: Password Login (used by device flow server-side approval) ---

    def _handle_login(self):
        body = self._read_body()
        username = body.get("username", "alice")
        password = body.get("password", "")

        token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
        start = time.time()
        try:
            r = requests.post(token_url, data={
                "grant_type": "password",
                "client_id": KEYCLOAK_CLIENT_ID,
                "username": username,
                "password": password,
                "scope": "openid",
            }, timeout=10)
            elapsed = int((time.time() - start) * 1000)

            if r.status_code != 200:
                self._send_json(r.status_code, {"error": True, "service": "keycloak", "message": r.text, "elapsed_ms": elapsed})
                return

            data = r.json()
            access_token = data.get("access_token", "")
            decoded = decode_token_safe(access_token)

            self._send_json(200, {
                "access_token": access_token,
                "token_type": data.get("token_type"),
                "expires_in": data.get("expires_in"),
                "decoded": decoded,
                "username": resolve_username(decoded) or username,
                "elapsed_ms": elapsed,
            })
        except Exception as e:
            self._send_error(502, "keycloak", str(e))

    # --- Auth: Authorization Code Exchange ---

    def _handle_code_exchange(self):
        body = self._read_body()
        code = body.get("code", "")
        redirect_uri = body.get("redirect_uri", "")

        token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
        start = time.time()
        try:
            r = requests.post(token_url, data={
                "grant_type": "authorization_code",
                "client_id": KEYCLOAK_CLIENT_ID,
                "code": code,
                "redirect_uri": redirect_uri,
            }, timeout=10)
            elapsed = int((time.time() - start) * 1000)

            if r.status_code != 200:
                self._send_json(r.status_code, {"error": True, "service": "keycloak", "message": r.text, "elapsed_ms": elapsed})
                return

            data = r.json()
            access_token = data.get("access_token", "")
            decoded = decode_token_safe(access_token)

            self._send_json(200, {
                "access_token": access_token,
                "token_type": data.get("token_type"),
                "expires_in": data.get("expires_in"),
                "decoded": decoded,
                "username": resolve_username(decoded),
                "elapsed_ms": elapsed,
            })
        except Exception as e:
            self._send_error(502, "keycloak", str(e))

    # --- Auth: Device Flow Start ---

    def _handle_device_start(self):
        device_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth/device"
        start = time.time()
        try:
            r = requests.post(device_url, data={
                "client_id": KEYCLOAK_CLIENT_ID,
                "scope": "openid",
            }, timeout=10)
            elapsed = int((time.time() - start) * 1000)

            if r.status_code != 200:
                self._send_json(r.status_code, {"error": True, "service": "keycloak", "message": r.text, "elapsed_ms": elapsed})
                return

            data = r.json()
            self._send_json(200, {
                "device_code": data.get("device_code"),
                "user_code": data.get("user_code"),
                "verification_uri": data.get("verification_uri"),
                "verification_uri_complete": data.get("verification_uri_complete"),
                "expires_in": data.get("expires_in"),
                "interval": data.get("interval", 5),
                "elapsed_ms": elapsed,
            })
        except Exception as e:
            self._send_error(502, "keycloak", str(e))

    # --- Auth: Device Flow Poll ---

    def _handle_device_poll(self):
        body = self._read_body()
        device_code = body.get("device_code", "")

        token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
        start = time.time()
        try:
            r = requests.post(token_url, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": KEYCLOAK_CLIENT_ID,
                "device_code": device_code,
            }, timeout=10)
            elapsed = int((time.time() - start) * 1000)

            data = r.json()
            if r.status_code == 200:
                access_token = data.get("access_token", "")
                decoded = decode_token_safe(access_token)
                self._send_json(200, {
                    "status": "complete",
                    "access_token": access_token,
                    "decoded": decoded,
                    "username": resolve_username(decoded),
                    "elapsed_ms": elapsed,
                })
            else:
                error = data.get("error", "unknown")
                self._send_json(200, {
                    "status": "pending" if error == "authorization_pending" else "slow_down" if error == "slow_down" else "error",
                    "error": error,
                    "error_description": data.get("error_description", ""),
                    "elapsed_ms": elapsed,
                })
        except Exception as e:
            self._send_error(502, "keycloak", str(e))

    # --- Auth: Device Flow Server-Side Approval ---

    @staticmethod
    def _fix_session_cookies(session):
        """Remove the Secure flag from session cookies.

        Keycloak sets Secure on cookies even for HTTP connections in dev mode.
        Python's requests library correctly refuses to send Secure cookies over
        HTTP, which breaks the multi-step redirect chain in the device
        verification flow. This is equivalent to how curl always stores and
        sends cookies regardless of the Secure flag.
        """
        for cookie in session.cookies:
            cookie.secure = False

    def _follow_keycloak_redirects(self, session, response):
        """Follow HTTP redirects, fixing Secure cookies at each hop.

        Keycloak's device verification flow involves a multi-step redirect
        chain (device → oidc/auth → login-actions/authenticate) where each
        redirect may set new Secure cookies. We follow redirects manually
        so we can fix cookie security flags between each hop.
        """
        for _ in range(10):
            if response.status_code not in (301, 302, 303, 307, 308):
                break
            location = response.headers.get("Location", "")
            if not location:
                break
            if location.startswith("/"):
                p = urlparse(KEYCLOAK_URL)
                location = f"{p.scheme}://{p.netloc}{location}"
            response = session.get(location, allow_redirects=False, timeout=10)
            self._fix_session_cookies(session)
        return response

    def _handle_device_approve(self):
        """Approve a device flow server-side for environments where the browser
        cannot directly access Keycloak (e.g., devcontainer, Docker-in-Docker).

        Emulates the browser flow: visit device verification page → submit
        login credentials → approve consent → device code becomes authorized.
        The agent polling (/api/auth/device-poll) then picks up the token.
        """
        body = self._read_body()
        user_code = body.get("user_code", "")
        username = body.get("username", "alice")
        password = body.get("password", "")

        if not user_code:
            self._send_error(400, "keycloak", "user_code is required")
            return

        start = time.time()
        session = requests.Session()

        try:
            # Step 1: Visit device verification page.
            # Keycloak issues a redirect chain: device → oidc/auth → login-actions/authenticate
            # Each redirect sets cookies with `Secure` flag that we must fix for HTTP.
            verify_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/device?user_code={user_code}"
            logger.info("Device approve step 1: GET %s", verify_url)
            r = session.get(verify_url, allow_redirects=False, timeout=10)
            self._fix_session_cookies(session)
            r = self._follow_keycloak_redirects(session, r)
            logger.info("Device approve step 1 result: status=%d url=%s", r.status_code, r.url[:120])

            # Step 2: Extract and submit the login form
            action_match = re.search(r'action="([^"]*)"', r.text)
            if not action_match:
                elapsed = int((time.time() - start) * 1000)
                logger.warning("Device approve: no login form found. status=%d content_length=%d", r.status_code, len(r.text))
                self._send_json(400, {
                    "error": True, "service": "keycloak",
                    "message": "Login form not found on device verification page",
                    "elapsed_ms": elapsed,
                })
                return

            action_url = html_mod.unescape(action_match.group(1))
            if action_url.startswith("/"):
                p = urlparse(KEYCLOAK_URL)
                action_url = f"{p.scheme}://{p.netloc}{action_url}"

            logger.info("Device approve step 2: POST login to %s", action_url[:120])
            r = session.post(
                action_url,
                data={"username": username, "password": password},
                allow_redirects=False, timeout=10,
            )
            self._fix_session_cookies(session)
            r = self._follow_keycloak_redirects(session, r)
            logger.info("Device approve step 2 result: status=%d url=%s", r.status_code, r.url[:120])

            # Step 3: Handle consent/grant page if Keycloak requires explicit approval
            if "oauth_grant" in r.url.lower() or "grant" in r.text[:2000].lower():
                consent_match = re.search(r'action="([^"]*)"', r.text)
                if consent_match:
                    consent_url = html_mod.unescape(consent_match.group(1))
                    if consent_url.startswith("/"):
                        p = urlparse(KEYCLOAK_URL)
                        consent_url = f"{p.scheme}://{p.netloc}{consent_url}"
                    logger.info("Device approve step 3: POST consent to %s", consent_url[:120])
                    r = session.post(consent_url, data={"accept": "Yes"}, allow_redirects=False, timeout=10)
                    self._fix_session_cookies(session)
                    r = self._follow_keycloak_redirects(session, r)
                    logger.info("Device approve step 3 result: status=%d url=%s", r.status_code, r.url[:120])

            elapsed = int((time.time() - start) * 1000)

            if "Device Login Successful" in r.text or "device/status" in r.url:
                self._send_json(200, {"status": "approved", "message": "Device login approved", "elapsed_ms": elapsed})
            else:
                logger.warning("Device approve: unexpected result. url=%s status=%d", r.url[:120], r.status_code)
                self._send_json(400, {
                    "error": True, "service": "keycloak",
                    "message": "Device approval did not complete — check credentials or user_code",
                    "final_url": r.url,
                    "elapsed_ms": elapsed,
                })

        except requests.Timeout:
            elapsed = int((time.time() - start) * 1000)
            self._send_error(504, "keycloak", f"Device approval timed out ({elapsed}ms)")
        except Exception as e:
            logger.exception("Device approve failed")
            elapsed = int((time.time() - start) * 1000)
            self._send_error(502, "keycloak", f"Device approval failed: {e}")

    # --- Auth: Logout (kill Keycloak sessions + clear proxy cookies) ---

    def _handle_logout(self):
        body = self._read_body()
        username = body.get("username", "")

        if not username:
            self._send_error(400, "keycloak", "username is required")
            return

        start = time.time()
        try:
            admin_token = self._get_admin_token()
            if not admin_token:
                self._send_error(502, "keycloak", "Failed to get admin token")
                return

            user_id, user = self._get_user_by_name(admin_token, username)
            if not user_id:
                self._send_error(404, "keycloak", f"User '{username}' not found")
                return

            # Terminate all sessions for this user
            requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/logout",
                headers={"Authorization": f"Bearer {admin_token}"},
                timeout=10,
            )

            elapsed = int((time.time() - start) * 1000)

            # Build response
            resp_body = json.dumps({
                "status": "logged_out",
                "username": username,
                "message": "All Keycloak sessions terminated",
                "elapsed_ms": elapsed,
            }, indent=2).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._cors_headers()

            # Expire Keycloak SSO cookies set via the reverse proxy
            for cookie_name in (
                "KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION",
                "KEYCLOAK_IDENTITY_LEGACY", "KEYCLOAK_SESSION_LEGACY",
                "AUTH_SESSION_ID", "AUTH_SESSION_ID_LEGACY", "KC_RESTART",
            ):
                for path in ("/", f"/realms/{KEYCLOAK_REALM}/"):
                    self.send_header(
                        "Set-Cookie",
                        f"{cookie_name}=; Path={path}; Max-Age=0; "
                        "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                    )

            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

        except Exception as e:
            logger.exception("Logout failed")
            self._send_error(502, "keycloak", str(e))

    # --- Consent: Get/Update agent delegation consent via Keycloak user attributes ---

    def _get_admin_token(self):
        """Obtain a Keycloak admin access token."""
        r = requests.post(
            f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
            data={
                "client_id": "admin-cli",
                "username": "admin",
                "password": "admin",
                "grant_type": "password",
            },
            timeout=10,
        )
        if r.status_code != 200:
            return None
        return r.json().get("access_token")

    def _get_user_by_name(self, admin_token, username):
        """Look up a Keycloak user by username or email, return (user_id, user_obj) or (None, None)."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        # Try exact username match first
        r = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users",
            params={"username": username, "exact": "true"},
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200 and r.json():
            user = r.json()[0]
            return user["id"], user
        # Fall back to email search (handles state.user = "alice@acme.com")
        if "@" in username:
            r = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users",
                params={"email": username, "exact": "true"},
                headers=headers,
                timeout=10,
            )
            if r.status_code == 200 and r.json():
                user = r.json()[0]
                return user["id"], user
        return None, None

    def _handle_consent_get(self):
        """Get the current agent_consent attribute for a user."""
        body = self._read_body()
        username = body.get("username", "")

        if not username:
            self._send_error(400, "consent", "username is required")
            return

        start = time.time()
        try:
            admin_token = self._get_admin_token()
            if not admin_token:
                self._send_error(502, "keycloak", "Failed to get admin token")
                return

            user_id, user = self._get_user_by_name(admin_token, username)
            if not user_id:
                self._send_error(404, "keycloak", f"User '{username}' not found")
                return

            attrs = user.get("attributes") or {}
            consent_raw = attrs.get("agent_consent", [""])[0] if attrs.get("agent_consent") else ""

            consent = None
            if consent_raw:
                try:
                    consent = json.loads(consent_raw)
                except (json.JSONDecodeError, TypeError):
                    consent = None

            elapsed = int((time.time() - start) * 1000)
            self._send_json(200, {
                "username": username,
                "consent": consent,
                "consent_raw": consent_raw,
                "elapsed_ms": elapsed,
            })
        except Exception as e:
            logger.exception("Consent get failed")
            self._send_error(502, "keycloak", str(e))

    def _handle_consent_update(self):
        """Update the agent_consent attribute for a user, then refresh their access token."""
        body = self._read_body()
        username = body.get("username", "")
        agents = body.get("agents", [])  # list of SPIFFE IDs the user consents to

        if not username:
            self._send_error(400, "consent", "username is required")
            return

        start = time.time()
        try:
            admin_token = self._get_admin_token()
            if not admin_token:
                self._send_error(502, "keycloak", "Failed to get admin token")
                return

            user_id, user = self._get_user_by_name(admin_token, username)
            if not user_id:
                self._send_error(404, "keycloak", f"User '{username}' not found")
                return

            # Build the may_act consent value
            if agents:
                consent_value = {
                    "sub": agents[0],  # Primary agent
                    "aud": agents,
                    "client_id": "ai-agent-service",
                }
                consent_json = json.dumps(consent_value, separators=(",", ":"))
            else:
                consent_json = ""

            # Update user attributes via Keycloak Admin API
            # Send essential identity fields alongside attributes to avoid
            # Keycloak nulling them out on the PUT (partial representation).
            existing_attrs = user.get("attributes") or {}
            existing_attrs["agent_consent"] = [consent_json] if consent_json else []

            update_body = {
                "email": user.get("email"),
                "emailVerified": user.get("emailVerified", False),
                "firstName": user.get("firstName"),
                "lastName": user.get("lastName"),
                "enabled": user.get("enabled", True),
                "attributes": existing_attrs,
            }

            r = requests.put(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
                json=update_body,
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )

            if r.status_code not in (200, 204):
                self._send_error(r.status_code, "keycloak",
                                 f"Failed to update user attributes: {r.text}")
                return

            elapsed = int((time.time() - start) * 1000)

            consent_obj = json.loads(consent_json) if consent_json else None
            self._send_json(200, {
                "status": "updated",
                "username": username,
                "consent": consent_obj,
                "agents": agents,
                "message": (
                    f"Agent consent updated for {username}. "
                    "Re-authenticate to get a token with the new may_act claim."
                ),
                "elapsed_ms": elapsed,
            })
        except Exception as e:
            logger.exception("Consent update failed")
            self._send_error(502, "keycloak", str(e))

    # --- SPIFFE SVID ---

    def _handle_spiffe_svid(self):
        body = self._read_body()
        agent_id = body.get("agent_id", "query-agent")
        agent_type = body.get("agent_type", "agent")  # "agent" or "subagent"
        spiffe_id = f"spiffe://demo.local/{agent_type}/{agent_id}"

        start = time.time()

        # Build step-by-step trace of what happens under the hood
        steps = []

        # Step 1: Construct SPIFFE ID from trust domain + workload path
        steps.append({
            "step": 1,
            "action": "Construct SPIFFE ID",
            "detail": f"Trust domain 'demo.local' + workload path '/{agent_type}/{agent_id}'",
            "result": spiffe_id,
            "status": "ok",
        })

        # Step 2: Check for SPIRE agent socket
        spire_socket_found = os.path.exists(SPIRE_SOCKET)
        caller_uid = os.getuid()
        caller_pid = os.getpid()
        steps.append({
            "step": 2,
            "action": "Connect to SPIRE Workload API",
            "detail": (
                f"The SPIRE agent exposes a Unix domain socket at {SPIRE_SOCKET}. "
                "Any workload on this host can connect to request an identity. "
                "The kernel attaches the caller's PID and UID to the socket connection — "
                "this is how SPIRE knows who is asking."
            ),
            "result": (
                f"Connected (caller PID={caller_pid}, UID={caller_uid})"
                if spire_socket_found else
                "Socket not found — SPIRE agent not available in this container"
            ),
            "status": "ok" if spire_socket_found else "skip",
        })

        # Step 3+: Attempt to fetch real SVID from SPIRE, or generate synthetic
        svid_token = None
        source = "synthetic"
        jwt_header = None

        if spire_socket_found:
            try:
                from spiffe import WorkloadApiClient

                # Sub-step 3a: Kernel-level attestation
                steps.append({
                    "step": 3,
                    "action": "SPIRE kernel-level attestation",
                    "detail": (
                        f"SPIRE agent reads the caller's identity from the kernel: "
                        f"UID={caller_uid} (via SO_PEERCRED on the Unix socket). "
                        "It then checks its registration entries for a selector matching "
                        f"'unix:uid:{caller_uid}'. This is zero-trust — no passwords or "
                        "API keys are exchanged, just kernel-verified process metadata."
                    ),
                    "result": f"Attestation selector: unix:uid:{caller_uid}",
                    "status": "ok",
                })

                client = WorkloadApiClient(socket_path=f"unix://{SPIRE_SOCKET}")
                svid_set = client.fetch_jwt_svids(audience={"token-exchange"})
                if svid_set and len(svid_set) > 0:
                    svid_token = svid_set[0].token
                    source = "spire"

                    # Parse JWT header for signing details
                    import base64
                    try:
                        hdr_b64 = svid_token.split(".")[0]
                        hdr_b64 += "=" * (4 - len(hdr_b64) % 4)
                        jwt_header = json.loads(base64.urlsafe_b64decode(hdr_b64))
                    except Exception:
                        jwt_header = {}

                    alg = jwt_header.get("alg", "?")
                    kid = jwt_header.get("kid", "?")

                    # Sub-step 3b: Entry match and SVID issuance
                    steps.append({
                        "step": 4,
                        "action": "SPIRE issues signed JWT-SVID",
                        "detail": (
                            f"The SPIRE agent matched selector 'unix:uid:{caller_uid}' "
                            f"to the registration entry for {spiffe_id}. "
                            f"The SPIRE server's CA then signed a JWT-SVID using {alg} "
                            f"(key ID: {kid[:12]}...). This cryptographic signature proves "
                            "the SVID was issued by the trust domain's root of trust."
                        ),
                        "result": f"JWT-SVID signed with {alg} by SPIRE CA (trust domain: demo.local)",
                        "status": "ok",
                    })
            except Exception as e:
                logger.info("SPIRE socket available but fetch failed: %s — using synthetic", e)

        if svid_token is None:
            now = int(time.time())
            claims = {
                "sub": spiffe_id,
                "aud": ["token-exchange"],
                "exp": now + 3600,
                "iat": now,
                "client_type": "ai_agent",
            }
            svid_token = jwt.encode(claims, "demo-secret", algorithm="HS256")
            source = "synthetic"
            steps.append({
                "step": 3,
                "action": "Mint JWT-SVID for demo",
                "detail": (
                    "In production, the SPIRE agent would attest the workload "
                    "(verify PID, UID, container labels) and issue a CA-signed JWT-SVID. "
                    "For this demo, we mint an equivalent JWT with the same claims structure."
                ),
                "result": f"JWT-SVID created with sub={spiffe_id}, aud=['token-exchange'], client_type='ai_agent'",
                "status": "ok",
            })

        # Final step: ready for Token Exchange
        next_step = max(s["step"] for s in steps) + 1
        steps.append({
            "step": next_step,
            "action": "SVID ready for Token Exchange",
            "detail": (
                "The Token Exchange service will verify this SVID's 'sub' claim is a "
                "registered agent in the SPIFFE trust domain 'demo.local', and that "
                "the audience includes 'token-exchange'."
            ),
            "result": "SVID will be sent as actor_token in the RFC 8693 exchange",
            "status": "ok",
        })

        elapsed = int((time.time() - start) * 1000)
        decoded = decode_token_safe(svid_token)

        self._send_json(200, {
            "svid_token": svid_token,
            "spiffe_id": spiffe_id,
            "source": source,
            "decoded": decoded,
            "jwt_header": jwt_header,
            "steps": steps,
            "elapsed_ms": elapsed,
        })

    # --- OPA Policy Evaluation ---

    def _handle_opa_evaluate(self):
        body = self._read_body()

        opa_input = body.get("input", {})
        start = time.time()
        try:
            # Query the full decision object for detailed results
            r = requests.post(f"{OPA_URL}/v1/data/delegation", json={"input": opa_input}, timeout=5)
            elapsed = int((time.time() - start) * 1000)

            if r.status_code != 200:
                self._send_json(r.status_code, {"error": True, "service": "opa", "message": r.text, "elapsed_ms": elapsed})
                return

            result = r.json().get("result", {})
            self._send_json(200, {
                "result": result,
                "input": opa_input,
                "elapsed_ms": elapsed,
            })
        except Exception as e:
            self._send_error(502, "opa", str(e))

    # --- Token Exchange ---

    def _handle_token_exchange(self):
        body = self._read_body()

        exchange_body = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": body.get("subject_token", ""),
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": body.get("actor_token", ""),
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": body.get("scope", "readonly"),
            "audience": "delegation",
        }

        start = time.time()
        try:
            r = requests.post(f"{TOKEN_EXCHANGE_URL}/v1/token/exchange", json=exchange_body, timeout=15)
            elapsed = int((time.time() - start) * 1000)

            data = r.json()

            # Decode the delegation token for display
            delegation_token = data.get("access_token")
            if delegation_token:
                data["delegation_token_decoded"] = decode_token_safe(delegation_token)

            data["elapsed_ms"] = elapsed

            # Decode input tokens so the UI can display them without prior state
            subject_token = body.get("subject_token", "")
            actor_token = body.get("actor_token", "")
            if subject_token:
                data["subject_token_decoded"] = decode_token_safe(subject_token)
            if actor_token:
                data["actor_token_decoded"] = decode_token_safe(actor_token)

            self._send_json(r.status_code, data)
        except Exception as e:
            self._send_error(502, "token-exchange", str(e))

    # --- Mediated Vault Credential Brokering (Step 6) ---

    def _handle_vault_credentials(self):
        """Broker dynamic database credentials via Token Exchange.

        The agent presents the delegation token from Step 5. Token Exchange
        validates the token (RS256 signature, expiry, revocation) and uses
        its own privileged Vault token to broker credentials. The agent never
        talks to Vault directly.
        """
        body = self._read_body()
        delegation_token = body.get("delegation_token", "")

        if not delegation_token:
            self._send_error(400, "token-exchange", "delegation_token is required")
            return

        start = time.time()
        steps = []

        # Decode delegation token client-side (for UI display only)
        delegation_decoded = decode_token_safe(delegation_token)
        scope = delegation_decoded.get("scope", "readonly") if delegation_decoded else "readonly"
        session_id = delegation_decoded.get("session_id", "") if delegation_decoded else ""
        vault_role = f"ai-agent-{scope}"

        steps.append({
            "step": 1,
            "action": "Present delegation token to Token Exchange",
            "detail": (
                "The agent sends the delegation token (from Step 5) to the "
                "Token Exchange Service's /v1/token/credentials endpoint. "
                "This token proves that a human authorized this agent to act."
            ),
            "result": f"Delegation token presented (session: {session_id}, scope: {scope})",
            "status": "ok",
        })

        steps.append({
            "step": 2,
            "action": "Token Exchange validates delegation token",
            "detail": (
                "Token Exchange verifies the RS256 signature using its own signing key, "
                "checks the token hasn't expired, and confirms it hasn't been revoked."
            ),
            "result": "Validating...",
            "status": "pending",
        })

        # Call Token Exchange to broker credentials
        try:
            r = requests.post(
                f"{TOKEN_EXCHANGE_URL}/v1/token/credentials",
                json={"delegation_token": delegation_token},
                timeout=15,
            )
            elapsed = int((time.time() - start) * 1000)
            data = r.json()

            if r.status_code == 200 and "error" not in data:
                steps[1]["result"] = "Token validated: signature OK, not expired, not revoked"
                steps[1]["status"] = "ok"

                steps.append({
                    "step": 3,
                    "action": f"Map scope to Vault role ({scope} → {vault_role})",
                    "detail": (
                        f"The authorized scope '{scope}' maps to Vault database role "
                        f"'{vault_role}', which controls the PostgreSQL permissions granted."
                    ),
                    "result": f"Vault role: {vault_role}",
                    "status": "ok",
                })

                steps.append({
                    "step": 4,
                    "action": "Vault issues dynamic credentials",
                    "detail": (
                        "Token Exchange uses its own privileged Vault token (from bootstrap) "
                        "to request credentials from Vault's database secrets engine. "
                        "The agent never authenticates to Vault directly."
                    ),
                    "result": f"Dynamic user: {data.get('username', '?')}, TTL: {data.get('ttl_seconds', '?')}s",
                    "status": "ok",
                })

                # Override host for host-network mode
                host = data.get("host", DB_HOST)
                if host == "postgresql":
                    host = DB_HOST

                self._send_json(200, {
                    "username": data.get("username", ""),
                    "password": data.get("password", ""),
                    "host": host,
                    "port": data.get("port", DB_PORT),
                    "database": data.get("database", DB_NAME),
                    "ttl_seconds": data.get("ttl_seconds", 0),
                    "lease_id": data.get("lease_id", ""),
                    "vault_role": data.get("vault_role", vault_role),
                    "delegation_verified": data.get("delegation_verified", True),
                    "scope": data.get("scope", scope),
                    "subject": data.get("subject", ""),
                    "actor": data.get("actor", ""),
                    "session_id": data.get("session_id", session_id),
                    "steps": steps,
                    "cli_command": (
                        f"curl -X POST {TOKEN_EXCHANGE_URL}/v1/token/credentials "
                        f"-d '{{\"delegation_token\": \"$DELEGATION_TOKEN\"}}'"
                    ),
                    "http_equivalent": {
                        "method": "POST",
                        "url": f"{TOKEN_EXCHANGE_URL}/v1/token/credentials",
                        "body": {"delegation_token": "<delegation-token-from-step-5>"},
                    },
                    "elapsed_ms": elapsed,
                })
            else:
                error_desc = data.get("error_description", data.get("error", "Unknown error"))
                steps[1]["result"] = f"Validation failed: {error_desc}"
                steps[1]["status"] = "fail"

                self._send_json(r.status_code if r.status_code >= 400 else 400, {
                    "error": data.get("error", "credential_broker_failed"),
                    "error_description": error_desc,
                    "steps": steps,
                    "elapsed_ms": elapsed,
                })
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            steps[1]["result"] = f"Error: {e}"
            steps[1]["status"] = "fail"
            self._send_error(502, "token-exchange", str(e))

    # --- Database Query ---

    def _handle_db_query(self):
        """Execute a SQL query using Vault-issued dynamic credentials.

        Security model: The SQL statement is intentionally passed through
        without application-level filtering. Defense-in-depth is enforced by
        Vault's dynamic credentials — the 'ai-agent-readonly' role grants only
        SELECT on the 'app' schema, so INSERT/UPDATE/DELETE/DROP are rejected
        by PostgreSQL itself. This design demonstrates that credential scoping
        (not query filtering) is the correct security boundary.
        """
        body = self._read_body()

        host = body.get("host", DB_HOST)
        port = body.get("port", DB_PORT)
        database = body.get("database", DB_NAME)
        username = body.get("username", "")
        password = body.get("password", "")
        sql = body.get("sql", "SELECT 1")

        # Override host for host-network mode
        if host == "postgresql":
            host = DB_HOST

        start = time.time()
        try:
            conn = psycopg2.connect(
                host=host, port=port, dbname=database,
                user=username, password=password,
                connect_timeout=5,
                options="-c search_path=app,public"
            )
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(sql)

            columns = [desc[0] for desc in cur.description] if cur.description else []
            rows = cur.fetchall() if cur.description else []

            cur.close()
            conn.close()
            elapsed = int((time.time() - start) * 1000)

            self._send_json(200, {
                "columns": columns,
                "rows": [list(row) for row in rows],
                "row_count": len(rows),
                "elapsed_ms": elapsed,
            })
        except psycopg2.OperationalError as e:
            elapsed = int((time.time() - start) * 1000)
            self._send_json(200, {
                "error": True,
                "service": "postgresql",
                "message": str(e).strip(),
                "elapsed_ms": elapsed,
                "connection_failed": True,
            })
        except psycopg2.Error as e:
            elapsed = int((time.time() - start) * 1000)
            self._send_error(400, "postgresql", str(e).strip())

    # --- Revocation ---

    def _handle_revoke(self):
        body = self._read_body()
        session_id = body.get("session_id", "")
        delegation_token = body.get("delegation_token", "")
        lease_id = body.get("lease_id", "")

        start = time.time()
        try:
            r = requests.post(f"{TOKEN_EXCHANGE_URL}/v1/token/revoke", json={
                "session_id": session_id,
                "token": delegation_token,
            }, timeout=10)
            elapsed = int((time.time() - start) * 1000)

            data = r.json()
            data["elapsed_ms"] = elapsed

            # Also revoke the Vault lease directly if we have one
            if lease_id and GATEWAY_VAULT_TOKEN:
                try:
                    requests.put(
                        f"{VAULT_ADDR}/v1/sys/leases/revoke",
                        headers={"X-Vault-Token": GATEWAY_VAULT_TOKEN},
                        json={"lease_id": lease_id},
                        timeout=10,
                    )
                    data["vault_lease_revoked"] = True
                    data["vault_lease_id"] = lease_id
                except Exception as ve:
                    logger.warning("Vault lease revocation failed: %s", ve)
                    data["vault_lease_revoked"] = False

            self._send_json(r.status_code, data)
        except Exception as e:
            self._send_error(502, "token-exchange", str(e))

    # --- Verify Revoked ---

    def _handle_verify_revoked(self):
        body = self._read_body()
        username = body.get("username", "")
        password = body.get("password", "")

        start = time.time()
        try:
            conn = psycopg2.connect(
                host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
                user=username, password=password,
                connect_timeout=5,
            )
            conn.close()
            elapsed = int((time.time() - start) * 1000)
            # If we get here, credentials still work (unexpected)
            self._send_json(200, {
                "revoked": False,
                "message": "Credentials still valid (Vault lease may not have expired yet)",
                "elapsed_ms": elapsed,
            })
        except psycopg2.OperationalError as e:
            elapsed = int((time.time() - start) * 1000)
            self._send_json(200, {
                "revoked": True,
                "message": "Connection denied — credentials successfully revoked",
                "pg_error": str(e).strip(),
                "elapsed_ms": elapsed,
            })

    # --- Audit Log ---

    def _handle_audit(self):
        start = time.time()
        try:
            r = requests.get(f"{TOKEN_EXCHANGE_URL}/v1/audit", timeout=5)
            elapsed = int((time.time() - start) * 1000)

            data = r.json()
            self._send_json(200, {"entries": data, "elapsed_ms": elapsed})
        except Exception as e:
            self._send_error(502, "token-exchange", str(e))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def _ensure_user_profile_attribute():
    """Ensure the 'agent_consent' attribute is registered in the Keycloak User Profile.

    Keycloak 26+ silently drops unknown attributes on user PUT unless they
    are declared in the realm's User Profile configuration.

    NOTE: This duplicates the admin token acquisition from DemoHandler._get_admin_token
    because it runs at startup before any handler instance exists.
    """
    try:
        # Get admin token (standalone — no handler instance at startup)
        r = requests.post(
            f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": "admin-cli",
                  "username": "admin", "password": "admin"},
            timeout=10,
        )
        if r.status_code != 200:
            logger.warning("Could not get admin token for user profile setup")
            return

        admin_token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {admin_token}",
                   "Content-Type": "application/json"}

        # Get current profile
        r = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/profile",
            headers=headers, timeout=10,
        )
        if r.status_code != 200:
            logger.warning("Could not read user profile config: %d", r.status_code)
            return

        profile = r.json()
        attr_names = [a["name"] for a in profile.get("attributes", [])]

        if "agent_consent" in attr_names:
            logger.info("User profile already has 'agent_consent' attribute")
            return

        # Add agent_consent attribute
        profile["attributes"].append({
            "name": "agent_consent",
            "displayName": "Agent Consent",
            "permissions": {"view": ["admin"], "edit": ["admin"]},
            "multivalued": False,
        })

        r = requests.put(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/profile",
            json=profile, headers=headers, timeout=10,
        )
        if r.status_code == 200:
            logger.info("Registered 'agent_consent' in Keycloak User Profile")
        else:
            logger.warning("Failed to update user profile: %d %s", r.status_code, r.text)
    except Exception as e:
        logger.warning("User profile setup failed (non-fatal): %s", e)


def main():
    _ensure_user_profile_attribute()
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), DemoHandler)
    logger.info("Demo UI server listening on http://0.0.0.0:%d", LISTEN_PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
