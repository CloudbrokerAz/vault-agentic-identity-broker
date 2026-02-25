#!/usr/bin/env python3
"""
Token Exchange Service — Stateless Fused JWT Minter

Accepts a human OIDC token (subject_token) and an agent SPIFFE JWT-SVID
(actor_token), validates both via offline JWKS verification, and mints
a fused delegation JWT with nested act{} claims per RFC 8693.

Endpoints:
  POST /v1/token/exchange   — RFC 8693 token exchange
  GET  /.well-known/jwks.json — RS256 public key
  GET  /health              — Service health
"""

import base64, hashlib, json, logging, os, time, uuid
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

import jwt as pyjwt
from jwt import PyJWKSet
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("token-exchange")

GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_TYPE_SPIFFE = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_TYPE_DELEGATION = "urn:agentic:token-type:delegation"
TOKEN_TYPE_AGENT_DELEGATION = "urn:agentic:token-type:agent-delegation"

GROUP_PERMISSIONS = {
    "data-analysts": ["readonly", "db:read", "db:query"],
    "trading-team": ["readonly", "db:read", "db:query"],
    "engineering": ["readonly", "readwrite", "db:read", "db:write", "db:query"],
}


def _error(code: str, desc: str) -> dict:
    return {"error": code, "error_description": desc}


def _find_jwk(jwks_data: dict, kid: str | None):
    """Find a signing key in a JWKS by kid, returning the crypto key or None."""
    jwk_set = PyJWKSet.from_dict(jwks_data)
    for k in jwk_set.keys:
        if kid and k.key_id == kid:
            return k.key
        if not kid:
            return k.key
    return None


class TokenExchangeService:
    """Stateless fused JWT minter with offline JWKS verification."""

    def __init__(self, keycloak_jwks_url="", spire_oidc_url="http://spire-oidc:8082",
                 signing_key_path="", issuer="token-exchange.demo.local",
                 max_delegation_depth=3, default_ttl=300, listen_port=8090):
        self.keycloak_jwks_url = keycloak_jwks_url or os.getenv(
            "KEYCLOAK_JWKS_URL", "http://keycloak:8080/realms/demo/protocol/openid-connect/certs")
        self.spire_oidc_url = spire_oidc_url
        self.issuer = issuer
        self.max_delegation_depth = max_delegation_depth
        self.default_ttl = default_ttl
        self.listen_port = listen_port
        self._jwks_cache: dict[str, tuple[dict, float]] = {}
        self._jwks_cache_ttl = 300

        if signing_key_path:
            with open(signing_key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()
        self._kid = hashlib.sha256(self._public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )).hexdigest()[:16]

    def _fetch_jwks(self, url: str) -> dict | None:
        cached = self._jwks_cache.get(url)
        if cached and (time.time() - cached[1]) < self._jwks_cache_ttl:
            return cached[0]
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                self._jwks_cache[url] = (data, time.time())
                return data
        except requests.RequestException as e:
            logger.warning("JWKS fetch failed for %s: %s", url, e)
        return None

    def _validate_human_token(self, token: str) -> dict:
        # Chain extension: check if it's our own delegation token
        try:
            claims = pyjwt.decode(token, self._public_key, algorithms=["RS256"], options={"verify_aud": False})
            if claims.get("iss") == self.issuer:
                return claims
        except pyjwt.InvalidTokenError:
            pass
        jwks_data = self._fetch_jwks(self.keycloak_jwks_url)
        if jwks_data is None:
            return _error("temporarily_unavailable", "Keycloak JWKS endpoint is unavailable")
        try:
            kid = pyjwt.get_unverified_header(token).get("kid")
            key = _find_jwk(jwks_data, kid)
            if key is None:
                return _error("invalid_request", f"No matching key in Keycloak JWKS for kid={kid}")
            claims = pyjwt.decode(token, key, algorithms=["RS256", "ES256"], options={"verify_aud": False})
            if "email" in claims and claims["email"]:
                claims.setdefault("sub", claims["email"])
            return claims
        except pyjwt.InvalidTokenError as e:
            return _error("invalid_request", f"Human token verification failed: {e}")

    def _validate_agent_token(self, token: str) -> dict:
        try:
            header = pyjwt.get_unverified_header(token)
            unverified = pyjwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        except pyjwt.InvalidTokenError as e:
            return _error("invalid_request", f"Invalid actor token: {e}")
        sub = unverified.get("sub", "")
        if not sub.startswith("spiffe://"):
            return _error("invalid_request", f"Actor token subject '{sub}' is not a SPIFFE ID")
        jwks_data = self._fetch_jwks(f"{self.spire_oidc_url}/keys")
        if jwks_data is None:
            return _error("temporarily_unavailable", "SPIRE JWKS endpoint is unavailable")
        try:
            kid = header.get("kid")
            key = _find_jwk(jwks_data, kid)
            if key is None:
                return _error("invalid_request", f"No matching key in SPIRE JWKS for kid={kid}")
            alg = header.get("alg", "RS256")
            if alg not in ("RS256", "ES256"):
                return _error("invalid_request", f"Unsupported algorithm {alg}")
            return pyjwt.decode(token, key, algorithms=["RS256", "ES256"],
                                audience="token-exchange", options={"verify_aud": True})
        except pyjwt.InvalidTokenError as e:
            return _error("invalid_request", f"SPIFFE JWT-SVID verification failed: {e}")

    def exchange_token(self, params: dict) -> dict:
        if params.get("grant_type") != GRANT_TYPE_TOKEN_EXCHANGE:
            return _error("unsupported_grant_type", f"Expected {GRANT_TYPE_TOKEN_EXCHANGE}")
        subject_token, actor_token = params.get("subject_token"), params.get("actor_token")
        scope = params.get("scope", "readonly")
        if not subject_token:
            return _error("invalid_request", "subject_token is required")
        if not actor_token:
            return _error("invalid_request", "actor_token is required")

        human = self._validate_human_token(subject_token)
        if "error" in human:
            return human
        agent = self._validate_agent_token(actor_token)
        if "error" in agent:
            return agent

        depth = human.get("delegation_depth", 0) if human.get("iss") == self.issuer else 0
        if depth >= self.max_delegation_depth:
            return _error("invalid_request", f"Maximum delegation depth ({self.max_delegation_depth}) exceeded")

        permitted = self._get_permitted_scopes(human)
        if scope not in permitted:
            return _error("invalid_scope", f"Requested scope '{scope}' not permitted. Available: {permitted}")

        agent_sub = agent.get("sub", "unknown")
        if depth == 0:
            act = {"sub": agent_sub, "act": {"sub": human.get("sub", "unknown")}}
        else:
            act = {"sub": agent_sub, "act": human.get("act", {})}

        now = datetime.now(timezone.utc)
        fused_jwt = pyjwt.encode({
            "iss": self.issuer, "sub": human.get("sub", "unknown"), "aud": "vault",
            "exp": int((now + timedelta(seconds=self.default_ttl)).timestamp()),
            "iat": int(now.timestamp()), "jti": str(uuid.uuid4()),
            "scope": scope, "act": act,
            "groups": human.get("groups", []), "may_act": human.get("may_act", {}),
            "delegation_depth": depth + 1,
        }, self._private_key, algorithm="RS256", headers={"kid": self._kid})

        return {"access_token": fused_jwt, "issued_token_type": TOKEN_TYPE_AGENT_DELEGATION,
                "token_type": "Bearer", "expires_in": self.default_ttl, "scope": scope}

    def _get_permitted_scopes(self, claims: dict) -> list[str]:
        if claims.get("iss") == self.issuer:
            s = claims.get("scope", "")
            return [s] if s else []
        permitted: set[str] = set()
        for g in claims.get("groups", []):
            permitted.update(GROUP_PERMISSIONS.get(g, []))
        return list(permitted)

    def jwks(self) -> dict:
        pub = self._public_key.public_numbers()
        def _b64(n):
            return base64.urlsafe_b64encode(
                n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")).rstrip(b"=").decode()
        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self._kid,
                          "n": _b64(pub.n), "e": _b64(pub.e)}]}


class TokenExchangeHandler(BaseHTTPRequestHandler):
    service: TokenExchangeService

    def log_message(self, fmt, *args):
        logger.info("[HTTP] %s", fmt % args)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "healthy", "service": "token-exchange", "version": "4.0.0"})
        elif self.path == "/.well-known/jwks.json":
            self._json(200, self.service.jwks())
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            params = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return self._json(400, {"error": "invalid_json"})
        if self.path == "/v1/token/exchange":
            result = self.service.exchange_token(params)
            self._json(200 if "error" not in result else 400, result)
        else:
            self._json(404, {"error": "not_found"})

    def _json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())


def main():
    svc = TokenExchangeService(
        keycloak_jwks_url=os.getenv("KEYCLOAK_JWKS_URL", ""),
        spire_oidc_url=os.getenv("SPIRE_OIDC_URL", "http://spire-oidc:8082"),
        signing_key_path=os.getenv("SIGNING_KEY_PATH", ""),
        issuer=os.getenv("TOKEN_ISSUER", "token-exchange.demo.local"),
        max_delegation_depth=int(os.getenv("MAX_DELEGATION_DEPTH", "3")),
        default_ttl=int(os.getenv("DEFAULT_TTL", "300")),
        listen_port=int(os.getenv("LISTEN_PORT", "8090")),
    )
    TokenExchangeHandler.service = svc
    server = HTTPServer(("0.0.0.0", svc.listen_port), TokenExchangeHandler)
    logger.info("Token Exchange (slim) on :%d | JWKS: %s | SPIRE: %s | Issuer: %s",
                svc.listen_port, svc.keycloak_jwks_url, svc.spire_oidc_url, svc.issuer)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
