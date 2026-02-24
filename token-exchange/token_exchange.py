#!/usr/bin/env python3
"""
Token Exchange Service - RFC 8693 Implementation for Agentic AI Delegation

Implements OAuth 2.0 Token Exchange (RFC 8693) with delegation semantics
for AI agent identity chains:

  Human (OIDC) -> Agent (SPIFFE) -> Sub-Agent -> ... -> Database

Key concepts:
  - subject_token: The human's OIDC token (the identity being delegated)
  - actor_token: The agent's identity token (SPIFFE JWT-SVID or delegation token)
  - Delegation: Output token has `act` claim identifying the actor chain
  - Scope narrowing: Each delegation level can only narrow, never widen scope
  - Chain depth: Configurable maximum delegation depth (default: 3)

Endpoints:
  POST /v1/token/exchange  - RFC 8693 token exchange
  POST /v1/delegate        - Simplified delegation (backward-compatible)
  POST /v1/token/revoke    - Revoke a delegation token and its credentials
  GET  /v1/delegation/chain - Get the full delegation chain for a session
  GET  /health             - Service health
"""

import hashlib
import hmac
import json
import logging
import os
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from urllib.parse import urlencode

import base64

import jwt as pyjwt
from jwt import PyJWKSet
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ─── Configuration ────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("token-exchange")


@dataclass
class ServiceConfig:
    """Configuration for the Token Exchange Service."""
    listen_port: int = 8090
    keycloak_url: str = "http://keycloak:8080"
    keycloak_realm: str = "demo"
    opa_endpoint: str = "http://opa:8181"
    vault_addr: str = "http://vault:8200"
    vault_token: str = ""
    trust_domain: str = "demo.local"
    spire_oidc_url: str = "http://spire-oidc:8082"
    signing_secret: str = "token-exchange-secret-change-in-production"  # deprecated: use RS256
    signing_key_path: str = ""  # Path to PEM private key; if empty, generates in-memory keypair
    max_delegation_depth: int = 3
    default_ttl: int = 300  # 5 minutes
    max_ttl: int = 1800     # 30 minutes
    jwks_cache_ttl: int = 300  # JWKS cache TTL in seconds
    vault_token_renewal_interval: int = 2700  # Renew Vault token every 45 minutes (before 1h period)
    mtls_enabled: bool = False  # Enable mTLS using SPIFFE X.509-SVIDs
    spire_agent_socket: str = "/tmp/spire-agent/public/api.sock"  # SPIRE Workload API socket

    @classmethod
    def from_env(cls) -> "ServiceConfig":
        return cls(
            listen_port=int(os.getenv("LISTEN_PORT", "8090")),
            keycloak_url=os.getenv("KEYCLOAK_URL", "http://keycloak:8080"),
            keycloak_realm=os.getenv("KEYCLOAK_REALM", "demo"),
            opa_endpoint=os.getenv("OPA_ENDPOINT", "http://opa:8181"),
            vault_addr=os.getenv("VAULT_ADDR", "http://vault:8200"),
            vault_token=os.getenv("VAULT_TOKEN", ""),
            trust_domain=os.getenv("TRUST_DOMAIN", "demo.local"),
            spire_oidc_url=os.getenv("SPIRE_OIDC_URL", "http://spire-oidc:8082"),
            signing_secret=os.getenv("SIGNING_SECRET", "token-exchange-secret-change-in-production"),
            signing_key_path=os.getenv("SIGNING_KEY_PATH", ""),
            max_delegation_depth=int(os.getenv("MAX_DELEGATION_DEPTH", "3")),
            default_ttl=int(os.getenv("DEFAULT_TTL", "300")),
            max_ttl=int(os.getenv("MAX_TTL", "1800")),
            jwks_cache_ttl=int(os.getenv("JWKS_CACHE_TTL", "300")),
            vault_token_renewal_interval=int(os.getenv("VAULT_TOKEN_RENEWAL_INTERVAL", "2700")),
            mtls_enabled=os.getenv("MTLS_ENABLED", "").lower() in ("true", "1", "yes"),
            spire_agent_socket=os.getenv("SPIRE_AGENT_SOCKET", "/tmp/spire-agent/public/api.sock"),
        )


# ─── RFC 8693 Constants ──────────────────────────────────────────────────────

GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

# Token type identifiers (RFC 8693 Section 3)
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_TYPE_SPIFFE = "urn:ietf:params:oauth:token-type:jwt"  # SPIFFE SVIDs are JWTs
TOKEN_TYPE_DELEGATION = "urn:agentic:token-type:delegation"

# Custom token types for the agentic identity broker
TOKEN_TYPE_AGENT_DELEGATION = "urn:agentic:token-type:agent-delegation"


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class DelegationChainLink:
    """A single link in the delegation chain."""
    subject: str           # Who is being acted on behalf of
    actor: str             # Who is acting
    actor_type: str        # "human", "agent", "sub-agent"
    scope: str             # Granted scope at this level
    timestamp: str         # When this link was created
    session_id: str        # Session identifier
    depth: int             # Chain depth (0 = human origin)


@dataclass
class DelegationSession:
    """Tracks a complete delegation session with its chain."""
    session_id: str
    chain: list[DelegationChainLink] = field(default_factory=list)
    db_credentials: Optional[dict] = None
    vault_lease_id: Optional[str] = None
    delegated_token: Optional[str] = None
    created_at: str = ""
    expires_at: str = ""
    revoked: bool = False

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


# ─── Token Exchange Service ───────────────────────────────────────────────────

class TokenExchangeService:
    """
    Implements RFC 8693 Token Exchange with delegation semantics.

    Supports:
    - Human -> Agent delegation (initial delegation)
    - Agent -> Sub-Agent delegation (chain extension)
    - Full delegation chain tracking and validation
    - Integration with OPA for policy decisions
    - Integration with Vault for dynamic credentials
    """

    def __init__(self, config: ServiceConfig):
        self.config = config
        self.sessions: dict[str, DelegationSession] = {}
        self.token_to_session: dict[str, str] = {}  # token_hash -> session_id
        self.audit_log: list[dict] = []
        self.issuer = f"http://token-exchange:{config.listen_port}"

        # JWKS cache for SPIRE OIDC provider
        self._jwks_cache: Optional[dict] = None
        self._jwks_cache_time: float = 0.0

        # Generate or load RSA signing keypair for delegation tokens
        if config.signing_key_path:
            with open(config.signing_key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            logger.info("Loaded signing key from %s", config.signing_key_path)
        else:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            logger.info("Generated in-memory RSA-2048 signing keypair")
        self._public_key = self._private_key.public_key()
        self._kid = hashlib.sha256(
            self._public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()[:16]

        # Start background Vault token renewal thread
        if config.vault_token:
            self._start_vault_renewal()

    # ── Vault Token Renewal ──────────────────────────────────────────────

    def _start_vault_renewal(self):
        """Start a daemon thread that periodically renews the Vault token."""
        def _renewal_loop():
            interval = self.config.vault_token_renewal_interval
            logger.info(
                "Vault token renewal thread started (interval: %ds)", interval
            )
            while True:
                time.sleep(interval)
                try:
                    resp = requests.post(
                        f"{self.config.vault_addr}/v1/auth/token/renew-self",
                        headers={"X-Vault-Token": self.config.vault_token},
                        json={"increment": f"{interval}s"},
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        auth = resp.json().get("auth", {})
                        ttl = auth.get("lease_duration", 0)
                        logger.info("Vault token renewed successfully (new TTL: %ds)", ttl)
                    else:
                        logger.warning(
                            "Vault token renewal failed: HTTP %d: %s",
                            resp.status_code,
                            resp.text[:200],
                        )
                except requests.RequestException as e:
                    logger.warning("Vault token renewal failed: %s", e)

        thread = threading.Thread(target=_renewal_loop, daemon=True, name="vault-renewal")
        thread.start()

    # ── SPIRE JWKS Fetching ──────────────────────────────────────────────

    def _fetch_spire_jwks(self) -> Optional[dict]:
        """
        Fetch JWKS from the SPIRE OIDC Discovery Provider.

        Returns the JWKS dict on success, or None on failure.
        Results are cached for jwks_cache_ttl seconds.
        """
        now = time.time()
        if self._jwks_cache is not None and (now - self._jwks_cache_time) < self.config.jwks_cache_ttl:
            return self._jwks_cache

        jwks_url = f"{self.config.spire_oidc_url}/keys"
        try:
            resp = requests.get(jwks_url, timeout=10)
            if resp.status_code == 200:
                jwks_data = resp.json()
                self._jwks_cache = jwks_data
                self._jwks_cache_time = now
                logger.info(
                    "SPIRE JWKS fetched successfully from %s (%d keys)",
                    jwks_url,
                    len(jwks_data.get("keys", [])),
                )
                return jwks_data
            else:
                logger.warning(
                    "SPIRE JWKS fetch failed: HTTP %d from %s",
                    resp.status_code,
                    jwks_url,
                )
                return None
        except requests.RequestException as e:
            logger.warning("SPIRE JWKS fetch failed: %s (url: %s)", e, jwks_url)
            return None

    # ── RFC 8693 Token Exchange ───────────────────────────────────────────

    def exchange_token(self, params: dict) -> dict:
        """
        Process an RFC 8693 Token Exchange request.

        Required parameters:
          - grant_type: urn:ietf:params:oauth:grant-type:token-exchange
          - subject_token: The token of the entity being acted on behalf of
          - subject_token_type: Type of the subject token
          - actor_token: The token of the entity that will act
          - actor_token_type: Type of the actor token

        Optional parameters:
          - scope: Requested scope (must be subset of subject's scope)
          - audience: Intended audience for the new token
          - requested_token_type: Type of token to issue
          - resource: Target resource URI
        """
        # Validate grant_type
        grant_type = params.get("grant_type")
        if grant_type != GRANT_TYPE_TOKEN_EXCHANGE:
            return self._error_response(
                "unsupported_grant_type",
                f"Expected {GRANT_TYPE_TOKEN_EXCHANGE}, got {grant_type}"
            )

        subject_token = params.get("subject_token")
        subject_token_type = params.get("subject_token_type", TOKEN_TYPE_ACCESS)
        actor_token = params.get("actor_token")
        actor_token_type = params.get("actor_token_type", TOKEN_TYPE_JWT)
        requested_scope = params.get("scope", "readonly")
        audience = params.get("audience", "database")

        if not subject_token:
            return self._error_response("invalid_request", "subject_token is required")
        if not actor_token:
            return self._error_response("invalid_request", "actor_token is required")

        # Step 1: Validate the subject token (human or delegating agent)
        subject_claims = self._validate_subject_token(subject_token, subject_token_type)
        if "error" in subject_claims:
            return subject_claims

        # Step 2: Validate the actor token (agent requesting delegation)
        actor_claims = self._validate_actor_token(actor_token, actor_token_type)
        if "error" in actor_claims:
            return actor_claims

        # Step 3: Check delegation chain depth
        existing_chain = self._extract_delegation_chain(subject_claims)
        chain_depth = len(existing_chain)
        if chain_depth >= self.config.max_delegation_depth:
            return self._error_response(
                "invalid_request",
                f"Maximum delegation depth ({self.config.max_delegation_depth}) exceeded"
            )

        # Step 4: Validate scope narrowing
        subject_scopes = self._get_permitted_scopes(subject_claims)
        if requested_scope not in subject_scopes:
            return self._error_response(
                "invalid_scope",
                f"Requested scope '{requested_scope}' not permitted. "
                f"Available: {subject_scopes}"
            )

        # Step 5: Evaluate OPA policy
        opa_result = self._evaluate_opa_policy(subject_claims, actor_claims, requested_scope)
        if not opa_result.get("allowed", False):
            reason = opa_result.get("reason", "policy_denied")
            self._record_audit("token_exchange", "denied", {
                "subject": subject_claims.get("sub", "unknown"),
                "actor": actor_claims.get("sub", "unknown"),
                "scope": requested_scope,
                "reason": reason,
            })
            return self._error_response("access_denied", f"Policy denied: {reason}")

        # Step 6: Build the delegation chain
        session_id = f"sess-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        # Build chain links
        chain = list(existing_chain)
        if chain_depth == 0:
            # Initial delegation: human -> agent
            chain.append(DelegationChainLink(
                subject=subject_claims.get("sub", subject_claims.get("email", "unknown")),
                actor=actor_claims.get("sub", "unknown"),
                actor_type="agent",
                scope=requested_scope,
                timestamp=now.isoformat(),
                session_id=session_id,
                depth=0,
            ))
        else:
            # Chain extension: agent -> sub-agent
            chain.append(DelegationChainLink(
                subject=subject_claims.get("sub", "unknown"),
                actor=actor_claims.get("sub", "unknown"),
                actor_type="sub-agent",
                scope=requested_scope,
                timestamp=now.isoformat(),
                session_id=session_id,
                depth=chain_depth,
            ))

        # Step 7: Issue the delegated token with `act` claim (RFC 8693 Section 4.1)
        ttl = min(self.config.default_ttl, self.config.max_ttl)
        expires_at = now + timedelta(seconds=ttl)

        # Build the `act` claim chain
        act_claim = self._build_act_claim(chain)

        # The original human subject is always preserved as the top-level subject
        original_subject = chain[0].subject if chain else subject_claims.get("sub", "unknown")

        # Preserve the original OIDC issuer for chain extensions
        original_issuer = subject_claims.get("original_issuer", subject_claims.get("iss", ""))
        if subject_claims.get("iss") == self.issuer:
            # Already a delegation token - keep the original issuer
            original_issuer = subject_claims.get("original_issuer", original_issuer)

        delegation_token_claims = {
            "iss": self.issuer,
            "sub": original_subject,
            "aud": audience,
            "exp": int(expires_at.timestamp()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "jti": str(uuid.uuid4()),
            "scope": requested_scope,
            "act": act_claim,
            "may_act": subject_claims.get("may_act", {}),
            "groups": subject_claims.get("groups", []),
            "original_issuer": original_issuer,
            "delegation_chain": [
                {
                    "subject": link.subject,
                    "actor": link.actor,
                    "actor_type": link.actor_type,
                    "scope": link.scope,
                    "depth": link.depth,
                }
                for link in chain
            ],
            "session_id": session_id,
            "client_id": actor_claims.get("client_id", actor_claims.get("sub", "")),
        }

        # Sign the delegation token with RS256
        delegation_token = pyjwt.encode(
            delegation_token_claims,
            self._private_key,
            algorithm="RS256",
            headers={"kid": self._kid},
        )

        # Step 8: Get Vault credentials if this is a terminal delegation
        # (i.e., the actor needs actual DB access)
        db_credentials = None
        vault_lease_id = None
        if audience == "database" or "db:" in requested_scope:
            db_credentials, vault_lease_id = self._broker_vault_credentials(
                requested_scope, session_id, original_subject,
                actor_claims.get("sub", "unknown"), chain
            )

        # Step 9: Store session
        session = DelegationSession(
            session_id=session_id,
            chain=chain,
            db_credentials=db_credentials,
            vault_lease_id=vault_lease_id,
            delegated_token=delegation_token,
            expires_at=expires_at.isoformat(),
        )
        self.sessions[session_id] = session
        token_hash = hashlib.sha256(delegation_token.encode()).hexdigest()
        self.token_to_session[token_hash] = session_id

        # Record audit
        self._record_audit("token_exchange", "success", {
            "session_id": session_id,
            "subject": original_subject,
            "actor": actor_claims.get("sub", "unknown"),
            "scope": requested_scope,
            "chain_depth": len(chain),
            "has_db_credentials": db_credentials is not None,
        })

        # Step 10: Build RFC 8693 response
        response = {
            "access_token": delegation_token,
            "issued_token_type": TOKEN_TYPE_AGENT_DELEGATION,
            "token_type": "Bearer",
            "expires_in": ttl,
            "scope": requested_scope,
            "session_id": session_id,
        }

        if db_credentials:
            response["db_credential"] = db_credentials

        response["delegation_chain"] = [
            {
                "subject": link.subject,
                "actor": link.actor,
                "actor_type": link.actor_type,
                "scope": link.scope,
                "depth": link.depth,
            }
            for link in chain
        ]

        return response

    # ── Backward-compatible Delegation ────────────────────────────────────

    def delegate(self, request: dict) -> dict:
        """
        Process a simplified delegation request (backward-compatible with
        the legacy delegation API).

        Converts to RFC 8693 token exchange internally.
        Requires agent_jwt_svid to be provided for cryptographic verification.
        """
        human_token = request.get("human_token", "")
        agent_spiffe_id = request.get("agent_spiffe_id", "")
        agent_jwt_svid = request.get("agent_jwt_svid", "")
        requested_scope = request.get("requested_scope", "readonly")

        # Require a real JWT-SVID for cryptographic verification
        if not agent_jwt_svid:
            return self._error_response(
                "invalid_request",
                "agent_jwt_svid is required. Synthetic SPIFFE tokens are no longer "
                "accepted; provide a real SPIFFE JWT-SVID from the SPIRE agent."
            )

        actor_token = agent_jwt_svid

        exchange_params = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": human_token,
            "subject_token_type": TOKEN_TYPE_ACCESS,
            "actor_token": actor_token,
            "actor_token_type": TOKEN_TYPE_SPIFFE,
            "scope": requested_scope,
            "audience": "database",
        }

        result = self.exchange_token(exchange_params)

        if "error" in result:
            return result

        # Convert response to legacy format
        return {
            "session_id": result["session_id"],
            "db_credential": result.get("db_credential"),
            "expires_at": datetime.fromtimestamp(
                time.time() + result["expires_in"], tz=timezone.utc
            ).isoformat(),
            "metadata": {
                "delegating_human": result.get("delegation_chain", [{}])[0].get("subject", "unknown"),
                "delegation_scope": requested_scope,
                "delegation_time": datetime.now(timezone.utc).isoformat(),
                "session_id": result["session_id"],
                "agent_spiffe_id": agent_spiffe_id,
                "delegation_depth": str(len(result.get("delegation_chain", []))),
                "token_exchange_flow": "rfc8693",
            },
            "delegation_token": result["access_token"],
        }

    # ── Token Validation ──────────────────────────────────────────────────

    def _validate_subject_token(self, token: str, token_type: str) -> dict:
        """Validate the subject token (human OIDC or delegation token)."""
        # First, try to validate as a delegation token (from chain extension)
        try:
            claims = pyjwt.decode(
                token,
                self._public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
            if claims.get("iss") == self.issuer:
                logger.info("Subject token is a delegation token (chain extension)")
                return claims
        except pyjwt.InvalidTokenError:
            pass

        # Validate as Keycloak OIDC token
        return self._validate_keycloak_token(token)

    def _validate_actor_token(self, token: str, token_type: str) -> dict:
        """
        Validate the actor token (SPIFFE JWT-SVID or agent identity).

        For SPIFFE JWT-SVIDs, verifies the cryptographic signature against
        the SPIRE OIDC Discovery Provider's JWKS endpoint. This ensures
        only tokens issued by the trusted SPIRE server are accepted.

        Behavior is fail-closed: if JWKS cannot be fetched, the token is
        rejected rather than silently accepted.
        """
        # First, peek at the token header to determine the algorithm
        try:
            unverified_header = pyjwt.get_unverified_header(token)
        except pyjwt.exceptions.DecodeError as e:
            return self._error_response("invalid_request", f"Invalid actor token: {e}")

        # Peek at the claims to check if this is a SPIFFE token
        try:
            unverified_claims = pyjwt.decode(
                token, options={"verify_signature": False, "verify_aud": False}
            )
        except pyjwt.InvalidTokenError as e:
            return self._error_response("invalid_request", f"Invalid actor token: {e}")

        sub = unverified_claims.get("sub", "")

        # If this is a SPIFFE token, verify signature against SPIRE JWKS
        if sub.startswith("spiffe://"):
            # Validate trust domain first (cheap check before network call)
            if not sub.startswith(f"spiffe://{self.config.trust_domain}/"):
                return self._error_response(
                    "invalid_request",
                    f"SPIFFE ID not in trust domain {self.config.trust_domain}"
                )

            # Fetch JWKS from SPIRE OIDC provider
            jwks_data = self._fetch_spire_jwks()
            if jwks_data is None:
                logger.error(
                    "SPIRE JWKS unavailable - rejecting actor token (fail-closed). "
                    "SPIRE OIDC provider at %s may be down.",
                    self.config.spire_oidc_url,
                )
                return self._error_response(
                    "temporarily_unavailable",
                    "SPIRE JWKS endpoint is unavailable. Cannot verify actor token signature."
                )

            # Verify the JWT signature against the SPIRE JWKS
            try:
                # Build signing keys from JWKS
                jwk_set = PyJWKSet.from_dict(jwks_data)

                # Find the right key (match by kid if present in header)
                kid = unverified_header.get("kid")
                signing_key = None
                for jwk_key in jwk_set.keys:
                    if kid and jwk_key.key_id == kid:
                        signing_key = jwk_key.key
                        break
                    elif not kid:
                        # No kid in header, use the first key
                        signing_key = jwk_key.key
                        break

                if signing_key is None:
                    return self._error_response(
                        "invalid_request",
                        f"No matching key found in SPIRE JWKS for kid={kid}"
                    )

                # Verify with actual cryptographic signature check
                alg = unverified_header.get("alg", "RS256")
                allowed_algorithms = ["RS256", "ES256"]
                if alg not in allowed_algorithms:
                    return self._error_response(
                        "invalid_request",
                        f"Unsupported algorithm {alg} in actor token. "
                        f"Allowed: {allowed_algorithms}"
                    )

                verified_claims = pyjwt.decode(
                    token,
                    signing_key,
                    algorithms=allowed_algorithms,
                    audience="token-exchange",
                    options={"verify_aud": True},
                )

                logger.info(
                    "Actor token cryptographically verified: SPIFFE ID %s (alg=%s, kid=%s)",
                    sub, alg, kid,
                )
                return verified_claims

            except pyjwt.InvalidTokenError as e:
                logger.warning(
                    "SPIFFE JWT-SVID signature verification failed for %s: %s",
                    sub, e,
                )
                return self._error_response(
                    "invalid_request",
                    f"SPIFFE JWT-SVID signature verification failed: {e}"
                )

        # Non-SPIFFE actor tokens are rejected - all actors must have
        # cryptographically verifiable identities
        return self._error_response(
            "invalid_request",
            f"Actor token subject '{sub}' is not a valid SPIFFE ID. "
            "All actor tokens must be SPIFFE JWT-SVIDs."
        )

    def _validate_keycloak_token(self, token: str) -> dict:
        """Validate a token against Keycloak's userinfo endpoint."""
        userinfo_url = (
            f"{self.config.keycloak_url}/realms/{self.config.keycloak_realm}"
            f"/protocol/openid-connect/userinfo"
        )

        try:
            resp = requests.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            if resp.status_code == 200:
                claims = resp.json()
                # Also parse the token itself for exp and other claims
                try:
                    token_claims = pyjwt.decode(
                        token, options={"verify_signature": False, "verify_aud": False}
                    )
                    claims.update({
                        "exp": token_claims.get("exp", int(time.time()) + 300),
                        "iat": token_claims.get("iat", int(time.time())),
                        "iss": token_claims.get("iss", ""),
                        "may_act": token_claims.get("may_act", claims.get("may_act", {})),
                    })
                except pyjwt.InvalidTokenError:
                    claims["exp"] = int(time.time()) + 300

                # Prefer email as subject
                if "email" in claims and claims["email"]:
                    claims["sub"] = claims["email"]

                logger.info("Subject token validated via Keycloak userinfo: sub=%s", claims.get("sub"))
                return claims
            else:
                logger.warning(
                    "Keycloak userinfo returned %d: %s", resp.status_code, resp.text[:200]
                )
                return self._error_response(
                    "invalid_request",
                    f"Identity provider rejected token (HTTP {resp.status_code})"
                )
        except requests.RequestException as e:
            logger.error("Keycloak userinfo validation failed: %s", e)
            return self._error_response(
                "temporarily_unavailable",
                "Identity provider is unavailable. Cannot validate subject token."
            )

    # ── Delegation Chain ──────────────────────────────────────────────────

    def _extract_delegation_chain(self, claims: dict) -> list[DelegationChainLink]:
        """Extract existing delegation chain from a token's claims."""
        chain_data = claims.get("delegation_chain", [])
        chain = []
        for link_data in chain_data:
            chain.append(DelegationChainLink(
                subject=link_data.get("subject", ""),
                actor=link_data.get("actor", ""),
                actor_type=link_data.get("actor_type", "agent"),
                scope=link_data.get("scope", ""),
                timestamp=link_data.get("timestamp", ""),
                session_id=link_data.get("session_id", ""),
                depth=link_data.get("depth", 0),
            ))
        return chain

    def _build_act_claim(self, chain: list[DelegationChainLink]) -> dict:
        """
        Build the RFC 8693 `act` claim from the delegation chain.

        The `act` claim is nested: the outermost is the immediate actor,
        each nested `act` is the next actor in the chain.

        Example for human -> agent -> sub-agent:
        {
            "sub": "spiffe://demo.local/subagent/sql-executor",
            "act": {
                "sub": "spiffe://demo.local/agent/query-agent",
                "act": {
                    "sub": "alice@acme.com"
                }
            }
        }
        """
        if not chain:
            return {}

        # Build from the bottom up (earliest delegation first)
        act = {"sub": chain[0].subject}  # Original human

        for link in chain:
            act = {
                "sub": link.actor,
                "act": act,
            }

        return act

    def _get_permitted_scopes(self, claims: dict) -> list[str]:
        """Determine permitted scopes based on the subject's claims."""
        groups = claims.get("groups", [])

        # Group-to-scope mapping (mirrors OPA data.json)
        group_permissions = {
            "data-analysts": ["readonly", "db:read", "db:query"],
            "trading-team": ["readonly", "db:read", "db:query"],
            "engineering": ["readonly", "readwrite", "db:read", "db:write", "db:query"],
        }

        # If this is already a delegation token, use its scope
        if claims.get("iss") == self.issuer:
            current_scope = claims.get("scope", "")
            if current_scope:
                return [current_scope]

        permitted = set()
        for group in groups:
            if group in group_permissions:
                permitted.update(group_permissions[group])

        # If no groups found, deny — no implicit permissions
        return list(permitted)

    # ── OPA Policy Evaluation ─────────────────────────────────────────────

    def _evaluate_opa_policy(self, subject_claims: dict, actor_claims: dict, scope: str) -> dict:
        """Evaluate the delegation policy via OPA."""
        actor_sub = actor_claims.get("sub", "")
        delegation_chain = subject_claims.get("delegation_chain", [])
        delegation_depth = len(delegation_chain)

        # For chain extension (delegation_depth > 0), reconstruct the original
        # human's claims from the delegation chain so OPA can validate against
        # trusted_issuers. The delegation token's issuer is the token-exchange
        # service, not Keycloak, so we need to pass the original human identity.
        if delegation_depth > 0 and subject_claims.get("iss") == self.issuer:
            # This is a delegation token being extended - use original human info
            human_sub = subject_claims.get("sub", "")
            human_groups = subject_claims.get("groups", [])
            human_may_act = subject_claims.get("may_act", {})
            human_exp = subject_claims.get("exp", 0)
            # Use the original Keycloak issuer for OPA validation
            human_iss = subject_claims.get("original_issuer", "http://keycloak:8080/realms/demo")
        else:
            human_sub = subject_claims.get("sub", "")
            human_groups = subject_claims.get("groups", [])
            human_may_act = subject_claims.get("may_act", {})
            human_exp = subject_claims.get("exp", 0)
            human_iss = subject_claims.get("iss", "")

        # Build OPA input matching the delegation.rego format
        opa_input = {
            "human_token": {
                "sub": human_sub,
                "groups": human_groups,
                "may_act": human_may_act,
                "exp": human_exp,
                "iss": human_iss,
            },
            "agent_spiffe_id": actor_sub,
            "requested_scope": scope,
            "current_time": int(time.time()),
            "delegation_depth": delegation_depth,
        }

        # For chain extensions, pass the parent's scope so OPA can enforce narrowing
        if delegation_depth > 0:
            parent_scope = subject_claims.get("scope", "")
            if parent_scope:
                opa_input["parent_scope"] = parent_scope

        try:
            resp = requests.post(
                f"{self.config.opa_endpoint}/v1/data/delegation/allow",
                json={"input": opa_input},
                timeout=5,
            )
            if resp.status_code == 200:
                result = resp.json()
                allowed = result.get("result", False)

                # Get detailed reason
                reason = "policy_evaluated"
                try:
                    decision_resp = requests.post(
                        f"{self.config.opa_endpoint}/v1/data/delegation/decision",
                        json={"input": opa_input},
                        timeout=5,
                    )
                    if decision_resp.status_code == 200:
                        decision = decision_resp.json().get("result", {})
                        reason = decision.get("reason", reason)
                except Exception:
                    pass

                return {"allowed": allowed, "reason": reason}
        except requests.RequestException as e:
            logger.error("OPA evaluation failed: %s", e)

        # Fail-closed: deny when policy engine is unavailable
        return {"allowed": False, "reason": "policy_engine_unavailable"}

    # ── Vault Credential Brokering ────────────────────────────────────────

    def _broker_vault_credentials(
        self, scope: str, session_id: str,
        human_subject: str, agent_id: str,
        chain: list[DelegationChainLink]
    ) -> tuple[Optional[dict], Optional[str]]:
        """Request dynamic database credentials from Vault."""
        if not self.config.vault_token:
            logger.warning("No Vault token configured, skipping credential brokering")
            return None, None

        role = self._scope_to_vault_role(scope)
        headers = {"X-Vault-Token": self.config.vault_token}

        # Update entity metadata with delegation chain context
        chain_summary = " -> ".join(
            f"{link.subject}({link.actor_type})" for link in chain
        )
        metadata = {
            "delegating_human": human_subject,
            "delegation_scope": scope,
            "delegation_time": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "agent_id": agent_id,
            "delegation_chain": chain_summary,
            "chain_depth": str(len(chain)),
        }

        try:
            # Look up the current token's entity ID, then persist delegation
            # metadata onto the Vault entity so it survives service restarts.
            lookup_resp = requests.get(
                f"{self.config.vault_addr}/v1/auth/token/lookup-self",
                headers=headers,
                timeout=5,
            )
            if lookup_resp.status_code == 200:
                entity_id = lookup_resp.json().get("data", {}).get("entity_id", "")
                if entity_id:
                    requests.post(
                        f"{self.config.vault_addr}/v1/identity/entity/id/{entity_id}",
                        headers=headers,
                        json={"metadata": metadata},
                        timeout=5,
                    )
                    logger.info(
                        "Vault entity metadata updated: entity=%s, session=%s",
                        entity_id, session_id,
                    )
                else:
                    # No entity attached to token - create a named entity
                    entity_name = f"delegation-{session_id}"
                    requests.post(
                        f"{self.config.vault_addr}/v1/identity/entity",
                        headers=headers,
                        json={"name": entity_name, "metadata": metadata},
                        timeout=5,
                    )
                    logger.info(
                        "Vault entity created: name=%s, session=%s",
                        entity_name, session_id,
                    )
        except Exception as exc:
            logger.warning("Failed to persist entity metadata to Vault: %s", exc)

        # Get dynamic credentials
        try:
            resp = requests.get(
                f"{self.config.vault_addr}/v1/database/creds/{role}",
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                creds = {
                    "username": data["data"]["username"],
                    "password": data["data"]["password"],
                    "host": "postgresql",
                    "port": 5432,
                    "database": "appdb",
                    "ttl_seconds": data.get("lease_duration", 300),
                    "lease_id": data.get("lease_id", ""),
                }
                logger.info(
                    "Vault credentials issued: user=%s, lease=%s, session=%s",
                    creds["username"], creds["lease_id"], session_id,
                )
                return creds, data.get("lease_id", "")
            else:
                logger.error("Vault credential request failed: %d %s", resp.status_code, resp.text)
        except requests.RequestException as e:
            logger.error("Vault request failed: %s", e)

        return None, None

    def _scope_to_vault_role(self, scope: str) -> str:
        """Map delegation scope to Vault database role."""
        if scope in ("readwrite", "db:write"):
            return "ai-agent-readwrite"
        return "ai-agent-readonly"

    # ── Token Revocation ──────────────────────────────────────────────────

    def revoke_token(self, token: str) -> dict:
        """Revoke a delegation token and its associated Vault credentials."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session_id = self.token_to_session.get(token_hash)

        if not session_id or session_id not in self.sessions:
            return {"status": "not_found", "message": "Token or session not found"}

        session = self.sessions[session_id]
        session.revoked = True

        # Revoke Vault lease if exists
        if session.vault_lease_id and self.config.vault_token:
            try:
                requests.put(
                    f"{self.config.vault_addr}/v1/sys/leases/revoke",
                    headers={"X-Vault-Token": self.config.vault_token},
                    json={"lease_id": session.vault_lease_id},
                    timeout=10,
                )
                logger.info("Vault lease revoked: %s", session.vault_lease_id)
            except Exception as e:
                logger.error("Vault revocation failed: %s", e)

        self._record_audit("revocation", "success", {
            "session_id": session_id,
            "vault_lease_id": session.vault_lease_id,
        })

        return {"status": "revoked", "session_id": session_id}

    # ── Delegation Chain Query ────────────────────────────────────────────

    def get_delegation_chain(self, session_id: str) -> dict:
        """Get the full delegation chain for a session."""
        if session_id not in self.sessions:
            return {"error": "session_not_found"}

        session = self.sessions[session_id]
        return {
            "session_id": session_id,
            "chain": [
                {
                    "subject": link.subject,
                    "actor": link.actor,
                    "actor_type": link.actor_type,
                    "scope": link.scope,
                    "depth": link.depth,
                    "timestamp": link.timestamp,
                }
                for link in session.chain
            ],
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "revoked": session.revoked,
            "chain_depth": len(session.chain),
            "has_credentials": session.db_credentials is not None,
        }

    # ── Helper Methods ────────────────────────────────────────────────────

    def _error_response(self, error: str, description: str) -> dict:
        """Build an RFC 8693 error response."""
        return {
            "error": error,
            "error_description": description,
        }

    def _record_audit(self, action: str, result: str, details: dict):
        """Record an audit entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "result": result,
            **details,
        }
        self.audit_log.append(entry)
        logger.info("[AUDIT] %s", json.dumps(entry))


# ─── HTTP Handler ─────────────────────────────────────────────────────────────

class TokenExchangeHandler(BaseHTTPRequestHandler):
    """HTTP handler for the Token Exchange Service."""

    service: TokenExchangeService = None  # Set by server setup

    def log_message(self, format, *args):
        logger.info("[HTTP] %s", format % args)

    def do_GET(self):
        if self.path == "/health":
            self._json_response(200, {
                "status": "healthy",
                "service": "token-exchange",
                "version": "3.0.0",
                "features": ["rfc8693", "delegation-chain", "vault-brokering", "rs256-signing", "spiffe-verification"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        elif self.path == "/.well-known/jwks.json":
            # Serve the public key for delegation token verification
            pub_numbers = self.service._public_key.public_numbers()

            def _int_to_base64url(n):
                b = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
                return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

            jwks = {
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.service._kid,
                    "n": _int_to_base64url(pub_numbers.n),
                    "e": _int_to_base64url(pub_numbers.e),
                }]
            }
            self._json_response(200, jwks)
        elif self.path == "/v1/audit":
            self._json_response(200, self.service.audit_log)
        elif self.path.startswith("/v1/delegation/chain"):
            # Parse session_id from query string
            parts = self.path.split("?")
            params = {}
            if len(parts) > 1:
                for kv in parts[1].split("&"):
                    k, _, v = kv.partition("=")
                    params[k] = v
            session_id = params.get("session_id", "")
            if not session_id:
                self._json_response(400, {"error": "session_id parameter required"})
                return
            result = self.service.get_delegation_chain(session_id)
            status = 200 if "error" not in result else 404
            self._json_response(status, result)
        else:
            self._json_response(404, {"error": "not_found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        try:
            params = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._json_response(400, {"error": "invalid_json"})
            return

        if self.path == "/v1/token/exchange":
            result = self.service.exchange_token(params)
            status = 200 if "error" not in result else 400
            self._json_response(status, result)

        elif self.path == "/v1/delegate":
            result = self.service.delegate(params)
            status = 200 if "error" not in result else (403 if result.get("error") == "access_denied" else 400)
            self._json_response(status, result)

        elif self.path == "/v1/token/revoke":
            token = params.get("token", "")
            if not token:
                self._json_response(400, {"error": "token parameter required"})
                return
            result = self.service.revoke_token(token)
            self._json_response(200, result)

        else:
            self._json_response(404, {"error": "not_found"})

    def _json_response(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Service", "token-exchange")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())


# ─── Server Entry Point ──────────────────────────────────────────────────────

def _setup_mtls_context(config):
    """
    Set up an SSL context using SPIFFE X.509-SVIDs from the SPIRE Workload API.

    Returns an ssl.SSLContext configured for mTLS, or None if SPIRE is unavailable.
    The context uses the X.509-SVID as the server certificate and requires
    client certificates verified against the SPIFFE trust bundle.
    """
    import tempfile
    try:
        from spiffe import WorkloadApiClient
    except ImportError:
        logger.warning("spiffe library not installed — mTLS disabled")
        return None

    socket_path = config.spire_agent_socket
    if not os.path.exists(socket_path):
        logger.warning("SPIRE agent socket not found at %s — mTLS disabled", socket_path)
        return None

    try:
        client = WorkloadApiClient(socket_path=f"unix://{socket_path}")
        x509_context = client.fetch_x509_context()

        if not x509_context.svids:
            logger.warning("No X.509-SVIDs received from SPIRE — mTLS disabled")
            return None

        svid = x509_context.default_svid
        trust_bundle = x509_context.x509_bundle_set

        # Write cert, key, and CA bundle to temp files for ssl.SSLContext
        # (ssl module requires file paths, not in-memory objects)
        cert_pem = svid.cert_chain_bytes
        key_pem = svid.private_key_bytes

        cert_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        cert_file.write(cert_pem)
        cert_file.close()

        key_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        key_file.write(key_pem)
        key_file.close()

        # Write trust bundle (CA certs for verifying client certificates)
        ca_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        for bundle in trust_bundle.bundles.values():
            for cert in bundle.x509_authorities:
                ca_file.write(cert.public_bytes(serialization.Encoding.PEM))
        ca_file.close()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file.name, key_file.name)
        ctx.load_verify_locations(ca_file.name)
        ctx.verify_mode = ssl.CERT_REQUIRED  # Require client certificates (mTLS)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        logger.info(
            "mTLS enabled: SPIFFE ID=%s, trust domain=%s",
            svid.spiffe_id, config.trust_domain,
        )

        # Clean up temp files (already loaded into SSLContext)
        for f in (cert_file.name, key_file.name, ca_file.name):
            try:
                os.unlink(f)
            except OSError:
                pass

        return ctx

    except Exception as e:
        logger.warning("Failed to set up mTLS from SPIRE: %s — falling back to HTTP", e)
        return None


def main():
    config = ServiceConfig.from_env()

    logger.info("Starting Token Exchange Service on :%d", config.listen_port)
    logger.info("  Keycloak: %s/realms/%s", config.keycloak_url, config.keycloak_realm)
    logger.info("  OPA: %s", config.opa_endpoint)
    logger.info("  Vault: %s", config.vault_addr)
    logger.info("  Trust domain: %s", config.trust_domain)
    logger.info("  SPIRE OIDC: %s", config.spire_oidc_url)
    logger.info("  Max delegation depth: %d", config.max_delegation_depth)
    logger.info("  mTLS: %s", "enabled" if config.mtls_enabled else "disabled")

    service = TokenExchangeService(config)
    TokenExchangeHandler.service = service

    server = HTTPServer(("0.0.0.0", config.listen_port), TokenExchangeHandler)

    # Wrap the server socket with TLS if mTLS is enabled and SPIRE is available
    if config.mtls_enabled:
        ssl_ctx = _setup_mtls_context(config)
        if ssl_ctx:
            server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
            logger.info("Token Exchange Service ready (mTLS)")
        else:
            logger.warning("mTLS requested but unavailable — serving plain HTTP")
            logger.info("Token Exchange Service ready (HTTP)")
    else:
        logger.info("Token Exchange Service ready (HTTP)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
