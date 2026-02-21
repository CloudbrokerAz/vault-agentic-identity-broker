#!/usr/bin/env python3
"""
AI Agent with SPIFFE Identity, Token Exchange (RFC 8693), and Sub-Agent Delegation

This agent demonstrates the full identity delegation chain with token exchange:
1. Obtains a SPIFFE SVID from the local SPIRE agent
2. Authenticates the human via Keycloak OIDC
3. Performs RFC 8693 token exchange (human token + agent SPIFFE → delegation token)
4. Receives short-lived database credentials from Vault
5. Optionally delegates to sub-agents via delegation chain extension
6. Queries PostgreSQL with the dynamic credentials
7. Credentials auto-expire after 5 minutes

The full audit trail and delegation chain is preserved at every step.
"""

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import jwt as pyjwt
import psycopg2
import requests
from tabulate import tabulate

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("ai-agent")


@dataclass
class AgentConfig:
    """Configuration for the AI agent."""
    spire_socket_path: str = "/tmp/spire-agent/public/api.sock"
    gateway_url: str = "http://token-exchange:8090"
    token_exchange_url: str = "http://token-exchange:8090"
    keycloak_url: str = "http://keycloak:8080"
    keycloak_realm: str = "demo"
    trust_domain: str = "demo.local"
    agent_spiffe_id: str = "spiffe://demo.local/agent/query-agent"
    db_host: str = "postgresql"
    db_port: int = 5432
    db_name: str = "appdb"

    @classmethod
    def from_env(cls) -> "AgentConfig":
        return cls(
            spire_socket_path=os.getenv("SPIRE_AGENT_SOCKET", cls.spire_socket_path),
            gateway_url=os.getenv("GATEWAY_URL", cls.gateway_url),
            token_exchange_url=os.getenv("TOKEN_EXCHANGE_URL", cls.token_exchange_url),
            keycloak_url=os.getenv("KEYCLOAK_URL", cls.keycloak_url),
            keycloak_realm=os.getenv("KEYCLOAK_REALM", cls.keycloak_realm),
            trust_domain=os.getenv("TRUST_DOMAIN", cls.trust_domain),
            agent_spiffe_id=os.getenv("AGENT_SPIFFE_ID", cls.agent_spiffe_id),
            db_host=os.getenv("DB_HOST", cls.db_host),
            db_port=int(os.getenv("DB_PORT", str(cls.db_port))),
            db_name=os.getenv("DB_NAME", cls.db_name),
        )


@dataclass
class DelegationSession:
    """Tracks an active delegation session with credentials."""
    session_id: str
    human_subject: str
    scope: str
    db_username: str
    db_password: str
    db_host: str
    db_port: int
    db_name: str
    lease_id: str
    ttl_seconds: int
    delegation_token: str = ""
    delegation_chain: list = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def expires_at(self) -> datetime:
        from datetime import timedelta
        return self.created_at + timedelta(seconds=self.ttl_seconds)

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def remaining_seconds(self) -> int:
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, int(delta.total_seconds()))


class SPIFFEIdentity:
    """Manages SPIFFE identity via SPIRE Workload API."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self._jwt_svid: Optional[str] = None

    def fetch_jwt_svid(self, audience: str = "token-exchange") -> str:
        """Fetch a JWT-SVID from the SPIRE Workload API."""
        logger.info("Fetching JWT-SVID from SPIRE agent...")

        try:
            from spiffe import WorkloadApiClient
            client = WorkloadApiClient(
                spiffe_socket=f"unix://{self.config.spire_socket_path}"
            )
            jwt_svid = client.fetch_jwt_svid(
                audiences=[audience],
                hint=self.config.agent_spiffe_id,
            )
            self._jwt_svid = jwt_svid.token
            logger.info("JWT-SVID obtained: spiffe_id=%s", jwt_svid.spiffe_id)
            return self._jwt_svid
        except Exception as e:
            logger.warning("SPIRE Workload API unavailable (%s), using demo SVID", e)
            return self._generate_demo_svid(audience)

    def _generate_demo_svid(self, audience: str) -> str:
        """Generate a demo JWT-SVID for testing without SPIRE."""
        now = int(time.time())
        claims = {
            "sub": self.config.agent_spiffe_id,
            "aud": [audience],
            "exp": now + 3600,
            "iat": now,
            "client_type": "ai_agent",
        }
        token = pyjwt.encode(claims, "demo-secret", algorithm="HS256")
        self._jwt_svid = token
        logger.info("Demo JWT-SVID generated for %s", self.config.agent_spiffe_id)
        return token

    @property
    def spiffe_id(self) -> str:
        return self.config.agent_spiffe_id


class HumanAuthenticator:
    """Handles human authentication via Keycloak OIDC."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.token_endpoint = (
            f"{config.keycloak_url}/realms/{config.keycloak_realm}"
            f"/protocol/openid-connect/token"
        )

    def authenticate(self, username: str, password: str) -> str:
        """Authenticate a human user via Keycloak's direct access grant."""
        logger.info("Authenticating human user: %s", username)

        try:
            resp = requests.post(
                self.token_endpoint,
                data={
                    "grant_type": "password",
                    "client_id": "demo-cli",
                    "username": username,
                    "password": password,
                    "scope": "openid",
                },
                timeout=10,
            )
            resp.raise_for_status()
            token_data = resp.json()
            access_token = token_data["access_token"]

            claims = pyjwt.decode(access_token, options={"verify_signature": False})
            logger.info(
                "Human authenticated: sub=%s, groups=%s",
                claims.get("email", claims.get("sub")),
                claims.get("groups", []),
            )
            return access_token

        except requests.RequestException as e:
            logger.error("Keycloak authentication failed: %s", e)
            raise RuntimeError(f"Human authentication failed: {e}") from e


class TokenExchangeClient:
    """
    Client for the Token Exchange Service (RFC 8693).

    Replaces the direct identity-gateway delegation with
    standard OAuth 2.0 Token Exchange.
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self.exchange_url = f"{config.token_exchange_url}/v1/token/exchange"
        self.delegate_url = f"{config.token_exchange_url}/v1/delegate"
        self.revoke_url = f"{config.token_exchange_url}/v1/token/revoke"
        self.chain_url = f"{config.token_exchange_url}/v1/delegation/chain"
        self.health_url = f"{config.token_exchange_url}/health"

    def exchange_token(
        self,
        human_token: str,
        agent_jwt_svid: str,
        requested_scope: str = "readonly",
        audience: str = "database",
    ) -> DelegationSession:
        """
        Perform RFC 8693 Token Exchange.

        Exchanges the human's OIDC token + agent's SPIFFE SVID
        for a delegated token with database credentials.
        """
        logger.info("Performing RFC 8693 token exchange: scope=%s", requested_scope)

        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": human_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": agent_jwt_svid,
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": requested_scope,
            "audience": audience,
        }

        try:
            resp = requests.post(self.exchange_url, json=payload, timeout=15)
            data = resp.json()

            if "error" in data:
                raise RuntimeError(
                    f"Token exchange failed: {data['error']} - "
                    f"{data.get('error_description', '')}"
                )

            db_cred = data.get("db_credential", {})
            chain = data.get("delegation_chain", [])

            session = DelegationSession(
                session_id=data["session_id"],
                human_subject=chain[0]["subject"] if chain else "unknown",
                scope=requested_scope,
                db_username=db_cred.get("username", ""),
                db_password=db_cred.get("password", ""),
                db_host=db_cred.get("host", self.config.db_host),
                db_port=db_cred.get("port", self.config.db_port),
                db_name=db_cred.get("database", self.config.db_name),
                lease_id=db_cred.get("lease_id", ""),
                ttl_seconds=data.get("expires_in", 300),
                delegation_token=data["access_token"],
                delegation_chain=chain,
            )

            logger.info(
                "Token exchange successful: session=%s, db_user=%s, chain_depth=%d",
                session.session_id, session.db_username, len(chain),
            )
            return session

        except requests.RequestException as e:
            raise RuntimeError(f"Token exchange request failed: {e}") from e

    def delegate_legacy(
        self,
        human_token: str,
        agent_spiffe_id: str,
        agent_jwt_svid: str,
        requested_scope: str = "readonly",
    ) -> DelegationSession:
        """
        Legacy delegation API (backward-compatible).
        Internally uses RFC 8693 token exchange.
        """
        logger.info("Requesting delegation (legacy API): scope=%s", requested_scope)

        payload = {
            "human_token": human_token,
            "agent_spiffe_id": agent_spiffe_id,
            "agent_jwt_svid": agent_jwt_svid,
            "requested_scope": requested_scope,
        }

        try:
            resp = requests.post(self.delegate_url, json=payload, timeout=15)
            if resp.status_code != 200:
                error_data = resp.json()
                raise RuntimeError(
                    f"Delegation failed ({resp.status_code}): "
                    f"{error_data.get('error', error_data.get('error_description', 'unknown'))}"
                )

            data = resp.json()
            db_cred = data.get("db_credential", {})

            session = DelegationSession(
                session_id=data["session_id"],
                human_subject=data.get("metadata", {}).get("delegating_human", "unknown"),
                scope=requested_scope,
                db_username=db_cred.get("username", ""),
                db_password=db_cred.get("password", ""),
                db_host=db_cred.get("host", self.config.db_host),
                db_port=db_cred.get("port", self.config.db_port),
                db_name=db_cred.get("database", self.config.db_name),
                lease_id=db_cred.get("lease_id", ""),
                ttl_seconds=db_cred.get("ttl_seconds", 300),
                delegation_token=data.get("delegation_token", ""),
                delegation_chain=data.get("metadata", {}).get("delegation_chain", []),
            )

            logger.info(
                "Delegation successful: session=%s, db_user=%s",
                session.session_id, session.db_username,
            )
            return session

        except requests.RequestException as e:
            raise RuntimeError(f"Delegation request failed: {e}") from e

    def get_delegation_chain(self, session_id: str) -> dict:
        """Get the full delegation chain for a session."""
        try:
            resp = requests.get(
                f"{self.chain_url}?session_id={session_id}", timeout=5
            )
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def revoke_token(self, token: str) -> dict:
        """Revoke a delegation token."""
        try:
            resp = requests.post(
                self.revoke_url, json={"token": token}, timeout=10
            )
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def check_health(self) -> dict:
        """Check the token exchange service's health."""
        try:
            resp = requests.get(self.health_url, timeout=5)
            return resp.json()
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}


class DatabaseQuerier:
    """Executes SQL queries using delegated database credentials."""

    def __init__(self, session: DelegationSession):
        self.session = session
        self._conn = None

    def connect(self) -> None:
        """Establish a database connection using the session's credentials."""
        if self.session.is_expired:
            raise RuntimeError(
                f"Session {self.session.session_id} has expired. "
                "Must re-authenticate through the delegation chain."
            )

        logger.info(
            "Connecting to database: host=%s, port=%d, db=%s, user=%s (ttl=%ds remaining)",
            self.session.db_host, self.session.db_port, self.session.db_name,
            self.session.db_username, self.session.remaining_seconds,
        )

        self._conn = psycopg2.connect(
            host=self.session.db_host,
            port=self.session.db_port,
            dbname=self.session.db_name,
            user=self.session.db_username,
            password=self.session.db_password,
            connect_timeout=5,
            options="-c search_path=app,public",
        )
        self._conn.autocommit = True
        logger.info("Database connection established")

    def query(self, sql: str) -> list[dict]:
        """Execute a read-only SQL query and return results."""
        if self._conn is None:
            self.connect()

        if self.session.is_expired:
            raise RuntimeError("Session expired during query")

        logger.info("Executing query: %s", sql[:200])
        with self._conn.cursor() as cur:
            cur.execute(sql)
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.info("Database connection closed")


# ─── Natural Language Query Mapping ────────────────────────────────────────

QUERY_MAPPINGS = {
    "show me all orders over $1000 from last month": """
        SELECT customer_name, product, quantity, unit_price, total_amount,
               order_date, status, region
        FROM app.order_summary
        WHERE total_amount > 1000
          AND order_date >= NOW() - INTERVAL '30 days'
        ORDER BY total_amount DESC
    """,
    "what are the top customers by order value": """
        SELECT customer_name,
               COUNT(*) as order_count,
               SUM(total_amount) as total_value,
               AVG(total_amount) as avg_order_value
        FROM app.orders
        WHERE status != 'cancelled'
        GROUP BY customer_name
        ORDER BY total_value DESC
    """,
    "show order summary by region": """
        SELECT region,
               COUNT(*) as total_orders,
               SUM(total_amount) as total_revenue,
               COUNT(CASE WHEN status = 'delivered' THEN 1 END) as delivered,
               COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending
        FROM app.orders
        GROUP BY region
        ORDER BY total_revenue DESC
    """,
    "list all products with low stock": """
        SELECT name, category, price, stock_quantity
        FROM app.products
        WHERE stock_quantity < 100
        ORDER BY stock_quantity ASC
    """,
    "show recent high-value orders": """
        SELECT id, customer_name, product, total_amount, order_date, status, value_tier
        FROM app.order_summary
        WHERE value_tier IN ('high-value', 'medium-value')
          AND order_date >= NOW() - INTERVAL '30 days'
        ORDER BY total_amount DESC
        LIMIT 10
    """,
}

DEFAULT_QUERY = """
    SELECT id, customer_name, product, total_amount, order_date, status
    FROM app.order_summary
    LIMIT 10
"""


def map_natural_language_to_sql(question: str) -> str:
    """Map a natural language question to SQL (simplified for demo)."""
    question_lower = question.lower().strip()
    if not question_lower:
        return DEFAULT_QUERY
    for pattern, sql in QUERY_MAPPINGS.items():
        if pattern in question_lower or question_lower in pattern:
            return sql
    return DEFAULT_QUERY


# ─── Demo Runner ───────────────────────────────────────────────────────────


def print_banner():
    print("\n" + "=" * 70)
    print("  Vault Agentic Identity Broker v2 - Token Exchange + Sub-Agents")
    print("  Flow: Human → Agent → [Sub-Agent] → Database")
    print("  Protocol: RFC 8693 OAuth 2.0 Token Exchange")
    print("=" * 70)


def print_step(num: int, description: str):
    print(f"\n{'─' * 60}")
    print(f"  Step {num}: {description}")
    print(f"{'─' * 60}")


def run_demo(question: str = "show me all orders over $1000 from last month"):
    """Run the full identity delegation demo with token exchange."""
    config = AgentConfig.from_env()

    print_banner()

    # ── Step 1: Human Authentication ──
    print_step(1, "Human authenticates via Keycloak OIDC")
    human_auth = HumanAuthenticator(config)
    username = os.getenv("DEMO_USERNAME", "alice")
    password = os.getenv("DEMO_PASSWORD", "alice-demo-password")

    try:
        human_token = human_auth.authenticate(username, password)
        claims = pyjwt.decode(human_token, options={"verify_signature": False})
        print(f"  [OK] Human authenticated: {claims.get('email', claims.get('sub'))}")
        print(f"  [OK] Groups: {claims.get('groups', [])}")
        print(f"  [OK] May act: {json.dumps(claims.get('may_act', {}))}")
    except Exception as e:
        print(f"  [FAIL] Authentication failed: {e}")
        sys.exit(1)

    # ── Step 2: Agent SPIFFE Identity ──
    print_step(2, "Agent obtains SPIFFE identity from SPIRE")
    spiffe = SPIFFEIdentity(config)
    agent_svid = spiffe.fetch_jwt_svid(audience="token-exchange")
    print(f"  [OK] SPIFFE ID: {spiffe.spiffe_id}")
    print(f"  [OK] JWT-SVID obtained (audience: token-exchange)")

    # ── Step 3: RFC 8693 Token Exchange ──
    print_step(3, "RFC 8693 Token Exchange at Token Exchange Service")
    tx_client = TokenExchangeClient(config)

    try:
        session = tx_client.exchange_token(
            human_token=human_token,
            agent_jwt_svid=agent_svid,
            requested_scope="readonly",
            audience="database",
        )
        print(f"  [OK] Token exchange successful (RFC 8693)")
        print(f"  [OK] Session ID: {session.session_id}")
        print(f"  [OK] Delegation token issued")
        print(f"  [OK] Delegation chain depth: {len(session.delegation_chain)}")
        for link in session.delegation_chain:
            print(f"       [{link.get('depth', '?')}] {link.get('subject', '?')} -> "
                  f"{link.get('actor', '?')} ({link.get('actor_type', '?')})")
    except Exception as e:
        print(f"  [FAIL] Token exchange failed: {e}")
        sys.exit(1)

    # ── Step 4: Vault Dynamic Credentials ──
    print_step(4, "Vault issues dynamic database credentials (5-min TTL)")
    print(f"  [OK] DB Username: {session.db_username}")
    print(f"  [OK] DB Host: {session.db_host}:{session.db_port}/{session.db_name}")
    print(f"  [OK] TTL: {session.ttl_seconds} seconds")
    print(f"  [OK] Lease ID: {session.lease_id}")

    # ── Step 5: Sub-Agent Delegation (optional) ──
    print_step(5, "Sub-agent delegation chain extension")
    if session.delegation_token:
        print(f"  [OK] Delegation token available for sub-agent handoff")
        print(f"  [INFO] Sub-agents can extend the chain via:")
        print(f"         POST /v1/token/exchange")
        print(f"         subject_token = <this delegation token>")
        print(f"         actor_token = <sub-agent SPIFFE SVID>")

        # Demonstrate sub-agent chain query
        chain_info = tx_client.get_delegation_chain(session.session_id)
        if "error" not in chain_info:
            print(f"  [OK] Chain verified: depth={chain_info.get('chain_depth', 0)}")
        else:
            print(f"  [INFO] Chain query: {chain_info}")
    else:
        print(f"  [SKIP] No delegation token (using legacy mode)")

    # ── Step 6: Query Database ──
    print_step(6, f"Agent queries database on behalf of {session.human_subject}")
    print(f"  Question: \"{question}\"")

    sql = map_natural_language_to_sql(question)
    print(f"  SQL: {sql.strip()[:150]}...")

    querier = DatabaseQuerier(session)
    try:
        results = querier.query(sql)
        if results:
            print(f"\n  Results ({len(results)} rows):")
            print(tabulate(results, headers="keys", tablefmt="grid", maxcolwidths=20))
        else:
            print("  No results found.")
    except Exception as e:
        print(f"  [FAIL] Query failed: {e}")
    finally:
        querier.close()

    # ── Step 7: Audit Trail ──
    print_step(7, "Audit trail and delegation chain verification")
    print(f"  Session: {session.session_id}")
    print(f"  Human: {session.human_subject}")
    print(f"  Agent: {spiffe.spiffe_id}")
    print(f"  DB User: {session.db_username}")
    print(f"  Credentials expire at: {session.expires_at.isoformat()}")
    print(f"  Remaining TTL: {session.remaining_seconds}s")
    print(f"  Token Exchange Flow: RFC 8693")

    print(f"\n{'=' * 70}")
    print("  Demo complete. Full identity chain verified via token exchange.")
    print(f"  Credentials will auto-expire in {session.remaining_seconds}s")
    print(f"{'=' * 70}\n")

    return session


def run_interactive():
    """Run in interactive mode, accepting questions from stdin."""
    config = AgentConfig.from_env()

    print_banner()
    print("\nAvailable queries:")
    for i, q in enumerate(QUERY_MAPPINGS.keys(), 1):
        print(f"  {i}. {q}")
    print(f"  {len(QUERY_MAPPINGS) + 1}. (enter custom query)")
    print()

    human_auth = HumanAuthenticator(config)
    username = os.getenv("DEMO_USERNAME", "alice")
    password = os.getenv("DEMO_PASSWORD", "alice-demo-password")
    human_token = human_auth.authenticate(username, password)

    spiffe = SPIFFEIdentity(config)
    agent_svid = spiffe.fetch_jwt_svid(audience="token-exchange")

    tx_client = TokenExchangeClient(config)

    while True:
        try:
            choice = input("\nEnter query number (or 'q' to quit): ").strip()
            if choice.lower() == "q":
                break

            questions = list(QUERY_MAPPINGS.keys())
            if choice.isdigit() and 1 <= int(choice) <= len(questions):
                question = questions[int(choice) - 1]
            else:
                question = choice

            # RFC 8693 token exchange for each query
            session = tx_client.exchange_token(
                human_token=human_token,
                agent_jwt_svid=agent_svid,
                requested_scope="readonly",
            )

            sql = map_natural_language_to_sql(question)
            querier = DatabaseQuerier(session)
            results = querier.query(sql)
            if results:
                print(tabulate(results, headers="keys", tablefmt="grid", maxcolwidths=20))
            else:
                print("No results found.")
            querier.close()

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")

    print("\nGoodbye.")


if __name__ == "__main__":
    mode = os.getenv("AGENT_MODE", "demo")
    if mode == "interactive":
        run_interactive()
    elif mode == "wait":
        print_banner()
        print("Agent running in wait mode. Use 'docker exec' to run queries.")
        while True:
            time.sleep(60)
    else:
        question = os.getenv(
            "DEMO_QUESTION",
            "show me all orders over $1000 from last month",
        )
        run_demo(question)
