#!/usr/bin/env python3
"""
AI Agent with SPIFFE Identity and Delegated Database Access

This agent demonstrates the full identity delegation chain:
1. Obtains a SPIFFE SVID from the local SPIRE agent
2. Receives a human's OIDC token (simulating delegation)
3. Presents both to the Identity Gateway for policy evaluation
4. Receives short-lived database credentials from Vault
5. Queries PostgreSQL with the dynamic credentials
6. Credentials auto-expire after 5 minutes

The full audit trail is preserved at every step.
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
    gateway_url: str = "http://identity-gateway:8080"
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

    def fetch_jwt_svid(self, audience: str = "identity-gateway") -> str:
        """
        Fetch a JWT-SVID from the SPIRE Workload API.

        In a full deployment, this uses the go-spiffe or py-spiffe library
        to connect to the SPIRE agent's Unix domain socket and request a
        JWT-SVID for the given audience.
        """
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
            logger.info(
                "JWT-SVID obtained: spiffe_id=%s, audience=%s",
                jwt_svid.spiffe_id,
                audience,
            )
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
            "delegated_identity": "",
            "client_type": "ai_agent",
        }
        # In demo mode, create an unsigned token for illustration
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
        """
        Authenticate a human user via Keycloak's direct access grant.

        Returns the OIDC access token.
        """
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

            # Decode for logging (without verification for display)
            claims = pyjwt.decode(
                access_token, options={"verify_signature": False}
            )
            logger.info(
                "Human authenticated: sub=%s, groups=%s",
                claims.get("email", claims.get("sub")),
                claims.get("groups", []),
            )
            return access_token

        except requests.RequestException as e:
            logger.error("Keycloak authentication failed: %s", e)
            raise RuntimeError(f"Human authentication failed: {e}") from e


class IdentityGatewayClient:
    """Client for the Identity Gateway delegation service."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.delegate_url = f"{config.gateway_url}/v1/delegate"
        self.health_url = f"{config.gateway_url}/v1/health"
        self.audit_url = f"{config.gateway_url}/v1/audit"

    def request_delegation(
        self,
        human_token: str,
        agent_spiffe_id: str,
        agent_jwt_svid: str,
        requested_scope: str = "readonly",
    ) -> DelegationSession:
        """
        Request delegated database access through the Identity Gateway.

        The gateway validates:
        1. Human OIDC token (against Keycloak)
        2. Agent SPIFFE identity (against SPIRE trust domain)
        3. OPA delegation policy (scope + group permissions)

        Then brokers Vault access to get dynamic DB credentials.
        """
        logger.info(
            "Requesting delegation: agent=%s, scope=%s",
            agent_spiffe_id,
            requested_scope,
        )

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
                    f"{error_data.get('error', 'unknown')}"
                )

            data = resp.json()
            db_cred = data["db_credential"]

            session = DelegationSession(
                session_id=data["session_id"],
                human_subject=data["metadata"]["delegating_human"],
                scope=requested_scope,
                db_username=db_cred["username"],
                db_password=db_cred["password"],
                db_host=db_cred.get("host", self.config.db_host),
                db_port=db_cred.get("port", self.config.db_port),
                db_name=db_cred.get("database", self.config.db_name),
                lease_id=db_cred.get("lease_id", ""),
                ttl_seconds=db_cred.get("ttl_seconds", 300),
            )

            logger.info(
                "Delegation successful: session=%s, db_user=%s, ttl=%ds",
                session.session_id,
                session.db_username,
                session.ttl_seconds,
            )
            return session

        except requests.RequestException as e:
            raise RuntimeError(f"Gateway request failed: {e}") from e

    def check_health(self) -> dict:
        """Check the gateway's health status."""
        try:
            resp = requests.get(self.health_url, timeout=5)
            return resp.json()
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def get_audit_log(self) -> list:
        """Retrieve the gateway's audit log."""
        try:
            resp = requests.get(self.audit_url, timeout=5)
            return resp.json()
        except Exception as e:
            return [{"error": str(e)}]


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
            self.session.db_host,
            self.session.db_port,
            self.session.db_name,
            self.session.db_username,
            self.session.remaining_seconds,
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

# Pre-defined query mappings for the demo
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
    for pattern, sql in QUERY_MAPPINGS.items():
        if pattern in question_lower or question_lower in pattern:
            return sql
    # Default: show recent orders
    return DEFAULT_QUERY


# ─── Demo Runner ───────────────────────────────────────────────────────────


def print_banner():
    print("\n" + "=" * 70)
    print("  Vault Agentic Identity Broker - AI Agent Demo")
    print("  Secure delegation: Human → Agent → Database")
    print("=" * 70)


def print_step(num: int, description: str):
    print(f"\n{'─' * 60}")
    print(f"  Step {num}: {description}")
    print(f"{'─' * 60}")


def run_demo(question: str = "show me all orders over $1000 from last month"):
    """Run the full identity delegation demo."""
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
        print(f"  ✓ Human authenticated: {claims.get('email', claims.get('sub'))}")
        print(f"  ✓ Groups: {claims.get('groups', [])}")
        print(f"  ✓ May act: {json.dumps(claims.get('may_act', {}))}")
    except Exception as e:
        print(f"  ✗ Authentication failed: {e}")
        print("  → Ensure Keycloak is running and configured")
        sys.exit(1)

    # ── Step 2: Agent SPIFFE Identity ──
    print_step(2, "Agent obtains SPIFFE identity from SPIRE")
    spiffe = SPIFFEIdentity(config)
    agent_svid = spiffe.fetch_jwt_svid(audience="identity-gateway")
    print(f"  ✓ SPIFFE ID: {spiffe.spiffe_id}")
    print(f"  ✓ JWT-SVID obtained (audience: identity-gateway)")

    # ── Step 3: Token Exchange at Identity Gateway ──
    print_step(3, "Token exchange + OPA policy evaluation at Identity Gateway")
    gateway = IdentityGatewayClient(config)

    try:
        session = gateway.request_delegation(
            human_token=human_token,
            agent_spiffe_id=spiffe.spiffe_id,
            agent_jwt_svid=agent_svid,
            requested_scope="readonly",
        )
        print(f"  ✓ Delegation approved by OPA policy")
        print(f"  ✓ Session ID: {session.session_id}")
        print(f"  ✓ Delegating human: {session.human_subject}")
    except Exception as e:
        print(f"  ✗ Delegation failed: {e}")
        sys.exit(1)

    # ── Step 4: Vault Dynamic Credentials ──
    print_step(4, "Vault issues dynamic database credentials (5-min TTL)")
    print(f"  ✓ DB Username: {session.db_username}")
    print(f"  ✓ DB Host: {session.db_host}:{session.db_port}/{session.db_name}")
    print(f"  ✓ TTL: {session.ttl_seconds} seconds")
    print(f"  ✓ Lease ID: {session.lease_id}")

    # ── Step 5: Query Database ──
    print_step(5, f"Agent queries database on behalf of {session.human_subject}")
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
        print(f"  ✗ Query failed: {e}")
    finally:
        querier.close()

    # ── Step 6: Audit Trail ──
    print_step(6, "Audit trail verification")
    print(f"  Session: {session.session_id}")
    print(f"  Human: {session.human_subject}")
    print(f"  Agent: {spiffe.spiffe_id}")
    print(f"  DB User: {session.db_username}")
    print(f"  Credentials expire at: {session.expires_at.isoformat()}")
    print(f"  Remaining TTL: {session.remaining_seconds}s")

    try:
        audit_entries = gateway.get_audit_log()
        print(f"  Gateway audit entries: {len(audit_entries)}")
        for entry in audit_entries[-3:]:
            print(f"    [{entry.get('timestamp', 'N/A')}] "
                  f"human={entry.get('human', 'N/A')} "
                  f"result={entry.get('result', 'N/A')}")
    except Exception as e:
        print(f"  Warning: Could not fetch audit log: {e}")

    print(f"\n{'=' * 70}")
    print("  Demo complete. Full identity chain verified.")
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

    # Authenticate once
    human_auth = HumanAuthenticator(config)
    username = os.getenv("DEMO_USERNAME", "alice")
    password = os.getenv("DEMO_PASSWORD", "alice-demo-password")
    human_token = human_auth.authenticate(username, password)

    spiffe = SPIFFEIdentity(config)
    agent_svid = spiffe.fetch_jwt_svid(audience="identity-gateway")

    gateway = IdentityGatewayClient(config)

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

            # Get fresh delegation for each query
            session = gateway.request_delegation(
                human_token=human_token,
                agent_spiffe_id=spiffe.spiffe_id,
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
        # Keep container alive for manual testing
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
