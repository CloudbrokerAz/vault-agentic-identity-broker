#!/usr/bin/env python3
"""
SQL Executor Sub-Agent

A sub-agent that receives delegated credentials from a parent agent
via RFC 8693 token exchange chain and executes SQL queries.

Delegation chain: Human → Parent Agent → SQL Executor Sub-Agent → Database

This demonstrates:
  - Sub-agent identity via SPIFFE
  - Delegation chain extension (depth 2)
  - Scope narrowing (parent's scope → readonly only)
  - Credential inheritance through token exchange
"""

import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import jwt as pyjwt
import psycopg2
import requests

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("subagent:sql-executor")


@dataclass
class SubAgentConfig:
    """Configuration for the SQL Executor sub-agent."""
    spiffe_id: str = "spiffe://demo.local/subagent/sql-executor"
    token_exchange_url: str = "http://token-exchange:8090"
    trust_domain: str = "demo.local"
    db_host: str = "postgresql"
    db_port: int = 5432
    db_name: str = "appdb"

    @classmethod
    def from_env(cls) -> "SubAgentConfig":
        return cls(
            spiffe_id=os.getenv("AGENT_SPIFFE_ID", cls.spiffe_id),
            token_exchange_url=os.getenv("TOKEN_EXCHANGE_URL", cls.token_exchange_url),
            trust_domain=os.getenv("TRUST_DOMAIN", cls.trust_domain),
            db_host=os.getenv("DB_HOST", cls.db_host),
            db_port=int(os.getenv("DB_PORT", str(cls.db_port))),
            db_name=os.getenv("DB_NAME", cls.db_name),
        )


class SQLExecutorSubAgent:
    """
    Sub-agent that extends a delegation chain to execute SQL queries.

    Flow:
    1. Receives a delegation token from the parent agent
    2. Exchanges it for a sub-delegation token via RFC 8693
    3. Receives database credentials in the exchange response
    4. Executes the query and returns results
    """

    def __init__(self, config: SubAgentConfig):
        self.config = config
        self._delegation_token: Optional[str] = None
        self._db_credentials: Optional[dict] = None
        self._session_id: Optional[str] = None

    def request_subdelegation(self, parent_delegation_token: str, scope: str = "readonly") -> dict:
        """
        Extend the delegation chain by exchanging the parent's delegation
        token for a sub-delegation token.

        This is the RFC 8693 Token Exchange with:
          - subject_token = parent's delegation token
          - actor_token = this sub-agent's SPIFFE identity
        """
        logger.info("Requesting sub-delegation: scope=%s", scope)

        # Create sub-agent's identity token
        actor_token = self._create_identity_token()

        exchange_params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_delegation_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token": actor_token,
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": scope,
            "audience": "database",
        }

        try:
            resp = requests.post(
                f"{self.config.token_exchange_url}/v1/token/exchange",
                json=exchange_params,
                timeout=15,
            )

            result = resp.json()
            if "error" in result:
                raise RuntimeError(
                    f"Sub-delegation failed: {result['error']} - "
                    f"{result.get('error_description', '')}"
                )

            self._delegation_token = result["access_token"]
            self._session_id = result["session_id"]
            self._db_credentials = result.get("db_credential")

            chain = result.get("delegation_chain", [])
            logger.info(
                "Sub-delegation successful: session=%s, depth=%d",
                self._session_id, len(chain),
            )

            return result

        except requests.RequestException as e:
            raise RuntimeError(f"Token exchange request failed: {e}") from e

    def execute_query(self, sql: str) -> list[dict]:
        """Execute a SQL query using the sub-delegated credentials."""
        if not self._db_credentials:
            raise RuntimeError("No database credentials. Call request_subdelegation first.")

        creds = self._db_credentials
        logger.info(
            "Executing query as sub-agent: user=%s, session=%s",
            creds["username"], self._session_id,
        )

        conn = psycopg2.connect(
            host=creds.get("host", self.config.db_host),
            port=creds.get("port", self.config.db_port),
            dbname=creds.get("database", self.config.db_name),
            user=creds["username"],
            password=creds["password"],
            connect_timeout=5,
            options="-c search_path=app,public",
        )
        conn.autocommit = True

        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                columns = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                results = [dict(zip(columns, row)) for row in rows]
                logger.info("Query returned %d rows", len(results))
                return results
        finally:
            conn.close()

    def get_delegation_chain(self) -> list[dict]:
        """Get the full delegation chain from our token."""
        if not self._delegation_token:
            return []
        try:
            claims = pyjwt.decode(
                self._delegation_token,
                options={"verify_signature": False, "verify_aud": False},
            )
            return claims.get("delegation_chain", [])
        except pyjwt.InvalidTokenError:
            return []

    def _create_identity_token(self) -> str:
        """Create this sub-agent's SPIFFE identity token."""
        claims = {
            "sub": self.config.spiffe_id,
            "aud": ["token-exchange"],
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "client_type": "sub_agent",
            "capabilities": ["sql_execute", "read_only"],
        }
        return pyjwt.encode(claims, "demo-secret", algorithm="HS256")

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id


class ResultFormatterSubAgent:
    """
    Sub-agent that formats query results.
    Does NOT need database credentials - works on already-fetched data.
    Demonstrates a sub-agent that participates in the delegation chain
    for audit purposes but doesn't need to extend it for DB access.
    """

    def __init__(self):
        self.spiffe_id = "spiffe://demo.local/subagent/result-formatter"

    def format_as_table(self, results: list[dict]) -> str:
        """Format results as an ASCII table."""
        if not results:
            return "No results."

        columns = list(results[0].keys())
        col_widths = {col: len(str(col)) for col in columns}
        for row in results:
            for col in columns:
                col_widths[col] = max(col_widths[col], len(str(row.get(col, ""))))

        # Cap column widths
        for col in col_widths:
            col_widths[col] = min(col_widths[col], 25)

        # Header
        header = " | ".join(str(col).ljust(col_widths[col])[:col_widths[col]] for col in columns)
        separator = "-+-".join("-" * col_widths[col] for col in columns)

        lines = [header, separator]
        for row in results:
            line = " | ".join(
                str(row.get(col, "")).ljust(col_widths[col])[:col_widths[col]]
                for col in columns
            )
            lines.append(line)

        return "\n".join(lines)

    def format_as_summary(self, results: list[dict]) -> dict:
        """Format results as a summary with statistics."""
        if not results:
            return {"row_count": 0, "columns": [], "summary": "No data"}

        columns = list(results[0].keys())
        summary = {
            "row_count": len(results),
            "columns": columns,
            "column_count": len(columns),
        }

        # Compute numeric column stats
        for col in columns:
            values = []
            for row in results:
                val = row.get(col)
                if isinstance(val, (int, float)):
                    values.append(val)

            if values:
                summary[f"{col}_min"] = min(values)
                summary[f"{col}_max"] = max(values)
                summary[f"{col}_avg"] = sum(values) / len(values)

        return summary


# ─── Demo: Sub-Agent Delegation Chain ─────────────────────────────────────────

def run_subagent_demo(parent_token: str):
    """
    Run a demo showing sub-agent delegation.

    This demonstrates the full chain:
    Human → Parent Agent → SQL Executor Sub-Agent → Database
    """
    config = SubAgentConfig.from_env()

    print("\n" + "=" * 60)
    print("  Sub-Agent Delegation Demo")
    print("  Chain: Human → Agent → Sub-Agent → DB")
    print("=" * 60)

    # Step 1: SQL Executor requests sub-delegation
    print("\n[1] SQL Executor requesting sub-delegation...")
    executor = SQLExecutorSubAgent(config)
    result = executor.request_subdelegation(parent_token, scope="readonly")

    chain = executor.get_delegation_chain()
    print(f"    Session: {executor.session_id}")
    print(f"    Chain depth: {len(chain)}")
    for link in chain:
        print(f"      [{link['depth']}] {link['subject']} → {link['actor']} ({link['actor_type']})")

    # Step 2: Execute query
    print("\n[2] Sub-agent executing query...")
    sql = "SELECT id, customer_name, total_amount, status FROM app.orders LIMIT 5"
    results = executor.execute_query(sql)

    # Step 3: Format results
    print("\n[3] Formatting results...")
    formatter = ResultFormatterSubAgent()
    table = formatter.format_as_table(results)
    summary = formatter.format_as_summary(results)

    print(f"\n{table}")
    print(f"\n    Summary: {summary['row_count']} rows, {summary['column_count']} columns")

    print("\n" + "=" * 60)
    print("  Sub-agent delegation chain complete")
    print("=" * 60)

    return results


if __name__ == "__main__":
    # In standalone mode, expect the parent delegation token as argument or env var
    parent_token = os.getenv("PARENT_DELEGATION_TOKEN", "")
    if not parent_token and len(sys.argv) > 1:
        parent_token = sys.argv[1]

    if not parent_token:
        print("Usage: python sql_executor.py <parent_delegation_token>")
        print("  or set PARENT_DELEGATION_TOKEN env var")
        sys.exit(1)

    run_subagent_demo(parent_token)
