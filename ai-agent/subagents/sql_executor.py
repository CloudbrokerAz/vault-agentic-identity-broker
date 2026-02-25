#!/usr/bin/env python3
"""
SQL Executor Sub-Agent

A sub-agent that receives a delegation token from a parent agent,
extends the delegation chain via RFC 8693 token exchange, then
authenticates to Vault independently to obtain its own DB credentials.

Delegation chain: Human → Parent Agent → SQL Executor Sub-Agent → Vault → Database

This demonstrates:
  - Sub-agent identity via SPIFFE
  - Delegation chain extension (depth 2)
  - Scope narrowing (parent's scope → readonly only)
  - Independent Vault authentication (SPIFFE + JWT)
  - Direct DB credential request from Vault
"""

import base64
import json
import logging
import os
import sys
import time
import uuid
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
    vault_addr: str = "http://vault:8200"
    trust_domain: str = "demo.local"
    db_host: str = "postgresql"
    db_port: int = 5432
    db_name: str = "appdb"

    @classmethod
    def from_env(cls) -> "SubAgentConfig":
        return cls(
            spiffe_id=os.getenv("AGENT_SPIFFE_ID", cls.spiffe_id),
            token_exchange_url=os.getenv("TOKEN_EXCHANGE_URL", cls.token_exchange_url),
            vault_addr=os.getenv("VAULT_ADDR", cls.vault_addr),
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
    2. Gets its own SPIFFE JWT-SVID
    3. Exchanges parent token for a sub-delegation JWT via RFC 8693
    4. Authenticates to Vault independently (SPIFFE + JWT auth)
    5. Requests its own database credentials from Vault
    6. Executes the query and returns results
    """

    def __init__(self, config: SubAgentConfig):
        self.config = config
        self._delegation_token: Optional[str] = None
        self._db_credentials: Optional[dict] = None
        self._session_id: Optional[str] = None
        self._vault_token: Optional[str] = None
        self._lease_id: Optional[str] = None

    def request_subdelegation(
        self,
        parent_delegation_token: str,
        scope: str = "readonly",
        agent_jwt_svid: str = "",
    ) -> dict:
        """
        Extend the delegation chain and obtain DB credentials via Vault.

        1. RFC 8693 Token Exchange: parent token + sub-agent SVID → fused JWT
        2. Vault SPIFFE auth → workload token
        3. Vault JWT auth with fused JWT → delegation token
        4. Vault DB creds request → username/password
        """
        logger.info("Requesting sub-delegation: scope=%s", scope)

        # Use the provided SPIFFE JWT-SVID or fetch from SPIRE
        if agent_jwt_svid:
            actor_token = agent_jwt_svid
        else:
            actor_token = self._fetch_jwt_svid()

        # Step 1: RFC 8693 token exchange → fused delegation JWT
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

            # Decode the fused JWT locally to extract session_id and chain info
            claims = self._decode_jwt_payload(self._delegation_token)
            self._session_id = claims.get("jti", str(uuid.uuid4()))

            chain_depth = int(claims.get("delegation_depth", 1))
            logger.info(
                "Sub-delegation token exchange successful: session=%s, depth=%d",
                self._session_id, chain_depth,
            )

        except requests.RequestException as e:
            raise RuntimeError(f"Token exchange request failed: {e}") from e

        # Step 2: Vault SPIFFE auth
        try:
            spiffe_resp = requests.post(
                f"{self.config.vault_addr}/v1/auth/jwt/login",
                json={"jwt": actor_token, "role": "gateway"},
                timeout=10,
            )
            spiffe_data = spiffe_resp.json()
            if "errors" in spiffe_data:
                raise RuntimeError(f"Vault SPIFFE auth failed: {spiffe_data['errors']}")
            logger.info("Sub-agent Vault SPIFFE auth successful")
        except requests.RequestException as e:
            raise RuntimeError(f"Vault SPIFFE auth request failed: {e}") from e

        # Step 3: Vault JWT auth with fused delegation token
        vault_jwt_role = f"delegated-agent-{scope}" if scope else "delegated-agent-readonly"
        try:
            jwt_resp = requests.post(
                f"{self.config.vault_addr}/v1/auth/jwt/login",
                json={"jwt": self._delegation_token, "role": vault_jwt_role},
                timeout=10,
            )
            jwt_data = jwt_resp.json()
            if "errors" in jwt_data:
                raise RuntimeError(f"Vault JWT auth failed: {jwt_data['errors']}")

            self._vault_token = jwt_data.get("auth", {}).get("client_token", "")
            if not self._vault_token:
                raise RuntimeError("Vault JWT auth returned no client_token")
            logger.info("Sub-agent Vault JWT auth successful: role=%s", vault_jwt_role)
        except requests.RequestException as e:
            raise RuntimeError(f"Vault JWT auth request failed: {e}") from e

        # Step 4: Request DB credentials from Vault
        vault_db_role = f"ai-agent-{scope}" if scope else "ai-agent-readonly"
        try:
            creds_resp = requests.get(
                f"{self.config.vault_addr}/v1/database/creds/{vault_db_role}",
                headers={"X-Vault-Token": self._vault_token},
                timeout=10,
            )
            creds_data = creds_resp.json()
            if "errors" in creds_data:
                raise RuntimeError(f"Vault DB creds failed: {creds_data['errors']}")

            cred_inner = creds_data.get("data", {})
            self._db_credentials = {
                "username": cred_inner.get("username", ""),
                "password": cred_inner.get("password", ""),
            }
            self._lease_id = creds_data.get("lease_id", "")
            logger.info(
                "Sub-agent Vault DB credentials obtained: user=%s, lease=%s",
                self._db_credentials["username"], self._lease_id,
            )
        except requests.RequestException as e:
            raise RuntimeError(f"Vault DB credential request failed: {e}") from e

        return result

    def execute_query(self, sql: str) -> list[dict]:
        """Execute a SQL query using the Vault-issued credentials."""
        if not self._db_credentials:
            raise RuntimeError("No database credentials. Call request_subdelegation first.")

        creds = self._db_credentials
        logger.info(
            "Executing query as sub-agent: user=%s, session=%s",
            creds["username"], self._session_id,
        )

        conn = psycopg2.connect(
            host=self.config.db_host,
            port=self.config.db_port,
            dbname=self.config.db_name,
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

    @staticmethod
    def _decode_jwt_payload(token: str) -> dict:
        """Decode a JWT payload locally without signature verification."""
        try:
            return pyjwt.decode(
                token,
                options={"verify_signature": False, "verify_aud": False},
            )
        except Exception:
            try:
                parts = token.split(".")
                if len(parts) >= 2:
                    payload = parts[1]
                    padding = 4 - len(payload) % 4
                    if padding != 4:
                        payload += "=" * padding
                    return json.loads(base64.urlsafe_b64decode(payload))
            except Exception:
                pass
            return {}

    def get_delegation_chain(self) -> list[dict]:
        """Get the full delegation chain from the fused JWT's nested act{} claims."""
        if not self._delegation_token:
            return []
        claims = self._decode_jwt_payload(self._delegation_token)
        chain = []
        current = claims
        depth = 0
        while "act" in current:
            depth += 1
            act = current["act"]
            chain.append({
                "subject": current.get("sub", "unknown"),
                "actor": act.get("sub", "unknown"),
                "actor_type": "agent" if "agent/" in act.get("sub", "") else "subagent",
                "scope": current.get("scope", "unknown"),
                "depth": depth,
            })
            current = act
        return chain

    def revoke_credentials(self) -> None:
        """Revoke the Vault credential lease."""
        if self._vault_token and self._lease_id:
            try:
                requests.put(
                    f"{self.config.vault_addr}/v1/sys/leases/revoke",
                    headers={"X-Vault-Token": self._vault_token},
                    json={"lease_id": self._lease_id},
                    timeout=10,
                )
                logger.info("Sub-agent Vault lease revoked: %s", self._lease_id)
            except requests.RequestException as e:
                logger.warning("Failed to revoke sub-agent Vault lease: %s", e)

    def _fetch_jwt_svid(self, audience: str = "token-exchange") -> str:
        """Fetch a JWT-SVID from the SPIRE Workload API."""
        spire_socket = os.getenv("SPIRE_AGENT_SOCKET", "/tmp/spire-agent/public/api.sock")
        try:
            from spiffe import WorkloadApiClient
            client = WorkloadApiClient(
                spiffe_socket=f"unix://{spire_socket}"
            )
            jwt_svid = client.fetch_jwt_svid(
                audiences=[audience],
                hint=self.config.spiffe_id,
            )
            logger.info("JWT-SVID obtained for sub-agent: %s", jwt_svid.spiffe_id)
            return jwt_svid.token
        except Exception as e:
            raise RuntimeError(
                f"SPIRE Workload API unavailable: {e}. "
                "Sub-agent cannot obtain a cryptographically verifiable identity."
            ) from e

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
    Run a demo showing sub-agent delegation with direct Vault auth.

    This demonstrates the full chain:
    Human → Parent Agent → SQL Executor Sub-Agent → Vault → Database
    """
    config = SubAgentConfig.from_env()

    print("\n" + "=" * 60)
    print("  Sub-Agent Delegation Demo (Direct Vault Auth)")
    print("  Chain: Human → Agent → Sub-Agent → Vault → DB")
    print("=" * 60)

    # Step 1: SQL Executor requests sub-delegation + Vault auth
    print("\n[1] SQL Executor requesting sub-delegation + Vault credentials...")
    executor = SQLExecutorSubAgent(config)
    result = executor.request_subdelegation(parent_token, scope="readonly")

    chain = executor.get_delegation_chain()
    print(f"    Session: {executor.session_id}")
    print(f"    Chain depth: {len(chain)}")
    for link in chain:
        print(f"      [{link['depth']}] {link['subject']} → {link['actor']} ({link['actor_type']})")

    # Step 2: Execute query
    print("\n[2] Sub-agent executing query with Vault-issued credentials...")
    sql = "SELECT id, customer_name, total_amount, status FROM app.orders LIMIT 5"
    results = executor.execute_query(sql)

    # Step 3: Format results
    print("\n[3] Formatting results...")
    formatter = ResultFormatterSubAgent()
    table = formatter.format_as_table(results)
    summary = formatter.format_as_summary(results)

    print(f"\n{table}")
    print(f"\n    Summary: {summary['row_count']} rows, {summary['column_count']} columns")

    # Step 4: Revoke credentials
    print("\n[4] Revoking sub-agent Vault credentials...")
    executor.revoke_credentials()

    print("\n" + "=" * 60)
    print("  Sub-agent delegation chain complete (direct Vault auth)")
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
