# Sentinel EGP Policies for Delegation Enforcement

Vault Enterprise Endpoint Governing Policies (EGPs) that enforce delegation
constraints on dynamic database credential requests. These policies replace OPA
as the policy engine, moving enforcement inside Vault itself.

All policies are applied to `database/creds/*` with `hard-mandatory` enforcement,
meaning they cannot be overridden and will block any credential request that
violates the delegation rules.

## Prerequisites

- **Vault Enterprise** (Sentinel is an Enterprise-only feature)
- Entity metadata populated via JWT/SPIFFE auth `claim_mappings`:
  - `human_user` -- the authenticated human (e.g., `alice@acme.com`)
  - `agent_identity` -- the agent's SPIFFE ID (e.g., `spiffe://demo.local/agent/query-agent`)
  - `delegation_scope` -- the delegated permission scope (e.g., `readonly`)
  - `chain_depth` -- delegation chain depth as a string integer (e.g., `1`)
  - `may_act` -- authorized agent SPIFFE ID pattern (e.g., `spiffe://demo.local/agent/*`)

## Policies

### require-delegation.sentinel

Validates that delegation metadata exists on the requesting entity:

- `human_user` must be present and non-empty
- `agent_identity` must be present and non-empty
- `delegation_scope` must be present and non-empty
- `agent_identity` must start with `spiffe://demo.local/` (trust domain validation)

**Without this policy**, any Vault token with the right ACL policy could request
database credentials without proving human authorization.

### enforce-scope.sentinel

Validates that the delegation scope matches the requested credential role:

- Paths ending in `readonly`: scope must be `readonly`, `db:read`, or `db:query`
- Paths ending in `readwrite`: scope must be `readwrite` or `db:write`
- Unknown role suffixes are denied

**Without this policy**, an agent delegated read-only access could request
readwrite credentials if it had both ACL policies attached.

### enforce-chain-depth.sentinel

Validates that the delegation chain has not exceeded the maximum depth:

- `chain_depth` metadata must be present
- Value must be <= 3 (human -> agent -> sub-agent -> sub-sub-agent)

**Without this policy**, delegation chains could extend indefinitely, increasing
the blast radius of a compromised agent.

### enforce-may-act.sentinel

Validates that the human explicitly authorized this specific agent:

- `may_act` metadata must be present and non-empty
- Must match `agent_identity` via exact match or wildcard suffix (`/*`)
- Example: `spiffe://demo.local/agent/*` authorizes any agent under that path

**Without this policy**, any registered agent could act on behalf of any human,
even if the human's token did not include a `may_act` claim for that agent.

## How Policies Are Loaded

The bootstrap script (`scripts/bootstrap.sh`, Step 8d) loads these policies
automatically on Vault Enterprise. Each policy file is base64-encoded and
written to `sys/policies/egp/<name>` via the Vault API.

```bash
# Example manual load:
POLICY=$(base64 < sentinel-policies/require-delegation.sentinel)
vault write sys/policies/egp/require-delegation \
    policy="${POLICY}" \
    paths='["database/creds/*"]' \
    enforcement_level="hard-mandatory"
```

On Vault OSS, the step is skipped with a warning.

## Testing

Sentinel policies are evaluated at request time. To verify:

1. Authenticate as an agent with proper delegation metadata -- credential
   request should succeed
2. Authenticate without delegation metadata -- request should be denied
   with a Sentinel policy failure
3. Authenticate with mismatched scope (e.g., `readonly` scope requesting
   `readwrite` creds) -- request should be denied
4. Authenticate with chain_depth > 3 -- request should be denied
