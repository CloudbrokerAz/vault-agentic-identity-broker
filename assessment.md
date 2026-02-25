Alignment Audit: Original Idea vs Implementation vs NIST Reality

What Aligns Well

The repo genuinely implements the core flow described in the original idea:

- RFC 8693 Token Exchange — 961-line Python service implementing subject_token + actor_token exchange with nested act{} claims per Section 4.1
- SPIFFE/SPIRE — Full server, agent, and OIDC discovery provider with trust domain demo.local
- Keycloak as IdP — OIDC, Device Auth Flow (RFC 8628), may_act claim, groups
- Vault dynamic credentials — 5-minute TTL PostgreSQL roles, auto-revocation, entity metadata
- Vault Sentinel EGPs — four hard-mandatory policies for delegation enforcement (replacing the previous OPA Rego policies)
- Sub-agent delegation chains — Working scope narrowing with configurable max depth
- 6-layer audit trail — Correlation from Keycloak through to PostgreSQL pgaudit (OPA layer removed; Vault Sentinel EGPs consolidate policy+audit)

So at the demo/PoC level described in Phase 1 of the original idea, the repo delivers. The question is whether the architecture holds up under scrutiny.

---

Fundamental Flaws

1. The "cryptographic proof" claim is hollow — SPIFFE SVIDs are never actually verified

This is the most serious issue. The original idea's central thesis is:

"cryptographically verifiable identity chain from user through agent to database"

But in token-exchange/token_exchange.py, the actor token (SPIFFE JWT-SVID) is parsed but never cryptographically verified against SPIRE's JWKS endpoint:

# What actually happens (trust domain string check only):

decoded = jwt.decode(actor_token, options={"verify_signature": False})
if not decoded.get("sub", "").startswith(f"spiffe://{SPIFFE_TRUST_DOMAIN}/"):
return None # reject

This is string prefix matching, not cryptographic verification. Any process that can forge a JWT with sub: "spiffe://demo.local/agent/query-agent" can impersonate any
agent. The entire SPIRE infrastructure — server, agent, attestation, SVID issuance — is rendered decorative if the relying party never checks signatures.

Why this matters: SPIFFE's value proposition is that SPIRE attests workloads via kernel introspection and issues short-lived cryptographic identities. If you don't verify
the signature, you have no attestation — you have a naming convention.

2. The Token Exchange service is a custom STS that breaks the OAuth model

In real RFC 8693, the Authorization Server (Keycloak) performs token exchange. The spec says:

"The token exchange request is made to the token endpoint of the authorization server"

This implementation creates a separate custom Python service that:

- Accepts tokens
- Mints its own HMAC-signed JWTs (not from Keycloak)
- Simultaneously brokers Vault credentials
- Holds a long-lived Vault token

This conflation creates problems:

- The "delegation token" is not a real OAuth token from any standards-compliant AS — no relying party can introspect or validate it against an IdP
- The service is a single point of compromise: if attacked, the adversary gets a Vault token that can create any database credential
- HMAC (symmetric) signing means anyone with the shared secret can forge delegation tokens
- It violates the principle of separation: token issuance and credential brokering should be distinct trust boundaries

The original idea described separate components: "Identity Gateway validates... then brokers Vault access". The implementation merges validation, policy, token minting,
and credential brokering into one service.

3. No mutual TLS — zero-trust in name only

The original idea states:

"Implicit trust based on network — eliminated by mandatory SPIFFE mTLS"

The implementation uses plain HTTP everywhere within the Docker network. Keycloak, Vault, Token Exchange, PostgreSQL — all communicate unencrypted. The SPIFFE
X.509-SVIDs that enable mTLS are never used for service-to-service communication.

In a real zero-trust architecture, every hop (Agent → Token Exchange → Vault → PostgreSQL) would use mTLS with SPIFFE X.509-SVIDs, so that network position grants zero
implicit trust. Without this, any container on the Docker network can call Vault or the Token Exchange service directly.

4. The may_act claim is hardcoded — no real delegation consent

The original idea describes may_act as the human pre-authorizing specific agents:

{"may_act": {"sub": "agent:query-agent-v2", "client_id": "ai-agent-service"}}

In the implementation, this claim is a hardcoded Keycloak protocol mapper — every token for every user always contains the same may_act claim. There's no:

- Dynamic consent UI where Alice chooses which agent to authorize
- Per-session delegation scoping
- Ability to revoke delegation authorization for a specific agent
- Distinction between "Alice authorizes agent X for task Y" vs "all users always authorize all agents"

This is a demo shortcut, but it undermines the entire delegation model. NIST's concept paper specifically calls out the need for "linking user identities to AI agents to
maintain accountability and oversight" — hardcoded blanket authorization isn't oversight.

5. Vault token for Token Exchange is over-privileged and long-lived

The bootstrap creates a Vault token for the Token Exchange service with broad database credential minting capability. This token:

- Lives for the lifetime of the service
- Can generate credentials for any configured role (readonly, readwrite)
- Is stored in .gateway.env on the filesystem
- Has no per-session or per-user scoping

This contradicts the architecture's own principle: "every credential is short-lived and automatically rotated." The Vault token that gates all database access is neither
short-lived nor scoped. A compromise of this single token (or the Token Exchange service) grants unrestricted credential generation.

6. Fail-open defaults contradict zero-trust

Two critical services fail open in demo mode:

- Keycloak unavailable → parse token unverified (bypass authentication)

Note: OPA has been replaced by Vault Sentinel EGPs, which are hard-mandatory and cannot be bypassed. However, the Token Exchange Service's Keycloak validation failure mode still needs attention. In a zero-trust architecture, unavailability of the identity provider must be a hard deny.

---

Gaps Against NIST NCCoE Concept Paper

The NIST NCCoE concept paper specifically names six standards for their planned demonstration. Here's how this repo maps:

┌───────────────────────────────────────┬─────────────────────────────────────────────────────┬────────────────────────────────────────────────┐
│ NIST Standard │ This Repo │ Gap │
├───────────────────────────────────────┼─────────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ OAuth 2.0/2.1 + extensions │ RFC 8693 implemented, but in custom STS not the AS │ Token exchange should be at the IdP │
├───────────────────────────────────────┼─────────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ OpenID Connect │ Keycloak OIDC working │ Adequate │
├───────────────────────────────────────┼─────────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ SPIFFE/SPIRE │ Deployed but SVIDs never cryptographically verified │ Core attestation value is unused │
├───────────────────────────────────────┼─────────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ SCIM │ Completely absent │ No agent provisioning/deprovisioning lifecycle │
├───────────────────────────────────────┼─────────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ MCP (Model Context Protocol) │ AgentGateway configured but not wired into demo │ Dead code in the architecture │
├───────────────────────────────────────┼─────────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ NGAC (Next Generation Access Control) │ Absent — Vault Sentinel EGPs used instead │ Different access control model │
└───────────────────────────────────────┴─────────────────────────────────────────────────────┴────────────────────────────────────────────────┘

The biggest gap is SCIM. NIST explicitly identifies the need to manage AI agents as identity objects with lifecycle operations (create, update, deprovision). This repo
hardcodes agents in SPIRE registration entries. There's no way to:

- Register a new agent at runtime
- Deprovision a compromised agent without updating SPIRE entries
- Manage agent metadata (capabilities, trust level, owner)
- Distinguish agent autonomy levels (human-in-the-loop vs autonomous)

NIST's four focus areas vs this repo:

1. Identification (distinguishing agents from humans, managing metadata) — Partially. SPIFFE IDs distinguish, but no metadata management or autonomy classification.
2. Authorization (OAuth + policy-based access control) — Present but with the STS architecture issues above.
3. Access Delegation (linking user identities to agents for accountability) — The act{} claim chain is good. The hardcoded may_act and lack of dynamic consent is not.
4. Logging and Transparency (linking agent actions to NHI) — The 6-layer audit trail (consolidated from 7 after OPA removal) is genuinely the strongest part of this implementation.

---

Gaps Against IETF WIMSE / Emerging Standards

The IETF WIMSE working group is building the actual standard for workload identity interoperability. Key gaps:

- Workload Identity Tokens (WITs) — WIMSE is defining a new token type for workload-to-workload auth. This repo uses JWT-SVIDs but doesn't align with the emerging WIT
  spec.
- Token Exchange and Translation Protocol — WIMSE's draft-saxe-wimse-token-exchange-and-translation addresses exactly this use case (translating between SPIFFE, OAuth, and
  other identity formats). The custom Token Exchange service reinvents this.
- SPIFFE Client Authentication for OAuth — An IETF draft for using SPIFFE identities as OAuth client credentials. This repo doesn't use it.
- Transaction Tokens — draft-ietf-oauth-transaction-tokens defines short-lived JWTs for propagating identity across workload chains — the exact use case of this repo's
  delegation tokens. But the repo's tokens don't conform to this spec.

---

What's Actually Good

To be fair about what works:

1. The delegation chain model with nested act{} claims is sound and aligns with RFC 8693 Section 4.1 correctly
2. Vault dynamic credentials with 5-min TTL is the right pattern — this genuinely solves the static credential problem
3. Policy enforcement with scope narrowing and depth limits is well-designed (now via Vault Sentinel EGPs)
4. Device Authorization Flow means the agent never sees the human's password — this is correct
5. The audit trail with session ID correlation is the implementation's strongest feature (now 6 layers after OPA removal)
6. Sub-agent delegation with scope narrowing is architecturally sound
7. The Docker Compose demo successfully demonstrates the concept end-to-end

---

Summary: Three Categories of Issues

Architectural (would need redesign):

- Token exchange belongs in Keycloak (the AS), not a custom STS
- SPIFFE SVIDs must be cryptographically verified or the entire trust model collapses
- mTLS between all services is non-negotiable for zero-trust
- Separation of token issuance from credential brokering

Missing capabilities (additive work):

- SCIM for agent lifecycle management
- Dynamic delegation consent (not hardcoded may_act)
- MCP protocol integration (configured but unused)
- WIMSE/Transaction Tokens alignment
- Asymmetric token signing (RS256/ES256)

Demo shortcuts (acceptable for PoC, must not ship):

- Fail-open on Keycloak unavailability (Sentinel EGPs are now hard-mandatory, fixing the OPA fail-open issue)
- Single Vault unseal key
- Long-lived Vault token for Token Exchange service
- Plain HTTP everywhere

The repo is a solid educational demo that successfully illustrates the concept of delegated agentic identity. But it's not a reference implementation you'd point at to say
"build like this" — because the core cryptographic verification that makes the architecture trustworthy is missing, and the custom STS pattern diverges from where the
standards are heading.

---

Sources:

- NIST NCCoE Concept Paper - Software and AI Agent Identity and Authorization
- NIST AI Agent Standards Initiative
- NCCoE Project Page - Software and AI Agent Identity and Authorization
- IETF WIMSE Working Group
- IETF OAuth SPIFFE Client Authentication Draft
- WIMSE Token Exchange and Translation Protocol
- SPIFFE WIT Support Discussion
