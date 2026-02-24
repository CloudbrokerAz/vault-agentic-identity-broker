# Alignment Notes

Tracking consistency fixes between demo-ui, README, DEMO-STORY, and ARCHITECTURE.

## Done

- [x] **1. Add demo-ui to README** — Added demo-ui to service endpoints table, project structure, components section, and Quick Start launch instructions.
- [x] **2. Auth modes — update docs** — Replaced Password Grant with Authorization Code Flow in README auth modes table. Updated Keycloak component to list both Device Flow and Auth Code Flow. Password Grant remains in CLI `demo.sh` only.
- [x] **5. Fix demo-ui step order** — Swapped Revocation and Audit Trail in the demo-ui (nav, panels, JS step numbers) so the flow is: ...Database Query → Revocation → Audit Trail. Matches DEMO-STORY ordering.
- [x] **6. Add SPIRE OIDC to ARCHITECTURE port map** — Added `:8082 SPIRE OIDC` and `:8500 Demo UI` to the exposed ports list.
- [x] **XSS fix** — Applied `escapeHtml()` to `syntaxHighlight()` match output to prevent innerHTML injection via JWT claims.

## To Discuss

- [ ] **3. AgentGateway role** — The demo-ui bypasses AgentGateway entirely (talks directly to Token Exchange, Keycloak, OPA, Vault). Need to discuss:
  - Why was it missed? The demo-ui was built as a browser-based educational tool that proxies directly to backend services, not as an agent client going through the gateway.
  - What is AgentGateway's purpose? It's the production front-door for AI agents: OIDC auth, RBAC, rate limiting, MCP/A2A protocol support, observability. It sits between agents and the Token Exchange.
  - Is it needed in the demo-ui? The demo-ui is a human-facing educational tool, not an agent. AgentGateway is designed for machine-to-machine (agent) traffic. Options:
    - (a) Route demo-ui Token Exchange calls through AgentGateway to show the full production path
    - (b) Keep direct access but add a step/panel in the demo-ui that explains AgentGateway's role
    - (c) Leave as-is since the demo-ui is educational, not simulating a real agent
  - What are the benefits of including it? Shows the complete production architecture end-to-end; demonstrates RBAC and rate limiting in action.

## To Do Later

- [ ] **4. Sub-agent delegation in demo-ui** — Add a sub-agent delegation step to the demo-ui (between Database Query and Revocation). Blocked on: fixing up the current agent implementation first. When ready, this step should show the chain extension flow (parent delegation token → sub-agent SVID → second RFC 8693 exchange → narrowed scope → nested act{} claim).
