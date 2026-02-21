package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ─── Token Verifier Tests ──────────────────────────────────────────────────

func createTestJWT(claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret"))
	return tokenString
}

func TestTokenVerifier_ParseUnverified_ValidToken(t *testing.T) {
	cfg := &Config{
		KeycloakURL:   "http://keycloak:8080",
		KeycloakRealm: "demo",
	}
	tv, err := NewTokenVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTokenVerifier() error: %v", err)
	}

	token := createTestJWT(jwt.MapClaims{
		"sub":    "alice-uuid-123",
		"email":  "alice@acme.com",
		"iss":    "http://keycloak:8080/realms/demo",
		"exp":    float64(time.Now().Add(1 * time.Hour).Unix()),
		"groups": []interface{}{"data-analysts", "trading-team"},
		"may_act": map[string]interface{}{
			"sub":       "agent:query-agent-v2",
			"client_id": "ai-agent-service",
		},
	})

	claims, err := tv.parseUnverified(token)
	if err != nil {
		t.Fatalf("parseUnverified() error: %v", err)
	}

	if claims.Subject != "alice@acme.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "alice@acme.com")
	}
	if claims.Email != "alice@acme.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "alice@acme.com")
	}
	if claims.Issuer != "http://keycloak:8080/realms/demo" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "http://keycloak:8080/realms/demo")
	}
	if len(claims.Groups) != 2 {
		t.Errorf("Groups count = %d, want 2", len(claims.Groups))
	}
	if claims.Groups[0] != "data-analysts" {
		t.Errorf("Groups[0] = %q, want %q", claims.Groups[0], "data-analysts")
	}
	if claims.MayAct == nil {
		t.Error("MayAct is nil, want non-nil")
	}
	if claims.MayAct["sub"] != "agent:query-agent-v2" {
		t.Errorf("MayAct.sub = %q, want %q", claims.MayAct["sub"], "agent:query-agent-v2")
	}
}

func TestTokenVerifier_ParseUnverified_EmailPreferredOverSub(t *testing.T) {
	cfg := &Config{KeycloakURL: "http://keycloak:8080", KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	token := createTestJWT(jwt.MapClaims{
		"sub":   "uuid-only-subject",
		"email": "bob@acme.com",
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	claims, err := tv.parseUnverified(token)
	if err != nil {
		t.Fatalf("parseUnverified() error: %v", err)
	}

	// Email should take precedence over sub for readability
	if claims.Subject != "bob@acme.com" {
		t.Errorf("Subject = %q, want %q (email should be preferred)", claims.Subject, "bob@acme.com")
	}
}

func TestTokenVerifier_ParseUnverified_SubOnly(t *testing.T) {
	cfg := &Config{KeycloakURL: "http://keycloak:8080", KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	token := createTestJWT(jwt.MapClaims{
		"sub": "alice-uuid-123",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	claims, err := tv.parseUnverified(token)
	if err != nil {
		t.Fatalf("parseUnverified() error: %v", err)
	}

	if claims.Subject != "alice-uuid-123" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "alice-uuid-123")
	}
}

func TestTokenVerifier_ParseUnverified_MissingSubject(t *testing.T) {
	cfg := &Config{KeycloakURL: "http://keycloak:8080", KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	token := createTestJWT(jwt.MapClaims{
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	_, err := tv.parseUnverified(token)
	if err == nil {
		t.Error("parseUnverified() should error on missing subject")
	}
	if !strings.Contains(err.Error(), "missing subject") {
		t.Errorf("Error = %q, want to contain 'missing subject'", err.Error())
	}
}

func TestTokenVerifier_ParseUnverified_InvalidTokenFormat(t *testing.T) {
	cfg := &Config{KeycloakURL: "http://keycloak:8080", KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	_, err := tv.parseUnverified("not-a-jwt-token")
	if err == nil {
		t.Error("parseUnverified() should error on invalid token")
	}
}

func TestTokenVerifier_ParseUnverified_EmptyGroups(t *testing.T) {
	cfg := &Config{KeycloakURL: "http://keycloak:8080", KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	token := createTestJWT(jwt.MapClaims{
		"sub": "alice@acme.com",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	claims, err := tv.parseUnverified(token)
	if err != nil {
		t.Fatalf("parseUnverified() error: %v", err)
	}

	if claims.Groups != nil {
		t.Errorf("Groups = %v, want nil", claims.Groups)
	}
}

func TestTokenVerifier_ParseUnverified_ExpiresAt(t *testing.T) {
	cfg := &Config{KeycloakURL: "http://keycloak:8080", KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	expTime := time.Now().Add(1 * time.Hour).Unix()
	token := createTestJWT(jwt.MapClaims{
		"sub": "alice@acme.com",
		"exp": float64(expTime),
	})

	claims, err := tv.parseUnverified(token)
	if err != nil {
		t.Fatalf("parseUnverified() error: %v", err)
	}

	if claims.ExpiresAt != expTime {
		t.Errorf("ExpiresAt = %d, want %d", claims.ExpiresAt, expTime)
	}
}

func TestTokenVerifier_ValidateViaUserinfo_Success(t *testing.T) {
	// Mock Keycloak userinfo endpoint
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/demo/protocol/openid-connect/userinfo" {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				http.Error(w, "no auth", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":    "alice-uuid",
				"email":  "alice@acme.com",
				"groups": []string{"data-analysts"},
				"may_act": map[string]interface{}{
					"sub": "agent:query-agent-v2",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer userInfoServer.Close()

	cfg := &Config{KeycloakURL: userInfoServer.URL, KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	testToken := createTestJWT(jwt.MapClaims{
		"sub": "alice-uuid",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	claims, err := tv.validateViaUserinfo(context.Background(), testToken)
	if err != nil {
		t.Fatalf("validateViaUserinfo() error: %v", err)
	}

	if claims.Subject != "alice@acme.com" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "alice@acme.com")
	}
}

func TestTokenVerifier_ValidateViaUserinfo_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := &Config{KeycloakURL: server.URL, KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	_, err := tv.validateViaUserinfo(context.Background(), "bad-token")
	if err == nil {
		t.Error("validateViaUserinfo() should error on 401 response")
	}
}

func TestTokenVerifier_ExtractClaimsFromMap(t *testing.T) {
	cfg := &Config{KeycloakURL: "http://keycloak:8080", KeycloakRealm: "demo"}
	tv, _ := NewTokenVerifier(cfg)

	tests := []struct {
		name      string
		claims    jwt.MapClaims
		wantSub   string
		wantErr   bool
	}{
		{
			name:    "full claims",
			claims:  jwt.MapClaims{"sub": "user1", "email": "user1@test.com", "iss": "http://test", "exp": float64(9999999999)},
			wantSub: "user1@test.com",
		},
		{
			name:    "sub only",
			claims:  jwt.MapClaims{"sub": "user-uuid", "exp": float64(9999999999)},
			wantSub: "user-uuid",
		},
		{
			name:    "missing subject",
			claims:  jwt.MapClaims{"exp": float64(9999999999)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tv.extractClaimsFromMap(tt.claims)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Subject != tt.wantSub {
				t.Errorf("Subject = %q, want %q", result.Subject, tt.wantSub)
			}
		})
	}
}

func TestNewTokenVerifier_URLConstruction(t *testing.T) {
	cfg := &Config{KeycloakURL: "https://auth.example.com", KeycloakRealm: "production"}
	tv, err := NewTokenVerifier(cfg)
	if err != nil {
		t.Fatalf("NewTokenVerifier() error: %v", err)
	}

	expectedJWKS := "https://auth.example.com/realms/production/protocol/openid-connect/certs"
	if tv.jwksURL != expectedJWKS {
		t.Errorf("jwksURL = %q, want %q", tv.jwksURL, expectedJWKS)
	}

	expectedIssuer := "https://auth.example.com/realms/production"
	if tv.issuerURL != expectedIssuer {
		t.Errorf("issuerURL = %q, want %q", tv.issuerURL, expectedIssuer)
	}
}

// ─── OPA Client Tests ──────────────────────────────────────────────────────

func TestOPAClient_Evaluate_Allow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/allow") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"result": true})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/decision") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"reason": "allowed"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewOPAClient(server.URL)
	allowed, reason, err := client.Evaluate(context.Background(), map[string]interface{}{
		"human_token": map[string]interface{}{
			"sub":    "alice@acme.com",
			"groups": []string{"data-analysts"},
		},
		"agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
		"requested_scope":  "readonly",
	})

	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if !allowed {
		t.Error("Evaluate() returned denied, expected allowed")
	}
	if reason != "allowed" {
		t.Errorf("reason = %q, want %q", reason, "allowed")
	}
}

func TestOPAClient_Evaluate_Deny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/allow") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"result": false})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/decision") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"reason": "scope_not_permitted"},
			})
			return
		}
	}))
	defer server.Close()

	client := NewOPAClient(server.URL)
	allowed, reason, err := client.Evaluate(context.Background(), map[string]interface{}{})
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if allowed {
		t.Error("Evaluate() returned allowed, expected denied")
	}
	if reason != "scope_not_permitted" {
		t.Errorf("reason = %q, want %q", reason, "scope_not_permitted")
	}
}

func TestOPAClient_Evaluate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewOPAClient(server.URL)
	_, _, err := client.Evaluate(context.Background(), map[string]interface{}{})
	if err == nil {
		t.Error("Evaluate() should error on 500 response")
	}
}

func TestOPAClient_Evaluate_ConnectionRefused(t *testing.T) {
	client := NewOPAClient("http://localhost:1") // Not listening
	_, _, err := client.Evaluate(context.Background(), map[string]interface{}{})
	if err == nil {
		t.Error("Evaluate() should error when OPA is unreachable")
	}
}

func TestOPAClient_Evaluate_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "not-json")
	}))
	defer server.Close()

	client := NewOPAClient(server.URL)
	_, _, err := client.Evaluate(context.Background(), map[string]interface{}{})
	if err == nil {
		t.Error("Evaluate() should error on invalid JSON response")
	}
}

func TestOPAClient_Evaluate_DecisionEndpointUnavailable(t *testing.T) {
	// Only /allow responds, /decision returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/allow") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"result": true})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewOPAClient(server.URL)
	allowed, reason, err := client.Evaluate(context.Background(), map[string]interface{}{})
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if !allowed {
		t.Error("Evaluate() should still return allow even if decision endpoint fails")
	}
	// Reason falls back to default
	if reason != "policy_evaluated" {
		t.Errorf("reason = %q, want %q (default fallback)", reason, "policy_evaluated")
	}
}

func TestNewOPAClient(t *testing.T) {
	client := NewOPAClient("http://opa:8181")
	if client.endpoint != "http://opa:8181" {
		t.Errorf("endpoint = %q, want %q", client.endpoint, "http://opa:8181")
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

// ─── Vault Broker Tests ────────────────────────────────────────────────────

func TestVaultBroker_ScopeToRole(t *testing.T) {
	vb := &VaultBroker{}

	tests := []struct {
		scope    string
		wantRole string
	}{
		{"readonly", "ai-agent-readonly"},
		{"db:read", "ai-agent-readonly"},
		{"db:query", "ai-agent-readonly"},
		{"readwrite", "ai-agent-readwrite"},
		{"db:write", "ai-agent-readwrite"},
		{"unknown-scope", "ai-agent-readonly"},   // default to readonly
		{"", "ai-agent-readonly"},                 // empty defaults to readonly
		{"READONLY", "ai-agent-readonly"},          // case-sensitive: not matched, defaults
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			got := vb.scopeToRole(tt.scope)
			if got != tt.wantRole {
				t.Errorf("scopeToRole(%q) = %q, want %q", tt.scope, got, tt.wantRole)
			}
		})
	}
}

func TestNewVaultBroker_DefaultConfig(t *testing.T) {
	cfg := &Config{
		VaultAddr:  "http://vault:8200",
		VaultToken: "",
	}

	vb, err := NewVaultBroker(cfg)
	if err != nil {
		t.Fatalf("NewVaultBroker() error: %v", err)
	}
	if vb.client == nil {
		t.Error("client is nil")
	}
}

func TestNewVaultBroker_WithToken(t *testing.T) {
	cfg := &Config{
		VaultAddr:  "http://vault:8200",
		VaultToken: "test-token-123",
	}

	vb, err := NewVaultBroker(cfg)
	if err != nil {
		t.Fatalf("NewVaultBroker() error: %v", err)
	}
	if vb.client.Token() != "test-token-123" {
		t.Errorf("token = %q, want %q", vb.client.Token(), "test-token-123")
	}
}

// ─── Config Tests ──────────────────────────────────────────────────────────

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear env vars to test defaults
	envVars := []string{"LISTEN_PORT", "KEYCLOAK_URL", "KEYCLOAK_REALM",
		"SPIRE_AGENT_SOCKET", "OPA_ENDPOINT", "VAULT_ADDR", "VAULT_TOKEN", "TRUST_DOMAIN"}
	originals := make(map[string]string)
	for _, k := range envVars {
		originals[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	defer func() {
		for k, v := range originals {
			if v != "" {
				os.Setenv(k, v)
			}
		}
	}()

	cfg := LoadConfig()

	if cfg.ListenPort != "8080" {
		t.Errorf("ListenPort = %q, want %q", cfg.ListenPort, "8080")
	}
	if cfg.KeycloakURL != "http://keycloak:8080" {
		t.Errorf("KeycloakURL = %q, want %q", cfg.KeycloakURL, "http://keycloak:8080")
	}
	if cfg.KeycloakRealm != "demo" {
		t.Errorf("KeycloakRealm = %q, want %q", cfg.KeycloakRealm, "demo")
	}
	if cfg.OPAEndpoint != "http://opa:8181" {
		t.Errorf("OPAEndpoint = %q, want %q", cfg.OPAEndpoint, "http://opa:8181")
	}
	if cfg.VaultAddr != "http://vault:8200" {
		t.Errorf("VaultAddr = %q, want %q", cfg.VaultAddr, "http://vault:8200")
	}
	if cfg.TrustDomain != "demo.local" {
		t.Errorf("TrustDomain = %q, want %q", cfg.TrustDomain, "demo.local")
	}
}

func TestLoadConfig_FromEnv(t *testing.T) {
	os.Setenv("LISTEN_PORT", "9090")
	os.Setenv("TRUST_DOMAIN", "prod.example.com")
	defer func() {
		os.Unsetenv("LISTEN_PORT")
		os.Unsetenv("TRUST_DOMAIN")
	}()

	cfg := LoadConfig()
	if cfg.ListenPort != "9090" {
		t.Errorf("ListenPort = %q, want %q", cfg.ListenPort, "9090")
	}
	if cfg.TrustDomain != "prod.example.com" {
		t.Errorf("TrustDomain = %q, want %q", cfg.TrustDomain, "prod.example.com")
	}
}

func TestGetEnv(t *testing.T) {
	os.Setenv("TEST_VAR_GETENV", "custom-value")
	defer os.Unsetenv("TEST_VAR_GETENV")

	if got := getEnv("TEST_VAR_GETENV", "default"); got != "custom-value" {
		t.Errorf("getEnv() = %q, want %q", got, "custom-value")
	}
	if got := getEnv("NONEXISTENT_VAR_XYZZY", "fallback"); got != "fallback" {
		t.Errorf("getEnv() = %q, want %q", got, "fallback")
	}
}

// ─── Gateway Handler Tests ─────────────────────────────────────────────────

func TestHandleHealth(t *testing.T) {
	cfg := &Config{VaultAddr: "http://vault:8200"}
	tv, _ := NewTokenVerifier(cfg)
	vb, _ := NewVaultBroker(cfg)

	gw := &Gateway{
		config:        cfg,
		logger:        newTestLogger(),
		tokenVerifier: tv,
		opaClient:     NewOPAClient("http://opa:8181"),
		vaultBroker:   vb,
		auditLog:      make([]AuditEntry, 0),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	w := httptest.NewRecorder()

	gw.HandleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "healthy" {
		t.Errorf("status = %q, want %q", resp["status"], "healthy")
	}
	if resp["timestamp"] == nil {
		t.Error("timestamp is missing")
	}
	components, ok := resp["components"].(map[string]interface{})
	if !ok {
		t.Fatal("components missing or wrong type")
	}
	if components["opa"] != "configured" {
		t.Errorf("components.opa = %q, want %q", components["opa"], "configured")
	}
	if components["vault"] != "configured" {
		t.Errorf("components.vault = %q, want %q", components["vault"], "configured")
	}
}

func TestHandleAuditLog_Empty(t *testing.T) {
	gw := &Gateway{
		logger:   newTestLogger(),
		auditLog: make([]AuditEntry, 0),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	w := httptest.NewRecorder()

	gw.HandleAuditLog(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var entries []AuditEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("audit entries = %d, want 0", len(entries))
	}
}

func TestHandleAuditLog_WithEntries(t *testing.T) {
	gw := &Gateway{
		logger: newTestLogger(),
		auditLog: []AuditEntry{
			{SessionID: "sess-1", Human: "alice@acme.com", Result: "success"},
			{SessionID: "sess-2", Human: "bob@acme.com", Result: "delegation_denied"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	w := httptest.NewRecorder()

	gw.HandleAuditLog(w, req)

	var entries []AuditEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 2 {
		t.Errorf("audit entries = %d, want 2", len(entries))
	}
	if entries[0].Human != "alice@acme.com" {
		t.Errorf("entries[0].Human = %q, want %q", entries[0].Human, "alice@acme.com")
	}
}

func TestHandleAuditLog_MethodNotAllowed(t *testing.T) {
	gw := &Gateway{logger: newTestLogger(), auditLog: make([]AuditEntry, 0)}

	req := httptest.NewRequest(http.MethodPost, "/v1/audit", nil)
	w := httptest.NewRecorder()

	gw.HandleAuditLog(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleDelegate_MethodNotAllowed(t *testing.T) {
	gw := &Gateway{logger: newTestLogger(), auditLog: make([]AuditEntry, 0)}

	req := httptest.NewRequest(http.MethodGet, "/v1/delegate", nil)
	w := httptest.NewRecorder()

	gw.HandleDelegate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleDelegate_InvalidBody(t *testing.T) {
	cfg := &Config{VaultAddr: "http://vault:8200", TrustDomain: "demo.local"}
	tv, _ := NewTokenVerifier(cfg)
	vb, _ := NewVaultBroker(cfg)

	gw := &Gateway{
		config:        cfg,
		logger:        newTestLogger(),
		tokenVerifier: tv,
		opaClient:     NewOPAClient("http://opa:8181"),
		vaultBroker:   vb,
		auditLog:      make([]AuditEntry, 0),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/delegate", bytes.NewReader([]byte("not-json")))
	req.Header.Set("X-Request-ID", "test-req-1")
	w := httptest.NewRecorder()

	gw.HandleDelegate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleDelegate_InvalidSPIFFEID(t *testing.T) {
	// Mock Keycloak to return valid userinfo
	keycloakServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":   "alice-uuid",
			"email": "alice@acme.com",
		})
	}))
	defer keycloakServer.Close()

	cfg := &Config{
		KeycloakURL:   keycloakServer.URL,
		KeycloakRealm: "demo",
		VaultAddr:     "http://vault:8200",
		TrustDomain:   "demo.local",
	}
	tv, _ := NewTokenVerifier(cfg)
	vb, _ := NewVaultBroker(cfg)

	gw := &Gateway{
		config:        cfg,
		logger:        newTestLogger(),
		tokenVerifier: tv,
		opaClient:     NewOPAClient("http://opa:8181"),
		vaultBroker:   vb,
		auditLog:      make([]AuditEntry, 0),
	}

	body, _ := json.Marshal(DelegationRequest{
		HumanToken:     createTestJWT(jwt.MapClaims{"sub": "alice@acme.com", "exp": float64(time.Now().Add(1 * time.Hour).Unix())}),
		AgentSPIFFEID:  "spiffe://evil.com/agent/bad",
		RequestedScope: "readonly",
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/delegate", bytes.NewReader(body))
	req.Header.Set("X-Request-ID", "test-req-2")
	w := httptest.NewRecorder()

	gw.HandleDelegate(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	// Verify audit entry was recorded
	if len(gw.auditLog) != 1 {
		t.Fatalf("auditLog length = %d, want 1", len(gw.auditLog))
	}
	if gw.auditLog[0].Result != "invalid_spiffe_id" {
		t.Errorf("auditLog[0].Result = %q, want %q", gw.auditLog[0].Result, "invalid_spiffe_id")
	}
}

// ─── Audit Recording Tests ─────────────────────────────────────────────────

func TestRecordAudit(t *testing.T) {
	gw := &Gateway{
		logger:   newTestLogger(),
		auditLog: make([]AuditEntry, 0),
	}

	gw.recordAudit("sess-1", "req-1", "alice@acme.com", "spiffe://demo.local/agent/qa", "readonly", "allow", "success", "")

	if len(gw.auditLog) != 1 {
		t.Fatalf("auditLog length = %d, want 1", len(gw.auditLog))
	}

	entry := gw.auditLog[0]
	if entry.SessionID != "sess-1" {
		t.Errorf("SessionID = %q, want %q", entry.SessionID, "sess-1")
	}
	if entry.Human != "alice@acme.com" {
		t.Errorf("Human = %q, want %q", entry.Human, "alice@acme.com")
	}
	if entry.Result != "success" {
		t.Errorf("Result = %q, want %q", entry.Result, "success")
	}
	if entry.Error != "" {
		t.Errorf("Error = %q, want empty", entry.Error)
	}
	if entry.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestRecordAudit_WithError(t *testing.T) {
	gw := &Gateway{
		logger:   newTestLogger(),
		auditLog: make([]AuditEntry, 0),
	}

	gw.recordAudit("sess-2", "req-2", "unknown", "spiffe://evil.com/bad", "readonly", "deny", "token_validation_failed", "token expired")

	entry := gw.auditLog[0]
	if entry.Error != "token expired" {
		t.Errorf("Error = %q, want %q", entry.Error, "token expired")
	}
	if entry.Result != "token_validation_failed" {
		t.Errorf("Result = %q, want %q", entry.Result, "token_validation_failed")
	}
}

func TestRecordAudit_MultipleEntries(t *testing.T) {
	gw := &Gateway{
		logger:   newTestLogger(),
		auditLog: make([]AuditEntry, 0),
	}

	gw.recordAudit("sess-1", "req-1", "alice", "agent1", "readonly", "allow", "success", "")
	gw.recordAudit("sess-2", "req-2", "bob", "agent2", "readwrite", "deny", "denied", "scope_not_permitted")
	gw.recordAudit("sess-3", "req-3", "alice", "agent1", "readonly", "allow", "success", "")

	if len(gw.auditLog) != 3 {
		t.Errorf("auditLog length = %d, want 3", len(gw.auditLog))
	}
}

// ─── WriteError Tests ──────────────────────────────────────────────────────

func TestWriteError(t *testing.T) {
	gw := &Gateway{logger: newTestLogger()}

	w := httptest.NewRecorder()
	gw.writeError(w, http.StatusForbidden, "access denied", "req-123", "sess-456")

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "access denied" {
		t.Errorf("error = %q, want %q", resp["error"], "access denied")
	}
	if resp["request_id"] != "req-123" {
		t.Errorf("request_id = %q, want %q", resp["request_id"], "req-123")
	}
	if resp["session_id"] != "sess-456" {
		t.Errorf("session_id = %q, want %q", resp["session_id"], "sess-456")
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want %q", w.Header().Get("Content-Type"), "application/json")
	}
}

// ─── Data Type Tests ───────────────────────────────────────────────────────

func TestDelegationRequest_JSON(t *testing.T) {
	req := DelegationRequest{
		HumanToken:     "tok-123",
		AgentSPIFFEID:  "spiffe://demo.local/agent/qa",
		AgentJWTSVID:   "svid-456",
		RequestedScope: "readonly",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded DelegationRequest
	json.Unmarshal(data, &decoded)

	if decoded.HumanToken != "tok-123" {
		t.Errorf("HumanToken = %q, want %q", decoded.HumanToken, "tok-123")
	}
	if decoded.AgentSPIFFEID != "spiffe://demo.local/agent/qa" {
		t.Errorf("AgentSPIFFEID = %q, want %q", decoded.AgentSPIFFEID, "spiffe://demo.local/agent/qa")
	}
}

func TestDBCredential_JSON(t *testing.T) {
	cred := DBCredential{
		Username: "v-spiffe-readonly-xYZ",
		Password: "secret",
		Host:     "postgresql",
		Port:     5432,
		Database: "appdb",
		TTL:      300,
		LeaseID:  "database/creds/ai-agent-readonly/abc123",
	}

	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded DBCredential
	json.Unmarshal(data, &decoded)

	if decoded.TTL != 300 {
		t.Errorf("TTL = %d, want %d", decoded.TTL, 300)
	}
	if decoded.Host != "postgresql" {
		t.Errorf("Host = %q, want %q", decoded.Host, "postgresql")
	}
}

func TestAuditEntry_JSON(t *testing.T) {
	entry := AuditEntry{
		Timestamp:      "2026-02-20T10:30:00Z",
		SessionID:      "sess-abc",
		RequestID:      "req-def",
		Human:          "alice@acme.com",
		AgentSPIFFEID:  "spiffe://demo.local/agent/qa",
		RequestedScope: "readonly",
		OPADecision:    "allow",
		Result:         "success",
	}

	data, _ := json.Marshal(entry)
	var decoded AuditEntry
	json.Unmarshal(data, &decoded)

	if decoded.SessionID != "sess-abc" {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, "sess-abc")
	}
	if decoded.Error != "" {
		t.Errorf("Error = %q, want empty (omitempty)", decoded.Error)
	}
}

// ─── Logging Middleware Tests ──────────────────────────────────────────────

func TestLoggingMiddleware(t *testing.T) {
	logger := newTestLogger()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			t.Error("X-Request-ID not set by middleware")
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware := loggingMiddleware(logger, handler)

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func newTestLogger() *log.Logger {
	return log.New(os.Stderr, "[test] ", log.LstdFlags)
}
