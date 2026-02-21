package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
)

func main() {
	cfg := LoadConfig()

	logger := log.New(os.Stdout, "[identity-gateway] ", log.LstdFlags|log.Lmicroseconds)

	gw, err := NewGateway(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize gateway: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/delegate", gw.HandleDelegate)
	mux.HandleFunc("/v1/health", gw.HandleHealth)
	mux.HandleFunc("/v1/audit", gw.HandleAuditLog)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.ListenPort),
		Handler:      loggingMiddleware(logger, mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Printf("Identity Gateway starting on :%s", cfg.ListenPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server error: %v", err)
		}
	}()

	<-done
	logger.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server shutdown error: %v", err)
	}
	logger.Println("Server stopped")
}

func loggingMiddleware(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := uuid.New().String()
		r.Header.Set("X-Request-ID", requestID)
		logger.Printf("[%s] %s %s started", requestID[:8], r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		logger.Printf("[%s] %s %s completed in %v", requestID[:8], r.Method, r.URL.Path, time.Since(start))
	})
}

// Config holds all gateway configuration
type Config struct {
	ListenPort       string
	KeycloakURL      string
	KeycloakRealm    string
	SPIRESocketPath  string
	OPAEndpoint      string
	VaultAddr        string
	VaultToken       string
	TrustDomain      string
}

func LoadConfig() *Config {
	return &Config{
		ListenPort:      getEnv("LISTEN_PORT", "8080"),
		KeycloakURL:     getEnv("KEYCLOAK_URL", "http://keycloak:8080"),
		KeycloakRealm:   getEnv("KEYCLOAK_REALM", "demo"),
		SPIRESocketPath: getEnv("SPIRE_AGENT_SOCKET", "/tmp/spire-agent/public/api.sock"),
		OPAEndpoint:     getEnv("OPA_ENDPOINT", "http://opa:8181"),
		VaultAddr:       getEnv("VAULT_ADDR", "http://vault:8200"),
		VaultToken:      getEnv("VAULT_TOKEN", ""),
		TrustDomain:     getEnv("TRUST_DOMAIN", "demo.local"),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// Gateway is the core identity gateway service
type Gateway struct {
	config        *Config
	logger        *log.Logger
	tokenVerifier *TokenVerifier
	opaClient     *OPAClient
	vaultBroker   *VaultBroker
	auditLog      []AuditEntry
}

// DelegationRequest is the request body for /v1/delegate
type DelegationRequest struct {
	HumanToken     string `json:"human_token"`
	AgentSPIFFEID  string `json:"agent_spiffe_id"`
	AgentJWTSVID   string `json:"agent_jwt_svid,omitempty"`
	RequestedScope string `json:"requested_scope"`
}

// DelegationResponse is the response body for /v1/delegate
type DelegationResponse struct {
	SessionID    string            `json:"session_id"`
	VaultToken   string            `json:"vault_token,omitempty"`
	DBCredential *DBCredential     `json:"db_credential,omitempty"`
	ExpiresAt    string            `json:"expires_at"`
	Metadata     map[string]string `json:"metadata"`
}

// DBCredential holds dynamic database credentials from Vault
type DBCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	TTL      int    `json:"ttl_seconds"`
	LeaseID  string `json:"lease_id"`
}

// AuditEntry captures the full delegation decision for audit purposes
type AuditEntry struct {
	Timestamp      string            `json:"timestamp"`
	SessionID      string            `json:"session_id"`
	RequestID      string            `json:"request_id"`
	Human          string            `json:"human"`
	AgentSPIFFEID  string            `json:"agent_spiffe_id"`
	RequestedScope string            `json:"requested_scope"`
	OPADecision    string            `json:"opa_decision"`
	VaultPolicy    string            `json:"vault_policy,omitempty"`
	DBUsername     string            `json:"db_username,omitempty"`
	LeaseID        string            `json:"lease_id,omitempty"`
	Result         string            `json:"result"`
	Error          string            `json:"error,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

func NewGateway(cfg *Config, logger *log.Logger) (*Gateway, error) {
	tokenVerifier, err := NewTokenVerifier(cfg)
	if err != nil {
		return nil, fmt.Errorf("token verifier init: %w", err)
	}

	opaClient := NewOPAClient(cfg.OPAEndpoint)
	vaultBroker, err := NewVaultBroker(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault broker init: %w", err)
	}

	return &Gateway{
		config:        cfg,
		logger:        logger,
		tokenVerifier: tokenVerifier,
		opaClient:     opaClient,
		vaultBroker:   vaultBroker,
		auditLog:      make([]AuditEntry, 0),
	}, nil
}

// HandleDelegate processes delegation requests
func (gw *Gateway) HandleDelegate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := r.Header.Get("X-Request-ID")
	sessionID := fmt.Sprintf("sess-%s", uuid.New().String()[:12])

	var req DelegationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		gw.writeError(w, http.StatusBadRequest, "Invalid request body", requestID, sessionID)
		return
	}

	// Step 1: Validate the human's OIDC token
	gw.logger.Printf("[%s] Validating human OIDC token...", sessionID)
	humanClaims, err := gw.tokenVerifier.ValidateHumanToken(r.Context(), req.HumanToken)
	if err != nil {
		gw.recordAudit(sessionID, requestID, "unknown", req.AgentSPIFFEID, req.RequestedScope, "n/a", "token_validation_failed", err.Error())
		gw.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Human token validation failed: %v", err), requestID, sessionID)
		return
	}
	gw.logger.Printf("[%s] Human token valid: sub=%s", sessionID, humanClaims.Subject)

	// Step 2: Validate the agent's SPIFFE identity
	gw.logger.Printf("[%s] Validating agent SPIFFE ID: %s", sessionID, req.AgentSPIFFEID)
	if !strings.HasPrefix(req.AgentSPIFFEID, fmt.Sprintf("spiffe://%s/", gw.config.TrustDomain)) {
		gw.recordAudit(sessionID, requestID, humanClaims.Subject, req.AgentSPIFFEID, req.RequestedScope, "n/a", "invalid_spiffe_id", "SPIFFE ID not in trust domain")
		gw.writeError(w, http.StatusForbidden, "Agent SPIFFE ID not in trusted domain", requestID, sessionID)
		return
	}

	// Step 3: Evaluate OPA policy
	gw.logger.Printf("[%s] Evaluating OPA delegation policy...", sessionID)
	opaInput := map[string]interface{}{
		"human_token": map[string]interface{}{
			"sub":      humanClaims.Subject,
			"groups":   humanClaims.Groups,
			"may_act":  humanClaims.MayAct,
			"exp":      humanClaims.ExpiresAt,
			"iss":      humanClaims.Issuer,
		},
		"agent_spiffe_id": req.AgentSPIFFEID,
		"requested_scope":  req.RequestedScope,
		"current_time":     time.Now().Unix(),
	}

	allowed, opaReason, err := gw.opaClient.Evaluate(r.Context(), opaInput)
	if err != nil {
		gw.recordAudit(sessionID, requestID, humanClaims.Subject, req.AgentSPIFFEID, req.RequestedScope, "error", "opa_error", err.Error())
		gw.writeError(w, http.StatusInternalServerError, fmt.Sprintf("OPA evaluation failed: %v", err), requestID, sessionID)
		return
	}

	if !allowed {
		gw.recordAudit(sessionID, requestID, humanClaims.Subject, req.AgentSPIFFEID, req.RequestedScope, "deny", "delegation_denied", opaReason)
		gw.writeError(w, http.StatusForbidden, fmt.Sprintf("Delegation denied by policy: %s", opaReason), requestID, sessionID)
		return
	}
	gw.logger.Printf("[%s] OPA policy: ALLOW (reason: %s)", sessionID, opaReason)

	// Step 4: Broker Vault access with delegation metadata
	gw.logger.Printf("[%s] Brokering Vault access for scope: %s", sessionID, req.RequestedScope)
	delegationMeta := map[string]string{
		"delegating_human":  humanClaims.Subject,
		"delegation_scope":  req.RequestedScope,
		"delegation_time":   time.Now().UTC().Format(time.RFC3339),
		"session_id":        sessionID,
		"agent_spiffe_id":   req.AgentSPIFFEID,
		"human_groups":      strings.Join(humanClaims.Groups, ","),
	}

	// Step 5: Get dynamic database credentials from Vault
	dbCreds, leaseID, err := gw.vaultBroker.GetDatabaseCredentials(r.Context(), req.RequestedScope, delegationMeta)
	if err != nil {
		gw.recordAudit(sessionID, requestID, humanClaims.Subject, req.AgentSPIFFEID, req.RequestedScope, "allow", "vault_error", err.Error())
		gw.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Vault credential generation failed: %v", err), requestID, sessionID)
		return
	}

	gw.logger.Printf("[%s] Vault issued credentials: user=%s, ttl=300s, lease=%s", sessionID, dbCreds.Username, leaseID)

	// Record successful audit entry
	gw.recordAudit(sessionID, requestID, humanClaims.Subject, req.AgentSPIFFEID, req.RequestedScope, "allow", "success", "")

	// Build response
	resp := DelegationResponse{
		SessionID: sessionID,
		DBCredential: dbCreds,
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
		Metadata:  delegationMeta,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Session-ID", sessionID)
	w.Header().Set("X-Request-ID", requestID)
	json.NewEncoder(w).Encode(resp)
}

// HandleHealth returns gateway health status
func (gw *Gateway) HandleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"components": map[string]string{
			"opa":   "configured",
			"vault": "configured",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// HandleAuditLog returns recent audit entries
func (gw *Gateway) HandleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gw.auditLog)
}

func (gw *Gateway) recordAudit(sessionID, requestID, human, agentSPIFFEID, scope, opaDecision, result, errMsg string) {
	entry := AuditEntry{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		SessionID:      sessionID,
		RequestID:      requestID,
		Human:          human,
		AgentSPIFFEID:  agentSPIFFEID,
		RequestedScope: scope,
		OPADecision:    opaDecision,
		Result:         result,
	}
	if errMsg != "" {
		entry.Error = errMsg
	}
	gw.auditLog = append(gw.auditLog, entry)
	gw.logger.Printf("[AUDIT] session=%s human=%s agent=%s scope=%s decision=%s result=%s",
		sessionID, human, agentSPIFFEID, scope, opaDecision, result)
}

func (gw *Gateway) writeError(w http.ResponseWriter, status int, msg, requestID, sessionID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":      msg,
		"request_id": requestID,
		"session_id": sessionID,
	})
}
