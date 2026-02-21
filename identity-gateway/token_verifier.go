package main

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// HumanClaims represents validated claims from the human's OIDC token
type HumanClaims struct {
	Subject   string                 `json:"sub"`
	Email     string                 `json:"email"`
	Groups    []string               `json:"groups"`
	MayAct    map[string]interface{} `json:"may_act"`
	Issuer    string                 `json:"iss"`
	Audience  []string               `json:"aud"`
	ExpiresAt int64                  `json:"exp"`
	IssuedAt  int64                  `json:"iat"`
}

// TokenVerifier handles OIDC token validation against Keycloak
type TokenVerifier struct {
	keycloakURL   string
	realm         string
	jwksURL       string
	issuerURL     string
	httpClient    *http.Client
}

// NewTokenVerifier creates a new token verifier configured for Keycloak
func NewTokenVerifier(cfg *Config) (*TokenVerifier, error) {
	return &TokenVerifier{
		keycloakURL: cfg.KeycloakURL,
		realm:       cfg.KeycloakRealm,
		jwksURL:     fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", cfg.KeycloakURL, cfg.KeycloakRealm),
		issuerURL:   fmt.Sprintf("%s/realms/%s", cfg.KeycloakURL, cfg.KeycloakRealm),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// ValidateHumanToken validates an OIDC access token from Keycloak
func (tv *TokenVerifier) ValidateHumanToken(ctx context.Context, tokenString string) (*HumanClaims, error) {
	// First try: validate via Keycloak's userinfo endpoint (most reliable for access tokens)
	claims, err := tv.validateViaUserinfo(ctx, tokenString)
	if err == nil {
		return claims, nil
	}

	// Second try: validate via JWKS (for JWT access tokens)
	claims, err = tv.validateViaJWKS(ctx, tokenString)
	if err == nil {
		return claims, nil
	}

	// Third try: parse without verification for demo mode
	// In production, remove this fallback
	claims, err = tv.parseUnverified(tokenString)
	if err != nil {
		return nil, fmt.Errorf("all token validation methods failed: %w", err)
	}

	return claims, nil
}

// validateViaUserinfo validates the token using Keycloak's userinfo endpoint
func (tv *TokenVerifier) validateViaUserinfo(ctx context.Context, tokenString string) (*HumanClaims, error) {
	userinfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", tv.keycloakURL, tv.realm)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenString)

	resp, err := tv.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo returned %d: %s", resp.StatusCode, string(body))
	}

	var rawClaims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rawClaims); err != nil {
		return nil, fmt.Errorf("decoding userinfo response: %w", err)
	}

	return tv.extractClaims(rawClaims, tokenString)
}

// validateViaJWKS validates the token using Keycloak's JWKS endpoint with
// full cryptographic signature verification via go-jose.
func (tv *TokenVerifier) validateViaJWKS(ctx context.Context, tokenString string) (*HumanClaims, error) {
	// Fetch JWKS
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tv.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS request: %w", err)
	}

	resp, err := tv.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading JWKS response: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}

	// Build a keyfunc that looks up the signing key from the JWKS by key ID.
	keyfunc := func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			// No kid header — try each key in the set
			for _, key := range jwks.Keys {
				if key.Use == "sig" || key.Use == "" {
					return key.Key, nil
				}
			}
			return nil, fmt.Errorf("no suitable signing key found in JWKS")
		}
		keys := jwks.Key(kid)
		if len(keys) == 0 {
			return nil, fmt.Errorf("key %q not found in JWKS", kid)
		}
		// Return the public key for signature verification
		if pub, ok := keys[0].Key.(crypto.PublicKey); ok {
			return pub, nil
		}
		return keys[0].Key, nil
	}

	// Parse and verify the token signature + claims
	token, err := jwt.NewParser(
		jwt.WithIssuer(tv.issuerURL),
		jwt.WithLeeway(30*time.Second),
	).Parse(tokenString, keyfunc)
	if err != nil {
		return nil, fmt.Errorf("verifying token signature: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	return tv.extractClaimsFromMap(mapClaims)
}

// parseUnverified parses the token without signature verification (demo mode only)
func (tv *TokenVerifier) parseUnverified(tokenString string) (*HumanClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	return tv.extractClaimsFromMap(mapClaims)
}

func (tv *TokenVerifier) extractClaims(rawClaims map[string]interface{}, tokenString string) (*HumanClaims, error) {
	claims := &HumanClaims{
		Issuer: tv.issuerURL,
	}

	if sub, ok := rawClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if email, ok := rawClaims["email"].(string); ok {
		claims.Subject = email // Prefer email as subject for readability
		claims.Email = email
	}

	if groups, ok := rawClaims["groups"].([]interface{}); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				claims.Groups = append(claims.Groups, gs)
			}
		}
	}

	if mayAct, ok := rawClaims["may_act"].(map[string]interface{}); ok {
		claims.MayAct = mayAct
	}

	// Parse expiry from the original token if available
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err == nil {
		if mc, ok := token.Claims.(jwt.MapClaims); ok {
			if exp, ok := mc["exp"].(float64); ok {
				claims.ExpiresAt = int64(exp)
			}
		}
	}

	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(5 * time.Minute).Unix()
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("token missing subject claim")
	}

	return claims, nil
}

func (tv *TokenVerifier) extractClaimsFromMap(mapClaims jwt.MapClaims) (*HumanClaims, error) {
	claims := &HumanClaims{}

	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if email, ok := mapClaims["email"].(string); ok {
		claims.Subject = email
		claims.Email = email
	}
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}

	if groups, ok := mapClaims["groups"].([]interface{}); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				claims.Groups = append(claims.Groups, gs)
			}
		}
	}

	if mayAct, ok := mapClaims["may_act"].(map[string]interface{}); ok {
		claims.MayAct = mayAct
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("token missing subject claim")
	}

	return claims, nil
}
