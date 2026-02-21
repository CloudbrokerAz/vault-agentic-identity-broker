package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OPAClient communicates with OPA for policy evaluation
type OPAClient struct {
	endpoint   string
	httpClient *http.Client
}

// OPARequest is the request body sent to OPA
type OPARequest struct {
	Input interface{} `json:"input"`
}

// OPAResponse is the response from OPA
type OPAResponse struct {
	Result OPAResult `json:"result"`
}

// OPAResult contains the policy evaluation result
type OPAResult struct {
	Allow    bool       `json:"allow"`
	Decision *OPADecision `json:"decision,omitempty"`
}

// OPADecision contains detailed decision information
type OPADecision struct {
	Allowed bool   `json:"allowed"`
	Human   string `json:"human"`
	Agent   string `json:"agent"`
	Scope   string `json:"scope"`
	Reason  string `json:"reason"`
}

// NewOPAClient creates a new OPA client
func NewOPAClient(endpoint string) *OPAClient {
	return &OPAClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Evaluate sends a policy evaluation request to OPA
func (c *OPAClient) Evaluate(ctx context.Context, input map[string]interface{}) (bool, string, error) {
	reqBody := OPARequest{Input: input}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return false, "", fmt.Errorf("marshaling OPA request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/data/delegation/allow", c.endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, "", fmt.Errorf("creating OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("reading OPA response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("OPA returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the simple allow response
	var allowResp struct {
		Result bool `json:"result"`
	}
	if err := json.Unmarshal(respBody, &allowResp); err != nil {
		return false, "", fmt.Errorf("decoding OPA response: %w", err)
	}

	// Also try to get the detailed decision
	reason := "policy_evaluated"
	decisionURL := fmt.Sprintf("%s/v1/data/delegation/decision", c.endpoint)
	decisionReq, err := http.NewRequestWithContext(ctx, http.MethodPost, decisionURL, bytes.NewReader(bodyBytes))
	if err == nil {
		decisionReq.Header.Set("Content-Type", "application/json")
		decisionResp, err := c.httpClient.Do(decisionReq)
		if err == nil {
			defer decisionResp.Body.Close()
			var decisionResult struct {
				Result struct {
					Reason string `json:"reason"`
				} `json:"result"`
			}
			if err := json.NewDecoder(decisionResp.Body).Decode(&decisionResult); err == nil {
				if decisionResult.Result.Reason != "" {
					reason = decisionResult.Result.Reason
				}
			}
		}
	}

	return allowResp.Result, reason, nil
}
