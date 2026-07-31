package kms

import (
	"context"
	"encoding/json"
	"net/http"
)

// CreatePolicyRequest is the request to create a PBAC policy.
type CreatePolicyRequest struct {
	Name      string            `json:"name"`
	Effect    string            `json:"effect"` // "allow" or "deny"
	Condition json.RawMessage   `json:"condition"`
	Resources []string          `json:"resources"`
	Subjects  []string          `json:"subjects"`
	Enabled   *bool             `json:"enabled,omitempty"`
}

// Policy represents a PBAC policy.
type Policy struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Effect    string          `json:"effect"`
	Condition json.RawMessage `json:"condition"`
	Resources []string        `json:"resources"`
	Subjects  []string        `json:"subjects"`
	Enabled   bool            `json:"enabled"`
}

// CreatePolicy creates a new PBAC policy. Requires security-officer role.
func (c *Client) CreatePolicy(ctx context.Context, req *CreatePolicyRequest) (*Policy, error) {
	var result Policy
	if err := c.doJSON(ctx, http.MethodPost, "/v1/policies", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListPolicies lists all PBAC policies. Requires security-officer role.
func (c *Client) ListPolicies(ctx context.Context) ([]*Policy, error) {
	var results []*Policy
	if err := c.doJSON(ctx, http.MethodGet, "/v1/policies", nil, &results); err != nil {
		return nil, err
	}
	return results, nil
}

// GetPolicy returns a single PBAC policy. Requires security-officer role.
func (c *Client) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	var result Policy
	if err := c.doJSON(ctx, http.MethodGet, "/v1/policies/"+policyID, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
