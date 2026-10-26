package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CreatePolicyRequest is the request to create a PBAC policy.
type CreatePolicyRequest struct {
	Name      string          `json:"name"`
	Effect    string          `json:"effect"` // "allow" or "deny"
	Condition json.RawMessage `json:"condition"`
	Resources []string        `json:"resources"`
	Subjects  []string        `json:"subjects"`
	// Tenant restricts the policy to a single tenant. Leaving it unset means
	// the policy is not tenant-scoped and applies to every tenant. A glob
	// pattern is accepted, so "tenant-*" covers a family of tenants.
	Tenant  *string `json:"tenant,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

// Policy represents a PBAC policy.
type Policy struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Effect    string          `json:"effect"`
	Condition json.RawMessage `json:"condition"`
	Resources []string        `json:"resources"`
	Subjects  []string        `json:"subjects"`
	// Tenant is the tenant the policy is restricted to, nil when the policy
	// applies to every tenant.
	Tenant  *string `json:"tenant"`
	Enabled bool    `json:"enabled"`
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

// DeletePolicy removes a PBAC policy. Returns nil on success (204 No Content).
// Requires security-officer role.
//
// Without this the operator could install a policy but never take it back,
// and a persisted policy that turns out to be wrong would outlive every
// restart.
func (c *Client) DeletePolicy(ctx context.Context, policyID string) error {
	resp, err := c.doRequest(ctx, http.MethodDelete, fmt.Sprintf("/v1/policies/%s", policyID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !isSuccess(resp.StatusCode) {
		return c.parseError(resp)
	}
	return nil
}
