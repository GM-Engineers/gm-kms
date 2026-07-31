package kms

import (
	"context"
	"fmt"
	"net/http"
)

// CreateKeyRequest is the request to create a new key.
type CreateKeyRequest struct {
	Name     string  `json:"name"`
	Spec     KeySpec `json:"spec"`
	TenantID string  `json:"tenant_id,omitempty"`
}

// CreateKey creates a new key. Requires key-admin role.
func (c *Client) CreateKey(ctx context.Context, req *CreateKeyRequest) (*KeyMeta, error) {
	body := map[string]interface{}{
		"name":      req.Name,
		"spec":      req.Spec,
		"tenant_id": c.effectiveTenant(req.TenantID),
	}

	var result keyResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/keys", body, &result); err != nil {
		return nil, err
	}
	return result.toKeyMeta(), nil
}

// GetKey returns metadata for a single key. Requires read-only role or higher.
func (c *Client) GetKey(ctx context.Context, keyID, tenantID string) (*KeyMeta, error) {
	path := fmt.Sprintf("/v1/keys/%s?tenant_id=%s", keyID, c.effectiveTenant(tenantID))
	var result keyResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return result.toKeyMeta(), nil
}

// ListKeys lists all keys for a tenant. Requires read-only role or higher.
func (c *Client) ListKeys(ctx context.Context, tenantID string) ([]*KeyMeta, error) {
	path := fmt.Sprintf("/v1/keys?tenant_id=%s", c.effectiveTenant(tenantID))
	var results []keyResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &results); err != nil {
		return nil, err
	}

	keys := make([]*KeyMeta, len(results))
	for i, r := range results {
		keys[i] = r.toKeyMeta()
	}
	return keys, nil
}

// RotateKey rotates a key to a new version. Requires key-admin role.
func (c *Client) RotateKey(ctx context.Context, keyID, tenantID string) (*KeyMeta, error) {
	path := fmt.Sprintf("/v1/keys/%s/rotate?tenant_id=%s", keyID, c.effectiveTenant(tenantID))
	var result keyResponse
	if err := c.doJSON(ctx, http.MethodPost, path, nil, &result); err != nil {
		return nil, err
	}
	return result.toKeyMeta(), nil
}

// DeleteKey deletes a key. Returns nil on success (204 No Content).
// Requires key-admin role.
func (c *Client) DeleteKey(ctx context.Context, keyID, tenantID string) error {
	path := fmt.Sprintf("/v1/keys/%s?tenant_id=%s", keyID, c.effectiveTenant(tenantID))
	resp, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !isSuccess(resp.StatusCode) {
		return c.parseError(resp)
	}
	return nil
}
