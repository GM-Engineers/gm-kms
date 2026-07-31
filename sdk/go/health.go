package kms

import (
	"context"
	"net/http"
)

// HealthResponse is the response from the health check endpoint.
type HealthResponse struct {
	Status     string                    `json:"status"`
	Version    string                    `json:"version"`
	Components map[string]string         `json:"components"`
}

// Health checks the overall KMS health. No authentication required.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var result HealthResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/health", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Healthz calls the Kubernetes liveness probe. No authentication required.
func (c *Client) Healthz(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodGet, "/healthz", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !isSuccess(resp.StatusCode) {
		return c.parseError(resp)
	}
	return nil
}

// Readyz calls the Kubernetes readiness probe. No authentication required.
func (c *Client) Readyz(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodGet, "/readyz", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !isSuccess(resp.StatusCode) {
		return c.parseError(resp)
	}
	return nil
}
