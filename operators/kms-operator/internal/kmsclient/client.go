// Package kmsclient provides a client for GM-KMS REST API
package kmsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client is a GM-KMS API client
type Client struct {
	serverURL string
	apiKey    string
	httpClient *http.Client
}

// Config holds KMS client configuration
type Config struct {
	ServerURL string
	APIKey    string
	Timeout   time.Duration
}

// New creates a new KMS client
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		serverURL: cfg.ServerURL,
		apiKey:    cfg.APIKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// KeyResponse represents a KMS key response
type KeyResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Spec      string            `json:"spec"`
	TenantID  string            `json:"tenant_id"`
	Status    string            `json:"status"`
	Version   uint32            `json:"version"`
	CreatedAt string            `json:"created_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// CreateKeyRequest represents a key creation request
type CreateKeyRequest struct {
	Name     string `json:"name"`
	Spec     string `json:"spec"`
	TenantID string `json:"tenant_id"`
}

// EncryptRequest represents an encryption request
type EncryptRequest struct {
	Plaintext string `json:"plaintext"`
	AAD      string `json:"aad,omitempty"`
}

// EncryptResponse represents an encryption response
type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag"`
}

// DecryptRequest represents a decryption request
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag"`
}

// CreateKey creates a new key in KMS
func (c *Client) CreateKey(ctx context.Context, req *CreateKeyRequest) (*KeyResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/keys", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var keyResp KeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &keyResp, nil
}

// GetKey retrieves a key by ID
func (c *Client) GetKey(ctx context.Context, keyID string) (*KeyResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/keys/"+keyID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var keyResp KeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &keyResp, nil
}

// DeleteKey deletes a key by ID
func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", c.serverURL+"/v1/keys/"+keyID, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// RotateKey rotates a key by ID
func (c *Client) RotateKey(ctx context.Context, keyID string) (*KeyResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/keys/"+keyID+"/rotate", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var keyResp KeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &keyResp, nil
}

// Encrypt encrypts data using a key
func (c *Client) Encrypt(ctx context.Context, keyID string, plaintext string) (*EncryptResponse, error) {
	body, err := json.Marshal(&EncryptRequest{Plaintext: plaintext})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/keys/"+keyID+"/encrypt", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var encryptResp EncryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&encryptResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &encryptResp, nil
}

// Decrypt decrypts data using a key
func (c *Client) Decrypt(ctx context.Context, keyID string, ciphertext, nonce, tag string) (string, error) {
	body, err := json.Marshal(&DecryptRequest{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/keys/"+keyID+"/decrypt", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Plaintext, nil
}

// Health checks KMS server health
func (c *Client) Health(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/v1/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
}
