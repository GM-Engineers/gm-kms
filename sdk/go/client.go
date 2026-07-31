package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is the KMS API client.
type Client struct {
	serverURL  string
	apiKey     string
	httpClient *http.Client
	tenantID   string
}

// ClientOption configures the KMS client.
type ClientOption func(*Client)

// WithAPIKey sets the API key for authentication.
func WithAPIKey(apiKey string) ClientOption {
	return func(c *Client) {
		c.apiKey = apiKey
	}
}

// WithTenantID sets the default tenant ID used for all operations.
func WithTenantID(tenantID string) ClientOption {
	return func(c *Client) {
		c.tenantID = tenantID
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// New creates a new KMS client.
func New(serverURL string, opts ...ClientOption) (*Client, error) {
	if _, err := url.Parse(serverURL); err != nil {
		return nil, fmt.Errorf("kms: invalid server URL: %w", err)
	}

	c := &Client{
		serverURL:  serverURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		tenantID:   "default",
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// doRequest performs an HTTP request and returns the response.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("kms: failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.serverURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("kms: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	return c.httpClient.Do(req)
}

// doJSON performs a request and decodes the JSON response into dst.
func (c *Client) doJSON(ctx context.Context, method, path string, body, dst interface{}) error {
	resp, err := c.doRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !isSuccess(resp.StatusCode) {
		return c.parseError(resp)
	}

	if dst != nil {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return fmt.Errorf("kms: failed to decode response: %w", err)
		}
	}
	return nil
}

// isSuccess returns true for 2xx status codes.
func isSuccess(code int) bool {
	return code >= 200 && code < 300
}

// parseError parses an error response from the KMS API.
func (c *Client) parseError(resp *http.Response) error {
	var errResp struct {
		Error       string `json:"error"`
		Message     string `json:"message"`
		RetryAfter  int    `json:"retry_after_secs"`
	}

	// Try to parse the body; if it fails, use status code
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return &APIError{StatusCode: resp.StatusCode, Message: resp.Status}
	}

	if json.Unmarshal(body, &errResp) == nil {
		msg := errResp.Error
		if msg == "" {
			msg = errResp.Message
		}
		if msg == "" {
			msg = resp.Status
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    msg,
			RetryAfter: errResp.RetryAfter,
		}
	}

	return &APIError{StatusCode: resp.StatusCode, Message: resp.Status}
}

// effectiveTenant returns tenant or client default.
func (c *Client) effectiveTenant(tenant string) string {
	if tenant != "" {
		return tenant
	}
	return c.tenantID
}
