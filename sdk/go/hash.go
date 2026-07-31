package kms

import (
	"context"
	"encoding/base64"
	"net/http"
)

// HashRequest is the request to compute a hash.
type HashRequest struct {
	Data      []byte
	Algorithm string // "sm3" or "sha256"
}

// HashResponse is the response from a hash operation.
type HashResponse struct {
	Hash      string `json:"hash"`      // hex-encoded
	Algorithm string `json:"algorithm"`
}

// Hash computes a cryptographic hash. Requires operator role or higher.
func (c *Client) Hash(ctx context.Context, req *HashRequest) (*HashResponse, error) {
	body := map[string]string{
		"data":      base64.StdEncoding.EncodeToString(req.Data),
		"algorithm": req.Algorithm,
	}

	var result HashResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/hash", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
