package kms

import (
	"context"
	"encoding/base64"
	"net/http"
)

// Sm9SignRequest is the request for SM9 identity-based signing.
type Sm9SignRequest struct {
	Identity string
	Data     []byte
}

// Sm9SignResponse is the response from SM9 signing.
type Sm9SignResponse struct {
	W string `json:"w"` // base64 G1 point
	H string `json:"h"` // hex Fr scalar
	S string `json:"s"` // base64 G1 point
}

// Sm9Sign performs SM9 identity-based signing. Requires operator role or higher.
func (c *Client) Sm9Sign(ctx context.Context, req *Sm9SignRequest) (*Sm9SignResponse, error) {
	body := map[string]string{
		"identity": req.Identity,
		"data":     base64.StdEncoding.EncodeToString(req.Data),
	}

	var result Sm9SignResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sm9/sign", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Sm9VerifyRequest is the request for SM9 signature verification.
type Sm9VerifyRequest struct {
	Identity  string
	Data      []byte
	W         string // base64 G1 point
	H         string // hex Fr scalar
	S         string // base64 G1 point
}

// Sm9VerifyResponse is the response from SM9 verification.
type Sm9VerifyResponse struct {
	Valid bool `json:"valid"`
}

// Sm9Verify verifies an SM9 identity-based signature. Requires operator role or higher.
func (c *Client) Sm9Verify(ctx context.Context, req *Sm9VerifyRequest) (*Sm9VerifyResponse, error) {
	body := map[string]string{
		"identity": req.Identity,
		"data":     base64.StdEncoding.EncodeToString(req.Data),
		"w":        req.W,
		"h":        req.H,
		"s":        req.S,
	}

	var result Sm9VerifyResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sm9/verify", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Sm9EncryptRequest is the request for SM9 identity-based encryption.
type Sm9EncryptRequest struct {
	Identity  string
	Plaintext []byte
}

// Sm9EncryptResponse is the response from SM9 encryption.
type Sm9EncryptResponse struct {
	C1 string `json:"c1"` // base64 G1 point
	C2 string `json:"c2"` // base64 symmetric ciphertext
	C3 string `json:"c3"` // hex hash
}

// Sm9Encrypt performs SM9 identity-based encryption. Requires operator role or higher.
func (c *Client) Sm9Encrypt(ctx context.Context, req *Sm9EncryptRequest) (*Sm9EncryptResponse, error) {
	body := map[string]string{
		"identity":  req.Identity,
		"plaintext": base64.StdEncoding.EncodeToString(req.Plaintext),
	}

	var result Sm9EncryptResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sm9/encrypt", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Sm9DecryptRequest is the request for SM9 identity-based decryption.
type Sm9DecryptRequest struct {
	Identity string
	C1       string // base64 G1 point
	C2       string // base64 symmetric ciphertext
	C3       string // hex hash
}

// Sm9DecryptResponse is the response from SM9 decryption.
type Sm9DecryptResponse struct {
	Plaintext []byte
}

// Sm9Decrypt performs SM9 identity-based decryption. Requires operator role or higher.
func (c *Client) Sm9Decrypt(ctx context.Context, req *Sm9DecryptRequest) ([]byte, error) {
	body := map[string]string{
		"identity": req.Identity,
		"c1":       req.C1,
		"c2":       req.C2,
		"c3":       req.C3,
	}

	var result struct {
		Plaintext string `json:"plaintext"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sm9/decrypt", body, &result); err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(result.Plaintext)
}
