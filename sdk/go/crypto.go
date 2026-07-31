package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
)

// EncryptRequest is the request to encrypt data.
type EncryptRequest struct {
	Plaintext []byte
	AAD       []byte
}

// EncryptResponse is the response from an encryption operation.
type EncryptResponse struct {
	Ciphertext []byte
	Nonce      []byte
	Tag        []byte
	KeyVersion uint32
}

// Encrypt encrypts plaintext using the specified key. Requires operator role or higher.
func (c *Client) Encrypt(ctx context.Context, keyID, tenantID string, req *EncryptRequest) (*EncryptResponse, error) {
	body := map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(req.Plaintext),
	}
	if len(req.AAD) > 0 {
		body["aad"] = base64.StdEncoding.EncodeToString(req.AAD)
	}

	var result struct {
		Ciphertext string `json:"ciphertext"`
		Nonce      string `json:"nonce"`
		Tag        string `json:"tag"`
		Version    uint32 `json:"version"`
	}

	path := fmt.Sprintf("/v1/keys/%s/encrypt?tenant_id=%s", keyID, c.effectiveTenant(tenantID))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &result); err != nil {
		return nil, err
	}

	ct, _ := base64.StdEncoding.DecodeString(result.Ciphertext)
	nonce, _ := base64.StdEncoding.DecodeString(result.Nonce)
	tag, _ := base64.StdEncoding.DecodeString(result.Tag)

	return &EncryptResponse{
		Ciphertext: ct,
		Nonce:      nonce,
		Tag:        tag,
		KeyVersion: result.Version,
	}, nil
}

// DecryptRequest is the request to decrypt data.
type DecryptRequest struct {
	Ciphertext []byte
	Nonce      []byte
	Tag        []byte
	AAD        []byte
}

// Decrypt decrypts ciphertext using the specified key. Requires operator role or higher.
func (c *Client) Decrypt(ctx context.Context, keyID, tenantID string, req *DecryptRequest) ([]byte, error) {
	body := map[string]string{
		"ciphertext": base64.StdEncoding.EncodeToString(req.Ciphertext),
		"nonce":      base64.StdEncoding.EncodeToString(req.Nonce),
		"tag":        base64.StdEncoding.EncodeToString(req.Tag),
	}
	if len(req.AAD) > 0 {
		body["aad"] = base64.StdEncoding.EncodeToString(req.AAD)
	}

	var result struct {
		Plaintext string `json:"plaintext"`
	}

	path := fmt.Sprintf("/v1/keys/%s/decrypt?tenant_id=%s", keyID, c.effectiveTenant(tenantID))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &result); err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(result.Plaintext)
}

// SignRequest is the request to sign data.
type SignRequest struct {
	Data []byte
}

// SignResponse is the response from a signing operation.
type SignResponse struct {
	Signature []byte
	Version   uint32
}

// Sign signs data using the specified key. Requires operator role or higher.
func (c *Client) Sign(ctx context.Context, keyID, tenantID string, req *SignRequest) (*SignResponse, error) {
	body := map[string]string{
		"data": base64.StdEncoding.EncodeToString(req.Data),
	}

	var result struct {
		Signature string `json:"signature"`
		Version   uint32 `json:"version"`
	}

	path := fmt.Sprintf("/v1/keys/%s/sign?tenant_id=%s", keyID, c.effectiveTenant(tenantID))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &result); err != nil {
		return nil, err
	}

	sig, _ := base64.StdEncoding.DecodeString(result.Signature)
	return &SignResponse{
		Signature: sig,
		Version:   result.Version,
	}, nil
}

// VerifyRequest is the request to verify a signature.
type VerifyRequest struct {
	Data      []byte
	Signature []byte
}

// VerifyResponse is the response from a verification operation.
type VerifyResponse struct {
	Valid bool `json:"valid"`
}

// Verify checks a signature using the specified key. Requires operator role or higher.
func (c *Client) Verify(ctx context.Context, keyID, tenantID string, req *VerifyRequest) (*VerifyResponse, error) {
	body := map[string]string{
		"data":      base64.StdEncoding.EncodeToString(req.Data),
		"signature": base64.StdEncoding.EncodeToString(req.Signature),
	}

	var result VerifyResponse

	path := fmt.Sprintf("/v1/keys/%s/verify?tenant_id=%s", keyID, c.effectiveTenant(tenantID))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
