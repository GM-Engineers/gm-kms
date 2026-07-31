package kms

import (
	"context"
	"encoding/base64"
	"net/http"
)

// DH algorithm constants.
const (
	DHAlgorithmECP256  = "ECDH-P256"
	DHAlgorithmECP384  = "ECDH-P384"
	DHAlgorithmX25519  = "X25519"
	DHAlgorithmSM2KEX  = "SM2-KEX"
)

// DhDeriveRequest is the request for DH key derivation.
type DhDeriveRequest struct {
	KeyID         string
	Algorithm     string
	PeerPublicKey []byte
}

// DhDeriveResponse is the response from DH key derivation.
type DhDeriveResponse struct {
	SharedSecret []byte `json:"shared_secret"` // base64
	KDF          string `json:"kdf"`
}

// DhDerive performs Diffie-Hellman key derivation. Requires operator role or higher.
func (c *Client) DhDerive(ctx context.Context, req *DhDeriveRequest) (*DhDeriveResponse, error) {
	body := map[string]string{
		"key_id":          req.KeyID,
		"algorithm":       req.Algorithm,
		"peer_public_key": base64.StdEncoding.EncodeToString(req.PeerPublicKey),
	}

	var result struct {
		SharedSecret string `json:"shared_secret"`
		KDF          string `json:"kdf"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/dh/derive", body, &result); err != nil {
		return nil, err
	}

	ss, _ := base64.StdEncoding.DecodeString(result.SharedSecret)
	return &DhDeriveResponse{
		SharedSecret: ss,
		KDF:          result.KDF,
	}, nil
}
