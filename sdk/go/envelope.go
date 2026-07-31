package kms

import (
	"context"
	"encoding/base64"
	"net/http"
)

// EnvelopeEncryptRequest is the request for envelope encryption.
type EnvelopeEncryptRequest struct {
	Plaintext []byte
	KEKID     string
	DEKLength int // defaults to 32 if 0
}

// EnvelopeEncryptResponse is the response from envelope encryption.
type EnvelopeEncryptResponse struct {
	WrappedDEK []byte
	DEKNonce   []byte
	Ciphertext []byte
	DataNonce  []byte
	Tag        []byte
	KEKVersion uint32
}

// EnvelopeEncrypt encrypts data using envelope encryption. Requires operator role or higher.
func (c *Client) EnvelopeEncrypt(ctx context.Context, req *EnvelopeEncryptRequest) (*EnvelopeEncryptResponse, error) {
	body := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(req.Plaintext),
		"kek_id":    req.KEKID,
	}
	if req.DEKLength > 0 {
		body["dek_length"] = req.DEKLength
	}

	var result struct {
		WrappedDEK string `json:"wrapped_dek"`
		DEKNonce   string `json:"dek_nonce"`
		Ciphertext string `json:"ciphertext"`
		DataNonce  string `json:"data_nonce"`
		Tag        string `json:"tag"`
		KEKVersion uint32 `json:"kek_version"`
	}

	if err := c.doJSON(ctx, http.MethodPost, "/v1/envelope/encrypt", body, &result); err != nil {
		return nil, err
	}

	wd, _ := base64.StdEncoding.DecodeString(result.WrappedDEK)
	dn, _ := base64.StdEncoding.DecodeString(result.DEKNonce)
	ct, _ := base64.StdEncoding.DecodeString(result.Ciphertext)
	dan, _ := base64.StdEncoding.DecodeString(result.DataNonce)
	tag, _ := base64.StdEncoding.DecodeString(result.Tag)

	return &EnvelopeEncryptResponse{
		WrappedDEK: wd,
		DEKNonce:   dn,
		Ciphertext: ct,
		DataNonce:  dan,
		Tag:        tag,
		KEKVersion: result.KEKVersion,
	}, nil
}

// EnvelopeDecryptRequest is the request for envelope decryption.
type EnvelopeDecryptRequest struct {
	WrappedDEK []byte
	DEKNonce   []byte
	Ciphertext []byte
	DataNonce  []byte
	Tag        []byte
	KEKID      string
	KEKVersion uint32
}

// EnvelopeDecrypt decrypts data using envelope decryption. Requires operator role or higher.
func (c *Client) EnvelopeDecrypt(ctx context.Context, req *EnvelopeDecryptRequest) ([]byte, error) {
	body := map[string]interface{}{
		"wrapped_dek": base64.StdEncoding.EncodeToString(req.WrappedDEK),
		"dek_nonce":   base64.StdEncoding.EncodeToString(req.DEKNonce),
		"ciphertext":  base64.StdEncoding.EncodeToString(req.Ciphertext),
		"data_nonce":  base64.StdEncoding.EncodeToString(req.DataNonce),
		"tag":         base64.StdEncoding.EncodeToString(req.Tag),
		"kek_id":      req.KEKID,
		"kek_version": req.KEKVersion,
	}

	var result struct {
		Plaintext string `json:"plaintext"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/envelope/decrypt", body, &result); err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(result.Plaintext)
}
