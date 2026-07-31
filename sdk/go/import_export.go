package kms

import (
	"context"
	"encoding/base64"
	"net/http"
)

// Import format constants.
const (
	ImportFormatPKCS8 = "pkcs8"
	ImportFormatJWK   = "jwk"
	ImportFormatRaw   = "raw"
)

// ImportKeyRequest is the request to import a key.
type ImportKeyRequest struct {
	Name                 string  `json:"name"`
	Spec                 KeySpec `json:"spec"`
	Format               string  `json:"format"`
	WrappedKey           []byte
	EncryptedTransportKey []byte
	SourceFingerprint    string  `json:"source_fingerprint"`
	TenantID             string  `json:"tenant_id,omitempty"`
}

// ImportKeyResponse is the response from key import.
type ImportKeyResponse struct {
	ID                string `json:"id"`
	Spec              string `json:"spec"`
	Imported          bool   `json:"imported"`
	SourceFingerprint string `json:"source_fingerprint"`
}

// ImportKey imports a key from an external source. Requires key-admin role.
func (c *Client) ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error) {
	format := req.Format
	if format == "" {
		format = ImportFormatPKCS8
	}

	body := map[string]interface{}{
		"name":                   req.Name,
		"spec":                   req.Spec,
		"format":                 format,
		"wrapped_key":            base64.StdEncoding.EncodeToString(req.WrappedKey),
		"encrypted_transport_key": base64.StdEncoding.EncodeToString(req.EncryptedTransportKey),
		"source_fingerprint":     req.SourceFingerprint,
		"tenant_id":              c.effectiveTenant(req.TenantID),
	}

	var result ImportKeyResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/keys/import", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportKeyRequest is the request to export a key.
type ExportKeyRequest struct {
	KeyID           string
	TargetSystem    string `json:"target_system"`
	TargetPublicKey []byte
	Purpose         string `json:"purpose"`
}

// ExportKeyResponse is the response from key export.
type ExportKeyResponse struct {
	WrappedKey            []byte
	EncryptedTransportKey []byte
	KeyFingerprint        string `json:"key_fingerprint"`
	ExportID              string `json:"export_id"`
	ExpiresAt             string `json:"expires_at"`
}

// ExportKey exports a key for migration or backup. Requires key-admin role.
func (c *Client) ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error) {
	body := map[string]interface{}{
		"target_system":     req.TargetSystem,
		"target_public_key": base64.StdEncoding.EncodeToString(req.TargetPublicKey),
		"purpose":           req.Purpose,
	}

	var result struct {
		WrappedKey            string `json:"wrapped_key"`
		EncryptedTransportKey string `json:"encrypted_transport_key"`
		KeyFingerprint        string `json:"key_fingerprint"`
		ExportID              string `json:"export_id"`
		ExpiresAt             string `json:"expires_at"`
	}

	if err := c.doJSON(ctx, http.MethodPost, "/v1/keys/export/"+req.KeyID, body, &result); err != nil {
		return nil, err
	}

	wk, _ := base64.StdEncoding.DecodeString(result.WrappedKey)
	etk, _ := base64.StdEncoding.DecodeString(result.EncryptedTransportKey)

	return &ExportKeyResponse{
		WrappedKey:            wk,
		EncryptedTransportKey: etk,
		KeyFingerprint:        result.KeyFingerprint,
		ExportID:              result.ExportID,
		ExpiresAt:             result.ExpiresAt,
	}, nil
}
