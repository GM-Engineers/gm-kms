package kms

import "time"

// KeySpec represents the cryptographic algorithm of a key.
type KeySpec string

const (
	SpecAes256Gcm    KeySpec = "aes-256-gcm"
	SpecSm4          KeySpec = "sm4"
	SpecEd25519      KeySpec = "ed25519"
	SpecSm2          KeySpec = "sm2"
	SpecEcdsaP256    KeySpec = "ecdsa-p256"
	SpecEcdsaP384    KeySpec = "ecdsa-p384"
	SpecSm9Signing   KeySpec = "sm9-signing"
	SpecSm9Encryption KeySpec = "sm9-encryption"
)

// KeyMeta contains key metadata returned by the KMS API.
type KeyMeta struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Spec      KeySpec    `json:"spec"`
	Status    string     `json:"status"`
	Version   uint32     `json:"version"`
	TenantID  string     `json:"tenant_id"`
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

// keyResponse is the raw JSON structure returned by the API for a single key.
type keyResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Spec      string `json:"spec"`
	Status    string `json:"status"`
	Version   uint32 `json:"version"`
	TenantID  string `json:"tenant_id"`
	CreatedAt string `json:"created_at"`
	RotatedAt string `json:"rotated_at,omitempty"`
}

func (r *keyResponse) toKeyMeta() *KeyMeta {
	createdAt, _ := time.Parse(time.RFC3339, r.CreatedAt)
	k := &KeyMeta{
		ID:        r.ID,
		Name:      r.Name,
		Spec:      KeySpec(r.Spec),
		Status:    r.Status,
		Version:   r.Version,
		TenantID:  r.TenantID,
		CreatedAt: createdAt,
	}
	if r.RotatedAt != "" {
		if rt, err := time.Parse(time.RFC3339, r.RotatedAt); err == nil {
			k.RotatedAt = &rt
		}
	}
	return k
}
