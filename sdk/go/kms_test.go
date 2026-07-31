package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer creates a test server and a client configured to use it.
func newTestServer(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	client, err := New(srv.URL, WithAPIKey("test-api-key"))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client, srv
}

func TestHealth(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		// Health doesn't require auth but client always sends API key
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"version": "0.1.0",
		})
	})
	defer srv.Close()

	result, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s", result.Status)
	}
}

func TestCreateKey(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header is set
		if r.Header.Get("X-API-KEY") != "test-api-key" {
			t.Errorf("expected X-API-KEY header, got %q", r.Header.Get("X-API-KEY"))
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/keys" {
			t.Errorf("expected /v1/keys, got %s", r.URL.Path)
		}

		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "test-key" {
			t.Errorf("expected name test-key, got %v", body["name"])
		}
		if body["spec"] != "aes-256-gcm" {
			t.Errorf("expected spec aes-256-gcm, got %v", body["spec"])
		}
		if body["tenant_id"] != "default" {
			t.Errorf("expected tenant_id default, got %v", body["tenant_id"])
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "key-uuid-123",
			"name":       "test-key",
			"spec":       "aes-256-gcm",
			"status":     "Active",
			"version":    float64(1),
			"tenant_id":  "default",
			"created_at": "2026-05-03T12:00:00Z",
		})
	})
	defer srv.Close()

	key, err := client.CreateKey(context.Background(), &CreateKeyRequest{
		Name: "test-key",
		Spec: SpecAes256Gcm,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.ID != "key-uuid-123" {
		t.Errorf("expected key-uuid-123, got %s", key.ID)
	}
	if key.Spec != SpecAes256Gcm {
		t.Errorf("expected aes-256-gcm, got %s", key.Spec)
	}
}

func TestGetKeyWithTenantQuery(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "tenant_id=my-tenant" {
			t.Errorf("expected tenant_id=my-tenant query, got %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "key-1",
			"name":       "k",
			"spec":       "sm2",
			"status":     "Active",
			"version":    float64(1),
			"tenant_id":  "my-tenant",
			"created_at": "2026-05-03T12:00:00Z",
		})
	})
	defer srv.Close()

	key, err := client.GetKey(context.Background(), "key-1", "my-tenant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.TenantID != "my-tenant" {
		t.Errorf("expected my-tenant, got %s", key.TenantID)
	}
}

func TestEncrypt(t *testing.T) {
	plaintext := []byte("hello world")
	expectedB64 := base64.StdEncoding.EncodeToString(plaintext)

	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify tenant_id is in query
		if r.URL.Query().Get("tenant_id") != "default" {
			t.Errorf("expected tenant_id=default, got %s", r.URL.Query().Get("tenant_id"))
		}

		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["plaintext"] != expectedB64 {
			t.Errorf("expected %s, got %s", expectedB64, body["plaintext"])
		}

		json.NewEncoder(w).Encode(map[string]string{
			"ciphertext": base64.StdEncoding.EncodeToString([]byte("encrypted")),
			"nonce":      base64.StdEncoding.EncodeToString([]byte("123456789012")),
			"tag":        base64.StdEncoding.EncodeToString([]byte("tag1234567890")),
		})
	})
	defer srv.Close()

	result, err := client.Encrypt(context.Background(), "key-1", "", &EncryptRequest{
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Ciphertext) != "encrypted" {
		t.Errorf("unexpected ciphertext: %s", result.Ciphertext)
	}
}

func TestSignVerify(t *testing.T) {
	data := []byte("sign this")

	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"signature": base64.StdEncoding.EncodeToString([]byte("sig")),
			"version":   float64(1),
		})
	})
	defer srv.Close()

	result, err := client.Sign(context.Background(), "key-1", "", &SignRequest{Data: data})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Signature) != "sig" {
		t.Errorf("unexpected signature: %s", result.Signature)
	}
}

func TestHash(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/hash" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["algorithm"] != "sm3" {
			t.Errorf("expected sm3, got %s", body["algorithm"])
		}
		json.NewEncoder(w).Encode(map[string]string{
			"hash":      "abcdef1234567890",
			"algorithm": "sm3",
		})
	})
	defer srv.Close()

	result, err := client.Hash(context.Background(), &HashRequest{
		Data:      []byte("hash me"),
		Algorithm: "sm3",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Algorithm != "sm3" {
		t.Errorf("expected sm3, got %s", result.Algorithm)
	}
}

func TestDeleteKey(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()

	err := client.DeleteKey(context.Background(), "key-1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIError(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "unauthorized",
		})
	})
	defer srv.Close()

	_, err := client.GetKey(context.Background(), "key-1", "")
	if err == nil {
		t.Fatal("expected error")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("expected 401, got %d", apiErr.StatusCode)
	}
}

func TestRateLimitError(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":            "rate_limit_exceeded",
			"retry_after_secs": float64(5),
		})
	})
	defer srv.Close()

	_, err := client.GetKey(context.Background(), "key-1", "")
	if err == nil {
		t.Fatal("expected error")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.RetryAfter != 5 {
		t.Errorf("expected RetryAfter=5, got %d", apiErr.RetryAfter)
	}
}

func TestSm9Sign(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sm9/sign" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"w": base64.StdEncoding.EncodeToString([]byte("w-point")),
			"h": "abcdef",
			"s": base64.StdEncoding.EncodeToString([]byte("s-point")),
		})
	})
	defer srv.Close()

	result, err := client.Sm9Sign(context.Background(), &Sm9SignRequest{
		Identity: "alice@example.com",
		Data:     []byte("sm9 data"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.H != "abcdef" {
		t.Errorf("unexpected h: %s", result.H)
	}
}

func TestEnvelopeEncrypt(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/envelope/encrypt" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["kek_id"] != "kek-1" {
			t.Errorf("expected kek-1, got %v", body["kek_id"])
		}
		if body["dek_length"] != float64(32) {
			t.Errorf("expected dek_length=32, got %v", body["dek_length"])
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"wrapped_dek": base64.StdEncoding.EncodeToString([]byte("dek")),
			"dek_nonce":   base64.StdEncoding.EncodeToString([]byte("nonce12")),
			"ciphertext":  base64.StdEncoding.EncodeToString([]byte("ct")),
			"data_nonce":  base64.StdEncoding.EncodeToString([]byte("dnonce")),
			"tag":         base64.StdEncoding.EncodeToString([]byte("tag12")),
			"kek_version": float64(1),
		})
	})
	defer srv.Close()

	result, err := client.EnvelopeEncrypt(context.Background(), &EnvelopeEncryptRequest{
		Plaintext: []byte("secret"),
		KEKID:     "kek-1",
		DEKLength: 32,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Ciphertext) != "ct" {
		t.Errorf("unexpected ciphertext: %s", result.Ciphertext)
	}
}

func TestDhDerive(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"shared_secret": base64.StdEncoding.EncodeToString([]byte("shared-secret")),
			"kdf":           "ECDH-P256-SHA256",
		})
	})
	defer srv.Close()

	result, err := client.DhDerive(context.Background(), &DhDeriveRequest{
		KeyID:         "key-1",
		Algorithm:     DHAlgorithmECP256,
		PeerPublicKey: []byte("peer-key"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KDF != "ECDH-P256-SHA256" {
		t.Errorf("unexpected KDF: %s", result.KDF)
	}
}

func TestImportKey(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/keys/import" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":                 "imported-uuid",
			"spec":               "aes-256-gcm",
			"imported":           true,
			"source_fingerprint": "abc123",
		})
	})
	defer srv.Close()

	result, err := client.ImportKey(context.Background(), &ImportKeyRequest{
		Name:                 "imported",
		Spec:                 SpecAes256Gcm,
		Format:               ImportFormatRaw,
		WrappedKey:           []byte("key-material"),
		EncryptedTransportKey: []byte("transport-key"),
		SourceFingerprint:    "abc123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Imported {
		t.Error("expected imported=true")
	}
}

func TestCreatePolicy(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":        "policy-1",
			"name":      "test-policy",
			"effect":    "allow",
			"resources": []string{"keys/*"},
			"subjects":  []string{"*"},
			"enabled":   true,
		})
	})
	defer srv.Close()

	result, err := client.CreatePolicy(context.Background(), &CreatePolicyRequest{
		Name:      "test-policy",
		Effect:    "allow",
		Resources: []string{"keys/*"},
		Subjects:  []string{"*"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "policy-1" {
		t.Errorf("expected policy-1, got %s", result.ID)
	}
}

func TestMfaSetup(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mfa/setup/user-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secret":           "JBSWY3DPEHPK3PXP",
			"provisioning_uri": "otpauth://totp/...",
			"backup_codes":     []string{"12345678", "87654321"},
		})
	})
	defer srv.Close()

	result, err := client.MfaSetup(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("unexpected secret: %s", result.Secret)
	}
}

func TestApprovals(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":               "approval-1",
			"operation":        "key_delete",
			"resource_id":      "key-1",
			"resource_type":    "key",
			"tenant_id":        "default",
			"requestor_id":     "user-1",
			"status":           "pending",
			"required_level":   "single",
			"current_level":    "none",
			"approvals_count":  float64(0),
			"rejections_count": float64(0),
			"created_at":       "2026-05-03T12:00:00Z",
			"expires_at":       "2026-05-04T12:00:00Z",
			"completed_at":     nil,
		})
	})
	defer srv.Close()

	result, err := client.CreateApproval(context.Background(), &CreateApprovalRequest{
		Operation:    "key_delete",
		ResourceID:   "key-1",
		ResourceType: "key",
		RequestorID:  "user-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != ApprovalPending {
		t.Errorf("expected pending, got %s", result.Status)
	}
}

func TestListAuditEvents(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("event_types") != "KeyCreated,KeyDeleted" {
			t.Errorf("unexpected event_types: %s", r.URL.Query().Get("event_types"))
		}
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("unexpected limit: %s", r.URL.Query().Get("limit"))
		}
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"event_id":   "evt-1",
				"timestamp":  "2026-05-03T12:00:00Z",
				"event_type": "KeyCreated",
				"actor_id":   "admin",
				"actor_type": "user",
				"action":     "create_key",
				"result":     "success",
			},
		})
	})
	defer srv.Close()

	results, err := client.ListAuditEvents(context.Background(), &AuditQuery{
		EventTypes: []string{"KeyCreated", "KeyDeleted"},
		Limit:      10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestWithTenantID(t *testing.T) {
	client, srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("tenant_id") != "my-org" {
			t.Errorf("expected tenant_id=my-org, got %s", r.URL.Query().Get("tenant_id"))
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "key-1",
			"name":       "k",
			"spec":       "sm2",
			"status":     "Active",
			"version":    float64(1),
			"tenant_id":  "my-org",
			"created_at": "2026-05-03T12:00:00Z",
		})
	})
	defer srv.Close()

	client.tenantID = "my-org"
	_, err := client.GetKey(context.Background(), "key-1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
