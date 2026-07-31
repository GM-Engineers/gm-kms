package kms

import (
	"context"
	"fmt"
	"net/http"
)

// MfaSetupResponse is the response from MFA setup.
type MfaSetupResponse struct {
	Secret          string   `json:"secret"`
	ProvisioningURI string   `json:"provisioning_uri"`
	BackupCodes     []string `json:"backup_codes"`
}

// MfaStatusResponse is the response from MFA status check.
type MfaStatusResponse struct {
	Enabled               bool   `json:"enabled"`
	MfaType               string `json:"mfa_type"`
	BackupCodesRemaining  int    `json:"backup_codes_remaining"`
}

// MfaSetup initiates MFA setup for a user. Requires security-officer role.
func (c *Client) MfaSetup(ctx context.Context, userID string) (*MfaSetupResponse, error) {
	var result MfaSetupResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/setup/"+userID, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// MfaVerify verifies a TOTP code for a user. Requires security-officer role.
// Returns true if valid, along with remaining attempts on failure.
func (c *Client) MfaVerify(ctx context.Context, userID, code string) (bool, int, error) {
	body := map[string]string{"code": code}

	var result struct {
		Valid             bool `json:"valid"`
		AttemptsRemaining int  `json:"attempts_remaining"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/verify/"+userID, body, &result); err != nil {
		return false, 0, err
	}
	return result.Valid, result.AttemptsRemaining, nil
}

// MfaBackup consumes a backup code for MFA recovery. Requires security-officer role.
func (c *Client) MfaBackup(ctx context.Context, userID, code string) (bool, error) {
	body := map[string]string{"code": code}

	var result struct {
		Valid           bool `json:"valid"`
		BackupCodeUsed  bool `json:"backup_code_used"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/backup/"+userID, body, &result); err != nil {
		return false, err
	}
	return result.Valid, nil
}

// MfaStatus returns the MFA status for a user. Requires security-officer role.
func (c *Client) MfaStatus(ctx context.Context, userID string) (*MfaStatusResponse, error) {
	var result MfaStatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/mfa/status/"+userID, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// MfaSetupLegacy initiates MFA setup via query parameter style.
func (c *Client) MfaSetupLegacy(ctx context.Context, userID string) (*MfaSetupResponse, error) {
	path := fmt.Sprintf("/v1/mfa/setup/%s", userID)
	var result MfaSetupResponse
	if err := c.doJSON(ctx, http.MethodPost, path, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
