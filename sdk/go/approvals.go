package kms

import (
	"context"
	"fmt"
	"net/http"
)

// ApprovalStatus represents the status of an approval request.
type ApprovalStatus string

const (
	ApprovalPending            ApprovalStatus = "pending"
	ApprovalApproved           ApprovalStatus = "approved"
	ApprovalRejected           ApprovalStatus = "rejected"
	ApprovalCancelled          ApprovalStatus = "cancelled"
	ApprovalExpired            ApprovalStatus = "expired"
	ApprovalEmergencyActivated ApprovalStatus = "emergency_activated"
	ApprovalEmergencyExpired   ApprovalStatus = "emergency_expired"
)

// ApprovalLevel represents the required approval level.
type ApprovalLevel string

const (
	ApprovalNone    ApprovalLevel = "none"
	ApprovalSingle  ApprovalLevel = "single"
	ApprovalDouble  ApprovalLevel = "double"
	ApprovalTriple  ApprovalLevel = "triple"
	ApprovalManager ApprovalLevel = "manager"
	ApprovalAdmin   ApprovalLevel = "admin"
)

// CreateApprovalRequest is the request to create an approval.
type CreateApprovalRequest struct {
	Operation    string `json:"operation"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	TenantID     string `json:"tenant_id"`
	// Deprecated: the server derives the requestor from the authenticated
	// API key and ignores this field (audit follow-up B7-a). It is kept for
	// source compatibility but never sent.
	RequestorID   string `json:"-"`
	Justification string `json:"justification,omitempty"`
}

// ApprovalRequest is the response representing an approval request.
type ApprovalRequest struct {
	ID              string        `json:"id"`
	Operation       string        `json:"operation"`
	ResourceID      string        `json:"resource_id"`
	ResourceType    string        `json:"resource_type"`
	TenantID        string        `json:"tenant_id"`
	RequestorID     string        `json:"requestor_id"`
	Justification   string        `json:"justification"`
	Status          ApprovalStatus `json:"status"`
	RequiredLevel   ApprovalLevel `json:"required_level"`
	CurrentLevel    ApprovalLevel `json:"current_level"`
	ApprovalsCount  int           `json:"approvals_count"`
	RejectionsCount int           `json:"rejections_count"`
	CreatedAt       string        `json:"created_at"`
	ExpiresAt       string        `json:"expires_at"`
	CompletedAt     *string       `json:"completed_at"`
}

// CreateApproval creates a new approval request. Requires any authenticated user.
func (c *Client) CreateApproval(ctx context.Context, req *CreateApprovalRequest) (*ApprovalRequest, error) {
	if req.TenantID == "" {
		req.TenantID = c.tenantID
	}

	var result ApprovalRequest
	if err := c.doJSON(ctx, http.MethodPost, "/v1/approvals", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetApproval returns an approval request by ID. Requires any authenticated user.
func (c *Client) GetApproval(ctx context.Context, requestID string) (*ApprovalRequest, error) {
	var result ApprovalRequest
	if err := c.doJSON(ctx, http.MethodGet, "/v1/approvals/"+requestID, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CancelApproval cancels an approval request. Requires any authenticated user.
//
// Deprecated: the requestorID parameter is ignored by the server, which
// derives the requestor from the authenticated API key (audit follow-up
// B7-a). It is kept for source compatibility but never sent.
func (c *Client) CancelApproval(ctx context.Context, requestID, requestorID string) (*ApprovalRequest, error) {
	body := map[string]string{}

	var result ApprovalRequest
	if err := c.doJSON(ctx, http.MethodPost, "/v1/approvals/"+requestID+"/cancel", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ApproveActionRequest is the request to approve/reject an approval.
//
// The approver's identity and authority are derived from the authenticated
// API key by the server, so the client-side fields are ignored (audit
// follow-up B7-a). They are deprecated and never sent.
type ApproveActionRequest struct {
	// Deprecated: ignored by the server; the approver is the API key.
	ApproverID string `json:"-"`
	// Deprecated: ignored by the server; the role comes from the API key.
	ApproverRole string `json:"-"`
	// Deprecated: ignored by the server; the rejector is the API key.
	RejectorID string `json:"-"`
	// Deprecated: ignored by the server; the role comes from the API key.
	RejectorRole string `json:"-"`
	Comment      string `json:"comment,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// ApproveAction approves an approval request. Requires security-officer role.
func (c *Client) ApproveAction(ctx context.Context, requestID string, req *ApproveActionRequest) (*ApprovalRequest, error) {
	body := map[string]interface{}{}
	if req.Comment != "" {
		body["comment"] = req.Comment
	}

	var result ApprovalRequest
	if err := c.doJSON(ctx, http.MethodPost, "/v1/approvals/"+requestID+"/approve", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RejectAction rejects an approval request. Requires security-officer role.
func (c *Client) RejectAction(ctx context.Context, requestID string, req *ApproveActionRequest) (*ApprovalRequest, error) {
	body := map[string]string{
		"reason": req.Reason,
	}

	var result ApprovalRequest
	if err := c.doJSON(ctx, http.MethodPost, "/v1/approvals/"+requestID+"/reject", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListPendingApprovals lists all pending approvals for a tenant. Requires security-officer role.
func (c *Client) ListPendingApprovals(ctx context.Context, tenantID string) ([]*ApprovalRequest, error) {
	path := fmt.Sprintf("/v1/approvals/pending/%s", c.effectiveTenant(tenantID))
	var results []*ApprovalRequest
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &results); err != nil {
		return nil, err
	}
	return results, nil
}
