package kms

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AuditEvent represents a single audit log entry.
type AuditEvent struct {
	EventID      string                 `json:"event_id"`
	Timestamp    string                 `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	ActorID      string                 `json:"actor_id"`
	ActorType    string                 `json:"actor_type"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Result       string                 `json:"result"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// AuditQuery represents query parameters for listing audit events.
type AuditQuery struct {
	EventTypes []string
	ActorID    string
	ResourceID string
	StartTime  string // RFC 3339
	EndTime    string // RFC 3339
	Limit      int
	Offset     int
}

// ListAuditEvents queries audit events. Requires security-officer or audit-admin role.
func (c *Client) ListAuditEvents(ctx context.Context, q *AuditQuery) ([]*AuditEvent, error) {
	params := url.Values{}
	if len(q.EventTypes) > 0 {
		params.Set("event_types", strings.Join(q.EventTypes, ","))
	}
	if q.ActorID != "" {
		params.Set("actor_id", q.ActorID)
	}
	if q.ResourceID != "" {
		params.Set("resource_id", q.ResourceID)
	}
	if q.StartTime != "" {
		params.Set("start_time", q.StartTime)
	}
	if q.EndTime != "" {
		params.Set("end_time", q.EndTime)
	}
	if q.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", q.Limit))
	}
	if q.Offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", q.Offset))
	}

	path := "/v1/audit/events"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var results []*AuditEvent
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &results); err != nil {
		return nil, err
	}
	return results, nil
}
