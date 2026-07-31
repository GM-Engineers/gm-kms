package kms

import "fmt"

// APIError represents an error returned by the KMS API.
type APIError struct {
	StatusCode int
	Message    string
	RetryAfter int // seconds, set when rate limited (429)
}

func (e *APIError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("kms: %s (retry after %ds)", e.Message, e.RetryAfter)
	}
	return fmt.Sprintf("kms: %s", e.Message)
}
