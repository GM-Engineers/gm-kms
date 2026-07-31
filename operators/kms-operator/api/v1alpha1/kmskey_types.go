// Package v1alpha1 contains API types for the KMS Operator
//
// KmsKey API:
//
// The KmsKey custom resource defines a key stored in GM-KMS.
// The operator will create/manage the key in KMS and sync it as a Kubernetes secret.
//
// Example:
//
// ```yaml
// apiVersion: kms.example.com/v1alpha1
// kind: KmsKey
// metadata:
//   name: my-app-key
// spec:
//   tenantId: "tenant-1"
//   spec: "aes-256-gcm"
//   secretName: "my-app-encryption-key"  # Name of the K8s secret to create
//   secretType: "kubernetes.io/tls"       # Optional, defaults to Opaque
// ```
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// KmsKeySpec defines the desired state of KmsKey
type KmsKeySpec struct {
	// TenantID is the KMS tenant ID
	TenantID string `json:"tenantId"`

	// Spec is the key specification (e.g., aes-256-gcm, sm4, ed25519)
	Spec string `json:"spec"`

	// SecretName is the name of the Kubernetes secret to create/update
	SecretName string `json:"secretName"`

	// SecretType is the Kubernetes secret type (default: Opaque)
	// +optional
	SecretType string `json:"secretType,omitempty"`

	// KeyID is the actual KMS key ID (populated by the controller)
	// +optional
	KeyID string `json:"keyId,omitempty"`

	// Version is the current key version (populated by the controller)
	// +optional
	Version uint32 `json:"version,omitempty"`
}

// KmsKeyStatus defines the observed state of KmsKey
type KmsKeyStatus struct {
	// KeyID is the KMS key ID
	// +optional
	KeyID string `json:"keyId,omitempty"`

	// Version is the current key version
	// +optional
	Version uint32 `json:"version,omitempty"`

	// Status is the current status (Creating, Ready, Rotating, Error)
	// +optional
	Status string `json:"status,omitempty"`

	// Message provides additional details about the status
	// +optional
	Message string `json:"message,omitempty"`

	// LastRotation is the timestamp of the last rotation
	// +optional
	LastRotation *metav1.Time `json:"lastRotation,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tenant",type="string",JSONPath=".spec.tenantId"
// +kubebuilder:printcolumn:name="Key Spec",type="string",JSONPath=".spec.spec"
// +kubebuilder:printcolumn:name="KMS Key ID",type="string",JSONPath=".status.keyId"
// +kubebuilder:printcolumn:name="Version",type="integer",JSONPath=".status.version"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.status"

// KmsKey is the Schema for the kmskeys API
type KmsKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KmsKeySpec   `json:"spec,omitempty"`
	Status KmsKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KmsKeyList contains a list of KmsKey
type KmsKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KmsKey `json:"items"`
}

// KmsKeyRotationPolicy defines the rotation policy
type KmsKeyRotationPolicy struct {
	// Enabled indicates whether automatic rotation is enabled
	Enabled bool `json:"enabled"`

	// RotationPeriod is the rotation period (e.g., "720h" for 30 days)
	RotationPeriod string `json:"rotationPeriod"`
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

func init() {
	SchemeBuilder.Register(&KmsKey{}, &KmsKeyList{})
}
