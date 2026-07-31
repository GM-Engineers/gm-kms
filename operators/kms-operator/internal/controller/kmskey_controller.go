// Package controller implements the KmsKey reconciler
package controller

import (
	"context"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	kmsv1alpha1 "github.com/GM-Engineers/gm-kms/operators/kms-operator/api/v1alpha1"
	"github.com/GM-Engineers/gm-kms/operators/kms-operator/internal/kmsclient"
)

// KmsKeyReconciler reconciles a KmsKey resource
type KmsKeyReconciler struct {
	client        client.Client
	scheme        *runtime.Scheme
	kmsClient     *kmsclient.Client
	watchNamespace string
}

// NewKmsKeyReconciler creates a new KmsKey reconciler
func NewKmsKeyReconciler(c client.Client, kmsClient *kmsclient.Client, watchNamespace string) *KmsKeyReconciler {
	return &KmsKeyReconciler{
		client:        c,
		kmsClient:     kmsClient,
		watchNamespace: watchNamespace,
	}
}

// +kubebuilder:rbac:groups=kms.example.com,resources=kmskeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kms.example.com,resources=kmskeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is the main reconciliation loop
func (r *KmsKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Check if we should process this namespace
	if r.watchNamespace != "" && req.Namespace != r.watchNamespace {
		return ctrl.Result{}, nil
	}

	// Fetch the KmsKey instance
	kmsKey := &kmsv1alpha1.KmsKey{}
	if err := r.client.Get(ctx, req.NamespacedName, kmsKey); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion
	if !kmsKey.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, kmsKey)
	}

	// Main reconciliation logic
	return r.reconcileKey(ctx, kmsKey)
}

func (r *KmsKeyReconciler) reconcileKey(ctx context.Context, kmsKey *kmsv1alpha1.KmsKey) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Generate a unique key name if not exists
	keyName := kmsKey.Spec.Name
	if keyName == "" {
		keyName = fmt.Sprintf("k8s-%s-%s", kmsKey.Namespace, kmsKey.Name)
	}

	// Check if key exists in KMS
	existingKey, err := r.kmsClient.GetKey(ctx, kmsKey.Spec.KeyID)
	if err != nil {
		return r.updateStatus(ctx, kmsKey, "", "", "Error", err.Error())
	}

	if existingKey == nil {
		// Create new key
		logger.Info("Creating new key in KMS", "name", keyName, "spec", kmsKey.Spec.Spec)

		createReq := &kmsclient.CreateKeyRequest{
			Name:     keyName,
			Spec:     kmsKey.Spec.Spec,
			TenantID: kmsKey.Spec.TenantID,
		}

		newKey, err := r.kmsClient.CreateKey(ctx, createReq)
		if err != nil {
			return r.updateStatus(ctx, kmsKey, "", "", "Creating", err.Error())
		}

		// Update spec with generated key ID
		kmsKey.Spec.KeyID = newKey.ID
		kmsKey.Spec.Version = newKey.Version

		if err := r.client.Update(ctx, kmsKey); err != nil {
			logger.Error(err, "Failed to update KmsKey with KeyID")
		}

		// Create Kubernetes secret with the key material
		if err := r.createSecret(ctx, kmsKey, newKey); err != nil {
			return r.updateStatus(ctx, kmsKey, newKey.ID, newKey.Version, "Error", err.Error())
		}

		return r.updateStatus(ctx, kmsKey, newKey.ID, newKey.Version, "Ready", "Key created and secret synced")
	}

	// Key exists, ensure secret is up to date
	if err := r.ensureSecret(ctx, kmsKey, existingKey); err != nil {
		return r.updateStatus(ctx, kmsKey, existingKey.ID, existingKey.Version, "Error", err.Error())
	}

	// Check if rotation is needed
	if kmsKey.Spec.Rotation != nil && kmsKey.Spec.Rotation.Enabled {
		if r.shouldRotate(kmsKey) {
			return r.rotateKey(ctx, kmsKey)
		}
	}

	return r.updateStatus(ctx, kmsKey, existingKey.ID, existingKey.Version, "Ready", "Key and secret in sync")
}

// getSecretName returns the secret name from spec or falls back to the resource name
func getSecretName(kmsKey *kmsv1alpha1.KmsKey) string {
	if kmsKey.Spec.SecretName != "" {
		return kmsKey.Spec.SecretName
	}
	return kmsKey.Name
}

func (r *KmsKeyReconciler) handleDeletion(ctx context.Context, kmsKey *kmsv1alpha1.KmsKey) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Delete the Kubernetes secret directly (ignore not found)
	secretName := getSecretName(kmsKey)

	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Namespace: kmsKey.Namespace,
		Name:      secretName,
	}, secret)

	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, err
	}

	if err == nil {
		// Secret exists, delete it
		if err := r.client.Delete(ctx, secret); err != nil {
			logger.Error(err, "Failed to delete secret")
			return ctrl.Result{}, err
		}
		logger.Info("Deleted secret", "name", secretName)
	}

	// Note: We don't delete the key from KMS intentionally
	// to preserve audit trail and allow recovery

	return ctrl.Result{}, nil
}

func (r *KmsKeyReconciler) createSecret(ctx context.Context, kmsKey *kmsv1alpha1.KmsKey, key *kmsclient.KeyResponse) error {
	logger := log.FromContext(ctx)

	secretType := corev1.SecretTypeOpaque
	if kmsKey.Spec.SecretType == "kubernetes.io/tls" {
		secretType = corev1.SecretTypeTLS
	}

	secretName := getSecretName(kmsKey)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: kmsKey.Namespace,
			Labels: map[string]string{
				"kms.example.com/managed":      "true",
				"kms.example.com/key-id":      key.ID,
				"kms.example.com/key-version": fmt.Sprintf("%d", key.Version),
			},
		},
		Type: secretType,
		Data: map[string][]byte{
			"key_id":   []byte(key.ID),
			"version":  []byte(fmt.Sprintf("%d", key.Version)),
			"metadata": []byte(fmt.Sprintf(`{"name":"%s","spec":"%s","tenant_id":"%s"}`, key.Name, key.Spec, key.TenantID)),
		},
	}

	// For TLS secrets, add the key material
	if secretType == corev1.SecretTypeTLS {
		// In a real implementation, we would call KMS to get the public key
		// For now, just store the key ID reference
	}

	if err := r.client.Create(ctx, secret); err != nil {
		logger.Error(err, "Failed to create secret")
		return err
	}

	logger.Info("Created secret", "name", secret.Name, "namespace", secret.Namespace)
	return nil
}

func (r *KmsKeyReconciler) ensureSecret(ctx context.Context, kmsKey *kmsv1alpha1.KmsKey, key *kmsclient.KeyResponse) error {
	logger := log.FromContext(ctx)

	secretName := getSecretName(kmsKey)

	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Namespace: kmsKey.Namespace,
		Name:      secretName,
	}, secret)

	if client.IgnoreNotFound(err) != nil {
		return err
	}

	if err != nil {
		// Secret doesn't exist, create it
		return r.createSecret(ctx, kmsKey, key)
	}

	// Check if secret is stale
	currentVersion := secret.Labels["kms.example.com/key-version"]
	if currentVersion != fmt.Sprintf("%d", key.Version) {
		logger.Info("Updating stale secret", "name", secret.Name, "oldVersion", currentVersion, "newVersion", key.Version)

		secret.Data["version"] = []byte(fmt.Sprintf("%d", key.Version))
		secret.Labels["kms.example.com/key-version"] = fmt.Sprintf("%d", key.Version)

		if err := r.client.Update(ctx, secret); err != nil {
			return err
		}
	}

	return nil
}

func (r *KmsKeyReconciler) shouldRotate(kmsKey *kmsv1alpha1.KmsKey) bool {
	if kmsKey.Status.LastRotation == nil {
		return false
	}

	if kmsKey.Spec.Rotation == nil || !kmsKey.Spec.Rotation.Enabled {
		return false
	}

	// Parse rotation period (e.g., "720h" for 30 days)
	period, err := time.ParseDuration(kmsKey.Spec.Rotation.RotationPeriod)
	if err != nil {
		return false
	}

	nextRotation := kmsKey.Status.LastRotation.Add(period)
	return time.Now().After(nextRotation)
}

func (r *KmsKeyReconciler) rotateKey(ctx context.Context, kmsKey *kmsv1alpha1.KmsKey) (ctrl.Result, error) {
	if kmsKey.Spec.KeyID == "" {
		return ctrl.Result{}, fmt.Errorf("no key ID to rotate")
	}

	logger := log.FromContext(ctx)
	logger.Info("Rotating key", "keyID", kmsKey.Spec.KeyID)

	newKey, err := r.kmsClient.RotateKey(ctx, kmsKey.Spec.KeyID)
	if err != nil {
		return r.updateStatus(ctx, kmsKey, kmsKey.Spec.KeyID, kmsKey.Spec.Version, "Rotating", err.Error())
	}

	// Update secret with new version
	if err := r.ensureSecret(ctx, kmsKey, newKey); err != nil {
		return r.updateStatus(ctx, kmsKey, newKey.ID, newKey.Version, "Rotating", err.Error())
	}

	now := metav1.Now()
	return r.updateStatusWithTime(ctx, kmsKey, newKey.ID, newKey.Version, "Ready", "Key rotated", &now)
}

func (r *KmsKeyReconciler) updateStatus(ctx context.Context, kmsKey *kmsv1alpha1.KmsKey, keyID string, version uint32, status, message string) (ctrl.Result, error) {
	return r.updateStatusWithTime(ctx, kmsKey, keyID, version, status, message, nil)
}

func (r *KmsKeyReconciler) updateStatusWithTime(ctx context.Context, kmsKey *kmsv1alpha1.KmsKey, keyID string, version uint32, status, message string, lastRotation *metav1.Time) (ctrl.Result, error) {
	oldStatus := kmsKey.Status

	kmsKey.Status = kmsv1alpha1.KmsKeyStatus{
		KeyID:        keyID,
		Version:      version,
		Status:       status,
		Message:      message,
		LastRotation: lastRotation,
	}

	if !reflect.DeepEqual(oldStatus, kmsKey.Status) {
		if err := r.client.Status().Update(ctx, kmsKey); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Requeue for retry if in error state
	if status == "Error" {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager configures the controller with a manager
func (r *KmsKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmsv1alpha1.KmsKey{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
