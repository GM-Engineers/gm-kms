// kms-operator main entry point
package main

import (
	"context"
	"flag"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	kmsv1alpha1 "github.com/GM-Engineers/gm-kms/operators/kms-operator/api/v1alpha1"
	"github.com/GM-Engineers/gm-kms/operators/kms-operator/internal/controller"
	"github.com/GM-Engineers/gm-kms/operators/kms-operator/internal/kmsclient"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kmsv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		enableLeaderElection bool
		kmsServerURL        string
		kmsAPIKey           string
		kmsClientTimeout    time.Duration
		watchNamespace       string
	)

	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false, "Enable leader election for controller manager")
	flag.StringVar(&kmsServerURL, "kms-server-url", "http://localhost:8080", "GM-KMS server URL")
	flag.StringVar(&kmsAPIKey, "kms-api-key", "", "GM-KMS API key (optional)")
	flag.DurationVar(&kmsClientTimeout, "kms-client-timeout", 30*time.Second, "Timeout for KMS client HTTP requests")
	flag.StringVar(&watchNamespace, "watch-namespace", "", "Namespace to watch for KmsKey resources (empty for all)")

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		LeaderElection:    enableLeaderElection,
		LeaderElectionID:  "kms-operator-lock",
	})
	if err != nil {
		os.Exit(1)
	}

	// Create KMS client
	kmsClient := kmsclient.New(kmsclient.Config{
		ServerURL: kmsServerURL,
		APIKey:    kmsAPIKey,
		Timeout:   kmsClientTimeout,
	})

	// Create controller
	kmsKeyController := controller.NewKmsKeyReconciler(
		mgr.GetClient(),
		kmsClient,
		watchNamespace,
	)

	if err := kmsKeyController.SetupWithManager(mgr); err != nil {
		os.Exit(1)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		os.Exit(1)
	}
}
