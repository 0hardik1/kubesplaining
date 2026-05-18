package collector

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDetectCloudProvider(t *testing.T) {
	t.Parallel()

	awsAuthSnapshot := models.NewSnapshot()
	awsAuthSnapshot.Resources.ConfigMaps = []models.ConfigMapSnapshot{
		{Name: "aws-auth", Namespace: "kube-system"},
	}

	eksLabelSnapshot := models.NewSnapshot()
	eksLabelSnapshot.Resources.Nodes = []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ip-10-0-0-1.ec2.internal",
				Labels: map[string]string{
					"eks.amazonaws.com/nodegroup": "default",
				},
			},
		},
	}

	gkeSnapshot := models.NewSnapshot()
	gkeSnapshot.Resources.Nodes = []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gke-cluster-default-pool-abc",
				Labels: map[string]string{
					"cloud.google.com/gke-nodepool": "default-pool",
				},
			},
		},
	}

	gkePrefixSnapshot := models.NewSnapshot()
	gkePrefixSnapshot.Resources.Nodes = []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"cloud.google.com/gke-boot-disk": "pd-standard",
				},
			},
		},
	}

	aksAzureSnapshot := models.NewSnapshot()
	aksAzureSnapshot.Resources.Nodes = []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"kubernetes.azure.com/cluster": "test",
				},
			},
		},
	}

	aksAgentpoolSnapshot := models.NewSnapshot()
	aksAgentpoolSnapshot.Resources.Nodes = []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"agentpool": "nodepool1",
				},
			},
		},
	}

	emptySnapshot := models.NewSnapshot()

	unknownLabelSnapshot := models.NewSnapshot()
	unknownLabelSnapshot.Resources.Nodes = []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"kubernetes.io/hostname": "self-hosted-1",
				},
			},
		},
	}

	// EKS takes precedence over GKE/AKS markers if both are somehow present;
	// the detector returns the first matching branch.
	eksAndGkeSnapshot := models.NewSnapshot()
	eksAndGkeSnapshot.Resources.ConfigMaps = []models.ConfigMapSnapshot{
		{Name: "aws-auth", Namespace: "kube-system"},
	}
	eksAndGkeSnapshot.Resources.Nodes = []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"cloud.google.com/gke-nodepool": "x"}}},
	}

	// aws-auth in a different namespace must not trip EKS detection.
	awsAuthWrongNSSnapshot := models.NewSnapshot()
	awsAuthWrongNSSnapshot.Resources.ConfigMaps = []models.ConfigMapSnapshot{
		{Name: "aws-auth", Namespace: "default"},
	}

	cases := []struct {
		name     string
		snapshot models.Snapshot
		want     string
	}{
		{name: "eks via aws-auth", snapshot: awsAuthSnapshot, want: "eks"},
		{name: "eks via node label", snapshot: eksLabelSnapshot, want: "eks"},
		{name: "gke via nodepool label", snapshot: gkeSnapshot, want: "gke"},
		{name: "gke via prefix label", snapshot: gkePrefixSnapshot, want: "gke"},
		{name: "aks via azure label", snapshot: aksAzureSnapshot, want: "aks"},
		{name: "aks via agentpool label", snapshot: aksAgentpoolSnapshot, want: "aks"},
		{name: "empty snapshot returns unknown", snapshot: emptySnapshot, want: ""},
		{name: "unknown label returns unknown", snapshot: unknownLabelSnapshot, want: ""},
		{name: "eks wins when overlapping", snapshot: eksAndGkeSnapshot, want: "eks"},
		{name: "aws-auth outside kube-system is ignored", snapshot: awsAuthWrongNSSnapshot, want: ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DetectCloudProvider(tc.snapshot)
			if got != tc.want {
				t.Fatalf("DetectCloudProvider() = %q, want %q", got, tc.want)
			}
		})
	}
}
