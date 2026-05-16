package secrets

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzeStaleEmitsForUnreferencedSecret(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			SecretsMetadata: []models.SecretMetadata{
				{Name: "stale-creds", Namespace: "team-a", Type: corev1.SecretTypeOpaque},
				{Name: "active-creds", Namespace: "team-a", Type: corev1.SecretTypeOpaque},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "app",
								EnvFrom: []corev1.EnvFromSource{
									{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "active-creds"}}},
								},
							},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if got := countByRule(findings, "KUBE-SECRETS-STALE-001"); got != 1 {
		t.Fatalf("expected exactly 1 KUBE-SECRETS-STALE-001 finding, got %d", got)
	}
	if !findingHasResource(findings, "KUBE-SECRETS-STALE-001", "team-a", "stale-creds") {
		t.Fatalf("expected stale finding to point at team-a/stale-creds")
	}
	if findingHasResource(findings, "KUBE-SECRETS-STALE-001", "team-a", "active-creds") {
		t.Fatalf("did not expect stale finding for actively-referenced secret")
	}
}

func TestAnalyzeStaleSkipsServiceAccountTokens(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			SecretsMetadata: []models.SecretMetadata{
				{Name: "legacy-token", Namespace: "default", Type: corev1.SecretTypeServiceAccountToken},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if countByRule(findings, "KUBE-SECRETS-STALE-001") != 0 {
		t.Fatalf("did not expect KUBE-SECRETS-STALE-001 for service-account-token secret")
	}
}

func TestReferencedSecretNamesCoversAllRefSurfaces(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "n"},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Env: []corev1.EnvVar{
									{Name: "DB", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "env-secret"}}}},
								},
								EnvFrom: []corev1.EnvFromSource{
									{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "envfrom-secret"}}},
								},
							},
						},
						Volumes: []corev1.Volume{
							{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "volume-secret"}}},
							{Name: "proj", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
								{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "projected-secret"}}},
							}}}},
						},
						ImagePullSecrets: []corev1.LocalObjectReference{{Name: "image-pull-secret"}},
					},
				},
			},
			ServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "team-sa", Namespace: "n"},
					Secrets: []corev1.ObjectReference{
						{Name: "sa-secret", Namespace: "n"},
					},
					ImagePullSecrets: []corev1.LocalObjectReference{
						{Name: "sa-pull-secret"},
					},
				},
			},
		},
	}

	used := referencedSecretNames(snapshot)

	for _, want := range []string{
		"n/env-secret",
		"n/envfrom-secret",
		"n/volume-secret",
		"n/projected-secret",
		"n/image-pull-secret",
		"n/sa-secret",
		"n/sa-pull-secret",
	} {
		if _, ok := used[want]; !ok {
			t.Errorf("expected referencedSecretNames to include %q, got %v", want, used)
		}
	}
}

func countByRule(findings []models.Finding, ruleID string) int {
	out := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			out++
		}
	}
	return out
}

func findingHasResource(findings []models.Finding, ruleID, namespace, name string) bool {
	for _, f := range findings {
		if f.RuleID != ruleID {
			continue
		}
		if f.Resource == nil {
			continue
		}
		if f.Resource.Namespace == namespace && f.Resource.Name == name {
			return true
		}
	}
	return false
}
