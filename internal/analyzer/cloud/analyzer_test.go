package cloud

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestAnalyzerName(t *testing.T) {
	t.Parallel()
	if got := New().Name(); got != "cloud" {
		t.Fatalf("Name() = %q, want %q", got, "cloud")
	}
}

// TestAnalyzerDispatchEKSReportsCoverageGap pins the one thing an empty EKS
// snapshot must say: access entries were not evaluated. Without this, a cluster
// migrated off aws-auth would come back clean from the whole IAM class.
func TestAnalyzerDispatchEKSReportsCoverageGap(t *testing.T) {
	t.Parallel()
	snap := models.NewSnapshot()
	snap.Metadata.CloudProvider = "eks"
	findings, err := New().Analyze(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyze(eks) returned error: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "KUBE-CLOUD-ACCESSENTRY-NOT-EVALUATED-001" {
		t.Fatalf("Analyze(eks) on an empty snapshot = %+v, want only the NOT-EVALUATED coverage finding", findings)
	}
}

func TestAnalyzerDispatchNoOpProviders(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		provider string
	}{
		{name: "empty provider is a no-op", provider: ""},
		{name: "none provider is a no-op", provider: "none"},
		{name: "gke is a no-op this slot", provider: "gke"},
		{name: "aks is a no-op this slot", provider: "aks"},
		{name: "unknown provider is silently ignored", provider: "digitalocean"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snap := models.NewSnapshot()
			snap.Metadata.CloudProvider = tc.provider
			findings, err := New().Analyze(context.Background(), snap)
			if err != nil {
				t.Fatalf("Analyze(%q) returned error: %v", tc.provider, err)
			}
			if len(findings) != 0 {
				t.Fatalf("Analyze(%q) returned %d findings; expected 0 in foundation slot", tc.provider, len(findings))
			}
		})
	}
}
