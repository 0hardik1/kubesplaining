package eks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// makeSA builds a ServiceAccount with the IRSA annotation set to arn (when
// arn != ""). Empty arn means "no IRSA annotation".
func makeSA(namespace, name, arn string) corev1.ServiceAccount {
	sa := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	if arn != "" {
		sa.Annotations = map[string]string{IRSAAnnotation: arn}
	}
	return sa
}

// makePod builds a pod with the given SA, image, and env-var name on a single
// container. Used by Rule #4 tests to compose snapshots compactly.
func makePod(namespace, name, saName, image, envName string) corev1.Pod {
	envs := []corev1.EnvVar{}
	if envName != "" {
		envs = append(envs, corev1.EnvVar{Name: envName, Value: "x"})
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			ServiceAccountName: saName,
			Containers: []corev1.Container{
				{Name: "main", Image: image, Env: envs},
			},
		},
	}
}

// findingsByRule lives in aws_auth_test.go (Unit 1) and is reused here.

func TestAnalyzeIRSAAdminRole(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		sa            corev1.ServiceAccount
		wantFinding   bool
		wantReason    string
		wantKeyword   string
		wantScore     float64
		wantSeverity  models.Severity
		wantEvidence  string // substring expected in evidence JSON
		wantRuleCount int
	}{
		{
			name:          "SA without IRSA annotation is silent",
			sa:            makeSA("default", "no-irsa", ""),
			wantFinding:   false,
			wantRuleCount: 0,
		},
		{
			name:          "SA with non-admin IRSA role is silent",
			sa:            makeSA("default", "reader-sa", "arn:aws:iam::123456789012:role/SomeReadRole"),
			wantFinding:   false,
			wantRuleCount: 0,
		},
		{
			name:          "SA with AdministratorAccess role fires admin-substring",
			sa:            makeSA("prod", "ops", "arn:aws:iam::123456789012:role/AdministratorAccess"),
			wantFinding:   true,
			wantReason:    "admin-substring",
			wantKeyword:   "Administrator",
			wantScore:     7.8,
			wantSeverity:  models.SeverityHigh,
			wantEvidence:  `"reason":"admin-substring"`,
			wantRuleCount: 1,
		},
		{
			name:          "SA with reserved SSO admin permission set fires reserved-sso-admin",
			sa:            makeSA("prod", "sso", "arn:aws:iam::123456789012:role/AWSReservedSSO_AdministratorAccess_a1b2c3d4"),
			wantFinding:   true,
			wantReason:    "reserved-sso-admin",
			wantKeyword:   "AWSReservedSSO_AdministratorAccess",
			wantScore:     9.2,
			wantSeverity:  models.SeverityHigh,
			wantEvidence:  `"reason":"reserved-sso-admin"`,
			wantRuleCount: 1,
		},
		{
			name:          "SA with MyAppFullAccess role fires admin-substring with FullAccess",
			sa:            makeSA("default", "app", "arn:aws:iam::123456789012:role/MyAppFullAccess"),
			wantFinding:   true,
			wantReason:    "admin-substring",
			wantKeyword:   "FullAccess",
			wantScore:     7.8,
			wantSeverity:  models.SeverityHigh,
			wantEvidence:  `"matchedKeyword":"FullAccess"`,
			wantRuleCount: 1,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snap := models.NewSnapshot()
			snap.Resources.ServiceAccounts = []corev1.ServiceAccount{tc.sa}
			findings := findingsByRule(AnalyzeIRSA(snap), "KUBE-CLOUD-IRSA-ADMIN-ROLE-001")
			if len(findings) != tc.wantRuleCount {
				t.Fatalf("AnalyzeIRSA emitted %d admin-role findings, want %d", len(findings), tc.wantRuleCount)
			}
			if !tc.wantFinding {
				return
			}
			f := findings[0]
			if f.Severity != tc.wantSeverity {
				t.Errorf("Severity = %q, want %q", f.Severity, tc.wantSeverity)
			}
			if f.Score != tc.wantScore {
				t.Errorf("Score = %v, want %v", f.Score, tc.wantScore)
			}
			if !strings.Contains(string(f.Evidence), tc.wantEvidence) {
				t.Errorf("Evidence = %s, want substring %q", string(f.Evidence), tc.wantEvidence)
			}
			var evidence map[string]any
			if err := json.Unmarshal(f.Evidence, &evidence); err != nil {
				t.Fatalf("evidence JSON invalid: %v", err)
			}
			if evidence["reason"] != tc.wantReason {
				t.Errorf("evidence.reason = %v, want %q", evidence["reason"], tc.wantReason)
			}
			if evidence["matchedKeyword"] != tc.wantKeyword {
				t.Errorf("evidence.matchedKeyword = %v, want %q", evidence["matchedKeyword"], tc.wantKeyword)
			}
		})
	}
}

func TestAnalyzeIRSAMissing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		sa            corev1.ServiceAccount
		pod           corev1.Pod
		wantRuleCount int
		wantHintKind  string // when wantRuleCount == 1, the expected hintKind
	}{
		{
			name:          "pod without IRSA using aws-cli image fires",
			sa:            makeSA("default", "default", ""),
			pod:           makePod("default", "cli-pod", "default", "amazon/aws-cli:latest", ""),
			wantRuleCount: 1,
			wantHintKind:  "image",
		},
		{
			name:          "pod whose SA has IRSA using aws-cli image is silent",
			sa:            makeSA("default", "default", "arn:aws:iam::123456789012:role/SomeReadRole"),
			pod:           makePod("default", "cli-pod", "default", "amazon/aws-cli:latest", ""),
			wantRuleCount: 0,
		},
		{
			name:          "pod without IRSA running nginx and no AWS env is silent",
			sa:            makeSA("default", "default", ""),
			pod:           makePod("default", "web", "default", "nginx:1.25", ""),
			wantRuleCount: 0,
		},
		{
			name:          "pod without IRSA but only AWS_REGION env is silent (excluded env)",
			sa:            makeSA("default", "default", ""),
			pod:           makePod("default", "web", "default", "nginx:1.25", "AWS_REGION"),
			wantRuleCount: 0,
		},
		{
			name:          "pod without IRSA carrying AWS_PROFILE env fires",
			sa:            makeSA("default", "default", ""),
			pod:           makePod("default", "app", "default", "nginx:1.25", "AWS_PROFILE"),
			wantRuleCount: 1,
			wantHintKind:  "env",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snap := models.NewSnapshot()
			snap.Resources.ServiceAccounts = []corev1.ServiceAccount{tc.sa}
			snap.Resources.Pods = []corev1.Pod{tc.pod}
			findings := findingsByRule(AnalyzeIRSA(snap), "KUBE-CLOUD-IRSA-MISSING-001")
			if len(findings) != tc.wantRuleCount {
				t.Fatalf("AnalyzeIRSA emitted %d missing-IRSA findings, want %d", len(findings), tc.wantRuleCount)
			}
			if tc.wantRuleCount == 0 {
				return
			}
			f := findings[0]
			if f.Severity != models.SeverityLow {
				t.Errorf("Severity = %q, want LOW", f.Severity)
			}
			if f.Score != 3.5 {
				t.Errorf("Score = %v, want 3.5", f.Score)
			}
			var evidence map[string]any
			if err := json.Unmarshal(f.Evidence, &evidence); err != nil {
				t.Fatalf("evidence JSON invalid: %v", err)
			}
			if evidence["hintKind"] != tc.wantHintKind {
				t.Errorf("evidence.hintKind = %v, want %q", evidence["hintKind"], tc.wantHintKind)
			}
		})
	}
}

// TestAnalyzeIRSAMissingSkipsControlledPods verifies that pods owned by a
// controller (Deployment/ReplicaSet/etc.) are not double-counted: only the
// workload representation flags.
func TestAnalyzeIRSAMissingSkipsControlledPods(t *testing.T) {
	t.Parallel()
	yes := true
	pod := makePod("default", "child", "default", "amazon/aws-cli:latest", "")
	pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rs", Controller: &yes}}
	snap := models.NewSnapshot()
	snap.Resources.ServiceAccounts = []corev1.ServiceAccount{makeSA("default", "default", "")}
	snap.Resources.Pods = []corev1.Pod{pod}
	findings := findingsByRule(AnalyzeIRSA(snap), "KUBE-CLOUD-IRSA-MISSING-001")
	if len(findings) != 0 {
		t.Fatalf("controlled pod should be skipped; got %d findings", len(findings))
	}
}
