package podsec

import (
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzerEmitsPSALabelsForUnlabeledViolatorNamespace(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				// No PSA labels at all.
				{ObjectMeta: metav1.ObjectMeta{Name: "tenant-no-labels"}},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "violator", Namespace: "tenant-no-labels"},
					Spec: corev1.PodSpec{
						ServiceAccountName: "custom",
						HostNetwork:        true, // Baseline violator
						Containers: []corev1.Container{
							{Name: "c", Image: "nginx@sha256:abc",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: ptrBool(false),
									RunAsNonRoot:             ptrBool(true),
									ReadOnlyRootFilesystem:   ptrBool(true),
									SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
								}},
						},
					},
				},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	mustHaveRule(t, got, "KUBE-PSA-LABELS-001")
}

func TestAnalyzerSkipsPSALabelsWhenEnforceLabeled(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "tenant-baseline", Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "baseline",
				}}},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "violator", Namespace: "tenant-baseline"},
					Spec: corev1.PodSpec{
						ServiceAccountName: "custom",
						HostNetwork:        true,
						Containers: []corev1.Container{
							{Name: "c", Image: "nginx@sha256:abc",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: ptrBool(false),
									RunAsNonRoot:             ptrBool(true),
								}},
						},
					},
				},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range got {
		if f.RuleID == "KUBE-PSA-LABELS-001" {
			t.Fatalf("expected no KUBE-PSA-LABELS-001 finding when enforce=baseline, got %+v", f)
		}
	}
}

func TestAnalyzerEmitsPSALabelsWhenEnforcePrivileged(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				// `privileged` is the most permissive level - explicit opt-out.
				{ObjectMeta: metav1.ObjectMeta{Name: "tenant-privileged", Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "privileged",
				}}},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "violator", Namespace: "tenant-privileged"},
					Spec: corev1.PodSpec{
						ServiceAccountName: "custom",
						HostNetwork:        true,
						Containers: []corev1.Container{
							{Name: "c", Image: "nginx@sha256:abc",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: ptrBool(false),
								}},
						},
					},
				},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	mustHaveRule(t, got, "KUBE-PSA-LABELS-001")
}

func TestAnalyzerSkipsPSALabelsWhenNoViolators(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "tenant-clean"}},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "clean", Namespace: "tenant-clean"},
					Spec: corev1.PodSpec{
						ServiceAccountName: "custom",
						Containers: []corev1.Container{
							{Name: "c", Image: "nginx@sha256:abc",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: ptrBool(false),
									RunAsNonRoot:             ptrBool(true),
									ReadOnlyRootFilesystem:   ptrBool(true),
									SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
								}},
						},
					},
				},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range got {
		if f.RuleID == "KUBE-PSA-LABELS-001" {
			t.Fatalf("expected no KUBE-PSA-LABELS-001 finding for clean namespace, got %+v", f)
		}
	}
}

func TestPSALabelsEvidenceCarriesLabelsAndViolators(t *testing.T) {
	t.Parallel()

	pri := true
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{
					"pod-security.kubernetes.io/audit": "baseline",
					"pod-security.kubernetes.io/warn":  "baseline",
				}}},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "tenant"},
					Spec: corev1.PodSpec{
						ServiceAccountName: "custom",
						Containers: []corev1.Container{
							{Name: "c", Image: "nginx@sha256:abc",
								SecurityContext: &corev1.SecurityContext{Privileged: &pri}},
						},
					},
				},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var f *models.Finding
	for i := range got {
		if got[i].RuleID == "KUBE-PSA-LABELS-001" {
			f = &got[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("expected KUBE-PSA-LABELS-001 finding, got none")
	}
	// Evidence should mention audit + warn labels and the privileged violator.
	ev := string(f.Evidence)
	if !strings.Contains(ev, "\"audit_label\":\"baseline\"") {
		t.Errorf("expected audit_label=baseline in evidence, got %s", ev)
	}
	if !strings.Contains(ev, "\"warn_label\":\"baseline\"") {
		t.Errorf("expected warn_label=baseline in evidence, got %s", ev)
	}
	if !strings.Contains(ev, "privileged") {
		t.Errorf("expected privileged violator in evidence, got %s", ev)
	}
	if f.Resource == nil || f.Resource.Kind != "Namespace" || f.Resource.Name != "tenant" {
		t.Errorf("expected Resource Namespace/tenant, got %+v", f.Resource)
	}
	if f.Namespace != "tenant" {
		t.Errorf("expected namespace tenant, got %q", f.Namespace)
	}
}

func TestChecksTriggeredByDetectsBaselineViolators(t *testing.T) {
	t.Parallel()

	pri := true
	un := corev1.UnmaskedProcMount
	cases := []struct {
		name string
		spec corev1.PodSpec
		want []string
	}{
		{
			name: "hostNetwork",
			spec: corev1.PodSpec{HostNetwork: true},
			want: []string{"hostNetwork"},
		},
		{
			name: "hostPID",
			spec: corev1.PodSpec{HostPID: true},
			want: []string{"hostPID"},
		},
		{
			name: "hostIPC",
			spec: corev1.PodSpec{HostIPC: true},
			want: []string{"hostIPC"},
		},
		{
			name: "privileged",
			spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "c", SecurityContext: &corev1.SecurityContext{Privileged: &pri}},
				},
			},
			want: []string{"privileged"},
		},
		{
			name: "hostPath volume",
			spec: corev1.PodSpec{
				Volumes: []corev1.Volume{
					{Name: "v", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}},
				},
			},
			want: []string{"hostPath"},
		},
		{
			name: "procMount unmasked",
			spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "c", SecurityContext: &corev1.SecurityContext{ProcMount: &un}},
				},
			},
			want: []string{"procMount"},
		},
		{
			name: "clean spec",
			spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "c", SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: ptrBool(false),
						RunAsNonRoot:             ptrBool(true),
					}},
				},
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := checksTriggeredBy(target{Kind: "Pod", Namespace: "ns", Name: "p", PodSpec: tc.spec})
			if len(got) != len(tc.want) {
				t.Fatalf("checksTriggeredBy(%s) = %v, want %v", tc.name, got, tc.want)
			}
			for i, c := range got {
				if c != tc.want[i] {
					t.Fatalf("checksTriggeredBy(%s)[%d] = %q, want %q", tc.name, i, c, tc.want[i])
				}
			}
		})
	}
}
