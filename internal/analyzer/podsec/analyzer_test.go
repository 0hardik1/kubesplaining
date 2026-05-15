package podsec

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzerFindsHighRiskPodSecurityIssues(t *testing.T) {
	t.Parallel()

	privileged := true

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "risky",
						Namespace: "default",
					},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ServiceAccountName: "default",
								HostNetwork:        true,
								Containers: []corev1.Container{
									{
										Name:  "app",
										Image: "nginx:latest",
										SecurityContext: &corev1.SecurityContext{
											Privileged: &privileged,
										},
									},
								},
								Volumes: []corev1.Volume{
									{
										Name: "rootfs",
										VolumeSource: corev1.VolumeSource{
											HostPath: &corev1.HostPathVolumeSource{Path: "/"},
										},
									},
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

	assertRulePresent(t, findings, "KUBE-SA-DEFAULT-001")
	assertRulePresent(t, findings, "KUBE-ESCAPE-003")
	assertRulePresent(t, findings, "KUBE-ESCAPE-001")
	assertRulePresent(t, findings, "KUBE-ESCAPE-006")
	assertRulePresent(t, findings, "KUBE-IMAGE-LATEST-001")
	assertRulePresent(t, findings, "KUBE-PODSEC-READONLY-001")
	assertRulePresent(t, findings, "KUBE-PODSEC-SECCOMP-001")
}

func TestAnalyzerIgnoresDigestPinnedNonRootWorkload(t *testing.T) {
	t.Parallel()

	falseValue := false
	trueValue := true
	runAsUser := int64(1000)
	runAsNonRoot := true

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "safe",
						Namespace: "default",
					},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ServiceAccountName: "safe",
								Containers: []corev1.Container{
									{
										Name:  "app",
										Image: "nginx@sha256:deadbeef",
										SecurityContext: &corev1.SecurityContext{
											AllowPrivilegeEscalation: &falseValue,
											RunAsUser:                &runAsUser,
											RunAsNonRoot:             &runAsNonRoot,
											ReadOnlyRootFilesystem:   &trueValue,
											SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
										},
									},
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

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
}

func TestPodSecReadOnlyFiresWhenWritable(t *testing.T) {
	t.Parallel()

	falseValue := false
	snapshot := safeBaseSnapshot("readonly-fires", "default", func(sc *corev1.SecurityContext) {
		sc.ReadOnlyRootFilesystem = &falseValue
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PODSEC-READONLY-001")
	assertRuleAbsent(t, findings, "KUBE-PODSEC-SECCOMP-001")
	assertRuleAbsent(t, findings, "KUBE-PODSEC-PROCMOUNT-001")
}

func TestPodSecReadOnlySkippedWhenTrue(t *testing.T) {
	t.Parallel()

	snapshot := safeBaseSnapshot("readonly-safe", "default", nil)
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PODSEC-READONLY-001")
}

func TestPodSecSeccompFiresWhenUnconfined(t *testing.T) {
	t.Parallel()

	snapshot := safeBaseSnapshot("seccomp-fires", "default", func(sc *corev1.SecurityContext) {
		sc.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PODSEC-SECCOMP-001")
}

func TestPodSecSeccompSkippedWhenRuntimeDefault(t *testing.T) {
	t.Parallel()

	snapshot := safeBaseSnapshot("seccomp-safe", "default", nil)
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PODSEC-SECCOMP-001")
}

// TestPodSecSeccompFallsBackToPodLevel checks that when the container omits SeccompProfile,
// the analyzer reads it off the pod-level SecurityContext (matching the runtime's
// inheritance rules) instead of always firing.
func TestPodSecSeccompFallsBackToPodLevel(t *testing.T) {
	t.Parallel()

	falseValue := false
	trueValue := true
	runAsUser := int64(1000)
	runAsNonRoot := true

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "seccomp-pod-fallback", Namespace: "default"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ServiceAccountName: "seccomp-pod-fallback",
								SecurityContext: &corev1.PodSecurityContext{
									SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
								},
								Containers: []corev1.Container{
									{
										Name:  "app",
										Image: "nginx@sha256:deadbeef",
										SecurityContext: &corev1.SecurityContext{
											AllowPrivilegeEscalation: &falseValue,
											RunAsUser:                &runAsUser,
											RunAsNonRoot:             &runAsNonRoot,
											ReadOnlyRootFilesystem:   &trueValue,
										},
									},
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
	assertRuleAbsent(t, findings, "KUBE-PODSEC-SECCOMP-001")
}

func TestPodSecProcMountFiresWhenUnmasked(t *testing.T) {
	t.Parallel()

	unmasked := corev1.UnmaskedProcMount
	snapshot := safeBaseSnapshot("procmount-fires", "default", func(sc *corev1.SecurityContext) {
		sc.ProcMount = &unmasked
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PODSEC-PROCMOUNT-001")
}

func TestPodSecProcMountSkippedWhenDefault(t *testing.T) {
	t.Parallel()

	defaultMount := corev1.DefaultProcMount
	snapshot := safeBaseSnapshot("procmount-default", "default", func(sc *corev1.SecurityContext) {
		sc.ProcMount = &defaultMount
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PODSEC-PROCMOUNT-001")
}

// safeBaseSnapshot returns a Deployment that satisfies every existing podsec rule (digest-pinned
// image, non-root, allowPrivilegeEscalation=false, readOnlyRootFilesystem=true, RuntimeDefault
// seccomp). The mutate callback may flip one field to exercise a specific rule.
func safeBaseSnapshot(name, namespace string, mutate func(*corev1.SecurityContext)) models.Snapshot {
	falseValue := false
	trueValue := true
	runAsUser := int64(1000)
	runAsNonRoot := true

	sc := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &falseValue,
		RunAsUser:                &runAsUser,
		RunAsNonRoot:             &runAsNonRoot,
		ReadOnlyRootFilesystem:   &trueValue,
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	if mutate != nil {
		mutate(sc)
	}

	return models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ServiceAccountName: name,
								Containers: []corev1.Container{
									{Name: "app", Image: "nginx@sha256:deadbeef", SecurityContext: sc},
								},
							},
						},
					},
				},
			},
		},
	}
}

func assertRuleAbsent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()

	for _, finding := range findings {
		if finding.RuleID == ruleID {
			t.Fatalf("expected rule %s to be absent, but found %+v", ruleID, finding)
		}
	}
}

func assertRulePresent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()

	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}

	t.Fatalf("expected rule %s to be present, findings=%v", ruleID, findings)
}
