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

// TestPodSecCapsFiresPerDangerousCapability covers every entry in dangerousCapabilities.
// One container gets exactly one capability added per case; each case expects exactly one
// KUBE-PODSEC-CAPS-001 finding to appear (no other capabilities should trigger).
func TestPodSecCapsFiresPerDangerousCapability(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cap  corev1.Capability
	}{
		{"SYS_PTRACE", "SYS_PTRACE"},
		{"DAC_OVERRIDE", "DAC_OVERRIDE"},
		{"SYS_MODULE", "SYS_MODULE"},
		{"SYS_RAWIO", "SYS_RAWIO"},
		{"MKNOD", "MKNOD"},
		{"AUDIT_WRITE", "AUDIT_WRITE"},
		{"SYS_CHROOT", "SYS_CHROOT"},
		{"NET_RAW", "NET_RAW"},
		{"BPF", "BPF"},
		{"SYS_ADMIN", "SYS_ADMIN"},
		{"NET_ADMIN", "NET_ADMIN"},
		// Prefix normalization: the kernel and many docs write CAP_<NAME>;
		// Kubernetes manifests usually omit the prefix. Both should match.
		{"CAP_SYS_PTRACE (with prefix)", "CAP_SYS_PTRACE"},
		// Case normalization: lower-case spelling from a sloppy manifest should
		// still match the dangerous-capabilities list.
		{"lower-case sys_admin", "sys_admin"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snapshot := safeBaseSnapshot("caps-"+tc.name, "default", func(sc *corev1.SecurityContext) {
				sc.Capabilities = &corev1.Capabilities{Add: []corev1.Capability{tc.cap}}
			})
			findings, err := New().Analyze(context.Background(), snapshot)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			assertRulePresent(t, findings, "KUBE-PODSEC-CAPS-001")
		})
	}
}

// TestPodSecCapsAllExpandsToEveryDangerousCap verifies that capabilities.add: ["ALL"]
// is treated as if every dangerous capability were added individually. The expected
// finding count is one per dangerousCapabilities map entry.
func TestPodSecCapsAllExpandsToEveryDangerousCap(t *testing.T) {
	t.Parallel()

	snapshot := safeBaseSnapshot("caps-all", "default", func(sc *corev1.SecurityContext) {
		sc.Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"ALL"}}
	})
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	count := 0
	for _, f := range findings {
		if f.RuleID == "KUBE-PODSEC-CAPS-001" {
			count++
		}
	}
	if count != len(dangerousCapabilities) {
		t.Fatalf("expected %d KUBE-PODSEC-CAPS-001 findings for capabilities.add: [ALL], got %d", len(dangerousCapabilities), count)
	}
}

// TestPodSecCapsSkipsBenignCapability checks that a capability not on the
// dangerous list (NET_BIND_SERVICE: bind to ports <1024, explicitly allowed by PSS
// Restricted) does not produce a finding.
func TestPodSecCapsSkipsBenignCapability(t *testing.T) {
	t.Parallel()

	snapshot := safeBaseSnapshot("caps-benign", "default", func(sc *corev1.SecurityContext) {
		sc.Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"NET_BIND_SERVICE"}}
	})
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PODSEC-CAPS-001")
}

// TestPodSecCapsSkipsWhenCapabilitiesNil ensures the rule stays quiet for the
// (default) case where securityContext.capabilities is unset. A separate
// container-hardening rule could surface "no explicit drop: [ALL]" advisory,
// but that's out of scope for CAPS-001.
func TestPodSecCapsSkipsWhenCapabilitiesNil(t *testing.T) {
	t.Parallel()

	snapshot := safeBaseSnapshot("caps-nil", "default", nil)
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PODSEC-CAPS-001")
}

// TestPodSecCapsEmitsOneFindingPerCapability checks that a container adding three
// dangerous capabilities yields three distinct KUBE-PODSEC-CAPS-001 findings so the
// report ranks each fix independently.
func TestPodSecCapsEmitsOneFindingPerCapability(t *testing.T) {
	t.Parallel()

	snapshot := safeBaseSnapshot("caps-multi", "default", func(sc *corev1.SecurityContext) {
		sc.Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}}
	})
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	count := 0
	for _, f := range findings {
		if f.RuleID == "KUBE-PODSEC-CAPS-001" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("expected 3 KUBE-PODSEC-CAPS-001 findings for a container adding 3 dangerous caps, got %d", count)
	}
}

// TestNormalizeCapability exercises the CAP_ prefix and case-normalization rules
// used to match manifest spellings against the dangerousCapabilities table.
func TestNormalizeCapability(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"SYS_ADMIN":     "SYS_ADMIN",
		"sys_admin":     "SYS_ADMIN",
		"CAP_SYS_ADMIN": "SYS_ADMIN",
		"cap_sys_admin": "SYS_ADMIN",
		"  NET_RAW  ":   "NET_RAW",
		"":              "",
	}
	for in, want := range cases {
		if got := normalizeCapability(in); got != want {
			t.Errorf("normalizeCapability(%q) = %q, want %q", in, got, want)
		}
	}
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
