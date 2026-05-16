package podsec

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsSensitivePVHostPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path string
		want bool
	}{
		{"/", true},
		{"/etc", true},
		{"/etc/kubernetes", true}, // under /etc is sensitive
		{"/proc", true},
		{"/sys", true},
		{"/root", true},
		{"/var/run/docker.sock", true},
		{"/var/run/containerd/containerd.sock", true},
		{"/run/containerd/containerd.sock", true},
		{"/var/lib/kubelet", true},
		{"/var/lib/kubelet/pods", true}, // under /var/lib/kubelet is sensitive
		{"/var/lib/docker", true},
		{"/var/lib/containerd", true},
		{"/var/log", true},
		{"/var/log/pods", true},
		{"/etc/", true}, // trailing slash treated same as /etc
		{"/data", false},
		{"/srv/app", false},
		{"/var/lib", false},   // not /var/lib alone
		{"/varieties", false}, // prefix-string but not a path prefix
		{"/etcetera", false},  // ditto
		{"", false},
		{"/var/lib/kubeletx", false}, // not under /var/lib/kubelet
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			if got := isSensitivePVHostPath(tc.path); got != tc.want {
				t.Errorf("isSensitivePVHostPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestAnalyzerEmitsPVHostPath(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "baseline",
				}}},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "tenant-a"},
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
						Volumes: []corev1.Volume{
							{
								Name: "node-data",
								VolumeSource: corev1.VolumeSource{
									PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim-kubelet"},
								},
							},
						},
					},
				},
			},
			PersistentVolumeClaims: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "claim-kubelet", Namespace: "tenant-a"},
					Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-kubelet"},
				},
			},
			PersistentVolumes: []corev1.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-kubelet"},
					Spec: corev1.PersistentVolumeSpec{
						PersistentVolumeSource: corev1.PersistentVolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet"},
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
	mustHaveRule(t, got, "KUBE-PV-HOSTPATH-001")
}

func TestAnalyzerSkipsPVHostPathOnNonSensitivePath(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "tenant-a"},
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
						Volumes: []corev1.Volume{
							{
								Name: "ok-data",
								VolumeSource: corev1.VolumeSource{
									PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim-data"},
								},
							},
						},
					},
				},
			},
			PersistentVolumeClaims: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "claim-data", Namespace: "tenant-a"},
					Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-data"},
				},
			},
			PersistentVolumes: []corev1.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-data"},
					Spec: corev1.PersistentVolumeSpec{
						PersistentVolumeSource: corev1.PersistentVolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/srv/app"},
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
		if f.RuleID == "KUBE-PV-HOSTPATH-001" {
			t.Fatalf("expected no KUBE-PV-HOSTPATH-001 finding for /srv/app PV, got %+v", f)
		}
	}
}

func TestAnalyzerSkipsPVHostPathWhenNoBoundPV(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "tenant-a"},
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
						Volumes: []corev1.Volume{
							{
								Name: "node-data",
								VolumeSource: corev1.VolumeSource{
									PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim-pending"},
								},
							},
						},
					},
				},
			},
			PersistentVolumeClaims: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "claim-pending", Namespace: "tenant-a"},
					// No VolumeName: claim is pending, no PV to inspect.
					Spec: corev1.PersistentVolumeClaimSpec{},
				},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range got {
		if f.RuleID == "KUBE-PV-HOSTPATH-001" {
			t.Fatalf("expected no KUBE-PV-HOSTPATH-001 finding for unbound PVC, got %+v", f)
		}
	}
}

func TestAnalyzerPVHostPathEvidenceFields(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "tenant-a"},
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
						Volumes: []corev1.Volume{
							{
								Name: "rootfs",
								VolumeSource: corev1.VolumeSource{
									PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim-root"},
								},
							},
						},
					},
				},
			},
			PersistentVolumeClaims: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "claim-root", Namespace: "tenant-a"},
					Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-root"},
				},
			},
			PersistentVolumes: []corev1.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-root"},
					Spec: corev1.PersistentVolumeSpec{
						PersistentVolumeSource: corev1.PersistentVolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/"},
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
	var pvFinding *models.Finding
	for i := range got {
		if got[i].RuleID == "KUBE-PV-HOSTPATH-001" {
			pvFinding = &got[i]
			break
		}
	}
	if pvFinding == nil {
		t.Fatalf("expected KUBE-PV-HOSTPATH-001 finding, got none")
	}
	if pvFinding.Severity != models.SeverityHigh {
		t.Errorf("expected severity HIGH, got %q", pvFinding.Severity)
	}
	if pvFinding.Resource == nil || pvFinding.Resource.Name != "p" {
		t.Errorf("expected Resource.Name=p, got %+v", pvFinding.Resource)
	}
	if pvFinding.Namespace != "tenant-a" {
		t.Errorf("expected namespace tenant-a, got %q", pvFinding.Namespace)
	}
}
