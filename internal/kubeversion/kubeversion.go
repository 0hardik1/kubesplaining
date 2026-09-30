// Package kubeversion holds server-version predicates shared by analyzers that
// gate a finding on the cluster's Kubernetes version. It exists so a
// version-gated rule and the privesc-graph edge behind it consult one tested
// band instead of drifting apart: the rbac analyzer and the privesc graph do
// not import each other (see the duplicated namespacesAllowingPrivileged), but
// they must agree exactly on which versions a CVE applies to, so that band lives
// here rather than being copied into both.
package kubeversion

import "k8s.io/apimachinery/pkg/util/version"

// StatefulSetControllerRevisionDeputy reports whether serverVersion is affected
// by CVE-2026-2270: the StatefulSet controller's ApplyRevision restored the
// whole StatefulSet (metadata included, not just .Spec) from a ControllerRevision,
// so a subject that can write both objects steers kube-controller-manager into
// creating a pod in a namespace it has no access to (a confused deputy).
//
// Fixed in v1.34.12, v1.35.9, v1.36.5, and v1.37.1 (announced 2026-09-23), so the
// affected bands are:
//
//	minor < 34                : all patches (older, unlisted, EOL minors are equally affected)
//	minor == 34, patch <= 11  : up to and including v1.34.11
//	minor == 35, patch <= 8   : up to and including v1.35.8
//	minor == 36, patch <= 4   : up to and including v1.36.4
//	minor == 37, patch == 0   : v1.37.0 only
//	otherwise                 : not affected (patched, or a later minor carrying the fix)
//
// The predicate is deliberately fail-CLOSED on an unparseable or empty version:
// it returns false when the version cannot be read, so the rule stays quiet
// rather than flagging a cluster whose patch level cannot be confirmed. A
// snapshot always carries the discovery version string
// (Snapshot.Metadata.ClusterVersion), so this only loses coverage for manifests
// scanned with `scan-resource`, which have no server to report a version.
//
// Only the major.minor.patch triple is consulted; distro suffixes such as
// "-gke.1234", "+k3s1", or "-eks-..." are ignored, which is exactly what
// ParseGeneric strips. That is a small, accepted imprecision: a vendor that
// backported the fix into an older upstream patch number (e.g. a "-gke" build of
// v1.34.11 that already carries the fix) would still be flagged. The finding
// copy tells the operator to confirm their build carries the fix, and the
// alternative — a per-distro backport table — would rot faster than it helps.
func StatefulSetControllerRevisionDeputy(serverVersion string) bool {
	v, err := version.ParseGeneric(serverVersion)
	if err != nil {
		return false
	}
	if v.Major() != 1 {
		// No Kubernetes major other than 1 exists; anything else is unrecognized,
		// so stay quiet rather than guess.
		return false
	}
	minor, patch := v.Minor(), v.Patch()
	switch {
	case minor < 34:
		return true
	case minor == 34:
		return patch <= 11
	case minor == 35:
		return patch <= 8
	case minor == 36:
		return patch <= 4
	case minor == 37:
		return patch == 0
	default:
		return false
	}
}
