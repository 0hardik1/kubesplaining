// Package containersec flags pod-template configuration that weakens container
// runtime hardening but does not directly grant RBAC privileges: missing resource
// limits / requests, missing liveness / readiness probes, lifecycle exec hooks,
// and image-pulling policies that disable digest pinning.
//
// Wave 0 ships this as a registered no-op stub so the engine's module slice has a
// stable factory entry to populate; Wave 1 slot #9 fills in the rule set. See
// the wave plan for the rule IDs this module will own (KUBE-CONTAINER-LIMITS-001,
// KUBE-CONTAINER-PROBE-001, KUBE-CONTAINER-LIFECYCLE-001, KUBE-CONTAINER-IMAGE-001).
package containersec
