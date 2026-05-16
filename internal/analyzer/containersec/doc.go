// Package containersec flags pod-template configuration that weakens container
// runtime hardening but does not directly grant RBAC privileges:
//
//   - KUBE-CONTAINER-LIMITS-001 — missing CPU / memory limits or requests; the
//     container lands in BestEffort QoS and enables noisy-neighbor and cryptojacking
//     scenarios.
//   - KUBE-CONTAINER-PROBE-001 — missing both liveness and readiness probes; wedged
//     containers stay in the Service endpoint set and never restart.
//   - KUBE-CONTAINER-LIFECYCLE-001 — a `lifecycle.postStart.exec` or
//     `lifecycle.preStop.exec` hook with a non-trivial command (anything beyond a
//     simple `sleep`), which is a common runtime-mutation / persistence primitive.
//   - KUBE-CONTAINER-IMAGE-001 — image reference without an `@sha256:` digest pin
//     combined with `imagePullPolicy: Always` (explicit or the kubelet default for
//     `:latest`), so a registry-side substitution lands silently on the next pod
//     start.
//
// The analyzer aggregates per workload: controller-owned pods are skipped (matching
// the podsec module's pattern) so each finding fires once per workload, not once per
// replica. The KUBE-CONTAINER-IMAGE-001 rule is intentionally scoped to digest pinning
// so it does not duplicate KUBE-IMAGE-LATEST-001 in the podsec module, which already
// flags mutable image tags on their own.
package containersec
