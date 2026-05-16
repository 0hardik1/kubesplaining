package podsec

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/analyzer/admission/mitigation"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	corev1 "k8s.io/api/core/v1"
)

// psaBaselineChecks lists the podsec-analyzer "check:" tag values that PSA
// Baseline blocks (and Restricted, which is a strict superset). Any pod whose
// PodSpec triggers one of these checks is, by definition, a Baseline violator.
// We can't ask `mitigation.WouldPSABlock` for a list directly because it's a
// switch; this slice is the complement of that switch's Baseline branch and
// must stay in sync with it.
var psaBaselineChecks = []string{
	"privileged",
	"hostNetwork",
	"hostPID",
	"hostIPC",
	"hostPath",
	"procMount",
}

// analyzePSALabels emits one KUBE-PSA-LABELS-001 finding per namespace whose
// pods would violate PSA Baseline AND whose namespace lacks an `enforce` label
// at baseline-or-stricter (or has it explicitly set to `privileged`). The
// rationale: Baseline-violating pods + no enforce label means a future identical
// pod will keep being admitted; PSA labels are the cluster's first line of
// defense. Per Kubernetes guidance, every namespace SHOULD carry the three PSA
// labels (`enforce`/`audit`/`warn`).
//
// The check is conservative: it only fires for namespaces that already have a
// concrete violator. A namespace that runs only well-behaved pods is not flagged
// (the operator may have other reasons to leave it unlabeled, e.g. system
// namespaces, and we don't want to noise up the report). Likewise, system
// namespaces (`kube-*`) and the `default` namespace's noise is handled by the
// standard exclusions preset, not here.
func analyzePSALabels(targets []target, snapshot models.Snapshot, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	if len(snapshot.Resources.Namespaces) == 0 {
		return findings
	}

	// Index namespaces by name for fast PSA label lookups.
	nsByName := make(map[string]corev1.Namespace, len(snapshot.Resources.Namespaces))
	for _, ns := range snapshot.Resources.Namespaces {
		nsByName[ns.Name] = ns
	}

	// violationsByNS[ns] = sorted, unique list of "kind/name (check)" violator strings.
	// Using a sorted string slice (rather than a map) keeps the finding's
	// evidence deterministic for golden tests and report regeneration.
	violationsByNS := map[string][]string{}
	for _, t := range targets {
		// Cluster-scope-only objects shouldn't appear in podsec targets, but
		// guard anyway: a target without a namespace can't carry namespace PSA labels.
		if t.Namespace == "" {
			continue
		}
		for _, check := range checksTriggeredBy(t) {
			line := fmt.Sprintf("%s/%s (%s)", t.Kind, t.Name, check)
			violationsByNS[t.Namespace] = appendUnique(violationsByNS[t.Namespace], line)
		}
	}

	// Stable iteration: namespaces in lexical order so the emitted finding
	// stream is deterministic across runs.
	namespaces := make([]string, 0, len(violationsByNS))
	for ns := range violationsByNS {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	for _, nsName := range namespaces {
		violators := violationsByNS[nsName]
		ns, ok := nsByName[nsName]
		if !ok {
			// The pod targets a namespace not present in the snapshot. Skip:
			// without a Namespace object we can't read PSA labels, and the
			// rule is specifically about the namespace's labels.
			continue
		}
		state := mitigation.PSAStateForLabels(ns.Labels)
		// HasEnforce returns true for baseline or restricted. We additionally
		// flag when the enforce label is explicitly `privileged`, which is the
		// most permissive level and equivalent to "no protection at all". Any
		// other case (missing enforce, unrecognized value) is also flagged.
		if state.HasEnforce() {
			continue
		}

		content := contentPSALabels001(nsName, state, violators)
		finding := psaLabelFinding(nsName, state, violators, content)
		findings = appendFinding(findings, seen, finding)
	}

	return findings
}

// checksTriggeredBy enumerates which podsec "check:" tags the given target's
// PodSpec would emit when run through the regular analyzer pass. Used to
// determine whether a pod is a PSA Baseline violator without depending on the
// other findings already produced by the same module (keeps psa_labels.go
// independent of analyzer.go's emission order).
func checksTriggeredBy(t target) []string {
	checks := make([]string, 0, 4)
	spec := t.PodSpec

	if spec.HostNetwork {
		checks = append(checks, "hostNetwork")
	}
	if spec.HostPID {
		checks = append(checks, "hostPID")
	}
	if spec.HostIPC {
		checks = append(checks, "hostIPC")
	}
	for _, vol := range spec.Volumes {
		if vol.HostPath != nil {
			checks = append(checks, "hostPath")
			break
		}
	}
	for _, c := range allContainers(spec) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			checks = append(checks, "privileged")
			break
		}
	}
	for _, c := range allContainers(spec) {
		if c.SecurityContext != nil && c.SecurityContext.ProcMount != nil && *c.SecurityContext.ProcMount == corev1.UnmaskedProcMount {
			checks = append(checks, "procMount")
			break
		}
	}

	// Only return checks that PSA Baseline (or Restricted) would block.
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		for _, blocker := range psaBaselineChecks {
			if c == blocker {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// appendUnique appends s to dst if it isn't already present. O(n) but n is the
// per-namespace violator count, which is tiny in practice.
func appendUnique(dst []string, s string) []string {
	for _, existing := range dst {
		if existing == s {
			return dst
		}
	}
	return append(dst, s)
}

// psaLabelFinding builds the namespace-scoped finding for KUBE-PSA-LABELS-001.
// The finding has no per-pod Resource (it's about the Namespace) and no
// Subject. The ID is rule:Namespace:<name> so re-runs produce a stable ID.
func psaLabelFinding(nsName string, state mitigation.PSAState, violators []string, content ruleContent) models.Finding {
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	evidence := struct {
		EnforceLabel  string   `json:"enforce_label"`
		AuditLabel    string   `json:"audit_label"`
		WarnLabel     string   `json:"warn_label"`
		BaselineViols []string `json:"baseline_violations"`
	}{
		EnforceLabel:  state.Enforce,
		AuditLabel:    state.Audit,
		WarnLabel:     state.Warn,
		BaselineViols: violators,
	}
	evidenceJSON := mustMarshalJSON(evidence)

	return models.Finding{
		ID:               fmt.Sprintf("KUBE-PSA-LABELS-001:Namespace:%s", nsName),
		RuleID:           "KUBE-PSA-LABELS-001",
		Severity:         models.SeverityMedium,
		Score:            scoring.Clamp(5.5),
		Category:         models.CategoryDefenseEvasion,
		Title:            content.Title,
		Description:      content.Description,
		Namespace:        nsName,
		Resource:         &models.ResourceRef{Kind: "Namespace", Name: nsName},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceJSON,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:pod_security", "check:psaLabels"},
	}
}

// mustMarshalJSON wraps json.Marshal: the inputs here are local structs of
// strings, so a marshal error is impossible. Returning an empty payload on the
// (impossible) error keeps the finding well-formed.
func mustMarshalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// contentPSALabels001 returns the namespace-level finding's enriched content.
// The narrative emphasizes (a) the namespace SHOULD carry PSA labels per
// Kubernetes guidance, (b) we observed concrete violators, so the gap matters,
// and (c) the operator may have meant `privileged` for a reason but they should
// still set audit+warn so future regressions are logged.
func contentPSALabels001(nsName string, state mitigation.PSAState, violators []string) ruleContent {
	enforceDesc := "missing"
	if state.Enforce != "" {
		enforceDesc = fmt.Sprintf("`%s`", state.Enforce)
	}
	auditDesc := "missing"
	if state.Audit != "" {
		auditDesc = fmt.Sprintf("`%s`", state.Audit)
	}
	warnDesc := "missing"
	if state.Warn != "" {
		warnDesc = fmt.Sprintf("`%s`", state.Warn)
	}

	violatorPreview := strings.Join(violators, ", ")
	if len(violators) > 5 {
		violatorPreview = strings.Join(violators[:5], ", ") + fmt.Sprintf(", and %d more", len(violators)-5)
	}

	return ruleContent{
		Title: fmt.Sprintf("Namespace `%s` runs Baseline violators but has no PSA enforce label", nsName),
		Scope: models.Scope{Level: models.ScopeNamespace, Detail: fmt.Sprintf("Namespace `%s`", nsName)},
		Description: fmt.Sprintf("Namespace `%s` carries PSA labels (`pod-security.kubernetes.io/enforce` = %s, `audit` = %s, `warn` = %s) but is running pods that violate the PSA Baseline level: %s. Per the Kubernetes Pod Security Standards contract, every namespace SHOULD declare an `enforce` label at baseline or stricter, even if the operator initially leaves it permissive (`privileged`) for legacy workloads. Without `enforce`, every future Pod create/update in this namespace is admitted regardless of how dangerous its PodSpec is.\n\n"+
			"PSA labels are the cluster's first line of defense at the namespace boundary: they're cheap, they're built in (no external admission webhook), and they document operator intent (\"this namespace is for system DaemonSets that need hostNetwork\" reads very differently from \"someone forgot to label this\"). The fact that this namespace already contains baseline-violating pods means the gap is not theoretical - the next deploy will silently regress.\n\n"+
			"If you genuinely need permissive workloads in this namespace, the recommended pattern is `enforce: privileged` with `audit: baseline` and `warn: baseline`: PSA admits the pod (you stay productive), the audit log records the violation (you have evidence), and the user-agent gets a warning (your engineers see it during `kubectl apply`).",
			nsName, enforceDesc, auditDesc, warnDesc, violatorPreview),
		Impact: "Future Pod create/update requests in this namespace bypass PSA entirely. A regression that adds `privileged: true` or `hostPath: /` to an existing workload is admitted with no warning, no audit-log entry, and no rejection.",
		AttackScenario: []string{
			"Attacker compromises a CI service account that can deploy to this namespace.",
			"They push a manifest that mounts `hostPath: /` (or sets `privileged: true`).",
			"PSA admits the pod with no warning - the namespace has no `enforce` label.",
			"They escape the container to the node, steal kubelet credentials, and pivot.",
		},
		Remediation: fmt.Sprintf("Apply `pod-security.kubernetes.io/enforce: baseline` (or `restricted`) to namespace `%s`, plus `audit: baseline` and `warn: baseline` so future regressions are logged. If the namespace genuinely needs permissive workloads, use `enforce: privileged` paired with `audit`/`warn` at `baseline`.", nsName),
		RemediationSteps: []string{
			"Pick the right enforce level. For most app namespaces use `restricted` (drops most root, hostPath, capabilities). For system DaemonSets use `baseline`. For namespaces that genuinely need privileged workloads, set `enforce: privileged` but add `audit: baseline` so violations are logged.",
			fmt.Sprintf("Apply the labels: `kubectl label namespace %s pod-security.kubernetes.io/enforce=baseline pod-security.kubernetes.io/audit=baseline pod-security.kubernetes.io/warn=baseline`. Pin the version with `pod-security.kubernetes.io/enforce-version=v1.30` (or your cluster version).", nsName),
			"Run `kubectl get pods -n " + nsName + " -o yaml | grep -E 'privileged|hostPath|hostNetwork'` and triage existing violators before tightening enforce. PSA only blocks new admissions; existing pods keep running, but a rolling restart will fail.",
			"Validate: `kubectl get namespace " + nsName + " -o jsonpath='{.metadata.labels}' | grep pod-security` returns the three labels.",
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes - Pod Security Admission", URL: "https://kubernetes.io/docs/concepts/security/pod-security-admission/"},
			{Title: "Kubernetes - Pod Security Standards", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
			{Title: "Kubernetes - Apply PSA labels to all namespaces", URL: "https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/"},
			{Title: "NSA/CISA Kubernetes Hardening Guide v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"},
		},
		MitreTechniques: []models.MitreTechnique{
			{ID: "T1610", Name: "Deploy Container", URL: "https://attack.mitre.org/techniques/T1610/"},
		},
	}
}
