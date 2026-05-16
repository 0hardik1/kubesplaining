// Cross-namespace secret-read detection: a workload-mounted ServiceAccount
// has RBAC permission to read Secrets in a *different* namespace from where
// the workload runs. The namespace boundary is K8s's primary isolation
// surface, and cross-namespace secret reads collapse it for the secret-read
// axis without needing any further pivot.
//
// Emit one finding per (subject, target_namespace) pair so the same
// over-broad ClusterRoleBinding doesn't flood the report with one finding
// per Secret it could reach. The target_namespace is the namespace the
// secret-read grant resolves to (or "*" when the grant comes from a
// ClusterRoleBinding without a Namespace).
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
)

// analyzeCrossNS emits one finding per (workload-mounted ServiceAccount, target
// namespace) pair where the SA can read Secrets in a namespace different from
// where the workload runs. Reads of the SA's own namespace do not fire (they
// are intra-namespace); cluster-wide ClusterRoleBinding-driven grants surface
// once per source-namespace pair.
//
// We rely on permissions.Aggregate as the canonical source of effective RBAC,
// matching the pattern used by the rbac and serviceaccount modules.
func (a *Analyzer) analyzeCrossNS(_ context.Context, snapshot models.Snapshot, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	saWorkloads := workloadNamespacesByServiceAccount(snapshot)
	if len(saWorkloads) == 0 {
		return findings
	}
	permsBySubject := permissions.Aggregate(snapshot)

	// Walk the workload SAs in stable order so the report is deterministic;
	// permissions.Aggregate returns a map so we cannot iterate it directly.
	keys := make([]string, 0, len(saWorkloads))
	for key := range saWorkloads {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		perms := permsBySubject[key]
		if perms == nil {
			continue
		}
		workloadNamespace := saWorkloads[key]

		// targets: namespace -> evidence about the grant. Stable map order
		// is enforced by sorting the keys when we emit findings below.
		targets := map[string]crossNSGrant{}

		for _, rule := range perms.Rules {
			if !ruleGrantsSecretRead(rule) {
				continue
			}
			grantNS := rule.Namespace
			if grantNS == workloadNamespace {
				// intra-namespace, not the cross-namespace pattern this rule covers.
				continue
			}
			// A grantNS == "" comes from a ClusterRoleBinding; it spans every
			// namespace, so the workload-namespace exclusion above already
			// caught the workload's own namespace and what's left is genuinely
			// cross-namespace from the SA's vantage point.
			grant, ok := targets[grantNS]
			if !ok {
				grant.Verbs = map[string]struct{}{}
			}
			grant.SourceRole = rule.SourceRole
			grant.SourceBinding = rule.SourceBinding
			for _, verb := range rule.Verbs {
				grant.Verbs[strings.ToLower(verb)] = struct{}{}
			}
			targets[grantNS] = grant
		}

		if len(targets) == 0 {
			continue
		}
		targetKeys := make([]string, 0, len(targets))
		for ns := range targets {
			targetKeys = append(targetKeys, ns)
		}
		sort.Strings(targetKeys)

		workloadSummary := summarizeCrossNSWorkloads(snapshot, perms.Subject)

		for _, targetNS := range targetKeys {
			grant := targets[targetNS]
			verbList := sortedKeys(grant.Verbs)
			findingID := fmt.Sprintf("KUBE-SECRETS-CROSSNS-001:%s:%s", perms.Subject.Key(), targetNSKey(targetNS))
			if _, ok := seen[findingID]; ok {
				continue
			}
			content := contentSecretsCrossNS001(perms.Subject, workloadNamespace, targetNS, workloadSummary, grant.SourceRole, grant.SourceBinding)
			findings = appendUnique(findings, seen, crossNSFinding(perms.Subject, targetNS, verbList, grant, findingID, content))
		}
	}

	return findings
}

// crossNSGrant captures the per-(subject, target-namespace) evidence: which
// verbs are granted and which Role/Binding pair brought them in. The first
// matching binding wins for evidence display; the union of verbs is reported
// for the operator's full picture.
type crossNSGrant struct {
	Verbs         map[string]struct{}
	SourceRole    string
	SourceBinding string
}

// ruleGrantsSecretRead reports whether a single aggregated rule lets its
// subject perform any of the read verbs (`get`, `list`, `watch`) on Secrets.
// Wildcard verbs and wildcard resources both count.
func ruleGrantsSecretRead(rule permissions.EffectiveRule) bool {
	if !ruleResourceMatches(rule, "secrets") {
		return false
	}
	for _, verb := range rule.Verbs {
		v := strings.ToLower(verb)
		if v == "*" || v == "get" || v == "list" || v == "watch" {
			return true
		}
	}
	return false
}

// ruleResourceMatches reports whether a rule's Resources list contains the
// given resource or the wildcard. APIGroup is not checked: the secrets
// resource only lives in the core API group, so a rule targeting "secrets"
// always implies the right resource even when APIGroups is left to default.
func ruleResourceMatches(rule permissions.EffectiveRule, resource string) bool {
	for _, candidate := range rule.Resources {
		if candidate == "*" || strings.ToLower(candidate) == resource {
			return true
		}
	}
	return false
}

// workloadNamespacesByServiceAccount returns the namespace each workload-mounted
// ServiceAccount runs in, keyed by SubjectRef.Key(). Only SAs that actually
// have a workload mount them appear here, matching the spec's "a pod's
// ServiceAccount" framing for KUBE-SECRETS-CROSSNS-001.
//
// When the same SA is mounted in workloads across multiple namespaces (rare,
// only possible by mounting a non-default SA reference), we keep the first
// namespace encountered: this is good enough for the cross-namespace flag
// because all namespaces other than the workload's are still cross-ns.
func workloadNamespacesByServiceAccount(snapshot models.Snapshot) map[string]string {
	result := map[string]string{}
	add := func(saName, namespace string) {
		if saName == "" {
			saName = "default"
		}
		ref := models.SubjectRef{Kind: "ServiceAccount", Name: saName, Namespace: namespace}
		key := ref.Key()
		if _, ok := result[key]; !ok {
			result[key] = namespace
		}
	}
	for _, pod := range snapshot.Resources.Pods {
		add(pod.Spec.ServiceAccountName, pod.Namespace)
	}
	for _, deployment := range snapshot.Resources.Deployments {
		add(deployment.Spec.Template.Spec.ServiceAccountName, deployment.Namespace)
	}
	for _, daemonSet := range snapshot.Resources.DaemonSets {
		add(daemonSet.Spec.Template.Spec.ServiceAccountName, daemonSet.Namespace)
	}
	for _, statefulSet := range snapshot.Resources.StatefulSets {
		add(statefulSet.Spec.Template.Spec.ServiceAccountName, statefulSet.Namespace)
	}
	for _, job := range snapshot.Resources.Jobs {
		add(job.Spec.Template.Spec.ServiceAccountName, job.Namespace)
	}
	for _, cronJob := range snapshot.Resources.CronJobs {
		add(cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName, cronJob.Namespace)
	}
	return result
}

// summarizeCrossNSWorkloads renders a one-line list of "<kind>/<name>"
// workloads in the SA's namespace that mount the SA. We deliberately keep
// it brief; the JSON evidence carries enough for tooling.
func summarizeCrossNSWorkloads(snapshot models.Snapshot, subject models.SubjectRef) string {
	type wl struct{ kind, name string }
	out := make([]wl, 0)
	saName := subject.Name
	saNs := subject.Namespace
	matches := func(namespace string, ref string) bool {
		if ref == "" {
			ref = "default"
		}
		return ref == saName && namespace == saNs
	}
	for _, pod := range snapshot.Resources.Pods {
		if matches(pod.Namespace, pod.Spec.ServiceAccountName) {
			out = append(out, wl{"Pod", pod.Name})
		}
	}
	for _, deployment := range snapshot.Resources.Deployments {
		if matches(deployment.Namespace, deployment.Spec.Template.Spec.ServiceAccountName) {
			out = append(out, wl{"Deployment", deployment.Name})
		}
	}
	for _, daemonSet := range snapshot.Resources.DaemonSets {
		if matches(daemonSet.Namespace, daemonSet.Spec.Template.Spec.ServiceAccountName) {
			out = append(out, wl{"DaemonSet", daemonSet.Name})
		}
	}
	for _, statefulSet := range snapshot.Resources.StatefulSets {
		if matches(statefulSet.Namespace, statefulSet.Spec.Template.Spec.ServiceAccountName) {
			out = append(out, wl{"StatefulSet", statefulSet.Name})
		}
	}
	for _, job := range snapshot.Resources.Jobs {
		if matches(job.Namespace, job.Spec.Template.Spec.ServiceAccountName) {
			out = append(out, wl{"Job", job.Name})
		}
	}
	for _, cronJob := range snapshot.Resources.CronJobs {
		if matches(cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName) {
			out = append(out, wl{"CronJob", cronJob.Name})
		}
	}
	if len(out) == 0 {
		return "(no observed workloads)"
	}
	parts := make([]string, 0, len(out))
	for _, w := range out {
		parts = append(parts, w.kind+"/"+w.name)
	}
	return strings.Join(parts, ", ")
}

// crossNSFinding materializes the cross-namespace finding shape. We do not
// reuse secretFinding/configMapFinding because the resource we want to point
// at is the ServiceAccount, not a Secret; mirrors the serviceaccount
// module's newFinding pattern but inlined to keep the secrets package
// self-contained.
func crossNSFinding(subject models.SubjectRef, targetNS string, verbs []string, grant crossNSGrant, findingID string, content ruleContent) models.Finding {
	evidence := map[string]any{
		"target_namespace": targetNS,
		"verbs":            verbs,
		"source_role":      grant.SourceRole,
		"source_binding":   grant.SourceBinding,
	}
	evidenceBytes, _ := json.Marshal(evidence)

	subj := subject
	return models.Finding{
		ID:          findingID,
		RuleID:      "KUBE-SECRETS-CROSSNS-001",
		Severity:    models.SeverityMedium,
		Score:       6.4,
		Category:    models.CategoryLateralMovement,
		Title:       content.Title,
		Description: content.Description,
		Subject:     &subj,
		Namespace:   subject.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "ServiceAccount",
			Name:      subject.Name,
			Namespace: subject.Namespace,
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       referencesFromContent(content),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:secrets", "check:crossNamespaceSecretRead"},
	}
}

// targetNSKey is the suffix used in finding IDs to denote the target
// namespace. ClusterRoleBinding-driven grants have an empty namespace; for
// finding-ID stability we render that as "*" so the canonical key is unique
// and human-readable.
func targetNSKey(targetNS string) string {
	if targetNS == "" {
		return "*"
	}
	return targetNS
}

// sortedKeys returns the deterministic ordering of a string-set's keys.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
