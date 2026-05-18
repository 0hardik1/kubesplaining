// Package eks - aws-auth ConfigMap analysis. Detects IAM principals mapped via
// kube-system/aws-auth to system:masters or to custom groups that themselves
// have cluster-admin reach via ClusterRoleBindings. Emits the
// KUBE-CLOUD-AWSAUTH-* rule family.
package eks

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	"gopkg.in/yaml.v3"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	awsAuthNamespace  = "kube-system"
	awsAuthConfigMap  = "aws-auth"
	awsAuthKeyRoles   = "mapRoles"
	awsAuthKeyUsers   = "mapUsers"
	groupSystemMaster = "system:masters"
	clusterAdminRole  = "cluster-admin"

	ruleSystemMasters = "KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001"
	ruleOverbroad     = "KUBE-CLOUD-AWSAUTH-OVERBROAD-001"
	ruleParseError    = "KUBE-CLOUD-AWSAUTH-PARSE-ERROR-001"
)

// awsAuthEntry mirrors one element of the YAML list stored under mapRoles /
// mapUsers in the aws-auth ConfigMap. Both ARN flavors share the same field
// set; we parse RoleARN and UserARN independently and pick whichever is set.
type awsAuthEntry struct {
	RoleARN  string   `yaml:"rolearn"`
	UserARN  string   `yaml:"userarn"`
	Username string   `yaml:"username"`
	Groups   []string `yaml:"groups"`
}

// AnalyzeAWSAuth returns aws-auth findings for the given snapshot.
// Returns nil if no aws-auth ConfigMap is present in kube-system.
func AnalyzeAWSAuth(snapshot models.Snapshot) []models.Finding {
	cm, ok := findAWSAuthConfigMap(snapshot)
	if !ok {
		return nil
	}

	var findings []models.Finding

	// Index ClusterRoleBindings by group name for the overbroad lookup. We
	// build this index once even when no custom groups are present; in the
	// hot path (only system:masters mappings, which is the more common
	// misconfig), the map is built but never queried.
	crbsByGroup := indexClusterRoleBindingsByGroup(snapshot.Resources.ClusterRoleBindings, snapshot.Resources.ClusterRoles)

	for _, key := range []string{awsAuthKeyRoles, awsAuthKeyUsers} {
		raw, present := cm.Data[key]
		if !present || strings.TrimSpace(raw) == "" {
			continue
		}
		entries, err := parseAWSAuthEntries(raw)
		if err != nil {
			findings = append(findings, parseErrorFinding(cm, key, err))
			continue
		}
		for _, entry := range entries {
			arn := entryARN(entry, key)
			if arn == "" {
				continue
			}
			if containsGroup(entry.Groups, groupSystemMaster) {
				findings = append(findings, systemMastersFinding(cm, key, arn, entry))
				continue
			}
			for _, group := range entry.Groups {
				if group == "" {
					continue
				}
				match, hit := crbsByGroup[group]
				if !hit {
					continue
				}
				findings = append(findings, overbroadFinding(cm, key, arn, entry, group, match))
				// Only emit one overbroad finding per (arn, entry); the
				// first admin-bound group wins. Tags / Evidence still
				// surface the specific binding.
				break
			}
		}
	}

	return findings
}

// findAWSAuthConfigMap returns the canonical kube-system/aws-auth ConfigMap
// from the snapshot, or false if not present. Off-namespace copies (e.g.
// default/aws-auth) are intentionally ignored: the EKS API server only reads
// the one in kube-system.
func findAWSAuthConfigMap(snapshot models.Snapshot) (models.ConfigMapSnapshot, bool) {
	for _, cm := range snapshot.Resources.ConfigMaps {
		if cm.Namespace == awsAuthNamespace && cm.Name == awsAuthConfigMap {
			return cm, true
		}
	}
	return models.ConfigMapSnapshot{}, false
}

// parseAWSAuthEntries unmarshals the YAML list stored under mapRoles /
// mapUsers. The aws-auth ConfigMap uses a YAML sequence even though the
// outer ConfigMap is itself a Kubernetes object, so we run yaml.Unmarshal on
// the raw string value.
func parseAWSAuthEntries(raw string) ([]awsAuthEntry, error) {
	var entries []awsAuthEntry
	if err := yaml.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// entryARN selects the ARN field appropriate for the source key (mapRoles
// uses rolearn, mapUsers uses userarn). Falling back to the other field
// keeps us robust against the occasional human edit that mixes the two.
func entryARN(entry awsAuthEntry, key string) string {
	switch key {
	case awsAuthKeyRoles:
		if entry.RoleARN != "" {
			return entry.RoleARN
		}
		return entry.UserARN
	case awsAuthKeyUsers:
		if entry.UserARN != "" {
			return entry.UserARN
		}
		return entry.RoleARN
	default:
		return ""
	}
}

// containsGroup reports whether the given group name appears (case-sensitive)
// in the entry's group list.
func containsGroup(groups []string, target string) bool {
	for _, g := range groups {
		if g == target {
			return true
		}
	}
	return false
}

// adminGroupBinding records the ClusterRoleBinding (and the ClusterRole it
// points at) that gives a Group subject effective cluster-admin reach. The
// role name is surfaced in evidence because, with custom wildcard ClusterRoles
// in play, "via binding X" alone is ambiguous: an operator wants to know
// whether the path is through the built-in `cluster-admin` or through a
// homemade `*/*/*` role they may not have realized exists.
type adminGroupBinding struct {
	BindingName string
	RoleName    string
}

// indexClusterRoleBindingsByGroup builds a map of Group name -> binding/role
// info for every ClusterRoleBinding that grants effective cluster-admin reach
// to a Group subject. A ClusterRole is "admin-equivalent" when it is either
// the built-in `cluster-admin` or when it contains a `verbs:[*], resources:[*],
// apiGroups:[*]` rule (see permissions.IsAdminEquivalentClusterRole). We
// deliberately key by the first matching binding only; evidence carries the
// binding and role names so the operator can audit the specific grant.
func indexClusterRoleBindingsByGroup(crbs []rbacv1.ClusterRoleBinding, clusterRoles []rbacv1.ClusterRole) map[string]adminGroupBinding {
	index := make(map[string]adminGroupBinding)
	for _, crb := range crbs {
		if crb.RoleRef.Kind != "ClusterRole" {
			continue
		}
		if !permissions.IsAdminEquivalentClusterRole(crb.RoleRef.Name, clusterRoles) {
			continue
		}
		for _, sub := range crb.Subjects {
			if sub.Kind != "Group" || sub.Name == "" {
				continue
			}
			if _, seen := index[sub.Name]; !seen {
				index[sub.Name] = adminGroupBinding{BindingName: crb.Name, RoleName: crb.RoleRef.Name}
			}
		}
	}
	return index
}

// sanitizeARN turns an ARN into a Finding.ID-safe suffix. The canonical
// pattern is "Rule:ns:name"; for cluster-scoped aws-auth findings we use
// "Rule:<sanitizedARN>" so each principal gets a stable, parseable ID.
func sanitizeARN(arn string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_")
	return replacer.Replace(arn)
}

// systemMastersFinding builds the KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001
// finding for an aws-auth entry that maps an IAM principal directly to the
// built-in system:masters group (apiserver-side cluster-admin).
func systemMastersFinding(cm models.ConfigMapSnapshot, key, arn string, entry awsAuthEntry) models.Finding {
	content := contentAWSAuthSystemMasters()
	evidence := map[string]any{
		"arn":             arn,
		"mappedUsername":  entry.Username,
		"mappedGroups":    entry.Groups,
		"sourceConfigMap": fmt.Sprintf("%s/%s", cm.Namespace, cm.Name),
		"entryType":       key,
	}
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s", ruleSystemMasters, sanitizeARN(arn)),
		RuleID:      ruleSystemMasters,
		Severity:    models.SeverityHigh,
		Score:       scoring.Clamp(8.6),
		Category:    models.CategoryPrivilegeEscalation,
		Title:       content.Title,
		Description: content.Description,
		Subject: &models.SubjectRef{
			Kind: "User",
			Name: arn,
		},
		Resource: &models.ResourceRef{
			Kind:      "ConfigMap",
			Name:      cm.Name,
			Namespace: cm.Namespace,
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       learnMoreURLs(content.LearnMore),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:cloud", "module:rbac", "provider:eks", "check:awsAuth"},
	}
}

// overbroadFinding builds the KUBE-CLOUD-AWSAUTH-OVERBROAD-001 finding for an
// aws-auth entry whose custom group (not system:masters) is bound to a
// cluster-admin-equivalent ClusterRole. The viaBinding evidence field names
// the specific binding, and viaClusterRole names the ClusterRole behind it so
// the operator can tell a built-in `cluster-admin` path from a custom
// triple-wildcard role.
func overbroadFinding(cm models.ConfigMapSnapshot, key, arn string, entry awsAuthEntry, group string, match adminGroupBinding) models.Finding {
	content := contentAWSAuthOverbroad()
	evidence := map[string]any{
		"arn":             arn,
		"mappedUsername":  entry.Username,
		"mappedGroups":    []string{group},
		"sourceConfigMap": fmt.Sprintf("%s/%s", cm.Namespace, cm.Name),
		"entryType":       key,
		"viaBinding":      match.BindingName,
		"viaClusterRole":  match.RoleName,
	}
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s", ruleOverbroad, sanitizeARN(arn)),
		RuleID:      ruleOverbroad,
		Severity:    models.SeverityMedium,
		Score:       scoring.Clamp(6.2),
		Category:    models.CategoryPrivilegeEscalation,
		Title:       content.Title,
		Description: content.Description,
		Subject: &models.SubjectRef{
			Kind: "User",
			Name: arn,
		},
		Resource: &models.ResourceRef{
			Kind:      "ConfigMap",
			Name:      cm.Name,
			Namespace: cm.Namespace,
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       learnMoreURLs(content.LearnMore),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:cloud", "module:rbac", "provider:eks", "check:awsAuth"},
	}
}

// parseErrorFinding emits a single INFO-severity diagnostic when the aws-auth
// ConfigMap contains an unparseable mapRoles / mapUsers payload. The intent
// is to surface the malformed key without crashing the analyzer; operators
// see a low-noise heads-up that one of their detectors did not run.
func parseErrorFinding(cm models.ConfigMapSnapshot, key string, err error) models.Finding {
	evidence := map[string]any{
		"sourceConfigMap": fmt.Sprintf("%s/%s", cm.Namespace, cm.Name),
		"malformedKey":    key,
		"parseError":      err.Error(),
	}
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", ruleParseError, cm.Namespace, key),
		RuleID:      ruleParseError,
		Severity:    models.SeverityInfo,
		Score:       scoring.Clamp(1.0),
		Category:    models.CategoryDefenseEvasion,
		Title:       fmt.Sprintf("aws-auth ConfigMap contains malformed YAML in key %q", key),
		Description: fmt.Sprintf("The %q key in %s/%s could not be parsed as a YAML list of aws-auth entries (%v). The downstream KUBE-CLOUD-AWSAUTH-* detectors skip this key, so any privilege escalations expressed through it are NOT surfaced. Fix the YAML to restore coverage.", key, cm.Namespace, cm.Name, err),
		Resource: &models.ResourceRef{
			Kind:      "ConfigMap",
			Name:      cm.Name,
			Namespace: cm.Namespace,
		},
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("ConfigMap %s/%s", cm.Namespace, cm.Name),
		},
		Impact:      "Aws-auth analyzer coverage is partially blind: IAM-principal-to-cluster-admin mappings via this key are not detected until the YAML parses.",
		Evidence:    evidenceBytes,
		Remediation: "Repair the malformed YAML under the offending key in the aws-auth ConfigMap so kubesplaining can re-evaluate it.",
		RemediationSteps: []string{
			fmt.Sprintf("Run `kubectl -n %s get configmap %s -o yaml` and inspect the %q key.", cm.Namespace, cm.Name, key),
			"Validate the YAML locally (yamllint, yq) before re-applying. The expected shape is a list of objects with rolearn/userarn, username, groups.",
			fmt.Sprintf("Re-apply with `kubectl -n %s edit configmap %s` or via your IaC pipeline, then re-run kubesplaining.", cm.Namespace, cm.Name),
		},
		Tags: []string{"module:cloud", "provider:eks", "check:awsAuthParse"},
	}
}

// learnMoreURLs flattens the structured LearnMore references into a slice of
// URLs for the legacy Finding.References field. Mirrors the helper used by
// the network analyzer so JSON / CSV / SARIF consumers see both the
// structured and the flat shape.
func learnMoreURLs(refs []models.Reference) []string {
	urls := make([]string, 0, len(refs))
	for _, r := range refs {
		urls = append(urls, r.URL)
	}
	return urls
}
