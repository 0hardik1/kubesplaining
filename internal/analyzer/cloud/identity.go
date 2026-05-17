// Package cloud: identity discovery. Walks the snapshot for cloud-IAM identities
// surfaced via IRSA annotations and the aws-auth ConfigMap, and returns them in
// a deduplicated, ARN-sorted slice. The privesc graph builder consumes this set
// to wire IAM-role nodes into the escalation graph; findings about the same
// identities are emitted by the per-rule analyzer files.
package cloud

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// irsaAnnotation is the EKS annotation that binds a ServiceAccount to an IAM
// role. Duplicated here (rather than imported from the eks subpackage) to keep
// internal/analyzer/cloud import-cycle-free: the eks package imports models, and
// nothing else in cloud/ pulls from eks today.
const irsaAnnotation = "eks.amazonaws.com/role-arn"

// awsAuthConfigMapName / Namespace identify the canonical aws-auth ConfigMap
// in kube-system that EKS reads to map IAM principals to Kubernetes groups.
const (
	awsAuthConfigMapName = "aws-auth"
	awsAuthNamespace     = "kube-system"
)

// awsAuthEntry mirrors the schema of a single mapRoles / mapUsers entry in the
// aws-auth ConfigMap. The ConfigMap stores `mapRoles` and `mapUsers` as YAML
// strings (not nested YAML), so we parse each as a list of these structs.
type awsAuthEntry struct {
	RoleARN  string   `yaml:"rolearn,omitempty"`
	UserARN  string   `yaml:"userarn,omitempty"`
	Username string   `yaml:"username,omitempty"`
	Groups   []string `yaml:"groups,omitempty"`
}

// CloudIdentitiesForSnapshot returns the deduplicated, sorted set of cloud
// identities discovered in the snapshot. Sources:
//
//   - ServiceAccount annotations carrying eks.amazonaws.com/role-arn (IRSA).
//   - The kube-system/aws-auth ConfigMap (mapRoles and mapUsers).
//
// When the same ARN appears in both sources, a single CloudIdentity is
// returned with both axes populated (IRSA binding + MappedGroups). YAML parse
// failures on aws-auth are skipped silently: identity.go feeds the privesc
// graph; finding emission lives in the analyzer files.
func CloudIdentitiesForSnapshot(snapshot models.Snapshot) []models.CloudIdentity {
	byARN := make(map[string]*models.CloudIdentity)

	// 1) IRSA-annotated ServiceAccounts.
	for _, sa := range snapshot.Resources.ServiceAccounts {
		arn, ok := sa.Annotations[irsaAnnotation]
		if !ok || arn == "" {
			continue
		}
		accountID, _, roleName, parseOK := parseIAMARN(arn)
		if !parseOK {
			continue
		}
		entry := getOrCreate(byARN, arn, models.CloudIdentity{
			Provider:     "aws",
			Kind:         models.CloudIdentityKindAWSIAMRole,
			ARN:          arn,
			AccountID:    accountID,
			RoleName:     roleName,
			DetectedFrom: "irsa",
		})
		entry.IRSA = &models.IRSABinding{
			ServiceAccountRef: models.SubjectRef{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: sa.Namespace,
			},
		}
	}

	// 2) aws-auth ConfigMap entries.
	for _, cm := range snapshot.Resources.ConfigMaps {
		if cm.Name != awsAuthConfigMapName || cm.Namespace != awsAuthNamespace {
			continue
		}
		// mapRoles: each entry is an IAM role.
		for _, entry := range parseAWSAuthEntries(cm.Data["mapRoles"]) {
			if entry.RoleARN == "" {
				continue
			}
			accountID, _, roleName, parseOK := parseIAMARN(entry.RoleARN)
			if !parseOK {
				continue
			}
			ident := getOrCreate(byARN, entry.RoleARN, models.CloudIdentity{
				Provider:     "aws",
				Kind:         models.CloudIdentityKindAWSIAMRole,
				ARN:          entry.RoleARN,
				AccountID:    accountID,
				RoleName:     roleName,
				DetectedFrom: "aws-auth-mapRoles",
			})
			ident.MappedGroups = mergeStrings(ident.MappedGroups, entry.Groups)
			// If the role was first seen via IRSA, prefer the more specific
			// detected_from for the combined entry: aws-auth-mapRoles + irsa.
			// Keep the original (whichever was set first) so callers can
			// tell which source recorded the entry initially.
		}
		// mapUsers: each entry is an IAM user.
		for _, entry := range parseAWSAuthEntries(cm.Data["mapUsers"]) {
			if entry.UserARN == "" {
				continue
			}
			accountID, _, userName, parseOK := parseIAMARN(entry.UserARN)
			if !parseOK {
				continue
			}
			ident := getOrCreate(byARN, entry.UserARN, models.CloudIdentity{
				Provider:     "aws",
				Kind:         models.CloudIdentityKindAWSIAMUser,
				ARN:          entry.UserARN,
				AccountID:    accountID,
				RoleName:     userName,
				DetectedFrom: "aws-auth-mapUsers",
			})
			ident.MappedGroups = mergeStrings(ident.MappedGroups, entry.Groups)
		}
	}

	// Flatten + sort.
	out := make([]models.CloudIdentity, 0, len(byARN))
	for _, v := range byARN {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ARN < out[j].ARN })
	return out
}

// getOrCreate looks up an entry by ARN; if absent, inserts the seed value and
// returns a pointer to the stored entry so callers can mutate it in place.
func getOrCreate(m map[string]*models.CloudIdentity, arn string, seed models.CloudIdentity) *models.CloudIdentity {
	if existing, ok := m[arn]; ok {
		return existing
	}
	cp := seed
	m[arn] = &cp
	return m[arn]
}

// parseAWSAuthEntries deserializes the YAML-list value of a single aws-auth
// key (e.g. the mapRoles string) into entries. Returns an empty slice on any
// parse error or on empty input; aws-auth misconfiguration is not this
// function's problem.
func parseAWSAuthEntries(value string) []awsAuthEntry {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var entries []awsAuthEntry
	if err := yaml.Unmarshal([]byte(value), &entries); err != nil {
		return nil
	}
	return entries
}

// parseIAMARN extracts (accountID, resourceKind, resourceName, ok) from an
// AWS IAM ARN. Mirrors the eks.ParseARN helper but lives here too so the
// cloud root package doesn't take a dependency on its own eks subpackage.
// Accepts both "role/Name" and "role:Name" resource forms.
func parseIAMARN(arn string) (accountID, kind, name string, ok bool) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" {
		return "", "", "", false
	}
	accountID = parts[4]
	resource := strings.Join(parts[5:], ":")
	if sep := strings.IndexAny(resource, "/:"); sep >= 0 {
		kind = resource[:sep]
		name = resource[sep+1:]
	} else {
		kind = resource
	}
	if kind == "" {
		return "", "", "", false
	}
	return accountID, kind, name, true
}

// mergeStrings appends b's elements to a, dropping duplicates. Order in a is
// preserved; new elements appear in b's order.
func mergeStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	out := append([]string{}, a...)
	for _, s := range b {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
