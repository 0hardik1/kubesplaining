// Package permissions - admin_equivalent.go: detect ClusterRoles that grant
// effective cluster-admin reach, whether by the well-known name "cluster-admin"
// or by a custom name with wildcard verbs+resources+apiGroups. Used by the
// cloud (aws-auth) and privesc (cloud_edges) modules so a CRB binding an
// aws-auth group to a custom super-admin ClusterRole is not missed.
package permissions

import (
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
)

// ClusterAdminRoleName is the canonical name of the built-in ClusterRole that
// grants `verbs:[*]` on `resources:[*]` in `apiGroups:[*]`. Exported so callers
// can avoid sprinkling the literal across the codebase.
const ClusterAdminRoleName = "cluster-admin"

// IsAdminEquivalentClusterRole reports whether the named ClusterRole grants
// effective cluster-admin reach: either it is the built-in "cluster-admin", or
// it contains at least one PolicyRule with `verbs:[*]`, `resources:[*]`, and
// `apiGroups:[*]`. The aws-auth admin rule and the SA->IRSA->aws-auth privesc
// chain both use this to avoid hardcoding the "cluster-admin" literal.
//
// An unknown role name (no matching ClusterRole in the slice) returns false:
// kubesplaining cannot verify reach without the rules, and we prefer a false
// negative over a false positive for an absent role.
func IsAdminEquivalentClusterRole(name string, clusterRoles []rbacv1.ClusterRole) bool {
	if name == ClusterAdminRoleName {
		return true
	}
	for _, cr := range clusterRoles {
		if cr.Name != name {
			continue
		}
		return ClusterRoleHasTripleWildcard(cr)
	}
	return false
}

// ClusterRoleHasTripleWildcard reports whether the given ClusterRole has at
// least one rule with wildcard verbs AND wildcard resources AND wildcard
// apiGroups. That triple is the structural definition of cluster-admin reach;
// a role with only `verbs:[*]` on a narrow resource list does NOT qualify.
func ClusterRoleHasTripleWildcard(cr rbacv1.ClusterRole) bool {
	for _, rule := range cr.Rules {
		if slices.Contains(rule.Verbs, "*") &&
			slices.Contains(rule.Resources, "*") &&
			slices.Contains(rule.APIGroups, "*") {
			return true
		}
	}
	return false
}
