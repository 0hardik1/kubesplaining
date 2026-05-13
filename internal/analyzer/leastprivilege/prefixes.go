package leastprivilege

import "strings"

// TabRuleIDPrefixes is the canonical set of rule-ID prefixes that surface in the
// "Least Privilege" HTML tab and the `--least-privilege-only` CLI mode. The list
// includes both the new audit-driven rules and the pre-existing static RBAC cleanup
// rules (`STALE-*`, `OVERBROAD-*`) because operators tightening Roles want them all in
// one view - dangling references, over-broad bindings, and unused verbs are different
// flavors of the same "this grant is broader than the workload needs" story.
var TabRuleIDPrefixes = []string{
	"KUBE-RBAC-UNUSED-",
	"KUBE-RBAC-WILDCARD-USED-PARTIAL-",
	"KUBE-RBAC-STALE-",
	"KUBE-RBAC-OVERBROAD-",
}

// IsLeastPrivilegeRule reports whether ruleID belongs to the least-privilege tab/filter.
// Callers: scan.go's --least-privilege-only post-filter, and the report builder's tab
// section assembly.
func IsLeastPrivilegeRule(ruleID string) bool {
	for _, p := range TabRuleIDPrefixes {
		if strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}
