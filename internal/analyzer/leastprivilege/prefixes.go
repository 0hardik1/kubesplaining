package leastprivilege

import "strings"

// TabRuleIDPrefixes is the canonical set of rule-ID prefixes that surface in the
// "Least Privilege" HTML tab and the `--least-privilege-only` CLI mode. Covers the
// audit-driven narrowing rules (UNUSED-*, WILDCARD-USED-PARTIAL-*) and the static
// stale-binding cleanup rules (STALE-*); operators tightening Roles want both in one
// view because dangling references and unused verbs are flavors of the same "this
// grant is broader than the workload needs" story. KUBE-RBAC-OVERBROAD-001 is
// intentionally absent: cluster-admin bindings have legitimate uses, and the LP tab
// now ships a dedicated "Subjects bound to cluster-admin" inventory table that lets
// operators review the list without each entry being flagged CRITICAL.
var TabRuleIDPrefixes = []string{
	"KUBE-RBAC-UNUSED-",
	"KUBE-RBAC-WILDCARD-USED-PARTIAL-",
	"KUBE-RBAC-STALE-",
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
