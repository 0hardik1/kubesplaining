// Package compliance maps Kubesplaining rule IDs to controls in the external compliance
// and hardening frameworks enterprise auditors expect to see (CIS Kubernetes Benchmark v1.9
// and NSA/CISA Kubernetes Hardening Guide v1.2). The table is decorated onto findings after
// analysis so JSON/CSV/SARIF/HTML consumers can filter or group by framework without each
// analyzer re-deriving the mapping.
//
// Single source of truth: edit ruleControls below to add or rename a control. The mapping
// is intentionally hand-maintained — the universe of rules is small enough that an explicit
// table is more honest than a heuristic, and the entries serve as documentation when a new
// rule is added (the next maintainer can see how peers are tagged).
package compliance

import (
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// Framework slugs used in FrameworkRef.Framework. Stable strings — consumers (the
// --compliance flag, the HTML tab data attribute) match against these.
const (
	FrameworkCIS19 = "CIS-1.9"      // CIS Kubernetes Benchmark v1.9
	FrameworkNSA   = "NSA-CISA-1.2" // NSA/CISA Kubernetes Hardening Guide v1.2
)

// FrameworkInfo carries display-only metadata for a framework slug; used by the HTML
// report's Compliance tab to render readable headings and link to the source document.
type FrameworkInfo struct {
	Slug      string
	Name      string // long human-readable name shown in the report
	ShortName string // short label shown in chips, tab counts
	URL       string // link to the published framework document
}

// Frameworks returns the registered frameworks in canonical display order. The slugs
// returned here are the same strings consumers pass via --compliance.
func Frameworks() []FrameworkInfo {
	return []FrameworkInfo{
		{
			Slug:      FrameworkCIS19,
			Name:      "CIS Kubernetes Benchmark v1.9",
			ShortName: "CIS v1.9",
			URL:       "https://www.cisecurity.org/benchmark/kubernetes",
		},
		{
			Slug:      FrameworkNSA,
			Name:      "NSA/CISA Kubernetes Hardening Guide v1.2",
			ShortName: "NSA / CISA",
			URL:       "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF",
		},
	}
}

// ResolveFramework returns the canonical slug for a user-supplied framework filter value,
// accepting case-insensitive matches against either the slug or a short alias ("cis", "nsa").
// Returns "" when the input does not name any registered framework.
func ResolveFramework(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	switch trimmed {
	case "":
		return ""
	case "cis", "cis-1.9", "cis1.9", "cis-kubernetes", "cis-kubernetes-1.9":
		return FrameworkCIS19
	case "nsa", "nsa-cisa", "nsa-cisa-1.2", "nsa/cisa", "hardening-guide":
		return FrameworkNSA
	}
	for _, f := range Frameworks() {
		if strings.EqualFold(value, f.Slug) {
			return f.Slug
		}
	}
	return ""
}

// cis is a constructor shortcut for a CIS Kubernetes Benchmark v1.9 control.
func cis(control, title string) models.FrameworkRef {
	return models.FrameworkRef{
		Framework: FrameworkCIS19,
		Control:   control,
		Title:     title,
		URL:       "https://www.cisecurity.org/benchmark/kubernetes",
	}
}

// nsa is a constructor shortcut for an NSA/CISA Kubernetes Hardening Guide v1.2 section.
func nsa(section, title string) models.FrameworkRef {
	return models.FrameworkRef{
		Framework: FrameworkNSA,
		Control:   section,
		Title:     title,
		URL:       "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF",
	}
}

// ruleControls is the canonical rule-ID → framework-control mapping. Add an entry for any
// new rule; rules without an entry simply ship without compliance tags (the report drops
// them from the Compliance tab but they remain in every other view). When a rule has
// multiple natural CIS or NSA controls listed, include all of them — the Compliance tab
// counts each (framework, control) pair independently.
var ruleControls = map[string][]models.FrameworkRef{
	// --- RBAC -------------------------------------------------------------------

	"KUBE-PRIVESC-001": {
		cis("5.1.4", "Minimize access to create pods"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-003": {
		cis("5.1.4", "Minimize access to create pods"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-005": {
		cis("5.1.2", "Minimize access to secrets"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-008": {
		cis("5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-009": {
		cis("5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-010": {
		cis("5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-012": {
		cis("5.1.4", "Minimize access to create pods"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-014": {
		cis("5.1.5", "Ensure that default service accounts are not actively used"),
		nsa("Authentication", "Service account tokens"),
	},
	"KUBE-PRIVESC-017": {
		cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-RBAC-OVERBROAD-001": {
		cis("5.1.1", "Ensure that the cluster-admin role is only used where required"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-RBAC-STALE-001": {
		cis("5.1.1", "Ensure that the cluster-admin role is only used where required"),
	},
	"KUBE-RBAC-STALE-002": {
		cis("5.1.1", "Ensure that the cluster-admin role is only used where required"),
	},

	// --- Least Privilege (audit-driven recommendations) -------------------------

	"KUBE-RBAC-UNUSED-ROLE-001": {
		cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-RBAC-UNUSED-RULE-001": {
		cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles"),
	},
	"KUBE-RBAC-UNUSED-VERB-001": {
		cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles"),
	},
	"KUBE-RBAC-WILDCARD-USED-PARTIAL-001": {
		cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles"),
	},

	// --- Pod Security ------------------------------------------------------------

	"KUBE-ESCAPE-001": {
		cis("5.2.1", "Minimize the admission of privileged containers"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-ESCAPE-002": {
		cis("5.2.2", "Minimize the admission of containers wishing to share the host process ID namespace"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-ESCAPE-003": {
		cis("5.2.4", "Minimize the admission of containers wishing to share the host network namespace"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-ESCAPE-004": {
		cis("5.2.3", "Minimize the admission of containers wishing to share the host IPC namespace"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-ESCAPE-005": {
		cis("5.2.12", "Minimize the admission of HostPath volumes"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-ESCAPE-006": {
		cis("5.2.12", "Minimize the admission of HostPath volumes"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-ESCAPE-008": {
		cis("5.2.12", "Minimize the admission of HostPath volumes"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-CONTAINERD-SOCKET-001": {
		cis("5.2.12", "Minimize the admission of HostPath volumes"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-HOSTPATH-001": {
		cis("5.2.12", "Minimize the admission of HostPath volumes"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-PODSEC-APE-001": {
		cis("5.2.5", "Minimize the admission of containers with allowPrivilegeEscalation"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-PODSEC-PROCMOUNT-001": {
		cis("5.2.1", "Minimize the admission of privileged containers"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-PODSEC-ROOT-001": {
		cis("5.2.6", "Minimize the admission of root containers"),
		nsa("Pod Security", "Non-root containers and rootless container engines"),
	},
	"KUBE-PODSEC-READONLY-001": {
		cis("5.7.3", "Apply Security Context to Your Pods and Containers"),
		nsa("Pod Security", "Immutable container file systems"),
	},
	"KUBE-PODSEC-SECCOMP-001": {
		cis("5.7.2", "Ensure that the seccomp profile is set to docker/default in your pod definitions"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-SA-DEFAULT-001": {
		cis("5.1.5", "Ensure that default service accounts are not actively used"),
		nsa("Authentication", "Service account tokens"),
	},
	"KUBE-IMAGE-LATEST-001": {
		nsa("Pod Security", "Image scanning"),
	},
	"KUBE-PV-HOSTPATH-001": {
		cis("5.2.12", "Minimize the admission of HostPath volumes"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-PSA-LABELS-001": {
		cis("5.2.1", "Minimize the admission of privileged containers"),
		nsa("Pod Security", "Pod Security Standards / Pod Security Admission"),
	},

	// --- Network Policy ----------------------------------------------------------

	"KUBE-NETPOL-COVERAGE-001": {
		cis("5.3.2", "Ensure that all Namespaces have NetworkPolicies defined"),
		nsa("Network Separation and Hardening", "Network policies"),
	},
	"KUBE-NETPOL-COVERAGE-002": {
		cis("5.3.2", "Ensure that all Namespaces have NetworkPolicies defined"),
		nsa("Network Separation and Hardening", "Network policies"),
	},
	"KUBE-NETPOL-COVERAGE-003": {
		cis("5.3.2", "Ensure that all Namespaces have NetworkPolicies defined"),
		nsa("Network Separation and Hardening", "Network policies"),
	},
	"KUBE-NETPOL-WEAKNESS-001": {
		nsa("Network Separation and Hardening", "Network policies"),
	},
	"KUBE-NETPOL-WEAKNESS-002": {
		nsa("Network Separation and Hardening", "Network policies"),
	},

	// --- Admission Webhooks -----------------------------------------------------

	"KUBE-ADMISSION-001": {
		cis("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller"),
		nsa("Pod Security", "Admission controllers"),
	},
	"KUBE-ADMISSION-002": {
		nsa("Pod Security", "Admission controllers"),
	},
	"KUBE-ADMISSION-003": {
		nsa("Pod Security", "Admission controllers"),
	},
	"KUBE-ADMISSION-NO-POLICY-ENGINE-001": {
		cis("5.2", "Pod Security Standards"),
		nsa("Pod Security", "Admission controllers"),
	},

	// --- Secrets & ConfigMaps ---------------------------------------------------

	"KUBE-SECRETS-001": {
		cis("5.1.5", "Ensure that default service accounts are not actively used"),
		nsa("Authentication", "Service account tokens"),
	},
	"KUBE-SECRETS-002": {
		cis("5.4.1", "Prefer using Secrets as files over Secrets as environment variables"),
		nsa("Pod Security", "Secrets"),
	},
	"KUBE-CONFIGMAP-001": {
		cis("5.4.2", "Consider external secret storage"),
		nsa("Pod Security", "Secrets"),
	},
	"KUBE-CONFIGMAP-002": {
		nsa("Network Separation and Hardening", "Control plane hardening"),
	},

	// --- Service Account --------------------------------------------------------

	"KUBE-SA-PRIVILEGED-001": {
		cis("5.1.3", "Minimize wildcard use in Roles and ClusterRoles"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-SA-PRIVILEGED-002": {
		cis("5.1.6", "Ensure that Service Account Tokens are only mounted where necessary"),
		nsa("Authentication", "Service account tokens"),
	},
	"KUBE-SA-DEFAULT-002": {
		cis("5.1.5", "Ensure that default service accounts are not actively used"),
		nsa("Authentication", "Service account tokens"),
	},
	"KUBE-SA-DAEMONSET-001": {
		cis("5.1.6", "Ensure that Service Account Tokens are only mounted where necessary"),
		nsa("Authentication", "Service account tokens"),
	},

	// --- Privesc graph paths ----------------------------------------------------
	// Graph paths inherit their seed rule's controls implicitly, but operators want them
	// to show up directly in compliance views (auditors care about "can anyone reach
	// cluster-admin?" as a standalone bullet, not just the seed permission).

	"KUBE-PRIVESC-PATH-CLUSTER-ADMIN": {
		cis("5.1.1", "Ensure that the cluster-admin role is only used where required"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-PATH-SYSTEM-MASTERS": {
		cis("5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-PATH-NODE-ESCAPE": {
		cis("5.2.1", "Minimize the admission of privileged containers"),
		nsa("Pod Security", "Application security: securityContext"),
	},
	"KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS": {
		cis("5.1.2", "Minimize access to secrets"),
		nsa("Authorization", "Role-based access control"),
	},
	"KUBE-PRIVESC-PATH-NAMESPACE-ADMIN": {
		cis("5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster"),
		nsa("Authorization", "Role-based access control"),
	},
}

// ControlsFor returns the registered framework controls for a rule ID, or nil when no entry
// exists. The returned slice MUST be treated as read-only by callers; Apply copies it onto
// each finding so per-finding mutations are isolated.
func ControlsFor(ruleID string) []models.FrameworkRef {
	return ruleControls[ruleID]
}

// Apply decorates each finding with its framework controls in-place. Findings whose rule has
// no mapping are left with a nil Frameworks slice. Apply is idempotent — calling it twice
// re-overwrites the slice with a fresh copy, so a downstream pass that adds/removes findings
// does not have to undo it.
func Apply(findings []models.Finding) []models.Finding {
	for i := range findings {
		controls := ruleControls[findings[i].RuleID]
		if len(controls) == 0 {
			findings[i].Frameworks = nil
			continue
		}
		copyOf := make([]models.FrameworkRef, len(controls))
		copy(copyOf, controls)
		findings[i].Frameworks = copyOf
	}
	return findings
}

// HasFramework reports whether a finding carries at least one control for the given framework
// slug. Used by the --compliance CLI filter to drop findings the operator did not ask about.
func HasFramework(f models.Finding, frameworkSlug string) bool {
	for _, ref := range f.Frameworks {
		if ref.Framework == frameworkSlug {
			return true
		}
	}
	return false
}

// FilterByFramework returns a new slice containing only findings tagged with any of the
// given framework slugs. An empty `frameworks` returns the input unchanged so callers can
// pass the parsed flag value directly without branching on emptiness. Unknown framework
// slugs match nothing — the caller is responsible for resolving aliases via ResolveFramework
// before reaching here.
func FilterByFramework(findings []models.Finding, frameworks []string) []models.Finding {
	if len(frameworks) == 0 {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		for _, want := range frameworks {
			if HasFramework(f, want) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}
