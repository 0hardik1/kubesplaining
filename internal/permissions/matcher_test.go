package permissions

import "testing"

func TestGrantsAPIGroupAwareness(t *testing.T) {
	tests := []struct {
		name      string
		apiGroups []string
		resources []string
		verbs     []string
		targets   []ResourceTarget
		want      []string
		expect    bool
	}{
		{
			name:      "core secrets matches core target",
			apiGroups: []string{""}, resources: []string{"secrets"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
		{
			name:      "custom-group secrets does not match core secrets",
			apiGroups: []string{"example.com"}, resources: []string{"secrets"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: false,
		},
		{
			name:      "wildcard apiGroup matches core target",
			apiGroups: []string{"*"}, resources: []string{"secrets"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
		{
			name:      "rbac group required for rolebindings",
			apiGroups: []string{""}, resources: []string{"rolebindings"}, verbs: []string{"create"},
			targets: []ResourceTarget{InGroup("rbac.authorization.k8s.io", "rolebindings")}, want: []string{"create"}, expect: false,
		},
		{
			name:      "rbac group matches rolebindings",
			apiGroups: []string{"rbac.authorization.k8s.io"}, resources: []string{"rolebindings"}, verbs: []string{"patch"},
			targets: []ResourceTarget{InGroup("rbac.authorization.k8s.io", "rolebindings")}, want: []string{"create", "update", "patch"}, expect: true,
		},
		{
			name:      "wildcard resource matches any target in the group",
			apiGroups: []string{""}, resources: []string{"*"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
		{
			name:      "verb must also match",
			apiGroups: []string{""}, resources: []string{"secrets"}, verbs: []string{"list"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Grants(tt.apiGroups, tt.resources, tt.verbs, nil, tt.targets, tt.want)
			if got != tt.expect {
				t.Errorf("Grants() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestGrantsResourceNamesSemantics(t *testing.T) {
	names := []string{"my-object"}
	tests := []struct {
		name      string
		resources []string
		verbs     []string
		targets   []ResourceTarget
		want      []string
		expect    bool
	}{
		{
			name:      "list on named collection is voided (cannot enumerate)",
			resources: []string{"secrets"}, verbs: []string{"list"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"list"}, expect: false,
		},
		{
			name:      "watch on named collection is voided",
			resources: []string{"secrets"}, verbs: []string{"watch"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"watch"}, expect: false,
		},
		{
			name:      "create on top-level resource is voided (no name at authz time)",
			resources: []string{"pods"}, verbs: []string{"create"},
			targets: []ResourceTarget{Core("pods")}, want: []string{"create"}, expect: false,
		},
		{
			name:      "deletecollection is voided",
			resources: []string{"secrets"}, verbs: []string{"deletecollection"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"deletecollection"}, expect: false,
		},
		{
			name:      "get on named object still matches (scoped read)",
			resources: []string{"secrets"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
		{
			name:      "update/patch on named object still matches",
			resources: []string{"secrets"}, verbs: []string{"patch"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"update", "patch"}, expect: true,
		},
		{
			name:      "impersonate scoped to named identity still matches (still dangerous)",
			resources: []string{"groups"}, verbs: []string{"impersonate"},
			targets: []ResourceTarget{Core("groups")}, want: []string{"impersonate"}, expect: true,
		},
		{
			name:      "create on a subresource is name-scopable (parent name in URL)",
			resources: []string{"serviceaccounts/token"}, verbs: []string{"create"},
			targets: []ResourceTarget{Core("serviceaccounts/token")}, want: []string{"create"}, expect: true,
		},
		{
			name:      "exec (create on pods/exec) is name-scopable",
			resources: []string{"pods/exec"}, verbs: []string{"create"},
			targets: []ResourceTarget{Core("pods/exec")}, want: []string{"create", "get"}, expect: true,
		},
		{
			name:      "wildcard verb does not resurrect a voided list",
			resources: []string{"secrets"}, verbs: []string{"*"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"list"}, expect: false,
		},
		{
			name:      "wildcard verb still authorizes a name-scopable get",
			resources: []string{"secrets"}, verbs: []string{"*"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Grants([]string{""}, tt.resources, tt.verbs, names, tt.targets, tt.want)
			if got != tt.expect {
				t.Errorf("Grants(resourceNames=%v) = %v, want %v", names, got, tt.expect)
			}
		})
	}
}

func TestEffectiveRuleGrantsAndNameScoped(t *testing.T) {
	unrestricted := EffectiveRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}}
	if unrestricted.NameScoped() {
		t.Error("rule without resourceNames should not report NameScoped")
	}
	if !unrestricted.Grants([]ResourceTarget{Core("secrets")}, "list") {
		t.Error("unrestricted list secrets should grant")
	}

	scoped := EffectiveRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list", "get"}, ResourceNames: []string{"tls"}}
	if !scoped.NameScoped() {
		t.Error("rule with resourceNames should report NameScoped")
	}
	if scoped.Grants([]ResourceTarget{Core("secrets")}, "list") {
		t.Error("name-scoped list secrets must not grant enumeration")
	}
	if !scoped.Grants([]ResourceTarget{Core("secrets")}, "get") {
		t.Error("name-scoped get secrets should still grant a scoped read")
	}
}

// TestSignersCoveredNameGrammar pins the signer-name grammar, which is the one place
// resourceNames does NOT mean "these object instances". For the virtual `signers`
// resource the names are signerNames, with their own wildcard forms, so an
// unrestricted rule covers every signer while a rule pinned to somebody else's
// signer covers none of the ones that matter.
func TestSignersCoveredNameGrammar(t *testing.T) {
	tests := []struct {
		name          string
		apiGroups     []string
		resources     []string
		verbs         []string
		resourceNames []string
		wantedVerbs   []string
		want          []string
	}{
		{
			name:      "no resourceNames covers every client-auth signer",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			wantedVerbs: []string{"sign"}, want: ClientAuthSigners,
		},
		{
			name:      "exact signer name",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"approve"},
			resourceNames: []string{SignerAPIServerClient}, wantedVerbs: []string{"approve"},
			want: []string{SignerAPIServerClient},
		},
		{
			name:      "domain wildcard covers the whole kubernetes.io family",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			resourceNames: []string{"kubernetes.io/*"}, wantedVerbs: []string{"sign"}, want: ClientAuthSigners,
		},
		{
			name:      "*/* covers everything",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			resourceNames: []string{"*/*"}, wantedVerbs: []string{"sign"}, want: ClientAuthSigners,
		},
		{
			name:      "third-party signer covers none of the apiserver-trusted ones",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			resourceNames: []string{"example.com/my-signer"}, wantedVerbs: []string{"sign"}, want: nil,
		},
		{
			name:      "third-party domain wildcard covers none either",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			resourceNames: []string{"example.com/*"}, wantedVerbs: []string{"sign"}, want: nil,
		},
		{
			name:      "wrong verb grants nothing",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"get", "list"},
			wantedVerbs: []string{"sign"}, want: nil,
		},
		{
			name:      "wrong API group grants nothing (a CRD named signers is not this one)",
			apiGroups: []string{"example.com"}, resources: []string{"signers"}, verbs: []string{"sign"},
			wantedVerbs: []string{"sign"}, want: nil,
		},
		{
			name:      "verb wildcard authorizes sign",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"*"},
			resourceNames: []string{SignerAPIServerClientKubelet}, wantedVerbs: []string{"sign"},
			want: []string{SignerAPIServerClientKubelet},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SignersCovered(tt.apiGroups, tt.resources, tt.verbs, tt.resourceNames, ClientAuthSigners, tt.wantedVerbs)
			if len(got) != len(tt.want) {
				t.Fatalf("SignersCovered() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("SignersCovered() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TestGrantsSubresourceWildcard pins the resources-axis grammar of ResourceMatches in
// kubernetes/kubernetes pkg/apis/rbac/v1/evaluation_helpers.go. "*/sub" matches that
// subresource of every resource, and nothing else. "resource/*" is not a wildcard
// upstream (it is compared as a literal string), so it must not match here either.
func TestGrantsSubresourceWildcard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		apiGroups []string
		resources []string
		verbs     []string
		target    ResourceTarget
		want      string
		expect    bool
	}{
		{
			name:      "*/status grants update on nodes/status",
			apiGroups: []string{""}, resources: []string{"*/status"}, verbs: []string{"update"},
			target: Core("nodes/status"), want: "update", expect: true,
		},
		{
			name:      "*/status grants update on certificatesigningrequests/status",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"*/status"}, verbs: []string{"update"},
			target: InGroup("certificates.k8s.io", "certificatesigningrequests/status"), want: "update", expect: true,
		},
		{
			name:      "*/exec grants create on pods/exec",
			apiGroups: []string{""}, resources: []string{"*/exec"}, verbs: []string{"create"},
			target: Core("pods/exec"), want: "create", expect: true,
		},
		{
			name:      "*/token grants create on serviceaccounts/token",
			apiGroups: []string{""}, resources: []string{"*/token"}, verbs: []string{"create"},
			target: Core("serviceaccounts/token"), want: "create", expect: true,
		},
		{
			name:      "*/exec does not grant the top-level pods resource",
			apiGroups: []string{""}, resources: []string{"*/exec"}, verbs: []string{"create"},
			target: Core("pods"), want: "create", expect: false,
		},
		{
			name:      "*/exec does not grant a different subresource",
			apiGroups: []string{""}, resources: []string{"*/exec"}, verbs: []string{"create"},
			target: Core("pods/attach"), want: "create", expect: false,
		},
		{
			name:      "pods/* is not a wildcard (Kubernetes has no resource/* form)",
			apiGroups: []string{""}, resources: []string{"pods/*"}, verbs: []string{"create"},
			target: Core("pods/exec"), want: "create", expect: false,
		},
		{
			name:      "*/status still needs the API group to match",
			apiGroups: []string{""}, resources: []string{"*/status"}, verbs: []string{"update"},
			target: InGroup("certificates.k8s.io", "certificatesigningrequests/status"), want: "update", expect: false,
		},
		{
			name:      "*/status still needs the verb to match",
			apiGroups: []string{""}, resources: []string{"*/status"}, verbs: []string{"get"},
			target: Core("nodes/status"), want: "update", expect: false,
		},
		{
			name:      "*/sub matches a subresource that itself contains a slash",
			apiGroups: []string{"authentication.k8s.io"}, resources: []string{"*/example.com/scopes"}, verbs: []string{"impersonate"},
			target: InGroup("authentication.k8s.io", "userextras/example.com/scopes"), want: "impersonate", expect: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Grants(tt.apiGroups, tt.resources, tt.verbs, nil, []ResourceTarget{tt.target}, []string{tt.want})
			if got != tt.expect {
				t.Errorf("Grants(resources=%v, target=%v) = %v, want %v", tt.resources, tt.target, got, tt.expect)
			}
		})
	}
}

// TestGrantsPrefixedVerbs documents the verbs axis for prefixed verbs. VerbMatches in
// kubernetes/kubernetes pkg/apis/rbac/v1/evaluation_helpers.go accepts only "*" or an
// exact string, so a verb like `associated-node:update` (DRA) or `impersonate:user-info`
// (KEP-5284 constrained impersonation) is one more opaque verb. "*" covers it; the
// unprefixed verb does not, and neither does any partial wildcard.
func TestGrantsPrefixedVerbs(t *testing.T) {
	t.Parallel()

	target := []ResourceTarget{InGroup("resource.k8s.io", "resourceclaims/status")}
	tests := []struct {
		name   string
		verbs  []string
		want   string
		expect bool
	}{
		{name: "* covers a prefixed verb", verbs: []string{"*"}, want: "associated-node:update", expect: true},
		{name: "exact prefixed verb matches", verbs: []string{"associated-node:update"}, want: "associated-node:update", expect: true},
		{name: "update does not cover associated-node:update", verbs: []string{"update"}, want: "associated-node:update", expect: false},
		{name: "a prefixed verb does not cover the plain verb", verbs: []string{"associated-node:update"}, want: "update", expect: false},
		{name: "no partial wildcard on verbs", verbs: []string{"impersonate-on:user-info:*"}, want: "impersonate-on:user-info:list", expect: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Grants([]string{"resource.k8s.io"}, []string{"resourceclaims/status"}, tt.verbs, nil, target, []string{tt.want})
			if got != tt.expect {
				t.Errorf("Grants(verbs=%v, want %q) = %v, want %v", tt.verbs, tt.want, got, tt.expect)
			}
		})
	}
}

// TestResourceNameIsLiteral pins ResourceNameMatches: a resourceNames entry is compared
// as an exact string, so "*" names an object literally called "*" and is not a
// wildcard. Grants itself does not compare names (the caller supplies none), so the
// observable rule is that a "*"-scoped rule is still name-scoped: it drops the
// collection verbs exactly as any other name-scoped rule does.
func TestResourceNameIsLiteral(t *testing.T) {
	t.Parallel()

	star := EffectiveRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list", "get"}, ResourceNames: []string{"*"}}
	if !star.NameScoped() {
		t.Fatal(`resourceNames ["*"] must count as name-scoped`)
	}
	if star.Grants([]ResourceTarget{Core("secrets")}, "list") {
		t.Error(`resourceNames ["*"] must not resurrect list: "*" is a literal name, not a wildcard`)
	}
}

func TestIsResourcePattern(t *testing.T) {
	t.Parallel()

	for resource, want := range map[string]bool{
		"*":        true,
		"*/status": true,
		"pods":     false,
		"pods/*":   false,
		"pods/log": false,
	} {
		if got := IsResourcePattern(resource); got != want {
			t.Errorf("IsResourcePattern(%q) = %v, want %v", resource, got, want)
		}
	}
}
