package models

import (
	"strings"
	"testing"
	"time"
)

func TestParseSeverityCanonical(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  Severity
	}{
		{"CRITICAL", SeverityCritical},
		{"critical", SeverityCritical},
		{" High ", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"info", SeverityInfo},
		{"", SeverityInfo}, // empty input is accepted as INFO
	}
	for _, tc := range cases {
		got, err := ParseSeverity(tc.input)
		if err != nil {
			t.Errorf("ParseSeverity(%q) returned error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseSeverityRejectsUnknown(t *testing.T) {
	t.Parallel()

	_, err := ParseSeverity("noise")
	if err == nil {
		t.Fatal("expected error for unknown severity")
	}
	if !strings.Contains(err.Error(), "noise") {
		t.Errorf("error message should include the bad input, got %q", err.Error())
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	t.Parallel()

	// Critical > High > Medium > Low > Info, and unknowns rank as Info (1).
	want := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}
	for sev, rank := range want {
		if sev.Rank() != rank {
			t.Errorf("Severity(%q).Rank() = %d, want %d", sev, sev.Rank(), rank)
		}
	}
	// Unknown severities default to the lowest rank.
	if Severity("garbage").Rank() != 1 {
		t.Errorf("unknown severity should rank 1, got %d", Severity("garbage").Rank())
	}
}

func TestScopeLevelRankAndLabel(t *testing.T) {
	t.Parallel()

	rank := map[ScopeLevel]int{
		ScopeCluster:   4,
		ScopeNamespace: 3,
		ScopeWorkload:  2,
		ScopeObject:    1,
	}
	for sl, want := range rank {
		if got := sl.Rank(); got != want {
			t.Errorf("Rank(%q) = %d, want %d", sl, got, want)
		}
	}
	if ScopeLevel("").Rank() != 0 {
		t.Errorf("empty scope should rank 0, got %d", ScopeLevel("").Rank())
	}

	label := map[ScopeLevel]string{
		ScopeCluster:    "Cluster",
		ScopeNamespace:  "Namespace",
		ScopeWorkload:   "Workload",
		ScopeObject:     "Object",
		ScopeLevel(""):  "Unknown",
		ScopeLevel("x"): "Unknown",
	}
	for sl, want := range label {
		if got := sl.Label(); got != want {
			t.Errorf("Label(%q) = %q, want %q", sl, got, want)
		}
	}
}

func TestSubjectRefKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ref  SubjectRef
		want string
	}{
		{SubjectRef{Kind: "User", Name: "alice"}, "User/alice"},
		{SubjectRef{Kind: "Group", Name: "ops"}, "Group/ops"},
		{SubjectRef{Kind: "ServiceAccount", Namespace: "team-a", Name: "deployer"}, "ServiceAccount/team-a/deployer"},
	}
	for _, tc := range cases {
		if got := tc.ref.Key(); got != tc.want {
			t.Errorf("Key(%#v) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestResourceRefKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ref  ResourceRef
		want string
	}{
		{ResourceRef{Kind: "ClusterRole", Name: "admin"}, "ClusterRole/admin"},
		{ResourceRef{Kind: "Pod", Namespace: "default", Name: "nginx"}, "Pod/default/nginx"},
	}
	for _, tc := range cases {
		if got := tc.ref.Key(); got != tc.want {
			t.Errorf("Key(%#v) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestNewSnapshotSeedsTimestampAndProvider(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC().Add(-1 * time.Second)
	snap := NewSnapshot()
	after := time.Now().UTC().Add(1 * time.Second)

	if snap.Metadata.CloudProvider != "none" {
		t.Errorf("CloudProvider default should be 'none', got %q", snap.Metadata.CloudProvider)
	}

	ts, err := time.Parse(time.RFC3339, snap.Metadata.SnapshotTimestamp)
	if err != nil {
		t.Fatalf("SnapshotTimestamp not RFC3339: %v", err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("SnapshotTimestamp %v should fall within [%v, %v]", ts, before, after)
	}
}

func TestParseSubjectRefRoundTrip(t *testing.T) {
	t.Parallel()

	refs := []SubjectRef{
		{Kind: "ServiceAccount", Namespace: "dev", Name: "ci"},
		{Kind: "User", Name: "alice"},
		{Kind: "User", Name: "arn:aws:iam::123456789012:role/Admin"},
		{Kind: "User", Name: "system:serviceaccount:dev:ci"},
		{Kind: "Group", Name: "system:authenticated"},
		{Kind: "Group", Name: "oidc:team/platform"},
	}
	for _, want := range refs {
		got, err := ParseSubjectRef(want.Key())
		if err != nil {
			t.Errorf("ParseSubjectRef(%q): %v", want.Key(), err)
			continue
		}
		if got != want {
			t.Errorf("ParseSubjectRef(%q) = %+v, want %+v", want.Key(), got, want)
		}
	}
}

func TestParseSubjectRefForms(t *testing.T) {
	t.Parallel()

	sa := SubjectRef{Kind: "ServiceAccount", Namespace: "dev", Name: "ci"}
	for _, value := range []string{"ServiceAccount/dev/ci", "serviceaccount/dev/ci", "sa/dev/ci", "SA/dev/ci", "  sa/dev/ci  "} {
		got, err := ParseSubjectRef(value)
		if err != nil || got != sa {
			t.Errorf("ParseSubjectRef(%q) = %+v, %v; want %+v", value, got, err, sa)
		}
	}
	if got, err := ParseSubjectRef("group/devs"); err != nil || got != (SubjectRef{Kind: "Group", Name: "devs"}) {
		t.Errorf("ParseSubjectRef(group/devs) = %+v, %v", got, err)
	}

	for _, value := range []string{
		"",                     // empty
		"ci",                   // no kind
		"ServiceAccount/ci",    // a ServiceAccount needs a namespace
		"ServiceAccount/dev/",  // empty name
		"ServiceAccount//ci",   // empty namespace
		"ServiceAccount/a/b/c", // a ServiceAccount name has no slash
		"User/",                // empty name
		"Pod/dev/web",          // not an RBAC subject kind
		"ClusterRole/cluster-admin",
	} {
		if got, err := ParseSubjectRef(value); err == nil {
			t.Errorf("ParseSubjectRef(%q) = %+v, want an error", value, got)
		}
	}
}
