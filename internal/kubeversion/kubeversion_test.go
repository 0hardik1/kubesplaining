package kubeversion

import "testing"

func TestStatefulSetControllerRevisionDeputy(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		// Fixed patch releases: quiet.
		{"1.34 fixed", "v1.34.12", false},
		{"1.34 well past fix", "v1.34.20", false},
		{"1.35 fixed", "v1.35.9", false},
		{"1.36 fixed", "v1.36.5", false},
		{"1.37 fixed", "v1.37.1", false},
		{"1.38 carries fix forward", "v1.38.0", false},
		{"far future minor", "v1.42.3", false},

		// Last affected patch in each supported minor: fire.
		{"1.34 last affected", "v1.34.11", true},
		{"1.35 last affected", "v1.35.8", true},
		{"1.36 last affected", "v1.36.4", true},
		{"1.37.0 only affected", "v1.37.0", true},

		// Below the fix in a supported minor: fire.
		{"1.34 mid band", "v1.34.5", true},
		{"1.35 zero patch", "v1.35.0", true},
		{"1.36 zero patch", "v1.36.0", true},

		// Older, unlisted, EOL minors are equally affected.
		{"1.33 EOL", "v1.33.7", true},
		{"1.30 EOL", "v1.30.0", true},
		{"1.7 ancient", "v1.7.0", true},

		// Distro suffixes are stripped down to the triple.
		{"gke suffix affected", "v1.35.8-gke.1000", true},
		{"gke suffix fixed", "v1.35.9-gke.1000", false},
		{"eks suffix affected", "v1.36.4-eks-abc123", true},
		{"k3s suffix fixed", "v1.37.1+k3s1", false},
		{"no v prefix", "1.36.4", true},
		{"whitespace tolerated", "  v1.36.4  ", true},
		{"major.minor only, patch defaults to 0", "v1.35", true},

		// Fail-closed: unreadable or empty versions stay quiet.
		{"empty", "", false},
		{"garbage", "not-a-version", false},
		{"unknown placeholder", "unknown", false},
		{"non-1 major", "v2.0.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StatefulSetControllerRevisionDeputy(tt.version); got != tt.want {
				t.Errorf("StatefulSetControllerRevisionDeputy(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
