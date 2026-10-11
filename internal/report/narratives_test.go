package report

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// TestHeroSinkLabel renders a few sink slugs into the human-readable phrase used
// inside each attack path's one-line summary, so a regression in the labeling
// table is caught without rendering a report.
func TestHeroSinkLabel(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		string(models.TargetClusterAdmin):      "cluster-admin",
		string(models.TargetSystemMasters):     "the system:masters group",
		string(models.TargetKubeSystemSecrets): "kube-system secrets",
		string(models.TargetNodeEscape):        "node root (container escape)",
		string(models.TargetNamespaceAdmin):    "namespace-admin",
		"":                                     "a sensitive sink",
	}
	for slug, want := range cases {
		if got := heroSinkLabel(slug); got != want {
			t.Errorf("heroSinkLabel(%q) = %q, want %q", slug, got, want)
		}
	}
}
