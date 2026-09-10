package eksaccess

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

const wrappedExport = `{
  "cluster": {"name": "prod", "accessConfig": {"authenticationMode": "api"}},
  "accessEntries": [
    {
      "accessEntry": {
        "principalArn": "arn:aws:iam::123456789012:role/PlatformAdmin",
        "type": "STANDARD",
        "username": "arn:aws:sts::123456789012:assumed-role/PlatformAdmin/{{SessionName}}",
        "kubernetesGroups": ["platform-admins", " "]
      },
      "associatedAccessPolicies": [
        {"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
         "accessScope": {"type": "Cluster", "namespaces": []}}
      ]
    },
    {"accessEntry": {"type": "STANDARD"}},
    {
      "accessEntry": {
        "principalArn": "arn:aws:iam::123456789012:role/NodeRole",
        "type": "EC2_LINUX",
        "kubernetesGroups": ["system:nodes", "system:bootstrappers"]
      }
    }
  ]
}`

func TestParseWrappedExport(t *testing.T) {
	t.Parallel()
	state, warnings, err := Parse([]byte(wrappedExport))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if state.ClusterName != "prod" || state.AuthenticationMode != models.EKSAuthModeAPI {
		t.Fatalf("cluster fields = %q / %q", state.ClusterName, state.AuthenticationMode)
	}
	if !state.AWSAuthIgnored() {
		t.Fatalf("API mode must report aws-auth as ignored")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "entry 1") {
		t.Fatalf("warnings = %v, want one for the entry without principalArn", warnings)
	}
	if len(state.AccessEntries) != 2 {
		t.Fatalf("entries = %d, want 2", len(state.AccessEntries))
	}
	// Sorted by ARN: NodeRole < PlatformAdmin.
	if state.AccessEntries[0].PrincipalARN != "arn:aws:iam::123456789012:role/NodeRole" {
		t.Fatalf("entries not sorted by principalArn: %+v", state.AccessEntries)
	}
	admin := state.AccessEntries[1]
	if got := admin.KubernetesGroups; len(got) != 1 || got[0] != "platform-admins" {
		t.Fatalf("groups = %v, want blank entries dropped", got)
	}
	if len(admin.AccessPolicies) != 1 {
		t.Fatalf("policies = %+v", admin.AccessPolicies)
	}
	if p := admin.AccessPolicies[0]; p.ScopeType != "cluster" || !strings.HasSuffix(p.PolicyARN, "AmazonEKSClusterAdminPolicy") {
		t.Fatalf("policy = %+v", p)
	}
}

func TestParseBareArrayAndBareEntry(t *testing.T) {
	t.Parallel()
	raw := `[{"principalArn": "arn:aws:iam::1:user/bob", "kubernetesGroups": ["viewers"],
	          "associatedAccessPolicies": [{"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
	          "accessScope": {"type": "namespace", "namespaces": ["dev"]}}]}]`
	state, warnings, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if state.AuthenticationMode != "" || len(state.AccessEntries) != 1 {
		t.Fatalf("state = %+v", state)
	}
	e := state.AccessEntries[0]
	if e.PrincipalARN != "arn:aws:iam::1:user/bob" || e.AccessPolicies[0].Namespaces[0] != "dev" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestParseRejectsUnrelatedDocuments(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "   ", `{"foo": 1}`, `not json`} {
		if _, _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", raw)
		}
	}
}

func TestLoadRecordsSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "entries.json")
	if err := writeFile(path, `{"accessEntries": []}`); err != nil {
		t.Fatal(err)
	}
	state, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if state.Source != path || len(state.AccessEntries) != 0 {
		t.Fatalf("state = %+v", state)
	}
	if _, _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("Load(missing) succeeded, want error")
	}
}
