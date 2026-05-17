package eks

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// awsAuthSnapshot is a tiny helper for tests that builds a Snapshot whose only
// ConfigMap is the canonical kube-system/aws-auth, with the given Data map.
func awsAuthSnapshot(t *testing.T, namespace, name string, data map[string]string, crbs []rbacv1.ClusterRoleBinding) models.Snapshot {
	t.Helper()
	snap := models.NewSnapshot()
	snap.Resources.ConfigMaps = []models.ConfigMapSnapshot{
		{
			Name:      name,
			Namespace: namespace,
			Data:      data,
		},
	}
	snap.Resources.ClusterRoleBindings = crbs
	return snap
}

// clusterAdminBindingFor returns a ClusterRoleBinding granting cluster-admin
// to the named Group subject. Tests use this to set up the indirect
// admin-via-group path that KUBE-CLOUD-AWSAUTH-OVERBROAD-001 detects.
func clusterAdminBindingFor(bindingName, groupName string) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: bindingName},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{Kind: "Group", Name: groupName},
		},
	}
}

func findingsByRule(findings []models.Finding, ruleID string) []models.Finding {
	matched := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == ruleID {
			matched = append(matched, f)
		}
	}
	return matched
}

func TestAnalyzeAWSAuth_NoConfigMap(t *testing.T) {
	t.Parallel()
	snap := models.NewSnapshot()
	if got := AnalyzeAWSAuth(snap); got != nil {
		t.Fatalf("AnalyzeAWSAuth on empty snapshot = %#v, want nil", got)
	}
}

func TestAnalyzeAWSAuth_SystemMastersMapping(t *testing.T) {
	t.Parallel()
	mapRoles := `- rolearn: arn:aws:iam::111111111111:role/Admin
  username: admin
  groups:
    - system:masters
`
	snap := awsAuthSnapshot(t, "kube-system", "aws-auth",
		map[string]string{"mapRoles": mapRoles}, nil)

	findings := AnalyzeAWSAuth(snap)
	matched := findingsByRule(findings, "KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001")
	if len(matched) != 1 {
		t.Fatalf("expected 1 SYSTEM-MASTERS finding, got %d (total %d)", len(matched), len(findings))
	}
	f := matched[0]
	if f.Severity != models.SeverityHigh {
		t.Fatalf("severity = %q, want HIGH", f.Severity)
	}
	if f.Score < 8.59 || f.Score > 8.61 {
		t.Fatalf("score = %v, want ~8.6", f.Score)
	}
	if f.Subject == nil || f.Subject.Kind != "User" || f.Subject.Name != "arn:aws:iam::111111111111:role/Admin" {
		t.Fatalf("subject = %#v, want User with the ARN", f.Subject)
	}
	if f.Resource == nil || f.Resource.Kind != "ConfigMap" || f.Resource.Namespace != "kube-system" || f.Resource.Name != "aws-auth" {
		t.Fatalf("resource = %#v, want kube-system/aws-auth", f.Resource)
	}
	if !strings.Contains(string(f.Evidence), "system:masters") {
		t.Fatalf("evidence missing system:masters: %s", f.Evidence)
	}
	if !strings.Contains(string(f.Evidence), `"entryType":"mapRoles"`) {
		t.Fatalf("evidence missing entryType=mapRoles: %s", f.Evidence)
	}
}

func TestAnalyzeAWSAuth_OverbroadGroupBinding(t *testing.T) {
	t.Parallel()
	mapUsers := `- userarn: arn:aws:iam::222222222222:user/dev
  username: dev
  groups:
    - developers
`
	crbs := []rbacv1.ClusterRoleBinding{
		clusterAdminBindingFor("dev-admins", "developers"),
	}
	snap := awsAuthSnapshot(t, "kube-system", "aws-auth",
		map[string]string{"mapUsers": mapUsers}, crbs)

	findings := AnalyzeAWSAuth(snap)
	matched := findingsByRule(findings, "KUBE-CLOUD-AWSAUTH-OVERBROAD-001")
	if len(matched) != 1 {
		t.Fatalf("expected 1 OVERBROAD finding, got %d (total %d)", len(matched), len(findings))
	}
	f := matched[0]
	if f.Severity != models.SeverityMedium {
		t.Fatalf("severity = %q, want MEDIUM", f.Severity)
	}
	if f.Score < 6.19 || f.Score > 6.21 {
		t.Fatalf("score = %v, want ~6.2", f.Score)
	}
	if !strings.Contains(string(f.Evidence), `"viaBinding":"dev-admins"`) {
		t.Fatalf("evidence missing viaBinding=dev-admins: %s", f.Evidence)
	}
	if !strings.Contains(string(f.Evidence), "developers") {
		t.Fatalf("evidence missing mapped group developers: %s", f.Evidence)
	}
	if strings.Contains(string(f.Evidence), "system:masters") {
		t.Fatalf("evidence should not mention system:masters in overbroad case: %s", f.Evidence)
	}
}

func TestAnalyzeAWSAuth_ReadOnlyGroup_NoFinding(t *testing.T) {
	t.Parallel()
	mapRoles := `- rolearn: arn:aws:iam::333333333333:role/ReadOnly
  username: viewer
  groups:
    - viewers
`
	// viewers has NO ClusterRoleBinding to cluster-admin.
	snap := awsAuthSnapshot(t, "kube-system", "aws-auth",
		map[string]string{"mapRoles": mapRoles}, nil)

	findings := AnalyzeAWSAuth(snap)
	for _, f := range findings {
		if f.RuleID == "KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001" || f.RuleID == "KUBE-CLOUD-AWSAUTH-OVERBROAD-001" {
			t.Fatalf("expected no aws-auth privesc findings for read-only group, got %s", f.RuleID)
		}
	}
}

func TestAnalyzeAWSAuth_MalformedYAML_ReturnsParseError(t *testing.T) {
	t.Parallel()
	// Malformed: bare scalar where the analyzer expects a YAML list. yaml.v3
	// surfaces this as an unmarshal error.
	mapRoles := "this is not a list, just a scalar string with: { broken } [yaml"
	snap := awsAuthSnapshot(t, "kube-system", "aws-auth",
		map[string]string{"mapRoles": mapRoles}, nil)

	// Must not panic.
	findings := AnalyzeAWSAuth(snap)

	// Optional parse-error diagnostic is emitted by this implementation; the
	// only hard requirement from the brief is that the analyzer does not
	// panic and does not surface a false-positive SYSTEM-MASTERS / OVERBROAD
	// finding for a key it could not parse.
	for _, f := range findings {
		if f.RuleID == "KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001" || f.RuleID == "KUBE-CLOUD-AWSAUTH-OVERBROAD-001" {
			t.Fatalf("malformed YAML produced a real finding %q; expected only the parse-error diagnostic", f.RuleID)
		}
	}
	parseErrors := findingsByRule(findings, "KUBE-CLOUD-AWSAUTH-PARSE-ERROR-001")
	if len(parseErrors) != 1 {
		t.Fatalf("expected 1 PARSE-ERROR diagnostic, got %d", len(parseErrors))
	}
	if parseErrors[0].Severity != models.SeverityInfo {
		t.Fatalf("parse-error severity = %q, want INFO", parseErrors[0].Severity)
	}
}

func TestAnalyzeAWSAuth_WrongNamespace_Silent(t *testing.T) {
	t.Parallel()
	mapRoles := `- rolearn: arn:aws:iam::444444444444:role/Admin
  username: admin
  groups:
    - system:masters
`
	// Same content, wrong namespace: EKS only reads kube-system/aws-auth, so
	// a default/aws-auth must not trip the detector.
	snap := awsAuthSnapshot(t, "default", "aws-auth",
		map[string]string{"mapRoles": mapRoles}, nil)

	findings := AnalyzeAWSAuth(snap)
	if findings != nil {
		t.Fatalf("expected nil findings for default/aws-auth, got %d", len(findings))
	}
}
