package eks

import (
	"encoding/json"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	policyARNClusterAdmin = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
	policyARNAdmin        = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy"
	policyARNView         = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
)

func clusterPolicy(arn string) models.EKSAccessPolicyAssociation {
	return models.EKSAccessPolicyAssociation{PolicyARN: arn, ScopeType: "cluster"}
}

func namespacePolicy(arn string, ns ...string) models.EKSAccessPolicyAssociation {
	return models.EKSAccessPolicyAssociation{PolicyARN: arn, ScopeType: "namespace", Namespaces: ns}
}

func eksSnapshot(state *models.EKSCloudState, crbs []rbacv1.ClusterRoleBinding) models.Snapshot {
	snap := models.NewSnapshot()
	snap.Metadata.CloudProvider = "eks"
	snap.Cloud.EKS = state
	snap.Resources.ClusterRoleBindings = crbs
	return snap
}

func evidenceOf(t *testing.T, f models.Finding) map[string]any {
	t.Helper()
	var ev map[string]any
	if err := json.Unmarshal(f.Evidence, &ev); err != nil {
		t.Fatalf("evidence is not JSON: %v", err)
	}
	return ev
}

func TestAnalyzeAccessEntries_NotEvaluatedWithoutExport(t *testing.T) {
	t.Parallel()

	// No aws-auth either: nothing in the IAM class ran, so LOW.
	snap := models.NewSnapshot()
	snap.Metadata.CloudProvider = "eks"
	got := AnalyzeAccessEntries(snap)
	if len(got) != 1 || got[0].RuleID != ruleAccessEntryNotEvaluated {
		t.Fatalf("findings = %+v, want exactly one NOT-EVALUATED", got)
	}
	if got[0].Severity != models.SeverityLow {
		t.Errorf("severity without aws-auth = %s, want LOW", got[0].Severity)
	}
	if got[0].ID != ruleAccessEntryNotEvaluated {
		t.Errorf("ID = %q, want the bare rule ID for a cluster-wide finding", got[0].ID)
	}
	if ev := evidenceOf(t, got[0]); ev["awsAuthConfigMapPresent"] != false {
		t.Errorf("evidence = %v", ev)
	}

	// With aws-auth present the ConfigMap half is covered: INFO.
	withAuth := awsAuthSnapshot(t, "kube-system", "aws-auth", map[string]string{"mapRoles": "[]\n"}, nil)
	withAuth.Metadata.CloudProvider = "eks"
	got = AnalyzeAccessEntries(withAuth)
	if len(got) != 1 || got[0].Severity != models.SeverityInfo {
		t.Fatalf("with aws-auth: findings = %+v, want one INFO", got)
	}
}

func TestAnalyzeAccessEntries_EmptyExportIsClean(t *testing.T) {
	t.Parallel()
	snap := eksSnapshot(&models.EKSCloudState{AuthenticationMode: models.EKSAuthModeAPI}, nil)
	if got := AnalyzeAccessEntries(snap); len(got) != 0 {
		t.Fatalf("findings = %+v, want none: an export with zero entries is an answer, not a gap", got)
	}
}

func TestAnalyzeAccessEntries_Shapes(t *testing.T) {
	t.Parallel()
	state := &models.EKSCloudState{
		ClusterName:        "prod",
		AuthenticationMode: models.EKSAuthModeAPI,
		Source:             "entries.json",
		AccessEntries: []models.EKSAccessEntry{
			{PrincipalARN: "arn:aws:iam::123456789012:role/Admin", Type: "STANDARD", AccessPolicies: []models.EKSAccessPolicyAssociation{clusterPolicy(policyARNClusterAdmin)}},
			{PrincipalARN: "arn:aws:iam::123456789012:role/NsAdmin", Type: "STANDARD", AccessPolicies: []models.EKSAccessPolicyAssociation{clusterPolicy(policyARNAdmin)}},
			{PrincipalARN: "arn:aws:iam::123456789012:role/Devs", Type: "STANDARD", KubernetesGroups: []string{"developers", "platform-admins"}},
			{PrincipalARN: "arn:aws:iam::123456789012:role/Viewer", Type: "STANDARD", AccessPolicies: []models.EKSAccessPolicyAssociation{clusterPolicy(policyARNView)}},
			{PrincipalARN: "arn:aws:iam::123456789012:role/ScopedAdmin", Type: "STANDARD", AccessPolicies: []models.EKSAccessPolicyAssociation{namespacePolicy(policyARNAdmin, "team-a")}},
			{PrincipalARN: "arn:aws:iam::123456789012:role/NodeRole", Type: "EC2_LINUX", KubernetesGroups: []string{"system:nodes"}},
			{PrincipalARN: "arn:aws:iam::123456789012:user/hand-edited", Type: "STANDARD", KubernetesGroups: []string{"system:masters"}},
		},
	}
	crbs := []rbacv1.ClusterRoleBinding{clusterAdminBindingFor("platform-admins-binding", "platform-admins")}
	got := AnalyzeAccessEntries(eksSnapshot(state, crbs))

	if n := len(findingsByRule(got, ruleAccessEntryNotEvaluated)); n != 0 {
		t.Errorf("NOT-EVALUATED fired %d times with an export loaded", n)
	}

	admins := findingsByRule(got, ruleAccessEntryClusterAdmin)
	if len(admins) != 2 {
		t.Fatalf("CLUSTER-ADMIN findings = %d, want 2 (policy + hand-edited system:masters): %+v", len(admins), admins)
	}
	adminIDs := map[string]bool{}
	for _, f := range admins {
		adminIDs[f.ID] = true
		if f.Severity != models.SeverityHigh || f.Subject == nil || f.Subject.Kind != "User" {
			t.Errorf("CLUSTER-ADMIN shape wrong: %+v", f)
		}
		if f.Resource == nil || f.Resource.Kind != "AccessEntry" {
			t.Errorf("CLUSTER-ADMIN resource = %+v, want AccessEntry", f.Resource)
		}
	}
	for _, want := range []string{
		ruleAccessEntryClusterAdmin + ":arn_aws_iam__123456789012_role_Admin",
		ruleAccessEntryClusterAdmin + ":arn_aws_iam__123456789012_user_hand-edited",
	} {
		if !adminIDs[want] {
			t.Errorf("missing finding ID %q in %v", want, adminIDs)
		}
	}
	if ev := evidenceOf(t, admins[0]); ev["clusterName"] != "prod" || ev["authenticationMode"] != "API" {
		t.Errorf("evidence lacks cluster context: %v", ev)
	}

	overbroad := findingsByRule(got, ruleAccessEntryOverbroad)
	if len(overbroad) != 2 {
		t.Fatalf("OVERBROAD findings = %d, want 2 (cluster-scoped admin policy + admin-bound group): %+v", len(overbroad), overbroad)
	}
	reasons := map[string]map[string]any{}
	for _, f := range overbroad {
		ev := evidenceOf(t, f)
		reasons[ev["reason"].(string)] = ev
		if f.Severity != models.SeverityMedium {
			t.Errorf("OVERBROAD severity = %s", f.Severity)
		}
	}
	if ev, ok := reasons["cluster-scoped-secrets-policy"]; !ok || ev["policyArn"] != policyARNAdmin {
		t.Errorf("policy-shape evidence = %v", ev)
	}
	if ev, ok := reasons["group-bound-to-admin-clusterrole"]; !ok || ev["viaBinding"] != "platform-admins-binding" || ev["viaClusterRole"] != "cluster-admin" {
		t.Errorf("group-shape evidence = %v", ev)
	}

	// Negative space: view policy, namespace-scoped admin, and the node entry
	// must produce nothing.
	for _, f := range got {
		ev := evidenceOf(t, f)
		switch ev["arn"] {
		case "arn:aws:iam::123456789012:role/Viewer",
			"arn:aws:iam::123456789012:role/ScopedAdmin",
			"arn:aws:iam::123456789012:role/NodeRole":
			t.Errorf("unexpected finding for %v: %s", ev["arn"], f.RuleID)
		}
	}
}

func TestAnalyzeAWSAuth_StandsDownInAPIMode(t *testing.T) {
	t.Parallel()
	data := map[string]string{"mapUsers": "- userarn: arn:aws:iam::123456789012:user/break-glass\n  username: break-glass\n  groups:\n    - system:masters\n"}
	snap := awsAuthSnapshot(t, "kube-system", "aws-auth", data, nil)
	if got := AnalyzeAWSAuth(snap); len(findingsByRule(got, ruleSystemMasters)) != 1 {
		t.Fatalf("baseline: expected the system:masters finding, got %+v", got)
	}
	snap.Cloud.EKS = &models.EKSCloudState{AuthenticationMode: models.EKSAuthModeAPI}
	if got := AnalyzeAWSAuth(snap); got != nil {
		t.Fatalf("API mode: aws-auth is ignored by the apiserver, want nil, got %+v", got)
	}
	snap.Cloud.EKS.AuthenticationMode = models.EKSAuthModeAPIAndConfigMap
	if got := AnalyzeAWSAuth(snap); len(got) != 1 {
		t.Fatalf("API_AND_CONFIG_MAP: aws-auth is live, want 1 finding, got %+v", got)
	}
}

func TestAccessPolicyHelpers(t *testing.T) {
	t.Parallel()
	if AccessPolicyName("arn:aws-us-gov:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy") != "AmazonEKSClusterAdminPolicy" {
		t.Error("partition-independent name extraction failed")
	}
	if AccessPolicyName("AmazonEKSViewPolicy") != "AmazonEKSViewPolicy" {
		t.Error("bare name should pass through")
	}
	if ClusterAdminPolicy(namespacePolicy(policyARNClusterAdmin, "x")) {
		t.Error("namespace-scoped ClusterAdminPolicy must not count as cluster-admin")
	}
	if !ClusterAdminPolicy(clusterPolicy(policyARNClusterAdmin)) {
		t.Error("cluster-scoped ClusterAdminPolicy must count")
	}
}
