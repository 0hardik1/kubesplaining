package cloud

import (
	"reflect"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// awsAuthMapRolesYAML is a small valid mapRoles document with one entry; the
// trailing newline is required for yaml.v3 to parse the leading "-".
const awsAuthMapRolesYAML = `- rolearn: arn:aws:iam::123456789012:role/eksNodeRole
  username: system:node:{{EC2PrivateDNSName}}
  groups:
    - system:bootstrappers
    - system:nodes
`

const awsAuthMapUsersYAML = `- userarn: arn:aws:iam::123456789012:user/break-glass
  username: break-glass
  groups:
    - system:masters
`

// snapshotWithAWSAuth builds a snapshot whose kube-system/aws-auth ConfigMap
// carries the two YAML strings. Caller passes "" to omit either key.
func snapshotWithAWSAuth(mapRoles, mapUsers string) models.Snapshot {
	data := map[string]string{}
	if mapRoles != "" {
		data["mapRoles"] = mapRoles
	}
	if mapUsers != "" {
		data["mapUsers"] = mapUsers
	}
	snap := models.NewSnapshot()
	snap.Resources.ConfigMaps = []models.ConfigMapSnapshot{{
		Name:      "aws-auth",
		Namespace: "kube-system",
		Data:      data,
	}}
	return snap
}

// saWithIRSA returns a ServiceAccount with the IRSA annotation set to arn.
func saWithIRSA(namespace, name, arn string) corev1.ServiceAccount {
	return corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{irsaAnnotation: arn},
		},
	}
}

func TestCloudIdentitiesForSnapshotEmpty(t *testing.T) {
	t.Parallel()
	snap := models.NewSnapshot()
	got := CloudIdentitiesForSnapshot(snap)
	if len(got) != 0 {
		t.Fatalf("empty snapshot returned %d identities, want 0", len(got))
	}
}

func TestCloudIdentitiesForSnapshotIRSAOnly(t *testing.T) {
	t.Parallel()
	snap := models.NewSnapshot()
	snap.Resources.ServiceAccounts = []corev1.ServiceAccount{
		saWithIRSA("prod", "billing-sa", "arn:aws:iam::123456789012:role/BillingRole"),
	}
	got := CloudIdentitiesForSnapshot(snap)
	if len(got) != 1 {
		t.Fatalf("got %d identities, want 1: %+v", len(got), got)
	}
	id := got[0]
	if id.Provider != "aws" || id.Kind != models.CloudIdentityKindAWSIAMRole {
		t.Errorf("identity kind/provider wrong: %+v", id)
	}
	if id.DetectedFrom != "irsa" {
		t.Errorf("DetectedFrom = %q, want irsa", id.DetectedFrom)
	}
	if id.AccountID != "123456789012" || id.RoleName != "BillingRole" {
		t.Errorf("account/role parse wrong: %+v", id)
	}
	if id.IRSA == nil {
		t.Fatalf("IRSA binding should be populated")
	}
	wantRef := models.SubjectRef{Kind: "ServiceAccount", Name: "billing-sa", Namespace: "prod"}
	if !reflect.DeepEqual(id.IRSA.ServiceAccountRef, wantRef) {
		t.Errorf("IRSA.ServiceAccountRef = %+v, want %+v", id.IRSA.ServiceAccountRef, wantRef)
	}
}

func TestCloudIdentitiesForSnapshotAWSAuth(t *testing.T) {
	t.Parallel()
	snap := snapshotWithAWSAuth(awsAuthMapRolesYAML, awsAuthMapUsersYAML)
	got := CloudIdentitiesForSnapshot(snap)
	if len(got) != 2 {
		t.Fatalf("got %d identities, want 2: %+v", len(got), got)
	}
	// Sorted by ARN: role/eksNodeRole < user/break-glass alphabetically.
	role := got[0]
	user := got[1]
	if role.Kind != models.CloudIdentityKindAWSIAMRole || role.DetectedFrom != "aws-auth-mapRoles" {
		t.Errorf("first identity expected mapRoles role, got %+v", role)
	}
	if role.RoleName != "eksNodeRole" {
		t.Errorf("role name = %q, want eksNodeRole", role.RoleName)
	}
	wantRoleGroups := []string{"system:bootstrappers", "system:nodes"}
	if !reflect.DeepEqual(role.MappedGroups, wantRoleGroups) {
		t.Errorf("role.MappedGroups = %v, want %v", role.MappedGroups, wantRoleGroups)
	}
	if user.Kind != models.CloudIdentityKindAWSIAMUser || user.DetectedFrom != "aws-auth-mapUsers" {
		t.Errorf("second identity expected mapUsers user, got %+v", user)
	}
	if user.RoleName != "break-glass" {
		t.Errorf("user name = %q, want break-glass", user.RoleName)
	}
	wantUserGroups := []string{"system:masters"}
	if !reflect.DeepEqual(user.MappedGroups, wantUserGroups) {
		t.Errorf("user.MappedGroups = %v, want %v", user.MappedGroups, wantUserGroups)
	}
}

func TestCloudIdentitiesForSnapshotIRSAPlusAWSAuthDedup(t *testing.T) {
	t.Parallel()
	const sharedARN = "arn:aws:iam::123456789012:role/BillingRole"
	// Both an IRSA-annotated SA and an aws-auth mapRoles entry reference the
	// same role. The result should be ONE CloudIdentity whose IRSA field is
	// populated AND whose MappedGroups carries the aws-auth groups.
	mapRoles := `- rolearn: ` + sharedARN + `
  username: billing
  groups:
    - billing-admins
`
	snap := snapshotWithAWSAuth(mapRoles, "")
	snap.Resources.ServiceAccounts = []corev1.ServiceAccount{
		saWithIRSA("prod", "billing-sa", sharedARN),
	}
	got := CloudIdentitiesForSnapshot(snap)
	if len(got) != 1 {
		t.Fatalf("got %d identities, want 1 (deduplicated): %+v", len(got), got)
	}
	id := got[0]
	if id.ARN != sharedARN {
		t.Errorf("ARN = %q, want %q", id.ARN, sharedARN)
	}
	if id.IRSA == nil {
		t.Errorf("IRSA binding should survive after aws-auth merge")
	}
	wantGroups := []string{"billing-admins"}
	if !reflect.DeepEqual(id.MappedGroups, wantGroups) {
		t.Errorf("MappedGroups = %v, want %v", id.MappedGroups, wantGroups)
	}
}

func TestCloudIdentitiesForSnapshotMalformedAWSAuthSkipped(t *testing.T) {
	t.Parallel()
	// A malformed YAML in mapRoles should be silently skipped (not panic and
	// not produce a finding).
	snap := snapshotWithAWSAuth("not: valid: yaml: at: all: [", awsAuthMapUsersYAML)
	got := CloudIdentitiesForSnapshot(snap)
	if len(got) != 1 {
		t.Fatalf("malformed mapRoles should not break; got %d, want 1", len(got))
	}
	if got[0].Kind != models.CloudIdentityKindAWSIAMUser {
		t.Errorf("expected only the mapUsers entry to survive, got %+v", got[0])
	}
}

func TestCloudIdentitiesForSnapshotAccessEntries(t *testing.T) {
	t.Parallel()
	snap := snapshotWithAWSAuth(awsAuthMapRolesYAML, awsAuthMapUsersYAML)
	snap.Cloud.EKS = &models.EKSCloudState{
		AuthenticationMode: models.EKSAuthModeAPIAndConfigMap,
		AccessEntries: []models.EKSAccessEntry{
			{PrincipalARN: "arn:aws:iam::123456789012:user/break-glass", KubernetesGroups: []string{"ops"}},
			{PrincipalARN: "arn:aws:iam::123456789012:role/PlatformAdmin", AccessPolicies: []models.EKSAccessPolicyAssociation{{PolicyARN: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy", ScopeType: "cluster"}}},
			{PrincipalARN: "not-an-arn"},
		},
	}
	got := CloudIdentitiesForSnapshot(snap)
	byARN := map[string]models.CloudIdentity{}
	for _, id := range got {
		byARN[id.ARN] = id
	}
	// break-glass is in both aws-auth (mapUsers) and an access entry: one
	// identity, both axes populated, aws-auth groups kept separate.
	bg, ok := byARN["arn:aws:iam::123456789012:user/break-glass"]
	if !ok || bg.AccessEntry == nil || bg.Kind != models.CloudIdentityKindAWSIAMUser {
		t.Fatalf("break-glass identity = %+v", bg)
	}
	if !reflect.DeepEqual(bg.MappedGroups, []string{"system:masters"}) || !reflect.DeepEqual(bg.AccessEntry.KubernetesGroups, []string{"ops"}) {
		t.Errorf("groups not kept per source: mapped=%v entry=%v", bg.MappedGroups, bg.AccessEntry.KubernetesGroups)
	}
	pa, ok := byARN["arn:aws:iam::123456789012:role/PlatformAdmin"]
	if !ok || pa.DetectedFrom != "eks-access-entry" || pa.Kind != models.CloudIdentityKindAWSIAMRole || pa.RoleName != "PlatformAdmin" {
		t.Fatalf("PlatformAdmin identity = %+v", pa)
	}
	if _, ok := byARN["not-an-arn"]; ok {
		t.Error("unparseable principal ARN must be skipped")
	}

	// API mode: the aws-auth ConfigMap is ignored, so its identities vanish
	// while the access-entry ones stay.
	snap.Cloud.EKS.AuthenticationMode = models.EKSAuthModeAPI
	got = CloudIdentitiesForSnapshot(snap)
	for _, id := range got {
		if id.ARN == "arn:aws:iam::123456789012:role/eksNodeRole" {
			t.Errorf("aws-auth-only identity survived API mode: %+v", id)
		}
		if id.ARN == "arn:aws:iam::123456789012:user/break-glass" && len(id.MappedGroups) != 0 {
			t.Errorf("aws-auth groups survived API mode: %+v", id)
		}
	}
}
