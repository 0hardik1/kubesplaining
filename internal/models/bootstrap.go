package models

import "strings"

// nodeClientApproverClusterRole is the ClusterRole kubeadm binds to its bootstrap
// group so the controller manager auto-approves kubelet client CSRs.
const nodeClientApproverClusterRole = "system:certificates.k8s.io:certificatesigningrequests:nodeclient"

// KubeadmBootstrapAutoApproval reports whether the cluster auto-approves kubelet
// client certificates for bootstrap-token holders: a ClusterRoleBinding gives a
// `system:bootstrappers*` group `create certificatesigningrequests/nodeclient`. On
// such a cluster a bootstrap token is a node identity for any node name, so
// whoever can write bootstrap-token Secrets in kube-system can mint one.
func KubeadmBootstrapAutoApproval(snapshot Snapshot) bool {
	for _, crb := range snapshot.Resources.ClusterRoleBindings {
		if crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != nodeClientApproverClusterRole {
			continue
		}
		for _, subject := range crb.Subjects {
			if subject.Kind == "Group" && strings.HasPrefix(subject.Name, "system:bootstrappers") {
				return true
			}
		}
	}
	return false
}
