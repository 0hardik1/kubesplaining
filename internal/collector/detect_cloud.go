// Package collector - cloud-provider detection helpers. Pure, snapshot-only
// logic (no API calls); used by both the live collector and the offline
// manifest loader so cloud-provider context is consistent across entrypoints.
package collector

import (
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// DetectCloudProvider inspects node labels, kube-system services, and the
// presence of the aws-auth ConfigMap to identify the cluster's cloud provider.
// Returns one of: "eks", "gke", "aks", "" (unknown), "none".
func DetectCloudProvider(snapshot models.Snapshot) string {
	if isEKS(snapshot) {
		return "eks"
	}
	if isGKE(snapshot) {
		return "gke"
	}
	if isAKS(snapshot) {
		return "aks"
	}
	return ""
}

// isEKS returns true when the snapshot contains the aws-auth ConfigMap in
// kube-system or any node carrying an eks.amazonaws.com/* label.
func isEKS(snapshot models.Snapshot) bool {
	for _, cm := range snapshot.Resources.ConfigMaps {
		if cm.Name == "aws-auth" && cm.Namespace == "kube-system" {
			return true
		}
	}
	for _, node := range snapshot.Resources.Nodes {
		for key := range node.Labels {
			if strings.HasPrefix(key, "eks.amazonaws.com/") {
				return true
			}
		}
	}
	return false
}

// isGKE returns true when any node carries a cloud.google.com/gke-* label or
// the canonical cloud.google.com/gke-nodepool label.
func isGKE(snapshot models.Snapshot) bool {
	for _, node := range snapshot.Resources.Nodes {
		for key := range node.Labels {
			if strings.HasPrefix(key, "cloud.google.com/gke-") {
				return true
			}
			if key == "cloud.google.com/gke-nodepool" {
				return true
			}
		}
	}
	return false
}

// isAKS returns true when any node carries a kubernetes.azure.com/* label or
// the AKS-specific agentpool label.
func isAKS(snapshot models.Snapshot) bool {
	for _, node := range snapshot.Resources.Nodes {
		for key := range node.Labels {
			if strings.HasPrefix(key, "kubernetes.azure.com/") {
				return true
			}
			if key == "agentpool" {
				return true
			}
		}
	}
	return false
}
