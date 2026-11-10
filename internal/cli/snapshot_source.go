package cli

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/eksaccess"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/spf13/cobra"
)

// snapshotSource holds the flags that decide which cluster state a command
// analyzes: a snapshot file or a live cluster, plus the two inputs that change
// what the snapshot says about the cloud provider. `scan` and `paths` both load
// through it, so the same flags give both commands the same snapshot.
type snapshotSource struct {
	conn                 connectionFlags
	inputFile            string
	namespaces           []string
	excludeNamespaces    []string
	includeManagedFields bool
	parallelism          int
	cloudProvider        string
	eksAccessEntriesFile string
}

// load returns the snapshot from inputFile when it is set, or collects one from
// the live cluster. It then applies --eks-access-entries and --cloud-provider.
func (s snapshotSource) load(cmd *cobra.Command, build BuildInfo) (models.Snapshot, error) {
	snapshot, err := loadOrCollectSnapshot(cmd, build, s.conn, s.inputFile, s.namespaces, s.excludeNamespaces, s.includeManagedFields, s.parallelism)
	if err != nil {
		return models.Snapshot{}, err
	}

	// --cloud-provider overrides the collector / manifest auto-detection.
	// "auto" keeps whatever was detected; "none" forces detectors off; the
	// concrete provider names pin detection so an operator can opt in even
	// when the snapshot lacks the usual heuristic signals (e.g. an EKS
	// cluster without aws-auth in kube-system).
	// --eks-access-entries loads the AWS-side half of EKS authentication,
	// which no Kubernetes API call can return. Supplying it is also a
	// strong provider signal, so under "auto" it promotes an undetected
	// snapshot to eks (an API-mode cluster has no aws-auth ConfigMap to
	// detect from).
	if s.eksAccessEntriesFile != "" {
		state, warnings, err := eksaccess.Load(s.eksAccessEntriesFile)
		if err != nil {
			return models.Snapshot{}, err
		}
		snapshot.Cloud.EKS = state
		snapshot.Metadata.CollectionWarnings = append(snapshot.Metadata.CollectionWarnings, warnings...)
		if s.cloudProvider == "auto" && (snapshot.Metadata.CloudProvider == "" || snapshot.Metadata.CloudProvider == "none") {
			snapshot.Metadata.CloudProvider = "eks"
		}
	}

	switch s.cloudProvider {
	case "auto":
		// keep whatever the collector / manifest loader populated
	case "none":
		snapshot.Metadata.CloudProvider = "none"
	case "eks", "gke", "aks":
		snapshot.Metadata.CloudProvider = s.cloudProvider
	default:
		return models.Snapshot{}, fmt.Errorf("invalid --cloud-provider %q (must be auto, eks, gke, aks, or none)", s.cloudProvider)
	}

	return snapshot, nil
}
