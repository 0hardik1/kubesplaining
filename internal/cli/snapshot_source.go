package cli

import (
	"fmt"
	"slices"

	"github.com/0hardik1/kubesplaining/internal/eksaccess"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/overlay"
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

	// The overlay: manifests to apply on top of the snapshot in memory, and
	// objects to delete from it. See package overlay.
	overlayPaths     []string
	overlayDeletes   []string
	overlayNamespace string
}

// bindOverlayFlags registers the what-if flags on a command that loads through
// snapshotSource.
func bindOverlayFlags(cmd *cobra.Command, s *snapshotSource) {
	cmd.Flags().StringArrayVar(&s.overlayPaths, "overlay", nil, "What-if: apply the manifests in this file or directory on top of the snapshot, in memory only (repeatable; - reads standard input). An object replaces the one with the same kind, namespace, and name, or is added. Kinds: Role, ClusterRole, RoleBinding, ClusterRoleBinding, ServiceAccount, Namespace, Pod.")
	cmd.Flags().StringArrayVar(&s.overlayDeletes, "overlay-delete", nil, "What-if: remove one object from the snapshot, in memory only (repeatable). Form: Kind/name for a ClusterRole or ClusterRoleBinding, Kind/namespace/name for a Role, RoleBinding, ServiceAccount, or Pod.")
	cmd.Flags().StringVar(&s.overlayNamespace, "overlay-namespace", "", "Namespace for an overlay object that has no metadata.namespace, as with kubectl apply -n")
}

// hasOverlay reports whether the user asked for a what-if change.
func (s snapshotSource) hasOverlay() bool {
	return len(s.overlayPaths) > 0 || len(s.overlayDeletes) > 0
}

// load returns the snapshot to analyze: the base snapshot, with the overlay
// applied when the user gave one. The overlay summary and its warnings go to
// stderr and into the snapshot's collection warnings, so a report made from the
// result says that it describes a cluster state that does not exist yet.
func (s snapshotSource) load(cmd *cobra.Command, build BuildInfo) (models.Snapshot, error) {
	snapshot, err := s.loadBase(cmd, build)
	if err != nil || !s.hasOverlay() {
		return snapshot, err
	}
	changed, result, err := s.applyOverlay(cmd, snapshot)
	if err != nil {
		return models.Snapshot{}, err
	}
	for _, line := range overlayNotes(result) {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "overlay: "+line); err != nil {
			return models.Snapshot{}, err
		}
	}
	return changed, nil
}

// applyOverlay returns a copy of snapshot with the overlay applied. It does not
// change snapshot, so `paths --diff` can compare the two.
func (s snapshotSource) applyOverlay(cmd *cobra.Command, snapshot models.Snapshot) (models.Snapshot, overlay.Result, error) {
	changed, result, err := overlay.Apply(snapshot, overlay.Options{
		Paths:            s.overlayPaths,
		Deletes:          s.overlayDeletes,
		DefaultNamespace: s.overlayNamespace,
		Stdin:            cmd.InOrStdin(),
	})
	if err != nil {
		return models.Snapshot{}, overlay.Result{}, err
	}
	changed.Metadata.CollectionWarnings = append(slices.Clone(snapshot.Metadata.CollectionWarnings), overlayNotes(result)...)
	return changed, result, nil
}

// overlayNotes is what a reader of the result must know about the overlay: that
// there is one, and each warning it gave.
func overlayNotes(result overlay.Result) []string {
	notes := []string{
		fmt.Sprintf("This result includes a what-if overlay (%s). It describes a cluster state that does not exist yet.", result.Summary()),
	}
	return append(notes, result.Warnings...)
}

// loadBase returns the snapshot from inputFile when it is set, or collects one
// from the live cluster. It then applies --eks-access-entries and
// --cloud-provider.
func (s snapshotSource) loadBase(cmd *cobra.Command, build BuildInfo) (models.Snapshot, error) {
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
