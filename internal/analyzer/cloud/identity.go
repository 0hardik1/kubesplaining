// Package cloud - identity discovery. Walks the snapshot for cloud-IAM identities
// surfaced via IRSA annotations and aws-auth mappings. This stub returns an empty
// slice; Unit 2 replaces with the real walk.
package cloud

import "github.com/0hardik1/kubesplaining/internal/models"

// CloudIdentitiesForSnapshot returns parsed cloud identities present in the snapshot.
// Unit 0 stub: returns empty. Unit 2 replaces.
func CloudIdentitiesForSnapshot(snapshot models.Snapshot) []models.CloudIdentity {
	_ = snapshot
	return nil
}
