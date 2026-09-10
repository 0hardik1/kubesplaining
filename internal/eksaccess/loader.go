// Package eksaccess loads an EKS access-entries export into models.EKSCloudState.
// Access entries live in the EKS control plane, not in the cluster, so the
// collector cannot list them; scripts/eks-access-entries.sh gathers them with
// the AWS CLI and this package reads the resulting file for `scan
// --eks-access-entries`. The loader is lenient about shape so a hand-assembled
// file from the raw CLI responses also works.
package eksaccess

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// export is the document scripts/eks-access-entries.sh writes.
type export struct {
	Cluster       *clusterDoc `json:"cluster,omitempty"`
	AccessEntries []entryDoc  `json:"accessEntries"`
}

// clusterDoc is the subset of `aws eks describe-cluster` we read.
type clusterDoc struct {
	Name         string `json:"name"`
	AccessConfig struct {
		AuthenticationMode string `json:"authenticationMode"`
	} `json:"accessConfig"`
}

// entryDoc is one element of accessEntries. Two shapes are accepted: the
// wrapped form {"accessEntry": {...}, "associatedAccessPolicies": [...]} that
// the script emits (mirroring the two CLI responses), and the bare form where
// the describe-access-entry fields sit at the top level.
type entryDoc struct {
	AccessEntry              *accessEntryDoc `json:"accessEntry,omitempty"`
	AssociatedAccessPolicies []policyDoc     `json:"associatedAccessPolicies,omitempty"`
	accessEntryDoc
}

type accessEntryDoc struct {
	PrincipalARN     string   `json:"principalArn"`
	Type             string   `json:"type"`
	Username         string   `json:"username"`
	KubernetesGroups []string `json:"kubernetesGroups"`
}

type policyDoc struct {
	PolicyARN   string `json:"policyArn"`
	AccessScope struct {
		Type       string   `json:"type"`
		Namespaces []string `json:"namespaces"`
	} `json:"accessScope"`
}

// Load reads path and returns the parsed state plus non-fatal warnings
// (entries skipped for a missing principalArn). A file that parses but holds
// no entries is valid: an API-mode cluster with every entry removed is a real
// configuration and the empty list is the answer.
func Load(path string) (*models.EKSCloudState, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read eks access entries: %w", err)
	}
	state, warnings, err := Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse eks access entries %s: %w", path, err)
	}
	state.Source = path
	return state, warnings, nil
}

// Parse decodes an export document. Both the object form ({"cluster": ...,
// "accessEntries": [...]}) and a bare JSON array of entries are accepted.
func Parse(raw []byte) (*models.EKSCloudState, []string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil, fmt.Errorf("file is empty")
	}
	var doc export
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &doc.AccessEntries); err != nil {
			return nil, nil, err
		}
	} else {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, nil, err
		}
		if doc.AccessEntries == nil && doc.Cluster == nil {
			return nil, nil, fmt.Errorf("no \"accessEntries\" key (expected the output of scripts/eks-access-entries.sh)")
		}
	}

	state := &models.EKSCloudState{}
	if doc.Cluster != nil {
		state.ClusterName = doc.Cluster.Name
		state.AuthenticationMode = strings.ToUpper(strings.TrimSpace(doc.Cluster.AccessConfig.AuthenticationMode))
	}

	var warnings []string
	for i, e := range doc.AccessEntries {
		fields := e.accessEntryDoc
		if e.AccessEntry != nil {
			fields = *e.AccessEntry
		}
		if strings.TrimSpace(fields.PrincipalARN) == "" {
			warnings = append(warnings, fmt.Sprintf("eks access entries: entry %d has no principalArn; skipped", i))
			continue
		}
		entry := models.EKSAccessEntry{
			PrincipalARN:     strings.TrimSpace(fields.PrincipalARN),
			Type:             strings.ToUpper(strings.TrimSpace(fields.Type)),
			Username:         fields.Username,
			KubernetesGroups: cleanStrings(fields.KubernetesGroups),
		}
		for _, p := range e.AssociatedAccessPolicies {
			if strings.TrimSpace(p.PolicyARN) == "" {
				continue
			}
			entry.AccessPolicies = append(entry.AccessPolicies, models.EKSAccessPolicyAssociation{
				PolicyARN:  strings.TrimSpace(p.PolicyARN),
				ScopeType:  strings.ToLower(strings.TrimSpace(p.AccessScope.Type)),
				Namespaces: cleanStrings(p.AccessScope.Namespaces),
			})
		}
		state.AccessEntries = append(state.AccessEntries, entry)
	}
	// Deterministic order so finding output does not depend on CLI pagination.
	sort.SliceStable(state.AccessEntries, func(i, j int) bool {
		return state.AccessEntries[i].PrincipalARN < state.AccessEntries[j].PrincipalARN
	})
	return state, warnings, nil
}

func cleanStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
