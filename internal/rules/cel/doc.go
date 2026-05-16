// Package cel implements a loader and evaluator for user-supplied custom rules
// written as YAML files with a CEL expression body. CEL is the K8s-native
// expression language (used by ValidatingAdmissionPolicy and CRD
// x-kubernetes-validations), so users do not have to learn a new DSL to write
// internal-policy rules. See examples/custom-rules/ for the wire format.
//
// The loader (LoadDir) reads *.cel.yaml files and compiles each rule's
// expression once at startup; the evaluator (Evaluate) iterates the snapshot's
// matched resources and emits a models.Finding whenever the expression returns
// true. Two top-level variables are bound in the CEL environment: "resource"
// holds the per-instance Kubernetes object (as a generic map) and "snapshot"
// holds the full collected Snapshot (also as a generic map), so cross-resource
// rules ("any pod that mounts secret X") remain expressible.
package cel
