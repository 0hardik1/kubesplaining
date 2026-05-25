# Kubesplaining Implementation Plan

Implementation roadmap. Status reflects code in-tree as of 2026-05-17.

Legend: `[x]` done · `[~]` partial · `[ ]` not started. Partial items list what's missing.

---

## CLI Interface

- [x] `download` — [internal/cli/download.go](internal/cli/download.go)
- [x] `scan` (live + `--input-file`) — [internal/cli/scan.go](internal/cli/scan.go)
- [x] `scan-resource` — [internal/cli/scan_resource.go](internal/cli/scan_resource.go)
- [x] `create-exclusions-file` — [internal/cli/create_exclusions.go](internal/cli/create_exclusions.go)
- [x] `report` (regenerate from findings JSON) — [internal/cli/report.go](internal/cli/report.go)
- [x] `version` — [internal/cli/version.go](internal/cli/version.go)
- [x] `--ci-mode` / `--ci-max-critical` / `--ci-max-high` exit-code gates — [internal/cli/scan.go:94-101](internal/cli/scan.go)
- [x] `--max-privesc-depth` flag — [internal/cli/scan.go:123](internal/cli/scan.go)
- [ ] `--custom-rules` flag for user-supplied rule files
- [ ] `--custom-guidance` / `--custom-appendix` on `report`

## Connection & Authentication

- [x] Kubeconfig / direct API+token / in-cluster SA — [internal/connection/manager.go](internal/connection/manager.go)
- [ ] **Permission discovery via `SelfSubjectAccessReview` / `SelfSubjectRulesReview`** — currently no pre-scan permission probe; missing perms are only observed lazily when a list call fails.

## Data Collection

- [x] Core RBAC / workload / network / webhook / node / SA / secret-metadata / configmap collection — [internal/collector/collector.go](internal/collector/collector.go)
- [~] Collector not yet split into per-resource files (one ~646-line `collector.go`). Cosmetic; leave until a second collector appears.
- [ ] `certificatesigningrequests` collection
- [ ] `storageclasses` collection
- [x] `persistentvolumes` / `persistentvolumeclaims` collection — added in slot #11 to back the PV hostPath bypass check
- [ ] `events` collection (optional)
- [ ] Cluster metadata: feature gates, PSP admission enabled flag
- [ ] Cloud provider detection + metadata — no `collector/cloud/`
- [ ] `--include-secret-values` + prominent warning

## Analysis Modules

### RBAC — [internal/analyzer/rbac/](internal/analyzer/rbac/analyzer.go)
- [x] Effective permission aggregation — [internal/permissions/aggregate.go](internal/permissions/aggregate.go)
- [x] Dangerous permissions: wildcards, pod/workload create, secret access, impersonate, escalate/bind, nodes/proxy, serviceaccounts/token, configmap modification (KUBE-PRIVESC-001, -003, -005, -008, -009, -010, -012, -014, -017)
- [x] Overly-broad bindings (KUBE-RBAC-OVERBROAD-001)
- [x] Stale / unused bindings — dangling RoleRef (`KUBE-RBAC-STALE-001`) and dangling ServiceAccount subjects (`KUBE-RBAC-STALE-002`). User/Group subject existence is intentionally not validated: the snapshot has no Users/Groups inventory (Kubernetes authenticates them externally and keeps no roster). Built-in `cluster-admin`/`admin`/`edit`/`view` ClusterRoles are allowlisted so partial snapshots don't false-fire.
- [x] CSR mint primitive (`KUBE-PRIVESC-011`): a subject holding cluster-scoped `create certificatesigningrequests` AND `update/patch certificatesigningrequests/approval` can self-mint a `system:masters` x509 client cert. The rbac analyzer emits the per-subject finding; the privesc graph adds a `csr_approve` edge from the subject to the `system_masters` sink so the BFS produces `KUBE-PRIVESC-PATH-SYSTEM-MASTERS` paths.
- [x] Remaining technique IDs, completing the documented 17-entry KUBE-PRIVESC taxonomy: -002 (pod `create` into a namespace whose Pod Security Admission does not block privileged pods; emitted alongside -001 since token theft and host escape are distinct impacts, and adds a `pod_create_privileged_escape` graph edge to the `node_escape` sink), -004 (`pods/exec` / `pods/attach`), -006 (secrets `get`-only, split from -005 which is now `list`/`watch`; the listing case wins when a subject holds both), -007 (secret `create` + `get` correlation: mint a legacy token Secret pointed at a privileged SA then read the controller-populated token; adds a `secret_mint_token` edge to the `token_mint` sink), -013 (`pods/ephemeralcontainers` `update`/`patch`; adds an `ephemeral_container_inject` edge to running pods' SAs), -015 (`pods/portforward`, scored as lateral movement rather than a cluster-sink escalation), -016 (`delete pods` + cluster-scoped `nodes/status` write or `delete nodes` correlation; adds a `node_drain_migrate` edge to the `node_escape` sink). All seven ship with content builders, glossary technique explainers, remediation hints, unit tests, and e2e fixtures (`testdata/e2e/vulnerable/16-privesc-rbac.yaml`).

### Pod Security — [internal/analyzer/podsec/](internal/analyzer/podsec/analyzer.go)
- [x] Container SecurityContext (privileged, runAsRoot, capabilities)
- [x] Pod namespaces (hostNetwork, hostPID, hostIPC)
- [x] Dangerous hostPath mounts, docker/containerd sockets
- [x] Default SA usage, mutable image tags
- [x] `allowPrivilegeEscalation` (`KUBE-PODSEC-APE-001`), `readOnlyRootFilesystem` (`KUBE-PODSEC-READONLY-001`), `seccompProfile` (`KUBE-PODSEC-SECCOMP-001`), `procMount: Unmasked` (`KUBE-PODSEC-PROCMOUNT-001`)
- [x] Exhaustive dangerous-capability list — `KUBE-PODSEC-CAPS-001` (one finding per container × capability) covering `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `NET_ADMIN`, `BPF`, `SYS_PTRACE`, `DAC_OVERRIDE`, `MKNOD`, `SYS_CHROOT`, `NET_RAW`, `AUDIT_WRITE`; `capabilities.add: [ALL]` expands to one finding per dangerous cap.
- [x] PersistentVolume hostPath bypass check (`KUBE-PV-HOSTPATH-001`) — Pod -> PVC -> PV walk; flags sensitive hostPath sources PSA cannot see through
- [x] Pod Security Admission namespace label assessment (`KUBE-PSA-LABELS-001`) — flags namespaces running Baseline violators with no `enforce` label
- [ ] Legacy PSP permissiveness

### Network Policy — [internal/analyzer/network/](internal/analyzer/network/analyzer.go)
- [x] Coverage & weakness (default-allow, namespace-wide allow)
- [x] Cross-namespace communication map (KUBE-NETPOL-CROSSNS-001)
- [x] Egress-to-metadata-endpoint (`169.254.169.254`) detection (KUBE-NETPOL-IMDS-001)

### Secrets & ConfigMaps — [internal/analyzer/secrets/](internal/analyzer/secrets/analyzer.go)
- [x] Long-lived SA token secrets, excessive secret access
- [x] Stale secrets (not referenced by any pod) — KUBE-SECRETS-STALE-001
- [x] Cross-namespace secret references — KUBE-SECRETS-CROSSNS-001
- [x] TLS secret expiry — KUBE-SECRETS-TLS-EXPIRY-001 (best-effort, reads cert-manager annotations)
- [x] ConfigMap credential heuristics (keys like `password`, `token`, `dsn`, ...) — KUBE-CONFIGMAP-CREDS-001
- [ ] `aws-auth` / `coredns` ConfigMap analysis
- [ ] EncryptionConfiguration check (best-effort)

### Service Account — [internal/analyzer/serviceaccount/](internal/analyzer/serviceaccount/analyzer.go)
- [x] Default SA usage, token audience/TTL
- [ ] SA permission aggregation with cross-module risk correlation
- [ ] DaemonSet SA blast-radius flag (token present on every node)

### Privilege Escalation Path Detection — [internal/analyzer/privesc/](internal/analyzer/privesc/)
- [x] Graph model — [internal/models/escalation.go](internal/models/escalation.go)
- [x] Graph builder: subject nodes + sinks (cluster-admin, kube-system-secrets, node-escape); RBAC edges (pod-create, exec, secrets, impersonate, bind/escalate, nodes/proxy, token-request, wildcard, rolebinding-write) + pod-escape edges (privileged/hostPID/hostNetwork/hostIPC/sensitive hostPath)
- [x] BFS pathfinder with `--max-privesc-depth` (default 5), shortest-path per (source, target) dedup, system subjects skipped as sources and waypoints
- [x] Findings with `EscalationPath` hops, severity/score shaped by target + chain length
- [x] Cloud identity edges (IRSA + aws-auth + IMDS-pivot for EKS), implemented in [internal/analyzer/privesc/cloud_edges.go](internal/analyzer/privesc/cloud_edges.go). Adds three edge shapes: (1) IRSA edges from SA to an external `aws-iam` node; (2) aws-auth edges from the external node onward to `system_masters` / `cluster_admin` sinks; (3) IMDS-pivot edges from SA to `node_escape` when the pod can reach 169.254.169.254 and lacks an IRSA binding. External nodes carry `IsExternal=true`, are skipped as BFS sources, and are treated as terminal sinks (so `KUBE-PRIVESC-PATH-AWS-IAM-ROLE` fires for every IRSA-annotated SA). The pathfinder continues traversal THROUGH external sinks when they carry aws-auth outbound edges, so longer `KUBE-PRIVESC-PATH-SYSTEM-MASTERS` / `KUBE-PRIVESC-PATH-CLUSTER-ADMIN` chains surface as separate paths.
- [x] CSR-based cluster-admin edge (KUBE-PRIVESC-011) — added to `internal/analyzer/privesc/graph.go` as the `csr_approve` action targeting the `system_masters` sink. Subject must hold both `create csr` and `update csr/approval` cluster-scoped; correlated across rules by `finalizeCSRApprovals`.
- [x] `system:masters` impersonation edge — emitted by `internal/analyzer/privesc/graph.go` when a subject holds cluster-scoped `impersonate groups` (which subsumes `system:masters`). Action `impersonate_system_masters` → `sinkSystemMasters`.
- [ ] Graph visualization page in HTML report

### Cloud Provider Integration ([internal/analyzer/cloud/](internal/analyzer/cloud/analyzer.go))
- [x] EKS: aws-auth mapping (`KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001`, `KUBE-CLOUD-AWSAUTH-OVERBROAD-001`, `KUBE-CLOUD-AWSAUTH-PARSE-ERROR-001`), IRSA trust-policy cross-check (`KUBE-CLOUD-IRSA-ADMIN-ROLE-001`, `KUBE-CLOUD-IRSA-MISSING-001`), IMDS exposure (`KUBE-CLOUD-IMDS-PIVOT-001`). Per-rule logic in [internal/analyzer/cloud/eks/](internal/analyzer/cloud/eks/). `--cloud-provider auto|eks|gke|aks|none` on `scan` controls dispatch; the collector's `DetectCloudProvider` keys off `eks.amazonaws.com/{nodegroup,compute-type}` node labels for the auto path.
- [ ] EKS: API server endpoint exposure (public LB / NodePort indicators).
- [ ] EKS: Access Entries (post-2023 replacement for the aws-auth ConfigMap). The current `KUBE-CLOUD-AWSAUTH-*` family reads `kube-system/aws-auth` only, so clusters fully migrated to Access Entries are invisible to the IAM-to-RBAC class of rules. Detection requires calling the EKS `ListAccessEntries` / `DescribeAccessEntry` API (the entries live in the AWS control plane, not in the cluster snapshot), so this needs either a side-car AWS API mode or a separate `--aws-credentials` opt-in path that the offline scanner does not have today. Documented as a known limitation under the `KUBE-CLOUD-AWSAUTH-*` block in [docs/findings.md](docs/findings.md).
- [ ] GKE: Workload Identity, metadata concealment
- [ ] AKS: AAD pod identity, managed identities

### Admission Controller & Webhooks — [internal/analyzer/admission/](internal/analyzer/admission/analyzer.go)
- [x] Webhook inventory + bypass risks
- [ ] "No mutating webhook present" / "no OPA/Gatekeeper/Kyverno detected" posture findings
- [ ] Webhook `objectSelector` / namespace-exemption bypass analysis

### Container Security — **NOT STARTED**
- [ ] Missing resource limits/requests (KUBE-INFRA-005 DoS)
- [ ] Missing liveness/readiness probes
- [ ] Lifecycle hook exec commands
- [ ] Image registry allowlist, pull policy, digest pinning

### Node Security — **NOT STARTED**
- [ ] Kubelet version / runtime / OS version with CVE hints
- [ ] Control-plane nodes without NoSchedule taint
- [ ] Pods scheduled on control-plane nodes

### etcd & Control Plane Exposure — **NOT STARTED**
- [ ] API server LoadBalancer/NodePort exposure
- [ ] `/var/lib/etcd` hostPath mount detection
- [ ] Kubelet anonymous auth / read-only port indicators

### Namespace Isolation — **NOT STARTED**
- [ ] Per-namespace security score (PSA + NetPol + default-SA + quotas)
- [ ] Cross-namespace risk matrix

## Risk Scoring & Prioritization

- [x] Severity rank + threshold filter — [internal/scoring/scorer.go](internal/scoring/scorer.go)
- [x] **Composite score: `base × exploitability × blast_radius + chain_modifier`** — `scoring.Factors` + `scoring.Compose` implement the formula; `scoring.ChainModifier` is applied in the engine post-run pass ([internal/analyzer/correlate.go](internal/analyzer/correlate.go))
- [x] Chain modifier correlation: non-privesc findings whose Subject has a privesc path get a score bump keyed on highest reachable sink severity
- [x] Cross-module dedup on `(RuleID, Subject, Resource)` keeping highest score and merging tags ([internal/analyzer/correlate.go](internal/analyzer/correlate.go))
- [x] Controller-owned pod collapse — already handled in [internal/analyzer/podsec/analyzer.go:186](internal/analyzer/podsec/analyzer.go) via `isControlledPod`
- [~] Per-analyzer migration to emit `scoring.Factors` (instead of hand-picked `Score`) — type is in place, RBAC still inlines the math. Migration per module is future work so each analyzer can pick its own exploitability/blast-radius inputs.
- [~] Verb-level merge (same subject+resource, different verbs on the same rule) — deferred; current same-rule collisions are already handled within-module via `seen` maps.

## Report Generation

- [x] HTML report with module sections, category breakdowns, executive summary — [internal/report/report.go](internal/report/report.go) (grouped view-model; [report_test.go](internal/report/report_test.go) covers structure)
- [x] JSON, CSV triage, SARIF
- [x] Privilege-escalation paths page — a dedicated "Escalation paths" HTML tab ([internal/report/privesc_paths_section.go](internal/report/privesc_paths_section.go)) that lists every `KUBE-PRIVESC-PATH-*` chain exhaustively, grouped by the sink each path reaches (cluster-admin, system:masters, kube-system secrets, node escape, namespace-admin, token mint, external AWS IAM) and sorted by sink danger then severity. Each card shows the source subject, sink, score, hop count, a one-line summary, and the full hop chain (rendered by the shared `escalationPathHTML` renderer so it matches the Findings tab), plus a deep link to the finding's full remediation. It is the exhaustive complement to the above-the-fold hero panel (capped at 3) and the interactive Attack Graph (capped capability slate). Static and CSS-tab-gated; the interactive whole-graph visualization stays the separate item below.
- [ ] Service account inventory page
- [ ] Appendix with methodology / glossary
- [ ] `--custom-guidance` / `--custom-appendix` injection

## Exclusions

- [x] YAML parser + matcher — [internal/exclusions/](internal/exclusions/)
- [x] Preset profiles (`minimal` / `standard` / `strict` / `none`) — auto-applied by `scan` / `scan-resource` / `report` via `--exclusions-preset` (default `standard`)
- [x] `--from-snapshot` pre-population for `create-exclusions-file`

## Output Formats

All four present: HTML, JSON, CSV, SARIF.

## Kubernetes Variant Support

- [x] Generic (any conformant cluster) works via client-go
- [ ] Variant auto-detection from node labels / CRDs (EKS, GKE, AKS, OpenShift, Rancher, k3s) and variant-scoped false-positive suppression

## Technique Database

- [~] ~10 of 41 IDs wired into analyzers (see Analysis Modules above). Remaining 30+ IDs pending their parent modules.

## Internals

- [x] Core models: `Finding`, `Snapshot`, `SubjectRef`
- [x] `EscalationGraph` / `EscalationNode` / `EscalationEdge` types in [internal/models/escalation.go](internal/models/escalation.go). `EscalationNode` carries `IsSink`, `IsSystem`, `IsExternal`, and an `EscalationTarget` enum (added `aws_iam_role` for cloud edges). `EscalationEdge` records `From`, `To`, `Technique`, `Action`, `Permission`, `Description`.
- [x] `CloudIdentity` model in [internal/models/cloud_identity.go](internal/models/cloud_identity.go). Captures IRSA bindings and aws-auth mappings into a single structure (`Kind`, `ARN`, `IRSA`, `MappedGroups`, ...); the loader in [internal/analyzer/cloud/identity.go](internal/analyzer/cloud/identity.go) builds these from the snapshot so the privesc cloud-edges layer and the per-rule eks analyzers share one source of truth instead of each re-parsing the ConfigMap / SA annotation.
- [~] Project layout: single-file collector and scoring stub diverge from the planned per-resource layout but this is cosmetic

## Testing

- [x] Unit tests on every analyzer + report structure test
- [x] `make e2e` kind cluster with intentionally-risky manifests ([scripts/kind-e2e.sh](scripts/kind-e2e.sh))
- [ ] Snapshot-based regression tests with expected-findings fixtures
- [ ] Variant-specific snapshots (EKS/GKE/AKS at minimum)
- [ ] Performance benchmarks on large snapshots

---

## Next Goal

**Cloud Provider Integration: GKE Workload Identity.** EKS just landed (aws-auth + IRSA + IMDS-pivot + privesc cloud-identity edges), so the natural sequel is GKE. The shape of the work is symmetrical: detect the provider from node labels (`cloud.google.com/gke-nodepool`), parse the per-ServiceAccount `iam.gke.io/gcp-service-account` annotation as the GKE analog of IRSA, and emit a `KUBE-CLOUD-GKE-WI-ADMIN-001` / `-MISSING-001` family that mirrors the EKS IRSA rules. The privesc graph already has the `external:*` node shape and a generic `aws_iam_role` target enum value, so adding `gcp_service_account` is a small drop-in: ensure the external node, wire SA -> external edges from the new annotation, and let the existing BFS / glossary / remediation pipelines reuse the EKS plumbing. GKE Workload Identity uses GCE metadata server (169.254.169.254) for the unbound fallback, so the IMDS-pivot helper reuses cleanly: the cloud module just needs a GKE-specific Fargate-equivalent (`spec.nodeName` matching a GKE-Autopilot node) carve-out. AKS managed identities follow next and round out the provider trio.

## Completed

- **Cloud Provider Integration: EKS** (this slot). Added the `cloud` analyzer module with an EKS sub-package: `internal/analyzer/cloud/analyzer.go` dispatches by `snapshot.Metadata.CloudProvider`, and `internal/analyzer/cloud/eks/{aws_auth,irsa,imds_pivot,detect,eks}.go` ships seven rule IDs: `KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001` (HIGH 8.6), `KUBE-CLOUD-AWSAUTH-OVERBROAD-001` (MEDIUM 6.2), `KUBE-CLOUD-AWSAUTH-PARSE-ERROR-001` (INFO), `KUBE-CLOUD-IRSA-ADMIN-ROLE-001` (HIGH 7.8 / 9.2 for reserved-SSO), `KUBE-CLOUD-IRSA-MISSING-001` (LOW 3.5), `KUBE-CLOUD-IMDS-PIVOT-001` (HIGH 8.2), `KUBE-CLOUD-PROVIDER-UNKNOWN-001` (INFO, reserved). Privesc graph extended with cloud-identity edges in `internal/analyzer/privesc/cloud_edges.go` (IRSA, aws-auth, IMDS-pivot) plus `KUBE-PRIVESC-PATH-AWS-IAM-ROLE` emitted from `internal/analyzer/privesc/analyzer.go` for paths terminating at an external IAM node; `models.TargetAWSIAMRole` and `EscalationNode.IsExternal` added to support external-identity nodes. `--cloud-provider auto|eks|gke|aks|none` flag on `scan` controls dispatch; auto-detection keys off `eks.amazonaws.com/{nodegroup,compute-type}` node labels. Glossary + Techniques entries added for `external_aws_iam`, `irsa_assume_role`, `aws_auth_admin`, `imds_node_role_pivot`. E2E coverage in `testdata/e2e/vulnerable/15-cloud-eks.yaml` with assertions in `testdata/e2e/expectations/cloud-eks.{expect,rollout}` against a `--exclusions-preset=minimal` scan so the kube-system-anchored aws-auth finding is not dropped; the kind nodes are stamped with `eks.amazonaws.com/nodegroup=kind-test` by `scripts/kind-e2e.sh` so `DetectCloudProvider` classifies the cluster as EKS.
- **Structured remediation hints across every analyzer**. The half-shipped `Finding.Remediation.Patch` feature is complete: `internal/remediation/{network,admission,secrets,serviceaccount,containersec}.go` join the existing `{podsec,rbac,privesc}` generators so all eight analyzer modules attach `RemediationHint` (kubectl patch, Kyverno / Gatekeeper policy, or RBAC diff) to every finding. Surfaced via a new `--remediation-patches` opt-in flag on `scan`, `scan-resource`, and `report`. The shared helpers (`jsonPatchHint`, `mergeHint`, `strategicHintRaw`, `commandOnlyHint`) live in `internal/remediation/common.go` alongside the original pod-spec wrappers. JSON / HTML / SARIF render the hints when present; CSV continues to omit them. Note: this is a behavioral change. Earlier in-tree podsec/rbac/privesc hint emission was unconditional; it is now gated by the same flag for consistency.
- CIS/NSA framework tags on every rule — `models.FrameworkRef` and `Finding.Frameworks` ([internal/models/finding.go](internal/models/finding.go)); hand-maintained rule → control mapping table for CIS Kubernetes Benchmark v1.9 and NSA/CISA Kubernetes Hardening Guide v1.2 ([internal/compliance/mapping.go](internal/compliance/mapping.go)); engine post-processing pass that decorates every finding ([internal/analyzer/engine.go](internal/analyzer/engine.go)); Compliance Coverage tab in the HTML report grouping by framework → control ([internal/report/compliance_section.go](internal/report/compliance_section.go), template additions in [internal/report/assets/report.html.tmpl](internal/report/assets/report.html.tmpl)); `--compliance cis|nsa` flag on `scan`, `scan-resource`, and `report` that filters output to findings tagged with the requested framework. JSON/SARIF/CSV outputs gain the `frameworks` field automatically — additive and back-compatible.
- Pod Security container-hardening trio — `KUBE-PODSEC-READONLY-001` (writable rootfs, MEDIUM), `KUBE-PODSEC-SECCOMP-001` (no seccomp profile / Unconfined, MEDIUM), `KUBE-PODSEC-PROCMOUNT-001` (`procMount: Unmasked`, HIGH). Detection in [internal/analyzer/podsec/analyzer.go](internal/analyzer/podsec/analyzer.go) (per-container loop + `seccompUnconfined` helper that consults both pod- and container-level SecurityContext). PSA mitigation extended in [internal/analyzer/admission/mitigation/psa.go](internal/analyzer/admission/mitigation/psa.go): `procMount` is Baseline-or-stricter-blocked; the other two are Restricted-only. E2E coverage via [testdata/e2e/vulnerable.yaml](testdata/e2e/vulnerable.yaml) `risky-app` (READONLY/SECCOMP fire from omitted fields; PROCMOUNT fires from explicit `procMount: Unmasked`).
- Stale / dangling RBAC bindings — `KUBE-RBAC-STALE-001` (dangling roleRef) and `KUBE-RBAC-STALE-002` (dangling ServiceAccount subject). Third pass in [internal/analyzer/rbac/analyzer.go](internal/analyzer/rbac/analyzer.go) emits one finding per (binding, subject) pair; built-in `cluster-admin`/`admin`/`edit`/`view` roles are allowlisted so partial snapshots don't false-fire, and `User`/`Group` subjects are intentionally not validated (Kubernetes has no inventory of them). Unit tests in [internal/analyzer/rbac/analyzer_test.go](internal/analyzer/rbac/analyzer_test.go); e2e fixtures in [testdata/e2e/vulnerable.yaml](testdata/e2e/vulnerable.yaml) and assertions in [scripts/kind-e2e.sh](scripts/kind-e2e.sh).
- Composite scoring & correlation (MVP) — `scoring.Factors` + `scoring.Compose`, `scoring.ChainModifier`, engine post-run correlation that bumps non-privesc findings whose Subject has a privesc chain, cross-module dedup on `(RuleID, Subject, Resource)`. Tests in [internal/scoring/scorer_test.go](internal/scoring/scorer_test.go) and [internal/analyzer/correlate_test.go](internal/analyzer/correlate_test.go).
- Privilege Escalation Path Detection (MVP) — verified on `make e2e`: picks up the `kubeadm:cluster-admins` direct cluster-admin path, the canonical 2-hop `create pods → mount default SA → node-escape via privileged pod`, and the 1-hop `secrets cluster-wide → kube-system-secrets` chain.
