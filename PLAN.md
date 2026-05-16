# Kubesplaining Implementation Plan

Implementation roadmap. Status reflects code in-tree as of 2026-04-21.

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
- [ ] `persistentvolumes` / `persistentvolumeclaims` collection
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
- [ ] Remaining technique IDs: -002 (pod create + PSA bypass), -004 (pods/exec), -006 (secrets get), -007 (secret creation token theft correlation), -011 (CSR), -013 (ephemeral containers), -015 (portforward), -016 (node drain)

### Pod Security — [internal/analyzer/podsec/](internal/analyzer/podsec/analyzer.go)
- [x] Container SecurityContext (privileged, runAsRoot, capabilities)
- [x] Pod namespaces (hostNetwork, hostPID, hostIPC)
- [x] Dangerous hostPath mounts, docker/containerd sockets
- [x] Default SA usage, mutable image tags
- [x] `allowPrivilegeEscalation` (`KUBE-PODSEC-APE-001`), `readOnlyRootFilesystem` (`KUBE-PODSEC-READONLY-001`), `seccompProfile` (`KUBE-PODSEC-SECCOMP-001`), `procMount: Unmasked` (`KUBE-PODSEC-PROCMOUNT-001`)
- [ ] Exhaustive dangerous-capability list (SYS_PTRACE, DAC_OVERRIDE, SYS_MODULE, SYS_RAWIO, MKNOD, AUDIT_WRITE, etc.)
- [ ] PersistentVolume hostPath bypass check (KUBE-ESCAPE-011)
- [ ] Pod Security Admission namespace label assessment — `pod-security.kubernetes.io/{enforce,audit,warn}`
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
- [ ] Cloud identity edges (IRSA/Workload Identity) — blocked on Cloud Provider Integration below
- [ ] CSR-based node impersonation edge (KUBE-PRIVESC-011)
- [ ] `system:masters` impersonation edge
- [ ] Graph visualization page in HTML report

### Cloud Provider Integration — **NOT STARTED**
- [ ] EKS: aws-auth mapping, IRSA trust-policy cross-check, IMDS exposure, API server endpoint exposure
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
- [ ] Privilege-escalation paths page
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
- [ ] `EscalationGraph` / `EscalationNode` / `EscalationEdge` types
- [ ] `CloudIdentity` model
- [~] Project layout: single-file collector and scoring stub diverge from the planned per-resource layout but this is cosmetic

## Testing

- [x] Unit tests on every analyzer + report structure test
- [x] `make e2e` kind cluster with intentionally-risky manifests ([scripts/kind-e2e.sh](scripts/kind-e2e.sh))
- [ ] Snapshot-based regression tests with expected-findings fixtures
- [ ] Variant-specific snapshots (EKS/GKE/AKS at minimum)
- [ ] Performance benchmarks on large snapshots

---

## Next Goal

**`Finding.Remediation.Patch`** (STRATEGY.md Tier 2.6). Generate a concrete remediation alongside each finding: a `kubectl patch` JSON snippet that removes the dangerous setting, or a Kyverno / Gatekeeper policy that would have blocked the manifest at admission time. Existing analyzers already carry `RemediationSteps`; this is the next-largest gap, since "tell me what to do" is the single most common ask in scanner reviews and nobody has shipped it for K8s. After that, the next leverage item is **`scan --baseline old.json` + `kubesplaining diff`** (STRATEGY.md Tier 2.7) for continuous-monitoring deltas.

## Completed

- CIS/NSA framework tags on every rule — `models.FrameworkRef` and `Finding.Frameworks` ([internal/models/finding.go](internal/models/finding.go)); hand-maintained rule → control mapping table for CIS Kubernetes Benchmark v1.9 and NSA/CISA Kubernetes Hardening Guide v1.2 ([internal/compliance/mapping.go](internal/compliance/mapping.go)); engine post-processing pass that decorates every finding ([internal/analyzer/engine.go](internal/analyzer/engine.go)); Compliance Coverage tab in the HTML report grouping by framework → control ([internal/report/compliance_section.go](internal/report/compliance_section.go), template additions in [internal/report/assets/report.html.tmpl](internal/report/assets/report.html.tmpl)); `--compliance cis|nsa` flag on `scan`, `scan-resource`, and `report` that filters output to findings tagged with the requested framework. JSON/SARIF/CSV outputs gain the `frameworks` field automatically — additive and back-compatible.
- Pod Security container-hardening trio — `KUBE-PODSEC-READONLY-001` (writable rootfs, MEDIUM), `KUBE-PODSEC-SECCOMP-001` (no seccomp profile / Unconfined, MEDIUM), `KUBE-PODSEC-PROCMOUNT-001` (`procMount: Unmasked`, HIGH). Detection in [internal/analyzer/podsec/analyzer.go](internal/analyzer/podsec/analyzer.go) (per-container loop + `seccompUnconfined` helper that consults both pod- and container-level SecurityContext). PSA mitigation extended in [internal/analyzer/admission/mitigation/psa.go](internal/analyzer/admission/mitigation/psa.go): `procMount` is Baseline-or-stricter-blocked; the other two are Restricted-only. E2E coverage via [testdata/e2e/vulnerable.yaml](testdata/e2e/vulnerable.yaml) `risky-app` (READONLY/SECCOMP fire from omitted fields; PROCMOUNT fires from explicit `procMount: Unmasked`).
- Stale / dangling RBAC bindings — `KUBE-RBAC-STALE-001` (dangling roleRef) and `KUBE-RBAC-STALE-002` (dangling ServiceAccount subject). Third pass in [internal/analyzer/rbac/analyzer.go](internal/analyzer/rbac/analyzer.go) emits one finding per (binding, subject) pair; built-in `cluster-admin`/`admin`/`edit`/`view` roles are allowlisted so partial snapshots don't false-fire, and `User`/`Group` subjects are intentionally not validated (Kubernetes has no inventory of them). Unit tests in [internal/analyzer/rbac/analyzer_test.go](internal/analyzer/rbac/analyzer_test.go); e2e fixtures in [testdata/e2e/vulnerable.yaml](testdata/e2e/vulnerable.yaml) and assertions in [scripts/kind-e2e.sh](scripts/kind-e2e.sh).
- Composite scoring & correlation (MVP) — `scoring.Factors` + `scoring.Compose`, `scoring.ChainModifier`, engine post-run correlation that bumps non-privesc findings whose Subject has a privesc chain, cross-module dedup on `(RuleID, Subject, Resource)`. Tests in [internal/scoring/scorer_test.go](internal/scoring/scorer_test.go) and [internal/analyzer/correlate_test.go](internal/analyzer/correlate_test.go).
- Privilege Escalation Path Detection (MVP) — verified on `make e2e`: picks up the `kubeadm:cluster-admins` direct cluster-admin path, the canonical 2-hop `create pods → mount default SA → node-escape via privileged pod`, and the 1-hop `secrets cluster-wide → kube-system-secrets` chain.
