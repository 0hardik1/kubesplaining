# Kubesplaining

[![Latest release](https://img.shields.io/github/v/release/0hardik1/kubesplaining?include_prereleases&sort=semver)](https://github.com/0hardik1/kubesplaining/releases)
[![Krew](https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fkubernetes-sigs%2Fkrew-index%2Fmaster%2Fplugins%2Fkubesplaining.yaml&query=%24.spec.version&label=krew&logo=kubernetes&logoColor=white)](https://github.com/kubernetes-sigs/krew-index/blob/master/plugins/kubesplaining.yaml)
[![License](https://img.shields.io/github/license/0hardik1/kubesplaining)](LICENSE)
[![CI](https://github.com/0hardik1/kubesplaining/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/0hardik1/kubesplaining/actions/workflows/lint.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/0hardik1/kubesplaining)](go.mod)

Kubesplaining is an open-source Kubernetes security assessment CLI that reads a live cluster or a captured snapshot and tells you exactly how an attacker can move through it. Unlike scanners that stop at "this resource is misconfigured," it builds a multi-hop RBAC privilege-escalation graph from every non-system subject to nine sinks (among them `cluster-admin`, `system:masters`, `node-escape`, and `kube-system-secrets`) and renders each chain with the actual verbs, evidence, and remediation. Outputs are risk-prioritized HTML, JSON, CSV, and SARIF reports for human review, GitHub code scanning, or CI delta gates.

<video src="https://github.com/user-attachments/assets/b286b407-391a-4495-be52-2841a77a2b9a" controls width="100%"></video>

*A tour of the HTML report: the Summary tab, the Attack paths tab with hover tracing and pinning, and the Findings tab.*

* [Live example report](https://0hardik1.github.io/kubesplaining/)

## Install

Pick whichever fits your workflow.

From a fresh clone (easiest, no install needed):

```bash
git clone https://github.com/0hardik1/kubesplaining
cd kubesplaining
make scan
```

`make scan` builds the binary (Hermit auto-downloads the pinned Go toolchain) and runs it against your current `kubectl` context in one step.

See [Installation](#installation) below for krew, `go install`, pre-built binaries, and checksums.

## vs the alternatives

Most scanners overlap on "is this pod privileged?" The differentiator is whether they show you the *chain* from a non-admin subject to cluster takeover, and whether they ship an actionable fix.

| Capability | kubesplaining | kubescape | trivy | polaris |
| --- | --- | --- | --- | --- |
| Multi-hop RBAC privesc graph | Yes (BFS over RBAC + pod state to 9 sinks, full hop chain) | No (per-binding flags only) | No | No |
| Per-finding remediation (patch / Kyverno / Gatekeeper) | Yes (prose + kubectl patch + policy YAML, per rule) | Partial (control description) | Partial (text only) | Partial (text only) |
| Snapshot diff for CI delta gates | Yes (`scan --baseline old.json`, fail only on *new* findings) | No | No | No |

Inspired by [Kinnaird McQuade](https://www.linkedin.com/in/kmcquade3/) at [BeyondTrust Phantom Labs](https://www.linkedin.com/company/beyondtrust-phantom-labs/) and his [Cloudsplaining](https://github.com/salesforce/cloudsplaining), which does the same job for AWS IAM. Kubesplaining reads a live cluster or a previously captured snapshot, analyzes it against a library of techniques, and produces a prioritized list of findings: explanation, not just detection.

## Why kubesplaining

Most Kubernetes scanners stop at "this resource is misconfigured." Kubesplaining answers a different question: **how would an attacker actually move through your cluster?** Given the RBAC bindings and pods you already have, it walks the escalation graph from every non-system subject and tells you which can reach `cluster-admin`, host root, or `kube-system` secrets, with the full hop chain attached.

It focuses on the ground attackers actually exploit:

- **Privilege escalation paths**: graph-based chains of "subject A can become subject B can reach sink X" via BFS to nine sinks (`cluster-admin`, `system:masters`, `node-escape`, `kube-system-secrets`, `namespace-admin`, `token-mint`, `aws-iam-role`, `traffic-intercept`, `node-identity`).
- **Overly permissive RBAC**: wildcards, impersonation, bind/escalate, secret reads, pod creation, token mint.
- **Pod-escape surface area**: privileged containers, host namespaces, sensitive hostPath mounts, container socket mounts.
- **Network isolation gaps**: namespaces with no NetworkPolicy, policies that allow broad internet egress.
- **Admission-control bypass**: webhooks that fail open, objectSelector bypasses, exempt sensitive namespaces.
- **Secrets and service-account hygiene**: legacy token secrets, credentials in ConfigMaps, default-SA mounting, DaemonSet token blast-radius.

Every finding names the technique, shows the evidence, and includes remediation.

**Use cases:**

- **Pentest / red-team engagements**: the escalation paths *are* the attack plan.
- **Security review before a new binding**: see if it closes the graph from someone untrusted to a sink.
- **Continuous assurance in CI**: `--ci-mode` with severity budgets fails the pipeline when high-severity findings cross a threshold.
- **Post-incident replay**: capture the snapshot, analyze offline, explain how the actor could have moved.

## Quickstart

After installing (see [Installation](#installation) below), point Kubesplaining at your current `kubectl` context:

```bash
kubesplaining scan                          # writes ./kubesplaining-report/
open kubesplaining-report/report.html       # macOS; xdg-open on Linux
```

To ask one question in the terminal, with no report to open:

```bash
kubesplaining paths --to cluster-admin              # who can reach cluster-admin?
kubesplaining paths --from ServiceAccount/dev/ci    # what can this identity reach?
```

See [Ask a question](#ask-a-question) for the output and the other filters.

Already cloned the repo? `make scan` builds the binary (Hermit auto-downloads the pinned Go toolchain) and runs it against your current `kubectl` context in one step, no separate install needed. Pass extra flags via `ARGS`, e.g. `make scan ARGS="--severity-threshold high --only-modules privesc"`.

For air-gapped or audit workflows, capture a snapshot first and analyze it offline:

```bash
kubesplaining download --output-file snapshot.json
kubesplaining scan --input-file snapshot.json
```

For one-off manifest checks without cluster access:

```bash
kubesplaining scan-resource --input-file deployment.yaml
```

## Installation

Pick the path that fits. They all produce the same `kubesplaining` CLI. The top of this README covers the from-clone path; this section adds krew, Go install, pre-built binaries, and Docker.

### kubectl krew

Install as a `kubectl` plugin via [Krew](https://krew.sigs.k8s.io/):

```bash
kubectl krew install kubesplaining
kubectl kubesplaining scan
```

Every command in this README works the same way behind `kubectl`, e.g. `kubectl kubesplaining scan --input-file snapshot.json`.

### Go install

```bash
go install github.com/0hardik1/kubesplaining/cmd/kubesplaining@latest
```

### Pre-built binary

Grab the archive matching your OS / arch from the [Releases page](https://github.com/0hardik1/kubesplaining/releases/latest), extract, and put `kubesplaining` on your `PATH`. Each release ships:

- `kubesplaining_<version>_Linux_x86_64.tar.gz` / `Linux_arm64.tar.gz`
- `kubesplaining_<version>_Darwin_x86_64.tar.gz` / `Darwin_arm64.tar.gz`
- `kubesplaining_<version>_Windows_x86_64.zip`
- `kubesplaining_<version>_checksums.txt` (SHA-256)

Verify the checksum, then move the binary into place:

```bash
shasum -a 256 -c kubesplaining_<version>_checksums.txt
sudo install kubesplaining /usr/local/bin/
```

### Docker

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/.kube/config:/kubeconfig:ro" -e KUBECONFIG=/kubeconfig \
  -v "$PWD:/work" -w /work \
  ghcr.io/0hardik1/kubesplaining:latest scan
```

The report is written to `./kubesplaining-report/` in the current directory. `--user` makes the container run as you, so it can read your kubeconfig and write the report with your ownership.

The image holds only the `kubesplaining` binary. Two kinds of kubeconfig do not work from inside it:

- A kubeconfig that calls a helper program for credentials (EKS with `aws eks get-token`, GKE with `gke-gcloud-auth-plugin`).
- A kubeconfig that points at `127.0.0.1` (kind, minikube, Docker Desktop).

For those clusters, use the binary. You can also capture a snapshot with the binary and analyze it in the container, which needs no kubeconfig:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work \
  ghcr.io/0hardik1/kubesplaining:latest scan --input-file snapshot.json
```

## What it checks

104 stable rule IDs across 11 modules today, plus the privilege-escalation graph that chains them. Full per-rule severity, detection logic, and remediation: [docs/findings.md](docs/findings.md).

| Module | Rules | Focus |
| --- | --- | --- |
| **rbac** | 33 | wildcard / impersonate / bind-escalate / secret-read / pod-create / nodes-proxy / token-create, the two-verb pairs the API server actually enforces (CSR create + approve, signer control, mutating-policy write + bind), and a version-gated CVE rule: write on both `statefulsets` and `controllerrevisions` steers kube-controller-manager into cross-namespace pod creation (CVE-2026-2270), reported only when the server version is unpatched |
| **podsec** | 19 | privileged, host namespaces, hostPath, container sockets, runAsRoot, dangerous capabilities, seccomp / procMount, PSA namespace labels, mutable tags |
| **containersec** | 4 | missing limits, missing probes, lifecycle exec hooks, images not digest-pinned |
| **network** | 7 | namespaces missing NetworkPolicy, broad-internet and IMDS egress, cross-namespace bridges, unselected workloads |
| **admission** | 4 | failurePolicy: Ignore, objectSelector bypass, sensitive-namespace exemptions, no policy engine at all |
| **secrets** | 8 | legacy SA token secrets, credential-like ConfigMap keys, CoreDNS tampering, cross-namespace Secret reach, TLS expiry, stale Secrets |
| **serviceaccount** | 4 | privileged SAs, default-SA RBAC, DaemonSet token blast-radius |
| **certificates** | 2 | CertificateSigningRequest objects: a workload ServiceAccount asking for a client cert, or a request against the `legacy-unknown` signer |
| **privesc** | 10 (9 sinks) | graph chains to cluster-admin / system:masters / node-escape / kube-system-secrets / namespace-admin / token-mint / aws-iam-role / traffic-intercept / node-identity. Hops are not only direct grants: workload controllers, catalogued operators steered as confused deputies (Flux, Argo CD, cert-manager, ...), and the CVE-2026-2270 StatefulSet-controller edge all appear as controller-mediated hops, and every path says whether its own recommended cut actually closes the route |
| **cloud** (EKS) | 9 | aws-auth and EKS Access Entry mappings to system:masters or admin-equivalent roles, IRSA admin roles, IMDS node-role pivot |
| **leastprivilege** | 4 | granted-but-unused RBAC verbs from audit-log diff; opt-in via `--audit-log`. See [docs/audit-logs.md](docs/audit-logs.md) for setup and the [Least-Privilege analyzer section](#least-privilege-analyzer-audit-log-driven) for the behavior matrix |

Every finding is tagged with a `RiskCategory` (`privilege_escalation`, `data_exfiltration`, `lateral_movement`, `infrastructure_modification`, `defense_evasion`) so the HTML report can group by impact lane.

Rule IDs are a **public surface**: they are stable across releases and referenced from `findings.json`, the SARIF output, and the e2e assertions in `scripts/kind-e2e.sh`.

## How it works

Four-stage pipeline:

```
┌───────────────┐    ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Connection   │ →  │  Collection   │ →  │   Analysis    │ →  │    Report     │
│  kubeconfig   │    │ snapshot.json │    │ 11 modules ∥  │    │  html/json/   │
│ / in-cluster  │    │ RBAC+workload │    │  findings[]   │    │   csv/sarif   │
└───────────────┘    └───────────────┘    └───────────────┘    └───────────────┘
```

The boundary that matters most: the **collector is the only thing that talks to the Kubernetes API**; analyzers consume a `Snapshot` and never make network calls. That's what makes `download` → `scan --input-file` work for offline analysis. Read-only access is sufficient: no admission webhooks, no agents, no CRDs installed.

For the per-stage walkthrough, the privesc graph mechanics, the data model, and the scoring formula: [docs/architecture.md](docs/architecture.md).

## Sample finding

What the output actually looks like. Each rule produces a `Finding` with stable `RuleID`, severity, evidence, and remediation; the privesc rules additionally carry an `EscalationPath` array.

<details>
<summary><strong>KUBE-PRIVESC-PATH-CLUSTER-ADMIN</strong>: service account reaches cluster-admin in 2 hops</summary>

```json
{
  "id": "KUBE-PRIVESC-PATH-CLUSTER-ADMIN:foo:builder-bot",
  "rule_id": "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
  "severity": "CRITICAL",
  "score": 9.3,
  "category": "privilege_escalation",
  "subject": { "kind": "ServiceAccount", "namespace": "foo", "name": "builder-bot" },
  "title": "ServiceAccount foo/builder-bot can reach cluster-admin equivalent in 2 hop(s)",
  "escalation_path": [
    {
      "from_subject": "ServiceAccount/foo/builder-bot",
      "to_subject":   "ServiceAccount/kube-system/replicaset-controller",
      "action":       "pod_create",
      "permission":   "create on pods",
      "gains":        "run a pod that mounts the kube-system replicaset-controller token"
    },
    {
      "from_subject": "ServiceAccount/kube-system/replicaset-controller",
      "to_subject":   "ClusterRole/cluster-admin",
      "action":       "wildcard_holder",
      "permission":   "*/*/*",
      "gains":        "this SA already holds cluster-admin equivalence"
    }
  ],
  "remediation": "Drop `create pods` from foo/builder-bot's role, OR move that workload off kube-system."
}
```

The HTML report renders this as a hop-by-hop card with technique explainers per edge; the SARIF output keeps the chain in the `properties.escalation_path` field of each result for IDE integration.

</details>

<details>
<summary><strong>KUBE-ESCAPE-001</strong>: privileged container with hostPath mount</summary>

```json
{
  "id": "KUBE-ESCAPE-001:default:debug-shell",
  "rule_id": "KUBE-ESCAPE-001",
  "severity": "CRITICAL",
  "score": 9.5,
  "category": "privilege_escalation",
  "resource": { "kind": "Pod", "namespace": "default", "name": "debug-shell" },
  "title": "Privileged container in default/debug-shell",
  "evidence": {
    "container": "debug",
    "securityContext": { "privileged": true },
    "volumeMounts": [{ "name": "host-root", "mountPath": "/host", "hostPath": "/" }]
  },
  "remediation": "Drop `privileged: true`; replace hostPath `/` with the specific files via ConfigMap / Secret / CSI."
}
```

</details>

<details>
<summary><strong>KUBE-RBAC-OVERBROAD-001</strong>: group bound directly to cluster-admin</summary>

```json
{
  "id": "KUBE-RBAC-OVERBROAD-001::ops-team-admin",
  "rule_id": "KUBE-RBAC-OVERBROAD-001",
  "severity": "CRITICAL",
  "score": 9.0,
  "category": "privilege_escalation",
  "subject": { "kind": "Group", "name": "ops-team" },
  "title": "Group ops-team is bound to cluster-admin",
  "evidence": {
    "clusterRoleBinding": "ops-team-admin",
    "roleRef": "cluster-admin"
  },
  "remediation": "Replace cluster-admin with a least-privilege role scoped to what ops-team actually needs."
}
```

</details>

For the full rule catalog (severity, detection, remediation per rule): [docs/findings.md](docs/findings.md).

## Ask a question

`scan` writes a full report. `paths` answers one question in the terminal. It searches the same graph, so each path has the same ID, score, and hops as the finding in the report.

**Who can reach a target?** `--to` keeps the paths that end at one target:

```console
$ kubesplaining paths --to cluster-admin
SEVERITY  SCORE  SOURCE                                TARGET         HOPS  CHAIN
CRITICAL  9.65   ServiceAccount/dashboard/admin-sa     cluster-admin  1     bound_to_cluster_admin
CRITICAL  9.25   ServiceAccount/monitoring/prometheus  cluster-admin  2     pod_create_token_theft > bound_to_cluster_admin

2 attack paths.
```

**What can one identity reach?** `--from` starts the search at that identity. Add `--verbose` to see each hop, the binding that grants it, and the fix:

```console
$ kubesplaining paths --from ServiceAccount/monitoring/prometheus --to cluster-admin --verbose
ServiceAccount/monitoring/prometheus -> cluster-admin
  severity: CRITICAL (score 9.25)   hops: 2
  id: KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/monitoring/prometheus:cluster_admin_equivalent

  1. pod_create_token_theft (moderate)
     from:       ServiceAccount/monitoring/prometheus
     to:         ServiceAccount/dashboard/admin-sa
     permission: create pods
     granted by: ClusterRoleBinding prometheus-reader (role prometheus-reader)
     result:     can create pods that mount ServiceAccount dashboard/admin-sa
  2. bound_to_cluster_admin (easy)
     from:       ServiceAccount/dashboard/admin-sa
     to:         cluster-admin
     permission: cluster-admin
     granted by: ClusterRoleBinding dashboard-admin (role cluster-admin)
     result:     bound to cluster-admin via dashboard-admin

  fix: Break the chain at the weakest hop: remove the create pods capability that enables hop 1 (ServiceAccount/monitoring/prometheus → ServiceAccount/dashboard/admin-sa).
    # Edit the binding and remove the offending subject from subjects:.
    kubectl edit clusterrolebinding prometheus-reader
```

The real output ends with a diff of that binding, left out here.

`paths` reads the live cluster by default. Each run collects the cluster again, so for more than one question capture the cluster one time and ask offline. An answer from a snapshot takes less than a second and needs no cluster access:

```bash
kubesplaining download --output-file snapshot.json
kubesplaining paths --input-file snapshot.json --to node-escape
kubesplaining paths --input-file snapshot.json --from ServiceAccount/dev/ci --output-format json
```

| Flag | Purpose |
| --- | --- |
| `--to <target>` | Keep the paths that end at one target: `cluster-admin`, `system-masters`, `kube-system-secrets`, `node-escape`, `namespace-admin[:<namespace>]`, `token-mint`, `aws-iam-role[:<arn>]`, `traffic-intercept`, `node-identity`. The names in `findings.json` (`kube_system_secrets`) also work. |
| `--from <identity>` | Start at one identity: `ServiceAccount/<namespace>/<name>` (or `sa/<namespace>/<name>`), `User/<name>`, `Group/<name>`. This is the form that the reports print, so you can paste it. `system:serviceaccount:<namespace>:<name>` also works. |
| `--id <finding-id>` | Keep the one path that has this finding ID. |
| `--verbose` | Show each hop with its binding and role, then the fix. |
| `--output-format json` | Print `{"total", "returned", "paths": [...]}`. Each path is a short record (source, target, severity, score, hops) without the explanatory prose of a full finding, so the output stays small for a script or an AI agent. |
| `--limit <n>` | List only the first N paths, highest severity and score first. `total` still counts all matches. |

Three behaviors to know:

- With no `--from`, `paths` lists the attack paths that `scan` reports, and the same exclusions apply. The output says how many paths the exclusions hide.
- `--from` ignores the exclusions, and it accepts an identity that `scan` does not use as a starting point: a built-in `system:` identity, a control-plane ServiceAccount, or a group such as `Group/system:authenticated` ("what can every authenticated user reach?").
- An identity that is not in the cluster is an error, not an empty answer. An empty answer for a mistyped name would look like "this identity is safe".

### Check a change before you apply it

`--overlay` applies manifests on top of a snapshot in memory. `--overlay-delete` removes one object. `--diff` then lists the attack paths that the change adds, removes, and changes. Nothing touches the cluster, so you can ask "does this RoleBinding open a path?" in a pull request, or "does this fix close the path?" before you run `kubectl`.

A new binding that looks harmless in review:

```console
$ kubesplaining paths --input-file snapshot.json --overlay ci-deployer-admin.yaml --diff
ADDED (2)
SEVERITY  SCORE  SOURCE                         TARGET         HOPS  CHAIN
CRITICAL  9.65   ServiceAccount/ci/deployer     cluster-admin  1     bound_to_cluster_admin
CRITICAL  9.25   ServiceAccount/default/reader  cluster-admin  2     pod_create_token_theft > bound_to_cluster_admin

The change adds 2 attack paths, removes 0, and changes 0. 2 stay the same.
$ echo $?
2
```

The first path is in the manifest. The second is not: `default/reader` can create pods, so it can now start a pod that runs as the new admin ServiceAccount.

A fix, checked before it is applied:

```console
$ kubesplaining paths --input-file snapshot.json --overlay-delete ClusterRoleBinding/reader-role --diff
REMOVED (2)
SEVERITY  SCORE  SOURCE                         TARGET               HOPS  CHAIN
CRITICAL  9.0    ServiceAccount/default/reader  node-escape          1     pod_create_privileged_escape
HIGH      8.45   ServiceAccount/default/reader  kube-system-secrets  1     read_secrets

The change adds 0 attack paths, removes 2, and changes 0. 0 stay the same.
```

A path that stays open by a second route is not listed as removed. It is listed under `CHANGED`, with the binding behind each route, so a fix that is not sufficient does not look like a fix:

```console
$ kubesplaining paths --input-file snapshot.json --to cluster-admin --overlay-delete ClusterRoleBinding/reader-admin-a --diff
CHANGED (1): still open, by a different route
ServiceAccount/default/reader -> cluster-admin
  before: bound_to_cluster_admin [ClusterRoleBinding reader-admin-a (role cluster-admin)]
          also: bound_to_cluster_admin [ClusterRoleBinding reader-admin-b (role cluster-admin)]
  after:  bound_to_cluster_admin [ClusterRoleBinding reader-admin-b (role cluster-admin)]

The change adds 0 attack paths, removes 0, and changes 1. 0 stay the same.
```

| Flag | Purpose |
| --- | --- |
| `--overlay <file\|dir\|->` | Apply the manifests in a file, in a directory (read recursively), or from standard input. An object replaces the one with the same kind, namespace, and name, or is added. Repeatable. |
| `--overlay-delete <object>` | Remove one object: `ClusterRoleBinding/<name>`, `ClusterRole/<name>`, `RoleBinding/<namespace>/<name>`, `Role/<namespace>/<name>`, `ServiceAccount/<namespace>/<name>`, `Pod/<namespace>/<name>`. An object that is not in the snapshot is an error. Repeatable. |
| `--overlay-namespace <ns>` | The namespace for a manifest that has no `metadata.namespace`, as with `kubectl apply -n`. Without it, such a manifest is an error. |
| `--diff` | Compare before and after. Exit code 2 when the change adds a path, 0 when it does not, 1 when the command fails. |

For a Helm chart or a Kustomize directory, render first and pipe the result in:

```bash
helm template my-release ./chart | kubesplaining paths --input-file snapshot.json --overlay - --diff
```

What the overlay does and does not model:

- It applies `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`, `ServiceAccount`, `Namespace`, and `Pod`. It skips other kinds and says so. A `Deployment` in the overlay adds no pod, because no controller runs. To model a new workload, overlay a `Pod` with the same pod spec.
- After a change to a ClusterRole, it derives the rules of the aggregated ClusterRoles (`admin`, `edit`, `view`, and your own) again, so a new role with an `aggregate-to-*` label has its effect.
- `--diff` does not apply the default exclusions, so a path that the change adds is never hidden. Pass an exclusions flag to apply them.
- `scan` takes the same three `--overlay` flags and writes a full report of the state after the change. The report says that it includes an overlay.

## Use with an AI agent

The repository ships an [Agent Skill](https://agentskills.io) named `attack-paths`. A skill is a Markdown file that tells a coding agent when and how to use a tool. With the skill installed, you can ask in plain words:

- "Who can reach cluster-admin in this cluster?"
- "What can the `ci` ServiceAccount in `dev` escalate to? Give me the smallest fix."
- "Review the RBAC in this cluster and show me the three worst paths."

The agent captures a snapshot with `kubesplaining download`, gets the answer from `kubesplaining paths` as JSON, explains each hop, proposes the change to the binding, and checks that change offline with `--overlay` and `--diff` before it shows it to you. The skill tells the agent not to change the cluster: you get a command or a patch, and you apply it.

In Claude Code:

```text
/plugin install kubesplaining --marketplace 0hardik1/kubesplaining
```

Or from a shell:

```bash
claude plugin marketplace add 0hardik1/kubesplaining
claude plugin install kubesplaining@kubesplaining
```

For other agents: the skill uses only the fields of the open [Agent Skills](https://agentskills.io) format, so an agent that reads `SKILL.md` files can use it. Copy [`plugins/kubesplaining/skills/attack-paths/`](plugins/kubesplaining/skills/attack-paths/) into the skills directory of your agent.

What to know before you use it:

- The skill needs the `kubesplaining` binary on your `PATH`, from a release that has the `paths` command (later than v1.3.0). It does not install the binary for you.
- The agent runs the binary with your kubeconfig, so it can read what you can read. `kubesplaining` only reads.
- The agent sees the output of `paths`: the names of identities, bindings, and roles. The skill tells it to keep the snapshot file out of the repository and not to send the file to a different service.

## Offline analysis

The collector and the analyzer are decoupled: the snapshot is a plain JSON file. Capture once, analyze repeatedly, in environments where credentials shouldn't sit on the analyst's machine:

```bash
# On a jumphost with cluster credentials:
kubesplaining download --output-file snapshot.json

# Move snapshot.json to your laptop / audit machine, then:
kubesplaining scan --input-file snapshot.json
```

Useful for:

- **Audit trails**: the snapshot is the evidence; reruns produce identical findings.
- **Air-gapped review**: analyze a production cluster without bringing kubeconfig off the jumphost.
- **Manifest scans**: `kubesplaining scan-resource --input-file deployment.yaml` runs the same analyzers against a single YAML, no cluster needed.

### Privacy posture for snapshots

The collector never reads raw Secret values (only metadata) and blanks every ConfigMap value through `redactConfigMapValues` so keys survive but payloads do not. Two well-known kube-system ConfigMaps are carve-outs and are stored verbatim because the analyzers that consume them need the values:

- `kube-system/aws-auth`: the EKS `mapRoles` / `mapUsers` payload (IAM role and user ARNs, mapped Kubernetes usernames and groups) is read by the cloud `aws-auth` analyzers to name the IAM principal that has cluster-admin reach. A snapshot from an EKS cluster therefore contains the cluster's IAM-to-RBAC trust map verbatim.
- `kube-system/coredns`: the Corefile value is substring-matched by `KUBE-CONFIGMAP-002` to detect rewrite directives and external DNS forwarders (`forward . 8.8.8.8`, `forward . 1.1.1.1`, `forward . tls://...`).

Treat snapshot files (and any HTML/JSON/CSV/SARIF reports generated from them) as sensitive when sharing across teams or storing in CI artifact buckets, especially on EKS clusters where the aws-auth carve-out exposes account IDs, IAM role inventory, and SSO group naming conventions. Every other ConfigMap value (including ones not on this allow-list) is blanked.

## Live EKS demo

Provisions a real EKS cluster in your own AWS account that exhibits a cross-namespace + AWS-pivot privilege escalation chain kubesplaining detects, then walks through actually exploiting it (privileged-pod node escape → harvest a co-resident IRSA token → assume the AWS role via STS → loop back as `system:masters` via aws-auth). Useful as a self-service teaching environment.

```bash
make eks-demo-up      # ~12 min: cluster + IAM + S3 + K8s manifests + aws-auth mapping
make eks-demo-scan    # ~30 sec: produces .tmp/eks-demo-report/report.html
make eks-demo-poc     # default dry-run; --execute to step through the attack interactively
make eks-demo-down    # ~10 min: tears down everything (cluster, IAM role, S3 bucket)
```

The cluster is named `holy-splain`. All AWS resources carry generic, account-agnostic names so the same scripts reproduce identically across operators. Cost: approximately $5/day while running.

Three docs go with the demo:

- [`docs/eks-demo.md`](docs/eks-demo.md): operator reference (prereqs, commands, troubleshooting).
- [`docs/eks-demo-walkthrough.md`](docs/eks-demo-walkthrough.md): chapter-style learning narrative. Walks through the attack chain step by step, explains every K8s and AWS internal involved (IRSA, projected SA tokens, Pod Security Admission, aws-auth, STS assume-role-with-web-identity), and ends with a defense recap of where each link in the chain could be broken.
- [`docs/eks-demo-iam.md`](docs/eks-demo-iam.md): operator IAM permissions required to run the setup.

## Least-Privilege analyzer (audit-log driven)

The `leastprivilege` module compares the RBAC permissions a ServiceAccount **has** (from the snapshot) against the ones it has **actually exercised** (from a kube-apiserver audit log) and flags the delta. It's the analog of AWS IAM Access Advisor for Kubernetes RBAC.

It emits four rule IDs:

- `KUBE-RBAC-UNUSED-ROLE-001`: Role bound to a mounted SA with zero observed events in the audit window.
- `KUBE-RBAC-UNUSED-RULE-001`: Every (verb, resource) triple in a Role rule is unused.
- `KUBE-RBAC-UNUSED-VERB-001`: Some verbs in a Role rule are unused; suggests a narrower verb list.
- `KUBE-RBAC-WILDCARD-USED-PARTIAL-001`: `verbs: ["*"]` is granted but the SA only used a subset.

The pre-existing `KUBE-RBAC-STALE-*` rules surface alongside in the Least Privilege HTML tab so dangling-binding cleanup and verb-level narrowing live in one view. Cluster-admin grants live in their own "Subjects bound to cluster-admin" inventory table on the same tab: directly bound subjects are listed for review rather than each one being flagged CRITICAL, because cluster-admin has legitimate uses (`system:masters`, break-glass groups) that vary by cluster. The standalone `KUBE-RBAC-OVERBROAD-001` finding still fires from the rbac module and shows up in the main Findings tab (and in JSON/CSV/SARIF output) for operators who want the per-binding alert.

### When does it fire?

The module is **opt-in via `--audit-log`**. A plain `kubesplaining scan` (no audit log) silently skips it, so no LP findings ship and existing CI baselines stay unchanged.

| Command | Audit log required? | What you get |
| --- | --- | --- |
| `kubesplaining scan` / `make scan` | No | Same behavior as before; module silently no-ops. |
| `scan --audit-log <path>` | Used if supplied | LP findings appear alongside the regular findings. |
| `scan --least-privilege-only --audit-log <path>` | **Yes** (CLI pre-flight errors if missing) | Only LP findings; HTML report opens on the Least Privilege tab; Summary / Attack paths / Findings / Compliance tabs are hidden. |
| `make scan-lp AUDIT_LOG=<path>` | **Yes** (Makefile errors if missing) | Same as the focused mode above; convenience target. |

### Quick start

```bash
# 1. Capture audit logs from your cluster - see docs/audit-logs.md for
#    kubeadm / kind / EKS setup. Audit policy level "Metadata" is enough.

# 2. Run the focused mode against a snapshot (or live cluster) + your audit log:
make scan-lp AUDIT_LOG=./audit.log ARGS="--input-file snapshot.json"

# or directly:
kubesplaining scan \
  --input-file snapshot.json \
  --audit-log ./audit.log \
  --audit-source native \
  --audit-window-days 30 \
  --least-privilege-only
```

### What's in the report

The Least Privilege tab carries two summary tables on top, each row spelling out the exact action:

- **Unused RBAC resources**: Roles/ClusterRoles/Bindings that look like delete candidates. Each row names the binding to remove (e.g. `Delete ClusterRoleBinding/dashboard-admin (scope down to a narrower ClusterRole)`).
- **Role to verb activity**: Verb-level narrowing opportunities with side-by-side **Used** vs **Unused** verb lists grouped by verb (`get: deployments|pods`), plus a "what to do" action and the suggested narrower-Role YAML on the per-finding card below.

When the audit log contains non-ServiceAccount callers (humans, groups, kubelets), the tab shows a one-line note explaining they're out of scope: kubesplaining only correlates ServiceAccount-bound RBAC, and human users belong in IdP / SSO group review.

### Audit log details

`docs/audit-logs.md` walks through enabling audit logging on **self-managed / kubeadm**, **kind**, and **EKS** clusters, what audit-policy level is needed, and how to export from CloudWatch. The privacy posture is preserved: audit `Metadata` level does **not** include request bodies, so secrets and ConfigMap values are still never read.

## CI integration

The SARIF output integrates with [GitHub code scanning](https://docs.github.com/en/code-security/code-scanning) so findings appear as PR annotations. On GitHub Actions, the [GitHub Action](#use-the-github-action) runs the scan and uploads `findings.sarif` in one step.

On any other CI system, call the CLI and fail the build on findings over budget with `--ci-mode`:

```bash
kubesplaining scan --ci-mode --ci-max-critical 0 --ci-max-high 0
```

`--ci-mode` exits with code 2 when the count of critical / high findings crosses the configured thresholds; combine with `--severity-threshold` to scope what counts. Any other failure (bad flags, unreachable cluster) exits with code 1, so a pipeline can tell "over budget" from "the scan did not run". The gate counts every finding: `--max-findings` shortens the HTML report only.

## Exclusions

`scan`, `scan-resource`, and `report` **auto-apply the `standard` exclusions preset by default**, so findings about built-in Kubernetes plumbing are suppressed up front. That covers kube-system / kube-public / kube-node-lease namespaces, kube-controller-manager service accounts (`clusterrole-aggregation-controller`, `generic-garbage-collector`, …), `system:*` users / groups / roles, and `kubeadm:*` groups and bootstrap roles. None of it is something an operator can change without breaking their cluster, so showing it as risk just buries the things that are actionable.

Pick a different baseline with `--exclusions-preset`:

| Preset | Behavior |
| --- | --- |
| `standard` (default) | Auto-applied. Filters kube-system / system:* / kubeadm:* noise. |
| `minimal` | Filters only `kube-public`, `kube-node-lease`, and `system:*`. |
| `none` (alias `strict`) | No built-in filtering: every finding surfaces, including control-plane noise. |

Layer custom rules on top with `--exclusions-file path.yml`. The user file is **merged** with the preset, so you keep the defaults and add your own suppressions (specific service accounts, expected workloads, custom rule-ID patterns). Generate a starter file:

```bash
kubesplaining create-exclusions-file --preset standard --output-file exclusions.yml
```

See [docs/exclusions.md](docs/exclusions.md) for the full YAML schema (Global / RBAC / PodSecurity / NetworkPolicy sections, all matchers support shell-style globs).

To audit what the defaults are hiding, re-run with `--exclusions-preset=none` and diff.

## Cheatsheet

### Commands

| Command | Purpose |
| --- | --- |
| `kubesplaining scan` | Analyze (live or `--input-file`) and write reports. |
| `kubesplaining paths` | Answer one question in the terminal: who can reach a target (`--to`), what an identity can reach (`--from`). |
| `kubesplaining download` | Capture a `snapshot.json` from a live cluster. Read-only. |
| `kubesplaining scan-resource` | Scan a single resource manifest for quick checks. |
| `kubesplaining report` | Re-render reports from an existing findings JSON. |
| `kubesplaining create-exclusions-file` | Emit a starter exclusions YAML. |
| `kubesplaining version` | Print build info. |

### Frequently used flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--severity-threshold` | `low` | Hide findings below this severity (`critical` / `high` / `medium` / `low` / `info`). |
| `--output-format` | `html,json` | Comma-separated list: `html`, `json`, `csv`, `sarif`. |
| `--output-dir` | `./kubesplaining-report` | Where reports are written. |
| `--only-modules` / `--skip-modules` | (none) | Scope analyzers (`rbac`, `podsec`, `network`, `admission`, `secrets`, `serviceaccount`, `privesc`, `leastprivilege`, `certificates`). |
| `--least-privilege-only` | `false` | Focus mode: hide everything except RBAC tightening opportunities and land on the **Least Privilege** tab. Requires `--audit-log`. |
| `--audit-log` | (none) | Path to a kube-apiserver audit log (file or directory; repeatable). Opt-in: without it the `leastprivilege` module is a no-op. See [docs/audit-logs.md](docs/audit-logs.md) for setup on self-managed, kind, and EKS. |
| `--audit-source` | `native` | Audit-log format: `native` (kube-apiserver JSON-lines) or `eks` (CloudWatch `filter-log-events` export). |
| `--audit-window-days` | `30` | How many days of audit history to consider. Widen for monthly cron jobs. |
| `--max-privesc-depth` | `5` | BFS depth cap for the escalation graph. |
| `--eks-access-entries` | (none) | Path to an EKS access-entries export from `scripts/eks-access-entries.sh <cluster>`. Access entries live in the EKS API, not the cluster, so without it an EKS scan reports `KUBE-CLOUD-ACCESSENTRY-NOT-EVALUATED-001` rather than silently skipping the IAM-to-RBAC class. See [docs/findings.md](docs/findings.md#cloud-provider-integration-eks-internalanalyzercloudeks). |
| `--ci-mode` | off | Exit with code 2 when over thresholds. Counts every finding. |
| `--ci-max-critical` / `--ci-max-high` | `0` / `0` | Max findings allowed at each severity in CI mode. |
| `--max-findings` / `--all-findings` | `0` / off | `--max-findings N` shortens `report.html` to every attack path plus the top N of the other findings. The default, `0`, lists every finding. `--all-findings` overrides the cap and stays for scripts that pass it. JSON, CSV, and SARIF always hold every finding. |
| `--exclusions-preset` | `standard` | `standard` / `minimal` / `none`. |
| `--exclusions-file` | (none) | User-supplied YAML, merged on top of the preset. |
| `--input-file` | (none) | Use a snapshot JSON instead of live collection. |
| `--namespaces` / `--exclude-namespaces` | (none) | Filter live collection by namespace. |
| `--parallelism` | `10` | Max parallel API requests during live collection. |

### Output formats

| Format | Use case |
| --- | --- |
| HTML | Human review; self-contained, works offline, includes per-finding educational copy |
| JSON | Programmatic consumption, snapshot diffing |
| CSV | Triage spreadsheets |
| SARIF | GitHub code scanning, IDE integration |

## FAQ

**Why is `system:masters` flagged in some clusters but not others?**
The privesc analyzer skips `system:*` subjects as *traversable intermediates* (so paths don't launder through the control plane) but it *does* report `system:*` as a sink-reach target if you can impersonate or otherwise escalate into it. If the analyzer doesn't see anyone with that capability, the rule stays silent. Three built-in groups are traversed rather than skipped: `system:authenticated`, `system:serviceaccounts`, and `system:serviceaccounts:<ns>`. Every identity of the matching type belongs to them, so a grant to one of them is reported as a path from each member.

**How accurate are the privesc paths?**
Each hop is validated against the snapshot's RBAC and pod state. The analyzer doesn't speculate. False positives come from chains that are *structurally* possible but operationally suppressed (e.g. an SA bound to a role that's never actually used). Severity is attenuated by chain length (hops ≥ 3 drop one bucket); use `--max-privesc-depth` to limit BFS aggressiveness.

**Can I run this against my prod cluster?**
Yes. Read-only access is sufficient. No webhooks, CRDs, agents, or pods are installed. Forbidden listings are downgraded to warnings, not fatal, so locked-down clusters still produce useful output.

**Why no admission webhook?**
Out of scope. The intent is *assessment*, not enforcement. If you want enforcement, generate Kyverno / Gatekeeper policies from the findings and hand them off to your policy engine.

**Why are findings excluded by default?**
The `standard` preset suppresses control-plane noise (kube-system, system:*, kubeadm:*) that an operator can't change without breaking their cluster. Re-run with `--exclusions-preset=none` to see everything.

## Where to go next

- **Full rule catalog** (implemented + planned): [docs/findings.md](docs/findings.md)
- **Architecture deep-dive** (per-stage walkthrough, scoring, data model): [docs/architecture.md](docs/architecture.md)
- **Exclusions YAML schema** (presets, sections, glob semantics): [docs/exclusions.md](docs/exclusions.md)
- **Roadmap & status**: [PLAN.md](PLAN.md)
- **Releases & changelog**: [CHANGELOG.md](CHANGELOG.md) / [GitHub Releases](https://github.com/0hardik1/kubesplaining/releases)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security disclosure**: [SECURITY.md](SECURITY.md) (GitHub Private Vulnerability Reporting only)
- **License**: [Apache-2.0](LICENSE)
- **End-to-end verification**: `make e2e` provisions a local kind cluster with intentionally risky manifests in `testdata/` and asserts expected findings

## Use the GitHub Action

The repository ships a composite Action at `action.yml`, so you can wire kubesplaining into a workflow without authoring the `docker run` invocation yourself. The action pulls the pinned GHCR image, executes a scan against either a live cluster (via a base64-encoded kubeconfig) or a pre-collected snapshot JSON, and optionally uploads the SARIF result to GitHub code scanning.

```yaml
# .github/workflows/kubesplaining.yml
name: Kubesplaining
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required by upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      # Option A: scan a pre-collected snapshot checked into the repo.
      - name: Scan offline snapshot
        uses: 0hardik1/kubesplaining@main
        with:
          input-file: testdata/snapshots/minimal-risky.json
          severity-threshold: medium
          fail-on-critical: 'true'
          upload-sarif: 'true'

      # Option B: scan a live cluster. Store the kubeconfig as a base64
      # secret (e.g. `cat ~/.kube/config | base64 | pbcopy`) under the
      # `KUBE_CONFIG_B64` repository secret first.
      # - name: Scan live cluster
      #   uses: 0hardik1/kubesplaining@main
      #   with:
      #     kubeconfig: ${{ secrets.KUBE_CONFIG_B64 }}
      #     severity-threshold: high
      #     compliance: cis
```

Inputs (all optional unless noted):

| Input | Default | Notes |
| --- | --- | --- |
| `version` | `latest` | GHCR image tag. To pin a release, use the bare version with no `v` prefix, for example `1.3.0`. |
| `kubeconfig` | (none) | Base64-encoded kubeconfig for live scans. Omit when using `input-file`. |
| `input-file` | (none) | Path (relative to the checkout) to a `kubesplaining download` snapshot JSON. |
| `severity-threshold` | `medium` | `critical` / `high` / `medium` / `low` / `info`. |
| `output-dir` | `./kubesplaining-report` | Created if missing. Holds `report.html`, `findings.json`, `findings.sarif`. |
| `fail-on-critical` | `true` | Adds `--ci-mode --ci-max-critical 0`; flip to `false` to surface findings without failing the build. |
| `upload-sarif` | `true` | Uploads `findings.sarif` via `github/codeql-action/upload-sarif@v4`. Requires `security-events: write`. |
| `compliance` | (none) | Optional filter: `cis` or `nsa`. |

The ref after `@` selects the action definition, and `version` selects the container image that it runs. The action definitions in releases v1.1.0 to v1.3.0 default `version` to `main`, an image tag that was never published. If you pin the action to one of those releases, set `version` too, for example `uses: 0hardik1/kubesplaining@v1.3.0` with `version: 1.3.0`.

Outputs: `report-dir` (absolute path to the report directory) and `sarif-file` (absolute path to `findings.sarif`, when emitted). The `.github/workflows/action-smoke.yml` workflow in this repo exercises the action against `testdata/snapshots/minimal-risky.json` on every PR that touches it.

## Credits

- [Kinnaird McQuade](https://www.linkedin.com/in/kmcquade3/), for the tool idea. His [Cloudsplaining](https://github.com/salesforce/cloudsplaining) inspired this project.
- [Ramesh Ramani](https://www.linkedin.com/in/rameshdotramani/) ([@secmesh](https://github.com/secmesh)): the least-privilege mode was inspired by his idea.
