# Kubesplaining vs. similar tools — full comparison

The [README](../README.md) carries a trimmed comparison covering the closest competitors. This doc is the long form: every Kubernetes security tool people commonly evaluate against kubesplaining, with notes on focus area, RBAC privesc capability, HTML output, offline support, and last meaningful release.

The space clusters into a few distinct lanes — CIS-benchmark checkers, manifest linters, broad-spectrum scanners, RBAC visualisers, offensive pentest kits. Kubesplaining sits at the intersection of "RBAC privilege-escalation graph" and "educational HTML report from an offline snapshot" — a combination that, as of writing, no single tool below covers.

| Tool | Stars | Primary focus | RBAC privesc paths | HTML report | Offline / snapshot | Last release |
|---|---|---|---|---|---|---|
| **Kubesplaining** | — | Cluster-wide RBAC privesc graph + educational HTML report | ✅ multi-hop BFS to 4 sinks | ✅ self-contained | ✅ `download` + `scan --input-file` | 2026 |
| [rbac-tool](https://github.com/alcideio/rbac-tool) | ~1.1k | RBAC visualisation, who-can queries, risky-perm rules | partial — flags risky permissions per-subject; does not BFS chains across multiple subjects to a sink | ✅ (graph as HTML/dot) | partial — connects to live cluster for discovery | 2024 |
| [krane](https://github.com/appvia/krane) | ~739 | RBAC static analysis + dashboard (RedisGraph-backed) | partial — built-in risk rules and Cypher ad-hoc queries over the RBAC graph; no out-of-the-box BFS to cluster-admin / system:masters sinks | ✅ (dashboard UI with network graph) | ✅ (can run against local RBAC YAML/JSON) | 2024 |
| [KubiScan](https://github.com/cyberark/KubiScan) | ~1.4k | Risky-RBAC permission scanner | partial — flags privileged service accounts and risky verbs; no graph / BFS chain analysis | ❌ (terminal tables) | ❌ (requires kubeconfig or in-cluster token) | 2023 |
| [kubescape](https://github.com/kubescape/kubescape) | ~11.3k | Broad scanner (NSA, MITRE, CIS controls) | ❌ | ✅ | ✅ (scans local YAML) | 2026 |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | ~8.0k | CIS Kubernetes Benchmark compliance | ❌ | ❌ | ❌ (runs as in-cluster job) | 2026 |
| [kube-linter](https://github.com/stackrox/kube-linter) | ~3.4k | Manifest linting (production-readiness) | ❌ | ❌ (json / sarif only) | ✅ (lints local YAML / Helm) | 2026 |
| [polaris](https://github.com/FairwindsOps/polaris) | ~3.4k | Best-practices policy engine + dashboard | ❌ | ✅ (live dashboard) | ✅ (lints local YAML) | 2026 |
| [kubeaudit](https://github.com/Shopify/kubeaudit) | ~1.9k | Workload security posture audit | ❌ | ❌ (json / sarif / pretty / logrus) | ✅ (manifest mode) | 2024 |
| [kube-score](https://github.com/zegl/kube-score) | ~3.1k | Static manifest scoring & recommendations | ❌ | ❌ (json / sarif / CI / human) | ✅ (static analysis of YAML) | 2025 |
| [trivy](https://github.com/aquasecurity/trivy) | ~34.8k | Vulnerability + misconfig + secrets + SBOM (broad) | ❌ | unverified (table / json / sarif primary) | ✅ (filesystem mode) | 2026 |
| [checkov](https://github.com/bridgecrewio/checkov) | ~8.7k | IaC static analysis (Terraform, K8s, CFN, ...) | ❌ | ❌ (CLI / json / sarif / junit / csv / cyclonedx / markdown) | ✅ (IaC scanner) | 2026 |
| [peirates](https://github.com/inguardians/peirates) | ~1.4k | Offensive pentest CLI (executes real privesc inside a pod) | n/a — *exploits* paths rather than analysing them statically | ❌ | ❌ (runs from inside a compromised pod) | 2026 |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | ~5.0k | External penetration testing of API endpoints | ❌ | ❌ | ❌ | **2022** — no longer actively developed; project recommends Trivy |
| [datree](https://github.com/datreeio/datree) | ~6.3k | Policy enforcement at apply time | ❌ | ❌ | ✅ | **2023** — repo archived June 2024; company shut down |
| [kubeval](https://github.com/instrumenta/kubeval) | ~3.2k | OpenAPI schema validation | ❌ | ❌ | ✅ | **2021** — no longer maintained; recommends `kubeconform` |

Star counts are approximate and were fetched at compile time of this doc; treat them as "order-of-magnitude correct, not exact." "Last release" is the most recent tagged release on GitHub.

## Closest competitors

The three tools that share the most surface area with kubesplaining are **rbac-tool**, **krane**, and **KubiScan** — all scoped to RBAC risk. None of them, however, walks the RBAC graph as an attack chain: they identify risky *permissions* on a single subject (wildcard verbs, bind-on-clusterrole, secrets/get) but they don't compose those permissions into a multi-hop path from `default/default` ➝ `cluster-admin` the way kubesplaining's privesc analyser does. Krane comes closest in spirit — it indexes RBAC into RedisGraph and exposes ad-hoc Cypher queries — but the user has to *write* the traversal. Kubesplaining ships the graph, the BFS, and the per-finding educational copy out of the box, plus the offline `download` ➝ `scan --input-file` workflow for environments where you can't keep credentials around.

If a reader has used **kubescape** or **trivy**, the easiest framing is: those tools tell you which *resources* are misconfigured; kubesplaining tells you which *subjects* can reach `cluster-admin` and how — and shows the chain in the HTML report.

## Notes on accuracy choices

- For **rbac-tool / krane / KubiScan** the privesc-paths column says "partial" rather than "yes" — each does *some* form of RBAC risk analysis, but none does the kubesplaining BFS-to-sink that emits a hop-by-hop chain. Calling them "no" would be unfair (especially krane, whose RedisGraph supports traversal — the user just has to author the Cypher); calling them "yes" would overclaim parity.
- **trivy HTML report** is marked "unverified" — Trivy supports a templating system that can produce HTML, but the README does not advertise an `--format html` flag the way kubescape does.
- **kube-bench** does not advertise HTML output anywhere on its README; marked "no" pending confirmation.
- **rbac-tool offline**: the README says it queries the discovery API on the local cluster, which suggests it needs a live connection for at least the discovery phase; the visualization step then operates on cached data — marked "partial."
- **peirates** is included for completeness but is not really comparable — it's an offensive tool you run *from inside* a compromised pod, not a defensive scanner.
- **datree / kubeval / kube-hunter** are listed despite being archived or unmaintained because they still appear in K8s-security tool roundups; the "Last release" column flags their status.

## See also

- Rapid7 blog post on rbac-tool: <https://www.rapid7.com/blog/post/2021/10/12/kubernetes-rbac-swiss-army-knife/>
- CyberArk blog on KubiScan: <https://developer.cyberark.com/blog/introducing-kubiscan-an-open-source-tool-for-scanning-risky-kubernetes-permissions/>
