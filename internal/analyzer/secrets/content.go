// Content for Secret/ConfigMap hygiene findings. Each builder takes runtime context
// (namespace, name, matched keys, Corefile snippet) and returns a ruleContent with
// scope, attacker walkthrough, ordered remediation, and authoritative references.
//
// Sources: Kubernetes Secret docs, KEP-1205 (BoundServiceAccountTokens), CIS Kubernetes
// Benchmark 5.4.1 / 5.1.5, NSA/CISA Hardening Guide v1.2, MITRE ATT&CK T1552.001/.007,
// CoreDNS docs, Aqua/Sysdig writeups on DNS rebinding inside clusters.
package secrets

import (
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

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

var (
	mitreT1552_001 = models.MitreTechnique{ID: "T1552.001", Name: "Credentials In Files", URL: "https://attack.mitre.org/techniques/T1552/001/"}
	mitreT1552_007 = models.MitreTechnique{ID: "T1552.007", Name: "Container API", URL: "https://attack.mitre.org/techniques/T1552/007/"}
	mitreT1078_004 = models.MitreTechnique{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts", URL: "https://attack.mitre.org/techniques/T1078/004/"}
	mitreT1539     = models.MitreTechnique{ID: "T1539", Name: "Steal Web Session Cookie", URL: "https://attack.mitre.org/techniques/T1539/"}
	mitreT1071_004 = models.MitreTechnique{ID: "T1071.004", Name: "DNS", URL: "https://attack.mitre.org/techniques/T1071/004/"}
	mitreT1556_004 = models.MitreTechnique{ID: "T1556.004", Name: "Network Provider DLL", URL: "https://attack.mitre.org/techniques/T1556/"}
	mitreT1565_002 = models.MitreTechnique{ID: "T1565.002", Name: "Transmitted Data Manipulation", URL: "https://attack.mitre.org/techniques/T1565/002/"}
)

var (
	refK8sSecrets       = models.Reference{Title: "Kubernetes — Secrets", URL: "https://kubernetes.io/docs/concepts/configuration/secret/"}
	refK8sConfigMap     = models.Reference{Title: "Kubernetes — ConfigMaps", URL: "https://kubernetes.io/docs/concepts/configuration/configmap/"}
	refBoundSATokens    = models.Reference{Title: "Kubernetes — Bound Service Account Tokens (KEP-1205)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens"}
	refLegacyTokens     = models.Reference{Title: "Kubernetes — LegacyServiceAccountTokenCleaner & deprecated token controller", URL: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#legacy-serviceaccount-token-tracking-and-cleaning"}
	refSecretsHardening = models.Reference{Title: "Kubernetes — Good practices for Secrets", URL: "https://kubernetes.io/docs/concepts/security/secrets-good-practices/"}
	refNSAHardening     = models.Reference{Title: "NSA/CISA Kubernetes Hardening Guidance v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"}
	refCoreDNSPlugins   = models.Reference{Title: "CoreDNS — plugin reference (rewrite, forward)", URL: "https://coredns.io/plugins/"}
	refCertManager      = models.Reference{Title: "cert-manager: Certificate resource", URL: "https://cert-manager.io/docs/usage/certificate/"}
	refTLSSecret        = models.Reference{Title: "Kubernetes: TLS secrets", URL: "https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets"}
	refK8sRBAC          = models.Reference{Title: "Kubernetes: RBAC authorization", URL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"}
)

func contentSecrets001(namespace, name string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Secret `%s/%s` is a long-lived `kubernetes.io/service-account-token` (legacy, no expiry)", namespace, name),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("Secret `%s/%s`: credential is valid until manually deleted; readable by any subject with `get/list secrets` in `%s`", namespace, name, namespace),
		},
		Description: fmt.Sprintf("Secret `%s/%s` has type `kubernetes.io/service-account-token`. This is the legacy ServiceAccount token model: the token-controller persists a JWT into a Secret, the token has *no expiry* (the audience is the API server, the validity is open-ended), and it is readable by any subject with `get/list secrets` permission in the namespace.\n\n"+
			"Since Kubernetes v1.22, Bound ServiceAccount Tokens (KEP-1205) replaced this model: the kubelet projects a *new* token into the pod's filesystem with a short TTL (default 1h) and the token is bound to the pod object, so deleting the pod invalidates the token. v1.24 stopped auto-creating these legacy Secret tokens, and v1.27+ ships the `LegacyServiceAccountTokenCleaner` controller that removes unused ones automatically. A legacy token Secret today is either an artifact of a pre-1.24 cluster, a manually-created `serviceAccountToken` Secret, or a controller that explicitly created one. None of these carry the bind-to-pod, time-bounded properties of projected tokens.\n\n"+
			"The risk profile: a leaked legacy token grants whatever permissions its ServiceAccount has, *forever*, with no automatic revocation. It survives Pod restarts, node reboots, audit events, and rotation of the SA itself. Detection of misuse requires explicit audit-log monitoring against the SA name; rotation requires deleting the Secret and reissuing.",
			namespace, name),
		Impact: "Anyone who exfiltrates this Secret holds a non-expiring credential with the ServiceAccount's full RBAC; rotation requires manual `kubectl delete secret` and re-issue, and there is no time-based mitigation.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises any subject with `get secrets` in `%s` (e.g., a forgotten `view`-style role, an over-permissive ConfigMap-reader role that wildcards resources, or a pod token with secret-read).", namespace),
			fmt.Sprintf("They `kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d` and obtain the raw JWT.", name, namespace),
			"They use the token against the kube-apiserver from outside the cluster (`kubectl --token=...`). No pod, no node, no IMDS hop required.",
			"Because the token has no `exp` claim and no audience binding to a Pod, it remains valid weeks or months later. Rotation in IR is manual: delete the Secret + recreate, and any cached copies attacker has are *still valid until that delete*.",
			"Attacker uses the SA's RBAC to read other Secrets, list pods cluster-wide (if SA has it), exec into pods, or escalate via any of the privesc paths the SA enables.",
		},
		Remediation: fmt.Sprintf("Migrate the consumer of `%s/%s` to a projected ServiceAccount token, then delete the Secret. Enable `LegacyServiceAccountTokenCleaner` on the cluster.", namespace, name),
		RemediationSteps: []string{
			fmt.Sprintf("Identify what reads `%s/%s`: `kubectl get pods -A -o json | jq '.items[] | select(.spec.volumes[]?.secret.secretName == \"%s\") | .metadata.namespace + \"/\" + .metadata.name'`. Also check Jobs, CronJobs, and external systems that might have copied the token out.", namespace, name, name),
			"Migrate each consumer to a projected SA token (`serviceAccountToken` projection in `volumes`) with a sensible `expirationSeconds` (e.g., 3600). The kubelet will refresh it automatically.",
			"For external consumers (CI runners, dashboards) that need a long-lived token, use TokenRequest API on demand instead of a stored Secret, or rotate via a sealed-secret / external-secret-store flow.",
			fmt.Sprintf("`kubectl delete secret %s -n %s` once consumers are migrated. Confirm no pod has a CrashLoopBackOff that mentions the missing token.", name, namespace),
			"Enable the `LegacyServiceAccountTokenCleaner` (default on v1.29+) so future stragglers get garbage-collected after their last-used timestamp ages out.",
		},
		LearnMore: []models.Reference{
			refBoundSATokens,
			refLegacyTokens,
			refK8sSecrets,
			refSecretsHardening,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1552_007, mitreT1078_004, mitreT1539},
	}
}

func contentSecrets002(name string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Opaque Secret `kube-system/%s` likely holds control-plane or addon credentials", name),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("Secret `kube-system/%s`: control-plane namespace; readers in `kube-system` are typically system controllers and high-privilege operators", name),
		},
		Description: fmt.Sprintf("Secret `kube-system/%s` has type `Opaque`. The `kube-system` namespace is reserved for control-plane workloads and cluster add-ons (cloud-controller-manager, CNI, CSI, ingress controllers, certificate operators, observability agents). Opaque Secrets there are almost always one of: cloud IAM credentials for the cloud-controller-manager, registry pull secrets for system images, TLS client certs for an etcd snapshot agent, kubeconfigs for an external-DNS controller, or addon-vendor API keys.\n\n"+
			"Because of where they live, these Secrets carry outsized blast radius compared to a workload Secret. A leak here typically grants either (a) credentials to the cloud account hosting the cluster, (b) the ability to publish or pull from the cluster's container registry, or (c) durable access to control-plane components that can be used to subvert further controls.\n\n"+
			"Two specific concerns: (1) `kube-system` Secrets are often forgotten when teams set up Vault or external-secret-store integrations, so they live on as the bootstrap credential, never rotated; (2) RBAC for `kube-system` is typically broad (operator service accounts often `cluster-admin`-adjacent) so the set of subjects that can read them is much larger than the team realizes.",
			name),
		Impact: "This Secret likely encodes credentials with cluster-wide or cloud-account reach. A read by any subject with `get secrets` in `kube-system` (operator SAs, kube-system pods, cluster-admin tokens) escalates to whatever the credential authorizes.",
		AttackScenario: []string{
			"Attacker gains a `kube-system` ServiceAccount token with `get secrets` (e.g., compromised addon, addon-installer Job, helm-release Secret reader).",
			fmt.Sprintf("They `kubectl get secret %s -n kube-system -o yaml` and decode each `data` key.", name),
			"They identify the credential type: AWS access key (`aws_access_key_id/aws_secret_access_key`), GCP service-account JSON, Azure tenant/client ID, Docker config (registry credentials), or an inline kubeconfig.",
			"They authenticate out-of-cluster with the credential: cloud account compromise, registry image-publishing for supply-chain implant, or a parallel kubeconfig that survives in-cluster RBAC revocation.",
			"They persist by issuing a new IAM key / pushing an unsigned image / writing a kubeconfig to a hidden location, then cover by deleting their access logs.",
		},
		Remediation: fmt.Sprintf("Audit `kube-system/%s`'s contents and consumers; rotate the credential; move long-lived credentials to a sealed-secret or external secret store; restrict who can `get secrets` in `kube-system`.", name),
		RemediationSteps: []string{
			fmt.Sprintf("Inspect the Secret's content shape (key names, not values) to identify the credential type via `kubectl get secret %s -n kube-system -o jsonpath='{.data}' | jq 'keys'`.", name),
			fmt.Sprintf("Find consumers: `kubectl get pods -n kube-system -o json | jq '.items[] | select(.spec.volumes[]?.secret.secretName == \"%s\" or .spec.containers[].envFrom[]?.secretRef.name == \"%s\") | .metadata.name'`.", name, name),
			"Rotate the underlying credential at its source (cloud IAM, registry, etc.) and update the Secret with the new value, preferably by switching to External Secrets Operator (Vault/SecretsManager backend) so the Secret becomes a generated artifact instead of source-of-truth.",
			"Tighten RBAC on `kube-system` Secrets so each operator SA only sees its own Secret, not `secrets` cluster-wide. Audit with `kubectl auth can-i get secrets -n kube-system --as=system:serviceaccount:kube-system:<sa>` for each one.",
			"Wire enforcement: a Kyverno or OPA Gatekeeper policy that flags any Pod referencing a long-lived `kube-system` Secret name not on an allowlist.",
		},
		LearnMore: []models.Reference{
			refSecretsHardening,
			refK8sSecrets,
			refNSAHardening,
			{Title: "External Secrets Operator", URL: "https://external-secrets.io/latest/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1552_007, mitreT1078_004},
	}
}

func contentConfigMap001(namespace, name string, matchedKeys []string) ruleContent {
	keysList := strings.Join(matchedKeys, ", ")
	return ruleContent{
		Title: fmt.Sprintf("ConfigMap `%s/%s` exposes credential-shaped keys (`%s`) in plaintext", namespace, name, keysList),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("ConfigMap `%s/%s`: readable by every subject with `get configmaps` in `%s`, ships unencrypted in etcd, surfaces in `kubectl describe` and audit logs", namespace, name, namespace),
		},
		Description: fmt.Sprintf("ConfigMap `%s/%s` contains keys with names matching credential-like patterns: `%s`. The Kubernetes API treats ConfigMaps as non-sensitive: etcd stores them unencrypted by default (encryption-at-rest is opt-in and almost always limited to Secrets), `kubectl describe configmap` prints values inline, audit logs include the data on get/list, and RBAC defaults give workload service accounts much wider read on ConfigMaps than on Secrets.\n\n"+
			"Storing a credential in a ConfigMap therefore violates the basic Kubernetes data-classification model in three ways simultaneously: (1) it appears in plaintext to anyone with `get configmaps` (a much larger set of subjects than `get secrets`); (2) it ends up in cluster backups, etcd dumps, and platform observability tooling that explicitly excludes Secrets; (3) it does not benefit from any of the surface area Kubernetes builds around Secrets (envelope encryption, file-mode 0600 projection, KMS provider, External Secrets Operator).\n\n"+
			"The matched keys are heuristic, since `key` matches both `apiKey` and `public_key`, so review is required before assuming compromise. In practice the pattern is strong: in production clusters this finding correlates with real leaks the majority of the time. Treat as exposed-until-proven-otherwise.",
			namespace, name, keysList),
		Impact: fmt.Sprintf("If any of the flagged keys (`%s`) actually hold a credential, that credential is exposed to a wide audience: every workload SA in `%s`, every backup operator, every audit log consumer, and possibly cluster-mirroring tooling.", keysList, namespace),
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises a workload in `%s` whose ServiceAccount has `get configmaps` (the typical default `view` role grants it).", namespace),
			fmt.Sprintf("They `kubectl get cm %s -n %s -o yaml` and read the matched keys directly. No decoding needed since ConfigMap data is plaintext.", name, namespace),
			"They identify the credential class (DB connection string, API key, OAuth client_secret, signing key) from the key name and value shape.",
			"They use the credential immediately: DB connection strings often grant the same write permission the application has; API keys often have no IP restriction; client_secrets unlock the upstream identity provider.",
			"Because audit-log review on ConfigMaps is rare, the read goes unnoticed until the upstream credential is rotated for unrelated reasons.",
		},
		Remediation: fmt.Sprintf("Move the credential out of `%s/%s` into a Kubernetes Secret (or, better, an external secret store) and remove the keys from the ConfigMap.", namespace, name),
		RemediationSteps: []string{
			fmt.Sprintf("Inspect each matched key (`%s`) to confirm whether it is a real credential. Some keys like `cache_key_prefix` are false positives.", keysList),
			fmt.Sprintf("For real credentials, create a Secret in `%s` and update consumers (envFrom or volume mounts) to read from the Secret.", namespace),
			"Rotate the credential at its source: if it was already in plaintext in a ConfigMap, treat it as compromised (assume any subject with view-on-configmaps had access).",
			fmt.Sprintf("Remove the credential keys from `%s/%s`. Verify the consumer still works (`kubectl rollout status`).", namespace, name),
			"Wire prevention: a Kyverno cluster policy that warns on `ConfigMap.data` keys matching `password|secret|token|credential|api_?key|access_?key|client_secret|connection_string|dsn`. Pair with External Secrets Operator so the right path of least resistance is to use a real secret store.",
		},
		LearnMore: []models.Reference{
			refK8sConfigMap,
			refK8sSecrets,
			refSecretsHardening,
			{Title: "External Secrets Operator", URL: "https://external-secrets.io/latest/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1552_007, mitreT1078_004},
	}
}

func contentConfigMap002() ruleContent {
	return ruleContent{
		Title: "CoreDNS Corefile contains rewrite or external-forward directives that make the cluster DNS plane mutable from `kube-system/coredns`",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "ConfigMap `kube-system/coredns`: every pod in the cluster uses this Corefile for resolution; a change here is a cluster-wide effect",
		},
		Description: "The CoreDNS Corefile in `kube-system/coredns` contains directives that change DNS behavior in ways that warrant explicit review: `rewrite` directives mutate query names or response data, and `forward` directives that send queries to external resolvers (`8.8.8.8`, `1.1.1.1`, `tls://...`) bypass the cluster's authoritative records and the cluster's egress firewall.\n\n" +
			"Two threat models matter here. (1) **Defensive misconfiguration**: a `rewrite` rule that maps an internal name to an external one can cause apps to talk to attacker-controlled hosts when the rule's intent was something else (typo, copy-paste from a tutorial). External `forward` to public resolvers means DNS queries (which often contain pod names, namespace names, internal service topology) leave the cluster perimeter unencrypted to a third-party operator with no DPA. (2) **Active subversion**: an attacker with write access to the `kube-system/coredns` ConfigMap (a far rarer condition, but exactly the prize for `KUBE-PRIVESC-005` chains) can add a `rewrite` rule that redirects `*.svc.cluster.local` to attacker pods, then capture every connection that does not pin TLS. The result is full cluster-wide MITM, and CoreDNS reloads the Corefile automatically with no operator action needed.\n\n" +
			"This is the most common active-subversion path discussed in DNS-rebinding-in-Kubernetes research: the CoreDNS ConfigMap is structurally a one-shot to compromise resolution for every pod, and clusters often grant `kube-system` ConfigMap write to addon installers, helm-controllers, and network operators that the security team hasn't audited.",
		Impact: "If the Corefile is malicious, every DNS query in the cluster can be silently redirected (including queries for in-cluster services, cloud APIs, and external SaaS), enabling MITM and data exfiltration. If the Corefile is merely sloppy, internal DNS names may leak to public resolvers.",
		AttackScenario: []string{
			"Attacker gains write access to `kube-system/coredns` (often via an over-broad `configmaps` permission on a control-plane SA, or a `KUBE-PRIVESC-005` secret-reads-then-token-theft chain that ends at a kube-system SA).",
			"They edit the Corefile to add `rewrite name regex (.*)\\.cluster\\.local\\. attacker-pod.poc.svc.cluster.local. answer auto`.",
			"CoreDNS reloads automatically (`reload` plugin), and within ~30 seconds every cluster service-discovery query is misdirected.",
			"Apps that don't pin TLS-SNI-to-IP fall over to attacker-pod, which terminates TLS with a self-signed cert (acceptable for many in-cluster integrations using `InsecureSkipVerify: true`).",
			"The attacker harvests credentials from the redirected traffic, then quietly removes the rewrite rule when done. `kube-system/coredns` change history is not audited by most teams.",
		},
		Remediation: "Audit each `rewrite` and `forward` directive against expected DNS topology, lock down write access to the `kube-system/coredns` ConfigMap, and add change detection.",
		RemediationSteps: []string{
			"`kubectl get cm coredns -n kube-system -o yaml` and review every `rewrite/forward` line. Confirm with the platform/networking team that each is intentional.",
			"For `forward` to public resolvers: prefer the cloud provider's private resolver (which respects VPC routing and is logged) over `8.8.8.8/1.1.1.1`. If public is required, restrict via egress NetworkPolicy.",
			"`kubectl auth can-i update configmaps -n kube-system --as=system:serviceaccount:<ns>:<sa>` for every SA. Most do not need this; tighten RBAC and remove cluster-wide `*` resource grants.",
			"Wire change detection: an admission policy (Kyverno) that alerts on any ConfigMap update in `kube-system` named `coredns`, or a GitOps source-of-truth so manual edits diverge visibly.",
			"Add a periodic CronJob that diffs the live Corefile against the GitOps version and pages on drift.",
		},
		LearnMore: []models.Reference{
			refCoreDNSPlugins,
			{Title: "Sysdig — Kubernetes DNS-based MITM via CoreDNS", URL: "https://sysdig.com/blog/kubernetes-coredns-attack/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1071_004, mitreT1556_004, mitreT1565_002},
	}
}

// contentSecretsStale001 narrates the case where a Secret is not referenced by any
// Pod (env / envFrom / volumes) or ServiceAccount (secrets / imagePullSecrets) in
// the snapshot. Stale Secrets are credential-exposure risk with zero operational
// value: rotating them is free, and leaving them around grows the read-attack
// surface every namespace consumer has via the default `view` cluster role.
func contentSecretsStale001(secret models.SecretMetadata) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Secret `%s/%s` is not referenced by any Pod or ServiceAccount in the snapshot", secret.Namespace, secret.Name),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("Secret `%s/%s`: still readable by every subject with `get/list secrets` in `%s`, but no observed workload mounts or consumes it", secret.Namespace, secret.Name, secret.Namespace),
		},
		Description: fmt.Sprintf("Secret `%s/%s` (type `%s`) was not found referenced from any of the workload-spec entry points the snapshot collects: pod containers' `env[].valueFrom.secretKeyRef`, container-level `envFrom[].secretRef`, pod `volumes[].secret.secretName`, and ServiceAccount `imagePullSecrets` / `secrets` lists.\n\n"+
			"In a healthy cluster this almost always means one of: (a) a workload that used to mount the Secret was deleted but the Secret was not garbage-collected, (b) the Secret was created speculatively (a bootstrap step, a CI/CD seed) and never wired in, (c) a Helm release was uninstalled with `--keep-history` or via `kubectl delete deployment` instead of `helm uninstall`, leaving Secrets behind, or (d) the Secret is consumed *outside* the snapshot's view (a CronJob / Job / DaemonSet in another namespace, an external system reading via the API server using SA credentials).\n\n"+
			"Stale Secrets are an asymmetric risk. They contribute *nothing* to current operations but they are still readable by every subject with `get/list secrets` in the namespace (which the namespace-default `view` and `edit` cluster roles both grant). Rotating them is free of operational impact since no consumer breaks. Deleting them tightens the blast radius of a future credential-read compromise without any deployment risk. The only operational cost is verifying the Secret really has no consumer outside the snapshot's view.",
			secret.Namespace, secret.Name, secret.Type),
		Impact: fmt.Sprintf("If `%s/%s` holds a real credential (token, password, API key, kubeconfig, registry pull secret), it is still in the blast radius of every subject with `get secrets` in `%s` even though no workload uses it. Compromise yields a credential the operator believes is decommissioned.", secret.Namespace, secret.Name, secret.Namespace),
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises any subject with `get secrets` in `%s`. Default `view`/`edit` cluster-role bindings, audit roles, debugging operators, helm-controller and external-secrets controller SAs all qualify.", secret.Namespace),
			fmt.Sprintf("They `kubectl get secret %s -n %s -o yaml` and decode `data` keys.", secret.Name, secret.Namespace),
			"They identify the credential class (token, kubeconfig, registry pull credentials, OAuth client secret) from the key shape.",
			"Because the Secret is unreferenced, no audit alert wires the read to a known consumer pattern: the access looks like a one-off `get` instead of a controller's expected token-refresh loop.",
			"They use the credential against the corresponding upstream system. The operator's team continues to assume the Secret is dormant and unused; rotation only happens if some unrelated audit catches the abuse.",
		},
		Remediation: fmt.Sprintf("Confirm `%s/%s` is genuinely unused (the snapshot may not have visibility into every consumer), then delete it. Treat the credential as compromised before rotation if the Secret has been long-lived.", secret.Namespace, secret.Name),
		RemediationSteps: []string{
			fmt.Sprintf("Confirm no out-of-snapshot consumer exists. `kubectl get pods -A -o json | jq '.items[] | select(.spec.volumes[]?.secret.secretName == \"%s\" or .spec.containers[]?.env[]?.valueFrom?.secretKeyRef?.name == \"%s\" or .spec.containers[]?.envFrom[]?.secretRef?.name == \"%s\") | .metadata.namespace + \"/\" + .metadata.name'`. Run for Jobs, CronJobs, and ServiceAccount `imagePullSecrets` too.", secret.Name, secret.Name, secret.Name),
			"Check change history (Argo / Flux / Helm) for the Secret name. Many stale Secrets are managed by GitOps and have a tracked owner; deleting them outside GitOps will cause the system to recreate them on the next sync.",
			fmt.Sprintf("If you confirm no consumer, treat the credential as exposed (anyone with secret-read in `%s` could have copied it). Rotate the upstream credential at its source (cloud IAM, registry, OIDC IDP).", secret.Namespace),
			fmt.Sprintf("`kubectl delete secret %s -n %s`. Watch for CrashLoopBackOff in the namespace for the next 24h, in case a Job or external system needed it.", secret.Name, secret.Namespace),
			"Wire prevention: schedule a periodic `secrets-janitor` Job that lists Secrets older than N days that no resource references, and emits a Slack/email warning. External tools like `kor` or `secret-scanner` automate this same check.",
		},
		LearnMore: []models.Reference{
			refK8sSecrets,
			refSecretsHardening,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1552_007},
	}
}

// contentSecretsCrossNS001 narrates the case where a workload's ServiceAccount has
// RBAC permission to read Secrets in a *different* namespace. Cross-namespace secret
// reads are the textbook lateral-movement primitive in K8s: the namespace boundary
// is the cluster's main isolation primitive, and a single SA grant that crosses it
// turns one workload into a cluster-wide credential reader.
func contentSecretsCrossNS001(subject models.SubjectRef, sourceNamespace, targetNamespace string, sourceWorkloads string, sourceRole, sourceBinding string) ruleContent {
	whereSourceNS := sourceNamespace
	if sourceNamespace == "" {
		whereSourceNS = "(no observed pod consumer)"
	}
	target := targetNamespace
	if targetNamespace == "" {
		target = "(cluster-wide)"
	}
	return ruleContent{
		Title: fmt.Sprintf("ServiceAccount `%s/%s` can read Secrets in namespace `%s` (used by workloads in `%s`)", subject.Namespace, subject.Name, target, whereSourceNS),
		Scope: models.Scope{
			Level:  models.ScopeNamespace,
			Detail: fmt.Sprintf("ServiceAccount `%s/%s` mounted in `%s`: holds `get`/`list`/`watch` on `secrets` in `%s` via `%s`/`%s`. A pod-to-API-server compromise reads every Secret in the target namespace.", subject.Namespace, subject.Name, whereSourceNS, target, sourceBinding, sourceRole),
		},
		Description: fmt.Sprintf("ServiceAccount `%s/%s` is mounted by workload(s) `%s` and has RBAC permission to `get`/`list`/`watch` Secrets in namespace `%s`, granted by `%s` (referencing `%s`). Namespace `%s` is the namespace the SA *lives in*; namespace `%s` is *different*. The grant therefore lets a compromised pod in `%s` enumerate or read every Secret in `%s` via the projected SA token, without leaving the namespace it runs in.\n\n"+
			"This pattern is the most common lateral-movement primitive in production K8s clusters because the namespace boundary is the platform's primary isolation surface. Network policies, PSA labels, ResourceQuotas, image-pull credentials, and audit groupings all key on namespace. An RBAC grant that punches through the boundary collapses that isolation for the secret-read axis: the attacker doesn't need a network path, doesn't need a pod-create, doesn't need to escape to the node, they just `kubectl get secret -n <other-namespace>` with the projected token.\n\n"+
			"Three patterns produce this finding in real clusters: (1) a shared ClusterRole (e.g. `secret-reader`) bound to a workload SA via a ClusterRoleBinding, granting it cluster-wide read; (2) a multi-tenant operator (Vault sync, External Secrets Operator, cert-manager) deliberately granted cross-namespace read but with a wider scope than the operator actually needs; (3) a copy-pasted Helm chart's ClusterRole that was meant to be a Role. Each is fixable by replacing the grant with namespace-scoped Roles, restricting `resourceNames`, or moving the consumer into the target namespace.",
			subject.Namespace, subject.Name, sourceWorkloads, target, sourceBinding, sourceRole, subject.Namespace, target, subject.Namespace, target),
		Impact: fmt.Sprintf("Anyone who compromises a pod running as `%s/%s` can read every Secret in `%s` over the projected SA token, without needing a network egress, host escape, or RBAC modification. Lateral movement to the credentials of every workload in `%s` becomes a single `kubectl get secret` away.", subject.Namespace, subject.Name, target, target),
		AttackScenario: []string{
			fmt.Sprintf("Attacker gains code execution inside a pod running as `%s/%s` (RCE on the application, dependency confusion, supply chain compromise of a base image, etc.).", subject.Namespace, subject.Name),
			"They read the projected SA token at `/var/run/secrets/kubernetes.io/serviceaccount/token`.",
			fmt.Sprintf("They run `kubectl --token=$(cat ...) get secrets -n %s` against the in-cluster API server. RBAC permits it because `%s/%s` was granted across the namespace boundary.", target, sourceBinding, sourceRole),
			fmt.Sprintf("They harvest every Secret in `%s`: TLS keys, OAuth client secrets, database passwords, registry pull credentials, ServiceAccount tokens, cloud provider IAM keys.", target),
			fmt.Sprintf("They use the harvested credentials laterally: pivot to the cloud account, push a malicious image to the registry, authenticate as another workload's SA, sign their own short-lived tokens via TokenRequest, etc. The original `%s/%s` pod is now optional; the cluster's secrets are exfiltrated.", subject.Namespace, subject.Name),
		},
		Remediation: fmt.Sprintf("Replace the cross-namespace grant with the narrowest possible scope: a Role in `%s` (not a ClusterRole), `resourceNames` for the specific Secrets the workload needs, or move the consumer into `%s`.", target, target),
		RemediationSteps: []string{
			"Identify what the pod *actually* reads. `kubectl logs` and audit logs for `objectRef.resource=secrets` will show the specific Secret names. Most cross-namespace grants are over-broad: the workload only needs 1-2 Secrets, not the whole namespace.",
			fmt.Sprintf("Replace the grant. Prefer (in order): (a) move the workload into `%s` so the grant becomes intra-namespace, (b) replace the ClusterRoleBinding with a RoleBinding in `%s` that points to a Role, (c) restrict the Role to `resourceNames: [foo, bar]` for the specific Secrets needed.", target, target),
			"For multi-tenant operators (External Secrets Operator, Vault sync, cert-manager), use the operator's per-namespace SecretStore / ClusterSecretStore selector mechanism instead of granting cluster-wide RBAC. The operator's docs document the right scoping.",
			fmt.Sprintf("Audit the binding. `kubectl get rolebindings,clusterrolebindings -A -o json | jq '.items[] | select(.subjects[]?.name == \"%s\" and .subjects[]?.namespace == \"%s\")'` shows everything that grants this SA cross-namespace read.", subject.Name, subject.Namespace),
			"Wire enforcement: a Kyverno or Gatekeeper ClusterPolicy that warns/blocks any RoleBinding that points a non-system ClusterRole at a workload SA, or any ClusterRole that grants `secrets:get` without a `resourceNames` constraint.",
		},
		LearnMore: []models.Reference{
			refK8sRBAC,
			refK8sSecrets,
			refSecretsHardening,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_007, mitreT1552_001, mitreT1078_004},
	}
}

// contentSecretsTLSExpiry001 narrates a TLS secret that is approaching expiry or has
// already expired. The Secret type alone (`kubernetes.io/tls`) doesn't tell us, so
// we lean on cert-manager's annotation conventions; the rule is best-effort and
// silently skips secrets without a parseable expiry annotation.
func contentSecretsTLSExpiry001(secret models.SecretMetadata, notAfter, daysToExpiry string, expired bool) ruleContent {
	state := fmt.Sprintf("expires in %s (NotAfter=%s)", daysToExpiry, notAfter)
	if expired {
		state = fmt.Sprintf("expired %s ago (NotAfter=%s)", daysToExpiry, notAfter)
	}
	return ruleContent{
		Title: fmt.Sprintf("TLS Secret `%s/%s` %s", secret.Namespace, secret.Name, state),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("Secret `%s/%s` (type `kubernetes.io/tls`): every Service, Ingress, and webhook callsite that references this Secret will start failing TLS handshake at NotAfter unless the certificate is rotated.", secret.Namespace, secret.Name),
		},
		Description: fmt.Sprintf("Secret `%s/%s` is a `kubernetes.io/tls` Secret and its certificate %s. The expiry is read from the `cert-manager.io/certificate-name` + `cert-manager.io/issuer-name` family of annotations (the de-facto standard cert-manager and ArgoCD set on every TLS Secret they issue): `cert-manager.io/not-after`, `cert-manager.io/notafter`, or the legacy `cert-manager.io/expiration` annotation.\n\n"+
			"The secret's payload (`tls.crt`) is *not* read by the kubesplaining collector (see the privacy contract in `CLAUDE.md`: raw secret values are never collected). This rule is therefore a best-effort check based on annotations only: it fires on Secrets whose annotations report an expiry within the next 30 days or already in the past, and silently skips Secrets that have no parseable expiry annotation. A real PKI tool (cert-manager's Certificate CR controller, an external probe like `cert-monitor`, or `kubectl cert-monitor`) is the authoritative source.\n\n"+
			"Why this matters: an expired TLS Secret is the single most common cause of an Ingress / webhook outage that pages SREs at 3am. cert-manager auto-renews most certificates, but renewal can fail silently if (a) the Issuer is misconfigured, (b) the ACME challenge can't reach Let's Encrypt because of a NetworkPolicy change, (c) the Issuer's credentials have rotated, or (d) the Certificate CR was deleted but the Secret was kept. A 30-day window gives the platform team room to investigate and re-issue before the outage.",
			secret.Namespace, secret.Name, state),
		Impact: fmt.Sprintf("Once `%s/%s` expires, every consumer of the cert (Ingress backends, mutating/validating webhooks, mTLS sidecars, internal Service-to-Service callers) starts failing TLS handshake. For a webhook Secret this means every API admission call into the cluster fails until the cert is rotated.", secret.Namespace, secret.Name),
		AttackScenario: []string{
			"This is primarily an availability finding, not an attacker-driven one. The relevant 'attacker' is time.",
			fmt.Sprintf("On the day the cert expires, every TLS handshake against the consumer of `%s/%s` returns `x509: certificate has expired`.", secret.Namespace, secret.Name),
			"For an Ingress: external traffic gets a browser warning, then is rejected. For a mutating webhook: every `kubectl apply` for matching resources hits `failed calling webhook ... x509`.",
			"For internal Service-to-Service mTLS (Istio, Linkerd, application-level mTLS): connections start dropping; sidecars surface as TLS-handshake-failure spikes in mesh dashboards.",
			"Recovery is manual: re-issue the cert (cert-manager Force Renew annotation, or a fresh `kubectl create secret tls`) and roll the consumer pods.",
		},
		Remediation: fmt.Sprintf("Re-issue the certificate before NotAfter. If `%s/%s` is owned by cert-manager, force renewal; if it was created manually, replace it with a cert-manager Certificate CR so renewal is automatic.", secret.Namespace, secret.Name),
		RemediationSteps: []string{
			fmt.Sprintf("Identify the Issuer. `kubectl get secret %s -n %s -o jsonpath='{.metadata.annotations}'` shows `cert-manager.io/issuer-name` and `cert-manager.io/certificate-name` if cert-manager owns the Secret.", secret.Name, secret.Namespace),
			"For cert-manager-owned Secrets, force renewal with `cmctl renew <certificate-name> -n <ns>` (or `kubectl annotate certificate <name> cert-manager.io/issue-temporary-certificate=true`). The Certificate controller will create a new CertificateRequest and refresh the Secret.",
			fmt.Sprintf("For manually-created Secrets, prefer migrating to a cert-manager Certificate CR pointing at an Issuer / ClusterIssuer. The chart for most ingress / webhook deployments includes one. Re-create with `kubectl apply -f` instead of editing `%s/%s` in place.", secret.Namespace, secret.Name),
			"Verify the cert-manager Issuer is healthy: `kubectl get clusterissuer,issuer -A` and check `Ready` condition. ACME failures (DNS, HTTP-01 challenge) are the most common renewal blockers.",
			"Wire prevention: enable cert-manager's `cert-manager.io/private-key-rotation-policy: Always` and renewBefore (default 360h ≈ 15d) on all Certificate CRs. Add a Prometheus alert on `certmanager_certificate_expiration_timestamp_seconds < (time() + 30 * 24 * 3600)`.",
		},
		LearnMore: []models.Reference{
			refTLSSecret,
			refCertManager,
			refSecretsHardening,
			{Title: "Let's Encrypt: Certificate lifetimes", URL: "https://letsencrypt.org/2024/12/11/eoy-letter-2024/"},
		},
		MitreTechniques: []models.MitreTechnique{},
	}
}

// contentConfigMapCreds001 narrates the heuristic case where a ConfigMap key name
// matches a credential-shaped pattern. Values are redacted in the snapshot (see
// the privacy contract in CLAUDE.md) so this is purely key-name based and false
// positives are expected (`api_key_format`, `password_strength_requirement`).
// Treat as a starting point for review, not a guaranteed leak.
func contentConfigMapCreds001(configMap models.ConfigMapSnapshot, matchedKey string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("ConfigMap `%s/%s` has key `%s` matching a credential-name pattern", configMap.Namespace, configMap.Name, matchedKey),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("ConfigMap `%s/%s`: key `%s` is readable in plaintext to every subject with `get configmaps` in `%s` and lands in unencrypted etcd, audit logs, and cluster backups.", configMap.Namespace, configMap.Name, matchedKey, configMap.Namespace),
		},
		Description: fmt.Sprintf("ConfigMap `%s/%s` contains the key `%s`. The key name matches a high-confidence credential pattern (`password`, `passwd`, `secret`, `token`, `api_key`/`apikey`, `aws_secret_access_key`, `dsn`, `connection_string`, etc.). The kubesplaining collector preserves ConfigMap keys but redacts values to maintain the cluster's privacy contract, so this rule cannot inspect the value, only the key name.\n\n"+
			"The risk is the same as `KUBE-CONFIGMAP-001`: ConfigMap data is non-sensitive by design. etcd does not encrypt it (encryption-at-rest is opt-in and almost always limited to Secrets), `kubectl describe configmap` prints values inline, audit logs include payloads on `get`/`list`, and the namespace-default `view` and `edit` cluster-role bindings give workload SAs much wider read on ConfigMaps than on Secrets. Storing a credential in a ConfigMap therefore exposes it to a *much larger* set of subjects than the equivalent Secret would.\n\n"+
			"Because this rule fires per-(ConfigMap, key) pair (versus `KUBE-CONFIGMAP-001` which surfaces a list of matched keys per ConfigMap), it produces a more granular finding stream. Use it for triage when you have many ConfigMaps to audit. Keys that match in name but not intent (`password_strength_requirement`, `api_key_format_version`, `cache_key_prefix`) are expected false positives: review the value out-of-band before treating as a real leak.",
			configMap.Namespace, configMap.Name, matchedKey),
		Impact: fmt.Sprintf("If the value of `%s` in `%s/%s` is a real credential, that credential is exposed to every subject with `get configmaps` in `%s`, which is typically every workload SA in the namespace via the default `view` cluster role.", matchedKey, configMap.Namespace, configMap.Name, configMap.Namespace),
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises any workload in `%s` whose ServiceAccount has `get configmaps` (the namespace-default `view` cluster role grants it; most pods running with the namespace `default` SA have it transitively).", configMap.Namespace),
			fmt.Sprintf("They `kubectl get configmap %s -n %s -o yaml` and read `data.%s` directly. ConfigMap values are plaintext: no decoding required.", configMap.Name, configMap.Namespace, matchedKey),
			"They identify the credential class from the value's shape (`postgres://user:pass@host/db` is a DSN, `eyJ...` is a JWT, AKIA-prefixed strings are AWS keys, `xoxb-` is Slack, `ghp_` is a GitHub token).",
			"They use the credential immediately. ConfigMap-stored credentials almost never have IP allowlists, short TTLs, or rotation automation: they were put in a ConfigMap *because* the team didn't want operational complexity.",
			"Detection lags. Audit-log review on ConfigMaps is rare in most clusters because ConfigMap reads are dominated by legitimate config-loading. The compromise typically surfaces only when the upstream credential is rotated for unrelated reasons.",
		},
		Remediation: fmt.Sprintf("Verify whether `%s` in `%s/%s` actually holds a credential; if so, move it to a Secret (or external secret store) and remove the key from the ConfigMap.", matchedKey, configMap.Namespace, configMap.Name),
		RemediationSteps: []string{
			fmt.Sprintf("Inspect the value: `kubectl get cm %s -n %s -o jsonpath='{.data.%s}'`. Confirm whether it's a real credential or a benign config (a feature-flag name, a cache prefix, a strength-requirement string).", configMap.Name, configMap.Namespace, matchedKey),
			fmt.Sprintf("If it's a real credential, rotate at the source first (cloud IAM, OIDC IDP, registry, database). Treat the original value as fully exposed: anyone with `view` on `%s` could have read it.", configMap.Namespace),
			fmt.Sprintf("Create a Secret with the new value: `kubectl create secret generic %s-credentials -n %s --from-literal=%s=$NEW`. Update consumers to read from the Secret via `envFrom` or volume mount instead of `valueFrom: configMapKeyRef`.", configMap.Name, configMap.Namespace, matchedKey),
			fmt.Sprintf("Remove the key from the ConfigMap: `kubectl patch cm %s -n %s --type=json -p='[{\"op\":\"remove\",\"path\":\"/data/%s\"}]'`. Verify consumers still work (`kubectl rollout status`).", configMap.Name, configMap.Namespace, matchedKey),
			"Wire prevention: a Kyverno ClusterPolicy that warns on `ConfigMap.data` keys matching `password|secret|token|api_?key|aws_secret_access_key|dsn|connection_string`. Pair with External Secrets Operator so the path of least resistance is to use a real secret store.",
		},
		LearnMore: []models.Reference{
			refK8sConfigMap,
			refK8sSecrets,
			refSecretsHardening,
			{Title: "External Secrets Operator", URL: "https://external-secrets.io/latest/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1552_007, mitreT1078_004},
	}
}
