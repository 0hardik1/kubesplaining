// Stale-secret detection: a Secret is unreferenced if no Pod env / envFrom /
// volume names it and no ServiceAccount lists it under `secrets` /
// `imagePullSecrets`. Stale credentials are pure exposure surface (every
// subject with `get secrets` in the namespace can still read them) with no
// operational value, so flagging them is one of the lowest-friction hygiene
// wins available.
//
// Service-account-token Secrets are intentionally excluded: they have their
// own dedicated rule (KUBE-SECRETS-001) and the legacy controller often
// creates ones that look "unreferenced" in the snapshot but are still owned
// by the SA controller.
package secrets

import (
	"context"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
)

// analyzeStale emits one finding per Secret in the snapshot that no Pod or
// ServiceAccount references. Pods are scanned for `env[].valueFrom.secretKeyRef`,
// `envFrom[].secretRef`, and `volumes[].secret.secretName`. ServiceAccounts are
// scanned for `secrets` and `imagePullSecrets`.
//
// The rule is best-effort: external consumers (a Job in another snapshot, an
// ArgoCD/Flux sync that hasn't run, a cluster-external client using the SA
// token) can still keep a Secret in active use even when this rule fires. The
// remediation prose tells the user to confirm before deleting.
func (a *Analyzer) analyzeStale(_ context.Context, snapshot models.Snapshot, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	used := referencedSecretNames(snapshot)

	for _, secret := range snapshot.Resources.SecretsMetadata {
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			// SA-token Secrets have a dedicated rule (KUBE-SECRETS-001) and
			// the SA controller's lifecycle owns them; skip here.
			continue
		}
		key := secretRefKey(secret.Namespace, secret.Name)
		if _, ok := used[key]; ok {
			continue
		}
		findings = appendUnique(findings, seen, secretFinding(secret,
			"KUBE-SECRETS-STALE-001", models.SeverityLow, 3.4,
			map[string]any{"type": secret.Type},
			"staleSecret",
			contentSecretsStale001(secret)))
	}

	return findings
}

// referencedSecretNames returns the set of `<namespace>/<name>` keys for every
// Secret named anywhere in the snapshot's Pod specs or ServiceAccount entries.
//
// We deliberately collect only the entry points the snapshot model exposes:
// Pod containers' `env[].valueFrom.secretKeyRef`, container-level `envFrom`,
// pod `volumes[].secret`, and ServiceAccount `secrets` / `imagePullSecrets`.
// Workload templates (Deployment / DaemonSet / StatefulSet / Job / CronJob)
// produce Pods at runtime, and the collector lists those Pods, so scanning
// the Pod set covers them transitively. Owner-less templates (CronJobs whose
// Job hasn't fired yet, Deployments in a paused state) would silently slip
// through this scan; the remediation prose flags that explicitly.
func referencedSecretNames(snapshot models.Snapshot) map[string]struct{} {
	used := make(map[string]struct{})

	add := func(namespace, name string) {
		if name == "" {
			return
		}
		used[secretRefKey(namespace, name)] = struct{}{}
	}

	for _, pod := range snapshot.Resources.Pods {
		collectPodSecretRefs(pod.Namespace, pod.Spec, add)
	}
	for _, deployment := range snapshot.Resources.Deployments {
		collectPodSecretRefs(deployment.Namespace, deployment.Spec.Template.Spec, add)
	}
	for _, daemonSet := range snapshot.Resources.DaemonSets {
		collectPodSecretRefs(daemonSet.Namespace, daemonSet.Spec.Template.Spec, add)
	}
	for _, statefulSet := range snapshot.Resources.StatefulSets {
		collectPodSecretRefs(statefulSet.Namespace, statefulSet.Spec.Template.Spec, add)
	}
	for _, job := range snapshot.Resources.Jobs {
		collectPodSecretRefs(job.Namespace, job.Spec.Template.Spec, add)
	}
	for _, cronJob := range snapshot.Resources.CronJobs {
		collectPodSecretRefs(cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template.Spec, add)
	}

	for _, sa := range snapshot.Resources.ServiceAccounts {
		for _, ref := range sa.Secrets {
			ns := ref.Namespace
			if ns == "" {
				ns = sa.Namespace
			}
			add(ns, ref.Name)
		}
		for _, ref := range sa.ImagePullSecrets {
			add(sa.Namespace, ref.Name)
		}
	}

	return used
}

// collectPodSecretRefs walks a PodSpec and reports every Secret name it
// references via env / envFrom / volumes. The add callback receives the
// Secret's namespace (the workload namespace, since cross-namespace mounts
// are not supported by Kubernetes) and the Secret name.
func collectPodSecretRefs(namespace string, spec corev1.PodSpec, add func(namespace, name string)) {
	collectContainerSecretRefs := func(env []corev1.EnvVar, envFrom []corev1.EnvFromSource) {
		for _, e := range env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				add(namespace, e.ValueFrom.SecretKeyRef.Name)
			}
		}
		for _, ef := range envFrom {
			if ef.SecretRef != nil {
				add(namespace, ef.SecretRef.Name)
			}
		}
	}
	for _, container := range spec.Containers {
		collectContainerSecretRefs(container.Env, container.EnvFrom)
	}
	for _, container := range spec.InitContainers {
		collectContainerSecretRefs(container.Env, container.EnvFrom)
	}
	for _, container := range spec.EphemeralContainers {
		// EphemeralContainerCommon embeds the Container shape, so Env / EnvFrom
		// resolve transparently through the embedded struct.
		collectContainerSecretRefs(container.Env, container.EnvFrom)
	}

	for _, volume := range spec.Volumes {
		if volume.Secret != nil {
			add(namespace, volume.Secret.SecretName)
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil {
					add(namespace, source.Secret.Name)
				}
			}
		}
	}

	for _, ref := range spec.ImagePullSecrets {
		add(namespace, ref.Name)
	}
}

// secretRefKey is the canonical "<namespace>/<name>" map key shared between
// the reference index and the secret-iteration loop.
func secretRefKey(namespace, name string) string {
	return namespace + "/" + name
}
