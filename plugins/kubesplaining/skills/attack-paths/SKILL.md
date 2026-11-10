---
name: attack-paths
description: Find, explain, and fix Kubernetes RBAC privilege-escalation paths with the kubesplaining CLI. Use when the user asks who can reach cluster-admin, what a ServiceAccount, user, or group can escalate to, how an identity could take over a node or read kube-system Secrets, how to tighten Kubernetes RBAC or reach least privilege, or for a security review of a cluster, a namespace, or RBAC manifests.
license: Apache-2.0
compatibility: Requires the kubesplaining CLI on PATH (a release after v1.3.0, which adds the paths command). Cluster access is optional. A snapshot file is sufficient.
metadata:
  author: 0hardik1
  homepage: https://github.com/0hardik1/kubesplaining
---

# Kubernetes attack paths with kubesplaining

`kubesplaining` reads a Kubernetes cluster and builds a graph of who can become
what. An **attack path** is a chain of permissions that takes one identity (the
**source**) to a dangerous position (the **target**). Example: a ServiceAccount
can create pods, a pod can run as a second ServiceAccount, and that second
ServiceAccount is bound to `cluster-admin`. No one grant in that chain looks
dangerous. The chain is.

Use the tool to answer the question. Do not work out escalation paths from raw
RBAC by reasoning alone: chains go through pods, tokens, controllers, and cloud
identities, and it is easy to miss a hop or to invent one.

## Rules

- **Do not change the cluster.** `kubesplaining` only reads. Keep it that way:
  do not run `kubectl apply`, `edit`, `patch`, `delete`, or `create`. Give the
  user the command or the patch. If the RBAC is in files in the repository
  (manifests, Helm, Kustomize), you can edit those files when the user asks,
  because a file change goes through review.
- **Work from a snapshot.** Capture the cluster one time, then ask each question
  against the file. An answer from a snapshot takes less than a second and needs
  no credentials.
- **Treat the snapshot as sensitive.** It has no Secret values, and ConfigMap
  values are blanked. It does have every RBAC rule, every workload spec, and on
  EKS the IAM role map. Write it outside the repository, do not commit it, and
  do not send it to a different service.
- **Do not read the whole snapshot.** The file is many megabytes for a real
  cluster. Ask the tool. When you need one object (a role, a binding), take
  only that object from the file, for example with `jq`.
- **Say what the tool said.** Give the counts and the chains from the output.
  If the tool gives an error, show the error. Do not turn it into "no paths".

## Step 1: Make sure the tool is there

```bash
kubesplaining paths --help
```

If the command is not found, try `kubectl kubesplaining paths --help` (the krew
plugin form). All commands below work the same behind `kubectl`.

If the tool is missing, or it says `unknown command "paths"` (v1.3.0 and
earlier), stop and give the user the install commands. Do not install it
without the user's agreement.

```bash
go install github.com/0hardik1/kubesplaining/cmd/kubesplaining@latest
kubectl krew install kubesplaining     # or: kubectl krew upgrade kubesplaining
```

Pre-built binaries: <https://github.com/0hardik1/kubesplaining/releases/latest>

## Step 2: Get a snapshot

If the user gave a snapshot file, use it. If not, capture one from the cluster
that the current `kubectl` context points to. Tell the user which context that
is (`kubectl config current-context`) before you read it, unless the user
already named the cluster.

```bash
kubesplaining download --output-file "$SNAPSHOT"
```

Use a path in a temporary directory for `$SNAPSHOT`. Reuse the file for every
question in the session. Capture again only after the cluster changes.

No cluster, only manifest files? `kubesplaining scan-resource --input-file
<file.yaml> --output-format json` checks one manifest. It finds risky workloads
and risky roles. It cannot find chains, because a chain needs the whole cluster.

## Step 3: Ask the question

Use `--output-format json`. Add `--limit` when you only need the top of the
list: the output has `total`, so you always know how many paths match.

| The user asks | Command |
| --- | --- |
| Who can reach cluster-admin? | `kubesplaining paths --input-file "$SNAPSHOT" --to cluster-admin --output-format json` |
| What can this ServiceAccount reach? | `kubesplaining paths --input-file "$SNAPSHOT" --from ServiceAccount/<namespace>/<name> --output-format json` |
| What can this user or group reach? | `--from User/<name>` or `--from Group/<name>` |
| What can every workload in a namespace reach? | `--from Group/system:serviceaccounts:<namespace>` |
| What can every authenticated identity reach? | `--from Group/system:authenticated` |
| Can X reach Y? Show me how. | `--from <X> --to <Y> --verbose --output-format json` |
| What are the worst paths in the cluster? | `kubesplaining paths --input-file "$SNAPSHOT" --output-format json --limit 20` |
| Give me the full report. | `kubesplaining scan --input-file "$SNAPSHOT" --output-dir <dir>` then point the user to `<dir>/report.html` |

Targets for `--to`: `cluster-admin`, `system-masters`, `kube-system-secrets`,
`node-escape`, `namespace-admin[:<namespace>]`, `token-mint`,
`aws-iam-role[:<arn>]`, `traffic-intercept`, `node-identity`. See
[references/reference.md](references/reference.md) for what each target and
each hop action means.

## Step 4: Read the answer

```json
{
  "total": 25,
  "returned": 1,
  "notes": ["..."],
  "paths": [
    {
      "id": "KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/monitoring/prometheus:cluster_admin_equivalent",
      "source": "ServiceAccount/monitoring/prometheus",
      "target": "cluster_admin_equivalent",
      "severity": "CRITICAL",
      "score": 9.25,
      "survives_first_fix": false,
      "hops": [
        {
          "step": 1,
          "action": "pod_create_token_theft",
          "from": "ServiceAccount/monitoring/prometheus",
          "to": "ServiceAccount/dashboard/admin-sa",
          "permission": "create pods",
          "source_binding": "prometheus-reader",
          "source_role": "prometheus-reader",
          "difficulty": "moderate"
        },
        {
          "step": 2,
          "action": "bound_to_cluster_admin",
          "from": "ServiceAccount/dashboard/admin-sa",
          "permission": "cluster-admin",
          "source_binding": "dashboard-admin",
          "source_role": "cluster-admin",
          "difficulty": "easy"
        }
      ]
    }
  ]
}
```

- `total` and `returned`: when `returned` is less than `total`, `--limit` cut
  the list. Say "the top N of M". Do not present a cut list as complete.
- `notes`: pass these on. One says that the exclusions hide some paths (system
  namespaces and built-in identities are hidden by default). One says that the
  result for a built-in `system:` identity is a lower bound.
- `source_binding` and `source_role`: the binding and role that grant the hop.
  With `binding_namespace`, the binding is a RoleBinding in that namespace.
  Without it, the binding is a ClusterRoleBinding.
- A hop with no `source_binding` does not come from one RBAC grant. It comes
  from a workload setting (a privileged pod, a host mount), from group
  membership, or from a cloud identity. The fix for that hop is not in RBAC.
- `difficulty`: `easy` means that the grant is the whole exploit. `moderate`
  needs a workload to exist or to be created. `hard` needs a timing window or
  infrastructure that the attacker controls.
- `survives_first_fix: true`: a second route to the same target stays open
  after the first-hop fix. Read Step 5 before you propose that fix.
- `--verbose` adds `remediation` (text), `fix_command`, `rbac_diff` (the change
  to the binding), `alternate_hops` (the second route), and `gains` on each hop.

Two answers that are easy to read wrong:

- **An error that says a subject "was not found"** means that the name is not
  in the cluster. It does not mean that the identity is safe. Check the
  namespace and the name. The error lists subjects with the same name.
- **Zero paths** means that the tool found no chain of 5 hops or less in its
  model. Say "kubesplaining found no path". Do not say "this is safe".

## Step 5: Propose the fix

Get the chain with `--verbose`, then find the smallest change that breaks it.

1. Start from `rbac_diff`. It removes the source from the binding behind hop 1.
   That is the default fix, because it changes only the identity in question.
2. If `survives_first_fix` is `true`, that fix is not sufficient. Show
   `alternate_hops`, and propose a change that closes both routes: cut the
   second route too, or cut a later hop that both routes share.
3. Look for one cut that closes many paths. When many sources reach a target
   through the same last hop (run the `--to` query and compare `source_binding`
   on the last hop), a fix at that hop is worth more than one fix per source.
4. Prefer a narrower grant to a removed grant when the workload needs part of
   the permission. A binding exists for a reason, so say what can stop working
   and let the user decide. Do not guess what the workload needs. If the user
   has audit logs, `kubesplaining scan --audit-log <path>` reports which
   granted permissions were not used.
5. Give the change as a command or a patch that the user applies. Do not apply
   it.

To confirm a fix after the user applies it, capture a new snapshot and run the
same query again.

## Step 6: Report

Give the answer first, then the evidence. A good report has:

- The answer in one sentence, with the count ("3 identities can reach
  cluster-admin").
- The paths that matter, one line each: source, target, and the chain of
  actions. Explain a hop in plain words when its name is not clear.
- The fix, as a command or a patch, and what it can break.
- The limits: a cut list, hidden paths, a lower bound, or an alternate route
  that the fix does not close.
