# Live EKS demo: holy-splain

> **Looking for the deep-dive learning narrative?** This doc is the operator reference (prereqs, commands, troubleshooting). For the chapter-style "first we want X because Y, then we pivot via Z" walkthrough of the attack chain, with K8s/AWS internals explained and a defense recap, read [`eks-demo-walkthrough.md`](eks-demo-walkthrough.md) alongside this one.

Kubesplaining ships an offline EKS mock under `testdata/e2e/vulnerable/15-cloud-eks.yaml`, exercised by `make e2e`. That fixture proves the EKS analyzer wiring works on a kind cluster, but it cannot demonstrate the post-detection PoC because no real AWS identity exists on the other end of the fake ARNs.

The **live** demo provisions a real EKS cluster named `holy-splain` in your own AWS account so you can see kubesplaining surface the privesc chain, then walk through actually exploiting it: harvest an IRSA token by escaping to the worker node, exchange it for AWS credentials via STS, exfil an S3 object, and loop back into Kubernetes as `system:masters` via aws-auth.

The whole thing is four make targets, ~15 minutes for cluster bootstrap, and ~$5/day if you forget to tear it down.

```bash
make eks-demo-up      # ~12 min: cluster + IAM + S3 + K8s manifests + aws-auth mapping
make eks-demo-scan    # ~30 sec: kubesplaining download + scan, opens .tmp/eks-demo-report/report.html
make eks-demo-poc     # default dry-run, prints all 10 steps; --execute to actually attack
make eks-demo-down    # ~10 min: removes cluster, IAM role, S3 bucket, kubeconfig contexts
```

## The attack chain

```
 ── Chain A (KUBE-PRIVESC-PATH-NODE-ESCAPE) ────────────────────────────
   User (kubeconfig from dev-team/dev-deployer-sa token)
      │  pods/create + pods/exec in dev-team only
      │  no cross-namespace RBAC, no cluster-scoped verbs
      │  ───  KUBE-PRIVESC-002 (pod_create_privileged_escape) ───
      ▼
   sink:node_escape

 ── Attacker glue (NOT in kubesplaining graph) ─────────────────────────
   On the node host: read /var/lib/kubelet/pods/<uid>/volumes/
     kubernetes.io~projected/<vol>/token of co-resident pods,
     identify the JWT whose subject claim is
     system:serviceaccount:prod-data:prod-data-pipeline-sa.

 ── Chain B (KUBE-PRIVESC-PATH-AWS-IAM-ROLE + SYSTEM-MASTERS) ─────────
   ServiceAccount  prod-data/prod-data-pipeline-sa
      │  KUBE-CLOUD-IRSA-ADMIN-ROLE-001 fires (name contains "Admin")
      │  KUBE-CLOUD-IRSA-001 (irsa_assume_role)
      ▼
   external:aws-iam:HolySplainProdDataPipelineAdministrator
      │  KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001 fires on aws-auth ConfigMap
      │  KUBE-CLOUD-AWSAUTH-001 (aws_auth_admin)
      ▼
   sink:system_masters
```

The chain crosses **two namespaces** but the attacker has no Kubernetes RBAC in the target one. They descend below the Kubernetes layer entirely. Kubesplaining surfaces this as **two independent privesc paths** in the report. The graph does not auto-merge them across the node boundary by design (modeling "node-escape implies token-theft of any co-resident pod" would explode in real clusters), so comprehensive coverage of *both* halves is what lets a human reader connect them. That is the educational point of the chain.

## What kubesplaining detects

| Rule ID | Severity | Half | Detection |
| --- | --- | --- | --- |
| `KUBE-PRIVESC-002` | High | A | `dev-deployer-sa` can `pods/create` in a namespace that does not enforce restricted PSA. |
| `KUBE-PRIVESC-PATH-NODE-ESCAPE` | High | A | BFS path: `dev-deployer-sa` → privileged pod → node host. |
| `KUBE-CLOUD-IRSA-ADMIN-ROLE-001` | High | B | `prod-data-pipeline-sa` IRSA annotation references a role whose name contains "Admin". |
| `KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001` | High | B | The aws-auth ConfigMap maps the same IAM role ARN to `system:masters`. |
| `KUBE-PRIVESC-PATH-AWS-IAM-ROLE` | High | B | BFS path: `prod-data-pipeline-sa` → external AWS IAM role. |
| `KUBE-PRIVESC-PATH-SYSTEM-MASTERS` | High | B | BFS path: `prod-data-pipeline-sa` → AWS IAM → aws-auth → cluster-admin. |

See [`findings.md`](findings.md) for the full per-rule reference.

## Prerequisites

- An AWS account with the IAM permissions documented in [`eks-demo-iam.md`](eks-demo-iam.md). `AdministratorAccess` is the path of least resistance for first-time runs.
- AWS credentials configured so `aws sts get-caller-identity` succeeds locally (env vars, `AWS_PROFILE`, etc.). Whatever your usual setup is, the demo will pick it up.
- The Hermit-pinned tools `eksctl`, `awscli`, and `kubectl`. The first `make eks-demo-up` triggers Hermit to auto-download all three into `~/Library/Caches/hermit`. If you have not run any other `make` target on this clone, run `make setup` first.
- ~$5/day cost budget while the cluster is up. Consider setting a one-time $20 AWS Budget on the account before your first run.
- Docker is **not** required (this is real EKS, unlike the `make e2e` kind workflow).

This demo writes to your **regular `~/.kube/config`**. `make eks-demo-up` lets eksctl add the cluster-admin context the same way `aws eks update-kubeconfig` always does. The PoC then adds two additional named contexts (`holy-splain-attacker`, `holy-splain-via-prod-irsa`) you can `kubectl config use-context ...` between to explore. `make eks-demo-down` removes all three. If you want strict isolation, `export KUBECONFIG=<some-path>` before any make target and everything respects it.

## What `make eks-demo-up` does

11 phases, each idempotent:

1. **Pre-flight.** Resolves your AWS identity, region, and account. Prints every AWS resource that is about to be created plus the cost estimate. Asks for `y/N` confirmation (skip with `--yes` or `EKS_DEMO_ASSUME_YES=1`).
2. **Cluster + OIDC + nodegroup.** `eksctl create cluster -f -` with an inline ClusterConfig: cluster `holy-splain`, managed nodegroup `default` of 2x `t3.small`, `iam.withOIDC: true`, `accessConfig.authenticationMode: API_AND_CONFIG_MAP`. Wall-clock ~12 minutes.
3. **Verify auth mode.** Re-reads `cluster.accessConfig.authenticationMode` and refuses to continue if anything other than `API_AND_CONFIG_MAP` or `CONFIG_MAP`. The PoC's final loopback step depends on this.
4. **Retrieve OIDC issuer.** Needed for the IAM trust policy condition.
5. **S3 bucket.** `kubesplaining-holysplain-secrets-<account>-<region>` with public-access block and a `flag.txt` object. Bucket name is account-and-region scoped so re-runs against the same account never collide.
6. **IAM role `HolySplainProdDataPipelineAdministrator`.** Trust policy: federated via the cluster OIDC, `StringEquals` on `sub == system:serviceaccount:prod-data:prod-data-pipeline-sa`. Permissions: `s3:GetObject` on the bucket and `sts:GetCallerIdentity`. The "Administrator" suffix in the role name is deliberate: real operators often give production data-pipeline roles admin-style names, and kubesplaining's IRSA analyzer flags exactly that pattern via `KUBE-CLOUD-IRSA-ADMIN-ROLE-001` (the heuristic looks for `Administrator`, `FullAccess`, or `PowerUserAccess` substrings in the role name).
7. **Apply K8s manifests.** Namespaces `dev-team` and `prod-data`, `dev-deployer-sa` + Role + RoleBinding (scoped to `dev-team` only), `prod-data-pipeline-sa` with the IRSA annotation, and a DaemonSet under `prod-data-pipeline-sa` that runs `aws-cli sleep infinity`. The DaemonSet matters: it guarantees a `prod-data-pipeline-sa` token mount on every node, so wherever the attacker pod lands, a token is co-resident to harvest.
8. **aws-auth mapping.** `eksctl create iamidentitymapping ... --group system:masters` adds the role ARN to the aws-auth ConfigMap. We use `eksctl` rather than `kubectl edit` because eksctl is the supported owner of the ConfigMap; any subsequent eksctl operation that touches identity mapping would otherwise clobber an ad-hoc edit.
9. **Sanity check.** Greps the live ConfigMap for the role ARN and exits non-zero if missing.
10. **State file.** Writes `.tmp/eks-demo-state.json` with cluster name, region, account ID, role ARN, bucket name, OIDC issuer, and `created_at`. `make eks-demo-down` reads this; it never re-asks for anything.
11. **Final banner.** Prints the three follow-up commands and the cost reminder.

Verify any phase in the AWS Console: EKS for the cluster, IAM for the role, S3 for the bucket. `kubectl get configmap aws-auth -n kube-system -o yaml | grep HolySplain` confirms the mapping is live.

## Reading the report

After `make eks-demo-scan` finishes, open `.tmp/eks-demo-report/report.html` in a browser. The **Findings** tab lists all five rule IDs from the table above. The **Attack Graph** tab shows both chains; switch between them in the path dropdown.

Inspecting the JSON directly is often faster for spot-checking:

```bash
# Chain A: dev-deployer-sa → node escape
jq '.findings[] | select(.rule_id == "KUBE-PRIVESC-PATH-NODE-ESCAPE") | {subject, escalation_path}' \
  .tmp/eks-demo-report/findings.json

# Chain B: prod-data-pipeline-sa → AWS IAM → aws-auth → system:masters
jq '.findings[] | select(.rule_id == "KUBE-PRIVESC-PATH-SYSTEM-MASTERS") | {subject, escalation_path}' \
  .tmp/eks-demo-report/findings.json
```

The two `escalation_path` arrays do not share any node. That is the cross-chain gap the PoC bridges by hand.

## The PoC walkthrough

`./scripts/eks-demo/poc.sh` (or `make eks-demo-poc`) defaults to **dry-run**: it prints all 10 steps with their commands and explanations but executes nothing. Pass `--execute` to step through interactively, pressing ENTER before each command runs.

### Step 1: become the attacker

The script mints a 1-hour ServiceAccount token for `dev-team:dev-deployer-sa` and writes a new kubeconfig context named `holy-splain-attacker` against the same cluster but using that token. The operator can `kubectl config use-context holy-splain-attacker` at any time afterward to explore the cluster as the compromised dev identity. This models a CI kubeconfig leak.

### Step 2: confirm namespace isolation

`kubectl --context=holy-splain-attacker auth can-i get pods -n prod-data` returns `no`. `... list secrets -A` returns `no`. `... create pods -n dev-team` returns `yes`. The attacker has **zero** legitimate RBAC path into `prod-data`. The remainder of the chain bypasses Kubernetes namespacing entirely.

### Step 3: apply the privileged escape pod

Predicted by kubesplaining as `KUBE-PRIVESC-002` / `KUBE-PRIVESC-PATH-NODE-ESCAPE`. The pod manifest (`scripts/eks-demo/privileged-attacker-pod.yaml`) has `hostPID: true`, `hostNetwork: true`, `securityContext.privileged: true`, and mounts host `/` at `/host`. The default scheduler places it on one of the two worker nodes.

### Step 4: demonstrate node-host access

`chroot /host` puts the attacker at the node's filesystem root. We list `/etc/kubernetes/` and `/var/lib/kubelet/pods/` as proof of root-on-node, sidestepping every Kubernetes-layer control.

### Step 5: harvest a co-resident IRSA token

Predicted by kubesplaining as `KUBE-CLOUD-IRSA-ADMIN-ROLE-001`. The script walks `/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token`, base64-decodes each JWT, and picks the one whose `sub` claim is `system:serviceaccount:prod-data:prod-data-pipeline-sa`. The DaemonSet guarantees this token is on every node.

> **This is the one step kubesplaining does not directly predict.** The graph does not model "node-escape implies any-pod-token-theft" because it would produce a combinatorial explosion in real clusters. Instead, kubesplaining surfaces both halves of the chain as independent findings, and the comprehensive coverage is what flags the risk. The teaching moment is to read the report holistically rather than expect a single tidy chain.

### Step 6: stash the token

The harvested JWT goes into a `STOLEN` shell variable. Nothing touches disk.

### Step 7: AssumeRoleWithWebIdentity

`aws sts assume-role-with-web-identity --role-arn <HolySplainProdDataPipelineAdministrator> --web-identity-token "$STOLEN"`. AWS validates the token against the role's OIDC trust policy: federated provider matches the cluster issuer, subject claim equals `system:serviceaccount:prod-data:prod-data-pipeline-sa`. The script exports `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` for the rest of the session.

### Step 8: exfiltrate the flag

With the assumed-role creds: `aws s3 cp s3://<bucket>/flag.txt -`. This is the data-loss arm of the chain, achievable even without the aws-auth loopback.

### Step 9: loop back to system:masters

Predicted by kubesplaining as `KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001` and `KUBE-PRIVESC-PATH-SYSTEM-MASTERS`. `aws eks update-kubeconfig --name holy-splain --role-arn <HolySplainProdDataPipelineAdministrator> --alias holy-splain-via-prod-irsa` writes a new context that authenticates with the assumed-role creds. The aws-auth mapping resolves to `system:masters`, so `kubectl --context=holy-splain-via-prod-irsa auth can-i '*' '*' --all-namespaces` returns `yes`. The chain is complete: a developer with namespaced `pods/create` in `dev-team` is now cluster-admin over the AWS plane.

### Step 10: stitching reveal

The script prints both `EscalationPath` arrays from `findings.json` side by side and captions the gap: kubesplaining did not connect these chains, but comprehensive coverage of both halves is what let you connect them as a human attacker.

## Cost and safety

- The cluster is ~$0.10/hr for the EKS control plane plus ~$0.04/hr for two `t3.small` nodes plus NAT/data transfer (~$0.05/hr), roughly **$5/day** if left running.
- `make eks-demo-up` records a `created_at` timestamp; `make eks-demo-down` reads it and prints how long the cluster was up plus an estimated AWS spend.
- The IAM role can do `s3:GetObject` on the demo bucket and call STS. It cannot assume any other role, modify IAM, or touch other AWS services.
- The S3 bucket has `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, and `RestrictPublicBuckets` all enabled. It contains a single `flag.txt` saying "you found the kubesplaining demo flag".
- Nothing touches your existing IAM users, roles, policies, or S3 buckets beyond what is documented above.
- Consider setting a one-time **$20 AWS Budget** on the account before your first run.

## Teardown

`make eks-demo-down` runs the reverse of setup, each step tolerant of "already gone":

1. Delete the K8s workloads (`kubectl delete -f` on the demo manifests).
2. Remove the aws-auth iamidentitymapping for `HolySplainProdDataPipelineAdministrator`.
3. Empty and delete the S3 bucket.
4. Delete the IAM role's inline policy, then the role itself.
5. `eksctl delete cluster --wait` (~10 minutes).
6. Remove the three demo kubeconfig contexts (`holy-splain-attacker`, `holy-splain-via-prod-irsa`, and the eksctl-bootstrapped admin context).
7. Delete the local state file.

Pass `--keep-iam` to skip the IAM and S3 deletion if you plan to rerun the PoC without recreating IAM trust. Pass `--cluster <name>` / `--region <r>` / `--role <name>` / `--bucket <name>` for partial-state recovery if the state file is missing.

Verify nothing is left behind:

```bash
aws eks list-clusters --region $AWS_REGION | grep holy-splain
aws iam list-roles --query "Roles[?starts_with(RoleName, \`HolySplain\`)].RoleName"
aws s3 ls | grep holysplain
kubectl config get-contexts | grep holy-splain
```

All four should return empty output.

## Troubleshooting

### `update-kubeconfig --role-arn` returns "User ... is not authorized"

`cluster.accessConfig.authenticationMode` must be `API_AND_CONFIG_MAP` or `CONFIG_MAP`. Newer EKS clusters created via the AWS Console default to `API`-only (access entries), which silently ignores the aws-auth ConfigMap. The setup script pins `API_AND_CONFIG_MAP` explicitly and re-checks it post-create. If you suspect drift:

```bash
aws eks describe-cluster --name holy-splain --query 'cluster.accessConfig.authenticationMode'
aws eks update-cluster-config --name holy-splain \
  --access-config authenticationMode=API_AND_CONFIG_MAP
```

### `assume-role-with-web-identity` returns `InvalidIdentityToken`

IAM trust policy propagation takes 10 to 30 seconds. The setup script sleeps 15 seconds after creating the role; if you still hit this on a re-run, sleep another 15 and retry. If it persists, double-check the `sub` claim in the harvested JWT matches the trust policy condition exactly: subject claim equals `system:serviceaccount:prod-data:prod-data-pipeline-sa`.

### eksctl refuses to create the cluster

`eksctl create cluster` refuses if its CloudFormation stack already exists. If a previous setup partially failed, delete the lingering stack:

```bash
eksctl utils describe-stacks --region $AWS_REGION --cluster holy-splain
eksctl delete cluster --name holy-splain --region $AWS_REGION --wait
```

Then re-run `make eks-demo-up`.

### Step 5 prints "no prod-data-pipeline-sa token on this node"

The DaemonSet rolled out, but the kubelet has not yet mounted the projected token volumes when the attacker pod ran the find. Wait 30 seconds and re-run step 5. Or confirm the DaemonSet is ready: `kubectl get daemonset prod-data-processor -n prod-data` should show `DESIRED=CURRENT=READY=2`.

### STS regional endpoint mismatch

Some regions reject web-identity tokens validated against a different region's STS endpoint. Make sure `AWS_REGION` in your local shell matches the cluster's region. The IRSA webhook handles this automatically inside the cluster.

### t3.small CPU credits exhausted

t3.small is burstable. A demo running > 4 hours can exhaust credits and become unusable. If you plan a longer session, edit the inline ClusterConfig in `scripts/eks-demo/setup.sh` to use `t3.medium`.

## Related references

- [`eks-demo-walkthrough.md`](eks-demo-walkthrough.md): the deep-dive learning narrative for the attack chain. Reads as "first we want X because Y, then we pivot via Z," explains every K8s/AWS internal the chain touches, and ends with a defense recap of where each link could be broken.
- [`eks-demo-iam.md`](eks-demo-iam.md): operator IAM permissions reference.
- [`findings.md`](findings.md): full kubesplaining rule catalog, including all `KUBE-CLOUD-*` rules referenced above.
- [`architecture.md`](architecture.md): how the privesc graph and the cloud analyzers fit together internally.
- [`audit-logs.md`](audit-logs.md): orthogonal least-privilege workflow; not needed for this demo.
- [`testdata/e2e/vulnerable/15-cloud-eks.yaml`](../testdata/e2e/vulnerable/15-cloud-eks.yaml): the offline mock fixture this demo's K8s manifests are derived from.
