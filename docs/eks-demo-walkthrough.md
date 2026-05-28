# Holy-splain walkthrough: a Kubernetes-to-AWS attack, explained

This document is the deep-dive companion to [`eks-demo.md`](eks-demo.md). The other doc tells you which commands to run and what to expect. This one walks through *why each step exists*, what an attacker is thinking at each turn, and what Kubernetes / AWS internals make the attack possible. It is written for someone who has used `kubectl` a bit but has never stared at a privesc chain that crosses cloud boundaries.

The story we are about to live through:

> A developer at a fictional company is given a low-privilege ServiceAccount token to deploy pods in their own namespace. That token leaks (a CI log, a misplaced file, a shared kubeconfig). Within twenty minutes, the attacker holding the token reads a production S3 bucket and is the cluster's `system:masters` administrator. They never needed any cross-namespace RBAC. They never exploited a CVE. Every door they walked through was unlocked on purpose by a real operational anti-pattern.

By the end you will know exactly which doors and how to lock them.

## How to read this doc

Have the live demo running (`make eks-demo-up`) and the report open (`make eks-demo-scan`, then open `.tmp/eks-demo-report/report.html`) while you read. Each section ends with a "Try it yourself" block that points at a specific command from `poc.sh` you can run by hand to feel what the attacker would feel. The end of the doc has a defense recap that goes back through every hop and asks what would have stopped it.

If at any point you want to step away, the cluster costs about $5 a day. `make eks-demo-down` removes everything in ten minutes.

## The cast of characters

The setup script creates a small but realistic two-namespace cluster.

```
EKS cluster  holy-splain     (region: us-east-1)
                                                                       AWS account 241317860001
                                                                       (your account, not the
                                                                        attacker's)
+----------------------------------------+
|                                        |
|  Namespace dev-team                    |     Namespace prod-data
|                                        |
|  ServiceAccount dev-deployer-sa        |     ServiceAccount prod-data-pipeline-sa
|     Role: pods/create, pods/exec       |       annotation:
|           in dev-team only             |         eks.amazonaws.com/role-arn
|                                        |         = arn:aws:iam::ACCOUNT:role/
|  (attacker starts here)                |           HolySplainProdDataPipelineAdministrator
|                                        |
|                                        |     DaemonSet prod-data-processor
|                                        |       one pod per worker node
|                                        |       runs as prod-data-pipeline-sa
+----------------------------------------+

   ───────  AWS side  ──────────────────────────────────────────────────────

   IAM Role HolySplainProdDataPipelineAdministrator
     Trust policy: federated via the cluster's OIDC issuer,
                   StringEquals on subject ==
                     system:serviceaccount:prod-data:prod-data-pipeline-sa
     Permissions:  s3:GetObject on kubesplaining-holysplain-secrets-...
                   sts:GetCallerIdentity
                   eks:DescribeCluster

   aws-auth ConfigMap in kube-system
     mapRoles entry:
       rolearn: arn:aws:iam::...:role/HolySplainProdDataPipelineAdministrator
       username: holy-splain-prod-data-pipeline-administrator
       groups:  [system:masters]

   S3 bucket  kubesplaining-holysplain-secrets-<account>-<region>
     contains  flag.txt  ("you found the kubesplaining demo flag")
```

A few things worth pausing on before we attack.

**`dev-deployer-sa` is genuinely low privilege.** Its Role is bound only within the `dev-team` namespace. It cannot list, get, or do anything in `prod-data`. It cannot read secrets cluster-wide. It cannot impersonate other identities. The only "interesting" verbs it has are `pods/create` and `pods/exec`, both scoped to its own namespace.

**The `prod-data-pipeline-sa` ServiceAccount is *not* the attacker.** It is the victim. It is the real production identity the cluster owner wanted to give a pipeline workload. Its IRSA annotation says "any pod running under me should be able to assume the IAM role `HolySplainProdDataPipelineAdministrator`." That is the legitimate use case. The vulnerability is the role's name and what aws-auth does with it.

**IRSA (IAM Roles for Service Accounts) is the Kubernetes-to-AWS identity bridge.** AWS-side, the IAM role's trust policy says "I trust JWTs issued by this EKS cluster's OIDC provider, but only for the specific subject `system:serviceaccount:prod-data:prod-data-pipeline-sa`." Kubernetes-side, when a pod is created with `serviceAccountName: prod-data-pipeline-sa`, the EKS Pod Identity Webhook (a mutating admission webhook installed by AWS) sees the SA's `eks.amazonaws.com/role-arn` annotation and injects two pieces of magic into the pod spec: a projected ServiceAccount token volume with audience `sts.amazonaws.com`, and the environment variables `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`. The AWS SDK, when it runs inside the pod, sees those env vars and automatically exchanges the projected token for short-lived AWS credentials via `sts:AssumeRoleWithWebIdentity`. The pod never needs an AWS access key.

**`aws-auth` is the Kubernetes-side of EKS authentication.** It is a ConfigMap in `kube-system`. When a request arrives at the EKS API server signed by IAM creds, the server asks STS "who is this?", gets back an IAM principal ARN, and looks up that ARN in `aws-auth` to translate it to a Kubernetes username and groups. Our aws-auth has one extra mapping: the role `HolySplainProdDataPipelineAdministrator` resolves to the group `system:masters`, which Kubernetes itself wires to `cluster-admin`. So if anything can authenticate to the API server *as that role*, the cluster treats it as god.

## What kubesplaining told you in advance

Run `make eks-demo-scan` and open the report. There are 83 findings total in this cluster (a real EKS cluster has dozens of "your cloud provider is doing unusual things" findings even before you start adding broken stuff). The six that matter for this attack:

1. **`KUBE-PRIVESC-002`** on `dev-team/dev-deployer-sa`. Says: "this subject can `pods/create` in a namespace that does not enforce restricted Pod Security Admission, so they can launch a privileged pod that escapes to the node." This is *the precondition* for everything that follows on the developer side.

2. **`KUBE-PRIVESC-PATH-NODE-ESCAPE`** on `dev-team/dev-deployer-sa`. Says: "starting from dev-deployer-sa, there is a single-hop path to escaping the Kubernetes layer entirely. Hop 1: `pod_create_privileged_escape`." This is the full Chain A.

3. **`KUBE-CLOUD-IRSA-ADMIN-ROLE-001`** on `prod-data/prod-data-pipeline-sa`. Says: "this SA is annotated to assume the IAM role `HolySplainProdDataPipelineAdministrator`, and the role name contains `Administrator`. That is a heuristic flag: any pod under this SA gets credentials to an AWS principal whose name screams 'overprivileged'."

4. **`KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001`** on the `kube-system/aws-auth` ConfigMap. Says: "this aws-auth has a mapping from an IAM principal directly to `system:masters`. Any caller who can assume that IAM role can authenticate to the cluster as cluster-admin."

5. **`KUBE-PRIVESC-PATH-AWS-IAM-ROLE`** on `prod-data/prod-data-pipeline-sa`. Says: "starting from this SA, there is a path that terminates outside Kubernetes at an AWS IAM role node. Hop 1: `irsa_assume_role`." This is half of Chain B.

6. **`KUBE-PRIVESC-PATH-SYSTEM-MASTERS`** on `prod-data/prod-data-pipeline-sa`. Says: "starting from this SA, there is a two-hop path that goes out through IRSA and back in through aws-auth to land at `system:masters`. Hop 1: `irsa_assume_role` to the AWS IAM role. Hop 2: `aws_auth_admin` to the cluster-admin sink." This is full Chain B.

**Two important things kubesplaining does *not* tell you.**

Chain A and Chain B never connect in the kubesplaining graph. They are reported as two separate paths because the privesc engine does not model the proposition "if you escape to the node, you can read the projected ServiceAccount token of any other pod scheduled on that node." Modeling it would produce a combinatorial explosion in real clusters (every pod gets implicit edges to every other pod on its node, recursively). The graph stays sane by drawing the line at the node boundary.

The PoC's whole trick is to **bridge that boundary by hand**. Chain A gets you onto the node host. Once you are root on the node, you read kubelet's on-disk projected token mount for `prod-data-pipeline-sa` and you have the starting subject of Chain B in your shell. The two chains are now one chain, walked by a human reader who saw both findings in the same report.

The teaching point: **comprehensive coverage of both halves of an attack is itself the alert.** You do not need the static analyzer to draw every possible connection. You need it to surface every interesting subject and every interesting capability, and a human reading the report figures out which pairs co-resident.

## Walkthrough

We now walk through `poc.sh` step by step. Each section opens with the question the attacker is asking, explains the technique they reach for, gives the command, and ends by stating what we have *now* that we did not have before. The PoC script is the operational version of this same content; this document is the explainer next to it.

### Step 1: become the developer

**The question:** I have a leaked token for `dev-team:dev-deployer-sa`. How do I use it?

A Kubernetes API server does not care how a token reached the caller. It validates the signature against the OIDC issuer (the cluster itself), checks the expiry, looks at the subject claim, and applies whatever RBAC binds to that subject. If you have the bytes of a valid token, you are that identity to the API server.

The cleanest way to use a stolen token is to add a kubeconfig context for it. A kubeconfig is a small YAML file that maps named contexts to (cluster, user) pairs, where "user" is just a credential bundle. You can have many contexts in one file and switch between them with `kubectl config use-context`. Our PoC reuses the cluster definition that eksctl already wrote (server URL, certificate authority) and just adds a new user whose credential is the stolen token.

```bash
TOKEN=$(kubectl create token dev-deployer-sa -n dev-team --duration=1h)
kubectl config set-credentials holy-splain-dev-deployer-sa --token="$TOKEN"
kubectl config set-context holy-splain-attacker \
  --cluster=holy-splain.us-east-1.eksctl.io \
  --user=holy-splain-dev-deployer-sa \
  --namespace=dev-team
```

We use `kubectl create token` here only because we are simulating the breach. A real attacker would already have the token from whatever leak they exploited. The command outputs a JSON Web Token whose subject claim is `system:serviceaccount:dev-team:dev-deployer-sa`.

> **Try it yourself:** after `poc.sh --execute` step 1, run `kubectl config get-contexts | grep holy-splain` to see the new context. Run `kubectl config use-context holy-splain-attacker` and then `kubectl auth whoami` to see Kubernetes confirm "you are dev-deployer-sa." Switch back with `kubectl config use-context admin_hardik@holy-splain.us-east-1.eksctl.io` (or whatever the eksctl-bootstrapped context is on your machine, visible via `kubectl config get-contexts`).

What we have now: a kubectl context we can throw any command at, where the API server believes the caller is the leaked developer identity.

### Step 2: confirm the cage we are in

**The question:** before I waste my one-hour token trying random things, what can I actually do?

This is what every competent attacker does first. Trying random RBAC verbs and getting `Forbidden` 403 responses leaves audit log entries that defenders will see. The cheapest enumeration is `kubectl auth can-i`, which returns `yes` or `no` without actually attempting the action. We probe three things: a cross-namespace read into `prod-data` (which is where the real value lives), a cluster-wide secret list (the most dangerous thing a low-priv compromise can have), and a same-namespace pod create (to confirm we have the verbs the kubesplaining report led us to expect).

```bash
kubectl --context=holy-splain-attacker auth can-i get pods -n prod-data
kubectl --context=holy-splain-attacker auth can-i list secrets -A
kubectl --context=holy-splain-attacker auth can-i create pods -n dev-team
```

Expected: `no`, `no`, `yes`. The result confirms our threat model: we are namespaced, we cannot directly reach `prod-data`, and our only useful capability is to create pods in our own namespace.

This is the moment a less determined attacker gives up. There is nothing here you can do with vanilla Kubernetes verbs that lets you cross into `prod-data`. To get out you have to *go down*, beneath the Kubernetes layer entirely.

What we have now: confirmation that the namespace boundary is real and that we have to find a way underneath it.

### Step 3: open a window in the cage by going through the floor

**The question:** how do I get from "I can create a pod in dev-team" to "I can read files on the node?"

A Kubernetes pod is, fundamentally, a process group running in Linux containers on a node. The node is just an EC2 instance with a kubelet daemon talking to the API server. The kubelet stores everything it needs to run pods, including all secrets and projected tokens those pods mount, in `/var/lib/kubelet` on that EC2 instance. If you can read `/var/lib/kubelet` on the node, you can read those secrets.

Kubernetes has many controls designed to keep a pod from reading the node's filesystem. Three of them matter here:

1. The pod spec must not have `hostPID`, `hostNetwork`, or `hostIPC` set, otherwise the pod sees host namespaces.
2. The pod spec must not have `securityContext.privileged: true`, otherwise the container kernel capabilities equal the host's.
3. The pod spec must not have a `hostPath` volume mounting the host filesystem.

By default in a Kubernetes cluster, *all three of those things are allowed*. The mechanism that turns them off is **Pod Security Admission**, an admission controller that rejects pods which violate a policy label set on the namespace. There are three policy levels:

- `privileged`: anything goes (the default for unlabeled namespaces).
- `baseline`: blocks the obvious dangerous stuff (hostPath, host namespaces, privileged).
- `restricted`: blocks the dangerous stuff plus everything that is "merely risky" (runs as root, mutable filesystem, capabilities other than minimal).

Look at the namespace setup in `testdata/eks-demo/k8s-manifests.yaml`: `dev-team` has *no* `pod-security.kubernetes.io/enforce` label. That means Pod Security Admission for that namespace is at the default `privileged` level, which means we can submit anything we want.

Kubesplaining flagged this. `KUBE-PRIVESC-002` exists *because* dev-team has `pods/create` AND does not enforce restricted. Either alone would be merely awkward. Together they are an attack precondition.

We apply this manifest as the attacker context:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: dev-team
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: shell
      image: public.ecr.aws/aws-cli/aws-cli:latest
      command: ["/bin/sh", "-c", "sleep 3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /
        type: Directory
```

`hostPID: true` puts us in the node's process namespace. `securityContext.privileged: true` removes the kernel-level restrictions. `volumes.hostPath path: /` mounts the entire node filesystem at `/host` inside the pod. The image is `public.ecr.aws/aws-cli/aws-cli` because we will need the aws CLI later anyway; any image works for this step.

Kubernetes accepts the pod. The default scheduler places it on one of the two worker nodes. It transitions to Running.

> **Try it yourself:** after the pod is up, run `kubectl --context=holy-splain-attacker exec attacker -n dev-team -- chroot /host /bin/sh -c "uname -a; whoami; id"`. The output shows the *node's* kernel, the *node's* root user, and uid=0. You are root on an EC2 instance.

What we have now: a Kubernetes pod, but functionally a root shell on the EC2 worker node it landed on.

### Step 4: prove we are on the node, not in a pod

**The question:** how do I know `chroot /host` actually gave me real host access and is not some sandbox illusion?

This step exists for the demo, not the attack. Real attackers do not need to prove anything to themselves. But for a learner, the visual that "yes this is the node, look at its hostname, look at the directories that only exist on a kubelet host" is what makes the previous step click.

```bash
kubectl --context=holy-splain-attacker exec attacker -n dev-team -- \
  chroot /host /bin/sh -c '
    cat /etc/hostname                          # the EC2 instance name
    ls /etc/kubernetes                         # only exists on a node
    ls /var/lib/kubelet/pods | head            # one directory per pod
  '
```

Output looks like:

```
ip-192-168-13-154.ec2.internal
kubelet
manifests
pki
41ac61e7-d421-408d-b8da-c58bccc34b71
5ba48433-921a-42ea-9921-df345f806d24
7d855b99-e396-4607-9369-892bce1114cd
...
```

The hostname `ip-192-168-13-154.ec2.internal` is the EKS worker's internal DNS name, which we could not see from inside any non-privileged pod. The `/etc/kubernetes` directory does not exist in containers (it is a node-only directory containing the kubelet's bootstrap config and the cluster CA). The `/var/lib/kubelet/pods/<UUID>` entries are kubelet's per-pod sandbox directories. There is one for every pod the kubelet has ever scheduled on this node, including the pods of other namespaces, even pods we have no RBAC permission to *see* through the API.

That last point is the one to internalize. The kubelet is the layer below Kubernetes RBAC. It does not check namespace boundaries when storing pod data, because at the kubelet's level there are no namespaces, only pods.

What we have now: we have visually confirmed we are root on the node, with read access to every pod's kubelet directory regardless of namespace.

### Step 5: harvest the production SA's IRSA token

**The question:** the kubelet stores every pod's secrets on this node. Is the pipeline pod scheduled here, and if so, what is in its token mount?

This is where Chain A and Chain B intersect.

Background you need: when a pod uses a ServiceAccount, the kubelet mounts a *projected* token into the pod at a known path. For a regular SA, that path is `/var/run/secrets/kubernetes.io/serviceaccount/token`. The kubelet's source for that mount is on the node at `/var/lib/kubelet/pods/<pod-uuid>/volumes/kubernetes.io~projected/<volume-name>/token`.

For IRSA-annotated SAs, the EKS Pod Identity Webhook injects a *second* projected token volume specifically for AWS use. Its audience is `sts.amazonaws.com` instead of the Kubernetes API server, and it is mounted at `/var/run/secrets/eks.amazonaws.com/serviceaccount/token` inside the pod. On the node, the volume name in the kubelet directory is `aws-iam-token`. The token itself is a JWT signed by the cluster's OIDC issuer (the same issuer the IAM role's trust policy already trusts), and its `sub` claim is `system:serviceaccount:<ns>:<sa>`.

We are root on the node. We walk every directory under `/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token`, base64-decode the middle segment of each JWT (which is the unsigned payload), and look for the one whose `sub` claim contains `prod-data-pipeline-sa`. The DaemonSet we set up earlier guarantees one such pod is scheduled on every worker node, so this search always succeeds.

```bash
kubectl --context=holy-splain-attacker exec attacker -n dev-team -- chroot /host /bin/sh -c '
  for t in $(find /var/lib/kubelet/pods -name token 2>/dev/null); do
    payload=$(awk -F. "{print \$2}" "$t" 2>/dev/null | base64 -d 2>/dev/null || true)
    case "$payload" in
      *prod-data-pipeline-sa*)
        echo "FOUND_PROD_TOKEN_PATH=$t"
        head -c 80 "$t"
        echo "$payload" | grep -o "sub[^,}]*" | head -1
        exit 0
        ;;
    esac
  done
  echo "no prod-data-pipeline-sa token on this node" >&2
  exit 1
'
```

The first line shows the path on the node where the token lives. The next two confirm the JWT and its subject claim. The relevant output looks like:

```
FOUND_PROD_TOKEN_PATH=/var/lib/kubelet/pods/5ba48433-.../volumes/kubernetes.io~projected/aws-iam-token/token
eyJhbGciOiJSUzI1NiIsImtpZCI6...
sub":"system:serviceaccount:prod-data:prod-data-pipeline-sa
```

The volume name `aws-iam-token` (rather than the default `kube-api-access-*`) is the giveaway: this is the IRSA-specific projected token, signed for `sts.amazonaws.com` audience. It is exactly the token AWS expects in an `sts:AssumeRoleWithWebIdentity` call.

> **The gap kubesplaining did not auto-bridge:** at this point we have *all* the information needed to chain to AWS. But kubesplaining surfaced Chain A (dev-deployer-sa to node escape) and Chain B (prod-data-pipeline-sa to system:masters) as separate findings. Look at the report and you will see them next to each other, each ending or starting where the node boundary is. The attacker who reads both findings makes the connection: "if I can be on a node, and a pod with the IRSA SA is also on that node, then escape lets me become that SA." A human bridges the graph gap. The defender's job is to see both halves in the report and react to *the combination*, not each half in isolation.

What we have now: the JWT bytes for `prod-data-pipeline-sa`, stolen from the kubelet's mount.

### Step 6: get the JWT out of the pod and into our shell

**The question:** how do I move the harvested token from inside the kubelet's process tree into the shell from which I will call AWS STS?

Simplest possible answer: re-run the find with `cat "$t"` instead of the metadata prints, capture its stdout in a shell variable. The PoC keeps the token entirely in shell memory and never writes it to disk. This is intentional: file-system writes leave forensic traces; shell variables do not.

```bash
STOLEN=$(kubectl --context=holy-splain-attacker exec attacker -n dev-team -- chroot /host /bin/sh -c '
  for t in $(find /var/lib/kubelet/pods -name token 2>/dev/null); do
    payload=$(awk -F. "{print \$2}" "$t" 2>/dev/null | base64 -d 2>/dev/null || true)
    case "$payload" in *prod-data-pipeline-sa*) cat "$t"; exit 0;; esac
  done
  exit 1
')
echo "stolen token (first 40 chars): ${STOLEN:0:40}..."
```

What we have now: `$STOLEN` is a valid IRSA token for `prod-data-pipeline-sa`, sitting in our shell, ready to be exchanged for AWS credentials.

### Step 7: trade the JWT for AWS credentials

**The question:** how do I tell AWS "I am `prod-data-pipeline-sa`, please give me credentials for the role this SA is allowed to assume?"

AWS provides exactly this exchange via `sts:AssumeRoleWithWebIdentity`. The call shape is:

1. We provide the role ARN we want to assume.
2. We provide the JWT (the "web identity token").
3. STS verifies the JWT's signature against the role's trust policy.
4. STS verifies the JWT's `sub` claim matches the trust policy's `StringEquals` condition.
5. If both match, STS issues a 15-minute set of credentials for the role.

Our IAM role's trust policy says: federated provider equals the cluster's OIDC issuer (matches), and `sub` equals `system:serviceaccount:prod-data:prod-data-pipeline-sa` (matches). So STS hands us short-lived credentials.

```bash
CREDS_JSON=$(aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::241317860001:role/HolySplainProdDataPipelineAdministrator \
  --role-session-name holy-splain-node-escape \
  --web-identity-token "$STOLEN" \
  --duration-seconds 900)

export AWS_ACCESS_KEY_ID=$(echo "$CREDS_JSON" | sed -nE 's/.*"AccessKeyId": *"([^"]+)".*/\1/p')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS_JSON" | sed -nE 's/.*"SecretAccessKey": *"([^"]+)".*/\1/p')
export AWS_SESSION_TOKEN=$(echo "$CREDS_JSON" | sed -nE 's/.*"SessionToken": *"([^"]+)".*/\1/p')

aws sts get-caller-identity
```

The closing `get-caller-identity` confirms whose creds we just exported. It returns:

```json
{
  "UserId": "AROATQL5KKKQRTUBHIAIL:holy-splain-node-escape",
  "Account": "241317860001",
  "Arn": "arn:aws:sts::241317860001:assumed-role/HolySplainProdDataPipelineAdministrator/holy-splain-node-escape"
}
```

This shell is now AWS. We are no longer a Kubernetes ServiceAccount holding a JWT; we are an active AWS IAM session for the production data pipeline's role. Every AWS API call from this shell goes out as that role.

What we have now: 15 minutes of AWS credentials for `HolySplainProdDataPipelineAdministrator`, the role kubesplaining warned us was overprivileged.

### Step 8: actually do the AWS thing

**The question:** what damage can we do AWS-side with these credentials?

The role's permissions policy in our demo grants only `s3:GetObject` on the demo bucket, `sts:GetCallerIdentity`, and `eks:DescribeCluster`. That is intentionally minimal so the demo does not accidentally let an attacker pivot into the AWS account proper. In a real cluster, an IRSA role named "admin" usually has *much* more: it might be able to read every S3 bucket, write Lambda code, manage RDS, decrypt KMS keys. The narrative we are demonstrating is the worst case: the IRSA role is the foothold and from there everything downstream is in scope.

The minimum demonstration is reading the demo bucket's flag.

```bash
aws s3 cp s3://kubesplaining-holysplain-secrets-241317860001-us-east-1/flag.txt -
```

Output:

```
you found the kubesplaining demo flag
```

In a real engagement this would be production customer data, ML model weights, KMS keys, anything the IRSA role had access to. The point of the step is that *the attack has already succeeded on the AWS side*, and we have not even started using the aws-auth loopback.

What we have now: proof that the chain landed at "data exfiltration possible." If the demo stopped here, you would still have a serious incident.

### Step 9: walk back into Kubernetes through the front door

**The question:** the IAM role I just assumed is mapped to `system:masters` in aws-auth. Can I use those AWS credentials to authenticate to the Kubernetes API server as the cluster administrator?

Yes. This is the loop closing.

EKS authentication accepts pre-signed STS GetCallerIdentity requests as bearer tokens. The aws CLI has a helper for this: `aws eks get-token --cluster-name <name>` takes the current AWS credentials in the environment, pre-signs an STS GetCallerIdentity request, base64-encodes it, and prints it as a Kubernetes-compatible bearer token. When you send that token to the EKS API server, the server forwards the pre-signed request to STS, STS returns the IAM principal ARN, and the API server looks that ARN up in aws-auth. Our ARN maps to `system:masters`. We are admin.

Critically: we do *not* pass `--role-arn` to `get-token`. We are already running with assumed-role credentials in the environment. Passing `--role-arn` would make get-token try to assume the role *again* (chain assume-role on top of assume-role-with-web-identity), and IAM does not allow a role to assume itself. The whole point is that the AWS credentials we have in scope are already the role.

```bash
K8S_TOKEN=$(aws eks get-token --cluster-name holy-splain --region us-east-1 \
  --output text --query 'status.token')

kubectl config set-credentials holy-splain-via-prod-irsa --token="$K8S_TOKEN"
kubectl config set-context holy-splain-via-prod-irsa \
  --cluster=holy-splain.us-east-1.eksctl.io \
  --user=holy-splain-via-prod-irsa

kubectl --context=holy-splain-via-prod-irsa auth can-i '*' '*' --all-namespaces
kubectl --context=holy-splain-via-prod-irsa get pods -A | head -8
```

`auth can-i '*' '*' --all-namespaces` returns `yes`. `get pods -A` lists every pod in the cluster, including kube-system pods we never had RBAC to see as the developer.

We have closed the loop. A developer with permission to create pods in their own namespace is now `system:masters` over the entire cluster. Five system boundaries crossed in nine steps: Kubernetes RBAC, Pod Security Admission, the node sandbox, AWS IAM trust policy, and aws-auth mapping. Every one of them was a working security control, used as designed. The chain succeeded because the designer's intent never accounted for the chain.

What we have now: cluster-admin access, demonstrated by listing pods cluster-wide.

### Step 10: re-read the report

**The question:** now that the attack is done, can I trace it back to the kubesplaining report and see exactly which signals would have stopped me at each hop if a defender had been looking?

The script prints both BFS paths side by side, extracted from `findings.json` with `jq`. Chain A:

```
ServiceAccount/dev-team/dev-deployer-sa
  --[pod_create_privileged_escape]-->  sink:node_escape
```

Chain B:

```
ServiceAccount/prod-data/prod-data-pipeline-sa
  --[irsa_assume_role]-->     User/arn:aws:iam::...:role/HolySplainProdDataPipelineAdministrator
  --[aws_auth_admin]-->       sink:system_masters
```

This is the moment of insight. The two paths share no nodes. The attacker bridges them by walking from the bottom of Chain A (where they have node access) to the top of Chain B (where they need an IRSA-bound SA token). The bridge happens entirely outside the graph, in the kubelet's `/var/lib/kubelet/pods` directory. Kubesplaining did not draw the bridge for you, but it *showed you both endpoints*. A defender reading the report sees Chain A and Chain B in the same cluster and asks: "if a Chain A subject lands on a node where a Chain B subject's pod is also running, what stops them?" The answer is nothing.

## Defense recap: where to break each link

If you came away from the walkthrough thinking "well that was a parade of paper-thin barriers," good. That is the educational outcome. The chain only works because *every* control along the way was set to its weakest viable setting. Here is each link and the smallest possible change that would have broken it.

**At step 2-3, the privileged pod**: enforce restricted Pod Security Admission on every namespace that does not have an explicit need for privileged workloads. The label `pod-security.kubernetes.io/enforce: restricted` on the `dev-team` namespace would have made step 3's pod manifest reject with `PodSecurity "restricted:latest"`. Chain A ends. There is no node access. Kubesplaining's `KUBE-PRIVESC-002` would no longer fire.

**At step 5, the projected token harvest**: this one is harder. The kubelet has to store the projected token *somewhere* the pod can read it, and once you are on the node you can read it. The defense here is not at the kubelet level but at the *placement* level: do not allow developer-facing namespaces to colocate with production-data namespaces on the same nodes. EKS has node groups; you can create a `prod-data` nodegroup with `eks.amazonaws.com/nodegroup` taints that only `prod-data` workloads tolerate, and a `dev-team` nodegroup that excludes them. With node isolation, a privileged pod in `dev-team` will be scheduled on a `dev-team` node, where no `prod-data-pipeline-sa` token mount will be found in `/var/lib/kubelet`. The chain dead-ends.

**At step 7, the IRSA trust policy**: the role's trust policy already pins the subject claim to one specific SA. That part is correct. The improvement is *audience* validation: the trust policy should also check `aud == sts.amazonaws.com` explicitly in its `StringEquals` block (the example IAM JSON in this repo already does so). This catches the variant where an attacker tries to substitute a token with a different audience.

**At step 7-8, what the IAM role can do**: the most leveraged defense in the chain. The role was named `HolySplainProdDataPipelineAdministrator` and its permissions are whatever the operator chose. The kubesplaining rule `KUBE-CLOUD-IRSA-ADMIN-ROLE-001` fires on the *name* because the name is the only signal a static analyzer has into AWS. The actual permissions could be tightly scoped (just `s3:GetObject` on one prefix) and the chain would deliver much less value. The naming convention itself is the lesson: do not give production IRSA roles names that contain `Administrator`, `FullAccess`, or `PowerUserAccess`. Naming a role honestly forces a conversation about whether it should actually have admin perms.

**At step 9, the aws-auth mapping**: this is the one that converts "AWS-side compromise" into "Kubernetes-side cluster-admin." Auditing aws-auth for entries that map to `system:masters` is the highest-value cluster-hygiene activity in EKS. If `HolySplainProdDataPipelineAdministrator` is mapped to a least-privilege Kubernetes group instead (or removed from aws-auth entirely), the assume-role-with-web-identity still gives the attacker AWS creds, but `kubectl auth can-i` returns `no` for everything interesting. Half the chain dies.

**At step 9, EKS Access Entries instead of aws-auth**: AWS now offers Access Entries, a managed alternative to the aws-auth ConfigMap. Migrating fully (setting the cluster's `authenticationMode` to `API` only) removes the aws-auth ConfigMap from the picture entirely. This is more invasive than the other defenses and has its own trade-offs (kubesplaining does not yet inspect Access Entries; that is a known gap documented in `PLAN.md`), but it is the long-term direction AWS is pushing for EKS.

A reasonable cluster could implement just the first defense (restricted PSA in non-privileged namespaces) and the fourth (audit IRSA role naming and permissions) and break this entire chain. Neither is hard. Neither is rare to skip in real-world deployments.

## Extending the demo

If you have the demo running and want to experiment, here are five variations worth trying.

1. **Add restricted PSA to `dev-team`.** Run `kubectl label namespace dev-team pod-security.kubernetes.io/enforce=restricted`. Re-run the PoC from step 3. Watch the privileged pod fail to start with a clear admission error. Re-run `make eks-demo-scan`. `KUBE-PRIVESC-002` should no longer fire.

2. **Strip the IRSA role's admin name.** Rename `HolySplainProdDataPipelineAdministrator` to `HolySplainProdDataPipeline`. Re-scan. `KUBE-CLOUD-IRSA-ADMIN-ROLE-001` stops firing because the name-substring heuristic does not match. The chain still works at exploit-time; the lesson is that name-based heuristics catch the obvious cases, not the subtle ones, and kubesplaining will move from "high confidence flag" to "no flag at all" with one rename.

3. **Drop the aws-auth mapping.** Run `eksctl delete iamidentitymapping --cluster holy-splain --region us-east-1 --arn arn:aws:iam::<account>:role/HolySplainProdDataPipelineAdministrator`. Re-run the PoC. Step 7 still works (AWS credentials are still issued). Step 8 still works (S3 read still succeeds). Step 9 *fails*: `kubectl auth can-i` returns `no` because the API server cannot resolve the assumed role to any Kubernetes identity. The K8s-side of the loop is broken.

4. **Add a NetworkPolicy isolating the production pods.** `prod-data` does not even need ingress from `dev-team`. A `default deny` NetworkPolicy on `prod-data` does not defend against this specific attack (the attacker goes through the node, not the network), but it is a useful exercise in observing what kubesplaining flags before and after.

5. **Use Pod Identity instead of IRSA.** AWS now offers EKS Pod Identity, a successor to IRSA that does not require an OIDC trust policy. Replace the IRSA annotation with a Pod Identity association. The attack changes shape (the trust path is different) but the principle is identical. This is an exercise in seeing that the *category* of attack survives a major piece of AWS modernization, even though the specific mechanism changes.

Have fun. When you are done, `make eks-demo-down` returns the account to zero residual state.

## Recap, in one paragraph

A developer's namespaced ServiceAccount, with only `pods/create` and `pods/exec` in its own namespace and no cross-namespace RBAC at all, became `system:masters` over the cluster by exploiting four operationally common decisions, none of them individually a vulnerability: a namespace without restricted Pod Security Admission, an IRSA-bound ServiceAccount on a DaemonSet that placed pods on every node, an IAM role with a name signaling broad permissions, and an aws-auth ConfigMap that mapped that role to cluster-admin. The attack used the projected SA token on the node host as the bridge between Kubernetes RBAC and AWS IAM. Kubesplaining surfaced both halves of the chain in the same report; bridging them was the work of a person reading carefully. The defense was never going to be "find the chain in a graph and stop it." The defense is to remove any one of the four operational decisions, and the chain disappears.
