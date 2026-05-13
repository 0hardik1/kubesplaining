# Obtaining audit logs for the Least Privilege analyzer

The `leastprivilege` module emits its strongest findings (`KUBE-RBAC-UNUSED-*`,
`KUBE-RBAC-WILDCARD-USED-PARTIAL-*`) by comparing the RBAC permissions a subject
*has* (from the snapshot) against the ones it has *actually exercised* (from the
kube-apiserver audit log). Without an audit log, the Least Privilege tab in the
HTML report falls back to static signals only (`KUBE-RBAC-STALE-*`,
`KUBE-RBAC-OVERBROAD-*`).

Audit logs are produced by `kube-apiserver` itself. Kubernetes does not expose a
"what permissions has subject X used?" API, so the audit log is the only
authoritative source. This document covers how to obtain one on the three
environments kubesplaining supports out of the box: **self-managed / kubeadm**,
**kind**, and **EKS**.

## What kubesplaining needs

Audit-policy level **`Metadata`** is sufficient. `Request` / `RequestResponse`
work too but produce 10–100× more data with no analytical benefit for this
feature - the analyzer only reads:

| Field | Why |
| --- | --- |
| `user.username` | Identifies the caller. ServiceAccounts appear as `system:serviceaccount:<ns>:<name>`. Human/group users are skipped in v1. |
| `verb` | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, `deletecollection`, `bind`, `escalate`, `impersonate`, etc. |
| `objectRef.apiGroup`, `objectRef.resource`, `objectRef.subresource` | Matched against RBAC rule resources. |
| `responseStatus.code` | Denied (`>= 400`) events are filtered out - they don't count as "used." |
| `requestReceivedTimestamp` | Drives the observation-window filter (`--audit-window-days`). |

The observation window should be **at least 30 days**, ideally 60–90 days, to
cover monthly cron jobs and rarely-exercised code paths.

## Self-managed / kubeadm

Audit logging on a kubeadm-installed control plane is two changes: an audit
policy file, and `kube-apiserver` flags pointing at it.

### 1. Create the audit policy

Write the file on each control-plane node at `/etc/kubernetes/audit-policy.yaml`:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
```

This logs one line per API request at `Metadata` level - exactly what we need.

### 2. Wire the apiserver

Edit `/etc/kubernetes/manifests/kube-apiserver.yaml` and add these flags to the
`kube-apiserver` container's command. The file is a static pod manifest;
kubelet picks up changes automatically (give it ~30s to restart the pod).

```yaml
- --audit-policy-file=/etc/kubernetes/audit-policy.yaml
- --audit-log-path=/var/log/kubernetes/audit/audit.log
- --audit-log-maxage=30
- --audit-log-maxbackup=10
- --audit-log-maxsize=200
```

Mount the policy file and the log directory into the apiserver pod by adding
these entries under `volumeMounts` and `volumes` in the same manifest:

```yaml
volumeMounts:
  - name: audit-policy
    mountPath: /etc/kubernetes/audit-policy.yaml
    readOnly: true
  - name: audit-logs
    mountPath: /var/log/kubernetes/audit
volumes:
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit-policy.yaml
      type: File
  - name: audit-logs
    hostPath:
      path: /var/log/kubernetes/audit
      type: DirectoryOrCreate
```

### 3. Pull the log

Copy the log off the control-plane node (replace `control-plane.example.com`
with your host):

```bash
scp control-plane.example.com:/var/log/kubernetes/audit/audit.log ./audit.log
```

### 4. Run kubesplaining

```bash
kubesplaining scan \
  --input-file snapshot.json \
  --audit-log ./audit.log \
  --audit-source native \
  --audit-window-days 30 \
  --least-privilege-only
```

Rotated logs (`audit.log.1`, `audit.log.2.gz`, ...) can be combined by passing a
directory:

```bash
kubesplaining scan \
  --input-file snapshot.json \
  --audit-log ./audit-logs/ \
  --audit-window-days 90 \
  --least-privilege-only
```

The loader automatically transparently decompresses `*.gz` files.

## kind

`kind`'s `kubeadm`-based control plane supports the same audit-policy mechanism
via the cluster config's `kubeadmConfigPatches` block.

### 1. Cluster config

```yaml
# kind-audit.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-policy-file: /etc/kubernetes/audit-policy.yaml
            audit-log-path: /var/log/kubernetes/audit/audit.log
          extraVolumes:
            - name: audit-policy
              hostPath: /etc/kubernetes/audit-policy.yaml
              mountPath: /etc/kubernetes/audit-policy.yaml
              readOnly: true
              pathType: File
            - name: audit-logs
              hostPath: /var/log/kubernetes/audit
              mountPath: /var/log/kubernetes/audit
              pathType: DirectoryOrCreate
    extraMounts:
      - hostPath: ./audit-policy.yaml
        containerPath: /etc/kubernetes/audit-policy.yaml
        readOnly: true
```

```yaml
# audit-policy.yaml (same directory)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
```

### 2. Create the cluster

```bash
kind create cluster --config kind-audit.yaml
```

### 3. Pull the log

```bash
docker cp kind-control-plane:/var/log/kubernetes/audit/audit.log ./audit.log
```

### 4. Run kubesplaining

```bash
kubesplaining scan \
  --input-file snapshot.json \
  --audit-log ./audit.log \
  --audit-window-days 7 \
  --least-privilege-only
```

For a short-lived kind cluster you may want `--audit-window-days 1` so the
analyzer doesn't dilute the signal across days where the cluster wasn't running.

## EKS

EKS's control plane is managed; audit logs are delivered to CloudWatch Logs
when the cluster has the `audit` log type enabled. Exports go through
`aws logs filter-log-events`.

### 1. Enable audit log delivery

```bash
aws eks update-cluster-config \
  --name my-cluster \
  --logging '{"clusterLogging":[{"types":["audit"],"enabled":true}]}'
```

This is a one-time change. AWS charges for log ingestion + storage; budget
~5–50¢ per million events depending on region.

### 2. Export the window you want to analyze

The Linux `date` invocation differs from BSD/macOS; both forms are shown.

```bash
# Linux
START_MS=$(($(date -u +%s -d '30 days ago') * 1000))

# macOS / BSD
START_MS=$(($(date -u -v-30d +%s) * 1000))

aws logs filter-log-events \
  --log-group-name "/aws/eks/my-cluster/cluster" \
  --log-stream-name-prefix "kube-apiserver-audit-" \
  --start-time "$START_MS" \
  --output json \
  > eks-audit.json
```

For long windows on busy clusters, paginate via `--next-token` or use
`aws logs tail` and post-process. The kubesplaining EKS parser accepts either
shape: the `{"events":[...]}` envelope from `filter-log-events`, or one
`{"message":"..."}` object per line.

### 3. Run kubesplaining

```bash
kubesplaining scan \
  --input-file snapshot.json \
  --audit-log ./eks-audit.json \
  --audit-source eks \
  --audit-window-days 30 \
  --least-privilege-only
```

A fixture export (`testdata/audit/eks/minimal-risky-eks-audit.json`) is
included in the repo and paired with `testdata/snapshots/minimal-risky.json`
for verification - running the command above against those two files should
emit a `KUBE-RBAC-UNUSED-VERB-001` finding for the `reader` ServiceAccount.

## Privacy posture

Audit `Metadata` level does **not** include request bodies. The privacy
guarantees from the README (secrets and ConfigMap values are never read) are
preserved - the audit log only carries verb/resource/timestamp/username/status
metadata.

## Troubleshooting

**No `KUBE-RBAC-UNUSED-*` findings appear.** Either (a) no audit data was
supplied, in which case the Least Privilege tab shows a help block; or (b)
every observed ServiceAccount has exercised every grant. Widen
`--audit-window-days` to verify - a 30-day window on a cluster that's only been
running for 7 days has 7 days of data, not 30.

**`usage: skip <file>: ...` warnings.** Individual files that fail to parse
(rotated mid-write, gzipped wrong, EKS export shape mismatch) produce a
warning but don't abort ingestion. Check the `collection_warnings` field in
`scan-metadata.json` for details.

**Audit log is huge.** A `Metadata`-level audit log runs ~1 KB per request.
A medium cluster (50 req/s sustained) produces ~4 GB/day. Use directory mode
to combine rotated logs without un-gzipping them manually:

```bash
kubesplaining scan --audit-log /var/log/kubernetes/audit/ ...
```
