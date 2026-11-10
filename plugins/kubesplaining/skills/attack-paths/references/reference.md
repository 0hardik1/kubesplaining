# Targets and hop actions

Read this file when a target name or a hop `action` in `kubesplaining paths`
output is not clear.

## Targets

A target is a position that gives an attacker control beyond the identity they
started with. The `--to` flag accepts the name in the first column. JSON output
uses the name in the second column.

| `--to` | In JSON | What the attacker has |
| --- | --- | --- |
| `cluster-admin` | `cluster_admin_equivalent` | All permissions on all resources in the cluster. |
| `system-masters` | `system_masters` | A credential in the `system:masters` group. The API server authorizes this group before RBAC runs, so no RBAC change can take the access away. |
| `kube-system-secrets` | `kube_system_secrets` | Read access to the Secrets in `kube-system`, which hold control-plane and add-on credentials. |
| `node-escape` | `node_escape` | Root on a node. From there: the kubelet credentials and every pod on that node. |
| `namespace-admin:<namespace>` | `namespace_admin` with `target_namespace` | All permissions in one namespace, which include the token of every ServiceAccount there. |
| `token-mint` | `token_mint` | The ability to create a token for a ServiceAccount of the attacker's choice, in any namespace. |
| `aws-iam-role:<arn>` | `aws_iam_role` with `target_role` | The ability to assume an AWS IAM role, which is access outside the cluster. |
| `traffic-intercept` | `traffic_intercept` | The ability to redirect the traffic of a Service to an address the attacker chooses. The attacker sees each request, with its bearer tokens. |
| `node-identity` | `node_identity` | A kubelet client identity (`system:node:<name>`) for a node of the attacker's choice. The node authorizer then gives it the Secrets and tokens of the pods on that node. |

## Hop actions

Each hop has an `action`. The `permission` field of the hop names the exact
grant, and with `--verbose` the `gains` field says what the hop gives.

### Direct RBAC grants

| Action | Meaning |
| --- | --- |
| `wildcard_permission` | Holds all verbs on all resources in all API groups. |
| `bound_to_cluster_admin` | Is a subject of a ClusterRoleBinding to `cluster-admin`. |
| `modify_role_binding` | Can create or update bindings and holds `bind`, so it can bind itself to a stronger role. |
| `bind_or_escalate` | Can write roles and holds `escalate`, so it can add rules to a role it is bound to. |
| `read_secrets` | Can read Secrets in `kube-system` or in all namespaces. |
| `implicit_group_membership` | Is a member of a group that the API server adds to each request (`system:authenticated`, `system:serviceaccounts`, `system:serviceaccounts:<namespace>`), so it holds the grants of that group. |

### Impersonation

| Action | Meaning |
| --- | --- |
| `impersonate` | Can impersonate any group or any ServiceAccount, not only one named subject. |
| `impersonate_user` | Can act as one named user. |
| `impersonate_group` | Can act as a member of one named group. |
| `impersonate_serviceaccount` | Can act as one ServiceAccount. |
| `impersonate_system_masters` | Can act as a member of `system:masters`, which bypasses RBAC. |
| `impersonate_node` | Can act as a node identity (`system:node:<name>` in `system:nodes`). |

### Tokens

| Action | Meaning |
| --- | --- |
| `token_request` | Can create a token for one ServiceAccount (`create serviceaccounts/token`). |
| `mint_arbitrary_token` | Can create a token for each ServiceAccount in each namespace. |
| `secret_mint_token` | Can create a legacy token Secret for a ServiceAccount and read the token from it. |
| `colocated_sa_token_theft` | Is namespace-admin, so it can take the token of a ServiceAccount in that namespace. |
| `node_token_request` | As a node identity, can request a token for a ServiceAccount whose pod runs on that node. |
| `node_secret_read` | As a node identity, can read the Secrets that pods on that node reference. |
| `bootstrap_token_mint` | Can write a bootstrap token Secret in `kube-system`, which becomes a kubelet client certificate. |

### Pods and workloads

| Action | Meaning |
| --- | --- |
| `pod_exec` | Can open a shell in a pod that runs as the next ServiceAccount (`pods/exec` or `pods/attach`). |
| `pod_create_token_theft` | Can create a pod that runs as the next ServiceAccount, and read its token there. |
| `workload_create_token_theft` | The same through a workload controller (Deployment, Job, and others). |
| `workload_hijack` | Can rewrite the pod template of an existing workload (a Deployment, a DaemonSet, and others), so that its pods run the attacker's code as the next ServiceAccount. |
| `pod_image_hijack` | Can change the container image of a running pod. |
| `ephemeral_container_inject` | Can add an ephemeral container to a running pod. |
| `pod_create_privileged_escape` | Can create a privileged pod in a namespace where Pod Security Admission does not block it, and escape to the node. |
| `workload_privileged_escape` | The same through a workload controller. |
| `pod_host_escape` | Runs in a pod that is already privileged or mounts the host, so it can escape to the node. No RBAC grant is involved. |
| `namespace_psa_label_flip` | Can change the Pod Security label of a namespace to `privileged`, then run a privileged pod there. |
| `mutating_policy_inject` | Can write a MutatingAdmissionPolicy that makes a pod privileged at admission. |
| `static_pod_admission_bypass` | Can write to the static pod directory of a control-plane node. |

### Nodes and certificates

| Action | Meaning |
| --- | --- |
| `nodes_proxy` | Can reach the kubelet API through `nodes/proxy`. |
| `node_drain_migrate` | Can evict pods and change node state, so that sensitive pods move to a node the attacker controls. |
| `control_plane_pki_theft` | Has root on a control-plane node, so it can read the cluster CA key and sign a `system:masters` certificate. |
| `csr_approve` | Can create and approve a CertificateSigningRequest for a privileged identity. |
| `csr_sign` | Is an authorized signer for API server client certificates. |
| `csr_nodeclient_autoapprove` | Can submit a kubelet client CSR that the controller manager approves automatically. |

### Controllers that act for the attacker

| Action | Meaning |
| --- | --- |
| `operator_reconcile` | Can write a custom resource that a controller acts on with its own, stronger identity (a confused deputy). Examples: Flux, Argo CD, cert-manager, Kyverno. |
| `statefulset_cross_namespace_pod` | Can make `kube-controller-manager` create a pod in a namespace the attacker cannot access (CVE-2026-2270, version-gated). |
| `apiservice_takeover` | Can point an API group registration at a Service the attacker controls. |
| `control_plane_backend_hijack` | Can take over the backend of an admission webhook or an aggregated API server, which the API server calls with its own credentials. |

### Service traffic

| Action | Meaning |
| --- | --- |
| `service_backend_rewrite` | Can change the selector, ports, or type of a Service. |
| `endpointslice_write` | Can add or change the EndpointSlices of a Service. |
| `pod_status_ip_spoof` | Can change the pod IP in the status of a pod that a Service selects. |

### Cloud identity (EKS)

| Action | Meaning |
| --- | --- |
| `irsa_assume_role` | The ServiceAccount is annotated with an IAM role (IRSA), so its token can assume that role. |
| `imds_node_role_pivot` | A pod can reach the instance metadata service and use the IAM role of the node. |
| `aws_auth_admin` | An IAM principal is mapped to `system:masters` in the `aws-auth` ConfigMap. |
| `access_entry_admin` | An IAM principal holds the EKS cluster admin access policy through an access entry. |
| `access_entry_secrets_read` | An IAM principal can read Secrets in all namespaces through an EKS access policy. |
