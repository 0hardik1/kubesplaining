# IAM permissions for `make eks-demo-up`

The kubesplaining EKS live demo provisions a real EKS cluster, an IAM role, an S3 bucket, an OIDC provider, and the supporting CloudFormation stacks that eksctl manages. The local AWS identity you run `make eks-demo-up` from needs permission to do all of that.

**The simplest answer is `AdministratorAccess`.** If your demo account is sandboxed (a sub-account, an Org member purely for kubesplaining experiments, etc.), attach `AdministratorAccess` to your user or role, run the demo, run teardown, and move on. The least-privilege variant below exists for operators whose account policy forbids `AdministratorAccess` even temporarily.

## Least-privilege policy

Attach this as a customer-managed inline or managed policy to your IAM principal. `Resource: "*"` is acceptable for a 15-minute demo: the actions are scoped to the resources eksctl, the demo scripts, and `aws-cli` create, and the demo's teardown removes everything afterward.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EKSClusterAndAddons",
      "Effect": "Allow",
      "Action": [
        "eks:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudFormationForEksctl",
      "Effect": "Allow",
      "Action": [
        "cloudformation:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2ForVPCAndNodegroup",
      "Effect": "Allow",
      "Action": [
        "ec2:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMForRolesAndOIDC",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:UpdateRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:PassRole",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:CreateOpenIDConnectProvider",
        "iam:DeleteOpenIDConnectProvider",
        "iam:GetOpenIDConnectProvider",
        "iam:TagOpenIDConnectProvider",
        "iam:CreateInstanceProfile",
        "iam:DeleteInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile",
        "iam:GetInstanceProfile",
        "iam:CreateServiceLinkedRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3DemoBucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging",
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListBucket",
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "sts:AssumeRoleWithWebIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LogsForCluster",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:DescribeLogGroups",
        "logs:PutRetentionPolicy",
        "logs:TagLogGroup"
      ],
      "Resource": "*"
    },
    {
      "Sid": "KMSForEksDefaultKey",
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:CreateGrant"
      ],
      "Resource": "*"
    }
  ]
}
```

## What each prefix is for

- **`eks:*`** — `eksctl create cluster`, `aws eks describe-cluster`, `eks:CreateAddon`, `eks:AssociateAccessPolicy`/`eks:CreateAccessEntry` (eksctl uses these internally even when you stay on aws-auth), `eks:UpdateClusterConfig`.
- **`cloudformation:*`** — eksctl backs every artifact in CloudFormation. Cluster, nodegroup, addons, IAM service-linked roles all live in CFN stacks (`eksctl-holy-splain-cluster`, `eksctl-holy-splain-nodegroup-default`, etc.).
- **`ec2:*`** — eksctl creates a dedicated VPC by default: subnets, internet gateway, NAT gateway, security groups, route tables, EIPs. Plus the nodegroup launches EC2 instances.
- **`iam:*` subset** — Create / delete / tag IAM roles and OIDC provider, plus `PassRole` for the cluster service role and nodegroup instance role, plus instance-profile operations for the nodegroup.
- **`s3:*` subset** — Create / delete the demo bucket, set its public-access block, put / get / delete `flag.txt`.
- **`sts:*`** — `sts:GetCallerIdentity` is the pre-flight identity probe; `sts:AssumeRoleWithWebIdentity` is what the PoC's step 7 calls (you need this on the operator principal, not just the role's trust policy, when you replay the call from your laptop).
- **`logs:*` subset** — eksctl creates a CloudWatch Logs group for cluster logs even when log delivery is disabled.
- **`kms:*` subset** — Only needed if `eks:*` paths trigger envelope encryption with the EKS default KMS key. Harmless if unused.

## Sanity check before running setup

```bash
aws sts get-caller-identity
aws eks list-clusters --region <your-region>
aws s3 ls
```

If all three succeed, your local creds are good to go. If `aws sts get-caller-identity` fails, see the AWS docs on [configuring the CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html).

## What the demo does NOT need

- No `iam:CreateUser`, `iam:CreateAccessKey`, `iam:CreatePolicy` — the demo only creates roles, not users or managed policies.
- No `iam:Pass*` on existing roles — only the role kubesplaining itself creates.
- No `route53:*`, `acm:*`, `elasticloadbalancing:*` — the demo does not configure ingress, custom DNS, or load balancers.
- No `secretsmanager:*`, `kms:CreateKey`, `kms:ScheduleKeyDeletion` — the demo does not use Secrets Manager or KMS-managed keys.
- No cross-account access. The demo lives entirely inside whichever AWS account `aws sts get-caller-identity` resolves to.
