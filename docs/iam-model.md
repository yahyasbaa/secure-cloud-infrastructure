# IAM model

All permissions are customer-written inline policies built with
`aws_iam_policy_document`. **No AWS-managed policy is attached anywhere** (no
`AdministratorAccess`, `PowerUserAccess`, `*FullAccess`, not even
`AmazonSSMManagedInstanceCore`), so every granted action is visible and
reviewable in this repository. There are no IAM users and no access keys.

Enforced by `tests/security/static/test_iam_policies.py` (static) and
`tests/security/live/test_live_posture.py` (deployed):

| Rule | How it is checked |
| --- | --- |
| No `*` or `service:*` actions in any Allow statement | every statement of every identity, trust and resource policy |
| `Resource "*"` only where AWS offers no resource-level permissions | each action is looked up in the policy_sentry IAM database; a scopable action on `*` fails the build |
| No admin / full-access managed policies | attachments and `managed_policy_arns` |
| No public trust (`Principal: "*"`) | every trust policy |
| OIDC trust pinned with `StringEquals` on `aud` **and** `sub`, no wildcards | deployment role |
| Human roles require MFA | `aws:MultiFactorAuthPresent = true` + `aws:MultiFactorAuthAge < 3600` |
| Service trust has confused-deputy protection | `aws:SourceAccount` / `aws:SourceArn` |
| Every statement has an explicit Sid, Effect, Action and Resource | identity policies |
| Every Sid is documented below | this file |
| Sessions ≤ 1 hour | `max_session_duration` |

## Roles

| Role | Trusted principal | Purpose |
| --- | --- | --- |
| `<name>-app` | `ec2.amazonaws.com` (instance profile) | Runtime identity of the application hosts |
| `<name>-deployment` | GitHub OIDC, `repo:<owner>/<repo>:environment:dev` only | Ship a new image (CI/CD) |
| `<name>-monitoring` | Operators in this account, **MFA required** | Read metrics, alarms and project logs |
| `<name>-security-audit` | Operators in this account, **MFA required** | Read security configuration and the audit trail |
| `<name>-vpc-flow-logs` | `vpc-flow-logs.amazonaws.com` + SourceAccount/SourceArn | Deliver VPC flow logs |
| `<name>-cloudtrail-to-cwl` | `cloudtrail.amazonaws.com` + SourceArn (this trail) | Stream CloudTrail into CloudWatch Logs |
| `<name>-db-enhanced-monitoring` | `monitoring.rds.amazonaws.com` + SourceAccount | Publish RDS OS metrics |
| `AWSServiceRoleForAutoScaling_<name>` | AWS service-linked role | Launch instances with CMK-encrypted EBS |

Infrastructure changes (`terraform apply`) are **not** performed by any of
these roles. They are applied by an administrator using their own,
MFA-protected credentials. The CI deployment role can ship code, not change
infrastructure, so a compromised pipeline cannot open the network, read
data or escalate IAM.

## Statement-by-statement justification

### Application role (`modules/iam/app_role.tf`)

- `ReadAppSecrets`: `secretsmanager:GetSecretValue`, `DescribeSecret` on
  exactly two ARNs: the API-token secret and the RDS-managed DB secret.
  Needed to authenticate API callers and connect to PostgreSQL.
- `DecryptSecretsViaSecretsManager`: `kms:Decrypt` on the data key **only
  when the request comes through Secrets Manager** (`kms:ViaService`). The
  host can never use the key to decrypt arbitrary ciphertext directly.
- `WriteAppLogs`: create streams and put events in the app log group only.
- `ReadImageTag`: read the single SSM parameter that selects the image tag.
- `PullAppImage`: pull layers from the single application ECR repository.
- `EcrAuthToken`: `ecr:GetAuthorizationToken` on `*`. This API has no
  resource-level permissions (AWS only accepts `*`); the token alone grants
  nothing, since repository access is still limited by `PullAppImage`.
- `SsmRegisterInstance`: `ssm:UpdateInstanceInformation`, scoped to EC2
  instance ARNs in this account/region, so Session Manager can register the
  host. Session Manager replaces SSH: there are no key pairs and port 22 is
  never open.
- `SsmSessionChannels`: the `ssmmessages:*Channel` and `ec2messages:*`
  actions (listed explicitly). These APIs offer no resource-level
  permissions, so `*` is the only valid resource. They only let the agent
  open the control/data channels used by Session Manager.

### Deployment role (`modules/iam/deployment_role.tf`)

- `EcrAuthToken`: as above. No resource-level support for
  `GetAuthorizationToken`, so `*` is required.
- `PushAppImage`: upload layers, put and describe images (including scan
  findings) in the single application repository. Tags are immutable, so a
  deployed tag can never be overwritten.
- `PublishImageTag`: read/write the one SSM parameter holding the image tag.
- `RollOutInstances`: start or cancel an instance refresh on the single
  application Auto Scaling group (exact ARN).
- `ObserveRollout`: `DescribeAutoScalingGroups` and
  `DescribeInstanceRefreshes`. These Describe APIs have no resource-level
  permissions, so `*` is required; they are read-only.

### Monitoring role (`modules/iam/operator_roles.tf`)

- `ReadMetricsAndAlarms`: CloudWatch `GetMetricData`, `GetMetricStatistics`,
  `ListMetrics`, `DescribeAlarmsForMetric`, `DescribeAnomalyDetectors`.
  CloudWatch metric APIs offer no resource-level permissions, so `*` is
  required; all are read-only.
- `ReadProjectAlarms`: `DescribeAlarms` and `DescribeAlarmHistory` on the
  exact ARNs of this stack's alarms.
- `ReadProjectLogs`: read events from this stack's log groups only.

### Security-audit role (`modules/iam/operator_roles.tf`)

- `AuditAccountInventory`: list/describe calls such as
  `ec2:DescribeSecurityGroups`, `iam:GetAccountAuthorizationDetails`,
  `cloudtrail:LookupEvents` and `s3:ListAllMyBuckets`. Every action in this
  statement was checked against the IAM reference: none supports
  resource-level permissions, so `*` is the only option. All are read-only.
- `AuditProjectRoles`: inspect the stack's own roles (exact ARNs).
- `AuditProjectKeys`: describe the two KMS keys and read their policies and
  rotation status.
- `AuditProjectBuckets`: read bucket policy, public-access block,
  encryption, versioning, logging and lifecycle configuration of the log
  buckets.
- `AuditTrailStatus`: trail status and event selectors of this trail.
- `AuditTrailLogs`: read the CloudTrail log group.
- `AuditSecretMetadata`: describe the secrets and read their resource
  policies (metadata only).
- `AuditDatabase`: describe the database instance.
- `DenyDataPlaneAccess`: an explicit **Deny** on `secretsmanager:GetSecretValue`,
  `kms:Decrypt`, `s3:GetObject*`, `ssm:GetParameter*` and `rds-db:connect`. An
  auditor credential leak therefore exposes configuration, never data. This
  holds even if someone later attaches a broader policy, because an explicit
  deny always wins.

### Service roles

- `DeliverFlowLogs` (`modules/network/flow_logs.tf`): create streams and put
  events in the flow-log group only. The `log-stream:*` suffix is
  unavoidable because the service names one stream per ENI.
- `DeliverTrailEvents` (`modules/logging/cloudtrail.tf`): put events in the
  CloudTrail log group only.
- `ManageRdsOsMetricsLogGroup` / `WriteRdsOsMetrics`
  (`modules/database/main.tf`): equivalent to the AWS-managed
  `AmazonRDSEnhancedMonitoringRole`, but limited to this account and region.

## Resource policies

- **KMS key policies**: the account root receives explicit administration
  and usage action lists (no `kms:*`), which delegates authorisation to IAM.
  Service principals receive only what they need, behind encryption-context
  and source conditions (CloudWatch Logs only for this stack's log groups;
  CloudTrail only for this trail). The Auto Scaling SLR may use the data key
  only through EC2 (`kms:ViaService`).
- **Secret policy**: denies `GetSecretValue` to every principal outside the
  account and blocks public policies.
- **Bucket policies**: deny non-TLS access; allow only the specific AWS log
  delivery services; deny deletion of CloudTrail log objects.
- **VPC endpoint policies**: allow only principals of this account
  (`aws:PrincipalAccount`), and the S3 gateway endpoint allows only
  `s3:GetObject` from the specific AWS-owned buckets the hosts need. Hosts
  cannot write to any bucket, which closes the most common exfiltration
  channel.
- **SNS topic policy**: only CloudWatch and EventBridge of this account may
  publish, and only over TLS.

## Privilege-escalation review

None of the roles holds `iam:*`, `iam:PassRole`, `iam:Put*Policy`,
`iam:Attach*`, `iam:CreateAccessKey`, `sts:AssumeRole` on other roles,
`lambda:*`, `ec2:RunInstances`, `ssm:SendCommand`, `kms:CreateGrant` or
`kms:PutKeyPolicy`. The well-known escalation paths therefore don't apply to
any runtime or CI identity.
