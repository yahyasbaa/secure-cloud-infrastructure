# Network security model

## Layout (default `10.20.0.0/16`, two AZs)

| Tier | Subnets | Route table | Hosts |
| --- | --- | --- | --- |
| public | `10.20.0.0/24`, `10.20.1.0/24` | local + `0.0.0.0/0 → IGW` | ALB nodes only |
| app | `10.20.10.0/24`, `10.20.11.0/24` | local + S3 gateway endpoint (prefix list) **only** | EC2 Auto Scaling group, interface endpoints |
| db | `10.20.20.0/24`, `10.20.21.0/24` | **local only** | RDS PostgreSQL |

There is **no NAT gateway**. Application hosts reach AWS APIs through VPC
interface endpoints (SSM, SSM messages, EC2 messages, Secrets Manager,
CloudWatch Logs, ECR API, ECR DKR) and OS packages and image layers through
the S3 gateway endpoint. With no internet route at all, a compromised host
has no direct path to an attacker's server, and NAT costs are avoided too.

No subnet assigns public IPs, the launch template forces
`associate_public_ip_address = false`, and the database sets
`publicly_accessible = false`.

## Required flows (security groups)

| Flow | Rule | Enforcement |
| --- | --- | --- |
| Internet → load balancer | TCP 443 from `alb_ingress_cidrs` (default `0.0.0.0/0`) | `alb` SG ingress, public NACL |
| Load balancer → application | TCP 8443 **from the `alb` SG only** | `app` SG ingress references `alb` SG |
| Application → database | TCP 5432 **from the `app` SG only** | `db` SG ingress references `app` SG; DB NACL admits only the app subnets |
| Application → AWS APIs | TCP 443 to the `endpoints` SG and the S3 prefix list | `app` SG egress |
| Internet → database | **DENY** | No route, no public IP, SG allows only the app SG, NACL allows only app subnets |
| Internet → application directly | **DENY** | No public IP, no IGW route, SG allows only the ALB SG |
| Database → anywhere | **DENY** | `db` SG has **no egress rules**; DB NACL egress only to app subnets (return traffic) |
| Endpoints → anywhere | **DENY** | `endpoints` SG has no egress rules |
| Default security group | **DENY** all | `aws_default_security_group` with no rules |

Rules are standalone `aws_vpc_security_group_*_rule` resources (no inline
rules that could hide additions) and reference security groups rather than
CIDRs wherever possible.

## Network ACLs (stateless second layer)

| NACL | Inbound allow | Outbound allow |
| --- | --- | --- |
| public | 443 from `alb_ingress_cidrs`; 1024–65535 from app subnets (return) | 1024–65535 to `alb_ingress_cidrs` (return); 8443 to app subnets |
| app | 8443 from public subnets; 443 from app subnets (endpoints); 1024–65535 from VPC (return); 32768–65535 from 0.0.0.0/0 (S3 return traffic only; no route exists for anything else) | 443 to 0.0.0.0/0 (bounded by the route table to endpoints/S3); 5432 to db subnets; 1024–65535 to VPC (return) |
| db | 5432 from app subnets | 1024–65535 to app subnets (return) |

Everything else falls through to the immutable final `DENY` rule.

## Edge protection

* AWS WAFv2: AWS Common Rule Set, Known Bad Inputs (incl. Log4Shell), Amazon
  IP reputation, Anonymous IP list (hosting providers in count mode), per-IP
  rate limit (default 1000 requests / 5 min). Logs go to CloudWatch with the
  `Authorization` header redacted.
* ALB: `drop_invalid_header_fields`, `desync_mitigation_mode = strictest`,
  access and connection logs, deletion protection (on by default).
* AWS Shield Standard is automatic on ALBs.

## Egress control (data exfiltration)

* The S3 gateway endpoint policy allows **only `s3:GetObject`**, and only on
  the AWS-owned buckets for Amazon Linux packages, ECR layers and SSM agent
  artifacts. `PutObject` to any bucket, including an attacker's, is denied
  at the network edge.
* Interface endpoint policies (Secrets Manager, Logs, ECR) allow only
  principals from this account (`aws:PrincipalAccount`), so stolen
  credentials from another account can't be used through them.

## Visibility

VPC Flow Logs record ALL traffic (accepted and rejected) for every ENI at
1-minute aggregation into a KMS-encrypted log group. Changes to security
groups, NACLs, routes, gateways and the VPC each raise an alarm (see
[monitoring.md](monitoring.md)).

## Verification

* `terraform/tests/network.tftest.hcl`: the module's flows, offline.
* `tests/security/static/test_network.py`: static checks over all Terraform.
* `tests/security/live/test_live_posture.py`: the deployed state (moto
  locally, AWS in the cloud). This suite caught a deliberately injected
  `0.0.0.0/0 → 5432` rule during development.
