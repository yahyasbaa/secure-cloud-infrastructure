# Cost

Approximate on-demand prices for `us-east-1`. Verify current prices with the
AWS Pricing Calculator before deploying. The stack is built to stay small,
but a secure three-tier design can't be entirely free: interface endpoints,
WAF and KMS have no free tier.

| Component | Default config | Approx. USD / month | Free Tier |
| --- | --- | --- | --- |
| Interface VPC endpoints | 7 endpoints × 1 AZ | ~51 | no |
| Application Load Balancer | 1 ALB, light traffic | ~17–20 | 750 h/month for eligible accounts (first 12 months) |
| RDS PostgreSQL | db.t4g.micro, 20 GiB gp3, single-AZ, 7-day backups | ~14 | 750 h + 20 GiB for eligible accounts |
| EC2 | 1 × t3.micro + 20 GiB gp3, detailed monitoring | ~10 | 750 h + 30 GiB for eligible accounts |
| AWS WAF | 1 web ACL + 5 rules | ~10 (+ $0.60 per million requests) | no |
| CloudWatch | 24 alarms (2 anomaly-detection), logs ingestion/storage | ~3–5 | 10 alarms, 5 GB logs |
| KMS | 2 CMKs (+1 for state) | ~3 | 20k requests free |
| Secrets Manager | 2 secrets | ~0.80 | 30-day trial |
| CloudTrail, S3, SNS, ECR | management events (first trail), small volumes | < 2 | mostly free |
| GuardDuty | disabled by default | 0 (30-day trial when enabled) | trial |
| **Total** | | **≈ $105–115 / month** (≈ $0.15 / hour) | ≈ $70–80 with Free Tier |

## Keeping it cheap

* A test deployment that runs for one hour and is destroyed costs well under
  1 USD. Use `make destroy ENV=dev CONFIRM=dev` when you're done.
* `interface_endpoint_az_count = 1` (default) halves endpoint cost. Raise it
  to the AZ count for production resilience.
* `enable_waf = false` saves ~$10 but removes an important control. Not
  recommended for anything internet-facing.
* NAT gateways (~$33/month plus data) are deliberately absent. They would
  also open an egress path.
* Set an AWS Budget alert on the account before deploying.
