# STEPS

## Prerequisites (do these first)

| What | Value |
|---|---|
| Machine | your EC2 instance: Ubuntu 24.04 (22.04 works), **t3.small**, **10 GB** disk, amd64 or arm64 |
| AWS account | one you may deploy into. Use a **test or sandbox account first** |
| Deployer permissions | AdministratorAccess (or: Lambda, IAM roles, DynamoDB, SNS, EventBridge, CloudWatch, CloudTrail, S3 full access) |
| Credentials | an IAM role on the instance, **or** `aws configure` (access key) |
| Region | default `eu-west-1`. Change with `REGION=...` on every command |
| Tokens / GitHub | none needed |
| Cost | cents per month: Lambda, DynamoDB on-demand, SNS, one CloudTrail trail (first copy of management events is free) |

## 1. Install tools (once)

```bash
git clone <your-private-repo-url> security-auto-remediation && cd security-auto-remediation
scripts/setup.sh          # python3, AWS CLI v2, OpenTofu 1.8.5, venv with pytest/moto
```

## 2. Check locally (no AWS needed)

```bash
scripts/verify.sh         # 95 tests against simulated AWS + terraform fmt
```

## 3. Deploy in DRY RUN (changes nothing)

```bash
NOTIFY_EMAIL=you@example.com scripts/deploy.sh     # confirm the SNS email you receive
export SECREM_URL=$(cd terraform && tofu output -raw approval_url) AWS_REGION=eu-west-1
.venv/bin/python scripts/secrem rules
.venv/bin/python scripts/secrem scan
.venv/bin/python scripts/secrem findings           # DRY_RUN = "would fix"; PENDING_APPROVAL; REPORTED
```

## 4. Prove it on real AWS (creates 3 insecure test resources, then deletes them)

```bash
.venv/bin/python scripts/verify_aws.py             # dry run: expects "reports, changes nothing"
DRY_RUN=false scripts/deploy.sh                    # switch to enforce
.venv/bin/python scripts/verify_aws.py             # enforce: expects fixes within minutes, no scan
```

## 5. Use it

```bash
.venv/bin/python scripts/secrem findings --state PENDING_APPROVAL
.venv/bin/python scripts/secrem approve 'rds-publicly-accessible#eu-west-1:mydb'
.venv/bin/python scripts/secrem reject  'iam-stale-access-key#bob/AKIA...' --reason "CI still uses it"
.venv/bin/python scripts/secrem rollback 's3-public-access-block#my-bucket'
```

## 6. Remove

```bash
scripts/destroy.sh        # fixes stay in place; destroy does not undo them
```

## If something fails

- `AccessDenied` calling the URL: your identity must match `approver_arns` for changes; any signed AWS identity may read. Newer AWS accounts also need `lambda:InvokeFunctionUrl` **and** `lambda:InvokeFunction` on your identity.
- No real-time fixes but scans work: check `enable_trail=true` and the `secrem-*-changes` EventBridge rules; look at `/aws/lambda/secrem-remediator` logs.
- Nothing is fixed: you are still in dry run. `DRY_RUN=false scripts/deploy.sh`.
