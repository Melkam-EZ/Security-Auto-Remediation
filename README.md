# Automated Security Remediation

Detects AWS security misconfigurations and fixes them automatically, with the safety rails that make that acceptable
in a real account. Serverless: one Python Lambda, EventBridge, DynamoDB, SNS. Deployed with OpenTofu/Terraform.

```
 CloudTrail ──► EventBridge ──┐   real time: the changed resource is re-checked seconds after the API call
 schedule (6h) ──────────────►├─► Lambda "remediator" ──► rules ──► AWS APIs (least-privilege role)
 you (signed HTTPS) ─────────►┘        │  decide → fix → re-check          ▲
                                       ├─► DynamoDB: every finding + full history (the audit trail)
                                       └─► SNS: email on every state CHANGE
```

## Rules

| Rule | Severity | Mode | What it does |
|---|---|---|---|
| `s3-public-access-block` | HIGH | auto | turns on all four Block Public Access settings |
| `s3-ssl-only` | MEDIUM | approve | adds a Deny for non-TLS requests (keeps your other statements) |
| `ec2-sg-open-ingress` | CRITICAL | auto | revokes 0.0.0.0/0 and ::/0 on sensitive ports (SSH, RDP, databases...) |
| `ec2-imdsv2` | MEDIUM | auto | requires IMDSv2 tokens on instances |
| `ebs-unencrypted` | MEDIUM | report | detection only (encrypting needs a copy; a person decides) |
| `iam-stale-access-key` | MEDIUM | approve | sets keys unused 90+ days to Inactive (not deleted) |
| `iam-user-no-mfa` | HIGH | report | detection only (only the person can enrol MFA) |
| `rds-publicly-accessible` | CRITICAL | approve | sets PubliclyAccessible=false |

Modes live in `policy/remediation-policy.json` (in Git: changing what may be fixed automatically is a reviewed commit).

## Safety rails (each has a test, and a mutation check that breaks it on purpose)

- **Dry run first** (the default): reports what it would fix, changes nothing, refuses approvals.
- **Re-check after every fix**: a fix that did not work is FAILED, never "remediated".
- **Undo**: every fix stores what it replaced; `secrem rollback` restores it and pauses auto-fixing that resource 24 h.
- **Blast-radius guard**: max 10 automatic fixes per run, 30 per hour; the surplus is BLOCKED and alerts a human.
- **Repeat offenders**: fixed 3 times and undone 3 times (a pipeline? a person?) → ESCALATED, auto-fix stops.
- **Expiring exceptions**: policy-file only; must name the resource, reason, approver, and expire within a year.
- **Approvals**: signed requests to a Function URL with AWS_IAM auth; identity comes from AWS, never from the request body.
- **No self-loops**: events caused by the remediator's own role are ignored.
- **Least privilege + explicit Deny** on destroying anything; a test checks every API call in the code is allowed and nothing extra is.
- **One at a time** (reserved concurrency 1) and optimistic locking on every state write.

Run it: see [STEPS.md](STEPS.md). Design details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What is and is not verified

Verified here: 95 tests (every rule, every state transition, every guard, the API, the signed CLI over real HTTP, IAM-vs-code
cross-check, Terraform structure) against simulated AWS (moto); a mutation check (22 deliberate breaks of the safety rails, all caught by the tests; `python tests/mutation_check.py`).
**Not verified here (no AWS account in this environment):** `tofu apply`, the real CloudTrail→EventBridge delivery, and the
real Function URL auth. `scripts/verify_aws.py` tests exactly those on your account.
