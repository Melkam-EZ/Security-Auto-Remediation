# Architecture

## The decision for one resource (`engine.process`)

```
check(resource)
 ├─ compliant ............................ finding open? → RESOLVED (kept 90 days, then DynamoDB TTL deletes it)
 └─ violation
     ├─ approved exception (unexpired) ... EXCEPTED
     ├─ rejected / rolled back recently .. held (REJECTED / ROLLED_BACK until suppressed_until)
     ├─ mode report ...................... REPORTED
     ├─ mode approve ..................... PENDING_APPROVAL  (a human runs `secrem approve`)
     └─ mode auto
         ├─ repeat_count ≥ 3 ............. ESCALATED (stop fighting whatever keeps undoing us)
         ├─ dry run ...................... DRY_RUN
         ├─ per-run / per-hour limit ..... BLOCKED
         └─ fix → re-check → compliant? .. REMEDIATED (+ pre_state for rollback)   else FAILED (3 attempts)
```

States: DETECTED, REPORTED, PENDING_APPROVAL, DRY_RUN, REMEDIATED, FAILED, BLOCKED, ESCALATED, EXCEPTED, REJECTED,
ROLLED_BACK, RESOLVED. A human may approve from PENDING_APPROVAL, ESCALATED, BLOCKED or FAILED.

## Two ways to find problems, on purpose

- **Real time**: CloudTrail records the API call, EventBridge matches it (`terraform/main.tf`, `watched`), the Lambda
  re-checks only the resources in the event. Seconds, not hours.
- **Scheduled scan** (every 6 h): lists everything. Catches resources that existed before the platform, missed or failed
  events, drift, key age (time passing is not an API call), and resources that disappeared (open findings → RESOLVED).

A test fails if a rule waits for an event that main.tf does not route.

## Data

DynamoDB `secrem-findings`, one item per `rule_id#resource_id`: state, evidence, plan, `pre_state` (what to restore),
`history` (last 30 transitions with actor and note), `version`. GSI `by_state` powers "show me everything pending".
Items named `_counter#YYYYMMDDHH` count automatic fixes per hour (atomic `ADD`) for the blast-radius guard.
`version` is an optimistic lock: when an event run and a scan reach the same resource, exactly one write wins and the
other skips (`Conflict`), then the next trigger re-evaluates.

## Why a rule engine of our own, not AWS Config

Config rules detect; remediation needs SSM documents per rule, and the guards (hourly limits, repeat offenders, holds,
verified undo) would each be another moving part. Here a rule is one small class (`check`, `remediate`, `rollback`) and
everything is testable with a fake AWS. Add a rule: write the class, add it to `rules/__init__.py` and the policy file.

## Identity and approvals

The Function URL uses `AWS_IAM`: AWS validates the SigV4 signature before the code runs and passes the caller as
`requestContext.authorizer.iam.userArn`. Reading is open to any signed identity AWS admits; approve/reject/rollback/scan
need an ARN matching `approver_arns` (wildcards allowed). The audit trail records that ARN, not a typed name.

## Known limits (be honest about them)

- Fixes that change behaviour (closing a port, making a DB private, disabling a key) can break something that depended on
  it; that is why risky rules default to `approve`, and why dry run is the default.
- Detection is only as complete as the rule list; 8 rules is a foundation, not a compliance programme.
- One region per deployment. Run the stack per region (or extend `regions`) for more.
- `iam-stale-access-key` uses "last used" data AWS updates with a delay of hours.
- Without a trail, whether management events reach EventBridge depends on account defaults; the stack creates a trail
  by default (`enable_trail`) so the real-time path does not depend on that. Run `scripts/verify_aws.py` to confirm.
