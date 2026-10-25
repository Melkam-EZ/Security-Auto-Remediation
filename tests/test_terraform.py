"""Static checks on the infrastructure code. Terraform cannot run here, so these tests pin the things that
silently break a deployment: IAM missing an action the code uses, event patterns missing an event a rule needs."""
import json
import re
from pathlib import Path

import hcl2

from secrem import rules

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform"


def clean(x):
    """python-hcl2 8.x keeps the quote marks on strings and keys; strip them so tests read naturally."""
    if isinstance(x, dict):
        return {clean(k): clean(v) for k, v in x.items()}
    if isinstance(x, list):
        return [clean(i) for i in x]
    if isinstance(x, str) and len(x) >= 2 and x[0] == x[-1] == '"':
        return x[1:-1]
    return x


def parse(name):
    with open(TF / name) as f:
        return clean(hcl2.load(f))


def policy_doc():
    raw = (TF / "policies" / "remediator.json").read_text()
    for var in ("table_arn", "topic_arn", "log_group_arn"):
        raw = raw.replace("${%s}" % var, f"arn:aws:fake:::{var}")
    return json.loads(raw)


def allowed_actions():
    return {a for st in policy_doc()["Statement"] if st["Effect"] == "Allow"
            for a in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])}


def denied_actions():
    return {a for st in policy_doc()["Statement"] if st["Effect"] == "Deny"
            for a in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])}


# method name -> IAM action. Python names are snake_case versions of the API name, with a few IAM exceptions.
SPECIAL = {"get_public_access_block": "GetBucketPublicAccessBlock", "put_public_access_block": "PutBucketPublicAccessBlock",
           "delete_public_access_block": "PutBucketPublicAccessBlock",   # S3 has no separate delete permission
           "list_mfa_devices": "ListMFADevices", "list_buckets": "ListAllMyBuckets", "modify_db_instance": "ModifyDBInstance",
           "describe_db_instances": "DescribeDBInstances", "get_paginator": None}
SERVICES = {"s3", "ec2", "iam", "rds"}


def camel(name):
    return "".join(p.capitalize() for p in name.split("_"))


def used_calls():
    """Every AWS API call the rules make, found by reading the source, as service:Action."""
    found = set()
    for path in (ROOT / "src" / "secrem" / "rules").glob("*.py"):
        src = path.read_text()
        for m in re.finditer(r'client\("(\w+)"[^)]*\)\.(\w+)\(', src):
            svc, meth = m.groups()
            if meth == "get_paginator":
                found.add((svc, "paginate", src[m.end():m.end() + 40]))
            else:
                found.add((svc, meth, None))
        for m in re.finditer(r'\b(iam|ec2|s3|rds)\.(\w+)\(', src):
            if m.group(2) != "get_paginator":
                found.add((m.group(1), m.group(2), None))
        for m in re.finditer(r'get_paginator\("(\w+)"\)', src):
            ctxline = src[max(0, m.start() - 120):m.start()]
            svc = re.findall(r'(?:client\("(\w+)"|\b(iam|ec2|s3|rds)\b)', ctxline)
            svc = [a or b for a, b in svc][-1]
            found.add((svc, m.group(1), None))
    actions = set()
    for svc, meth, _ in found:
        if meth == "paginate":
            continue
        action = SPECIAL.get(meth) or camel(meth)
        actions.add(f"{svc}:{action}")
    return actions


def test_every_api_call_in_the_rules_is_allowed_by_the_role():
    used = used_calls()
    assert len(used) >= 20, used                                # the scan really found the calls
    missing = sorted(a for a in used if a not in allowed_actions())
    assert not missing, f"the Lambda would get AccessDenied for: {missing}"


def test_the_role_allows_nothing_the_code_does_not_use():
    used = used_calls()
    extra = sorted(a for a in allowed_actions() if a.split(":")[0] in SERVICES and a not in used)
    assert not extra, f"least privilege: remove {extra}"


def test_destructive_actions_are_explicitly_denied_and_never_allowed():
    for must in ("s3:DeleteBucket", "ec2:TerminateInstances", "rds:DeleteDBInstance", "iam:DeleteAccessKey",
                 "iam:CreateAccessKey", "iam:PassRole", "cloudtrail:StopLogging"):
        assert must in denied_actions(), must
    assert not (allowed_actions() & denied_actions())
    assert not any("*" in a for a in allowed_actions()), "no wildcard actions"


def test_rule_events_are_all_wired_to_eventbridge():
    tf = parse("main.tf")
    watched = tf["locals"][0]["watched"]
    by_source = {v["source"]: set(v["events"]) for v in watched.values()}
    for cls in rules.ALL:
        if not cls.events:
            continue
        assert cls.event_source in by_source, f"{cls.id}: no EventBridge rule for {cls.event_source}"
        missing = set(cls.events) - by_source[cls.event_source]
        assert not missing, f"{cls.id} waits for events that never arrive: {sorted(missing)}"


def resources(kind):
    return {name: body for block in parse("main.tf").get("resource", []) for k, v in block.items() if k == kind for name, body in v.items()}


def test_dry_run_is_the_default_and_reaches_the_function():
    var = {k: v for b in parse("variables.tf")["variable"] for k, v in b.items()}
    assert var["dry_run"]["default"] is True
    env = resources("aws_lambda_function")["fn"]["environment"][0]["variables"]
    assert "var.dry_run" in str(env["DRY_RUN"])


def test_single_concurrency_runtime_and_timeout():
    fn = resources("aws_lambda_function")["fn"]
    assert fn["reserved_concurrent_executions"] == 1
    assert fn["runtime"] == "python3.12" and fn["handler"] == "secrem.handler.lambda_handler" and fn["timeout"] >= 120


def test_function_url_requires_aws_iam():
    assert resources("aws_lambda_function_url")["approvals"]["authorization_type"] == "AWS_IAM"


def test_findings_table_matches_what_the_code_expects():
    t = resources("aws_dynamodb_table")["findings"]
    assert t["hash_key"] == "finding_id"
    gsi = t["global_secondary_index"][0]
    assert gsi["name"] == "by_state" and gsi["hash_key"] == "state" and gsi["range_key"] == "updated_epoch"
    assert t["ttl"][0]["attribute_name"] == "expires_epoch" and t["ttl"][0]["enabled"] is True
    assert t["point_in_time_recovery"][0]["enabled"] is True


def test_alarms_cover_crashes_guard_and_failed_fixes():
    alarms = resources("aws_cloudwatch_metric_alarm")
    assert {a["metric_name"] for a in alarms.values()} == {"Errors", "GuardTripped", "RemediationFailed"}
    emitted = (ROOT / "src" / "secrem" / "engine.py").read_text()
    for name in ("GuardTripped", "RemediationFailed"):
        assert f'emit("{name}"' in emitted


def test_every_trigger_may_invoke_the_function():
    perms = resources("aws_lambda_permission")
    assert set(perms) == {"changes", "scan"}
    assert all(p["principal"] == "events.amazonaws.com" for p in perms.values())


def test_log_group_exists_before_function_and_has_retention():
    assert resources("aws_cloudwatch_log_group")["fn"]["retention_in_days"]


def test_outputs_include_the_approval_url():
    assert "approval_url" in {k for b in parse("outputs.tf")["output"] for k in b}
