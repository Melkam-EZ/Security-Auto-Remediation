import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from secrem import rules
from secrem.policy import Policy, PolicyError

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def pol(**over):
    data = {"rules": {"s3-public-access-block": {"mode": "auto"}, "ebs-unencrypted": {"mode": "report"}}}
    data.update(over)
    return Policy(data, rules.CATALOG, NOW)


def exc(**kw):
    return {"rule": "s3-public-access-block", "resource": "legacy-*", "expires": "2026-09-01", "reason": "r", "approved_by": "x", **kw}


def test_lambda_zip_layout_finds_its_policy():
    subprocess.run([str(ROOT / "scripts" / "build_zip.sh")], check=True, capture_output=True)
    build = ROOT / "terraform" / "build"
    code = f"import sys; sys.path.insert(0, {str(build)!r}); from secrem import handler; print(handler.POLICY_PATH)"
    out = subprocess.run([sys.executable, "-B", "-I", "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == str(ROOT / "terraform" / "build" / "policy" / "remediation-policy.json")
    assert not list((ROOT / "terraform" / "build").rglob("__pycache__"))


@pytest.mark.parametrize("bad,msg", [
    ({"rules": {"nope": {"mode": "auto"}}}, "unknown rule"),
    ({"rules": {"s3-ssl-only": {"mode": "yolo"}}}, "mode must be"),
    ({"rules": {"ebs-unencrypted": {"mode": "auto"}}}, "cannot be fixed automatically"),
    ({"rules": {}}, "rules"),
    ({"regions": []}, "regions"),
    ({"guard": {"max_auto_per_run": 0}}, "guard"),
    ({"exceptions": [exc(resource="*")]}, "every resource"),
    ({"exceptions": [exc(reason="")]}, "reason"),
    ({"exceptions": [exc(approved_by="")]}, "approved_by"),
    ({"exceptions": [exc(expires="soon")]}, "YYYY-MM-DD"),
    ({"exceptions": [exc(expires="2030-01-01")]}, "renewed, not permanent"),
    ({"exceptions": [exc(rule="s3-ssl-only")]}, "unknown rule"),
])
def test_unsafe_or_meaningless_policies_are_refused(bad, msg):
    with pytest.raises(PolicyError, match=msg):
        pol(**bad)


def test_exceptions_match_by_pattern_and_expire():
    p = pol(exceptions=[exc()])
    assert p.active_exception("s3-public-access-block", "legacy-site", NOW)
    assert not p.active_exception("s3-public-access-block", "new-site", NOW)
    assert not p.active_exception("ebs-unencrypted", "legacy-site", NOW)
    late = datetime(2026, 9, 2, tzinfo=timezone.utc)
    assert not p.active_exception("s3-public-access-block", "legacy-site", late)
    assert p.expired_exceptions(late) and not p.expired_exceptions(NOW)
    assert p.expiring_soon(14, datetime(2026, 8, 25, tzinfo=timezone.utc)) and not p.expiring_soon(14, NOW)


def test_exception_on_its_last_day_still_applies():
    assert pol(exceptions=[exc()]).active_exception("s3-public-access-block", "legacy-x", datetime(2026, 9, 1, 23, tzinfo=timezone.utc))


def test_approver_patterns():
    p = pol(approvers=["arn:aws:sts::1:assumed-role/Admin/*"])
    assert p.is_approver("arn:aws:sts::1:assumed-role/Admin/alice")
    assert not p.is_approver("arn:aws:sts::1:assumed-role/Dev/alice") and not p.is_approver("")
    assert not pol().is_approver("arn:aws:sts::1:user/x")           # empty list approves nobody


def test_shipped_policy_is_valid_and_conservative():
    p = Policy.load(ROOT / "policy" / "remediation-policy.json", rules.CATALOG)
    assert set(p.rule_ids()) == set(rules.CATALOG)
    assert p.mode("rds-publicly-accessible") == "approve" and p.mode("iam-stale-access-key") == "approve"
    assert p.mode("ebs-unencrypted") == "report" and p.mode("iam-user-no-mfa") == "report"
    assert p.data["exceptions"] == []
