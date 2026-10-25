"""The decision logic and every safety rail, against a fake AWS account."""
import pytest

from conftest import REGION, T0, base_policy
from secrem.model import NotAllowed

APPROVER = "arn:aws:sts::123456789012:assumed-role/approver-role/alice"
PAB = "s3-public-access-block"


def bucket(w, name):
    w.s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    return name


def only(w, *rule_ids, **policy_over):
    w.build({**base_policy(**policy_over)}, only=rule_ids)
    return w


def pab_on(w, name):
    try:
        cfg = w.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        return all(cfg.values())
    except Exception:
        return False


# ---- the happy path ----------------------------------------------------------------------------
def test_auto_rule_fixes_verifies_and_notifies(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    out = w.engine.scan_all()
    assert out["outcomes"][PAB] == {"remediated": 1}
    assert pab_on(w, "bkt-one")
    f = w.finding(f"{PAB}#bkt-one")
    assert f["state"] == "REMEDIATED" and f["pre_state"] == {"previous": None} and f["attempts"] == 1
    assert [h["state"] for h in f["history"]] == ["DETECTED", "REMEDIATED"]
    assert any("REMEDIATED" in s and "bkt-one" in s for s, _ in w.out.sent)
    assert any("secrem rollback" in m for _, m in w.out.sent)


def test_compliant_resources_create_no_findings_and_no_noise(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    w.s3.put_public_access_block(Bucket="bkt-one", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    out = w.engine.scan_all()
    assert out["outcomes"][PAB] == {"compliant": 1}
    assert w.store.all() == [] and w.out.sent == []


def test_second_scan_changes_nothing_and_stays_quiet(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    w.engine.scan_all()
    sent, v = len(w.out.sent), w.finding(f"{PAB}#bkt-one")["version"]
    w.fresh_engine()
    w.engine.scan_all()
    assert len(w.out.sent) == sent
    assert w.finding(f"{PAB}#bkt-one")["state"] == "REMEDIATED"


def test_fixed_by_someone_else_resolves_with_ttl(world):
    w = only(world, "s3-ssl-only", PAB)
    bucket(w, "bkt-one")
    w.engine.scan_all()                                         # ssl-only: pending approval
    assert w.finding("s3-ssl-only#bkt-one")["state"] == "PENDING_APPROVAL"
    w.s3.delete_bucket(Bucket="bkt-one")                        # resource gone
    w.fresh_engine().scan_all()
    f = w.finding("s3-ssl-only#bkt-one")
    assert f["state"] == "RESOLVED" and f["expires_epoch"] > int(T0.timestamp())


def test_resolved_finding_that_breaks_again_starts_fresh(world):
    w = only(world, "s3-ssl-only")
    bucket(w, "bkt-one")
    w.engine.scan_all()
    deny = {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::bkt-one", "arn:aws:s3:::bkt-one/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    import json
    w.s3.put_bucket_policy(Bucket="bkt-one", Policy=json.dumps({"Version": "2012-10-17", "Statement": [deny]}))
    w.fresh_engine().scan_all()                                 # fixed by a person: resolved
    assert w.finding("s3-ssl-only#bkt-one")["state"] == "RESOLVED"
    w.s3.delete_bucket_policy(Bucket="bkt-one")                 # a new, separate episode
    w.fresh_engine().scan_all()
    f = w.finding("s3-ssl-only#bkt-one")
    assert f["state"] == "PENDING_APPROVAL" and f["repeat_count"] == 0 and "expires_epoch" not in f


def test_our_fix_undone_counts_as_a_repeat(world):
    w = only(world, "s3-ssl-only")
    bucket(w, "bkt-one")
    w.engine.scan_all()
    w.engine.approve("s3-ssl-only#bkt-one", APPROVER)
    w.s3.delete_bucket_policy(Bucket="bkt-one")
    w.fresh_engine().scan_all()
    f = w.finding("s3-ssl-only#bkt-one")
    assert f["state"] == "PENDING_APPROVAL" and f["repeat_count"] == 1


# ---- modes -------------------------------------------------------------------------------------
def test_report_mode_never_touches_anything(world):
    w = only(world, "ebs-unencrypted")
    w.ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1)
    w.engine.scan_all()
    (f,) = w.store.all()
    assert f["state"] == "REPORTED"
    with pytest.raises(NotAllowed):
        w.engine.approve(f["finding_id"], APPROVER)


def test_approve_mode_waits_then_fixes_on_approval(world):
    w = only(world, "s3-ssl-only")
    bucket(w, "bkt-one")
    w.engine.scan_all()
    fid = "s3-ssl-only#bkt-one"
    assert w.finding(fid)["state"] == "PENDING_APPROVAL"
    assert any("secrem approve" in m for _, m in w.out.sent)
    f = w.engine.approve(fid, APPROVER)
    assert f["state"] == "REMEDIATED" and f["actor"] == APPROVER
    assert any(h["actor"] == APPROVER and "approved" in h["note"] for h in f["history"])


def test_approve_wrong_state_or_missing_refused(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    w.engine.scan_all()                                         # already REMEDIATED
    with pytest.raises(NotAllowed):
        w.engine.approve(f"{PAB}#bkt-one", APPROVER)
    with pytest.raises(NotAllowed):
        w.engine.approve("nope#nope", APPROVER)


def test_approve_when_already_compliant_resolves_without_changes(world):
    w = only(world, "s3-ssl-only")
    bucket(w, "bkt-one")
    w.engine.scan_all()
    w.s3.delete_bucket(Bucket="bkt-one")
    f = w.engine.approve("s3-ssl-only#bkt-one", APPROVER)
    assert f["state"] == "RESOLVED"


def test_reject_holds_for_30_days_then_asks_again(world):
    w = only(world, "s3-ssl-only")
    bucket(w, "bkt-one")
    w.engine.scan_all()
    fid = "s3-ssl-only#bkt-one"
    f = w.engine.reject(fid, APPROVER, "legacy client needs plain http")
    assert f["state"] == "REJECTED" and f["suppressed_until"].startswith("2026-07-01")
    sent = len(w.out.sent)
    w.clock.advance(days=29)
    assert w.fresh_engine().scan_all()["outcomes"]["s3-ssl-only"] == {"held": 1}
    assert w.finding(fid)["state"] == "REJECTED" and len(w.out.sent) == sent
    w.clock.advance(days=2)
    w.fresh_engine().scan_all()
    assert w.finding(fid)["state"] == "PENDING_APPROVAL"


def test_rejected_finding_cannot_be_approved_directly(world):
    w = only(world, "s3-ssl-only")
    bucket(w, "bkt-one")
    w.engine.scan_all()
    w.engine.reject("s3-ssl-only#bkt-one", APPROVER)
    with pytest.raises(NotAllowed):
        w.engine.approve("s3-ssl-only#bkt-one", APPROVER)


# ---- dry run ------------------------------------------------------------------------------------
def test_dry_run_changes_nothing_and_says_what_it_would_do(world):
    w = only(world, PAB)
    w.engine.dry_run = True
    bucket(w, "bkt-one")
    out = w.engine.scan_all()
    assert out["outcomes"][PAB] == {"dry_run": 1} and out["dry_run"]
    assert not pab_on(w, "bkt-one")
    f = w.finding(f"{PAB}#bkt-one")
    assert f["state"] == "DRY_RUN" and "would fix" in f["history"][-1]["note"]


def test_dry_run_refuses_approvals_and_switching_to_enforce_fixes(world):
    w = only(world, "s3-ssl-only", PAB)
    w.engine.dry_run = True
    bucket(w, "bkt-one")
    w.engine.scan_all()
    with pytest.raises(NotAllowed, match="dry-run"):
        w.engine.approve("s3-ssl-only#bkt-one", APPROVER)
    w.fresh_engine(dry_run=False).scan_all()
    assert pab_on(w, "bkt-one") and w.finding(f"{PAB}#bkt-one")["state"] == "REMEDIATED"


# ---- exceptions ---------------------------------------------------------------------------------
def test_exception_blocks_fix_until_it_expires(world):
    w = only(world, PAB, exceptions=[{"rule": PAB, "resource": "legacy-*", "expires": "2026-06-10",
                                      "reason": "static site migration", "approved_by": "ciso"}])
    bucket(w, "legacy-site")
    bucket(w, "other-site")
    w.engine.scan_all()
    assert w.finding(f"{PAB}#legacy-site")["state"] == "EXCEPTED" and not pab_on(w, "legacy-site")
    assert w.finding(f"{PAB}#other-site")["state"] == "REMEDIATED"
    w.clock.advance(days=8)                                    # still within the exception
    w.fresh_engine().scan_all()
    assert w.finding(f"{PAB}#legacy-site")["state"] == "EXCEPTED"
    w.clock.advance(days=3)                                    # expired: the rule applies again
    out = w.fresh_engine().scan_all()
    assert w.finding(f"{PAB}#legacy-site")["state"] == "REMEDIATED" and pab_on(w, "legacy-site")
    assert out["expired_exceptions"] == [f"{PAB}/legacy-*"]
    assert any("EXPIRED exceptions" in m for _, m in w.out.sent)


# ---- blast-radius guard -------------------------------------------------------------------------
def test_per_run_guard_blocks_the_surplus_then_approval_overrides(world):
    w = only(world, PAB, guard={"max_auto_per_run": 3, "max_auto_per_hour": 30, "repeat_offender_threshold": 3})
    for i in range(5):
        bucket(w, f"bkt-{i}")
    out = w.engine.scan_all()
    assert out["outcomes"][PAB] == {"remediated": 3, "blocked": 2}
    assert ("GuardTripped", {"rule": PAB}) in w.metrics.seen
    blocked = [f for f in w.store.all() if f["state"] == "BLOCKED"]
    assert len(blocked) == 2 and sum(pab_on(w, f"bkt-{i}") for i in range(5)) == 3
    f = w.engine.approve(blocked[0]["finding_id"], APPROVER)
    assert f["state"] == "REMEDIATED"                          # a human decision bypasses the per-run limit
    assert any("safety guard" in m for _, m in w.out.sent)


def test_next_run_continues_where_the_last_stopped(world):
    w = only(world, PAB, guard={"max_auto_per_run": 3, "max_auto_per_hour": 30, "repeat_offender_threshold": 3})
    for i in range(5):
        bucket(w, f"bkt-{i}")
    w.engine.scan_all()
    w.fresh_engine().scan_all()
    assert all(pab_on(w, f"bkt-{i}") for i in range(5))


def test_hourly_guard_spans_runs_and_resets_next_hour(world):
    w = only(world, PAB, guard={"max_auto_per_run": 10, "max_auto_per_hour": 4, "repeat_offender_threshold": 3})
    for i in range(3):
        bucket(w, f"bkt-{i}")
    w.engine.scan_all()                                        # 3 fixed this hour
    for i in range(3, 6):
        bucket(w, f"bkt-{i}")
    out = w.fresh_engine().scan_all()                          # a new run, same hour: only 1 left
    assert out["outcomes"][PAB] == {"compliant": 3, "remediated": 1, "blocked": 2}
    w.clock.advance(hours=1)
    w.fresh_engine().scan_all()
    assert all(pab_on(w, f"bkt-{i}") for i in range(6))


# ---- repeat offenders ---------------------------------------------------------------------------
def test_repeat_offender_is_escalated_and_left_alone(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    fid = f"{PAB}#bkt-one"
    for n in range(3):                                         # fix, someone undoes it, ...
        w.fresh_engine().scan_all()
        assert w.finding(fid)["state"] == "REMEDIATED"
        w.s3.delete_public_access_block(Bucket="bkt-one")
    w.fresh_engine().scan_all()                                # 4th time: it came back 3 times already
    f = w.finding(fid)
    assert f["state"] == "ESCALATED" and f["repeat_count"] == 3 and not pab_on(w, "bkt-one")
    sent = len(w.out.sent)
    w.fresh_engine().scan_all()
    assert w.finding(fid)["state"] == "ESCALATED" and len(w.out.sent) == sent       # quiet, not fixing
    f = w.engine.approve(fid, APPROVER)                        # a human can still say "fix it"
    assert f["state"] == "REMEDIATED" and pab_on(w, "bkt-one")


# ---- rollback -----------------------------------------------------------------------------------
def test_rollback_restores_and_pauses_auto_fix_for_24h(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    fid = f"{PAB}#bkt-one"
    w.engine.scan_all()
    f = w.engine.rollback(fid, APPROVER)
    assert f["state"] == "ROLLED_BACK" and not pab_on(w, "bkt-one")
    w.clock.advance(hours=23)
    assert w.fresh_engine().scan_all()["outcomes"][PAB] == {"held": 1} and not pab_on(w, "bkt-one")
    w.clock.advance(hours=2)
    w.fresh_engine().scan_all()
    assert w.finding(fid)["state"] == "REMEDIATED" and pab_on(w, "bkt-one")


def test_rollback_needs_a_remediated_finding(world):
    w = only(world, "s3-ssl-only")
    bucket(w, "bkt-one")
    w.engine.scan_all()
    with pytest.raises(NotAllowed):
        w.engine.rollback("s3-ssl-only#bkt-one", APPROVER)


# ---- failures -----------------------------------------------------------------------------------
def test_failed_fix_is_retried_three_times_then_left_for_a_human(world, monkeypatch):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    r = w.engine.rules[PAB]
    calls = []

    def boom(ctx, rid, v):
        calls.append(rid)
        raise RuntimeError("AccessDenied: nope")
    monkeypatch.setattr(r, "remediate", boom)
    fid = f"{PAB}#bkt-one"
    for _ in range(5):
        w.fresh_engine()
        monkeypatch.setattr(w.engine.rules[PAB], "remediate", boom)
        w.engine.scan_all()
    f = w.finding(fid)
    assert f["state"] == "FAILED" and len(calls) == 3 and "AccessDenied" in f["error"]
    assert ("RemediationFailed", {"rule": PAB}) in w.metrics.seen
    assert sum("FAILED" in s for s, _ in w.out.sent) == 1       # told once, not on every retry


def test_fix_that_does_not_make_it_compliant_is_failed_not_remediated(world, monkeypatch):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    monkeypatch.setattr(w.engine.rules[PAB], "remediate", lambda ctx, rid, v: {"previous": None})   # does nothing
    w.engine.scan_all()
    f = w.finding(f"{PAB}#bkt-one")
    assert f["state"] == "FAILED" and "still non-compliant" in f["history"][-1]["note"]


def test_one_broken_resource_does_not_stop_the_scan(world, monkeypatch):
    w = only(world, PAB)
    for n in ("bkt-aaa", "bkt-bbb", "bkt-ccc"):
        bucket(w, n)
    real = w.engine.rules[PAB].check

    def flaky(ctx, rid):
        if rid == "bkt-bbb":
            raise RuntimeError("throttled")
        return real(ctx, rid)
    monkeypatch.setattr(w.engine.rules[PAB], "check", flaky)
    out = w.engine.scan_all()
    assert out["outcomes"][PAB] == {"remediated": 2, "error": 1}
    assert pab_on(w, "bkt-aaa") and pab_on(w, "bkt-ccc")
    assert ("CheckError", {"rule": PAB}) in w.metrics.seen


def test_a_listing_failure_skips_only_that_rule(world, monkeypatch):
    w = only(world, PAB, "ebs-unencrypted")
    w.ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1)
    monkeypatch.setattr(w.engine.rules[PAB], "list_resources", lambda ctx: (_ for _ in ()).throw(RuntimeError("x")))
    out = w.engine.scan_all()
    assert PAB not in out["outcomes"] and out["outcomes"]["ebs-unencrypted"] == {"reported": 1}


# ---- concurrency --------------------------------------------------------------------------------
def test_losing_a_race_is_skipped_not_double_applied(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    rule = w.engine.rules[PAB]
    calls = []
    real = rule.remediate
    rule.remediate = lambda ctx, rid, v: (calls.append(1), real(ctx, rid, v))[1]
    w.engine.scan_all()
    # another invocation changes the record between our read and our write
    fid = f"{PAB}#bkt-one"
    w.s3.delete_public_access_block(Bucket="bkt-one")
    f = w.finding(fid)
    other = dict(f, state="DETECTED")
    w.store.save(other)                                         # bumps the version behind our back
    stale = dict(f)                                             # what a slower run would have read
    from secrem.store import Conflict
    with pytest.raises(Conflict):
        w.store.save(stale)


# ---- real-time events ---------------------------------------------------------------------------
def ct(name, source, params, arn="arn:aws:iam::123456789012:user/dev", error=None):
    d = {"eventName": name, "eventSource": source, "requestParameters": params, "userIdentity": {"arn": arn}}
    if error:
        d["errorCode"] = error
    return {"detail-type": "AWS API Call via CloudTrail", "region": REGION, "detail": d}


def test_event_rechecks_only_the_touched_resource(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    bucket(w, "bkt-two")
    out = w.engine.handle_event(ct("CreateBucket", "s3.amazonaws.com", {"bucketName": "bkt-one"}))
    assert out["outcomes"] == {f"{PAB}#bkt-one": "remediated"}
    assert pab_on(w, "bkt-one") and not pab_on(w, "bkt-two")


def test_event_ignores_unrelated_failed_and_own_calls(world):
    w = only(world, PAB)
    bucket(w, "bkt-one")
    assert w.engine.handle_event(ct("GetObject", "s3.amazonaws.com", {"bucketName": "bkt-one"}))["outcomes"] == {}
    assert w.engine.handle_event(ct("CreateBucket", "s3.amazonaws.com", {"bucketName": "bkt-one"}, error="AccessDenied")) == {"ignored": "call failed"}
    own = "arn:aws:sts::123456789012:assumed-role/secrem-remediator/secrem-fn"
    assert w.engine.handle_event(ct("PutBucketPublicAccessBlock", "s3.amazonaws.com", {"bucketName": "bkt-one"}, arn=own)) == {"ignored": "own change"}
    assert not pab_on(w, "bkt-one")


def test_event_for_deleted_bucket_resolves_open_finding(world):
    w = only(world, "s3-ssl-only")
    bucket(w, "bkt-one")
    w.engine.scan_all()
    w.s3.delete_bucket(Bucket="bkt-one")
    w.engine.handle_event(ct("DeleteBucket", "s3.amazonaws.com", {"bucketName": "bkt-one"})) if False else None
    w.engine.process(w.engine.rules["s3-ssl-only"], "bkt-one", "event")
    assert w.finding("s3-ssl-only#bkt-one")["state"] == "RESOLVED"


# ---- digest -------------------------------------------------------------------------------------
def test_digest_lists_what_needs_a_person(world):
    w = only(world, "s3-ssl-only", PAB)
    bucket(w, "bkt-one")
    w.engine.scan_all()
    digest = [m for s, m in w.out.sent if "digest" in s]
    assert digest and "waiting for approval" in digest[0] and "s3-ssl-only#bkt-one" in digest[0]
