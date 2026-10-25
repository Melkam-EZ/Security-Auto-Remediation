"""Each rule against a fake AWS account: it must flag the bad thing, leave good things alone, fix only what it
should, and undo the fix exactly."""
import json
from datetime import datetime, timezone

import pytest

from conftest import REGION
from secrem.model import ResourceGone


def rule(w, rid):
    return w.engine.rules[rid]


# ---- S3 ------------------------------------------------------------------------------------------
def test_pab_flags_bucket_without_block_and_fix_and_rollback(world):
    w = world
    w.s3.create_bucket(Bucket="bkt-one", CreateBucketConfiguration={"LocationConstraint": REGION})
    r = rule(w, "s3-public-access-block")
    v = r.check(w.ctx, "bkt-one")
    assert v and "not fully blocked" in v.detail
    pre = r.remediate(w.ctx, "bkt-one", v)
    assert r.check(w.ctx, "bkt-one") is None
    r.rollback(w.ctx, "bkt-one", pre)
    assert r.check(w.ctx, "bkt-one") is not None


def test_pab_partial_block_is_flagged_and_rollback_restores_partial(world):
    w = world
    w.s3.create_bucket(Bucket="bkt-one", CreateBucketConfiguration={"LocationConstraint": REGION})
    w.s3.put_public_access_block(Bucket="bkt-one", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    r = rule(w, "s3-public-access-block")
    v = r.check(w.ctx, "bkt-one")
    assert "BlockPublicPolicy" in v.detail and "BlockPublicAcls" not in v.detail
    pre = r.remediate(w.ctx, "bkt-one", v)
    r.rollback(w.ctx, "bkt-one", pre)
    cfg = w.s3.get_public_access_block(Bucket="bkt-one")["PublicAccessBlockConfiguration"]
    assert cfg["BlockPublicAcls"] and not cfg["BlockPublicPolicy"]


def test_pab_missing_bucket_is_gone(world):
    with pytest.raises(ResourceGone):
        rule(world, "s3-public-access-block").check(world.ctx, "nope-nope")


def _tls_statement(w, bucket):
    pol = json.loads(w.s3.get_bucket_policy(Bucket=bucket)["Policy"])
    return pol["Statement"]


def test_ssl_only_adds_deny_keeps_existing_statements_and_rollback_removes_only_ours(world):
    w = world
    w.s3.create_bucket(Bucket="bkt-one", CreateBucketConfiguration={"LocationConstraint": REGION})
    mine = {"Sid": "Mine", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bkt-one/*"}
    w.s3.put_bucket_policy(Bucket="bkt-one", Policy=json.dumps({"Version": "2012-10-17", "Statement": [mine]}))
    r = rule(w, "s3-ssl-only")
    v = r.check(w.ctx, "bkt-one")
    assert v
    pre = r.remediate(w.ctx, "bkt-one", v)
    sids = [s.get("Sid") for s in _tls_statement(w, "bkt-one")]
    assert sids == ["Mine", "SecRemDenyInsecureTransport"]
    assert r.check(w.ctx, "bkt-one") is None
    r.remediate(w.ctx, "bkt-one", v)  # idempotent: no duplicate statement
    assert len(_tls_statement(w, "bkt-one")) == 2
    r.rollback(w.ctx, "bkt-one", pre)
    assert [s.get("Sid") for s in _tls_statement(w, "bkt-one")] == ["Mine"]


def test_ssl_only_rollback_deletes_policy_when_nothing_else_left(world):
    w = world
    w.s3.create_bucket(Bucket="bkt-one", CreateBucketConfiguration={"LocationConstraint": REGION})
    r = rule(w, "s3-ssl-only")
    v = r.check(w.ctx, "bkt-one")
    pre = r.remediate(w.ctx, "bkt-one", v)
    r.rollback(w.ctx, "bkt-one", pre)
    with pytest.raises(Exception):
        w.s3.get_bucket_policy(Bucket="bkt-one")


def test_ssl_only_recognises_existing_equivalent_policy(world):
    w = world
    w.s3.create_bucket(Bucket="bkt-one", CreateBucketConfiguration={"LocationConstraint": REGION})
    deny = {"Sid": "Theirs", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": ["arn:aws:s3:::bkt-one", "arn:aws:s3:::bkt-one/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    w.s3.put_bucket_policy(Bucket="bkt-one", Policy=json.dumps({"Version": "2012-10-17", "Statement": [deny]}))
    assert rule(w, "s3-ssl-only").check(w.ctx, "bkt-one") is None


# ---- EC2 -----------------------------------------------------------------------------------------
def _sg(w, name="web", perms=None):
    vpc = w.ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = w.ec2.create_security_group(GroupName=name, Description="t", VpcId=vpc)["GroupId"]
    for p in perms or []:
        w.ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[p])
    return sg


def _perm(port, cidr="0.0.0.0/0", to=None):
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": to or port, "IpRanges": [{"CidrIp": cidr}]}


def _rules_of(w, sg):
    return w.ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"]


def test_sg_open_ssh_revoked_but_open_https_and_private_ssh_kept(world):
    w = world
    sg = _sg(w, perms=[_perm(22), _perm(443), _perm(22, "10.0.0.0/8")])
    r = rule(w, "ec2-sg-open-ingress")
    rid = f"{REGION}:{sg}"
    v = r.check(w.ctx, rid)
    assert v and "22" in v.detail
    pre = r.remediate(w.ctx, rid, v)
    left = {(p["FromPort"], i["CidrIp"]) for p in _rules_of(w, sg) for i in p["IpRanges"]}
    assert left == {(443, "0.0.0.0/0"), (22, "10.0.0.0/8")}
    assert r.check(w.ctx, rid) is None
    r.rollback(w.ctx, rid, pre)
    r.rollback(w.ctx, rid, pre)  # twice is fine (Duplicate is tolerated)
    left = {(p["FromPort"], i["CidrIp"]) for p in _rules_of(w, sg) for i in p["IpRanges"]}
    assert (22, "0.0.0.0/0") in left


def test_sg_port_range_covering_sensitive_port_and_all_traffic_flagged(world):
    w = world
    sg1 = _sg(w, "range", perms=[_perm(20, to=30)])
    sg2 = _sg(w, "all", perms=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    r = rule(w, "ec2-sg-open-ingress")
    assert r.check(w.ctx, f"{REGION}:{sg1}") is not None
    assert r.check(w.ctx, f"{REGION}:{sg2}") is not None


def test_sg_ipv6_open_flagged(world):
    w = world
    sg = _sg(w, perms=[{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    r = rule(w, "ec2-sg-open-ingress")
    v = r.check(w.ctx, f"{REGION}:{sg}")
    assert v
    r.remediate(w.ctx, f"{REGION}:{sg}", v)
    assert r.check(w.ctx, f"{REGION}:{sg}") is None


def test_sg_clean_and_missing(world):
    w = world
    sg = _sg(w, perms=[_perm(443)])
    r = rule(w, "ec2-sg-open-ingress")
    assert r.check(w.ctx, f"{REGION}:{sg}") is None
    with pytest.raises(ResourceGone):
        r.check(w.ctx, f"{REGION}:sg-0123456789abcdef0")


def _instance(w):
    ami = w.ec2.describe_images()["Images"][0]["ImageId"]
    return w.ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]


def test_imdsv2_enforced_and_rolled_back(world):
    w = world
    iid = _instance(w)
    r = rule(w, "ec2-imdsv2")
    rid = f"{REGION}:{iid}"
    v = r.check(w.ctx, rid)
    assert v
    pre = r.remediate(w.ctx, rid, v)
    assert r.check(w.ctx, rid) is None
    r.rollback(w.ctx, rid, pre)
    assert r.check(w.ctx, rid) is not None


def test_ebs_unencrypted_is_report_only(world):
    w = world
    vid = w.ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1)["VolumeId"]
    w.ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1, Encrypted=True)
    r = rule(w, "ebs-unencrypted")
    assert not r.can_remediate
    flagged = [x for x in r.list_resources(w.ctx) if r.check(w.ctx, x)]
    assert flagged == [f"{REGION}:{vid}"]
    with pytest.raises(NotImplementedError):
        r.remediate(w.ctx, flagged[0], None)


# ---- IAM / RDS -----------------------------------------------------------------------------------
def test_stale_key_inactive_after_limit_and_rollback(world):
    w = world
    w.clock.t = datetime.now(timezone.utc)                   # moto stamps keys with the real time
    w.iam.create_user(UserName="bob")
    key = w.iam.create_access_key(UserName="bob")["AccessKey"]["AccessKeyId"]
    r = rule(w, "iam-stale-access-key")
    rid = f"bob/{key}"
    assert r.check(w.ctx, rid) is None                       # brand new
    w.clock.advance(days=92)
    v = r.check(w.ctx, rid)
    assert v and "never used" in v.detail
    pre = r.remediate(w.ctx, rid, v)
    assert w.iam.list_access_keys(UserName="bob")["AccessKeyMetadata"][0]["Status"] == "Inactive"
    assert r.check(w.ctx, rid) is None
    r.rollback(w.ctx, rid, pre)
    assert w.iam.list_access_keys(UserName="bob")["AccessKeyMetadata"][0]["Status"] == "Active"


def test_stale_key_gone_user_and_key(world):
    w = world
    r = rule(w, "iam-stale-access-key")
    with pytest.raises(ResourceGone):
        r.check(w.ctx, "ghost/AKIAXXXXXXXXXXXXXXXX")
    w.iam.create_user(UserName="bob")
    with pytest.raises(ResourceGone):
        r.check(w.ctx, "bob/AKIAXXXXXXXXXXXXXXXX")


def test_no_mfa_only_for_console_users_without_device(world):
    w = world
    for u in ("console-nomfa", "console-mfa", "api-only"):
        w.iam.create_user(UserName=u)
    for u in ("console-nomfa", "console-mfa"):
        w.iam.create_login_profile(UserName=u, Password="Aa1!aaaaaaaaaaaa", PasswordResetRequired=False)
    dev = w.iam.create_virtual_mfa_device(VirtualMFADeviceName="d")["VirtualMFADevice"]["SerialNumber"]
    w.iam.enable_mfa_device(UserName="console-mfa", SerialNumber=dev, AuthenticationCode1="123456", AuthenticationCode2="654321")
    r = rule(w, "iam-user-no-mfa")
    flagged = [u for u in r.list_resources(w.ctx) if r.check(w.ctx, u)]
    assert flagged == ["console-nomfa"]


def test_rds_public_fixed_and_rolled_back(world):
    w = world
    w.rds.create_db_instance(DBInstanceIdentifier="db1", DBInstanceClass="db.t3.micro", Engine="postgres",
                             MasterUsername="u", MasterUserPassword="Passw0rd12345", AllocatedStorage=20, PubliclyAccessible=True)
    w.rds.create_db_instance(DBInstanceIdentifier="db2", DBInstanceClass="db.t3.micro", Engine="postgres",
                             MasterUsername="u", MasterUserPassword="Passw0rd12345", AllocatedStorage=20, PubliclyAccessible=False)
    r = rule(w, "rds-publicly-accessible")
    assert r.check(w.ctx, f"{REGION}:db2") is None
    v = r.check(w.ctx, f"{REGION}:db1")
    assert v
    pre = r.remediate(w.ctx, f"{REGION}:db1", v)
    assert r.check(w.ctx, f"{REGION}:db1") is None
    r.rollback(w.ctx, f"{REGION}:db1", pre)
    assert r.check(w.ctx, f"{REGION}:db1") is not None
    with pytest.raises(ResourceGone):
        r.check(w.ctx, f"{REGION}:nope")


# ---- events --------------------------------------------------------------------------------------
def test_events_name_the_resource(world):
    w = world
    ev = {"region": REGION, "detail": {"requestParameters": {"bucketName": "bkt-nine"}}}
    assert rule(w, "s3-public-access-block").resources_from_event(ev) == ["bkt-nine"]
    ev = {"region": REGION, "detail": {"requestParameters": {"groupId": "sg-1"}}}
    assert rule(w, "ec2-sg-open-ingress").resources_from_event(ev) == [f"{REGION}:sg-1"]
