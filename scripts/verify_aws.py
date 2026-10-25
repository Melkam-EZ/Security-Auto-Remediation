#!/usr/bin/env python3
"""End-to-end check against your REAL AWS account, after scripts/deploy.sh.

Creates three deliberately insecure resources (an S3 bucket with public access NOT blocked, a security group open to
the world on SSH, an unencrypted 1 GiB EBS volume), then watches the platform react:
  * real-time path: the fix must arrive within minutes of the change, with no scan involved
  * scan path:      a manual scan must report the unencrypted volume (report-only rule)
  * approval API:   a signed request to the Function URL must work
Then it deletes everything it created (always, even on failure). In DRY RUN deployments it checks that the platform
REPORTS but changes nothing. Cost: a few cents at most. Run from the repo root:  .venv/bin/python scripts/verify_aws.py
"""
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from secrem import cli  # noqa: E402

WAIT_SECONDS = 240


def tf_output():
    tf = "tofu" if subprocess.run(["which", "tofu"], capture_output=True).returncode == 0 else "terraform"
    out = subprocess.run([tf, "output", "-json"], cwd=ROOT / "terraform", capture_output=True, text=True, check=True).stdout
    return {k: v["value"] for k, v in json.loads(out).items()}


def wait(label, predicate, seconds=WAIT_SECONDS):
    end = time.time() + seconds
    while time.time() < end:
        if predicate():
            return True
        time.sleep(10)
    return False


def main():
    out = tf_output()
    dry_run, url, fn = out["dry_run"], out["approval_url"], out["function_name"]
    region = cli.region_of(url)
    s3, ec2, lam = (boto3.client(s, region_name=region) for s in ("s3", "ec2", "lambda"))
    session = boto3.session.Session(region_name=region)
    results, made = [], {}
    print(f"region={region} function={fn} mode={'DRY RUN' if dry_run else 'ENFORCE'}")

    def check(name, ok, hint=""):
        results.append(ok)
        print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"   <- {hint}"))

    try:
        # 1. the approval API accepts our signature
        status, rules = cli.call("GET", url, "/rules", session=session)
        check("approval API answers a signed request", status == 200 and len(rules) == 8, f"status {status}: {rules}")

        # 2. make three bad things
        bucket = f"secrem-verify-{uuid.uuid4().hex[:10]}"
        s3.create_bucket(Bucket=bucket, **({"CreateBucketConfiguration": {"LocationConstraint": region}} if region != "us-east-1" else {}))
        made["bucket"] = bucket
        vpc = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
        vpc_id = vpc[0]["VpcId"] if vpc else ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
        sg = ec2.create_security_group(GroupName=f"secrem-verify-{uuid.uuid4().hex[:8]}", Description="secrem verify", VpcId=vpc_id)["GroupId"]
        made["sg"] = sg
        vol = ec2.create_volume(AvailabilityZone=f"{region}a", Size=1, VolumeType="gp3")["VolumeId"]
        made["vol"] = vol
        t0 = time.time()
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        print(f"created bucket {bucket}, open SG {sg}, unencrypted volume {vol}; waiting up to {WAIT_SECONDS}s for the real-time path ...")

        def pab_on():
            try:
                cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                return all(cfg.values())
            except ClientError:
                return False

        def sg_open():
            perms = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"]
            return any(r["CidrIp"] == "0.0.0.0/0" for p in perms for r in p.get("IpRanges", []))

        if dry_run:
            time.sleep(60)
            f = cli.call("GET", url, f"/findings/{cli._q(f's3-public-access-block#{bucket}')}", session=session)[1]
            check("dry run: bucket finding recorded as DRY_RUN", f.get("state") == "DRY_RUN", f"state={f.get('state')}")
            check("dry run: bucket was NOT changed", not pab_on(), "the bucket was modified in dry-run mode!")
            check("dry run: security group was NOT changed", sg_open(), "the group was modified in dry-run mode!")
        else:
            check("real-time: bucket public access block fixed without a scan", wait("pab", pab_on),
                  "no fix after %ds: is there a CloudTrail trail (enable_trail=true)? check the Lambda logs" % WAIT_SECONDS)
            print(f"      fixed {int(time.time() - t0)}s after the change")
            check("real-time: open SSH rule revoked without a scan", wait("sg", lambda: not sg_open()), "see the Lambda logs")
            f = cli.call("GET", url, f"/findings/{cli._q(f's3-public-access-block#{bucket}')}", session=session)[1]
            check("finding says REMEDIATED and keeps the undo data", f.get("state") == "REMEDIATED" and f.get("pre_state") is not None, str(f.get("state")))

        # 3. the scan path: report-only rule sees the unencrypted volume
        lam.invoke(FunctionName=fn, Payload=json.dumps({"action": "scan"}).encode())
        f = cli.call("GET", url, f"/findings/{cli._q(f'ebs-unencrypted#{region}:{vol}')}", session=session)[1]
        check("scan: unencrypted volume REPORTED (never touched)", f.get("state") == "REPORTED", f"state={f.get('state')}")
    finally:
        print("cleaning up ...")
        for label, fn_ in (("bucket", lambda: s3.delete_bucket(Bucket=made["bucket"])),
                           ("security group", lambda: ec2.delete_security_group(GroupId=made["sg"])),
                           ("volume", lambda: ec2.delete_volume(VolumeId=made["vol"]))):
            key = {"bucket": "bucket", "security group": "sg", "volume": "vol"}[label]
            if key in made:
                try:
                    fn_()
                except ClientError as exc:
                    print(f"  could not delete {label} {made[key]}: {exc.response['Error']['Code']} (delete it by hand)")
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if results and all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
