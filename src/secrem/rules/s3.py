"""S3: public access block, and TLS-only access."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..model import ResourceGone, Violation
from .base import Rule

PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
SSL_SID = "SecRemDenyInsecureTransport"


def _code(exc):
    return exc.response.get("Error", {}).get("Code", "")


def _bucket_events(event):
    name = (event.get("detail", {}).get("requestParameters") or {}).get("bucketName")
    return [name] if name else []


class PublicAccessBlock(Rule):
    id = "s3-public-access-block"
    title = "S3 bucket does not block public access"
    severity = "HIGH"
    event_source = "s3.amazonaws.com"
    events = ("CreateBucket", "PutBucketPublicAccessBlock", "DeletePublicAccessBlock")

    def list_resources(self, ctx):
        return [b["Name"] for b in ctx.client("s3").list_buckets().get("Buckets", [])]

    def _current(self, ctx, bucket):
        try:
            cfg = ctx.client("s3").get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            return {k: bool(cfg.get(k, False)) for k in PAB_KEYS}
        except ClientError as exc:
            if _code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return None
            if _code(exc) == "NoSuchBucket":
                raise ResourceGone(bucket)
            raise

    def check(self, ctx, bucket):
        current = self._current(ctx, bucket)
        if current is not None and all(current.values()):
            return None
        missing = list(PAB_KEYS) if current is None else [k for k, v in current.items() if not v]
        return Violation(f"public access is not fully blocked (off: {', '.join(missing)})", {"current": current})

    def plan(self, violation):
        return "turn on all four S3 Block Public Access settings for the bucket"

    def remediate(self, ctx, bucket, violation):
        ctx.client("s3").put_public_access_block(
            Bucket=bucket, PublicAccessBlockConfiguration={k: True for k in PAB_KEYS})
        return {"previous": violation.evidence.get("current")}

    def rollback(self, ctx, bucket, pre_state):
        previous = pre_state.get("previous")
        if previous is None:
            ctx.client("s3").delete_public_access_block(Bucket=bucket)
        else:
            ctx.client("s3").put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=previous)

    def resources_from_event(self, event):
        return _bucket_events(event)


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _denies_insecure_transport(statement, bucket):
    """True if this statement denies every request that is not over TLS, for the bucket and its objects."""
    if statement.get("Effect") != "Deny":
        return False
    principal = statement.get("Principal")
    if principal != "*" and principal != {"AWS": "*"}:
        return False
    actions = _as_list(statement.get("Action", []))
    if not any(a in ("s3:*", "*") for a in actions):
        return False
    cond = statement.get("Condition", {}).get("Bool", {})
    if str(cond.get("aws:SecureTransport", "")).lower() != "false":
        return False
    resources = set(_as_list(statement.get("Resource", [])))
    return {f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"} <= resources or "*" in resources


class SslOnly(Rule):
    id = "s3-ssl-only"
    title = "S3 bucket allows unencrypted (HTTP) requests"
    severity = "MEDIUM"
    event_source = "s3.amazonaws.com"
    events = ("CreateBucket", "PutBucketPolicy", "DeleteBucketPolicy")

    def list_resources(self, ctx):
        return [b["Name"] for b in ctx.client("s3").list_buckets().get("Buckets", [])]

    def _policy(self, ctx, bucket):
        try:
            return json.loads(ctx.client("s3").get_bucket_policy(Bucket=bucket)["Policy"])
        except ClientError as exc:
            if _code(exc) == "NoSuchBucketPolicy":
                return None
            if _code(exc) == "NoSuchBucket":
                raise ResourceGone(bucket)
            raise

    def check(self, ctx, bucket):
        policy = self._policy(ctx, bucket)
        statements = _as_list((policy or {}).get("Statement", []))
        if any(_denies_insecure_transport(s, bucket) for s in statements):
            return None
        return Violation("no bucket policy statement denies plain-HTTP requests", {"had_policy": policy is not None})

    def plan(self, violation):
        return f"add a bucket-policy statement '{SSL_SID}' that denies any request not using TLS (existing statements are kept)"

    def remediate(self, ctx, bucket, violation):
        policy = self._policy(ctx, bucket) or {"Version": "2012-10-17", "Statement": []}
        statements = [s for s in _as_list(policy.get("Statement", [])) if s.get("Sid") != SSL_SID]
        statements.append({
            "Sid": SSL_SID, "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        })
        policy["Statement"] = statements
        ctx.client("s3").put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
        return {"had_policy": violation.evidence.get("had_policy", False)}

    def rollback(self, ctx, bucket, pre_state):
        """Remove only OUR statement. Anything anyone added to the policy since is left alone."""
        policy = self._policy(ctx, bucket)
        if policy is None:
            return
        rest = [s for s in _as_list(policy.get("Statement", [])) if s.get("Sid") != SSL_SID]
        if rest:
            policy["Statement"] = rest
            ctx.client("s3").put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
        else:
            ctx.client("s3").delete_bucket_policy(Bucket=bucket)

    def resources_from_event(self, event):
        return _bucket_events(event)
