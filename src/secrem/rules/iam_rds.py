"""IAM: stale access keys, users without MFA.  RDS: publicly accessible databases."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ..context import regional
from ..model import ResourceGone, Violation
from .base import Rule


def _code(exc):
    return exc.response.get("Error", {}).get("Code", "")


class StaleAccessKey(Rule):
    id = "iam-stale-access-key"
    title = "IAM access key is active but unused for too long"
    severity = "MEDIUM"
    event_source = ""
    events = ()
    default_params = {"max_age_days": 90}

    def list_resources(self, ctx):
        iam, out = ctx.client("iam"), []
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
                    out.append(f"{user['UserName']}/{key['AccessKeyId']}")
        return out

    def check(self, ctx, resource_id):
        user, _, key_id = resource_id.partition("/")
        iam = ctx.client("iam")
        try:
            keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                raise ResourceGone(resource_id)
            raise
        key = next((k for k in keys if k["AccessKeyId"] == key_id), None)
        if key is None:
            raise ResourceGone(resource_id)
        if key["Status"] != "Active":
            return None
        last = iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {}).get("LastUsedDate")
        reference = last or key["CreateDate"]
        idle_days = (ctx.now() - reference).days
        if idle_days <= self.params["max_age_days"]:
            return None
        what = "last used" if last else "created and never used"
        return Violation(f"active key {what} {idle_days} days ago (limit {self.params['max_age_days']})",
                         {"user": user, "key_id": key_id, "idle_days": idle_days})

    def plan(self, violation):
        return "set the key to Inactive (not deleted: it can be re-activated with a rollback). Anything still using it will fail"

    def remediate(self, ctx, resource_id, violation):
        ev = violation.evidence
        ctx.client("iam").update_access_key(UserName=ev["user"], AccessKeyId=ev["key_id"], Status="Inactive")
        return {"user": ev["user"], "key_id": ev["key_id"]}

    def rollback(self, ctx, resource_id, pre_state):
        ctx.client("iam").update_access_key(UserName=pre_state["user"], AccessKeyId=pre_state["key_id"], Status="Active")


class UserWithoutMfa(Rule):
    """Detection only: enrolling an MFA device is something only the person can do."""
    id = "iam-user-no-mfa"
    title = "IAM user can sign in to the console without MFA"
    severity = "HIGH"
    can_remediate = False

    def list_resources(self, ctx):
        out = []
        for page in ctx.client("iam").get_paginator("list_users").paginate():
            out += [u["UserName"] for u in page["Users"]]
        return out

    def check(self, ctx, user):
        iam = ctx.client("iam")
        try:
            iam.get_login_profile(UserName=user)               # has a console password
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":                   # no password (or no such user): not this rule's concern
                return None
            raise
        if iam.list_mfa_devices(UserName=user)["MFADevices"]:
            return None
        return Violation("console password set but no MFA device enrolled", {"user": user})


class PublicDatabase(Rule):
    id = "rds-publicly-accessible"
    title = "RDS database instance is publicly accessible"
    severity = "CRITICAL"
    event_source = "rds.amazonaws.com"
    events = ("CreateDBInstance", "ModifyDBInstance")

    def list_resources(self, ctx):
        out = []
        for region in ctx.regions:
            for page in ctx.client("rds", region).get_paginator("describe_db_instances").paginate():
                out += [f"{region}:{d['DBInstanceIdentifier']}" for d in page["DBInstances"]]
        return out

    def check(self, ctx, resource_id):
        region, name = regional(resource_id)
        try:
            dbs = ctx.client("rds", region).describe_db_instances(DBInstanceIdentifier=name)["DBInstances"]
        except ClientError as exc:
            if _code(exc) == "DBInstanceNotFound":
                raise ResourceGone(resource_id)
            raise
        if not dbs:
            raise ResourceGone(resource_id)
        if not dbs[0].get("PubliclyAccessible"):
            return None
        return Violation("database is reachable from the internet (PubliclyAccessible=true)", {"engine": dbs[0].get("Engine")})

    def plan(self, violation):
        return "set PubliclyAccessible=false immediately. Clients that connect over the public internet will lose access"

    def remediate(self, ctx, resource_id, violation):
        region, name = regional(resource_id)
        ctx.client("rds", region).modify_db_instance(DBInstanceIdentifier=name, PubliclyAccessible=False, ApplyImmediately=True)
        return {"publicly_accessible": True}

    def rollback(self, ctx, resource_id, pre_state):
        region, name = regional(resource_id)
        ctx.client("rds", region).modify_db_instance(DBInstanceIdentifier=name, PubliclyAccessible=True, ApplyImmediately=True)

    def resources_from_event(self, event):
        name = (event.get("detail", {}).get("requestParameters") or {}).get("dBInstanceIdentifier")
        return [f"{event['region']}:{name}"] if name else []
