"""EC2: world-open security groups, IMDSv2, unencrypted EBS volumes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ..context import regional
from ..model import ResourceGone, Violation
from .base import Rule

SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 1521, 6379, 27017, 9200, 11211, 2375, 5984, 9042]
WORLD_V4, WORLD_V6 = "0.0.0.0/0", "::/0"


def _code(exc):
    return exc.response.get("Error", {}).get("Code", "")


def _exposes_sensitive(perm, sensitive):
    proto = perm.get("IpProtocol")
    if proto == "-1":                       # all protocols, all ports
        return True
    if proto not in ("tcp", "udp"):         # ICMP and others are not what this rule is about
        return False
    low, high = perm.get("FromPort", 0), perm.get("ToPort", 65535)
    return any(low <= port <= high for port in sensitive)


class OpenSecurityGroup(Rule):
    id = "ec2-sg-open-ingress"
    title = "Security group allows the whole internet to reach a sensitive port"
    severity = "CRITICAL"
    event_source = "ec2.amazonaws.com"
    events = ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules")
    default_params = {"sensitive_ports": SENSITIVE_PORTS}

    def list_resources(self, ctx):
        out = []
        for region in ctx.regions:
            for page in ctx.client("ec2", region).get_paginator("describe_security_groups").paginate():
                out += [f"{region}:{g['GroupId']}" for g in page["SecurityGroups"]]
        return out

    def check(self, ctx, resource_id):
        region, sg_id = regional(resource_id)
        try:
            groups = ctx.client("ec2", region).describe_security_groups(GroupIds=[sg_id])["SecurityGroups"]
        except ClientError as exc:
            if _code(exc) in ("InvalidGroup.NotFound", "InvalidGroupId.Malformed"):
                raise ResourceGone(resource_id)
            raise
        if not groups:
            raise ResourceGone(resource_id)
        revoke, described = [], []
        for perm in groups[0].get("IpPermissions", []):
            if not _exposes_sensitive(perm, self.params["sensitive_ports"]):
                continue
            v4 = [{k: v for k, v in r.items() if k in ("CidrIp", "Description")}
                  for r in perm.get("IpRanges", []) if r.get("CidrIp") == WORLD_V4]
            v6 = [{k: v for k, v in r.items() if k in ("CidrIpv6", "Description")}
                  for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == WORLD_V6]
            if not (v4 or v6):
                continue
            spec = {"IpProtocol": perm["IpProtocol"]}
            if perm["IpProtocol"] != "-1":
                spec.update(FromPort=perm["FromPort"], ToPort=perm["ToPort"])
            if v4:
                spec["IpRanges"] = v4
            if v6:
                spec["Ipv6Ranges"] = v6
            revoke.append(spec)
            ports = "all ports" if perm["IpProtocol"] == "-1" else f"{perm['IpProtocol']}/{perm['FromPort']}-{perm['ToPort']}"
            described.append(ports)
        if not revoke:
            return None
        return Violation(f"open to the internet on {', '.join(described)}", {"revoke": revoke})

    def plan(self, violation):
        return "revoke ONLY the 0.0.0.0/0 and ::/0 ingress rules on sensitive ports (other rules stay)"

    def remediate(self, ctx, resource_id, violation):
        region, sg_id = regional(resource_id)
        revoke = violation.evidence["revoke"]
        ctx.client("ec2", region).revoke_security_group_ingress(GroupId=sg_id, IpPermissions=revoke)
        return {"revoked": revoke}

    def rollback(self, ctx, resource_id, pre_state):
        region, sg_id = regional(resource_id)
        try:
            ctx.client("ec2", region).authorize_security_group_ingress(GroupId=sg_id, IpPermissions=pre_state["revoked"])
        except ClientError as exc:
            if _code(exc) != "InvalidPermission.Duplicate":   # already restored: fine
                raise

    def resources_from_event(self, event):
        group = (event.get("detail", {}).get("requestParameters") or {}).get("groupId")
        return [f"{event['region']}:{group}"] if group else []


class Imdsv2(Rule):
    id = "ec2-imdsv2"
    title = "EC2 instance still allows IMDSv1 (credential theft via SSRF)"
    severity = "HIGH"
    event_source = "ec2.amazonaws.com"
    events = ("RunInstances", "ModifyInstanceMetadataOptions")

    def list_resources(self, ctx):
        out = []
        for region in ctx.regions:
            for page in ctx.client("ec2", region).get_paginator("describe_instances").paginate(
                    Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]):
                for res in page["Reservations"]:
                    out += [f"{region}:{i['InstanceId']}" for i in res["Instances"]]
        return out

    def check(self, ctx, resource_id):
        region, iid = regional(resource_id)
        try:
            reservations = ctx.client("ec2", region).describe_instances(InstanceIds=[iid])["Reservations"]
        except ClientError as exc:
            if _code(exc).startswith("InvalidInstanceID"):
                raise ResourceGone(resource_id)
            raise
        instances = [i for r in reservations for i in r["Instances"]]
        if not instances or instances[0]["State"]["Name"] in ("terminated", "shutting-down"):
            raise ResourceGone(resource_id)
        tokens = instances[0].get("MetadataOptions", {}).get("HttpTokens", "optional")
        if tokens == "required":
            return None
        return Violation("HttpTokens is 'optional' (IMDSv1 allowed)", {"http_tokens": tokens})

    def plan(self, violation):
        return "set HttpTokens=required (IMDSv2 only). Software that still uses IMDSv1 will stop working"

    def remediate(self, ctx, resource_id, violation):
        region, iid = regional(resource_id)
        ctx.client("ec2", region).modify_instance_metadata_options(InstanceId=iid, HttpTokens="required")
        return {"http_tokens": violation.evidence.get("http_tokens", "optional")}

    def rollback(self, ctx, resource_id, pre_state):
        region, iid = regional(resource_id)
        ctx.client("ec2", region).modify_instance_metadata_options(InstanceId=iid, HttpTokens=pre_state["http_tokens"])

    def resources_from_event(self, event):
        detail = event.get("detail", {})
        params = detail.get("requestParameters") or {}
        if "instanceId" in params:
            return [f"{event['region']}:{params['instanceId']}"]
        items = ((detail.get("responseElements") or {}).get("instancesSet") or {}).get("items", [])
        return [f"{event['region']}:{i['instanceId']}" for i in items if "instanceId" in i]


class UnencryptedVolume(Rule):
    """Detection only: an existing EBS volume cannot be encrypted in place (it needs snapshot, copy, replace)."""
    id = "ebs-unencrypted"
    title = "EBS volume is not encrypted"
    severity = "MEDIUM"
    can_remediate = False

    def list_resources(self, ctx):
        out = []
        for region in ctx.regions:
            for page in ctx.client("ec2", region).get_paginator("describe_volumes").paginate():
                out += [f"{region}:{v['VolumeId']}" for v in page["Volumes"]]
        return out

    def check(self, ctx, resource_id):
        region, vid = regional(resource_id)
        try:
            vols = ctx.client("ec2", region).describe_volumes(VolumeIds=[vid])["Volumes"]
        except ClientError as exc:
            if _code(exc).startswith("InvalidVolume"):
                raise ResourceGone(resource_id)
            raise
        if not vols:
            raise ResourceGone(resource_id)
        if vols[0].get("Encrypted"):
            return None
        return Violation("volume is not encrypted; to fix: snapshot it, copy the snapshot with encryption on, "
                         "create a volume from the copy, swap it in", {"size_gb": vols[0].get("Size")})
