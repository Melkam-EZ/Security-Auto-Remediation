import os
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

os.environ.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="eu-west-1")
for k in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
    os.environ.pop(k, None)

from secrem import rules  # noqa: E402
from secrem.context import Context  # noqa: E402
from secrem.engine import Engine  # noqa: E402
from secrem.notify import Metrics  # noqa: E402
from secrem.policy import Policy  # noqa: E402
from secrem.store import FindingStore  # noqa: E402

REGION = "eu-west-1"
T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


class Outbox:
    """Stands in for SNS so tests can read what a human would have been told."""
    def __init__(self):
        self.sent = []

    def send(self, subject, message):
        self.sent.append((subject, message))
        return True


class Silent(Metrics):
    def __init__(self):
        self.seen = []

    def emit(self, name, value=1, **dims):
        self.seen.append((name, dims))


def base_policy(**over):
    data = {"regions": [REGION], "approvers": ["arn:aws:iam::123456789012:role/approver*"],
            "rules": {"s3-public-access-block": {"mode": "auto"}, "s3-ssl-only": {"mode": "approve"},
                      "ec2-sg-open-ingress": {"mode": "auto"}, "ec2-imdsv2": {"mode": "auto"},
                      "ebs-unencrypted": {"mode": "report"},
                      "iam-stale-access-key": {"mode": "approve", "params": {"max_age_days": 90}},
                      "iam-user-no-mfa": {"mode": "report"}, "rds-publicly-accessible": {"mode": "approve"}}}
    data.update(over)
    return data


def make_table():
    ddb = boto3.resource("dynamodb", region_name=REGION)
    return ddb.create_table(
        TableName="findings", BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"},
                              {"AttributeName": "state", "AttributeType": "S"},
                              {"AttributeName": "updated_epoch", "AttributeType": "N"}],
        GlobalSecondaryIndexes=[{"IndexName": "by_state", "Projection": {"ProjectionType": "ALL"},
                                 "KeySchema": [{"AttributeName": "state", "KeyType": "HASH"},
                                               {"AttributeName": "updated_epoch", "KeyType": "RANGE"}]}])


class World:
    """Everything a test needs: a fake AWS account, an engine, and handles to inspect both."""
    def __init__(self, policy=None, dry_run=False, only=None):
        self.clock, self.out, self.metrics = Clock(), Outbox(), Silent()
        self.table = make_table()
        self.s3 = boto3.client("s3", region_name=REGION)
        self.ec2 = boto3.client("ec2", region_name=REGION)
        self.iam = boto3.client("iam", region_name=REGION)
        self.rds = boto3.client("rds", region_name=REGION)
        self.build(policy or base_policy(), dry_run, only)

    def build(self, policy_data, dry_run=False, only=None):
        if only:
            policy_data = dict(policy_data, rules={k: v for k, v in policy_data["rules"].items() if k in only})
        self.policy = Policy(policy_data, rules.CATALOG, self.clock())
        self.ctx = Context([REGION], clock=self.clock)
        self.store = FindingStore(self.table)
        self.engine = Engine(self.ctx, self.policy, rules.build(self.policy), self.store, self.out, self.metrics,
                             dry_run=dry_run, remediator_arn="arn:aws:iam::123456789012:role/secrem-remediator")

    def fresh_engine(self, **kw):
        """A new Lambda invocation: same account and table, empty per-run counters."""
        self.build({**self.policy.data}, kw.get("dry_run", self.engine.dry_run))
        return self.engine

    def finding(self, fid):
        return self.store.get(fid)

    def states(self):
        return {f["finding_id"]: f["state"] for f in self.store.all()}


@pytest.fixture
def world():
    with mock_aws():
        yield World()


@pytest.fixture
def make_world():
    with mock_aws():
        yield World
