"""Findings in DynamoDB: the audit trail and the state machine's memory.

One item per (rule, resource). Writes use optimistic locking (a version number): an EventBridge-triggered run and
a scheduled scan may look at the same resource at the same moment, and exactly one of them may win a transition.
"""
from __future__ import annotations

import json

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from .model import OPEN_STATES

JSON_FIELDS = ("evidence", "pre_state", "history")
COUNTER_PREFIX = "_counter#"
KEEP_RESOLVED_DAYS = 90
MAX_HISTORY = 30


class Conflict(Exception):
    """Someone else changed this finding first. Skip it now; the next event or scan will pick it up."""


def _encode(item):
    out = {k: v for k, v in item.items() if v is not None}
    for k in JSON_FIELDS:
        if k in out:
            out[k] = json.dumps(out[k], default=str)
    return out


def _decode(raw):
    if raw is None:
        return None
    item = dict(raw)
    for k in JSON_FIELDS:
        if k in item and isinstance(item[k], str):
            item[k] = json.loads(item[k])
    for k in ("version", "repeat_count", "attempts", "updated_epoch"):
        if k in item:
            item[k] = int(item[k])
    return item


class FindingStore:
    def __init__(self, table):
        self.table = table

    def get(self, finding_id):
        return _decode(self.table.get_item(Key={"finding_id": finding_id}, ConsistentRead=True).get("Item"))

    def create(self, item):
        item = dict(item, version=1)
        try:
            self.table.put_item(Item=_encode(item), ConditionExpression="attribute_not_exists(finding_id)")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise Conflict(item["finding_id"])
            raise
        return item

    def save(self, item):
        """Write the item if nobody changed it since we read it."""
        expected = item["version"]
        item = dict(item, version=expected + 1)
        try:
            self.table.put_item(Item=_encode(item), ConditionExpression="version = :v",
                                ExpressionAttributeValues={":v": expected})
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise Conflict(item["finding_id"])
            raise
        return item

    # ---- listing -------------------------------------------------------------------------
    def _scan(self, **kwargs):
        items, key = [], None
        while True:
            page = self.table.scan(**kwargs, **({"ExclusiveStartKey": key} if key else {}))
            items += page["Items"]
            key = page.get("LastEvaluatedKey")
            if not key:
                return [_decode(i) for i in items if not i["finding_id"].startswith(COUNTER_PREFIX)]

    def all(self):
        return self._scan()

    def by_state(self, state):
        items, key = [], None
        while True:
            page = self.table.query(IndexName="by_state", KeyConditionExpression=Key("state").eq(state),
                                    **({"ExclusiveStartKey": key} if key else {}))
            items += page["Items"]
            key = page.get("LastEvaluatedKey")
            if not key:
                return [_decode(i) for i in items]

    def open_for_rule(self, rule_id):
        return self._scan(FilterExpression=Attr("rule_id").eq(rule_id) & Attr("state").is_in(list(OPEN_STATES)))

    # ---- counters (blast-radius guard) ------------------------------------------------------
    def bump(self, key, ttl_epoch):
        resp = self.table.update_item(
            Key={"finding_id": COUNTER_PREFIX + key},
            UpdateExpression="ADD n :one SET expires_epoch = :ttl",
            ExpressionAttributeValues={":one": 1, ":ttl": ttl_epoch}, ReturnValues="UPDATED_NEW")
        return int(resp["Attributes"]["n"])

    def counter(self, key):
        item = self.table.get_item(Key={"finding_id": COUNTER_PREFIX + key}, ConsistentRead=True).get("Item")
        return int(item["n"]) if item else 0
