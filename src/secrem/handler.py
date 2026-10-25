"""Lambda entry point. One function, four kinds of trigger:

  * Function URL request   (a human approving or looking)        -> api.handle
  * EventBridge CloudTrail event (something just changed)        -> engine.handle_event   (real-time path)
  * EventBridge schedule or {"action": "scan"}                   -> engine.scan_all       (catches everything else)
"""
from __future__ import annotations

import os
from pathlib import Path

import boto3

from . import api, rules
from .context import Context
from .engine import Engine
from .notify import Metrics, Notifier
from .policy import Policy
from .store import FindingStore

def _find_policy():
    """In the repo the policy sits beside src/; in the Lambda zip it sits beside the secrem/ package."""
    if os.environ.get("POLICY_FILE"):
        return Path(os.environ["POLICY_FILE"])
    here = Path(__file__).resolve().parent
    for base in (here.parent, here.parent.parent):
        if (base / "policy" / "remediation-policy.json").exists():
            return base / "policy" / "remediation-policy.json"
    raise FileNotFoundError("policy/remediation-policy.json not found")


POLICY_PATH = _find_policy()


def build_engine(env=None, session=None, clock=None):
    env = os.environ if env is None else env
    session = session or boto3.session.Session()
    policy = Policy.load(POLICY_PATH, rules.CATALOG)
    extra = [a for a in env.get("APPROVERS", "").split(",") if a.strip()]
    policy.data["approvers"] = policy.approvers + [a.strip() for a in extra]
    regions = [r for r in env.get("REGIONS", "").split(",") if r.strip()] or policy.regions
    policy.data["regions"] = regions
    ctx = Context(regions, session, clock)
    table = session.resource("dynamodb", region_name=regions[0]).Table(env["FINDINGS_TABLE"])
    topic = env.get("TOPIC_ARN")
    notifier = Notifier(topic, session.client("sns", region_name=regions[0]) if topic else None)
    return Engine(ctx, policy, rules.build(policy), FindingStore(table), notifier, Metrics(),
                  dry_run=env.get("DRY_RUN", "true").lower() != "false", remediator_arn=env.get("REMEDIATOR_ROLE_ARN", ""))


def lambda_handler(event, context=None, engine=None):
    engine = engine or build_engine()
    if "requestContext" in event and "http" in event.get("requestContext", {}):
        return api.handle(event, engine)
    if event.get("source") == "aws.events" or event.get("detail-type") == "Scheduled Event" or event.get("action") == "scan":
        return engine.scan_all()
    if "CloudTrail" in str(event.get("detail-type", "")):
        return engine.handle_event(event)
    return {"ignored": "unrecognised event"}
