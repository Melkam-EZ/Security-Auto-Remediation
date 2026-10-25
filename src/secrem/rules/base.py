"""The contract every rule follows.

  list_resources  every resource this rule should look at (used by the scheduled full scan)
  check           is ONE resource compliant? returns None, or a Violation (what is wrong + the evidence)
  remediate       fix it, touching only what the violation names; returns what is needed to undo it
  rollback        undo a remediation
  resources_from_event   which resources a CloudTrail event says may have changed (real-time path)

check() must be read-only and cheap to repeat: the engine calls it before deciding, and again after a fix to
verify the fix worked. remediate() must be idempotent: running it twice must not hurt.
"""
from __future__ import annotations


class Rule:
    id = ""
    title = ""
    severity = "MEDIUM"          # LOW | MEDIUM | HIGH | CRITICAL
    event_source = ""            # CloudTrail eventSource that can change this resource, e.g. "s3.amazonaws.com"
    events = ()                  # CloudTrail eventNames that should trigger a re-check
    can_remediate = True         # False: detection only, a human must fix it
    default_params: dict = {}

    def __init__(self, params=None):
        self.params = {**self.default_params, **(params or {})}

    def list_resources(self, ctx):
        raise NotImplementedError

    def check(self, ctx, resource_id):
        raise NotImplementedError

    def remediate(self, ctx, resource_id, violation):
        raise NotImplementedError("this rule is detection-only")

    def rollback(self, ctx, resource_id, pre_state):
        raise NotImplementedError("this rule cannot be rolled back")

    def plan(self, violation) -> str:
        """One sentence: what the fix will do. Shown in dry-run, in approval requests and in the audit trail."""
        return "no automatic fix"

    def resources_from_event(self, event) -> list:
        return []
