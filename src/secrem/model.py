"""The vocabulary: finding states, what a rule reports, and the errors rules may raise."""
from __future__ import annotations

from dataclasses import dataclass, field

# A finding is one rule broken by one resource. Its state says what the platform has done about it.
DETECTED = "DETECTED"                  # seen, not yet decided (transient)
REPORTED = "REPORTED"                  # report-only rule: a human has to fix it
PENDING_APPROVAL = "PENDING_APPROVAL"  # fixable, but waits for a human to approve
DRY_RUN = "DRY_RUN"                    # would have been fixed; dry-run mode changes nothing
REMEDIATED = "REMEDIATED"              # fixed and re-checked
FAILED = "FAILED"                      # the fix errored or did not make the resource compliant
BLOCKED = "BLOCKED"                    # safety guard stopped an automatic fix (too many at once)
ESCALATED = "ESCALATED"                # keeps coming back: stop fighting, ask a human
EXCEPTED = "EXCEPTED"                  # an approved, expiring exception covers it
REJECTED = "REJECTED"                  # a human said "do not fix" (held for a while)
ROLLED_BACK = "ROLLED_BACK"            # a human undid the fix (held for a while)
RESOLVED = "RESOLVED"                  # compliant now (fixed by someone else, or the resource is gone)

# States that still need attention (they appear in the digest and are re-checked on every scan).
OPEN_STATES = (DETECTED, REPORTED, PENDING_APPROVAL, DRY_RUN, FAILED, BLOCKED, ESCALATED, EXCEPTED, REJECTED, ROLLED_BACK)
# States from which a human may approve the fix.
APPROVABLE = (PENDING_APPROVAL, ESCALATED, BLOCKED, FAILED)
MODES = ("auto", "approve", "report")


class ResourceGone(Exception):
    """The resource no longer exists (so there is nothing left to fix)."""


class NotAllowed(Exception):
    """The caller may not do this (wrong identity or wrong state)."""


@dataclass
class Violation:
    detail: str                                   # one human sentence: what is wrong
    evidence: dict = field(default_factory=dict)  # exactly what was found; also what the fix will act on
