"""The engine: finds violations, decides what to do about each, and does it safely.

For every violation the decision is, in order:
  1. not broken any more            -> RESOLVED (if it was open)
  2. covered by an approved exception (with an expiry date)  -> EXCEPTED, no action
  3. a human said "leave it" / undid our fix recently        -> held, no action
  4. rule mode 'report'             -> REPORTED
  5. rule mode 'approve'            -> PENDING_APPROVAL (a human decides)
  6. rule mode 'auto'               -> safety checks, then fix, then RE-CHECK that the fix worked:
        keeps coming back?          -> ESCALATED (stop fighting whatever keeps re-breaking it)
        dry-run mode?               -> DRY_RUN (say what would be done, change nothing)
        too many fixes this hour?   -> BLOCKED (something is wrong: a person must look)
        fix errored / did not work  -> FAILED (alert)
        otherwise                   -> REMEDIATED, with what is needed to undo it
"""
from __future__ import annotations

import sys
import traceback
from datetime import timedelta

from .model import (APPROVABLE, BLOCKED, DETECTED, DRY_RUN, ESCALATED, EXCEPTED, FAILED, OPEN_STATES,
                    PENDING_APPROVAL, REJECTED, REMEDIATED, REPORTED, RESOLVED, ROLLED_BACK, NotAllowed,
                    ResourceGone)
from .store import MAX_HISTORY, KEEP_RESOLVED_DAYS, Conflict

MAX_FIX_ATTEMPTS = 3
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class Engine:
    def __init__(self, ctx, policy, rules, store, notifier, metrics, dry_run=False, remediator_arn=""):
        self.ctx, self.policy, self.rules = ctx, policy, rules
        self.store, self.notifier, self.metrics = store, notifier, metrics
        self.dry_run = dry_run
        self.remediator_arn = remediator_arn
        self.auto_this_run = 0
        self.changes = 0                  # state changes in this invocation: decides whether a digest is worth sending

    # ---- time helpers ----------------------------------------------------------------------
    def _now_iso(self):
        return self.ctx.now().isoformat(timespec="seconds")

    def _epoch(self):
        return int(self.ctx.now().timestamp())

    # ---- the decision for one resource -----------------------------------------------------
    def process(self, rule, resource_id, source="scan"):
        """Returns a short outcome word. Never raises for a problem with ONE resource."""
        try:
            return self._process(rule, resource_id, source)
        except Conflict:
            return "conflict"          # another run is handling it right now
        except Exception as exc:       # noqa: BLE001 - one bad resource must not stop the whole scan
            print(f"[error] {rule.id} {resource_id}: {type(exc).__name__}: {exc}", file=sys.stderr)
            traceback.print_exc()
            self.metrics.emit("CheckError", 1, rule=rule.id)
            return "error"

    def _fid(self, rule, resource_id):
        return f"{rule.id}#{resource_id}"

    def _process(self, rule, resource_id, source):
        fid = self._fid(rule, resource_id)
        try:
            violation = rule.check(self.ctx, resource_id)
        except ResourceGone:
            violation = None
        f = self.store.get(fid)

        if violation is None:                                   # 1. compliant
            if f and f["state"] in OPEN_STATES:
                self._transition(f, RESOLVED, "secrem", "compliant now (or the resource is gone)")
                return "resolved"
            return "compliant"

        if f is None:
            f = self._new_finding(rule, resource_id, violation)
        else:
            was_remediated = f["state"] == REMEDIATED
            f.update(last_seen=self._now_iso(), detail=violation.detail, evidence=violation.evidence,
                     plan=rule.plan(violation))
            if f["state"] in (REMEDIATED, RESOLVED):            # it came back
                if was_remediated:
                    f["repeat_count"] += 1
                f["attempts"] = 0
                self._transition(f, DETECTED, "secrem",
                                 "violation is back" + (f" (our fix was undone; repeat #{f['repeat_count']})" if was_remediated else ""))

        exception = self.policy.active_exception(rule.id, resource_id, self.ctx.now())      # 2. approved exception
        if exception:
            if f["state"] != EXCEPTED:
                self._transition(f, EXCEPTED, "policy", f"exception until {exception['expires']}: {exception['reason']} "
                                                       f"(approved by {exception['approved_by']})")
            else:
                self._touch(f)
            return "excepted"

        if f["state"] in (REJECTED, ROLLED_BACK) and f.get("suppressed_until", "") > self._now_iso():   # 3. held
            self._touch(f)
            return "held"

        mode = self.policy.mode(rule.id)
        f["mode"] = mode
        if mode == "report":                                    # 4.
            return self._settle(f, REPORTED, "detection only: a human has to fix this", "reported", notify=True)
        if mode == "approve":                                   # 5.
            return self._settle(f, PENDING_APPROVAL, f"waiting for approval. Fix: {f['plan']}", "pending", notify=True)
        return self._auto(rule, f, violation)                   # 6.

    def _new_finding(self, rule, resource_id, violation):
        now = self._now_iso()
        item = {"finding_id": self._fid(rule, resource_id), "rule_id": rule.id, "resource_id": resource_id,
                "severity": rule.severity, "title": rule.title, "detail": violation.detail, "plan": rule.plan(violation),
                "evidence": violation.evidence, "state": DETECTED, "mode": self.policy.mode(rule.id),
                "first_seen": now, "last_seen": now, "updated_at": now, "updated_epoch": self._epoch(),
                "repeat_count": 0, "attempts": 0, "history": [{"at": now, "state": DETECTED, "actor": "secrem",
                                                              "note": violation.detail}]}
        saved = self.store.create(item)
        self.metrics.emit("FindingsDetected", 1, rule=rule.id)
        return saved

    def _settle(self, f, state, note, outcome, notify):
        if f["state"] == state:
            self._touch(f)
        else:
            self._transition(f, state, "secrem", note, notify=notify)
        return outcome

    # ---- automatic fixing, with its safety checks ----------------------------------------------
    def _auto(self, rule, f, violation):
        guard = self.policy.guard
        if f["state"] == ESCALATED:                              # stays until a human decides
            self._touch(f)
            return "escalated"
        if f["repeat_count"] >= guard["repeat_offender_threshold"]:
            self._transition(f, ESCALATED, "secrem",
                             f"fixed {f['repeat_count']} times and undone every time. Something keeps re-creating it "
                             "(a pipeline? a person?). Automatic fixing stopped; fix the cause, then approve or reject",
                             notify=True)
            self.metrics.emit("Escalated", 1, rule=rule.id)
            return "escalated"
        if f["state"] == FAILED and f["attempts"] >= MAX_FIX_ATTEMPTS:
            self._touch(f)
            return "failed"
        if self.dry_run:
            return self._settle(f, DRY_RUN, f"DRY RUN: would fix. {f['plan']}", "dry_run", notify=False)
        hour_key = self.ctx.now().strftime("%Y%m%d%H")
        if self.auto_this_run >= guard["max_auto_per_run"] or self.store.counter(hour_key) >= guard["max_auto_per_hour"]:
            if f["state"] != BLOCKED:
                self.metrics.emit("GuardTripped", 1, rule=rule.id)
            return self._settle(f, BLOCKED, "safety guard: too many automatic fixes in a short time. "
                                            "Is something wrong? Check recent changes, then approve or raise the limits",
                                "blocked", notify=True)
        return self._remediate(rule, f, violation, actor="secrem")

    def _remediate(self, rule, f, violation, actor):
        rid = f["resource_id"]
        f["attempts"] = f.get("attempts", 0) + 1
        try:
            pre_state = rule.remediate(self.ctx, rid, violation)
            after = rule.check(self.ctx, rid)
        except ResourceGone:
            self._transition(f, RESOLVED, actor, "resource disappeared while fixing")
            return "resolved"
        except Exception as exc:  # noqa: BLE001
            self.metrics.emit("RemediationFailed", 1, rule=rule.id)
            self._transition(f, FAILED, actor, f"fix failed: {type(exc).__name__}: {exc}", notify=True, error=str(exc)[:500])
            return "failed"
        self.auto_this_run += 1
        hour = self.ctx.now()
        self.store.bump(hour.strftime("%Y%m%d%H"), int((hour + timedelta(hours=3)).timestamp()))
        if after is not None:                                     # we changed something, but it is still wrong
            self.metrics.emit("RemediationFailed", 1, rule=rule.id)
            self._transition(f, FAILED, actor, f"fix applied but the resource is still non-compliant: {after.detail}",
                             notify=True, pre_state=pre_state, error=after.detail[:500])
            return "failed"
        self.metrics.emit("Remediated", 1, rule=rule.id)
        self._transition(f, REMEDIATED, actor, f"fixed: {rule.plan(violation)}", notify=True, pre_state=pre_state,
                         error="", suppressed_until="")
        return "remediated"

    # ---- human actions (approve / reject / rollback) -----------------------------------------------
    def _load(self, finding_id):
        f = self.store.get(finding_id)
        if f is None:
            raise NotAllowed(f"no such finding: {finding_id}")
        if f["rule_id"] not in self.rules:
            raise NotAllowed(f"rule {f['rule_id']} is not enabled")
        return f, self.rules[f["rule_id"]]

    def approve(self, finding_id, actor):
        f, rule = self._load(finding_id)
        if f["state"] not in APPROVABLE:
            raise NotAllowed(f"a finding in state {f['state']} cannot be approved (needs one of {', '.join(APPROVABLE)})")
        if self.dry_run:
            raise NotAllowed("the platform is in dry-run mode: nothing is changed until it is switched to enforce")
        if not rule.can_remediate:
            raise NotAllowed("this rule is detection-only; fix the resource by hand")
        try:
            violation = rule.check(self.ctx, f["resource_id"])
        except ResourceGone:
            violation = None
        if violation is None:
            self._transition(f, RESOLVED, actor, "approved, but it is already compliant: nothing to do")
            return self.store.get(finding_id)
        f.update(evidence=violation.evidence, detail=violation.detail)
        self._transition(f, f["state"], actor, f"approved by {actor}")
        f = self.store.get(finding_id)
        self._remediate(rule, f, violation, actor=actor)
        return self.store.get(finding_id)

    def reject(self, finding_id, actor, reason=""):
        f, _ = self._load(finding_id)
        if f["state"] not in APPROVABLE:
            raise NotAllowed(f"a finding in state {f['state']} cannot be rejected")
        until = (self.ctx.now() + timedelta(days=self.policy.hold["reject_days"])).isoformat(timespec="seconds")
        self._transition(f, REJECTED, actor, f"rejected by {actor}: {reason or 'no reason given'} "
                                            f"(not raised again until {until[:10]})", suppressed_until=until)
        return self.store.get(finding_id)

    def rollback(self, finding_id, actor):
        f, rule = self._load(finding_id)
        if f["state"] != REMEDIATED or not f.get("pre_state"):
            raise NotAllowed("only a REMEDIATED finding can be rolled back")
        try:
            rule.rollback(self.ctx, f["resource_id"], f["pre_state"])
        except ResourceGone:
            self._transition(f, RESOLVED, actor, "resource is gone, nothing to roll back")
            return self.store.get(finding_id)
        until = (self.ctx.now() + timedelta(hours=self.policy.hold["rollback_hours"])).isoformat(timespec="seconds")
        self._transition(f, ROLLED_BACK, actor, f"rolled back by {actor}. Automatic fixing is paused for this "
                                                f"resource until {until}", suppressed_until=until, notify=True)
        return self.store.get(finding_id)

    # ---- state writes -----------------------------------------------------------------------------
    def _touch(self, f):
        """Same state, just note that we saw it again."""
        self.store.save(f)

    def _transition(self, f, state, actor, note, notify=False, **fields):
        now = self._now_iso()
        changed = f.get("state") != state
        self.changes += changed
        f.update(fields)
        f.update(state=state, actor=actor, updated_at=now, updated_epoch=self._epoch())
        f["history"] = (f.get("history", []) + [{"at": now, "state": state, "actor": actor, "note": note[:300]}])[-MAX_HISTORY:]
        if state == RESOLVED:
            f["expires_epoch"] = self._epoch() + KEEP_RESOLVED_DAYS * 86400     # DynamoDB TTL cleans old records
        else:
            f.pop("expires_epoch", None)
        saved = self.store.save(f)
        f.update(version=saved["version"])
        if notify and changed:                      # tell people about CHANGES, never repeat the same news
            self._notify(f, note)

    def _notify(self, f, note):
        subject = f"[SecRem] {f['severity']} {f['rule_id']} {f['resource_id']} -> {f['state']}"
        lines = [f"{f['title']}", f"Resource: {f['resource_id']}", f"Detail:   {f['detail']}", f"Now:      {f['state']}: {note}"]
        if f["state"] in APPROVABLE:
            lines += ["", f"Approve:  secrem approve '{f['finding_id']}'", f"Reject:   secrem reject '{f['finding_id']}' --reason '...'"]
        if f["state"] == REMEDIATED:
            lines += ["", f"Undo:     secrem rollback '{f['finding_id']}'"]
        self.notifier.send(subject, "\n".join(lines))

    # ---- entry points: full scan and real-time events ---------------------------------------------
    def scan_all(self):
        counts = {}
        for rule in self.rules.values():
            seen = set()
            try:
                resources = rule.list_resources(self.ctx)
            except Exception as exc:  # noqa: BLE001
                print(f"[error] listing for {rule.id}: {type(exc).__name__}: {exc}", file=sys.stderr)
                self.metrics.emit("CheckError", 1, rule=rule.id)
                continue
            for rid in resources:
                seen.add(rid)
                self._count(counts, rule, self.process(rule, rid, "scan"))
            for f in self.store.open_for_rule(rule.id):         # open findings whose resource did not show up: gone?
                if f["resource_id"] not in seen:
                    self._count(counts, rule, self.process(rule, f["resource_id"], "scan"))
        summary = {"outcomes": counts, "dry_run": self.dry_run,
                   "expired_exceptions": [f"{e['rule']}/{e['resource']}" for e in self.policy.expired_exceptions(self.ctx.now())],
                   "exceptions_expiring_soon": [f"{e['rule']}/{e['resource']} ({e['expires']})" for e in self.policy.expiring_soon(14, self.ctx.now())]}
        self.metrics.emit("ScanCompleted", 1)
        self._digest(summary)
        return summary

    @staticmethod
    def _count(counts, rule, outcome):
        counts.setdefault(rule.id, {})
        counts[rule.id][outcome] = counts[rule.id].get(outcome, 0) + 1

    def _digest(self, summary):
        today = self.ctx.now().strftime("%Y%m%d")
        first_today = self.store.bump("digest" + today, self._epoch() + 3 * 86400) == 1
        if not (self.changes or first_today):       # nothing new: stay quiet (one reminder a day at most)
            return
        lines = []
        pending = self.store.by_state(PENDING_APPROVAL)
        if pending:
            lines.append(f"{len(pending)} finding(s) waiting for approval:")
            lines += [f"  {x['severity']:<8} {x['finding_id']}" for x in sorted(pending, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))[:20]]
        for label, key in (("EXPIRED exceptions (the rule applies again!)", "expired_exceptions"),
                           ("Exceptions expiring within 14 days", "exceptions_expiring_soon")):
            if summary[key]:
                lines += ["", label + ":"] + [f"  {x}" for x in summary[key]]
        stuck = [x for state in (FAILED, BLOCKED, ESCALATED) for x in self.store.by_state(state)]
        if stuck:
            lines += ["", f"{len(stuck)} finding(s) that need a person (FAILED / BLOCKED / ESCALATED):"]
            lines += [f"  {x['state']:<9} {x['finding_id']}: {x['detail']}" for x in stuck[:20]]
        if lines:
            self.notifier.send("[SecRem] scan digest" + (" (DRY RUN)" if self.dry_run else ""), "\n".join(lines))

    def handle_event(self, event):
        """One CloudTrail 'API call' event: re-check only the resources it touched, with the rules that care."""
        detail = event.get("detail", {})
        name, source = detail.get("eventName"), detail.get("eventSource")
        if detail.get("errorCode"):                              # the call failed: nothing changed
            return {"ignored": "call failed"}
        actor_arn = (detail.get("userIdentity") or {}).get("arn", "")
        if self.remediator_arn and self._is_self(actor_arn):     # our own fix: do not react to ourselves
            return {"ignored": "own change"}
        outcomes = {}
        for rule in self.rules.values():
            if rule.event_source == source and name in rule.events:
                for rid in rule.resources_from_event(event):
                    outcomes[f"{rule.id}#{rid}"] = self.process(rule, rid, "event")
        return {"event": name, "outcomes": outcomes}

    def _is_self(self, actor_arn):
        """assumed-role ARNs look like arn:aws:sts::123:assumed-role/ROLE/session; compare on the role name."""
        role = self.remediator_arn.rsplit("/", 1)[-1]
        return f"assumed-role/{role}/" in actor_arn or actor_arn == self.remediator_arn
