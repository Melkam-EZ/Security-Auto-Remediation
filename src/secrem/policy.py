"""The remediation policy: which rules run, in which mode, with which limits, and which exceptions apply.

It lives in Git (policy/remediation-policy.json) and ships inside the Lambda package, so every change to what
the platform may fix automatically is a reviewed commit and a deploy, never a console click.
"""
from __future__ import annotations

import fnmatch
import json
from datetime import date, datetime, timedelta, timezone

from .model import MODES

MAX_EXCEPTION_DAYS = 366
DEFAULTS = {
    "regions": ["eu-west-1"],
    "guard": {"max_auto_per_run": 10, "max_auto_per_hour": 30, "repeat_offender_threshold": 3},
    "hold": {"rollback_hours": 24, "reject_days": 30},
    "approvers": [],
    "exceptions": [],
}


class PolicyError(ValueError):
    pass


def _today(now):
    return now.date() if isinstance(now, datetime) else now


class Policy:
    def __init__(self, data: dict, rule_catalog: dict | None = None, now: datetime | None = None):
        """rule_catalog: {rule_id: rule class}, used to reject unknown rules and impossible modes."""
        self.data = {**DEFAULTS, **{k: v for k, v in data.items() if not k.startswith("_")}}
        for key in ("guard", "hold"):
            self.data[key] = {**DEFAULTS[key], **self.data.get(key, {})}
        self.now = now or datetime.now(timezone.utc)
        self._validate(rule_catalog)

    # ---- loading ---------------------------------------------------------------------------
    @classmethod
    def load(cls, path, rule_catalog=None, now=None):
        with open(path) as f:
            return cls(json.load(f), rule_catalog, now)

    # ---- validation: refuse a policy that would be unsafe or meaningless -----------------------
    def _validate(self, catalog):
        d = self.data
        if not d["regions"] or not all(isinstance(r, str) and r for r in d["regions"]):
            raise PolicyError("regions must be a non-empty list of region names")
        rules = d.get("rules")
        if not isinstance(rules, dict) or not rules:
            raise PolicyError("policy needs a 'rules' object")
        for rid, cfg in rules.items():
            if catalog is not None and rid not in catalog:
                raise PolicyError(f"unknown rule '{rid}'")
            mode = cfg.get("mode")
            if mode not in MODES:
                raise PolicyError(f"rule '{rid}': mode must be one of {MODES}")
            if catalog is not None and mode != "report" and not catalog[rid].can_remediate:
                raise PolicyError(f"rule '{rid}' cannot be fixed automatically; its mode must be 'report'")
        g = d["guard"]
        for key in ("max_auto_per_run", "max_auto_per_hour", "repeat_offender_threshold"):
            if not isinstance(g[key], int) or g[key] < 1:
                raise PolicyError(f"guard.{key} must be a whole number >= 1")
        for ex in d["exceptions"]:
            self._validate_exception(ex, rules)

    def _validate_exception(self, ex, rules):
        for key in ("rule", "resource", "expires", "reason", "approved_by"):
            if not ex.get(key):
                raise PolicyError(f"exception {ex}: '{key}' is required (exceptions must say why, who and until when)")
        if ex["rule"] not in rules:
            raise PolicyError(f"exception for unknown rule '{ex['rule']}'")
        if ex["resource"].strip("*?") == "":
            raise PolicyError("an exception may not match every resource; name the resource")
        try:
            expires = date.fromisoformat(ex["expires"])
        except ValueError:
            raise PolicyError(f"exception {ex['rule']}/{ex['resource']}: expires must be YYYY-MM-DD")
        if expires > _today(self.now) + timedelta(days=MAX_EXCEPTION_DAYS):
            raise PolicyError(f"exception {ex['rule']}/{ex['resource']}: expires more than {MAX_EXCEPTION_DAYS} days away; "
                              "exceptions must be renewed, not permanent")

    # ---- accessors -----------------------------------------------------------------------
    @property
    def regions(self):
        return list(self.data["regions"])

    @property
    def guard(self):
        return self.data["guard"]

    @property
    def hold(self):
        return self.data["hold"]

    @property
    def approvers(self):
        return list(self.data["approvers"])

    def rule_ids(self):
        return list(self.data["rules"])

    def mode(self, rule_id):
        return self.data["rules"][rule_id]["mode"]

    def params(self, rule_id):
        return dict(self.data["rules"][rule_id].get("params", {}))

    def active_exception(self, rule_id, resource_id, now=None):
        """The exception covering this finding today, or None. Expired exceptions never apply."""
        today = _today(now or self.now)
        for ex in self.data["exceptions"]:
            if ex["rule"] == rule_id and fnmatch.fnmatchcase(resource_id, ex["resource"]):
                if date.fromisoformat(ex["expires"]) >= today:
                    return ex
        return None

    def expired_exceptions(self, now=None):
        today = _today(now or self.now)
        return [ex for ex in self.data["exceptions"] if date.fromisoformat(ex["expires"]) < today]

    def expiring_soon(self, days=14, now=None):
        today = _today(now or self.now)
        soon = today + timedelta(days=days)
        return [ex for ex in self.data["exceptions"] if today <= date.fromisoformat(ex["expires"]) <= soon]

    def is_approver(self, arn: str) -> bool:
        return bool(arn) and any(fnmatch.fnmatchcase(arn, p) for p in self.approvers)
