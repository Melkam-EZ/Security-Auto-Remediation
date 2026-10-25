"""The approval API: a Lambda Function URL with AWS_IAM auth.

AWS verifies the caller's SigV4 signature BEFORE this code runs and tells us who they are
(requestContext.authorizer.iam.userArn). We never trust a name sent in the body: the identity comes only from AWS.
Reading is open to any caller AWS lets in; changing anything needs the caller's ARN to match an approver pattern.
"""
from __future__ import annotations

import json
import re
from urllib.parse import unquote

from .model import NotAllowed

SAFE_ID = re.compile(r"^[A-Za-z0-9_.:/@+=,-]{1,300}#[A-Za-z0-9_.:/@+=,-]{1,300}$")


def _resp(code, body):
    return {"statusCode": code, "headers": {"content-type": "application/json"}, "body": json.dumps(body, default=str)}


def _caller(event):
    return (((event.get("requestContext") or {}).get("authorizer") or {}).get("iam") or {}).get("userArn", "")


def _summary(f):
    return {k: f.get(k) for k in ("finding_id", "severity", "state", "mode", "title", "detail", "plan", "first_seen",
                                  "last_seen", "repeat_count", "attempts", "suppressed_until")}


def handle(event, engine):
    http = (event.get("requestContext") or {}).get("http") or {}
    method, path = http.get("method", "GET").upper(), event.get("rawPath", "/")
    caller = _caller(event)
    if not caller:
        return _resp(403, {"error": "no authenticated IAM identity on the request"})
    query = event.get("queryStringParameters") or {}
    try:
        body = json.loads(event.get("body") or "{}") if method == "POST" else {}
    except ValueError:
        return _resp(400, {"error": "body must be JSON"})

    if method == "GET" and path == "/health":
        return _resp(200, {"ok": True, "dry_run": engine.dry_run})
    if method == "GET" and path == "/rules":
        return _resp(200, [{"id": r.id, "title": r.title, "severity": r.severity, "mode": engine.policy.mode(r.id),
                            "can_remediate": r.can_remediate} for r in engine.rules.values()])
    if method == "GET" and path == "/findings":
        state = query.get("state")
        items = engine.store.by_state(state) if state else engine.store.all()
        items.sort(key=lambda f: (f.get("severity", ""), f["finding_id"]))
        return _resp(200, [_summary(f) for f in items])
    m = re.fullmatch(r"/findings/(.+?)(?:/(approve|reject|rollback))?", path)
    fid = unquote(m.group(1)) if m else ""
    if m and SAFE_ID.match(fid):
        action = m.group(2)
        if method == "GET" and not action:
            f = engine.store.get(fid)
            return _resp(200, f) if f else _resp(404, {"error": "no such finding"})
        if method == "POST" and action:
            if not engine.policy.is_approver(caller):
                return _resp(403, {"error": "your identity is not on the approver list", "you_are": caller})
            try:
                if action == "approve":
                    f = engine.approve(fid, caller)
                elif action == "reject":
                    f = engine.reject(fid, caller, str(body.get("reason", ""))[:300])
                else:
                    f = engine.rollback(fid, caller)
            except NotAllowed as exc:
                return _resp(409, {"error": str(exc)})
            return _resp(200, _summary(f))
    if method == "POST" and path == "/scan":
        if not engine.policy.is_approver(caller):
            return _resp(403, {"error": "your identity is not on the approver list", "you_are": caller})
        return _resp(200, engine.scan_all())
    return _resp(404, {"error": f"no route {method} {path}"})
