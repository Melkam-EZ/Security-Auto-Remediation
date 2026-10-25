"""secrem: the command line for humans. Talks to the approval API, signing every request with your AWS credentials.

  secrem findings [--state PENDING_APPROVAL]     list
  secrem show FINDING_ID                         everything about one finding, including its history
  secrem approve FINDING_ID                      let the platform fix it
  secrem reject FINDING_ID --reason "why"        leave it alone (for 30 days by default)
  secrem rollback FINDING_ID                     undo a fix
  secrem scan                                    run a full scan now
  secrem rules                                   which rules run, in which mode

The API URL comes from SECREM_URL (terraform output approval_url).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def region_of(url):
    m = re.search(r"\.lambda-url\.([a-z0-9-]+)\.on\.aws", url)
    return m.group(1) if m else os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "eu-west-1"


def call(method, base_url, path, body=None, query=None, session=None):
    """One signed request. Returns (status, parsed JSON)."""
    url = base_url.rstrip("/") + path + (("?" + urllib.parse.urlencode(query)) if query else "")
    data = json.dumps(body).encode() if body is not None else None
    session = session or boto3.session.Session()
    creds = session.get_credentials()
    if creds is None:
        raise SystemExit("no AWS credentials found (aws configure, or set AWS_PROFILE)")
    headers = {"content-type": "application/json"} if data else {}
    req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(creds.get_frozen_credentials(), "lambda", region_of(base_url)).add_auth(req)
    http = urllib.request.Request(url, data=data, method=method, headers=dict(req.headers.items()))
    try:
        with urllib.request.urlopen(http, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"error": raw.decode(errors="replace")[:300]}


def _q(fid):
    return urllib.parse.quote(fid, safe="")


def main(argv=None, session=None, out=None):
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="secrem", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("SECREM_URL"), help="approval API URL (default: $SECREM_URL)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("findings")
    p.add_argument("--state")
    for name in ("show", "approve", "rollback"):
        sub.add_parser(name).add_argument("finding_id")
    p = sub.add_parser("reject")
    p.add_argument("finding_id")
    p.add_argument("--reason", default="")
    sub.add_parser("scan")
    sub.add_parser("rules")
    a = ap.parse_args(argv)
    if not a.url:
        print("set SECREM_URL (terraform output approval_url) or pass --url", file=sys.stderr)
        return 2

    if a.cmd == "findings":
        status, data = call("GET", a.url, "/findings", query={"state": a.state} if a.state else None, session=session)
    elif a.cmd == "rules":
        status, data = call("GET", a.url, "/rules", session=session)
    elif a.cmd == "scan":
        status, data = call("POST", a.url, "/scan", body={}, session=session)
    elif a.cmd == "show":
        status, data = call("GET", a.url, f"/findings/{_q(a.finding_id)}", session=session)
    elif a.cmd == "reject":
        status, data = call("POST", a.url, f"/findings/{_q(a.finding_id)}/reject", body={"reason": a.reason}, session=session)
    else:
        status, data = call("POST", a.url, f"/findings/{_q(a.finding_id)}/{a.cmd}", body={}, session=session)

    if status >= 400:
        print(f"error {status}: {data.get('error', data)}", file=sys.stderr)
        return 1
    if a.cmd == "findings":
        for f in data:
            print(f"{f['state']:<17} {f['severity']:<8} {f['finding_id']}  {f['detail']}", file=out)
        if not data:
            print("no findings", file=out)
    elif a.cmd == "rules":
        for r in data:
            print(f"{r['mode']:<8} {r['severity']:<8} {r['id']}  {r['title']}", file=out)
    else:
        print(json.dumps(data, indent=2, default=str), file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
