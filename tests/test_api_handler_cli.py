"""The human-facing edges: the approval API, the Lambda entry point and the signed command line."""
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import quote

import pytest

from conftest import REGION, base_policy
from secrem import api, cli, handler

APPROVER = "arn:aws:iam::123456789012:role/approver-alice"
STRANGER = "arn:aws:iam::123456789012:user/mallory"


def req(method, path, caller=APPROVER, body=None, query=None):
    ev = {"rawPath": path, "requestContext": {"http": {"method": method}}, "queryStringParameters": query}
    if caller:
        ev["requestContext"]["authorizer"] = {"iam": {"userArn": caller}}
    if body is not None:
        ev["body"] = json.dumps(body)
    return ev


def setup(w):
    w.build(base_policy(), only=("s3-ssl-only", "s3-public-access-block"))
    w.s3.create_bucket(Bucket="bkt-one", CreateBucketConfiguration={"LocationConstraint": REGION})
    w.engine.scan_all()
    return "s3-ssl-only#bkt-one"


def call(w, *a, **kw):
    r = api.handle(req(*a, **kw), w.engine)
    return r["statusCode"], json.loads(r["body"])


# ---- API ----------------------------------------------------------------------------------------
def test_no_identity_no_service(world):
    setup(world)
    assert call(world, "GET", "/findings", caller=None)[0] == 403


def test_anyone_signed_in_may_read_but_only_approvers_may_change(world):
    fid = setup(world)
    code, items = call(world, "GET", "/findings", caller=STRANGER)
    assert code == 200 and {i["finding_id"] for i in items} == {fid, "s3-public-access-block#bkt-one"}
    for action in ("approve", "reject", "rollback"):
        code, body = call(world, "POST", f"/findings/{quote(fid, safe='')}/{action}", caller=STRANGER, body={})
        assert code == 403 and body["you_are"] == STRANGER
    assert call(world, "POST", "/scan", caller=STRANGER, body={})[0] == 403
    assert world.finding(fid)["state"] == "PENDING_APPROVAL"


def test_identity_in_the_body_is_never_trusted(world):
    fid = setup(world)
    code, _ = call(world, "POST", f"/findings/{quote(fid, safe='')}/approve", caller=STRANGER,
                   body={"actor": APPROVER, "userArn": APPROVER})
    assert code == 403


def test_approver_flow_approve_and_rollback_records_who(world):
    fid = setup(world)
    path = f"/findings/{quote(fid, safe='')}"
    code, f = call(world, "POST", path + "/approve", body={})
    assert code == 200 and f["state"] == "REMEDIATED"
    code, full = call(world, "GET", path)
    assert code == 200 and full["actor"] == APPROVER and full["history"][-1]["actor"] == APPROVER
    code, f = call(world, "POST", path + "/rollback", body={})
    assert code == 200 and f["state"] == "ROLLED_BACK"


def test_reject_with_reason_and_conflicts_are_409(world):
    fid = setup(world)
    path = f"/findings/{quote(fid, safe='')}"
    code, f = call(world, "POST", path + "/reject", body={"reason": "needed by legacy app"})
    assert code == 200 and f["state"] == "REJECTED"
    code, body = call(world, "POST", path + "/approve", body={})
    assert code == 409 and "REJECTED" in body["error"]


def test_filter_by_state_unknown_finding_and_unknown_route(world):
    fid = setup(world)
    code, items = call(world, "GET", "/findings", query={"state": "PENDING_APPROVAL"})
    assert [i["finding_id"] for i in items] == [fid]
    assert call(world, "GET", "/findings/" + quote("nope#nope", safe=""))[0] == 404
    assert call(world, "GET", "/nothing")[0] == 404
    assert call(world, "GET", "/findings/not-a-valid-id")[0] == 404


def test_scan_and_rules_and_health(world):
    setup(world)
    code, out = call(world, "POST", "/scan", body={})
    assert code == 200 and "outcomes" in out
    code, rules = call(world, "GET", "/rules")
    assert {r["id"] for r in rules} == {"s3-ssl-only", "s3-public-access-block"}
    assert call(world, "GET", "/health")[1]["ok"] is True


def test_finding_ids_containing_slashes_work(world):
    w = world
    w.build(base_policy(), only=("iam-stale-access-key",))
    from datetime import datetime, timezone
    w.clock.t = datetime.now(timezone.utc)
    w.iam.create_user(UserName="bob")
    key = w.iam.create_access_key(UserName="bob")["AccessKey"]["AccessKeyId"]
    w.clock.advance(days=100)
    w.engine.scan_all()
    fid = f"iam-stale-access-key#bob/{key}"
    code, f = call(w, "POST", f"/findings/{quote(fid, safe='')}/approve", body={})
    assert code == 200 and f["state"] == "REMEDIATED"


def test_bad_json_body(world):
    setup(world)
    ev = req("POST", "/scan")
    ev["body"] = "{nope"
    assert api.handle(ev, world.engine)["statusCode"] == 400


# ---- Lambda entry point ---------------------------------------------------------------------------
def test_handler_routes_each_trigger(world):
    w = world
    w.build(base_policy(), only=("s3-public-access-block",))
    w.s3.create_bucket(Bucket="bkt-one", CreateBucketConfiguration={"LocationConstraint": REGION})
    w.s3.create_bucket(Bucket="bkt-two", CreateBucketConfiguration={"LocationConstraint": REGION})
    ev = {"detail-type": "AWS API Call via CloudTrail", "source": "aws.s3", "region": REGION,
          "detail": {"eventName": "CreateBucket", "eventSource": "s3.amazonaws.com",
                     "requestParameters": {"bucketName": "bkt-one"}, "userIdentity": {"arn": "arn:aws:iam::1:user/x"}}}
    out = handler.lambda_handler(ev, None, engine=w.engine)
    assert list(out["outcomes"]) == ["s3-public-access-block#bkt-one"]
    out = handler.lambda_handler({"source": "aws.events", "detail-type": "Scheduled Event"}, None, engine=w.fresh_engine())
    assert out["outcomes"]["s3-public-access-block"] == {"remediated": 1, "compliant": 1}
    assert handler.lambda_handler(req("GET", "/health"), None, engine=w.engine)["statusCode"] == 200
    assert handler.lambda_handler({"hello": 1}, None, engine=w.engine) == {"ignored": "unrecognised event"}


def test_build_engine_reads_environment(world):
    w = world
    env = {"FINDINGS_TABLE": "findings", "DRY_RUN": "false", "APPROVERS": "arn:aws:iam::1:role/a*, arn:aws:iam::1:role/b",
           "REGIONS": REGION, "REMEDIATOR_ROLE_ARN": "arn:aws:iam::1:role/r"}
    e = handler.build_engine(env)
    assert e.dry_run is False and e.policy.is_approver("arn:aws:iam::1:role/b") and e.policy.is_approver("arn:aws:iam::1:role/abc")
    assert not e.policy.is_approver("arn:aws:iam::1:role/c")
    assert handler.build_engine({**env, "DRY_RUN": "true"}).dry_run is True
    assert handler.build_engine({k: v for k, v in env.items() if k != "DRY_RUN"}).dry_run is True      # safe default


# ---- command line: real HTTP, real SigV4 signing ------------------------------------------------------
class Recorder(BaseHTTPRequestHandler):
    seen = []

    def _do(self):
        n = int(self.headers.get("content-length") or 0)
        Recorder.seen.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": self.rfile.read(n)})
        if "missing" in self.path:
            code, body = 404, {"error": "no such finding"}
        else:
            code, body = 200, [{"finding_id": "r#x", "state": "PENDING_APPROVAL", "severity": "HIGH", "detail": "d"}] if self.path.startswith("/findings") and self.command == "GET" and "%23" not in self.path else {"ok": True}
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = _do

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    Recorder.seen = []
    srv = HTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def run(argv, url, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    out = io.StringIO()
    rc = cli.main(["--url", url, *argv], out=out)
    return rc, out.getvalue()


def test_cli_signs_every_request_for_lambda(server, monkeypatch):
    rc, out = run(["findings", "--state", "PENDING_APPROVAL"], server, monkeypatch)
    assert rc == 0 and "PENDING_APPROVAL" in out
    (r,) = Recorder.seen
    auth = r["headers"]["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") and "/eu-west-1/lambda/aws4_request" in auth
    assert "x-amz-date" in {k.lower() for k in r["headers"]} and r["path"] == "/findings?state=PENDING_APPROVAL"


def test_cli_posts_encoded_ids_and_reason(server, monkeypatch):
    rc, _ = run(["reject", "iam-stale-access-key#bob/AKIA1", "--reason", "needed"], server, monkeypatch)
    r = Recorder.seen[-1]
    assert rc == 0 and r["method"] == "POST" and r["path"] == "/findings/iam-stale-access-key%23bob%2FAKIA1/reject"
    assert json.loads(r["body"]) == {"reason": "needed"} and "Authorization" in r["headers"]


def test_cli_reports_errors_and_missing_url(server, monkeypatch, capsys):
    rc, _ = run(["show", "missing"], server, monkeypatch)
    assert rc == 1 and "no such finding" in capsys.readouterr().err
    monkeypatch.delenv("SECREM_URL", raising=False)
    assert cli.main(["rules"]) == 2


def test_cli_region_comes_from_the_function_url():
    assert cli.region_of("https://abc123.lambda-url.us-east-2.on.aws/") == "us-east-2"
