#!/usr/bin/env python3
"""Do the tests actually protect the safety rails? Break each rail on purpose in a scratch copy and require the
test suite to fail. A mutation that survives means a rail with no test behind it.

    python tests/mutation_check.py
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (file, exact text, replacement, what we broke)
MUTATIONS = [
    ("src/secrem/engine.py", "        if self.dry_run:\n            return self._settle", "        if False:\n            return self._settle", "dry-run no longer stops fixes"),
    ("src/secrem/engine.py", "if self.auto_this_run >= guard[\"max_auto_per_run\"]", "if self.auto_this_run > guard[\"max_auto_per_run\"]", "per-run guard off by one"),
    ("src/secrem/engine.py", "or self.store.counter(hour_key) >= guard[\"max_auto_per_hour\"]", "or False", "hourly guard removed"),
    ("src/secrem/engine.py", "if f[\"repeat_count\"] >= guard[\"repeat_offender_threshold\"]", "if f[\"repeat_count\"] > guard[\"repeat_offender_threshold\"]", "repeat-offender threshold off by one"),
    ("src/secrem/engine.py", "if after is not None:  ", "if False:  ", "post-fix verification removed"),
    ("src/secrem/engine.py", "if self.remediator_arn and self._is_self(actor_arn)", "if False and self._is_self(actor_arn)", "loop prevention removed"),
    ("src/secrem/engine.py", "f.get(\"suppressed_until\", \"\") > self._now_iso()", "f.get(\"suppressed_until\", \"\") < self._now_iso()", "rejection / rollback hold inverted"),
    ("src/secrem/engine.py", "if notify and changed:", "if notify:", "notifications repeat on every scan"),
    ("src/secrem/engine.py", "if self.dry_run:\n            raise NotAllowed", "if False:\n            raise NotAllowed", "approvals allowed during dry-run"),
    ("src/secrem/engine.py", "if f[\"state\"] not in APPROVABLE:\n            raise NotAllowed(f\"a finding in state {f['state']} cannot be approved", "if False:\n            raise NotAllowed(f\"a finding in state {f['state']} cannot be approved", "any state may be approved"),
    ("src/secrem/api.py", "            if not engine.policy.is_approver(caller):\n                return _resp(403, {\"error\": \"your identity is not on the approver list\", \"you_are\": caller})\n            try:", "            if False:\n                return _resp(403, {})\n            try:", "anyone may approve"),
    ("src/secrem/api.py", "    if not caller:\n", "    if False:\n", "unauthenticated requests accepted"),
    ("src/secrem/handler.py", "env.get(\"DRY_RUN\", \"true\")", "env.get(\"DRY_RUN\", \"false\")", "dry-run is no longer the default"),
    ("src/secrem/policy.py", "if date.fromisoformat(ex[\"expires\"]) >= today:\n                    return ex", "if True:\n                    return ex", "exceptions never expire"),
    ("src/secrem/policy.py", "if ex[\"resource\"].strip(\"*?\") == \"\":", "if False:", "match-everything exceptions allowed"),
    ("src/secrem/policy.py", "if expires > _today(self.now) + timedelta(days=MAX_EXCEPTION_DAYS):", "if False:", "permanent exceptions allowed"),
    ("src/secrem/store.py", "ConditionExpression=\"attribute_not_exists(finding_id)\"", "ConditionExpression=\"attribute_exists(finding_id) OR attribute_not_exists(finding_id)\"", "create can overwrite an existing finding"),
    ("src/secrem/rules/ec2.py", 'WORLD_V4, WORLD_V6 = "0.0.0.0/0"', 'WORLD_V4, WORLD_V6 = "0.0.0.1/0"', "open-to-world check broken"),
    ("terraform/policies/remediator.json", ", \"iam:PassRole\"", "", "explicit deny on PassRole removed"),
    ("terraform/main.tf", "reserved_concurrent_executions = 1", "reserved_concurrent_executions = 5", "concurrency limit raised"),
    ("terraform/main.tf", "authorization_type = \"AWS_IAM\"", "authorization_type = \"NONE\"", "approval URL made public"),
    ("terraform/variables.tf", "default     = true\n}\n\nvariable \"scan_schedule\"", "default     = false\n}\n\nvariable \"scan_schedule\"", "terraform dry_run default flipped"),
]


def run(mutation):
    path, old, new, what = mutation
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "build", "*.zip", ".terraform", ".pytest_cache"))
        target = work / path
        text = target.read_text()
        if text.count(old) != 1:
            return "BAD-MUTATION", f"pattern found {text.count(old)} times in {path}"
        target.write_text(text.replace(old, new))
        r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "tests"], cwd=work,
                           capture_output=True, text=True)
        return ("CAUGHT" if r.returncode != 0 else "SURVIVED"), what


def main():
    results = [(m, *run(m)) for m in MUTATIONS]
    for m, verdict, what in results:
        print(f"{verdict:<13} {m[0]:<38} {what}")
    bad = [r for r in results if r[1] != "CAUGHT"]
    print(f"\n{len(results) - len(bad)}/{len(results)} mutations caught")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
