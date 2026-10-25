#!/usr/bin/env bash
# Local checks (no AWS account needed): the whole test suite against a simulated AWS (moto) + Terraform formatting.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
$PY -m pytest -q
command -v tofu >/dev/null && tofu fmt -check -recursive terraform && echo "terraform fmt: ok"
echo "OK"
