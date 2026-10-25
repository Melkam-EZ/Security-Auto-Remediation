#!/usr/bin/env bash
# Lays out terraform/build/ = the Lambda package (the secrem/ package + the policy file). boto3 is already in Lambda.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf terraform/build && mkdir -p terraform/build/policy
cp -r src/secrem terraform/build/secrem
find terraform/build -name __pycache__ -prune -exec rm -rf {} +
cp policy/remediation-policy.json terraform/build/policy/
echo "built terraform/build ($(find terraform/build -type f | wc -l) files)"
