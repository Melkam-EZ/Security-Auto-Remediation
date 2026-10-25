#!/usr/bin/env bash
# Remove everything this project created (the trail bucket is emptied and deleted too).
# Anything the platform FIXED stays fixed: destroy does not undo remediations. Use `secrem rollback` first if needed.
set -euo pipefail
cd "$(dirname "$0")/.."
TF=$(command -v tofu || command -v terraform)
REGION=${REGION:-eu-west-1}; export AWS_REGION=$REGION AWS_DEFAULT_REGION=$REGION
scripts/build_zip.sh >/dev/null
cd terraform
$TF init -input=false >/dev/null
$TF destroy -auto-approve -input=false -var "region=$REGION"
rm -rf build secrem.zip
