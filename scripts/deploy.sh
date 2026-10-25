#!/usr/bin/env bash
# Deploy (or update) the platform. Starts in DRY RUN: it reports what it WOULD fix and changes nothing.
#   scripts/deploy.sh                       dry run
#   DRY_RUN=false scripts/deploy.sh         enforce (automatic fixes on)
#   NOTIFY_EMAIL=you@example.com ...        also get findings by email (confirm the SNS email)
#   REGION=eu-west-1                        region to deploy to and watch
set -euo pipefail
cd "$(dirname "$0")/.."
TF=$(command -v tofu || command -v terraform) || { echo "install OpenTofu first: scripts/setup.sh"; exit 1; }
REGION=${REGION:-eu-west-1}; DRY_RUN=${DRY_RUN:-true}
export AWS_REGION=$REGION AWS_DEFAULT_REGION=$REGION

arn=$(aws sts get-caller-identity --query Arn --output text)
# Whoever deploys may approve: turn "assumed-role/ROLE/session" into "assumed-role/ROLE/*"
case "$arn" in *:assumed-role/*) approver="${arn%/*}/*";; *) approver="$arn";; esac
echo "region=$REGION dry_run=$DRY_RUN approver=$approver"

scripts/build_zip.sh
cd terraform
$TF init -input=false -upgrade >/dev/null
emails='[]'; [ -n "${NOTIFY_EMAIL:-}" ] && emails="[\"$NOTIFY_EMAIL\"]"
$TF apply -auto-approve -input=false -var "region=$REGION" -var "dry_run=$DRY_RUN" \
  -var "approver_arns=[\"$approver\"]" -var "notify_emails=$emails"

url=$($TF output -raw approval_url)
echo
echo "Deployed. Next:"
echo "  export SECREM_URL=$url"
echo "  export AWS_REGION=$REGION"
echo "  .venv/bin/python scripts/secrem rules"
echo "  .venv/bin/python scripts/secrem scan && .venv/bin/python scripts/secrem findings"
