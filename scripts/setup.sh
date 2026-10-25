#!/usr/bin/env bash
# One-time prerequisites on Ubuntu 22.04/24.04 (amd64 or arm64): python3, pip, unzip, AWS CLI v2, OpenTofu 1.8.5.
set -euo pipefail
TOFU_VERSION=1.8.5
arch=$(uname -m); case "$arch" in x86_64) a=amd64; awsa=x86_64;; aarch64) a=arm64; awsa=aarch64;; *) echo "unsupported CPU $arch"; exit 1;; esac

sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv unzip curl git

if ! command -v aws >/dev/null; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${awsa}.zip" -o /tmp/awscli.zip
  unzip -q -o /tmp/awscli.zip -d /tmp && sudo /tmp/aws/install
fi
if ! command -v tofu >/dev/null; then
  curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_${a}.zip" -o /tmp/tofu.zip
  sudo unzip -q -o /tmp/tofu.zip tofu -d /usr/local/bin
fi

cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/pip install -q -e '.[dev]'
echo "tools: $(aws --version 2>&1 | cut -d' ' -f1) | $(tofu version | head -1) | $(.venv/bin/python --version)"

if aws sts get-caller-identity >/dev/null 2>&1; then
  echo "AWS identity: $(aws sts get-caller-identity --query Arn --output text)"
else
  echo "NO AWS CREDENTIALS. Attach an IAM role to this instance, or run: aws configure"
fi
