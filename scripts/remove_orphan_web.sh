#!/usr/bin/env bash
set -euo pipefail
docker rm -f iam-server-web-1 2>/dev/null || true
docker ps -a --filter name=iam-server --format '{{.Names}} {{.Status}}'
echo "remove_orphan_web.sh: OK"
