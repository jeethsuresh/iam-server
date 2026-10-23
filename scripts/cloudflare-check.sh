#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../cloudflare"
npm ci --no-audit --no-fund
npm run check
npm test
