#!/usr/bin/env bash
set -euo pipefail
OUT="/tmp/forge_ilzt1a.js"
docker cp forge_app_1:/app/.next/server/chunks/src_lib_0ilzt1a._.js "$OUT"
# Also grab related chunks that might hold helpers
docker cp forge_app_1:/app/.next/server/chunks/src_lib_0cwye1d._.js /tmp/forge_cwye.js 2>/dev/null || true
docker cp forge_app_1:/app/.next/server/chunks/src_lib_0pmkjmg._.js /tmp/forge_pmkj.js 2>/dev/null || true
ls -la /tmp/forge_*.js 2>/dev/null || true

python3 - <<'PY'
from pathlib import Path
import re
t=Path("/tmp/forge_ilzt1a.js").read_text(errors="ignore")
# Pretty-print by splitting on function keywords roughly
# Find async function _ and R near app image
idx=t.find("did not produce an app image")
print("error at", idx)
print(t[max(0,idx-2500):idx+800])
print("\n\n==== FULL FILE (pretty-ish) ====")
# Insert newlines before common tokens for readability
pretty=t
for tok in ["async function ","function ","let ","const ","await ","if(","return ","throw "]:
    pretty=pretty.replace(tok, "\n"+tok)
Path("/tmp/forge_ilzt1a_pretty.js").write_text(pretty)
print(pretty[:12000])
PY
echo "probe_forge_tagging.sh: OK"
