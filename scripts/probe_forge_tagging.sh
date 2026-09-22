#!/usr/bin/env bash
set -euo pipefail
OUT="/tmp/forge_ilzt1a.js"
docker cp forge_app_1:/app/.next/server/chunks/src_lib_0ilzt1a._.js "$OUT"
echo "copied $(wc -c <"$OUT") bytes"
python3 - <<'PY'
from pathlib import Path
import re
t=Path("/tmp/forge_ilzt1a.js").read_text(errors="ignore")
print("len", len(t))
for m in re.finditer(r".{0,80}did not produce an app image.{0,600}", t):
    print("---ERR---")
    print(m.group(0))
    print()
for pat in ["compose images","Successfully tagged","Tagging compose","app image","IMAGE ID","images --format","Repository","unknown"]:
    count=t.count(pat)
    print(f"{pat!r} count={count}")
    i=t.find(pat)
    if i>=0:
        print(t[max(0,i-180):i+400])
        print("----")
PY
echo "probe_forge_tagging.sh: OK"
