#!/usr/bin/env bash
set -euo pipefail

echo "=== forge_app_1 ==="
docker inspect forge_app_1 --format '{{.Name}} image={{.Config.Image}} id={{.Image}}' 2>&1 || true

echo "=== find chunk ==="
docker exec forge_app_1 sh -c 'ls /app/.next/server/chunks/src_lib_0ilzt1a* 2>/dev/null; ls /app/.next/server/chunks/*ilzt* 2>/dev/null | head'
chunk="$(docker exec forge_app_1 sh -c 'ls /app/.next/server/chunks/src_lib_0ilzt1a* 2>/dev/null | head -1' || true)"
echo "chunk=$chunk"
if [[ -z "$chunk" ]]; then
  chunk="$(docker exec forge_app_1 sh -c 'grep -rl "did not produce an app image" /app/.next/server/chunks 2>/dev/null | head -1' || true)"
  echo "chunk_via_grep=$chunk"
fi
if [[ -n "$chunk" ]]; then
  docker exec forge_app_1 python3 - <<PY
import pathlib,re
p=pathlib.Path("""$chunk""")
t=p.read_text(errors="ignore")
print("len", len(t))
for m in re.finditer(r".{0,120}did not produce an app image.{0,500}", t):
    print("---ERR---")
    print(m.group(0))
for pat in ["compose images","Successfully tagged","image=(unknown)","Tagging compose","appImage","IMAGE ID","images --format","Repository"]:
    idxs=[i for i in range(len(t)) if t.startswith(pat,i)]
    print(pat, "count", len(idxs))
    for i in idxs[:3]:
        print("===", pat, i, "===")
        print(t[max(0,i-200):i+350])
        print()
PY
fi
echo "probe_forge_tagging.sh: OK"
