#!/usr/bin/env bash
# Dump Forge's release image-tagging helper from the Forge container (read-only).
set -euo pipefail

echo "=== forge-ish containers ==="
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>&1 | head -40 || true

forge_ctr=""
forge_ctr="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'forge|orchestrat' | head -1 || true)"
if [[ -z "$forge_ctr" ]]; then
  forge_ctr="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Ei 'forge|orchestrat' | head -1 || true)"
fi
echo "forge_ctr=${forge_ctr:-none}"

if [[ -n "$forge_ctr" ]]; then
  echo "=== searching chunk for app image error string ==="
  docker exec "$forge_ctr" sh -c 'find /app -name "*ilzt1a*" 2>/dev/null; find /app/.next -name "*.js" 2>/dev/null | head'
  chunk="$(docker exec "$forge_ctr" sh -c 'ls /app/.next/server/chunks/src_lib_0ilzt1a* 2>/dev/null | head -1' || true)"
  echo "chunk=$chunk"
  if [[ -n "$chunk" ]]; then
    docker exec "$forge_ctr" sh -c "grep -o '.{0,80}did not produce an app image.{0,120}' '$chunk' | head -5" || true
    docker exec "$forge_ctr" sh -c "grep -oE '.{0,60}compose images.{0,80}|.{0,60}Successfully tagged.{0,80}|.{0,40}image=\\(unknown\\).{0,80}|.{0,40}app image.{0,100}' '$chunk' | head -40" || true
    # Extract a readable slice around the error
    docker exec "$forge_ctr" sh -c "python3 - <<'PY'
import pathlib,re
p=pathlib.Path('$chunk')
t=p.read_text(errors='ignore')
for m in re.finditer(r'.{0,200}did not produce an app image.{0,400}', t):
    print('---MATCH---')
    print(m.group(0))
    print()
for pat in ['compose images','Successfully tagged','image=(unknown)','tagCompose','appImage','IMAGE ID']:
    i=t.find(pat)
    if i>=0:
        print('===', pat, 'at', i, '===')
        print(t[max(0,i-150):i+250])
        print()
PY" 2>&1 | head -200
  fi
fi
echo "probe_forge_tagging.sh: OK"
