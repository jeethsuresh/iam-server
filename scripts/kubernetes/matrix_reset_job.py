"""Specialize one maintenance job without persisting a reset in its CronJob."""
import json
import re
import sys
from pathlib import Path

path, server, image = sys.argv[1:]
if server != "gravitas.cool" or not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}", image):
    raise SystemExit("Unexpected Matrix reset target")
job = json.loads(Path(path).read_text())
containers = job["spec"]["template"]["spec"]["containers"]
if len(containers) != 1 or containers[0]["name"] != "iam" or containers[0]["image"] != image:
    raise SystemExit("Reset job must use the exact maintenance release image")
container = containers[0]
container["env"] = [e for e in container.get("env", []) if e["name"] != "MATRIX_ROOM_RESET_SERVER"]
container["env"].append({"name": "MATRIX_ROOM_RESET_SERVER", "value": server})
container["command"] = [
    "/usr/local/bin/iam-entrypoint", "/app/bin/lakehouse", "eval",
    'LakehouseIam.Release.migrate(); IO.inspect(LakehouseMatrix.Release.reset_rooms(System.fetch_env!("MATRIX_ROOM_RESET_SERVER")), label: "Matrix room reset")',
]
# An uncertain job is inspected, not automatically replayed after it may commit.
job["spec"]["backoffLimit"] = 0
Path(path).write_text(json.dumps(job, indent=2) + "\n")
