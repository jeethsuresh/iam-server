"""Provision one persistent Gravitas signing identity without printing key material."""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

SERVER = "https://02fe9a55-8048-421e-a03f-eae9a4a60472.k8s.ondigitalocean.com"
NAME = "iam-matrix-signing"


def command(args, body=None):
    result = subprocess.run(args, input=body, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError("Kubernetes signing-key operation failed; no existing key was replaced")
    return result.stdout


def material(resource):
    data = resource["data"]
    encoded = base64.b64decode(data["MATRIX_SIGNING_KEY"], validate=True).decode("ascii")
    seed = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    key_id = base64.b64decode(data["MATRIX_SIGNING_KEY_ID"], validate=True).decode("ascii")
    if len(seed) != 32 or not re.fullmatch(r"ed25519:[A-Za-z0-9_]+", key_id):
        raise RuntimeError("The existing Matrix signing identity is invalid; refusing to replace it")
    return seed, key_id


def validate(resource):
    return material(resource)[1]


def provision(context, directory, run=command):
    if not context:
        raise RuntimeError("Set KUBE_CONTEXT explicitly")
    kube = ["kubectl", "--context", context, "--namespace", "iam"]
    server = run(kube + ["config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"])
    if server != SERVER:
        raise RuntimeError("Refusing an unexpected Gravitas cluster")

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    backup = directory / "matrix-signing-key.json"
    saved = json.loads(backup.read_text()) if backup.exists() else None
    if saved:
        validate(saved)

    response = run(kube + ["get", "secret", NAME, "-o", "json", "--ignore-not-found=true"])
    existing = json.loads(response) if response.strip() else None
    legacy = None
    if existing is None:
        response = run(kube + ["get", "secret", "iam-secrets", "-o", "json", "--ignore-not-found=true"])
        shared = json.loads(response).get("data", {}) if response.strip() else {}
        if shared.get("MATRIX_SIGNING_KEY"):
            legacy = {
                "apiVersion": "v1", "kind": "Secret", "type": "Opaque", "immutable": True,
                "metadata": {"name": NAME, "namespace": "iam"},
                "data": {"MATRIX_SIGNING_KEY": shared["MATRIX_SIGNING_KEY"],
                         "MATRIX_SIGNING_KEY_ID": shared.get("MATRIX_SIGNING_KEY_ID", base64.b64encode(b"ed25519:gravitas1").decode())},
            }
    resource = existing or legacy or saved
    if resource is None:
        seed = base64.b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        resource = {
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque", "immutable": True,
            "metadata": {"name": NAME, "namespace": "iam"},
            "data": {
                "MATRIX_SIGNING_KEY": base64.b64encode(seed.encode()).decode(),
                "MATRIX_SIGNING_KEY_ID": base64.b64encode(b"ed25519:gravitas1").decode(),
            },
        }
    key_id = validate(resource)
    if saved and material(saved) != material(resource):
        raise RuntimeError("The retained Matrix signing backup differs; refusing key rotation")

    # Persist the identity before its first cluster use. If cluster creation
    # fails, a retry uses this same seed and key ID instead of generating another.
    if not saved:
        retained = {k: resource[k] for k in ["apiVersion", "kind", "type", "data"]}
        retained["data"] = {k: resource["data"][k] for k in ["MATRIX_SIGNING_KEY", "MATRIX_SIGNING_KEY_ID"]}
        retained.update({"metadata": {"name": NAME, "namespace": "iam"}, "immutable": True})
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(retained, handle)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        resource = retained
    else:
        os.chmod(backup, 0o600)

    if existing is None:
        run(kube + ["create", "-f", "-"], json.dumps(resource))
    elif existing.get("immutable") is not True:
        run(kube + ["patch", "secret", NAME, "--type=merge", "-p", '{"immutable":true}'])
    return key_id


if __name__ == "__main__":
    try:
        root = Path(__file__).resolve().parents[2]
        key_id = provision(os.environ.get("KUBE_CONTEXT"), root / ".local/gravitas")
        print(f"Persistent Matrix signing identity ready: iam/{NAME}, {key_id}")
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        # Neither captured command output nor Secret objects enter diagnostics.
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        raise SystemExit(f"Matrix signing-key provisioning failed: {message}")
