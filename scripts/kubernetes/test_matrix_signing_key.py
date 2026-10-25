import base64
import json
import stat
import tempfile
import unittest
from pathlib import Path

from matrix_signing_key import SERVER, provision, validate


class Cluster:
    def __init__(self):
        self.server = SERVER
        self.secret = None
        self.legacy = None
        self.mutations = []

    def run(self, args, body=None):
        if "config" in args:
            return self.server
        if "get" in args:
            if "iam-secrets" in args:
                return json.dumps(self.legacy) if self.legacy else ""
            return json.dumps(self.secret) if self.secret else ""
        if "create" in args:
            assert self.secret is None
            self.secret = json.loads(body)
        elif "patch" in args:
            self.secret["immutable"] = True
        else:
            raise AssertionError(args)
        self.mutations.append(args)
        return ""


class SigningKeyTest(unittest.TestCase):
    def test_repeated_setup_retains_one_identity_and_owner_only_backup(self):
        cluster = Cluster()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private"
            self.assertEqual(provision("test", path, cluster.run), "ed25519:gravitas1")
            first = cluster.secret["data"].copy()
            self.assertEqual(provision("test", path, cluster.run), "ed25519:gravitas1")
            self.assertEqual(cluster.secret["data"], first)
            self.assertEqual(len(cluster.mutations), 1)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            backup = path / "matrix-signing-key.json"
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertEqual(json.loads(backup.read_text())["data"], first)
            validate(cluster.secret)

    def test_recreation_restores_the_saved_seed_instead_of_rotating_the_same_key_id(self):
        cluster = Cluster()
        with tempfile.TemporaryDirectory() as directory:
            provision("test", directory, cluster.run)
            first = cluster.secret["data"].copy()
            cluster.secret = None
            provision("test", directory, cluster.run)
            self.assertEqual(cluster.secret["data"], first)

    def test_first_setup_imports_an_existing_identity_without_copying_iam_secrets(self):
        cluster = Cluster()
        encoded = base64.b64encode(b"x" * 32)
        original = base64.b64encode(encoded).decode()
        cluster.legacy = {"data": {"MATRIX_SIGNING_KEY": original, "JWT_SECRET": "unrelated"}}
        with tempfile.TemporaryDirectory() as directory:
            provision("test", directory, cluster.run)
            self.assertEqual(cluster.secret["data"]["MATRIX_SIGNING_KEY"], original)
            self.assertEqual(set(cluster.secret["data"]), {"MATRIX_SIGNING_KEY", "MATRIX_SIGNING_KEY_ID"})
            backup = json.loads((Path(directory) / "matrix-signing-key.json").read_text())
            self.assertNotIn("JWT_SECRET", backup["data"])

    def test_another_cluster_is_never_mutated(self):
        cluster = Cluster()
        cluster.server = "https://another.example"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                provision("test", directory, cluster.run)
            self.assertEqual(cluster.mutations, [])
            self.assertFalse((Path(directory) / "matrix-signing-key.json").exists())

    def test_a_conflicting_backup_never_replaces_the_live_key(self):
        cluster = Cluster()
        with tempfile.TemporaryDirectory() as directory:
            provision("test", directory, cluster.run)
            live = cluster.secret["data"].copy()
            backup = Path(directory) / "matrix-signing-key.json"
            saved = json.loads(backup.read_text())
            encoded = base64.b64encode(b"x" * 32)
            saved["data"]["MATRIX_SIGNING_KEY"] = base64.b64encode(encoded).decode()
            backup.write_text(json.dumps(saved))
            with self.assertRaises(RuntimeError):
                provision("test", directory, cluster.run)
            self.assertEqual(cluster.secret["data"], live)
            self.assertEqual(len(cluster.mutations), 1)

    def test_an_existing_mutable_identity_is_frozen_without_changing_its_material(self):
        cluster = Cluster()
        with tempfile.TemporaryDirectory() as directory:
            provision("test", directory, cluster.run)
            first = cluster.secret["data"].copy()
            cluster.secret["immutable"] = False
            provision("test", directory, cluster.run)
            self.assertTrue(cluster.secret["immutable"])
            self.assertEqual(cluster.secret["data"], first)


if __name__ == "__main__":
    unittest.main()
