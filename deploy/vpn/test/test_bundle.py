#!/usr/bin/env python3
"""Bundle tree and dotenv checks. These call bundle.py, not a mock of it."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "bundle.py"


def run_bundle(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(BUNDLE), *args], capture_output=True, text=True)


def seed(root: Path) -> None:
    files = {
        "manifest.json": "{}\n",
        "headscale/db.sqlite": "sqlite-bytes",
        "headscale/noise_private.key": "noise",
        "state/enroll/config.json": "{}\n",
        "state/enroll/headscale.apikey": "hskey-api-test",
        "state/headplane/cookie_secret": "0123456789abcdef0123456789abcdef",
        "state/dotenv": "COMPOSE_PROJECT_NAME=idoris-vpn-r2d\nHEADPLANE_PORT=3000\n",
        "state/headscale/managed.json": "{}\n",
        "state/headscale/config.yaml": "server_url: https://vpn.example.test\n",
        "state/headscale/policy.hujson": "{}\n",
        "state/headplane/config.yaml": "server:\n  base_url: http://127.0.0.1:3000\n",
        "state/compose.yaml": "name: idoris-vpn\n",
        "admin-mode": "mode=published\n",
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


class BundleTreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "bundle"
        self.root.mkdir()
        seed(self.root)

    def test_accepts_a_regular_tree(self) -> None:
        got = run_bundle("tree", str(self.root))
        self.assertEqual(got.returncode, 0, got.stderr)
        info = json.loads(got.stdout)
        self.assertEqual(info["dotenv"]["COMPOSE_PROJECT_NAME"], "idoris-vpn-r2d")
        self.assertEqual(info["admin_mode"], "published")

    def test_rejects_symlink(self) -> None:
        os.symlink("/etc/passwd", self.root / "state" / "escape")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("symlink", got.stderr)

    def test_rejects_fifo(self) -> None:
        fifo = self.root / "state" / "pipe"
        os.mkfifo(fifo)
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("special", got.stderr)

    def test_rejects_empty_derp_key(self) -> None:
        (self.root / "headscale" / "derp_server_private.key").write_text("")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("DERP", got.stderr)

    def test_rejects_image_override_and_unknown_key(self) -> None:
        dotenv = self.root / "state" / "dotenv"
        dotenv.write_text(dotenv.read_text() + "ENROLL_IMAGE=evil:latest\n")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("image override", got.stderr)
        dotenv.write_text("COMPOSE_PROJECT_NAME=idoris-vpn-r2d\nNOT_A_KEY=1\n")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("not allowed", got.stderr)

    def test_token_labels_regular_file_is_ignored(self) -> None:
        path = self.root / "state" / "enroll" / "token-labels.json"
        path.write_text("{}\n")
        got = run_bundle("tree", str(self.root))
        self.assertEqual(got.returncode, 0, got.stderr)
        info = json.loads(got.stdout)
        self.assertIn("state/enroll/token-labels.json", info["ignored"])

    def test_token_labels_symlink_is_rejected(self) -> None:
        os.symlink("/tmp", self.root / "state" / "enroll" / "token-labels.json")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("symlink", got.stderr)

    def test_rejects_uid_zero(self) -> None:
        (self.root / "state" / "dotenv").write_text(
            "COMPOSE_PROJECT_NAME=idoris-vpn-r2d\nENROLL_UID=0\nENROLL_GID=65532\n"
        )
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("ENROLL_UID", got.stderr)


class DotenvTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(
                "\n# comment\nHEADPLANE_BIND=127.0.0.1\n"
                "HEADPLANE_ACCESS=tunnel\nENROLL_PUBLIC_URL=https://enroll.example.test\n"
            )
            name = fh.name
        self.addCleanup(lambda: os.unlink(name))
        got = run_bundle("dotenv", name)
        self.assertEqual(got.returncode, 0, got.stderr)
        info = json.loads(got.stdout)
        self.assertEqual(info["HEADPLANE_BIND"], "127.0.0.1")
        self.assertEqual(info["HEADPLANE_ACCESS"], "tunnel")


def write_tar(path: Path, members: list[tuple[str, bytes | None]]) -> None:
    with tarfile.open(path, "w") as handle:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                info.size = 0
                handle.addfile(info)
            else:
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))


class SidecarArchiveTest(unittest.TestCase):
    """sidecar/state.tar is optional. When present it is an identity archive."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="idoris-bundle-sidecar-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "bundle"
        self.root.mkdir()
        seed(self.root)
        self.archive = self.root / "sidecar" / "state.tar"
        self.archive.parent.mkdir(parents=True)

    def test_tree_without_sidecar_archive_stays_valid(self) -> None:
        self.archive.parent.rmdir()
        got = run_bundle("tree", str(self.root))
        self.assertEqual(got.returncode, 0, got.stderr)

    def test_rejects_archive_without_regular_identity(self) -> None:
        write_tar(self.archive, [("notes.txt", b"other\n")])
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("tailscaled.state", got.stderr)
        direct = run_bundle("sidecar-tar", str(self.archive))
        self.assertNotEqual(direct.returncode, 0)
        self.assertIn("tailscaled.state", direct.stderr)

    def test_rejects_lookalike_and_directory_members(self) -> None:
        write_tar(self.archive, [("tailscaled.state.bak", b"nope\n")])
        got = run_bundle("sidecar-tar", str(self.archive))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("tailscaled.state", got.stderr)
        write_tar(self.archive, [("tailscaled.state", None)])
        got = run_bundle("sidecar-tar", str(self.archive))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("tailscaled.state", got.stderr)

    def test_rejects_lstrip_lookalikes_and_accepts_dot_slash(self) -> None:
        # str.lstrip("./") strips every leading "." and "/", so these names
        # used to count as tailscaled.state and validate_tar would allow a
        # destructive restore.
        for name in (
            ".tailscaled.state",
            "./..tailscaled.state",
            "./.tailscaled.state",
        ):
            write_tar(self.archive, [(name, b"lookalike\n")])
            got = run_bundle("sidecar-tar", str(self.archive))
            self.assertNotEqual(got.returncode, 0, name)
            self.assertIn("no regular tailscaled.state", got.stderr, name)
        write_tar(self.archive, [("./tailscaled.state", b"node-key\n")])
        got = run_bundle("sidecar-tar", str(self.archive))
        self.assertEqual(got.returncode, 0, got.stderr)
        write_tar(self.archive, [("./sub/tailscaled.state", b"node-key\n")])
        nested = run_bundle("sidecar-tar", str(self.archive))
        self.assertEqual(nested.returncode, 0, nested.stderr)

    def test_accepts_regular_nested_and_empty_identity(self) -> None:
        write_tar(
            self.archive,
            [("tailscaled.state", b"node-key\n"), ("notes.txt", b"n\n")],
        )
        got = run_bundle("tree", str(self.root))
        self.assertEqual(got.returncode, 0, got.stderr)
        direct = run_bundle("sidecar-tar", str(self.archive))
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertEqual(direct.stdout, "")
        write_tar(self.archive, [("var/lib/tailscale/tailscaled.state", b"")])
        nested = run_bundle("sidecar-tar", str(self.archive))
        self.assertEqual(nested.returncode, 0, nested.stderr)

    def test_rejects_truncated_identity_archive(self) -> None:
        raw = self.archive.with_suffix(".full.tar")
        payload = b"R" * 20000
        write_tar(raw, [("tailscaled.state", payload)])
        self.archive.write_bytes(raw.read_bytes()[:512 + 100])
        got = run_bundle("sidecar-tar", str(self.archive))
        self.assertNotEqual(got.returncode, 0)


if __name__ == "__main__":
    unittest.main()
