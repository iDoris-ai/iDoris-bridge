#!/usr/bin/env python3
"""Unit checks for deploy/vpn/enroll_lock.py. No Docker."""

from __future__ import annotations

import contextlib
import errno
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from enroll_lock import LeaveUnchanged, _replace, locked_update, merge_bootstrap_rows  # noqa: E402


def _config(digest: str) -> dict:
    return {
        "control_url": "https://vpn.example.org",
        "tenants": [{
            "name": "office",
            "headscale_user_id": "1",
            "token_hashes": [{"hash": digest, "label": "bootstrap-office"}],
        }],
    }


class LockedUpdateTest(unittest.TestCase):
    def test_leave_unchanged_keeps_bytes_and_inode(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "config.json"
        path.write_text('{"control_url":"https://vpn.example.org"}\n')
        before = path.stat()

        def mutate(cfg):
            cfg["control_url"] = "https://r4o.example"
            return LeaveUnchanged()

        locked_update(path, mutate)
        after = path.stat()
        self.assertEqual(path.read_text(), '{"control_url":"https://vpn.example.org"}\n')
        self.assertEqual(after.st_ino, before.st_ino)
        lock = Path(str(path) + ".lock")
        self.assertTrue(lock.is_file())
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_rewrite_preserves_mode_and_leaves_no_temp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "config.json"
        path.write_text("{}\n")
        os.chmod(path, 0o640)

        def mutate(cfg):
            cfg["control_url"] = "https://r4o.example"
            return cfg

        locked_update(path, mutate)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertEqual(json.loads(path.read_text())["control_url"], "https://r4o.example")
        leftovers = [name for name in os.listdir(tmp.name) if name.startswith(".enroll-")]
        self.assertEqual(leftovers, [])

    def test_symlink_is_refused(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        target = directory / "real.json"
        target.write_text("{}\n")
        link = directory / "config.json"
        link.symlink_to(target)

        def mutate(cfg):
            return {"control_url": "https://r4o.example"}

        with self.assertRaises(OSError):
            locked_update(link, mutate)
        self.assertEqual(target.read_text(), "{}\n")

    def test_merge_keeps_loaded_hashes(self) -> None:
        digest = "ab" * 32
        extra = "cd" * 32
        cfg = _config(digest)
        merged = merge_bootstrap_rows(
            cfg,
            "https://vpn.example.org",
            "extra|2|tag:member||10m|%s|member\n" % extra,
        )
        self.assertEqual(merged["tenants"][0]["token_hashes"][0]["hash"], digest)
        self.assertEqual(merged["tenants"][1]["name"], "extra")
        self.assertEqual(merged["tenants"][1]["token_hashes"][0]["hash"], extra)
        self.assertEqual(merged["control_url"], "https://vpn.example.org")


_REVOKED = "ab" * 32
_KEPT = "cd" * 32


def _document(url, hashes):
    body = {
        "control_url": url,
        "tenants": [{
            "name": "acme",
            "headscale_user_id": "1",
            "token_hashes": list(hashes),
        }],
    }
    return (json.dumps(body, indent=2) + "\n").encode("utf-8")


@contextlib.contextmanager
def _patched_os(**names):
    saved = {name: getattr(os, name) for name in names}
    try:
        for name, fn in names.items():
            setattr(os, name, fn)
        yield
    finally:
        for name, fn in saved.items():
            setattr(os, name, fn)


class ReplaceDurabilityTest(unittest.TestCase):
    """The Python writer must not publish a config whose data is not durable.

    Go restores <config>.bak only when the live file is empty. That backup
    still contains a hash a completed revoke already removed. These tests
    model a crash that drops bytes not covered by fsync, and they inject
    fsync errors. They do not claim a later truncate of a finished file is
    safe: Go still restores the stale backup in that case.
    """

    def _live_and_stale_bak(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "config.json"
        path.write_bytes(_document("https://vpn.example.org", [_KEPT]))
        os.chmod(path, 0o640)
        bak = Path(str(path) + ".bak")
        bak.write_bytes(_document("https://vpn.example.org", [_REVOKED, _KEPT]))
        os.chmod(bak, 0o640)
        return path, bak

    def test_crash_without_temp_fsync_does_not_resurrect_revoked_hash(self) -> None:
        # Model the rename crash window: a replaced file whose temp inode was
        # not fsynced reads back empty. Go would then copy .bak onto it.
        path, bak = self._live_and_stale_bak()
        synced = set()
        real_fsync = os.fsync
        real_replace = os.replace

        def fsync(fd):
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode):
                synced.add((st.st_dev, st.st_ino))
            return real_fsync(fd)

        def replace(src, dst):
            st = os.stat(src)
            real_replace(src, dst)
            if (st.st_dev, st.st_ino) not in synced:
                os.truncate(dst, 0)

        def mutate(cfg):
            cfg["control_url"] = "https://replaced.example"
            return cfg

        with _patched_os(fsync=fsync, replace=replace):
            locked_update(path, mutate)
        live = path.read_bytes()
        if live == b"":
            live = bak.read_bytes()
            path.write_bytes(live)
        self.assertIn(b"https://replaced.example", live)
        self.assertNotIn(_REVOKED.encode("ascii"), live)
        self.assertIn(_KEPT.encode("ascii"), live)
        self.assertEqual(bak.read_bytes(), _document("https://vpn.example.org", [_REVOKED, _KEPT]))

    def test_metadata_fsync_replace_directory_order(self) -> None:
        path, _bak = self._live_and_stale_bak()
        before = path.stat()
        events = []
        seen = {}
        real_fchmod = os.fchmod
        real_fsync = os.fsync
        real_replace = os.replace
        real_geteuid = os.geteuid

        def fchmod(fd, mode):
            events.append(("fchmod", os.fstat(fd).st_ino))
            return real_fchmod(fd, mode)

        def fchown(fd, uid, gid):
            events.append(("fchown", os.fstat(fd).st_ino))
            seen["owner"] = (uid, gid)
            return None

        def geteuid():
            return 0

        def fsync(fd):
            st = os.fstat(fd)
            kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
            events.append(("fsync-" + kind, st.st_ino))
            return real_fsync(fd)

        def replace(src, dst):
            events.append(("replace", os.stat(src).st_ino))
            return real_replace(src, dst)

        def mutate(cfg):
            cfg["control_url"] = "https://replaced.example"
            return cfg

        with _patched_os(fchmod=fchmod, fchown=fchown, geteuid=geteuid, fsync=fsync, replace=replace):
            locked_update(path, mutate)
        file_syncs = [i for i, ev in enumerate(events) if ev[0] == "fsync-file"]
        self.assertEqual(len(file_syncs), 1)
        sync_at = file_syncs[0]
        ino = events[sync_at][1]
        self.assertTrue(any(ev == ("fchmod", ino) for ev in events[:sync_at]))
        self.assertTrue(any(ev == ("fchown", ino) for ev in events[:sync_at]))
        replaces = [i for i, ev in enumerate(events) if ev[0] == "replace"]
        self.assertEqual(len(replaces), 1)
        self.assertGreater(replaces[0], sync_at)
        self.assertEqual(events[replaces[0]][1], ino)
        dir_syncs = [i for i, ev in enumerate(events) if ev[0] == "fsync-dir"]
        self.assertEqual(len(dir_syncs), 1)
        self.assertGreater(dir_syncs[0], replaces[0])
        self.assertEqual(seen["owner"], (before.st_uid, before.st_gid))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertNotIn(_REVOKED.encode("ascii"), path.read_bytes())

    def test_temp_fsync_error_does_not_publish(self) -> None:
        path, bak = self._live_and_stale_bak()
        original = path.read_bytes()
        before = path.stat().st_ino
        replaced = []
        real_replace = os.replace
        real_fsync = os.fsync

        def replace(src, dst):
            replaced.append(dst)
            return real_replace(src, dst)

        def fsync_file_fails(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "injected temp fsync failure")
            return real_fsync(fd)

        def mutate(cfg):
            cfg["control_url"] = "https://replaced.example"
            return cfg

        with _patched_os(fsync=fsync_file_fails, replace=replace):
            with self.assertRaises(OSError) as caught:
                locked_update(path, mutate)
        self.assertEqual(caught.exception.errno, errno.EIO)
        self.assertEqual(replaced, [])
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.stat().st_ino, before)
        self.assertEqual(bak.read_bytes(), _document("https://vpn.example.org", [_REVOKED, _KEPT]))
        leftovers = [name for name in os.listdir(path.parent) if name.startswith(".enroll-")]
        self.assertEqual(leftovers, [])

    def test_directory_fsync_error_propagates_without_rollback(self) -> None:
        path, bak = self._live_and_stale_bak()
        before = path.stat().st_ino
        real_fsync = os.fsync

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "injected directory fsync failure")
            return real_fsync(fd)

        def mutate(cfg):
            cfg["control_url"] = "https://replaced.example"
            return cfg

        with _patched_os(fsync=fsync):
            with self.assertRaises(OSError) as caught:
                locked_update(path, mutate)
        self.assertEqual(caught.exception.errno, errno.EIO)
        self.assertIn("was replaced", str(caught.exception))
        self.assertNotEqual(path.stat().st_ino, before)
        self.assertIn(b"https://replaced.example", path.read_bytes())
        self.assertNotIn(_REVOKED.encode("ascii"), path.read_bytes())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertEqual(bak.read_bytes(), _document("https://vpn.example.org", [_REVOKED, _KEPT]))

    def test_replace_error_leaves_the_live_file(self) -> None:
        path, bak = self._live_and_stale_bak()
        original = path.read_bytes()
        before = path.stat().st_ino

        def replace(src, dst):
            raise OSError(errno.EIO, "injected replace failure")

        def mutate(cfg):
            cfg["control_url"] = "https://replaced.example"
            return cfg

        with _patched_os(replace=replace):
            with self.assertRaises(OSError):
                locked_update(path, mutate)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.stat().st_ino, before)
        self.assertEqual(bak.read_bytes(), _document("https://vpn.example.org", [_REVOKED, _KEPT]))
        leftovers = [name for name in os.listdir(path.parent) if name.startswith(".enroll-")]
        self.assertEqual(leftovers, [])

    def test_empty_payload_is_not_published(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "config.json"
        path.write_bytes(b"keep\n")
        os.chmod(path, 0o640)
        before = path.stat().st_ino
        with self.assertRaises(ValueError):
            _replace(path, b"", 0o640, None)
        self.assertEqual(path.read_bytes(), b"keep\n")
        self.assertEqual(path.stat().st_ino, before)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
