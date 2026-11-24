"""CLI validation of subnet routes before policy or state is written."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


VPN_DIR = Path(__file__).resolve().parents[1]


class PolicyCIDRTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = self.root / "policy.hujson"
        self.config = self.root / "headscale-config.yaml"
        self.state = self.root / "managed.json"
        self.policy.write_text((VPN_DIR / "headscale/policy.hujson").read_text())
        self.config.write_text((VPN_DIR / "headscale/config.yaml").read_text())

    def run_policy(self, command="init", org="acme", *cidrs):
        argv = [sys.executable, str(VPN_DIR / "policy.py"), command,
                "--policy", str(self.policy), "--headscale-config", str(self.config),
                "--state", str(self.state), "--org", org]
        for cidr in cidrs:
            argv.extend(("--lan-cidr", cidr))
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def assert_rejected(self, result, message):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(message, result.stderr)

    def test_rejects_invalid_and_non_unicast_cli_cidrs_without_writing(self):
        original = self.policy.read_text()
        cases = {
            "192.168.1.1/24": "invalid LAN CIDR",
            "fd7a:115c:a1e0::/48": "must be IPv4",
            "0.0.0.0/0": "exit-node route",
            "0.0.0.0/8": "overlaps unsuitable LAN network",
            "127.0.0.0/8": "overlaps unsuitable LAN network",
            "169.254.0.0/16": "overlaps unsuitable LAN network",
            "224.0.0.0/4": "overlaps unsuitable LAN network",
            "240.0.0.0/4": "overlaps unsuitable LAN network",
            "100.64.0.0/10": "overlaps Headscale tailnet",
            "100.64.1.0/24": "overlaps Headscale tailnet",
            "100.0.0.0/8": "overlaps Headscale tailnet",
        }
        for cidr, message in cases.items():
            with self.subTest(cidr=cidr):
                self.assert_rejected(self.run_policy("init", "acme", cidr), message)
                self.assertEqual(self.policy.read_text(), original)
                self.assertFalse(self.state.exists())

    def test_uses_configured_tailnet_prefix_and_accepts_adjacent_lan(self):
        config = self.config
        config.write_text(config.read_text().replace("v4: 100.64.0.0/10", "v4: 10.80.0.0/16"))
        self.assert_rejected(self.run_policy("init", "acme", "10.80.2.0/24"), "overlaps Headscale tailnet 10.80.0.0/16")
        self.assert_rejected(self.run_policy("init", "acme", "100.64.1.0/24"), "overlaps unsuitable LAN network 100.64.0.0/10")
        result = self.run_policy("init", "acme", "10.79.0.0/16", "10.81.0.0/16")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["orgs"][0]["lan_cidrs"], ["10.79.0.0/16", "10.81.0.0/16"])

    def test_accepts_literal_quoted_v4_scalar(self):
        self.config.write_text(self.config.read_text().replace(
            "v4: 100.64.0.0/10", "v4: '100.64.0.0/10' # tailnet"))
        result = self.run_policy("init", "acme", "10.20.0.0/16")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_unsupported_or_ambiguous_config_without_writing(self):
        original = self.policy.read_text()
        stock = self.config.read_text()
        cases = (
            stock.replace("prefixes:\n  v4: 100.64.0.0/10", "prefixes: {v4: 100.64.0.0/10}"),
            stock.replace("prefixes:\n  v4: 100.64.0.0/10", "prefixes:\n  v4: 100.64.0.0/10\n  v4: 10.0.0.0/8"),
            stock + "\nprefixes:\n  v4: 10.0.0.0/8\n",
            stock.replace("v4: 100.64.0.0/10", "v4: ${TAILNET_CIDR}"),
        )
        for config in cases:
            with self.subTest(config=config[-90:]):
                self.config.write_text(config)
                self.assert_rejected(self.run_policy("init", "acme", "10.20.0.0/16"), "unsupported Headscale")
                self.assertEqual(self.policy.read_text(), original)
                self.assertFalse(self.state.exists())

    def test_rejects_cross_tenant_overlap_and_accepts_disjoint_and_same_tenant(self):
        self.assertEqual(self.run_policy("init", "acme", "10.20.0.0/16").returncode, 0)
        before = self.policy.read_text(), self.state.read_text()
        self.assert_rejected(self.run_policy("add-tenant", "globex", "10.20.1.0/24"), "overlaps 10.20.0.0/16 for 'acme'")
        self.assert_rejected(self.run_policy("add-tenant", "globex", "10.0.0.0/8"), "overlaps 10.20.0.0/16 for 'acme'")
        self.assertEqual((self.policy.read_text(), self.state.read_text()), before)
        self.assertEqual(self.run_policy("init", "acme", "10.20.1.0/24", "10.20.0.0/16").returncode, 0)
        result = self.run_policy("add-tenant", "globex", "10.21.0.0/16")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["orgs"][1]["lan_cidrs"], ["10.21.0.0/16"])

    def test_rejects_invalid_persisted_routes_on_rerun(self):
        self.assertEqual(self.run_policy("init", "acme", "10.20.0.0/16").returncode, 0)
        self.assertEqual(self.run_policy("add-tenant", "globex", "10.21.0.0/16").returncode, 0)
        for cidr, message in (("100.64.1.0/24", "overlaps Headscale tailnet"),
                              ("224.1.0.0/16", "overlaps unsuitable LAN network"),
                              ("10.20.1.0/24", "overlaps 10.20.0.0/16 for 'acme'")):
            with self.subTest(cidr=cidr):
                state = json.loads(self.state.read_text())
                state["orgs"][1]["lan_cidrs"] = [cidr]
                self.state.write_text(json.dumps(state))
                before = self.policy.read_text(), self.state.read_text()
                self.assert_rejected(self.run_policy("init", "acme"), message)
                self.assertEqual((self.policy.read_text(), self.state.read_text()), before)

    def test_reconstructed_routes_are_validated_without_state_file(self):
        self.assertEqual(self.run_policy("init", "acme", "10.20.0.0/16").returncode, 0)
        self.state.unlink()
        config = self.config
        config.write_text(config.read_text().replace("v4: 100.64.0.0/10", "v4: 10.0.0.0/8"))
        before = self.policy.read_text()
        self.assert_rejected(self.run_policy("init", "acme"), "overlaps Headscale tailnet 10.0.0.0/8")
        self.assertEqual(self.policy.read_text(), before)
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
