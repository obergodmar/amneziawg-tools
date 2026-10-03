#!/usr/bin/env python3
"""Exercise Darwin awg-quick without root, a tunnel, or macOS.

Usage: python3 tests/darwin-quick.py [path/to/darwin.bash]
Requires Python 3 and Bash 4+ (set BASH to its path on macOS).
"""

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest


SOURCE = (
    Path(sys.argv.pop(1))
    if len(sys.argv) > 1
    else Path(__file__).resolve().parents[1] / "src/wg-quick/darwin.bash"
)


class DarwinQuickTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awg-darwin-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run = self.root / "amneziawg"
        self.run.mkdir()
        self.other = self.root / "wireguard"
        self.other.mkdir()
        self.name = self.run / "mesh.name"
        self.name.write_text("utun42\n")
        (self.other / "mesh.name").write_text("unrelated\n")
        (self.other / "utun42.sock").write_text("unrelated\n")
        self.sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(self.sock.close)
        self.sock.bind(str(self.run / "utun42.sock"))
        for path in (self.name, self.run / "utun42.sock"):
            os.utime(path, (1000000, 1000000))
        # Load functions without dispatching a privileged up/down operation.
        source = SOURCE.read_text().split("# ~~ function override insertion point ~~")[
            0
        ]
        source = source.replace("/var/run/", str(self.root) + "/")
        self.script = self.root / "functions.bash"
        self.script.write_text(source)

    def invoke(self, commands):
        harness = (
            r"""
source "$TEST_SCRIPT"
INTERFACE=mesh
REAL_INTERFACE=utun42
wg() { echo 'Unexpected WireGuard CLI call' >&2; return 99; }
awg() {
    printf '%s\n' "$*" >> "$TEST_LOG"
    case "$*" in
        'show interfaces') echo utun42 ;;
        'show utun42 endpoints') echo 'peer 192.0.2.1:51820' ;;
        'setconf utun42 '*) cat "$3" > "$TEST_CONFIG" ;;
        *) return 98 ;;
    esac
}
stat() {
    [[ $1 == -f && $2 == %m ]] || return 97
    "$TEST_PYTHON" -c 'import os,sys; print(int(os.stat(sys.argv[1]).st_mtime))' "$3"
}
"""
            + commands
        )
        env = os.environ | {
            "TEST_SCRIPT": str(self.script),
            "TEST_LOG": str(self.root / "calls"),
            "TEST_CONFIG": str(self.root / "config"),
            "TEST_PYTHON": sys.executable,
        }
        result = subprocess.run(
            [os.environ.get("BASH", "bash"), "-c", harness],
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_discovers_matching_awg_socket_and_name(self):
        self.invoke(
            'REAL_INTERFACE=""; get_real_interface; [[ $REAL_INTERFACE == utun42 ]]'
        )
        self.assertIn("show interfaces", (self.root / "calls").read_text())

    def test_rejects_stale_interface_name(self):
        os.utime(self.name, (999900, 999900))
        self.invoke('REAL_INTERFACE=""; ! get_real_interface; [[ -z $REAL_INTERFACE ]]')

    def test_configures_amnezia_parameters_with_awg(self):
        self.invoke("WG_CONFIG=$'[Interface]\\nJc = 4'; set_config")
        self.assertEqual((self.root / "config").read_text(), "[Interface]\nJc = 4\n")

    def test_reads_endpoints_with_awg(self):
        self.invoke("collect_endpoints; [[ ${ENDPOINTS[*]} == 192.0.2.1 ]]")

    def test_down_removes_only_amnezia_runtime_files(self):
        self.invoke("cmd_down")
        self.assertFalse(self.name.exists())
        self.assertFalse((self.run / "utun42.sock").exists())
        self.assertEqual((self.other / "mesh.name").read_text(), "unrelated\n")
        self.assertEqual((self.other / "utun42.sock").read_text(), "unrelated\n")


if __name__ == "__main__":
    unittest.main()
