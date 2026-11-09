import tempfile
import unittest
from pathlib import Path

from minimalize import strip_diagnostics

FIELD_BLOCK = (
    "\t// Read-loop diagnostics, not a wire capture or an application-success count.\n"
    "\tlastDataPacketNano atomic.Int64\n"
    "\tinboundDataPackets atomic.Uint64\n"
    "\tdataDecryptErrors  atomic.Uint64\n"
)
COUNTER_UPDATES = (
    "\t\tc.lastDataPacketNano.Store(int64(time.Since(start)))\n"
    "\t\tc.inboundDataPackets.Add(1)\n"
)
DECRYPT_ERROR_COUNTER = "\t\t\tc.dataDecryptErrors.Add(1)\n"
KEEPALIVE_DIAGNOSTICS = (
    "\t\t\t\tlastData := \"never\"\n"
    "\t\t\t\tif timestamp := c.lastDataPacketNano.Load(); timestamp != 0 {\n"
    "\t\t\t\t\tlastData = (time.Since(start) - time.Duration(timestamp)).Round(time.Second).String()\n"
    "\t\t\t\t}\n"
    "\t\t\t\treturn fmt.Errorf(\"%w: no packet received for %s (last-send=%s, last-data-packet=%s, inbound-data-packets=%d, data-decrypt-errors=%d)\",\n"
    "\t\t\t\t\tErrPingRestart, idle.Round(time.Second), c.SinceSend().Round(time.Second), lastData,\n"
    "\t\t\t\t\tc.inboundDataPackets.Load(), c.dataDecryptErrors.Load())\n"
)
KEEPALIVE_BASE = "\t\t\t\treturn fmt.Errorf(\"%w: no packet received for %s\", ErrPingRestart, idle.Round(time.Second))\n"


class MinimalSourceTests(unittest.TestCase):
    def fixture(self, root):
        client = root / "transport/openvpn/client.go"
        client.parent.mkdir(parents=True)
        client.write_text(
            "type Client struct {\n\tlastSendNano atomic.Int64\n"
            + FIELD_BLOCK + "}\n"
            + "func (c *Client) read() {\n" + COUNTER_UPDATES
            + "\t\tplain, err := c.decryptDataPacket(packet)\n"
            + "\t\tif err != nil {\n" + DECRYPT_ERROR_COUNTER
            + "\t\t\tcontinue\n\t\t}\n}\n"
            + "func operationContextError(ctx context.Context, fallback error) error {\n"
            + "\treturn fmt.Errorf(\"key exchange: %w\", fallback)\n}\n"
        )
        keepalive = root / "transport/openvpn/keepalive.go"
        keepalive.write_text("func keepaliveError() error {\n" + KEEPALIVE_DIAGNOSTICS + "}\n")
        diagnostics = root / "transport/openvpn/keepalive_diagnostics_test.go"
        diagnostics.write_text("package openvpn\n")
        (root / "transport/openvpn/keepalive_test.go").write_text("package openvpn\n")
        (root / "transport/openvpn/rekey_test.go").write_text(
            "func TestResetErrorContext() { wait server reset; key exchange; read key method 2 server record }\n"
        )

    def test_removes_counters_and_preserves_error_context(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            strip_diagnostics(root)
            client = (root / "transport/openvpn/client.go").read_text()
            keepalive = (root / "transport/openvpn/keepalive.go").read_text()
            self.assertNotIn(FIELD_BLOCK, client)
            self.assertNotIn(COUNTER_UPDATES, client)
            self.assertNotIn(DECRYPT_ERROR_COUNTER, client)
            self.assertNotIn("lastDataPacketNano", keepalive)
            self.assertIn(KEEPALIVE_BASE, keepalive)
            self.assertIn("key exchange: %w", client)
            self.assertIn("wait server reset", (root / "transport/openvpn/rekey_test.go").read_text())
            self.assertFalse((root / "transport/openvpn/keepalive_diagnostics_test.go").exists())
            self.assertTrue((root / "transport/openvpn/keepalive_test.go").exists())

    def test_refuses_unexpected_counter_references_before_mutating(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            extra = root / "transport/openvpn/other.go"
            extra.write_text("package openvpn\nvar _ = inboundDataPackets\n")
            before = (root / "transport/openvpn/client.go").read_text()
            with self.assertRaises(AssertionError):
                strip_diagnostics(root)
            self.assertEqual((root / "transport/openvpn/client.go").read_text(), before)
            self.assertTrue((root / "transport/openvpn/keepalive_diagnostics_test.go").exists())

    def test_requires_exact_counter_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            client = root / "transport/openvpn/client.go"
            client.write_text("type Client struct {}\n")
            before = client.read_text()
            with self.assertRaises(AssertionError):
                strip_diagnostics(root)
            self.assertEqual(client.read_text(), before)
            self.assertTrue((root / "transport/openvpn/keepalive_diagnostics_test.go").exists())

    def test_requires_diagnostic_test_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            diagnostics = root / "transport/openvpn/keepalive_diagnostics_test.go"
            diagnostics.unlink()
            before = (root / "transport/openvpn/client.go").read_text()
            with self.assertRaises(AssertionError):
                strip_diagnostics(root)
            self.assertEqual((root / "transport/openvpn/client.go").read_text(), before)


    def test_ci_pins_and_compares_the_exact_minimal_candidate(self):
        script = Path(__file__).with_name("minimal-ci.sh").read_text()
        self.assertIn("sha=c38b5ba746ffcf6113222f72275b2cd4542a9bc8", script)
        self.assertIn("sha=76b7ec3ff9854d32cb3964403c065928ecdc9dd6", script)
        self.assertIn("go1.24.0.linux-amd64.tar.gz", script)
        self.assertIn("dea9ca38a0b852a74e81c26134671af7c0fbe65d81b0dc1c5bfe22cf7d4c8858", script)
        self.assertIn("Verified Go 1.24.0 build", script)
        self.assertIn('python3 "$HERE/minimalize.py" "$work/full"', script)
        self.assertIn('diff -ru --exclude=.git "$work/full" "$work/minimal"', script)
        self.assertNotIn('python3 "$HERE/minimalize.py" "$work/minimal"', script)


if __name__ == "__main__":
    unittest.main()
