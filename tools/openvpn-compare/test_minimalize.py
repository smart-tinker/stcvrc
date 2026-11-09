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


class MinimalSourceTests(unittest.TestCase):
    def fixture(self, root):
        client = root / "transport/openvpn/client.go"
        client.parent.mkdir(parents=True)
        client.write_text("type Client struct {\n\tlastSendNano atomic.Int64\n" + FIELD_BLOCK + "}\n")
        diagnostics = root / "transport/openvpn/keepalive_diagnostics_test.go"
        diagnostics.write_text("package openvpn\n")
        (root / "transport/openvpn/keepalive_test.go").write_text("package openvpn\n")

    def test_removes_only_diagnostic_fields_and_test(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            strip_diagnostics(root)
            client = (root / "transport/openvpn/client.go").read_text()
            self.assertNotIn(FIELD_BLOCK, client)
            self.assertIn("lastSendNano", client)
            self.assertFalse((root / "transport/openvpn/keepalive_diagnostics_test.go").exists())
            self.assertTrue((root / "transport/openvpn/keepalive_test.go").exists())

    def test_refuses_diagnostic_counter_references_outside_removed_test(self):
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

    def test_requires_exact_field_block(self):
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


if __name__ == "__main__":
    unittest.main()
