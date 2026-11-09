from pathlib import Path
import sys

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
KEEPALIVE_BASE = (
    "\t\t\t\treturn fmt.Errorf(\"%w: no packet received for %s\", "
    "ErrPingRestart, idle.Round(time.Second))\n"
)
COUNTERS = ("lastDataPacketNano", "inboundDataPackets", "dataDecryptErrors")
CLIENT = Path("transport/openvpn/client.go")
KEEPALIVE = Path("transport/openvpn/keepalive.go")
DIAGNOSTICS_TEST = Path("transport/openvpn/keepalive_diagnostics_test.go")


def strip_diagnostics(root: Path) -> None:
    root = Path(root)
    client = root / CLIENT
    keepalive = root / KEEPALIVE
    diagnostics_test = root / DIAGNOSTICS_TEST
    if not client.is_file() or not keepalive.is_file() or not diagnostics_test.is_file():
        raise AssertionError("expected client, keepalive and diagnostics-only test sources")

    source = client.read_text()
    keepalive_source = keepalive.read_text()
    for label, text, fragment in (
        ("diagnostic field block", source, FIELD_BLOCK),
        ("read-loop counters", source, COUNTER_UPDATES),
        ("decrypt-error counter", source, DECRYPT_ERROR_COUNTER),
        ("keepalive diagnostic message", keepalive_source, KEEPALIVE_DIAGNOSTICS),
    ):
        if text.count(fragment) != 1:
            raise AssertionError(f"{label} must match exactly once")

    for path in root.rglob("*.go"):
        if path in (client, keepalive, diagnostics_test):
            continue
        if any(counter in path.read_text(errors="strict") for counter in COUNTERS):
            raise AssertionError(f"unexpected diagnostic counter reference in {path.relative_to(root)}")

    minimal_client = source.replace(FIELD_BLOCK, "", 1)
    minimal_client = minimal_client.replace(COUNTER_UPDATES, "", 1)
    minimal_client = minimal_client.replace(DECRYPT_ERROR_COUNTER, "", 1)
    minimal_keepalive = keepalive_source.replace(KEEPALIVE_DIAGNOSTICS, KEEPALIVE_BASE, 1)
    if any(counter in minimal_client or counter in minimal_keepalive for counter in COUNTERS):
        raise AssertionError("diagnostic counter remains after structural removal")

    client.write_text(minimal_client)
    keepalive.write_text(minimal_keepalive)
    diagnostics_test.unlink()
    for path in root.rglob("*.go"):
        if any(counter in path.read_text(errors="strict") for counter in COUNTERS):
            raise AssertionError(f"diagnostic counter remains in {path.relative_to(root)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: minimalize.py SOURCE_ROOT")
    strip_diagnostics(Path(sys.argv[1]))
    print("Removed optional read-loop diagnostic counters; retained error context", flush=True)
