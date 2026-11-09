from pathlib import Path
import sys

FIELD_BLOCK = (
    "\t// Read-loop diagnostics, not a wire capture or an application-success count.\n"
    "\tlastDataPacketNano atomic.Int64\n"
    "\tinboundDataPackets atomic.Uint64\n"
    "\tdataDecryptErrors  atomic.Uint64\n"
)
COUNTERS = ("lastDataPacketNano", "inboundDataPackets", "dataDecryptErrors")
DIAGNOSTICS_TEST = Path("transport/openvpn/keepalive_diagnostics_test.go")
CLIENT = Path("transport/openvpn/client.go")


def strip_diagnostics(root: Path) -> None:
    root = Path(root)
    client = root / CLIENT
    diagnostics_test = root / DIAGNOSTICS_TEST
    if not client.is_file() or not diagnostics_test.is_file():
        raise AssertionError("expected client source and diagnostics-only test")
    source = client.read_text()
    if source.count(FIELD_BLOCK) != 1:
        raise AssertionError("diagnostic field block must match exactly once")
    remaining = source.replace(FIELD_BLOCK, "", 1)
    if any(counter in remaining for counter in COUNTERS):
        raise AssertionError("unexpected diagnostic counter use in client.go")
    for path in root.rglob("*.go"):
        if path in (client, diagnostics_test):
            continue
        text = path.read_text(errors="strict")
        if any(counter in text for counter in COUNTERS):
            raise AssertionError(f"diagnostic counter referenced by {path.relative_to(root)}")
    client.write_text(remaining)
    diagnostics_test.unlink()
    for path in root.rglob("*.go"):
        text = path.read_text(errors="strict")
        if any(counter in text for counter in COUNTERS):
            raise AssertionError(f"diagnostic counter remains in {path.relative_to(root)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: minimalize.py SOURCE_ROOT")
    strip_diagnostics(Path(sys.argv[1]))
    print("Removed optional diagnostic fields and diagnostics-only tests", flush=True)
