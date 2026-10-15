"""Bounded diagnostics/reconnect for the existing pinned lab SSH route."""
import json
from pathlib import Path
import subprocess
import time

CONNECT_SECONDS = 40


def lab_options(options):
    result = [x for x in options if not x.startswith('ConnectionAttempts=')]
    # Existing callers do not contain ConnectionAttempts; reject a dangling -o.
    if len(result) != len(options):
        raise ValueError('Configure attempts only in lab_options')
    return [f'ConnectTimeout={CONNECT_SECONDS}' if x.startswith('ConnectTimeout=') else x
            for x in result] + ['-o', 'ConnectionAttempts=1']


def command_budget(remote_seconds):
    if not 1 <= remote_seconds <= 600:
        raise ValueError('Unbounded remote deadline')
    return CONNECT_SECONDS + remote_seconds


def classify(stderr, returncode=None, timed_out=False):
    if timed_out:
        return 'timeout'
    text = stderr.decode('utf-8', errors='replace').lower()
    if any(x in text for x in ('host key verification failed', 'remote host identification has changed')):
        return 'pin'
    if any(x in text for x in ('bad permissions', 'load key ', 'reading configuration data failed',
                                "can't open user config", 'bad owner or permissions')):
        return 'local-config'
    if 'permission denied (publickey' in text or 'authentication failed' in text:
        return 'auth'
    if any(x in text for x in ('connection timed out', 'connection refused', 'no route to host',
                                'connection reset', 'connection closed', 'could not resolve')):
        return 'connect-unknown-hop'
    return 'unknown-ssh' if returncode == 255 else 'remote-exit'


class TransportFailure(RuntimeError):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def run(argv, timeout, diagnostics, *, read_only=False):
    attempts = 3 if read_only else 1
    for attempt in range(attempts):
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout)
            if result.returncode == 0:
                return result.stdout.decode('utf-8-sig', errors='replace').strip()
            stderr, code, timed_out = result.stderr, result.returncode, False
        except subprocess.TimeoutExpired as exc:
            stderr, code, timed_out = exc.stderr or b'', None, True
        kind = classify(stderr, code, timed_out)
        root = Path(diagnostics)
        root.mkdir(parents=True, exist_ok=True)
        stem = str(time.time_ns())
        # Do not persist argv or stdout: they may contain private command payloads.
        (root / (stem + '.stderr')).write_bytes(stderr[:65536])
        (root / (stem + '.json')).write_text(json.dumps({
            'errorClass': kind, 'exit': code, 'timedOut': timed_out,
            'attempt': attempt + 1, 'readOnly': read_only,
        }), encoding='ascii')
        if attempt + 1 == attempts or kind in ('pin', 'auth', 'local-config', 'remote-exit'):
            raise TransportFailure(kind)
        time.sleep((2, 5)[attempt])
