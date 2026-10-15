"""Bounded userVM-only native rotation test using an exact REJECT listener."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import threading
import time

import psutil
import stmc_yaml

MIB = 1024 * 1024
WORKERS = 64
SECONDS = 480
REQUEST_LIMIT = 600000
CORE_CPU_LIMIT = 240
CORE_RSS_LIMIT = 256 * MIB
LISTENER = {'name': 'STCVRC-ROTATION-REJECT', 'type': 'http',
            'listen': '127.0.0.1', 'port': 18985, 'proxy': 'REJECT'}
CONTROL = Path(r'C:\Users\FixtureUser\stcvrc-autostart-control')
SERVICE = Path(r'C:\ProgramData\clash-verge-service')
OWNER = hashlib.sha256(b'S-1-5-21-1-2-3-1001').hexdigest()


def safe_path(path, root):
    def ordinary(value):
        text = os.fspath(value)
        if re.match(r'^\\\\\?\\[A-Za-z]:\\', text):
            text = text[4:]
        elif text.startswith('\\\\'):
            raise ValueError('UNC or device path is outside the lab')
        return Path(text)
    path, root = ordinary(path), ordinary(root)
    if not path.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
        raise ValueError('Path outside expected root')
    for parent in (path, *path.parents):
        if parent.is_symlink() or parent.is_junction():
            raise ValueError('Reparse path')
    return path


def writer_limits(state):
    writer = state['last_writer_config']
    core_writer = state['last_clash_config']['log_config']
    size, count = writer['max_log_size'], writer['max_log_files']
    if writer != core_writer or not state['core_should_be_running']:
        raise ValueError('Writer configuration disagreement')
    if not isinstance(size, int) or not 64 * 1024 <= size <= 10 * MIB:
        raise ValueError('Writer size outside lab bound')
    if not isinstance(count, int) or not 1 <= count <= 8:
        raise ValueError('Writer count outside lab bound')
    return size, count


def log_snapshot(root):
    result = {}
    for path in root.glob('service*.log'):
        try:
            safe_path(path, root)
            stat = path.stat()
        except FileNotFoundError:
            continue
        result[path.name] = {'bytes': stat.st_size, 'active': 'latest' in path.stem}
    return result


def rotation_result(snapshots, size, count):
    seen = {}
    for snapshot in snapshots:
        for name, entry in snapshot.items():
            if not entry['active']:
                seen[name] = max(seen.get(name, 0), entry['bytes'])
    final = snapshots[-1] if snapshots else {}
    closed = {name: entry for name, entry in final.items() if not entry['active']}
    full = {name for name, length in seen.items() if size <= length <= size + 64 * 1024}
    evicted = full - set(final)
    return {'pass': len(full) >= count + 1 and bool(evicted) and len(closed) == count,
            'fullRotations': len(full), 'evictedFullFiles': len(evicted),
            'retainedClosedFiles': len(closed), 'maxRetainedBytes': max(seen.values(), default=0)}


def closed_connect_probe(request, port):
    with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
        connection.sendall(request)
        response = b''
        while b'\r\n\r\n' not in response and len(response) < 1024:
            part = connection.recv(128)
            if not part:
                return 'socketErrors'
            response += part
        if not response.startswith(b'HTTP/') or b'\r\n\r\n' not in response:
            return 'socketErrors'
        if response.split(b' ', 2)[1] != b'200':
            return 'httpRejected'
        # Mihomo accepts CONNECT before routing; only EOF/reset proves closure.
        if response.split(b'\r\n\r\n', 1)[1]:
            return 'unexpectedPayload'
        try:
            return 'unexpectedPayload' if connection.recv(1) else 'acceptedThenClosed'
        except ConnectionResetError:
            return 'acceptedThenClosed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--core-sha256', required=True)
    args = parser.parse_args()
    if os.environ.get('COMPUTERNAME') != 'LABHOST':
        raise RuntimeError('Wrong host')
    safe_path(CONTROL, Path(r'C:\Users\FixtureUser'))
    if (CONTROL/'run-id.txt').read_text() != args.run_id or (CONTROL/'.stcvrc-desktop-gate').read_text() != 'STCVRC_DESKTOP_GATE_V1':
        raise RuntimeError('Wrong lab ownership')
    owner = safe_path(SERVICE/'users'/OWNER, SERVICE)
    state = json.loads(safe_path(owner/'desired-state.json', owner).read_text())
    size, count = writer_limits(state)
    logs = safe_path(Path(state['last_writer_config']['directory']), owner)
    runtime = state['last_clash_config']['core_config']
    profile = stmc_yaml.load(safe_path(Path(runtime['config_path']), owner).read_bytes())
    if profile.get('tun', {}).get('enable') or LISTENER not in profile.get('listeners', []):
        raise RuntimeError('Exact isolated REJECT listener missing')
    core = safe_path(Path(runtime['core_path']), SERVICE/'cores')
    if hashlib.sha256(core.read_bytes()).hexdigest() != args.core_sha256:
        raise RuntimeError('Wrong core')
    processes = [p for p in psutil.process_iter(['name','exe']) if p.info['name'] == 'verge-mihomo.exe']
    if len(processes) != 1 or safe_path(Path(processes[0].info['exe']), SERVICE/'cores').resolve() != core.resolve():
        raise RuntimeError('Wrong running core')
    process = processes[0]
    if process.ppid() != psutil.win_service_get('clash_verge_service').pid():
        raise RuntimeError('Core is not service-owned')
    if not any(c.status == psutil.CONN_LISTEN and c.laddr.ip == '127.0.0.1'
               and c.laddr.port == LISTENER['port'] for c in process.net_connections(kind='tcp')):
        raise RuntimeError('REJECT listener is not owned by the core')
    before_cpu = process.cpu_times()
    counters = {'httpRejected': 0, 'acceptedThenClosed': 0, 'socketErrors': 0, 'unexpectedPayload': 0}
    lock, stop = threading.Lock(), threading.Event()
    hostname = 'stcvrc-rotation.' + '.'.join(['r' * 40] * 4) + '.invalid'
    request = f'CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}:443\r\n\r\n'.encode('ascii')

    def worker():
        while not stop.is_set():
            key = 'socketErrors'
            try:
                key = closed_connect_probe(request, LISTENER['port'])
            except OSError:
                pass
            with lock:
                counters[key] += 1
                if counters['unexpectedPayload'] or sum(counters.values()) >= REQUEST_LIMIT:
                    stop.set()
            stop.wait(0.002)

    snapshots = [log_snapshot(logs)]
    peak_rss = 0
    started = time.monotonic()
    reason = 'timeout'
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(worker) for _ in range(WORKERS)]
        try:
            while time.monotonic() - started < SECONDS and not stop.wait(1):
                snapshots.append(log_snapshot(logs))
                peak_rss = max(peak_rss, process.memory_info().rss)
                cpu = process.cpu_times()
                if peak_rss > CORE_RSS_LIMIT or cpu.user + cpu.system - before_cpu.user - before_cpu.system > CORE_CPU_LIMIT:
                    reason = 'resource-limit'
                    break
                if sum(entry['bytes'] for entry in snapshots[-1].values()) > (count + 2) * (size + 64 * 1024):
                    reason = 'storage-limit'
                    break
                if rotation_result(snapshots, size, count)['pass']:
                    reason = 'rotation-proven'
                    break
        finally:
            stop.set()
        for future in futures:
            future.result()
    time.sleep(1)
    if counters['unexpectedPayload']:
        reason = 'unexpected-payload'
    elif sum(counters.values()) >= REQUEST_LIMIT and reason != 'rotation-proven':
        reason = 'request-limit'
    snapshots.append(log_snapshot(logs))
    after_cpu = process.cpu_times()
    result = rotation_result(snapshots, size, count)
    result.update(runId=args.run_id, elapsedSeconds=round(time.monotonic()-started, 3),
                  reason=reason, maxBytes=size, maxFiles=count, counters=counters,
                  bounds={'seconds': SECONDS, 'workers': WORKERS, 'requests': REQUEST_LIMIT,
                          'coreCpuSeconds': CORE_CPU_LIMIT, 'coreRssBytes': CORE_RSS_LIMIT},
                  coreCpuSeconds=round(after_cpu.user+after_cpu.system-before_cpu.user-before_cpu.system, 3),
                  corePeakRssBytes=peak_rss, trafficScope='loopback-to-fixed-REJECT', snapshots=snapshots)
    result['pass'] &= reason == 'rotation-proven' and counters['unexpectedPayload'] == 0
    print(json.dumps(result))
    return 0 if result['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
