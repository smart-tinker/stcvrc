"""Disposable Linux network namespace only; no production inputs."""
import argparse
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import threading
import time


def assess(scenario, evidence):
    if scenario == 'lzo-data':
        if not evidence.get('control_ready') or not evidence.get('direct_blocked'):
            return 'INVALID'
    elif not evidence.get('baseline') or not evidence.get('direct_blocked'):
        return 'INVALID'
    if scenario == 'recovery' and (not evidence.get('server_lost') or
                                   not evidence.get('server_restarted')):
        return 'INVALID'
    if not evidence.get('live') or evidence.get('inactivity', 0):
        return 'FAIL'
    if scenario == 'deadline':
        return 'PASS' if evidence.get('timeout_observed') else 'FAIL'
    if scenario == 'lzo-data':
        if evidence.get('compressed_frames', 0) <= 0:
            return 'INVALID'
        return 'PASS' if (
            evidence.get('response_status') == 200 and
            evidence.get('payload_matches') and
            evidence.get('compressed_frames', 0) > 0 and
            evidence.get('no_direct_bypass')
        ) else 'FAIL'
    if scenario == 'recovery':
        return 'PASS' if (
            evidence.get('outage_status') != 200 and
            evidence.get('no_direct_bypass') and
            evidence.get('new_handshake') and
            evidence.get('recovered') and
            evidence.get('recovery_samples', 0) == evidence.get('expected_recovery_samples', -1) > 0
        ) else 'FAIL'
    if scenario.startswith('idle'):
        return 'PASS' if evidence.get('resumed') else 'FAIL'
    return 'PASS' if (evidence.get('rekeys', 0) >= 2 and evidence.get('epochs', 0) >= 2 and
                      evidence.get('post_epoch_samples', 0) >= 20 and
                      evidence.get('samples', 0) == evidence.get('expected', -1)) else 'FAIL'


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)


@contextlib.contextmanager
def process(args, log):
    with log.open('w') as output:
        child = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT)
        try:
            yield child
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)


def certificates(work):
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=ci-ca', '-keyout', str(work/'ca.key'), '-out', str(work/'ca.crt'))
    for name, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
        command('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+name,
                '-keyout', str(work/(name+'.key')), '-out', str(work/(name+'.csr')))
        (work/(name+'.ext')).write_text('extendedKeyUsage='+usage+'\n')
        command('openssl', 'x509', '-req', '-in', str(work/(name+'.csr')), '-CA', str(work/'ca.crt'),
                '-CAkey', str(work/'ca.key'), '-CAcreateserial', '-days', '1',
                '-extfile', str(work/(name+'.ext')), '-out', str(work/(name+'.crt')))


class Endpoint(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        # Direct traffic uses the server's own .1 address; only VPN clients get .2+.
        if not re.fullmatch(r'10\.77\.0\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])', self.client_address[0]):
            self.server.direct_hits += 1
            self.send_error(403, 'direct path')
            return
        self.send_response(200)
        if self.path == '/lzo-data':
            body = b'A' * 8192
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.end_headers()
        try:
            if self.path == '/stream':
                for i in range(200):
                    self.wfile.write((str(i)+'\n').encode())
                    self.wfile.flush()
                    time.sleep(0.2)
            else:
                self.wfile.write(b'VPN-ONLY\n')
        except (BrokenPipeError, ConnectionResetError):
            pass


def request(proxy, path='/probe'):
    conn = http.client.HTTPConnection('127.0.0.1' if proxy else '10.77.0.1', 18081 if proxy else 18080, timeout=8)
    conn.request('GET', 'http://10.77.0.1:18080'+path if proxy else path)
    return conn, conn.getresponse()


def probe():
    try:
        conn, response = request(True)
        with contextlib.closing(conn):
            return response.status == 200 and response.read() == b'VPN-ONLY\n'
    except (OSError, http.client.HTTPException):
        return False


def run(core, scenario):
    with tempfile.TemporaryDirectory(prefix='openvpn-compare-') as directory:
        work = Path(directory)
        certificates(work)
        (work/'server.conf').write_text(f'''local 127.0.0.1
port 1194
proto udp
dev tun-ci
server 10.77.0.0 255.255.255.0
topology subnet
ca {work}/ca.crt
cert {work}/server.crt
key {work}/server.key
dh none
data-ciphers AES-256-GCM
cipher AES-256-GCM
auth SHA256
disable-dco
keepalive 1 5
reneg-sec {5 if scenario == 'rekey' else 0}
tran-window 3
verb 4
''')
        config = {'mixed-port':18081, 'allow-lan':False, 'bind-address':'127.0.0.1',
                  'mode':'rule', 'log-level':'debug', 'ipv6':False,
                  'tun':{'enable':False}, 'dns':{'enable':False},
                  'proxies':[{'name':'vpn', 'type':'openvpn', 'server':'127.0.0.1',
                              'port':1194, 'proto':'udp', 'cipher':'AES-256-GCM',
                              'auth':'SHA256', 'ca':(work/'ca.crt').read_text(),
                              'cert':(work/'client.crt').read_text(), 'key':(work/'client.key').read_text(),
                              'udp':True}], 'rules':['MATCH,vpn']}
        if scenario in ('idle-local', 'idle-lzo', 'lzo-data', 'deadline', 'recovery'):
            config['proxies'][0].update(ping=1, **{'ping-restart':5})
        if scenario in ('idle-lzo', 'lzo-data'):
            config['proxies'][0]['comp-lzo'] = 'yes'
            with (work/'server.conf').open('a') as stream:
                stream.write('allow-compression yes\ncomp-lzo yes\n')
        (work/'core.json').write_text(json.dumps(config))
        evidence = {'baseline':False, 'direct_blocked':False}
        with process(['openvpn','--config',str(work/'server.conf')], work/'server.log') as server:
            for _ in range(50):
                if 'Initialization Sequence Completed' in (work/'server.log').read_text():
                    break
                if server.poll() is not None:
                    raise RuntimeError('OpenVPN server setup failed: '+(work/'server.log').read_text()[-3000:])
                time.sleep(0.1)
            else:
                raise RuntimeError('OpenVPN server did not initialize')
            backend = http.server.ThreadingHTTPServer(('0.0.0.0',18080), Endpoint)
            backend.direct_hits = 0
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            try:
                conn, response = request(False)
                evidence['direct_blocked'] = response.status == 403
                response.read(); conn.close()
                direct_hits_before_scenario = backend.direct_hits
                server_log = work/'server.log'
                with process([str(core), '-d', str(work/'home'), '-f',str(work/'core.json')], work/'core.log') as client:
                    if scenario == 'lzo-data':
                        evidence['control_ready'] = server.poll() is None and evidence['direct_blocked']
                    # Startup readiness only; never retry the measured scenario.
                    for _ in range(10):
                        if probe():
                            evidence['baseline'] = True
                            break
                        if client.poll() is not None:
                            break
                        time.sleep(0.2)
                    if evidence['baseline'] or scenario == 'lzo-data':
                        if scenario == 'lzo-data':
                            evidence.update(response_status=0, payload_matches=False,
                                            compressed_frames=0, no_direct_bypass=False)
                            core_log = work/'core.log'
                            frames_before = core_log.read_text(errors='replace').count('STCVRC_CI_LZO_COMPRESSED_FRAME') if core_log.exists() else 0
                            try:
                                conn, response = request(True, '/lzo-data')
                                with contextlib.closing(conn):
                                    evidence['response_status'] = response.status
                                    evidence['payload_matches'] = response.read() == b'A' * 8192
                            except (OSError, http.client.HTTPException):
                                pass
                            frames_after = core_log.read_text(errors='replace').count('STCVRC_CI_LZO_COMPRESSED_FRAME') if core_log.exists() else 0
                            evidence['compressed_frames'] = max(0, frames_after - frames_before)
                            evidence['no_direct_bypass'] = backend.direct_hits == direct_hits_before_scenario
                        elif scenario == 'deadline':
                            conn, response = request(True, '/stream')
                            try:
                                if response.status != 200:
                                    raise RuntimeError('deadline setup HTTP failed')
                                received = [response.readline() for _ in range(4)]
                                evidence['stream_before_stop'] = received == [b'0\n', b'1\n', b'2\n', b'3\n']
                                if not evidence['stream_before_stop']:
                                    raise RuntimeError('deadline setup stream invalid')
                                os.kill(server.pid, signal.SIGSTOP)
                                stopped = time.monotonic()
                                try:
                                    limit = stopped + 6.5
                                    while time.monotonic() < limit:
                                        if 'ping-restart timeout' in (work/'core.log').read_text():
                                            evidence['timeout_observed'] = True
                                            evidence['timeout_after_stop'] = time.monotonic() - stopped
                                            break
                                        time.sleep(0.05)
                                    evidence.setdefault('timeout_observed', False)
                                finally:
                                    os.kill(server.pid, signal.SIGCONT)
                            finally:
                                conn.close()
                        elif scenario == 'recovery':
                            evidence.update(
                                server_lost=False, outage_status=0, no_direct_bypass=False,
                                server_restarted=False, new_handshake=False, recovered=False,
                                recovery_status=0, recovery_samples=0, expected_recovery_samples=10,
                            )
                            server.terminate()
                            try:
                                server.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                server.kill()
                                server.wait(timeout=5)
                            evidence['server_lost'] = server.poll() is not None
                            if evidence['server_lost']:
                                try:
                                    conn, response = request(True)
                                    evidence['outage_status'] = response.status
                                    response.read()
                                    conn.close()
                                except (OSError, http.client.HTTPException):
                                    pass
                                evidence['no_direct_bypass'] = backend.direct_hits == direct_hits_before_scenario
                                server_log = work/'restarted-server.log'
                                with process(['openvpn','--config',str(work/'server.conf')], server_log) as restored:
                                    for _ in range(50):
                                        if 'Initialization Sequence Completed' in server_log.read_text():
                                            evidence['server_restarted'] = True
                                            break
                                        if restored.poll() is not None:
                                            break
                                        time.sleep(0.1)
                                    if evidence['server_restarted']:
                                        try:
                                            conn, response = request(True, '/stream')
                                            with contextlib.closing(conn):
                                                evidence['recovery_status'] = response.status
                                                if response.status == 200:
                                                    for i in range(evidence['expected_recovery_samples']):
                                                        if response.readline() != (str(i)+'\n').encode():
                                                            break
                                                        evidence['recovery_samples'] += 1
                                        except (OSError, http.client.HTTPException):
                                            pass
                                        restarted_logs = server_log.read_text(errors='replace')
                                        evidence['new_handshake'] = 'Control Channel: TLSv' in restarted_logs
                                        evidence['recovered'] = (
                                            evidence['recovery_status'] == 200 and
                                            evidence['recovery_samples'] == evidence['expected_recovery_samples']
                                        )
                                        evidence['live'] = client.poll() is None and restored.poll() is None
                        elif scenario.startswith('idle'):
                            time.sleep(14)
                            evidence['resumed'] = probe()
                        else:
                            evidence.update(samples=0, expected=200, post_epoch_samples=0)
                            try:
                                conn, response = request(True, '/stream')
                                with contextlib.closing(conn):
                                    if response.status == 200:
                                        for i in range(200):
                                            if response.readline() != (str(i)+'\n').encode():
                                                break
                                            evidence['samples'] += 1
                                            completed = (work/'server.log').read_text().count('Control Channel: TLSv') - 1
                                            if completed >= 2:
                                                evidence['post_epoch_samples'] += 1
                            except (OSError, http.client.HTTPException):
                                pass
                    logs = server_log.read_text()
                    evidence['epochs'] = max(0, logs.count('Control Channel: TLSv') - 1)
                    evidence['rekeys'] = len(re.findall(r'TLS: soft reset', logs))
                    evidence['inactivity'] = len(re.findall(r'Inactivity timeout', logs))
                    if scenario != 'recovery':
                        evidence['live'] = client.poll() is None and server.poll() is None
                    evidence['verdict'] = assess(scenario, evidence)
                    evidence['scenario'] = scenario
                    evidence['core_sha256'] = hashlib.sha256(core.read_bytes()).hexdigest()
                    # Only disposable test identities are present in these logs.
                    for name in ('server.log', 'restarted-server.log', 'core.log'):
                        if not (work/name).exists():
                            continue
                        lines = (work/name).read_text(errors='replace').splitlines()
                        selected = [line for line in lines if 'STCVRC_CI_LZO_COMPRESSED_FRAME' in line or any(word in line.lower() for word in
                                    ('error', 'warn', 'soft reset', 'inactivity', 'handshake complete', 'push_reply', 'control channel:', 'data channel:'))]
                        print(json.dumps({'log':name, 'events':selected[-35:]}), flush=True)
            finally:
                backend.shutdown(); backend.server_close(); thread.join(timeout=5)
        return evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--scenario', choices=('idle','idle-local','idle-lzo','lzo-data','rekey','deadline','recovery'), required=True)
    parser.add_argument('--namespace-parent', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.readlink('/proc/self/ns/net') == args.namespace_parent:
        raise SystemExit('Refusing to run outside a new network namespace')
    command('ip', 'link', 'set', 'lo', 'up')
    result = run(args.core.resolve(), args.scenario)
    args.output.write_text(json.dumps(result)+'\n')
    print(json.dumps(result), flush=True)
    raise SystemExit(2 if result['verdict'] == 'INVALID' else 0)
