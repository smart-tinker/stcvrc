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
import subprocess
import tempfile
import threading
import time


def assess(scenario, evidence):
    if not evidence.get('baseline') or not evidence.get('direct_blocked'):
        return 'INVALID'
    if not evidence.get('live') or evidence.get('inactivity', 0):
        return 'FAIL'
    if scenario == 'idle':
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
            self.send_error(403, 'direct path')
            return
        self.send_response(200)
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
                              'auth':'SHA256', 'ca':str(work/'ca.crt'),
                              'cert':str(work/'client.crt'), 'key':str(work/'client.key'),
                              'udp':True}], 'rules':['MATCH,vpn']}
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
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            try:
                conn, response = request(False)
                evidence['direct_blocked'] = response.status == 403
                response.read(); conn.close()
                with process([str(core), '-d', str(work/'home'), '-f',str(work/'core.json')], work/'core.log') as client:
                    # Startup readiness only; never retry the measured scenario.
                    for _ in range(10):
                        if probe():
                            evidence['baseline'] = True
                            break
                        if client.poll() is not None:
                            break
                        time.sleep(0.2)
                    if evidence['baseline']:
                        if scenario == 'idle':
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
                    logs = (work/'server.log').read_text()
                    evidence['epochs'] = max(0, logs.count('Control Channel: TLSv') - 1)
                    evidence['rekeys'] = len(re.findall(r'TLS: soft reset', logs))
                    evidence['inactivity'] = len(re.findall(r'Inactivity timeout', logs))
                    evidence['live'] = client.poll() is None and server.poll() is None
                    evidence['verdict'] = assess(scenario, evidence)
                    evidence['scenario'] = scenario
                    evidence['core_sha256'] = hashlib.sha256(core.read_bytes()).hexdigest()
                    # Only disposable test identities are present in these logs.
                    for name in ('server.log', 'core.log'):
                        lines = (work/name).read_text(errors='replace').splitlines()
                        selected = [line for line in lines if any(word in line.lower() for word in
                                    ('error', 'warn', 'soft reset', 'inactivity', 'handshake complete', 'push_reply', 'control channel:', 'data channel:'))]
                        print(json.dumps({'log':name, 'events':selected[-35:]}), flush=True)
            finally:
                backend.shutdown(); backend.server_close(); thread.join(timeout=5)
        return evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--scenario', choices=('idle','rekey'), required=True)
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
