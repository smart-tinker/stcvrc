"""Bounded, one-shot STCVRC observation. Never changes the controller/runtime."""
from __future__ import annotations

import argparse
from collections import Counter
import contextlib
import copy
import ctypes
from datetime import datetime, timezone
import gzip
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.request

import psutil
import stmc_yaml

VERSION = 1
MIB = 1024 * 1024
DAY = 86400
WORK_BUDGET_SECONDS = 35
FINALIZE_RESERVE_SECONDS = 10
MARKER = 'STCVRC_OBSERVER_V1'
LEAVES = ('4VPS', 'GC')
GROUPS = ('FOREIGN-EGRESS', 'VPS-POOL', 'VPS-LATENCY', 'RU-DIRECT',
          'LT-ROUTE', 'ELITECH-ROUTE', 'OSEN-ROUTE')
NAMES = frozenset((*LEAVES, *GROUPS, 'DIRECT', 'REJECT', 'LOCAL-DIRECT',
                   'LT-OPENVPN', 'ELITECH-OPENVPN', 'OSEN-OPENVPN'))
LISTENERS = ({'name': 'STCVRC-PROBE-4VPS', 'type': 'http', 'listen': '127.0.0.1',
              'port': 18981, 'proxy': '4VPS'},
             {'name': 'STCVRC-PROBE-GC', 'type': 'http', 'listen': '127.0.0.1',
              'port': 18982, 'proxy': 'GC'})
TARGETS = (('google-204', 'www.gstatic.com', '/generate_204', 204),
           ('control-body', 'www.cloudflare.com', '/cdn-cgi/trace', 200),
           ('openai-unauthenticated', 'api.openai.com', '/v1/models', 401))
TIME_RE = re.compile(r'(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)')
CLASSES = (
    ('vpn-auth', ('auth_failed', 'auth failed')),
    ('vpn-decrypt', ('data-decrypt-error', 'decrypt error')),
    ('vpn-reconnect', ('ping-restart', 'control loop requested reconnect', 'control loop stopped')),
    ('vpn-link-error', ('openvpn link closed while reading packet',
                        'error reading packet from openvpn link',
                        'error writing packet to openvpn link', 'error writing ping packet')),
    ('vpn-channel', ('negotiated data channel', 'data key changed')),
    ('provider-reference', ('proxy vps-default not found', 'proxy not found')),
    ('provider-pull', ('pull error',)),
    ('dns-resolution', ("can't resolve ip", "couldn't find ip", 'dns resolve failed')),
    ('connection-timeout', ('i/o timeout', 'deadline exceeded')),
    ('connection-refused', ('connection refused', 'connection was refused')),
    ('cancelled', ('context canceled', 'operation was canceled')),
    ('ui-panic', ('panic', 'cannot move state from destroyed')),
)


def utc(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat()


def parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return date.timestamp() if date.tzinfo else None
    except ValueError:
        return None


def digest(value):
    return hashlib.sha256(value).hexdigest()


def error_class(exc):
    if isinstance(exc, (TimeoutError, socket.timeout, subprocess.TimeoutExpired)):
        return 'timeout'
    if isinstance(exc, ssl.SSLError):
        return 'tls'
    if isinstance(exc, ConnectionRefusedError):
        return 'refused'
    if isinstance(exc, urllib.error.HTTPError):
        return 'http-error'
    if isinstance(exc, urllib.error.URLError):
        return error_class(exc.reason) if isinstance(exc.reason, Exception) else 'transport'
    if isinstance(exc, PermissionError):
        return 'access-denied'
    if isinstance(exc, OSError):
        return 'io'
    return 'invalid-data'


def shared_open(path, closed_only=False):
    reject_links(path)
    if os.name != 'nt':
        stream = open(path, 'rb')
        if os.fstat(stream.fileno()).st_nlink != 1:
            stream.close()
            raise ValueError('Hard-linked source is outside the collector contract')
        return stream
    import msvcrt
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CreateFileW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                  ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
    handle = kernel.CreateFileW(str(path), 0x80000000, 1 if closed_only else 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    stream = os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY), 'rb')
    try:
        kernel.GetFinalPathNameByHandleW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32)
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        final = buffer.value.removeprefix('\\\\?\\')
        kernel.GetLongPathNameW.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
        expected = ctypes.create_unicode_buffer(32768)
        expected_length = kernel.GetLongPathNameW(os.path.abspath(path), expected, len(expected))
        if (not length or length >= len(buffer) or os.fstat(stream.fileno()).st_nlink != 1
                or not expected_length or expected_length >= len(expected)
                or os.path.normcase(final) != os.path.normcase(expected.value.removeprefix('\\\\?\\'))):
            raise ValueError('Source handle escaped the expected single-link path')
        return stream
    except BaseException:
        stream.close()
        raise


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.new')
    encoded = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    with open(temporary, 'wb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def reject_links(path):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        if item.exists() and (item.is_symlink() or getattr(item.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('Reparse point is not an observer boundary')
    return path


def init_store(root):
    root = reject_links(root)
    marker = root / '.stcvrc-observer'
    if root.exists() and any(root.iterdir()) and not marker.exists():
        raise ValueError('Nonempty unowned observer destination')
    root.mkdir(parents=True, exist_ok=True)
    if marker.exists() and marker.read_text() != MARKER:
        raise ValueError('Wrong observer marker')
    if not marker.exists():
        marker.write_text(MARKER, encoding='ascii')
    for name in ('timeline', 'archive'):
        reject_links(root / name).mkdir(exist_ok=True)
    return root


@contextlib.contextmanager
def single_writer(root):
    lock = open(root / 'observer.lock', 'a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            lock.seek(0, 2)
            if not lock.tell():
                lock.write(b'0'); lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        lock.close()


def observer_profile(profile):
    result = copy.deepcopy(profile)
    proxies = {p.get('name'): p for p in result.get('proxies', [])}
    if any(proxies.get(name, {}).get('type') != 'vless' for name in LEAVES):
        raise ValueError('Expected the two accepted VLESS leaves')
    existing = result.setdefault('listeners', [])
    for listener in LISTENERS:
        matches = [x for x in existing if x.get('name') == listener['name'] or str(x.get('port')) == str(listener['port'])]
        if matches and matches != [listener]:
            raise ValueError('Listener name/port collision')
        if not matches:
            existing.append(copy.deepcopy(listener))
    return result


def classify_line(line, endpoints=None):
    text = line.lower()
    counter = re.search(r'\bdata-decrypt-errors\s*[:=]\s*(\d+)', text)
    # A cumulative counter must not hide a reconnect or look like a new error.
    event_text = text[:counter.start()] + text[counter.end():] if counter else text
    kind = next((name for name, markers in CLASSES if any(x in event_text for x in markers)),
                'vpn-statistics' if counter else None)
    if not kind:
        return None
    route = next((n for n in (*GROUPS, 'LT-OPENVPN', 'ELITECH-OPENVPN', 'OSEN-OPENVPN') if n.lower() in text), 'UNKNOWN')
    if route == 'UNKNOWN' and endpoints:
        route = next((name for name, endpoint in endpoints.items() if endpoint and endpoint in line), 'UNKNOWN')
    match = TIME_RE.search(line)
    timestamp = match.group(1) if match else None
    result = {'class': kind, 'route': route, 'sourceTime': timestamp,
              'sourceTimeHasOffset': parse_time(timestamp) is not None}
    if counter:
        result['dataDecryptErrors'] = int(counter.group(1))
    return result


def log_files(roots):
    roots = [roots] if isinstance(roots, Path) else roots
    files = []
    for root in roots:
        reject_links(root)
        files.extend(root.rglob('*.log'))
    return files


def scan_logs(logs, state, endpoints=None, max_bytes=4*MIB):
    cursors = state.setdefault('logCursors', {})
    result = {'counts': {}, 'events': [], 'readBytes': 0, 'backlogBytes': 0,
              'readErrors': 0, 'resets': 0, 'missingSources': 0, 'eventsOmitted': 0}
    seen = set()
    counts = Counter()
    files = sorted(log_files(logs), key=lambda p: p.stat().st_mtime)
    for path in files:
        try:
            reject_links(path)
            stat = path.stat()
            key = f'{stat.st_dev}:{stat.st_ino}'
            seen.add(key)
            cursor = cursors.get(key, {'offset': 0, 'prefixLength': 0, 'prefix': ''})
            with shared_open(path) as stream:
                prefix = stream.read(cursor['prefixLength'])
                if stat.st_size < cursor['offset'] or (cursor['prefixLength'] and digest(prefix) != cursor['prefix']):
                    cursor = {'offset': 0, 'prefixLength': 0, 'prefix': ''}
                    result['resets'] += 1
                stream.seek(0)
                prefix = stream.read(min(64, stat.st_size))
                stream.seek(cursor['offset'])
                available = max(0, max_bytes-result['readBytes'])
                data = stream.read(min(available, max(0, stat.st_size-cursor['offset'])))
                result['readBytes'] += len(data)
                end = data.rfind(b'\n')+1
                for line in data[:end].decode('utf-8', errors='replace').splitlines():
                    event = classify_line(line, endpoints)
                    if event:
                        counts[event['class'] + ':' + event['route']] += 1
                        if len(result['events']) < 256:
                            result['events'].append(event)
                        else:
                            result['eventsOmitted'] += 1
                cursor.update(offset=cursor['offset']+end, prefixLength=len(prefix), prefix=digest(prefix))
                # Overlong lines are not allowed to stall all future observations.
                if not end and len(data) >= min(max_bytes, MIB):
                    cursor['offset'] += len(data)
                    result['eventsOmitted'] += 1
                cursors[key] = cursor
                result['backlogBytes'] += max(0, stat.st_size-cursor['offset'])
        except (OSError, ValueError):
            result['readErrors'] += 1
    for key in set(cursors)-seen:
        result['missingSources'] += 1
        del cursors[key]
    result['counts'] = dict(counts)
    return result


def native_view(proxies, state, now, epoch):
    result = {'groups': {}, 'leaves': {}}
    group = proxies.get('VPS-LATENCY', {})
    url = group.get('testUrl')
    for name in GROUPS:
        item = proxies.get(name, {})
        result['groups'][name] = {'type': item.get('type') if item.get('type') in ('Selector','Fallback','URLTest') else 'UNKNOWN',
                                  'now': item.get('now') if item.get('now') in NAMES else 'UNKNOWN',
                                  'fixed': item.get('fixed') if item.get('fixed') in NAMES else None}
    known = state.setdefault('healthSeen', {})
    for name in LEAVES:
        item = proxies.get(name, {})
        specific = item.get('extra', {}).get(url, {}) if isinstance(url, str) else {}
        history = specific.get('history', [])
        last = history[-1] if history else {}
        stamp = parse_time(last.get('time'))
        age = now-stamp if stamp is not None else None
        identity = digest(f'{epoch}:{name}:{last.get("time", "")}'.encode())
        result['leaves'][name] = {
            'generalAlive': item.get('alive') if isinstance(item.get('alive'), bool) else None,
            'testAlive': specific.get('alive') if isinstance(specific.get('alive'), bool) else None,
            'healthTarget': 'native-selection' if url else 'UNKNOWN',
            'sourceUtc': utc(stamp) if stamp is not None else None,
            'ageSeconds': round(age, 3) if age is not None else None,
            'fresh': age is not None and 0 <= age <= 150,
            'delayMs': last.get('delay') if isinstance(last.get('delay'), (int,float)) else None,
            'newSample': stamp is not None and known.get(name) != identity,
        }
        if stamp is not None:
            known[name] = identity
    return result


def api_get(port, secret, endpoint):
    if endpoint not in ('/proxies', '/providers/rules', '/version'):
        raise ValueError('Non-observation API endpoint')
    request = urllib.request.Request(f'http://127.0.0.1:{port}{endpoint}',
                                     headers={'Authorization': 'Bearer ' + secret})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=2) as response:
        payload = response.read(2*MIB+1)
        if len(payload) > 2*MIB:
            raise ValueError('Oversized controller response')
        return json.loads(payload)


@lru_cache(maxsize=1)
def curl_capability(executable):
    completed = subprocess.run([str(executable),'--disable','--version'],capture_output=True,
                               timeout=2,creationflags=0x08000000 if os.name == 'nt' else 0)
    match = re.match(rb'curl (\d+)\.(\d+)\.(\d+)',completed.stdout)
    return bool(completed.returncode == 0 and match and tuple(map(int,match.groups())) >= (8,4,0))


def body_probe(port, target, limit=8192, timeout=6):
    identifier, host, path, expected = target
    result = {'target': identifier, 'success': False, 'status': None, 'bodyComplete': False,
              'bodyBytes': 0, 'errorClass': None}
    started = time.monotonic()
    try:
        executable = Path(os.environ.get('WINDIR', 'C:/Windows'))/'System32/curl.exe'
        if not curl_capability(executable):
            result['errorClass'] = 'curl-capability'
            result['durationMs'] = round((time.monotonic()-started)*1000)
            return result
        separator = b'\nSTCVRC_STATUS:'
        command = [str(executable), '--disable', '--silent', '--show-error',
                   '--proxy', f'http://127.0.0.1:{port}', '--noproxy', '',
                   '--max-time', str(timeout), '--max-filesize', str(limit),
                   '--header', 'Accept-Encoding: identity', '--output', '-',
                   '--write-out', separator.decode()+'%{http_code}', 'https://'+host+path]
        completed = subprocess.run(command, capture_output=True, timeout=timeout+2,
                                   creationflags=0x08000000 if os.name == 'nt' else 0)
        data, marker, status = completed.stdout.rpartition(separator)
        if not marker or not status.isdigit() or len(completed.stdout) > limit+100:
            raise ValueError('Probe framing')
        result['status'] = int(status)
        result['bodyBytes'] = len(data)
        result['bodyComplete'] = completed.returncode == 0
        if completed.returncode:
            result['errorClass'] = {28:'timeout',18:'incomplete-body',63:'body-limit',
                                    60:'tls',35:'tls',7:'connect',56:'transport'}.get(completed.returncode,'transport')
        elif int(status) != expected:
            result['errorClass'] = 'http-status'
        elif identifier == 'control-body' and not (b'ip=' in data and b'tls=' in data):
            result['errorClass'] = 'body-contract'
        elif identifier == 'google-204' and data:
            result['errorClass'] = 'body-contract'
        elif identifier == 'openai-unauthenticated':
            try:
                error = json.loads(data).get('error')
                valid = isinstance(error, dict) and isinstance(error.get('message'), str) and bool(error['message'])
            except (ValueError, AttributeError, UnicodeError):
                valid = False
            result['success'] = valid
            result['errorClass'] = None if valid else 'body-contract'
        else:
            result['success'] = True
    except Exception as exc:
        result['errorClass'] = error_class(exc)
    result['durationMs'] = round((time.monotonic()-started)*1000)
    return result


def host_view(label='home'):
    result = {'bootUtc': utc(psutil.boot_time()), 'processes': [], 'service': 'UNKNOWN', 'networkHash': None}
    if os.name == 'nt':
        ticks = ctypes.c_uint64()
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetTickCount64.restype = ctypes.c_uint64
        result['uptimeMs'] = kernel.GetTickCount64()
        result['awake100ns'] = ticks.value if kernel.QueryUnbiasedInterruptTime(ctypes.byref(ticks)) else None
    try:
        service = psutil.win_service_get('clash_verge_service').as_dict()
        result['service'] = {'status': service['status'], 'startType': service['start_type'], 'pid': service['pid']}
    except (AttributeError, psutil.Error):
        pass
    for process in psutil.process_iter(['pid','ppid','name','create_time']):
        role = process.info['name']
        if label == 'lab' and role == 'core.exe':
            try:
                if process.exe().lower() == r'C:\ProgramData\STCVRC-observer-lab\bin\core.exe'.lower():
                    role = 'verge-mihomo.exe'
            except psutil.Error:
                continue
        if role not in ('verge-mihomo.exe', 'clash-verge.exe', 'clash-verge-service.exe', 'clash_verge_service.exe'):
            continue
        session = ctypes.c_uint32()
        session_id = None
        if os.name == 'nt' and ctypes.windll.kernel32.ProcessIdToSessionId(process.pid, ctypes.byref(session)):
            session_id = session.value
        result['processes'].append({'pid': process.pid, 'parent': process.info['ppid'],
                                    'role': role, 'startUtc': utc(process.info['create_time']),
                                    'session': session_id})
    network = {name: {'up': stats.isup, 'mtu': stats.mtu,
                     'addresses': [str(x.address) for x in psutil.net_if_addrs().get(name, [])]}
               for name, stats in psutil.net_if_stats().items()}
    result['networkHash'] = digest(json.dumps(network, sort_keys=True).encode())
    return result


def file_version(path):
    if os.name != 'nt':
        return None
    library = ctypes.WinDLL('version', use_last_error=True)
    library.GetFileVersionInfoSizeW.argtypes = (ctypes.c_wchar_p, ctypes.c_void_p)
    size = library.GetFileVersionInfoSizeW(str(path), None)
    if not 52 <= size <= MIB:
        return None
    data = ctypes.create_string_buffer(size)
    library.GetFileVersionInfoW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
    if not library.GetFileVersionInfoW(str(path), 0, size, data):
        return None
    pointer = ctypes.c_void_p(); length = ctypes.c_uint32()
    library.VerQueryValueW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32))
    if not library.VerQueryValueW(data, '\\', ctypes.byref(pointer), ctypes.byref(length)) or length.value < 52:
        return None
    values = struct.unpack('<13I', ctypes.string_at(pointer, 52))
    if values[0] != 0xFEEF04BD:
        return None
    return '.'.join(map(str,(values[4]>>16,values[4]&65535,values[5]>>16,values[5]&65535)))


SERVICE_ROOT = Path('C:/ProgramData/clash-verge-service')


def runtime_layout(app, service_owner_sid=None):
    base = Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Clash Verge'
    paths = {'ui':base/'clash-verge.exe','core':base/'verge-mihomo.exe','service':base/'resources/clash-verge-service.exe'}
    layout = {'kind':'legacy-appdata','config':app/'clash-verge.yaml','logs':[app/'logs'],'binaries':paths}
    if service_owner_sid is not None:
        if not re.fullmatch(r'S-1-5-21-\d+-\d+-\d+-\d+',service_owner_sid):
            raise ValueError('Invalid service owner SID')
        owner=SERVICE_ROOT/'users'/digest(service_owner_sid.encode('ascii'))
        layout.update(kind='service-owner',config=owner/'runtime/config.yaml',
                      logs=[app/'logs',owner/'logs',SERVICE_ROOT/'logs'])
        paths.update(core=SERVICE_ROOT/'cores/verge-mihomo.exe',service=SERVICE_ROOT/'bin/clash-verge-service.exe')
    return layout


def binary_view(state, label, layout=None):
    base = Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Clash Verge'
    paths = layout['binaries'].copy() if layout else {'ui':base/'clash-verge.exe','core':base/'verge-mihomo.exe','service':base/'resources/clash-verge-service.exe'}
    if label == 'lab' and not (layout and layout['kind']=='service-owner') and not paths['core'].exists():
        paths['core'] = Path(r'C:\ProgramData\STCVRC-observer-lab\bin\core.exe')
    cache = state.setdefault('binaryCache',{})
    result = {}
    for role,path in paths.items():
        if not path.exists():
            result[role] = {'status':'absent'}
            continue
        stat = path.stat(); identity = [stat.st_ino,stat.st_size,stat.st_mtime_ns]
        if cache.get(role,{}).get('identity') != identity:
            hasher = hashlib.sha256()
            with shared_open(path) as source:
                while data := source.read(MIB):hasher.update(data)
            cache[role] = {'identity':identity,'sha256':hasher.hexdigest(),'fileVersion':file_version(path)}
        result[role] = {key:cache[role][key] for key in ('sha256','fileVersion')}
    return result


def windows_events(since):
    if os.name != 'nt':
        return {'status': 'not-windows', 'events': []}
    milliseconds = int(min(DAY, max(60, time.time()-since))*1000)
    command = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
               "$q='*[System[(EventID=1 or EventID=12 or EventID=13 or EventID=42 or EventID=107 or EventID=6005 or EventID=6006 or EventID=6008) and TimeCreated[timediff(@SystemTime) <= "
               +str(milliseconds)+"]]]';try{$e=@(Get-WinEvent -LogName System -FilterXPath $q -MaxEvents 200 -ErrorAction Stop);"
               "$o=@($e|ForEach-Object{@{id=$_.Id;provider=$_.ProviderName;utc=$_.TimeCreated.ToUniversalTime().ToString('o');record=$_.RecordId}});"
               "ConvertTo-Json -InputObject $o -Compress}catch{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){'[]'}else{exit 2}}")
    executable = Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    completed = subprocess.run([str(executable), '-NoProfile','-NonInteractive','-Command',command],
                               capture_output=True, timeout=10, creationflags=0x08000000)
    if completed.returncode:
        return {'status': 'unavailable', 'events': []}
    events = json.loads(completed.stdout.decode('utf-8-sig'))
    allowed = {'Microsoft-Windows-Power-Troubleshooter','Microsoft-Windows-Kernel-Power',
               'Microsoft-Windows-Kernel-General','EventLog'}
    return {'status': 'ok', 'events': [x for x in events if x.get('provider') in allowed]}


def scheduler_events(since, task_name):
    if task_name not in ('STCVRC-Observer', 'STCVRC-Observer-Lab'):
        raise ValueError('Unknown observer task')
    if os.name != 'nt':
        return {'status': 'not-windows', 'events': []}
    lookback = int(min(DAY, max(60, time.time()-since)))
    query = (f'*[System[TimeCreated[timediff(@SystemTime) <= {lookback*1000}]]'
             f' and EventData[Data[@Name="TaskName"]="\\{task_name}"]]')
    code = r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$channel='Microsoft-Windows-TaskScheduler/Operational'
try {
 $log=Get-WinEvent -ListLog $channel
 $result=@{status='disabled';enabled=[bool]$log.IsEnabled;maxBytes=$log.MaximumSizeInBytes;recordCount=$log.RecordCount;events=@();truncated=$false}
 if($log.IsEnabled){
  $events=@()
  try{$events=@(Get-WinEvent -LogName $channel -FilterXPath '__QUERY__' -MaxEvents 100)}
  catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
  $result.status='ok';$result.truncated=($events.Count -eq 100)
  $result.events=@($events|ForEach-Object{
   $item=@{id=$_.Id;level=$_.Level;utc=$_.TimeCreated.ToUniversalTime().ToString('o');record=$_.RecordId}
   $xml=[xml]$_.ToXml()
   foreach($data in $xml.Event.EventData.Data){
    if($data.Name -in @('ResultCode','ErrorValue')){
     $number=[uint64]0
     if([uint64]::TryParse([string]$data.'#text',[ref]$number)){$item[$data.Name]=$number}
    }
   }
   $item
  })
 }
 $result|ConvertTo-Json -Depth 5 -Compress
}catch{exit 2}
""".replace('__QUERY__', query)
    executable = Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    completed = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-Command', code],
                               capture_output=True, timeout=8, creationflags=0x08000000)
    if completed.returncode:
        return {'status': 'unavailable', 'events': [], 'lookbackSeconds': lookback}
    result = json.loads(completed.stdout.decode('utf-8-sig'))
    result['lookbackSeconds'] = lookback
    return result


def physical_gateway():
    if os.name != 'nt':
        return {'status':'not-windows'}
    code = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
            "$physical=@(Get-NetAdapter -Physical|Where-Object Status -eq 'Up'|ForEach-Object ifIndex);"
            "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|"
            "Where-Object {$_.NextHop -ne '0.0.0.0' -and $_.InterfaceIndex -in $physical}|"
            "Sort-Object @{Expression={$_.RouteMetric+$_.InterfaceMetric}}|Select-Object -First 1;"
            "if(-not $r){exit 2};$p=New-Object Net.NetworkInformation.Ping;"
            "try{$a=$p.Send($r.NextHop,1000);@{success=($a.Status -eq 'Success');delayMs=$a.RoundtripTime}|ConvertTo-Json -Compress}finally{$p.Dispose()}")
    completed = subprocess.run([str(Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'),
                               '-NoProfile','-NonInteractive','-Command',code],
                               capture_output=True, timeout=8, creationflags=0x08000000)
    if completed.returncode:
        return {'status':'unavailable'}
    value = json.loads(completed.stdout.decode('utf-8-sig'))
    return {'status':'sampled', 'scope':'physical-ipv4-default', 'success':value.get('success') is True,
            'delayMs':value.get('delayMs') if value.get('success') is True else None}


def gap_reason(previous, now, power):
    if previous is None:
        return 'baseline-unknown'
    if now < previous:
        return 'clock-backwards'
    if now-previous <= 300:
        return 'within-cadence'
    events = power.get('events', []) if power.get('status') == 'ok' else []
    sleeps = [parse_time(e.get('utc')) for e in events if e.get('id') == 42 and e.get('provider') == 'Microsoft-Windows-Kernel-Power']
    resumes = [parse_time(e.get('utc')) for e in events if e.get('id') == 1 and e.get('provider') == 'Microsoft-Windows-Power-Troubleshooter']
    if any(s is not None and previous <= s <= previous+120 and
           any(r is not None and s < r <= now and now-r <= 120 for r in resumes) for s in sleeps):
        return 'confirmed-sleep'
    stops = [parse_time(e.get('utc')) for e in events if e.get('id') == 13 and e.get('provider') == 'Microsoft-Windows-Kernel-General']
    starts = [parse_time(e.get('utc')) for e in events if e.get('id') == 12 and e.get('provider') == 'Microsoft-Windows-Kernel-General']
    if any(s is not None and previous <= s <= previous+120 and
           any(r is not None and s < r <= now and now-r <= 120 for r in starts) for s in stops):
        return 'confirmed-shutdown'
    return 'unexplained'


def archive_logs(logs, root, state, now, limit=32*MIB, deadline=None):
    copied = 0
    result = {'newFiles': 0, 'sourceBytes': 0, 'errors': 0, 'deferred': 0,
              'discardedPartialFiles': 0, 'prunedIndexEntries': 0}
    entries = state.setdefault('archives', {})
    for partial in (root/'archive').glob('*.gz.partial'):
        reject_links(partial)
        if not re.fullmatch('[a-f0-9]{64}\\.gz\\.partial',partial.name) or not partial.is_file():
            raise ValueError('Unexpected partial archive')
        partial.unlink()
        result['discardedPartialFiles'] += 1
    files = log_files(logs)
    newest = {}
    for path in files:
        if path.parent not in newest or path.stat().st_mtime > newest[path.parent].stat().st_mtime:
            newest[path.parent] = path
    source_keys = set()
    for path in files:
        stat = path.stat()
        key = digest(f'{stat.st_dev}:{stat.st_ino}:{stat.st_size}:{stat.st_mtime_ns}'.encode())
        source_keys.add(key)
        if newest[path.parent] == path:
            continue
        if key in entries:
            continue
        if (copied+stat.st_size > limit
                or deadline is not None and time.monotonic() >= deadline):
            result['deferred'] += 1
            continue
        destination = root/'archive'/(key+'.gz')
        partial = destination.with_suffix('.gz.partial')
        try:
            reject_links(path)
            # Denying write sharing proves no writer still holds this log on Windows.
            with shared_open(path, closed_only=True) as source, open(partial, 'xb') as compressed:
                with gzip.GzipFile(filename='',fileobj=compressed,mode='wb') as target:
                    remaining = stat.st_size
                    while remaining:
                        if deadline is not None and time.monotonic() >= deadline:
                            raise TimeoutError('Archive deferred at observation deadline')
                        data = source.read(min(65536, remaining))
                        if not data:
                            raise OSError('Source changed')
                        target.write(data); remaining -= len(data)
                compressed.flush(); os.fsync(compressed.fileno())
            os.replace(partial,destination)
            entries[key] = {'captured': now, 'bytes': destination.stat().st_size, 'sourceBytes': stat.st_size}
            copied += stat.st_size
            result['newFiles'] += 1
        except (OSError, ValueError) as exc:
            partial.unlink(missing_ok=True)
            if isinstance(exc, TimeoutError) or getattr(exc, 'winerror', None) == 32:
                result['deferred'] += 1
            else:
                result['errors'] += 1
    # Retain dedup while either the source or its retained archive exists.
    for key in set(entries)-source_keys:
        if not re.fullmatch('[a-f0-9]{64}',key):
            raise ValueError('Unexpected archive index key')
        archive = root/'archive'/(key+'.gz')
        reject_links(archive)
        if not archive.exists():
            del entries[key]
            result['prunedIndexEntries'] += 1
    result['sourceBytes'] = copied
    return result


def retention(root, state, now, timeline_limit=256*MIB, archive_limit=1536*MIB):
    removed = {'timelineFiles': 0, 'archiveFiles': 0, 'budgetLimited': False}
    for folder, limit, key in (('timeline', timeline_limit, 'timelineFiles'), ('archive', archive_limit, 'archiveFiles')):
        files = []
        for path in (root/folder).iterdir():
            reject_links(path)
            if not path.is_file():
                raise ValueError('Unexpected observer data entry')
            if folder == 'timeline':
                try:
                    created = datetime.strptime(path.stem, '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp()
                except ValueError:
                    raise ValueError('Unexpected timeline filename')
            else:
                if not re.fullmatch('[a-f0-9]{64}\\.gz', path.name):
                    raise ValueError('Unexpected archive filename')
                created = state.get('archives', {}).get(path.stem, {}).get('captured', path.stat().st_mtime)
            files.append((created, path, path.stat().st_size))
        total = sum(x[2] for x in files)
        for created, path, size in sorted(files):
            if now-created <= 30*DAY and total <= limit:
                continue
            if folder == 'timeline' and path.stem == utc(now)[:10]:
                removed['budgetLimited'] = True
                continue
            removed['budgetLimited'] |= now-created <= 30*DAY
            path.unlink()
            total -= size
            removed[key] += 1
    return removed


def append_record(root, record):
    if parse_time(record.get('observedUtc')) is None:
        raise ValueError('Invalid observation timestamp')
    path = root/'timeline'/(record['observedUtc'][:10]+'.jsonl')
    if path.exists():
        with open(path, 'r+b') as stream:
            stream.seek(0, 2)
            length = stream.tell()
            if length:
                stream.seek(max(0, length-128*1024))
                tail = stream.read()
                if tail.endswith(b'\n') and record.get('sampleId'):
                    previous = json.loads(tail.rstrip(b'\n').split(b'\n')[-1])
                    if previous.get('sampleId') == record['sampleId']:
                        return
                if not tail.endswith(b'\n'):
                    last = tail.rfind(b'\n')
                    stream.truncate(max(0, length-len(tail)+last+1))
                    record['repairedPartialRecord'] = True
    encoded = (json.dumps(record, separators=(',', ':'), ensure_ascii=True)+'\n').encode('ascii')
    if len(encoded) > 128*1024:
        raise ValueError('Oversized observation')
    with open(path, 'ab') as stream:
        stream.write(encoded); stream.flush(); os.fsync(stream.fileno())


def recover_pending(root):
    path = root/'pending.json'
    if not path.exists():
        return False
    if path.stat().st_size > 16*MIB:
        raise ValueError('Oversized pending commit')
    pending = json.loads(path.read_text())
    if pending.get('schemaVersion') != VERSION or not isinstance(pending.get('state'), dict):
        raise ValueError('Invalid pending commit')
    append_record(root, pending['record'])
    atomic_json(root/'state.json', pending['state'])
    path.unlink()
    return True


def commit_record(root, record, state):
    atomic_json(root/'pending.json', {'schemaVersion':VERSION,'record':record,'state':state})
    recover_pending(root)


def observe(app, root, label, active=False, service_owner_sid=None):
    started = time.monotonic(); now = time.time()
    stage_deadline = started+WORK_BUDGET_SECONDS-FINALIZE_RESERVE_SECONDS
    layout = runtime_layout(app, service_owner_sid)
    root = init_store(root)
    with single_writer(root):
        recovered = recover_pending(root)
        state_path = root/'state.json'
        checkpoint = 'new'
        try:
            if state_path.exists() and state_path.stat().st_size > 16*MIB:
                raise ValueError('Oversized checkpoint')
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            if not isinstance(state, dict) or state.get('schemaVersion', VERSION) != VERSION:
                raise ValueError('State schema')
            checkpoint = 'ok' if state else 'new'
            if not state and any((root/'timeline').iterdir()):
                checkpoint = 'invalid'
        except (ValueError, OSError):
            state = {}; checkpoint = 'invalid'
        if checkpoint == 'invalid':
            state['trafficSuspendedUntil'] = now+DAY
        previous = state.get('lastUtc')
        gap = now-previous if isinstance(previous, (int,float)) else None
        record = {'schemaVersion': VERSION, 'observedUtc': utc(now), 'label': label,
                  'sequence': state.get('sequence', 0)+1, 'checkpoint': checkpoint,
                  'gapSeconds': round(gap,3) if gap is not None else None,
                  'gapUnexplained': gap is not None and (gap > 300 or gap < 0),
                  'components': {}, 'stageDurationMs': {}, 'application': []}
        record['sampleId'] = digest(f'{label}:{time.time_ns()}:{record["sequence"]}'.encode())
        record['observerSha256'] = digest(Path(__file__).read_bytes())
        record['runtimeLayout'] = layout['kind']
        record['recoveredCommit'] = recovered
        runtime = None
        epoch = 'UNKNOWN'
        try:
            host = host_view(label); record['host'] = host
            cores = [p for p in host['processes'] if p['role'] == 'verge-mihomo.exe']
            # Process creation times identify the core; Windows boot_time is an estimate.
            epoch = digest(json.dumps(sorted(cores,key=lambda p:p['pid']),sort_keys=True).encode())
            record['coreEpoch'] = epoch
            record['components']['host'] = 'ok'
        except Exception as exc:
            record['components']['host'] = error_class(exc)
        try:
            with shared_open(layout['config']) as source:
                body = source.read(4*MIB+1)
            if len(body) > 4*MIB:
                raise ValueError('Oversized runtime file')
            runtime = stmc_yaml.load(body)
            record['runtimeHash'] = digest(body)
            controller = runtime.get('external-controller', '')
            if not re.fullmatch(r'127\.0\.0\.1:\d{1,5}', controller):
                raise ValueError('Controller must be loopback')
            port = int(controller.rsplit(':',1)[1]); secret = runtime.get('secret', '')
            raw = api_get(port, secret, '/proxies')
            record['native'] = native_view(raw.get('proxies', {}), state, time.time(), epoch)
            record['nativePolicy'] = {}
            for group in runtime.get('proxy-groups', []):
                if group.get('name') in ('VPS-LATENCY','VPS-POOL'):
                    record['nativePolicy'][group['name']] = {
                        field: group.get(field) if isinstance(group.get(field),(int,bool)) else None
                        for field in ('interval','timeout','tolerance','lazy','hidden')}
            record['components']['controller'] = 'ok'
            record['providers'] = {}
            # Optional metadata failures must not suppress independent leaf probes.
            try:
                providers = api_get(port, secret, '/providers/rules').get('providers', {})
                for name in ('ru-service-domains','tspu-foreign-domains'):
                    item = providers.get(name, {})
                    stamp = parse_time(item.get('updatedAt'))
                    record['providers'][name] = {'ruleCount': item.get('ruleCount') if isinstance(item.get('ruleCount'), int) else None,
                        'updatedUtc': utc(stamp) if stamp is not None else None,
                        'ageSeconds': round(now-stamp) if stamp is not None else None,
                        'intervalSeconds':None}
                    interval = runtime.get('rule-providers',{}).get(name,{}).get('interval')
                    if isinstance(interval,int):record['providers'][name]['intervalSeconds']=interval
                record['components']['providers'] = 'ok'
            except Exception as exc:
                record['components']['providers'] = error_class(exc)
            record['coreVersion'] = 'UNKNOWN'
            try:
                version = api_get(port, secret, '/version').get('version')
                record['coreVersion'] = version if isinstance(version,str) and re.fullmatch(r'[a-zA-Z0-9._+-]{1,100}', version) else 'UNKNOWN'
                record['components']['version'] = 'ok'
            except Exception as exc:
                record['components']['version'] = error_class(exc)
        except Exception as exc:
            record['components']['controller'] = error_class(exc)
        endpoints = {p['name']:p.get('server','') for p in (runtime or {}).get('proxies', [])
                     if p.get('name') in ('LT-OPENVPN','ELITECH-OPENVPN','OSEN-OPENVPN')}
        for key, function in (
            ('binaries', lambda: binary_view(state,label,layout)),
            ('logs', lambda: scan_logs(layout['logs'], state, endpoints)),
            ('archive', lambda: archive_logs(layout['logs'], root, state, now, deadline=stage_deadline)),
            ('power', lambda: windows_events(previous or now-60)),
            ('scheduler', lambda: scheduler_events(previous or now-60,
                'STCVRC-Observer-Lab' if label == 'lab' else 'STCVRC-Observer')),
            ('gateway', physical_gateway)):
            if time.monotonic() >= stage_deadline:
                record['components'][key] = 'deadline'
                continue
            stage_started = time.monotonic()
            try:
                record[key] = function(); record['components'][key] = 'ok'
            except Exception as exc:
                record['components'][key] = error_class(exc)
            finally:
                record['stageDurationMs'][key] = round((time.monotonic()-stage_started)*1000)
        day = utc(now)[:10]
        traffic_path = root/'traffic.json'
        try:
            budget = json.loads(traffic_path.read_text()) if traffic_path.exists() else {'day':day,'reserved':0}
            if not isinstance(budget.get('day'), str) or not isinstance(budget.get('reserved'), int):
                raise ValueError('Invalid traffic checkpoint')
            if not traffic_path.exists() and previous is not None:
                budget['suspendedUntil'] = now+DAY
        except (OSError,ValueError):
            budget = {'day':day,'reserved':0,'suspendedUntil':now+DAY}
        if day > budget['day']:
            budget.update(day=day, reserved=0)
        listeners = (runtime or {}).get('listeners', [])
        active_ready = (now >= max(state.get('trafficSuspendedUntil',0),budget.get('suspendedUntil',0)) and record['components']['controller'] == 'ok'
                        and all(x in listeners for x in LISTENERS))
        if active and active_ready and now-budget.get('lastApplication', 0) >= 300:
            budget['lastApplication'] = now
            # Sample both leaves before advancing to the next destination.
            for target in TARGETS:
                for listener in LISTENERS:
                    if budget['reserved']+8193 > 16*MIB or time.monotonic() >= stage_deadline:
                        record['application'].append({'leaf':listener['proxy'], 'target':target[0], 'errorClass':'budget-or-deadline', 'success':None})
                        continue
                    # Reserve before I/O; a killed worker cannot silently reset the traffic budget.
                    budget['reserved'] += 8193
                    atomic_json(traffic_path, budget)
                    probe = body_probe(listener['port'], target)
                    probe['leaf'] = listener['proxy']
                    record['application'].append(probe)
        atomic_json(traffic_path, budget)
        record['applicationMode'] = 'forced-leaves' if active and active_ready else 'disabled-or-listeners-missing'
        record['traffic'] = {'day': budget['day'], 'reservedBodyBytes': budget['reserved'], 'limitBodyBytes':16*MIB,
                             'transportOverheadMeasured': False}
        native_bytes = sum(p.stat().st_size for p in log_files(layout['logs']))
        archive_cap = max(0, min(1536*MIB, 3*1024*MIB-native_bytes-272*MIB))
        record['retention'] = retention(root, state, now, timeline_limit=256*MIB-128*1024, archive_limit=archive_cap)
        timeline_bytes = sum(p.stat().st_size for p in (root/'timeline').iterdir())
        if timeline_bytes > 256*MIB-128*1024:
            raise ValueError('Timeline daily capacity exhausted')
        record['storage'] = {'nativeLogBytes':native_bytes, 'archiveLimitBytes':archive_cap,
                             'nativeExceedsTotalBudget':native_bytes > 3*1024*MIB}
        record['gapReason'] = gap_reason(previous, now, record.get('power', {}))
        record['gapUnexplained'] = record['gapReason'] in ('clock-backwards','unexplained','baseline-unknown')
        record['durationMs'] = round((time.monotonic()-started)*1000)
        record['runtimeMutation'] = False
        state.update(schemaVersion=VERSION, sequence=record['sequence'], lastUtc=now)
        commit_record(root, record, state)
        return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-dir', type=Path, required=True)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--label', choices=('home','work','lab'), required=True)
    parser.add_argument('--active', action='store_true')
    parser.add_argument('--service-owner-sid')
    args = parser.parse_args()
    try:
        record = observe(args.app_dir, args.data_dir, args.label, args.active, args.service_owner_sid)
        print(json.dumps({k:record[k] for k in ('observedUtc','sequence','components','applicationMode','durationMs')}))
        return 0
    except Exception as exc:
        print(json.dumps({'status':'collector-failed','errorClass':error_class(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
