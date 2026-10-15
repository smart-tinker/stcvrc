"""Opt-in userVM corporate canaries. Never changes a selector or stores HTTP bodies."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.parse import urlsplit


LEAVES=(('LT-OPENVPN','LT Gitlab',18983),('ELITECH-OPENVPN','Elitech Gitlab',18984))


def corporate_dns(runtime,hostname,leaf):
    matches=[]
    for pattern,servers in runtime.get('dns',{}).get('nameserver-policy',{}).items():
        suffix=pattern[2:] if pattern.startswith('+.') else pattern
        if hostname==suffix or (pattern.startswith('+.') and hostname.endswith('.'+suffix)):
            matches.append((len(suffix),servers))
    if not matches:
        raise ValueError('Corporate canary requires its existing DNS policy')
    servers=max(matches,key=lambda item:item[0])[1]
    servers=servers if isinstance(servers,list) else [servers]
    route=leaf.replace('-OPENVPN','-ROUTE')
    if not servers or any(not isinstance(s,str) or s.count('#')!=1 or s.split('#')[1]!=route for s in servers):
        raise ValueError('Corporate DNS must be pinned to its own approved route')
    return [s.split('#')[0]+'#'+leaf for s in servers]


def add_corporate_canaries(profile,runtime,settings):
    result=copy.deepcopy(profile)
    probes=[]
    policies={}
    for name,site,port in LEAVES:
        leaves=[item for item in runtime.get('proxies',[]) if item.get('name')==name]
        sites=[item for item in settings.get('test_list',[]) if item.get('name')==site]
        if len(leaves)!=1 or leaves[0].get('type')!='openvpn' or leaves[0].get('dialer-proxy'):
            raise ValueError('Expected an independent corporate OpenVPN leaf')
        if len(sites)!=1:
            raise ValueError('Expected one existing corporate site canary')
        url=sites[0]['url'];parsed=urlsplit(url)
        if (parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError('Corporate canary URL must not contain credentials or query data')
        for key in ('ca','cert','key','tls-auth','tls-crypt'):
            value=leaves[0].get(key)
            if value and (not isinstance(value,str) or '-----BEGIN ' not in value):
                raise ValueError('External credential files require separate lab staging')
        if any(p.get('name')==name for p in result['proxies']):
            raise ValueError('Corporate leaf collision')
        listener={'name':'STCVRC-LAB-'+name,'type':'http','listen':'127.0.0.1',
                  'port':port,'proxy':name}
        if any(p.get('port')==port or p.get('name')==listener['name'] for p in result.get('listeners',[])):
            raise ValueError('Corporate listener collision')
        result['proxies'].append(copy.deepcopy(leaves[0]))
        result.setdefault('listeners',[]).append(listener)
        policies[parsed.hostname]=corporate_dns(runtime,parsed.hostname,name)
        probes.append({'leaf':name,'port':port,'url':url})
    # Keep private DNS inside its leaf without adding a host DNS listener or TUN.
    result['dns']={'enable':True,'listen':'','enhanced-mode':'redir-host','ipv6':False,
                   'respect-rules':False,'nameserver':['system://'],
                   'default-nameserver':['system://'],'nameserver-policy':policies}
    return result,probes


def probe(items):
    results=[]
    curl=Path(os.environ['WINDIR'])/'System32/curl.exe'
    for item in items:
        if (item['leaf'],item['port']) not in {(leaf,port) for leaf,_,port in LEAVES}:
            raise ValueError('Unexpected leaf/listener')
        started=time.monotonic()
        response=subprocess.run([str(curl),'--disable','--silent','--show-error',
            '--proxy','http://127.0.0.1:'+str(item['port']),'--noproxy','',
            '--max-time','25','--max-filesize','131072','--output','NUL',
            '--write-out','%{http_code}|%{size_download}',item['url']],
            capture_output=True,timeout=28,creationflags=0x08000000)
        fields=response.stdout.decode('ascii').strip().split('|')
        if len(fields)!=2 or not all(field.isdigit() for field in fields):
            raise ValueError('Unexpected curl summary')
        status,size=map(int,fields)
        results.append({'leaf':item['leaf'],'status':status,'bodyBytes':size,
            'bodyComplete':response.returncode==0,'curlExit':response.returncode,
            'durationMs':round((time.monotonic()-started)*1000),
            'success':response.returncode==0 and status in (200,301,302,303,307,308)})
    return {'checks':results,'pass':len(results)==2 and all(row['success'] for row in results)}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(probe(json.loads(args.probe.read_text()))))
