"""Bounded IPv4 subnet discovery and connect-only service observation.
No credentials, exploits, raw packet dependency or Internet target scans.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor,as_completed
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
import ctypes
import errno
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import psutil
from PySide6.QtCore import QThread,Signal

PRIVATE=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
SERVICES={21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS/TCP',80:'HTTP',110:'POP3',135:'RPC',139:'NetBIOS',143:'IMAP',443:'HTTPS',445:'SMB',515:'LPD',631:'IPP',1433:'SQL Server',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',8000:'HTTP alternate',8080:'HTTP alternate',8443:'HTTPS alternate',9100:'Print service'}
PROFILES={'Discovery':[80,443], 'Standard':[21,22,23,53,80,135,139,443,445,3389,5900,8080,8443,9100], 'Extended':sorted(SERVICES)}

def utc():return datetime.now(timezone.utc).isoformat(timespec='milliseconds')
def hidden_options():return {'creationflags':subprocess.CREATE_NO_WINDOW} if os.name=='nt' else {}

def command(args,timeout=3):
    try:
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,
            encoding='utf-8',errors='replace',**hidden_options())
        return result.returncode,result.stdout,result.stderr
    except (OSError,subprocess.TimeoutExpired) as exc:return -1,'',str(exc)

def normalize_mac(value):
    cleaned=re.sub(r'[^0-9a-fA-F]','',str(value))
    if len(cleaned)!=12 or cleaned.lower() in ('000000000000','ffffffffffff'):return ''
    if int(cleaned[:2],16)&1:return ''
    return ':'.join(cleaned[i:i+2].upper() for i in range(0,12,2))

def validate_scope(value,max_hosts=4094,allow_loopback=False):
    try:network=ipaddress.ip_network(value.strip(),strict=False)
    except ValueError as exc:raise ValueError('Enter an IPv4 subnet such as 192.168.1.0/24.') from exc
    if network.version!=4:raise ValueError('This release discovers IPv4 subnets. IPv6 host sockets remain available in Workstation inspector.')
    if not any(network.subnet_of(n) for n in PRIVATE) and not (allow_loopback and network.subnet_of(ipaddress.ip_network('127.0.0.0/8'))):
        raise ValueError('Choose an RFC1918 private subnet: 10.x, 172.16-31.x, or 192.168.x.')
    count=network.num_addresses if network.prefixlen>=31 else network.num_addresses-2
    if count>max_hosts:raise ValueError(f'This scope has {count:,} host addresses. Select a smaller subnet; this release scans at most {max_hosts:,} per run.')
    return network

def parse_ports(text):
    ports=set()
    for item in text.split(','):
        item=item.strip()
        if not item:continue
        if '-' in item:
            a,b=(int(n.strip()) for n in item.split('-',1))
            if not 1<=a<=b<=65535 or b-a>63:raise ValueError('Use port ranges within 1..65535, at most 64 ports total.')
            ports.update(range(a,b+1))
        else:ports.add(int(item))
    if not ports or len(ports)>64 or any(not 1<=p<=65535 for p in ports):raise ValueError('Choose 1 to 64 TCP ports, each within 1..65535.')
    return sorted(ports)

def routes():
    if os.name=='nt':
        code,out,_=command(['route','print','-4'],4)
        candidates=[]
        for line in out.splitlines():
            m=re.match(r'\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+([\d.]+)\s+(\d+)',line)
            if m:candidates.append({'gateway':m[1],'source':m[2],'metric':int(m[3])})
        return sorted(candidates,key=lambda r:r['metric'])
    result=[]
    try:
        for line in Path('/proc/net/route').read_text().splitlines()[1:]:
            f=line.split()
            if len(f)>7 and f[1]=='00000000' and int(f[3],16)&2:
                result.append({'interface':f[0],'gateway':socket.inet_ntoa(struct.pack('<I',int(f[2],16))),'metric':int(f[6])})
    except (OSError,ValueError):pass
    return sorted(result,key=lambda r:r['metric'])

def detect_profiles():
    warnings=[]
    try:addresses=psutil.net_if_addrs()
    except (psutil.Error,OSError) as exc:addresses={};warnings.append('Adapter addresses unavailable: '+str(exc))
    try:stats=psutil.net_if_stats()
    except (psutil.Error,OSError) as exc:stats={};warnings.append('Link status unavailable: '+str(exc))
    route_list=routes();profiles=[]
    for name,items in addresses.items():
        st=stats.get(name)
        if st and not st.isup:continue
        mac=next((normalize_mac(a.address) for a in items if a.family not in (socket.AF_INET,socket.AF_INET6)), '')
        for address in items:
            if address.family!=socket.AF_INET or not address.netmask:continue
            try:
                ip=ipaddress.ip_address(address.address)
                if not any(ip in n for n in PRIVATE):continue
                network=ipaddress.ip_network(f'{ip}/{address.netmask}',strict=False)
            except ValueError:continue
            route=next((r for r in route_list if r.get('source')==str(ip) or r.get('interface')==name),{})
            profiles.append({'name':name,'ip':str(ip),'mask':address.netmask,'scope':str(network),'gateway':route.get('gateway',''),
                             'mac':mac,'default':bool(route),'metric':route.get('metric',999999),'up':st.isup if st else None})
    return sorted(profiles,key=lambda r:(not r['default'],r['metric'],r['name'])),warnings

class ProfileWorker(QThread):
    ready=Signal(object,object)
    def run(self):
        try:p,w=detect_profiles();self.ready.emit(p,w)
        except Exception as exc:self.ready.emit([],['Adapter detection failed: '+str(exc)])

def neighbors(profile,network):
    found={}
    if os.name=='nt':
        args=['arp','-a']
        if profile.get('ip'):args+=['-N',profile['ip']]
        _,out,_=command(args,4)
        for line in out.splitlines():
            m=re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})\s+',line)
            if m:
                try:
                    mac=normalize_mac(m[2]);ip=ipaddress.ip_address(m[1])
                    if mac and ip in network:found[str(ip)]=mac
                except ValueError:pass
    else:
        try:
            for line in Path('/proc/net/arp').read_text().splitlines()[1:]:
                f=line.split()
                if len(f)>=6 and (not profile.get('name') or f[5]==profile['name']):
                    mac=normalize_mac(f[3]);ip=ipaddress.ip_address(f[0])
                    if mac and int(f[2],16)&2 and ip in network:found[str(ip)]=mac
        except (OSError,ValueError):pass
    return found

def windows_arp(address,source=''):
    if os.name!='nt':return ''
    try:
        target=struct.unpack('=I',socket.inet_aton(address))[0]
        src=struct.unpack('=I',socket.inet_aton(source))[0] if source else 0
        buffer=(ctypes.c_ubyte*8)();length=ctypes.c_ulong(8)
        code=ctypes.WinDLL('iphlpapi').SendARP(ctypes.c_ulong(target),ctypes.c_ulong(src),buffer,ctypes.byref(length))
        if code==0 and length.value==6:return normalize_mac(bytes(buffer[:6]).hex())
    except (OSError,ValueError):pass
    return ''

class RateLimit:
    def __init__(self,rate=80):self.delay=1/max(1,rate);self.next=0;self.lock=threading.Lock()
    def acquire(self,cancel):
        with self.lock:
            when=max(time.monotonic(),self.next);self.next=when+self.delay
        while time.monotonic()<when:
            if cancel.wait(min(.05,when-time.monotonic())):return False
        return not cancel.is_set()

@dataclass
class ScanOptions:
    scope:str
    profile:dict=field(default_factory=dict)
    ports:list=field(default_factory=lambda:PROFILES['Standard'].copy())
    profile_name:str='Standard'
    workers:int=24
    timeout:float=.35
    rate:int=80
    resolve:bool=True
    metadata:bool=True
    def validate(self,allow_loopback=False):
        network=validate_scope(self.scope,allow_loopback=allow_loopback)
        if not self.ports or len(self.ports)>64 or any(type(p) is not int or not 1<=p<=65535 for p in self.ports):raise ValueError('Invalid TCP port selection.')
        if not 1<=self.workers<=64:raise ValueError('Concurrency must be 1..64.')
        if not math.isfinite(self.timeout) or not .1<=self.timeout<=3:raise ValueError('Connection timeout must be 0.1..3 seconds.')
        if not 1<=self.rate<=200:raise ValueError('Probe rate must be 1..200 per second.')
        if self.profile.get('scope'):
            attached=ipaddress.ip_network(self.profile['scope'],strict=False)
            if not network.subnet_of(attached):raise ValueError('Selected scope must be inside this adapter subnet. Refresh adapters or choose Manual scope.')
        self.scope=str(network);return network

class VendorDB:
    def __init__(self,path=None):
        try:self.data=json.loads(Path(path or Path(__file__).resolve().parents[1]/'assets/oui.json').read_text(encoding='utf-8'))
        except (OSError,ValueError):self.data={}
    def lookup(self,mac):
        mac=normalize_mac(mac)
        if not mac:return 'Unavailable'
        if int(mac[:2],16)&2:return 'Private / randomized MAC'
        key=mac.replace(':','')
        return next((self.data[key[:length]] for length in (9,7,6) if key[:length] in self.data),'Prefix not in bundled registry')

def ping_once(address):
    binary=shutil.which('ping')
    if not binary:return False,None,'ICMP utility unavailable'
    args=[binary,'-n','1','-w','800',address] if os.name=='nt' else [binary,'-n','-c','1','-W','1',address]
    code,out,err=command(args,2)
    # Windows can return success for an ICMP unreachable report. Require an echo-reply TTL.
    good=code==0 and re.search(r'\bttl\s*[=:]\s*\d+',out,re.I) is not None
    m=re.search(r'time\s*([=<])\s*([\d.]+)\s*ms',out,re.I)
    return good,(float(m[2]) if m else None),'' if good else ('No ICMP echo reply' if code!=-1 else err[:200])

def tcp_probe(address,port,timeout):
    started=time.monotonic()
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout);code=connection.connect_ex((address,port))
        elapsed=round((time.monotonic()-started)*1000,2)
        if code==0:return 'Open',elapsed
        if code in (errno.ECONNREFUSED,10061):return 'Refused',elapsed
        return 'No response',None
    except (OSError,TimeoutError):return 'No response',None

def reverse_name(address):
    script='import socket,json,sys; print(json.dumps(socket.gethostbyaddr(sys.argv[1])[0],ensure_ascii=True))'
    runtime=Path(sys.executable).with_name('python.exe') if os.name=='nt' and Path(sys.executable).name.lower()=='pythonw.exe' else Path(sys.executable)
    code,out,_=command([str(runtime),'-c',script,address],1.3)
    try:return str(json.loads(out))[:255] if code==0 else ''
    except ValueError:return ''

def web_metadata(address,port,timeout=1.2):
    result={'port':port};secure=port in (443,8443);connection=None
    try:
        if secure:
            context=ssl.create_default_context()
            try:
                with socket.create_connection((address,port),timeout=timeout) as raw:
                    with context.wrap_socket(raw,server_hostname=address) as tls:
                        cert=tls.getpeercert();result['tls']={'verified':True,'not_after':cert.get('notAfter',''),'subject':str(cert.get('subject',()))[:512],
                            'sha256':hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()}
            except ssl.SSLCertVerificationError as exc:
                result['tls']={'verified':False,'verification_error':str(exc)[:512]}
                # Observation only: collect the presented certificate fingerprint. Do not claim trust.
                with socket.create_connection((address,port),timeout=timeout) as raw:
                    with ssl._create_unverified_context().wrap_socket(raw,server_hostname=address) as tls:
                        result['tls']['sha256']=hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                return result
            connection=http.client.HTTPSConnection(address,port,timeout=timeout,context=context)
        else:connection=http.client.HTTPConnection(address,port,timeout=timeout)
        connection.request('HEAD','/',headers={'User-Agent':'ConnWatch-Network/3.0','Connection':'close'})
        response=connection.getresponse();result['status']=response.status
        for key in ('Server','Content-Type','Location'):result[key.lower()]=(response.getheader(key) or '')[:512]
    except (OSError,ValueError,http.client.HTTPException) as exc:result['observation_error']=str(exc)[:300]
    finally:
        if connection:connection.close()
    return result

def probe_host(address,options,cancel,limiter,cached=None,vendors=None):
    start=time.monotonic();record={'ip':address,'time':utc(),'presence':'No response','mac':'','vendor':'Unavailable','hostname':'','role':'Unclassified',
        'icmp':False,'response_ms':None,'ports':{},'web':[],'evidence':[],'observations':[],'checked_ports':[],'requested_ports':options.ports,'duration_ms':0}
    cached=cached or {};vendors=vendors or VendorDB()
    if address==options.profile.get('ip'):
        record['presence']='Responding';record['evidence'].append('Selected adapter address');record['mac']=options.profile.get('mac','');record['role']='This workstation'
    if not limiter.acquire(cancel):return None
    good,latency,error=ping_once(address);record['icmp']=good
    if good:record['presence']='Responding';record['response_ms']=latency;record['evidence'].append('ICMP echo reply')
    if error:record['observations'].append(error)
    initial=[p for p in (443,80) if p in options.ports] or options.ports[:2]
    def check(port):
        if not limiter.acquire(cancel):return False
        status,latency=tcp_probe(address,port,options.timeout);record['ports'][str(port)]={'state':status,'service_hint':SERVICES.get(port,'TCP service')};record['checked_ports'].append(port)
        if status in ('Open','Refused'):
            record['presence']='Responding';record['evidence'].append(f'TCP {status.lower()} response on {port}')
            if record['response_ms'] is None:record['response_ms']=latency
        return True
    for port in initial:
        if not check(port):break
    mac=cached.get(address,'')
    if os.name=='nt' and not mac and not cancel.is_set():
        if limiter.acquire(cancel):mac=windows_arp(address,options.profile.get('ip',''))
        if mac:record['evidence'].append('Windows ARP observation')
    if mac:record['mac']=mac;record['evidence'].append('ARP / neighbor-table MAC available')
    if record['presence']=='No response' and mac:record['presence']='Neighbor observed'
    if record['presence']!='No response':
        for port in options.ports:
            if port not in record['checked_ports'] and not check(port):break
        if options.resolve and not cancel.is_set():record['hostname']=reverse_name(address)
        if options.metadata:
            for key,observation in record['ports'].items():
                port=int(key)
                if port in (80,443,8080,8443) and observation['state']=='Open' and not cancel.is_set():
                    if limiter.acquire(cancel):record['web'].append(web_metadata(address,port))
    if address==options.profile.get('gateway'):record['role']='Gateway'
    elif record['role']!='This workstation' and any(record['ports'].get(str(p),{}).get('state')=='Open' for p in (515,631,9100)):record['role']='Print services observed'
    record['vendor']=vendors.lookup(record['mac']);record['duration_ms']=round((time.monotonic()-start)*1000,2)
    record['complete_port_profile']=set(record['checked_ports'])==set(options.ports)
    record['cancelled']=cancel.is_set()
    return record

class DiscoveryWorker(QThread):
    batch=Signal(object)
    progress=Signal(int,int,str)
    complete=Signal(object)
    failed=Signal(str)
    def __init__(self,options,parent=None,probe=None,allow_loopback=False):
        super().__init__(parent);self.options=options;self.cancel=threading.Event();self.probe=probe or probe_host;self.allow_loopback=allow_loopback
    def stop(self):self.cancel.set();self.requestInterruption()
    def run(self):
        try:
            network=self.options.validate(self.allow_loopback);targets=[str(ip) for ip in network.hosts()];total=len(targets)
            cache=neighbors(self.options.profile,network);vendors=VendorDB();limiter=RateLimit(self.options.rate)
            batch=[];completed=0;responding=0;started=time.monotonic();self.progress.emit(0,total,'Discovering selected subnet')
            executor=ThreadPoolExecutor(max_workers=self.options.workers)
            futures={executor.submit(self.probe,ip,self.options,self.cancel,limiter,cache,vendors):ip for ip in targets}
            try:
                for future in as_completed(futures):
                    if future.cancelled():continue
                    try:record=future.result()
                    except Exception as exc:record={'ip':futures[future],'time':utc(),'presence':'Probe error','ports':{},'evidence':[], 'observations':[str(exc)[:300]],'requested_ports':self.options.ports,'checked_ports':[]}
                    if record is not None:
                        batch.append(record);completed+=1;responding+=record['presence']=='Responding'
                    if len(batch)>=8 or self.cancel.is_set():
                        if batch:self.batch.emit(batch);batch=[]
                    self.progress.emit(completed,total,'Stopping outstanding probes' if self.cancel.is_set() else f'{responding} responding addresses')
                    if self.cancel.is_set():
                        for queued in futures:queued.cancel()
            finally:executor.shutdown(wait=True,cancel_futures=True)
            if batch:self.batch.emit(batch)
            # A refreshed neighbor table can enrich MAC visibility without inventing a live response.
            after=neighbors(self.options.profile,network)
            self.complete.emit({'status':'Cancelled' if self.cancel.is_set() else 'Completed','completed':completed,'total':total,
                'duration_seconds':round(time.monotonic()-started,2),'neighbors':after,'ended':utc()})
        except Exception as exc:self.failed.emit(f'{type(exc).__name__}: {exc}')
