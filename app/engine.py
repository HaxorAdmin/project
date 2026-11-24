"""Background collectors. Qt widgets and SQLite stay on the GUI thread."""
from __future__ import annotations
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
import platform
import socket
import time
import psutil
from PySide6.QtCore import QThread, Signal
from .detection import Connection, snapshot


def process_details(pid,expected_started=None):
    if pid is None:return {'error':'No visible process ID. Try an elevated launch on your own machine.'}
    try:
        p=psutil.Process(pid)
        if expected_started is not None and abs(p.create_time()-expected_started)>0.01:
            return {'error':'This PID has been reused. Refresh before inspecting this process.'}
        result={'pid':pid}
        for name,fn in [('name',p.name),('exe',p.exe),('username',p.username),('created',p.create_time),
                        ('command',lambda:' '.join(p.cmdline())),('memory',lambda:p.memory_info().rss)]:
            try:result[name]=fn()
            except (psutil.Error,OSError):result[name]='Unavailable'
        return result
    except (psutil.Error,OSError) as exc:return {'error':str(exc) or 'Process exited or access was denied.'}


def adapters(warnings=None):
    warnings=warnings if warnings is not None else []
    def read(fn,label):
        try:return fn()
        except (psutil.Error,OSError) as exc:
            warnings.append(label+' unavailable: '+str(exc));return {}
    stats=read(psutil.net_if_stats,'Interface link status')
    addresses=read(psutil.net_if_addrs,'Interface addresses')
    counts=read(lambda:psutil.net_io_counters(pernic=True),'Interface counters')
    result=[]
    for name in sorted(set(stats)|set(addresses)|set(counts)):
        entries=addresses.get(name,[]);st=stats.get(name);io=counts.get(name)
        result.append({'name':name,'up':st.isup if st else None,'speed':st.speed if st else None,
            'ipv4':', '.join(a.address for a in entries if a.family==socket.AF_INET) or 'Unavailable',
            'ipv6':', '.join(a.address for a in entries if a.family==socket.AF_INET6) or 'Unavailable',
            'sent':io.bytes_sent if io else None,'recv':io.bytes_recv if io else None})
    return result


def synthetic(index):
    result=[]
    services=[('demo-browser',1200,'198.51.100.20',443,'tcp'),('demo-sync',1300,'198.51.100.30',443,'tcp'),
              ('demo-updater',1400,'203.0.113.80',8443,'tcp'),('demo-dns',1500,'192.0.2.53',53,'udp'),
              ('demo-client',2200,'203.0.113.50',4444,'tcp'),('demo-backup',1600,'198.51.100.44',22,'tcp')]
    for i in range(18+index%5):
        name,pid,address,port,proto=services[i%len(services)]
        result.append(Connection(proto,'192.0.2.10',51000+i,address,port,'ESTABLISHED' if proto=='tcp' else 'NONE',pid,name,float(pid)))
    if index>=4:result.append(Connection('tcp','192.0.2.10',53000,'203.0.113.99',9443,'ESTABLISHED',2300,'demo-telemetry',2300))
    if index%10==8:
        result.extend(Connection('tcp','192.0.2.10',54000+i,'198.51.100.30',443,'ESTABLISHED',1300,'demo-sync',1300) for i in range(16))
    result.extend([Connection('tcp','127.0.0.1',8000,'',0,'LISTEN',1700,'demo-local-api',1700),
                   Connection('udp','0.0.0.0',5353,'',0,'NONE',1800,'demo-discovery',1800)])
    return result

class ScanWorker(QThread):
    ready=Signal(object)
    failed=Signal(str)
    def __init__(self,demo=False,index=0,parent=None):super().__init__(parent);self.demo=demo;self.index=index
    def run(self):
        try:
            now=datetime.now(timezone.utc).isoformat(timespec='milliseconds')
            if self.demo:
                connections=synthetic(self.index)
                data={'time':now,'connections':connections,'warnings':['SYNTHETIC DEMO: all processes, endpoints and traffic are simulated.'],
                    'network':[{'name':'Demo Ethernet','up':True,'speed':1000,'ipv4':'192.0.2.10','ipv6':'2001:db8::10','sent':500000+self.index*90000,'recv':900000+self.index*240000}],
                    'traffic':{'sent':500000+self.index*90000,'recv':900000+self.index*240000},'monotonic':time.monotonic()}
            else:
                connections,warnings=snapshot();network=adapters(warnings)
                try:io=psutil.net_io_counters()
                except (psutil.Error,OSError) as exc:io=None;warnings.append('Host traffic counters unavailable: '+str(exc))
                data={'time':now,'connections':connections,'warnings':warnings,'network':network,
                      'traffic':{'sent':io.bytes_sent,'recv':io.bytes_recv} if io else None,'monotonic':time.monotonic()}
            self.ready.emit(data)
        except Exception as exc:self.failed.emit(f'{type(exc).__name__}: {exc}')

class DetailWorker(QThread):
    ready=Signal(object)
    def __init__(self,pid,started,parent=None):super().__init__(parent);self.pid=pid;self.started=started
    def run(self):self.ready.emit(process_details(self.pid,self.started))

class HashWorker(QThread):
    ready=Signal(str)
    failed=Signal(str)
    def __init__(self,path,parent=None):super().__init__(parent);self.path=path
    def run(self):
        try:
            digest=hashlib.sha256();size=0
            with open(self.path,'rb') as f:
                before=os.fstat(f.fileno())
                while True:
                    if self.isInterruptionRequested():return
                    block=f.read(1024*1024)
                    if not block:break
                    size+=len(block)
                    if size>1024*1024*1024:raise ValueError('File exceeds the 1 GiB hash limit.')
                    digest.update(block)
                after=os.fstat(f.fileno())
                if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('File changed during hashing. Try again.')
            self.ready.emit(digest.hexdigest())
        except Exception as exc:self.failed.emit(str(exc))
