"""Persistent subnet scan evidence, device annotations and scoped change records."""
from __future__ import annotations
import csv
from datetime import datetime,timezone,timedelta
import html
import json
from pathlib import Path
import sqlite3
import uuid
from .discovery import utc,VendorDB,SERVICES,normalize_mac


def exposures(device):
    opened={int(p) for p,v in device.get('ports',{}).items() if v.get('state')=='Open'}
    result=[]
    for port in sorted(opened & {21,23,110,143}):result.append(f'Review potential cleartext service on TCP {port} ({SERVICES[port]})')
    for port in sorted(opened & {22,3389,5900}):result.append(f'Possible remote-administration service on TCP {port} ({SERVICES[port]})')
    if 445 in opened:result.append('SMB reachable on TCP 445; verify that file sharing is expected')
    for web in device.get('web',[]):
        if web.get('tls',{}).get('verified') is False:result.append(f"TLS trust/name validation failed on {web['port']}; inspect the certificate context")
    return result

def compare_records(previous,current):
    before={d['ip']:d for d in previous if d.get('presence') in ('Responding','Neighbor observed')}
    after={d['ip']:d for d in current if d.get('presence') in ('Responding','Neighbor observed')}
    changes=[]
    for ip in sorted(set(after)-set(before)):changes.append({'ip':ip,'kind':'New address observed','detail':after[ip]['presence']})
    errors={d['ip'] for d in current if d.get('presence')=='Probe error'}
    for ip in sorted(set(before)-set(after)-errors):changes.append({'ip':ip,'kind':'Not observed this scan','detail':'No observation in this scan; this is not proof the device is offline.'})
    for ip in sorted(set(before)&set(after)):
        a,b=before[ip],after[ip]
        if a.get('mac') and b.get('mac') and a['mac']!=b['mac']:changes.append({'ip':ip,'kind':'MAC identity changed','detail':a['mac']+' -> '+b['mac']})
        if a.get('hostname') and b.get('hostname') and a['hostname']!=b['hostname']:changes.append({'ip':ip,'kind':'Hostname changed','detail':a['hostname']+' -> '+b['hostname']})
        common=set(a.get('ports',{}))&set(b.get('ports',{}))
        for p in sorted(common,key=int):
            old=a['ports'][p]['state'];new=b['ports'][p]['state']
            if old!=new and (old=='Open' or new=='Open'):
                changes.append({'ip':ip,'kind':'TCP service state changed','detail':f'TCP {p}: {old} -> {new}'})
    return changes

class InventoryStore:
    def __init__(self,directory):
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(self.directory/'network.db');self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON');self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS network_scans(id TEXT PRIMARY KEY,started TEXT NOT NULL,ended TEXT,status TEXT NOT NULL,scope TEXT NOT NULL,options TEXT NOT NULL,total INTEGER NOT NULL,summary TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS observations(scan_id TEXT NOT NULL REFERENCES network_scans(id) ON DELETE CASCADE,ip TEXT NOT NULL,time TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(scan_id,ip));
        CREATE TABLE IF NOT EXISTS assets(scope TEXT NOT NULL,ip TEXT NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,last_scan TEXT NOT NULL,label TEXT NOT NULL DEFAULT '',owner TEXT NOT NULL DEFAULT '',review TEXT NOT NULL DEFAULT 'Unreviewed',notes TEXT NOT NULL DEFAULT '',payload TEXT NOT NULL,PRIMARY KEY(scope,ip));
        CREATE TABLE IF NOT EXISTS network_changes(id INTEGER PRIMARY KEY,scan_id TEXT NOT NULL REFERENCES network_scans(id) ON DELETE CASCADE,ip TEXT NOT NULL,kind TEXT NOT NULL,detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS annotation_journal(id INTEGER PRIMARY KEY,time TEXT NOT NULL,scope TEXT NOT NULL,ip TEXT NOT NULL,label TEXT NOT NULL,owner TEXT NOT NULL,review TEXT NOT NULL,notes TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS net_scan_scope ON network_scans(scope,started);
        ''')
        with self.db:self.db.execute("UPDATE network_scans SET status='Interrupted',ended=? WHERE status='Running'",(utc(),))
    def begin(self,options,total):
        sid=uuid.uuid4().hex
        with self.db:self.db.execute('INSERT INTO network_scans(id,started,status,scope,options,total) VALUES(?,?,?,?,?,?)',(sid,utc(),'Running',options['scope'],json.dumps(options),total))
        return sid
    def record(self,sid,records):
        scan=self.get_scan(sid)
        with self.db:
            for d in records:
                if not d.get('ip'):raise ValueError('An observation requires an IP address.')
                self.db.execute('INSERT OR REPLACE INTO observations VALUES(?,?,?,?)',(sid,d['ip'],d['time'],json.dumps(d)))
                if d.get('presence') in ('Responding','Neighbor observed'):
                    payload={**d,'review_findings':exposures(d)}
                    self.db.execute('''INSERT INTO assets(scope,ip,first_seen,last_seen,last_scan,payload) VALUES(?,?,?,?,?,?)
                        ON CONFLICT(scope,ip) DO UPDATE SET last_seen=excluded.last_seen,last_scan=excluded.last_scan,payload=excluded.payload''',
                        (scan['scope'],d['ip'],d['time'],d['time'],sid,json.dumps(payload)))
    def finish(self,sid,summary):
        scan=self.get_scan(sid);enriched=[];vendors=VendorDB()
        for d in self.records(sid):
            mac=summary.get('neighbors',{}).get(d['ip'])
            if mac and not d.get('mac'):
                d['mac']=normalize_mac(mac);d['vendor']=vendors.lookup(d['mac'])
                d.setdefault('evidence',[]).append('Neighbor table observed after the address sweep')
                if d.get('presence')=='No response':d['presence']='Neighbor observed'
                enriched.append(d)
        if enriched:self.record(sid,enriched)
        records=self.records(sid)
        summary={**summary,'responding':sum(d.get('presence')=='Responding' for d in records),
            'observed':sum(d.get('presence') in ('Responding','Neighbor observed') for d in records),'recorded':len(records),'probe_errors':sum(d.get('presence')=='Probe error' for d in records)}
        previous=self.db.execute("SELECT id,started FROM network_scans WHERE scope=? AND id<>? AND status='Completed' AND rowid<(SELECT rowid FROM network_scans WHERE id=?) ORDER BY rowid DESC LIMIT 1",(scan['scope'],sid,sid)).fetchone()
        summary['compared_to']={'scan_id':previous[0],'started':previous[1]} if previous else None
        # Cancelled/failed/partial scans never create false disappearance events.
        changes=compare_records(self.records(previous[0]),records) if previous and summary['status']=='Completed' else []
        with self.db:
            self.db.execute('UPDATE network_scans SET status=?,ended=?,summary=? WHERE id=?',(summary['status'],summary.get('ended',utc()),json.dumps(summary),sid))
            self.db.execute('DELETE FROM network_changes WHERE scan_id=?',(sid,))
            for change in changes:self.db.execute('INSERT INTO network_changes(scan_id,ip,kind,detail) VALUES(?,?,?,?)',(sid,change['ip'],change['kind'],change['detail']))
        return summary
    def scans(self):
        return [dict(r) for r in self.db.execute('SELECT *,(SELECT COUNT(*) FROM observations WHERE scan_id=network_scans.id) recorded FROM network_scans ORDER BY rowid DESC')]
    def get_scan(self,sid):
        r=self.db.execute('SELECT * FROM network_scans WHERE id=?',(sid,)).fetchone()
        if not r:raise ValueError('Choose a saved network scan.')
        d=dict(r);d['options']=json.loads(d['options']);d['summary']=json.loads(d['summary']);return d
    def records(self,sid):return [json.loads(r[0]) for r in self.db.execute('SELECT payload FROM observations WHERE scan_id=? ORDER BY ip',(sid,))]
    def devices(self,scope=None,sid=None):
        sql='SELECT * FROM assets';args=()
        if scope:sql+=' WHERE scope=?';args=(scope,)
        sql+=' ORDER BY last_seen DESC';result=[]
        for r in self.db.execute(sql,args):
            d=dict(r);d['data']=json.loads(d.pop('payload'));d['current']=not sid or d['last_scan']==sid;result.append(d)
        return result
    def annotate(self,scope,ip,label,owner,review,notes):
        if review not in ('Unreviewed','Expected','Investigate'):raise ValueError('Invalid review decision.')
        with self.db:
            self.db.execute('UPDATE assets SET label=?,owner=?,review=?,notes=? WHERE scope=? AND ip=?',(label[:200],owner[:200],review,notes[:5000],scope,ip))
            self.db.execute('INSERT INTO annotation_journal(time,scope,ip,label,owner,review,notes) VALUES(?,?,?,?,?,?,?)',(utc(),scope,ip,label[:200],owner[:200],review,notes[:5000]))
    def changes(self,sid=None):
        query='SELECT c.*,s.started,s.scope FROM network_changes c JOIN network_scans s ON c.scan_id=s.id';args=()
        if sid:query+=' WHERE scan_id=?';args=(sid,)
        return [dict(r) for r in self.db.execute(query+' ORDER BY c.id DESC LIMIT 10000',args)]
    def history(self,scope,ip):
        return [dict(r) for r in self.db.execute('SELECT s.started,s.status,o.payload FROM observations o JOIN network_scans s ON o.scan_id=s.id WHERE s.scope=? AND o.ip=? ORDER BY s.started DESC LIMIT 100',(scope,ip))]
    def note_history(self,scope,ip):return [dict(r) for r in self.db.execute('SELECT * FROM annotation_journal WHERE scope=? AND ip=? ORDER BY id DESC',(scope,ip))]
    def purge(self,days,max_scans=None):
        if not 1<=days<=3650:raise ValueError('Choose retention from 1 to 3650 days.')
        cutoff=(datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
        with self.db:self.db.execute("DELETE FROM network_scans WHERE status<>'Running' AND started<?",(cutoff,))
        if max_scans is not None:
            if not 1<=max_scans<=10000:raise ValueError('Invalid scan-count retention limit.')
            with self.db:self.db.execute("DELETE FROM network_scans WHERE id IN (SELECT id FROM network_scans WHERE status<>'Running' ORDER BY rowid DESC LIMIT -1 OFFSET ?)",(max_scans,))
        # Address annotations stay available even if old raw scans are purged.
    def close(self):self.db.close()


def export_data(store,sid):
    scan=store.get_scan(sid)
    return {'application':'ConnWatch Network 3.0.0','developed_by':'ZakirUllah','exported_utc':utc(),'scan':scan,
            'observations':store.records(sid),'device_annotations':store.devices(scan['scope'],sid),'annotation_context':'Current at export time; observations retain scan-time evidence.',
            'annotation_journal':[dict(r) for r in store.db.execute('SELECT * FROM annotation_journal WHERE scope=? ORDER BY id',(scan['scope'],))],'changes':store.changes(sid)}

def network_report(data):
    e=lambda v:html.escape(str(v));s=data['scan'];observed=[d for d in data['observations'] if d.get('presence') in ('Responding','Neighbor observed')]
    rows=[]
    for d in observed:
        opened=', '.join(str(p) for p,v in d.get('ports',{}).items() if v['state']=='Open') or 'None observed'
        rows.append('<tr>'+''.join('<td>'+e(x)+'</td>' for x in [d['ip'],d.get('hostname') or 'Unavailable',d.get('mac') or 'Unavailable',d.get('vendor') or 'Unavailable',d['presence'],opened])+'</tr>')
    changes=''.join('<li>'+e(c['ip']+' / '+c['kind']+' / '+c['detail'])+'</li>' for c in data['changes'])
    findings=''.join('<li>'+e(d['ip']+' / '+finding)+'</li>' for d in observed for finding in exposures(d))
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>ConnWatch Network Assessment</title><style>
    body{{font-family:Arial,sans-serif;font-size:10.5pt;color:#163047;margin:28px}}h1{{font-size:23pt;color:#087c72}}h2{{font-size:14pt}}p{{line-height:1.5}}
    table{{width:100%;border-collapse:collapse;font-size:8.5pt}}td,th{{border:1px solid #d4e0e7;padding:8px;text-align:left}}th{{background:#edf6f5}}</style></head><body>
    <h1>ConnWatch Network Assessment</h1><p><b>Developed by ZakirUllah</b></p>
    <p>Scope: <b>{e(s['scope'])}</b><br>Status: {e(s['status'])}<br>Started (UTC): {e(s['started'])}<br>Ended (UTC): {e(s['ended'] or 'In progress')}<br>
    Adapter: {e(s['options'].get('profile',{}).get('name','Manual'))}<br>Ports selected: {e(s['options'].get('ports',[]))}<br>Scan ID: {e(s['id'])}</p>
    <h2>Observed addresses: {len(observed)} / Recorded address attempts: {len(data['observations'])}</h2>
    <p>Presence is supported by the listed discovery methods. Cached neighbor observations do not prove current reachability. No response is not proof of absence.
    Service labels are port-based hints; they do not identify software versions or confirm vulnerabilities. JSON contains every recorded address attempt and coverage details.</p>
    <table width="100%" cellspacing="0" cellpadding="7"><tr><th>IPv4</th><th>Hostname</th><th>MAC</th><th>Vendor prefix</th><th>Presence</th><th>Open TCP ports</th></tr>{''.join(rows) or '<tr><td colspan="6">No device observations recorded.</td></tr>'}</table>
    <h2>Changes from the previous completed scan</h2><ul>{changes or '<li>No comparable change records.</li>'}</ul><h2>Configuration review notes</h2><ul>{findings or '<li>No selected service review notes were generated.</li>'}</ul>
    <p>Encrypted/private device information, traffic contents and credentials are not collected. MAC vendor prefixes can differ from the actual product manufacturer. Review personal network details before sharing.</p></body></html>'''

def export_network(store,sid,path,kind):
    path=Path(path)
    if path.resolve().parent==store.directory.resolve() and path.name in {'network.db','network.db-wal','network.db-shm','connwatch.db','connwatch.db-wal','connwatch.db-shm','settings.ini','network-settings.ini','allowlist.json','workspace.lock','connwatch.log'}:raise ValueError('Choose an export filename outside active application data.')
    data=export_data(store,sid)
    if kind=='html':path.write_text(network_report(data),encoding='utf-8')
    elif kind=='json':
        temp=path.with_suffix(path.suffix+'.tmp');temp.write_text(json.dumps(data,indent=2,ensure_ascii=True));temp.replace(path)
    elif kind=='csv':
        with path.open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.writer(f);w.writerow(['IP','Time UTC','Presence','Hostname','MAC','Vendor','Role hint','Open TCP ports','Checked TCP ports','Evidence'])
            for d in data['observations']:
                row=[d['ip'],d['time'],d['presence'],d.get('hostname',''),d.get('mac',''),d.get('vendor',''),d.get('role',''),
                     ','.join(str(p) for p,v in d.get('ports',{}).items() if v['state']=='Open'),','.join(map(str,d.get('checked_ports',[]))),'; '.join(d.get('evidence',[]))]
                w.writerow(["'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for v in row])
    else:raise ValueError('Unknown export format')
