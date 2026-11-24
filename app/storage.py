"""Local SQLite session store. All writes are transactional."""
from __future__ import annotations
import csv
from datetime import datetime, timezone, timedelta
import html
import json
from pathlib import Path
import sqlite3
import uuid
from dataclasses import asdict
from .detection import Allowlist

DEFAULT_RULES = {'version':1,'rules':[
    {'address':'127.0.0.0/8','ports':'*','protocol':'any','note':'Local loopback'},
    {'address':'::1','ports':'*','protocol':'any','note':'IPv6 loopback'}]}

def utc(): return datetime.now(timezone.utc).isoformat(timespec='milliseconds')

def atomic_json(path, data):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix('.tmp')
    with temp.open('w',encoding='utf-8') as f:
        json.dump(data,f,indent=2,ensure_ascii=True)
    temp.replace(path)

class Store:
    def __init__(self, directory):
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.rule_path=self.directory/'allowlist.json'
        if not self.rule_path.exists(): atomic_json(self.rule_path,DEFAULT_RULES)
        self.db=sqlite3.connect(self.directory/'connwatch.db')
        self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,started TEXT NOT NULL,ended TEXT,mode TEXT NOT NULL,host TEXT NOT NULL,baseline TEXT);
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY,session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,time TEXT NOT NULL,count INTEGER NOT NULL,payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,time TEXT NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Open',note TEXT NOT NULL DEFAULT '',payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS scan_session ON scans(session_id,id);
        CREATE INDEX IF NOT EXISTS alert_session ON alerts(session_id,id);
        ''')
        # A previous hard stop must not look like a still-running session.
        with self.db:self.db.execute('UPDATE sessions SET ended=COALESCE((SELECT MAX(time) FROM scans WHERE session_id=sessions.id),started) WHERE ended IS NULL')
    def rules(self):
        Allowlist.load(self.rule_path)
        return json.loads(self.rule_path.read_text())
    def save_rules(self, data):
        test=self.directory/'validate-rules.json'
        try:
            atomic_json(test,data);Allowlist.load(test)
            atomic_json(self.rule_path,data)
        finally:test.unlink(missing_ok=True)
    def start(self,mode,host):
        sid=uuid.uuid4().hex
        with self.db:self.db.execute('INSERT INTO sessions(id,started,mode,host) VALUES(?,?,?,?)',(sid,utc(),mode,host))
        return sid
    def stop(self,sid):
        with self.db:self.db.execute('UPDATE sessions SET ended=? WHERE id=?',(utc(),sid))
    def save_scan(self,sid,data,alerts):
        with self.db:
            self.db.execute('INSERT INTO scans(session_id,time,count,payload) VALUES(?,?,?,?)',
                (sid,data['time'],len(data['connections']),json.dumps(data)))
            for a in alerts:self.db.execute('INSERT INTO alerts(session_id,time,kind,payload) VALUES(?,?,?,?)',
                (sid,a['time'],a['kind'],json.dumps(a)))
            # Keep the newest 10,000 full scans per session; alert events remain until session retention.
            self.db.execute('DELETE FROM scans WHERE session_id=? AND id NOT IN (SELECT id FROM scans WHERE session_id=? ORDER BY id DESC LIMIT 10000)',(sid,sid))
    def sessions(self):
        return [dict(r) for r in self.db.execute('''SELECT s.*, (SELECT COUNT(*) FROM scans WHERE session_id=s.id) scans,
            (SELECT COUNT(*) FROM alerts WHERE session_id=s.id) alerts FROM sessions s ORDER BY started DESC''')]
    def scans(self,sid):
        return [json.loads(r[0]) for r in self.db.execute('SELECT payload FROM scans WHERE session_id=? ORDER BY id',(sid,))]
    def alerts(self,sid=None):
        query='SELECT * FROM alerts';args=()
        if sid:query+=' WHERE session_id=?';args=(sid,)
        query+=' ORDER BY id DESC LIMIT 5000'
        result=[]
        for row in self.db.execute(query,args):
            r=dict(row);r['data']=json.loads(r.pop('payload'));result.append(r)
        return result
    def triage(self,aid,status,note):
        if status not in ('Open','Accepted','Resolved'):raise ValueError('Invalid alert status')
        with self.db:self.db.execute('UPDATE alerts SET status=?,note=? WHERE id=?',(status,note,aid))
    def baseline(self,sid,connections):
        data=[list(endpoint(c)) for c in connections if c.remote_address]
        with self.db:self.db.execute('UPDATE sessions SET baseline=? WHERE id=?',(json.dumps(sorted(set(map(tuple,data)))),sid))
        return set(map(tuple,data))
    def purge(self,days):
        if not 1<=days<=3650:raise ValueError('Retention must be 1..3650 days')
        before=(datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
        with self.db:self.db.execute('DELETE FROM sessions WHERE ended IS NOT NULL AND ended<?',(before,))
    def close(self):self.db.close()

def endpoint(c):return (c.protocol,c.remote_address,c.remote_port)

def report_data(store,sid):
    session=next((s for s in store.sessions() if s['id']==sid),None)
    if not session:raise ValueError('Choose a saved session first.')
    return {'application':'ConnWatch Workstation / Network 3.0.0','developed_by':'ZakirUllah','exported_utc':utc(),
            'session':session,'alerts':store.alerts(sid),'scans':store.scans(sid)}

def report_html(data):
    e=lambda v:html.escape(str(v))
    s=data['session'];alerts=data['alerts']
    rows=''.join('<tr>'+''.join('<td>'+e(v)+'</td>' for v in [r['time'],r['data']['kind'],r['data']['process'],r['data']['pid'],
            r['data']['remote_address'],r['data']['remote_port'],r['status'],r['note']])+'</tr>' for r in alerts)
    return f'''<!DOCTYPE html><html><head><meta charset="utf-8"><title>ConnWatch session report</title>
    <style>body{{font-family:Arial,sans-serif;font-size:11pt;color:#14283d;margin:36px}}h1{{font-size:24pt;color:#087d73}}h2{{font-size:14pt}}
    table{{border-collapse:collapse;width:100%;font-size:8.5pt}}td,th{{padding:9px;border:1px solid #d5dfe7;text-align:left;word-wrap:break-word}}
    th{{background:#edf5f7}}p{{line-height:1.7}}.tag{{color:#087d73}}</style></head><body>
    <p class="tag">LOCAL NETWORK DEFENSE / SESSION REPORT</p><h1>ConnWatch Desktop</h1><p><b>Developed by ZakirUllah</b></p>
    <p>Mode: <b>{e(s['mode'])}</b><br>Host: {e(s['host'])}<br>Session: {e(s['id'])}<br>Started (UTC): {e(s['started'])}<br>
    Ended (UTC): {e(s['ended'] or 'Recording at export time')}<br>Exported (UTC): {e(data['exported_utc'])}</p>
    <h2>{s['scans']} retained scans / {s['alerts']} recorded alert events</h2>
    <p>Unapproved endpoints require investigation. They are not proof of malware. Process visibility depends on OS permissions.
    Synthetic demo sessions must not be presented as live host evidence. Detailed socket history is available in the JSON export.</p>
    <table><tr><th>UTC time</th><th>Finding</th><th>Process</th><th>PID</th><th>Remote IP</th><th>Port</th><th>Status</th><th>Analyst note</th></tr>
    {rows or '<tr><td colspan="8">No alerts in this session.</td></tr>'}</table></body></html>'''

def export_file(store,sid,path,kind):
    path=Path(path)
    protected=[store.rule_path,store.directory/'allowlist.json',store.directory/'demo-allowlist.json',store.directory/'workspace.lock',store.directory/'connwatch.db',store.directory/'connwatch.db-wal',store.directory/'connwatch.db-shm',store.directory/'settings.ini',store.directory/'connwatch.log']
    if path.resolve() in [p.resolve() for p in protected]:raise ValueError('Do not overwrite application data with an export.')
    data=report_data(store,sid)
    if kind=='json':atomic_json(path,data)
    elif kind=='html':path.write_text(report_html(data),encoding='utf-8')
    elif kind=='csv':
        with path.open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.writer(f);writer.writerow(['UTC time','Kind','Process','PID','Protocol','Remote IP','Remote port','Status','Note','Mode'])
            for r in data['alerts']:
                a=r['data'];row=[r['time'],a['kind'],a['process'],a['pid'],a['protocol'],a['remote_address'],a['remote_port'],r['status'],r['note'],data['session']['mode']]
                writer.writerow(["'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for v in row])
    else:raise ValueError('Unknown export format')
