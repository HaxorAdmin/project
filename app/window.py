"""ConnWatch Desktop native user interface."""
from __future__ import annotations
from collections import Counter, deque
from dataclasses import asdict
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import platform
import socket
import sys
import time

from PySide6.QtCore import Qt, QTimer, QSettings, QUrl, QStandardPaths
from PySide6.QtGui import QDesktopServices, QFont, QTextDocument, QPageSize, QIcon, QPageLayout
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import (QApplication,QMainWindow,QWidget,QFrame,QVBoxLayout,QHBoxLayout,QGridLayout,
    QLabel,QPushButton,QStackedWidget,QLineEdit,QComboBox,QSpinBox,QCheckBox,QFormLayout,QSplitter,
    QDialog,QDialogButtonBox,QMessageBox,QFileDialog,QInputDialog,QPlainTextEdit,QScrollArea,QSystemTrayIcon,QMenu)
from .detection import Allowlist, Detector
from .engine import ScanWorker,DetailWorker,HashWorker
from .storage import Store,atomic_json,endpoint,report_data,report_html,export_file
from .widgets import Card,Table,SparkChart,label,button,icon,stylesheet


def human_bytes(n):
    if n is None:return 'Unavailable'
    n=float(n)
    for unit in ['B','KB','MB','GB','TB']:
        if abs(n)<1024:return f'{n:,.1f} {unit}'
        n/=1024
    return f'{n:,.1f} PB'

def panel(title=None):
    frame=QFrame();frame.setObjectName('panel');v=QVBoxLayout(frame);v.setContentsMargins(18,16,18,16);v.setSpacing(12)
    if title:v.addWidget(label(title,'sectionTitle'))
    return frame,v

def row(*widgets):
    h=QHBoxLayout();h.setSpacing(10)
    for w in widgets:
        if w is None:h.addStretch()
        else:h.addWidget(w)
    return h

class RuleDialog(QDialog):
    def __init__(self,parent=None,rule=None):
        super().__init__(parent);self.setWindowTitle('Endpoint rule');self.setMinimumWidth(500)
        v=QVBoxLayout(self);v.addWidget(label('Approve a verified endpoint','title'))
        v.addWidget(label('Match address, port and protocol together. A rule is a trust decision, not a malware verdict.','muted'))
        form=QFormLayout();self.address=QLineEdit();self.address.setPlaceholderText('IP address or CIDR, e.g. 192.0.2.10/32')
        self.ports=QLineEdit();self.ports.setPlaceholderText('443, 8443 or *');self.protocol=QComboBox();self.protocol.addItems(['tcp','udp','any'])
        self.note=QLineEdit();self.note.setPlaceholderText('Why is this service expected?')
        for name,w in [('Address / CIDR',self.address),('Allowed ports',self.ports),('Protocol',self.protocol),('Review note',self.note)]:form.addRow(name,w)
        v.addLayout(form);self.error=label('','muted');v.addWidget(self.error)
        controls=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel);controls.accepted.connect(self.validate);controls.rejected.connect(self.reject);v.addWidget(controls)
        if rule:
            self.address.setText(rule['address']);self.ports.setText('*' if rule['ports']=='*' else ', '.join(map(str,rule['ports'])))
            self.protocol.setCurrentText(rule.get('protocol','any'));self.note.setText(rule.get('note',''))
    def validate(self):
        try:
            address=str(ipaddress.ip_network(self.address.text().strip(),strict=False))
            ports=self.ports.text().strip()
            if ports!='*':
                ports=sorted(set(int(p.strip()) for p in ports.split(',')))
                if not ports or any(not 1<=p<=65535 for p in ports):raise ValueError('Ports must be 1 to 65535.')
            self.rule={'address':address,'ports':ports,'protocol':self.protocol.currentText(),'note':self.note.text().strip()}
            self.accept()
        except ValueError as exc:self.error.setText('Check the rule: '+str(exc))

class ProcessDialog(QDialog):
    def __init__(self,parent,connection,demo=False):
        super().__init__(parent);self.setWindowTitle('Process investigation');self.resize(760,570);self.workers=[];self.path=None
        v=QVBoxLayout(self);v.addWidget(label('Process investigation','title'));v.addWidget(label('Local inspection only. File hashes identify files; they do not prove a file is safe.','muted'))
        self.text=QPlainTextEdit();self.text.setReadOnly(True);v.addWidget(self.text,1)
        self.hash=button('Calculate SHA-256',self.calculate);self.hash.setEnabled(False)
        v.addLayout(row(self.hash,None,button('Close',self.close)))
        self.current=connection
        if demo:
            self.text.setPlainText(f'SYNTHETIC DEMO\n\nProcess: {connection.process}\nPID: {connection.pid}\n\nExecutable inspection and hashing are disabled for synthetic processes.')
        else:
            self.text.setPlainText('Reading available process information...')
            worker=DetailWorker(connection.pid,connection.process_started,self);worker.ready.connect(self.show_data);self.workers.append(worker);worker.start()
    def show_data(self,data):
        if 'error' in data:self.text.setPlainText(data['error']);return
        lines=[]
        for key,value in data.items():
            if key=='created' and isinstance(value,(int,float)):value=datetime.fromtimestamp(value,timezone.utc).isoformat()
            if key=='memory' and isinstance(value,int):value=human_bytes(value)
            lines.append(f'{key.upper()}\n{value}\n')
        self.text.setPlainText('\n'.join(lines))
        path=data.get('exe')
        if path and path!='Unavailable':self.path=path;self.hash.setEnabled(True)
    def calculate(self):
        self.hash.setEnabled(False);self.text.appendPlainText('\nHASHING FILE ON DISK...')
        worker=HashWorker(self.path,self);worker.ready.connect(lambda value:self.text.appendPlainText('SHA-256\n'+value));worker.failed.connect(lambda value:self.text.appendPlainText('Hash unavailable: '+value));worker.finished.connect(lambda:self.hash.setEnabled(True));self.workers.append(worker);worker.start()
    def reject(self):
        if any(w.isRunning() for w in self.workers):
            for w in self.workers:w.requestInterruption()
            return
        super().reject()
    def closeEvent(self,event):
        if any(w.isRunning() for w in self.workers):
            for w in self.workers:w.requestInterruption()
            QMessageBox.information(self,'Finishing inspection','Please wait for the current local inspection to finish, then close this window.');event.ignore();return
        event.accept()

class MainWindow(QMainWindow):
    PAGE_NAMES=['Overview','Connections','Alert inbox','Processes','Rules','Sessions','Network','Settings','About']
    TITLES=['Connection intelligence','Live connections','Alert investigation','Process activity','Endpoint trust rules','Recorded sessions','Network interfaces','Workspace settings','Built for local visibility']
    SUBTITLES=['A clear view of what your computer is talking to.','Search, filter and inspect the current socket snapshot.','Review context, record a decision, keep an audit trail.','Processes with visible sockets in the latest snapshot.','Reviewed rules match address, port and protocol together.','Reopen your evidence and export a professional report.','Host interface totals; these are not per-process traffic counters.','Configure collection, detection, appearance and retention.','ConnWatch Desktop 2.0.0 / Developed by ZakirUllah']
    def __init__(self,directory=None):
        super().__init__();self.setWindowTitle('ConnWatch Desktop | Developed by ZakirUllah');self.setWindowIcon(QIcon(str(Path(__file__).resolve().parents[1]/'assets/connwatch.png')));self.resize(1460,950);self.setMinimumSize(1160,760)
        if directory is None:directory=QStandardPaths.writableLocation(QStandardPaths.AppLocalDataLocation)
        self.store=Store(directory);self.settings=QSettings(str(self.store.directory/'settings.ini'),QSettings.IniFormat)
        self.light=self.settings.value('light',False,type=bool);self.interval=self.settings.value('interval',3,type=int)
        self.cooldown=self.settings.value('cooldown',300,type=int);self.threshold=self.settings.value('threshold',15,type=int)
        self.retention=self.settings.value('retention',30,type=int);self.notify=self.settings.value('notify',False,type=bool)
        self.rules_data={'version':1,'rules':[]};self.running=False;self.demo=False;self.session=None;self.worker=None;self.detector=None;self.latest=None;self.baseline_set=None
        self.scan_index=0;self.timeline=deque(maxlen=60);self.traffic_points=deque(maxlen=60);self.previous_traffic=None;self.dialogs=[]
        self.timer=QTimer(self);self.timer.timeout.connect(self.collect)
        self.build();self.apply_theme();self.load_rules();self.refresh_sessions()
        self.store.purge(self.retention)
    def build(self):
        central=QWidget();self.setCentralWidget(central);shell=QHBoxLayout(central);shell.setContentsMargins(0,0,0,0);shell.setSpacing(0)
        sidebar=QFrame();sidebar.setObjectName('sidebar');sidebar.setFixedWidth(215);nav=QVBoxLayout(sidebar);nav.setContentsMargins(16,26,16,18);nav.setSpacing(5)
        nav.addWidget(label('CONNWATCH','brand'));nav.addWidget(label('DESKTOP / NETWORK DEFENSE','eyebrow'));nav.addSpacing(30)
        self.nav=[]
        for i,name in enumerate(self.PAGE_NAMES):
            b=button('  '+name,lambda i=i:self.navigate(i),'nav');b.setCheckable(True);b.setIcon(icon(['grid','signal','shield','list','shield','list','signal','gear','list'][i]));b.setIconSize(__import__('PySide6.QtCore',fromlist=['QSize']).QSize(20,20));self.nav.append(b);nav.addWidget(b)
        nav.addStretch();self.demo_button=button('Try synthetic demo',self.toggle_demo);nav.addWidget(self.demo_button)
        nav.addSpacing(12);nav.addWidget(label('Developed by\nZakirUllah','muted'));nav.addWidget(label('v2.0.0  /  LOCAL-FIRST','eyebrow'));shell.addWidget(sidebar)
        right=QVBoxLayout();right.setContentsMargins(30,24,30,12);right.setSpacing(15);shell.addLayout(right,1)
        self.mode_label=label('LIVE MODE / READY','eyebrow');self.mode_label.setMinimumWidth(290);self.mode_label.setWordWrap(False);self.state_label=label('Not recording','muted')
        self.export_button=button('Export report',self.export_dialog);self.start_button=button('Start monitoring',self.toggle_run,'primary')
        right.addLayout(row(self.mode_label,None,self.state_label,self.export_button,self.start_button))
        self.page_title=label('','title');self.page_subtitle=label('','muted');right.addWidget(self.page_title);right.addWidget(self.page_subtitle)
        self.banner=label('Start monitoring to collect real connections. Try the labelled demo to explore the interface.','muted');self.banner.setStyleSheet('padding:10px 13px;border-left:3px solid #30bda0;');right.addWidget(self.banner)
        self.stack=QStackedWidget();right.addWidget(self.stack,1)
        for builder in [self.overview_page,self.connections_page,self.alerts_page,self.processes_page,self.rules_page,self.sessions_page,self.network_page,self.settings_page,self.about_page]:
            page=QWidget();layout=QVBoxLayout(page);layout.setContentsMargins(0,0,0,0);layout.setSpacing(14);builder(layout);self.stack.addWidget(page)
        self.footer=label('All data stays on this device. No network probes, cloud upload or reputation lookups.','muted');right.addWidget(self.footer)
        self.statusBar().showMessage('Ready. Choose Start monitoring or Try synthetic demo.')
        self.navigate(0)
        self.tray=None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray=QSystemTrayIcon(self.windowIcon(),self);self.tray.setToolTip('ConnWatch Desktop');menu=QMenu(self)
            show=menu.addAction('Show ConnWatch');show.triggered.connect(self.showNormal);stop=menu.addAction('Stop monitoring');stop.triggered.connect(self.stop_monitoring)
            self.tray.setContextMenu(menu);self.tray.activated.connect(lambda reason:self.showNormal() if reason==QSystemTrayIcon.DoubleClick else None);self.tray.show()
    def navigate(self,index):
        self.stack.setCurrentIndex(index);self.page_title.setText(self.TITLES[index]);self.page_subtitle.setText(self.SUBTITLES[index])
        for i,b in enumerate(self.nav):b.setChecked(i==index)
        if index==5:self.refresh_sessions()
        if index==2:self.refresh_alerts()
    def overview_page(self,v):
        grid=QHBoxLayout();self.cards=[Card('Visible sockets','0','TCP and UDP'),Card('Remote endpoints','0','Unique address / port / protocol'),Card('Open alerts','0','Current session review queue'),Card('Baseline changes','—','Capture a comparison baseline')]
        for c in self.cards:grid.addWidget(c)
        v.addLayout(grid)
        charts=QHBoxLayout();self.connection_chart=SparkChart('Connection activity','Latest 60 snapshots • socket records')
        self.traffic_chart=SparkChart('Host traffic','KB/s • aggregate interface counters',('Download','Upload'),('#39ddbc','#789dff'))
        charts.addWidget(self.connection_chart);charts.addWidget(self.traffic_chart);v.addLayout(charts,1)
        lower=QHBoxLayout();left,lv=panel('Recent findings');self.recent=Table(['UTC time','Process','Finding','Remote endpoint']);self.recent.doubleClicked.connect(lambda _:self.navigate(2));lv.addWidget(self.recent)
        lower.addWidget(left,3);right,rv=panel('Workspace posture');self.posture=label('No scan collected yet.','muted');rv.addWidget(self.posture)
        rv.addWidget(button('Capture comparison baseline',self.capture_baseline));rv.addWidget(button('Review endpoint rules',lambda:self.navigate(4)));rv.addStretch();rv.addWidget(label('A baseline records what you observed.\nIt does not automatically trust it.','muted'));lower.addWidget(right,2);v.addLayout(lower,1)
    def connections_page(self,v):
        self.connection_search=QLineEdit();self.connection_search.setPlaceholderText('Search process, PID, IP address, port or state...')
        self.protocol_filter=QComboBox();self.protocol_filter.addItems(['All protocols','TCP','UDP']);self.verdict_filter=QComboBox();self.verdict_filter.addItems(['All verdicts','KNOWN','REVIEW','LOCAL'])
        v.addLayout(row(self.connection_search,self.protocol_filter,self.verdict_filter,button('Capture baseline',self.capture_baseline)))
        self.connections=Table(['Process','PID','Protocol','Local endpoint','Remote endpoint','State','Rule verdict','Baseline'])
        self.connection_search.textChanged.connect(self.connections.proxy.set_term);self.protocol_filter.currentTextChanged.connect(self.filter_connections);self.verdict_filter.currentTextChanged.connect(self.filter_connections)
        split=QSplitter();split.addWidget(self.connections);details,dv=panel('Connection details');details.setMinimumWidth(255);details.setMaximumWidth(350)
        self.connection_detail=label('Select a row to inspect its endpoint and process.','muted');self.connection_detail.setTextInteractionFlags(Qt.TextSelectableByMouse);dv.addWidget(self.connection_detail);dv.addStretch()
        dv.addWidget(button('Inspect process',self.inspect_connection));dv.addWidget(button('Add endpoint rule…',self.trust_connection));split.addWidget(details);split.setStretchFactor(0,4);split.setStretchFactor(1,1);v.addWidget(split,1)
        self.connections.selectionModel().selectionChanged.connect(self.connection_selected);self.connections.doubleClicked.connect(lambda _:self.inspect_connection())
        v.addWidget(label('LOCAL rows have no remote peer. UDP may not expose its peer. Rule verdicts are review decisions, not malware classifications.','muted'))
    def alerts_page(self,v):
        self.alert_search=QLineEdit();self.alert_search.setPlaceholderText('Search saved findings, processes, endpoints and notes...')
        self.alert_scope=QComboBox();self.alert_scope.addItems(['Current session','All sessions']);self.alert_scope.currentIndexChanged.connect(self.refresh_alerts)
        v.addLayout(row(self.alert_search,self.alert_scope,button('Refresh',self.refresh_alerts)))
        self.alert_table=Table(['UTC time','Process','PID','Finding','Remote IP','Port','Status','Analyst note','Mode'])
        self.alert_search.textChanged.connect(self.alert_table.proxy.set_term);v.addWidget(self.alert_table,1)
        v.addLayout(row(button('Mark resolved',lambda:self.triage('Resolved')),button('Accept as expected',lambda:self.triage('Accepted')),button('Reopen',lambda:self.triage('Open')),button('View finding',self.view_finding),None))
        v.addWidget(label('Accepting an alert records your decision. It does not add an allowlist rule. The inbox shows at most the latest 5,000 events in its scope.','muted'))
    def processes_page(self,v):
        self.process_search=QLineEdit();self.process_search.setPlaceholderText('Search process name or PID...');v.addLayout(row(self.process_search,button('Inspect selected process',self.inspect_process)))
        self.process_table=Table(['Process','PID','Sockets','Remote endpoints','Unapproved sockets','Protocols'])
        self.process_search.textChanged.connect(self.process_table.proxy.set_term);self.process_table.doubleClicked.connect(lambda _:self.inspect_process());v.addWidget(self.process_table,1)
        v.addWidget(label('This page lists processes represented in the visible connection snapshot. Traffic rates on Overview are host totals, not per-process estimates.','muted'))
    def rules_page(self,v):
        v.addLayout(row(button('Add rule',self.add_rule,'primary'),button('Edit selected',self.edit_rule),button('Delete selected',self.delete_rule),None,button('Import JSON',self.import_rules),button('Export JSON',self.export_rules)))
        self.rules_scope=label('LIVE endpoint rules','eyebrow');v.addWidget(self.rules_scope);self.rule_table=Table(['Address / CIDR','Ports','Protocol','Review note']);v.addWidget(self.rule_table,1)
        v.addWidget(label('Rules apply to the next scan after saving. Existing alert records retain their original finding. Import replaces rules only after validation and your confirmation.','muted'))
    def sessions_page(self,v):
        v.addLayout(row(button('Refresh sessions',self.refresh_sessions),button('Open session summary',self.session_summary),button('Use session baseline',self.use_session_baseline),None,button('Export selected session',self.export_selected)))
        self.session_table=Table(['Started (UTC)','Mode','Retained scans','Alert events','Ended / last recovered','Session ID'])
        self.session_table.doubleClicked.connect(lambda _:self.session_summary());v.addWidget(self.session_table,1)
        v.addWidget(label('Full snapshots are retained up to 10,000 per session. Alert events are retained until the session is removed by the configured age policy.','muted'))
    def network_page(self,v):
        self.network_summary=label('Start a scan to read network interfaces.','muted');v.addWidget(self.network_summary)
        self.network_table=Table(['Interface','State','Link Mbps','IPv4','IPv6','Total sent','Total received']);v.addWidget(self.network_table,1)
        v.addWidget(label('Counters come from the OS since its last counter reset, often system boot. Tunnels and virtual adapters can affect host aggregates. No packet contents are collected.','muted'))
    def settings_page(self,v):
        frame,fv=panel('Collection and detection');form=QFormLayout();self.interval_spin=QSpinBox();self.interval_spin.setRange(1,60);self.interval_spin.setValue(self.interval);self.interval_spin.setSuffix(' seconds')
        self.cooldown_spin=QSpinBox();self.cooldown_spin.setRange(1,86400);self.cooldown_spin.setValue(self.cooldown);self.cooldown_spin.setSuffix(' seconds')
        self.threshold_spin=QSpinBox();self.threshold_spin.setRange(2,10000);self.threshold_spin.setValue(self.threshold)
        self.retention_spin=QSpinBox();self.retention_spin.setRange(1,3650);self.retention_spin.setValue(self.retention);self.retention_spin.setSuffix(' days')
        self.theme_combo=QComboBox();self.theme_combo.addItems(['Dark','Light']);self.theme_combo.setCurrentText('Light' if self.light else 'Dark')
        self.notify_check=QCheckBox('Notify on new live alert batches when a system tray is available');self.notify_check.setChecked(self.notify)
        for name,w in [('Scan interval',self.interval_spin),('Repeat alert cooldown',self.cooldown_spin),('Burst threshold (30-second window)',self.threshold_spin),('Closed-session retention',self.retention_spin),('Appearance',self.theme_combo),('Notifications',self.notify_check)]:form.addRow(name,w)
        fv.addLayout(form);fv.addWidget(button('Save settings',self.save_settings,'primary'));v.addWidget(frame)
        self.storage_label=label('Data folder: '+str(self.store.directory),'muted');self.storage_label.setTextInteractionFlags(Qt.TextSelectableByMouse);v.addWidget(self.storage_label)
        v.addLayout(row(button('Open data folder',self.open_data),button('Apply retention cleanup',self.cleanup),None));v.addStretch()
    def about_page(self,v):
        frame,fv=panel();fv.addWidget(label('CONNWATCH DESKTOP','eyebrow'));fv.addWidget(label('Visibility with context.','title'))
        fv.addWidget(label('Developed by ZakirUllah','title'));fv.addWidget(label('Version 2.0.0 • Native Qt desktop application • Local SQLite workspace','muted'))
        fv.addSpacing(12);fv.addWidget(label('What goes beyond a connection list?\n\n• Match reviewed endpoint rules and flag exceptions.\n• Capture an observation baseline and see newly observed endpoints.\n• Investigate process details and calculate an executable file hash.\n• Resolve or accept alerts with a saved analyst note.\n• Reopen sessions and export JSON, CSV, HTML or PDF evidence.\n• Track connection counts and host traffic over time.'))
        fv.addSpacing(12);fv.addWidget(label('Boundaries','sectionTitle'));fv.addWidget(label('Passive local observation. No packet capture, firewall blocking, automatic malware verdicts, cloud analytics, geolocation or scanning of other hosts. Short-lived connections between scans can be missed. Operating-system permissions can hide sockets or process details. Synthetic sessions are always labelled.','muted'));v.addWidget(frame);v.addStretch()
    def apply_theme(self):
        self.setStyleSheet(stylesheet(self.light))
        for chart in [self.connection_chart,self.traffic_chart]:chart.setProperty('light',self.light);chart.update()
    def error(self,text):QMessageBox.warning(self,'ConnWatch',str(text))
    def toggle_run(self):
        if self.running:self.stop_monitoring()
        else:self.start_monitoring()
    def start_monitoring(self):
        if self.worker and self.worker.isRunning():return
        try:
            rules=Allowlist.load(self.store.rule_path)
            self.detector=Detector(rules,self.cooldown,self.threshold,30)
            self.session=self.store.start('SYNTHETIC DEMO' if self.demo else 'LIVE', 'Demo workstation' if self.demo else socket.gethostname())
            self.running=True;self.baseline_set=None;self.scan_index=0;self.timeline.clear();self.traffic_points.clear();self.previous_traffic=None
            self.latest=None;self.start_button.setText('Stop monitoring');self.demo_button.setEnabled(False);self.state_label.setText('Recording • '+str(self.interval)+'s interval')
            self.mode_label.setText('SYNTHETIC DEMO / RECORDING' if self.demo else 'LIVE MODE / RECORDING')
            self.timer.start(self.interval*1000);self.collect();self.refresh_sessions()
        except Exception as exc:self.error(exc)
    def stop_monitoring(self):
        self.timer.stop();self.running=False;self.start_button.setText('Start monitoring');self.demo_button.setEnabled(not(self.worker and self.worker.isRunning()));self.state_label.setText('Capture stopped')
        self.mode_label.setText('SYNTHETIC DEMO / STOPPED' if self.demo else 'LIVE MODE / STOPPED')
        if self.session:
            try:self.store.stop(self.session)
            except Exception as exc:self.error(exc)
        self.refresh_sessions()
    def toggle_demo(self):
        if self.running or (self.worker and self.worker.isRunning()):return
        self.demo=not self.demo
        self.store.rule_path=self.store.directory/('demo-allowlist.json' if self.demo else 'allowlist.json')
        if not self.store.rule_path.exists():
            atomic_json(self.store.rule_path,{'version':1,'rules':[
                {'address':'198.51.100.20','ports':[443],'protocol':'tcp','note':'Synthetic approved browser endpoint'},
                {'address':'198.51.100.30','ports':[443],'protocol':'tcp','note':'Synthetic approved sync endpoint'},
                {'address':'192.0.2.53','ports':[53],'protocol':'udp','note':'Synthetic approved DNS endpoint'}]})
        self.demo_button.setText('Return to live mode' if self.demo else 'Try synthetic demo')
        self.session=None;self.latest=None;self.baseline_set=None;self.timeline.clear();self.traffic_points.clear();self.connection_chart.set_points([]);self.traffic_chart.set_points([])
        for table in [self.connections,self.process_table,self.network_table,self.recent]:table.fill([])
        for i,c in enumerate(self.cards):c.update('—' if i==3 else '0')
        self.mode_label.setText('SYNTHETIC DEMO / READY' if self.demo else 'LIVE MODE / READY')
        self.banner.setText('SYNTHETIC DEMO: all processes, connections and traffic shown are simulated.' if self.demo else 'Live mode selected. Start monitoring to collect your own host connections.')
        self.load_rules();self.posture.setText('Start a scan to collect workspace metrics.');self.network_summary.setText('Start a scan to read network interfaces.');self.refresh_alerts()
    def collect(self):
        if not self.running or (self.worker and self.worker.isRunning()):return
        worker=ScanWorker(self.demo,self.scan_index,self);self.worker=worker
        worker.ready.connect(lambda data,sid=self.session:self.scan_ready(data) if self.running and self.session==sid else None);worker.failed.connect(lambda message,sid=self.session:self.scan_failed(message) if self.session==sid else None);worker.finished.connect(self.worker_finished);worker.start()
    def worker_finished(self):
        worker=self.sender()
        if worker:worker.deleteLater()
        if self.worker is worker:self.worker=None
        if not self.running:self.demo_button.setEnabled(True)
    def scan_failed(self,message):
        self.stop_monitoring();self.banner.setText('Collection stopped: '+message);self.statusBar().showMessage('Collection failed. Completed scans remain saved.')
    def scan_ready(self,data):
        if not self.running:return
        try:
            connections=data['connections'];alerts=self.detector.inspect(connections,data['time'],data['monotonic'])
            serial={**data,'connections':[asdict(c) for c in connections],'mode':'SYNTHETIC DEMO' if self.demo else 'LIVE'}
            self.store.save_scan(self.session,serial,alerts)
            self.latest=data;self.scan_index+=1;self.timeline.append((len(connections),));self.connection_chart.set_points(list(self.timeline))
            rates=(0,0)
            if self.previous_traffic and data['traffic']:
                old,when=self.previous_traffic;elapsed=max(0.001,data['monotonic']-when)
                rates=(max(0,data['traffic']['recv']-old['recv'])/elapsed/1024,max(0,data['traffic']['sent']-old['sent'])/elapsed/1024)
            self.previous_traffic=(data['traffic'],data['monotonic']) if data['traffic'] else None
            if data['traffic']:self.traffic_points.append(rates)
            self.traffic_chart.set_points(list(self.traffic_points));self.traffic_chart.subtitle='KB/s • aggregate interface counters' if data['traffic'] else 'Host traffic counters unavailable'
            self.render_snapshot();self.refresh_alerts()
            if self.stack.currentIndex()==5:self.refresh_sessions()
            warnings=data['warnings']
            self.banner.setText('SYNTHETIC DEMO: all process, network and traffic data is simulated.' if self.demo else ('Visibility: '+' '.join(warnings) if warnings else 'Live capture active. Endpoint alerts are review findings, not confirmed threats.'))
            self.statusBar().showMessage(f"Last scan (UTC): {data['time']}  |  {len(connections)} visible sockets  |  {len(alerts)} new alert events")
            if alerts and self.notify and self.tray and not self.demo:self.tray.showMessage('ConnWatch: new findings',f'{len(alerts)} connection events need review.',QSystemTrayIcon.Information,4000)
        except Exception as exc:self.scan_failed(f'Could not record scan: {exc}')
    def render_snapshot(self):
        if not self.latest:return
        connections=self.latest['connections'];rules=self.detector.allowlist if self.detector else Allowlist.load(self.store.rule_path)
        endpoints={endpoint(c) for c in connections if c.remote_address}
        self.cards[0].update(len(connections));self.cards[1].update(len(endpoints))
        additions=endpoints-self.baseline_set if self.baseline_set is not None else None
        self.cards[3].update(len(additions) if additions is not None else '—', 'New endpoints vs. captured baseline' if additions is not None else 'Capture a comparison baseline')
        rows=[]
        for c in connections:
            verdict='LOCAL' if not c.remote_address else ('KNOWN' if rules.known(c) else 'REVIEW')
            change='—' if not c.remote_address or self.baseline_set is None else ('In baseline' if endpoint(c) in self.baseline_set else 'New endpoint')
            rows.append([c.process,c.pid,c.protocol.upper(),f'[{c.local_address}]:{c.local_port}',f'[{c.remote_address}]:{c.remote_port}' if c.remote_address else '—',c.status,verdict,change])
        self.connections.fill(rows,connections)
        grouped={}
        for c in connections:grouped.setdefault((c.pid,c.process_started,c.process),[]).append(c)
        self.process_table.fill([[key[2],key[0],len(cs),len({endpoint(c) for c in cs if c.remote_address}),sum(bool(c.remote_address and not rules.known(c)) for c in cs),', '.join(sorted({c.protocol.upper() for c in cs}))] for key,cs in grouped.items()],[cs[0] for cs in grouped.values()])
        self.network_table.fill([[n['name'],'Unknown' if n['up'] is None else ('Up' if n['up'] else 'Down'),n['speed'],n['ipv4'],n['ipv6'],human_bytes(n['sent']),human_bytes(n['recv'])] for n in self.latest['network']])
        self.network_summary.setText(f"{len(self.latest['network'])} interfaces • Total sent {human_bytes((self.latest['traffic'] or {}).get('sent'))} • Total received {human_bytes((self.latest['traffic'] or {}).get('recv'))}")
        hidden=sum(c.pid is None or c.process=='unavailable' for c in connections)
        self.posture.setText(f"{'Synthetic demonstration' if self.demo else 'Local host collection'}\n\n{len(grouped)} visible process identities\n{hidden} sockets with limited attribution\n{len(rules.rules)} endpoint rules\n{self.scan_index} saved scans this session\n\nStorage: local SQLite\nBaseline: {'captured' if self.baseline_set is not None else 'not captured'}")
    def filter_connections(self):
        self.connections.proxy.protocol=self.protocol_filter.currentText();self.connections.proxy.verdict=self.verdict_filter.currentText();self.connections.proxy.invalidateFilter()
    def connection_selected(self,*_):
        c=self.connections.selected()
        if not c:self.connection_detail.setText('Select a current row to inspect its endpoint and process.');return
        zone='No remote peer'
        if c.remote_address:
            try:zone='Globally routable address' if ipaddress.ip_address(c.remote_address.split('%')[0]).is_global else 'Non-global address'
            except ValueError:zone='Address classification unavailable'
        self.connection_detail.setText(f'{c.process}\nPID: {c.pid if c.pid is not None else "Unavailable"}\n\n{c.protocol.upper()} / {c.status}\n\nLocal\n[{c.local_address}]:{c.local_port}\n\nRemote\n'+(f'[{c.remote_address}]:{c.remote_port}' if c.remote_address else 'Not available')+f'\n\n{zone}\n\nDouble-click to inspect this process.')
    def inspect_connection(self):
        c=self.connections.selected()
        if not c:self.error('Select a connection first.');return
        self.show_process(c)
    def inspect_process(self):
        c=self.process_table.selected()
        if not c:self.error('Select a process first.');return
        self.show_process(c)
    def show_process(self,c):
        dialog=ProcessDialog(self,c,self.demo);dialog.setAttribute(Qt.WA_DeleteOnClose);self.dialogs.append(dialog);dialog.finished.connect(lambda _:self.dialogs.remove(dialog) if dialog in self.dialogs else None);dialog.show()
    def trust_connection(self):
        c=self.connections.selected()
        if not c or not c.remote_address:self.error('Choose a connection with a remote endpoint.');return
        self.rule_dialog({'address':c.remote_address.split('%')[0],'ports':[c.remote_port],'protocol':c.protocol,'note':'Reviewed endpoint for '+c.process})
    def capture_baseline(self):
        if not self.latest or not self.session:self.error('Collect at least one scan first.');return
        self.baseline_set=self.store.baseline(self.session,self.latest['connections']);self.render_snapshot();self.statusBar().showMessage(f'Captured {len(self.baseline_set)} endpoints for comparison. Rules were not changed.')
    def refresh_alerts(self,*_):
        sid=self.session if self.alert_scope.currentIndex()==0 else None
        alerts=[] if self.alert_scope.currentIndex()==0 and not sid else self.store.alerts(sid)
        modes={s['id']:s['mode'] for s in self.store.sessions()}
        self.alert_table.fill([[r['time'],r['data']['process'],r['data']['pid'],r['kind'],r['data']['remote_address'],r['data']['remote_port'],r['status'],r['note'],modes.get(r['session_id'],'Unknown')] for r in alerts],alerts)
        current=self.store.alerts(self.session) if self.session else []
        self.cards[2].update(self.store.db.execute("SELECT COUNT(*) FROM alerts WHERE session_id=? AND status='Open'",(self.session,)).fetchone()[0] if self.session else 0)
        self.recent.fill([[r['time'][11:19],r['data']['process'],{'unapproved_endpoint':'Endpoint review','connection_burst':'Connection burst'}.get(r['kind'],r['kind']),f"{r['data']['remote_address']}:{r['data']['remote_port']}"] for r in current[:5]],current[:5])
    def triage(self,status):
        selected=self.alert_table.selected()
        if not selected:self.error('Select an alert first.');return
        note,ok=QInputDialog.getMultiLineText(self,'Analyst decision',f'Status: {status}\nAdd your explanation:',selected['note'])
        if ok:self.store.triage(selected['id'],status,note[:5000]);self.refresh_alerts()
    def view_finding(self):
        r=self.alert_table.selected()
        if not r:self.error('Select an alert first.');return
        d=QDialog(self);d.setWindowTitle('Saved alert evidence');d.resize(700,550);v=QVBoxLayout(d);t=QPlainTextEdit();t.setReadOnly(True);t.setPlainText(json.dumps(r,indent=2));v.addWidget(t);v.addWidget(button('Close',d.accept));d.exec()
    def load_rules(self):
        try:
            self.rules_scope.setText('SYNTHETIC DEMO rules • separate from live rules' if self.demo else 'LIVE endpoint rules');self.rules_data=self.store.rules();self.rule_table.fill([[r['address'],'*' if r['ports']=='*' else ', '.join(map(str,r['ports'])),r.get('protocol','any'),r.get('note','')] for r in self.rules_data['rules']],list(enumerate(self.rules_data['rules'])))
            if self.detector:self.detector.allowlist=Allowlist.load(self.store.rule_path)
            self.render_snapshot()
        except Exception as exc:self.error('Allowlist could not be loaded: '+str(exc))
    def rule_dialog(self,rule=None,index=None):
        dialog=RuleDialog(self,rule)
        if dialog.exec()==QDialog.Accepted:
            data=json.loads(json.dumps(self.rules_data))
            if index is None:data['rules'].append(dialog.rule)
            else:data['rules'][index]=dialog.rule
            try:self.store.save_rules(data);self.load_rules()
            except Exception as exc:self.error(exc)
    def add_rule(self):self.rule_dialog()
    def edit_rule(self):
        selected=self.rule_table.selected()
        if selected is None:self.error('Select a rule first.');return
        self.rule_dialog(selected[1],selected[0])
    def delete_rule(self):
        selected=self.rule_table.selected()
        if selected is None:self.error('Select a rule first.');return
        if QMessageBox.question(self,'Delete endpoint rule','Remove the selected rule? New matching connections may raise review alerts.')!=QMessageBox.Yes:return
        data=json.loads(json.dumps(self.rules_data));del data['rules'][selected[0]]
        try:self.store.save_rules(data);self.load_rules()
        except Exception as exc:self.error(exc)
    def import_rules(self):
        path,_=QFileDialog.getOpenFileName(self,'Import reviewed allowlist','','JSON rules (*.json)')
        if not path:return
        try:
            Allowlist.load(path);data=json.loads(Path(path).read_text())
            if QMessageBox.question(self,'Replace trust rules',f"Import {len(data['rules'])} rules and replace the current rules?")!=QMessageBox.Yes:return
            self.store.save_rules(data);self.load_rules()
        except Exception as exc:self.error(exc)
    def export_rules(self):
        path,_=QFileDialog.getSaveFileName(self,'Export allowlist','allowlist-export.json','JSON (*.json)')
        if path:
            try:
                protected={'connwatch.db','connwatch.db-wal','connwatch.db-shm','allowlist.json','demo-allowlist.json','settings.ini','connwatch.log','workspace.lock'}
                if Path(path).resolve() in [(self.store.directory/name).resolve() for name in protected]:raise ValueError('Choose an export file outside active workspace data.')
                atomic_json(path,self.rules_data)
            except Exception as exc:self.error(exc)
    def refresh_sessions(self):
        sessions=self.store.sessions();self.session_table.fill([[s['started'],s['mode'],s['scans'],s['alerts'],s['ended'] or 'Recording',s['id']] for s in sessions],sessions)
    def session_summary(self):
        s=self.session_table.selected()
        if not s:self.error('Select a session first.');return
        d=QDialog(self);d.setWindowTitle('Recorded session');d.resize(720,520);v=QVBoxLayout(d);t=QPlainTextEdit();t.setReadOnly(True)
        t.setPlainText(json.dumps(s,indent=2)+'\n\nFull snapshots and findings are available through Export selected session.');v.addWidget(t);v.addWidget(button('Close',d.accept));d.exec()
    def use_session_baseline(self):
        selected=self.session_table.selected()
        if not selected:self.error('Select a saved session first.');return
        if not self.latest or not self.session:self.error('Collect a scan in the current session first.');return
        expected='SYNTHETIC DEMO' if self.demo else 'LIVE'
        if selected['mode']!=expected:self.error('Compare sessions in the same mode. Synthetic and live baselines stay separate.');return
        values=json.loads(selected['baseline']) if selected['baseline'] else None
        if values is None:
            scans=self.store.scans(selected['id'])
            if not scans:self.error('This session has no saved scans.');return
            values=[[c['protocol'],c['remote_address'],c['remote_port']] for c in scans[-1]['connections'] if c['remote_address']]
        self.baseline_set=set(map(tuple,values))
        with self.store.db:self.store.db.execute('UPDATE sessions SET baseline=? WHERE id=?',(json.dumps(sorted(self.baseline_set)),self.session))
        self.render_snapshot();self.statusBar().showMessage('Comparing current endpoints with saved session '+selected['started']+'. Trust rules were not changed.')
    def export_selected(self):
        s=self.session_table.selected()
        if not s:self.error('Select a session first.');return
        self.export_dialog(s['id'])
    def export_dialog(self,sid=None):
        sid=sid or self.session
        if not sid:self.error('Start a session first, or select an earlier session on the Sessions page.');return
        path,filter_=QFileDialog.getSaveFileName(self,'Export session report','ConnWatch-session-report.pdf','PDF report (*.pdf);;HTML report (*.html);;CSV alerts (*.csv);;JSON full evidence (*.json)')
        if not path:return
        kind={'PDF report (*.pdf)':'pdf','HTML report (*.html)':'html','CSV alerts (*.csv)':'csv','JSON full evidence (*.json)':'json'}[filter_]
        if not Path(path).suffix:path+='.'+kind
        try:
            if kind=='pdf':
                # Prevent any export mode from replacing the live database / configuration.
                if Path(path).resolve() in [p.resolve() for p in self.store.directory.glob('*') if p.name in ['connwatch.db','connwatch.db-wal','connwatch.db-shm','settings.ini','allowlist.json','demo-allowlist.json','connwatch.log','workspace.lock']]:raise ValueError('Choose a report filename outside application data.')
                doc=QTextDocument();doc.setHtml(report_html(report_data(self.store,sid)));printer=QPrinter(QPrinter.HighResolution);printer.setOutputFormat(QPrinter.PdfFormat);printer.setOutputFileName(path);printer.setPageSize(QPageSize(QPageSize.A4));printer.setPageOrientation(QPageLayout.Landscape);doc.print_(printer)
                if not Path(path).is_file() or Path(path).stat().st_size<100:raise OSError('PDF was not written. Check the destination permissions.')
            else:export_file(self.store,sid,path,kind)
            self.statusBar().showMessage('Report exported: '+path)
            QMessageBox.information(self,'Report saved','Saved to:\n'+path+'\n\nReview process names, endpoints and notes before sharing.')
        except Exception as exc:self.error('Export failed: '+str(exc))
    def save_settings(self):
        if self.running:self.error('Stop monitoring before changing collection settings.');return
        self.interval=self.interval_spin.value();self.cooldown=self.cooldown_spin.value();self.threshold=self.threshold_spin.value();self.retention=self.retention_spin.value();self.notify=self.notify_check.isChecked();self.light=self.theme_combo.currentText()=='Light'
        for k in ['interval','cooldown','threshold','retention','notify','light']:self.settings.setValue(k,getattr(self,k))
        self.settings.sync();self.apply_theme();self.statusBar().showMessage('Settings saved. New collection settings apply to the next session.')
    def cleanup(self):
        if QMessageBox.question(self,'Apply retention',f'Delete closed sessions older than {self.retention} days? This cannot be undone.')!=QMessageBox.Yes:return
        self.store.purge(self.retention);self.refresh_sessions();self.refresh_alerts();self.statusBar().showMessage('Retention policy applied.')
    def open_data(self):QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.store.directory)))
    def closeEvent(self,event):
        if any(w.isVisible() and any(t.isRunning() for t in w.workers) for w in self.dialogs):self.error('Wait for process inspection or hashing to finish before closing.');event.ignore();return
        if self.worker and self.worker.isRunning():
            self.stop_monitoring();self.statusBar().showMessage('Finishing the current collector call. Close again in a moment.');event.ignore();return
        self.stop_monitoring()
        if self.tray:self.tray.hide()
        self.store.close();event.accept()
