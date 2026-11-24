"""ConnWatch's network-first desktop workspace."""
from dataclasses import asdict
from datetime import datetime,timezone
import html
import ipaddress
import json
from pathlib import Path
import time
from PySide6.QtCore import Qt,QTimer,QSettings,QUrl,QPropertyAnimation,QEasingCurve,QStandardPaths
from PySide6.QtGui import QIcon,QDesktopServices,QTextDocument,QPageLayout,QPageSize
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import (QApplication,QMainWindow,QWidget,QFrame,QVBoxLayout,QHBoxLayout,QGridLayout,QComboBox,QLineEdit,
    QStackedWidget,QLabel,QProgressBar,QSplitter,QPlainTextEdit,QDialog,QDialogButtonBox,QInputDialog,QFormLayout,
    QCheckBox,QSpinBox,QDoubleSpinBox,QTabWidget,QFileDialog,QMessageBox,QGraphicsOpacityEffect,QScrollArea)
from .widgets import label,button,icon,Table,SparkChart,stylesheet
from .network_widgets import AnimatedCard,NetworkMap
from .discovery import ProfileWorker,DiscoveryWorker,ScanOptions,PROFILES,parse_ports,validate_scope,utc
from .inventory import InventoryStore,exposures,export_data,network_report,export_network


def panel(title=None):
    f=QFrame();f.setObjectName('panel');v=QVBoxLayout(f);v.setContentsMargins(19,17,19,17);v.setSpacing(12)
    if title:v.addWidget(label(title,'sectionTitle'))
    return f,v

def row(*widgets):
    h=QHBoxLayout();h.setSpacing(10)
    for w in widgets:
        if w is None:h.addStretch()
        else:h.addWidget(w)
    return h

class DeviceNotes(QDialog):
    def __init__(self,parent,asset):
        super().__init__(parent);self.setWindowTitle('Device annotations');self.resize(580,420);v=QVBoxLayout(self);v.addWidget(label('Record your device context','title'));form=QFormLayout()
        self.name=QLineEdit(asset['label']);self.owner=QLineEdit(asset['owner']);self.review=QComboBox();self.review.addItems(['Unreviewed','Expected','Investigate']);self.review.setCurrentText(asset['review']);self.notes=QPlainTextEdit(asset['notes'])
        for title,w in [('Display name',self.name),('Owner / team',self.owner),('Review status',self.review),('Notes',self.notes)]:form.addRow(title,w)
        v.addLayout(form);controls=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel);controls.accepted.connect(self.accept);controls.rejected.connect(self.reject);v.addWidget(controls)

class DeviceDialog(QDialog):
    def __init__(self,parent,asset,store):
        super().__init__(parent);self.setWindowTitle('Device evidence • '+asset['ip']);self.resize(940,690);v=QVBoxLayout(self);v.addWidget(label(asset['label'] or asset['data'].get('hostname') or asset['ip'],'title'));v.addWidget(label('Address-based evidence. A vendor prefix or open port does not establish device identity.','muted'));tabs=QTabWidget();v.addWidget(tabs,1)
        d=asset['data'];overview=QPlainTextEdit();overview.setReadOnly(True)
        overview.setPlainText('\n'.join([f"IPv4: {asset['ip']}",f"Scope: {asset['scope']}",f"Hostname: {d.get('hostname') or 'Unavailable'}",f"MAC: {d.get('mac') or 'Unavailable'}",f"Vendor prefix: {d.get('vendor') or 'Unavailable'}",f"Role hint: {d.get('role','Unclassified')}",f"Presence: {d.get('presence')}",f"First observed (UTC): {asset['first_seen']}",f"Last observed (UTC): {asset['last_seen']}",f"Review: {asset['review']}",f"Owner: {asset['owner']}",f"Notes: {asset['notes']}",'','Evidence:','\n'.join(d.get('evidence',[])),'','Review notes:','\n'.join(exposures(d)) or 'No review items generated.']))
        tabs.addTab(overview,'Overview')
        services=Table(['TCP port','Service hint','Observed state']);requested=set(d.get('requested_ports',[]))|{int(p) for p in d.get('ports',{})}
        from .discovery import SERVICES
        services.fill([[p,SERVICES.get(p,'TCP service'),d.get('ports',{}).get(str(p),{}).get('state','Not attempted')] for p in sorted(requested)]);tabs.addTab(services,'Services')
        web=QPlainTextEdit();web.setReadOnly(True);web.setPlainText(json.dumps(d.get('web',[]),indent=2));tabs.addTab(web,'Web / TLS observations')
        history=QPlainTextEdit();history.setReadOnly(True);history.setPlainText(json.dumps({'address_observations':store.history(asset['scope'],asset['ip']),'annotation_journal':store.note_history(asset['scope'],asset['ip'])},indent=2));tabs.addTab(history,'Observation history')
        raw=QPlainTextEdit();raw.setReadOnly(True);raw.setPlainText(json.dumps(d,indent=2));tabs.addTab(raw,'Raw evidence');v.addWidget(button('Close',self.accept))

class NetworkWindow(QMainWindow):
    PAGES=['Dashboard','Devices','Scan history','Change timeline','Scan settings']
    TITLES=['Network intelligence','Device inventory','Recorded network scans','What changed on your network','Discovery policy']
    SUBTITLES=['Discover your subnet. Investigate services. Keep the evidence.','Search observed addresses, identify owners and inspect the discovery evidence.','Every attempted address is recorded, including no-response outcomes.','Compare completed scans of the same subnet without guessing device availability.','Control scan scope, pacing, scheduling, appearance and retention.']
    def __init__(self,directory=None,auto_detect=True):
        super().__init__();self.setWindowTitle('ConnWatch Network | Developed by ZakirUllah');self.setWindowIcon(QIcon(str(Path(__file__).resolve().parents[1]/'assets/connwatch.png')));self.resize(1500,980);self.setMinimumSize(1150,800)
        self.directory=Path(directory or QStandardPaths.writableLocation(QStandardPaths.AppLocalDataLocation));self.store=InventoryStore(self.directory)
        self.settings=QSettings(str(self.directory/'network-settings.ini'),QSettings.IniFormat);self.light=self.settings.value('light',False,type=bool);self.motion=self.settings.value('motion',True,type=bool)
        self.worker=None;self.profile_worker=None;self.profiles=[];self.active_scan=None;self.active_scope='';self.last_summary=None;self.running=False;self.host_window=None;self.closing=False;self.animations=[];self.result_cache={};self.refresh_pending=False;self.storage_failure=''
        self.elapsed=QTimer(self);self.elapsed.timeout.connect(self.elapsed_tick);self.repeat_timer=QTimer(self);self.repeat_timer.setSingleShot(True);self.repeat_timer.timeout.connect(self.repeat_scan)
        self.store.purge(self.settings.value('retention',90,type=int),self.settings.value('max_scans',500,type=int))
        self.build();self.apply_theme();self.refresh_history();self.refresh_changes();self.navigate(0)
        scans=self.store.scans()
        if scans:
            self.active_scan=scans[0]['id'];self.active_scope=scans[0]['scope'];self.refresh_inventory();self.update_metrics()
        self.store.purge(self.settings.value('retention',90,type=int),self.settings.value('max_scans',500,type=int))
        if auto_detect:QTimer.singleShot(100,self.detect_adapters)
    def build(self):
        root=QWidget();self.setCentralWidget(root);shell=QHBoxLayout(root);shell.setContentsMargins(0,0,0,0);shell.setSpacing(0)
        side=QFrame();side.setObjectName('sidebar');side.setFixedWidth(222);self.sidebar=QVBoxLayout(side);self.sidebar.setContentsMargins(17,27,17,20);self.sidebar.setSpacing(7)
        self.sidebar.addWidget(label('ConnWatch','brand'));self.sidebar.addWidget(label('NETWORK INTELLIGENCE','eyebrow'));self.sidebar.addSpacing(32);self.nav=[]
        for i,name in enumerate(self.PAGES):
            b=button('  '+name,lambda i=i:self.navigate(i),'nav');b.setCheckable(True);b.setIcon(icon(['grid','signal','list','shield','gear'][i]));self.nav.append(b);self.sidebar.addWidget(b)
        self.sidebar.addSpacing(25);self.sidebar.addWidget(label('INVESTIGATION TOOLS','eyebrow'));self.sidebar.addWidget(button('Workstation inspector',self.open_host));self.sidebar.addStretch()
        self.sidebar.addWidget(label('Developed by\nZakirUllah','muted'));self.sidebar.addWidget(label('VERSION 3.0.0','eyebrow'));shell.addWidget(side)
        area=QVBoxLayout();area.setContentsMargins(28,23,28,12);area.setSpacing(14);shell.addLayout(area,1)
        self.status_chip=label('READY TO DISCOVER','eyebrow');self.status_chip.setMinimumWidth(265);self.status_chip.setWordWrap(False);self.scan_state=label('No scan running','muted');self.export_button=button('Export assessment',self.export_dialog);self.scan_button=button('Scan network',self.toggle_scan,'primary')
        area.addLayout(row(self.status_chip,None,self.scan_state,self.export_button,self.scan_button));self.heading=label('','title');self.subtitle=label('','muted');area.addWidget(self.heading);area.addWidget(self.subtitle)
        scope_panel,scope_layout=panel();scope_layout.setContentsMargins(14,12,14,12)
        self.adapter_combo=QComboBox();self.adapter_combo.setMinimumWidth(190);self.adapter_combo.addItem('Detecting network adapters...');self.adapter_combo.currentIndexChanged.connect(self.adapter_changed)
        self.scope_edit=QLineEdit();self.scope_edit.setPlaceholderText('IPv4 subnet, e.g. 192.168.1.0/24');self.scope_edit.setMinimumWidth(160)
        self.profile_combo=QComboBox();self.profile_combo.addItems(['Discovery','Standard','Extended','Custom']);self.profile_combo.setCurrentText(self.settings.value('profile','Standard'))
        self.refresh_button=button('Refresh adapters',self.detect_adapters)
        scope_layout.addLayout(row(label('ADAPTER','eyebrow'),self.adapter_combo,label('SCOPE','eyebrow'),self.scope_edit,self.profile_combo,self.refresh_button));area.addWidget(scope_panel)
        self.scope_hint=label('Select an adapter or enter a private subnet. No network probes are sent until you start a scan.','muted');area.addWidget(self.scope_hint)
        self.progress=QProgressBar();self.progress.setRange(0,100);self.progress.setValue(0);self.progress.setTextVisible(False);self.progress.setFixedHeight(5);area.addWidget(self.progress)
        self.stack=QStackedWidget();area.addWidget(self.stack,1)
        for builder in [self.dashboard_page,self.devices_page,self.history_page,self.changes_page,self.settings_page]:
            page=QWidget();v=QVBoxLayout(page);v.setContentsMargins(0,0,0,0);v.setSpacing(14);builder(v)
            if builder==self.dashboard_page:
                scroll=QScrollArea();scroll.setWidgetResizable(True);scroll.setFrameShape(QFrame.NoFrame);page.setObjectName('scrollBody');scroll.setWidget(page);self.stack.addWidget(scroll)
            else:self.stack.addWidget(page)
        self.footer=label('Evidence stays in your workspace. Response coverage depends on device settings, routing and network isolation.','muted');area.addWidget(self.footer)
        self.statusBar().showMessage('Ready. Select your subnet and start network discovery.')
    def dashboard_page(self,v):
        self.cards=[AnimatedCard('Observed devices',0,'Confirmed responses + neighbor observations'),AnimatedCard('Responding',0,'ICMP or TCP response / adapter address'),AnimatedCard('New addresses',0,'Compared with the previous completed scan'),AnimatedCard('Open TCP services',0,'Observed in the selected port profile')]
        metrics=QHBoxLayout()
        for c in self.cards:metrics.addWidget(c)
        v.addLayout(metrics)
        middle=QHBoxLayout();self.map=NetworkMap();self.map.selected.connect(self.select_ip);middle.addWidget(self.map,3)
        right,rv=panel('Scan coverage');self.coverage=label('No network scan has been recorded yet.','muted');rv.addWidget(self.coverage);rv.addStretch();rv.addWidget(button('Review discovered devices',lambda:self.navigate(1)));rv.addWidget(button('Open scan history',lambda:self.navigate(2)));middle.addWidget(right,2);v.addLayout(middle,2)
        bottom=QHBoxLayout();left,lv=panel('Recent network changes');self.recent_changes=Table(['IPv4','Change','Details']);lv.addWidget(self.recent_changes);bottom.addWidget(left,3)
        right,rv=panel('Review focus');self.findings=label('Configuration review notes will appear after a scan.','muted');rv.addWidget(self.findings);rv.addStretch();bottom.addWidget(right,2);v.addLayout(bottom,1)
    def devices_page(self,v):
        self.device_search=QLineEdit();self.device_search.setPlaceholderText('Search address, hostname, vendor, MAC, port or review status...')
        self.presence_filter=QComboBox();self.presence_filter.addItems(['All presence','Responding','Neighbor observed','Not observed this scan']);self.presence_filter.currentTextChanged.connect(self.filter_devices)
        v.addLayout(row(self.device_search,self.presence_filter,button('Inspect device',self.inspect_device),button('Edit notes',self.edit_notes)))
        self.device_table=Table(['Name / hostname','IPv4','MAC address','Vendor prefix','Presence','Open TCP','Review']);self.device_table.setWordWrap(False);self.device_table.verticalHeader().setDefaultSectionSize(43);self.device_table.doubleClicked.connect(lambda _:self.inspect_device());self.device_search.textChanged.connect(self.device_table.proxy.set_term);v.addWidget(self.device_table,1)
        v.addWidget(label('Inventory is address-based within the selected subnet. Names and vendor prefixes are observations, not guaranteed hardware identities.','muted'))
    def history_page(self,v):
        v.addLayout(row(button('Refresh',self.refresh_history),button('View scan evidence',self.view_scan),button('Use this scan in Dashboard',self.use_scan),None,button('Export selected scan',self.export_selected)))
        self.history_table=Table(['Started (UTC)','Scope','Profile','Attempted / targets','Observed','Status','Duration']);self.history_table.doubleClicked.connect(lambda _:self.view_scan());v.addWidget(self.history_table,1)
        v.addWidget(label('Cancelled or interrupted scans retain their recorded observations. Only completed comparable scans generate disappearance/change events.','muted'))
    def changes_page(self,v):
        self.change_search=QLineEdit();self.change_search.setPlaceholderText('Search address, subnet, change type or details...');v.addLayout(row(self.change_search,button('Refresh',self.refresh_changes)))
        self.change_table=Table(['Scan time (UTC)','Subnet','IPv4','Change','Evidence']);self.change_search.textChanged.connect(self.change_table.proxy.set_term);v.addWidget(self.change_table,1)
        v.addWidget(label('A missing observation is not a confirmed offline device. Port-state changes are compared only for ports checked in both scans.','muted'))
    def settings_page(self,v):
        scroll=QScrollArea();scroll.setWidgetResizable(True);scroll.setFrameShape(QFrame.NoFrame);body=QWidget();body.setObjectName('scrollBody');bv=QVBoxLayout(body);bv.setContentsMargins(0,0,0,0)
        frame,fv=panel('Probe policy');form=QFormLayout();self.custom_ports=QLineEdit(self.settings.value('custom_ports','22,80,443,445,3389,8080'))
        self.workers_spin=QSpinBox();self.workers_spin.setRange(1,64);self.workers_spin.setValue(self.settings.value('workers',24,type=int))
        self.timeout_spin=QDoubleSpinBox();self.timeout_spin.setRange(.1,3);self.timeout_spin.setSingleStep(.1);self.timeout_spin.setValue(self.settings.value('timeout',.35,type=float));self.timeout_spin.setSuffix(' seconds')
        self.rate_spin=QSpinBox();self.rate_spin.setRange(1,200);self.rate_spin.setValue(self.settings.value('rate',80,type=int))
        self.resolve_check=QCheckBox('Resolve hostnames for observed addresses');self.resolve_check.setChecked(self.settings.value('resolve',True,type=bool))
        self.metadata_check=QCheckBox('Read HTTP response headers and TLS certificate observations on open web ports');self.metadata_check.setChecked(self.settings.value('metadata',True,type=bool))
        for title,w in [('Custom TCP ports (up to 64)',self.custom_ports),('Parallel addresses',self.workers_spin),('TCP connect timeout',self.timeout_spin),('Paced probe starts / second',self.rate_spin),('Names',self.resolve_check),('Web metadata',self.metadata_check)]:form.addRow(title,w)
        fv.addLayout(form);bv.addWidget(frame)
        frame,fv=panel('Scheduling and appearance');form=QFormLayout();self.schedule_check=QCheckBox('Repeat after a finished scan while this app stays open');self.schedule_check.setChecked(self.settings.value('schedule',False,type=bool))
        self.minutes_spin=QSpinBox();self.minutes_spin.setRange(2,1440);self.minutes_spin.setValue(self.settings.value('minutes',15,type=int));self.minutes_spin.setSuffix(' minutes')
        self.motion_check=QCheckBox('Smooth page transitions and discovery pulse');self.motion_check.setChecked(self.motion);self.theme_combo=QComboBox();self.theme_combo.addItems(['Dark','Light']);self.theme_combo.setCurrentText('Light' if self.light else 'Dark')
        self.retention_spin=QSpinBox();self.retention_spin.setRange(1,3650);self.retention_spin.setValue(self.settings.value('retention',90,type=int));self.retention_spin.setSuffix(' days')
        self.max_scans_spin=QSpinBox();self.max_scans_spin.setRange(10,10000);self.max_scans_spin.setValue(self.settings.value('max_scans',500,type=int))
        for title,w in [('Repeat scanning',self.schedule_check),('Repeat delay',self.minutes_spin),('Animation',self.motion_check),('Theme',self.theme_combo),('Raw scan retention',self.retention_spin),('Maximum retained scans',self.max_scans_spin)]:form.addRow(title,w)
        fv.addLayout(form);fv.addLayout(row(button('Save policy',self.save_settings,'primary'),button('Open workspace',self.open_data),button('Apply retention',self.purge),None));bv.addWidget(frame)
        bv.addWidget(label('Developed by ZakirUllah • ConnWatch Network 3.0.0','muted'));bv.addWidget(label('Discovery uses private IPv4 scopes with up to 4,094 hosts per run. No authentication attempts, credential collection, exploits, packet interception or automatic blocking are performed. Service names are port-based hints. Offline manufacturer prefixes use Wireshark’s IEEE/registry-derived database.','muted'));bv.addStretch();scroll.setWidget(body);v.addWidget(scroll)
    def navigate(self,index):
        for active in list(self.animations):
            active.stop()
            if hasattr(active,'page') and active.page.graphicsEffect() is active.effect:active.page.setGraphicsEffect(None)
            active.deleteLater()
        self.animations.clear()
        self.stack.setCurrentIndex(index);self.heading.setText(self.TITLES[index]);self.subtitle.setText(self.SUBTITLES[index])
        for i,b in enumerate(self.nav):b.setChecked(i==index)
        if self.motion:
            page=self.stack.currentWidget();effect=QGraphicsOpacityEffect(page);page.setGraphicsEffect(effect);animation=QPropertyAnimation(effect,b'opacity',self);animation.setDuration(170);animation.setStartValue(.18);animation.setEndValue(1);animation.setEasingCurve(QEasingCurve.OutCubic)
            animation.page=page;animation.effect=effect;self.animations.append(animation)
            def done():
                if page.graphicsEffect() is effect:page.setGraphicsEffect(None)
                if animation in self.animations:self.animations.remove(animation)
                animation.deleteLater()
            animation.finished.connect(done);animation.start()
    def apply_theme(self):
        background='#f1f5f9' if self.light else '#091422'
        self.setStyleSheet(stylesheet(self.light)+'QWidget#scrollBody,QScrollArea{background:'+background+';border:none;}'+'''QProgressBar{border:none;background:#20354b;border-radius:2px;}QProgressBar::chunk{background:#35cbae;border-radius:2px;}QTabWidget::pane{border:1px solid #294156;border-radius:7px;}QTabBar::tab{padding:11px 15px;}QTabBar::tab:selected{color:#31b99d;}''')
        self.map.light=self.light;self.map.update()
        for card in self.cards:card.motion=self.motion
    def error(self,message):QMessageBox.warning(self,'ConnWatch Network',str(message))
    def detect_adapters(self):
        if self.running or self.profile_worker:return
        self.refresh_button.setEnabled(False);self.scan_button.setEnabled(False);self.profile_worker=ProfileWorker(self);self.profile_worker.ready.connect(self.profiles_ready);self.profile_worker.finished.connect(self.profiles_finished);self.profile_worker.start()
    def profiles_ready(self,profiles,warnings):
        self.profiles=profiles;self.adapter_combo.blockSignals(True);self.adapter_combo.clear()
        for p in profiles:self.adapter_combo.addItem(p['name']+' • '+p['ip'])
        self.adapter_combo.addItem('Manual private subnet');self.adapter_combo.blockSignals(False);self.adapter_changed()
        if warnings:self.scope_hint.setText(self.scope_hint.text()+' • '+' | '.join(warnings))
    def profiles_finished(self):
        if self.profile_worker:self.profile_worker.deleteLater();self.profile_worker=None
        self.refresh_button.setEnabled(True);self.scan_button.setEnabled(True)
    def selected_profile(self):
        i=self.adapter_combo.currentIndex();return self.profiles[i] if 0<=i<len(self.profiles) else {}
    def adapter_changed(self,*_):
        p=self.selected_profile()
        if p:
            self.scope_edit.setText(p['scope']);self.scope_hint.setText(f"Detected private IPv4 {p['ip']} • Netmask {p['mask']} • Gateway {p['gateway'] or 'Unavailable'}")
        elif not self.running:
            self.scope_edit.setText(self.settings.value('manual_scope',''));self.scope_hint.setText('Manual scope: enter the private subnet you intend to scan. Up to 4,094 host addresses per run.')
    def options(self):
        profile_name=self.profile_combo.currentText();ports=parse_ports(self.custom_ports.text()) if profile_name=='Custom' else PROFILES[profile_name].copy()
        return ScanOptions(self.scope_edit.text().strip(),dict(self.selected_profile()),ports,profile_name,self.workers_spin.value(),self.timeout_spin.value(),self.rate_spin.value(),self.resolve_check.isChecked(),self.metadata_check.isChecked())
    def toggle_scan(self):
        if self.running:self.stop_scan()
        else:self.start_scan()
    def start_scan(self):
        if self.worker or self.profile_worker:return
        try:
            options=self.options();network=options.validate();self.repeat_timer.stop();self.active_scope=options.scope
            total=network.num_addresses if network.prefixlen>=31 else network.num_addresses-2
            self.active_scan=self.store.begin(asdict(options),total);self.result_cache={};self.storage_failure='';self.last_summary=None;self.running=True;self.started_at=time.monotonic();self.scan_button.setText('Stop scan');self.status_chip.setText('DISCOVERY IN PROGRESS')
            self.set_scope_enabled(False);self.progress.setRange(0,total);self.progress.setValue(0);self.elapsed.start(1000);self.map.set_scanning(True,self.motion)
            self.worker=DiscoveryWorker(options,self);self.worker.batch.connect(self.record_batch);self.worker.progress.connect(self.scan_progress);self.worker.complete.connect(self.scan_complete);self.worker.failed.connect(self.scan_failed);self.worker.finished.connect(self.worker_finished);self.worker.start()
            self.refresh_inventory();self.refresh_history();self.update_metrics()
        except Exception as exc:self.error(exc)
    def set_scope_enabled(self,enabled):
        for w in [self.adapter_combo,self.scope_edit,self.profile_combo,self.refresh_button,self.custom_ports,self.workers_spin,self.timeout_spin,self.rate_spin,self.resolve_check,self.metadata_check,self.schedule_check,self.minutes_spin,self.retention_spin,self.max_scans_spin,self.theme_combo,self.motion_check]:w.setEnabled(enabled)
    def stop_scan(self):
        if self.worker:self.worker.stop();self.scan_button.setEnabled(False);self.scan_state.setText('Finishing in-flight probes...');self.status_chip.setText('STOPPING DISCOVERY')
        self.repeat_timer.stop()
    def record_batch(self,records):
        try:
            if self.storage_failure:return
            self.store.record(self.active_scan,records)
            self.result_cache.update({r['ip']:r for r in records})
            if not self.refresh_pending:
                self.refresh_pending=True;QTimer.singleShot(250,self.refresh_during_scan)
        except Exception as exc:
            self.storage_failure=str(exc)
            if self.worker:self.worker.stop()
            self.error('Could not save scan evidence: '+str(exc))
    def refresh_during_scan(self):
        self.refresh_pending=False
        if not self.closing:self.refresh_inventory();self.update_metrics()
    def scan_progress(self,completed,total,message):
        self.progress.setMaximum(total);self.progress.setValue(completed);self.scan_state.setText(f'{completed:,} / {total:,} addresses • {message}')
    def elapsed_tick(self):
        seconds=int(time.monotonic()-self.started_at);self.statusBar().showMessage(f'Scan elapsed {seconds//60:02d}:{seconds%60:02d} • Completed address results are saved as they arrive.')
    def scan_complete(self,summary):
        if self.storage_failure:summary={**summary,'status':'Failed','error':self.storage_failure}
        try:self.last_summary=self.store.finish(self.active_scan,summary)
        except Exception as exc:self.error('Could not finalize scan: '+str(exc))
        self.store.purge(self.retention_spin.value(),self.max_scans_spin.value())
        self.finish_ui();self.refresh_inventory();self.update_metrics();self.refresh_history();self.refresh_changes()
        if self.schedule_check.isChecked() and summary['status']=='Completed' and not self.closing:self.repeat_timer.start(self.minutes_spin.value()*60000);self.statusBar().showMessage(f'Next scan scheduled in {self.minutes_spin.value()} minutes while the app stays open.')
    def scan_failed(self,message):
        try:self.store.finish(self.active_scan,{'status':'Failed','ended':utc(),'error':message})
        except Exception:pass
        self.finish_ui();self.refresh_history();self.error(message)
    def finish_ui(self):
        self.running=False;self.elapsed.stop();self.map.set_scanning(False);self.scan_button.setText('Scan network');self.scan_button.setEnabled(True);self.set_scope_enabled(True);self.status_chip.setText('ASSESSMENT READY')
        if self.last_summary:self.scan_state.setText(f"{self.last_summary['status']} • {self.last_summary['observed']} observed • {self.last_summary['duration_seconds']:g}s")
    def worker_finished(self):
        if self.worker:self.worker.deleteLater();self.worker=None
        if self.closing:QTimer.singleShot(0,self.close)
    def repeat_scan(self):
        if not self.closing and not self.running and self.schedule_check.isChecked():self.start_scan()
    def refresh_inventory(self):
        self.assets=self.store.devices(self.active_scope or None,self.active_scan);self.filter_devices()
        visible=[a for a in self.assets if a['current']];profile=self.store.get_scan(self.active_scan)['options'].get('profile',{}) if self.active_scan else {}
        self.map.set_devices(visible,self.active_scope,profile.get('gateway',''))
    def filter_devices(self,*_):
        assets=getattr(self,'assets',[]);selected=self.presence_filter.currentText()
        def presence(a):return a['data'].get('presence','Unknown') if a['current'] else 'Not observed this scan'
        if selected!='All presence':assets=[a for a in assets if presence(a)==selected]
        self.device_table.fill([[a['label'] or a['data'].get('hostname') or a['ip'],a['ip'],a['data'].get('mac') or 'Unavailable',a['data'].get('vendor') or 'Unavailable',presence(a),', '.join(str(p) for p,v in a['data'].get('ports',{}).items() if v['state']=='Open') or 'None observed',a['review']] for a in assets],assets)
    def update_metrics(self):
        if not self.active_scan:return
        scan=self.store.get_scan(self.active_scan);records=list(self.result_cache.values()) if self.running else self.store.records(self.active_scan);observed=[d for d in records if d.get('presence') in ('Responding','Neighbor observed')];changes=self.store.changes(self.active_scan)
        values=[len(observed),sum(d['presence']=='Responding' for d in observed),sum(c['kind']=='New address observed' for c in changes),sum(v['state']=='Open' for d in observed for v in d.get('ports',{}).values())]
        for c,value in zip(self.cards,values):c.update(value)
        self.coverage.setText(f"Subnet: {scan['scope']}\n\n{len(records):,} of {scan['total']:,} addresses attempted\n{len(observed)} addresses observed\n{sum(d.get('presence')=='No response' for d in records)} no-response outcomes\n\nProfile: {scan['options']['profile_name']}\n{len(scan['options']['ports'])} selected TCP ports\nState: {scan['status']}\n\nAll address attempts are retained in this scan's JSON evidence.")
        focus=[(d['ip'],finding) for d in observed for finding in exposures(d)]
        self.findings.setText('\n\n'.join(ip+'\n'+finding for ip,finding in focus[:4]) if focus else 'No review notes from the selected service checks. This does not establish that every device is secure.')
        self.recent_changes.fill([[c['ip'],c['kind'],c['detail']] for c in changes[:5]])
    def select_ip(self,ip):self.navigate(1);self.device_search.setText(ip)
    def inspect_device(self):
        asset=self.device_table.selected()
        if not asset:self.error('Select an observed device address first.');return
        DeviceDialog(self,asset,self.store).exec()
    def edit_notes(self):
        asset=self.device_table.selected()
        if not asset:self.error('Select a device first.');return
        dialog=DeviceNotes(self,asset)
        if dialog.exec()==QDialog.Accepted:self.store.annotate(asset['scope'],asset['ip'],dialog.name.text(),dialog.owner.text(),dialog.review.currentText(),dialog.notes.toPlainText());self.refresh_inventory()
    def refresh_history(self):
        scans=self.store.scans();rows=[]
        for s in scans:
            opts=json.loads(s['options']);summary=json.loads(s['summary']);rows.append([s['started'],s['scope'],opts.get('profile_name',''),f"{s['recorded']} / {s['total']}",summary.get('observed','—'),s['status'],str(summary.get('duration_seconds','—'))+'s'])
        self.history_table.fill(rows,scans)
    def refresh_changes(self):
        changes=self.store.changes();self.change_table.fill([[c['started'],c['scope'],c['ip'],c['kind'],c['detail']] for c in changes],changes)
    def use_scan(self):
        if self.running:self.error('Finish the current scan before opening an earlier assessment.');return
        selected=self.history_table.selected()
        if not selected:self.error('Select a saved scan first.');return
        self.active_scan=selected['id'];self.active_scope=selected['scope'];self.refresh_inventory();self.update_metrics();self.navigate(0);self.status_chip.setText('SAVED ASSESSMENT')
    def view_scan(self):
        s=self.history_table.selected()
        if not s:self.error('Select a saved scan.');return
        d=QDialog(self);d.resize(1000,650);d.setWindowTitle('Address-attempt evidence');v=QVBoxLayout(d);v.addWidget(label(s['scope']+' • '+s['status'],'title'));table=Table(['IPv4','Presence','Hostname','MAC','Checked TCP ports','Duration ms'])
        records=self.store.records(s['id']);table.fill([[r['ip'],r['presence'],r.get('hostname',''),r.get('mac',''),', '.join(map(str,r.get('checked_ports',[]))),r.get('duration_ms','')] for r in records],records);v.addWidget(table,1);v.addWidget(button('Close',d.accept));d.exec()
    def export_selected(self):
        selected=self.history_table.selected()
        if not selected:self.error('Select a saved scan.');return
        self.export_dialog(selected['id'])
    def export_dialog(self,sid=None):
        sid=sid or self.active_scan
        if not sid:self.error('Record a network scan first.');return
        path,kind=QFileDialog.getSaveFileName(self,'Export network assessment','ConnWatch-Network-Assessment.pdf','PDF (*.pdf);;HTML (*.html);;CSV (*.csv);;JSON (*.json)')
        if not path:return
        extension={'PDF (*.pdf)':'pdf','HTML (*.html)':'html','CSV (*.csv)':'csv','JSON (*.json)':'json'}[kind]
        if not Path(path).suffix:path+='.'+extension
        try:
            if extension=='pdf':
                if Path(path).resolve().parent==self.directory.resolve() and Path(path).name in {'network.db','network.db-wal','network.db-shm','connwatch.db','settings.ini','network-settings.ini','workspace.lock','connwatch.log'}:raise ValueError('Choose a report file outside active application data.')
                document=QTextDocument();document.setHtml(network_report(export_data(self.store,sid)));printer=QPrinter(QPrinter.HighResolution);printer.setOutputFormat(QPrinter.PdfFormat);printer.setPageSize(QPageSize(QPageSize.A4));printer.setPageOrientation(QPageLayout.Landscape);printer.setOutputFileName(path);document.print_(printer)
                if not Path(path).is_file() or Path(path).stat().st_size<100:raise OSError('PDF could not be written.')
            else:export_network(self.store,sid,path,extension)
            self.statusBar().showMessage('Assessment exported: '+path)
        except Exception as exc:self.error('Export failed: '+str(exc))
    def save_settings(self):
        if self.running:self.error('Stop the active scan before changing policy.');return
        try:parse_ports(self.custom_ports.text())
        except ValueError as exc:self.error(exc);return
        values={'custom_ports':self.custom_ports.text(),'workers':self.workers_spin.value(),'timeout':self.timeout_spin.value(),'rate':self.rate_spin.value(),'resolve':self.resolve_check.isChecked(),'metadata':self.metadata_check.isChecked(),'schedule':self.schedule_check.isChecked(),'minutes':self.minutes_spin.value(),'motion':self.motion_check.isChecked(),'light':self.theme_combo.currentText()=='Light','retention':self.retention_spin.value(),'max_scans':self.max_scans_spin.value(),'profile':self.profile_combo.currentText(),'manual_scope':self.scope_edit.text() if not self.selected_profile() else ''}
        for key,value in values.items():self.settings.setValue(key,value)
        self.settings.sync();self.light=values['light'];self.motion=values['motion'];self.apply_theme()
        if not values['schedule']:self.repeat_timer.stop()
        self.statusBar().showMessage('Discovery policy saved. Scheduling begins after your next completed scan.')
    def open_data(self):QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.directory)))
    def purge(self):
        if QMessageBox.question(self,'Apply retention',f'Delete raw scans older than {self.retention_spin.value()} days and keep at most the newest {self.max_scans_spin.value()} finished scans? Device annotations will remain.')!=QMessageBox.Yes:return
        self.store.purge(self.retention_spin.value(),self.max_scans_spin.value());self.refresh_history();self.refresh_changes()
        scans=self.store.scans()
        if self.active_scan and self.active_scan not in {s['id'] for s in scans}:
            self.active_scan=scans[0]['id'] if scans else None;self.active_scope=scans[0]['scope'] if scans else ''
        self.refresh_inventory()
        if self.active_scan:self.update_metrics()
        else:
            for card in self.cards:card.update(0)
            self.map.set_devices([]);self.coverage.setText('No retained scans.');self.recent_changes.fill([])
    def open_host(self):
        if self.host_window:
            self.host_window.showNormal();self.host_window.raise_();self.host_window.activateWindow();return
        from .workstation import WorkstationWindow
        self.host_window=WorkstationWindow(self.directory);self.host_window.setAttribute(Qt.WA_DeleteOnClose);self.host_window.closed.connect(self.host_closed);self.host_window.setWindowTitle('ConnWatch • Workstation inspector');self.host_window.demo_button.hide();self.host_window.banner.setText('Start capture to inspect this workstation’s processes and network sockets.');self.host_window.mode_label.setText('WORKSTATION INSPECTOR');self.host_window.footer.setText('Host socket evidence complements the separate subnet discovery workspace.');self.host_window.show()
    def host_closed(self):self.host_window=None
    def closeEvent(self,event):
        self.closing=True;self.repeat_timer.stop()
        if self.worker:
            self.stop_scan();self.scan_state.setText('Saving in-flight results before closing...');event.ignore();return
        if self.profile_worker:
            event.ignore();QTimer.singleShot(100,self.close);return
        if self.host_window:
            if self.host_window.worker and self.host_window.worker.isRunning():self.host_window.stop_monitoring();event.ignore();QTimer.singleShot(200,self.close);return
            if any(any(t.isRunning() for t in d.workers) for d in self.host_window.dialogs):
                for d in self.host_window.dialogs:
                    for t in d.workers:t.requestInterruption()
                event.ignore();QTimer.singleShot(200,self.close);return
            self.host_window.close();self.host_window=None
        self.elapsed.stop();self.store.close();event.accept()
