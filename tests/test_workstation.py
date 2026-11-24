import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import csv
from dataclasses import replace,asdict
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch
from PySide6.QtWidgets import QApplication,QDialog
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from app.detection import Allowlist,Detector,Connection,demo_snapshot,snapshot
from app.storage import Store,utc,endpoint,report_data,report_html,export_file
from app.engine import synthetic,HashWorker,process_details,ScanWorker
from app.window import MainWindow,RuleDialog,ProcessDialog

APP=QApplication.instance() or QApplication([])
APP.setApplicationName('ConnWatchTests');APP.setOrganizationName('ZakirUllah')

def spin(predicate,seconds=4):
    until=time.time()+seconds
    while time.time()<until:
        APP.processEvents()
        if predicate():return True
        time.sleep(.01)
    return False

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name)
        self.addCleanup(self.temp.cleanup);self.addCleanup(self.store.close)
        self.c=demo_snapshot()[0];self.sid=self.store.start('TEST','test-host')
    def record(self,c=None):
        c=c or self.c;a=Detector(Allowlist()).inspect([c],utc())
        self.store.save_scan(self.sid,{'time':utc(),'mode':'TEST','connections':[asdict(c)],'warnings':[]},a)
    def test_default_conservative_rules(self):
        rules=Allowlist.load(self.store.rule_path)
        self.assertFalse(rules.known(self.c));self.assertTrue(rules.known(replace(self.c,remote_address='127.0.0.1')))
    def test_invalid_rules_preserve_original(self):
        before=self.store.rule_path.read_bytes()
        with self.assertRaises(ValueError):self.store.save_rules({'version':1,'rules':[{'address':'bad','ports':[1]}]})
        self.assertEqual(self.store.rule_path.read_bytes(),before)
    def test_write_full_snapshot(self):
        self.record();data=self.store.scans(self.sid)
        self.assertEqual(data[0]['connections'][0]['remote_address'],self.c.remote_address)
    def test_alert_evidence(self):
        self.record();a=self.store.alerts(self.sid)[0]['data']
        for key in ['time','process','pid','remote_address','remote_port','protocol']:self.assertIn(key,a)
    def test_triage_persists(self):
        self.record();aid=self.store.alerts(self.sid)[0]['id'];self.store.triage(aid,'Resolved','Verified service')
        self.assertEqual(self.store.alerts(self.sid)[0]['status'],'Resolved');self.assertEqual(self.store.alerts(self.sid)[0]['note'],'Verified service')
    def test_invalid_triage(self):
        with self.assertRaises(ValueError):self.store.triage(1,'Bad','')
    def test_baseline_is_not_trust(self):
        b=self.store.baseline(self.sid,[self.c]);self.assertIn(endpoint(self.c),b)
        self.assertFalse(Allowlist.load(self.store.rule_path).known(self.c))
    def test_sessions_modes(self):
        other=self.store.start('SYNTHETIC DEMO','Demo');self.record()
        self.assertEqual(self.store.alerts(other),[]);self.assertEqual(len(self.store.sessions()),2)
    def test_atomic_scan_rollback(self):
        with self.assertRaises(Exception):self.store.save_scan(self.sid,{'time':utc(),'connections':[]},[{'time':utc()}])
        self.assertEqual(self.store.scans(self.sid),[])
    def test_export_json(self):
        self.record();p=Path(self.temp.name)/'e.json';export_file(self.store,self.sid,p,'json');d=json.loads(p.read_text());self.assertEqual(d['developed_by'],'ZakirUllah');self.assertEqual(len(d['scans']),1)
    def test_export_html_escaped(self):
        self.record(replace(self.c,process='<script>test</script>'));d=report_html(report_data(self.store,self.sid));self.assertIn('&lt;script&gt;',d);self.assertNotIn('<script>',d)
    def test_export_csv_formula(self):
        self.record(replace(self.c,process='=1+1'));p=Path(self.temp.name)/'e.csv';export_file(self.store,self.sid,p,'csv');self.assertIn("'=1+1",p.read_text(encoding='utf-8-sig'))
    def test_no_export_over_database(self):
        with self.assertRaises(ValueError):export_file(self.store,self.sid,self.store.directory/'connwatch.db','json')
    def test_no_export_over_rules(self):
        with self.assertRaises(ValueError):export_file(self.store,self.sid,self.store.rule_path,'html')
    def test_retention_closed_only(self):
        old=(datetime.now(timezone.utc)-timedelta(days=50)).isoformat()
        closed=self.store.start('TEST','old')
        with self.store.db:self.store.db.execute('UPDATE sessions SET started=?,ended=? WHERE id=?',(old,old,closed))
        self.store.purge(30);ids={s['id'] for s in self.store.sessions()};self.assertNotIn(closed,ids);self.assertIn(self.sid,ids)
    def test_missing_session(self):
        with self.assertRaises(ValueError):report_data(self.store,'missing')

class DetectionTests(unittest.TestCase):
    def setUp(self):self.c=demo_snapshot()[0]
    def rules(self,address='198.51.100.20',ports=[443],protocol='tcp'):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'rules';p.write_text(json.dumps({'version':1,'rules':[{'address':address,'ports':ports,'protocol':protocol}]}));return Allowlist.load(p)
    def test_exact(self):self.assertTrue(self.rules().known(self.c))
    def test_port_pair(self):self.assertFalse(self.rules(ports=[80]).known(self.c))
    def test_protocol_pair(self):self.assertFalse(self.rules(protocol='udp').known(self.c))
    def test_cidr(self):self.assertTrue(self.rules(address='198.51.100.0/24').known(self.c))
    def test_ipv6(self):self.assertTrue(self.rules(address='2001:db8::/32').known(replace(self.c,remote_address='2001:db8::3')))
    def test_wildcard(self):self.assertTrue(self.rules(ports='*').known(self.c))
    def test_invalid_port(self):
        with self.assertRaises(ValueError):self.rules(ports=[True])
    def test_no_peer(self):self.assertEqual(Detector(Allowlist()).inspect([replace(self.c,remote_address='')],utc()),[])
    def test_suppression_and_expiry(self):
        d=Detector(Allowlist(),cooldown=10);self.assertEqual(len(d.inspect([self.c],utc(),0)),1);self.assertEqual(d.inspect([self.c],utc(),1),[]);self.assertEqual(len(d.inspect([self.c],utc(),10)),1)
    def test_pid_reuse(self):
        d=Detector(Allowlist());d.inspect([self.c],utc(),0);self.assertEqual(len(d.inspect([replace(self.c,process_started=99)],utc(),1)),1)
    def test_burst(self):
        d=Detector(self.rules(),burst_threshold=3);a=d.inspect([replace(self.c,local_port=6000+i) for i in range(3)],utc(),0);self.assertEqual([r['kind'] for r in a],['connection_burst'])
    def test_hidden_pid_not_burst(self):
        d=Detector(self.rules(),burst_threshold=2);self.assertEqual(d.inspect([replace(self.c,pid=None,local_port=6000+i) for i in range(3)],utc(),0),[])
    def test_live_tcp(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen()
            with socket.create_connection(server.getsockname()):
                peer,_=server.accept()
                with peer:
                    cs,_=snapshot();self.assertTrue(any(c.remote_port==server.getsockname()[1] for c in cs))
    def test_live_udp(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1',0));cs,_=snapshot();self.assertTrue(any(c.protocol=='udp' and c.local_port==udp.getsockname()[1] for c in cs))
    def test_process_identity_guard(self):
        self.assertIn('error',process_details(os.getpid(),0))
    def test_optional_interface_failure_does_not_stop_scan(self):
        from app.engine import adapters
        warnings=[]
        with patch('app.engine.psutil.net_if_stats',side_effect=PermissionError('denied')):
            result=adapters(warnings)
        self.assertTrue(warnings);self.assertTrue(all(n['up'] is None for n in result))
    def test_sha256_worker(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file';p.write_bytes(b'ConnWatch');result=[];w=HashWorker(str(p));w.ready.connect(result.append);w.start()
            self.assertTrue(spin(lambda:bool(result)));w.wait();self.assertEqual(result[0],hashlib.sha256(b'ConnWatch').hexdigest())

class GuiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.w=MainWindow(self.temp.name);self.w.show();APP.processEvents();self.errors=[];self.w.error=self.errors.append
    def tearDown(self):
        self.w.stop_monitoring();spin(lambda:self.w.worker is None)
        self.w.close();APP.processEvents();self.temp.cleanup()
    def demo(self):
        self.w.toggle_demo();self.w.start_monitoring();self.assertTrue(spin(lambda:self.w.latest is not None));self.w.timer.stop();self.assertEqual(self.errors,[])
    def test_all_navigation_buttons(self):
        for i,b in enumerate(self.w.nav):QTest.mouseClick(b,Qt.LeftButton);self.assertEqual(self.w.stack.currentIndex(),i)
    def test_start_stop_actual_buttons(self):
        QTest.mouseClick(self.w.demo_button,Qt.LeftButton);QTest.mouseClick(self.w.start_button,Qt.LeftButton)
        self.assertTrue(spin(lambda:self.w.latest is not None));self.assertTrue(self.w.running);QTest.mouseClick(self.w.start_button,Qt.LeftButton);self.assertFalse(self.w.running)
    def test_demo_persists_scan(self):
        self.demo();self.assertEqual(len(self.w.store.scans(self.w.session)),1);self.assertIn('SYNTHETIC DEMO',self.w.banner.text());self.assertEqual(len(self.w.store.alerts(self.w.session)),3)
    def test_demo_rules_isolated(self):
        before=self.w.store.rule_path.read_bytes();self.w.toggle_demo();self.assertEqual(self.w.store.rule_path.name,'demo-allowlist.json');self.w.toggle_demo();self.assertEqual(self.w.store.rule_path.read_bytes(),before)
    def test_search_filter(self):
        self.demo();self.w.connection_search.setText('demo-client');APP.processEvents();self.assertEqual(self.w.connections.proxy.rowCount(),3)
    def test_protocol_filter(self):
        self.demo();self.w.protocol_filter.setCurrentText('UDP');APP.processEvents();self.assertEqual(self.w.connections.proxy.rowCount(),4)
    def test_verdict_filter(self):
        self.demo();self.w.verdict_filter.setCurrentText('LOCAL');APP.processEvents();self.assertEqual(self.w.connections.proxy.rowCount(),2)
    def test_baseline_comparison(self):
        self.demo();self.w.capture_baseline();data=dict(self.w.latest);data['connections']=synthetic(4);data['time']=utc();data['monotonic']+=3;self.w.scan_ready(data);self.assertEqual(self.w.cards[3].value.text(),'1')
    def test_process_inventory(self):
        self.demo();self.assertEqual(len(self.w.process_table.data_model.rows),8)
    def test_rule_change_applies(self):
        self.demo();data=self.w.store.rules();data['rules'].append({'address':'203.0.113.50','ports':[4444],'protocol':'tcp'});self.w.store.save_rules(data);self.w.load_rules();self.assertTrue(self.w.detector.allowlist.known(next(c for c in self.w.latest['connections'] if c.process=='demo-client')))
        with patch('app.window.QFileDialog.getSaveFileName',return_value=(str(self.w.store.directory/'connwatch.db'),'JSON (*.json)')):self.w.export_rules()
        self.assertEqual(len(self.errors),1);self.assertGreater(len(self.w.store.sessions()),0)
    def test_triage_ui(self):
        self.demo();self.w.navigate(2);self.w.alert_table.selectRow(0)
        with patch('app.window.QInputDialog.getMultiLineText',return_value=('Verified locally',True)):self.w.triage('Resolved')
        self.assertEqual(self.w.cards[2].value.text(),'2')
    def test_demo_process_inspection_is_labelled(self):
        self.demo();d=ProcessDialog(self.w,self.w.latest['connections'][0],True)
        self.assertIn('SYNTHETIC DEMO',d.text.toPlainText());self.assertFalse(d.hash.isEnabled());d.close()
    def test_prior_session_baseline(self):
        self.demo();old=self.w.session;self.w.capture_baseline();self.w.stop_monitoring();spin(lambda:self.w.worker is None)
        self.w.start_monitoring();self.assertTrue(spin(lambda:self.w.latest is not None));self.w.timer.stop();self.w.refresh_sessions()
        row=next(i for i,s in enumerate(self.w.session_table.data_model.objects) if s['id']==old)
        proxy=self.w.session_table.proxy.mapFromSource(self.w.session_table.data_model.index(row,0));self.w.session_table.selectRow(proxy.row())
        self.w.use_session_baseline();self.assertIsNotNone(self.w.baseline_set);self.assertEqual(self.w.cards[3].value.text(),'0')
    def test_rapid_stop_switch_no_mixed_modes(self):
        self.w.start_monitoring();self.w.stop_monitoring();self.assertTrue(spin(lambda:self.w.worker is None));self.w.toggle_demo();self.w.start_monitoring();self.assertTrue(spin(lambda:self.w.latest is not None));self.assertTrue(self.w.latest['connections'][0].process.startswith('demo-'))
    def test_settings_persist_and_light(self):
        self.w.interval_spin.setValue(7);self.w.theme_combo.setCurrentText('Light');self.w.save_settings();self.assertEqual(self.w.settings.value('interval',type=int),7);self.assertTrue(self.w.light)
    def test_no_settings_change_while_recording(self):
        self.demo();self.w.save_settings();self.assertIn('Stop monitoring',self.errors[-1])
    def test_invalid_rule_dialog(self):
        d=RuleDialog(self.w);d.address.setText('bad address');d.ports.setText('443');d.validate();self.assertNotEqual(d.error.text(),'');d.reject()
    def test_valid_rule_dialog(self):
        d=RuleDialog(self.w);d.address.setText('192.0.2.0/24');d.ports.setText('443, 8443');d.validate();self.assertEqual(d.result(),QDialog.Accepted);self.assertEqual(d.rule['ports'],[443,8443])
    def test_pdf_export(self):
        self.demo();p=Path(self.temp.name)/'session.pdf'
        with patch('app.window.QFileDialog.getSaveFileName',return_value=(str(p),'PDF report (*.pdf)')),patch('app.window.QMessageBox.information'):
            self.w.export_dialog()
        self.assertTrue(p.read_bytes().startswith(b'%PDF'));self.assertEqual(self.errors,[])
    def test_export_html_gui(self):
        self.demo();p=Path(self.temp.name)/'session.html'
        with patch('app.window.QFileDialog.getSaveFileName',return_value=(str(p),'HTML report (*.html)')),patch('app.window.QMessageBox.information'):self.w.export_dialog()
        self.assertIn('SYNTHETIC DEMO',p.read_text())
    def test_live_background_collection(self):
        self.w.start_monitoring();self.assertTrue(spin(lambda:self.w.latest is not None));self.assertEqual(self.w.store.sessions()[0]['mode'],'LIVE');self.assertEqual(self.errors,[])

if __name__=='__main__':unittest.main(verbosity=2)
