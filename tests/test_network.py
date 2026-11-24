import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from dataclasses import asdict
from datetime import datetime,timezone,timedelta
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ipaddress,json,socket,sys,tempfile,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from PySide6.QtWidgets import QApplication,QDialog
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from app.discovery import (ScanOptions,DiscoveryWorker,RateLimit,VendorDB,detect_profiles,normalize_mac,
    parse_ports,validate_scope,probe_host,tcp_probe,ping_once,web_metadata,reverse_name,utc)
from app.inventory import InventoryStore,compare_records,export_data,network_report,export_network,exposures
from app.network_window import NetworkWindow,DeviceNotes,DeviceDialog

APP=QApplication.instance() or QApplication([])

def spin(fn,timeout=5):
    stop=time.monotonic()+timeout
    while time.monotonic()<stop:
        APP.processEvents()
        if fn():return True
        time.sleep(.01)
    return False

def record(ip='192.168.50.1',presence='Responding',ports=None,mac='00:11:22:33:44:55'):
    return {'ip':ip,'time':utc(),'presence':presence,'hostname':'test-host','mac':mac,'vendor':'Test fixture vendor',
            'role':'Unclassified','ports':ports or {'80':{'state':'Open','service_hint':'HTTP'}},'evidence':['Unit-test fixture'],
            'requested_ports':[80,443],'checked_ports':[80],'duration_ms':3,'web':[]}

def fake_probe(ip,opts,cancel,limiter,cache,vendors):
    if cancel.is_set():return None
    return record(ip,presence='Responding' if ip.endswith('.1') else 'No response')

class ScopeTests(unittest.TestCase):
    def test_private_192(self):self.assertEqual(str(validate_scope('192.168.50.12/24')),'192.168.50.0/24')
    def test_private_10(self):self.assertEqual(validate_scope('10.0.0.0/30').num_addresses,4)
    def test_private_172(self):self.assertEqual(validate_scope('172.16.0.0/24').prefixlen,24)
    def test_public_rejected(self):
        for scope in ['8.8.8.0/24','172.32.0.0/24','198.51.100.0/24','127.0.0.1/32']:
            with self.assertRaises(ValueError):validate_scope(scope)
    def test_ipv6_rejected(self):
        with self.assertRaises(ValueError):validate_scope('fd00::/120')
    def test_large_rejected(self):
        with self.assertRaises(ValueError):validate_scope('10.0.0.0/8')
    def test_maximum_scope(self):self.assertEqual(validate_scope('192.168.0.0/20').num_addresses,4096)
    def test_single_host(self):self.assertEqual(list(validate_scope('192.168.1.2/32').hosts()),[ipaddress.ip_address('192.168.1.2')])
    def test_port_ranges(self):self.assertEqual(parse_ports('80,443,8000-8002,80'),[80,443,8000,8001,8002])
    def test_port_limit(self):
        with self.assertRaises(ValueError):parse_ports('1-65535')
    def test_bad_port(self):
        for text in ['0','65536','abc','']:
            with self.assertRaises(ValueError):parse_ports(text)
    def test_scope_adapter_boundary(self):
        with self.assertRaises(ValueError):ScanOptions('192.168.2.0/24',profile={'scope':'192.168.1.0/24'}).validate()
    def test_nan_timeout(self):
        with self.assertRaises(ValueError):ScanOptions('192.168.1.0/24',timeout=float('nan')).validate()
    def test_invalid_workers(self):
        with self.assertRaises(ValueError):ScanOptions('192.168.1.0/24',workers=500).validate()
    def test_rate_limit_cancel(self):
        cancel=threading.Event();cancel.set();self.assertFalse(RateLimit().acquire(cancel))
    def test_real_netmask_detection(self):
        addresses={'Ethernet':[SimpleNamespace(family=socket.AF_INET,address='192.168.50.12',netmask='255.255.254.0'),SimpleNamespace(family=999,address='00:11:22:33:44:55')]}
        with patch('app.discovery.psutil.net_if_addrs',return_value=addresses),patch('app.discovery.psutil.net_if_stats',return_value={'Ethernet':SimpleNamespace(isup=True)}),patch('app.discovery.routes',return_value=[{'source':'192.168.50.12','gateway':'192.168.50.1','metric':1}]):
            profiles,_=detect_profiles()
        self.assertEqual(profiles[0]['scope'],'192.168.50.0/23');self.assertEqual(profiles[0]['gateway'],'192.168.50.1')
    def test_down_adapter_excluded(self):
        a={'Ethernet':[SimpleNamespace(family=socket.AF_INET,address='192.168.1.2',netmask='255.255.255.0')]}
        with patch('app.discovery.psutil.net_if_addrs',return_value=a),patch('app.discovery.psutil.net_if_stats',return_value={'Ethernet':SimpleNamespace(isup=False)}):self.assertEqual(detect_profiles()[0],[])
    def test_missing_addresses_warning(self):
        with patch('app.discovery.psutil.net_if_addrs',side_effect=PermissionError('denied')):
            p,w=detect_profiles()
        self.assertEqual(p,[]);self.assertTrue(w)
    def test_mac_normalization(self):self.assertEqual(normalize_mac('00-11-22-33-44-55'),'00:11:22:33:44:55')
    def test_invalid_mac(self):
        for text in ['00:00:00:00:00:00','ff:ff:ff:ff:ff:ff','01:11:22:33:44:55','bad']:self.assertEqual(normalize_mac(text),'')
    def test_random_mac_vendor(self):self.assertEqual(VendorDB().lookup('02:11:22:33:44:55'),'Private / randomized MAC')
    def test_longest_vendor_prefix(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'vendors';p.write_text(json.dumps({'001122':'Broad','0011223':'Specific','001122334':'Most specific'}))
            self.assertEqual(VendorDB(p).lookup('00:11:22:33:44:55'),'Most specific')

class ProbeTests(unittest.TestCase):
    def setUp(self):
        arp = patch("app.discovery.windows_arp", return_value="")
        arp.start()
        self.addCleanup(arp.stop)

    def test_windows_unreachable_not_echo(self):
        with patch('app.discovery.shutil.which',return_value='ping'),patch('app.discovery.command',return_value=(0,'Reply from 192.168.1.1: Destination host unreachable.','')):
            self.assertFalse(ping_once('192.168.1.2')[0])
    def test_echo_with_ttl(self):
        with patch('app.discovery.shutil.which',return_value='ping'),patch('app.discovery.command',return_value=(0,'64 bytes time=1.2 ms TTL=64','')):
            self.assertEqual(ping_once('192.168.1.2')[:2],(True,1.2))
    def test_ping_missing(self):
        with patch('app.discovery.shutil.which',return_value=None):self.assertFalse(ping_once('192.168.1.2')[0])
    def test_real_tcp_open(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen();self.assertEqual(tcp_probe('127.0.0.1',server.getsockname()[1],.2)[0],'Open')
    def test_real_tcp_refused(self):
        with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
        self.assertEqual(tcp_probe('127.0.0.1',port,.2)[0],'Refused')
    def test_cached_is_not_live(self):
        opts=ScanOptions('192.168.50.0/30',ports=[80],resolve=False,metadata=False)
        with patch('app.discovery.ping_once',return_value=(False,None,'No reply')),patch('app.discovery.tcp_probe',return_value=('No response',None)):
            r=probe_host('192.168.50.1',opts,threading.Event(),RateLimit(200),{'192.168.50.1':'00:11:22:33:44:55'})
        self.assertEqual(r['presence'],'Neighbor observed')
    def test_no_response_full_record(self):
        opts=ScanOptions('192.168.50.0/30',ports=[80,443,22],resolve=False,metadata=False)
        with patch('app.discovery.ping_once',return_value=(False,None,'No reply')),patch('app.discovery.tcp_probe',return_value=('No response',None)):
            r=probe_host('192.168.50.1',opts,threading.Event(),RateLimit(200))
        self.assertEqual(r['presence'],'No response');self.assertFalse(r['complete_port_profile']);self.assertIn(22,r['requested_ports']);self.assertNotIn(22,r['checked_ports'])
    def test_refused_establishes_response(self):
        opts=ScanOptions('192.168.50.0/30',ports=[80],resolve=False,metadata=False)
        with patch('app.discovery.ping_once',return_value=(False,None,'')),patch('app.discovery.tcp_probe',return_value=('Refused',.8)):
            r=probe_host('192.168.50.1',opts,threading.Event(),RateLimit(200))
        self.assertEqual(r['presence'],'Responding');self.assertEqual(r['ports']['80']['state'],'Refused')
    def test_cancel_no_probe(self):
        cancel=threading.Event();cancel.set()
        with patch('app.discovery.ping_once') as ping:self.assertIsNone(probe_host('192.168.50.1',ScanOptions('192.168.50.0/30'),cancel,RateLimit()));ping.assert_not_called()
    def test_reverse_timeout(self):
        with patch('app.discovery.command',return_value=(-1,'','timeout')):self.assertEqual(reverse_name('192.168.50.1'),'')
    def test_http_head_on_owned_loopback(self):
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):self.send_response(200);self.send_header('Content-Type','text/plain');self.end_headers()
            def log_message(self,*a):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:self.assertEqual(web_metadata('127.0.0.1',server.server_port)['status'],200)
        finally:server.shutdown();server.server_close();thread.join()
    def test_worker_records_each_target(self):
        worker=DiscoveryWorker(ScanOptions('192.168.50.0/30',ports=[80],resolve=False,metadata=False),probe=fake_probe);batches=[];done=[];worker.batch.connect(lambda b:batches.extend(b));worker.complete.connect(done.append);worker.start()
        self.assertTrue(spin(lambda:bool(done)));worker.wait();self.assertEqual(len(batches),2);self.assertEqual(done[0]['status'],'Completed')
    def test_worker_cancellation(self):
        def slow(ip,opts,cancel,*args):cancel.wait(.1);return None if cancel.is_set() else record(ip)
        worker=DiscoveryWorker(ScanOptions('192.168.50.0/24',workers=2),probe=slow);done=[];worker.complete.connect(done.append);worker.start();time.sleep(.03);worker.stop();self.assertTrue(spin(lambda:bool(done)));worker.wait();self.assertEqual(done[0]['status'],'Cancelled');self.assertLess(done[0]['completed'],254)
    def test_worker_real_loopback(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen()
            opts=ScanOptions('127.0.0.1/32',ports=[server.getsockname()[1]],resolve=False,metadata=False)
            worker=DiscoveryWorker(opts,allow_loopback=True);done=[];rows=[];worker.batch.connect(lambda b:rows.extend(b));worker.complete.connect(done.append);worker.start();self.assertTrue(spin(lambda:bool(done)));worker.wait();self.assertEqual(rows[0]['presence'],'Responding')

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=InventoryStore(self.temp.name);self.addCleanup(self.temp.cleanup);self.addCleanup(self.store.close)
        self.opts=asdict(ScanOptions('192.168.50.0/30',ports=[80],resolve=False,metadata=False));self.sid=self.store.begin(self.opts,2)
    def finish(self,status='Completed'):return self.store.finish(self.sid,{'status':status,'ended':utc(),'duration_seconds':1,'neighbors':{}})
    def test_no_response_retained(self):self.store.record(self.sid,[record(),record('192.168.50.2','No response')]);self.finish();self.assertEqual(len(self.store.records(self.sid)),2);self.assertEqual(len(self.store.devices()),1)
    def test_batch_rollback(self):
        with self.assertRaises(ValueError):self.store.record(self.sid,[record(),{'time':utc()}])
        self.assertEqual(self.store.records(self.sid),[])
    def test_first_seen_preserved(self):
        self.store.record(self.sid,[record()]);first=self.store.devices()[0]['first_seen'];self.store.record(self.sid,[record()]);self.assertEqual(self.store.devices()[0]['first_seen'],first)
    def test_annotations_preserved_on_rescan(self):
        self.store.record(self.sid,[record()]);self.store.annotate(self.opts['scope'],'192.168.50.1','Router','Home','Expected','Verified');self.store.record(self.sid,[record()]);self.assertEqual(self.store.devices()[0]['label'],'Router')
    def test_neighbor_enrichment_is_not_echo(self):
        self.store.record(self.sid,[record(presence='No response',mac='')]);s=self.store.finish(self.sid,{'status':'Completed','neighbors':{'192.168.50.1':'00:11:22:33:44:55'}});self.assertEqual(s['responding'],0);self.assertEqual(s['observed'],1)
    def test_new_and_not_observed(self):
        change=compare_records([record()],[record('192.168.50.2')]);self.assertEqual({r['kind'] for r in change},{'New address observed','Not observed this scan'})
    def test_mac_changed(self):self.assertEqual(compare_records([record()],[record(mac='00:22:33:44:55:66')])[0]['kind'],'MAC identity changed')
    def test_port_profile_not_false_closed(self):self.assertEqual(compare_records([record(ports={'80':{'state':'Open'}})],[record(ports={'443':{'state':'Open'}})]),[])
    def test_port_change(self):self.assertEqual(compare_records([record()],[record(ports={'80':{'state':'Refused'}})])[0]['kind'],'TCP service state changed')
    def test_cancelled_scan_not_change_baseline(self):
        self.store.record(self.sid,[record()]);self.finish();sid=self.store.begin(self.opts,2);self.store.finish(sid,{'status':'Cancelled'});self.assertEqual(self.store.changes(sid),[])
    def test_completed_scan_compared(self):
        self.store.record(self.sid,[record()]);self.finish();sid=self.store.begin(self.opts,2);self.store.record(sid,[record('192.168.50.2')]);self.store.finish(sid,{'status':'Completed'});self.assertEqual(len(self.store.changes(sid)),2)
    def test_annotation_journal_keeps_old_notes(self):
        self.store.record(self.sid,[record()]);self.store.annotate(self.opts['scope'],'192.168.50.1','A','Home','Expected','First');self.store.annotate(self.opts['scope'],'192.168.50.1','B','Home','Investigate','Second');self.assertEqual([r['notes'] for r in self.store.note_history(self.opts['scope'],'192.168.50.1')],['Second','First'])
    def test_probe_error_not_disappearance(self):
        self.assertEqual(compare_records([record()],[record(presence='Probe error')]),[])
    def test_same_timestamp_scans_still_compare(self):
        self.store.record(self.sid,[record()]);self.finish();sid=self.store.begin(self.opts,2)
        stamp=self.store.get_scan(self.sid)['started']
        with self.store.db:self.store.db.execute('UPDATE network_scans SET started=? WHERE id=?',(stamp,sid))
        self.store.record(sid,[record('192.168.50.2')]);self.store.finish(sid,{'status':'Completed'});self.assertEqual(len(self.store.changes(sid)),2);self.assertEqual(self.store.scans()[0]['id'],sid)
    def test_json_includes_all_attempts(self):
        self.store.record(self.sid,[record(),record('192.168.50.2','No response')]);path=Path(self.temp.name)/'export.json';export_network(self.store,self.sid,path,'json');self.assertEqual(len(json.loads(path.read_text())['observations']),2)
    def test_report_escape(self):
        d=record();d['hostname']='<script>bad</script>';self.store.record(self.sid,[d]);report=network_report(export_data(self.store,self.sid));self.assertIn('&lt;script&gt;',report);self.assertNotIn('<script>',report)
    def test_csv_formula(self):
        d=record();d['hostname']='=2+2';self.store.record(self.sid,[d]);p=Path(self.temp.name)/'export.csv';export_network(self.store,self.sid,p,'csv');self.assertIn("'=2+2",p.read_text(encoding='utf-8-sig'))
    def test_database_export_blocked(self):
        with self.assertRaises(ValueError):export_network(self.store,self.sid,Path(self.temp.name)/'network.db','json')
    def test_service_hints_are_review_notes(self):
        d=record(ports={'23':{'state':'Open'},'3389':{'state':'Open'}});r=exposures(d);self.assertEqual(len(r),2);self.assertTrue(all('malware' not in x.lower() for x in r))
    def test_count_retention_keeps_newest(self):
        self.finish()
        for i in range(3):
            sid=self.store.begin(self.opts,2);self.store.finish(sid,{'status':'Completed'})
        self.store.purge(90,max_scans=2);self.assertEqual(len(self.store.scans()),2)
    def test_retention_keeps_annotations(self):
        self.store.record(self.sid,[record()]);self.finish();old=(datetime.now(timezone.utc)-timedelta(days=200)).isoformat()
        with self.store.db:self.store.db.execute('UPDATE network_scans SET started=? WHERE id=?',(old,self.sid))
        self.store.purge(90);self.assertEqual(self.store.scans(),[]);self.assertEqual(len(self.store.devices()),1)

class GuiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.w=NetworkWindow(self.temp.name,auto_detect=False);self.w.motion=False;self.errors=[];self.w.error=self.errors.append;self.w.show();APP.processEvents()
        self.w.profiles_ready([{'name':'Test adapter','ip':'192.168.50.2','scope':'192.168.50.0/30','mask':'255.255.255.252','gateway':'192.168.50.1','mac':'00:11:22:33:44:55','default':True}],[])
    def tearDown(self):
        if self.w.worker:self.w.stop_scan();spin(lambda:self.w.worker is None)
        self.w.close();APP.processEvents();self.temp.cleanup()
    def run_scan(self):
        with patch('app.network_window.DiscoveryWorker',side_effect=lambda opts,parent:DiscoveryWorker(opts,parent,probe=fake_probe)):
            self.w.start_scan();self.assertTrue(spin(lambda:self.w.worker is None))
        self.assertEqual(self.errors,[])
    def test_detected_adapter_scope(self):self.assertEqual(self.w.scope_edit.text(),'192.168.50.0/30');self.assertIn('192.168.50.2',self.w.scope_hint.text())
    def test_no_demo_control(self):self.assertFalse(any('demo' in b.text().lower() for b in self.w.findChildren(__import__('PySide6.QtWidgets',fromlist=['QPushButton']).QPushButton)))
    def test_navigation(self):
        for i,b in enumerate(self.w.nav):QTest.mouseClick(b,Qt.LeftButton);self.assertEqual(self.w.stack.currentIndex(),i)
    def test_live_scan_workflow(self):self.run_scan();self.assertEqual(self.w.store.get_scan(self.w.active_scan)['status'],'Completed');self.assertEqual(self.w.store.get_scan(self.w.active_scan)['summary']['recorded'],2)
    def test_device_filter_search(self):
        self.run_scan();self.w.device_search.setText('192.168.50.1');self.assertEqual(self.w.device_table.proxy.rowCount(),1);self.w.device_table.selectRow(0)
        self.w.store.annotate(self.w.active_scope,'192.168.50.1','Gateway','Home','Expected','Reviewed');self.w.refresh_inventory()
        self.assertEqual(self.w.device_table.selected()['label'],'Gateway')
    def test_presence_filter(self):self.run_scan();self.w.presence_filter.setCurrentText('Neighbor observed');self.assertEqual(self.w.device_table.proxy.rowCount(),0)
    def test_invalid_scope_not_started(self):self.w.scope_edit.setText('8.8.8.0/24');self.w.start_scan();self.assertFalse(self.w.running);self.assertTrue(self.errors)
    def test_settings_saved(self):self.w.rate_spin.setValue(40);self.w.motion_check.setChecked(False);self.w.save_settings();self.assertEqual(self.w.settings.value('rate',type=int),40);self.assertFalse(self.w.motion)
    def test_device_notes_dialog(self):
        self.run_scan();a=self.w.store.devices()[0];d=DeviceNotes(self.w,a);d.name.setText('Gateway');d.accept();self.assertEqual(d.name.text(),'Gateway')
    def test_device_evidence_dialog(self):self.run_scan();d=DeviceDialog(self.w,self.w.store.devices()[0],self.w.store);self.assertIn('192.168.50.1',d.windowTitle());d.close()
    def test_pdf_export(self):
        self.run_scan();p=Path(self.temp.name)/'assessment.pdf'
        with patch('app.network_window.QFileDialog.getSaveFileName',return_value=(str(p),'PDF (*.pdf)')):self.w.export_dialog()
        self.assertTrue(p.read_bytes().startswith(b'%PDF'));self.assertEqual(self.errors,[])
    def test_json_export_gui(self):
        self.run_scan();p=Path(self.temp.name)/'assessment.json'
        with patch('app.network_window.QFileDialog.getSaveFileName',return_value=(str(p),'JSON (*.json)')):self.w.export_dialog()
        self.assertEqual(len(json.loads(p.read_text())['observations']),2)
    def test_repeat_scheduling(self):self.w.schedule_check.setChecked(True);self.run_scan();self.assertTrue(self.w.repeat_timer.isActive());self.w.repeat_timer.stop()
    def test_map_click_filters(self):self.w.select_ip('192.168.50.1');self.assertEqual(self.w.stack.currentIndex(),1);self.assertEqual(self.w.device_search.text(),'192.168.50.1')
    def test_workstation_can_close_and_reopen(self):
        self.w.open_host();first=self.w.host_window;first.close();APP.processEvents();self.assertIsNone(self.w.host_window)
        self.w.open_host();self.assertIsNot(self.w.host_window,first);self.assertTrue(self.w.host_window.isVisible());self.w.host_window.close();APP.processEvents()
    def test_animations_complete(self):
        self.w.motion=True
        for i in range(5):self.w.navigate(i);QTest.qWait(200)
        self.assertTrue(spin(lambda:len(self.w.animations)==0,1))

if __name__=='__main__':unittest.main(verbosity=2)
