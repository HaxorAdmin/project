"""Network application entry point with early startup diagnostics and safe single-instance focus."""
import argparse
import faulthandler
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import traceback

TITLE='ConnWatch Network | Developed by ZakirUllah'

def focus_existing():
    if os.name!='nt':return False
    try:
        import ctypes
        user=ctypes.WinDLL('user32',use_last_error=True)
        user.FindWindowW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p];user.FindWindowW.restype=ctypes.c_void_p
        user.ShowWindow.argtypes=[ctypes.c_void_p,ctypes.c_int];user.SetForegroundWindow.argtypes=[ctypes.c_void_p]
        window=user.FindWindowW(None,TITLE)
        if window:user.ShowWindow(window,9);user.SetForegroundWindow(window);return True
    except OSError:pass
    return False

def fallback_message(text):
    if os.name=='nt':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0,str(text),'ConnWatch startup error',0x10)
        except Exception:pass
    elif sys.stderr:print(text,file=sys.stderr)

def main():
    parser=argparse.ArgumentParser(description=TITLE)
    parser.add_argument('--data-dir',help='Optional separate workspace directory')
    parser.add_argument('--self-check',action='store_true',help='Check imports, database and native GUI creation without sending scan probes')
    args=parser.parse_args()
    if args.data_dir:directory=Path(os.path.expandvars(args.data_dir)).expanduser()
    elif os.name=='nt':directory=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'AppData/Local')))/'ZakirUllah/ConnWatchDesktop'
    else:directory=Path(os.environ.get('XDG_DATA_HOME',str(Path.home()/'.local/share')))/'ZakirUllah/ConnWatchDesktop'
    directory.mkdir(parents=True,exist_ok=True)
    handler=RotatingFileHandler(directory/'connwatch.log',maxBytes=2*1024*1024,backupCount=2,encoding='utf-8')
    logging.basicConfig(handlers=[handler],level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s',force=True)
    fault=(directory/'startup-trace.log').open('a',encoding='utf-8',buffering=1)
    faulthandler.enable(fault);faulthandler.dump_traceback_later(20,file=fault)
    lock=None
    try:
        logging.info('Startup stage: importing Qt')
        from PySide6.QtWidgets import QApplication,QMessageBox
        from PySide6.QtCore import QLockFile,QTimer
        app=QApplication(sys.argv[:1]);app.setApplicationName('ConnWatchDesktop');app.setOrganizationName('ZakirUllah');app.setStyle('Fusion')
        lock=QLockFile(str(directory/'workspace.lock'));lock.setStaleLockTime(30000)
        if not lock.tryLock(100):
            faulthandler.cancel_dump_traceback_later()
            if focus_existing():logging.info('Focused an existing network window');return 0
            info=lock.getLockInfo();logging.warning('Workspace already owned: %s',info)
            QMessageBox.information(None,'ConnWatch workspace is already open','Another process owns this workspace. Switch to its window, or close that ConnWatch instance before reopening.\n\nWorkspace:\n'+str(directory)+'\n\nLock owner information: '+str(info));return 1
        def hook(kind,value,trace):
            logging.error('Desktop callback error',exc_info=(kind,value,trace))
            QMessageBox.critical(None,'ConnWatch error',str(value)+'\n\nDiagnostic log:\n'+str(directory/'connwatch.log'))
        sys.excepthook=hook
        logging.info('Startup stage: importing network workspace')
        from app.network_window import NetworkWindow
        logging.info('Startup stage: constructing network database and window')
        window=NetworkWindow(directory,auto_detect=not args.self_check)
        if args.self_check:
            window.motion=False;window.show();app.processEvents();window.close();app.processEvents();faulthandler.cancel_dump_traceback_later()
            if sys.stdout:print(json.dumps({'status':'passed','version':'3.0.0','imports':'ok','database':'ok','native_window':'ok','scan_probes_sent':0}))
            return 0
        window.show();window.raise_();window.activateWindow()
        logging.info('Startup stage: window shown; event loop ready')
        QTimer.singleShot(0,faulthandler.cancel_dump_traceback_later)
        return app.exec()
    except Exception:
        logging.exception('Startup failed');fallback_message('ConnWatch could not finish starting.\n\n'+traceback.format_exc()[-1800:]+'\n\nLog: '+str(directory/'connwatch.log'));return 2
    finally:
        faulthandler.cancel_dump_traceback_later()
        if lock:lock.unlock()
        faulthandler.disable();fault.close()

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        fallback_message(traceback.format_exc()[-2000:]);raise
