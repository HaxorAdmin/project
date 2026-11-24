"""Optional workstation evidence tool inside the network product."""
from PySide6.QtWidgets import QLabel
from PySide6.QtCore import Signal
from .window import MainWindow
from .widgets import label

class WorkstationWindow(MainWindow):
    closed=Signal()
    def closeEvent(self,event):
        super().closeEvent(event)
        if event.isAccepted():self.closed.emit()
    def build(self):
        super().build();self.demo_button.hide();self.banner.setText('Start capture to inspect workstation processes and socket ownership.')
        self.mode_label.setText('WORKSTATION INSPECTOR')
        for widget in self.findChildren(QLabel):
            if 'LOCAL-FIRST' in widget.text():widget.setText('VERSION 3.0.0')
    def toggle_demo(self):return
    def about_page(self,v):
        v.addWidget(label('Workstation evidence','title'));v.addWidget(label('Developed by ZakirUllah • ConnWatch Network 3.0.0','muted'))
        v.addWidget(label('Inspect socket ownership, reviewed endpoint rules, executable information and SHA-256 file hashes. Save host-session evidence separately from subnet-discovery assessments.'))
        v.addWidget(label('Capture is limited to this workstation’s visible socket/process table. Use the main Network workspace for subnet discovery and device history.','muted'));v.addStretch()
