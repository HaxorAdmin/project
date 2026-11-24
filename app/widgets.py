"""Reusable native Qt widgets and ConnWatch's local visual theme."""
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QRectF, QPointF
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen, QFont, QLinearGradient, QIcon, QPixmap
from PySide6.QtWidgets import QWidget, QFrame, QVBoxLayout, QHBoxLayout, QLabel, QTableView, QHeaderView, QAbstractItemView

TEAL='#39ddbc';MUTED='#8da3bb'

def icon(kind='signal',color=TEAL):
    image=QPixmap(28,28);image.fill(Qt.transparent)
    p=QPainter(image);p.setRenderHint(QPainter.Antialiasing);p.setPen(QPen(QColor(color),1.8))
    if kind=='signal':
        path=QPainterPath(QPointF(3,16))
        for x,y in [(8,16),(11,7),(16,23),(20,12),(25,12)]:path.lineTo(x,y)
        p.drawPath(path)
    elif kind=='shield':
        path=QPainterPath(QPointF(14,3))
        for x,y in [(24,7),(22,18),(14,25),(6,18),(4,7),(14,3)]:path.lineTo(x,y)
        p.drawPath(path)
    elif kind=='grid':
        for x,y in [(4,4),(16,4),(4,16),(16,16)]:p.drawRoundedRect(x,y,8,8,2,2)
    elif kind=='gear':
        p.drawEllipse(6,6,16,16);p.drawEllipse(11,11,6,6)
    else:
        p.drawRoundedRect(4,4,20,20,4,4)
        for y in [10,15,20]:p.drawLine(9,y,20,y)
    p.end();return QIcon(image)

def label(text,object_name=None):
    l=QLabel(str(text));l.setTextFormat(Qt.PlainText)
    if object_name:l.setObjectName(object_name)
    l.setWordWrap(True)
    return l

def button(text,callback=None,kind='secondary'):
    from PySide6.QtWidgets import QPushButton
    b=QPushButton(text);b.setProperty('kind',kind);b.setCursor(Qt.PointingHandCursor)
    if callback:b.clicked.connect(lambda checked=False:callback())
    return b

class Card(QFrame):
    def __init__(self,title,value='0',caption=''):
        super().__init__();self.setObjectName('card');layout=QVBoxLayout(self);layout.setContentsMargins(20,17,20,17);layout.setSpacing(7)
        self.title=label(title,'cardTitle');self.value=label(value,'metric');self.caption=label(caption,'muted')
        layout.addWidget(self.title);layout.addWidget(self.value);layout.addWidget(self.caption)
    def update(self,value,caption=None):
        self.value.setText(str(value))
        if caption is not None:self.caption.setText(caption)

class GridModel(QAbstractTableModel):
    def __init__(self,headers,parent=None):super().__init__(parent);self.headers=headers;self.rows=[];self.objects=[]
    def rowCount(self,parent=QModelIndex()):return 0 if parent.isValid() else len(self.rows)
    def columnCount(self,parent=QModelIndex()):return 0 if parent.isValid() else len(self.headers)
    def data(self,index,role=Qt.DisplayRole):
        if not index.isValid():return None
        value=self.rows[index.row()][index.column()]
        if role in (Qt.DisplayRole,Qt.ToolTipRole):return str(value) if value is not None else 'Unavailable'
        if role==Qt.ForegroundRole:
            if str(value) in ('REVIEW','Open','New endpoint','unapproved_endpoint','connection_burst','Neighbor observed','Investigate','Probe error'):return QColor('#efb56f')
            if str(value) in ('KNOWN','Resolved','Up','Accepted','In baseline','Responding','Expected','Completed'):return QColor('#32b99d')
        if role==Qt.UserRole:return value
        return None
    def headerData(self,section,orientation,role=Qt.DisplayRole):
        if role==Qt.DisplayRole and orientation==Qt.Horizontal:return self.headers[section]
    def replace(self,rows,objects=None):
        self.beginResetModel();self.rows=rows;self.objects=objects or [];self.endResetModel()

class SearchProxy(QSortFilterProxyModel):
    def __init__(self,parent=None):super().__init__(parent);self.term='';self.protocol='All protocols';self.verdict='All verdicts'
    def set_term(self,value):self.term=value.casefold().strip();self.invalidateFilter()
    def filterAcceptsRow(self,row,parent):
        model=self.sourceModel();values=model.rows[row]
        if self.term and self.term not in ' '.join(str(v) for v in values).casefold():return False
        if self.protocol!='All protocols' and self.protocol.casefold() not in [str(v).casefold() for v in values]:return False
        if self.verdict!='All verdicts' and self.verdict not in [str(v) for v in values]:return False
        return True
    def lessThan(self,left,right):
        a=left.data(Qt.UserRole);b=right.data(Qt.UserRole)
        if type(a) in (int,float) and type(b) in (int,float):return a<b
        if isinstance(a,str) and isinstance(b,str):
            try:
                import ipaddress
                left_ip=ipaddress.ip_address(a);right_ip=ipaddress.ip_address(b)
                if left_ip.version==right_ip.version:return int(left_ip)<int(right_ip)
            except ValueError:pass
        return str(a).casefold()<str(b).casefold()

class Table(QTableView):
    def __init__(self,headers,search=True):
        super().__init__();self.data_model=GridModel(headers,self);self.proxy=SearchProxy(self);self.proxy.setSourceModel(self.data_model);self.setModel(self.proxy)
        self.setSortingEnabled(True);self.setSelectionBehavior(QAbstractItemView.SelectRows);self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers);self.setAlternatingRowColors(True);self.setShowGrid(False)
        self.verticalHeader().hide();self.verticalHeader().setDefaultSectionSize(39)
        self.horizontalHeader().setMinimumSectionSize(65);self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.setMinimumHeight(145)
    def fill(self,rows,objects=None):
        previous=self.selected()
        self.data_model.replace(rows,objects)
        selected_index=None
        if previous is not None and objects:
            if previous in objects:selected_index=objects.index(previous)
            elif isinstance(previous,dict):
                def identity(item):
                    if not isinstance(item,dict):return None
                    if 'scope' in item and 'ip' in item:return ('address',item['scope'],item['ip'])
                    if 'id' in item:return ('id',item['id'])
                    return None
                key=identity(previous)
                if key is not None:selected_index=next((i for i,item in enumerate(objects) if identity(item)==key),None)
        if selected_index is not None:
            source=self.data_model.index(selected_index,0)
            self.selectRow(self.proxy.mapFromSource(source).row())
        # Widths remain user-resizable; do not reset scroll position on every refresh.
        if not getattr(self,'sized',False):
            self.resizeColumnsToContents()
            for i in range(len(self.data_model.headers)):self.setColumnWidth(i,min(260,max(95,self.columnWidth(i)+15)))
            self.sized=True
    def selected(self):
        indexes=self.selectionModel().selectedRows()
        if not indexes:return None
        row=self.proxy.mapToSource(indexes[0]).row()
        return self.data_model.objects[row] if row<len(self.data_model.objects) else None

class SparkChart(QWidget):
    def __init__(self,title,subtitle,series=('Connections',),colors=(TEAL,)):
        super().__init__();self.title=title;self.subtitle=subtitle;self.series=series;self.colors=colors;self.points=[];self.setMinimumHeight(210)
    def set_points(self,points):self.points=points;self.update()
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.Antialiasing)
        light=self.property('light') or False;bg='#ffffff' if light else '#101f31';fg='#182e44' if light else '#e4edf8';muted='#6b829b' if light else MUTED
        p.setBrush(QColor(bg));p.setPen(Qt.NoPen);p.drawRoundedRect(self.rect(),12,12)
        p.setPen(QColor(fg));p.setFont(QFont('Segoe UI',11,QFont.DemiBold));p.drawText(20,30,self.title)
        p.setPen(QColor(muted));p.setFont(QFont('Segoe UI',9));p.drawText(20,51,self.subtitle)
        plot=QRectF(45,78,self.width()-68,self.height()-116)
        maximum=max([v for point in self.points for v in point] or [1]);maximum=max(1,maximum*1.15)
        for i in range(4):
            y=plot.top()+plot.height()*i/3;p.setPen(QPen(QColor('#dce6ef' if light else '#23374e'),1));p.drawLine(QPointF(plot.left(),y),QPointF(plot.right(),y))
            p.setPen(QColor(muted));p.drawText(7,int(y+4),str(round(maximum*(1-i/3))))
        if not self.points:
            p.setPen(QColor(muted));p.drawText(plot,Qt.AlignCenter,'Start monitoring to collect a timeline')
        for j,color in enumerate(self.colors):
            if len(self.points)<2:continue
            path=QPainterPath()
            for i,point in enumerate(self.points):
                pt=QPointF(plot.left()+i*plot.width()/(len(self.points)-1),plot.bottom()-point[j]/maximum*plot.height())
                if i==0:path.moveTo(pt)
                else:path.lineTo(pt)
            fill=QPainterPath(path);fill.lineTo(plot.right(),plot.bottom());fill.lineTo(plot.left(),plot.bottom());fill.closeSubpath()
            gradient=QLinearGradient(0,plot.top(),0,plot.bottom());top=QColor(color);top.setAlpha(50);bottom=QColor(color);bottom.setAlpha(0)
            gradient.setColorAt(0,top);gradient.setColorAt(1,bottom);p.fillPath(fill,gradient);p.setPen(QPen(QColor(color),2.4));p.drawPath(path)
        p.setFont(QFont('Segoe UI',9))
        x=20
        for name,color in zip(self.series,self.colors):p.setPen(QColor(color));p.drawText(x,self.height()-15,name);x+=150
        p.end()

def stylesheet(light=False):
    from pathlib import Path
    up=(Path(__file__).resolve().parents[1]/'assets/chevron-up.png').as_posix();down=(Path(__file__).resolve().parents[1]/'assets/chevron-down.png').as_posix()
    bg='#f1f5f9' if light else '#091422';panel='#ffffff' if light else '#101f31';border='#dbe4ee' if light else '#22364d';fg='#182d43' if light else '#e4edf8';muted='#647a91' if light else '#8da3bb';alt='#f7f9fc' if light else '#122235';inputbg='#f5f8fb' if light else '#0c1929'
    return f'''
    QWidget{{font-family:"Segoe UI","DejaVu Sans";font-size:12px;color:{fg};}}QMainWindow,QDialog{{background:{bg};}}
    QFrame#sidebar{{background:{panel};border-right:1px solid {border};}}QLabel#brand{{font-size:23px;font-weight:700;letter-spacing:-1px;}}
    QLabel#eyebrow{{font-size:10px;color:#29bca1;font-weight:700;letter-spacing:2px;}}QLabel#title{{font-size:27px;font-weight:700;}}
    QLabel#muted,QLabel#cardTitle{{color:{muted};}}QLabel#metric{{font-size:34px;font-weight:700;}}
    QFrame#card,QFrame#panel{{background:{panel};border:1px solid {border};border-radius:12px;}}
    QPushButton{{background:{panel};border:1px solid {border};border-radius:7px;padding:9px 14px;font-weight:600;}}
    QPushButton:hover{{border-color:#2bab94;background:{alt};}}QPushButton:disabled{{color:{muted};border-color:{border};}}
    QPushButton[kind="primary"]{{background:#32c9aa;color:#06231d;border:none;}}QPushButton[kind="primary"]:hover{{background:#51e2c3;}}
    QPushButton[kind="nav"]{{text-align:left;border:none;padding:12px 14px;background:transparent;color:{muted};font-size:13px;}}
    QPushButton[kind="nav"]:checked{{background:{'#ddf5ee' if light else '#14372f'};color:{'#07836b' if light else '#44ddbc'};}}
    QPushButton[kind="nav"]:hover{{background:{alt};}}QLineEdit,QComboBox,QSpinBox,QDoubleSpinBox,QPlainTextEdit,QTextEdit{{background:{inputbg};border:1px solid {border};border-radius:7px;padding:8px;selection-background-color:#1c8a77;}}
    QSpinBox,QDoubleSpinBox{{padding:5px 24px 5px 10px;min-height:22px;}}
    QSpinBox QLineEdit,QDoubleSpinBox QLineEdit{{padding:0;border:none;background:transparent;}}
    QSpinBox::up-button,QDoubleSpinBox::up-button{{subcontrol-origin:border;subcontrol-position:top right;width:22px;border:none;}}
    QSpinBox::down-button,QDoubleSpinBox::down-button{{subcontrol-origin:border;subcontrol-position:bottom right;width:22px;border:none;}}
    QSpinBox::up-arrow,QDoubleSpinBox::up-arrow{{image:url("{up}");width:9px;height:6px;}}
    QSpinBox::down-arrow,QDoubleSpinBox::down-arrow{{image:url("{down}");width:9px;height:6px;}}
    QComboBox QAbstractItemView{{background:{panel};selection-background-color:#207e70;}}
    QTableView{{background:{panel};alternate-background-color:{alt};border:1px solid {border};border-radius:8px;selection-background-color:{'#cdeee6' if light else '#1c4140'};selection-color:{fg};}}
    QHeaderView::section{{background:{panel};color:{muted};border:none;border-bottom:1px solid {border};padding:12px 9px;text-align:left;font-size:11px;font-weight:600;}}
    QTableView::item{{padding:5px 9px;border-bottom:1px solid {border};}}QScrollBar:vertical{{background:{panel};width:9px;}}QScrollBar::handle:vertical{{background:{border};min-height:25px;border-radius:4px;}}QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0px;}}
    QScrollBar:horizontal{{background:{panel};height:9px;}}QScrollBar::handle:horizontal{{background:{border};min-width:25px;border-radius:4px;}}
    QGroupBox{{border:1px solid {border};border-radius:10px;margin-top:15px;padding:15px;}}QGroupBox::title{{subcontrol-origin:margin;left:12px;color:{muted};}}
    QCheckBox{{spacing:8px;}}QSplitter::handle{{background:{bg};width:10px;}}QToolTip{{background:{panel};color:{fg};border:1px solid {border};padding:6px;}}
    QStatusBar{{color:{muted};background:{panel};}}QMenu{{background:{panel};border:1px solid {border};padding:5px;}}QMenu::item{{padding:8px 25px;}}QMenu::item:selected{{background:{alt};}}
    '''
