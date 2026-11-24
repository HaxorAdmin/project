"""Animated native Qt dashboard components."""
import math
from PySide6.QtCore import Qt,QTimer,QVariantAnimation,QEasingCurve,Signal,QPointF,QRectF
from PySide6.QtGui import QPainter,QColor,QPen,QFont
from PySide6.QtWidgets import QWidget
from .widgets import Card

class AnimatedCard(Card):
    def __init__(self,title,value='0',caption=''):
        super().__init__(title,value,caption);self.animation=QVariantAnimation(self);self.animation.setDuration(220);self.animation.setEasingCurve(QEasingCurve.OutCubic)
        self.animation.valueChanged.connect(lambda v:self.value.setText(str(round(v))));self.motion=True;self.target=0
    def update(self,value,caption=None):
        if caption is not None:self.caption.setText(caption)
        if not self.motion or not isinstance(value,(int,float)):self.animation.stop();self.value.setText(str(value));return
        if value==self.target:return
        self.target=value;current=float(self.value.text()) if self.value.text().replace('.','',1).isdigit() else 0
        self.animation.stop();self.animation.setStartValue(current);self.animation.setEndValue(float(value));self.animation.start()

class NetworkMap(QWidget):
    selected=Signal(str)
    def __init__(self,parent=None):
        super().__init__(parent);self.devices=[];self.gateway='';self.scope='';self.hits=[];self.angle=0;self.scanning=False;self.light=False
        self.setMinimumHeight(270);self.timer=QTimer(self);self.timer.setInterval(40);self.timer.timeout.connect(self.tick)
    def tick(self):self.angle=(self.angle+2)%360;self.update()
    def set_scanning(self,enabled,motion=True):
        self.scanning=enabled
        if enabled and motion:self.timer.start()
        else:self.timer.stop()
        self.update()
    def set_devices(self,devices,scope='',gateway=''):self.devices=devices;self.scope=scope;self.gateway=gateway;self.update()
    def mousePressEvent(self,event):
        for bounds,ip in self.hits:
            if bounds.contains(event.position()):self.selected.emit(ip);return
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.Antialiasing);bg='#ffffff' if self.light else '#101f31';fg='#17324a' if self.light else '#e6eef8';muted='#678099' if self.light else '#8da3bb';line='#dbe8ef' if self.light else '#263d53'
        p.setPen(Qt.NoPen);p.setBrush(QColor(bg));p.drawRoundedRect(self.rect(),13,13)
        p.setPen(QColor(fg));p.setFont(QFont('Segoe UI',11,QFont.DemiBold));p.drawText(21,29,'Network discovery map')
        p.setPen(QColor(muted));p.setFont(QFont('Segoe UI',9));p.drawText(21,49,'Observed addresses • logical grouping, not physical switch topology')
        center=QPointF(self.width()/2,self.height()/2+25);radius=min(self.width()*.32,(self.height()-150)/2)
        self.hits=[]
        if self.scanning:
            p.setPen(QPen(QColor('#1d665e'),1));p.setBrush(Qt.NoBrush)
            for r in [42,53,64]:p.drawEllipse(center,r,r)
            theta=math.radians(self.angle);p.setPen(QPen(QColor('#35d9b9'),2));p.drawLine(center,QPointF(center.x()+radius*math.cos(theta),center.y()+radius*math.sin(theta)))
        shown=self.devices[:8]
        for i,device in enumerate(shown):
            d=device.get('data',device);theta=math.radians(-90+i*360/max(1,len(shown)))
            node=QPointF(center.x()+min(self.width()*.35,270)*math.cos(theta),center.y()+radius*math.sin(theta));color='#38d7b6' if d.get('presence')=='Responding' else '#eab776'
            p.setPen(QPen(QColor(line),1.3));p.drawLine(center,node)
            p.setPen(QPen(QColor(color),1.6));p.setBrush(QColor(bg));p.drawEllipse(node,8,8)
            ip=d.get('ip','');title=device.get('label') or d.get('hostname') or ip
            if len(title)>21:title=title[:18]+'...'
            p.setFont(QFont('Segoe UI',9));p.setPen(QColor(fg));p.drawText(QRectF(node.x()-95,node.y()+13,190,21),Qt.AlignCenter,title)
            if title!=ip:p.setPen(QColor(muted));p.setFont(QFont('Segoe UI',8));p.drawText(QRectF(node.x()-90,node.y()+31,180,19),Qt.AlignCenter,ip)
            self.hits.append((QRectF(node.x()-85,node.y()-10,170,60),ip))
        p.setBrush(QColor('#143c3a'));p.setPen(QPen(QColor('#39ddbc'),2));p.drawEllipse(center,32,32)
        p.setPen(QColor('#54e7c8'));p.setFont(QFont('Segoe UI',9,QFont.Bold));p.drawText(QRectF(center.x()-70,center.y()-8,140,20),Qt.AlignCenter,'Gateway' if self.gateway else 'Subnet')
        p.setPen(QColor(muted));p.setFont(QFont('Segoe UI',8));p.drawText(QRectF(center.x()-105,center.y()+38,210,19),Qt.AlignCenter,self.gateway or self.scope)
        if not shown:
            p.setPen(QColor(muted));p.drawText(QRectF(20,self.height()-43,self.width()-40,25),Qt.AlignCenter,'Discovered addresses will appear here')
        elif len(self.devices)>8:p.setPen(QColor(muted));p.drawText(21,self.height()-16,f'+ {len(self.devices)-8} more addresses in Devices')
        p.end()
