"""Optional PDF presentation builder; requires ReportLab and DejaVu fonts."""
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.utils import ImageReader
from PIL import Image
import os
ROOT=Path(__file__).resolve().parents[1]
for n,f in [('R','DejaVuSans.ttf'),('B','DejaVuSans-Bold.ttf'),('M','DejaVuSansMono.ttf')]:pdfmetrics.registerFont(TTFont(n,str(Path(os.environ.get('CONNWATCH_FONT_DIR','/usr/share/fonts/truetype/dejavu'))/f)))
W,H=960,540;BG='#091422';PANEL='#102338';FG='#e4edf8';MUTED='#94acc5';TEAL='#39ddbc';ORANGE='#efb56f';page=0
c=canvas.Canvas(str(ROOT/'docs/ConnWatch-Network-Presentation.pdf'),pagesize=(W,H));c.setTitle('ConnWatch Network 3.0 | Project Presentation');c.setAuthor('ZakirUllah')
def rect(x,y,w,h,color,r=0):
 c.setFillColor(HexColor(color));c.setStrokeColor(HexColor(color))
 if r:c.roundRect(x,y,w,h,r,fill=1,stroke=0)
 else:c.rect(x,y,w,h,fill=1,stroke=0)
def text(x,y,t,size=14,color=FG,font='R'):
 c.setFont(font,size);c.setFillColor(HexColor(color));c.drawString(x,y,t)
def para(x,top,t,w=400,size=14,color=MUTED):
 p=Paragraph(t,ParagraphStyle('p',fontName='R',fontSize=size,leading=size*1.5,textColor=HexColor(color)));_,h=p.wrap(w,1000);assert top-h>=65,(page,t);p.drawOn(c,x,top-h)
def start(section,title,subtitle=''):
 global page
 page+=1;rect(0,0,W,H,BG);rect(0,535,W,5,TEAL);text(44,498,'CONNWATCH NETWORK / '+section,10,TEAL,'B');text(44,451,title,29,FG,'B')
 if subtitle:para(44,432,subtitle,872,12)
 c.setStrokeColor(HexColor('#243a50'));c.line(44,49,916,49);text(44,28,'Developed by ZakirUllah',9,MUTED);text(680,28,f'NETWORK DEFENSE / {page:02d}',9,MUTED)
def card(x,y,w,h,title,body):
 rect(x,y,w,h,PANEL,12);text(x+18,y+h-30,title,16,TEAL,'B');para(x+18,y+h-47,body,w-36,13)
def image(name,x,y,w,h):c.drawImage(str(ROOT/'docs'/name),x,y,w,h,preserveAspectRatio=True,anchor='c',mask='auto')
def end():c.showPage()

start('VERSION 3.0','Know your subnet. Keep the evidence.','A native network-discovery and investigation workspace.')
text(46,332,'ConnWatch',49,FG,'B');text(46,273,'Network',49,TEAL,'B');para(48,229,'Discover addresses.<br/>Review available services.<br/>Record what changed.',355,20,FG)
image('Network-Workspace.png',435,95,480,313);text(48,85,'Developed by ZakirUllah',16,TEAL,'B');end()
start('01 / NETWORK-FIRST','Start with the actual network adapter.','Automatic private IPv4 and real netmask detection help select the intended scan scope.')
card(44,176,275,205,'Private IPv4','The address assigned to the selected Ethernet, Wi-Fi or VPN interface. Multiple adapters can lead to different networks.')
card(342,176,275,205,'Subnet / CIDR','The adapter netmask defines the range. The tool displays the actual range and does not silently assume every network is /24.')
card(640,176,275,205,'Gateway context','Available route evidence identifies the default gateway. The selected scope is visible before you start discovery.')
para(48,130,'The selected scope stays inside an RFC1918 private range. Runs are bounded to 4,094 host addresses.',850,14,FG);end()
start('02 / DISCOVERY EVIDENCE','Use several signals. Preserve their meaning.','Different devices answer different discovery methods.')
card(44,179,275,203,'ICMP echo','An actual echo reply supports reachability. Unreachable messages are not counted as a successful echo.')
card(342,179,275,203,'TCP response','An accepted or refused connection gives response evidence. Only accepted connections are recorded as open TCP services.')
card(640,179,275,203,'ARP / neighbors','Available MAC observations improve address inventory. A cached neighbor entry is kept distinct from confirmed current responses.')
para(48,132,'No response is not proof of absence. Sleeping devices, firewalls and Wi-Fi isolation can reduce discovery coverage.',850,14,FG);end()
start('03 / DEVICE INVENTORY','Turn observations into a useful inventory.','Inspect each observed address and keep the context you actually know.')
card(44,177,425,206,'Available technical details','IPv4, hostname, MAC, vendor prefix, role hints, presence evidence, selected TCP services and optional web/TLS observations.')
card(490,177,425,206,'Your review context','Friendly display name, owner/team, Expected or Investigate status, notes, first/last observation and the annotation history.')
para(48,130,'A vendor prefix or port number does not prove a hardware model or software version. Unknown details remain unavailable.',850,14,FG);end()
start('04 / SUBNET ASSESSMENT','Control the checks you send.','Discovery, Standard, Extended and Custom TCP profiles keep the scope explicit.')
card(44,183,275,199,'Bounded workload','Choose up to 64 TCP ports. Configure parallel addresses, connection timeout and probe-operation pacing.')
card(342,183,275,199,'Coverage evidence','Record requested ports, checked ports and whether the chosen service profile was completed for each address.')
card(640,183,275,199,'Stop safely','Cancel queued work, let in-flight calls finish and retain partial address evidence with a Cancelled scan status.')
para(48,137,'No credentials, authentication attempts, exploits or automatic blocking are part of discovery.',850,14,FG);end()
start('05 / COMPLETE RECORDS','Save outcomes, including silence.','Every recorded address attempt belongs to a scope, time and policy.')
card(44,179,275,203,'Per-address results','Responding, Neighbor observed, No response and Probe error stay distinct. Raw evidence includes available response details.')
card(342,179,275,203,'Transactional storage','SQLite keeps batched scan evidence. Interrupted or cancelled assessments retain the results already saved.')
card(640,179,275,203,'Practical retention','Defaults: 90 days and the newest 500 finished scans. Both limits are configurable; device annotations remain available.')
para(48,132,'PDF/HTML are readable assessments. CSV supports review. JSON preserves retained per-address attempts and annotation context.',850,13);end()
start('06 / CHANGE TIMELINE','Compare equivalent observations.','Completed scans of the same CIDR scope form the automatic comparison baseline.')
card(44,177,425,206,'Record the changes','Newly observed addresses, missing observations, MAC/hostname changes and selected TCP service-state changes.')
card(490,177,425,206,'Avoid invented conclusions','Do not use cancelled scans as disappearance baselines. Compare a port only if both scans checked it. Missing observations are not offline verdicts.')
para(48,130,'The comparison source is stored in the assessment summary so the change has traceable context.',850,14,FG);end()
start('07 / WEB AND CERTIFICATES','Read available service metadata.','Optional checks are limited to observed open web ports on the selected private targets.')
card(44,178,425,205,'HTTP observations','HEAD response status and selected headers. Redirects are not followed and credentials are not sent.')
card(490,178,426,205,'TLS observations','Default-trust/IP-name verification outcome and a presented certificate fingerprint when obtainable. A failed verification stays failed.')
para(48,132,'An IP-name mismatch or private certificate needs context. These checks are not a confirmed vulnerability or malware assessment.',850,14,FG);end()
start('08 / DESKTOP EXPERIENCE','A clear policy. A smoother workspace.','Native transitions, discovery pulse, interactive map selection, dark/light appearance and reduced-motion controls.')
image('Discovery-Policy.png',40,70,570,330)
text(640,358,'Visible scan settings',17,TEAL,'B');para(640,332,'Adapter, subnet, port profile, concurrency, timeout and pacing are explicit.',272,13)
text(640,248,'Repeat assessments',17,TEAL,'B');para(640,222,'Optional repeat scanning while the application remains open. Runs do not overlap.',272,13)
text(640,139,'Keep the interface focused',16,TEAL,'B');para(640,114,'Network discovery is primary. Workstation inspection is a secondary tool.',272,12);end()
start('09 / VALIDATION','Check the pipeline end to end.','127 automated tests passed on Linux across network and retained workstation behavior.')
card(44,177,275,206,'Core and evidence','Subnet/netmask detection, scope limits, discovery classification, cancellation, comparisons, retention, annotations and exports.')
card(342,177,275,206,'Native GUI checks','Navigation, fields, filters, dialogs, scheduling, transitions, PDF export and startup-only self-check without scan probes.')
card(640,177,275,206,'Owned live sockets','Actual loopback TCP/HTTP tests. Three GUI assessments recorded Open, Open, then Refused, with a saved state-change event.')
para(48,131,'Windows packages are cross-built and structurally checked. Native Windows and the user’s LAN still require target-machine acceptance testing.',850,13);end()
start('10 / FIRST NETWORK RUN','A simple acceptance workflow.','Use your own network and verify the scope before starting.')
steps=[('1','Open the new release','Close the earlier ConnWatch copy, then open version 3.0.'),('2','Check adapter and subnet','Confirm the private address and netmask against your OS network settings.'),('3','Discover, inspect, annotate','Start Discovery or Standard. Inspect one device and record its owner/context.'),('4','Rescan and export','Review a second scan’s changes, then export the assessment evidence.')]
for i,(n,title,body) in enumerate(steps):
 y=317-i*66;text(49,y,n,27,TEAL,'B');text(96,y+7,title,17,FG,'B');para(96,y-4,body,790,13)
end()
start('11 / HONEST LIMITS','Build on evidence, not guesses.','Some information cannot be obtained through a private-subnet discovery sweep.')
card(44,169,425,215,'Current boundaries','No guarantee every physical device is found.<br/><br/>No remote process lists or credentials.<br/><br/>No intercepted encrypted traffic.<br/><br/>No exhaustive UDP or IPv6 subnet scan.')
card(490,169,426,215,'Future development','Trusted Windows signing and native acceptance automation.<br/><br/>Richer mDNS/SSDP identification.<br/><br/>IPv6 and managed multi-VLAN discovery.<br/><br/>Optional authenticated inventory integrations.')
para(48,126,'Future items are not shown as active capabilities. This release remains an unsigned development build.',850,13,FG);end()
start('12 / TAKEAWAY','Discover. Investigate. Remember.','A network inventory is stronger when every conclusion has supporting evidence.')
text(48,314,'ConnWatch Network',43,FG,'B');para(48,268,'A visible scope.<br/>An observed device.<br/>A recorded change.',820,25,FG)
text(48,91,'Developed by ZakirUllah',19,TEAL,'B');text(680,91,'QUESTIONS / LIVE RUN',12,MUTED,'B');end()
c.save();print('Presentation pages:',page)
