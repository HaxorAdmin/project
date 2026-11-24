"""Build a portable Windows x64 folder from official embedded Python and Windows wheels.
Run on Linux with Go cross-compilation or on Windows. No binary extension is renamed.
"""
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
import shutil,hashlib,json
import pefile
ROOT=Path(__file__).resolve().parents[1]
BUILD=ROOT/'build';OUT=BUILD/'ConnWatch-Desktop-Windows';OUT.mkdir(exist_ok=True)
RUNTIME=OUT/'runtime';RUNTIME.mkdir(exist_ok=True)
with ZipFile(BUILD/'python-3.12.10-embed-amd64.zip') as z:z.extractall(RUNTIME)
(RUNTIME/'python312._pth').write_text('python312.zip\n.\nLib/site-packages\n../application\nimport site\n')
SITE=RUNTIME/'Lib/site-packages';SITE.mkdir(parents=True,exist_ok=True)
all_files={}
for wheel in (BUILD/'windows-wheels').glob('*.whl'):
 with ZipFile(wheel) as z:
  for name in z.namelist():
   if not name.endswith('/'):all_files[name]=z.read(name)
mods=['QtCore','QtGui','QtWidgets','QtPrintSupport','QtTest']
selected=set()
for name in all_files:
 if name.startswith(('psutil/','shiboken6/')) or '.dist-info/' in name:selected.add(name)
 if name.startswith('PySide6/'):
  if name.endswith(('.py','.pyi','.typed')) and '/qml/' not in name and '/examples/' not in name:selected.add(name)
  if any(name==f'PySide6/{m}.pyd' for m in mods):selected.add(name)
  if name=='PySide6/plugins/platforms/qwindows.dll':selected.add(name)
  if name.startswith('PySide6/plugins/imageformats/') and name.endswith(('/qico.dll','/qjpeg.dll','/qgif.dll')):selected.add(name)
  if name.startswith('PySide6/plugins/styles/'):selected.add(name)
# Traverse PE imports and include shipped dependencies in their original package locations.
binaries={Path(name).name.casefold():name for name in all_files if name.lower().endswith(('.dll','.pyd'))}
queue=[name for name in selected if name.lower().endswith(('.dll','.pyd'))]
visited=set()
while queue:
 name=queue.pop()
 if name in visited:continue
 visited.add(name)
 pe=pefile.PE(data=all_files[name],fast_load=True);pe.parse_data_directories(directories=[1,13])
 imports=list(getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]))+list(getattr(pe,'DIRECTORY_ENTRY_DELAY_IMPORT',[]))
 for entry in imports:
  dep=entry.dll.decode().casefold()
  if dep in binaries:
   target=binaries[dep]
   if target not in selected:selected.add(target);queue.append(target)
 pe.close()
for name in selected:
 p=SITE/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(all_files[name])
application=OUT/'application'
if application.exists():shutil.rmtree(application)
(application/'app').mkdir(parents=True)
for p in (ROOT/'app').glob('*.py'):shutil.copy2(p,application/'app'/p.name)
shutil.copy2(ROOT/'main.py',application/'main.py')
shutil.copytree(ROOT/'assets',application/'assets',dirs_exist_ok=True)
shutil.copy2(BUILD/'ConnWatch.exe',OUT/'ConnWatch.exe')
shutil.copy2(ROOT/'scripts/windows/Uninstall.ps1',OUT/'Uninstall.ps1')
shutil.copytree(ROOT/'licenses',OUT/'licenses',dirs_exist_ok=True)
shutil.copytree(ROOT/'docs',OUT/'docs',dirs_exist_ok=True)
if (ROOT/'README.md').exists():shutil.copy2(ROOT/'README.md',OUT/'README.md')
# Include all source, tests and build scripts, preserving ability to inspect / modify the app.
for name in ['app','scripts','tests','assets','docs','licenses']:
 target=OUT/'source'/name
 for p in (ROOT/name).rglob('*'):
  if p.is_file() and not any(k in p.parts for k in ['__pycache__']) and p.suffix not in ['.syso','.zip']:
   dest=target/p.relative_to(ROOT/name);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
for name in ['main.py','requirements.txt','README.md','LICENSE','Start-Kali.sh']:
 shutil.copy2(ROOT/name,OUT/'source'/name)
# Record the exact distributed bytes for local integrity checks.
manifest={str(p.relative_to(OUT)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.json'}
(OUT/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2))
zip_path=BUILD/'windows-payload.zip'
with ZipFile(zip_path,'w',ZIP_DEFLATED,compresslevel=8) as z:
 for p in sorted(OUT.rglob('*')):
  if p.is_file():z.write(p,p.relative_to(OUT))
print('Portable files:',len(manifest),'selected Windows package files:',len(selected),'ZIP MiB:',round(zip_path.stat().st_size/1024**2,1))
print('Root executable:',pefile.PE(str(OUT/'ConnWatch.exe')).FILE_HEADER.Machine)
