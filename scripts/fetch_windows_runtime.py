"""Reproduce pinned Windows runtime inputs for the packaging script."""
from pathlib import Path
import hashlib,subprocess,sys,urllib.request
ROOT=Path(__file__).resolve().parents[1];BUILD=ROOT/'build';BUILD.mkdir(exist_ok=True)
p=BUILD/'python-3.12.10-embed-amd64.zip'
if not p.exists():urllib.request.urlretrieve('https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip',p)
expected='4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3'
if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise RuntimeError('Embedded runtime checksum differs from the tested input.')
subprocess.run([sys.executable,'-m','pip','download','--only-binary=:all:','--platform','win_amd64','--python-version','312','--implementation','cp','--abi','cp312','--dest',str(BUILD/'windows-wheels'),'PySide6-Essentials==6.8.3','shiboken6==6.8.3','psutil==7.2.2'],check=True)
print('Pinned Windows inputs are ready.')
