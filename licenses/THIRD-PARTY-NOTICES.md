# Third-party components

ConnWatch Network is an open-source, local desktop application developed for ZakirUllah. Third-party libraries retain their original authorship and licenses. The author credit in the application does not claim authorship of Python, Qt, PySide6, psutil or Go.

The Windows distribution bundles the official CPython 3.12.10 Windows x64 embeddable runtime, PySide6-Essentials / shiboken6 6.8.3, and psutil 7.2.2. The native launcher and installer are compiled from the included Go source with Go 1.27.4. The distribution uses dynamically loaded Qt libraries and leaves those files accessible for inspection and replacement with compatible versions. The app source and build scripts are included; no restriction is imposed on modifying these files for debugging those changes.

- Python license: `runtime/LICENSE.txt`. CPython source: https://www.python.org/downloads/release/python-31210/
- Qt / PySide6 / Shiboken: LGPLv3 / applicable GPL terms and Qt exception. See included `LGPL-3.0.txt`, `GPL-3.0.txt`, `Qt-GPL-exception.txt`, package metadata and component notices. Upstream PySide source at the exact release: https://code.qt.io/cgit/pyside/pyside-setup.git/tree/?h=6.8.3
- Qt source and license information: https://download.qt.io/archive/qt/6.8/6.8.3/ and https://doc.qt.io/qt-6.8/licensing.html
- psutil BSD license is included in `runtime/Lib/site-packages/psutil-7.2.2.dist-info/LICENSE`; source: https://github.com/giampaolo/psutil/tree/release-7.2.2
- Go BSD license is included as `Go-LICENSE.txt`; source: https://go.dev/dl/

The commercial license notice carried in upstream wheel metadata is preserved as upstream metadata; ConnWatch does not claim a purchased Qt commercial license. The included open-source license texts and upstream component terms apply. Windows system libraries remain part of Windows and are not replaced by this app.

## Manufacturer prefix data
The bundled `assets/oui.json` is derived from Wireshark's generated manufacturer registry, downloaded from https://www.wireshark.org/download/automated/data/manuf . Its generated header attributes the data to TShark and describes IEEE allocation prefix sizes (24, 28 and 36 bits). The original registry-derived names retain their source attribution; see `assets/vendor-source.json` for the snapshot URL and count. Wireshark's COPYING text is included as `Wireshark-COPYING.txt`. The direct IEEE download was not used for this bundled snapshot. The app reads the snapshot offline and does not upload device MAC addresses to a lookup service.
