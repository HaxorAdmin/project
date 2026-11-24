# GitHub publication verification

Date: 2026-11-24

- Linux Python 3.12.14, PySide6-Essentials/shiboken6 6.8.3, psutil 7.2.2.
- `QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -v`: **127 tests passed**.
- `main.py --data-dir <temporary-workspace> --self-check`: passed; imports, database and native window initialized; **zero scan probes sent**.
- Windows ARP calls in probe unit fixtures are mocked to keep these tests isolated on either platform.
- The supplied Windows installer and portable ZIP are preserved byte-for-byte from the 3.0.0 delivery. Updated documentation and isolated test fixtures are included in the repository/source ZIP.
- Existing Linux/loopback integration evidence is retained in `VALIDATION.md` and `integration-check.json`.
- Native Windows installation and real-LAN discovery have not been verified in this publication environment. The Windows binaries remain unsigned.

The checks above are local executed checks. They are not claims of a completed GitHub Actions run or native Windows acceptance.
