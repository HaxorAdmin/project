# Troubleshooting

| Symptom | What to check |
| --- | --- |
| Windows blocks the EXE | This release is unsigned. Use your normal app approval process or reviewed source with trusted Python; do not disable security as a routine installation step. |
| Process exists but no new window | Close the existing ConnWatch copy, check the taskbar/tray and try again. A second Windows launch attempts to restore the current network window. An older v2 window can hold the same workspace lock. |
| EXE starts then disappears | Fully extract the portable ZIP, keep the runtime/application folders together, run the diagnostic command below and inspect startup logs. |
| Python reports missing modules | Run pip through the same virtual-environment interpreter used to launch the app. |
| Qt xcb/platform error | Launch from a graphical Linux desktop and install the exact missing system library named by Qt. `libxcb-cursor0` is a common Kali/Debian requirement. |
| No adapter is available | Restricted environments may block interface enumeration. Check the OS network connection; the GUI also offers manual private-scope entry. |
| Scope rejected | Use a permitted RFC1918 private IPv4 range, within the selected adapter scope and host limit. Large actual subnets require a smaller selected range. |
| Some devices missing | Check correct adapter, VLAN/routing boundaries, Wi-Fi client isolation, sleeping hosts and firewalls. No response does not prove absence. |
| MAC/vendor unavailable | Routed targets may not expose a device MAC. Randomized MACs and missing registry entries limit vendor identification. |
| TLS warning on a private service | A certificate issued for a DNS name may fail verification when contacted by IP. A recorded fingerprint does not mean the certificate was trusted. |
| Repeated scans stop when app closes | Repeat scheduling runs only while the application remains open. |

## Windows diagnostic command

Open CMD in the extracted portable folder:

```bat
runtime\python.exe -X faulthandler application\main.py
```

Check `%LOCALAPPDATA%\ZakirUllah\ConnWatchDesktop` for `connwatch.log`, `startup-trace.log` and `launcher-startup.log`. The zero-probe startup diagnostic is:

```bat
runtime\python.exe application\main.py --self-check
```

For source, replace the interpreter with `.venv\Scripts\python.exe` and the entry point with `main.py`.

## Reporting an issue

Include OS version, package version, install/portable/source edition, exact error and steps to reproduce. Remove private IPs, hostnames, account names, tokens and unrelated log contents before sharing. Do not post your complete database publicly. Keep existing records backed up; deleting a database or active workspace lock is not a general startup fix.
