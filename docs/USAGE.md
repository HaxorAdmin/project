# ConnWatch Network 3.0
**Developed by ZakirUllah**

ConnWatch is now a network-discovery and evidence workspace. It detects available private IPv4 adapters and their actual netmasks, discovers addresses inside a selected subnet, records the results, and compares completed assessments. Workstation socket/process investigation is retained as a secondary tool. The network interface has no end-user demo mode or live/demo toggle.

## Windows - quick start

1. Close the earlier ConnWatch window, including any copy started through CMD. The old and new release share a per-user workspace lock.
2. Download **ConnWatch-Network-Setup-3.0.0.exe**, double-click it and confirm the per-user install. Open the **ConnWatch Network** shortcut.
3. Wait for adapter detection. Select the intended Ethernet, Wi-Fi or VPN adapter. Check the detected private IP, real subnet/netmask and gateway shown above the dashboard.
4. Keep **Standard** for selected common TCP services, or select **Discovery** for a lighter first scan.
5. Click **Scan network**. Results are saved in batches while it runs. Use **Stop scan** to finish in-flight probes and keep partial evidence.
6. Open **Devices**, select an address, then choose **Inspect device**. Use **Edit notes** to record the owner, a friendly name and your review decision.
7. Scan the same subnet again later. **Change timeline** compares completed scans. **Scan history** reopens and exports earlier assessments.

The setup includes Python/Qt. No CMD, pip or separate Python installation is needed for the Windows package. It targets Windows 10/11 x64. It remains an unsigned development release: no trusted publisher signature or native Windows acceptance test is claimed. Windows app-control policy may block unsigned executables. Signing was not silently added and the installer does not change Windows security settings.

### Portable edition

Extract **ConnWatch-Network-Windows-3.0.0.zip** into a **new empty folder**, then double-click `ConnWatch.exe`. Keep `runtime`, `application`, `docs` and other distributed files beside it. Do not extract the EXE itself with an archive utility. Use the ZIP for the portable edition or run the setup EXE normally.

### Startup and duplicate windows

The network launcher now records startup output, and the Python entry point writes stage logs before building the UI. A second Windows launch attempts to restore the existing **ConnWatch Network** window instead of only saying it is already open. If an older v2 process still owns the workspace, close that copy first; this release will not force-kill unrelated Python programs or remove an active lock.

If a window does not appear, open CMD inside the extracted portable folder and run:

```bat
runtime\python.exe -X faulthandler application\main.py
```

A startup-only diagnostic that sends **zero scan probes** is:

```bat
runtime\python.exe application\main.py --self-check
```

The early diagnostic files are in `%LOCALAPPDATA%\ZakirUllah\ConnWatchDesktop`: `connwatch.log`, `startup-trace.log` and `launcher-startup.log`. The first is rotated; the second records a startup traceback if initialization stalls. With `--data-dir`, the application logs are in that selected workspace; the native launcher log stays in the default per-user folder. The optional command below creates an independent workspace without deleting old records:

```bat
runtime\python.exe application\main.py --data-dir "%LOCALAPPDATA%\ConnWatch-Network-Check"
```

## Kali / Linux GUI

Extract the source package and open a terminal in its `ConnWatch-Network` folder:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py
```

Later use `.venv/bin/python main.py` or `./Start-Kali.sh`. A graphical desktop and Python 3.10+ are required. If `venv` is unavailable, install your distribution's `python3-venv` package. Qt's xcb platform may need `libxcb-cursor0` on some Kali/Debian desktop images. Reading adapters can be restricted in a container; the app reports that and exposes manual private-subnet entry. Running inside a Kali VM scans the network that VM is attached to; it does not automatically gain visibility into every network attached to the Windows host.

## What is implemented

| Area | Implemented behavior |
| --- | --- |
| Adapter detection | Uses available interface IPv4 addresses and actual netmasks; associates default-route/gateway evidence where available; prioritizes default-route adapters |
| Scope | User-visible adapter and CIDR selector; private RFC1918 IPv4 scopes; at most 4,094 host addresses per run; large adapter ranges are shown accurately and require a smaller selected range |
| Discovery evidence | ICMP echo checks, paced TCP connect/refusal checks, Windows SendARP observations, and OS ARP/neighbor tables |
| Device inventory | IP, available hostname/MAC, offline manufacturer-prefix lookup, role hints, observed presence, selected open TCP services, first/last observation and owner/review notes |
| Services | Discovery, Standard, Extended and Custom profiles; up to 64 chosen TCP ports; no password attempts, logins or exploitation |
| Web/TLS observations | Optional HEAD response metadata on observed open web ports; certificate trust/name-check result and presented SHA-256 fingerprint when obtainable |
| History | Every completed address attempt, no-response outcome, checked/requested port coverage, errors, timestamps, scan scope and policy recorded in SQLite |
| Changes | Newly observed addresses, missing observations, MAC/hostname changes and common checked-port state changes between completed scans of the same scope |
| Review journal | Friendly name, owner, Unreviewed/Expected/Investigate decision and notes; earlier annotation edits are preserved in a journal |
| Repeat scans | Optional 2-1,440 minute delay after a completed scan while the app remains open; no overlapping discovery runs |
| Reports | PDF, HTML, CSV and detailed JSON; JSON includes recorded address attempts and annotation context/journal |
| Experience | Native Qt GUI, network map, scan progress, smooth numeric/page transitions, discovery pulse, dark/light themes and reduced-motion setting |
| Workstation inspector | Previous process/socket inventory, host rules, alert triage, executable details and SHA-256 file inspection retained separately |

## Discovery profiles

- **Discovery:** TCP 80 and 443, plus the discovery evidence methods.
- **Standard:** TCP 21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 5900, 8080, 8443 and 9100.
- **Extended:** All 23 service ports in `app/discovery.py`, including common database/printing ports.
- **Custom:** Choose up to 64 ports in **Scan settings**. Comma-separated values and short ranges are accepted, for example `22,80,443,8000-8003`.

Defaults are 24 parallel addresses, 0.35-second TCP connect timeout and pacing at 80 probe-operation starts per second. A web/TLS metadata observation can involve more than one protocol exchange; this is not a packet-per-second guarantee. Hostname lookups are separately time-bounded. Reduce concurrency/rate or increase timeout on a congested network. Stop requests cancel queued work; in-flight OS ARP, connection and metadata calls must finish or time out.

After an initial discovery response or neighbor observation, the tool checks the selected service profile. For addresses that provide no initial discovery evidence, remaining service checks may be skipped; the evidence explicitly records `requested_ports`, `checked_ports` and `complete_port_profile`. This keeps a broad subnet sweep bounded without claiming ports were checked when they were not.

## Read the results correctly

- **Responding:** An ICMP echo reply, TCP open/refused response, or the selected workstation adapter address supplied direct observation evidence. A TCP refusal establishes a response; it is not an open service.
- **Neighbor observed:** A MAC/neighbor observation exists but this scan did not confirm ICMP/TCP reachability. A cache entry can be stale. This is not treated as a verified live response.
- **No response:** The attempted discovery methods did not provide evidence. The device may sleep, block probes, sit behind isolation or use different services. This does not prove absence or an offline device.
- **Probe error:** An exception interrupted that address's check. Its error text is recorded. It does not create a false disappearance event in change comparison.
- **Not observed this scan:** A previously observed inventory address was not observed in this selected run. This is a coverage statement, not an offline verdict.

The network map is a **logical grouping**, not an inferred wiring/switch topology. It displays up to eight recent observations; the complete address inventory remains in Devices. Role labels are evidence-based hints: a gateway comes from route data; a printer-related role comes from observed printing ports. Hostnames and manufacturer prefixes do not conclusively identify hardware or owners. Private/randomized MACs are labelled accordingly. Unknown details remain unavailable.

Port-based review notes identify possible cleartext, remote-administration or file-sharing exposure. They are not confirmed vulnerabilities or malware verdicts. TCP 53 is not a UDP DNS assessment. This version does not claim an exhaustive UDP service scan or IPv6 subnet enumeration.

### Web/TLS specifics

Only observed open TCP 80/443/8080/8443 receive optional web checks. HEAD headers are read without following redirects or sending credentials. A default-trust/IP-name TLS verification failure is recorded. A separate, explicitly unverified handshake may collect only the presented certificate fingerprint; that does not turn a failed certificate into a trusted one. Private services with DNS-name certificates commonly fail verification when reached by IP. The app does not decrypt other devices' traffic.

## Data and retention

The workspace is per user, normally `%LOCALAPPDATA%\ZakirUllah\ConnWatchDesktop` on Windows and under `~/.local/share/ZakirUllah/ConnWatchDesktop` on Linux. Network data is in `network.db`; retained v2 workstation data stays in `connwatch.db`. Policy is in `network-settings.ini`.

Every recorded address attempt is stored transactionally. Raw scans default to **90 days and the latest 500 finished scans**, configurable in Scan settings. Cleanup runs at startup and after a completed/finalized scan, or explicitly through **Apply retention**. Device inventory annotations and their review journal remain after raw-scan retention; they do not imply old scan evidence is still available. JSON reports include current annotation context separately from historical scan-time observations. Reports include UTC times and may contain private device names and addresses: review them before sharing.

Only completed scans of the **same CIDR scope** are used for automatic comparison. Cancelled/failed/interrupted scans retain their available evidence but do not become disappearance baselines. Ports are compared only when both scans actually checked the port, so selecting a different profile does not create an invented closure. The comparison source is recorded in the summary.

## What a subnet scan cannot promise

Only scan networks you own or are authorized to assess. Visibility is limited by routing, Wi-Fi client isolation, firewalls, sleeping devices and host behavior. MAC observations normally apply to the selected broadcast domain; routed hosts may have no device MAC available. The app cannot guarantee every physical device is found.

It does not collect credentials, remote running-process lists, encrypted traffic contents, packet captures or device filesystem contents. It does not exploit vulnerabilities, try default passwords, block traffic, change router configuration or query a cloud malware/geolocation service. Endpoint process details require running the workstation component on that host; a subnet scan does not grant remote access.

## Verification and source

From the source folder:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests -v
```

Tests use controlled fixtures and owned loopback sockets; they are not user-facing fake scan results. See `docs/test-results.txt`, `docs/integration-check.json` and `docs/VALIDATION.md`. The test environment did not scan the user's actual LAN. Windows binaries are cross-compiled/packaged and structurally checked; native Windows 10/11 installation, network discovery and acceptance testing remain necessary on the target machine.

Main files: `app/discovery.py` (scope/adapter/probe workers), `app/inventory.py` (network evidence and reports), `app/network_window.py` (GUI), `app/network_widgets.py` (map/animations), `main.py` (startup/focus/diagnostics). The native launcher/installer source is in `scripts/windows/`; the pinned runtime packaging helper is `scripts/build_windows.py`.

## Planned improvements - not shipped

Signed Windows releases, native Windows acceptance automation, managed background capture, multi-VLAN orchestration, IPv6 discovery, richer mDNS/SSDP identification, optional authenticated SNMP inventory and a configurable detection-rule engine are future work. They are not displayed as active capabilities.

**Developed by ZakirUllah**
