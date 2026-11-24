# Architecture and languages

Developed by ZakirUllah

| Technology | Role |
| --- | --- |
| Python | Application startup, discovery workers, evidence handling, tests and packaging helpers |
| PySide6 / Qt | Native desktop UI, signals/workers, tables, graphics, transitions and PDF printing |
| Go | Native Windows GUI launcher and per-user setup executable |
| SQLite / SQL | Persistent scan records, inventory, notes, change history and workstation records |
| HTML / CSS | Exported report structure and styling |
| PowerShell | Windows uninstall support |
| POSIX shell | Kali launcher |
| JSON / INI | Offline manufacturer snapshot, manifests and settings |

## How a scan works

1. The GUI obtains available local interface addresses/netmasks and available gateway evidence.
2. The selected private IPv4 scope and scan options are validated before work starts.
3. Bounded workers perform paced discovery and selected TCP checks, with optional web/TLS metadata.
4. Results are stored transactionally, including no-response attempts and coverage details.
5. Completed scans of the same scope can be compared using mutually checked evidence.
6. The GUI presents inventory/history and exports selected evidence.

## Main files

| Path | Purpose |
| --- | --- |
| `main.py` | Startup logging, workspace lock, duplicate focus and self-check |
| `app/discovery.py` | Adapter/scope handling, probe limits, discovery workers and vendor lookup |
| `app/inventory.py` | Network SQLite storage, comparisons, annotations, retention and reports |
| `app/network_window.py` | Main network workspace and interaction flow |
| `app/network_widgets.py` | Network visualization and animation widgets |
| `app/window.py`, `app/engine.py`, `app/storage.py`, `app/detection.py` | Retained workstation inspector behavior |
| `scripts/windows/launcher/main.go` | Launch the bundled runtime without a console window |
| `scripts/windows/setup/main.go` | Per-user Windows installation |
| `scripts/build_windows.py` | Package the embedded runtime and application dependencies |
| `tests/` | Network and workstation regression coverage |

## Storage and boundaries

`network.db` holds network assessments. `connwatch.db` stores retained workstation evidence separately. `network-settings.ini` holds network policy/preferences. Default raw-scan retention is 90 days and the latest 500 finished scans; annotations and their journal remain after raw-scan retention.

Discovery is observation-based and bounded. No remote login, credential collection, exploitation, traffic decryption or automatic blocking is implemented. The map is a logical grouping of observations rather than physical topology discovery. See [detailed usage](USAGE.md) for exact meanings and limitations.
