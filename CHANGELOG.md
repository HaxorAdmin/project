# Changelog

## 3.0.0

- Added the network discovery workspace with private IPv4 adapter/subnet selection.
- Added bounded discovery, TCP profiles and optional HTTP/TLS observations.
- Added device inventory, owner/review notes and annotation history.
- Added persistent address-attempt evidence, scan history, comparisons and retention.
- Added repeat scheduling and PDF/HTML/CSV/JSON reports.
- Added network visualization, light/dark themes and reduced-motion controls.
- Retained workstation investigation in a separate inspector.
- Added early startup logging, zero-probe self-check and Windows duplicate-window focus attempts.
- Removed end-user demo controls from the network workspace.

### GitHub documentation update

Added installation guides, architecture, troubleshooting, contribution guidance and download checksums. Production application code remains the same as the supplied 3.0.0 Windows packages. Windows test fixtures now mock OS ARP calls explicitly.

### Release status

Unsigned development release. Linux regression tests and startup checks are recorded in the validation documents. Native Windows acceptance and publisher signing remain outstanding.
