# ConnWatch Network 3.0 - validation
Developed by ZakirUllah

## Executed behavior

- Automated network tests cover actual-netmask adapter selection, private-scope boundaries, host-count and port limits, cancellation, a paced-probe gate, echo-reply interpretation, cache versus response classification, vendor-prefix matching and optional metadata.
- Test fixtures cover a /30 subnet end to end: two address attempts are saved, including a no-response result. Fixtures are isolated automated tests, not production GUI data.
- Real tests use only owned loopback sockets. TCP open/refused behavior and an actual HTTP HEAD exchange were exercised. No neighboring execution-environment subnet or user's LAN was scanned.
- A separate native Qt GUI integration harness performed three owned-loopback assessments. They recorded Open, Open and then Refused for the controlled service, and the service-state change appeared in the stored timeline. Its summary is `integration-check.json`. Loopback scope was enabled only inside that test harness; it is not exposed by the production private-subnet selector.
- SQLite transaction rollback, no-response preservation, neighbor enrichment, first-seen preservation, annotations, the annotation journal, scan comparison, cancellation/baseline isolation, count/age retention and safe exports are tested.
- GUI tests exercise navigation, profile/scope fields, filters, view dialogs, settings, repeat scheduling, map selection and completed page transitions. Retained workstation behavior has a separate regression suite.
- The application `--self-check` path created the native window and network database and exited successfully without sending any scan probes.
- The generated network PDF was rendered with Poppler and visually reviewed. Its headings, evidence table, change section and caveats are readable. UI dark/light screens and policy controls were inspected; spinbox field readability and scroll-area styling were corrected during visual QA.

## Environment and limits

Executed on Linux with Python 3.12.14, psutil 7.2.2 and PySide6-Essentials / shiboken6 6.8.3. Actual interface-address enumeration is restricted by the execution environment, so automatic address detection is tested with controlled interface records and gateway evidence rather than claimed as a successful native Windows discovery. The GUI exposes manual private-subnet selection when interface data is unavailable.

The Windows x64 launcher and setup are cross-compiled GUI PE executables with the packaged official embedded Python and pinned Windows wheels. Package manifests, application-source equality and shipped PE dependencies are checked. Native Windows installation, duplicate-window focus behavior, ARP API execution, firewall-dependent reachability and end-to-end scanning on the user's real network have not been executed here. The release remains unsigned. Check `test-results.txt` for the final executed test count and full outcome.

The manufacturer snapshot contains 58,821 prefix assignments from Wireshark's IEEE/registry-derived generated database. Longest-prefix matching is tested. Private/randomized MACs are labelled instead of assigned a confident vendor identity.

No claim is made that every physical device is discoverable. Responses, cached neighbors, unknown data and missing observations are distinct. Ports are service hints and review context, not proven vulnerabilities. Scheduled scanning runs only while the application remains open. Device-level process lists, traffic contents and credentials are not collected.
