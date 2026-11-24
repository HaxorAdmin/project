# 3.0.0 - Network workspace
Developed by ZakirUllah

This release changes the primary application from a workstation connection viewer into a private-subnet discovery workspace. The main navigation is Dashboard, Devices, Scan history, Change timeline and Scan settings. Demo controls and the old local-first product tag are removed from the network user flow. Workstation inspection remains available as a separate secondary window.

Adds adapter/IP/netmask detection, scoped ping/TCP/ARP evidence, offline vendor-prefix lookup, bounded hostname and web/TLS observations, persistent per-address results, annotation journal, comparable-scan changes, reports, repeat-scan policy, retention limits, discovery-map selection and native transitions.

Startup diagnostics begin before GUI construction. The Windows launcher preserves child output, startup stalls get a traceback log, and another network-window launch attempts foreground focus. An older v2 process must still be closed; active workspace locks are not removed blindly. No Windows protection setting is changed by the installer.

Known remaining release work: trusted signing and native Windows acceptance testing. Future discovery scope includes IPv6, richer mDNS/SSDP identification and managed background/multi-VLAN workflows; these are not active features in 3.0.
