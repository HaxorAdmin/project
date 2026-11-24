"""Connection collection and deterministic allowlist / detection logic."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import ipaddress
import json
import socket
import time
from pathlib import Path
import psutil

@dataclass(frozen=True)
class Connection:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    pid: int | None
    process: str
    process_started: float | None = None

    def key(self):
        return (self.protocol, self.local_address, self.local_port,
                self.remote_address, self.remote_port, self.pid, self.process_started)

@dataclass(frozen=True)
class Rule:
    network: object
    ports: tuple[int, ...] | None
    protocol: str

    def matches(self, connection):
        try:
            address = ipaddress.ip_address(connection.remote_address.split('%')[0])
        except ValueError:
            return False
        return (address in self.network and
                (self.ports is None or connection.remote_port in self.ports) and
                self.protocol in ('any', connection.protocol))

class Allowlist:
    def __init__(self, rules=()):
        self.rules = tuple(rules)

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(data, dict) or set(data) - {'version', 'rules'} or (type(data.get('version')) is not int or data.get('version') != 1) or not isinstance(data.get('rules'), list):
            raise ValueError('Allowlist requires version: 1 and a rules array.')
        rules = []
        for index, item in enumerate(data['rules'], 1):
            if not isinstance(item, dict) or set(item) - {'address','ports','protocol','note'}:
                raise ValueError(f'Rule {index}: unknown fields or invalid object.')
            try:
                network = ipaddress.ip_network(item['address'], strict=False)
                ports = item['ports']
                protocol = item.get('protocol', 'any')
                if protocol not in ('tcp', 'udp', 'any'):
                    raise ValueError('protocol must be tcp, udp or any')
                if ports != '*':
                    if not isinstance(ports, list) or not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
                        raise ValueError('ports must be a non-empty array of integers 1..65535, or "*"')
                    ports = tuple(ports)
                else:
                    ports = None
                rules.append(Rule(network, ports, protocol))
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f'Rule {index}: {exc}') from exc
        return cls(rules)

    def known(self, connection):
        return any(rule.matches(connection) for rule in self.rules)

def snapshot():
    """Return visible socket records and visibility warnings; never invent process names."""
    connections, warnings, cache = [], set(), {}
    try:
        raw = psutil.net_connections(kind='inet')
    except psutil.AccessDenied as exc:
        raise PermissionError('Connection access denied. Run an elevated terminal on your own machine.') from exc
    for entry in raw:
        pid = entry.pid
        if pid not in cache:
            name, started = 'unavailable', None
            if pid is not None:
                try:
                    process = psutil.Process(pid)
                    name, started = process.name(), process.create_time()
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    warnings.add('Some process details are unavailable (permissions or process exited).')
            else:
                warnings.add('Some sockets have no visible PID. OS permissions may limit visibility.')
            cache[pid] = name, started
        name, started = cache[pid]
        local = entry.laddr
        remote = entry.raddr
        connections.append(Connection(
            'tcp' if entry.type == socket.SOCK_STREAM else 'udp',
            local.ip if local else '', local.port if local else 0,
            remote.ip if remote else '', remote.port if remote else 0,
            entry.status, pid, name, started))
    return sorted(connections, key=lambda c: (c.protocol, c.pid or -1, c.local_address, c.local_port, c.remote_address, c.remote_port)), sorted(warnings)

class Detector:
    def __init__(self, allowlist, cooldown=300, burst_threshold=15, burst_window=30):
        self.allowlist = allowlist
        self.cooldown = cooldown
        self.threshold = burst_threshold
        self.window = burst_window
        self.last_alert = {}
        self.previous = set()
        self.events = defaultdict(deque)

    def inspect(self, connections, timestamp, now=None):
        now = time.monotonic() if now is None else now
        # Expire suppression state so long-running monitoring has bounded stale memory.
        self.last_alert = {k:v for k,v in self.last_alert.items() if now-v < self.cooldown}
        alerts, current = [], set()
        for connection in connections:
            current.add(connection.key())
            if not connection.remote_address:
                continue  # Listeners / unconnected UDP are logged, not foreign endpoints.
            process_key = (connection.pid, connection.process_started, connection.process)
            if connection.pid is not None and connection.key() not in self.previous:
                self.events[process_key].append(now)
            if not self.allowlist.known(connection):
                key = ('endpoint', process_key, connection.protocol, connection.remote_address, connection.remote_port)
                if key not in self.last_alert:
                    alerts.append(self.alert('unapproved_endpoint', connection, timestamp,
                        'Remote address / port / protocol is outside the allowlist. Review; this alone does not prove malware.'))
                    self.last_alert[key] = now
        for key in list(self.events):
            events = self.events[key]
            while events and now-events[0] >= self.window:
                events.popleft()
            if not events:
                del self.events[key]
                continue
            suppression = ('burst', key)
            if len(events) >= self.threshold and suppression not in self.last_alert:
                representative = next((c for c in connections if (c.pid,c.process_started,c.process)==key and c.remote_address), None)
                if representative:
                    alerts.append(self.alert('connection_burst', representative, timestamp,
                        f'{len(events)} newly observed socket records within {self.window:g}s; normal browsers can also cause bursts.'))
                    self.last_alert[suppression] = now
        self.previous = current
        return alerts

    @staticmethod
    def alert(kind, connection, timestamp, reason):
        return {'time':timestamp, 'kind':kind, 'severity':'review', **asdict(connection), 'reason':reason}

def demo_snapshot(scan_index=0):
    """Synthetic documentation addresses, never presented as live host evidence."""
    return [Connection('tcp','192.0.2.10',51000,'198.51.100.20',443,'ESTABLISHED',1200,'demo-browser',1),
            Connection('tcp','192.0.2.10',51001,'203.0.113.50',4444,'ESTABLISHED',2200,'demo-client',2),
            Connection('udp','127.0.0.1',5353,'',0,'NONE',3300,'demo-dns',3)]
