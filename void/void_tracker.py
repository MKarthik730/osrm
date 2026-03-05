"""
Void — Ultimate LAN Tracker  v2.0
====================================
The most complete LAN device tracker possible.

Features:
  ✓ Continuous ARP scanning — finds every device
  ✓ Tracks devices by MAC (survives IP changes)
  ✓ Full device profiling (OS, ports, services, vendor)
  ✓ Real-time traffic per device (upload + download)
  ✓ Online/offline history with timestamps
  ✓ First seen / last seen / total sessions
  ✓ Rogue device alerts (unknown MAC joins network)
  ✓ Wake-on-LAN support
  ✓ Device labelling (give devices custom names)
  ✓ Export to JSON / CSV
  ✓ WebSocket live dashboard
  ✓ Desktop notifications on new device
  ✓ Persistent storage (survives restarts)

Install:
    pip install scapy websockets netifaces

Run (needs admin for packet capture):
    sudo python void_tracker.py          # Linux/macOS
    python void_tracker.py               # Windows as Administrator

Dashboard:
    http://localhost:9876
    http://<your-ip>:9876   (any device on LAN)
"""

import asyncio
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import ipaddress
import logging
import platform
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("Void.Tracker")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)-8s  %(message)s",
                    datefmt="%H:%M:%S")

try:
    import websockets
except ImportError:
    print("pip install websockets scapy netifaces"); sys.exit(1)

# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────

HTTP_PORT    = 9876
WS_PORT      = 9877
SCAN_INTERVAL   = 15    # ARP rescan every N seconds
OFFLINE_TIMEOUT = 60    # seconds before marking device offline
DB_FILE      = "void_tracker.db"
LABELS_FILE  = "void_labels.json"

# ─────────────────────────────────────────────
#  OUI vendor lookup
# ─────────────────────────────────────────────

OUI = {
    "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "28:CD:C1":"Apple","AC:BC:32":"Apple","F0:18:98":"Apple","3C:22:FB":"Apple",
    "A4:C3:F0":"Google","54:60:09":"Google","00:1A:11":"Google",
    "FC:AA:14":"Amazon","74:75:48":"Amazon","F0:27:2D":"Amazon",
    "EC:FA:BC":"Samsung","F4:7B:5E":"Samsung","50:32:37":"Huawei",
    "B4:FB:E4":"TP-Link","50:C7:BF":"TP-Link","14:CC:20":"TP-Link",
    "00:18:E7":"Netgear","C4:04:15":"Netgear","00:1E:2A":"Netgear",
    "00:17:88":"Philips Hue","00:1B:21":"Intel","8C:8D:28":"Intel",
    "58:44:98":"Xiaomi","78:11:DC":"Xiaomi","00:1C:BF":"Xiaomi",
    "00:14:BF":"Linksys","00:50:56":"VMware","00:0C:29":"VMware",
}

def get_vendor(mac: str) -> str:
    return OUI.get(mac.upper()[:8], "")

def get_icon(vendor: str, hostname: str) -> str:
    v = (vendor + hostname).lower()
    if any(x in v for x in ["apple","iphone","ipad","macbook"]): return "🍎"
    if any(x in v for x in ["samsung","android","pixel","huawei","xiaomi","oneplus"]): return "📱"
    if any(x in v for x in ["google","chromecast","nest"]): return "🔵"
    if any(x in v for x in ["amazon","echo","kindle","fire"]): return "📦"
    if any(x in v for x in ["tp-link","netgear","linksys","router","gateway"]): return "📡"
    if any(x in v for x in ["raspberry","pi"]): return "🍓"
    if any(x in v for x in ["philips","hue","bulb","light","iot"]): return "💡"
    if any(x in v for x in ["intel","laptop","desktop","pc","windows"]): return "💻"
    if any(x in v for x in ["vmware","virtual"]): return "🖥️"
    if any(x in v for x in ["printer","canon","epson","hp"]): return "🖨️"
    if any(x in v for x in ["tv","roku","firetv","appletv","shield"]): return "📺"
    return "📟"

# ─────────────────────────────────────────────
#  Device model
# ─────────────────────────────────────────────

@dataclass
class Device:
    mac:          str
    ip:           str   = ""
    hostname:     str   = ""
    vendor:       str   = ""
    icon:         str   = "📟"
    label:        str   = ""        # custom user label

    # Status
    online:       bool  = True
    first_seen:   float = field(default_factory=time.time)
    last_seen:    float = field(default_factory=time.time)
    last_offline: float = 0.0
    session_count: int  = 1
    total_online_secs: float = 0.0

    # Fingerprint
    os_guess:     str   = ""
    open_ports:   List[int]       = field(default_factory=list)
    services:     Dict[str,str]   = field(default_factory=dict)

    # Traffic
    bytes_in:     int   = 0
    bytes_out:    int   = 0
    speed_in:     float = 0.0
    speed_out:    float = 0.0
    history_in:   List[int] = field(default_factory=list)
    history_out:  List[int] = field(default_factory=list)

    # Internal
    _prev_in:     int   = field(default=0, repr=False)
    _prev_out:    int   = field(default=0, repr=False)
    _session_start: float = field(default_factory=time.time, repr=False)

    # Event log (last 100 events)
    events:       List[dict] = field(default_factory=list)

    def display_name(self) -> str:
        return self.label or self.hostname or self.ip or self.mac

    def add_event(self, kind: str, detail: str = ""):
        evt = {"ts": time.time(), "kind": kind, "detail": detail}
        self.events.append(evt)
        if len(self.events) > 100:
            self.events.pop(0)

    def mark_online(self, ip: str, hostname: str):
        was_offline = not self.online
        self.online    = True
        self.last_seen = time.time()
        if ip and ip != self.ip:
            if self.ip:
                self.add_event("ip_change", f"{self.ip} → {ip}")
            self.ip = ip
        if hostname and not self.hostname:
            self.hostname = hostname
        if was_offline:
            self.session_count   += 1
            self._session_start   = time.time()
            self.add_event("online", f"IP={ip}")
            if self.last_offline:
                gap = time.time() - self.last_offline
                log.info("BACK ONLINE  %s  (was offline %.0fs)", self.display_name(), gap)

    def mark_offline(self):
        if self.online:
            self.online       = False
            self.last_offline = time.time()
            self.total_online_secs += time.time() - self._session_start
            self.add_event("offline")
            log.info("OFFLINE      %s", self.display_name())

    def update_speed(self, elapsed: float):
        if elapsed > 0:
            self.speed_in  = (self.bytes_in  - self._prev_in)  / elapsed
            self.speed_out = (self.bytes_out - self._prev_out) / elapsed
        self._prev_in  = self.bytes_in
        self._prev_out = self.bytes_out
        self.history_in.append(round(self.speed_in))
        self.history_out.append(round(self.speed_out))
        if len(self.history_in)  > 60: self.history_in.pop(0)
        if len(self.history_out) > 60: self.history_out.pop(0)

    def uptime_pct(self) -> float:
        total = time.time() - self.first_seen
        online_secs = self.total_online_secs
        if self.online:
            online_secs += time.time() - self._session_start
        return round((online_secs / total * 100) if total > 0 else 0, 1)

    def to_dict(self) -> dict:
        return {
            "mac":          self.mac,
            "ip":           self.ip,
            "hostname":     self.hostname,
            "vendor":       self.vendor,
            "icon":         self.icon,
            "label":        self.label,
            "name":         self.display_name(),
            "online":       self.online,
            "first_seen":   self.first_seen,
            "last_seen":    self.last_seen,
            "last_offline": self.last_offline,
            "session_count":self.session_count,
            "uptime_pct":   self.uptime_pct(),
            "os_guess":     self.os_guess,
            "open_ports":   self.open_ports,
            "services":     self.services,
            "bytes_in":     self.bytes_in,
            "bytes_out":    self.bytes_out,
            "speed_in":     round(self.speed_in),
            "speed_out":    round(self.speed_out),
            "history_in":   self.history_in,
            "history_out":  self.history_out,
            "events":       self.events[-20:],
        }

# ─────────────────────────────────────────────
#  Database  (SQLite — persists across restarts)
# ─────────────────────────────────────────────

class Database:
    def __init__(self, path: str = DB_FILE):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._create()

    def _create(self):
        with self._lock:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                mac           TEXT PRIMARY KEY,
                ip            TEXT,
                hostname      TEXT,
                vendor        TEXT,
                label         TEXT DEFAULT '',
                os_guess      TEXT DEFAULT '',
                open_ports    TEXT DEFAULT '[]',
                services      TEXT DEFAULT '{}',
                first_seen    REAL,
                last_seen     REAL,
                last_offline  REAL DEFAULT 0,
                session_count INTEGER DEFAULT 1,
                total_online  REAL DEFAULT 0,
                bytes_in      INTEGER DEFAULT 0,
                bytes_out     INTEGER DEFAULT 0,
                trusted       INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS events (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                mac     TEXT,
                ts      REAL,
                kind    TEXT,
                detail  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_mac ON events(mac);
            CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(ts);
            """)
            self.conn.commit()

    def upsert_device(self, d: Device):
        with self._lock:
            self.conn.execute("""
            INSERT INTO devices
              (mac,ip,hostname,vendor,label,os_guess,open_ports,services,
               first_seen,last_seen,last_offline,session_count,total_online,bytes_in,bytes_out)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(mac) DO UPDATE SET
              ip=excluded.ip, hostname=excluded.hostname,
              label=excluded.label, os_guess=excluded.os_guess,
              open_ports=excluded.open_ports, services=excluded.services,
              last_seen=excluded.last_seen, last_offline=excluded.last_offline,
              session_count=excluded.session_count, total_online=excluded.total_online,
              bytes_in=excluded.bytes_in, bytes_out=excluded.bytes_out
            """, (
                d.mac, d.ip, d.hostname, d.vendor, d.label,
                d.os_guess, json.dumps(d.open_ports), json.dumps(d.services),
                d.first_seen, d.last_seen, d.last_offline,
                d.session_count, d.total_online_secs,
                d.bytes_in, d.bytes_out,
            ))
            self.conn.commit()

    def log_event(self, mac: str, kind: str, detail: str = ""):
        with self._lock:
            self.conn.execute(
                "INSERT INTO events (mac,ts,kind,detail) VALUES (?,?,?,?)",
                (mac, time.time(), kind, detail)
            )
            self.conn.commit()

    def load_all(self) -> List[dict]:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_events(self, mac: str = None, limit: int = 200) -> List[dict]:
        with self._lock:
            if mac:
                cur = self.conn.execute(
                    "SELECT * FROM events WHERE mac=? ORDER BY ts DESC LIMIT ?", (mac, limit))
            else:
                cur = self.conn.execute(
                    "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def set_label(self, mac: str, label: str):
        with self._lock:
            self.conn.execute("UPDATE devices SET label=? WHERE mac=?", (label, mac))
            self.conn.commit()

    def set_trusted(self, mac: str, trusted: bool):
        with self._lock:
            self.conn.execute("UPDATE devices SET trusted=? WHERE mac=?", (1 if trusted else 0, mac))
            self.conn.commit()

    def get_trusted(self) -> Set[str]:
        with self._lock:
            cur = self.conn.execute("SELECT mac FROM devices WHERE trusted=1")
            return {row[0] for row in cur.fetchall()}

# ─────────────────────────────────────────────
#  Network utilities
# ─────────────────────────────────────────────

def get_local_subnet() -> str:
    try:
        import netifaces
        gws = netifaces.gateways()
        iface = gws.get("default", {}).get(netifaces.AF_INET, [None,None])[1]
        if iface:
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET,[{}])[0]
            ip, mask = addrs.get("addr",""), addrs.get("netmask","255.255.255.0")
            if ip:
                return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))
    except Exception:
        pass
    # fallback: connect trick
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except Exception:
        return "192.168.1.0/24"

def get_my_macs() -> Set[str]:
    macs = set()
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_LINK, [{}])
            for a in addrs:
                mac = a.get("addr","").lower()
                if mac and mac != "00:00:00:00:00:00":
                    macs.add(mac)
    except Exception:
        pass
    return macs

def arp_scan(subnet: str) -> List[Tuple[str,str,str]]:
    """Returns list of (ip, mac, hostname)."""
    results = []
    # Try nmap first
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-PR", "--min-rate=1000", subnet],
            stderr=subprocess.DEVNULL, timeout=30, text=True
        )
        ip = hostname = ""
        for line in out.splitlines():
            m = re.search(r"Nmap scan report for (.+)", line)
            if m:
                raw = m.group(1)
                h = re.match(r"(.+?)\s+\((.+)\)", raw)
                hostname, ip = (h.group(1), h.group(2)) if h else ("", raw)
            m2 = re.search(r"MAC Address: ([0-9A-F:]{17})", line)
            if m2 and ip:
                results.append((ip, m2.group(1).lower(), hostname))
                ip = hostname = ""
        if results:
            return results
    except Exception:
        pass

    # Fallback: read ARP table
    try:
        out = subprocess.check_output(["arp", "-a"],
                                      stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})", line, re.I)
            if m:
                ip = m.group(1)
                mac = m.group(2).replace("-",":").lower()
                try:
                    h = socket.gethostbyaddr(ip)[0]
                except Exception:
                    h = ""
                results.append((ip, mac, h))
    except Exception:
        pass
    return results

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def wake_on_lan(mac: str) -> bool:
    """Send WoL magic packet to wake a sleeping device."""
    try:
        mac_bytes = bytes.fromhex(mac.replace(":","").replace("-",""))
        magic = b"\xFF" * 6 + mac_bytes * 16
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic, ("255.255.255.255", 9))
        sock.close()
        log.info("WoL magic packet sent to %s", mac)
        return True
    except Exception as e:
        log.error("WoL failed: %s", e)
        return False

def quick_port_scan(ip: str) -> Tuple[List[int], Dict[str,str]]:
    """Fast TCP connect scan on common ports."""
    COMMON_PORTS = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
        554:"RTSP", 1883:"MQTT", 3389:"RDP", 5000:"UPnP",
        5900:"VNC", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 9100:"Printer",
    }
    open_ports = []
    services = {}

    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                services[str(port)] = COMMON_PORTS.get(port, "unknown")
            s.close()
        except Exception:
            pass

    threads = [threading.Thread(target=check, args=(p,)) for p in COMMON_PORTS]
    for t in threads: t.start()
    for t in threads: t.join()
    return sorted(open_ports), services

# ─────────────────────────────────────────────
#  Packet Sniffer
# ─────────────────────────────────────────────

class Sniffer:
    def __init__(self, devices: Dict[str, Device], my_macs: Set[str]):
        self.devices  = devices
        self.my_macs  = my_macs
        self.running  = False
        self._lock    = threading.Lock()

    def start(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self.running = False

    def _run(self):
        try:
            import scapy.all as scapy
            def process(pkt):
                if not pkt.haslayer(scapy.Ether): return
                src  = pkt[scapy.Ether].src.lower()
                dst  = pkt[scapy.Ether].dst.lower()
                size = len(pkt)
                with self._lock:
                    if src in self.devices and src not in self.my_macs:
                        self.devices[src].bytes_out += size
                    if dst in self.devices and dst not in self.my_macs and dst != "ff:ff:ff:ff:ff:ff":
                        self.devices[dst].bytes_in += size
            scapy.sniff(prn=process, store=False,
                        stop_filter=lambda _: not self.running)
        except ImportError:
            self._raw_socket_fallback()
        except Exception as e:
            log.warning("Sniffer error: %s", e)

    def _raw_socket_fallback(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(1.0)
            while self.running:
                try:
                    data, _ = sock.recvfrom(65535)
                    if len(data) < 14: continue
                    dst  = ":".join(f"{b:02x}" for b in data[0:6])
                    src  = ":".join(f"{b:02x}" for b in data[6:12])
                    size = len(data)
                    with self._lock:
                        if src in self.devices: self.devices[src].bytes_out += size
                        if dst in self.devices and dst != "ff:ff:ff:ff:ff:ff":
                            self.devices[dst].bytes_in += size
                except socket.timeout:
                    continue
        except Exception as e:
            log.warning("Raw socket fallback error: %s", e)

# ─────────────────────────────────────────────
#  Core Tracker Engine
# ─────────────────────────────────────────────

class VoidTracker:
    def __init__(self):
        self.devices:  Dict[str, Device] = {}
        self.db        = Database()
        self.my_macs   = get_my_macs()
        self.subnet    = get_local_subnet()
        self.trusted   = self.db.get_trusted()
        self._lock     = threading.Lock()
        self._ws_clients: Set = set()
        self._last_speed_ts = time.time()
        self._alerts:  List[dict] = []
        self._sniffer  = None

        # Load saved devices from DB
        self._load_from_db()

    def _load_from_db(self):
        for row in self.db.load_all():
            mac = row["mac"]
            d = Device(
                mac          = mac,
                ip           = row["ip"] or "",
                hostname     = row["hostname"] or "",
                vendor       = row["vendor"] or "",
                label        = row["label"] or "",
                os_guess     = row["os_guess"] or "",
                open_ports   = json.loads(row["open_ports"] or "[]"),
                services     = json.loads(row["services"] or "{}"),
                first_seen   = row["first_seen"] or time.time(),
                last_seen    = row["last_seen"] or time.time(),
                last_offline = row["last_offline"] or 0,
                session_count= row["session_count"] or 1,
                total_online_secs = row["total_online"] or 0,
                bytes_in     = row["bytes_in"] or 0,
                bytes_out    = row["bytes_out"] or 0,
                online       = False,  # assume offline until confirmed
                icon         = get_icon(row["vendor"] or "", row["hostname"] or ""),
            )
            self.devices[mac] = d
        log.info("Loaded %d device(s) from database", len(self.devices))

    async def start(self):
        log.info("Subnet: %s", self.subnet)
        log.info("My MACs: %s", self.my_macs)

        # Initial scan
        await self._scan()

        # Start packet sniffer
        self._sniffer = Sniffer(self.devices, self.my_macs)
        self._sniffer.start()

        # Background tasks
        asyncio.create_task(self._scan_loop())
        asyncio.create_task(self._speed_loop())
        asyncio.create_task(self._offline_check_loop())
        asyncio.create_task(self._db_persist_loop())
        asyncio.create_task(self._fingerprint_loop())

    async def _scan(self):
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, arp_scan, self.subnet)
        now = time.time()

        for ip, mac, hostname in results:
            if mac in self.my_macs:
                continue

            with self._lock:
                if mac not in self.devices:
                    # Brand new device!
                    v = get_vendor(mac)
                    h = hostname or resolve_hostname(ip)
                    d = Device(
                        mac      = mac,
                        ip       = ip,
                        hostname = h,
                        vendor   = v,
                        icon     = get_icon(v, h),
                    )
                    d.add_event("discovered", f"IP={ip}")
                    self.devices[mac] = d
                    self.db.upsert_device(d)
                    self.db.log_event(mac, "discovered", f"IP={ip}")

                    # Alert if not trusted
                    alert = {
                        "ts":   now,
                        "kind": "new_device",
                        "mac":  mac,
                        "ip":   ip,
                        "vendor": v,
                        "name": h or ip,
                        "trusted": mac in self.trusted,
                    }
                    self._alerts.append(alert)
                    if len(self._alerts) > 100:
                        self._alerts.pop(0)

                    if mac not in self.trusted:
                        log.warning("🚨 NEW DEVICE: %s  %s  (%s)", mac, ip, v)
                    else:
                        log.info("✓ Known device: %s  %s  (%s)", mac, ip, v)
                else:
                    self.devices[mac].mark_online(ip, hostname)

    async def _scan_loop(self):
        while True:
            await asyncio.sleep(SCAN_INTERVAL)
            await self._scan()

    async def _speed_loop(self):
        while True:
            await asyncio.sleep(1)
            now = time.time()
            elapsed = now - self._last_speed_ts
            self._last_speed_ts = now
            with self._lock:
                for d in self.devices.values():
                    d.update_speed(elapsed)
            await self._broadcast()

    async def _offline_check_loop(self):
        while True:
            await asyncio.sleep(10)
            now = time.time()
            with self._lock:
                for d in self.devices.values():
                    if d.online and (now - d.last_seen) > OFFLINE_TIMEOUT:
                        d.mark_offline()
                        self.db.log_event(d.mac, "offline")

    async def _db_persist_loop(self):
        while True:
            await asyncio.sleep(30)
            with self._lock:
                for d in self.devices.values():
                    self.db.upsert_device(d)

    async def _fingerprint_loop(self):
        """Fingerprint new devices in background (doesn't block scanner)."""
        fingerprinted = set()
        while True:
            await asyncio.sleep(5)
            with self._lock:
                to_scan = [
                    d for d in self.devices.values()
                    if d.online and d.ip and d.mac not in fingerprinted and not d.open_ports
                ]
            for d in to_scan[:3]:   # scan max 3 at a time
                loop = asyncio.get_event_loop()
                ports, services = await loop.run_in_executor(None, quick_port_scan, d.ip)
                with self._lock:
                    d.open_ports = ports
                    d.services   = services
                fingerprinted.add(d.mac)
                log.info("Fingerprinted %s — ports: %s", d.display_name(), ports)

    # ── WebSocket broadcast ─────────────────────────────────────

    async def _broadcast(self):
        if not self._ws_clients:
            return
        payload = self._snapshot()
        dead = set()
        for ws in self._ws_clients:
            try:
                await ws.send(payload)
            except Exception:
                dead.add(ws)
        self._ws_clients -= dead

    def _snapshot(self) -> str:
        with self._lock:
            devices = [d.to_dict() for d in self.devices.values()]
        online  = sum(1 for d in self.devices.values() if d.online)
        offline = len(self.devices) - online
        return json.dumps({
            "type":      "update",
            "devices":   devices,
            "online":    online,
            "offline":   offline,
            "total":     len(self.devices),
            "alerts":    self._alerts[-10:],
            "total_in":  sum(d.speed_in  for d in self.devices.values()),
            "total_out": sum(d.speed_out for d in self.devices.values()),
            "ts":        time.time(),
        })

    # ── Commands from browser ───────────────────────────────────

    async def handle_command(self, cmd: dict) -> dict:
        action = cmd.get("action")

        if action == "label":
            mac = cmd.get("mac","")
            label = cmd.get("label","")
            with self._lock:
                if mac in self.devices:
                    self.devices[mac].label = label
            self.db.set_label(mac, label)
            return {"ok": True}

        elif action == "trust":
            mac = cmd.get("mac","")
            self.trusted.add(mac)
            self.db.set_trusted(mac, True)
            return {"ok": True}

        elif action == "untrust":
            mac = cmd.get("mac","")
            self.trusted.discard(mac)
            self.db.set_trusted(mac, False)
            return {"ok": True}

        elif action == "wol":
            mac = cmd.get("mac","")
            ok = wake_on_lan(mac)
            return {"ok": ok}

        elif action == "events":
            mac = cmd.get("mac")
            return {"events": self.db.get_events(mac)}

        elif action == "export_json":
            with self._lock:
                data = [d.to_dict() for d in self.devices.values()]
            return {"data": data}

        elif action == "scan_now":
            asyncio.create_task(self._scan())
            return {"ok": True}

        return {"error": "unknown action"}
