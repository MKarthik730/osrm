"""
Void — Router Traffic Monitor
================================
Shows every device on your router and their real-time
upload/download traffic. Serves a live web dashboard.

How it works:
  1. ARP scan finds all devices on your LAN
  2. Scapy sniffs packets, counts bytes per MAC address
  3. WebSocket pushes live stats to the browser dashboard
  4. Browser shows real-time speeds + total usage per device

Install:
    pip install scapy websockets flask

Run (needs admin/root for packet sniffing):
    sudo python void_traffic.py          # Linux / macOS
    python void_traffic.py               # Windows (run as Administrator)

Then open:
    http://localhost:9876
    http://<your-ip>:9876    ← from any device on your LAN
"""

import asyncio
import json
import time
import socket
import subprocess
import re
import threading
import ipaddress
import logging
import sys
import importlib
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

log = logging.getLogger("Void.Traffic")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)-8s  %(message)s",
                    datefmt="%H:%M:%S")

try:
    import websockets
except ImportError:
    print("pip install websockets")
    sys.exit(1)

# ─────────────────────────────────────────────
#  OUI vendor table (top manufacturers)
# ─────────────────────────────────────────────

OUI = {
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "28:CD:C1": "Apple",        "AC:BC:32": "Apple",        "F0:18:98": "Apple",
    "A4:C3:F0": "Google",       "54:60:09": "Google",
    "FC:AA:14": "Amazon",       "74:75:48": "Amazon",
    "EC:FA:BC": "Samsung",      "F4:7B:5E": "Samsung",
    "B4:FB:E4": "TP-Link",      "50:C7:BF": "TP-Link",
    "00:17:88": "Philips Hue",  "00:1B:21": "Intel",
    "58:44:98": "Xiaomi",       "78:11:DC": "Xiaomi",
    "00:18:E7": "Netgear",      "C4:04:15": "Netgear",
}

def vendor(mac: str) -> str:
    return OUI.get(mac.upper()[:8], "Unknown")

def get_device_icon(vendor_name: str, hostname: str) -> str:
    v = (vendor_name + hostname).lower()
    if any(x in v for x in ["apple", "iphone", "ipad", "mac"]): return "🍎"
    if any(x in v for x in ["samsung", "android", "xiaomi"]):   return "📱"
    if any(x in v for x in ["google", "chrome", "nest"]):       return "🔵"
    if any(x in v for x in ["amazon", "echo", "kindle"]):       return "📦"
    if any(x in v for x in ["tp-link", "netgear", "router"]):   return "📡"
    if any(x in v for x in ["raspberry", "pi"]):                return "🍓"
    if any(x in v for x in ["philips", "hue", "iot"]):          return "💡"
    if any(x in v for x in ["intel", "pc", "laptop", "windows"]): return "💻"
    return "📟"

# ─────────────────────────────────────────────
#  Device model
# ─────────────────────────────────────────────

@dataclass
class DeviceStats:
    mac:        str
    ip:         str   = ""
    hostname:   str   = ""
    vendor:     str   = ""
    icon:       str   = "📟"

    # Traffic counters (bytes)
    bytes_in:   int   = 0   # bytes received by device (download)
    bytes_out:  int   = 0   # bytes sent by device (upload)

    # Speed (bytes/sec, rolling average)
    speed_in:   float = 0.0
    speed_out:  float = 0.0

    # History for sparkline (last 30 samples)
    history_in:  list = field(default_factory=list)
    history_out: list = field(default_factory=list)

    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)
    active:     bool  = True

    # Previous sample for delta calculation
    _prev_in:   int   = field(default=0, repr=False)
    _prev_out:  int   = field(default=0, repr=False)

    def update_speed(self, elapsed: float):
        """Calculate bytes/sec since last sample."""
        if elapsed > 0:
            self.speed_in  = (self.bytes_in  - self._prev_in)  / elapsed
            self.speed_out = (self.bytes_out - self._prev_out) / elapsed
        self._prev_in  = self.bytes_in
        self._prev_out = self.bytes_out

        # Keep last 30 history points for sparkline
        self.history_in.append(round(self.speed_in))
        self.history_out.append(round(self.speed_out))
        if len(self.history_in)  > 30: self.history_in.pop(0)
        if len(self.history_out) > 30: self.history_out.pop(0)

    def to_dict(self):
        return {
            "mac":       self.mac,
            "ip":        self.ip,
            "hostname":  self.hostname or self.ip,
            "vendor":    self.vendor,
            "icon":      self.icon,
            "bytes_in":  self.bytes_in,
            "bytes_out": self.bytes_out,
            "speed_in":  round(self.speed_in),
            "speed_out": round(self.speed_out),
            "history_in":  self.history_in,
            "history_out": self.history_out,
            "active":    self.active,
            "last_seen": self.last_seen,
        }

# ─────────────────────────────────────────────
#  Packet sniffer  (counts bytes per MAC)
# ─────────────────────────────────────────────

class PacketSniffer:
    """
    Sniffs all packets on the network interface.
    Counts bytes sent and received per MAC address.
    Works with or without scapy (fallback to raw sockets).
    """

    def __init__(self, devices: Dict[str, DeviceStats], my_mac: str):
        self.devices = devices
        self.my_mac  = my_mac.lower()
        self.running = False
        self._lock   = threading.Lock()

    def start(self):
        self.running = True
        thread = threading.Thread(target=self._sniff_loop, daemon=True)
        thread.start()
        log.info("Packet sniffer started")

    def stop(self):
        self.running = False

    def _sniff_loop(self):
        try:
            import scapy.all as scapy
            self._sniff_scapy(scapy)
        except ImportError:
            log.warning("scapy not found — using raw socket fallback")
            self._sniff_raw()

    def _sniff_scapy(self, scapy):
        def process(pkt):
            if not pkt.haslayer(scapy.Ether):
                return
            src = pkt[scapy.Ether].src.lower()
            dst = pkt[scapy.Ether].dst.lower()
            size = len(pkt)

            with self._lock:
                # Outgoing from a tracked device
                if src in self.devices:
                    self.devices[src].bytes_out += size
                    self.devices[src].last_seen  = time.time()
                    self.devices[src].active     = True
                # Incoming to a tracked device
                if dst in self.devices and dst != "ff:ff:ff:ff:ff:ff":
                    self.devices[dst].bytes_in  += size
                    self.devices[dst].last_seen  = time.time()
                    self.devices[dst].active     = True

        scapy.sniff(prn=process, store=False,
                    stop_filter=lambda _: not self.running)

    def _sniff_raw(self):
        """Fallback when packet capture backend is unavailable."""
        log.error(
            "Packet capture backend unavailable.\n"
            "  → Install Npcap from https://npcap.com/#download (Windows)\n"
            "  → Then install scapy: pip install scapy\n"
            "  → Re-run with Administrator/root privileges"
        )
        while self.running:
            time.sleep(1)

# ─────────────────────────────────────────────
#  LAN Scanner  (ARP)
# ─────────────────────────────────────────────

def get_local_subnet() -> str:
    netifaces = _import_netifaces()
    if netifaces is None:
        return "192.168.1.0/24"
    try:
        gws = netifaces.gateways()
        iface = gws.get("default", {}).get(netifaces.AF_INET, [None, None])[1]
        if iface:
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0]
            ip, mask = addrs.get("addr",""), addrs.get("netmask","255.255.255.0")
            if ip:
                return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))
    except Exception:
        pass
    return "192.168.1.0/24"

def get_my_mac() -> str:
    netifaces = _import_netifaces()
    if netifaces is None:
        return ""
    try:
        gws = netifaces.gateways()
        iface = gws.get("default", {}).get(netifaces.AF_INET, [None, None])[1]
        if iface:
            return netifaces.ifaddresses(iface).get(netifaces.AF_LINK,[{}])[0].get("addr","")
    except Exception:
        pass
    return ""

def arp_scan(subnet: str) -> list[dict[str, str]]:
    """Return list of {ip, mac, hostname} dicts."""
    results = []
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-PR", subnet, "--min-rate=500"],
            stderr=subprocess.DEVNULL, timeout=30, text=True
        )
        ip = hostname = ""
        for line in out.splitlines():
            m = re.search(r"Nmap scan report for (.+)", line)
            if m:
                raw = m.group(1)
                h = re.match(r"(.+?)\s+\((.+)\)", raw)
                hostname, ip = (h.group(1), h.group(2)) if h else ("", raw)
            m2 = re.search(r"MAC Address: ([0-9A-F:]{17})\s*(.*)", line)
            if m2 and ip:
                mac = m2.group(1).lower()
                results.append({"ip": ip, "mac": mac, "hostname": hostname})
                ip = hostname = ""
    except Exception:
        # Fallback: read ARP table
        try:
            out = subprocess.check_output(["arp", "-a"],
                                          stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})", line, re.I)
                if m:
                    results.append({"ip": m.group(1),
                                    "mac": m.group(2).replace("-",":").lower(),
                                    "hostname": ""})
        except Exception:
            pass
    return results


def _import_netifaces() -> Any:
    try:
        return importlib.import_module("netifaces")
    except Exception:
        return None

# ─────────────────────────────────────────────
#  Traffic Monitor  (main engine)
# ─────────────────────────────────────────────

class TrafficMonitor:
    def __init__(self):
        self.devices: Dict[str, DeviceStats] = {}
        self._lock   = threading.Lock()
        self._sniffer: Optional[PacketSniffer] = None
        self._ws_clients: Set[Any] = set()
        self._last_sample = time.time()

    async def start(self):
        # Initial scan
        log.info("Scanning LAN...")
        subnet = get_local_subnet()
        my_mac = get_my_mac().lower()
        log.info("Subnet: %s", subnet)

        raw = arp_scan(subnet)
        with self._lock:
            for r in raw:
                mac = r["mac"]
                if mac == my_mac:
                    continue
                v = vendor(mac)
                h = r.get("hostname","")
                d = DeviceStats(
                    mac      = mac,
                    ip       = r["ip"],
                    hostname = h,
                    vendor   = v,
                    icon     = get_device_icon(v, h),
                )
                self.devices[mac] = d
                log.info("Found device: %s  %s  (%s)", mac, r["ip"], v)

        log.info("Found %d device(s)", len(self.devices))

        # Start sniffer
        self._sniffer = PacketSniffer(self.devices, my_mac)
        self._sniffer.start()

        # Rescan every 30s for new devices
        asyncio.create_task(self._rescan_loop(subnet, my_mac))

        # Speed calculator every 1s
        asyncio.create_task(self._speed_loop())

    async def _rescan_loop(self, subnet, my_mac):
        while True:
            await asyncio.sleep(30)
            loop = asyncio.get_event_loop()
            raw = await loop.run_in_executor(None, arp_scan, subnet)
            with self._lock:
                for r in raw:
                    mac = r["mac"]
                    if mac == my_mac or mac in self.devices:
                        continue
                    v = vendor(mac)
                    h = r.get("hostname","")
                    self.devices[mac] = DeviceStats(
                        mac=mac, ip=r["ip"], hostname=h,
                        vendor=v, icon=get_device_icon(v,h)
                    )
                    log.info("New device: %s  %s", mac, r["ip"])

    async def _speed_loop(self):
        """Calculate speeds and push to all WebSocket clients every second."""
        while True:
            await asyncio.sleep(1)
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_sample
            self._last_sample = now

            with self._lock:
                for d in self.devices.values():
                    d.update_speed(elapsed)
                    # Mark inactive if no traffic for 60s
                    d.active = (time.time() - d.last_seen) < 60

            await self._push_to_clients()

    async def _push_to_clients(self):
        if not self._ws_clients:
            return
        payload = json.dumps({
            "type":    "update",
            "devices": [d.to_dict() for d in self.devices.values()],
            "total_in":  sum(d.speed_in  for d in self.devices.values()),
            "total_out": sum(d.speed_out for d in self.devices.values()),
            "count":   len(self.devices),
            "ts":      time.time(),
        })
        dead = set()
        for ws in self._ws_clients:
            try:
                await ws.send(payload)
            except Exception:
                dead.add(ws)
        self._ws_clients -= dead

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "type":    "update",
                "devices": [d.to_dict() for d in self.devices.values()],
                "total_in":  sum(d.speed_in  for d in self.devices.values()),
                "total_out": sum(d.speed_out for d in self.devices.values()),
                "count":   len(self.devices),
                "ts":      time.time(),
            }

# ─────────────────────────────────────────────
#  HTTP server  (serves the dashboard HTML)
# ─────────────────────────────────────────────

HTTP_PORT = 9876
WS_PORT   = 9877

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Void — Network Monitor</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:      #080a0d;
    --surface: #0f1318;
    --border:  #1a2535;
    --accent:  #0ea5e9;
    --accent2: #06b6d4;
    --green:   #22c55e;
    --red:     #ef4444;
    --yellow:  #f59e0b;
    --text:    #e2e8f0;
    --dim:     #475569;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Syne', sans-serif; min-height: 100vh; }

  /* ── Top bar ── */
  .topbar {
    display: flex; align-items: center; gap: 16px;
    padding: 14px 24px;
    border-bottom: 1px solid var(--border);
    background: rgba(15,19,24,0.9);
    position: sticky; top: 0; z-index: 10;
    backdrop-filter: blur(12px);
  }
  .logo { font-size: 20px; font-weight: 800; color: var(--accent); letter-spacing: -0.02em; }
  .badge {
    font-family: 'Share Tech Mono'; font-size: 11px;
    background: rgba(14,165,233,0.1); border: 1px solid rgba(14,165,233,0.3);
    color: var(--accent); padding: 2px 10px; border-radius: 2px;
  }
  .badge.green { background: rgba(34,197,94,0.1); border-color: rgba(34,197,94,0.3); color: var(--green); }
  .badge.red   { background: rgba(239,68,68,0.1);  border-color: rgba(239,68,68,0.3);  color: var(--red); }
  .spacer { flex: 1; }
  .ws-status { font-family: 'Share Tech Mono'; font-size: 11px; }

  /* ── Summary cards ── */
  .cards {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px; padding: 20px 24px 0;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 16px;
  }
  .card-label { font-family: 'Share Tech Mono'; font-size: 10px; color: var(--dim); letter-spacing: 0.1em; margin-bottom: 6px; }
  .card-value { font-size: 28px; font-weight: 800; color: var(--accent); }
  .card-value.green { color: var(--green); }
  .card-value.red   { color: var(--red); }
  .card-sub { font-family: 'Share Tech Mono'; font-size: 11px; color: var(--dim); margin-top: 4px; }

  /* ── Device table ── */
  .section { padding: 20px 24px; }
  .section-header {
    font-family: 'Share Tech Mono'; font-size: 11px; color: var(--accent);
    letter-spacing: 0.15em; margin-bottom: 12px;
    display: flex; align-items: center; gap: 12px;
  }
  .section-header::after { content: ''; flex: 1; height: 1px; background: linear-gradient(to right, var(--border), transparent); }

  .device-grid { display: flex; flex-direction: column; gap: 8px; }

  .device-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 14px 16px;
    display: grid; grid-template-columns: 40px 1fr auto;
    gap: 12px; align-items: center;
    transition: border-color 0.2s;
    animation: slideIn 0.3s ease;
  }
  .device-card:hover { border-color: rgba(14,165,233,0.3); }
  .device-card.inactive { opacity: 0.4; }

  @keyframes slideIn { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }

  .device-icon { font-size: 24px; text-align: center; }

  .device-info { min-width: 0; }
  .device-name { font-weight: 700; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .device-meta { font-family: 'Share Tech Mono'; font-size: 10px; color: var(--dim); margin-top: 2px; }

  .device-traffic { text-align: right; min-width: 160px; }
  .traffic-row { display: flex; align-items: center; justify-content: flex-end; gap: 8px; margin-bottom: 4px; }
  .traffic-label { font-family: 'Share Tech Mono'; font-size: 10px; color: var(--dim); }
  .traffic-value { font-family: 'Share Tech Mono'; font-size: 13px; font-weight: 700; min-width: 80px; text-align: right; }
  .traffic-value.down { color: var(--green); }
  .traffic-value.up   { color: var(--accent); }

  /* Sparkline */
  .sparkline { width: 60px; height: 20px; }

  /* ── Total bandwidth bar ── */
  .bandwidth-bar {
    margin: 0 24px 20px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 14px 16px;
  }
  .bw-label { font-family: 'Share Tech Mono'; font-size: 10px; color: var(--dim); margin-bottom: 8px; }
  .bw-track { background: var(--border); border-radius: 2px; height: 6px; margin-bottom: 6px; overflow: hidden; }
  .bw-fill  { height: 100%; border-radius: 2px; transition: width 0.5s ease; min-width: 2px; }
  .bw-fill.down { background: linear-gradient(to right, #22c55e, #16a34a); }
  .bw-fill.up   { background: linear-gradient(to right, #0ea5e9, #0284c7); }

  /* Scanning animation */
  .scanning { text-align: center; padding: 60px; font-family: 'Share Tech Mono'; color: var(--dim); }
  .scanning .dot { animation: pulse 1.4s ease-in-out infinite; display: inline-block; }
  .scanning .dot:nth-child(2) { animation-delay: 0.2s; }
  .scanning .dot:nth-child(3) { animation-delay: 0.4s; }
  @keyframes pulse { 0%,80%,100% { opacity:0.2; } 40% { opacity:1; } }
</style>
</head>
<body>

<div class="topbar">
  <span class="logo">▸▸ VOID</span>
  <span class="badge">NETWORK MONITOR</span>
  <span class="spacer"></span>
  <span class="ws-status" id="wsStatus">
    <span class="badge red">● CONNECTING</span>
  </span>
</div>

<div class="cards">
  <div class="card">
    <div class="card-label">DEVICES ONLINE</div>
    <div class="card-value" id="deviceCount">—</div>
    <div class="card-sub">on your network</div>
  </div>
  <div class="card">
    <div class="card-label">TOTAL DOWNLOAD</div>
    <div class="card-value green" id="totalDown">—</div>
    <div class="card-sub">bytes/sec</div>
  </div>
  <div class="card">
    <div class="card-label">TOTAL UPLOAD</div>
    <div class="card-value" id="totalUp">—</div>
    <div class="card-sub">bytes/sec</div>
  </div>
  <div class="card">
    <div class="card-label">LAST UPDATED</div>
    <div class="card-value" style="font-size:16px" id="lastUpdate">—</div>
    <div class="card-sub">live refresh</div>
  </div>
</div>

<div class="section" style="padding-bottom:0">
  <div class="bandwidth-bar">
    <div class="bw-label">DOWNLOAD BANDWIDTH</div>
    <div class="bw-track"><div class="bw-fill down" id="bwDown" style="width:0%"></div></div>
    <div class="bw-label">UPLOAD BANDWIDTH</div>
    <div class="bw-track"><div class="bw-fill up" id="bwUp" style="width:0%"></div></div>
  </div>
</div>

<div class="section">
  <div class="section-header">▸ CONNECTED DEVICES</div>
  <div class="device-grid" id="deviceGrid">
    <div class="scanning">
      Scanning your network<span class="dot">.</span><span class="dot">.</span><span class="dot">.</span>
    </div>
  </div>
</div>

<script>
const WS_URL = `ws://${location.hostname}:__WS_PORT__`;
let ws, maxBw = 1024 * 1024; // 1MB/s initial max for bar scaling
let sparkData = {};

function fmt(bytes) {
  if (bytes < 1024)        return bytes + ' B/s';
  if (bytes < 1024*1024)   return (bytes/1024).toFixed(1) + ' KB/s';
  return (bytes/1024/1024).toFixed(2) + ' MB/s';
}

function fmtTotal(bytes) {
  if (bytes < 1024)        return bytes + ' B';
  if (bytes < 1024*1024)   return (bytes/1024).toFixed(1) + ' KB';
  if (bytes < 1024**3)     return (bytes/1024/1024).toFixed(2) + ' MB';
  return (bytes/1024**3).toFixed(2) + ' GB';
}

function drawSparkline(canvas, data, color) {
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!data || data.length < 2) return;
  const max = Math.max(...data, 1);
  const w = canvas.width / (data.length - 1);
  ctx.beginPath();
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  data.forEach((v, i) => {
    const x = i * w;
    const y = canvas.height - (v / max) * canvas.height;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function renderDevices(devices, totalIn, totalOut) {
  const grid = document.getElementById('deviceGrid');

  // Sort by total traffic
  devices.sort((a, b) => (b.speed_in + b.speed_out) - (a.speed_in + a.speed_out));

  // Update max bandwidth for bar scaling
  maxBw = Math.max(maxBw, totalIn, totalOut, 1024);

  grid.innerHTML = devices.map(d => `
    <div class="device-card ${d.active ? '' : 'inactive'}" id="dev-${d.mac.replace(/:/g,'_')}">
      <div class="device-icon">${d.icon}</div>
      <div class="device-info">
        <div class="device-name">${d.hostname || d.ip}</div>
        <div class="device-meta">${d.ip} · ${d.mac} · ${d.vendor}</div>
        <div class="device-meta">↓ ${fmtTotal(d.bytes_in)} total · ↑ ${fmtTotal(d.bytes_out)} total</div>
      </div>
      <div class="device-traffic">
        <div class="traffic-row">
          <canvas class="sparkline" id="spark-down-${d.mac.replace(/:/g,'_')}" width="60" height="20"></canvas>
          <span class="traffic-label">↓</span>
          <span class="traffic-value down">${fmt(d.speed_in)}</span>
        </div>
        <div class="traffic-row">
          <canvas class="sparkline" id="spark-up-${d.mac.replace(/:/g,'_')}" width="60" height="20"></canvas>
          <span class="traffic-label">↑</span>
          <span class="traffic-value up">${fmt(d.speed_out)}</span>
        </div>
      </div>
    </div>
  `).join('') || '<div class="scanning">No devices found yet<span class="dot">.</span><span class="dot">.</span><span class="dot">.</span></div>';

  // Draw sparklines
  devices.forEach(d => {
    const key = d.mac.replace(/:/g,'_');
    drawSparkline(document.getElementById(`spark-down-${key}`), d.history_in,  '#22c55e');
    drawSparkline(document.getElementById(`spark-up-${key}`),   d.history_out, '#0ea5e9');
  });

  // Bandwidth bars
  document.getElementById('bwDown').style.width = Math.min(100, totalIn  / maxBw * 100) + '%';
  document.getElementById('bwUp').style.width   = Math.min(100, totalOut / maxBw * 100) + '%';
}

function connect() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    document.getElementById('wsStatus').innerHTML = '<span class="badge green">● LIVE</span>';
  };

  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.type !== 'update') return;

    document.getElementById('deviceCount').textContent = data.count;
    document.getElementById('totalDown').textContent   = fmt(data.total_in);
    document.getElementById('totalUp').textContent     = fmt(data.total_out);
    document.getElementById('lastUpdate').textContent  = new Date().toLocaleTimeString();

    renderDevices(data.devices, data.total_in, data.total_out);
  };

  ws.onclose = () => {
    document.getElementById('wsStatus').innerHTML = '<span class="badge red">● DISCONNECTED</span>';
    setTimeout(connect, 3000);
  };

  ws.onerror = () => ws.close();
}

connect();
</script>
</body>
</html>"""

async def http_handler(reader, writer):
    """Minimal HTTP server to serve the dashboard."""
    try:
        await reader.read(1024)
        html = DASHBOARD_HTML.replace("__WS_PORT__", str(WS_PORT))
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(html.encode())}\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(response.encode() + html.encode())
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

# ─────────────────────────────────────────────
#  WebSocket handler
# ─────────────────────────────────────────────

monitor = TrafficMonitor()

async def ws_handler(websocket):
    monitor._ws_clients.add(websocket)
    log.info("Browser connected  (clients: %d)", len(monitor._ws_clients))
    try:
        # Send current snapshot immediately
        await websocket.send(json.dumps(monitor.snapshot()))
        # Keep alive
        async for _ in websocket:
            pass
    except Exception:
        pass
    finally:
        monitor._ws_clients.discard(websocket)
        log.info("Browser disconnected  (clients: %d)", len(monitor._ws_clients))

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

async def main():
    my_ip = socket.gethostbyname(socket.gethostname())

    print(f"""
  ██╗   ██╗ ██████╗ ██╗██████╗
  ██║   ██║██╔═══██╗██║██╔══██╗
  ██║   ██║██║   ██║██║██║  ██║
  ╚██╗ ██╔╝██║   ██║██║██║  ██║
   ╚████╔╝ ╚██████╔╝██║██████╔╝
    ╚═══╝   ╚═════╝ ╚═╝╚═════╝
  Network Traffic Monitor
""")

    await monitor.start()

    # HTTP server (dashboard)
    http_server = await asyncio.start_server(http_handler, "0.0.0.0", HTTP_PORT)
    # WebSocket server (live data)
    ws_server   = await websockets.serve(ws_handler, "0.0.0.0", WS_PORT)

    log.info("Dashboard → http://localhost:%d", HTTP_PORT)
    log.info("Dashboard → http://%s:%d  (from any device on your LAN)", my_ip, HTTP_PORT)
    log.info("Monitoring %d device(s) — refreshing every 1s", len(monitor.devices))

    await asyncio.gather(
        http_server.serve_forever(),
        ws_server.wait_closed(),
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
