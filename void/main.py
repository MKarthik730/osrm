"""
Void — Main Runner
======================
Run this on your machine to:
  1. Discover all nearby devices (WiFi, Bluetooth, BLE, mDNS)
  2. Ping every discovered device
  3. Query info from devices running Void server
  4. Interactive shell to send commands

Usage:
    python main.py                  # full scan
    python main.py --no-bt          # skip Bluetooth
    python main.py --no-fingerprint # skip nmap (faster)
    python main.py server           # run as Void server
    python main.py demo             # run a local demo (no scan needed)

Install dependencies first:
    pip install python-nmap bleak netifaces zeroconf
    sudo apt install nmap    # Linux
    brew install nmap        # macOS
"""

import asyncio
import sys
import os
import json
import time
import logging
import argparse
import socket

sys.path.insert(0, os.path.dirname(__file__))
from discovery import DiscoveryEngine, Device
from protocol import (
    VoidServer, VoidClient, BroadcastPinger,
    VOID_PORT, system_ping
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("Void")

# ── Pretty printer ─────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
BLUE   = "\033[94m"

TYPE_COLORS = {
    "wifi":      CYAN,
    "bluetooth": YELLOW,
    "ble":       "\033[95m",
    "mdns":      GREEN,
}

def print_banner():
    print(f"""
{BOLD}{CYAN}
  ██╗   ██╗ ██████╗ ██╗██████╗
  ██║   ██║██╔═══██╗██║██╔══██╗
  ██║   ██║██║   ██║██║██║  ██║
  ╚██╗ ██╔╝██║   ██║██║██║  ██║
   ╚████╔╝ ╚██████╔╝██║██████╔╝
    ╚═══╝   ╚═════╝ ╚═╝╚═════╝
{RESET}{DIM}  Device Discovery & Communication Protocol{RESET}
""")

def print_device(d: Device, index: int):
    color = TYPE_COLORS.get(d.device_type, RESET)
    badge = f"{color}[{d.device_type.upper():9s}]{RESET}"
    name  = f"{BOLD}{d.name}{RESET}"
    print(f"  {index:>3}.  {badge}  {name}")
    if d.ip:       print(f"         {DIM}IP        {RESET}{d.ip}")
    if d.mac:      print(f"         {DIM}MAC       {RESET}{d.mac}")
    if d.hostname and d.hostname != d.name:
                   print(f"         {DIM}Hostname  {RESET}{d.hostname}")
    if d.vendor:   print(f"         {DIM}Vendor    {RESET}{d.vendor}")
    if d.os_guess: print(f"         {DIM}OS        {RESET}{d.os_guess}")
    if d.rssi is not None:
                   bar = "█" * max(1, int((d.rssi + 100) / 10))
                   print(f"         {DIM}Signal    {RESET}{bar} {d.rssi} dBm")
    if d.open_ports:
        svc_list = [f"{p}({d.services.get(str(p), '?')})" for p in d.open_ports[:6]]
        print(f"         {DIM}Ports     {RESET}{', '.join(svc_list)}")
    if d.mdns_type:
                   print(f"         {DIM}mDNS      {RESET}{d.mdns_type}")
    print()

def print_ping_result(r: dict):
    icmp = r.get("icmp", {})
    ok   = icmp.get("reachable", False)
    ms   = icmp.get("avg_ms")
    proto = r.get("protocol", "not available")
    proto_rtt = r.get("protocol_rtt_ms")

    status = f"{GREEN}●{RESET}" if ok else f"{RED}✗{RESET}"
    ms_str = f"{ms:.1f}ms" if ms else "timeout"
    proto_str = (f"{GREEN}ok  {proto_rtt}ms{RESET}" if proto == "ok"
                 else f"{DIM}{proto}{RESET}")

    print(f"  {status}  {r['device']:<28s}  {r['ip']:<16s}  ICMP={ms_str:<12}  Protocol={proto_str}")


# ── Scan ──────────────────────────────────────────────────────

async def do_scan(args) -> list:
    engine = DiscoveryEngine(
        scan_lan         = not args.no_lan,
        scan_bt          = not args.no_bt,
        scan_ble         = not args.no_bt,
        scan_mdns        = True,
        nmap_fingerprint = not args.no_fingerprint,
    )

    print(f"{BOLD}Scanning...{RESET}  (WiFi/LAN={'on' if not args.no_lan else 'off'}  "
          f"Bluetooth={'on' if not args.no_bt else 'off'}  "
          f"nmap={'on' if not args.no_fingerprint else 'off'})\n")

    t0 = time.time()
    devices = await engine.run()
    elapsed = time.time() - t0

    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}  Found {len(devices)} device(s) in {elapsed:.1f}s{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}\n")

    for i, d in enumerate(devices, 1):
        print_device(d, i)

    engine.save("void_devices.json")
    print(f"{DIM}  Saved to devices.json{RESET}\n")
    return devices


# ── Ping all ──────────────────────────────────────────────────

async def do_ping_all(devices: list):
    print(f"\n{BOLD}Pinging {len(devices)} device(s)...{RESET}\n")
    pinger = BroadcastPinger()
    results = await pinger.ping_all(devices)
    for r in results:
        print_ping_result(r)
    print()


# ── Interactive shell ─────────────────────────────────────────

async def interactive_shell(devices: list):
    if not devices:
        print("No devices to interact with.")
        return

    while True:
        print(f"\n{BOLD}Commands:{RESET}  list | ping <#> | query <#> <field> | connect <#> | quit")
        try:
            line = await asyncio.get_event_loop().run_in_executor(None, input, "> ")
        except (EOFError, KeyboardInterrupt):
            break

        parts = line.strip().split()
        if not parts:
            continue
        cmd = parts[0].lower()

        if cmd == "quit":
            break

        elif cmd == "list":
            for i, d in enumerate(devices, 1):
                color = TYPE_COLORS.get(d.device_type, "")
                print(f"  {i:>2}. {color}[{d.device_type}]{RESET}  {d.name}  {d.ip or ''}  {d.mac or ''}")

        elif cmd == "ping" and len(parts) >= 2:
            try:
                idx = int(parts[1]) - 1
                d = devices[idx]
                if not d.ip:
                    print(f"  {YELLOW}No IP for {d.name}{RESET}")
                    continue
                print(f"  Pinging {d.name} ({d.ip})...")
                r = system_ping(d.ip, count=4)
                status = f"{GREEN}reachable{RESET}" if r["reachable"] else f"{RED}unreachable{RESET}"
                print(f"  {status}  avg={r['avg_ms']}ms" if r["avg_ms"] else f"  {status}")
            except (IndexError, ValueError):
                print("  Invalid device number")

        elif cmd == "query" and len(parts) >= 3:
            try:
                idx   = int(parts[1]) - 1
                field = parts[2]
                d = devices[idx]
                if not d.ip:
                    print(f"  {YELLOW}No IP for {d.name}{RESET}")
                    continue
                client = VoidClient(d, port=VOID_PORT, timeout=5)
                await client.connect()
                result = await client.query(field)
                print(f"  {field}: {result}")
                await client.disconnect()
            except (IndexError, ValueError):
                print("  Usage: query <device#> <field>")
            except Exception as e:
                print(f"  {RED}Error: {e}{RESET}")

        elif cmd == "connect" and len(parts) >= 2:
            try:
                idx = int(parts[1]) - 1
                d = devices[idx]
                if not d.ip:
                    print(f"  {YELLOW}No IP for {d.name}{RESET}")
                    continue
                print(f"  Connecting to {d.name} ({d.ip}:{VOID_PORT})...")
                client = VoidClient(d, port=VOID_PORT, timeout=5)
                await client.connect()
                print(f"  {GREEN}Connected!{RESET}  Type commands (exit to quit):")
                while True:
                    try:
                        sub = await asyncio.get_event_loop().run_in_executor(None, input, f"  [{d.name}]> ")
                    except (EOFError, KeyboardInterrupt):
                        break
                    sub = sub.strip()
                    if sub == "exit": break
                    if sub.startswith("query "):
                        r = await client.query(sub[6:].strip())
                        print(f"  → {r}")
                    elif sub.startswith("cmd "):
                        r = await client.command(sub[4:].strip())
                        print(f"  → {r}")
                    elif sub == "ping":
                        rtt = await client.ping()
                        print(f"  → {rtt:.1f}ms")
                    else:
                        print(f"  Commands: query <field> | cmd <command> | ping | exit")
                await client.disconnect()
            except (IndexError, ValueError):
                print("  Invalid device number")
            except Exception as e:
                print(f"  {RED}Could not connect: {e}{RESET}  (Is Void server running on that device?)")

        else:
            print(f"  Unknown command: {cmd}")


# ── Server mode ───────────────────────────────────────────────

async def run_server():
    server = VoidServer(port=VOID_PORT)

    # Register custom query handlers
    @server.on_query("cpu")
    def cpu_usage():
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            vals = list(map(int, line.split()[1:]))
            idle = vals[3]
            total = sum(vals)
            return f"{100 - (idle * 100 // total)}%"
        except Exception:
            return "unavailable"

    @server.on_query("memory")
    def memory_info():
        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()
            info = {l.split(":")[0]: int(l.split()[1]) for l in lines[:3]}
            used = info["MemTotal"] - info["MemFree"]
            return f"{used // 1024}MB / {info['MemTotal'] // 1024}MB"
        except Exception:
            return "unavailable"

    # Register custom command handlers
    @server.on_command("echo")
    def echo_cmd(args):
        return {"echo": args.get("text", "")}

    @server.on_command("whoami")
    def whoami_cmd(args):
        return {"user": os.getenv("USER", "unknown"), "host": socket.gethostname()}

    print(f"\n{BOLD}{GREEN}Void Server running on port {VOID_PORT}{RESET}")
    print(f"  Queries available:  {', '.join(server.query_handlers.keys())}")
    print(f"  Commands available: {', '.join(server.command_handlers.keys())}\n")

    await server.run()


# ── Entry point ───────────────────────────────────────────────

async def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Void — Device Discovery & Protocol")
    parser.add_argument("mode", nargs="?", default="scan", choices=["scan", "server", "ping"])
    parser.add_argument("--no-bt",          action="store_true", help="Skip Bluetooth scanning")
    parser.add_argument("--no-lan",         action="store_true", help="Skip LAN/WiFi scanning")
    parser.add_argument("--no-fingerprint", action="store_true", help="Skip nmap OS/port scan (faster)")
    parser.add_argument("--load",           action="store_true", help="Load devices from devices.json instead of scanning")
    args = parser.parse_args()

    if args.mode == "server":
        await run_server()
        return

    if args.mode == "ping" or args.load:
        engine = DiscoveryEngine()
        engine.load("void_devices.json")
        devices = list(engine.registry.values())
        if not devices:
            print(f"{YELLOW}No saved devices. Run without --load first.{RESET}")
            return
    else:
        devices = await do_scan(args)

    if devices:
        await do_ping_all(devices)
        await interactive_shell(devices)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")