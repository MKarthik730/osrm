"""
Void Protocol — Communication Layer
========================================
After discovering devices, this protocol lets you:
  - Ping any device (TCP/UDP/ICMP)
  - Send custom commands
  - Query device info
  - Subscribe to device events
  - Broadcast to all devices

Frame format (8-byte header):
  +---------+---------+---------+---------+----------+-----------------+
  | Version | Type    | Flags   | SeqNum  | Length   | Payload         |
  | 1 byte  | 1 byte  | 1 byte  | 1 byte  | 2 bytes  | 0–65527 bytes   |
  +---------+---------+---------+---------+----------+-----------------+

All integers big-endian. Total header = 6 bytes.
"""

import asyncio
import struct
import socket
import subprocess
import platform
import time
import json
import os
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from discovery import Device

log = logging.getLogger("Void.Protocol")

# ─────────────────────────────────────────────
#  Frame definition
# ─────────────────────────────────────────────

VOID_VERSION = 0x01
VOID_PORT    = 9876       # default port your protocol listens on
HEADER_FMT      = "!BBBBH"  # version, type, flags, seq, length
HEADER_SIZE     = 6
MAX_PAYLOAD     = 65527

# Flags
FLAG_ACK        = 0x01
FLAG_COMPRESSED = 0x02
FLAG_BROADCAST  = 0x04
FLAG_ENCRYPTED  = 0x08

class MsgType:
    HELLO      = 0x01   # introduce yourself, get device info back
    HELLO_ACK  = 0x02   # response with device info
    PING       = 0x03   # alive check
    PONG       = 0x04   # alive response
    QUERY      = 0x05   # request a specific info field
    QUERY_RESP = 0x06   # response to query
    COMMAND    = 0x07   # send a command string
    CMD_RESP   = 0x08   # command result
    SUBSCRIBE  = 0x09   # subscribe to events from device
    EVENT      = 0x0A   # unsolicited event from device
    BROADCAST  = 0x0B   # message to all devices
    DISCONNECT = 0x0C   # graceful close
    ERROR      = 0xFF   # error response

MSG_NAMES = {v: k for k, v in MsgType.__dict__.items() if not k.startswith("_")}


@dataclass
class VoidFrame:
    type:    int
    payload: bytes = b""
    flags:   int   = 0
    seq:     int   = 0

    def encode(self) -> bytes:
        if len(self.payload) > MAX_PAYLOAD:
            raise ValueError("Payload too large")
        header = struct.pack(HEADER_FMT,
                             VOID_VERSION,
                             self.type,
                             self.flags,
                             self.seq & 0xFF,
                             len(self.payload))
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> "VoidFrame":
        if len(data) < HEADER_SIZE:
            raise ValueError("Frame too short")
        ver, ftype, flags, seq, length = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
        if ver != VOID_VERSION:
            raise ValueError(f"Unknown version: {ver}")
        payload = data[HEADER_SIZE: HEADER_SIZE + length]
        return cls(type=ftype, payload=payload, flags=flags, seq=seq)

    def __repr__(self):
        name = MSG_NAMES.get(self.type, f"0x{self.type:02X}")
        return f"Frame({name}, seq={self.seq}, payload={len(self.payload)}B)"


async def recv_frame(reader) -> VoidFrame:
    header = await reader.readexactly(HEADER_SIZE)
    _, _, _, _, length = struct.unpack(HEADER_FMT, header)
    payload = await reader.readexactly(length) if length else b""
    return VoidFrame.decode(header + payload)

async def send_frame(writer, frame: VoidFrame):
    writer.write(frame.encode())
    await writer.drain()


# ─────────────────────────────────────────────
#  Payload helpers
# ─────────────────────────────────────────────

def make_hello(device_name: str, capabilities: List[str]) -> bytes:
    return json.dumps({"name": device_name, "caps": capabilities,
                       "ts": int(time.time())}).encode()

def make_query(field: str) -> bytes:
    return field.encode()[:64]

def make_command(cmd: str, args: Dict = None) -> bytes:
    return json.dumps({"cmd": cmd, "args": args or {}}).encode()

def parse_json_payload(payload: bytes) -> Any:
    try:
        return json.loads(payload)
    except Exception:
        return payload.decode(errors="replace")


# ─────────────────────────────────────────────
#  ICMP / system ping
# ─────────────────────────────────────────────

def system_ping(ip: str, count=3, timeout=2) -> Dict:
    """Platform-aware ICMP ping. Returns latency stats."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=timeout * count + 2)
        # parse avg RTT
        m = None
        if system == "windows":
            import re
            m = re.search(r"Average = (\d+)ms", out)
            avg = float(m.group(1)) if m else None
        else:
            import re
            m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", out)
            avg = float(m.group(1)) if m else None
        return {"reachable": True, "avg_ms": avg, "output": out.strip().splitlines()[-1]}
    except Exception:
        return {"reachable": False, "avg_ms": None, "output": "timeout"}


# ─────────────────────────────────────────────
#  Void Client  (connects to one device)
# ─────────────────────────────────────────────

class VoidClient:
    """
    Connects to a device running VoidServer and lets you
    query, command, and subscribe to it.
    """

    def __init__(self, device: Device, port=VOID_PORT, timeout=10):
        self.device  = device
        self.host    = device.ip
        self.port    = port
        self.timeout = timeout
        self.reader  = None
        self.writer  = None
        self._seq    = 0
        self._connected = False
        self._listeners: List[Callable] = []

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFF
        return self._seq

    async def connect(self):
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), timeout=self.timeout
        )
        # Send HELLO
        hello = VoidFrame(
            type=MsgType.HELLO,
            payload=make_hello("Void-Controller", ["query", "command", "subscribe"]),
            seq=self._next_seq()
        )
        await send_frame(self.writer, hello)
        resp = await asyncio.wait_for(recv_frame(self.reader), timeout=self.timeout)
        if resp.type == MsgType.HELLO_ACK:
            info = parse_json_payload(resp.payload)
            log.info("Connected to %s → info: %s", self.device.name, info)
            self._connected = True
        return self

    async def ping(self) -> float:
        """Send protocol-level PING, return RTT in ms."""
        t0 = time.monotonic()
        await send_frame(self.writer, VoidFrame(type=MsgType.PING, seq=self._next_seq()))
        resp = await asyncio.wait_for(recv_frame(self.reader), timeout=self.timeout)
        rtt = (time.monotonic() - t0) * 1000
        if resp.type == MsgType.PONG:
            log.info("PONG from %s in %.1f ms", self.device.name, rtt)
        return rtt

    async def query(self, field: str) -> Any:
        """Query a specific field from the device (e.g. 'cpu', 'memory', 'temp')."""
        await send_frame(self.writer, VoidFrame(
            type=MsgType.QUERY, payload=make_query(field), seq=self._next_seq()
        ))
        resp = await asyncio.wait_for(recv_frame(self.reader), timeout=self.timeout)
        return parse_json_payload(resp.payload)

    async def command(self, cmd: str, args: Dict = None) -> Any:
        """Send a command string and get a result back."""
        await send_frame(self.writer, VoidFrame(
            type=MsgType.COMMAND, payload=make_command(cmd, args), seq=self._next_seq()
        ))
        resp = await asyncio.wait_for(recv_frame(self.reader), timeout=self.timeout)
        return parse_json_payload(resp.payload)

    async def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to events from this device."""
        self._listeners.append(callback)
        await send_frame(self.writer, VoidFrame(
            type=MsgType.SUBSCRIBE, payload=event_type.encode(), seq=self._next_seq()
        ))
        log.info("Subscribed to '%s' events from %s", event_type, self.device.name)

    async def listen(self):
        """Background loop — dispatches incoming events to listeners."""
        while self._connected:
            try:
                frame = await asyncio.wait_for(recv_frame(self.reader), timeout=60)
                if frame.type == MsgType.EVENT:
                    data = parse_json_payload(frame.payload)
                    for cb in self._listeners:
                        asyncio.create_task(cb(self.device, data))
                elif frame.type == MsgType.PING:
                    await send_frame(self.writer, VoidFrame(type=MsgType.PONG, seq=frame.seq))
            except asyncio.TimeoutError:
                await self.ping()
            except Exception:
                self._connected = False
                break

    async def disconnect(self):
        if self._connected:
            await send_frame(self.writer, VoidFrame(type=MsgType.DISCONNECT))
            self._connected = False
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


# ─────────────────────────────────────────────
#  Void Server  (runs on each target device)
# ─────────────────────────────────────────────

class VoidServer:
    """
    Runs on a device and responds to Void queries/commands.
    Deploy this on any device you want to be "reachable".
    """

    def __init__(self, port=VOID_PORT, device_name=None):
        self.port = port
        self.name = device_name or socket.gethostname()
        self.command_handlers: Dict[str, Callable] = {}
        self.query_handlers:   Dict[str, Callable] = {}
        self._subscribers:     Dict[str, List] = {}
        self._register_defaults()

    def _register_defaults(self):
        """Built-in query handlers."""
        import platform as pl
        self.query_handlers["hostname"] = lambda: socket.gethostname()
        self.query_handlers["os"]       = lambda: f"{pl.system()} {pl.release()}"
        self.query_handlers["uptime"]   = lambda: self._uptime()
        self.query_handlers["ip"]       = lambda: self._local_ip()
        self.query_handlers["time"]     = lambda: time.strftime("%Y-%m-%d %H:%M:%S")

    def _uptime(self) -> str:
        try:
            with open("/proc/uptime") as f:
                secs = float(f.read().split()[0])
            h, m = divmod(int(secs), 3600)
            return f"{h}h {m // 60}m"
        except Exception:
            return "unknown"

    def _local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "unknown"

    def on_query(self, field: str):
        """Decorator to register a query handler."""
        def decorator(fn):
            self.query_handlers[field] = fn
            return fn
        return decorator

    def on_command(self, cmd: str):
        """Decorator to register a command handler."""
        def decorator(fn):
            self.command_handlers[cmd] = fn
            return fn
        return decorator

    async def _handle(self, reader, writer):
        addr = writer.get_extra_info("peername", "?")
        log.info("Connection from %s", addr)
        try:
            while True:
                frame = await asyncio.wait_for(recv_frame(reader), timeout=120)

                if frame.type == MsgType.HELLO:
                    info = json.dumps({
                        "name": self.name,
                        "os": self.query_handlers["os"](),
                        "ip": self.query_handlers["ip"](),
                        "caps": list(self.command_handlers.keys()),
                        "queries": list(self.query_handlers.keys()),
                    }).encode()
                    await send_frame(writer, VoidFrame(
                        type=MsgType.HELLO_ACK, payload=info, seq=frame.seq
                    ))

                elif frame.type == MsgType.PING:
                    await send_frame(writer, VoidFrame(type=MsgType.PONG, seq=frame.seq))

                elif frame.type == MsgType.QUERY:
                    field = frame.payload.decode(errors="replace").strip()
                    handler = self.query_handlers.get(field)
                    result = handler() if handler else f"unknown field: {field}"
                    await send_frame(writer, VoidFrame(
                        type=MsgType.QUERY_RESP,
                        payload=json.dumps(result).encode(),
                        seq=frame.seq
                    ))

                elif frame.type == MsgType.COMMAND:
                    req = parse_json_payload(frame.payload)
                    cmd  = req.get("cmd", "") if isinstance(req, dict) else str(req)
                    args = req.get("args", {}) if isinstance(req, dict) else {}
                    handler = self.command_handlers.get(cmd)
                    if handler:
                        try:
                            result = await handler(args) if asyncio.iscoroutinefunction(handler) else handler(args)
                        except Exception as e:
                            result = {"error": str(e)}
                    else:
                        result = {"error": f"unknown command: {cmd}"}
                    await send_frame(writer, VoidFrame(
                        type=MsgType.CMD_RESP,
                        payload=json.dumps(result).encode(),
                        seq=frame.seq
                    ))

                elif frame.type == MsgType.SUBSCRIBE:
                    event_type = frame.payload.decode(errors="replace")
                    self._subscribers.setdefault(event_type, []).append(writer)
                    log.info("Subscribed: %s → %s", addr, event_type)

                elif frame.type == MsgType.DISCONNECT:
                    break

        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            log.error("Session error: %s", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass
            log.info("Session closed: %s", addr)

    async def broadcast_event(self, event_type: str, data: Any):
        """Push an event to all subscribers of event_type."""
        payload = json.dumps({"type": event_type, "data": data, "ts": time.time()}).encode()
        frame = VoidFrame(type=MsgType.EVENT, payload=payload)
        dead = []
        for writer in self._subscribers.get(event_type, []):
            try:
                await send_frame(writer, frame)
            except Exception:
                dead.append(writer)
        for w in dead:
            self._subscribers[event_type].remove(w)

    async def run(self):
        server = await asyncio.start_server(self._handle, "0.0.0.0", self.port)
        log.info("Void server '%s' on port %d", self.name, self.port)
        async with server:
            await server.serve_forever()


# ─────────────────────────────────────────────
#  Broadcast pinger — ping all discovered devices
# ─────────────────────────────────────────────

class BroadcastPinger:
    """
    Ping all devices (ICMP + protocol-level) and report results.
    """

    async def ping_all(self, devices: List[Device], protocol_port=VOID_PORT) -> List[Dict]:
        tasks = [self._ping_one(d, protocol_port) for d in devices if d.ip]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _ping_one(self, device: Device, port: int) -> Dict:
        result = {"device": device.name, "ip": device.ip, "mac": device.mac}

        # ICMP ping
        loop = asyncio.get_event_loop()
        icmp = await loop.run_in_executor(None, system_ping, device.ip)
        result["icmp"] = icmp

        # Protocol ping
        try:
            client = VoidClient(device, port=port, timeout=3)
            await client.connect()
            rtt = await client.ping()
            result["protocol_rtt_ms"] = round(rtt, 2)
            result["protocol"] = "ok"
            await client.disconnect()
        except Exception as e:
            result["protocol"] = f"not available ({e})"

        return result