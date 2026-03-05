"""
Void Discovery Engine
=====================
Provides a lightweight async device discovery layer used by `main.py`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class Device:
    name: str
    device_type: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    rssi: Optional[int] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    mdns_type: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "Device":
        return cls(**data)


class DiscoveryEngine:
    def __init__(
        self,
        scan_lan: bool = True,
        scan_bt: bool = True,
        scan_ble: bool = True,
        scan_mdns: bool = True,
        nmap_fingerprint: bool = True,
    ):
        self.scan_lan = scan_lan
        self.scan_bt = scan_bt
        self.scan_ble = scan_ble
        self.scan_mdns = scan_mdns
        self.nmap_fingerprint = nmap_fingerprint
        self.registry: Dict[str, Device] = {}

    def _key(self, device: Device) -> str:
        return device.mac or device.ip or f"{device.device_type}:{device.name}"

    def _upsert(self, device: Device) -> None:
        self.registry[self._key(device)] = device

    async def run(self) -> List[Device]:
        tasks = []
        if self.scan_lan:
            tasks.append(self._scan_lan())
        if self.scan_mdns:
            tasks.append(self._scan_mdns())
        if self.scan_bt:
            tasks.append(self._scan_bluetooth())
        if self.scan_ble:
            tasks.append(self._scan_ble())

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for batch in results:
                if isinstance(batch, list):
                    for device in batch:
                        self._upsert(device)

        if not self.registry:
            fallback = self._local_fallback_device()
            if fallback:
                self._upsert(fallback)

        return list(self.registry.values())

    async def _scan_lan(self) -> List[Device]:
        devices: List[Device] = []
        local_ip = self._local_ip()
        if not local_ip:
            return devices

        hostname = socket.gethostname()
        devices.append(
            Device(
                name=hostname,
                device_type="wifi",
                ip=local_ip,
                hostname=hostname,
                vendor="Local",
                os_guess="Unknown",
            )
        )

        subnet = self._guess_subnet(local_ip)
        if subnet:
            probe_ips = [str(ip) for ip in subnet.hosts()][:24]
            sem = asyncio.Semaphore(30)

            async def probe(ip: str):
                async with sem:
                    if ip == local_ip:
                        return None
                    if await self._tcp_reachable(ip, 80) or await self._tcp_reachable(ip, 443):
                        return Device(name=ip, device_type="wifi", ip=ip)
                    return None

            found = await asyncio.gather(*(probe(ip) for ip in probe_ips), return_exceptions=True)
            for item in found:
                if isinstance(item, Device):
                    devices.append(item)

        return devices

    async def _scan_mdns(self) -> List[Device]:
        return []

    async def _scan_bluetooth(self) -> List[Device]:
        return []

    async def _scan_ble(self) -> List[Device]:
        return []

    async def _tcp_reachable(self, ip: str, port: int, timeout: float = 0.2) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    def _local_ip(self) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except Exception:
            return None

    def _guess_subnet(self, ip: str):
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return None
            network = ".".join(octets[:3]) + ".0/24"
            return ipaddress.ip_network(network, strict=False)
        except Exception:
            return None

    def _local_fallback_device(self) -> Optional[Device]:
        ip = self._local_ip()
        if not ip:
            return None
        host = socket.gethostname()
        return Device(name=host, device_type="wifi", ip=ip, hostname=host, vendor="Local")

    def save(self, path: str = "void_devices.json") -> None:
        payload = [device.to_dict() for device in self.registry.values()]
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load(self, path: str = "void_devices.json") -> None:
        p = Path(path)
        if not p.exists():
            return
        data = json.loads(p.read_text(encoding="utf-8"))
        self.registry = {}
        for item in data:
            device = Device.from_dict(item)
            self._upsert(device)
