"""
Port scanner — nmap subprocess wrapper.
Runs a full 65535-port scan with service/version detection.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Port:
    number: int
    protocol: str          # tcp / udp
    state: str             # open / closed / filtered
    service: str           # http, ssh, …
    product: str           # Apache, OpenSSH, …
    version: str           # 2.4.51, 8.9p1, …
    extra_info: str        # any extra nmap notes

    def display(self) -> str:
        parts = [self.service]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)


@dataclass
class ScanResult:
    host: str
    ip: str
    status: str            # up / down
    ports: list[Port] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]


# ── nmap helpers ─────────────────────────────────────────────────────────────

def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _parse_xml(xml_output: str) -> list[Port]:
    ports: list[Port] = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return ports

    for host_el in root.findall("host"):
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")

            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            if state not in ("open", "filtered"):
                continue

            ports.append(Port(
                number=int(port_el.get("portid", 0)),
                protocol=port_el.get("protocol", "tcp"),
                state=state,
                service=service_el.get("name", "") if service_el is not None else "",
                product=service_el.get("product", "") if service_el is not None else "",
                version=service_el.get("version", "") if service_el is not None else "",
                extra_info=service_el.get("extrainfo", "") if service_el is not None else "",
            ))
    return ports


def _get_ip(xml_output: str) -> str:
    try:
        root = ET.fromstring(xml_output)
        for host_el in root.findall("host"):
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv4":
                    return addr_el.get("addr", "")
    except Exception:
        pass
    return ""


def _get_status(xml_output: str) -> str:
    try:
        root = ET.fromstring(xml_output)
        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            if status_el is not None:
                return status_el.get("state", "unknown")
    except Exception:
        pass
    return "unknown"


# ── Public API ───────────────────────────────────────────────────────────────

def scan_host(
    host: str,
    ports: str = "1-65535",
    min_rate: int = 5000,
    timeout: int = 300,
) -> ScanResult:
    """
    Run nmap against `host` and return a ScanResult.

    Args:
        host:     hostname or IP
        ports:    port range string (default full scan)
        min_rate: nmap --min-rate (packets/sec). 5000 keeps full scan < 15 min
        timeout:  subprocess timeout in seconds
    """
    if not _nmap_available():
        return ScanResult(
            host=host, ip="", status="error",
            error="nmap not found — install it: https://nmap.org/download.html"
        )

    cmd = [
        "nmap",
        "-p", ports,
        "-sV",                         # service/version detection
        "--min-rate", str(min_rate),
        "-T4",                         # aggressive timing
        "-oX", "-",                    # XML to stdout
        "--open",                      # only open ports in output
        host,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        xml_out = proc.stdout
        if proc.returncode != 0 and not xml_out.strip():
            return ScanResult(host=host, ip="", status="error",
                              error=proc.stderr.strip() or "nmap exited with error")

        return ScanResult(
            host=host,
            ip=_get_ip(xml_out),
            status=_get_status(xml_out),
            ports=_parse_xml(xml_out),
        )

    except subprocess.TimeoutExpired:
        return ScanResult(host=host, ip="", status="error",
                          error=f"Scan timed out after {timeout}s")
    except Exception as exc:
        return ScanResult(host=host, ip="", status="error", error=str(exc))


def scan_hosts(
    hosts: list[str],
    ports: str = "1-65535",
    min_rate: int = 5000,
    timeout_per_host: int = 300,
) -> list[ScanResult]:
    """Scan a list of hosts sequentially (nmap is already parallelised internally)."""
    results: list[ScanResult] = []
    for host in hosts:
        results.append(scan_host(host, ports=ports, min_rate=min_rate, timeout=timeout_per_host))
    return results
