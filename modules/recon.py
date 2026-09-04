#!/usr/bin/env python3
"""
recon.py — host discovery, port scanning, service fingerprinting, SMB analysis
"""

import asyncio
import ipaddress
import json
import logging
import socket
import struct
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple

log = logging.getLogger("sentinel.recon")

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143,
    389, 443, 445, 464, 593, 636, 3268, 3269, 3306, 3389,
    5985, 5986, 8080, 8443, 8888, 9090, 47001
]

SERVICE_BANNERS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    464: "kpasswd",
    3268: "LDAP-GC",
    3269: "LDAPS-GC",
    3306: "MySQL",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
}


class ReconEngine:
    def __init__(self, target: str, iface: str, output_dir: Path):
        self.target = target
        self.iface = iface
        self.output_dir = output_dir
        self.results = {}

    async def discover_hosts(self) -> List[str]:
        """ICMP ping sweep with async concurrent probes"""
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            hosts = [str(h) for h in network.hosts()]
        except ValueError:
            hosts = [self.target]

        log.info(f"probing {len(hosts)} addresses")
        sem = asyncio.Semaphore(100)

        async def probe(ip):
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "ping", "-c1", "-W1", ip,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await proc.wait()
                    return ip if proc.returncode == 0 else None
                except Exception:
                    return None

        results = await asyncio.gather(*[probe(h) for h in hosts])
        live = [r for r in results if r]
        log.info(f"live hosts: {live}")
        return live

    async def fingerprint_services(self, hosts: List[str]) -> Dict[str, List[int]]:
        """TCP connect scan across common ports"""
        sem = asyncio.Semaphore(200)
        services = {h: [] for h in hosts}

        async def probe_port(host, port):
            async with sem:
                try:
                    conn = asyncio.open_connection(host, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=1.5)
                    writer.close()
                    await writer.wait_closed()
                    services[host].append(port)
                    log.debug(f"{host}:{port} open")
                except Exception:
                    pass

        tasks = [probe_port(h, p) for h in hosts for p in COMMON_PORTS]
        await asyncio.gather(*tasks)
        return services

    async def check_smb_signing(self, hosts: List[str]) -> List[str]:
        """Check SMB signing via raw negotiate protocol request"""
        signing_disabled = []

        for host in hosts:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, 445))

                # NetBIOS session request
                nb_session = b"\x00\x00\x00\x54"

                # SMB negotiate request
                smb_header = (
                    b"\xffSMB"          # magic
                    b"\x72"             # SMB_COM_NEGOTIATE
                    b"\x00" * 4        # status
                    b"\x18"             # flags
                    b"\x01\x28"        # flags2
                    b"\x00" * 12       # reserved
                    b"\xff\xff"        # tid
                    b"\x00\x00"        # pid
                    b"\x00\x00"        # uid
                    b"\x00\x00"        # mid
                )

                dialects = b"\x02NT LM 0.12\x00"
                word_count = b"\x00"
                byte_count = struct.pack("<H", len(dialects))

                packet = smb_header + word_count + byte_count + dialects
                nb_packet = struct.pack(">I", len(packet)) + packet

                sock.send(nb_packet)
                response = sock.recv(1024)
                sock.close()

                if len(response) > 39:
                    security_mode = response[39]
                    signing_required = bool(security_mode & 0x08)
                    if not signing_required:
                        signing_disabled.append(host)
                        log.info(f"{host}: SMB signing NOT required — relay target")

            except Exception as e:
                log.debug(f"{host} SMB probe failed: {e}")

        return signing_disabled

    def save_report(self, hosts, services, signing_disabled):
        report = {
            "hosts": hosts,
            "services": services,
            "smb_signing_disabled": signing_disabled,
            "service_names": {
                h: {str(p): SERVICE_BANNERS.get(p, "unknown") for p in ports}
                for h, ports in services.items()
            }
        }
        out = self.output_dir / "recon.json"
        out.write_text(json.dumps(report, indent=2))
        log.info(f"recon report saved to {out}")
