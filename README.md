# sentinel

Passive internal network recon and credential harvesting framework.

Designed for homelab red team ops against segmented networks.

## Modules

- `sentinel.py` — core orchestrator
- `modules/recon.py` — host discovery, port scanning, service fingerprinting
- `modules/poison.py` — LLMNR/NBT-NS poisoning via Responder integration
- `modules/relay.py` — NTLM relay chain automation
- `modules/harvest.py` — credential extraction and hash cracking pipeline
- `modules/persist.py` — persistence mechanisms (cron, rc.local, systemd)
- `modules/exfil.py` — data exfiltration over covert channels

## Usage

```bash
python3 sentinel.py --target 10.10.10.0/24 --mode passive
python3 sentinel.py --target 10.10.10.0/24 --mode aggressive --relay
python3 sentinel.py --mode harvest --wordlist /usr/share/wordlists/rockyou.txt
```

## Requirements

- Python 3.10+
- Responder
- Impacket
- Nmap
- Hashcat (optional)
