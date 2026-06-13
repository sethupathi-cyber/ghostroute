"""
ghostroute/modules/tor_routing.py
==================================
System-wide Tor transparent proxy routing via Linux iptables.

This module implements AnonSurf-style traffic redirection:
  - A custom iptables NAT chain (GHOSTROUTE) intercepts all outgoing traffic.
  - Traffic belonging to the Tor process itself is exempted to prevent loops.
  - Private RFC1918 ranges and multicast are left untouched.
  - All other TCP is transparently redirected to Tor's TransPort (9040).
  - DNS (UDP + TCP port 53) is redirected to Tor's DNSPort (5353).
  - /etc/resolv.conf is backed up and replaced with 127.0.0.1 nameserver.

Requires root privileges and a running Tor daemon configured with:
  TransPort 9040
  DNSPort 5353
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from core.config import Config
from core.state import StateManager
from core.utils import (
    get_tor_uid,
    ip6tables,
    iptables,
    run_cmd,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger("ghostroute.tor_routing")

# ── Constants ─────────────────────────────────────────────────────────────────

CHAIN_NAME = "GHOSTROUTE"
RESOLV_BACKUP = "/tmp/ghostroute.resolv.bak"
RESOLV_PATH = "/etc/resolv.conf"

# RFC1918 private ranges + loopback + multicast that must bypass Tor
BYPASS_RANGES: list[str] = [
    "127.0.0.0/8",    # loopback
    "10.0.0.0/8",     # RFC1918 class A
    "172.16.0.0/12",  # RFC1918 class B
    "192.168.0.0/16", # RFC1918 class C
    "224.0.0.0/4",    # multicast
    "100.64.0.0/10",  # carrier-grade NAT (RFC6598)
]


# ── Main class ────────────────────────────────────────────────────────────────

class TorRouting:
    """
    Manages system-wide transparent Tor routing via iptables NAT chains.

    Usage::

        routing = TorRouting(config, state)
        routing.enable()
        # ... all traffic now routes through Tor ...
        routing.disable()
    """

    def __init__(self, config: Config, state: StateManager) -> None:
        """
        Initialise TorRouting.

        Args:
            config: Loaded GhostRoute configuration object.
            state:  Shared runtime state manager.
        """
        self.config = config
        self.state = state
        self._trans_port: int = getattr(config, "tor_trans_port", 9040)
        self._dns_port: int = getattr(config, "tor_dns_port", 5353)
        logger.debug(
            "TorRouting initialised (TransPort=%d, DNSPort=%d)",
            self._trans_port,
            self._dns_port,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def enable(self) -> None:
        """
        Activate system-wide Tor transparent routing.

        Steps:
          1. Resolve the UID that the Tor process runs under.
          2. Backup /etc/resolv.conf.
          3. Create the GHOSTROUTE iptables NAT chain.
          4. Exempt Tor's own traffic (avoid routing loops).
          5. Exempt private / multicast address ranges.
          6. Redirect TCP → TransPort 9040.
          7. Redirect DNS (UDP+TCP 53) → DNSPort 5353.
          8. Attach chain to the OUTPUT hook.
          9. Replace /etc/resolv.conf with 127.0.0.1.
         10. Update shared state.

        Raises:
            RuntimeError: If any iptables command fails.
            PermissionError: If running without root privileges.
        """
        if os.geteuid() != 0:
            raise PermissionError("TorRouting.enable() requires root privileges")

        if self.is_active():
            logger.warning("GHOSTROUTE chain already active — skipping enable()")
            return

        tor_uid = get_tor_uid()
        logger.info("Enabling Tor transparent routing (tor UID=%d)", tor_uid)

        # 1. Backup resolv.conf before any modifications
        self._backup_resolv()

        # 2. Create the NAT chain
        iptables(["-t", "nat", "-N", CHAIN_NAME])
        logger.debug("Created iptables NAT chain: %s", CHAIN_NAME)

        # 3. Exempt Tor process traffic (avoid loop)
        iptables([
            "-t", "nat", "-A", CHAIN_NAME,
            "-m", "owner", "--uid-owner", str(tor_uid),
            "-j", "RETURN",
        ])
        logger.debug("Exempted Tor UID %d from GHOSTROUTE chain", tor_uid)

        # 4. Exempt private / reserved ranges
        for cidr in BYPASS_RANGES:
            iptables([
                "-t", "nat", "-A", CHAIN_NAME,
                "-d", cidr,
                "-j", "RETURN",
            ])
        logger.debug("Exempted %d private/reserved CIDR ranges", len(BYPASS_RANGES))

        # 5. Redirect DNS UDP traffic → Tor DNSPort
        iptables([
            "-t", "nat", "-A", CHAIN_NAME,
            "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-ports", str(self._dns_port),
        ])

        # 6. Redirect DNS TCP traffic → Tor DNSPort (rare but valid)
        iptables([
            "-t", "nat", "-A", CHAIN_NAME,
            "-p", "tcp", "--dport", "53",
            "-j", "REDIRECT", "--to-ports", str(self._dns_port),
        ])
        logger.debug("DNS (53 UDP+TCP) → DNSPort %d", self._dns_port)

        # 7. Redirect all remaining TCP → Tor TransPort
        iptables([
            "-t", "nat", "-A", CHAIN_NAME,
            "-p", "tcp",
            "--syn",
            "-j", "REDIRECT", "--to-ports", str(self._trans_port),
        ])
        logger.debug("All TCP SYN → TransPort %d", self._trans_port)

        # 8. Attach chain to OUTPUT
        iptables(["-t", "nat", "-A", "OUTPUT", "-j", CHAIN_NAME])
        logger.info("GHOSTROUTE chain attached to OUTPUT hook")

        # 9. Update /etc/resolv.conf
        self._write_tor_resolv()

        # 10. Update state
        self.state.set("tor_routing_active", True)
        self.state.set("tor_routing_trans_port", self._trans_port)
        self.state.set("tor_routing_dns_port", self._dns_port)
        logger.info("Tor transparent routing ENABLED")

    def disable(self) -> None:
        """
        Deactivate Tor transparent routing and restore original networking.

        Steps:
          1. Remove GHOSTROUTE reference from OUTPUT chain.
          2. Flush and delete the GHOSTROUTE chain.
          3. Restore /etc/resolv.conf from backup.
          4. Update shared state.

        This method is safe to call even if routing was never enabled.
        """
        if os.geteuid() != 0:
            raise PermissionError("TorRouting.disable() requires root privileges")

        logger.info("Disabling Tor transparent routing")

        # 1. Detach chain from OUTPUT (ignore error if not present)
        try:
            iptables(["-t", "nat", "-D", "OUTPUT", "-j", CHAIN_NAME])
        except subprocess.CalledProcessError:
            logger.debug("GHOSTROUTE not found in OUTPUT chain — already removed")

        # 2. Flush all rules in the chain, then delete it
        try:
            iptables(["-t", "nat", "-F", CHAIN_NAME])
            iptables(["-t", "nat", "-X", CHAIN_NAME])
            logger.debug("Flushed and deleted GHOSTROUTE chain")
        except subprocess.CalledProcessError:
            logger.debug("GHOSTROUTE chain did not exist — nothing to flush/delete")

        # 3. Restore resolv.conf
        self._restore_resolv()

        # 4. Update state
        self.state.set("tor_routing_active", False)
        logger.info("Tor transparent routing DISABLED")

    def is_active(self) -> bool:
        """
        Check whether the GHOSTROUTE iptables chain currently exists.

        Returns:
            True if the chain is present in the nat table, False otherwise.
        """
        try:
            result = run_cmd(
                ["iptables", "-t", "nat", "-L", CHAIN_NAME, "--line-numbers", "-n"],
                check=False,
            )
            return result.returncode == 0
        except FileNotFoundError:
            logger.error("iptables binary not found")
            return False

    def status(self) -> dict:
        """
        Return a status snapshot of the current Tor routing configuration.

        Returns:
            dict with keys:
                active       (bool)   – whether the chain exists
                chain_name   (str)    – always 'GHOSTROUTE'
                trans_port   (int)    – configured TransPort
                dns_port     (int)    – configured DNSPort
                rules_count  (int)    – number of rules in chain (or 0)
                resolv_backed_up (bool) – whether resolv backup exists
        """
        active = self.is_active()
        rules_count = 0

        if active:
            try:
                result = run_cmd(
                    ["iptables", "-t", "nat", "-L", CHAIN_NAME, "--line-numbers", "-n"],
                    check=False,
                )
                # Count non-header lines
                lines = [
                    ln for ln in result.stdout.splitlines()
                    if ln and not ln.startswith("Chain") and not ln.startswith("target")
                ]
                rules_count = len(lines)
            except Exception as exc:
                logger.warning("Could not count chain rules: %s", exc)

        return {
            "active": active,
            "chain_name": CHAIN_NAME,
            "trans_port": self._trans_port,
            "dns_port": self._dns_port,
            "rules_count": rules_count,
            "resolv_backed_up": Path(RESOLV_BACKUP).exists(),
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _backup_resolv(self) -> None:
        """
        Back up /etc/resolv.conf to RESOLV_BACKUP.

        Safe to call multiple times — will not overwrite an existing backup so
        that the *original* ISP resolver is preserved across multiple enable()
        calls.
        """
        src = Path(RESOLV_PATH)
        dst = Path(RESOLV_BACKUP)

        if dst.exists():
            logger.debug("resolv.conf backup already exists at %s — not overwriting", dst)
            return

        try:
            shutil.copy2(str(src), str(dst))
            logger.debug("resolv.conf backed up: %s → %s", src, dst)
        except OSError as exc:
            logger.error("Failed to back up resolv.conf: %s", exc)
            raise

    def _restore_resolv(self) -> None:
        """
        Restore /etc/resolv.conf from the backup created by _backup_resolv().

        Falls back to writing a safe Google DNS entry if the backup is missing.
        """
        src = Path(RESOLV_BACKUP)
        dst = Path(RESOLV_PATH)

        if src.exists():
            try:
                shutil.copy2(str(src), str(dst))
                src.unlink()
                logger.info("resolv.conf restored from backup")
            except OSError as exc:
                logger.error("Failed to restore resolv.conf: %s", exc)
                raise
        else:
            # Safety fallback — write a public DNS so the machine is still usable
            logger.warning(
                "No resolv.conf backup found at %s — writing fallback DNS", src
            )
            try:
                dst.write_text(
                    "# GhostRoute fallback — original resolv.conf backup not found\n"
                    "nameserver 8.8.8.8\n"
                    "nameserver 8.8.4.4\n",
                    encoding="utf-8",
                )
            except OSError as exc:
                logger.error("Failed to write fallback resolv.conf: %s", exc)
                raise

    def _write_tor_resolv(self) -> None:
        """
        Replace /etc/resolv.conf with a localhost-only nameserver entry so
        that all DNS queries are handled by Tor's DNSPort (redirected by
        iptables to port 5353).
        """
        content = (
            "# Generated by GhostRoute — Tor DNS mode\n"
            "# All DNS queries are tunnelled through Tor\n"
            "nameserver 127.0.0.1\n"
        )
        try:
            Path(RESOLV_PATH).write_text(content, encoding="utf-8")
            logger.debug("Updated /etc/resolv.conf → nameserver 127.0.0.1")
        except OSError as exc:
            logger.error("Failed to write Tor resolv.conf: %s", exc)
            raise
