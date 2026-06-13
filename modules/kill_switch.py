"""
GhostRoute — Kill Switch Module
Hard/soft iptables kill switch preventing any traffic from leaking
if the anonymization tunnel drops unexpectedly.
"""

import logging
import subprocess
import threading
import time
from pathlib import Path

from core.config import Config
from core.state import StateManager
from core.utils import run_cmd, iptables, get_tor_uid

logger = logging.getLogger("ghostroute.kill_switch")

_BACKUP_FILE = "/tmp/ghostroute.iptables.bak"


class KillSwitch:
    """
    Hard / Soft Network Kill Switch.

    Hard mode: Applies strict iptables rules that DROP all traffic except
    loopback and the Tor process UID — immediately blocks everything if
    called. Used when a tunnel drop is detected or triggered manually.

    Soft mode: Launches a background monitor thread that watches Tor/proxy
    health and automatically engages hard mode if connectivity is lost.
    """

    def __init__(self, config: Config, state: StateManager) -> None:
        self.config = config
        self.state = state
        self._monitor_thread: threading.Thread | None = None
        self._stop_monitor = threading.Event()
        self._hard_active = False

    # ── Public API ────────────────────────────────────────────────────────────

    def enable(self, mode: str | None = None) -> None:
        """
        Enable kill switch.

        Args:
            mode: 'hard' (immediate DROP rules) or 'soft' (background monitor).
                  Reads from config if not specified.
        """
        mode = mode or self.config.get("kill_switch.mode", "hard")
        logger.info(f"[KillSwitch] Enabling in '{mode}' mode...")

        self._backup_rules()

        if mode == "hard":
            self._apply_hard_rules()
        elif mode == "soft":
            self._start_soft_monitor()
        else:
            logger.warning(f"[KillSwitch] Unknown mode '{mode}', defaulting to 'hard'.")
            self._apply_hard_rules()

        self.state.set_module("kill_switch", True)
        logger.info(f"[KillSwitch] ✓ Kill switch ACTIVE ({mode} mode).")

    def disable(self) -> None:
        """
        Disable kill switch and restore original iptables rules.
        """
        logger.info("[KillSwitch] Disabling kill switch, restoring iptables...")

        self._stop_monitor.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)

        self._restore_rules()
        self._hard_active = False
        self.state.set_module("kill_switch", False)
        logger.info("[KillSwitch] ✓ Kill switch disabled, system traffic restored.")

    def trigger(self) -> None:
        """Manually trigger the hard kill switch immediately."""
        logger.warning("[KillSwitch] Manual kill switch triggered!")
        self._apply_hard_rules()

    def is_active(self) -> bool:
        """Return True if kill switch rules are applied."""
        return self._hard_active or self.state.is_enabled("kill_switch")

    def status(self) -> dict:
        """Return kill switch status info."""
        return {
            "active": self.is_active(),
            "hard_rules_applied": self._hard_active,
            "monitor_running": (
                self._monitor_thread is not None
                and self._monitor_thread.is_alive()
            ),
            "backup_exists": Path(_BACKUP_FILE).exists(),
            "mode": self.config.get("kill_switch.mode", "hard"),
        }

    # ── Private: Hard Rules ───────────────────────────────────────────────────

    def _apply_hard_rules(self) -> None:
        """Apply strict iptables DROP rules, allowing only Tor egress."""
        logger.warning("[KillSwitch] Applying HARD kill switch rules...")

        try:
            tor_uid = get_tor_uid()
        except Exception:
            tor_uid = None
            logger.warning("[KillSwitch] Could not determine Tor UID; Tor egress rule skipped.")

        rules = []

        # Set default DROP policies
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            rules.append(["-P", chain, "DROP"])

        # Allow loopback
        rules.append(["-A", "INPUT",  "-i", "lo", "-j", "ACCEPT"])
        rules.append(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

        # Allow established / related connections (for already-open tunnels)
        rules.append(["-A", "INPUT",  "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        rules.append(["-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

        # Allow Tor process outbound (by UID)
        if tor_uid is not None:
            rules.append(["-A", "OUTPUT", "-m", "owner", "--uid-owner", str(tor_uid), "-j", "ACCEPT"])

        # Allow DHCP (so we keep network if Tor reconnects)
        rules.append(["-A", "OUTPUT", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"])
        rules.append(["-A", "INPUT",  "-p", "udp", "--sport", "67:68", "-j", "ACCEPT"])

        for args in rules:
            try:
                iptables(args)
            except Exception as e:
                logger.warning(f"[KillSwitch] Rule failed ({' '.join(args)}): {e}")

        self._hard_active = True
        logger.warning("[KillSwitch] ⚠ Hard kill switch ENGAGED — all non-Tor traffic blocked.")

    # ── Private: Soft Monitor ─────────────────────────────────────────────────

    def _start_soft_monitor(self) -> None:
        """Start background thread monitoring Tor health."""
        self._stop_monitor.clear()
        interval = self.config.get("kill_switch.monitor_interval", 5)

        def _monitor():
            logger.info(f"[KillSwitch] Soft monitor started (interval={interval}s).")
            while not self._stop_monitor.is_set():
                if not self._check_tor_alive():
                    logger.warning("[KillSwitch] Tor tunnel DOWN — engaging hard kill switch!")
                    self._apply_hard_rules()
                self._stop_monitor.wait(interval)
            logger.info("[KillSwitch] Soft monitor stopped.")

        self._monitor_thread = threading.Thread(target=_monitor, daemon=True, name="ks-monitor")
        self._monitor_thread.start()

    def _check_tor_alive(self) -> bool:
        """Return True if Tor SOCKS port is reachable."""
        import socket
        port = self.config.get("tor.socks_port", 9050)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3):
                return True
        except OSError:
            return False

    # ── Private: Backup / Restore ─────────────────────────────────────────────

    def _backup_rules(self) -> None:
        """Backup current iptables rules to file."""
        try:
            result = run_cmd(["iptables-save"], check=True)
            Path(_BACKUP_FILE).write_text(result.stdout)
            logger.debug(f"[KillSwitch] iptables rules backed up to {_BACKUP_FILE}")
        except Exception as e:
            logger.warning(f"[KillSwitch] Could not backup iptables rules: {e}")

    def _restore_rules(self) -> None:
        """Restore iptables rules from backup."""
        backup = Path(_BACKUP_FILE)
        if backup.exists():
            try:
                run_cmd(["iptables-restore", str(backup)], check=True)
                logger.info("[KillSwitch] iptables rules restored from backup.")
                backup.unlink(missing_ok=True)
            except Exception as e:
                logger.error(f"[KillSwitch] Failed to restore iptables rules: {e}")
                logger.error("[KillSwitch] Manual recovery: iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -F")
        else:
            logger.warning(f"[KillSwitch] No backup found at {_BACKUP_FILE}. Resetting to ACCEPT policies.")
            for chain in ("INPUT", "OUTPUT", "FORWARD"):
                try:
                    iptables(["-P", chain, "ACCEPT"])
                except Exception:
                    pass
            try:
                iptables(["-F"])
                iptables(["-X"])
            except Exception:
                pass
