"""
GhostRoute — IPv6 Leak Prevention Module
Disables IPv6 via sysctl and drops all IPv6 traffic via ip6tables.
"""

import json
import logging
import os
from pathlib import Path

from core.config import Config
from core.state import StateManager
from core.utils import run_cmd, ip6tables, sysctl_set, sysctl_get

logger = logging.getLogger("ghostroute.ipv6_block")

_STATE_FILE = "/tmp/ghostroute.ipv6.json"

# sysctl keys we modify
_SYSCTL_KEYS = [
    "net.ipv6.conf.all.disable_ipv6",
    "net.ipv6.conf.default.disable_ipv6",
    "net.ipv6.conf.lo.disable_ipv6",
]


class IPv6Block:
    """
    IPv6 Leak Prevention.

    Disables the IPv6 kernel stack via sysctl and applies ip6tables DROP
    policies on all chains to ensure no IPv6 traffic can escape even if
    the sysctl setting is not honoured by a running service.
    """

    def __init__(self, config: Config, state: StateManager) -> None:
        self.config = config
        self.state = state

    # ── Public API ────────────────────────────────────────────────────────────

    def enable(self) -> None:
        """
        Enable IPv6 blocking:
        1. Save current sysctl values.
        2. Set all disable_ipv6 keys to 1.
        3. Apply ip6tables DROP policies and flush chains.
        """
        logger.info("[IPv6Block] Enabling IPv6 leak prevention...")

        self._save_state()

        # Disable IPv6 via sysctl
        for key in _SYSCTL_KEYS:
            try:
                sysctl_set(key, "1")
                logger.debug(f"  sysctl {key}=1")
            except Exception as e:
                logger.warning(f"  Could not set {key}: {e}")

        # Drop all IPv6 at firewall level
        try:
            for chain in ("INPUT", "OUTPUT", "FORWARD"):
                ip6tables(["-P", chain, "DROP"])
            ip6tables(["-F"])          # Flush all chains
            ip6tables(["-X"])          # Delete user-defined chains
            logger.info("[IPv6Block] ip6tables: all IPv6 traffic blocked.")
        except Exception as e:
            logger.warning(f"[IPv6Block] ip6tables error (may not support IPv6): {e}")

        self.state.set_module("ipv6_block", True)
        logger.info("[IPv6Block] ✓ IPv6 leak prevention ACTIVE.")

    def disable(self) -> None:
        """Restore original sysctl IPv6 settings and reset ip6tables policies."""
        logger.info("[IPv6Block] Disabling IPv6 block, restoring original settings...")

        self._restore_state()

        # Restore ip6tables to ACCEPT
        try:
            for chain in ("INPUT", "OUTPUT", "FORWARD"):
                ip6tables(["-P", chain, "ACCEPT"])
            ip6tables(["-F"])
            logger.info("[IPv6Block] ip6tables: IPv6 traffic re-allowed.")
        except Exception as e:
            logger.warning(f"[IPv6Block] Could not reset ip6tables: {e}")

        self.state.set_module("ipv6_block", False)
        logger.info("[IPv6Block] ✓ IPv6 block disabled.")

    def is_active(self) -> bool:
        """Return True if IPv6 is currently disabled."""
        try:
            val = sysctl_get("net.ipv6.conf.all.disable_ipv6").strip()
            return val == "1"
        except Exception:
            return False

    def status(self) -> dict:
        """Return current IPv6 block status."""
        active = self.is_active()
        saved = self._load_saved_state()
        return {
            "active": active,
            "module_state": self.state.is_enabled("ipv6_block"),
            "sysctl_disabled": active,
            "original_values": saved,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _save_state(self) -> None:
        """Save current sysctl IPv6 values to temp file."""
        saved = {}
        for key in _SYSCTL_KEYS:
            try:
                saved[key] = sysctl_get(key).strip()
            except Exception:
                saved[key] = "0"  # Default: IPv6 enabled
        try:
            Path(_STATE_FILE).write_text(json.dumps(saved))
            logger.debug(f"[IPv6Block] Saved sysctl state to {_STATE_FILE}")
        except Exception as e:
            logger.warning(f"[IPv6Block] Could not save state: {e}")

    def _restore_state(self) -> None:
        """Restore sysctl IPv6 values from saved state."""
        saved = self._load_saved_state()
        if not saved:
            logger.warning("[IPv6Block] No saved state found, restoring IPv6 defaults (enabled).")
            for key in _SYSCTL_KEYS:
                try:
                    sysctl_set(key, "0")
                except Exception as e:
                    logger.warning(f"  Could not restore {key}: {e}")
            return

        for key, val in saved.items():
            try:
                sysctl_set(key, val)
                logger.debug(f"  Restored {key}={val}")
            except Exception as e:
                logger.warning(f"  Could not restore {key}: {e}")

    def _load_saved_state(self) -> dict:
        """Load saved sysctl state. Returns empty dict if not found."""
        try:
            if Path(_STATE_FILE).exists():
                return json.loads(Path(_STATE_FILE).read_text())
        except Exception as e:
            logger.warning(f"[IPv6Block] Could not read saved state: {e}")
        return {}
