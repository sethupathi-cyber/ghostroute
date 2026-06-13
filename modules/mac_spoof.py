"""
GhostRoute — MAC Address Spoofing Module
Randomizes hardware MAC address per session to prevent device fingerprinting.
"""

import logging
import random
import re
from pathlib import Path

from core.config import Config
from core.state import StateManager
from core.utils import run_cmd, get_default_interface

logger = logging.getLogger("ghostroute.mac_spoof")

_SAVED_MAC_FILE = "/tmp/ghostroute.mac.json"


class MACSpoof:
    """
    MAC Address Randomization.

    Changes the hardware MAC address of the specified (or auto-detected)
    network interface to a randomly generated unicast MAC. Falls back to
    manual MAC generation if macchanger is not available.
    """

    def __init__(self, config: Config, state: StateManager) -> None:
        self.config = config
        self.state = state
        self._original_mac: str | None = None
        self._active_iface: str | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    def enable(self, interface: str | None = None) -> None:
        """
        Enable MAC spoofing on the specified interface.

        Args:
            interface: Interface name (e.g., 'eth0', 'wlan0').
                       Uses config value if not given; auto-detects if 'auto'.
        """
        iface = interface or self.config.get("mac.interface", "auto")
        if iface == "auto":
            iface = get_default_interface()

        if not iface:
            raise RuntimeError("[MACSpoof] Could not determine network interface.")

        logger.info(f"[MACSpoof] Spoofing MAC on interface: {iface}")

        original = self.get_current_mac(iface)
        self._original_mac = original
        self._active_iface = iface
        self._save_original(iface, original)

        # Bring interface down
        run_cmd(["ip", "link", "set", "dev", iface, "down"])

        # Apply random MAC
        new_mac = self._set_random_mac(iface)

        # Bring interface back up
        run_cmd(["ip", "link", "set", "dev", iface, "up"])

        logger.info(f"[MACSpoof] ✓ MAC changed: {original} → {new_mac}")
        self.state.set_module("mac_spoof", True)

    def disable(self) -> None:
        """Restore the original MAC address."""
        saved = self._load_original()
        iface = saved.get("interface") or self._active_iface
        original_mac = saved.get("mac") or self._original_mac

        if not iface or not original_mac:
            logger.warning("[MACSpoof] No saved MAC to restore. Skipping.")
            self.state.set_module("mac_spoof", False)
            return

        logger.info(f"[MACSpoof] Restoring MAC on {iface}: {original_mac}")
        try:
            run_cmd(["ip", "link", "set", "dev", iface, "down"])
            self._set_mac(iface, original_mac)
            run_cmd(["ip", "link", "set", "dev", iface, "up"])
            logger.info(f"[MACSpoof] ✓ MAC restored to {original_mac}")
        except Exception as e:
            logger.error(f"[MACSpoof] Failed to restore MAC: {e}")

        self.state.set_module("mac_spoof", False)

    def get_current_mac(self, interface: str) -> str:
        """Read the current MAC address of an interface."""
        mac_file = Path(f"/sys/class/net/{interface}/address")
        if mac_file.exists():
            return mac_file.read_text().strip()
        # Fallback: parse ip link show
        try:
            result = run_cmd(["ip", "link", "show", interface])
            match = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "unknown"

    def get_random_mac(self) -> str:
        """
        Generate a valid random unicast MAC address.
        Ensures the locally administered bit is set and multicast bit is clear.
        """
        mac = [random.randint(0x00, 0xFF) for _ in range(6)]
        mac[0] = (mac[0] & 0xFE) | 0x02   # Clear multicast, set locally administered
        return ":".join(f"{b:02x}" for b in mac)

    def status(self) -> dict:
        """Return MAC spoof status."""
        iface = self._active_iface or self.config.get("mac.interface", "auto")
        if iface == "auto":
            try:
                iface = get_default_interface()
            except Exception:
                iface = "unknown"

        current = "unknown"
        if iface and iface != "unknown":
            try:
                current = self.get_current_mac(iface)
            except Exception:
                pass

        return {
            "active": self.state.is_enabled("mac_spoof"),
            "interface": iface,
            "original_mac": self._original_mac,
            "current_mac": current,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _set_random_mac(self, interface: str) -> str:
        """Set a random MAC using macchanger if available, else manual method."""
        # Try macchanger first
        try:
            result = run_cmd(["macchanger", "-r", interface])
            match = re.search(r"New MAC:\s+([0-9a-f:]{17})", result.stdout, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception:
            logger.debug("[MACSpoof] macchanger not available, using manual MAC generation.")

        # Manual: generate random MAC and apply via ip link
        new_mac = self.get_random_mac()
        self._set_mac(interface, new_mac)
        return new_mac

    def _set_mac(self, interface: str, mac: str) -> None:
        """Set a specific MAC address on interface using ip link."""
        run_cmd(["ip", "link", "set", "dev", interface, "address", mac])

    def _save_original(self, interface: str, mac: str) -> None:
        """Persist original MAC to temp file."""
        import json
        try:
            Path(_SAVED_MAC_FILE).write_text(
                json.dumps({"interface": interface, "mac": mac})
            )
        except Exception as e:
            logger.warning(f"[MACSpoof] Could not save original MAC: {e}")

    def _load_original(self) -> dict:
        """Load saved original MAC from temp file."""
        import json
        try:
            if Path(_SAVED_MAC_FILE).exists():
                return json.loads(Path(_SAVED_MAC_FILE).read_text())
        except Exception:
            pass
        return {}
