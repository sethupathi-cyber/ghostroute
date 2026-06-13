"""
ghostroute/modules/obfuscation/obfs4.py
=======================================
obfs4 pluggable transport integration for GhostRoute.

obfs4 is a randomising-style pluggable transport that makes Tor traffic
look like random noise, defeating deep-packet inspection (DPI) signatures.
This module automates:
  • Discovering the ``obfs4proxy`` binary on the host system.
  • Writing the necessary ``torrc`` Bridge/ClientTransportPlugin lines.
  • Signalling Tor (via stem) to reload its configuration.
  • Tracking enable/disable state in the shared StateManager.

Prerequisites (on the target Linux host):
  - ``obfs4proxy`` installed (``apt install obfs4proxy`` on Debian/Ubuntu).
  - A valid obfs4 bridge address in the GhostRoute configuration:
      ``obfuscation.obfs4.bridge``
    Format: ``<IP>:<PORT> <FINGERPRINT> cert=<CERT> iat-mode=<MODE>``

Author: GhostRoute Security Team
Python: 3.10+
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.config import Config
    from core.state import StateManager

logger = logging.getLogger("ghostroute.obfuscation.obfs4")

# Candidate locations to search for the obfs4proxy binary.
OBFS4PROXY_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/obfs4proxy",
    "/usr/local/bin/obfs4proxy",
    "/opt/obfs4proxy/obfs4proxy",
)

# torrc option names managed by this module (used for clean removal).
MANAGED_TORRC_KEYS: tuple[str, ...] = (
    "UseBridges",
    "ClientTransportPlugin",
    "Bridge",
)


class Obfs4TransportError(Exception):
    """Raised when the Obfs4Transport module encounters an unrecoverable error."""


class Obfs4Transport:
    """
    Manages obfs4 pluggable-transport configuration for the Tor daemon.

    The module writes Bridge/ClientTransportPlugin directives to the torrc
    file managed by GhostRoute (not the system-wide torrc), then signals
    Tor to reload.

    Parameters
    ----------
    config:
        Global GhostRoute configuration object.
    state:
        Shared runtime state manager.
    """

    MODULE_NAME = "obfs4"

    def __init__(self, config: "Config", state: "StateManager") -> None:
        self._config = config
        self._state = state
        self._enabled: bool = False
        self._binary_path: str | None = self._find_binary()

        logger.debug(
            "Obfs4Transport initialised. Binary: %s",
            self._binary_path or "NOT FOUND",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enable(self) -> None:
        """
        Enable the obfs4 pluggable transport.

        Steps
        -----
        1. Verify the ``obfs4proxy`` binary is present.
        2. Resolve the bridge address from config (raises if missing).
        3. Build torrc lines and write them via the Config helper.
        4. Signal Tor to reload configuration.
        5. Update state.

        Raises
        ------
        Obfs4TransportError
            If the binary is missing, no bridge address is configured, or Tor
            fails to apply the new configuration.
        """
        if self._enabled:
            logger.debug("obfs4 transport already enabled.")
            return

        if not self.is_available():
            raise Obfs4TransportError(
                f"obfs4proxy binary not found. Install it with: "
                f"apt install obfs4proxy  (or equivalent for your distro). "
                f"Searched: {list(OBFS4PROXY_CANDIDATES)}"
            )

        bridge_address = self._resolve_bridge_address()

        logger.info(
            "Enabling obfs4 transport. Bridge: %s…",
            bridge_address[:32],  # Truncate for safe logging (no full cert).
        )

        torrc_lines = self.get_torrc_lines()
        self._write_torrc_lines(torrc_lines)

        self._reload_tor()

        self._enabled = True
        self._update_state(enabled=True, bridge=bridge_address)
        logger.info("obfs4 transport enabled successfully.")

    def disable(self) -> None:
        """
        Disable the obfs4 transport.

        Removes Bridge/ClientTransportPlugin/UseBridges lines from the torrc
        (that were added by this module) and reloads Tor.

        Raises
        ------
        Obfs4TransportError
            If the torrc cannot be modified or Tor fails to reload.
        """
        if not self._enabled:
            logger.debug("obfs4 transport is not enabled — nothing to disable.")
            return

        logger.info("Disabling obfs4 transport.")
        self._remove_torrc_lines()
        self._reload_tor()

        self._enabled = False
        self._update_state(enabled=False, bridge=None)
        logger.info("obfs4 transport disabled.")

    def is_available(self) -> bool:
        """
        Return True if the ``obfs4proxy`` binary is discoverable on this system.

        Searches the pre-defined candidate paths and then falls back to
        ``shutil.which()`` for any directory in ``$PATH``.
        """
        return self._find_binary() is not None

    def get_torrc_lines(self) -> list[str]:
        """
        Return the torrc lines required to activate the obfs4 transport.

        The bridge address is read from the configuration at call time, so
        this method can be called before or after ``enable()``.

        Returns
        -------
        list[str]
            Lines to be appended to / merged into the managed torrc.

        Raises
        ------
        Obfs4TransportError
            If no bridge address is configured and none can be resolved.
        """
        binary = self._binary_path or self._find_binary()
        if binary is None:
            raise Obfs4TransportError("obfs4proxy binary not found.")

        bridge_address = self._resolve_bridge_address()

        return [
            "# --- GhostRoute obfs4 transport (managed) ---",
            "UseBridges 1",
            f"ClientTransportPlugin obfs4 exec {binary}",
            f"Bridge obfs4 {bridge_address}",
            "# --- end GhostRoute obfs4 ---",
        ]

    def status(self) -> dict:
        """
        Return a status dictionary for this module.

        Returns
        -------
        dict
            Keys:
            - ``module``: str — always ``'obfs4'``.
            - ``enabled``: bool
            - ``available``: bool — whether the binary is present.
            - ``binary_path``: str | None
            - ``bridge_configured``: bool — whether a bridge address exists in config.
        """
        bridge_configured = bool(
            self._config.get("obfuscation.obfs4.bridge", default="")
        )
        return {
            "module": self.MODULE_NAME,
            "enabled": self._enabled,
            "available": self.is_available(),
            "binary_path": self._binary_path,
            "bridge_configured": bridge_configured,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_binary(self) -> str | None:
        """
        Locate the ``obfs4proxy`` binary.

        Checks candidate paths first (faster, deterministic), then falls back
        to a PATH search via ``shutil.which()``.

        Returns
        -------
        str | None
            Absolute path to the binary, or None if not found.
        """
        for path in OBFS4PROXY_CANDIDATES:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        # Fall back to PATH search.
        found = shutil.which("obfs4proxy")
        if found:
            return found
        return None

    def _resolve_bridge_address(self) -> str:
        """
        Retrieve the obfs4 bridge address from configuration.

        The configuration key is ``obfuscation.obfs4.bridge``.
        Expected format::

            <IP>:<PORT> <FINGERPRINT> cert=<BASE64> iat-mode=<0|1|2>

        Raises
        ------
        Obfs4TransportError
            If no bridge address is set in the configuration.
        """
        bridge: str = self._config.get("obfuscation.obfs4.bridge", default="")
        if not bridge or not bridge.strip():
            raise Obfs4TransportError(
                "No obfs4 bridge address configured. "
                "Set 'obfuscation.obfs4.bridge' in your GhostRoute config.\n"
                "Format: <IP>:<PORT> <FINGERPRINT> cert=<CERT> iat-mode=<MODE>\n"
                "You can get bridges from: https://bridges.torproject.org/"
            )
        return bridge.strip()

    def _write_torrc_lines(self, lines: list[str]) -> None:
        """
        Append the given torrc lines to GhostRoute's managed torrc.

        The managed torrc path is read from ``config.tor.torrc_path``.

        Parameters
        ----------
        lines:
            Lines to append.

        Raises
        ------
        Obfs4TransportError
            If the torrc file cannot be written.
        """
        torrc_path = self._get_torrc_path()
        try:
            # Read existing content so we can avoid duplicate blocks.
            if torrc_path.exists():
                existing = torrc_path.read_text(encoding="utf-8")
            else:
                existing = ""

            # Remove any previously managed obfs4 block.
            existing = self._strip_managed_block(existing)

            new_content = existing.rstrip("\n") + "\n\n" + "\n".join(lines) + "\n"
            torrc_path.write_text(new_content, encoding="utf-8")
            logger.debug("Wrote obfs4 torrc lines to: %s", torrc_path)
        except OSError as exc:
            raise Obfs4TransportError(
                f"Cannot write to torrc at '{torrc_path}': {exc}"
            ) from exc

    def _remove_torrc_lines(self) -> None:
        """
        Remove the GhostRoute-managed obfs4 block from the torrc.

        Raises
        ------
        Obfs4TransportError
            If the torrc cannot be read or written.
        """
        torrc_path = self._get_torrc_path()
        if not torrc_path.exists():
            logger.debug("torrc not found at '%s' — nothing to remove.", torrc_path)
            return
        try:
            existing = torrc_path.read_text(encoding="utf-8")
            cleaned = self._strip_managed_block(existing)
            torrc_path.write_text(cleaned, encoding="utf-8")
            logger.debug("Removed obfs4 torrc lines from: %s", torrc_path)
        except OSError as exc:
            raise Obfs4TransportError(
                f"Cannot modify torrc at '{torrc_path}': {exc}"
            ) from exc

    def _strip_managed_block(self, content: str) -> str:
        """
        Remove the GhostRoute-managed obfs4 block from a torrc string.

        The block is delimited by::

            # --- GhostRoute obfs4 transport (managed) ---
            ...
            # --- end GhostRoute obfs4 ---

        Parameters
        ----------
        content:
            Raw torrc file content.

        Returns
        -------
        str
            Content with the managed block removed.
        """
        start_marker = "# --- GhostRoute obfs4 transport (managed) ---"
        end_marker = "# --- end GhostRoute obfs4 ---"

        start_idx = content.find(start_marker)
        end_idx = content.find(end_marker)

        if start_idx == -1 or end_idx == -1:
            return content  # No managed block found.

        before = content[:start_idx].rstrip("\n")
        after = content[end_idx + len(end_marker):].lstrip("\n")
        return before + "\n" + after if after else before + "\n"

    def _get_torrc_path(self) -> Path:
        """Return the configured torrc path as a ``pathlib.Path`` object."""
        raw: str = self._config.get(
            "tor.torrc_path", default="/etc/tor/ghostroute-torrc"
        )
        return Path(raw)

    def _reload_tor(self) -> None:
        """
        Signal the Tor daemon to reload its configuration (SIGHUP / stem).

        Attempts to use the stem controller first (preferred: no process
        restart required).  Falls back to sending SIGHUP to the Tor process
        PID stored in the state manager.

        Raises
        ------
        Obfs4TransportError
            If Tor cannot be signalled.
        """
        try:
            self._reload_via_stem()
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "stem reload failed (%s), trying SIGHUP fallback.", exc
            )

        try:
            self._reload_via_sighup()
        except Exception as exc:
            raise Obfs4TransportError(
                f"Failed to reload Tor after obfs4 configuration change: {exc}"
            ) from exc

    def _reload_via_stem(self) -> None:
        """
        Use the stem Tor controller to send a RELOAD signal.

        Reads the control port and password from the config.
        """
        import stem  # type: ignore[import-untyped]
        import stem.control  # type: ignore[import-untyped]

        control_port: int = int(
            self._config.get("tor.control_port", default=9051)
        )
        control_password: str = self._config.get(
            "tor.control_password", default=""
        )

        with stem.control.Controller.from_port(port=control_port) as ctrl:
            ctrl.authenticate(password=control_password)
            ctrl.signal(stem.Signal.RELOAD)
            logger.debug("Sent RELOAD signal to Tor via stem (port %d).", control_port)

        # Give Tor a moment to apply the new config.
        time.sleep(1.5)

    def _reload_via_sighup(self) -> None:
        """
        Send SIGHUP to the Tor process to trigger a configuration reload.

        Reads the Tor PID from the state manager.

        Raises
        ------
        Obfs4TransportError
            If the PID is unavailable or the signal cannot be delivered.
        """
        import signal as _signal

        tor_pid: int | None = self._state.get("tor.pid")
        if not tor_pid:
            raise Obfs4TransportError(
                "Tor PID not available in state — cannot send SIGHUP."
            )

        os.kill(tor_pid, _signal.SIGHUP)
        logger.debug("Sent SIGHUP to Tor process (PID %d).", tor_pid)
        time.sleep(1.5)

    def _update_state(self, *, enabled: bool, bridge: str | None) -> None:
        """Persist the module's runtime state to the StateManager."""
        try:
            self._state.set(
                "obfuscation.obfs4",
                {
                    "enabled": enabled,
                    "bridge": bridge,
                    "binary_path": self._binary_path,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to update state for obfs4: %s", exc)

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Obfs4Transport enabled={self._enabled} "
            f"available={self.is_available()} "
            f"binary={self._binary_path!r}>"
        )
