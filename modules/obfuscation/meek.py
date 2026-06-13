"""
ghostroute/modules/obfuscation/meek.py
======================================
Meek-lite CDN transport integration for GhostRoute.

Meek-lite uses domain-fronting to disguise Tor traffic as HTTPS requests to
a major CDN (e.g., Azure, Google, Amazon), making deep-packet inspection
and blocking significantly harder because the traffic is indistinguishable
from normal CDN traffic.

The ``obfs4proxy`` binary also ships a meek-lite client implementation, so
no additional binary is required beyond what the obfs4 module already uses.

Architecture
------------
  Application → Tor (SOCKS5) → meek-lite client (obfs4proxy)
    → HTTPS POST to CDN front → CDN → Meek bridge server → Tor network

Configuration keys (in GhostRoute config)
-----------------------------------------
  obfuscation.meek.url      - Meek bridge URL (default: Azure)
  obfuscation.meek.front    - CDN fronting domain (default: ajax.aspnetcdn.com)
  obfuscation.meek.bridge   - Bridge IP:PORT + fingerprint
  tor.torrc_path            - Path to managed torrc
  tor.control_port          - Tor control port (default: 9051)
  tor.control_password      - Tor control password

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

logger = logging.getLogger("ghostroute.obfuscation.meek")

# Known binary candidates (meek-lite is included in obfs4proxy ≥ 0.0.7).
OBFS4PROXY_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/obfs4proxy",
    "/usr/local/bin/obfs4proxy",
    "/opt/obfs4proxy/obfs4proxy",
)

# Default meek-lite Azure bridge parameters from Tor Project.
DEFAULT_MEEK_URL = "https://meek.azureedge.net/"
DEFAULT_MEEK_FRONT = "ajax.aspnetcdn.com"
# Default public meek-azure bridge (fingerprint from official Tor metrics).
DEFAULT_MEEK_BRIDGE = (
    "0.0.2.0:1 B9E7141C594AF25699E0079C1F0146F409495296"
)


class MeekTransportError(Exception):
    """Raised when the MeekTransport module encounters an unrecoverable error."""


class MeekTransport:
    """
    Manages meek-lite CDN transport configuration for the Tor daemon.

    Meek-lite replaces normal Tor connections with HTTPS POST requests sent
    to a CDN, which forwards them to a Tor bridge.  This module writes the
    appropriate torrc directives and reloads Tor.

    Parameters
    ----------
    config:
        Global GhostRoute configuration object.
    state:
        Shared runtime state manager.
    """

    MODULE_NAME = "meek"

    def __init__(self, config: "Config", state: "StateManager") -> None:
        self._config = config
        self._state = state
        self._enabled: bool = False
        self._binary_path: str | None = self._find_binary()

        logger.debug(
            "MeekTransport initialised. Binary (obfs4proxy): %s",
            self._binary_path or "NOT FOUND",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enable(self) -> None:
        """
        Enable the meek-lite CDN transport.

        Steps
        -----
        1. Verify the ``obfs4proxy`` binary is present (ships meek-lite).
        2. Read meek URL, front, and bridge from config (uses defaults if absent).
        3. Write ClientTransportPlugin + Bridge lines to the managed torrc.
        4. Reload Tor via stem or SIGHUP.
        5. Update runtime state.

        Raises
        ------
        MeekTransportError
            If the binary is missing or Tor cannot be reloaded.
        """
        if self._enabled:
            logger.debug("Meek transport already enabled.")
            return

        if not self.is_available():
            raise MeekTransportError(
                "obfs4proxy binary not found (required for meek-lite). "
                "Install it with: apt install obfs4proxy"
            )

        meek_url = self._config.get("obfuscation.meek.url", default=DEFAULT_MEEK_URL)
        meek_front = self._config.get(
            "obfuscation.meek.front", default=DEFAULT_MEEK_FRONT
        )
        meek_bridge = self._config.get(
            "obfuscation.meek.bridge", default=DEFAULT_MEEK_BRIDGE
        )

        logger.info(
            "Enabling meek-lite transport. Front: %s  URL: %s",
            meek_front,
            meek_url,
        )

        torrc_lines = self.get_torrc_lines()
        self._write_torrc_lines(torrc_lines)
        self._reload_tor()

        self._enabled = True
        self._update_state(
            enabled=True,
            url=meek_url,
            front=meek_front,
            bridge=meek_bridge,
        )
        logger.info("Meek-lite transport enabled successfully.")

    def disable(self) -> None:
        """
        Disable the meek-lite transport.

        Removes the managed meek-lite block from the torrc and reloads Tor.

        Raises
        ------
        MeekTransportError
            If the torrc cannot be modified or Tor fails to reload.
        """
        if not self._enabled:
            logger.debug("Meek transport is not enabled — nothing to disable.")
            return

        logger.info("Disabling meek-lite transport.")
        self._remove_torrc_lines()
        self._reload_tor()

        self._enabled = False
        self._update_state(enabled=False, url=None, front=None, bridge=None)
        logger.info("Meek-lite transport disabled.")

    def is_available(self) -> bool:
        """
        Return True if ``obfs4proxy`` (which ships meek-lite) is available.

        Checks candidate paths, then falls back to ``shutil.which()``.
        """
        return self._find_binary() is not None

    def get_torrc_lines(self) -> list[str]:
        """
        Return the torrc lines required to activate meek-lite transport.

        Reads meek URL, front domain, and bridge address from config.
        Uses built-in defaults for the official Tor Project Azure bridge if
        no config keys are set.

        Returns
        -------
        list[str]
            Lines to be merged into the managed torrc.

        Raises
        ------
        MeekTransportError
            If the binary path cannot be resolved.
        """
        binary = self._binary_path or self._find_binary()
        if binary is None:
            raise MeekTransportError(
                "obfs4proxy binary not found — cannot generate torrc lines."
            )

        meek_url = self._config.get("obfuscation.meek.url", default=DEFAULT_MEEK_URL)
        meek_front = self._config.get(
            "obfuscation.meek.front", default=DEFAULT_MEEK_FRONT
        )
        meek_bridge = self._config.get(
            "obfuscation.meek.bridge", default=DEFAULT_MEEK_BRIDGE
        )

        return [
            "# --- GhostRoute meek-lite transport (managed) ---",
            "UseBridges 1",
            f"ClientTransportPlugin meek_lite exec {binary}",
            f"Bridge meek_lite {meek_bridge} url={meek_url} front={meek_front}",
            "# --- end GhostRoute meek-lite ---",
        ]

    def status(self) -> dict:
        """
        Return a status dictionary for this module.

        Returns
        -------
        dict
            Keys:
            - ``module``: str — always ``'meek'``.
            - ``enabled``: bool
            - ``available``: bool
            - ``binary_path``: str | None — path to obfs4proxy.
            - ``meek_url``: str — configured CDN URL.
            - ``meek_front``: str — configured fronting domain.
        """
        return {
            "module": self.MODULE_NAME,
            "enabled": self._enabled,
            "available": self.is_available(),
            "binary_path": self._binary_path,
            "meek_url": self._config.get(
                "obfuscation.meek.url", default=DEFAULT_MEEK_URL
            ),
            "meek_front": self._config.get(
                "obfuscation.meek.front", default=DEFAULT_MEEK_FRONT
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_binary(self) -> str | None:
        """
        Locate the ``obfs4proxy`` binary.

        Returns
        -------
        str | None
            Absolute path to the binary, or None if not found.
        """
        for path in OBFS4PROXY_CANDIDATES:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return shutil.which("obfs4proxy")

    def _get_torrc_path(self) -> Path:
        """Return the configured torrc path as a ``pathlib.Path``."""
        raw: str = self._config.get(
            "tor.torrc_path", default="/etc/tor/ghostroute-torrc"
        )
        return Path(raw)

    def _write_torrc_lines(self, lines: list[str]) -> None:
        """
        Append the meek-lite block to the managed torrc.

        Removes any previously written meek-lite block first to prevent
        duplicate directives.

        Raises
        ------
        MeekTransportError
            If the file cannot be written.
        """
        torrc_path = self._get_torrc_path()
        try:
            existing = torrc_path.read_text(encoding="utf-8") if torrc_path.exists() else ""
            existing = self._strip_managed_block(existing)
            new_content = existing.rstrip("\n") + "\n\n" + "\n".join(lines) + "\n"
            torrc_path.write_text(new_content, encoding="utf-8")
            logger.debug("Wrote meek-lite torrc block to: %s", torrc_path)
        except OSError as exc:
            raise MeekTransportError(
                f"Cannot write meek-lite config to torrc '{torrc_path}': {exc}"
            ) from exc

    def _remove_torrc_lines(self) -> None:
        """
        Remove the GhostRoute-managed meek-lite block from the torrc.

        Raises
        ------
        MeekTransportError
            If the file cannot be modified.
        """
        torrc_path = self._get_torrc_path()
        if not torrc_path.exists():
            logger.debug("torrc not found at '%s' — nothing to remove.", torrc_path)
            return
        try:
            existing = torrc_path.read_text(encoding="utf-8")
            cleaned = self._strip_managed_block(existing)
            torrc_path.write_text(cleaned, encoding="utf-8")
            logger.debug("Removed meek-lite block from torrc: %s", torrc_path)
        except OSError as exc:
            raise MeekTransportError(
                f"Cannot modify torrc at '{torrc_path}': {exc}"
            ) from exc

    def _strip_managed_block(self, content: str) -> str:
        """
        Remove the meek-lite managed block from a torrc string.

        The block is bounded by::

            # --- GhostRoute meek-lite transport (managed) ---
            ...
            # --- end GhostRoute meek-lite ---

        Parameters
        ----------
        content:
            Raw torrc file content.

        Returns
        -------
        str
            Content with the managed block excised.
        """
        start_marker = "# --- GhostRoute meek-lite transport (managed) ---"
        end_marker = "# --- end GhostRoute meek-lite ---"

        start_idx = content.find(start_marker)
        end_idx = content.find(end_marker)

        if start_idx == -1 or end_idx == -1:
            return content

        before = content[:start_idx].rstrip("\n")
        after = content[end_idx + len(end_marker):].lstrip("\n")
        return before + "\n" + after if after else before + "\n"

    def _reload_tor(self) -> None:
        """
        Signal Tor to reload its configuration.

        Attempts stem controller first; falls back to SIGHUP via PID from state.

        Raises
        ------
        MeekTransportError
            If Tor cannot be signalled.
        """
        try:
            self._reload_via_stem()
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "stem Tor reload failed (%s), trying SIGHUP.", exc
            )

        try:
            self._reload_via_sighup()
        except Exception as exc:
            raise MeekTransportError(
                f"Failed to reload Tor after meek-lite config change: {exc}"
            ) from exc

    def _reload_via_stem(self) -> None:
        """Use stem to send a RELOAD signal to the Tor controller."""
        import stem  # type: ignore[import-untyped]
        import stem.control  # type: ignore[import-untyped]

        port: int = int(self._config.get("tor.control_port", default=9051))
        password: str = self._config.get("tor.control_password", default="")

        with stem.control.Controller.from_port(port=port) as ctrl:
            ctrl.authenticate(password=password)
            ctrl.signal(stem.Signal.RELOAD)
            logger.debug("Sent RELOAD to Tor via stem (port %d).", port)

        time.sleep(1.5)

    def _reload_via_sighup(self) -> None:
        """
        Send SIGHUP to the Tor process using its PID from state.

        Raises
        ------
        MeekTransportError
            If the PID is not stored in state.
        """
        import signal as _signal

        tor_pid: int | None = self._state.get("tor.pid")
        if not tor_pid:
            raise MeekTransportError(
                "Tor PID not available in state — cannot send SIGHUP."
            )

        os.kill(tor_pid, _signal.SIGHUP)
        logger.debug("Sent SIGHUP to Tor (PID %d).", tor_pid)
        time.sleep(1.5)

    def _update_state(
        self,
        *,
        enabled: bool,
        url: str | None,
        front: str | None,
        bridge: str | None,
    ) -> None:
        """Persist the module's runtime state."""
        try:
            self._state.set(
                "obfuscation.meek",
                {
                    "enabled": enabled,
                    "url": url,
                    "front": front,
                    "bridge": bridge,
                    "binary_path": self._binary_path,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to update state for meek: %s", exc)

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<MeekTransport enabled={self._enabled} "
            f"available={self.is_available()} "
            f"binary={self._binary_path!r}>"
        )
