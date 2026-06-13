"""
ghostroute/modules/tor_manager.py
===================================
Tor daemon lifecycle management and circuit control via the stem library.

Responsibilities:
  - Generate a torrc configuration file tailored to GhostRoute's requirements.
  - Launch Tor as a subprocess and wait for full bootstrap.
  - Provide stem Controller access for identity rotation (NEWNYM) and
    circuit introspection.
  - Implement stream isolation by returning unique (username, password) pairs
    keyed on a caller-supplied session_id — each unique pair forces Tor to use
    a separate circuit.
  - Expose bootstrap progress as a 0-100 integer for TUI display.

Tor must be installed on the system (``tor`` binary in PATH).
"""

from __future__ import annotations

import hashlib
import logging
import os
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

from stem import Signal, StreamStatus
from stem.control import Controller, EventType
from stem.process import launch_tor_with_config

from core.config import Config
from core.state import StateManager
from core.utils import get_tor_uid, run_cmd

logger = logging.getLogger("ghostroute.tor_manager")

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_SOCKS_PORT = 9050
DEFAULT_TRANS_PORT = 9040
DEFAULT_DNS_PORT = 5353
DEFAULT_CONTROL_PORT = 9051
DEFAULT_CONTROL_PASSWORD = "ghostroute_ctrl"
TORRC_PATH = "/tmp/ghostroute.torrc"
TOR_DATA_DIR = "/tmp/ghostroute_tor_data"
BOOTSTRAP_TIMEOUT = 90  # seconds


# ── Main class ────────────────────────────────────────────────────────────────


class TorManager:
    """
    Full lifecycle manager for the Tor daemon used by GhostRoute.

    The class wraps:
      * torrc template generation
      * subprocess launch with stem bootstrap monitoring
      * stem Controller connection for runtime control
      * NEWNYM (new identity) signalling
      * Circuit / exit-node introspection
      * Stream-isolated proxy credential generation

    Example::

        mgr = TorManager(config, state)
        mgr.start()
        host, port, user, pwd = mgr.get_stream_isolated_proxy("scan_session_1")
        mgr.new_identity()
        mgr.stop()
    """

    def __init__(self, config: Config, state: StateManager) -> None:
        """
        Initialise TorManager.

        Args:
            config: Loaded GhostRoute configuration object.
            state:  Shared runtime state manager.
        """
        self.config = config
        self.state = state

        self._socks_port: int = getattr(config, "tor_socks_port", DEFAULT_SOCKS_PORT)
        self._trans_port: int = getattr(config, "tor_trans_port", DEFAULT_TRANS_PORT)
        self._dns_port: int = getattr(config, "tor_dns_port", DEFAULT_DNS_PORT)
        self._control_port: int = getattr(config, "tor_control_port", DEFAULT_CONTROL_PORT)
        self._control_password: str = getattr(
            config, "tor_control_password", DEFAULT_CONTROL_PASSWORD
        )

        self._process: Optional[subprocess.Popen] = None
        self._controller: Optional[Controller] = None
        self._bootstrap_progress: int = 0
        self._circuits: dict[str, Any] = {}
        self._lock = threading.Lock()

        logger.debug(
            "TorManager initialised (SOCKS=%d, Trans=%d, DNS=%d, Ctrl=%d)",
            self._socks_port,
            self._trans_port,
            self._dns_port,
            self._control_port,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Start the Tor daemon and wait for a complete bootstrap.

        Steps:
          1. Write a torrc config file to TORRC_PATH.
          2. Ensure the data directory exists.
          3. Launch Tor via subprocess.
          4. Monitor bootstrap via stem until 100 % or timeout.
          5. Connect the stem Controller and authenticate.
          6. Register a CIRC event listener for circuit tracking.
          7. Update shared state.

        Raises:
            RuntimeError: If Tor fails to bootstrap within BOOTSTRAP_TIMEOUT seconds.
            FileNotFoundError: If the 'tor' binary is not installed.
        """
        if self.is_running():
            logger.warning("Tor is already running (PID %d) — skipping start()", self._process.pid)
            return

        logger.info("Starting Tor daemon…")
        torrc_path = self._write_torrc()

        # Ensure data directory exists
        Path(TOR_DATA_DIR).mkdir(parents=True, exist_ok=True)

        # Launch Tor subprocess
        try:
            self._process = subprocess.Popen(
                ["tor", "-f", torrc_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                "Tor binary not found. Install with: apt install tor"
            ) from exc

        logger.info("Tor process started (PID %d)", self._process.pid)

        # Wait for bootstrap
        if not self.wait_for_bootstrap(timeout=BOOTSTRAP_TIMEOUT):
            self._process.kill()
            raise RuntimeError(
                f"Tor failed to bootstrap within {BOOTSTRAP_TIMEOUT}s "
                f"(last progress: {self._bootstrap_progress}%)"
            )

        # Connect stem Controller
        self._connect_controller()

        # Update state
        self.state.set("tor_running", True)
        self.state.set("tor_pid", self._process.pid)
        self.state.set("tor_socks_port", self._socks_port)
        logger.info("Tor daemon fully bootstrapped and ready")

    def stop(self) -> None:
        """
        Gracefully stop the Tor daemon.

        Sends SIGTERM first; if Tor hasn't exited within 5 seconds, sends
        SIGKILL. Also closes the stem Controller connection and clears state.
        """
        logger.info("Stopping Tor daemon…")

        # Close stem controller first
        if self._controller is not None:
            try:
                self._controller.close()
            except Exception as exc:
                logger.warning("Error closing stem Controller: %s", exc)
            finally:
                self._controller = None

        if self._process is not None:
            try:
                # Attempt graceful shutdown via SIGTERM
                self._process.send_signal(signal.SIGTERM)
                try:
                    self._process.wait(timeout=5)
                    logger.info("Tor process exited gracefully")
                except subprocess.TimeoutExpired:
                    logger.warning("Tor did not exit in 5s — sending SIGKILL")
                    self._process.kill()
                    self._process.wait()
            except ProcessLookupError:
                logger.debug("Tor process already exited")
            finally:
                self._process = None

        # Clean up temp files
        for path in [TORRC_PATH]:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass

        self.state.set("tor_running", False)
        self.state.set("tor_pid", None)
        logger.info("Tor daemon stopped")

    def new_identity(self) -> None:
        """
        Request a new Tor circuit by sending the NEWNYM signal.

        This causes Tor to use different circuits for subsequent connections.
        Note: there is a minimum cooldown between NEWNYM signals (usually 10s).

        Raises:
            RuntimeError: If the Controller is not connected.
        """
        ctrl = self._require_controller()
        try:
            ctrl.signal(Signal.NEWNYM)
            logger.info("NEWNYM signal sent — new Tor identity requested")
        except Exception as exc:
            logger.error("Failed to send NEWNYM: %s", exc)
            raise RuntimeError(f"NEWNYM failed: {exc}") from exc

    def get_circuits(self) -> list[dict]:
        """
        Return a list of currently active Tor circuits with path information.

        Each circuit dict contains:
          - id         (str): circuit identifier
          - status     (str): e.g. 'BUILT', 'EXTENDING'
          - path       (list[dict]): list of hop dicts with 'fingerprint' and 'nickname'
          - purpose    (str): circuit purpose label

        Returns:
            List of circuit dicts. Empty list if controller unavailable.
        """
        ctrl = self._require_controller()
        circuits: list[dict] = []

        try:
            for circ in ctrl.get_circuits():
                path_info = []
                for fp, nickname in circ.path:
                    hop: dict[str, str] = {"fingerprint": fp, "nickname": nickname or ""}
                    # Try to get country from consensus
                    try:
                        desc = ctrl.get_network_status(fp, default=None)
                        if desc and hasattr(desc, "country"):
                            hop["country"] = desc.country or "??"
                        else:
                            hop["country"] = "??"
                    except Exception:
                        hop["country"] = "??"
                    path_info.append(hop)

                circuits.append({
                    "id": circ.id,
                    "status": str(circ.status),
                    "path": path_info,
                    "purpose": str(circ.purpose) if circ.purpose else "GENERAL",
                })
        except Exception as exc:
            logger.warning("Failed to retrieve circuits: %s", exc)

        return circuits

    def get_exit_node(self) -> dict:
        """
        Return information about the current Tor exit node.

        The exit node is the last hop of the first BUILT general-purpose circuit
        that has a complete 3-hop path.

        Returns:
            dict with keys: fingerprint, nickname, country, address.
            All values may be empty strings if the info is unavailable.
        """
        ctrl = self._require_controller()
        result = {
            "fingerprint": "",
            "nickname": "",
            "country": "",
            "address": "",
        }

        try:
            for circ in ctrl.get_circuits():
                if str(circ.status) != "BUILT" or len(circ.path) < 3:
                    continue
                exit_fp, exit_nick = circ.path[-1]
                result["fingerprint"] = exit_fp
                result["nickname"] = exit_nick or ""

                desc = ctrl.get_network_status(exit_fp, default=None)
                if desc:
                    result["address"] = str(desc.address) if desc.address else ""
                    result["country"] = str(desc.country) if hasattr(desc, "country") else ""
                break
        except Exception as exc:
            logger.warning("Could not retrieve exit node info: %s", exc)

        return result

    def get_stream_isolated_proxy(self, session_id: str) -> tuple[str, int, str, str]:
        """
        Return SOCKS5 proxy credentials that enforce stream isolation.

        Tor uses the SOCKS5 username/password to isolate streams onto separate
        circuits when IsolateSOCKSAuth is enabled in torrc (which our template
        includes). Each unique (username, password) pair gets its own circuit.

        Args:
            session_id: An arbitrary string identifying the caller's session
                        (e.g. a scan name, target host, or UUID). Different
                        session IDs will use different Tor circuits.

        Returns:
            Tuple of (host, port, username, password) suitable for use with
            a SOCKS5 library (e.g. PySocks / requests[socks]).
        """
        # Derive a stable but opaque credential from the session_id
        digest = hashlib.sha256(session_id.encode()).hexdigest()
        username = f"gr_{digest[:16]}"
        password = digest[16:32]

        logger.debug(
            "Stream-isolated proxy for session '%s': user=%s", session_id, username
        )
        return ("127.0.0.1", self._socks_port, username, password)

    def wait_for_bootstrap(self, timeout: int = 60) -> bool:
        """
        Block until Tor reports 100% bootstrap progress or timeout.

        Parses Tor's stdout output for BOOTSTRAP PROGRESS lines and updates
        the internal ``_bootstrap_progress`` counter.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            True if bootstrap reached 100%, False on timeout or process exit.
        """
        if self._process is None:
            logger.error("wait_for_bootstrap called but Tor process is None")
            return False

        deadline = time.monotonic() + timeout
        logger.info("Waiting for Tor bootstrap (timeout=%ds)…", timeout)

        while time.monotonic() < deadline:
            # Check if process died
            if self._process.poll() is not None:
                logger.error("Tor process exited during bootstrap (code %d)", self._process.returncode)
                return False

            line = self._process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue

            line = line.strip()
            logger.debug("Tor: %s", line)

            if "BOOTSTRAP" in line and "PROGRESS=" in line:
                try:
                    progress_str = line.split("PROGRESS=")[1].split()[0]
                    self._bootstrap_progress = int(progress_str)
                    logger.info("Tor bootstrap: %d%%", self._bootstrap_progress)
                    if self._bootstrap_progress >= 100:
                        logger.info("Tor bootstrap complete!")
                        return True
                except (IndexError, ValueError):
                    pass

            # Also catch the human-readable form from newer Tor versions
            if "Bootstrapped 100%" in line or "Done" in line and "100%" in line:
                self._bootstrap_progress = 100
                return True

        logger.error("Tor bootstrap timed out after %ds (progress=%d%%)", timeout, self._bootstrap_progress)
        return False

    def get_bootstrap_progress(self) -> int:
        """
        Return the last observed Tor bootstrap progress percentage.

        Returns:
            Integer 0-100.
        """
        return self._bootstrap_progress

    def is_running(self) -> bool:
        """
        Check whether the managed Tor subprocess is alive.

        Returns:
            True if the process exists and has not yet exited.
        """
        if self._process is None:
            return False
        return self._process.poll() is None

    # ── Private helpers ───────────────────────────────────────────────────────

    def _write_torrc(self) -> str:
        """
        Generate a torrc configuration file tailored for GhostRoute and write
        it to TORRC_PATH.

        Returns:
            Absolute path to the written torrc file.
        """
        # Hash the control password for HashedControlPassword directive
        try:
            result = run_cmd(
                ["tor", "--hash-password", self._control_password], check=True
            )
            hashed_pw = result.stdout.strip()
        except Exception as exc:
            logger.warning("Could not hash tor control password (%s) — using CookieAuth", exc)
            hashed_pw = None

        lines = [
            "# GhostRoute torrc — auto-generated, do not edit",
            f"SocksPort {self._socks_port} IsolateSOCKSAuth IsolateClientAddr",
            f"SocksPort 0.0.0.0:{self._socks_port} IsolateSOCKSAuth IsolateClientAddr",
            f"TransPort {self._trans_port}",
            f"DNSPort {self._dns_port}",
            f"ControlPort {self._control_port}",
            f"DataDirectory {TOR_DATA_DIR}",
            "Log notice stdout",
            "RunAsDaemon 0",
            # Stream isolation options
            "SocksPolicy accept 127.0.0.1",
            "SocksPolicy reject *",
            # Circuit configuration
            "MaxCircuitDirtiness 60",
            "NewCircuitPeriod 30",
            "EnforceDistinctSubnets 1",
            # Entry guard management
            "UseEntryGuards 1",
            "NumEntryGuards 3",
        ]

        if hashed_pw:
            lines.append(f"HashedControlPassword {hashed_pw}")
        else:
            lines.append("CookieAuthentication 1")

        torrc_content = "\n".join(lines) + "\n"

        try:
            Path(TORRC_PATH).write_text(torrc_content, encoding="utf-8")
            logger.debug("torrc written to %s", TORRC_PATH)
        except OSError as exc:
            logger.error("Failed to write torrc: %s", exc)
            raise

        return TORRC_PATH

    def _connect_controller(self) -> None:
        """
        Establish a stem Controller connection to the running Tor daemon.

        Authenticates using the configured control password (or cookie if
        hashing was unavailable). Registers circuit event listeners.

        Raises:
            RuntimeError: If the connection or authentication fails.
        """
        max_attempts = 10
        for attempt in range(1, max_attempts + 1):
            try:
                ctrl = Controller.from_port(port=self._control_port)
                ctrl.authenticate(password=self._control_password)
                self._controller = ctrl
                logger.info("stem Controller connected on port %d", self._control_port)

                # Register circuit event listener
                ctrl.add_event_listener(self._on_circ_event, EventType.CIRC)
                logger.debug("CIRC event listener registered")
                return
            except Exception as exc:
                if attempt == max_attempts:
                    raise RuntimeError(
                        f"Cannot connect to Tor controller after {max_attempts} attempts: {exc}"
                    ) from exc
                logger.debug(
                    "Controller connect attempt %d/%d failed: %s — retrying…",
                    attempt, max_attempts, exc,
                )
                time.sleep(1)

    def _require_controller(self) -> Controller:
        """
        Return the active Controller or raise RuntimeError if unavailable.
        """
        if self._controller is None:
            raise RuntimeError(
                "Tor Controller is not connected — call start() first"
            )
        return self._controller

    def _on_circ_event(self, event: Any) -> None:
        """
        Callback for stem CIRC events. Keeps the internal circuits dict in sync
        and updates shared state with circuit counts.

        Args:
            event: A stem CircuitEvent instance.
        """
        with self._lock:
            circ_id = event.id
            status = str(event.status)

            if status in ("CLOSED", "FAILED"):
                self._circuits.pop(circ_id, None)
            else:
                self._circuits[circ_id] = {
                    "id": circ_id,
                    "status": status,
                    "path": event.path,
                    "purpose": str(event.purpose) if event.purpose else "GENERAL",
                    "updated_at": time.time(),
                }

        self.state.set("tor_circuit_count", len(self._circuits))
        logger.debug("CIRC event: id=%s status=%s total=%d", circ_id, status, len(self._circuits))
