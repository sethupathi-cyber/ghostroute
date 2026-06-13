"""
ghostroute/core/state.py
========================
Runtime state management for GhostRoute.

Maintains two orthogonal views of the daemon's current condition:

* :class:`ModuleState` — which protection modules are currently active.
* :class:`RuntimeInfo` — live operational metrics (current IP, circuit
  counts, rotation statistics, etc.).

Both are stored as frozen-able :mod:`dataclasses` so they can be serialised
to JSON and reloaded across restarts.  The :class:`StateManager` owns both
objects and exposes a clean API consumed by every other subsystem.

The persistence file is written to ``/tmp/ghostroute.state.json`` so that it
survives short daemon restarts but is automatically cleaned up on reboot.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

log = logging.getLogger("ghostroute")

# Path where state is persisted between restarts.
STATE_FILE = Path("/tmp/ghostroute.state.json")


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class ModuleState:
    """Boolean activation flags for every GhostRoute protection module.

    Each field corresponds to a named subsystem.  A value of *True* means
    the module has been successfully started and is currently operative.
    """

    tor_routing: bool = False
    """Transparent Tor routing (iptables REDIRECT) is active."""

    tor_manager: bool = False
    """The embedded Tor process manager is running."""

    proxy_chain: bool = False
    """SOCKS5 proxy-chaining layer is active."""

    ip_rotator: bool = False
    """Automatic IP rotation scheduler is running."""

    obfs4: bool = False
    """obfs4 bridge-based traffic obfuscation is active."""

    meek: bool = False
    """Meek domain-fronting obfuscation tunnel is active."""

    packet_padding: bool = False
    """Random packet-padding module is injecting cover traffic."""

    protocol_mimicry: bool = False
    """Protocol-mimicry module is reshaping traffic patterns."""

    timing_jitter: bool = False
    """Timing-jitter module is adding randomised inter-packet delays."""

    dns_protect: bool = False
    """DNS protection (DNS-over-Tor / DNSCrypt / DoH) is active."""

    ipv6_block: bool = False
    """IPv6 traffic is being completely blocked via ip6tables."""

    kill_switch: bool = False
    """Hard / soft kill-switch is armed."""

    mac_spoof: bool = False
    """MAC-address spoofing has been applied to the active interface."""


@dataclass
class RuntimeInfo:
    """Live operational metrics collected by GhostRoute at runtime."""

    current_ip: str = "Unknown"
    """The last confirmed external IP address."""

    current_country: str = "Unknown"
    """Country associated with *current_ip* (from GeoIP lookup)."""

    current_isp: str = "Unknown"
    """ISP / AS name associated with *current_ip*."""

    active_circuits: int = 0
    """Number of active Tor circuits as reported by the Tor control port."""

    active_proxies: int = 0
    """Number of healthy proxies currently in the rotation pool."""

    rotation_count: int = 0
    """Total number of IP rotations performed in this session."""

    last_rotation: float = 0.0
    """Unix timestamp of the most recent IP rotation (0 if none)."""

    session_start: float = 0.0
    """Unix timestamp when the GhostRoute session was started."""

    tor_pid: int = 0
    """PID of the managed Tor process (0 if not running)."""

    proxy_pool_size: int = 0
    """Total number of proxies in the pool (healthy + unhealthy)."""


# ---------------------------------------------------------------------------
# State manager
# ---------------------------------------------------------------------------

class StateManager:
    """Central runtime state manager for GhostRoute.

    Owns a :class:`ModuleState` and a :class:`RuntimeInfo` instance, keeps
    them in sync with a JSON persistence file, and exposes a thread-safe-ish
    (GIL-protected) mutation API.

    Example usage::

        state = StateManager()
        state.load()
        state.set_module("tor_routing", True)
        state.update_runtime("current_ip", "1.2.3.4")
        state.save()

    Parameters
    ----------
    state_file:
        Path to the JSON file used for persistence.  Defaults to
        ``/tmp/ghostroute.state.json``.
    """

    def __init__(self, state_file: Path = STATE_FILE) -> None:
        self._state_file = state_file
        self._modules = ModuleState()
        self._runtime = RuntimeInfo()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def modules(self) -> ModuleState:
        """The :class:`ModuleState` dataclass instance (read-only access)."""
        return self._modules

    @property
    def runtime(self) -> RuntimeInfo:
        """The :class:`RuntimeInfo` dataclass instance (read-only access)."""
        return self._runtime

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load persisted state from the JSON file.

        If the file does not exist or is malformed the manager silently
        starts with fresh default values.  Fields present in the file but
        not in the current dataclass schema are ignored (forward-compat).

        Raises
        ------
        OSError
            If the file exists but cannot be opened due to permission errors.
        """
        if not self._state_file.exists():
            log.debug(
                "State file %s not found — starting with defaults.",
                self._state_file,
            )
            return

        try:
            raw = self._state_file.read_text(encoding="utf-8")
            data: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError as exc:
            log.warning(
                "State file is corrupt (%s) — starting with defaults.", exc
            )
            return

        # Restore ModuleState — only recognised fields.
        module_data: dict[str, Any] = data.get("modules", {})
        module_field_names = {f.name for f in fields(ModuleState)}
        for key, val in module_data.items():
            if key in module_field_names and isinstance(val, bool):
                setattr(self._modules, key, val)

        # Restore RuntimeInfo — only recognised fields.
        runtime_data: dict[str, Any] = data.get("runtime", {})
        runtime_field_names = {f.name for f in fields(RuntimeInfo)}
        for key, val in runtime_data.items():
            if key in runtime_field_names:
                setattr(self._runtime, key, val)

        log.debug("State loaded from %s.", self._state_file)

    def save(self) -> None:
        """Persist the current state to the JSON file.

        The file is written atomically (write to a temp file then rename) so
        that a crash mid-write never leaves a corrupt state file.

        Raises
        ------
        OSError
            If the target path is not writable.
        """
        payload = {
            "modules": asdict(self._modules),
            "runtime": asdict(self._runtime),
        }
        tmp_path = self._state_file.with_suffix(".tmp")
        try:
            tmp_path.write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
            tmp_path.replace(self._state_file)
        except OSError as exc:
            log.error("Failed to save state: %s", exc)
            raise

        log.debug("State saved to %s.", self._state_file)

    # ------------------------------------------------------------------
    # Module state API
    # ------------------------------------------------------------------

    def set_module(self, name: str, enabled: bool) -> None:
        """Enable or disable a named protection module.

        Parameters
        ----------
        name:
            Attribute name on :class:`ModuleState`, e.g. ``"tor_routing"``.
        enabled:
            *True* to mark the module as active; *False* to mark it inactive.

        Raises
        ------
        AttributeError
            If *name* is not a valid module field on :class:`ModuleState`.
        """
        if not hasattr(self._modules, name):
            raise AttributeError(
                f"Unknown module {name!r}. "
                f"Valid modules: {[f.name for f in fields(ModuleState)]}"
            )
        setattr(self._modules, name, bool(enabled))
        log.debug("Module %r set to %s.", name, enabled)

    def is_enabled(self, name: str) -> bool:
        """Return whether the named module is currently active.

        Parameters
        ----------
        name:
            Attribute name on :class:`ModuleState`.

        Returns
        -------
        bool
            *True* if the module flag is set; *False* otherwise.

        Raises
        ------
        AttributeError
            If *name* is not a recognised module.
        """
        if not hasattr(self._modules, name):
            raise AttributeError(
                f"Unknown module {name!r}. "
                f"Valid modules: {[f.name for f in fields(ModuleState)]}"
            )
        return bool(getattr(self._modules, name))

    def get_all_states(self) -> dict[str, bool]:
        """Return a dictionary mapping every module name to its boolean state.

        Returns
        -------
        dict[str, bool]
            E.g. ``{"tor_routing": True, "kill_switch": False, ...}``.
        """
        return asdict(self._modules)

    # ------------------------------------------------------------------
    # Runtime info API
    # ------------------------------------------------------------------

    def update_runtime(self, field: str, value: Any) -> None:
        """Update a single field on the :class:`RuntimeInfo` dataclass.

        Parameters
        ----------
        field:
            Attribute name on :class:`RuntimeInfo`, e.g. ``"current_ip"``.
        value:
            New value.  Must be compatible with the field's declared type.

        Raises
        ------
        AttributeError
            If *field* is not a recognised :class:`RuntimeInfo` attribute.
        """
        if not hasattr(self._runtime, field):
            raise AttributeError(
                f"Unknown RuntimeInfo field {field!r}. "
                f"Valid fields: {[f.name for f in fields(RuntimeInfo)]}"
            )
        setattr(self._runtime, field, value)
        log.debug("RuntimeInfo.%s updated to %r.", field, value)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def mark_session_start(self) -> None:
        """Record the current time as the session-start timestamp."""
        self._runtime.session_start = time.time()

    def increment_rotation_count(self) -> None:
        """Increment the rotation counter and update *last_rotation*."""
        self._runtime.rotation_count += 1
        self._runtime.last_rotation = time.time()

    def reset_modules(self) -> None:
        """Reset all module flags to *False* (e.g. on clean shutdown)."""
        for f in fields(ModuleState):
            setattr(self._modules, f.name, False)
        log.debug("All module states reset to False.")

    def reset_runtime(self) -> None:
        """Reset :class:`RuntimeInfo` to default values."""
        self._runtime = RuntimeInfo()
        log.debug("RuntimeInfo reset to defaults.")

    def __repr__(self) -> str:  # pragma: no cover
        active = [k for k, v in self.get_all_states().items() if v]
        return (
            f"<StateManager active_modules={active} "
            f"ip={self._runtime.current_ip!r}>"
        )
