"""
ghostroute/modules/obfuscation/__init__.py
==========================================
Obfuscation orchestrator for GhostRoute.

Manages all traffic obfuscation sub-modules (obfs4, meek, packet_padding,
protocol_mimicry, timing_jitter) through a unified API with priority-chain
ordering.  Only modules that are both available on the system AND enabled in
the configuration are activated.

Priority chain:
  Higher-priority modules are started first so that lower-priority layers wrap
  around them in sequence.  The default order mirrors typical deployment
  hardness: obfs4 → meek → packet_padding → protocol_mimicry → timing_jitter.

Author: GhostRoute Security Team
Python: 3.10+
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ghostroute.modules.obfuscation.obfs4 import Obfs4Transport
from ghostroute.modules.obfuscation.meek import MeekTransport
from ghostroute.modules.obfuscation.padding import PacketPaddingProxy
from ghostroute.modules.obfuscation.mimicry import ProtocolMimicry
from ghostroute.modules.obfuscation.timing import TimingJitter

if TYPE_CHECKING:
    from core.config import Config
    from core.state import StateManager

logger = logging.getLogger("ghostroute.obfuscation")

# Canonical module names recognised by this engine.
KNOWN_MODULES: tuple[str, ...] = (
    "obfs4",
    "meek",
    "packet_padding",
    "protocol_mimicry",
    "timing_jitter",
)

# Default priority order (index 0 = highest priority / started first).
DEFAULT_PRIORITY: list[str] = list(KNOWN_MODULES)


class ObfuscationEngineError(Exception):
    """Raised when the ObfuscationEngine encounters an unrecoverable error."""


class ObfuscationEngine:
    """
    Top-level orchestrator for GhostRoute traffic obfuscation.

    Each sub-module is created eagerly at construction time so that their
    availability can be checked immediately.  Modules are only *activated*
    when ``enable_all()`` or ``enable_module()`` is explicitly called.

    Parameters
    ----------
    config:
        Global GhostRoute configuration object (core.config.Config).
    state:
        Shared runtime state manager (core.state.StateManager).
    """

    def __init__(self, config: "Config", state: "StateManager") -> None:
        self._config = config
        self._state = state

        # Instantiate every sub-module — never start them yet.
        self.obfs4: Obfs4Transport = Obfs4Transport(config, state)
        self.meek: MeekTransport = MeekTransport(config, state)
        self.padding: PacketPaddingProxy = PacketPaddingProxy(config, state)
        self.mimicry: ProtocolMimicry = ProtocolMimicry(config, state)
        self.timing: TimingJitter = TimingJitter(config, state)

        # Map canonical names → module instances for generic dispatch.
        self._modules: dict[str, object] = {
            "obfs4": self.obfs4,
            "meek": self.meek,
            "packet_padding": self.padding,
            "protocol_mimicry": self.mimicry,
            "timing_jitter": self.timing,
        }

        # Track which modules are currently active (enabled).
        self._active: set[str] = set()

        # Load persisted priority from config, fall back to default.
        self._priority: list[str] = self._load_priority()

        logger.info(
            "ObfuscationEngine initialised. Priority chain: %s",
            " → ".join(self._priority),
        )

    # ------------------------------------------------------------------
    # Priority management
    # ------------------------------------------------------------------

    def _load_priority(self) -> list[str]:
        """
        Load the module priority order from the configuration file.

        Falls back to ``DEFAULT_PRIORITY`` if no order is persisted or if
        the stored value contains unknown module names.
        """
        try:
            stored: list[str] = self._config.get(
                "obfuscation.priority", default=[]
            )
            if not stored:
                return list(DEFAULT_PRIORITY)
            # Validate: keep only known names; append missing ones at end.
            valid = [m for m in stored if m in KNOWN_MODULES]
            missing = [m for m in KNOWN_MODULES if m not in valid]
            return valid + missing
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not load obfuscation priority from config: %s. "
                "Using default.",
                exc,
            )
            return list(DEFAULT_PRIORITY)

    def set_priority(self, priority_list: list[str]) -> None:
        """
        Set the active module priority order and persist it to the config.

        Parameters
        ----------
        priority_list:
            Ordered list of module names.  Must contain only recognised module
            names (see ``KNOWN_MODULES``).  Duplicate entries are deduplicated
            while preserving the first occurrence.

        Raises
        ------
        ValueError
            If an unknown module name is present in *priority_list*.
        """
        seen: set[str] = set()
        deduped: list[str] = []
        for name in priority_list:
            if name not in KNOWN_MODULES:
                raise ValueError(
                    f"Unknown obfuscation module: '{name}'. "
                    f"Known modules: {list(KNOWN_MODULES)}"
                )
            if name not in seen:
                seen.add(name)
                deduped.append(name)

        # Append any missing modules at the end to keep the list complete.
        for name in KNOWN_MODULES:
            if name not in seen:
                deduped.append(name)

        self._priority = deduped
        try:
            self._config.set("obfuscation.priority", self._priority)
            self._config.save()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to persist priority to config: %s", exc)

        logger.info(
            "Obfuscation priority updated: %s", " → ".join(self._priority)
        )

    def get_priority(self) -> list[str]:
        """Return the current module priority order (copy)."""
        return list(self._priority)

    # ------------------------------------------------------------------
    # Bulk enable / disable
    # ------------------------------------------------------------------

    def enable_all(self) -> None:
        """
        Enable all configured obfuscation modules in priority order.

        Modules that are not available on the current system (e.g. missing
        binaries) are skipped with a warning rather than raising an exception,
        so that partial deployments remain functional.
        """
        logger.info("Enabling all obfuscation modules (priority order).")
        errors: list[str] = []

        for name in self._priority:
            try:
                self.enable_module(name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not enable module '%s': %s", name, exc)
                errors.append(f"{name}: {exc}")

        if errors:
            logger.warning(
                "Some obfuscation modules failed to enable:\n  %s",
                "\n  ".join(errors),
            )

    def disable_all(self) -> None:
        """
        Disable all currently active obfuscation modules.

        Modules are disabled in *reverse* priority order so that the outer
        wrapping layers are torn down before the inner transport layers.
        """
        logger.info("Disabling all obfuscation modules.")
        # Disable in reverse order of priority.
        for name in reversed(self._priority):
            if name in self._active:
                try:
                    self.disable_module(name)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Error disabling module '%s': %s", name, exc
                    )

    # ------------------------------------------------------------------
    # Per-module enable / disable
    # ------------------------------------------------------------------

    def enable_module(self, name: str) -> None:
        """
        Enable a specific obfuscation module by name.

        Parameters
        ----------
        name:
            One of ``'obfs4'``, ``'meek'``, ``'packet_padding'``,
            ``'protocol_mimicry'``, ``'timing_jitter'``.

        Raises
        ------
        ValueError
            If *name* is not a recognised module name.
        ObfuscationEngineError
            If the module fails to start.
        """
        self._validate_name(name)

        if name in self._active:
            logger.debug("Module '%s' is already active — skipping.", name)
            return

        module = self._modules[name]

        # Availability check (modules that have a binary dependency).
        if hasattr(module, "is_available") and not module.is_available():
            raise ObfuscationEngineError(
                f"Module '{name}' is not available on this system "
                f"(missing binary or dependency)."
            )

        logger.info("Enabling obfuscation module: %s", name)
        try:
            module.enable()  # type: ignore[union-attr]
            self._active.add(name)
            logger.info("Module '%s' enabled successfully.", name)
        except Exception as exc:
            raise ObfuscationEngineError(
                f"Failed to enable module '{name}': {exc}"
            ) from exc

    def disable_module(self, name: str) -> None:
        """
        Disable a specific obfuscation module by name.

        Parameters
        ----------
        name:
            Module name to disable.

        Raises
        ------
        ValueError
            If *name* is not recognised.
        ObfuscationEngineError
            If the module fails to stop cleanly.
        """
        self._validate_name(name)

        if name not in self._active:
            logger.debug("Module '%s' is not active — nothing to disable.", name)
            return

        module = self._modules[name]
        logger.info("Disabling obfuscation module: %s", name)
        try:
            module.disable()  # type: ignore[union-attr]
            self._active.discard(name)
            logger.info("Module '%s' disabled successfully.", name)
        except Exception as exc:
            raise ObfuscationEngineError(
                f"Failed to disable module '{name}': {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Inspection helpers
    # ------------------------------------------------------------------

    def get_active_modules(self) -> list[str]:
        """Return the names of all currently enabled modules (sorted by priority)."""
        return [m for m in self._priority if m in self._active]

    def status(self) -> dict:
        """
        Return a comprehensive status snapshot of all obfuscation sub-modules.

        Returns
        -------
        dict
            Keys:
            - ``engine_active``: bool — True if at least one module is enabled.
            - ``active_modules``: list[str] — currently enabled module names.
            - ``priority``: list[str] — current priority chain.
            - ``modules``: dict[str, dict] — per-module status dictionaries.
        """
        module_statuses: dict[str, dict] = {}
        for name, module in self._modules.items():
            try:
                module_statuses[name] = module.status()  # type: ignore[union-attr]
            except Exception as exc:  # noqa: BLE001
                module_statuses[name] = {"error": str(exc)}

        return {
            "engine_active": bool(self._active),
            "active_modules": self.get_active_modules(),
            "priority": self.get_priority(),
            "modules": module_statuses,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_name(self, name: str) -> None:
        """Raise ValueError if *name* is not a known module name."""
        if name not in KNOWN_MODULES:
            raise ValueError(
                f"Unknown obfuscation module: '{name}'. "
                f"Valid options: {list(KNOWN_MODULES)}"
            )

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ObfuscationEngine active={self.get_active_modules()} "
            f"priority={self._priority}>"
        )
