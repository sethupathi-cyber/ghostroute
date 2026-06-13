"""
GhostRoute — Timing Jitter Obfuscation Module
Injects randomised delays into outbound connections to defeat
traffic timing correlation attacks.
"""

import logging
import random
import time
import threading

from core.config import Config
from core.state import StateManager

logger = logging.getLogger("ghostroute.obfuscation.timing")


class TimingJitter:
    """
    Timing Jitter Injection.

    Adds a random delay before data is transmitted. This disrupts
    end-to-end timing correlation attacks where an adversary monitors
    both the Tor entry and exit simultaneously to correlate traffic
    by packet timing patterns.

    Usage:
        jitter.apply_jitter()          # Sleep for random duration
        jitter.wrap_send(send_fn, data)  # Apply jitter then send
    """

    def __init__(self, config: Config, state: StateManager) -> None:
        self.config = config
        self.state = state

        obf_cfg = config.get_section("obfuscation") or {}
        timing_cfg = obf_cfg.get("timing", {})

        self._min_ms: int = timing_cfg.get("min_jitter_ms", 5)
        self._max_ms: int = timing_cfg.get("max_jitter_ms", 200)
        self._active: bool = False
        self._jitter_count: int = 0
        self._total_jitter_ms: float = 0.0
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def enable(self) -> None:
        """Enable timing jitter."""
        self._active = True
        self._jitter_count = 0
        self._total_jitter_ms = 0.0
        self.state.set_module("timing_jitter", True)
        logger.info(
            f"[TimingJitter] ✓ Timing jitter ENABLED "
            f"(range: {self._min_ms}–{self._max_ms}ms)"
        )

    def disable(self) -> None:
        """Disable timing jitter."""
        self._active = False
        self.state.set_module("timing_jitter", False)
        logger.info("[TimingJitter] Timing jitter disabled.")

    def set_range(self, min_ms: int, max_ms: int) -> None:
        """
        Update the jitter range at runtime.

        Args:
            min_ms: Minimum jitter in milliseconds
            max_ms: Maximum jitter in milliseconds
        """
        if min_ms < 0 or max_ms < min_ms:
            raise ValueError(f"Invalid jitter range: min={min_ms}, max={max_ms}")
        self._min_ms = min_ms
        self._max_ms = max_ms
        logger.info(f"[TimingJitter] Range updated: {min_ms}–{max_ms}ms")

    def apply_jitter(self) -> float:
        """
        Sleep for a random duration within the configured range.

        Returns:
            Actual sleep duration in milliseconds.
        """
        if not self._active:
            return 0.0

        # Use uniform distribution; could also use exponential for more realism
        jitter_ms = random.uniform(self._min_ms, self._max_ms)
        time.sleep(jitter_ms / 1000.0)

        with self._lock:
            self._jitter_count += 1
            self._total_jitter_ms += jitter_ms

        logger.debug(f"[TimingJitter] Applied {jitter_ms:.1f}ms jitter")
        return jitter_ms

    def wrap_send(self, send_func, data: bytes) -> None:
        """
        Wrapper: apply timing jitter, then call send_func(data).

        Args:
            send_func: Callable that sends data (e.g., socket.send)
            data:      Bytes to send
        """
        self.apply_jitter()
        send_func(data)

    def get_avg_jitter(self) -> float:
        """Return average applied jitter in milliseconds."""
        with self._lock:
            if self._jitter_count == 0:
                return 0.0
            return self._total_jitter_ms / self._jitter_count

    def status(self) -> dict:
        """Return timing jitter status."""
        return {
            "active": self._active,
            "min_ms": self._min_ms,
            "max_ms": self._max_ms,
            "jitter_count": self._jitter_count,
            "avg_jitter_ms": round(self.get_avg_jitter(), 2),
        }
