"""
ghostroute/modules/ip_rotator.py
==================================
GhostRoute — IP Rotation Engine
---------------------------------
Manages automatic IP rotation across multiple modes:

  - **time**    : Rotate after a fixed interval (seconds).
  - **request** : Rotate after N HTTP requests.
  - **manual**  : User triggers rotation explicitly.

Integration points:
  - Calls ``tor_manager.new_identity()`` for Tor-based rotation.
  - Advances ``proxy_chain.get_next_proxy()`` for proxy rotation.
  - Fetches the new public IP to confirm the change.
  - Provides per-request isolated SOCKS5 credentials for separate Tor
    circuits (via ``IsolateSOCKSAuth`` and credential uniqueness).

Dependencies:
  pip install requests[socks] stem rich

Author: GhostRoute Security Team
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Optional

import requests
from requests.exceptions import RequestException

logger = logging.getLogger("ghostroute.ip_rotator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODE_TIME = "time"
MODE_REQUEST = "request"
MODE_MANUAL = "manual"

VALID_MODES = {MODE_TIME, MODE_REQUEST, MODE_MANUAL}

# Public IP discovery endpoints (tried in order)
IP_CHECK_URLS: list[str] = [
    "https://api.ipify.org?format=text",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://checkip.amazonaws.com",
    "https://ip.rootnet.in",
]

# Default Tor SOCKS5 proxy (local Tor daemon)
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050

# Tor supports credential-based circuit isolation.  Each unique
# (username, password) pair creates an independent Tor circuit when
# the ``IsolateSOCKSAuth`` option is enabled on the SOCKSPort.
TOR_CIRCUIT_ISOLATION_PORT = 9050   # same port; auth forces new circuit


# ---------------------------------------------------------------------------
# IPRotator
# ---------------------------------------------------------------------------

class IPRotator:
    """
    Automated IP rotation engine for GhostRoute.

    Supports three rotation modes:

    ``time``
        A background thread calls :meth:`rotate` after every *interval*
        seconds.

    ``request``
        :meth:`on_request` must be called for every outgoing HTTP request.
        When the internal counter reaches *requests_per_ip*, rotation is
        triggered automatically.

    ``manual``
        No automatic rotation; the caller invokes :meth:`rotate` directly.

    Example usage::

        rotator = IPRotator(config, state, tor_manager=tm, proxy_chain=pc)
        rotator.enable(mode='time')
        ...
        result = rotator.rotate(reason='scheduled')
        print(result['new_ip'])
    """

    def __init__(
        self,
        config: "Config",                   # type: ignore[name-defined]
        state: "StateManager",              # type: ignore[name-defined]
        tor_manager=None,
        proxy_chain=None,
    ) -> None:
        """
        Args:
            config:       GhostRoute :class:`~core.config.Config` instance.
            state:        GhostRoute :class:`~core.state.StateManager` instance.
            tor_manager:  Optional Tor manager with ``new_identity()`` method.
            proxy_chain:  Optional :class:`~modules.proxy_chain.ProxyChainEngine`.
        """
        self._config = config
        self._state = state
        self._tor = tor_manager
        self._proxy_chain = proxy_chain

        # ---- Runtime settings (can be changed at runtime) ----
        self._mode: str = str(getattr(config, "rotation_mode", MODE_MANUAL))
        self._interval: int = int(getattr(config, "rotation_interval", 60))
        self._requests_per_ip: int = int(getattr(config, "rotation_requests_per_ip", 10))

        # ---- State ----
        self._enabled: bool = False
        self._rotation_count: int = 0
        self._request_count: int = 0
        self._current_ip: str = ""
        self._last_rotation_time: float = 0.0
        self._lock = threading.RLock()

        # ---- Background timer thread ----
        self._timer_thread: Optional[threading.Thread] = None
        self._timer_stop = threading.Event()

        # ---- Circuit isolation ----
        # Maps request_id → (username, password) used for Tor isolation
        self._circuit_map: dict[str, tuple[str, str]] = {}

        logger.info(
            "IPRotator initialised (mode=%s, interval=%ds, req_per_ip=%d)",
            self._mode,
            self._interval,
            self._requests_per_ip,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def enable(self, mode: Optional[str] = None) -> None:
        """
        Activate the IP rotator.

        Args:
            mode: Rotation mode — ``'time'``, ``'request'``, or ``'manual'``.
                  If *None*, the mode configured in ``config`` is used.

        Raises:
            ValueError: If *mode* is not a recognised value.
        """
        if mode is not None:
            self.set_mode(mode)

        with self._lock:
            if self._enabled:
                logger.debug("IPRotator already enabled")
                return

            # Seed the current IP before starting rotation
            self._current_ip = self.get_current_ip()
            self._enabled = True
            self._request_count = 0

        self._state.set("ip_rotator_enabled", True)
        self._state.set("rotation_mode", self._mode)
        self._state.set("current_ip", self._current_ip)

        if self._mode == MODE_TIME:
            self._start_timer()

        logger.info(
            "IPRotator enabled (mode=%s, current_ip=%s)",
            self._mode,
            self._current_ip,
        )

    def disable(self) -> None:
        """
        Deactivate the IP rotator.

        Stops any running background timer thread and updates state.
        """
        with self._lock:
            if not self._enabled:
                return
            self._enabled = False

        self._stop_timer()
        self._state.set("ip_rotator_enabled", False)
        logger.info("IPRotator disabled (total rotations: %d)", self._rotation_count)

    # ------------------------------------------------------------------
    # Core rotation
    # ------------------------------------------------------------------

    def rotate(self, reason: str = "manual") -> dict:
        """
        Perform a single IP rotation.

        Rotation sequence:

        1. Record the old IP.
        2. If Tor is available → call ``tor_manager.new_identity()``.
        3. If a proxy chain is available → advance to the next proxy.
        4. Wait briefly for the new circuit / proxy to become active.
        5. Fetch the new public IP.
        6. Update state counters.
        7. Return a summary dict.

        Args:
            reason: Human-readable description of why rotation was triggered
                    (e.g. ``'scheduled'``, ``'request_limit'``, ``'manual'``).

        Returns:
            Dict with keys:
              - ``old_ip``      : Previous public IP address.
              - ``new_ip``      : New public IP address.
              - ``latency_ms``  : Time taken for the rotation + IP fetch (ms).
              - ``method``      : Rotation method used (``'tor'``, ``'proxy'``, ``'both'``).
              - ``success``     : Whether the IP actually changed.
              - ``reason``      : The *reason* argument passed in.
              - ``rotation_num``: Cumulative rotation counter.
        """
        start = time.perf_counter()
        method_parts: list[str] = []

        with self._lock:
            old_ip = self._current_ip

        logger.info("Rotating IP (reason=%s, old_ip=%s) …", reason, old_ip)

        # Step 1: Tor identity rotation
        if self._tor is not None:
            try:
                self._tor.new_identity()
                method_parts.append("tor")
                logger.debug("Tor new_identity() called successfully")
            except Exception as exc:
                logger.warning("Tor new_identity() failed: %s", exc)

        # Step 2: Proxy chain advancement
        if self._proxy_chain is not None:
            try:
                next_proxy = self._proxy_chain.get_next_proxy()
                if next_proxy:
                    method_parts.append("proxy")
                    logger.debug("Advanced to proxy: %s", next_proxy.address)
            except Exception as exc:
                logger.warning("Proxy chain advancement failed: %s", exc)

        # Step 3: Wait for circuit establishment
        # Tor needs ~1–3 s; proxies switch immediately.
        settle_time = 2.0 if "tor" in method_parts else 0.3
        time.sleep(settle_time)

        # Step 4: Confirm new IP
        new_ip = self.get_current_ip()
        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        # Step 5: Update counters
        with self._lock:
            self._rotation_count += 1
            self._request_count = 0
            self._current_ip = new_ip
            self._last_rotation_time = time.time()
            rotation_num = self._rotation_count

        # Step 6: Update state
        self._state.set("current_ip", new_ip)
        self._state.set("rotation_count", self._rotation_count)
        self._state.set("last_rotation", self._last_rotation_time)

        success = new_ip != old_ip
        method = "+".join(method_parts) if method_parts else "none"

        result = {
            "old_ip": old_ip,
            "new_ip": new_ip,
            "latency_ms": latency_ms,
            "method": method,
            "success": success,
            "reason": reason,
            "rotation_num": rotation_num,
        }

        if success:
            logger.info(
                "✓ Rotation #%d complete: %s → %s via %s (%.0f ms)",
                rotation_num, old_ip, new_ip, method, latency_ms,
            )
        else:
            logger.warning(
                "⚠ Rotation #%d: IP did not change (%s) via %s (%.0f ms)",
                rotation_num, new_ip, method, latency_ms,
            )

        return result

    # ------------------------------------------------------------------
    # Per-request integration
    # ------------------------------------------------------------------

    def on_request(self) -> None:
        """
        Notify the rotator that an outgoing HTTP request is being made.

        In ``request`` mode, increments the internal counter and triggers
        :meth:`rotate` when the threshold is reached.  In other modes, this
        is a no-op.
        """
        if not self._enabled or self._mode != MODE_REQUEST:
            return

        with self._lock:
            self._request_count += 1
            count = self._request_count
            threshold = self._requests_per_ip

        if count >= threshold:
            logger.debug(
                "Request threshold reached (%d/%d) — triggering rotation",
                count,
                threshold,
            )
            # Rotate in a daemon thread to avoid blocking the caller
            t = threading.Thread(
                target=self.rotate,
                kwargs={"reason": "request_limit"},
                daemon=True,
            )
            t.start()

    def get_proxy_for_request(self, request_id: str) -> dict:
        """
        Return an isolated SOCKS5 proxy configuration for a specific request.

        Each unique *request_id* receives a dedicated ``(username, password)``
        pair.  When used with a Tor daemon that has ``IsolateSOCKSAuth``
        enabled on the SOCKSPort, each pair forces a distinct Tor circuit,
        giving every request a different exit node.

        Args:
            request_id: Unique identifier for this request (e.g. UUID, task ID).

        Returns:
            Dict with keys ``http`` and ``https`` for use with
            ``requests.Session.proxies``.

        Example::

            proxies = rotator.get_proxy_for_request(str(uuid.uuid4()))
            resp = requests.get("https://example.com", proxies=proxies)
        """
        with self._lock:
            if request_id not in self._circuit_map:
                # Use a unique UUID pair to force circuit isolation
                username = f"user_{uuid.uuid4().hex[:12]}"
                password = uuid.uuid4().hex
                self._circuit_map[request_id] = (username, password)

            username, password = self._circuit_map[request_id]

        # Use configured Tor SOCKS port or fall back to default
        tor_host = str(getattr(self._config, "tor_socks_host", TOR_SOCKS_HOST))
        tor_port = int(getattr(self._config, "tor_socks_port", TOR_SOCKS_PORT))

        proxy_url = f"socks5h://{username}:{password}@{tor_host}:{tor_port}"
        return {"http": proxy_url, "https": proxy_url}

    # ------------------------------------------------------------------
    # Runtime reconfiguration
    # ------------------------------------------------------------------

    def set_interval(self, seconds: int) -> None:
        """
        Change the time-based rotation interval at runtime.

        If the rotator is currently running in ``time`` mode, the background
        thread is restarted with the new interval.

        Args:
            seconds: New interval in seconds (must be ≥ 1).

        Raises:
            ValueError: If *seconds* is less than 1.
        """
        if seconds < 1:
            raise ValueError(f"Rotation interval must be ≥ 1 second, got {seconds}")

        with self._lock:
            self._interval = seconds

        self._state.set("rotation_interval", seconds)
        logger.info("Rotation interval changed to %d seconds", seconds)

        # Restart timer thread with new interval if currently in time mode
        if self._enabled and self._mode == MODE_TIME:
            self._stop_timer()
            self._start_timer()

    def set_requests_per_ip(self, count: int) -> None:
        """
        Change the request-count rotation threshold at runtime.

        Args:
            count: Number of requests before triggering rotation (must be ≥ 1).

        Raises:
            ValueError: If *count* is less than 1.
        """
        if count < 1:
            raise ValueError(f"Requests per IP must be ≥ 1, got {count}")

        with self._lock:
            self._requests_per_ip = count

        self._state.set("rotation_requests_per_ip", count)
        logger.info("Requests-per-IP threshold changed to %d", count)

    def set_mode(self, mode: str) -> None:
        """
        Switch the rotation mode at runtime.

        Stops the background timer if switching away from ``time`` mode, and
        starts it if switching to ``time`` mode while the rotator is enabled.

        Args:
            mode: One of ``'time'``, ``'request'``, or ``'manual'``.

        Raises:
            ValueError: If *mode* is not recognised.
        """
        if mode not in VALID_MODES:
            raise ValueError(
                f"Invalid rotation mode {mode!r}. Valid: {sorted(VALID_MODES)}"
            )

        with self._lock:
            old_mode = self._mode
            self._mode = mode

        if old_mode == MODE_TIME and mode != MODE_TIME:
            self._stop_timer()

        if mode == MODE_TIME and self._enabled:
            self._start_timer()

        self._state.set("rotation_mode", mode)
        logger.info("Rotation mode changed: %s → %s", old_mode, mode)

    # ------------------------------------------------------------------
    # IP discovery
    # ------------------------------------------------------------------

    def get_current_ip(self) -> str:
        """
        Fetch the current public IP address by probing external echo services.

        Routes the request through Tor / proxy if available, so the returned
        IP reflects the anonymised exit address.

        Returns:
            IP address string, or ``"unknown"`` if all endpoints fail.
        """
        proxies: dict[str, str] = {}

        # Build proxy dict for requests
        if self._tor is not None:
            tor_host = str(getattr(self._config, "tor_socks_host", TOR_SOCKS_HOST))
            tor_port = int(getattr(self._config, "tor_socks_port", TOR_SOCKS_PORT))
            proxy_url = f"socks5h://{tor_host}:{tor_port}"
            proxies = {"http": proxy_url, "https": proxy_url}

        elif self._proxy_chain is not None:
            node = self._proxy_chain.get_next_proxy()
            if node:
                proxies = {"http": node.url, "https": node.url}

        for url in IP_CHECK_URLS:
            try:
                resp = requests.get(
                    url,
                    proxies=proxies if proxies else None,
                    timeout=10,
                )
                ip = resp.text.strip()
                if ip:
                    logger.debug("Current IP from %s: %s", url, ip)
                    return ip
            except RequestException as exc:
                logger.debug("IP check failed for %s: %s", url, exc)
                continue
            except Exception as exc:
                logger.debug("Unexpected error during IP check: %s", exc)
                continue

        logger.warning("All IP discovery endpoints failed — returning 'unknown'")
        return "unknown"

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """
        Return the current state of the IP rotator.

        Returns:
            Dict containing:
              - ``mode``               : Current rotation mode.
              - ``enabled``            : Whether the rotator is active.
              - ``interval_seconds``   : Time-mode interval.
              - ``requests_per_ip``    : Request-mode threshold.
              - ``request_count``      : Current request count toward threshold.
              - ``rotation_count``     : Total rotations performed.
              - ``current_ip``         : Current public IP.
              - ``last_rotation_time`` : Unix timestamp of last rotation.
              - ``last_rotation_ago``  : Seconds since last rotation.
              - ``tor_available``      : Whether Tor manager is attached.
              - ``proxy_available``    : Whether proxy chain is attached.
        """
        with self._lock:
            now = time.time()
            last_ago = (
                round(now - self._last_rotation_time, 1)
                if self._last_rotation_time
                else None
            )
            return {
                "mode": self._mode,
                "enabled": self._enabled,
                "interval_seconds": self._interval,
                "requests_per_ip": self._requests_per_ip,
                "request_count": self._request_count,
                "rotation_count": self._rotation_count,
                "current_ip": self._current_ip,
                "last_rotation_time": self._last_rotation_time,
                "last_rotation_ago": last_ago,
                "tor_available": self._tor is not None,
                "proxy_available": self._proxy_chain is not None,
            }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _start_timer(self) -> None:
        """Start the background timer rotation thread."""
        if self._timer_thread and self._timer_thread.is_alive():
            return

        self._timer_stop.clear()
        self._timer_thread = threading.Thread(
            target=self._timer_loop,
            name="ip-rotation-timer",
            daemon=True,
        )
        self._timer_thread.start()
        logger.info("Rotation timer thread started (interval=%ds)", self._interval)

    def _stop_timer(self) -> None:
        """Signal and join the timer thread."""
        self._timer_stop.set()
        if self._timer_thread and self._timer_thread.is_alive():
            self._timer_thread.join(timeout=5)
            logger.debug("Rotation timer thread stopped")

    def _timer_loop(self) -> None:
        """
        Background loop for time-based IP rotation.

        Waits for ``_interval`` seconds between each rotation.  Uses an
        :class:`threading.Event` so it wakes immediately when signalled to
        stop (avoids a full-interval delay on disable).
        """
        logger.debug("Timer loop started with interval=%ds", self._interval)
        while not self._timer_stop.wait(timeout=self._interval):
            if not self._enabled:
                break
            try:
                self.rotate(reason="scheduled")
            except Exception as exc:
                logger.error("Timer rotation failed: %s", exc, exc_info=True)
        logger.debug("Timer loop exiting")
