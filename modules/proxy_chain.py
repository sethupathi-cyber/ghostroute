"""
ghostroute/modules/proxy_chain.py
==================================
GhostRoute — Proxy Chain Engine
--------------------------------
Provides a fully-featured proxy scraping, validation, and chaining system
that drives proxychains4 for system-wide anonymity.

Components:
  - ProxyNode       : Dataclass representing a single proxy endpoint.
  - ProxyScraper    : Concurrently fetches and parses proxy lists from the web.
  - ProxyValidator  : Tests connectivity, measures latency, detects anonymity.
  - ProxyChainEngine: Orchestrates the full proxy lifecycle; writes
                      /etc/proxychains4.conf and integrates with GhostRoute
                      state/config subsystems.

Dependencies:
  pip install requests[socks] PySocks rich

Author: GhostRoute Security Team
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
import random

import requests
from requests.exceptions import RequestException

# ---------------------------------------------------------------------------
# Lazy imports — optional heavy deps (stem, rich) imported only when needed.
# ---------------------------------------------------------------------------
logger = logging.getLogger("ghostroute.proxy_chain")

# ---------------------------------------------------------------------------
# Default public proxy sources (plain-text IP:PORT lists)
# ---------------------------------------------------------------------------
DEFAULT_PROXY_SOURCES: list[str] = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]

# Mapping file-name / URL hints → protocol string
_PROTO_HINTS: dict[str, str] = {
    "socks5": "socks5",
    "socks4": "socks4",
    "http": "http",
    "https": "http",
}

ANONYMITY_ELITE = "elite"
ANONYMITY_ANONYMOUS = "anonymous"
ANONYMITY_TRANSPARENT = "transparent"
ANONYMITY_UNKNOWN = "unknown"

PROXYCHAINS_CONF_PATH = "/etc/proxychains4.conf"
PROXYCHAINS_BACKUP_PATH = "/etc/proxychains4.conf.ghostroute.bak"

# ---------------------------------------------------------------------------
# ProxyNode
# ---------------------------------------------------------------------------

@dataclass
class ProxyNode:
    """
    Represents a single proxy endpoint with associated metadata used for
    scoring, selection, and configuration file generation.
    """

    host: str
    port: int
    protocol: str = "socks5"          # socks4 | socks5 | http
    username: str = ""
    password: str = ""
    latency_ms: float = 0.0           # Measured round-trip latency in ms
    reputation_score: float = 1.0     # 0.0 – 1.0; decreases on failure
    anonymity: str = ANONYMITY_UNKNOWN # transparent | anonymous | elite
    country: str = ""
    last_check: float = 0.0           # Unix timestamp of last validation
    alive: bool = True
    fail_count: int = 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def address(self) -> str:
        """Return host:port string."""
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        """Return proxy URL for requests library."""
        if self.username and self.password:
            return f"{self.protocol}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}:{self.port}"

    @property
    def proxychains_line(self) -> str:
        """
        Format the proxy as a proxychains4.conf entry.
        Example: socks5 192.168.1.1 1080 user pass
        """
        parts = [self.protocol, self.host, str(self.port)]
        if self.username:
            parts.append(self.username)
        if self.password:
            parts.append(self.password)
        return " ".join(parts)

    def to_dict(self) -> dict:
        """Serialise to a plain dict (for JSON/YAML state snapshots)."""
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "username": self.username,
            "password": self.password,
            "latency_ms": round(self.latency_ms, 2),
            "reputation_score": round(self.reputation_score, 3),
            "anonymity": self.anonymity,
            "country": self.country,
            "last_check": self.last_check,
            "alive": self.alive,
            "fail_count": self.fail_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ProxyNode":
        """Deserialise from a plain dict."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# ProxyScraper
# ---------------------------------------------------------------------------

class ProxyScraper:
    """
    Fetches proxy lists from multiple public sources concurrently and parses
    them into :class:`ProxyNode` instances.

    Supported line formats:
      - ``ip:port``
      - ``ip:port:protocol``
      - ``ip:port:protocol:username:password``
      - ``ip:port:username:password``   (protocol inferred from URL hint)
    """

    def __init__(self, sources: list[str] | None = None) -> None:
        """
        Initialise the scraper.

        Args:
            sources: List of URLs to fetch proxy lists from.  Defaults to
                     :data:`DEFAULT_PROXY_SOURCES` when *None*.
        """
        self._sources: list[str] = sources if sources is not None else list(DEFAULT_PROXY_SOURCES)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 GhostRoute/1.0"})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scrape_all(self, workers: int = 10) -> list[ProxyNode]:
        """
        Fetch all sources concurrently.

        Args:
            workers: Maximum number of parallel download threads.

        Returns:
            Deduplicated list of :class:`ProxyNode` objects.
        """
        nodes: list[ProxyNode] = []
        seen: set[str] = set()

        logger.info("Starting proxy scrape from %d sources", len(self._sources))

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scraper") as pool:
            future_map = {pool.submit(self._scrape_source, url): url for url in self._sources}
            for future in as_completed(future_map):
                url = future_map[future]
                try:
                    batch = future.result()
                    for node in batch:
                        key = f"{node.host}:{node.port}"
                        if key not in seen:
                            seen.add(key)
                            nodes.append(node)
                    logger.debug("Source %s yielded %d unique proxies", url, len(batch))
                except Exception as exc:
                    logger.warning("Failed to scrape %s: %s", url, exc)

        logger.info("Scraped %d unique proxies in total", len(nodes))
        return nodes

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scrape_source(self, url: str) -> list[ProxyNode]:
        """
        Fetch one source URL and parse every line into ProxyNode objects.

        Args:
            url: Remote URL serving a plain-text proxy list.

        Returns:
            List of successfully parsed :class:`ProxyNode` instances.
        """
        # Infer default protocol from URL path
        default_proto = "socks5"
        url_lower = url.lower()
        for hint, proto in _PROTO_HINTS.items():
            if hint in url_lower:
                default_proto = proto
                break

        try:
            resp = self._session.get(url, timeout=15)
            resp.raise_for_status()
        except RequestException as exc:
            logger.debug("HTTP error fetching %s: %s", url, exc)
            return []

        nodes: list[ProxyNode] = []
        for line in resp.text.splitlines():
            node = self._parse_proxy_line(line.strip(), default_proto=default_proto)
            if node is not None:
                nodes.append(node)
        return nodes

    def _parse_proxy_line(self, line: str, default_proto: str = "socks5") -> Optional["ProxyNode"]:
        """
        Parse a single line from a proxy list into a :class:`ProxyNode`.

        Accepted formats (any delimiter: colon or whitespace)::

            192.168.1.1:1080
            192.168.1.1:1080:socks5
            192.168.1.1:1080:socks5:user:pass
            192.168.1.1:1080:user:pass

        Args:
            line: Raw text line.
            default_proto: Protocol to assign when not present in the line.

        Returns:
            A :class:`ProxyNode` or *None* if the line cannot be parsed.
        """
        if not line or line.startswith("#"):
            return None

        # Normalise separators — allow whitespace or colons
        parts = re.split(r"[\s:]+", line)

        # Minimum: host + port
        if len(parts) < 2:
            return None

        host, port_str = parts[0], parts[1]

        # Validate host (IPv4 or hostname)
        if not re.match(r"^[\w.\-]+$", host):
            return None

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                return None
        except ValueError:
            return None

        # Determine protocol and optional credentials
        protocol = default_proto
        username = ""
        password = ""

        if len(parts) == 3:
            # Could be protocol or username — check against known protocols
            candidate = parts[2].lower()
            if candidate in ("socks4", "socks5", "http", "https"):
                protocol = "http" if candidate == "https" else candidate
            else:
                # Treat as username with no password — unusual but accepted
                username = parts[2]

        elif len(parts) == 4:
            # Either proto:user or user:pass (no proto)
            candidate = parts[2].lower()
            if candidate in ("socks4", "socks5", "http", "https"):
                protocol = "http" if candidate == "https" else candidate
                username = parts[3]
            else:
                username = parts[2]
                password = parts[3]

        elif len(parts) >= 5:
            # proto:user:pass (or more fields — take first 5)
            candidate = parts[2].lower()
            if candidate in ("socks4", "socks5", "http", "https"):
                protocol = "http" if candidate == "https" else candidate
                username = parts[3]
                password = parts[4]
            else:
                username = parts[2]
                password = parts[3]

        return ProxyNode(
            host=host,
            port=port,
            protocol=protocol,
            username=username,
            password=password,
        )


# ---------------------------------------------------------------------------
# ProxyValidator
# ---------------------------------------------------------------------------

class ProxyValidator:
    """
    Tests a list of :class:`ProxyNode` instances for liveness, measures
    round-trip latency, and classifies their anonymity level.

    Anonymity classification:
      - **elite**       : No identifying headers leaked; IP is not in response.
      - **anonymous**   : Via / Proxy-Connection headers present but no real IP.
      - **transparent** : X-Forwarded-For or X-Real-IP contains client address.
    """

    # Public IP check endpoints (redundancy)
    _CHECK_URLS = [
        "https://httpbin.org/anything",
        "http://httpbin.org/anything",
    ]

    def __init__(self, timeout: int = 10) -> None:
        """
        Args:
            timeout: Socket / HTTP timeout in seconds for each validation probe.
        """
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_all(
        self,
        proxies: list[ProxyNode],
        workers: int = 20,
    ) -> list[ProxyNode]:
        """
        Validate a list of proxies concurrently.

        Args:
            proxies: Proxy nodes to test.
            workers: Thread pool size.

        Returns:
            Sorted list of *alive* proxies (lowest latency first).
        """
        logger.info("Validating %d proxies with %d workers …", len(proxies), workers)
        alive: list[ProxyNode] = []

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="validator") as pool:
            future_map = {pool.submit(self.validate_one, p): p for p in proxies}
            for future in as_completed(future_map):
                try:
                    node = future.result()
                    if node.alive:
                        alive.append(node)
                except Exception as exc:
                    logger.debug("Validation future raised: %s", exc)

        alive.sort(key=lambda n: n.latency_ms)
        logger.info("%d / %d proxies are alive", len(alive), len(proxies))
        return alive

    def validate_one(self, proxy: ProxyNode) -> ProxyNode:
        """
        Test a single proxy for connectivity, latency, and anonymity.

        Connects through the proxy to an HTTP echo service and inspects the
        response headers / body to classify anonymity level.

        Args:
            proxy: The proxy node to test (mutated in-place and returned).

        Returns:
            The same :class:`ProxyNode` with updated fields.
        """
        proxy.last_check = time.time()
        proxy.alive = False

        proxies_dict = {
            "http": proxy.url,
            "https": proxy.url,
        }

        for check_url in self._CHECK_URLS:
            try:
                start = time.perf_counter()
                resp = requests.get(
                    check_url,
                    proxies=proxies_dict,
                    timeout=self._timeout,
                    allow_redirects=True,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000

                if resp.status_code == 200:
                    proxy.alive = True
                    proxy.latency_ms = round(elapsed_ms, 2)
                    proxy.fail_count = 0
                    proxy.anonymity = self._detect_anonymity(
                        dict(resp.headers),
                        resp.text,
                        proxy.host,
                    )
                    return proxy

            except RequestException:
                continue
            except Exception as exc:
                logger.debug("Unexpected validation error for %s: %s", proxy.address, exc)
                continue

        # All endpoints failed
        proxy.fail_count += 1
        proxy.reputation_score = max(0.0, proxy.reputation_score - 0.1)
        return proxy

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_anonymity(
        self,
        response_headers: dict,
        response_body: str,
        real_proxy_ip: str,
    ) -> str:
        """
        Determine the anonymity level of a proxy based on HTTP headers returned
        by an echo endpoint.

        Decision logic:

        1. If X-Forwarded-For or X-Real-IP in headers/body → **transparent**.
        2. If Via, Proxy-Connection, X-Proxy-Id, etc. present → **anonymous**.
        3. None of the above → **elite**.

        Args:
            response_headers: Response header dict from the echo endpoint.
            response_body:    Raw response body text.
            real_proxy_ip:    The proxy's own IP address (not our real IP).

        Returns:
            One of: ``'transparent'``, ``'anonymous'``, ``'elite'``.
        """
        # Normalise header keys to lower-case
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        # Leak indicators — presence suggests client IP is exposed
        transparent_indicators = [
            "x-forwarded-for",
            "x-real-ip",
            "x-client-ip",
            "client-ip",
            "forwarded",
            "x-originating-ip",
        ]

        # Proxy self-identification headers — reveals proxy presence but not
        # the real client IP.
        anonymous_indicators = [
            "via",
            "proxy-connection",
            "x-proxy-id",
            "x-proxy-by",
            "proxy-agent",
        ]

        # Check for transparent leak: any header that typically carries the
        # original client IP.
        for h in transparent_indicators:
            if h in headers_lower:
                return ANONYMITY_TRANSPARENT

        # Check body for our *real* public IP embedded in the response (some
        # transparent proxies add it only to the body JSON).
        # We cannot know the user's actual public IP here, so we look for any
        # IP-like string that differs from the proxy host.
        body_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", response_body)
        for ip in body_ips:
            if ip != real_proxy_ip and not ip.startswith(("10.", "172.", "192.168.", "127.")):
                return ANONYMITY_TRANSPARENT

        # Check for anonymous proxy headers
        for h in anonymous_indicators:
            if h in headers_lower:
                return ANONYMITY_ANONYMOUS

        return ANONYMITY_ELITE


# ---------------------------------------------------------------------------
# ProxyChainEngine
# ---------------------------------------------------------------------------

class ProxyChainEngine:
    """
    High-level proxy chain orchestrator for GhostRoute.

    Responsibilities:
      - Scrape public proxy sources and validate them.
      - Maintain a scored pool of live proxies.
      - Write / restore ``/etc/proxychains4.conf``.
      - Provide rotation strategies: round-robin, random, latency-based.
      - Run a background health-monitor thread.
    """

    # Selection modes
    MODE_ROUND_ROBIN = "round_robin"
    MODE_RANDOM = "random"
    MODE_LATENCY = "latency"

    def __init__(self, config: "Config", state: "StateManager") -> None:  # type: ignore[name-defined]
        """
        Args:
            config:  GhostRoute :class:`~core.config.Config` instance.
            state:   GhostRoute :class:`~core.state.StateManager` instance.
        """
        self._config = config
        self._state = state

        # Proxy pool — all known proxies regardless of alive status.
        self._pool: list[ProxyNode] = []
        self._pool_lock = threading.RLock()

        # Round-robin cursor
        self._rr_index: int = 0

        # Per-session proxy assignments: session_id → ProxyNode
        self._session_map: dict[str, ProxyNode] = {}

        # Background health monitor thread handle
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_stop = threading.Event()

        # Scraper / validator helpers
        sources = getattr(config, "proxy_sources", None) or DEFAULT_PROXY_SOURCES
        self._scraper = ProxyScraper(sources=sources)
        timeout = getattr(config, "proxy_timeout", 10)
        self._validator = ProxyValidator(timeout=timeout)

        # Interval (seconds) between background health checks
        self._health_interval: int = int(getattr(config, "proxy_health_interval", 300))

        # Chain length used when writing proxychains4.conf
        self._chain_length: int = int(getattr(config, "proxy_chain_length", 3))

        # Selection mode
        self._selection_mode: str = getattr(
            config, "proxy_selection_mode", self.MODE_LATENCY
        )

        logger.info("ProxyChainEngine initialised (mode=%s)", self._selection_mode)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def enable(self) -> None:
        """
        Activate the proxy chain subsystem.

        Steps:
          1. Load any proxies from the configured proxy file (if set).
          2. If the pool is empty, scrape + validate from public sources.
          3. Write ``/etc/proxychains4.conf``.
          4. Start the background health monitor.
          5. Update GhostRoute state.
        """
        logger.info("Enabling ProxyChainEngine …")

        proxy_file = getattr(self._config, "proxy_file", None)
        if proxy_file and os.path.isfile(proxy_file):
            self.load_from_file(proxy_file)

        if not self._live_proxies():
            self.scrape_and_validate()

        if not self._live_proxies():
            logger.warning("No live proxies available — proxy chain is empty")
            return

        self.write_proxychains_conf()
        self.start_health_monitor()
        self._state.set("proxy_chain_enabled", True)
        self._state.set("proxy_pool_size", len(self._live_proxies()))
        logger.info("ProxyChainEngine enabled with %d live proxies", len(self._live_proxies()))

    def disable(self) -> None:
        """
        Deactivate the proxy chain subsystem.

        Stops the health monitor, restores the original proxychains4.conf
        backup (if it exists), and updates state.
        """
        logger.info("Disabling ProxyChainEngine …")
        self._stop_health_monitor()
        self._restore_proxychains_conf()
        self._state.set("proxy_chain_enabled", False)
        logger.info("ProxyChainEngine disabled")

    # ------------------------------------------------------------------
    # Proxy pool management
    # ------------------------------------------------------------------

    def load_from_file(self, path: str) -> None:
        """
        Parse a user-supplied proxy file and add all valid entries to the pool.

        Accepted formats per line::

            ip:port
            ip:port:protocol
            ip:port:protocol:username:password

        Args:
            path: Absolute or relative path to the proxy list file.

        Raises:
            FileNotFoundError: If *path* does not exist.
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Proxy file not found: {path}")

        parser = ProxyScraper()
        nodes: list[ProxyNode] = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                node = parser._parse_proxy_line(line.strip())
                if node is not None:
                    nodes.append(node)

        with self._pool_lock:
            existing_keys = {f"{n.host}:{n.port}" for n in self._pool}
            added = 0
            for node in nodes:
                key = f"{node.host}:{node.port}"
                if key not in existing_keys:
                    self._pool.append(node)
                    existing_keys.add(key)
                    added += 1

        logger.info("Loaded %d proxies from %s (%d new)", len(nodes), path, added)

    def scrape_and_validate(self, scraper_workers: int = 10, validator_workers: int = 20) -> None:
        """
        Scrape public sources and validate the results, updating the pool with
        live proxies.

        Args:
            scraper_workers:   Threads for concurrent source fetching.
            validator_workers: Threads for concurrent proxy validation.
        """
        logger.info("Scraping public proxy sources …")
        raw = self._scraper.scrape_all(workers=scraper_workers)
        logger.info("Validating %d scraped proxies …", len(raw))
        live = self._validator.validate_all(raw, workers=validator_workers)

        with self._pool_lock:
            existing_keys = {f"{n.host}:{n.port}" for n in self._pool}
            added = 0
            for node in live:
                key = f"{node.host}:{node.port}"
                if key not in existing_keys:
                    self._pool.append(node)
                    existing_keys.add(key)
                    added += 1

        logger.info("Added %d new live proxies to pool (total=%d)", added, len(self._live_proxies()))

    def add_proxy(self, proxy_str: str) -> None:
        """
        Parse and add a single proxy string to the pool.

        Args:
            proxy_str: Proxy line in any supported format.

        Raises:
            ValueError: If the proxy string cannot be parsed.
        """
        parser = ProxyScraper()
        node = parser._parse_proxy_line(proxy_str.strip())
        if node is None:
            raise ValueError(f"Cannot parse proxy: {proxy_str!r}")

        with self._pool_lock:
            for existing in self._pool:
                if existing.host == node.host and existing.port == node.port:
                    logger.debug("Proxy %s already in pool, skipping", node.address)
                    return
            self._pool.append(node)
            logger.info("Added proxy: %s (%s)", node.address, node.protocol)

    def remove_proxy(self, host: str, port: int) -> None:
        """
        Remove a proxy from the pool by host and port.

        Args:
            host: Proxy hostname or IP address.
            port: Proxy port number.
        """
        with self._pool_lock:
            before = len(self._pool)
            self._pool = [n for n in self._pool if not (n.host == host and n.port == port)]
            removed = before - len(self._pool)
            if removed:
                logger.info("Removed proxy %s:%d from pool", host, port)
            else:
                logger.warning("Proxy %s:%d not found in pool", host, port)

    # ------------------------------------------------------------------
    # Proxy selection
    # ------------------------------------------------------------------

    def get_next_proxy(self, mode: Optional[str] = None) -> Optional[ProxyNode]:
        """
        Return the next proxy according to the selection strategy.

        Args:
            mode: Override the engine's configured mode for this call.
                  One of ``'round_robin'``, ``'random'``, ``'latency'``.

        Returns:
            A live :class:`ProxyNode` or *None* if the pool is empty.
        """
        live = self._live_proxies()
        if not live:
            logger.warning("get_next_proxy: no live proxies available")
            return None

        selected_mode = mode or self._selection_mode

        with self._pool_lock:
            if selected_mode == self.MODE_RANDOM:
                return random.choice(live)

            if selected_mode == self.MODE_LATENCY:
                # Pick the proxy with the best composite score
                return max(live, key=self._score_proxy)

            # Default: round-robin
            self._rr_index = self._rr_index % len(live)
            node = live[self._rr_index]
            self._rr_index += 1
            return node

    def get_chain(self, length: Optional[int] = None) -> list[ProxyNode]:
        """
        Return a list of proxies suitable for use as a proxy chain.

        The chain is built using the configured selection mode, ensuring no
        duplicate host in the chain when possible.

        Args:
            length: Number of proxies in the chain.  Defaults to the engine's
                    configured ``proxy_chain_length``.

        Returns:
            Ordered list of :class:`ProxyNode` instances (may be shorter than
            *length* if the pool has fewer live proxies).
        """
        length = length or self._chain_length
        live = self._live_proxies()

        if not live:
            return []

        # Score and sort — best proxies first
        scored = sorted(live, key=self._score_proxy, reverse=True)

        chain: list[ProxyNode] = []
        seen_hosts: set[str] = set()

        for node in scored:
            if node.host not in seen_hosts:
                chain.append(node)
                seen_hosts.add(node.host)
            if len(chain) >= length:
                break

        # If we couldn't fill the chain with unique hosts, allow duplicates
        if len(chain) < length and live:
            remaining = length - len(chain)
            extras = random.choices(live, k=remaining)
            chain.extend(extras)

        return chain

    def get_session_proxy(self, session_id: str) -> dict:
        """
        Return a proxy configuration dict for a specific session, maintaining
        consistent assignment for the lifetime of that session.

        If the session already has a proxy assigned, return the same one
        (provided it is still alive).  Otherwise assign the next best proxy.

        Args:
            session_id: Unique identifier for the session / request context.

        Returns:
            Dict with keys ``http`` and ``https`` ready for
            ``requests.Session.proxies``, or empty dict if no proxies available.
        """
        with self._pool_lock:
            existing = self._session_map.get(session_id)
            if existing and existing.alive:
                return {"http": existing.url, "https": existing.url}

            node = self.get_next_proxy()
            if node is None:
                return {}

            self._session_map[session_id] = node
            return {"http": node.url, "https": node.url}

    # ------------------------------------------------------------------
    # Health monitoring
    # ------------------------------------------------------------------

    def health_check_all(self) -> None:
        """
        Re-validate every proxy in the pool.

        Dead proxies with ``fail_count`` exceeding the configured threshold
        are pruned from the pool.
        """
        with self._pool_lock:
            pool_snapshot = list(self._pool)

        logger.info("Health-checking %d proxies …", len(pool_snapshot))
        max_fails = int(getattr(self._config, "proxy_max_fail_count", 5))

        checked = self._validator.validate_all(pool_snapshot, workers=20)
        checked_map = {f"{n.host}:{n.port}": n for n in checked}

        with self._pool_lock:
            updated: list[ProxyNode] = []
            for node in self._pool:
                key = f"{node.host}:{node.port}"
                refreshed = checked_map.get(key, node)
                if refreshed.alive or refreshed.fail_count < max_fails:
                    updated.append(refreshed)
                else:
                    logger.debug("Pruning dead proxy %s (fail_count=%d)", key, refreshed.fail_count)
            self._pool = updated

        live_count = len(self._live_proxies())
        self._state.set("proxy_pool_size", live_count)
        logger.info("Health check complete — %d live proxies remain", live_count)

    def start_health_monitor(self) -> None:
        """
        Launch a background daemon thread that periodically calls
        :meth:`health_check_all`.
        """
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.debug("Health monitor already running")
            return

        self._monitor_stop.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="proxy-health-monitor",
            daemon=True,
        )
        self._monitor_thread.start()
        logger.info("Proxy health monitor started (interval=%ds)", self._health_interval)

    # ------------------------------------------------------------------
    # proxychains4.conf management
    # ------------------------------------------------------------------

    def write_proxychains_conf(self) -> None:
        """
        Write ``/etc/proxychains4.conf`` from the current proxy pool.

        Backs up the original file (once) before overwriting.  The chain type
        is driven by ``config.proxy_chain_type`` (default: ``dynamic_chain``).

        Raises:
            PermissionError: If the process lacks write access to ``/etc``.
            RuntimeError:    If there are no live proxies to write.
        """
        live = self._live_proxies()
        if not live:
            raise RuntimeError("Cannot write proxychains4.conf: no live proxies")

        chain = self.get_chain()

        # Backup original config (first time only)
        if os.path.isfile(PROXYCHAINS_CONF_PATH) and not os.path.isfile(PROXYCHAINS_BACKUP_PATH):
            shutil.copy2(PROXYCHAINS_CONF_PATH, PROXYCHAINS_BACKUP_PATH)
            logger.info("Backed up original proxychains4.conf → %s", PROXYCHAINS_BACKUP_PATH)

        chain_type = getattr(self._config, "proxy_chain_type", "dynamic_chain")
        dns_proxy = getattr(self._config, "proxy_dns", True)
        quiet = getattr(self._config, "proxy_quiet_mode", True)
        tcp_timeout = int(getattr(self._config, "proxy_tcp_timeout", 8000))
        tcp_con_timeout = int(getattr(self._config, "proxy_tcp_connect_timeout", 8000))

        lines: list[str] = [
            "# GhostRoute — Auto-generated proxychains4.conf",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "# Do not edit — managed by GhostRoute.",
            "",
            f"{chain_type}",
            "",
            "# Proxy DNS requests (prevent DNS leaks)",
            f"{'proxy_dns' if dns_proxy else '# proxy_dns'}",
            "",
            "# Quiet mode — suppress per-connection log output",
            f"{'quiet_mode' if quiet else '# quiet_mode'}",
            "",
            f"tcp_read_time_out {tcp_timeout}",
            f"tcp_connect_time_out {tcp_con_timeout}",
            "",
            "[ProxyList]",
            "# Proxy chain (best proxies first):",
        ]

        for node in chain:
            lines.append(node.proxychains_line)

        conf_content = "\n".join(lines) + "\n"

        try:
            with open(PROXYCHAINS_CONF_PATH, "w", encoding="utf-8") as fh:
                fh.write(conf_content)
            logger.info(
                "Wrote %s (%d proxies, chain_type=%s)",
                PROXYCHAINS_CONF_PATH,
                len(chain),
                chain_type,
            )
        except PermissionError as exc:
            raise PermissionError(
                f"Need root to write {PROXYCHAINS_CONF_PATH}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """
        Return a summary of the proxy pool's current state.

        Returns:
            Dict containing:
              - ``total``              : Total proxies in pool.
              - ``alive``              : Live proxies.
              - ``dead``               : Dead / failed proxies.
              - ``avg_latency_ms``     : Average latency of live proxies.
              - ``anonymity_breakdown``: Count by anonymity level.
              - ``selection_mode``     : Current selection strategy.
              - ``chain_length``       : Configured chain length.
        """
        with self._pool_lock:
            total = len(self._pool)
            live = [n for n in self._pool if n.alive]
            dead = [n for n in self._pool if not n.alive]

        avg_lat = (
            sum(n.latency_ms for n in live) / len(live) if live else 0.0
        )

        anon_breakdown: dict[str, int] = {
            ANONYMITY_ELITE: 0,
            ANONYMITY_ANONYMOUS: 0,
            ANONYMITY_TRANSPARENT: 0,
            ANONYMITY_UNKNOWN: 0,
        }
        for node in live:
            key = node.anonymity if node.anonymity in anon_breakdown else ANONYMITY_UNKNOWN
            anon_breakdown[key] += 1

        return {
            "total": total,
            "alive": len(live),
            "dead": len(dead),
            "avg_latency_ms": round(avg_lat, 2),
            "anonymity_breakdown": anon_breakdown,
            "selection_mode": self._selection_mode,
            "chain_length": self._chain_length,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _live_proxies(self) -> list[ProxyNode]:
        """Return a snapshot of alive proxies (lock-safe)."""
        with self._pool_lock:
            return [n for n in self._pool if n.alive]

    def _score_proxy(self, proxy: ProxyNode) -> float:
        """
        Compute a composite quality score for a proxy.

        Higher score = better proxy.

        Score components:
          - Anonymity level: elite=3, anonymous=2, transparent=1, unknown=0.5
          - Latency penalty: lower latency → higher score.
          - Fail count penalty: more failures → lower score.
          - Reputation multiplier.

        Args:
            proxy: Proxy node to score.

        Returns:
            Float quality score (higher is better).
        """
        anon_weights = {
            ANONYMITY_ELITE: 3.0,
            ANONYMITY_ANONYMOUS: 2.0,
            ANONYMITY_TRANSPARENT: 1.0,
            ANONYMITY_UNKNOWN: 0.5,
        }
        anon_score = anon_weights.get(proxy.anonymity, 0.5)

        # Latency score: 0–10 scaled so 100 ms = 10, 5000 ms ≈ 0
        latency_score = max(0.0, 10.0 - proxy.latency_ms / 500.0)

        # Fail count penalty: -0.5 per failure, floor at 0
        fail_penalty = max(0.0, 5.0 - proxy.fail_count * 0.5)

        score = (anon_score * 3.0 + latency_score + fail_penalty) * proxy.reputation_score
        return round(score, 4)

    def _monitor_loop(self) -> None:
        """Background health-check loop (runs in daemon thread)."""
        logger.debug("Health monitor loop started")
        while not self._monitor_stop.wait(timeout=self._health_interval):
            try:
                self.health_check_all()
            except Exception as exc:
                logger.error("Health monitor error: %s", exc, exc_info=True)
        logger.debug("Health monitor loop exiting")

    def _stop_health_monitor(self) -> None:
        """Signal and join the health monitor thread."""
        self._monitor_stop.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
            logger.info("Health monitor stopped")

    def _restore_proxychains_conf(self) -> None:
        """Restore the proxychains4.conf backup if it exists."""
        if os.path.isfile(PROXYCHAINS_BACKUP_PATH):
            shutil.copy2(PROXYCHAINS_BACKUP_PATH, PROXYCHAINS_CONF_PATH)
            os.remove(PROXYCHAINS_BACKUP_PATH)
            logger.info("Restored original proxychains4.conf from backup")
        else:
            logger.debug("No proxychains4.conf backup found — nothing to restore")
