"""
ghostroute/modules/obfuscation/padding.py
=========================================
Packet padding transparent proxy for GhostRoute.

This module implements a lightweight SOCKS5-compatible TCP proxy (asyncio)
that inserts random-length padding bytes into every forwarded data chunk.
The goal is to defeat size-based traffic fingerprinting / traffic analysis
(TA) attacks by making packet lengths non-deterministic.

Architecture
------------
  Tor application (SOCKS consumer)
      ↓
  PacketPaddingProxy  (localhost:9060)   ← this module
      ↓  [data + random padding appended]
  Tor SOCKS5 listener  (localhost:9050)

Padding scheme
--------------
For each chunk of *outbound* data (app → Tor), ``_pad_data()`` appends
``random.randint(min_bytes, max_bytes)`` random bytes.  The receiving side
(Tor) ignores the trailing garbage because Tor itself operates on SOCKS5
framing + TLS; the extra bytes ride inside the TCP stream where the real
Tor protocol data is encapsulated end-to-end.

  ┌──────────────┬─────────────────────┐
  │  Original    │  Random Padding     │
  │  data bytes  │  (min..max random)  │
  └──────────────┴─────────────────────┘

Configuration keys
------------------
  obfuscation.padding.listen_host    (default: 127.0.0.1)
  obfuscation.padding.listen_port    (default: 9060)
  obfuscation.padding.forward_host   (default: 127.0.0.1)
  obfuscation.padding.forward_port   (default: 9050)
  obfuscation.padding.min_bytes      (default: 16)
  obfuscation.padding.max_bytes      (default: 512)

Author: GhostRoute Security Team
Python: 3.10+
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.config import Config
    from core.state import StateManager

logger = logging.getLogger("ghostroute.obfuscation.padding")

# Default proxy bind address.
DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 9060

# Default forward target (Tor SOCKS5).
DEFAULT_FORWARD_HOST = "127.0.0.1"
DEFAULT_FORWARD_PORT = 9050

# Default padding range (bytes).
DEFAULT_MIN_PADDING = 16
DEFAULT_MAX_PADDING = 512

# Maximum simultaneous proxy sessions.
MAX_CONNECTIONS = 256


class PacketPaddingError(Exception):
    """Raised when the PacketPaddingProxy encounters an unrecoverable error."""


class _PaddingSession:
    """
    Manages a single proxied TCP connection with padding applied.

    This class handles the full lifecycle of one client connection:
      1. Accept connection from application.
      2. Open upstream connection to Tor SOCKS5.
      3. Bidirectionally relay data, applying padding on the downstream→upstream path.

    Parameters
    ----------
    reader, writer:
        asyncio streams for the accepted client connection.
    fwd_host, fwd_port:
        Forward destination (Tor SOCKS5 port).
    pad_data_func:
        Callable that takes ``bytes`` and returns padded ``bytes``.
    counter:
        Shared list[int] used to count processed packets (by reference).
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        fwd_host: str,
        fwd_port: int,
        pad_data_func,
        counter: list[int],
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._fwd_host = fwd_host
        self._fwd_port = fwd_port
        self._pad_data = pad_data_func
        self._counter = counter

    async def run(self) -> None:
        """
        Run the bidirectional proxy relay for this session.

        Opens the upstream connection, then pumps data in both directions
        concurrently.  Padding is applied only on the client→upstream path
        (outbound to Tor).
        """
        client_addr = self._writer.get_extra_info("peername", "?")
        logger.debug("New padding session from %s → %s:%d",
                     client_addr, self._fwd_host, self._fwd_port)
        try:
            up_reader, up_writer = await asyncio.open_connection(
                self._fwd_host, self._fwd_port
            )
        except OSError as exc:
            logger.error(
                "Cannot connect to upstream %s:%d: %s",
                self._fwd_host, self._fwd_port, exc,
            )
            self._writer.close()
            return

        try:
            await asyncio.gather(
                self._relay_downstream_to_upstream(up_writer),
                self._relay_upstream_to_downstream(up_reader),
                return_exceptions=True,
            )
        finally:
            # Tear down both sides cleanly.
            for w in (self._writer, up_writer):
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:  # noqa: BLE001
                    pass

    async def _relay_downstream_to_upstream(
        self, up_writer: asyncio.StreamWriter
    ) -> None:
        """
        Relay client → upstream, applying random padding to each chunk.

        Reads until EOF, pads each chunk, and forwards to Tor SOCKS5.
        """
        try:
            while True:
                data = await self._reader.read(4096)
                if not data:
                    break
                padded = self._pad_data(data)
                up_writer.write(padded)
                await up_writer.drain()
                self._counter[0] += 1
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("Downstream→upstream relay error: %s", exc)

    async def _relay_upstream_to_downstream(
        self, up_reader: asyncio.StreamReader
    ) -> None:
        """
        Relay upstream → client.

        Return traffic (Tor → app) is relayed as-is — we do *not* pad
        inbound data because the application needs to parse it correctly.
        """
        try:
            while True:
                data = await up_reader.read(4096)
                if not data:
                    break
                self._writer.write(data)
                await self._writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("Upstream→downstream relay error: %s", exc)


class PacketPaddingProxy:
    """
    Asyncio-based transparent TCP proxy that appends random padding to each
    outbound data chunk to defeat size-based traffic analysis.

    The proxy runs in a dedicated daemon thread with its own asyncio event loop
    so it does not block the main GhostRoute control thread.

    Parameters
    ----------
    config:
        Global GhostRoute configuration object.
    state:
        Shared runtime state manager.
    """

    MODULE_NAME = "packet_padding"

    def __init__(self, config: "Config", state: "StateManager") -> None:
        self._config = config
        self._state = state

        # Runtime parameters — may be updated at any time via set_padding_range().
        self._min_bytes: int = int(
            config.get("obfuscation.padding.min_bytes", default=DEFAULT_MIN_PADDING)
        )
        self._max_bytes: int = int(
            config.get("obfuscation.padding.max_bytes", default=DEFAULT_MAX_PADDING)
        )

        # Proxy network config.
        self._listen_host: str = config.get(
            "obfuscation.padding.listen_host", default=DEFAULT_LISTEN_HOST
        )
        self._listen_port: int = int(
            config.get("obfuscation.padding.listen_port", default=DEFAULT_LISTEN_PORT)
        )
        self._fwd_host: str = config.get(
            "obfuscation.padding.forward_host", default=DEFAULT_FORWARD_HOST
        )
        self._fwd_port: int = int(
            config.get("obfuscation.padding.forward_port", default=DEFAULT_FORWARD_PORT)
        )

        # Runtime state.
        self._enabled: bool = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.Server | None = None
        self._thread: threading.Thread | None = None

        # Thread-safe packet counter: list[int] used as mutable int reference.
        self._packets_processed: list[int] = [0]

        logger.debug(
            "PacketPaddingProxy initialised. Listen: %s:%d  Forward: %s:%d  "
            "Padding: %d–%d bytes",
            self._listen_host, self._listen_port,
            self._fwd_host, self._fwd_port,
            self._min_bytes, self._max_bytes,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enable(self) -> None:
        """
        Start the asyncio padding proxy server in a background daemon thread.

        The server listens on ``listen_host:listen_port`` and proxies all
        connections to ``forward_host:forward_port`` (Tor SOCKS5 by default).

        Raises
        ------
        PacketPaddingError
            If the server is already running or the port cannot be bound.
        """
        if self._enabled:
            logger.debug("PacketPaddingProxy already enabled.")
            return

        logger.info(
            "Starting PacketPaddingProxy on %s:%d  →  %s:%d  "
            "(padding: %d–%d bytes)",
            self._listen_host, self._listen_port,
            self._fwd_host, self._fwd_port,
            self._min_bytes, self._max_bytes,
        )

        # Signal event to know when the loop is ready.
        ready_event = threading.Event()
        error_holder: list[Exception | None] = [None]

        self._thread = threading.Thread(
            target=self._run_loop,
            args=(ready_event, error_holder),
            daemon=True,
            name="ghostroute-padding-proxy",
        )
        self._thread.start()

        # Wait up to 5 seconds for the server to bind and start.
        if not ready_event.wait(timeout=5.0):
            raise PacketPaddingError(
                "PacketPaddingProxy failed to start within 5 seconds."
            )

        if error_holder[0] is not None:
            raise PacketPaddingError(
                f"PacketPaddingProxy startup error: {error_holder[0]}"
            )

        self._enabled = True
        self._packets_processed[0] = 0
        self._update_state(enabled=True)
        logger.info("PacketPaddingProxy running on %s:%d", self._listen_host, self._listen_port)

    def disable(self) -> None:
        """
        Stop the padding proxy server and clean up the background thread.

        After this call, traffic is no longer intercepted or padded.

        Raises
        ------
        PacketPaddingError
            If the server cannot be stopped cleanly within the timeout.
        """
        if not self._enabled:
            logger.debug("PacketPaddingProxy is not running — nothing to stop.")
            return

        logger.info("Stopping PacketPaddingProxy.")

        if self._loop is not None and self._server is not None:
            # Schedule server closure on the proxy loop.
            future = asyncio.run_coroutine_threadsafe(
                self._shutdown_server(), self._loop
            )
            try:
                future.result(timeout=5.0)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error during proxy server shutdown: %s", exc)

        # Stop the event loop so the thread exits.
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)

        if self._thread is not None:
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                logger.warning(
                    "Padding proxy thread did not terminate in time."
                )

        self._server = None
        self._loop = None
        self._thread = None
        self._enabled = False
        self._update_state(enabled=False)
        logger.info("PacketPaddingProxy stopped.")

    def set_padding_range(self, min_bytes: int, max_bytes: int) -> None:
        """
        Update the padding range at runtime (no restart required).

        Parameters
        ----------
        min_bytes:
            Minimum number of padding bytes to append per chunk (≥ 0).
        max_bytes:
            Maximum number of padding bytes to append per chunk.

        Raises
        ------
        ValueError
            If ``min_bytes < 0``, ``max_bytes < min_bytes``, or
            ``max_bytes > 65535``.
        """
        if min_bytes < 0:
            raise ValueError(f"min_bytes must be ≥ 0, got {min_bytes}.")
        if max_bytes < min_bytes:
            raise ValueError(
                f"max_bytes ({max_bytes}) must be ≥ min_bytes ({min_bytes})."
            )
        if max_bytes > 65535:
            raise ValueError(
                f"max_bytes ({max_bytes}) exceeds maximum allowed (65535)."
            )

        self._min_bytes = min_bytes
        self._max_bytes = max_bytes
        logger.info(
            "Padding range updated: %d–%d bytes", min_bytes, max_bytes
        )

    def _pad_data(self, data: bytes) -> bytes:
        """
        Append random padding bytes to *data*.

        The padding length is drawn uniformly from
        ``[self._min_bytes, self._max_bytes]``.

        Parameters
        ----------
        data:
            Original payload bytes.

        Returns
        -------
        bytes
            Original payload with random padding appended.
        """
        pad_length = random.randint(self._min_bytes, self._max_bytes)
        padding = os.urandom(pad_length)  # Cryptographically random (Linux: /dev/urandom).
        return data + padding

    def status(self) -> dict:
        """
        Return a status snapshot for this module.

        Returns
        -------
        dict
            Keys:
            - ``module``: str — always ``'packet_padding'``.
            - ``enabled``: bool
            - ``listen_host``: str
            - ``listen_port``: int
            - ``forward_host``: str
            - ``forward_port``: int
            - ``padding_min_bytes``: int
            - ``padding_max_bytes``: int
            - ``packets_processed``: int — cumulative padded packet count.
        """
        return {
            "module": self.MODULE_NAME,
            "enabled": self._enabled,
            "listen_host": self._listen_host,
            "listen_port": self._listen_port,
            "forward_host": self._fwd_host,
            "forward_port": self._fwd_port,
            "padding_min_bytes": self._min_bytes,
            "padding_max_bytes": self._max_bytes,
            "packets_processed": self._packets_processed[0],
        }

    # ------------------------------------------------------------------
    # Internal asyncio server helpers
    # ------------------------------------------------------------------

    def _run_loop(
        self,
        ready_event: threading.Event,
        error_holder: list[Exception | None],
    ) -> None:
        """
        Entry point for the background daemon thread.

        Creates a fresh asyncio event loop, starts the TCP server, signals the
        ``ready_event``, then runs the loop until ``disable()`` stops it.
        """
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(
                self._start_server(ready_event, error_holder)
            )
            self._loop.run_forever()
        except Exception as exc:  # noqa: BLE001
            logger.error("Padding proxy loop terminated with error: %s", exc)
        finally:
            try:
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
                self._loop.close()
            except Exception:  # noqa: BLE001
                pass

    async def _start_server(
        self,
        ready_event: threading.Event,
        error_holder: list[Exception | None],
    ) -> None:
        """
        Bind and start the asyncio TCP server.

        On success, sets ``ready_event`` so the calling thread can proceed.
        On failure, stores the exception in ``error_holder`` and still sets
        ``ready_event`` so ``enable()`` doesn't hang.
        """
        try:
            self._server = await asyncio.start_server(
                self._handle_connection,
                host=self._listen_host,
                port=self._listen_port,
                limit=2 ** 16,  # 64 KiB read-buffer per stream.
            )
            logger.debug(
                "Padding proxy server bound to %s:%d",
                self._listen_host, self._listen_port,
            )
        except OSError as exc:
            error_holder[0] = exc
        finally:
            ready_event.set()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        asyncio connection handler — called for every new client connection.

        Creates a ``_PaddingSession`` and runs it.
        """
        session = _PaddingSession(
            reader=reader,
            writer=writer,
            fwd_host=self._fwd_host,
            fwd_port=self._fwd_port,
            pad_data_func=self._pad_data,
            counter=self._packets_processed,
        )
        await session.run()

    async def _shutdown_server(self) -> None:
        """Close the asyncio server and wait for all open connections to drain."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            logger.debug("Padding proxy asyncio server closed.")

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def _update_state(self, *, enabled: bool) -> None:
        """Persist module state to the StateManager."""
        try:
            self._state.set(
                "obfuscation.packet_padding",
                {
                    "enabled": enabled,
                    "listen_port": self._listen_port,
                    "forward_port": self._fwd_port,
                    "padding_min": self._min_bytes,
                    "padding_max": self._max_bytes,
                    "packets_processed": self._packets_processed[0],
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to update state for packet_padding: %s", exc)

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<PacketPaddingProxy enabled={self._enabled} "
            f"port={self._listen_port} "
            f"padding={self._min_bytes}–{self._max_bytes}B "
            f"processed={self._packets_processed[0]}>"
        )
