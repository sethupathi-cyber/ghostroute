"""
GhostRoute — Protocol Mimicry Obfuscation Module
Makes outbound traffic appear as standard HTTPS or WebSocket traffic
to confuse Deep Packet Inspection (DPI) systems.
"""

import logging
import random
import struct
import time

from core.config import Config
from core.state import StateManager

logger = logging.getLogger("ghostroute.obfuscation.mimicry")

# Common HTTP User-Agents for mimicry
_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# Common domains for HTTPS mimicry Host headers
_COVER_DOMAINS = [
    "www.google.com",
    "www.cloudflare.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
]


class ProtocolMimicry:
    """
    Protocol Mimicry Layer.

    Wraps outbound traffic payloads to resemble common web protocols:
    - 'https': Prepends fake HTTP/1.1 GET/POST request headers
    - 'websocket': Wraps data in WebSocket frame format

    This module provides a wrap_data() function used by the proxy engine
    to disguise payload content. It is not a standalone network daemon —
    it operates as a transform layer.

    Note: For deep integration with Tor, use obfs4/meek transports which
    perform real protocol-level obfuscation. This module adds an application-
    layer camouflage layer on top.
    """

    def __init__(self, config: Config, state: StateManager) -> None:
        self.config = config
        self.state = state
        self._protocol: str = "https"
        self._active: bool = False
        self._wrap_count: int = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def enable(self, protocol: str = "https") -> None:
        """
        Enable protocol mimicry.

        Args:
            protocol: 'https' or 'websocket'
        """
        if protocol not in ("https", "websocket"):
            raise ValueError(f"Unknown mimicry protocol: {protocol}. Use 'https' or 'websocket'.")

        self._protocol = protocol
        self._active = True
        self._wrap_count = 0
        self.state.set_module("protocol_mimicry", True)
        logger.info(f"[Mimicry] ✓ Protocol mimicry ENABLED ({protocol})")

    def disable(self) -> None:
        """Disable protocol mimicry."""
        self._active = False
        self.state.set_module("protocol_mimicry", False)
        logger.info("[Mimicry] Protocol mimicry disabled.")

    def set_protocol(self, protocol: str) -> None:
        """Switch mimicry protocol at runtime."""
        if protocol not in ("https", "websocket"):
            raise ValueError(f"Unknown protocol: {protocol}")
        old = self._protocol
        self._protocol = protocol
        logger.info(f"[Mimicry] Protocol changed: {old} → {protocol}")

    def wrap_data(self, data: bytes) -> bytes:
        """
        Wrap data payload to look like the configured protocol.

        Args:
            data: Raw bytes to wrap

        Returns:
            Bytes with mimicry headers/framing prepended
        """
        if not self._active:
            return data

        self._wrap_count += 1

        if self._protocol == "https":
            return self._wrap_as_https(data)
        elif self._protocol == "websocket":
            return self._wrap_as_websocket(data)
        return data

    def unwrap_data(self, data: bytes) -> bytes:
        """
        Strip mimicry framing from received data (for two-way mimicry).
        For one-way (outbound only) use, this is a passthrough.
        """
        if not self._active:
            return data
        # In practice, unwrapping requires coordinated endpoint support.
        # For outbound-only mimicry (to Tor/proxy), we pass through.
        return data

    def status(self) -> dict:
        """Return current mimicry status."""
        return {
            "active": self._active,
            "protocol": self._protocol,
            "wrap_count": self._wrap_count,
        }

    # ── Private: HTTPS Mimicry ────────────────────────────────────────────────

    def _wrap_as_https(self, data: bytes) -> bytes:
        """
        Prepend fake HTTP/1.1 request headers to make traffic resemble HTTPS.
        Uses random Cover domains and User-Agents for variability.
        """
        host   = random.choice(_COVER_DOMAINS)
        ua     = random.choice(_USER_AGENTS)
        path   = self._random_path()
        method = random.choice(["GET", "GET", "GET", "POST"])  # Weighted toward GET

        if method == "POST":
            headers = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(data)}\r\n"
                f"Connection: keep-alive\r\n"
                f"Accept-Encoding: gzip, deflate, br\r\n"
                f"Cache-Control: no-cache\r\n"
                f"\r\n"
            )
        else:
            headers = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Accept-Language: en-US,en;q=0.5\r\n"
                f"Accept-Encoding: gzip, deflate, br\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )

        return headers.encode() + data

    # ── Private: WebSocket Mimicry ────────────────────────────────────────────

    def _wrap_as_websocket(self, data: bytes) -> bytes:
        """
        Wrap data as a WebSocket binary frame (RFC 6455).

        Frame format:
          Byte 0: FIN=1, Opcode=2 (binary)
          Byte 1: MASK=1, payload len
          Bytes 2+: Optional extended length, masking key, payload
        """
        fin_opcode = 0x82  # FIN=1, opcode=2 (binary frame)
        payload_len = len(data)

        if payload_len < 126:
            header = struct.pack("BB", fin_opcode, 0x80 | payload_len)
        elif payload_len < 65536:
            header = struct.pack("!BBH", fin_opcode, 0xFE, payload_len)
        else:
            header = struct.pack("!BBQ", fin_opcode, 0xFF, payload_len)

        # Generate random 4-byte masking key (WebSocket client requirement)
        mask_key = bytes([random.randint(0, 255) for _ in range(4)])

        # XOR-mask the payload
        masked_data = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))

        return header + mask_key + masked_data

    # ── Private: Helpers ──────────────────────────────────────────────────────

    def _random_path(self) -> str:
        """Generate a realistic-looking URL path."""
        paths = [
            "/api/v1/data",
            "/assets/js/bundle.min.js",
            "/cdn/images/logo.png",
            "/static/css/main.css",
            "/feed.json",
            "/metrics",
            f"/r/{self._random_hex(8)}",
            f"/t/{self._random_hex(12)}.gif",
        ]
        return random.choice(paths)

    @staticmethod
    def _random_hex(length: int) -> str:
        return "".join(random.choices("0123456789abcdef", k=length))
