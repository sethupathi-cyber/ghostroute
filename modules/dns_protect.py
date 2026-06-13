"""
ghostroute/modules/dns_protect.py
===================================
DNS leak protection with multiple backend modes.

Modes:
  tor       — Rely on Tor's built-in DNSPort (5353).  The TorRouting module
              redirects port 53 UDP/TCP to 5353 via iptables, so simply setting
              nameserver 127.0.0.1 in resolv.conf is sufficient.

  dnscrypt  — Launch dnscrypt-proxy as a subprocess, pointing at a well-known
              DNS-over-HTTPS stamp.  Update resolv.conf to 127.0.0.1:53 (the
              dnscrypt-proxy listen address).

  doh       — Spawn a lightweight in-process DNS-over-HTTPS forwarder using
              raw sockets + the dnslib library (no external binary required).
              Listens on 127.0.0.2:53 to avoid conflicting with other services.

The class also provides a verify_no_leak() method that performs a DNS lookup
through the current resolver and checks whether the responding server's IP
falls outside known ISP ranges (uses a public API for simplicity).

Requires:
  - dnscrypt-proxy installed for 'dnscrypt' mode (optional)
  - dnslib Python package for 'doh' mode  (pip install dnslib)
  - requests package for verify_no_leak()
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

import requests

from core.config import Config
from core.state import StateManager
from core.utils import run_cmd

logger = logging.getLogger("ghostroute.dns_protect")

# ── Constants ─────────────────────────────────────────────────────────────────

RESOLV_PATH = "/etc/resolv.conf"
RESOLV_BACKUP = "/tmp/ghostroute.dns.resolv.bak"
DNSCRYPT_CONFIG_PATH = "/tmp/ghostroute-dnscrypt.toml"
DNSCRYPT_LISTEN = "127.0.0.1:53"

# Public DoH resolvers for the built-in proxy
DOH_RESOLVERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
]

# DoH proxy listen address (use 127.0.0.2 to avoid collisions with Tor)
DOH_LISTEN_HOST = "127.0.0.2"
DOH_LISTEN_PORT = 53


# ── Main class ────────────────────────────────────────────────────────────────


class DNSProtect:
    """
    DNS leak prevention with pluggable backend modes.

    Usage::

        dns = DNSProtect(config, state)
        dns.enable(mode='doh')
        result = dns.verify_no_leak()
        dns.disable()
    """

    def __init__(self, config: Config, state: StateManager) -> None:
        """
        Initialise DNSProtect.

        Args:
            config: Loaded GhostRoute configuration object.
            state:  Shared runtime state manager.
        """
        self.config = config
        self.state = state
        self._mode: Optional[str] = None
        self._dnscrypt_process: Optional[subprocess.Popen] = None
        self._doh_thread: Optional[threading.Thread] = None
        self._doh_stop_event = threading.Event()
        self._active = False
        logger.debug("DNSProtect initialised")

    # ── Public API ────────────────────────────────────────────────────────────

    def enable(self, mode: Optional[str] = None) -> None:
        """
        Enable DNS leak protection using the specified mode.

        Args:
            mode: One of 'tor', 'dnscrypt', 'doh'.  If None, falls back to
                  config.dns_mode, then defaults to 'tor'.

        Raises:
            ValueError:    If an unsupported mode is specified.
            RuntimeError:  If the chosen backend fails to start.
        """
        if self._active:
            logger.warning("DNSProtect already active (mode=%s) — call disable() first", self._mode)
            return

        resolved_mode = mode or getattr(self.config, "dns_mode", "tor")
        if resolved_mode not in ("tor", "dnscrypt", "doh"):
            raise ValueError(
                f"Unsupported DNS mode: '{resolved_mode}'. "
                "Choose from: tor, dnscrypt, doh"
            )

        logger.info("Enabling DNS protection (mode=%s)", resolved_mode)
        self._backup_resolv()

        if resolved_mode == "tor":
            self._enable_tor_mode()
        elif resolved_mode == "dnscrypt":
            self._start_dnscrypt()
        elif resolved_mode == "doh":
            self._start_doh_proxy()

        self._mode = resolved_mode
        self._active = True
        self.state.set("dns_protect_active", True)
        self.state.set("dns_protect_mode", resolved_mode)
        logger.info("DNS protection ENABLED (mode=%s)", resolved_mode)

    def disable(self) -> None:
        """
        Disable DNS leak protection and restore the original resolv.conf.

        Safe to call even if enable() was never called.
        """
        logger.info("Disabling DNS protection (mode=%s)", self._mode)

        # Stop mode-specific processes/threads
        if self._mode == "dnscrypt":
            self._stop_dnscrypt()
        elif self._mode == "doh":
            self._stop_doh_proxy()

        self._restore_resolv()
        self._mode = None
        self._active = False
        self.state.set("dns_protect_active", False)
        self.state.set("dns_protect_mode", None)
        logger.info("DNS protection DISABLED")

    def verify_no_leak(self) -> dict:
        """
        Verify that DNS queries are not leaking to the ISP resolver.

        Uses the dnsleaktest.com API to perform a leak test:
          1. Resolve a unique subdomain of dnsleaktest.com.
          2. Query the API for which resolvers were used.
          3. Evaluate if any of them appear to be ISP infrastructure.

        Returns:
            dict with keys:
              status   (str)  : 'protected', 'leaked', or 'unknown'
              resolvers (list): list of resolver dicts (ip, country, isp)
              message  (str)  : human-readable summary
        """
        result: dict = {
            "status": "unknown",
            "resolvers": [],
            "message": "",
        }

        try:
            # Step 1: Get a unique test ID from the API
            resp = requests.get(
                "https://dnsleaktest.com/test",
                timeout=10,
                headers={"User-Agent": "GhostRoute/1.0"},
            )
            # The API returns JSON with a 'id' field for the unique subdomain
            data = resp.json()
            test_id = data.get("id", "")

            if not test_id:
                result["message"] = "Could not obtain test ID from dnsleaktest.com"
                return result

            # Step 2: Trigger DNS lookups (dnsleaktest resolves these to log resolvers)
            for i in range(10):
                try:
                    socket.getaddrinfo(
                        f"{i}.{test_id}.dnsleaktest.com",
                        80,
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                    )
                except socket.gaierror:
                    pass  # Expected — we just need the DNS query to be made

            time.sleep(1)

            # Step 3: Fetch resolver report
            report_resp = requests.get(
                f"https://dnsleaktest.com/results?id={test_id}",
                timeout=10,
                headers={"User-Agent": "GhostRoute/1.0"},
            )
            report = report_resp.json()
            resolvers = report if isinstance(report, list) else report.get("resolvers", [])

            result["resolvers"] = resolvers

            # Heuristic: if any resolver's country is the current machine's country,
            # or ISP name looks like a major ISP, flag as potentially leaked.
            # For now we consider any non-Tor exit resolver as potentially leaked.
            suspicious = [
                r for r in resolvers
                if not _is_tor_exit(r.get("ip", ""))
            ]

            if not resolvers:
                result["status"] = "unknown"
                result["message"] = "No resolver data returned"
            elif suspicious:
                result["status"] = "leaked"
                result["message"] = (
                    f"DNS may be leaking through {len(suspicious)} non-Tor resolver(s)"
                )
            else:
                result["status"] = "protected"
                result["message"] = "All DNS queries route through Tor exit nodes"

        except requests.RequestException as exc:
            logger.warning("DNS leak verification failed (network error): %s", exc)
            result["status"] = "unknown"
            result["message"] = f"Network error during leak test: {exc}"
        except Exception as exc:
            logger.warning("DNS leak verification failed: %s", exc)
            result["status"] = "unknown"
            result["message"] = f"Unexpected error: {exc}"

        return result

    def status(self) -> dict:
        """
        Return a status snapshot of the DNS protection module.

        Returns:
            dict with keys: active, mode, resolv_backed_up, dnscrypt_running,
            doh_running, listen_address.
        """
        doh_running = (
            self._doh_thread is not None
            and self._doh_thread.is_alive()
        )
        dnscrypt_running = (
            self._dnscrypt_process is not None
            and self._dnscrypt_process.poll() is None
        )

        listen = ""
        if self._mode == "doh":
            listen = f"{DOH_LISTEN_HOST}:{DOH_LISTEN_PORT}"
        elif self._mode == "dnscrypt":
            listen = DNSCRYPT_LISTEN

        return {
            "active": self._active,
            "mode": self._mode,
            "resolv_backed_up": Path(RESOLV_BACKUP).exists(),
            "dnscrypt_running": dnscrypt_running,
            "doh_running": doh_running,
            "listen_address": listen,
        }

    # ── Mode implementations ─────────────────────────────────────────────────

    def _enable_tor_mode(self) -> None:
        """
        Configure DNS to use Tor's DNSPort.

        Simply writes nameserver 127.0.0.1 to /etc/resolv.conf.  The
        TorRouting module's iptables rules redirect port 53 → 5353 (DNSPort).
        """
        content = (
            "# GhostRoute — DNS-over-Tor mode\n"
            "# Queries redirected to Tor DNSPort by iptables\n"
            "nameserver 127.0.0.1\n"
        )
        try:
            Path(RESOLV_PATH).write_text(content, encoding="utf-8")
            logger.debug("resolv.conf updated for Tor DNS mode")
        except OSError as exc:
            logger.error("Failed to update resolv.conf for Tor mode: %s", exc)
            raise

    def _start_dnscrypt(self) -> None:
        """
        Start dnscrypt-proxy as a subprocess and configure resolv.conf.

        Generates a minimal TOML config, launches dnscrypt-proxy in the
        background, waits up to 5 seconds for the listener to become ready,
        then updates /etc/resolv.conf.

        Raises:
            FileNotFoundError: If dnscrypt-proxy binary is not installed.
            RuntimeError:      If the proxy fails to bind within 5 seconds.
        """
        if not shutil.which("dnscrypt-proxy"):
            raise FileNotFoundError(
                "dnscrypt-proxy not found. Install with: apt install dnscrypt-proxy"
            )

        # Write a minimal dnscrypt-proxy TOML config
        config_content = f"""# GhostRoute dnscrypt-proxy config — auto-generated
listen_addresses = ['{DNSCRYPT_LISTEN}']
server_names = ['cloudflare', 'google']
log_level = 2
fallback_resolvers = ['9.9.9.9:53', '8.8.8.8:53']
ignore_system_dns = true

[sources.public-resolvers]
urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
cache_file = '/tmp/ghostroute-dnscrypt-resolvers.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 72
prefix = ''
"""
        try:
            Path(DNSCRYPT_CONFIG_PATH).write_text(config_content, encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Failed to write dnscrypt config: {exc}") from exc

        try:
            self._dnscrypt_process = subprocess.Popen(
                ["dnscrypt-proxy", "-config", DNSCRYPT_CONFIG_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError("dnscrypt-proxy binary not found") from exc

        # Wait for dnscrypt-proxy to be ready
        logger.info("Waiting for dnscrypt-proxy to start…")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", 53), timeout=0.5):
                    break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.2)
        else:
            self._dnscrypt_process.kill()
            raise RuntimeError("dnscrypt-proxy failed to bind on port 53 within 5s")

        # Update resolv.conf
        try:
            Path(RESOLV_PATH).write_text(
                "# GhostRoute — DNSCrypt mode\nnameserver 127.0.0.1\n",
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("Failed to update resolv.conf for dnscrypt mode: %s", exc)
            raise

        logger.info("dnscrypt-proxy started (PID %d)", self._dnscrypt_process.pid)

    def _stop_dnscrypt(self) -> None:
        """Terminate the dnscrypt-proxy subprocess."""
        if self._dnscrypt_process is not None:
            try:
                self._dnscrypt_process.terminate()
                self._dnscrypt_process.wait(timeout=5)
                logger.info("dnscrypt-proxy stopped")
            except subprocess.TimeoutExpired:
                self._dnscrypt_process.kill()
                logger.warning("dnscrypt-proxy killed (did not stop in 5s)")
            except Exception as exc:
                logger.warning("Error stopping dnscrypt-proxy: %s", exc)
            finally:
                self._dnscrypt_process = None

        # Remove temp config
        Path(DNSCRYPT_CONFIG_PATH).unlink(missing_ok=True)

    def _start_doh_proxy(self) -> None:
        """
        Start a lightweight in-process DNS-over-HTTPS forwarder.

        The proxy listens on DOH_LISTEN_HOST:DOH_LISTEN_PORT (127.0.0.2:53)
        using a background daemon thread.  It receives DNS queries via UDP,
        forwards them as DNS-over-HTTPS to the configured resolvers, and
        returns the responses.

        Raises:
            ImportError:  If the dnslib library is not installed.
            RuntimeError: If the UDP socket cannot be bound.
        """
        try:
            import dnslib  # noqa: F401 – verify import before starting thread
        except ImportError as exc:
            raise ImportError(
                "dnslib is required for DoH mode. Install with: pip install dnslib"
            ) from exc

        self._doh_stop_event.clear()
        self._doh_thread = threading.Thread(
            target=self._doh_proxy_worker,
            name="ghostroute-doh-proxy",
            daemon=True,
        )
        self._doh_thread.start()

        # Wait briefly to confirm the thread bound successfully
        time.sleep(0.5)
        if not self._doh_thread.is_alive():
            raise RuntimeError("DoH proxy thread exited immediately — check logs")

        # Update resolv.conf to point at our listener
        try:
            Path(RESOLV_PATH).write_text(
                f"# GhostRoute — DNS-over-HTTPS mode\nnameserver {DOH_LISTEN_HOST}\n",
                encoding="utf-8",
            )
        except OSError as exc:
            self._doh_stop_event.set()
            raise RuntimeError(f"Failed to update resolv.conf for DoH mode: {exc}") from exc

        logger.info(
            "DoH proxy listening on %s:%d", DOH_LISTEN_HOST, DOH_LISTEN_PORT
        )

    def _stop_doh_proxy(self) -> None:
        """Signal the DoH proxy thread to stop and wait for it to exit."""
        self._doh_stop_event.set()
        if self._doh_thread is not None:
            self._doh_thread.join(timeout=3)
            self._doh_thread = None
        logger.info("DoH proxy stopped")

    def _doh_proxy_worker(self) -> None:
        """
        Worker function for the in-process DoH proxy thread.

        Binds a UDP socket on DOH_LISTEN_HOST:DOH_LISTEN_PORT, receives raw
        DNS query packets, forwards them to a public DoH resolver via HTTPS,
        and sends back the DNS response.

        Uses dnslib for DNS message parsing and construction, and requests for
        HTTP communication with DoH endpoints.
        """
        import dnslib

        resolver_index = 0  # Round-robin across DOH_RESOLVERS

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)  # Allow stop_event polling
            sock.bind((DOH_LISTEN_HOST, DOH_LISTEN_PORT))
            logger.debug(
                "DoH proxy UDP socket bound on %s:%d",
                DOH_LISTEN_HOST, DOH_LISTEN_PORT,
            )
        except OSError as exc:
            logger.error(
                "DoH proxy failed to bind %s:%d — %s",
                DOH_LISTEN_HOST, DOH_LISTEN_PORT, exc,
            )
            return

        session = requests.Session()
        session.headers.update({"Content-Type": "application/dns-message"})

        while not self._doh_stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._doh_stop_event.is_set():
                    logger.warning("DoH proxy socket error: %s", exc)
                break

            try:
                # Parse DNS query for logging
                query = dnslib.DNSRecord.parse(data)
                qname = str(query.q.qname) if query.questions else "<unknown>"
                logger.debug("DoH proxy: resolving %s for %s", qname, addr)

                # Forward to DoH resolver using DNS-wire-format POST
                resolver_url = DOH_RESOLVERS[resolver_index % len(DOH_RESOLVERS)]
                resolver_index += 1

                resp = session.post(
                    resolver_url,
                    data=data,
                    headers={"Accept": "application/dns-message"},
                    timeout=5,
                )
                resp.raise_for_status()

                # Send raw DNS response back to the client
                sock.sendto(resp.content, addr)
                logger.debug("DoH proxy: response forwarded (%d bytes)", len(resp.content))

            except dnslib.DNSError as exc:
                logger.warning("DoH proxy: invalid DNS packet from %s: %s", addr, exc)
            except requests.RequestException as exc:
                logger.warning("DoH proxy: upstream HTTP error: %s", exc)
                # Return SERVFAIL to client
                try:
                    query = dnslib.DNSRecord.parse(data)
                    reply = query.reply()
                    reply.header.rcode = dnslib.RCODE.SERVFAIL
                    sock.sendto(reply.pack(), addr)
                except Exception:
                    pass
            except Exception as exc:
                logger.warning("DoH proxy: unexpected error: %s", exc)

        sock.close()
        logger.debug("DoH proxy worker exited")

    # ── resolv.conf helpers ───────────────────────────────────────────────────

    def _backup_resolv(self) -> None:
        """Back up /etc/resolv.conf to RESOLV_BACKUP (won't overwrite existing)."""
        src = Path(RESOLV_PATH)
        dst = Path(RESOLV_BACKUP)
        if dst.exists():
            logger.debug("DNS resolv backup already exists — not overwriting")
            return
        try:
            shutil.copy2(str(src), str(dst))
            logger.debug("resolv.conf backed up for DNS protect: %s → %s", src, dst)
        except OSError as exc:
            logger.error("Failed to backup resolv.conf: %s", exc)
            raise

    def _restore_resolv(self) -> None:
        """Restore /etc/resolv.conf from RESOLV_BACKUP."""
        src = Path(RESOLV_BACKUP)
        dst = Path(RESOLV_PATH)
        if src.exists():
            try:
                shutil.copy2(str(src), str(dst))
                src.unlink()
                logger.info("resolv.conf restored (DNS protect)")
            except OSError as exc:
                logger.error("Failed to restore resolv.conf: %s", exc)
                raise
        else:
            logger.warning("No resolv.conf backup at %s — writing fallback", src)
            try:
                dst.write_text("nameserver 8.8.8.8\nnameserver 8.8.4.4\n", encoding="utf-8")
            except OSError as exc:
                logger.error("Failed to write fallback resolv.conf: %s", exc)


# ── Module-level helpers ──────────────────────────────────────────────────────


def _is_tor_exit(ip: str) -> bool:
    """
    Naive heuristic: check if the given IP is a known Tor exit node by
    querying the Tor Project's exit list API.

    Args:
        ip: IPv4 address string.

    Returns:
        True if the IP appears in the Tor exit list, False otherwise.
    """
    try:
        resp = requests.get(
            f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ip}",
            timeout=5,
        )
        return ip in resp.text
    except Exception:
        return False
