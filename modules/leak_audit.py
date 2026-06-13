"""
GhostRoute — Leak Audit Module
Comprehensive network leak detection: IP, DNS, IPv6, proxy headers, Tor exit verification.
"""

import json
import logging
import socket
import time
from typing import Any

import requests

from core.config import Config

logger = logging.getLogger("ghostroute.leak_audit")

# Use a short timeout; if the tunnel is broken, fast failure is better
_DEFAULT_TIMEOUT = 15


class LeakAudit:
    """
    Comprehensive Leak Detection Scanner.

    Checks all known leak vectors:
      - External IP address (via multiple independent APIs)
      - DNS resolver identity (home ISP DNS leak)
      - IPv6 reachability
      - HTTP proxy header leaks (X-Forwarded-For, Via, X-Real-IP)
      - Tor exit node verification
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.timeout = config.get("audit.timeout", _DEFAULT_TIMEOUT)

    # ── Public API ────────────────────────────────────────────────────────────

    def run_full_audit(self) -> dict:
        """
        Run all leak checks and return a comprehensive report dict.

        Returns:
            dict with keys: ip, dns, ipv6, headers, tor, summary, timestamp
        """
        logger.info("[LeakAudit] Starting full leak audit...")
        start = time.time()

        report: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ip":        self._safe_check("IP check",           self.check_ip),
            "dns":       self._safe_check("DNS leak check",     self.check_dns_leak),
            "ipv6":      self._safe_check("IPv6 leak check",    self.check_ipv6_leak),
            "headers":   self._safe_check("Proxy header check", self.check_proxy_headers),
            "tor":       self._safe_check("Tor exit check",     lambda: {"is_tor_exit": self.check_tor_exit()}),
        }

        # Build summary
        leaks = []
        if not report["ip"].get("all_consistent"):
            leaks.append("IP inconsistency between check APIs")
        if report["dns"].get("home_isp_detected"):
            leaks.append("DNS LEAK — home ISP resolver visible")
        if report["ipv6"].get("ipv6_reachable"):
            leaks.append("IPv6 LEAK — IPv6 address exposed")
        if report["headers"].get("ip_in_headers"):
            leaks.append(f"PROXY HEADER LEAK — IP in headers: {report['headers'].get('ip_in_headers')}")
        if not report["tor"].get("is_tor_exit"):
            leaks.append("Exit node is NOT a known Tor exit (may be direct / proxy)")

        report["summary"] = {
            "leaks_detected": len(leaks),
            "leak_details": leaks,
            "safe": len(leaks) == 0,
            "duration_seconds": round(time.time() - start, 2),
        }

        logger.info(
            f"[LeakAudit] Audit complete in {report['summary']['duration_seconds']}s. "
            f"Leaks: {len(leaks)}"
        )
        return report

    def check_ip(self) -> dict:
        """
        Query multiple IP lookup APIs to verify consistent anonymised IP.

        Returns:
            external_ip, country, isp, is_tor_exit, is_vpn, all_consistent
        """
        urls = self.config.get("audit.check_urls", [
            "https://api.ipify.org?format=json",
            "https://ipinfo.io/json",
            "https://httpbin.org/ip",
        ])

        results = []
        for url in urls:
            try:
                r = requests.get(url, timeout=self.timeout)
                r.raise_for_status()
                data = r.json()
                # Normalise varying API response shapes
                ip = data.get("ip") or data.get("origin", "").split(",")[0].strip()
                results.append(ip)
            except Exception as e:
                logger.debug(f"[LeakAudit] IP check URL failed ({url}): {e}")

        unique_ips = list(set(results))
        primary_ip = results[0] if results else "Unknown"

        # Get enriched info from ipinfo
        country, isp = "Unknown", "Unknown"
        try:
            r = requests.get(f"https://ipinfo.io/{primary_ip}/json", timeout=self.timeout)
            info = r.json()
            country = info.get("country", "Unknown")
            isp     = info.get("org", "Unknown")
        except Exception:
            pass

        return {
            "external_ip":    primary_ip,
            "country":        country,
            "isp":            isp,
            "all_ips_seen":   unique_ips,
            "all_consistent": len(unique_ips) <= 1,
        }

    def check_dns_leak(self) -> dict:
        """
        Detect DNS leaks by checking active resolvers in /etc/resolv.conf
        and testing DNS resolution path.

        Returns:
            resolvers_seen, home_isp_detected, resolver_countries
        """
        resolvers: list[str] = []

        # Parse /etc/resolv.conf
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            resolvers.append(parts[1])
        except Exception as e:
            logger.warning(f"[LeakAudit] Could not read /etc/resolv.conf: {e}")

        # Known Tor / safe resolvers (loopback)
        safe_resolvers = {"127.0.0.1", "127.0.0.53", "::1"}
        external_resolvers = [r for r in resolvers if r not in safe_resolvers]

        home_isp_detected = len(external_resolvers) > 0

        # Get country info for each external resolver
        resolver_countries: dict[str, str] = {}
        for resolver_ip in external_resolvers[:3]:  # Limit checks
            try:
                r = requests.get(
                    f"https://ipinfo.io/{resolver_ip}/json",
                    timeout=self.timeout
                )
                info = r.json()
                resolver_countries[resolver_ip] = info.get("org", "Unknown")
            except Exception:
                resolver_countries[resolver_ip] = "Unknown"

        return {
            "resolvers_configured": resolvers,
            "external_resolvers":   external_resolvers,
            "home_isp_detected":    home_isp_detected,
            "resolver_info":        resolver_countries,
        }

    def check_ipv6_leak(self) -> dict:
        """
        Test whether IPv6 is reachable externally.

        Returns:
            ipv6_reachable (bool), ipv6_address (str if found)
        """
        ipv6_address: str | None = None
        reachable = False

        # Method 1: try to connect to an IPv6-only endpoint
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.connect(("2606:4700:4700::1111", 53))  # Cloudflare IPv6 DNS
            ipv6_address = sock.getsockname()[0]
            sock.close()
            if not ipv6_address.startswith("::1") and not ipv6_address.startswith("fe80"):
                reachable = True
        except Exception:
            pass

        # Method 2: try HTTP to IPv6-only endpoint
        if not reachable:
            try:
                r = requests.get(
                    "https://ipv6.icanhazip.com",
                    timeout=5
                )
                ipv6_address = r.text.strip()
                reachable = bool(ipv6_address and ":" in ipv6_address)
            except Exception:
                pass

        return {
            "ipv6_reachable": reachable,
            "ipv6_address":   ipv6_address,
        }

    def check_proxy_headers(self) -> dict:
        """
        Check if our real IP is exposed in HTTP proxy-related headers.

        Returns:
            headers_found, anonymity_level, ip_in_headers
        """
        leak_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "Via",
            "Proxy-Connection",
            "X-Proxy-ID",
            "Forwarded",
        ]

        try:
            r = requests.get("https://httpbin.org/headers", timeout=self.timeout)
            received_headers = r.json().get("headers", {})
        except Exception as e:
            logger.warning(f"[LeakAudit] Header check failed: {e}")
            return {
                "error": str(e),
                "headers_found": [],
                "anonymity_level": "unknown",
                "ip_in_headers": None,
            }

        found = {h: received_headers[h] for h in leak_headers if h in received_headers}
        ip_in_headers: str | None = None

        # Check if any header contains an IP-like value
        import re
        ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        for val in found.values():
            match = ip_pattern.search(str(val))
            if match and not match.group().startswith("127."):
                ip_in_headers = match.group()
                break

        # Determine anonymity level
        if ip_in_headers:
            anonymity = "transparent"  # Real IP visible
        elif found:
            anonymity = "anonymous"    # Proxy detected but no real IP
        else:
            anonymity = "elite"        # No proxy headers

        return {
            "headers_found":   found,
            "anonymity_level": anonymity,
            "ip_in_headers":   ip_in_headers,
        }

    def check_tor_exit(self) -> bool:
        """
        Verify current external IP is a known Tor exit node.

        Uses Tor Project's exit list check API.
        """
        try:
            # Get our current IP first
            r = requests.get("https://api.ipify.org?format=json", timeout=self.timeout)
            my_ip = r.json().get("ip", "")
            if not my_ip:
                return False

            # Check Tor exit list
            check_url = f"https://check.torproject.org/api/ip"
            r2 = requests.get(check_url, timeout=self.timeout)
            data = r2.json()
            return bool(data.get("IsTor", False))

        except Exception as e:
            logger.debug(f"[LeakAudit] Tor exit check failed: {e}")
            return False

    def print_report(self, report: dict) -> None:
        """Pretty-print the audit report using rich tables."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
            from rich import box
            con = Console()
        except ImportError:
            print(json.dumps(report, indent=2))
            return

        safe = report.get("summary", {}).get("safe", False)
        leaks = report.get("summary", {}).get("leak_details", [])

        # Header
        status_text = "[bold green]✓ NO LEAKS DETECTED[/]" if safe else f"[bold red]⚠ {len(leaks)} LEAK(S) DETECTED[/]"
        con.print(Panel(status_text, title="[bold cyan]GhostRoute Leak Audit Report[/]", border_style="cyan"))

        # IP Table
        ip = report.get("ip", {})
        t = Table("Check", "Result", box=box.SIMPLE_HEAD, border_style="bright_blue")
        t.add_row("External IP",   f"[green]{ip.get('external_ip', 'N/A')}[/]")
        t.add_row("Country",       ip.get("country", "N/A"))
        t.add_row("ISP / AS",      ip.get("isp", "N/A"))
        t.add_row("Consistent IPs", "[green]Yes[/]" if ip.get("all_consistent") else "[red]No — multiple IPs seen[/]")
        con.print(Panel(t, title="[cyan]IP Check[/]"))

        # DNS Table
        dns = report.get("dns", {})
        leak_flag = "[red]YES — HOME ISP DNS LEAKED[/]" if dns.get("home_isp_detected") else "[green]No[/]"
        t2 = Table("Check", "Result", box=box.SIMPLE_HEAD, border_style="bright_blue")
        t2.add_row("Configured Resolvers", str(dns.get("resolvers_configured", [])))
        t2.add_row("External Resolvers",   str(dns.get("external_resolvers", [])))
        t2.add_row("Home ISP DNS Leak",    leak_flag)
        con.print(Panel(t2, title="[cyan]DNS Leak Check[/]"))

        # IPv6 Table
        ipv6 = report.get("ipv6", {})
        v6_flag = "[red]YES — IPv6 EXPOSED[/]" if ipv6.get("ipv6_reachable") else "[green]No[/]"
        t3 = Table("Check", "Result", box=box.SIMPLE_HEAD, border_style="bright_blue")
        t3.add_row("IPv6 Reachable", v6_flag)
        t3.add_row("IPv6 Address",   ipv6.get("ipv6_address") or "N/A")
        con.print(Panel(t3, title="[cyan]IPv6 Leak Check[/]"))

        # Headers Table
        hdrs = report.get("headers", {})
        anon_color = {"elite": "green", "anonymous": "yellow", "transparent": "red"}.get(
            hdrs.get("anonymity_level", "unknown"), "white"
        )
        t4 = Table("Check", "Result", box=box.SIMPLE_HEAD, border_style="bright_blue")
        t4.add_row("Anonymity Level", f"[{anon_color}]{hdrs.get('anonymity_level', 'unknown')}[/]")
        t4.add_row("IP in Headers",   f"[red]{hdrs['ip_in_headers']}[/]" if hdrs.get("ip_in_headers") else "[green]None[/]")
        t4.add_row("Proxy Headers",   str(list(hdrs.get("headers_found", {}).keys())) or "None")
        con.print(Panel(t4, title="[cyan]Proxy Header Check[/]"))

        # Tor Check
        is_tor = report.get("tor", {}).get("is_tor_exit", False)
        con.print(f"  Tor Exit Node : {'[green]Yes ✓[/]' if is_tor else '[yellow]No (direct/proxy path)[/]'}\n")

        # Leak summary
        if leaks:
            con.print("[bold red]⚠ Leak Details:[/]")
            for leak in leaks:
                con.print(f"  [red]• {leak}[/]")
        else:
            con.print("[bold green]✓ All checks passed. No leaks detected.[/]")

        duration = report.get("summary", {}).get("duration_seconds", 0)
        con.print(f"\n[dim]Audit completed in {duration}s at {report.get('timestamp')}[/]\n")

    # ── Private helpers ───────────────────────────────────────────────────────

    def _safe_check(self, name: str, fn) -> dict:
        """Run a check function, catching all exceptions gracefully."""
        try:
            return fn()
        except Exception as e:
            logger.warning(f"[LeakAudit] {name} failed: {e}")
            return {"error": str(e)}
