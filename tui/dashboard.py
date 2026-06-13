"""
GhostRoute — System-Wide Anonymity Platform
Dashboard TUI module — full interactive terminal UI using rich + prompt_toolkit
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Optional, Callable

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich import box
from rich.style import Style
from rich.rule import Rule

console = Console()

# ─────────────────────────────── Color Palette ───────────────────────────────
C_BRAND    = "bold bright_cyan"
C_ON       = "bold bright_green"
C_OFF      = "bold red"
C_WARN     = "bold yellow"
C_INFO     = "bold bright_white"
C_DIM      = "dim white"
C_ACCENT   = "bold magenta"
C_BORDER   = "bright_cyan"
C_HEADER   = "bold bright_white on #0d1b2a"

MODULE_KEYS = {
    "1":  ("tor_routing",      "System-Wide Tor Routing",   "iptables → Tor TransPort"),
    "2":  ("tor_manager",      "Tor Circuit Manager",        "Tor daemon + circuit control"),
    "3":  ("proxy_chain",      "Proxy Chain Engine",         "SOCKS4/5/HTTP chain + scraper"),
    "4":  ("ip_rotator",       "IP Rotation Engine",         "Per-request + time/request modes"),
    "5a": ("obfs4",            "obfs4 Transport",            "Pluggable transport layer"),
    "5b": ("meek",             "meek-lite Transport",        "CDN front via Azure/Cloudflare"),
    "5c": ("packet_padding",   "Packet Padding",             "Random byte padding per packet"),
    "5d": ("protocol_mimicry", "Protocol Mimicry",           "HTTPS/WebSocket disguise"),
    "5e": ("timing_jitter",    "Timing Jitter",              "Randomised transmission delay"),
    "6":  ("dns_protect",      "DNS Leak Protection",        "dnscrypt / Tor DNS / DoH"),
    "7":  ("ipv6_block",       "IPv6 Leak Block",            "sysctl disable + ip6tables DROP"),
    "8":  ("kill_switch",      "Kill Switch",                "Hard iptables DROP on leak"),
    "9":  ("mac_spoof",        "MAC Address Spoof",          "Random MAC per session"),
}


def _status_badge(enabled: bool) -> Text:
    """Return a coloured status badge."""
    if enabled:
        return Text(" ● ON  ", style=C_ON)
    return Text(" ○ OFF ", style=C_OFF)


def _header_panel() -> Panel:
    """Top header with branding."""
    lines = Text()
    lines.append("  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██████╗  ██████╗ ██╗   ██╗████████╗███████╗\n", style="bold bright_cyan")
    lines.append(" ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝\n", style="bold cyan")
    lines.append(" ██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝██║   ██║██║   ██║   ██║   █████╗  \n", style="bold cyan")
    lines.append(" ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  \n", style="bold blue")
    lines.append(" ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗\n", style="bold blue")
    lines.append("  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝\n", style="bold bright_blue")
    lines.append("          System-Wide Anonymity Platform  •  For Authorized Security Operations Only\n", style="dim white")

    return Panel(
        Align.center(lines),
        style="bold bright_cyan",
        border_style=C_BORDER,
        padding=(0, 2),
    )


def _status_panel(runtime_info: dict) -> Panel:
    """Live status bar panel showing current IP, circuit, latency."""
    ip       = runtime_info.get("current_ip", "Resolving...")
    country  = runtime_info.get("current_country", "Unknown")
    isp      = runtime_info.get("current_isp", "Unknown")
    circuits = runtime_info.get("active_circuits", 0)
    proxies  = runtime_info.get("active_proxies", 0)
    rotations = runtime_info.get("rotation_count", 0)
    session_start = runtime_info.get("session_start", time.time())

    elapsed = str(timedelta(seconds=int(time.time() - session_start))).split(".")[0]

    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="left",  ratio=1)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="right",  ratio=1)

    left = Text()
    left.append("🌐  IP: ", style="dim white")
    left.append(ip, style=C_ON if ip not in ("Unknown", "Resolving...") else C_WARN)
    left.append(f"  [{country}]", style=C_DIM)

    mid = Text()
    mid.append("⚡ Circuits: ", style="dim white")
    mid.append(str(circuits), style=C_ACCENT)
    mid.append("   Proxies: ", style="dim white")
    mid.append(str(proxies), style=C_ACCENT)

    right = Text()
    right.append("🔄 Rotations: ", style="dim white")
    right.append(str(rotations), style=C_INFO)
    right.append(f"   ⏱ {elapsed}", style=C_DIM)

    grid.add_row(left, mid, right)

    return Panel(grid, title="[bold bright_cyan]● LIVE STATUS[/]", border_style="bright_cyan", padding=(0, 1))


def _modules_panel(states: dict) -> Panel:
    """Module toggle panel showing all modules with status."""
    table = Table(
        box=box.SIMPLE_HEAD,
        expand=True,
        show_header=True,
        header_style=C_HEADER,
        border_style="bright_blue",
        padding=(0, 1),
    )
    table.add_column("Key",     style="bold bright_yellow", width=5, justify="center")
    table.add_column("Module",  style=C_INFO, ratio=3)
    table.add_column("Description", style=C_DIM, ratio=4)
    table.add_column("Status",  justify="center", width=9)

    # Group obfuscation sub-modules
    for key, (module_id, name, desc) in MODULE_KEYS.items():
        if key.startswith("5") and key != "5a":
            prefix = "  └─ " if key != "5a" else "  ┌─ "
        elif key == "5a":
            # Add obfuscation header row
            table.add_row(
                Text("5", style="bold bright_yellow"),
                Text("Traffic Obfuscation", style="bold bright_white"),
                Text("Pluggable transports + shaping", style=C_DIM),
                Text("GROUP", style="dim"),
            )
            prefix = "  └─ "
        else:
            prefix = ""

        enabled = states.get(module_id, False)
        badge   = _status_badge(enabled)

        row_style = "on #0a1520" if enabled else ""
        table.add_row(
            Text(f"[{key}]", style="bold bright_yellow"),
            Text(f"{prefix}{name}", style=C_ON if enabled else C_INFO),
            Text(desc, style=C_DIM),
            badge,
            style=row_style,
        )

    return Panel(
        table,
        title="[bold bright_cyan]⚙  MODULES[/]",
        border_style="bright_blue",
        padding=(0, 1),
    )


def _controls_panel() -> Panel:
    """Bottom controls / hotkey reference."""
    controls = [
        ("[1-9/5a-5e]", "Toggle module"),
        ("[A]", "Rotate IP now"),
        ("[L]", "Leak audit"),
        ("[S]", "Scrape+validate proxies"),
        ("[C]", "Show circuits"),
        ("[P]", "Add proxy"),
        ("[R]", "Set rotation interval"),
        ("[O]", "Set obfuscation priority"),
        ("[Q]", "Quit & restore system"),
    ]

    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)

    chunks = [controls[i:i+3] for i in range(0, len(controls), 3)]
    for chunk in chunks:
        row = []
        for key, action in chunk:
            t = Text()
            t.append(f"{key} ", style="bold bright_yellow")
            t.append(action, style=C_DIM)
            row.append(t)
        while len(row) < 3:
            row.append(Text(""))
        grid.add_row(*row)

    return Panel(grid, title="[bold bright_cyan]⌨  CONTROLS[/]", border_style="bright_blue", padding=(0, 1))


def _logs_panel(logs: list[str]) -> Panel:
    """Recent log messages panel."""
    text = Text()
    for entry in logs[-8:]:  # Show last 8 lines
        if "[ERROR]" in entry or "[WARN]" in entry:
            text.append(entry + "\n", style=C_WARN)
        elif "[OK]" in entry or "[SUCCESS]" in entry:
            text.append(entry + "\n", style=C_ON)
        else:
            text.append(entry + "\n", style=C_DIM)

    return Panel(text, title="[bold bright_cyan]📋  LOGS[/]", border_style="bright_blue", padding=(0, 1))


def build_layout(states: dict, runtime_info: dict, logs: list[str]) -> Layout:
    """Build the full TUI layout."""
    layout = Layout()

    layout.split_column(
        Layout(name="header",   size=9),
        Layout(name="status",   size=5),
        Layout(name="main",     ratio=1),
        Layout(name="controls", size=7),
    )

    layout["main"].split_row(
        Layout(name="modules", ratio=3),
        Layout(name="logs",    ratio=2),
    )

    layout["header"].update(_header_panel())
    layout["status"].update(_status_panel(runtime_info))
    layout["modules"].update(_modules_panel(states))
    layout["logs"].update(_logs_panel(logs))
    layout["controls"].update(_controls_panel())

    return layout


class Dashboard:
    """
    Main TUI dashboard. Renders the full interactive GhostRoute interface.
    Calls toggle callbacks on keypress.
    """

    def __init__(
        self,
        state_manager,
        get_runtime_info: Callable[[], dict],
        on_toggle: Callable[[str], None],
        on_rotate: Callable[[], None],
        on_audit: Callable[[], None],
        on_scrape: Callable[[], None],
        on_quit: Callable[[], None],
        on_add_proxy: Callable[[str], None],
        on_set_interval: Callable[[int], None],
        on_set_priority: Callable[[list], None],
        on_show_circuits: Callable[[], None],
    ):
        self.state_manager   = state_manager
        self.get_runtime     = get_runtime_info
        self.on_toggle       = on_toggle
        self.on_rotate       = on_rotate
        self.on_audit        = on_audit
        self.on_scrape       = on_scrape
        self.on_quit         = on_quit
        self.on_add_proxy    = on_add_proxy
        self.on_set_interval = on_set_interval
        self.on_set_priority = on_set_priority
        self.on_show_circuits = on_show_circuits

        self.logs: list[str] = []
        self._running = False

    def log(self, message: str) -> None:
        """Add a log entry to the dashboard log panel."""
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{ts}] {message}")
        if len(self.logs) > 200:
            self.logs = self.logs[-200:]

    def run(self) -> None:
        """Start the live TUI loop."""
        import sys
        import termios
        import tty

        self._running = True

        def get_char() -> str:
            """Read a single character from stdin (raw mode)."""
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = sys.stdin.read(1)
                # Handle multi-char sequences (arrow keys etc.)
                if ch == '\x1b':
                    ch += sys.stdin.read(2)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            return ch

        with Live(
            build_layout(
                self.state_manager.get_all_states(),
                self.get_runtime(),
                self.logs,
            ),
            console=console,
            refresh_per_second=2,
            screen=True,
        ) as live:

            # Input thread
            def input_loop():
                pending = ""
                while self._running:
                    try:
                        ch = get_char().lower().strip()
                    except Exception:
                        break

                    if ch == 'q':
                        self._running = False
                        self.on_quit()
                        break

                    elif ch == 'a':
                        self.log("[INFO] Manual IP rotation triggered...")
                        threading.Thread(target=self.on_rotate, daemon=True).start()

                    elif ch == 'l':
                        self.log("[INFO] Running leak audit...")
                        threading.Thread(target=self.on_audit, daemon=True).start()

                    elif ch == 's':
                        self.log("[INFO] Scraping + validating proxies...")
                        threading.Thread(target=self.on_scrape, daemon=True).start()

                    elif ch == 'c':
                        self.log("[INFO] Fetching circuit info...")
                        threading.Thread(target=self.on_show_circuits, daemon=True).start()

                    elif ch == 'p':
                        # Prompt for proxy in a secondary console (outside live)
                        live.stop()
                        proxy_str = console.input("\n[bold yellow]Enter proxy (ip:port:type or ip:port:type:user:pass):[/] ")
                        if proxy_str.strip():
                            self.on_add_proxy(proxy_str.strip())
                            self.log(f"[OK] Added proxy: {proxy_str.strip()}")
                        live.start()

                    elif ch == 'r':
                        live.stop()
                        val = console.input("\n[bold yellow]Set rotation interval (seconds, e.g. 60):[/] ")
                        try:
                            self.on_set_interval(int(val.strip()))
                            self.log(f"[OK] Rotation interval set to {val}s")
                        except ValueError:
                            self.log("[WARN] Invalid interval value")
                        live.start()

                    elif ch == 'o':
                        live.stop()
                        console.print("\n[bold yellow]Current priority:[/] obfs4, meek, timing_jitter, packet_padding, protocol_mimicry")
                        val = console.input("[bold yellow]Enter new priority (comma-separated):[/] ")
                        modules = [m.strip() for m in val.split(",") if m.strip()]
                        if modules:
                            self.on_set_priority(modules)
                            self.log(f"[OK] Obfuscation priority set to: {', '.join(modules)}")
                        live.start()

                    elif ch in MODULE_KEYS:
                        module_id = MODULE_KEYS[ch][0]
                        self.on_toggle(ch)
                        new_state = self.state_manager.is_enabled(module_id)
                        status_str = "enabled" if new_state else "disabled"
                        self.log(f"[{'OK' if new_state else 'INFO'}] {MODULE_KEYS[ch][1]} {status_str}")

                    # Refresh layout
                    live.update(build_layout(
                        self.state_manager.get_all_states(),
                        self.get_runtime(),
                        self.logs,
                    ))

            input_thread = threading.Thread(target=input_loop, daemon=True)
            input_thread.start()

            # Render loop
            while self._running:
                live.update(build_layout(
                    self.state_manager.get_all_states(),
                    self.get_runtime(),
                    self.logs,
                ))
                time.sleep(0.5)

    def stop(self) -> None:
        """Stop the dashboard."""
        self._running = False
