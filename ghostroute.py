#!/usr/bin/env python3
"""
GhostRoute — System-Wide Anonymity Platform
Main entry point: CLI + TUI launcher

Usage:
    sudo python ghostroute.py [COMMAND] [OPTIONS]

Commands:
    tui                 Launch interactive terminal UI (default)
    start               Start GhostRoute with configured/specified modules
    stop                Stop all modules and restore system state
    status              Show current module states and runtime info
    toggle <module>     Toggle a specific module on/off
    rotate              Trigger manual IP rotation
    audit               Run leak detection audit
    config <key> <val>  Set a configuration value
    proxy add <proxy>   Add a proxy to the pool
    proxy scrape        Scrape and validate proxies from public sources
    proxy list          List current proxy pool

Examples:
    sudo python ghostroute.py tui
    sudo python ghostroute.py start --modules tor_routing,dns_protect,kill_switch
    sudo python ghostroute.py toggle kill_switch
    sudo python ghostroute.py config rotation.interval_seconds 60
    sudo python ghostroute.py proxy add 185.199.0.1:1080:socks5
"""

import sys
import os
import argparse
import signal
import logging
import threading
import time
from typing import Optional

# ── Ensure project root is in path ───────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils    import require_root, setup_logging
from core.config   import Config
from core.state    import StateManager

# ── Lazy module imports (only load what's needed) ────────────────────────────
def _load_modules(config: Config, state: StateManager):
    """Import and instantiate all GhostRoute modules."""
    from modules.tor_routing    import TorRouting
    from modules.tor_manager    import TorManager
    from modules.proxy_chain    import ProxyChainEngine
    from modules.ip_rotator     import IPRotator
    from modules.dns_protect    import DNSProtect
    from modules.ipv6_block     import IPv6Block
    from modules.kill_switch    import KillSwitch
    from modules.mac_spoof      import MACSpoof
    from modules.leak_audit     import LeakAudit
    from modules.obfuscation    import ObfuscationEngine

    tor_routing  = TorRouting(config, state)
    tor_manager  = TorManager(config, state)
    proxy_chain  = ProxyChainEngine(config, state)
    dns_protect  = DNSProtect(config, state)
    ipv6_block   = IPv6Block(config, state)
    kill_switch  = KillSwitch(config, state)
    mac_spoof    = MACSpoof(config, state)
    obfuscation  = ObfuscationEngine(config, state)
    ip_rotator   = IPRotator(config, state, tor_manager=tor_manager, proxy_chain=proxy_chain)
    leak_audit   = LeakAudit(config)

    return {
        "tor_routing":      tor_routing,
        "tor_manager":      tor_manager,
        "proxy_chain":      proxy_chain,
        "ip_rotator":       ip_rotator,
        "dns_protect":      dns_protect,
        "ipv6_block":       ipv6_block,
        "kill_switch":      kill_switch,
        "mac_spoof":        mac_spoof,
        "obfuscation":      obfuscation,
        "leak_audit":       leak_audit,
    }


# ── Module Key → Module ID mapping (mirrors dashboard.py MODULE_KEYS) ────────
KEY_TO_MODULE = {
    "1":  "tor_routing",
    "2":  "tor_manager",
    "3":  "proxy_chain",
    "4":  "ip_rotator",
    "5a": "obfs4",
    "5b": "meek",
    "5c": "packet_padding",
    "5d": "protocol_mimicry",
    "5e": "timing_jitter",
    "6":  "dns_protect",
    "7":  "ipv6_block",
    "8":  "kill_switch",
    "9":  "mac_spoof",
}

NAME_TO_KEY = {v: k for k, v in KEY_TO_MODULE.items()}

OBFUSCATION_SUBS = {"obfs4", "meek", "packet_padding", "protocol_mimicry", "timing_jitter"}


class GhostRoute:
    """
    Main GhostRoute controller. Manages module lifecycle and coordinates
    between all subsystems.
    """

    def __init__(self, config_path: str = "/etc/ghostroute/config.yaml"):
        self.config  = Config(config_path)
        self.config.load()

        self.state   = StateManager()
        self.state.load()

        self.logger  = logging.getLogger("ghostroute")
        self.modules = {}
        self._shutdown_event = threading.Event()

    def initialize(self) -> None:
        """Load all modules."""
        self.logger.info("Initializing GhostRoute modules...")
        self.modules = _load_modules(self.config, self.state)
        self.logger.info("All modules loaded successfully.")

    def enable_module(self, module_key: str) -> bool:
        """
        Enable a module by its key (e.g., '1', '5a') or name (e.g., 'tor_routing').
        Returns True on success.
        """
        # Resolve key to module name
        if module_key in KEY_TO_MODULE:
            module_id = KEY_TO_MODULE[module_key]
        elif module_key in NAME_TO_KEY:
            module_id = module_key
        else:
            self.logger.error(f"Unknown module: {module_key}")
            return False

        try:
            if module_id in OBFUSCATION_SUBS:
                self.modules["obfuscation"].enable_module(module_id)
            elif module_id in self.modules:
                self.modules[module_id].enable()
            else:
                self.logger.error(f"Module not loaded: {module_id}")
                return False

            self.logger.info(f"[+] Module '{module_id}' ENABLED")
            return True

        except Exception as e:
            self.logger.error(f"Failed to enable '{module_id}': {e}")
            return False

    def disable_module(self, module_key: str) -> bool:
        """Disable a module by key or name."""
        if module_key in KEY_TO_MODULE:
            module_id = KEY_TO_MODULE[module_key]
        elif module_key in NAME_TO_KEY:
            module_id = module_key
        else:
            self.logger.error(f"Unknown module: {module_key}")
            return False

        try:
            if module_id in OBFUSCATION_SUBS:
                self.modules["obfuscation"].disable_module(module_id)
            elif module_id in self.modules:
                self.modules[module_id].disable()
            else:
                self.logger.error(f"Module not loaded: {module_id}")
                return False

            self.logger.info(f"[-] Module '{module_id}' DISABLED")
            return True

        except Exception as e:
            self.logger.error(f"Failed to disable '{module_id}': {e}")
            return False

    def toggle_module(self, module_key: str) -> bool:
        """Toggle a module. Returns new state (True=enabled)."""
        if module_key in KEY_TO_MODULE:
            module_id = KEY_TO_MODULE[module_key]
        elif module_key in NAME_TO_KEY:
            module_id = module_key
        else:
            self.logger.error(f"Unknown module: {module_key}")
            return False

        currently = self.state.is_enabled(module_id)
        if currently:
            return not self.disable_module(module_key)
        else:
            return self.enable_module(module_key)

    def rotate_ip(self) -> dict:
        """Trigger manual IP rotation."""
        if not self.state.is_enabled("ip_rotator"):
            # Try direct Tor NEWNYM if rotator not enabled but Tor is
            if self.state.is_enabled("tor_manager"):
                self.modules["tor_manager"].new_identity()
                time.sleep(5)
                new_ip = self._get_current_ip()
                self.logger.info(f"[+] IP rotated via Tor NEWNYM → {new_ip}")
                return {"method": "tor_newnym", "new_ip": new_ip}
            return {"error": "IP Rotator and Tor not enabled"}

        result = self.modules["ip_rotator"].rotate(reason="manual_command")
        self.logger.info(f"[+] IP rotated: {result.get('old_ip')} → {result.get('new_ip')}")
        return result

    def run_audit(self) -> dict:
        """Run full leak audit and print report."""
        self.logger.info("[*] Running leak audit...")
        report = self.modules["leak_audit"].run_full_audit()
        self.modules["leak_audit"].print_report(report)
        return report

    def start_with_modules(self, module_names: list[str]) -> None:
        """Enable a specific list of modules by name."""
        for name in module_names:
            self.enable_module(name.strip())

    def stop_all(self) -> None:
        """Disable all active modules and restore system state."""
        self.logger.info("[*] Stopping all GhostRoute modules and restoring system...")

        # Disable in reverse order (kill_switch last, or first to restore traffic)
        disable_order = [
            "ip_rotator", "obfuscation", "proxy_chain",
            "tor_manager", "tor_routing",
            "mac_spoof", "dns_protect", "ipv6_block", "kill_switch",
        ]

        for module_id in disable_order:
            if self.state.is_enabled(module_id) and module_id in self.modules:
                try:
                    if module_id == "obfuscation":
                        self.modules["obfuscation"].disable_all()
                    else:
                        self.modules[module_id].disable()
                    self.logger.info(f"[-] {module_id} disabled")
                except Exception as e:
                    self.logger.warning(f"[!] Error disabling {module_id}: {e}")

        self.state.save()
        self.logger.info("[+] System restored. GhostRoute stopped.")

    def _get_current_ip(self) -> str:
        """Fetch current external IP."""
        try:
            import requests
            r = requests.get("https://api.ipify.org?format=json", timeout=10)
            return r.json().get("ip", "Unknown")
        except Exception:
            return "Unknown"

    def get_runtime_info(self) -> dict:
        """Return current runtime info dict for TUI display."""
        info = {
            "current_ip":      self.state.runtime.current_ip,
            "current_country": self.state.runtime.current_country,
            "current_isp":     self.state.runtime.current_isp,
            "active_circuits": self.state.runtime.active_circuits,
            "active_proxies":  self.state.runtime.active_proxies,
            "rotation_count":  self.state.runtime.rotation_count,
            "session_start":   self.state.runtime.session_start,
            "tor_pid":         self.state.runtime.tor_pid,
            "proxy_pool_size": self.state.runtime.proxy_pool_size,
        }
        return info

    def launch_tui(self) -> None:
        """Launch the interactive TUI dashboard."""
        from tui.dashboard import Dashboard

        dashboard = Dashboard(
            state_manager    = self.state,
            get_runtime_info = self.get_runtime_info,
            on_toggle        = self.toggle_module,
            on_rotate        = self.rotate_ip,
            on_audit         = self.run_audit,
            on_scrape        = self._scrape_proxies,
            on_quit          = self._quit,
            on_add_proxy     = self._add_proxy,
            on_set_interval  = self._set_rotation_interval,
            on_set_priority  = self._set_obfuscation_priority,
            on_show_circuits = self._show_circuits,
        )

        def update_ip_background():
            while not self._shutdown_event.is_set():
                ip = self._get_current_ip()
                self.state.update_runtime("current_ip", ip)
                self._shutdown_event.wait(30)

        threading.Thread(target=update_ip_background, daemon=True).start()

        try:
            dashboard.run()
        except KeyboardInterrupt:
            pass

    def _scrape_proxies(self) -> None:
        """Background proxy scrape + validate."""
        if "proxy_chain" in self.modules:
            self.modules["proxy_chain"].scrape_and_validate()

    def _add_proxy(self, proxy_str: str) -> None:
        if "proxy_chain" in self.modules:
            self.modules["proxy_chain"].add_proxy(proxy_str)

    def _set_rotation_interval(self, seconds: int) -> None:
        self.config.set("rotation.interval_seconds", seconds)
        self.config.save()
        if "ip_rotator" in self.modules:
            self.modules["ip_rotator"].set_interval(seconds)

    def _set_obfuscation_priority(self, priority: list) -> None:
        self.config.set("obfuscation.priority", priority)
        self.config.save()
        if "obfuscation" in self.modules:
            self.modules["obfuscation"].set_priority(priority)

    def _show_circuits(self) -> None:
        if "tor_manager" in self.modules and self.state.is_enabled("tor_manager"):
            circuits = self.modules["tor_manager"].get_circuits()
            self.logger.info(f"Active Tor circuits ({len(circuits)}):")
            for i, c in enumerate(circuits):
                self.logger.info(f"  Circuit {i+1}: {c}")

    def _quit(self) -> None:
        self._shutdown_event.set()
        self.stop_all()


# ── Signal handler for clean exit ────────────────────────────────────────────
_gr_instance: Optional[GhostRoute] = None

def _handle_signal(sig, frame):
    print("\n[!] Caught signal, shutting down GhostRoute...")
    if _gr_instance:
        _gr_instance.stop_all()
    sys.exit(0)


# ── CLI argument parser ───────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostroute",
        description="GhostRoute — System-Wide Anonymity Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--config", default="/etc/ghostroute/config.yaml",
        help="Path to config YAML file (default: /etc/ghostroute/config.yaml)"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    sub = parser.add_subparsers(dest="command")

    # tui
    sub.add_parser("tui", help="Launch interactive TUI (default)")

    # start
    start_p = sub.add_parser("start", help="Start GhostRoute")
    start_p.add_argument(
        "--modules", "-m",
        help="Comma-separated module names to enable (e.g. tor_routing,dns_protect,kill_switch). "
             "If omitted, all modules defined in config are started."
    )

    # stop
    sub.add_parser("stop", help="Stop all modules and restore system")

    # status
    sub.add_parser("status", help="Show current status")

    # toggle
    tgl = sub.add_parser("toggle", help="Toggle a module on/off")
    tgl.add_argument("module", help="Module key (1-9, 5a-5e) or name")

    # rotate
    sub.add_parser("rotate", help="Manual IP rotation")

    # audit
    sub.add_parser("audit", help="Run leak audit")

    # config
    cfg = sub.add_parser("config", help="Get/set config value")
    cfg.add_argument("key",   help="Dot-notation config key (e.g. rotation.interval_seconds)")
    cfg.add_argument("value", nargs="?", help="Value to set (omit to read current value)")

    # proxy
    proxy_p = sub.add_parser("proxy", help="Proxy pool management")
    proxy_sub = proxy_p.add_subparsers(dest="proxy_cmd")
    proxy_add = proxy_sub.add_parser("add",    help="Add a proxy")
    proxy_add.add_argument("proxy_str", help="Proxy string: ip:port:type or ip:port:type:user:pass")
    proxy_sub.add_parser("scrape",  help="Scrape + validate proxies from public sources")
    proxy_sub.add_parser("list",    help="List current proxy pool status")

    return parser


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    global _gr_instance

    parser = build_parser()
    args   = parser.parse_args()

    # Default to TUI if no command given
    if not args.command:
        args.command = "tui"

    # Root check for all commands that touch system networking
    system_commands = {"start", "stop", "toggle", "tui"}
    if args.command in system_commands:
        try:
            require_root()
        except PermissionError:
            print("[!] GhostRoute requires root privileges for system networking.")
            print("    Run with: sudo python ghostroute.py")
            sys.exit(1)

    logger = setup_logging(verbose=getattr(args, "verbose", False))

    gr = GhostRoute(config_path=args.config)
    gr.initialize()
    _gr_instance = gr

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # ── Dispatch commands ─────────────────────────────────────────────────────
    if args.command == "tui":
        logger.info("Launching GhostRoute TUI...")
        gr.launch_tui()

    elif args.command == "start":
        if args.modules:
            modules = [m.strip() for m in args.modules.split(",")]
            logger.info(f"Starting modules: {modules}")
            gr.start_with_modules(modules)
        else:
            # Start all modules
            logger.info("Starting all modules...")
            for key in KEY_TO_MODULE:
                gr.enable_module(key)
        logger.info("[+] GhostRoute started. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            gr.stop_all()

    elif args.command == "stop":
        gr.stop_all()

    elif args.command == "status":
        states = gr.state.get_all_states()
        info   = gr.get_runtime_info()
        from rich.console import Console
        from rich.table import Table
        from rich import box as rbox
        con = Console()
        con.print(f"\n[bold cyan]GhostRoute Status[/]")
        con.print(f"  Current IP  : [green]{info['current_ip']}[/]")
        con.print(f"  Country     : {info['current_country']}")
        con.print(f"  Rotations   : {info['rotation_count']}")
        con.print(f"  Proxy Pool  : {info['proxy_pool_size']} nodes\n")
        t = Table("Module", "State", box=rbox.SIMPLE)
        for mod, enabled in states.items():
            t.add_row(mod, "[green]ON[/]" if enabled else "[red]OFF[/]")
        con.print(t)

    elif args.command == "toggle":
        gr.toggle_module(args.module)

    elif args.command == "rotate":
        result = gr.rotate_ip()
        print(f"[+] Rotation result: {result}")

    elif args.command == "audit":
        gr.run_audit()

    elif args.command == "config":
        if args.value is not None:
            # Try to cast value
            val = args.value
            if val.lower() in ("true", "false"):
                val = val.lower() == "true"
            elif val.isdigit():
                val = int(val)
            gr.config.set(args.key, val)
            gr.config.save()
            print(f"[+] Set {args.key} = {val}")
        else:
            current = gr.config.get(args.key)
            print(f"{args.key} = {current}")

    elif args.command == "proxy":
        if args.proxy_cmd == "add":
            gr.modules["proxy_chain"].add_proxy(args.proxy_str)
            print(f"[+] Proxy added: {args.proxy_str}")
        elif args.proxy_cmd == "scrape":
            print("[*] Scraping and validating proxies...")
            gr.modules["proxy_chain"].scrape_and_validate()
            status = gr.modules["proxy_chain"].status()
            print(f"[+] Pool: {status['alive']} alive / {status['total']} total")
        elif args.proxy_cmd == "list":
            status = gr.modules["proxy_chain"].status()
            print(f"Proxy Pool Status:")
            print(f"  Total   : {status.get('total', 0)}")
            print(f"  Alive   : {status.get('alive', 0)}")
            print(f"  Dead    : {status.get('dead', 0)}")
            print(f"  Avg RTT : {status.get('avg_latency_ms', 0):.1f}ms")
            print(f"  Anonymity breakdown: {status.get('anonymity_breakdown', {})}")


if __name__ == "__main__":
    main()
