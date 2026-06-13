"""
ghostroute/core/config.py
=========================
Configuration management for GhostRoute.

Loads, merges, validates, and persists configuration data stored in a YAML
file.  Ships with sane :data:`DEFAULT_CONFIG` values that are deep-merged
with whatever the operator supplies — missing keys always fall back to the
built-in defaults so that partial config files are fully supported.

Keys are accessed via dot-notation strings (e.g. ``"tor.socks_port"``) to
provide an ergonomic API without exposing the nested dict structure directly.

Typical usage::

    cfg = Config()
    cfg.load()
    print(cfg.get("tor.socks_port"))   # → 9050
    cfg.set("rotation.interval_seconds", 300)
    cfg.save()
"""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("ghostroute")

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "tor": {
        "socks_port": 9050,
        "control_port": 9051,
        "trans_port": 9040,
        "dns_port": 5353,
        "control_password": "ghostroute",
        "max_circuits": 5,
        "circuit_timeout": 30,
        "data_dir": "/tmp/ghostroute-tor",
    },
    "proxy": {
        "list_file": "/etc/ghostroute/proxies.txt",
        "chain_length": 2,
        "timeout": 10,
        "health_check_interval": 60,
        "rotation_mode": "round-robin",  # round-robin | random | latency
        "scraper_sources": [
            "https://api.proxyscrape.com/v3/free-proxy-list/get"
            "?request=displayproxies&protocol=socks5",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        ],
    },
    "rotation": {
        "enabled": True,
        "interval_seconds": 120,
        "requests_per_ip": 50,
        "mode": "time",  # time | request | manual
    },
    "obfuscation": {
        "priority": [
            "obfs4",
            "meek",
            "timing_jitter",
            "packet_padding",
            "protocol_mimicry",
        ],
        "padding": {
            "min_bytes": 0,
            "max_bytes": 512,
        },
        "timing": {
            "min_jitter_ms": 5,
            "max_jitter_ms": 200,
        },
        "obfs4": {
            "bridge": "",  # operator-supplied bridge line
        },
        "meek": {
            "url": "https://meek.azureedge.net/",
            "front": "ajax.aspnetcdn.com",
        },
    },
    "dns": {
        "mode": "tor",  # tor | dnscrypt | doh
        "dnscrypt_config": "/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
        "doh_url": "https://cloudflare-dns.com/dns-query",
        "backup_resolver": "127.0.0.1",
    },
    "kill_switch": {
        "mode": "hard",  # hard | soft
        "monitor_interval": 5,
    },
    "mac": {
        "interface": "auto",  # auto | specific interface name
        "mode": "random",     # random | preserve
    },
    "audit": {
        "check_urls": [
            "https://api.ipify.org?format=json",
            "https://ipinfo.io/json",
            "https://httpbin.org/ip",
        ],
        "dns_leak_url": "https://dnsleaktest.com",
        "timeout": 15,
    },
}


# ---------------------------------------------------------------------------
# Deep-merge helper (module-private)
# ---------------------------------------------------------------------------

def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into a copy of *base*.

    Unlike ``dict.update`` this preserves nested keys that exist in *base*
    but are absent from *override*.

    Parameters
    ----------
    base:
        The dictionary providing default values.
    override:
        The dictionary whose values take precedence.

    Returns
    -------
    dict
        A new dictionary containing the merged result.
    """
    result = copy.deepcopy(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = copy.deepcopy(val)
    return result


# ---------------------------------------------------------------------------
# Config class
# ---------------------------------------------------------------------------

class Config:
    """GhostRoute configuration manager.

    Reads a YAML config file and merges it with :data:`DEFAULT_CONFIG`.
    Exposes dot-notation getters / setters for individual keys and a
    section getter for bulk reads.

    Parameters
    ----------
    config_path:
        Absolute path to the YAML configuration file.  Defaults to
        ``/etc/ghostroute/config.yaml``.
    """

    def __init__(self, config_path: str = "/etc/ghostroute/config.yaml") -> None:
        self._config_path = Path(config_path)
        self._data: dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load the YAML config file and deep-merge it with defaults.

        If the file does not exist the manager continues with the built-in
        defaults — no error is raised.  This lets the daemon start without
        any config file present and the operator can generate one later via
        :meth:`save`.

        Raises
        ------
        yaml.YAMLError
            If the YAML file is syntactically invalid.
        OSError
            If the file exists but cannot be read.
        """
        if not self._config_path.exists():
            log.info(
                "Config file %s not found — using built-in defaults.",
                self._config_path,
            )
            self._data = copy.deepcopy(DEFAULT_CONFIG)
            return

        try:
            raw_text = self._config_path.read_text(encoding="utf-8")
        except OSError as exc:
            log.error("Cannot read config file: %s", exc)
            raise

        try:
            user_config: dict[str, Any] = yaml.safe_load(raw_text) or {}
        except yaml.YAMLError as exc:
            log.error("Config file YAML parse error: %s", exc)
            raise

        if not isinstance(user_config, dict):
            log.warning(
                "Config file does not contain a YAML mapping — "
                "ignoring and using defaults."
            )
            self._data = copy.deepcopy(DEFAULT_CONFIG)
            return

        self._data = _deep_merge(DEFAULT_CONFIG, user_config)
        log.debug("Config loaded from %s.", self._config_path)

    def save(self) -> None:
        """Write the current configuration back to the YAML file.

        Creates any missing parent directories with ``mode=0o755``.

        Raises
        ------
        OSError
            If the file cannot be created or written.
        """
        self._config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)

        try:
            yaml_text = yaml.safe_dump(
                self._data,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=True,
            )
            self._config_path.write_text(yaml_text, encoding="utf-8")
        except OSError as exc:
            log.error("Failed to write config file: %s", exc)
            raise

        log.debug("Config saved to %s.", self._config_path)

    # ------------------------------------------------------------------
    # Dot-notation key access
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value by dot-notation key.

        Parameters
        ----------
        key:
            A dot-separated path into the config dict, e.g.
            ``"tor.socks_port"`` or ``"obfuscation.timing.min_jitter_ms"``.
        default:
            Returned if the key path does not exist.  Defaults to *None*.

        Returns
        -------
        Any
            The value at *key*, or *default* if the path does not exist.

        Examples
        --------
        >>> cfg.get("tor.socks_port")
        9050
        >>> cfg.get("nonexistent.key", 42)
        42
        """
        try:
            return self._resolve(key)
        except KeyError:
            return default

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value by dot-notation key.

        Intermediate dictionaries are created automatically if they do not
        already exist, so it is safe to call ``set`` on nested keys that
        were not present in the original file.

        Parameters
        ----------
        key:
            A dot-separated path, e.g. ``"tor.socks_port"``.
        value:
            The new value to assign.

        Examples
        --------
        >>> cfg.set("rotation.interval_seconds", 300)
        >>> cfg.set("obfuscation.obfs4.bridge", "obfs4 1.2.3.4:1234 ...")
        """
        parts = key.split(".")
        node: dict[str, Any] = self._data
        for part in parts[:-1]:
            if part not in node or not isinstance(node[part], dict):
                node[part] = {}
            node = node[part]
        node[parts[-1]] = value
        log.debug("Config key %r set to %r.", key, value)

    def get_section(self, section: str) -> dict[str, Any]:
        """Return a deep copy of an entire top-level configuration section.

        Parameters
        ----------
        section:
            Top-level key name, e.g. ``"tor"``, ``"proxy"``, ``"dns"``.

        Returns
        -------
        dict
            A deep copy of the section dict so callers cannot mutate
            the internal state.

        Raises
        ------
        KeyError
            If *section* does not exist in the loaded configuration.
        """
        if section not in self._data:
            raise KeyError(
                f"Config section {section!r} not found. "
                f"Available sections: {list(self._data.keys())}"
            )
        return copy.deepcopy(self._data[section])

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------

    def reset_to_defaults(self) -> None:
        """Discard all loaded configuration and revert to built-in defaults.

        The change is in-memory only until :meth:`save` is called.
        """
        self._data = copy.deepcopy(DEFAULT_CONFIG)
        log.info("Configuration reset to built-in defaults.")

    @property
    def config_path(self) -> Path:
        """The filesystem path this :class:`Config` reads from and writes to."""
        return self._config_path

    @property
    def data(self) -> dict[str, Any]:
        """A deep copy of the entire configuration dict (read-only snapshot)."""
        return copy.deepcopy(self._data)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve(self, key: str) -> Any:
        """Walk the nested dict tree using dot-separated *key* parts.

        Parameters
        ----------
        key:
            Dot-separated path string.

        Returns
        -------
        Any
            The value found at the path.

        Raises
        ------
        KeyError
            If any segment along the path is not found.
        """
        node: Any = self._data
        for part in key.split("."):
            if not isinstance(node, dict):
                raise KeyError(
                    f"Path segment {part!r} cannot be traversed — "
                    f"parent is not a dict (key: {key!r})."
                )
            node = node[part]  # raises KeyError naturally if absent
        return node

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Config path={self._config_path!r} sections={list(self._data.keys())}>"
