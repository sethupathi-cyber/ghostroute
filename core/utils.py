"""
ghostroute/core/utils.py
========================
Shared utility functions for GhostRoute.

Provides wrappers for common system-level operations: running commands,
manipulating iptables/ip6tables rules, reading/writing sysctl keys,
enumerating network interfaces, resolving the Tor system-user UID, and
configuring the Rich-based logging handler used across the whole project.

All functions that interact with the kernel or firewall expect to be called
from a root context.  Use ``require_root()`` as the very first call in any
entry-point that touches privileged resources.
"""

from __future__ import annotations

import logging
import os
import pwd
import re
import subprocess
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler

# ---------------------------------------------------------------------------
# Module-level logger (created lazily; callers normally use setup_logging())
# ---------------------------------------------------------------------------
_log: Optional[logging.Logger] = None


def _get_logger() -> logging.Logger:
    """Return the module-level logger, creating a basic one if needed."""
    global _log
    if _log is None:
        _log = logging.getLogger("ghostroute")
    return _log


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a system command and return the completed-process object.

    Parameters
    ----------
    cmd:
        Argument list passed directly to :func:`subprocess.run`.
    check:
        When *True* (default) a non-zero return code raises
        :class:`RuntimeError` with the full stderr attached.

    Returns
    -------
    subprocess.CompletedProcess
        The result object containing ``returncode``, ``stdout``, and
        ``stderr``.

    Raises
    ------
    RuntimeError
        If *check* is *True* and the command exits with a non-zero status.
    """
    log = _get_logger()
    log.debug("run_cmd: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Executable not found: {cmd[0]!r}. Is it installed?"
        ) from exc

    if check and result.returncode != 0:
        stderr_snippet = result.stderr.strip()
        raise RuntimeError(
            f"Command failed (exit {result.returncode}): {' '.join(cmd)}\n"
            f"stderr: {stderr_snippet}"
        )

    if result.returncode != 0:
        log.warning(
            "run_cmd non-zero exit (%d): %s",
            result.returncode,
            " ".join(cmd),
        )

    return result


# ---------------------------------------------------------------------------
# iptables / ip6tables helpers
# ---------------------------------------------------------------------------

def iptables(args: list[str]) -> None:
    """Execute an ``iptables`` command with the supplied arguments.

    Parameters
    ----------
    args:
        Arguments appended after ``iptables``.  For example,
        ``['-A', 'OUTPUT', '-j', 'DROP']``.

    Raises
    ------
    RuntimeError
        If the underlying ``iptables`` command fails.
    """
    run_cmd(["iptables"] + args)


def ip6tables(args: list[str]) -> None:
    """Execute an ``ip6tables`` command with the supplied arguments.

    Parameters
    ----------
    args:
        Arguments appended after ``ip6tables``.

    Raises
    ------
    RuntimeError
        If the underlying ``ip6tables`` command fails.
    """
    run_cmd(["ip6tables"] + args)


# ---------------------------------------------------------------------------
# sysctl helpers
# ---------------------------------------------------------------------------

def sysctl_set(key: str, value: str) -> None:
    """Write a sysctl key-value pair via the ``sysctl`` command.

    Parameters
    ----------
    key:
        Dotted sysctl key, e.g. ``"net.ipv4.ip_forward"``.
    value:
        String value to assign.

    Raises
    ------
    RuntimeError
        If the ``sysctl`` invocation fails.
    """
    log = _get_logger()
    log.debug("sysctl_set: %s = %s", key, value)
    run_cmd(["sysctl", "-w", f"{key}={value}"])


def sysctl_get(key: str) -> str:
    """Read a sysctl key and return its value as a string.

    Parameters
    ----------
    key:
        Dotted sysctl key, e.g. ``"net.ipv4.ip_forward"``.

    Returns
    -------
    str
        The trimmed string value reported by ``sysctl``.

    Raises
    ------
    RuntimeError
        If the ``sysctl`` invocation fails or the key is unrecognised.
    """
    result = run_cmd(["sysctl", "-n", key])
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Network interface discovery
# ---------------------------------------------------------------------------

def get_network_interfaces() -> list[str]:
    """Return a list of active non-loopback interface names.

    The function reads ``/proc/net/dev`` directly to avoid dependency on
    external tools.  Only interfaces that have received at least one byte
    (i.e. are active) are included.  The loopback interface (``lo``) is
    always excluded.

    Returns
    -------
    list[str]
        Sorted list of interface names such as ``['eth0', 'wlan0']``.

    Raises
    ------
    OSError
        If ``/proc/net/dev`` cannot be read (non-Linux host).
    """
    proc_dev = Path("/proc/net/dev")
    interfaces: list[str] = []

    with proc_dev.open() as fh:
        # Skip the two header lines.
        lines = fh.readlines()[2:]

    for line in lines:
        # Format: "  eth0:  <rx_bytes> ... <tx_bytes> ..."
        parts = line.split(":")
        if len(parts) < 2:
            continue
        iface = parts[0].strip()
        if iface == "lo":
            continue
        # Check that the interface has received bytes (it is active).
        stats = parts[1].split()
        try:
            rx_bytes = int(stats[0])
        except (IndexError, ValueError):
            continue
        if rx_bytes > 0:
            interfaces.append(iface)

    interfaces.sort()
    return interfaces


def get_default_interface() -> str:
    """Return the name of the default-route network interface.

    Parses the output of ``ip route`` looking for the line that begins with
    ``default``.

    Returns
    -------
    str
        Interface name, e.g. ``"eth0"``.

    Raises
    ------
    RuntimeError
        If no default route is found or ``ip`` is not available.
    """
    result = run_cmd(["ip", "route"])
    for line in result.stdout.splitlines():
        # Example line: "default via 192.168.1.1 dev eth0 proto dhcp ..."
        match = re.search(r"^default\s+.*\bdev\s+(\S+)", line)
        if match:
            return match.group(1)
    raise RuntimeError(
        "Could not determine the default network interface from 'ip route' output."
    )


# ---------------------------------------------------------------------------
# Tor system user
# ---------------------------------------------------------------------------

def get_tor_uid() -> int:
    """Return the numeric UID of the system ``tor`` user.

    GhostRoute uses this UID when building iptables rules that exempt the
    Tor daemon's own traffic from the transparent-proxy redirect so as to
    avoid routing loops.

    Returns
    -------
    int
        The UID of the ``tor`` system user.

    Raises
    ------
    RuntimeError
        If no user named ``tor`` or ``debian-tor`` exists on the system.
    """
    for candidate in ("tor", "debian-tor", "_tor"):
        try:
            return pwd.getpwnam(candidate).pw_uid
        except KeyError:
            continue
    raise RuntimeError(
        "No Tor system user found (tried: 'tor', 'debian-tor', '_tor'). "
        "Is Tor installed?"
    )


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def require_root() -> None:
    """Assert that the current process is running as root (UID 0).

    Raises
    ------
    PermissionError
        If the effective user ID is not 0.
    """
    if os.geteuid() != 0:
        raise PermissionError(
            "GhostRoute must be run as root (or via sudo). "
            f"Current UID: {os.geteuid()}"
        )


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the project-wide Rich logging handler.

    Calling this function more than once is safe; subsequent calls update the
    log level on the existing logger without adding duplicate handlers.

    Parameters
    ----------
    verbose:
        When *True* the log level is set to ``DEBUG``; otherwise ``INFO``.

    Returns
    -------
    logging.Logger
        The configured ``"ghostroute"`` logger instance.
    """
    global _log

    level = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger("ghostroute")
    logger.setLevel(level)

    # Avoid adding duplicate handlers if setup_logging is called multiple times.
    if not any(isinstance(h, RichHandler) for h in logger.handlers):
        rich_handler = RichHandler(
            level=level,
            rich_tracebacks=True,
            tracebacks_show_locals=verbose,
            markup=True,
            show_path=verbose,
        )
        rich_handler.setFormatter(
            logging.Formatter(fmt="%(message)s", datefmt="[%X]")
        )
        logger.addHandler(rich_handler)
    else:
        # Update level on existing handlers.
        for handler in logger.handlers:
            handler.setLevel(level)

    _log = logger
    return logger


# ---------------------------------------------------------------------------
# Process check
# ---------------------------------------------------------------------------

def is_process_running(name: str) -> bool:
    """Check whether at least one process with the given name is running.

    Inspects ``/proc/<pid>/comm`` for each numeric subdirectory under
    ``/proc``.  This approach avoids spawning an external process and works
    on any Linux kernel.

    Parameters
    ----------
    name:
        The process name to search for (compared against ``/proc/<pid>/comm``
        which contains at most 15 characters, matching the kernel truncation
        behaviour of ``ps``).

    Returns
    -------
    bool
        *True* if at least one running process matches *name*.
    """
    proc = Path("/proc")
    target = name[:15]  # kernel truncates comm to 15 chars

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        comm_file = entry / "comm"
        try:
            comm = comm_file.read_text().strip()
        except OSError:
            # Process may have exited between iterdir() and read_text().
            continue
        if comm == target:
            return True
    return False
