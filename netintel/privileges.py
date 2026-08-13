"""Raw-socket privilege detection.

Capture and traceroute need privileges that a normal user process does not
have. Finding that out from a ``PermissionError`` in the middle of an
operation is a poor experience, so the state is checked up front and shown in
the UI before anything is attempted.
"""

from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PrivilegeStatus:
    """Whether raw sockets are usable, and what to do if they are not."""

    available: bool
    detail: str

    @property
    def hint(self) -> str:
        if self.available:
            return ""
        # Read through a plain `str`: a type checker narrows `sys.platform` to
        # the platform it is running on and then calls the other branches dead
        # code, which they are not — this ships to all three.
        system: str = sys.platform
        if system.startswith("linux"):
            return (
                "Run with sudo, or grant the interpreter the capability once: "
                "sudo setcap cap_net_raw,cap_net_admin+eip "
                "$(readlink -f $(which python3))"
            )
        if system == "darwin":
            return (
                "Run with sudo, or make /dev/bpf* readable for your user "
                "(the Wireshark installer's ChmodBPF helper does this)."
            )
        return "Run the application as Administrator, and install Npcap."


def _windows_privileges() -> PrivilegeStatus:  # pragma: no cover - platform specific
    """Windows has no raw-socket capability to probe; ask for elevation instead."""
    import ctypes

    try:
        # ``windll`` exists only on Windows, so a type checker running on any
        # other platform correctly reports it as missing.
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        elevated = False
    return PrivilegeStatus(
        available=elevated,
        detail="administrator" if elevated else "not elevated",
    )


def check_raw_socket_privileges() -> PrivilegeStatus:
    """Probe for raw-socket access without sending anything."""
    if os.name == "nt":
        return _windows_privileges()

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return PrivilegeStatus(available=True, detail="running as root")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP):
            return PrivilegeStatus(available=True, detail="raw sockets permitted (CAP_NET_RAW)")
    except PermissionError:
        return PrivilegeStatus(available=False, detail="raw sockets not permitted")
    except OSError as exc:
        return PrivilegeStatus(available=False, detail=f"raw sockets unavailable: {exc}")
