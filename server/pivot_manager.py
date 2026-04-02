import subprocess


# ── Internal helpers ──────────────────────────────────────────────────────────

def _run(cmd: list[str]) -> dict:
    """Run a system command and return ok, returncode, error."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "ok":         result.returncode == 0,
        "returncode": result.returncode,
        "error":      result.stderr.strip(),
    }


# ── Interface management ──────────────────────────────────────────────────────

def ensure_interface(interface: str = "ligolo") -> dict:
    """
    Create and bring up a TUN interface if it does not already exist.
    Safe to call multiple times — skips creation if the interface is already up.

    Args:
        interface: Name of the TUN interface to create (e.g. 'ligolo', 'ligolo1')
    """
    # Check if interface already exists
    check = subprocess.run(["ip", "link", "show", interface], capture_output=True)
    if check.returncode == 0:
        return {"ok": True, "created": False, "interface": interface}

    create = _run(["ip", "tuntap", "add", "user", "root", "mode", "tun", interface])
    if not create["ok"]:
        return {"ok": False, "created": False, "error": create["error"]}

    up = _run(["ip", "link", "set", interface, "up"])
    if not up["ok"]:
        return {"ok": False, "created": True, "error": up["error"]}

    return {"ok": True, "created": True, "interface": interface}


# ── Route management ──────────────────────────────────────────────────────────

def add_route(subnet: str, interface: str = "ligolo") -> dict:
    """
    Add a kernel route for <subnet> through the TUN interface.

    Called after the operator connects the ligolo-ng session and starts
    the tunnel in the ligolo-ng console (session → start).

    Args:
        subnet:    CIDR notation, e.g. '10.0.2.0/24'
        interface: TUN interface name (must match the one used at proxy start)
    """
    return _run(["ip", "route", "add", subnet, "dev", interface])


def del_route(subnet: str, interface: str = "ligolo") -> dict:
    """
    Remove the kernel route for <subnet> through the TUN interface.

    Args:
        subnet:    CIDR notation, e.g. '10.0.2.0/24'
        interface: TUN interface name
    """
    return _run(["ip", "route", "del", subnet, "dev", interface])
