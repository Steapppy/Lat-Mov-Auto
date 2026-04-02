import subprocess
from typing import Optional

# Module-level process handle — survives the lifetime of the FastAPI process.
# If the server restarts, the operator must call /pivot/proxy/start again.
_proxy_proc: Optional[subprocess.Popen] = None


# ── Internal helpers ──────────────────────────────────────────────────────────

def _run(cmd: list[str]) -> dict:
    """Run a system command and return ok, returncode, error."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "ok":         result.returncode == 0,
        "returncode": result.returncode,
        "error":      result.stderr.strip(),
    }


# ── Proxy process management ──────────────────────────────────────────────────

def start_proxy(interface: str = "ligolo", listen_port: int = 11601,
                proxy_bin: str = "ligolo-ng-proxy") -> dict:
    """
    Create the TUN interface and start the ligolo-ng proxy.

    The proxy listens for incoming agent connections on 0.0.0.0:<listen_port>.
    A self-signed certificate is used (-selfcert) so no PKI setup is required.

    Args:
        interface:  Name of the TUN interface to create (default: 'ligolo')
        listen_port: Port the proxy listens on (default: 11601)
        proxy_bin:  Path or name of the ligolo-ng proxy binary

    Returns:
        dict with status, pid, port, interface
    """
    global _proxy_proc

    if _proxy_proc and _proxy_proc.poll() is None:
        return {"status": "already_running", "pid": _proxy_proc.pid,
                "port": listen_port, "interface": interface}

    # Create TUN interface (silently ignore if it already exists)
    _run(["ip", "tuntap", "add", "user", "root", "mode", "tun", interface])
    _run(["ip", "link", "set", interface, "up"])

    _proxy_proc = subprocess.Popen(
        [proxy_bin, "-selfcert", "-laddr", f"0.0.0.0:{listen_port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return {"status": "started", "pid": _proxy_proc.pid,
            "port": listen_port, "interface": interface}


def stop_proxy(interface: str = "ligolo") -> dict:
    """
    Terminate the ligolo-ng proxy and remove the TUN interface.

    Args:
        interface: Name of the TUN interface to remove

    Returns:
        dict with status
    """
    global _proxy_proc

    if _proxy_proc and _proxy_proc.poll() is None:
        _proxy_proc.terminate()
        try:
            _proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _proxy_proc.kill()
    _proxy_proc = None

    _run(["ip", "link", "del", interface])
    return {"status": "stopped"}


def proxy_status() -> dict:
    """Return whether the proxy process is currently running."""
    if _proxy_proc and _proxy_proc.poll() is None:
        return {"running": True, "pid": _proxy_proc.pid}
    return {"running": False, "pid": None}


# ── Route management ──────────────────────────────────────────────────────────

def add_route(subnet: str, interface: str = "ligolo") -> dict:
    """
    Add a kernel route for <subnet> through the TUN interface.

    Called after the operator connects the ligolo-ng session and starts
    the tunnel in the ligolo-ng console.

    Args:
        subnet:    CIDR notation, e.g. '10.0.2.0/24'
        interface: TUN interface name (must match the one used at proxy start)

    Returns:
        dict with ok, error
    """
    return _run(["ip", "route", "add", subnet, "dev", interface])


def del_route(subnet: str, interface: str = "ligolo") -> dict:
    """
    Remove the kernel route for <subnet> through the TUN interface.

    Args:
        subnet:    CIDR notation, e.g. '10.0.2.0/24'
        interface: TUN interface name

    Returns:
        dict with ok, error
    """
    return _run(["ip", "route", "del", subnet, "dev", interface])
