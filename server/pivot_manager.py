import os
import shutil
import subprocess


_proxy_proc = None   # running ligolo-ng proxy subprocess, or None


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


# ── Proxy process management ──────────────────────────────────────────────────

def start_proxy(interface: str = "ligolo", port: int = 11601, proxy_bin: str = "./proxy") -> dict:
    """
    Ensure the TUN interface exists, then launch the ligolo-ng proxy as a
    background subprocess.  Safe to call when already running — returns
    already_running=True without spawning a second process.
    """
    global _proxy_proc
    if _proxy_proc and _proxy_proc.poll() is None:
        return {"ok": True, "already_running": True, "pid": _proxy_proc.pid, "port": port}

    if not os.path.isfile(proxy_bin):
        return {"ok": False, "error": f"proxy binary not found at '{proxy_bin}'"}
    if not os.access(proxy_bin, os.X_OK):
        return {"ok": False, "error": f"proxy binary not executable — run: chmod +x {proxy_bin}"}

    iface = ensure_interface(interface)
    if not iface["ok"]:
        return {"ok": False, "error": f"TUN interface: {iface['error']}"}

    proxy_cmd = [proxy_bin, "-selfcert", "-laddr", f"0.0.0.0:{port}"]

    # Pick the best available terminal so the operator can interact with the proxy console
    if os.environ.get("TMUX") and shutil.which("tmux"):
        cmd = ["tmux", "new-window", "-n", "ligolo-proxy"] + proxy_cmd
    elif shutil.which("xterm"):
        cmd = ["xterm", "-title", "ligolo-ng proxy", "-e"] + proxy_cmd
    else:
        # Headless fallback — operator must run proxy manually and type 'start'
        cmd = proxy_cmd

    try:
        _proxy_proc = subprocess.Popen(cmd)
        return {"ok": True, "already_running": False, "pid": _proxy_proc.pid,
                "port": port, "interface": interface}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def stop_proxy() -> dict:
    """Terminate the running proxy process."""
    global _proxy_proc
    if _proxy_proc is None or _proxy_proc.poll() is not None:
        _proxy_proc = None
        return {"ok": True, "was_running": False}
    _proxy_proc.terminate()
    try:
        _proxy_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _proxy_proc.kill()
    _proxy_proc = None
    return {"ok": True, "was_running": True}


def get_proxy_status() -> dict:
    """Return current proxy state."""
    global _proxy_proc
    if _proxy_proc is None:
        return {"running": False}
    if _proxy_proc.poll() is None:
        return {"running": True, "pid": _proxy_proc.pid}
    code = _proxy_proc.returncode
    _proxy_proc = None
    return {"running": False, "exit_code": code}
