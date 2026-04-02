import subprocess
from typing import Optional


# ── Internal helpers ──────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 30) -> dict:
    """Run an impacket CLI tool and return stdout, stderr, returncode."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "stdout":     result.stdout,
            "stderr":     result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Timed out after {timeout}s", "returncode": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"Tool not found: {cmd[0]}", "returncode": -1}


def _build_target(domain: str, username: str, secret: str,
                  target_ip: str, cred_type: str) -> tuple[str, list[str]]:
    """
    Return (target_string, extra_flags) for an impacket command.

    Plaintext  →  domain/user:pass@ip,  no extra flags
    NTLM hash  →  domain/user@ip,       [-hashes, :NTHASH]
    """
    if cred_type == "ntlm":
        return f"{domain}/{username}@{target_ip}", ["-hashes", f":{secret}"]
    return f"{domain}/{username}:{secret}@{target_ip}", []


def _format_output(result: dict) -> str:
    """Combine stdout + stderr into a single trimmed string."""
    out = result["stdout"]
    if result["stderr"].strip():
        out += f"\n[stderr] {result['stderr'].strip()}"
    return out.strip()


# ── Execution modules ─────────────────────────────────────────────────────────

def wmi_exec(target_ip: str, domain: str, username: str, secret: str,
             command: str, cred_type: str = "plaintext", timeout: int = 30) -> str:
    """
    Execute a command on a remote host via WMI (impacket-wmiexec).

    Works with plaintext passwords and NTLM pass-the-hash.
    WMI execution leaves less disk artefacts than SMB service-based methods.

    Args:
        target_ip:  IP of the remote target
        domain:     Windows domain or 'WORKGROUP'
        username:   Account to authenticate as
        secret:     Password (plaintext) or NT hash (ntlm)
        command:    Command to run on the remote host
        cred_type:  'plaintext' or 'ntlm'
        timeout:    Seconds before the call is aborted

    Returns:
        Command output as a string
    """
    target_str, extra_flags = _build_target(domain, username, secret, target_ip, cred_type)
    cmd = ["impacket-wmiexec"] + extra_flags + [target_str, command]
    return _format_output(_run(cmd, timeout))


def smb_exec(target_ip: str, domain: str, username: str, secret: str,
             command: str, cred_type: str = "plaintext", timeout: int = 30) -> str:
    """
    Execute a command on a remote host via SMB (impacket-smbexec).

    Creates a temporary Windows service to run the command and captures output
    via a named pipe. Requires SMB (445) to be reachable.

    Args:
        target_ip:  IP of the remote target
        domain:     Windows domain or 'WORKGROUP'
        username:   Account to authenticate as
        secret:     Password (plaintext) or NT hash (ntlm)
        command:    Command to run on the remote host
        cred_type:  'plaintext' or 'ntlm'
        timeout:    Seconds before the call is aborted

    Returns:
        Command output as a string
    """
    target_str, extra_flags = _build_target(domain, username, secret, target_ip, cred_type)
    cmd = ["impacket-smbexec"] + extra_flags + [target_str, command]
    return _format_output(_run(cmd, timeout))
