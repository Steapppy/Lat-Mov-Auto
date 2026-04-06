from neo4j import GraphDatabase
from neo4j.graph import Node, Relationship, Path

NEO4J_URI  = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "neo4j"


def _get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# ── Serialization ─────────────────────────────────────────────────────────────

def _serialize_path(path: Path) -> dict:
    nodes = list(path.nodes)
    rels  = list(path.relationships)
    steps = []
    for i, rel in enumerate(rels):
        steps.append({
            "from":      nodes[i].get("name", ""),
            "from_type": list(nodes[i].labels)[0] if nodes[i].labels else "Unknown",
            "rel":       rel.type,
            "to":        nodes[i + 1].get("name", ""),
            "to_type":   list(nodes[i + 1].labels)[0] if nodes[i + 1].labels else "Unknown",
        })
    return {"steps": steps, "length": len(rels)}


def _serialize_value(v):
    """Recursively convert Neo4j graph types to plain Python."""
    if isinstance(v, Path):
        return _serialize_path(v)
    if isinstance(v, Node):
        return {"labels": list(v.labels), **dict(v)}
    if isinstance(v, Relationship):
        return {"type": v.type, **dict(v)}
    if isinstance(v, list):
        return [_serialize_value(i) for i in v]
    if isinstance(v, dict):
        return {k: _serialize_value(val) for k, val in v.items()}
    return v


# ── Core query runner ─────────────────────────────────────────────────────────

def run_query(cypher: str, params: dict = None) -> list[dict]:
    """
    Execute any Cypher query and return results as a list of plain dicts.
    Path, Node, and Relationship values are automatically serialized.
    This is the primary entry point for the AI decision engine.
    """
    with _get_driver() as driver:
        with driver.session() as session:
            result = session.run(cypher, params or {})
            return [_serialize_value(dict(record)) for record in result]


# ── Connectivity ──────────────────────────────────────────────────────────────

def check_connection() -> dict:
    try:
        with _get_driver() as driver:
            driver.verify_connectivity()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Named helpers (common BloodHound patterns) ────────────────────────────────

def get_da_paths(username: str, domain: str) -> list[dict]:
    """All shortest paths from a node to the Domain Admins group."""
    cypher = """
        MATCH (u {name: $username}), (g:Group)
        WHERE g.name =~ ('(?i)domain admins@' + $domain)
        MATCH p = allShortestPaths((u)-[*1..15]->(g))
        RETURN p
    """
    results = run_query(cypher, {"username": username, "domain": domain})
    return [r["p"] for r in results]


def get_admin_targets(username: str) -> list[dict]:
    """Computers where username has direct AdminTo rights."""
    cypher = """
        MATCH (u {name: $username})-[:AdminTo]->(c:Computer)
        RETURN c.name AS computer, c.operatingsystem AS os, c.enabled AS enabled
    """
    return run_query(cypher, {"username": username})


def get_sessions(computer: str) -> list[dict]:
    """Users with active sessions on a computer."""
    cypher = """
        MATCH (u:User)-[:HasSession]->(c:Computer {name: $computer})
        RETURN u.name AS user, u.enabled AS enabled, u.admincount AS is_admin
    """
    return run_query(cypher, {"computer": computer})


def get_kerberoastable(domain: str) -> list[dict]:
    """Kerberoastable accounts (hasspn=true) in the domain, admins first."""
    cypher = """
        MATCH (u:User {hasspn: true})
        WHERE u.domain = $domain
        RETURN u.name AS user, u.serviceprincipalnames AS spns,
               u.admincount AS is_admin, u.enabled AS enabled
        ORDER BY u.admincount DESC
    """
    return run_query(cypher, {"domain": domain.upper()})


def get_asreproastable(domain: str) -> list[dict]:
    """AS-REP Roastable accounts (dontreqpreauth=true) in the domain."""
    cypher = """
        MATCH (u:User {dontreqpreauth: true})
        WHERE u.domain = $domain
        RETURN u.name AS user, u.admincount AS is_admin, u.enabled AS enabled
    """
    return run_query(cypher, {"domain": domain.upper()})


def sync_all() -> dict:
    """
    Dump every node and every relationship from Neo4j as plain Python dicts.
    Called by POST /bloodhound/sync — results are stored in bh_nodes / bh_edges.
    """
    nodes_cypher = """
        MATCH (n)
        WHERE n.name IS NOT NULL
        RETURN labels(n)[0] AS node_type, n.name AS name, properties(n) AS props
    """
    edges_cypher = """
        MATCH (a)-[r]->(b)
        WHERE a.name IS NOT NULL AND b.name IS NOT NULL
        RETURN a.name        AS source_name,
               labels(a)[0]  AS source_type,
               type(r)        AS rel_type,
               b.name        AS target_name,
               labels(b)[0]  AS target_type,
               properties(r) AS rel_props
    """
    nodes = run_query(nodes_cypher)
    edges = run_query(edges_cypher)
    return {"nodes": nodes, "edges": edges}


def get_owned_paths(owned_nodes: list[str], domain: str) -> list[dict]:
    """
    All shortest paths from any owned/compromised node to Domain Admins.
    Pass a list of node names (users or computers already compromised).
    """
    cypher = """
        UNWIND $owned AS owned_name
        MATCH (u {name: owned_name}), (g:Group)
        WHERE g.name =~ ('(?i)domain admins@' + $domain)
        MATCH p = allShortestPaths((u)-[*1..15]->(g))
        RETURN owned_name AS source, p
    """
    results = run_query(cypher, {"owned": owned_nodes, "domain": domain})
    return [{"source": r["source"], **r["p"]} for r in results]
