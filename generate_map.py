#!/usr/bin/env python3
"""
generate_map.py — Auto-generate network_map.html from recon + SharpHound [+ certipy]

Usage:
  python generate_map.py --recon recon.json --sharphound loot.zip [-c certipy.json] [-o network_map.html]
"""

import argparse, json, zipfile, re, html as _html_mod
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# INPUT PARSERS
# ─────────────────────────────────────────────────────────────────────────────

def load_recon(path):
    with open(path) as f:
        data = json.load(f)
    hosts = data.get('hosts', data) if isinstance(data, dict) else data
    target = data.get('target', '') if isinstance(data, dict) else ''
    return hosts, target


def load_sharphound(zip_path):
    result = {}
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            lname = name.lower()
            for kind in ('computers', 'users', 'groups', 'domains', 'ous', 'containers', 'gpos'):
                if kind in lname and lname.endswith('.json'):
                    with zf.open(name) as f:
                        raw = json.load(f)
                    items = raw.get('data', raw) if isinstance(raw, dict) else raw
                    if isinstance(items, list):
                        result.setdefault(kind, []).extend(items)
                    break
    return result


def load_certipy(path):
    if not path:
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f'[!] Could not load certipy file: {e}')
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# OBJECT INDEXER
# ─────────────────────────────────────────────────────────────────────────────

def index_objects(sh):
    """SID.upper() → {name, full_name, type, props, aces, raw}"""
    sid_map = {}
    type_for = {'computers': 'computer', 'users': 'user', 'groups': 'group', 'domains': 'domain'}

    for kind, items in sh.items():
        base_type = type_for.get(kind, kind.rstrip('s'))
        for obj in items:
            props = obj.get('Properties', obj)
            sid = (obj.get('ObjectIdentifier') or props.get('objectsid') or props.get('objectid') or '').upper()
            full_name = (props.get('name') or props.get('Name') or '').upper()
            short = full_name.split('@')[0].split('.')[0]
            if not sid or not short:
                continue
            sid_map[sid] = {
                'name': short,
                'full_name': full_name,
                'type': base_type,
                'props': props,
                'aces': obj.get('Aces', []),
                'raw': obj,
            }

    for sid, obj in sid_map.items():
        props = obj['props']
        if obj['type'] == 'computer':
            dn = props.get('distinguishedname', '').upper()
            if 'OU=DOMAIN CONTROLLERS' in dn or props.get('isdc'):
                obj['type'] = 'dc'
        elif obj['type'] == 'user':
            if not props.get('enabled', True):
                obj['type'] = 'user_disabled'
            elif props.get('admincount', False):
                obj['type'] = 'user_da'

    return sid_map


# ─────────────────────────────────────────────────────────────────────────────
# GRAPH BUILDER
# ─────────────────────────────────────────────────────────────────────────────

_ACL_RIGHTS = {'GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl',
               'ForceChangePassword', 'AllExtendedRights', 'AddMember', 'Owns'}

# Groups always shown (attack-relevant)
_WHITELIST_GROUPS = frozenset([
    'DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS',
    'ACCOUNT OPERATORS', 'ADMINISTRATORS', 'BACKUP OPERATORS',
    'SERVER OPERATORS', 'DNSADMINS', 'PRINT OPERATORS',
])

# Default Windows noise — never shown
_SKIP_GROUPS = frozenset([
    'DOMAIN USERS', 'DOMAIN COMPUTERS', 'DOMAIN GUESTS', 'DOMAIN CONTROLLERS',
    'GUESTS', 'USERS', 'EVERYONE', 'AUTHENTICATED USERS', 'INTERACTIVE', 'NETWORK',
    'REMOTE INTERACTIVE LOGON', 'ENTERPRISE DOMAIN CONTROLLERS',
    'READ-ONLY DOMAIN CONTROLLERS', 'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS',
    'CLONEABLE DOMAIN CONTROLLERS', 'GROUP POLICY CREATOR OWNERS', 'PROTECTED USERS',
    'CERT PUBLISHERS', 'RAS AND IAS SERVERS', 'ALLOWED RODC PASSWORD REPLICATION GROUP',
    'DENIED RODC PASSWORD REPLICATION GROUP', 'RDS REMOTE ACCESS SERVERS',
    'RDS ENDPOINT SERVERS', 'RDS MANAGEMENT SERVERS', 'EVENT LOG READERS',
    'DISTRIBUTED COM USERS', 'PERFORMANCE MONITOR USERS', 'PERFORMANCE LOG USERS',
    'REMOTE DESKTOP USERS', 'REMOTE MANAGEMENT USERS', 'NETWORK CONFIGURATION OPERATORS',
    'CRYPTOGRAPHIC OPERATORS', 'CERTIFICATE SERVICE DCOM ACCESS', 'REPLICATORS',
    'WINDOWS AUTHORIZATION ACCESS GROUP', 'PRE-WINDOWS 2000 COMPATIBLE ACCESS',
    'TERMINAL SERVER LICENSE SERVERS', 'INCOMING FOREST TRUST BUILDERS',
    'HYPER-V ADMINISTRATORS', 'ACCESS CONTROL ASSISTANCE OPERATORS', 'IIS_IUSRS',
    'KEY ADMINS', 'ENTERPRISE KEY ADMINS', 'STORAGE REPLICA ADMINISTRATORS',
    'DNSUPDATEPROXY',
])

# Groups whose LocalAdmin edges are obvious/default — skip those edges
_IMPLICIT_ADMIN_GROUPS = frozenset(['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS', 'ADMINISTRATORS'])


def _recon_hostnames(recon_hosts):
    """Return set of short hostnames that have at least one open port."""
    return {h['hostname'].split('.')[0].upper()
            for h in recon_hosts
            if h.get('hostname') and h.get('ports')}


def build_nodes(sid_map, recon_hosts, certipy_data):
    scanned = _recon_hostnames(recon_hosts)
    nodes = []

    for sid, obj in sid_map.items():
        t = obj['type']
        if t in ('ou', 'container', 'gpo'):
            continue

        props = obj['props']
        name = obj['name']

        # ── Filter: computers only if in recon scan ──
        if t in ('computer', 'workstation', 'dc'):
            if name not in scanned:
                continue

        # ── Filter: groups — whitelist only, skip noise ──
        if t == 'group':
            if name in _SKIP_GROUPS:
                continue
            if name not in _WHITELIST_GROUPS:
                # Keep non-whitelisted group only if it has LocalAdmin on a scanned computer
                # (detected later via edges — skip here, add in post-pass if needed)
                continue

        spns = props.get('serviceprincipalnames', [])
        flags = []
        if spns and t in ('user', 'user_da'):
            flags.append('kerb')
        if t == 'user_da':
            flags.append('da')
        if t == 'user_disabled':
            flags.append('disabled')
        if props.get('unconstraineddelegation'):
            flags.append('unconstrained')
        for ace in obj['aces']:
            if ace.get('RightName') == 'GenericAll' and not ace.get('IsInherited', False):
                flags.append('critical')
                break

        info = {'Type': _type_label(t)}
        if t in ('dc', 'computer', 'workstation'):
            info['IP'] = _find_ip(name, recon_hosts)
            info['OS'] = props.get('operatingsystem', 'Unknown')
            info['FQDN'] = obj['full_name']
        elif t in ('user', 'user_da', 'user_disabled'):
            info['SAM'] = props.get('samaccountname', name)
            info['Enabled'] = 'Yes' if props.get('enabled', True) else 'No'
            info['Admin Count'] = 'Yes' if props.get('admincount', False) else 'No'
            if spns:
                info['SPNs'] = ', '.join(spns[:3])
        elif t == 'group':
            members = [sid_map[m['ObjectIdentifier'].upper()]['name']
                       for m in obj['raw'].get('Members', [])
                       if m.get('ObjectIdentifier', '').upper() in sid_map]
            info['Members'] = ', '.join(members[:6]) if members else '(none)'
        elif t == 'domain':
            info['Functional Level'] = props.get('functionallevel', 'Unknown')
            info['SID'] = sid

        nodes.append({
            'id': safe_id(name),
            'label': name,
            'type': t,
            'info': info,
            'flags': list(set(flags)),
            '_sid': sid,
        })

    # CA nodes from certipy
    for _, ca in (certipy_data.get('Certificate Authorities') or {}).items():
        ca_name = ca.get('CA Name', 'Unknown-CA')
        vulns = list((ca.get('[!] Vulnerabilities') or {}).keys())
        nodes.append({
            'id': safe_id(ca_name),
            'label': ca_name,
            'type': 'ca',
            'info': {'Type': 'Certificate Authority', 'DNS': ca.get('DNS Name', ''),
                     'Web Enrollment': ca.get('Web Enrollment', 'N/A'),
                     'Vulnerabilities': ', '.join(vulns) if vulns else 'None'},
            'flags': ['vuln'] if vulns else [],
        })

    # Vulnerable template nodes from certipy
    for _, tpl in (certipy_data.get('Certificate Templates') or {}).items():
        vulns = list((tpl.get('[!] Vulnerabilities') or {}).keys())
        if not vulns:
            continue
        tpl_name = tpl.get('Template Name', 'Unknown-Template')
        nodes.append({
            'id': safe_id(tpl_name),
            'label': f'{tpl_name}\n({",".join(vulns)})',
            'type': 'cert_template',
            'info': {'Type': 'Certificate Template', 'Vulnerabilities': ', '.join(vulns),
                     'Client Auth': str(tpl.get('Client Authentication', False)),
                     'Enrollee Supplies Subject': str(tpl.get('Enrollee Supplies Subject', False))},
            'flags': ['vuln'],
        })

    return nodes


def build_edges(sid_map, nodes):
    """Build vis edge list. nodes is the output of build_nodes()."""
    sid_to_vis = {n['_sid']: n['id'] for n in nodes if '_sid' in n}
    vis_ids = {n['id'] for n in nodes}

    # Reverse map: vis_id → name (for skip logic)
    vis_to_name = {n['id']: n['label'] for n in nodes}

    edges = []
    seen = set()
    counter = [1]

    def add(from_id, to_id, group, label, acl_type=None, critical=False):
        if not from_id or from_id not in vis_ids or to_id not in vis_ids:
            return
        if from_id == to_id:
            return
        key = (from_id, to_id, label)
        if key in seen:
            return
        seen.add(key)
        e = {'id': counter[0], 'from': from_id, 'to': to_id, 'group': group, 'label': label}
        if acl_type:
            e['aclType'] = acl_type
        if critical:
            e['critical'] = True
        edges.append(e)
        counter[0] += 1

    for sid, obj in sid_map.items():
        if obj['type'] in ('ou', 'container', 'gpo', 'domain'):
            continue
        obj_vis = sid_to_vis.get(sid)
        if not obj_vis:
            continue

        # MemberOf: group.Members → from member to group
        if obj['type'] == 'group':
            for m in obj['raw'].get('Members', []):
                m_sid = m.get('ObjectIdentifier', '').upper()
                add(sid_to_vis.get(m_sid, ''), obj_vis, 'memberof', 'MemberOf')

        # LocalAdmin: computer.LocalAdmins.Results → from admin to computer
        # Skip DA/EA/Administrators group → computers (implicit, obvious)
        if obj['type'] in ('dc', 'computer', 'workstation'):
            container = obj['raw'].get('LocalAdmins', {})
            results = container.get('Results', []) if isinstance(container, dict) else container
            for r in results:
                r_sid = (r.get('ObjectIdentifier') or r.get('PrincipalSID') or '').upper()
                r_vis = sid_to_vis.get(r_sid, '')
                r_name = vis_to_name.get(r_vis, '')
                if r_name in _IMPLICIT_ADMIN_GROUPS:
                    continue  # skip obvious DA/EA → computer edges
                add(r_vis, obj_vis, 'localadmin', 'LocalAdmin')

        # ACLs: object.Aces → from principal to this object
        # Skip ACEs where the principal is DA/EA/Administrators — they have rights on everything by default
        for ace in obj['aces']:
            right = ace.get('RightName', '')
            if right not in _ACL_RIGHTS or ace.get('IsInherited', False):
                continue
            p_sid = ace.get('PrincipalSID', '').upper()
            p_vis = sid_to_vis.get(p_sid)
            if not p_vis:
                continue
            if vis_to_name.get(p_vis, '') in _IMPLICIT_ADMIN_GROUPS:
                continue
            is_critical = right == 'GenericAll' and obj['type'] in ('user_da', 'group')
            add(p_vis, obj_vis, 'acl', right, acl_type=right, critical=is_critical)

        # SPN Kerberoastable: user SPN → target host
        if obj['type'] in ('user', 'user_da'):
            for spn in obj['props'].get('serviceprincipalnames', []):
                if '/' in spn:
                    host = spn.split('/')[1].split('.')[0].upper()
                    add(obj_vis, safe_id(host), 'spn', 'HasSPN')

    # Certipy: template → CA
    for _, tpl in ({}).items():  # placeholder, extend if certipy nodes present
        pass

    return edges


def compute_stats(sid_map, recon_hosts, edges):
    hosts = sum(1 for h in recon_hosts if h.get('ports'))
    users = sum(1 for obj in sid_map.values()
                if obj['type'] in ('user', 'user_da', 'user_disabled'))
    kerb = sum(1 for obj in sid_map.values()
               if obj['props'].get('serviceprincipalnames') and obj['type'] in ('user', 'user_da'))
    critical = sum(1 for e in edges if e.get('critical'))
    return {'hosts': hosts, 'users': users, 'kerberoastable': kerb, 'critical_acl': critical}


def find_attack_path(sid_map, nodes, edges):
    """Return (banner_text, [vis_node_ids]) for the best critical ACL path."""
    critical = [e for e in edges if e.get('critical')]
    if not critical:
        return None, []

    id_to_name = {n['id']: n['label'] for n in nodes}

    e = critical[0]
    attacker = id_to_name.get(e['from'], e['from'])
    target = id_to_name.get(e['to'], e['to'])

    # Find an entry computer where attacker is local admin
    attacker_sid = next((obj['_sid'] if '_sid' in obj else None
                         for obj in [n for n in nodes if n['id'] == e['from']]), None)
    entry = None
    if attacker_sid:
        for obj in sid_map.values():
            if obj['type'] not in ('dc', 'computer', 'workstation'):
                continue
            results = obj['raw'].get('LocalAdmins', {}).get('Results', [])
            for r in results:
                if r.get('ObjectIdentifier', '').upper() == attacker_sid:
                    entry = obj['name']
                    break
            if entry:
                break

    dc = next((obj['name'] for obj in sid_map.values() if obj['type'] == 'dc'), None)

    path_names = list(filter(None, [entry, attacker, target, dc]))
    path_ids = [safe_id(n) for n in path_names]
    banner = ' → '.join(path_names) + f' ({e["label"]}) → DA → DCSync → Full Compromise'
    return banner, path_ids


# ─────────────────────────────────────────────────────────────────────────────
# RECON TABLE
# ─────────────────────────────────────────────────────────────────────────────

_HIGHLIGHT_PORTS = {5985, 5986, 443, 8443, 3389}


def render_recon_table(recon_hosts, sid_map):
    rows = []
    for h in sorted(recon_hosts, key=lambda x: [int(p) for p in x.get('ip', '0.0.0.0').split('.')]):
        ip = h.get('ip', '')
        hostname = h.get('hostname', '')
        ports = h.get('ports', [])
        if not ports:
            continue

        short = hostname.split('.')[0].upper() if hostname else ''
        obj = next((o for o in sid_map.values() if o['name'] == short), None)

        role_html = _role_html(obj)
        os_html = _os_html(obj)

        chips = ''.join(
            f'<span class="port-chip{" highlight" if p["port"] in _HIGHLIGHT_PORTS else ""}">{p["port"]}</span>'
            for p in ports
        )
        svcs = ', '.join(dict.fromkeys(
            p.get('service', str(p['port'])) for p in ports
        ))
        extra = ''
        if obj and obj['props'].get('unconstraineddelegation'):
            extra = ' · <strong style="color:var(--accent-purple)">Unconstrained Delegation</strong>'
        if not hostname:
            hn_html = '<span style="color:var(--text-muted);font-style:italic">(unknown)</span>'
        else:
            hn_html = _he(hostname)

        rows.append(
            f'      <tr>\n'
            f'        <td class="td-ip">{ip}</td>\n'
            f'        <td class="td-host">{hn_html}</td>\n'
            f'        <td>{role_html}</td>\n'
            f'        <td>{os_html}</td>\n'
            f'        <td>{chips}</td>\n'
            f'        <td>{_he(svcs)}{extra}</td>\n'
            f'      </tr>'
        )
    return '\n'.join(rows)


def _role_html(obj):
    if not obj:
        return '<span style="color:var(--text-muted)">—</span>'
    if obj['type'] == 'dc':
        return '<span class="role-dc">Domain Controller</span>'
    return '<span class="role-ws">Workstation</span>'


def _os_html(obj):
    if not obj:
        return '<span class="os-icon">❓</span> Unknown'
    os = obj['props'].get('operatingsystem', '')
    if 'server' in os.lower():
        return f'<span class="os-icon">🖥️</span> {_he(os)}'
    elif 'windows' in os.lower():
        return f'<span class="os-icon">💻</span> {_he(os)}'
    return f'<span class="os-icon">❓</span> {_he(os) or "Unknown"}'


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def safe_id(name):
    return re.sub(r'[^a-zA-Z0-9_]', '_', name.lower().strip())


def _type_label(t):
    return {
        'dc': 'Domain Controller', 'workstation': 'Workstation', 'computer': 'Computer',
        'user': 'Domain User', 'user_da': 'Domain Admin', 'user_disabled': 'Disabled Account',
        'group': 'Security Group', 'domain': 'AD Domain',
        'ca': 'Certificate Authority', 'cert_template': 'Certificate Template',
    }.get(t, t.title())


def _find_ip(name, recon_hosts):
    for h in recon_hosts:
        hn = h.get('hostname', '').split('.')[0].upper()
        if hn == name.upper():
            return h.get('ip', 'N/A')
    return 'N/A'


def _he(s):
    return _html_mod.escape(str(s))


# ─────────────────────────────────────────────────────────────────────────────
# HTML RENDERER
# ─────────────────────────────────────────────────────────────────────────────

def render_html(nodes, edges, stats, recon_hosts, sid_map, domain_name, domain_sid,
                subnet, scan_date, attack_banner, attack_path_ids, certipy_data):

    node_data_js = {}
    for n in nodes:
        node_data_js[n['id']] = {
            'id': n['id'],
            'label': n['label'],
            'type': n['type'],
            'info': n['info'],
            'flags': n['flags'],
        }

    edge_defs_js = []
    for e in edges:
        ed = {'from': e['from'], 'to': e['to'], 'group': e['group'], 'label': e['label']}
        if e.get('aclType'):
            ed['aclType'] = e['aclType']
        if e.get('critical'):
            ed['critical'] = True
        edge_defs_js.append(ed)

    # Certipy section (only rendered if data present)
    vuln_templates = []
    for _, tpl in (certipy_data.get('Certificate Templates') or {}).items():
        vulns = list((tpl.get('[!] Vulnerabilities') or {}).keys())
        if vulns:
            vuln_templates.append({'name': tpl.get('Template Name', '?'), 'vulns': vulns,
                                   'client_auth': tpl.get('Client Authentication', False),
                                   'esc': ', '.join(vulns)})
    certipy_section = _render_certipy_section(certipy_data, vuln_templates) if certipy_data else ''

    recon_rows = render_recon_table(recon_hosts, sid_map)
    functional_level = next((obj['props'].get('functionallevel', '')
                              for obj in sid_map.values() if obj['type'] == 'domain'), '')

    return _HTML_TEMPLATE \
        .replace('%%DOMAIN%%', _he(domain_name)) \
        .replace('%%FUNCTIONAL_LEVEL%%', _he(functional_level)) \
        .replace('%%SCAN_DATE%%', _he(scan_date)) \
        .replace('%%DOMAIN_SID%%', _he(domain_sid)) \
        .replace('%%SUBNET%%', _he(subnet)) \
        .replace('%%STAT_HOSTS%%', str(stats['hosts'])) \
        .replace('%%STAT_USERS%%', str(stats['users'])) \
        .replace('%%STAT_KERB%%', str(stats['kerberoastable'])) \
        .replace('%%STAT_CRITICAL%%', str(stats['critical_acl'])) \
        .replace('%%ATTACK_BANNER%%', _he(attack_banner or 'No critical ACL path detected')) \
        .replace('%%WATERMARK%%', _he(f'{domain_name} · {subnet} · vis-network 9.1.9')) \
        .replace('%%RECON_ROWS%%', recon_rows) \
        .replace('%%CERTIPY_SECTION%%', certipy_section) \
        .replace('%%NODEDATA_JSON%%', json.dumps(node_data_js, indent=2)) \
        .replace('%%EDGEDEFS_JSON%%', json.dumps(edge_defs_js, indent=2)) \
        .replace('%%ATTACK_PATH_IDS%%', json.dumps(attack_path_ids))


def _render_certipy_section(certipy_data, vuln_templates):
    if not vuln_templates:
        return ''
    rows = ''
    for t in vuln_templates:
        rows += (
            f'      <tr>\n'
            f'        <td class="td-host">{_he(t["name"])}</td>\n'
            f'        <td><span style="color:var(--accent-red);font-weight:700">{_he(t["esc"])}</span></td>\n'
            f'        <td>{"Yes" if t["client_auth"] else "No"}</td>\n'
            f'      </tr>\n'
        )
    cas = ''
    for _, ca in (certipy_data.get('Certificate Authorities') or {}).items():
        name = ca.get('CA Name', '?')
        dns = ca.get('DNS Name', '?')
        web = ca.get('Web Enrollment', 'N/A')
        vulns = ', '.join((ca.get('[!] Vulnerabilities') or {}).keys()) or '—'
        cas += (f'<span style="color:var(--text-secondary)"><strong style="color:var(--accent-purple)">{_he(name)}</strong>'
                f' ({_he(dns)}) — Web: {_he(web)} — Vulns: <span style="color:var(--accent-red)">{_he(vulns)}</span></span><br>')

    return f'''
<!-- ═══════════════════════ CERTIPY SECTION ═══════════════════════ -->
<div class="table-section">
  <div class="section-header">
    <div>
      <div class="section-title">PKI / ADCS Analysis <span style="font-size:12px;color:var(--accent-red);font-weight:400">(certipy)</span></div>
      <div class="section-sub">{cas}</div>
    </div>
  </div>
  <table>
    <thead><tr><th>Template</th><th>Vulnerabilities</th><th>Client Auth</th></tr></thead>
    <tbody>
{rows}    </tbody>
  </table>
</div>'''


# ─────────────────────────────────────────────────────────────────────────────
# HTML TEMPLATE
# ─────────────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%%DOMAIN%% — Network Intelligence Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  :root {
    --bg-primary: #0d1117; --bg-secondary: #161b22; --bg-tertiary: #21262d;
    --border: #30363d; --accent-red: #e94560; --accent-blue: #58a6ff;
    --accent-orange: #f0883e; --accent-green: #3fb950;
    --accent-purple: #bc8cff; --accent-yellow: #d29922;
    --text-primary: #e6edf3; --text-secondary: #8b949e; --text-muted: #484f58;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; }
  .header { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 18px 32px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; }
  .header-left { display: flex; align-items: center; gap: 16px; }
  .header-logo { width: 40px; height: 40px; background: linear-gradient(135deg, var(--accent-red), #b52040); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 20px; font-weight: 800; color: #fff; letter-spacing: -1px; }
  .header-title h1 { font-size: 18px; font-weight: 700; letter-spacing: 0.3px; }
  .header-title p { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }
  .header-meta { display: flex; align-items: center; gap: 20px; }
  .meta-chip { background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 4px 12px; font-size: 11px; color: var(--text-secondary); font-family: 'Courier New', monospace; }
  .meta-chip span { color: var(--accent-blue); }
  .badge-live { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--accent-green); font-weight: 600; }
  .badge-live::before { content: ''; width: 7px; height: 7px; background: var(--accent-green); border-radius: 50%; box-shadow: 0 0 6px var(--accent-green); animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
  .stats-bar { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--border); border-bottom: 1px solid var(--border); }
  .stat-card { background: var(--bg-secondary); padding: 16px 24px; display: flex; align-items: center; gap: 14px; }
  .stat-icon { width: 38px; height: 38px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0; }
  .stat-icon.hosts { background: rgba(88,166,255,.15); } .stat-icon.users { background: rgba(63,185,80,.15); }
  .stat-icon.kerb { background: rgba(210,153,34,.15); } .stat-icon.critical { background: rgba(233,69,96,.15); }
  .stat-value { font-size: 26px; font-weight: 700; line-height: 1; }
  .stat-card.hosts .stat-value { color: var(--accent-blue); } .stat-card.users .stat-value { color: var(--accent-green); }
  .stat-card.kerb .stat-value { color: var(--accent-yellow); } .stat-card.critical .stat-value { color: var(--accent-red); }
  .stat-label { font-size: 12px; color: var(--text-secondary); margin-top: 3px; }
  .controls-bar { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 10px 24px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .controls-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; margin-right: 4px; }
  .toggle-btn { display: flex; align-items: center; gap: 6px; padding: 5px 12px; border-radius: 5px; border: 1px solid var(--border); background: var(--bg-tertiary); color: var(--text-secondary); font-size: 12px; cursor: pointer; transition: all 0.18s; }
  .toggle-btn .dot { width: 8px; height: 8px; border-radius: 50%; }
  .toggle-btn.active { border-color: currentColor; }
  .toggle-btn.active[data-group="memberof"] { color: #8b949e; background: rgba(139,148,158,.1); }
  .toggle-btn.active[data-group="localadmin"] { color: var(--accent-orange); background: rgba(240,136,62,.1); }
  .toggle-btn.active[data-group="acl"] { color: var(--accent-red); background: rgba(233,69,96,.1); }
  .toggle-btn.active[data-group="spn"] { color: var(--accent-yellow); background: rgba(210,153,34,.1); }
  .toggle-btn.active[data-group="cert"] { color: var(--accent-purple); background: rgba(188,140,255,.1); }
  .sep { width: 1px; height: 22px; background: var(--border); margin: 0 4px; }
  .action-btn { padding: 5px 14px; border-radius: 5px; border: 1px solid; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.18s; }
  .btn-attack { border-color: var(--accent-red); background: rgba(233,69,96,.12); color: var(--accent-red); }
  .btn-attack:hover { background: rgba(233,69,96,.25); }
  .btn-reset { border-color: var(--border); background: var(--bg-tertiary); color: var(--text-secondary); }
  .btn-reset:hover { background: var(--border); color: var(--text-primary); }
  .btn-physics { border-color: var(--accent-blue); background: rgba(88,166,255,.08); color: var(--accent-blue); }
  .btn-physics:hover { background: rgba(88,166,255,.2); }
  .main-layout { display: grid; grid-template-columns: 1fr 280px; height: calc(100vh - 160px); min-height: 520px; }
  .graph-wrapper { position: relative; border-right: 1px solid var(--border); height: 100%; min-height: 520px; }
  #network-graph { width: 100%; height: 100%; min-height: 520px; background: var(--bg-primary); }
  .graph-watermark { position: absolute; bottom: 14px; left: 18px; font-size: 10px; color: var(--text-muted); pointer-events: none; font-family: 'Courier New', monospace; }
  .attack-path-banner { display: none; position: absolute; top: 12px; left: 50%; transform: translateX(-50%); background: rgba(233,69,96,.18); border: 1px solid var(--accent-red); border-radius: 6px; padding: 6px 18px; font-size: 12px; color: var(--accent-red); font-weight: 600; z-index: 10; animation: fadein 0.3s ease; }
  @keyframes fadein { from { opacity: 0; transform: translateX(-50%) translateY(-6px); } to { opacity: 1; transform: translateX(-50%) translateY(0); } }
  .sidebar { display: flex; flex-direction: column; overflow-y: auto; background: var(--bg-secondary); }
  .panel { border-bottom: 1px solid var(--border); padding: 16px; }
  .panel-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-muted); margin-bottom: 12px; font-weight: 600; }
  .legend-section { margin-bottom: 12px; }
  .legend-section-title { font-size: 10px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--text-muted); margin-bottom: 6px; }
  .legend-item { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-secondary); margin-bottom: 5px; }
  .legend-node { width: 14px; height: 14px; border-radius: 2px; flex-shrink: 0; }
  .legend-node.circle { border-radius: 50%; }
  .legend-edge { width: 28px; height: 2px; flex-shrink: 0; border-radius: 1px; }
  .legend-edge.dashed { background: none !important; border-top: 2px dashed; }
  .node-detail { flex: 1; padding: 16px; }
  .node-detail .panel-title { margin-bottom: 14px; }
  .detail-placeholder { text-align: center; padding: 32px 12px; color: var(--text-muted); font-size: 12px; }
  .detail-placeholder .ph-icon { font-size: 32px; margin-bottom: 8px; opacity: 0.4; }
  #detail-content { display: none; }
  .detail-header { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 14px; }
  .detail-icon-wrap { width: 36px; height: 36px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0; }
  .detail-name { font-size: 15px; font-weight: 700; word-break: break-all; }
  .detail-type { font-size: 11px; color: var(--text-secondary); margin-top: 2px; }
  .detail-row { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--border); padding: 7px 0; font-size: 12px; gap: 8px; }
  .detail-row:last-child { border-bottom: none; }
  .detail-key { color: var(--text-muted); flex-shrink: 0; }
  .detail-val { color: var(--text-primary); text-align: right; word-break: break-all; }
  .flag-badges { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 12px; }
  .flag-badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .flag-da       { background: rgba(233,69,96,.2); color: var(--accent-red); border: 1px solid rgba(233,69,96,.4); }
  .flag-kerb     { background: rgba(210,153,34,.2); color: #e3ad3b; border: 1px solid rgba(210,153,34,.4); }
  .flag-disabled { background: rgba(139,148,158,.15); color: var(--text-secondary); border: 1px solid var(--border); }
  .flag-local    { background: rgba(240,136,62,.2); color: var(--accent-orange); border: 1px solid rgba(240,136,62,.4); }
  .flag-unconstrained { background: rgba(188,140,255,.2); color: var(--accent-purple); border: 1px solid rgba(188,140,255,.4); }
  .flag-critical { background: rgba(233,69,96,.3); color: #ff6b85; border: 1px solid rgba(233,69,96,.6); animation: glow 2s infinite; }
  .flag-vuln     { background: rgba(188,140,255,.2); color: var(--accent-purple); border: 1px solid rgba(188,140,255,.4); }
  @keyframes glow { 0%,100% { box-shadow: 0 0 4px rgba(233,69,96,.4); } 50% { box-shadow: 0 0 10px rgba(233,69,96,.7); } }
  .table-section { padding: 24px 32px; background: var(--bg-primary); border-top: 1px solid var(--border); }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  .section-title { font-size: 16px; font-weight: 700; }
  .section-sub { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead tr { background: var(--bg-tertiary); }
  th { padding: 10px 16px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); }
  td { padding: 11px 16px; border-bottom: 1px solid var(--border); color: var(--text-secondary); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--bg-tertiary); }
  .td-ip { font-family: 'Courier New', monospace; color: var(--accent-blue); }
  .td-host { color: var(--text-primary); font-weight: 600; }
  .port-chip { display: inline-block; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 3px; padding: 1px 6px; font-family: 'Courier New', monospace; font-size: 11px; color: var(--text-secondary); margin: 1px; }
  .port-chip.highlight { border-color: var(--accent-orange); color: var(--accent-orange); }
  .os-badge { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; }
  .os-icon { font-size: 14px; }
  .role-dc { display: inline-block; background: rgba(233,69,96,.15); border: 1px solid rgba(233,69,96,.4); border-radius: 4px; padding: 1px 8px; font-size: 10px; font-weight: 700; color: var(--accent-red); text-transform: uppercase; letter-spacing: 0.5px; }
  .role-ws { display: inline-block; background: rgba(88,166,255,.1); border: 1px solid rgba(88,166,255,.3); border-radius: 4px; padding: 1px 8px; font-size: 10px; font-weight: 700; color: var(--accent-blue); text-transform: uppercase; letter-spacing: 0.5px; }
  .footer { background: var(--bg-secondary); border-top: 1px solid var(--border); padding: 12px 32px; display: flex; align-items: center; justify-content: space-between; font-size: 11px; color: var(--text-muted); }
  .footer-brand { color: var(--accent-red); font-weight: 700; }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg-primary); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: #484f58; }
</style>
</head>
<body>

<header class="header">
  <div class="header-left">
    <div class="header-logo">AD</div>
    <div class="header-title">
      <h1>%%DOMAIN%% &mdash; Network Intelligence Report</h1>
      <p>Active Directory Attack Surface Analysis &bull; %%FUNCTIONAL_LEVEL%%</p>
    </div>
  </div>
  <div class="header-meta">
    <div class="meta-chip">Date: <span>%%SCAN_DATE%%</span></div>
    <div class="meta-chip">Domain SID: <span>%%DOMAIN_SID%%</span></div>
    <div class="badge-live">ACTIVE</div>
  </div>
</header>

<div class="stats-bar">
  <div class="stat-card hosts">
    <div class="stat-icon hosts">&#x1F5A5;&#xFE0F;</div>
    <div><div class="stat-value">%%STAT_HOSTS%%</div><div class="stat-label">Hosts Discovered</div></div>
  </div>
  <div class="stat-card users">
    <div class="stat-icon users">&#x1F464;</div>
    <div><div class="stat-value">%%STAT_USERS%%</div><div class="stat-label">Domain Users</div></div>
  </div>
  <div class="stat-card kerb">
    <div class="stat-icon kerb">&#x1F3AB;</div>
    <div><div class="stat-value">%%STAT_KERB%%</div><div class="stat-label">Kerberoastable Accounts</div></div>
  </div>
  <div class="stat-card critical">
    <div class="stat-icon critical">&#x26A0;&#xFE0F;</div>
    <div><div class="stat-value">%%STAT_CRITICAL%%</div><div class="stat-label">Critical ACL Paths</div></div>
  </div>
</div>

<div class="controls-bar">
  <span class="controls-label">Show Edges</span>
  <button class="toggle-btn active" data-group="memberof" onclick="toggleGroup('memberof', this)">
    <span class="dot" style="background:#8b949e"></span> MemberOf
  </button>
  <button class="toggle-btn active" data-group="localadmin" onclick="toggleGroup('localadmin', this)">
    <span class="dot" style="background:#f0883e"></span> LocalAdmin
  </button>
  <button class="toggle-btn active" data-group="acl" onclick="toggleGroup('acl', this)">
    <span class="dot" style="background:#e94560"></span> ACLs
  </button>
  <button class="toggle-btn active" data-group="spn" onclick="toggleGroup('spn', this)">
    <span class="dot" style="background:#d29922"></span> Kerberoast SPN
  </button>
  <button class="toggle-btn active" data-group="cert" onclick="toggleGroup('cert', this)" id="certBtn" style="display:none">
    <span class="dot" style="background:#bc8cff"></span> ADCS
  </button>
  <div class="sep"></div>
  <button class="action-btn btn-attack" onclick="highlightAttackPath()">&#x26A1; Highlight Attack Path</button>
  <button class="action-btn btn-reset" onclick="resetView()">&#x21BA; Reset View</button>
  <button class="action-btn btn-physics" id="physicsBtn" onclick="togglePhysics()">&#x2699; Physics: ON</button>
</div>

<div class="main-layout">
  <div class="graph-wrapper">
    <div class="attack-path-banner" id="attackBanner">&#x26A1; %%ATTACK_BANNER%%</div>
    <div id="network-graph"></div>
    <div class="graph-watermark">%%WATERMARK%%</div>
  </div>
  <div class="sidebar">
    <div class="panel">
      <div class="panel-title">Legend</div>
      <div class="legend-section">
        <div class="legend-section-title">Node Types</div>
        <div class="legend-item"><div class="legend-node" style="background:#e94560;border-radius:50%;border:2px solid #ff8fa3;width:16px;height:16px"></div> Domain Root</div>
        <div class="legend-item"><div class="legend-node" style="background:#2a0a0a;border:2px solid #e94560"></div> Domain Controller</div>
        <div class="legend-item"><div class="legend-node" style="background:#0d1f3a;border:2px solid #58a6ff"></div> Workstation</div>
        <div class="legend-item"><div class="legend-node" style="background:#1c1c1c;border:2px solid #484f58"></div> Unknown Host</div>
        <div class="legend-item"><div class="legend-node circle" style="background:#2d1200;border:2px solid #f0883e"></div> Domain Admin</div>
        <div class="legend-item"><div class="legend-node circle" style="background:#0a1f12;border:2px solid #3fb950"></div> Standard User</div>
        <div class="legend-item"><div class="legend-node circle" style="background:#141414;border:2px dashed #484f58"></div> Disabled Account</div>
        <div class="legend-item"><div class="legend-node" style="clip-path:polygon(50% 0%,0% 100%,100% 100%);background:#1a0d33;border:none;width:16px;height:14px"></div> Security Group</div>
        <div class="legend-item"><div class="legend-node" style="background:#1a0d33;border:2px solid #bc8cff"></div> CA / Template</div>
      </div>
      <div class="legend-section">
        <div class="legend-section-title">Edge Types</div>
        <div class="legend-item"><div class="legend-edge dashed" style="border-color:#8b949e;width:28px"></div> MemberOf</div>
        <div class="legend-item"><div class="legend-edge" style="background:#f0883e"></div> LocalAdmin</div>
        <div class="legend-item"><div class="legend-edge" style="background:#e94560;height:3px"></div> GenericAll (Critical)</div>
        <div class="legend-item"><div class="legend-edge dashed" style="border-color:#e94560"></div> ForceChangePwd</div>
        <div class="legend-item"><div class="legend-edge dashed" style="border-color:#f0883e"></div> GenericWrite</div>
        <div class="legend-item"><div class="legend-edge" style="background:#d29922"></div> HasSPN (Kerberoast)</div>
        <div class="legend-item"><div class="legend-edge dashed" style="border-color:#bc8cff"></div> ADCS</div>
      </div>
    </div>
    <div class="node-detail">
      <div class="panel-title">Node Details</div>
      <div class="detail-placeholder" id="detail-placeholder">
        <div class="ph-icon">&#x1F50D;</div>
        Click any node to inspect details
      </div>
      <div id="detail-content">
        <div class="detail-header">
          <div class="detail-icon-wrap" id="d-icon"></div>
          <div><div class="detail-name" id="d-name"></div><div class="detail-type" id="d-type"></div></div>
        </div>
        <div id="d-rows"></div>
        <div class="flag-badges" id="d-flags"></div>
      </div>
    </div>
  </div>
</div>

<div class="table-section">
  <div class="section-header">
    <div>
      <div class="section-title">Network Topology</div>
      <div class="section-sub">Discovered via port scan of %%SUBNET%%</div>
    </div>
  </div>
  <table>
    <thead><tr><th>IP Address</th><th>Hostname</th><th>Role</th><th>Operating System</th><th>Open Ports</th><th>Services</th></tr></thead>
    <tbody>
%%RECON_ROWS%%
    </tbody>
  </table>
</div>

%%CERTIPY_SECTION%%

<footer class="footer">
  <div>Generated by <span class="footer-brand">Lat-Mov-Auto</span> &bull; AI-powered lateral movement framework</div>
  <div>%%DOMAIN%% &bull; %%SUBNET%% &bull; Scan date: %%SCAN_DATE%%</div>
</footer>

<script>
if (typeof vis === 'undefined') {
  document.getElementById('network-graph').innerHTML =
    '<div style="color:#e94560;padding:40px;font-family:monospace">vis-network failed to load from CDN. Check internet connection.</div>';
}

const nodeData = %%NODEDATA_JSON%%;
const edgeDefs = %%EDGEDEFS_JSON%%;
const attackPathIds = %%ATTACK_PATH_IDS%%;

// Show ADCS toggle if cert edges exist
if (edgeDefs.some(e => e.group === 'cert')) {
  document.getElementById('certBtn').style.display = '';
}

function nodeStyle(type) {
  const s = {
    domain:        { shape:'star',     size:34, color:{background:'#e94560',border:'#ff8fa3',highlight:{background:'#ff2a4a',border:'#fff'}}, font:{color:'#fff',size:13,bold:true}, borderWidth:3 },
    dc:            { shape:'box',      size:20, color:{background:'#2a0a0a',border:'#e94560',highlight:{background:'#3d0f0f',border:'#ff6b85'}}, font:{color:'#ff8fa3',size:12,bold:true}, borderWidth:2 },
    workstation:   { shape:'box',      size:20, color:{background:'#0d1f3a',border:'#58a6ff',highlight:{background:'#1a3458',border:'#79c0ff'}}, font:{color:'#79c0ff',size:12,bold:true}, borderWidth:2 },
    computer:      { shape:'box',      size:18, color:{background:'#0d1f3a',border:'#58a6ff',highlight:{background:'#1a3458',border:'#79c0ff'}}, font:{color:'#79c0ff',size:11}, borderWidth:1.5 },
    unknown:       { shape:'box',      size:16, color:{background:'#1c1c1c',border:'#484f58',highlight:{background:'#252525',border:'#6e7681'}}, font:{color:'#8b949e',size:11}, borderWidth:1, borderDashes:[4,3] },
    user_da:       { shape:'ellipse',  size:18, color:{background:'#2d1200',border:'#f0883e',highlight:{background:'#3d1800',border:'#ffa05c'}}, font:{color:'#f0883e',size:11,bold:true}, borderWidth:2 },
    user:          { shape:'ellipse',  size:16, color:{background:'#0a1f12',border:'#3fb950',highlight:{background:'#0f2d1c',border:'#56d364'}}, font:{color:'#3fb950',size:11}, borderWidth:1.5 },
    user_disabled: { shape:'ellipse',  size:14, color:{background:'#141414',border:'#484f58',highlight:{background:'#1c1c1c',border:'#6e7681'}}, font:{color:'#484f58',size:10}, borderWidth:1, borderDashes:[4,3] },
    group:         { shape:'triangle', size:24, color:{background:'#1a0d33',border:'#bc8cff',highlight:{background:'#231044',border:'#d2a8ff'}}, font:{color:'#bc8cff',size:11,bold:true}, borderWidth:2 },
    ca:            { shape:'box',      size:18, color:{background:'#1a1040',border:'#bc8cff',highlight:{background:'#231054',border:'#d2a8ff'}}, font:{color:'#bc8cff',size:11,bold:true}, borderWidth:2 },
    cert_template: { shape:'diamond',  size:16, color:{background:'#3a1a40',border:'#bc8cff',highlight:{background:'#4a2050',border:'#e94560'}}, font:{color:'#e94560',size:10,bold:true}, borderWidth:1.5 },
  };
  return s[type] || s['user'];
}

function edgeStyle(def) {
  const base = {
    arrows: { to: { enabled:true, scaleFactor:0.6, type:'arrow' } },
    smooth: { type:'curvedCW', roundness:0.2 },
    selectionWidth: 2, hoverWidth: 1,
    font: { size:9, color:'#8b949e', strokeWidth:2, strokeColor:'#0d1117', align:'horizontal' },
    labelHighlightBold: true,
  };
  if (def.group === 'memberof')   return {...base, color:{color:'#484f58',highlight:'#8b949e',hover:'#6e7681'}, dashes:[5,4], width:1, font:{...base.font,color:'#484f58'}};
  if (def.group === 'localadmin') return {...base, color:{color:'#b86020',highlight:'#f0883e',hover:'#f0883e'}, width:2};
  if (def.group === 'spn')        return {...base, color:{color:'#a07010',highlight:'#d29922',hover:'#d29922'}, width:1.5, font:{...base.font,color:'#d29922'}};
  if (def.group === 'cert')       return {...base, color:{color:'#7a4ab0',highlight:'#bc8cff',hover:'#bc8cff'}, dashes:[5,4], width:1.5, font:{...base.font,color:'#bc8cff'}};
  if (def.group === 'acl') {
    const t = def.aclType;
    if (t === 'GenericAll') {
      const crit = def.critical;
      return {...base, color:{color:crit?'#e94560':'#b52040',highlight:'#ff2a4a',hover:'#ff2a4a'}, width:crit?3:2, font:{...base.font,color:'#e94560',size:10,bold:true}, smooth:{type:'curvedCW',roundness:0.3}};
    }
    if (t === 'ForceChangePassword') return {...base, color:{color:'#c02040',highlight:'#e94560',hover:'#e94560'}, dashes:[6,3], width:2, font:{...base.font,color:'#e94560'}};
    if (t === 'GenericWrite')   return {...base, color:{color:'#b86020',highlight:'#f0883e',hover:'#f0883e'}, dashes:[5,4], width:2, font:{...base.font,color:'#f0883e'}};
    if (t === 'AddMember')      return {...base, color:{color:'#c04020',highlight:'#f06040',hover:'#f06040'}, dashes:[4,4], width:1.5};
    return {...base, color:{color:'#b52040',highlight:'#e94560',hover:'#e94560'}, width:1.5};
  }
  return base;
}

function buildTooltip(d) {
  const rows = Object.entries(d.info).map(([k,v]) =>
    `<tr><td style="color:#8b949e;padding:2px 8px 2px 0;white-space:nowrap">${k}</td><td style="color:#e6edf3;padding:2px 0">${v}</td></tr>`
  ).join('');
  const flagStr = (d.flags||[]).join(', ').toUpperCase() || '—';
  return `<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 14px;font-size:12px;font-family:Segoe UI,sans-serif;max-width:340px;box-shadow:0 4px 24px rgba(0,0,0,.5)">
    <div style="font-weight:700;color:#e6edf3;margin-bottom:8px;font-size:13px">${d.label.replace(/\n/g,' ')}</div>
    <table style="border-collapse:collapse">${rows}</table>
    ${d.flags&&d.flags.length?`<div style="margin-top:8px;font-size:10px;color:#f0883e;font-weight:600;text-transform:uppercase">Flags: ${flagStr}</div>`:''}
  </div>`;
}

// Build vis nodes
const visNodes = [];
for (const [id, d] of Object.entries(nodeData)) {
  const s = nodeStyle(d.type);
  visNodes.push({
    id, label: d.label, title: buildTooltip(d),
    shape: s.shape, size: s.size, color: s.color,
    font: {...s.font, multi: false},
    borderWidth: s.borderWidth,
    borderWidthSelected: (s.borderWidth||1)+1,
    shapeProperties: s.borderDashes ? {borderDashes: s.borderDashes} : {},
    _data: d,
  });
}

// Build vis edges
let edgeIdCounter = 1;
const allEdges = edgeDefs.map(def => ({
  id: edgeIdCounter++, from: def.from, to: def.to,
  label: def.label, group: def.group,
  _critical: def.critical||false, _aclType: def.aclType||null,
  ...edgeStyle(def),
}));

const container = document.getElementById('network-graph');
const nodes = new vis.DataSet(visNodes);
const edges = new vis.DataSet(allEdges);

const options = {
  physics: {
    enabled: true,
    solver: 'forceAtlas2Based',
    forceAtlas2Based: { gravitationalConstant:-45, centralGravity:0.01, springLength:130, springConstant:0.06, damping:0.6, avoidOverlap:1.0 },
    stabilization: { enabled:true, iterations:500, updateInterval:25, fit:true },
    minVelocity: 1.0,
  },
  interaction: { hover:true, tooltipDelay:100, zoomView:true, dragNodes:true },
  nodes: { borderWidth:2, shadow:{enabled:true,color:'rgba(0,0,0,0.5)',size:8,x:2,y:2}, chosen:true },
  edges: { shadow:{enabled:false}, chosen:true },
  layout: { randomSeed: 42 },
};

const network = new vis.Network(container, { nodes, edges }, options);

// Lock physics off as soon as stabilization completes — prevents perpetual rotation
network.on('stabilizationIterationsDone', () => {
  network.setOptions({ physics: { enabled: false } });
  document.getElementById('physicsBtn').textContent = '⚙ Physics: OFF';
  network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
});
// Safety fallback: force-stop after 4s regardless
setTimeout(() => {
  network.setOptions({ physics: { enabled: false } });
  document.getElementById('physicsBtn').textContent = '⚙ Physics: OFF';
}, 4000);

// ── CONTROLS ──────────────────────────────────────────────────────────────────

const flagLabels = {
  da:            { cls:'flag-da',            text:'Domain Admin' },
  kerb:          { cls:'flag-kerb',          text:'Kerberoastable' },
  disabled:      { cls:'flag-disabled',      text:'Disabled' },
  local:         { cls:'flag-local',         text:'Local Admin' },
  unconstrained: { cls:'flag-unconstrained', text:'Unconstrained Delegation' },
  critical:      { cls:'flag-critical',      text:'CRITICAL PATH' },
  vuln:          { cls:'flag-vuln',          text:'Vulnerable' },
  entry:         { cls:'flag-da',            text:'Entry Point' },
};
const typeIcons = {
  domain: {icon:'🌐', bg:'rgba(233,69,96,.2)'}, dc: {icon:'🖥️', bg:'rgba(233,69,96,.15)'},
  workstation: {icon:'💻', bg:'rgba(88,166,255,.15)'}, computer: {icon:'💻', bg:'rgba(88,166,255,.15)'},
  unknown: {icon:'❓', bg:'rgba(72,79,88,.2)'},
  user_da: {icon:'👑', bg:'rgba(240,136,62,.2)'}, user: {icon:'👤', bg:'rgba(63,185,80,.15)'},
  user_disabled: {icon:'🔒', bg:'rgba(72,79,88,.2)'}, group: {icon:'👥', bg:'rgba(188,140,255,.2)'},
  ca: {icon:'🏛️', bg:'rgba(188,140,255,.2)'}, cert_template: {icon:'📄', bg:'rgba(233,69,96,.15)'},
};

network.on('click', params => {
  if (!params.nodes.length) return;
  const n = nodes.get(params.nodes[0]);
  if (!n || !n._data) return;
  const d = n._data;
  document.getElementById('detail-placeholder').style.display = 'none';
  document.getElementById('detail-content').style.display = 'block';
  const ti = typeIcons[d.type] || {icon:'?', bg:'rgba(72,79,88,.2)'};
  const iconEl = document.getElementById('d-icon');
  iconEl.textContent = ti.icon;
  iconEl.style.background = ti.bg;
  document.getElementById('d-name').textContent = d.label.replace(/\n/g,' ');
  document.getElementById('d-type').textContent = d.info.Type || d.type;
  const rowsEl = document.getElementById('d-rows');
  rowsEl.innerHTML = Object.entries(d.info).map(([k,v]) =>
    `<div class="detail-row"><span class="detail-key">${k}</span><span class="detail-val">${v}</span></div>`
  ).join('');
  const flagsEl = document.getElementById('d-flags');
  flagsEl.innerHTML = (d.flags||[]).map(f => {
    const fl = flagLabels[f] || {cls:'flag-disabled', text:f};
    return `<span class="flag-badge ${fl.cls}">${fl.text}</span>`;
  }).join('');
});

function toggleGroup(group, btn) {
  btn.classList.toggle('active');
  const show = btn.classList.contains('active');
  const toUpdate = allEdges.filter(e => e.group === group).map(e => ({...e, hidden: !show}));
  edges.update(toUpdate);
}

let attackHighlighted = false;
function highlightAttackPath() {
  if (!attackPathIds.length) { alert('No critical attack path detected in this dataset.'); return; }
  attackHighlighted = !attackHighlighted;
  document.getElementById('attackBanner').style.display = attackHighlighted ? 'block' : 'none';
  if (attackHighlighted) {
    const pathSet = new Set(attackPathIds);
    const onPath = e => pathSet.has(e.from) && pathSet.has(e.to);
    nodes.update(visNodes.map(n => ({
      id: n.id,
      opacity: pathSet.has(n.id) ? 1.0 : 0.15,
    })));
    edges.update(allEdges.map(e => ({
      id: e.id,
      hidden: !onPath(e),
      width: onPath(e) ? 4 : e.width,
    })));
    network.fit({ nodes: attackPathIds, animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
  } else {
    nodes.update(visNodes.map(n => ({id: n.id, opacity: 1.0})));
    edges.update(allEdges.map(e => ({id: e.id, hidden: false, width: e.width})));
  }
}

function resetView() {
  attackHighlighted = false;
  document.getElementById('attackBanner').style.display = 'none';
  nodes.update(visNodes.map(n => ({id: n.id, opacity: 1.0})));
  edges.update(allEdges.map(e => ({id: e.id, opacity: 1.0, width: e.width})));
  network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
}

let physicsOn = false;
function togglePhysics() {
  physicsOn = !physicsOn;
  network.setOptions({ physics: { enabled: physicsOn } });
  document.getElementById('physicsBtn').textContent = '⚙ Physics: ' + (physicsOn ? 'ON' : 'OFF');
}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Generate network_map.html from recon + SharpHound [+ certipy]')
    parser.add_argument('--recon',       required=True,  help='Recon JSON file')
    parser.add_argument('--sharphound',  required=True,  help='SharpHound ZIP file')
    parser.add_argument('-c', '--certipy', default=None, help='Certipy JSON output (optional)')
    parser.add_argument('-o', '--output',  default='network_map.html', help='Output file (default: network_map.html)')
    args = parser.parse_args()

    print(f'[*] Loading recon:      {args.recon}')
    recon_hosts, subnet = load_recon(args.recon)

    print(f'[*] Loading SharpHound: {args.sharphound}')
    sh_data = load_sharphound(args.sharphound)

    certipy_data = {}
    if args.certipy:
        print(f'[*] Loading certipy:    {args.certipy}')
        certipy_data = load_certipy(args.certipy)

    print('[*] Indexing AD objects...')
    sid_map = index_objects(sh_data)

    domain_obj = next((obj for obj in sid_map.values() if obj['type'] == 'domain'), None)
    domain_name = domain_obj['full_name'].split('@')[-1] if domain_obj else 'UNKNOWN'
    domain_sid  = next(iter(k for k, v in sid_map.items() if v['type'] == 'domain'), '')
    scan_date   = datetime.now().strftime('%Y-%m-%d')

    print('[*] Building graph nodes...')
    nodes = build_nodes(sid_map, recon_hosts, certipy_data)

    print('[*] Building graph edges...')
    edges = build_edges(sid_map, nodes)

    stats = compute_stats(sid_map, recon_hosts, edges)
    attack_banner, attack_path_ids = find_attack_path(sid_map, nodes, edges)

    print(f'[*] Rendering HTML ({len(nodes)} nodes, {len(edges)} edges)...')
    html = render_html(
        nodes, edges, stats, recon_hosts, sid_map,
        domain_name, domain_sid, subnet, scan_date,
        attack_banner, attack_path_ids, certipy_data,
    )

    Path(args.output).write_text(html, encoding='utf-8')
    print(f'[+] Done -> {args.output}')
    print(f'    Hosts: {stats["hosts"]}  Users: {stats["users"]}  Kerberoastable: {stats["kerberoastable"]}  Critical ACLs: {stats["critical_acl"]}')
    if attack_banner:
        print(f'    Attack path: {attack_banner}'.encode('ascii', errors='replace').decode())


if __name__ == '__main__':
    main()
