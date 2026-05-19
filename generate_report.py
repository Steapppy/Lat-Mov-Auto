#!/usr/bin/env python3
"""Generate the Lat-Mov-Auto project report PDF."""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas
from datetime import datetime

# ── Palette ──────────────────────────────────────────────────────────────────
DARK        = colors.HexColor("#111827")
ACCENT      = colors.HexColor("#1a56db")
ACCENT_DARK = colors.HexColor("#0e3fa3")
MID         = colors.HexColor("#374151")
LIGHT       = colors.HexColor("#6b7280")
BORDER      = colors.HexColor("#e5e7eb")
BG_SOFT     = colors.HexColor("#f9fafb")
BG_BLUE     = colors.HexColor("#eff6ff")
BG_GREEN    = colors.HexColor("#ecfdf5")
BG_YELLOW   = colors.HexColor("#fffbeb")
BG_RED      = colors.HexColor("#fef2f2")
GREEN       = colors.HexColor("#065f46")
YELLOW      = colors.HexColor("#92400e")
RED         = colors.HexColor("#991b1b")
CODE_BG     = colors.HexColor("#1e293b")
CODE_FG     = colors.HexColor("#e2e8f0")
WHITE       = colors.white

PAGE_W, PAGE_H = A4
MARGIN = 2.2 * cm


# ── Page template with header/footer ─────────────────────────────────────────
class PageTemplate:
    def __init__(self, title):
        self.title = title

    def __call__(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # Top accent bar
        canvas.setFillColor(DARK)
        canvas.rect(0, h - 1.1 * cm, w, 1.1 * cm, fill=1, stroke=0)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, h - 1.1 * cm, 0.6 * cm, 1.1 * cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.drawString(MARGIN, h - 0.7 * cm, "LAT-MOV-AUTO")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#9ca3af"))
        canvas.drawRightString(w - MARGIN, h - 0.7 * cm, self.title)

        # Footer
        canvas.setFillColor(BORDER)
        canvas.rect(MARGIN, 1.2 * cm, w - 2 * MARGIN, 0.03 * cm, fill=1, stroke=0)
        canvas.setFillColor(LIGHT)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 0.75 * cm, "Confidential — Internal Use Only")
        canvas.drawRightString(w - MARGIN, 0.75 * cm, f"Page {doc.page}")

        canvas.restoreState()


# ── Custom flowables ──────────────────────────────────────────────────────────
class SectionHeader(Flowable):
    """Full-width dark section header bar."""
    def __init__(self, text, number=None):
        super().__init__()
        self.text   = text
        self.number = number
        self.width  = PAGE_W - 2 * MARGIN
        self.height = 0.75 * cm

    def draw(self):
        c = self.canv
        c.setFillColor(DARK)
        c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        if self.number:
            c.setFillColor(ACCENT)
            c.rect(0, 0, 0.55 * cm, self.height, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 8)
            c.drawCentredString(0.275 * cm, 0.22 * cm, self.number)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(0.75 * cm, 0.22 * cm, self.text)
        else:
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(0.4 * cm, 0.22 * cm, self.text)


class CodeBlock(Flowable):
    """Dark code block."""
    def __init__(self, lines, width=None):
        super().__init__()
        self.lines = lines
        self.width = width or (PAGE_W - 2 * MARGIN)
        self.pad   = 0.3 * cm
        self.height = (len(lines) * 0.42 * cm) + 2 * self.pad

    def draw(self):
        c = self.canv
        c.setFillColor(CODE_BG)
        c.roundRect(0, 0, self.width, self.height, 4, fill=1, stroke=0)
        c.setFillColor(CODE_FG)
        c.setFont("Courier", 8)
        y = self.height - self.pad - 0.3 * cm
        for line in self.lines:
            c.drawString(self.pad, y, line)
            y -= 0.42 * cm


class StatusPill(Flowable):
    """Coloured status pill (Built / Planned / In Progress)."""
    COLOURS = {
        "Built":       (BG_GREEN,  GREEN),
        "Planned":     (BG_YELLOW, YELLOW),
        "In Progress": (BG_BLUE,   ACCENT_DARK),
        "Low":         (BG_GREEN,  GREEN),
        "Medium":      (BG_YELLOW, YELLOW),
        "High":        (BG_RED,    RED),
    }
    def __init__(self, text):
        super().__init__()
        self.text   = text
        self.width  = 2.0 * cm
        self.height = 0.4 * cm

    def draw(self):
        bg, fg = self.COLOURS.get(self.text, (BG_SOFT, MID))
        c = self.canv
        c.setFillColor(bg)
        c.roundRect(0, 0, self.width, self.height, 4, fill=1, stroke=0)
        c.setFillColor(fg)
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(self.width / 2, 0.1 * cm, self.text)


# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()
    s = {}

    s["body"] = ParagraphStyle("body",
        fontName="Helvetica", fontSize=9.5, leading=15,
        textColor=MID, alignment=TA_JUSTIFY,
        spaceAfter=6)

    s["body_left"] = ParagraphStyle("body_left",
        parent=s["body"], alignment=TA_LEFT)

    s["h2"] = ParagraphStyle("h2",
        fontName="Helvetica-Bold", fontSize=12, leading=16,
        textColor=DARK, spaceBefore=18, spaceAfter=6)

    s["h3"] = ParagraphStyle("h3",
        fontName="Helvetica-Bold", fontSize=10, leading=14,
        textColor=ACCENT_DARK, spaceBefore=10, spaceAfter=4)

    s["bullet"] = ParagraphStyle("bullet",
        fontName="Helvetica", fontSize=9.5, leading=14,
        textColor=MID, leftIndent=14, firstLineIndent=-10,
        spaceAfter=3)

    s["caption"] = ParagraphStyle("caption",
        fontName="Helvetica", fontSize=8, leading=11,
        textColor=LIGHT, alignment=TA_CENTER)

    s["cover_label"] = ParagraphStyle("cover_label",
        fontName="Helvetica-Bold", fontSize=8, leading=12,
        textColor=ACCENT, spaceBefore=0, spaceAfter=6,
        wordWrap=None)

    s["cover_title"] = ParagraphStyle("cover_title",
        fontName="Helvetica-Bold", fontSize=26, leading=32,
        textColor=DARK, spaceAfter=8)

    s["cover_sub"] = ParagraphStyle("cover_sub",
        fontName="Helvetica", fontSize=14, leading=18,
        textColor=MID, spaceAfter=24)

    s["table_header"] = ParagraphStyle("table_header",
        fontName="Helvetica-Bold", fontSize=8.5, leading=12,
        textColor=WHITE)

    s["table_cell"] = ParagraphStyle("table_cell",
        fontName="Helvetica", fontSize=8.5, leading=12,
        textColor=MID)

    s["table_cell_bold"] = ParagraphStyle("table_cell_bold",
        fontName="Helvetica-Bold", fontSize=8.5, leading=12,
        textColor=DARK)

    s["info_box"] = ParagraphStyle("info_box",
        fontName="Helvetica", fontSize=9.5, leading=14,
        textColor=MID, leftIndent=6, rightIndent=6)

    return s


def bullet(text, style):
    return Paragraph(f"• &nbsp; {text}", style)


def info_box(text, style, bg=BG_BLUE, bar=ACCENT):
    """Blue info callout box."""
    content = Paragraph(text, style["info_box"])
    tbl = Table([[content]], colWidths=[PAGE_W - 2 * MARGIN - 0.5 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), bg),
        ("LEFTPADDING",  (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
        ("LINEBEFORE",   (0, 0), (0, -1), 3, bar),
        ("ROUNDEDCORNERS", [4]),
    ]))
    return tbl


# ── Build PDF ─────────────────────────────────────────────────────────────────
def build(path):
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.6 * cm, bottomMargin=1.8 * cm,
        title="Lat-Mov-Auto — Project Report",
        author="Lat-Mov-Auto Team",
    )

    tmpl = PageTemplate("Project Documentation Report — April 2026")
    s = make_styles()
    story = []

    # ══════════════════════════════════════════════════════════════════
    # COVER
    # ══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 3 * cm))

    # Accent rule
    story.append(HRFlowable(width="100%", thickness=3, color=ACCENT, spaceAfter=20))

    story.append(Paragraph("PROJECT DOCUMENTATION REPORT", s["cover_label"]))
    story.append(Paragraph("Lat-Mov-Auto", s["cover_title"]))
    story.append(Paragraph("AI-Assisted Lateral Movement Automation Framework", s["cover_sub"]))

    # Meta table
    meta = Table(
        [[
            Paragraph("<b>Date</b><br/>April 2026",         s["body_left"]),
            Paragraph("<b>Project</b><br/>Lat-Mov-Auto",    s["body_left"]),
            Paragraph("<b>Status</b><br/>Active Development", s["body_left"]),
            Paragraph("<b>Classification</b><br/>Confidential", s["body_left"]),
        ]],
        colWidths=[(PAGE_W - 2 * MARGIN) / 4] * 4,
    )
    meta.setStyle(TableStyle([
        ("BOX",          (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID",    (0, 0), (-1, -1), 0.5, BORDER),
        ("BACKGROUND",   (0, 0), (-1, -1), BG_SOFT),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("LEFTPADDING",  (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(meta)
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════════
    story.append(SectionHeader("1.  Executive Summary"))
    story.append(Spacer(1, 0.3 * cm))

    story.append(info_box(
        "Lat-Mov-Auto is an end-of-studies internship project building a proof-of-concept "
        "Command &amp; Control (C2) framework focused on automating lateral movement techniques "
        "within Active Directory environments. The framework is designed to demonstrate the "
        "full attack lifecycle — from initial reconnaissance to credential harvesting and "
        "authenticated remote execution — using only native Windows protocols.",
        s
    ))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "The project consists of three main components: a lightweight C# agent deployed on "
        "compromised hosts, a Python FastAPI C2 server managing agents and storing loot, and "
        "an operator CLI used to issue commands, run modules, and analyse results. The framework "
        "integrates with n8n for automated event notifications and is designed to be extensible "
        "with new post-exploitation modules.",
        s["body"]
    ))

    story.append(Paragraph(
        "As of April 2026, the core framework is operational and has been tested in a controlled "
        "lab environment. The authentication module — the central focus of recent development — "
        "is fully functional with automatic service detection, credential sweeping, credential "
        "spraying, and remote command execution capabilities.",
        s["body"]
    ))

    # ══════════════════════════════════════════════════════════════════
    # 2. ARCHITECTURE
    # ══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.4 * cm))
    story.append(SectionHeader("2.  Architecture Overview"))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("2.1  Component Breakdown", s["h3"]))

    # Architecture table
    arch_data = [
        [
            Paragraph("Component", s["table_header"]),
            Paragraph("Technology", s["table_header"]),
            Paragraph("Role", s["table_header"]),
        ],
        [
            Paragraph("<b>C2 Server</b>", s["table_cell_bold"]),
            Paragraph("Python 3 / FastAPI / SQLite", s["table_cell"]),
            Paragraph("Central hub — task queue, result storage, credential DB, loot files", s["table_cell"]),
        ],
        [
            Paragraph("<b>Agent</b>", s["table_cell_bold"]),
            Paragraph("C# / .NET 10 / Single-file EXE", s["table_cell"]),
            Paragraph("Deployed on target hosts — beacons, executes tasks, returns results", s["table_cell"]),
        ],
        [
            Paragraph("<b>Operator CLI</b>", s["table_cell_bold"]),
            Paragraph("Python 3", s["table_cell"]),
            Paragraph("Interactive REPL for issuing commands and viewing results", s["table_cell"]),
        ],
        [
            Paragraph("<b>n8n Integration</b>", s["table_cell_bold"]),
            Paragraph("n8n Webhooks", s["table_cell"]),
            Paragraph("Fire-and-forget event notifications (new agent, task result, file upload)", s["table_cell"]),
        ],
        [
            Paragraph("<b>Database</b>", s["table_cell_bold"]),
            Paragraph("SQLite (loot.db)", s["table_cell"]),
            Paragraph("Persists agents, tasks, results, hosts, credentials, tunnels", s["table_cell"]),
        ],
    ]
    col_w = (PAGE_W - 2 * MARGIN)
    arch_tbl = Table(arch_data, colWidths=[col_w * 0.2, col_w * 0.28, col_w * 0.52])
    arch_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), DARK),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, BG_SOFT]),
        ("GRID",         (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(arch_tbl)
    story.append(Spacer(1, 0.35 * cm))

    story.append(Paragraph("2.2  Communication Flow", s["h3"]))
    story.append(CodeBlock([
        "Agent  ──(HTTPS beacon / POST /checkin)──▶  C2 Server  ◀──  Operator CLI",
        "       ◀──(task: type + instruction)──────  C2 Server",
        "       ──(POST /result: output)───────────▶  C2 Server  ──▶  n8n Webhook",
        "                                              │",
        "                                           loot.db (SQLite)",
    ]))
    story.append(Spacer(1, 0.35 * cm))

    story.append(Paragraph("2.3  Database Schema (key tables)", s["h3"]))
    db_data = [
        [Paragraph("Table", s["table_header"]), Paragraph("Key Columns", s["table_header"]), Paragraph("Purpose", s["table_header"])],
        [Paragraph("agents", s["table_cell_bold"]),     Paragraph("agent_id, hostname, username, ip, last_seen", s["table_cell"]),               Paragraph("Registered beaconing agents", s["table_cell"])],
        [Paragraph("tasks", s["table_cell_bold"]),      Paragraph("task_id, agent_id, task_type, instruction, status", s["table_cell"]),          Paragraph("Pending / sent / completed task queue", s["table_cell"])],
        [Paragraph("results", s["table_cell_bold"]),    Paragraph("result_id, task_id, agent_id, output, received_at", s["table_cell"]),          Paragraph("Task output returned by agents", s["table_cell"])],
        [Paragraph("hosts", s["table_cell_bold"]),      Paragraph("ip, hostname, open_ports, services, discovered_by", s["table_cell"]),          Paragraph("Recon-discovered hosts and port data", s["table_cell"])],
        [Paragraph("credentials", s["table_cell_bold"]),Paragraph("username, secret, cred_type, source_host, harvested_at", s["table_cell"]),     Paragraph("Harvested credentials (plaintext / NTLM)", s["table_cell"])],
        [Paragraph("tunnels", s["table_cell_bold"]),    Paragraph("agent_id, interface, subnet, status", s["table_cell"]),                        Paragraph("Active ligolo-ng pivot tunnels", s["table_cell"])],
    ]
    db_tbl = Table(db_data, colWidths=[col_w * 0.18, col_w * 0.44, col_w * 0.38])
    db_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, BG_SOFT]),
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(db_tbl)

    # ══════════════════════════════════════════════════════════════════
    # 3. IMPLEMENTED MODULES
    # ══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.4 * cm))
    story.append(SectionHeader("3.  Implemented Modules"))
    story.append(Spacer(1, 0.3 * cm))

    # ── 3.1 Agent
    story.append(KeepTogether([
        Paragraph("3.1  Agent (C# .NET 10)", s["h3"]),
        Paragraph(
            "The agent is compiled as a self-contained, single-file Windows executable with no "
            "external dependencies. It beacons to the C2 server at a configurable interval "
            "(default 5 seconds), receives tasks, executes them, and posts results back.",
            s["body"]
        ),
        Paragraph("Capabilities:", s["body_left"]),
        bullet("Asynchronous beacon loop with task polling via <b>POST /checkin</b>", s["bullet"]),
        bullet("Shell command execution via <b>cmd.exe /c</b>", s["bullet"]),
        bullet("Tool download from <b>/files/</b> server endpoint to <b>%TEMP%</b>", s["bullet"]),
        bullet("File upload back to server via <b>POST /upload</b> (multipart)", s["bullet"]),
        bullet("Self-reported IP, hostname, and username on each checkin", s["bullet"]),
    ]))

    story.append(Spacer(1, 0.3 * cm))

    # ── 3.2 Recon
    story.append(KeepTogether([
        Paragraph("3.2  Reconnaissance Module", s["h3"]),
        Paragraph(
            "The recon module performs fully asynchronous network scanning from the agent. "
            "It accepts a single IP or CIDR range, performs a parallel ping sweep, then "
            "scans common ports on all alive hosts. Results are returned as structured JSON "
            "and stored in the hosts table for use by downstream modules.",
            s["body"]
        ),
        Paragraph("Technical details:", s["body_left"]),
        bullet("Parallel <b>ICMP ping sweep</b> with 1 s timeout", s["bullet"]),
        bullet("Port scan of 14 common ports: 21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443", s["bullet"]),
        bullet("<b>Banner grabbing</b> on text-based protocols (HTTP, FTP, SMTP, SSH)", s["bullet"]),
        bullet("<b>Reverse DNS resolution</b> for hostname discovery", s["bullet"]),
        bullet("Results stored to <b>hosts</b> table and uploaded to loot as JSON", s["bullet"]),
        bullet("Operator CLI renders results as a formatted table (IP / Hostname / Port / Service / Banner)", s["bullet"]),
    ]))

    story.append(Spacer(1, 0.3 * cm))

    # ── 3.3 Post-exploitation tools
    story.append(KeepTogether([
        Paragraph("3.3  Post-Exploitation Tool Delivery", s["h3"]),
        Paragraph(
            "A generic tool-delivery model allows the operator to upload offensive tools "
            "to the server's <b>/files/</b> directory and execute them on agents on demand. "
            "Tools are downloaded to <b>%TEMP%</b>, executed, and any output files are "
            "automatically uploaded back to the server.",
            s["body"]
        ),
        Paragraph("Supported modules:", s["body_left"]),
        bullet("<b>SharpHound</b> — Active Directory enumeration; ZIP output auto-uploaded", s["bullet"]),
        bullet("<b>Certipy</b> — ADCS certificate template enumeration; JSON/TXT output auto-uploaded", s["bullet"]),
        bullet("<b>Secretsdump / DPAPI</b> — generic tool execution (Mimikatz, SharpDPAPI, etc.)", s["bullet"]),
    ]))

    story.append(Spacer(1, 0.3 * cm))

    # ── 3.4 Authentication
    story.append(Paragraph("3.4  Authentication &amp; Lateral Movement Module", s["h3"]))
    story.append(Paragraph(
        "The authentication module is the primary focus of the current development phase. "
        "It provides multiple modes of authenticated access to remote Windows hosts using "
        "only native Windows binaries — no third-party tools required on the agent.",
        s["body"]
    ))

    story.append(Paragraph("Supported services:", s["body_left"]))
    svc_data = [
        [Paragraph("Service", s["table_header"]), Paragraph("Protocol", s["table_header"]), Paragraph("Default Probe", s["table_header"]), Paragraph("Custom -c", s["table_header"])],
        [Paragraph("WinRM", s["table_cell_bold"]),  Paragraph("HTTP/5985 via winrs", s["table_cell"]),         Paragraph("whoami &amp;&amp; hostname &amp;&amp; ipconfig", s["table_cell"]), Paragraph("Full stdout capture", s["table_cell"])],
        [Paragraph("SMB",   s["table_cell_bold"]),  Paragraph("TCP/445 via net use", s["table_cell"]),          Paragraph("IPC$ connect + net view (shares)", s["table_cell"]),              Paragraph("Not supported (auth only)", s["table_cell"])],
        [Paragraph("WMI",   s["table_cell_bold"]),  Paragraph("TCP/135 via wmic", s["table_cell"]),             Paragraph("process list brief", s["table_cell"]),                            Paragraph("process call create (no stdout)", s["table_cell"])],
    ]
    svc_tbl = Table(svc_data, colWidths=[col_w * 0.12, col_w * 0.26, col_w * 0.36, col_w * 0.26])
    svc_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, BG_SOFT]),
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(svc_tbl)
    story.append(Spacer(1, 0.25 * cm))

    story.append(Paragraph("Authentication modes:", s["body_left"]))
    story.append(KeepTogether([
        bullet("<b>Auto-sweep</b> — no service specified; queries recon DB for open lateral movement ports and tries all detected services sequentially, reporting success/failure per service", s["bullet"]),
        bullet("<b>Forced service</b> (<code>-s winrm|smb|wmi</code>) — authenticate to a specific service only", s["bullet"]),
        bullet("<b>Custom command</b> (<code>-c &lt;cmd&gt;</code>) — run any command on the remote host via WinRM; uses shlex parsing to handle multi-word commands with spaces", s["bullet"]),
        bullet("<b>Credential spray</b> (<code>spray &lt;target&gt;</code>) — try all credentials stored in the DB against a target, output an access matrix", s["bullet"]),
        bullet("<b>Multi-target spray</b> (<code>--all</code>) — one credential set against every host in the DB with lateral movement ports open", s["bullet"]),
        bullet("<b>Auto-store</b> — any successful authentication automatically persists the credential to the DB for downstream use", s["bullet"]),
    ]))

    story.append(Spacer(1, 0.25 * cm))
    story.append(Paragraph("Operator CLI examples:", s["body_left"]))
    story.append(CodeBlock([
        "# Auto-sweep all services detected by recon",
        "authenticate -u administrator -p Password1 10.0.2.8",
        "",
        "# Force WinRM and run a custom command",
        "authenticate -u administrator -p Password1 -s winrm -c \"net user /domain\" 10.0.2.8",
        "",
        "# Spray all stored credentials against one target",
        "spray 10.0.2.8",
        "",
        "# One credential set against all known hosts",
        "authenticate -u administrator -p Password1 --all",
    ]))

    # ══════════════════════════════════════════════════════════════════
    # 4. OPERATOR CLI
    # ══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.4 * cm))
    story.append(SectionHeader("4.  Operator CLI"))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "The operator CLI is an interactive REPL that communicates with the C2 server over "
        "HTTP. It operates in two modes: global mode for cross-agent operations, and interact "
        "mode scoped to a specific agent.",
        s["body"]
    ))

    story.append(Paragraph("Global mode commands:", s["h3"]))
    cmd_data = [
        [Paragraph("Command", s["table_header"]), Paragraph("Description", s["table_header"])],
        [Paragraph("agents",              s["table_cell_bold"]), Paragraph("List all registered agents with last seen timestamp", s["table_cell"])],
        [Paragraph("hosts",               s["table_cell_bold"]), Paragraph("List all recon-discovered hosts and open ports", s["table_cell"])],
        [Paragraph("credentials",         s["table_cell_bold"]), Paragraph("List all harvested credentials from the DB", s["table_cell"])],
        [Paragraph("loot",                s["table_cell_bold"]), Paragraph("List files uploaded by agents (SharpHound ZIPs, etc.)", s["table_cell"])],
        [Paragraph("results &lt;id&gt;",  s["table_cell_bold"]), Paragraph("Show all task results for a given agent", s["table_cell"])],
        [Paragraph("interact &lt;id&gt;", s["table_cell_bold"]), Paragraph("Enter interact mode for a specific agent", s["table_cell"])],
    ]
    cmd_tbl = Table(cmd_data, colWidths=[col_w * 0.28, col_w * 0.72])
    cmd_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, BG_SOFT]),
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ]))
    story.append(cmd_tbl)

    # ══════════════════════════════════════════════════════════════════
    # 5. TESTING STATUS
    # ══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.4 * cm))
    story.append(SectionHeader("5.  Testing Status"))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "All modules have been tested in a controlled lab environment (VMware) with a Windows "
        "Active Directory domain (ICCN.LOCAL). The test topology includes a Windows Server 2019 "
        "Domain Controller and Windows 10 workstations.",
        s["body"]
    ))

    test_data = [
        [
            Paragraph("Module / Feature", s["table_header"]),
            Paragraph("Status", s["table_header"]),
            Paragraph("Notes", s["table_header"]),
        ],
        [Paragraph("Agent beacon / checkin",        s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Tested — stable beaconing at 5 s interval", s["table_cell"])],
        [Paragraph("Shell command execution",        s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Tested — full stdout/stderr capture", s["table_cell"])],
        [Paragraph("Recon (ping + port scan)",       s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Tested — table display, stored to hosts DB", s["table_cell"])],
        [Paragraph("SharpHound integration",         s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Tested — ZIP auto-uploaded to loot", s["table_cell"])],
        [Paragraph("Certipy integration",            s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Tested — output files auto-uploaded", s["table_cell"])],
        [Paragraph("Secretsdump / DPAPI",            s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Generic tool execution, tested with Mimikatz", s["table_cell"])],
        [Paragraph("Auth sweep (WinRM/SMB/WMI)",     s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Tested — correct service detection from recon", s["table_cell"])],
        [Paragraph("Custom command (-c flag)",        s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Tested — shlex fix applied for multi-word commands", s["table_cell"])],
        [Paragraph("Auto-store credentials",         s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Implemented — to be validated in next session", s["table_cell"])],
        [Paragraph("Credential spray (spray cmd)",   s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Implemented — to be validated in next session", s["table_cell"])],
        [Paragraph("Multi-target spray (--all)",     s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Implemented — to be validated in next session", s["table_cell"])],
        [Paragraph("n8n webhook notifications",      s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Tested — new agent and task result events firing", s["table_cell"])],
        [Paragraph("Pivot / tunnel management",      s["table_cell_bold"]), Paragraph("Built", s["table_cell"]),    Paragraph("Ligolo-ng integration — register/remove tunnels", s["table_cell"])],
    ]

    def status_cell(text):
        colours = {"Built": (BG_GREEN, GREEN), "Planned": (BG_YELLOW, YELLOW), "In Progress": (BG_BLUE, ACCENT_DARK)}
        bg, fg = colours.get(text, (BG_SOFT, MID))
        p = Paragraph(f"<b>{text}</b>", ParagraphStyle("sc", fontName="Helvetica-Bold", fontSize=7.5, textColor=fg))
        t = Table([[p]], colWidths=[1.8*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), bg),
            ("TOPPADDING", (0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
            ("LEFTPADDING",(0,0),(-1,-1), 4),
            ("RIGHTPADDING",(0,0),(-1,-1), 4),
            ("ROUNDEDCORNERS",[4]),
        ]))
        return t

    test_data_rendered = [test_data[0]]
    for row in test_data[1:]:
        test_data_rendered.append([row[0], status_cell(row[1].text), row[2]])

    test_tbl = Table(test_data_rendered, colWidths=[col_w * 0.33, col_w * 0.15, col_w * 0.52])
    test_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, BG_SOFT]),
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(test_tbl)

    # ══════════════════════════════════════════════════════════════════
    # 6. UPCOMING WORK
    # ══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.4 * cm))
    story.append(SectionHeader("6.  Upcoming Work"))
    story.append(Spacer(1, 0.3 * cm))

    story.append(info_box(
        "The following features are planned for the next development session. They are ordered "
        "by priority and dependency — items 1 and 2 are prerequisites for a clean Pass-the-Hash "
        "implementation.",
        s, bg=BG_YELLOW, bar=colors.HexColor("#d97706")
    ))
    story.append(Spacer(1, 0.3 * cm))

    upcoming = [
        (
            "1", "Credential Storage Improvements",
            "Medium", "Operator only",
            [
                "The current credential store has known issues to be reviewed and fixed.",
                "Improve deduplication logic — avoid storing the same (username, secret) pair multiple times.",
                "Add cred_type field support for NTLM hashes (preparation for Pass-the-Hash).",
                "Display improvements in the 'credentials' command (mask secrets, show service tags).",
            ]
        ),
        (
            "2", "Pass-the-Hash (PtH) Authentication",
            "Medium", "Operator + Agent",
            [
                "Add -H <NTLM_hash> flag as an alternative to -p <password> in authenticate.",
                "Operator stores hash-based credentials with cred_type='ntlm' in the DB.",
                "Agent downloads Invoke-TheHash.ps1 (or equivalent) from /files/ on demand.",
                "Enables full attack chain: secretsdump → harvest NTLM → PtH lateral move.",
                "Maps to MITRE ATT&CK T1550.002 (Use Alternate Authentication Material).",
            ]
        ),
    ]

    for num, title, complexity, scope, points in upcoming:
        story.append(KeepTogether([
            SectionHeader(f"   {num}.  {title}", number=num),
            Spacer(1, 0.2 * cm),
            Table([[
                Paragraph(f"<b>Complexity:</b> {complexity}", s["body_left"]),
                Paragraph(f"<b>Scope:</b> {scope}", s["body_left"]),
            ]], colWidths=[col_w / 2, col_w / 2]),
            Spacer(1, 0.15 * cm),
            *[bullet(p, s["bullet"]) for p in points],
            Spacer(1, 0.3 * cm),
        ]))

    # ══════════════════════════════════════════════════════════════════
    # 7. MITRE ATT&CK MAPPING
    # ══════════════════════════════════════════════════════════════════
    story.append(SectionHeader("7.  MITRE ATT&CK Mapping"))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "The table below maps implemented and planned capabilities to the MITRE ATT&CK framework.",
        s["body"]
    ))

    mitre_data = [
        [Paragraph("Technique ID", s["table_header"]), Paragraph("Name", s["table_header"]), Paragraph("Module", s["table_header"]), Paragraph("Status", s["table_header"])],
        [Paragraph("T1018",     s["table_cell_bold"]), Paragraph("Remote System Discovery",              s["table_cell"]), Paragraph("Recon module",              s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1046",     s["table_cell_bold"]), Paragraph("Network Service Discovery",            s["table_cell"]), Paragraph("Recon — port scan",         s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1021.001", s["table_cell_bold"]), Paragraph("Remote Services: WinRM",               s["table_cell"]), Paragraph("Auth module",               s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1021.002", s["table_cell_bold"]), Paragraph("Remote Services: SMB",                 s["table_cell"]), Paragraph("Auth module",               s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1047",     s["table_cell_bold"]), Paragraph("Windows Management Instrumentation",   s["table_cell"]), Paragraph("Auth module",               s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1059.001", s["table_cell_bold"]), Paragraph("Command &amp; Scripting: PowerShell",  s["table_cell"]), Paragraph("Tool delivery",             s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1078",     s["table_cell_bold"]), Paragraph("Valid Accounts",                       s["table_cell"]), Paragraph("Auth — auto-store",         s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1110.003", s["table_cell_bold"]), Paragraph("Credential Stuffing",                  s["table_cell"]), Paragraph("spray / --all",             s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1003",     s["table_cell_bold"]), Paragraph("OS Credential Dumping",                s["table_cell"]), Paragraph("Secretsdump / Mimikatz",    s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1558",     s["table_cell_bold"]), Paragraph("Steal or Forge Kerberos Tickets",      s["table_cell"]), Paragraph("Certipy / SharpHound",      s["table_cell"]), Paragraph("Built",   s["table_cell"])],
        [Paragraph("T1550.002", s["table_cell_bold"]), Paragraph("Pass the Hash",                        s["table_cell"]), Paragraph("PtH module",                s["table_cell"]), Paragraph("Planned", s["table_cell"])],
    ]
    mitre_tbl = Table(mitre_data, colWidths=[col_w * 0.16, col_w * 0.38, col_w * 0.28, col_w * 0.18])
    mitre_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, BG_SOFT]),
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(mitre_tbl)

    # ══════════════════════════════════════════════════════════════════
    # Build
    # ══════════════════════════════════════════════════════════════════
    doc.build(story, onFirstPage=tmpl, onLaterPages=tmpl)
    print(f"[+] Report written to: {path}")


if __name__ == "__main__":
    build("Lat-Mov-Auto_Project_Report.pdf")
