import time
from threading import Lock
from typing import Any

from jinja2 import Environment, FileSystemLoader
from fpdf import FPDF

TEMPLATE_ENV = Environment(loader=FileSystemLoader("app/reports/templates"))
REPORT_TEMPLATE = TEMPLATE_ENV.get_template("report.html")

SESSION_TTL_SECONDS = 30 * 60
MAX_SESSION_COUNT = 100

_SESSION_LOCK = Lock()
_REPORT_SESSIONS: dict[str, dict[str, Any]] = {}


def _build_summary(vulns):
    summary = {}
    for vuln in vulns:
        severity = vuln.get("severity", "Low")
        summary[severity] = summary.get(severity, 0) + 1
    return summary


def _prune_sessions(now: float):
    expired = [
        session_id
        for session_id, payload in _REPORT_SESSIONS.items()
        if now - payload["created_at"] > SESSION_TTL_SECONDS
    ]
    for session_id in expired:
        _REPORT_SESSIONS.pop(session_id, None)

    if len(_REPORT_SESSIONS) > MAX_SESSION_COUNT:
        ordered = sorted(_REPORT_SESSIONS.items(), key=lambda item: item[1]["created_at"])
        overflow = len(_REPORT_SESSIONS) - MAX_SESSION_COUNT
        for session_id, _payload in ordered[:overflow]:
            _REPORT_SESSIONS.pop(session_id, None)


def create_report_session(session_id: str, vulns, uploaded_files, errors):
    now = time.time()
    payload = {
        "id": session_id,
        "created_at": now,
        "vulns": vulns,
        "summary": _build_summary(vulns),
        "total": len(vulns),
        "uploaded_files": uploaded_files,
        "errors": errors,
    }

    with _SESSION_LOCK:
        _prune_sessions(now)
        _REPORT_SESSIONS[session_id] = payload

    return payload


def get_report_session(session_id: str):
    now = time.time()
    with _SESSION_LOCK:
        _prune_sessions(now)
        return _REPORT_SESSIONS.get(session_id)


def render_report_html(session_payload):
    return REPORT_TEMPLATE.render(
        vulns=session_payload["vulns"],
        total=session_payload["total"],
        summary=session_payload["summary"],
    )


def render_report_pdf_bytes(session_payload):
    def safe_text(value: Any) -> str:
        if value is None:
            return ""
        return str(value).encode("latin-1", "replace").decode("latin-1")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    def write_block(text: str, height: int = 6):
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.w - pdf.l_margin - pdf.r_margin, height, text)

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "VAPT Consolidated Report", ln=True)

    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Total Findings: {session_payload['total']}", ln=True)
    pdf.ln(2)

    summary = session_payload.get("summary", {})
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Severity Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for severity in ["Critical", "High", "Medium", "Low"]:
        pdf.cell(0, 6, f"- {severity}: {summary.get(severity, 0)}", ln=True)

    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Findings", ln=True)

    for idx, vuln in enumerate(session_payload.get("vulns", []), start=1):
        if pdf.get_y() > 265:
            pdf.add_page()

        title = safe_text(vuln.get("title") or "Untitled finding")
        severity = safe_text(vuln.get("severity") or "Low")
        tool = safe_text(vuln.get("tool") or "Unknown")
        owasp = safe_text(vuln.get("owasp") or "Unknown")
        description = safe_text(vuln.get("description") or "No description provided.")
        fix = safe_text(vuln.get("fix") or "No fix provided.")

        pdf.set_font("Helvetica", "B", 11)
        write_block(f"{idx}. {title}", 7)
        pdf.set_font("Helvetica", "", 10)
        write_block(f"Severity: {severity} | Tool: {tool} | OWASP: {owasp}")
        write_block(f"Description: {description}")
        write_block(f"Fix: {fix}")
        pdf.ln(2)

    raw_pdf = pdf.output(dest="S")
    if isinstance(raw_pdf, str):
        return raw_pdf.encode("latin-1", "replace")
    return bytes(raw_pdf)
