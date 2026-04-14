import time
from threading import Lock

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

TEMPLATE_ENV = Environment(loader=FileSystemLoader("app/reports/templates"))
REPORT_TEMPLATE = TEMPLATE_ENV.get_template("report.html")
PDF_TEMPLATE = TEMPLATE_ENV.get_template("report_pdf.html")

SESSION_TTL_SECONDS = 10 * 60
PDF_GENERATION_TIMEOUT_SECONDS = 120
MAX_SESSION_COUNT = 100

_SESSION_LOCK = Lock()
_REPORT_SESSIONS: dict[str, dict[str, object]] = {}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def _build_summary(vulns):
    summary = {severity: 0 for severity in SEVERITY_ORDER}
    for vuln in vulns:
        severity = vuln.get("severity", "Low")
        summary[severity] = summary.get(severity, 0) + 1
    return summary


def _build_group_context(vulns):
    grouped_map = {}
    scan_summary_map = {}

    for vuln in vulns:
        source_file = vuln.get("source_file", "Unknown file")
        scan_type = vuln.get("scan_type", "Unknown")
        severity = vuln.get("severity", "Low")

        group = grouped_map.setdefault(
            source_file,
            {
                "source_file": source_file,
                "tool": vuln.get("tool", "Unknown"),
                "scan_type": scan_type,
                "summary": {label: 0 for label in SEVERITY_ORDER},
                "findings": [],
                "total": 0,
            },
        )
        group["summary"][severity] = group["summary"].get(severity, 0) + 1
        group["findings"].append(vuln)
        group["total"] += 1

        row = scan_summary_map.setdefault(
            scan_type,
            {
                "scan_type": scan_type,
                "summary": {label: 0 for label in SEVERITY_ORDER},
                "total": 0,
            },
        )
        row["summary"][severity] = row["summary"].get(severity, 0) + 1
        row["total"] += 1

    grouped_reports = sorted(grouped_map.values(), key=lambda item: item["source_file"].lower())
    scan_summary = sorted(scan_summary_map.values(), key=lambda item: item["scan_type"].lower())
    grand_total = {
        "scan_type": "Grand Total",
        "summary": _build_summary(vulns),
        "total": len(vulns),
    }
    return grouped_reports, scan_summary, grand_total


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
        "html_cache": None,
        "pdf_cache": None,
        "pdf_status": "queued",
        "pdf_error": None,
        "pdf_started_at": None,
        "pdf_updated_at": None,
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


def get_session_ttl_minutes():
    return SESSION_TTL_SECONDS // 60


def render_report_html(session_payload):
    grouped_reports, scan_summary, grand_total = _build_group_context(session_payload["vulns"])
    return REPORT_TEMPLATE.render(
        vulns=session_payload["vulns"],
        total=session_payload["total"],
        summary=session_payload["summary"],
        grouped_reports=grouped_reports,
        scan_summary=scan_summary,
        grand_total=grand_total,
        severity_order=SEVERITY_ORDER,
    )


def render_report_pdf_html(session_payload):
    grouped_reports, scan_summary, grand_total = _build_group_context(session_payload["vulns"])
    return PDF_TEMPLATE.render(
        vulns=session_payload["vulns"],
        total=session_payload["total"],
        summary=session_payload["summary"],
        grouped_reports=grouped_reports,
        scan_summary=scan_summary,
        grand_total=grand_total,
        severity_order=SEVERITY_ORDER,
    )


def _get_or_build_html_cache(session_id: str):
    with _SESSION_LOCK:
        payload = _REPORT_SESSIONS.get(session_id)
        if not payload:
            return None
        if payload["html_cache"]:
            return payload["html_cache"]

    html_content = render_report_html(payload)

    with _SESSION_LOCK:
        current = _REPORT_SESSIONS.get(session_id)
        if not current:
            return None
        if not current["html_cache"]:
            current["html_cache"] = html_content
        return current["html_cache"]


def prime_report_pdf_cache(session_id: str):
    now = time.time()
    with _SESSION_LOCK:
        payload = _REPORT_SESSIONS.get(session_id)
        if not payload:
            return

        if payload["pdf_status"] == "ready" and payload["pdf_cache"]:
            return

        if payload["pdf_status"] == "processing":
            started_at = payload.get("pdf_started_at")
            if started_at and now - started_at <= PDF_GENERATION_TIMEOUT_SECONDS:
                return

        payload["pdf_status"] = "processing"
        payload["pdf_error"] = None
        payload["pdf_started_at"] = now

    try:
        payload = get_report_session(session_id)
        if not payload:
            raise RuntimeError("Report session not found or expired.")

        pdf_html_content = render_report_pdf_html(payload)
        pdf_bytes = HTML(string=pdf_html_content).write_pdf()
    except Exception as exc:
        with _SESSION_LOCK:
            payload = _REPORT_SESSIONS.get(session_id)
            if not payload:
                return
            payload["pdf_status"] = "failed"
            payload["pdf_error"] = str(exc)
            payload["pdf_started_at"] = None
            payload["pdf_updated_at"] = time.time()
        return

    with _SESSION_LOCK:
        payload = _REPORT_SESSIONS.get(session_id)
        if not payload:
            return
        payload["pdf_cache"] = pdf_bytes
        payload["pdf_status"] = "ready"
        payload["pdf_error"] = None
        payload["pdf_started_at"] = None
        payload["pdf_updated_at"] = time.time()


def get_report_pdf_status(session_id: str):
    now = time.time()
    with _SESSION_LOCK:
        _prune_sessions(now)
        payload = _REPORT_SESSIONS.get(session_id)
        if not payload:
            return None

        if payload["pdf_status"] == "processing":
            started_at = payload.get("pdf_started_at")
            if started_at and now - started_at > PDF_GENERATION_TIMEOUT_SECONDS:
                payload["pdf_status"] = "failed"
                payload["pdf_error"] = "PDF generation timed out. Please retry download."
                payload["pdf_started_at"] = None
                payload["pdf_updated_at"] = now

        return {
            "status": payload["pdf_status"],
            "ready": payload["pdf_status"] == "ready" and payload["pdf_cache"] is not None,
            "error": payload["pdf_error"],
        }


def get_cached_report_pdf(session_id: str):
    now = time.time()
    with _SESSION_LOCK:
        _prune_sessions(now)
        payload = _REPORT_SESSIONS.get(session_id)
        if not payload:
            return None
        return payload["pdf_cache"]


def get_or_render_report_html(session_id: str):
    now = time.time()
    with _SESSION_LOCK:
        _prune_sessions(now)
        payload = _REPORT_SESSIONS.get(session_id)
        if not payload:
            return None
        cached = payload.get("html_cache")

    if cached:
        return cached

    return _get_or_build_html_cache(session_id)
