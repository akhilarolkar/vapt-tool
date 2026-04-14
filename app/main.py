import asyncio
import json
import uuid

from fastapi import FastAPI, UploadFile, File, Request, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates

from app.parsers.trivy import parse_trivy
from app.parsers.zap import parse_zap
from app.parsers.bandit import parse_bandit
from app.core.normalize import normalize
from app.core.owasp import map_owasp
from app.reports.generator import (
    create_report_session,
    get_or_render_report_html,
    get_cached_report_pdf,
    get_report_pdf_status,
    get_report_session,
    get_session_ttl_minutes,
    prime_report_pdf_cache,
)

app = FastAPI()

templates = Jinja2Templates(directory="app/ui/templates")


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def empty_summary():
    return {severity: 0 for severity in SEVERITY_ORDER}


def infer_scan_type_from_filename(filename: str, tool: str):
    name = (filename or "").lower()
    if tool == "Bandit":
        return "SAST"
    if tool == "ZAP":
        return "DAST"
    if tool == "Trivy":
        if "image" in name:
            return "Image Scan"
        if "fs" in name or "filesystem" in name or "rootfs" in name:
            return "Filesystem Scan"
        if "dep" in name or "dependency" in name:
            return "Dependency Scan"
        return "Trivy Scan"
    return "Unknown"


def detect_and_parse(data):
    if "Results" in data:
        return True, parse_trivy(data)
    elif "SchemaVersion" in data and isinstance(data.get("Results"), list):
        return True, parse_trivy(data)
    elif "site" in data:
        return True, parse_zap(data)
    elif "results" in data and "metrics" in data:
        return True, parse_bandit(data)
    return False, []


def parse_upload_content(filename: str, content: bytes):
    try:
        data = json.loads(content)
    except Exception:
        return [], [f"{filename}: invalid JSON"], []

    recognized, parsed_vulns = detect_and_parse(data)
    if not recognized:
        return [], [f"{filename}: unsupported report format"], []

    for vuln in parsed_vulns:
        vuln["source_file"] = filename
        if not vuln.get("scan_type"):
            vuln["scan_type"] = infer_scan_type_from_filename(filename, vuln.get("tool", "Unknown"))

    return parsed_vulns, [], [filename]


async def process_upload_file(file: UploadFile):
    filename = file.filename or "unnamed.json"

    if not filename.endswith(".json"):
        return [], [f"{filename}: only JSON files are allowed"], []

    content = await file.read()
    return await asyncio.to_thread(parse_upload_content, filename, content)


async def collect_vulnerabilities(files: list[UploadFile]):
    vulns = []
    errors = []
    uploaded_files = []

    results = await asyncio.gather(*(process_upload_file(file) for file in files))

    for parsed_vulns, file_errors, accepted_files in results:
        vulns.extend(parsed_vulns)
        errors.extend(file_errors)
        uploaded_files.extend(accepted_files)

    return vulns, errors, uploaded_files


def prepare_vulnerabilities(vulns):
    normalized_vulns = normalize(vulns)
    mapped_vulns = map_owasp(normalized_vulns)

    summary = empty_summary()
    for vuln in mapped_vulns:
        severity = vuln.get("severity", "Low")
        summary[severity] = summary.get(severity, 0) + 1

    grouped_map = {}
    for vuln in mapped_vulns:
        source_file = vuln.get("source_file", "Unknown file")
        group = grouped_map.setdefault(
            source_file,
            {
                "source_file": source_file,
                "tool": vuln.get("tool", "Unknown"),
                "scan_type": vuln.get("scan_type") or infer_scan_type_from_filename(source_file, vuln.get("tool", "Unknown")),
                "summary": empty_summary(),
                "findings": [],
                "total": 0,
            },
        )
        severity = vuln.get("severity", "Low")
        group["summary"][severity] = group["summary"].get(severity, 0) + 1
        group["findings"].append(vuln)
        group["total"] += 1

    grouped_reports = sorted(grouped_map.values(), key=lambda item: item["source_file"].lower())

    scan_summary_map = {}
    for vuln in mapped_vulns:
        scan_type = vuln.get("scan_type") or "Unknown"
        row = scan_summary_map.setdefault(
            scan_type,
            {
                "scan_type": scan_type,
                "summary": empty_summary(),
                "total": 0,
            },
        )
        severity = vuln.get("severity", "Low")
        row["summary"][severity] = row["summary"].get(severity, 0) + 1
        row["total"] += 1

    scan_summary = sorted(scan_summary_map.values(), key=lambda item: item["scan_type"].lower())

    grand_total = {
        "scan_type": "Grand Total",
        "summary": summary,
        "total": len(mapped_vulns),
    }

    return mapped_vulns, summary, grouped_reports, scan_summary, grand_total


@app.post("/upload")
async def upload(background_tasks: BackgroundTasks, files: list[UploadFile] = File(...)):
    vulns, errors, uploaded_files = await collect_vulnerabilities(files)
    if not vulns:
        return {"error": "No supported JSON reports found", "details": errors}

    vulns, _summary, _grouped_reports, _scan_summary, _grand_total = await asyncio.to_thread(prepare_vulnerabilities, vulns)

    report_id = str(uuid.uuid4())
    await asyncio.to_thread(create_report_session, report_id, vulns, uploaded_files, errors)
    background_tasks.add_task(prime_report_pdf_cache, report_id)

    return {
        "message": "Combined report prepared. Themed PDF is being generated in background.",
        "processed_files": uploaded_files,
        "errors": errors,
        "session_id": report_id,
        "html_report": f"/reports/{report_id}/html",
        "pdf_report": f"/reports/{report_id}/pdf",
        "pdf_status": f"/reports/{report_id}/pdf-status",
        "report_session_ttl_minutes": get_session_ttl_minutes(),
        "total_vulnerabilities": len(vulns)
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "errors": [],
            "uploaded_files": [],
            "grouped_reports": [],
            "scan_summary": [],
            "grand_total": {"scan_type": "Grand Total", "summary": empty_summary(), "total": 0},
            "severity_order": SEVERITY_ORDER,
        },
    )


@app.post("/upload-ui", response_class=HTMLResponse)
async def upload_ui(request: Request, background_tasks: BackgroundTasks, files: list[UploadFile] = File(...)):
    vulns, errors, uploaded_files = await collect_vulnerabilities(files)
    if not vulns:
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "request": request,
                "errors": errors or ["No supported JSON reports found"],
                "uploaded_files": uploaded_files,
                "grouped_reports": [],
                "scan_summary": [],
                "grand_total": {"scan_type": "Grand Total", "summary": empty_summary(), "total": 0},
                "severity_order": SEVERITY_ORDER,
            },
        )

    vulns, summary, grouped_reports, scan_summary, grand_total = await asyncio.to_thread(prepare_vulnerabilities, vulns)

    report_id = str(uuid.uuid4())
    await asyncio.to_thread(create_report_session, report_id, vulns, uploaded_files, errors)
    background_tasks.add_task(prime_report_pdf_cache, report_id)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "vulns": vulns,
            "summary": summary,
            "total": len(vulns),
            "errors": errors,
            "uploaded_files": uploaded_files,
            "grouped_reports": grouped_reports,
            "scan_summary": scan_summary,
            "grand_total": grand_total,
            "severity_order": SEVERITY_ORDER,
            "pdf": f"/reports/{report_id}/pdf",
            "html": f"/reports/{report_id}/html",
            "report_session_id": report_id,
            "pdf_status_url": f"/reports/{report_id}/pdf-status",
            "report_session_ttl_minutes": get_session_ttl_minutes(),
        },
    )


@app.get("/reports/{session_id}/html", response_class=HTMLResponse)
async def view_report_html(session_id: str):
    session = await asyncio.to_thread(get_report_session, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Report session not found or expired.")

    html_content = await asyncio.to_thread(get_or_render_report_html, session_id)
    if not html_content:
        raise HTTPException(status_code=404, detail="Report session not found or expired.")
    return HTMLResponse(content=html_content)


@app.get("/reports/{session_id}/pdf-status")
async def report_pdf_status(session_id: str):
    status = await asyncio.to_thread(get_report_pdf_status, session_id)
    if not status:
        raise HTTPException(status_code=404, detail="Report session not found or expired.")
    return JSONResponse(content=status)


@app.get("/reports/{session_id}/pdf")
async def download_report_pdf(session_id: str):
    session = await asyncio.to_thread(get_report_session, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Report session not found or expired.")

    status = await asyncio.to_thread(get_report_pdf_status, session_id)
    if not status:
        raise HTTPException(status_code=404, detail="Report session not found or expired.")

    if status["status"] in {"queued", "processing"}:
        return JSONResponse(
            status_code=202,
            content={
                "message": "Themed PDF is still being prepared. Please retry in a few seconds.",
                "status": status["status"],
            },
            headers={"Retry-After": "3"},
        )

    if status["status"] == "failed":
        await asyncio.to_thread(prime_report_pdf_cache, session_id)
        status = await asyncio.to_thread(get_report_pdf_status, session_id)
        if not status or status["status"] != "ready":
            raise HTTPException(status_code=500, detail="Failed to generate themed PDF.")

    pdf_bytes = await asyncio.to_thread(get_cached_report_pdf, session_id)
    if not pdf_bytes:
        await asyncio.to_thread(prime_report_pdf_cache, session_id)
        pdf_bytes = await asyncio.to_thread(get_cached_report_pdf, session_id)
        if not pdf_bytes:
            raise HTTPException(status_code=500, detail="Failed to generate themed PDF.")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="vapt-report-{session_id}.pdf"'
        },
    )
