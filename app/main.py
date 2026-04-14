import asyncio
import json
import uuid
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.parsers.trivy import parse_trivy
from app.parsers.zap import parse_zap
from app.parsers.bandit import parse_bandit
from app.core.normalize import normalize
from app.core.owasp import map_owasp
from app.reports.generator import generate_report

app = FastAPI()

templates = Jinja2Templates(directory="app/ui/templates")
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

# Serve generated reports
app.mount("/reports", StaticFiles(directory=str(REPORTS_DIR)), name="reports")


def detect_and_parse(data):
    if "Results" in data:
        return parse_trivy(data)
    elif "site" in data:
        return parse_zap(data)
    elif "results" in data and "metrics" in data:
        return parse_bandit(data)
    return None


def parse_upload_content(filename: str, content: bytes):
    try:
        data = json.loads(content)
    except Exception:
        return [], [f"{filename}: invalid JSON"], []

    parsed_vulns = detect_and_parse(data)
    if not parsed_vulns:
        return [], [f"{filename}: unsupported report format"], []

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

    summary = {}
    for vuln in mapped_vulns:
        summary[vuln["severity"]] = summary.get(vuln["severity"], 0) + 1

    return mapped_vulns, summary


@app.post("/upload")
async def upload(files: list[UploadFile] = File(...)):
    vulns, errors, uploaded_files = await collect_vulnerabilities(files)
    if not vulns:
        return {"error": "No supported JSON reports found", "details": errors}

    vulns, _summary = await asyncio.to_thread(prepare_vulnerabilities, vulns)

    report_id = str(uuid.uuid4())
    report_paths = await asyncio.to_thread(generate_report, vulns, report_id)

    return {
        "message": "Combined report generated",
        "processed_files": uploaded_files,
        "errors": errors,
        "html_report": f"/reports/{report_paths['html']}",
        "pdf_report": f"/reports/{report_paths['pdf']}",
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
        },
    )


@app.post("/upload-ui", response_class=HTMLResponse)
async def upload_ui(request: Request, files: list[UploadFile] = File(...)):
    vulns, errors, uploaded_files = await collect_vulnerabilities(files)
    if not vulns:
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "request": request,
                "errors": errors or ["No supported JSON reports found"],
                "uploaded_files": uploaded_files,
            },
        )

    vulns, summary = await asyncio.to_thread(prepare_vulnerabilities, vulns)

    report_id = str(uuid.uuid4())
    report_paths = await asyncio.to_thread(generate_report, vulns, report_id)

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
            "pdf": f"/reports/{report_paths['pdf']}",
            "html": f"/reports/{report_paths['html']}",
        },
    )
