from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from pathlib import Path

REPORTS_DIR = Path("reports")
TEMPLATE_ENV = Environment(loader=FileSystemLoader("app/reports/templates"))
REPORT_TEMPLATE = TEMPLATE_ENV.get_template("report.html")


def generate_report(vulns, report_id):
    summary = {}
    for v in vulns:
        summary[v["severity"]] = summary.get(v["severity"], 0) + 1

    html_content = REPORT_TEMPLATE.render(
        vulns=vulns,
        total=len(vulns),
        summary=summary
    )

    REPORTS_DIR.mkdir(exist_ok=True)
    html_filename = f"{report_id}.html"
    pdf_filename = f"{report_id}.pdf"
    html_path = REPORTS_DIR / html_filename
    pdf_path = REPORTS_DIR / pdf_filename

    # Save HTML
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Generate PDF
    HTML(string=html_content).write_pdf(str(pdf_path))

    return {
        "html": html_filename,
        "pdf": pdf_filename
    }
