OWASP_MAP = {
    "SQL Injection": "A03: Injection",
    "Cross Site Scripting": "A03: Injection",
    "Broken Authentication": "A07: Auth Failures"
}

def map_owasp(vulns):
    for v in vulns:
        for key in OWASP_MAP:
            if key.lower() in (v["title"] or "").lower():
                v["owasp"] = OWASP_MAP[key]
                break
        else:
            v["owasp"] = "Unknown"
    return vulns