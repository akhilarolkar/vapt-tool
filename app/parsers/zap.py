def parse_zap(data):
    vulns = []

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            vulns.append({
                "title": alert.get("alert"),
                "severity": alert.get("risk"),
                "cvss": 0,
                "description": alert.get("description"),
                "fix": alert.get("solution"),
                "cve": "",
                "tool": "ZAP"
            })

    return vulns