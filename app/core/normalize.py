def normalize(vulns):
    severity_aliases = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Low",
        "informational": "Low",
    }

    for v in vulns:
        severity = v.get("severity")
        if isinstance(severity, str):
            normalized = severity_aliases.get(severity.strip().lower())
            if normalized:
                v["severity"] = normalized

        if not v.get("severity"):
            cvss = v.get("cvss", 0)
            if cvss >= 9:
                v["severity"] = "Critical"
            elif cvss >= 7:
                v["severity"] = "High"
            elif cvss >= 4:
                v["severity"] = "Medium"
            else:
                v["severity"] = "Low"

    return vulns
