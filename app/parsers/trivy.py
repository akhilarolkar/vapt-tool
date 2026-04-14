def parse_trivy(data):
    vulns = []

    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            vulns.append({
                "title": v.get("Title"),
                "severity": v.get("Severity"),
                "cvss": (
                    v.get("CVSS", {})
                    .get("nvd", {})
                    .get("V3Score", 0)
                ),
                "description": v.get("Description"),
                "fix": v.get("FixedVersion"),
                "cve": v.get("VulnerabilityID"),
                "tool": "Trivy"
            })

    return vulns