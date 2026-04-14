def parse_bandit(data):
    vulns = []

    for issue in data.get("results", []):
        filename = issue.get("filename", "")
        line_number = issue.get("line_number")
        location = filename
        if filename and line_number:
            location = f"{filename}:{line_number}"

        title = issue.get("test_name") or issue.get("test_id") or "Bandit finding"
        description = issue.get("issue_text") or ""
        if location:
            description = f"{description} ({location})".strip()

        vulns.append({
            "title": title,
            "severity": issue.get("issue_severity"),
            "cvss": 0,
            "description": description,
            "fix": issue.get("more_info", ""),
            "cve": issue.get("test_id", ""),
            "tool": "Bandit",
        })

    return vulns
