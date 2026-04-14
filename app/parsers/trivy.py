def _infer_trivy_scan_type(data, result):
    artifact_type = str(data.get("ArtifactType", "")).lower()
    result_type = str(result.get("Type", "")).lower()
    target = str(result.get("Target", "")).lower()

    if artifact_type in {"container_image", "container", "image"}:
        return "Image Scan"
    if artifact_type in {"filesystem", "rootfs", "repository"}:
        return "Filesystem Scan"

    if result_type in {"os-pkgs", "lang-pkgs", "library"}:
        return "Dependency Scan"
    if result_type in {"config", "misconfig"}:
        return "Filesystem Scan"

    if "image" in target:
        return "Image Scan"
    if "rootfs" in target or "filesystem" in target:
        return "Filesystem Scan"

    return "Trivy Scan"


def parse_trivy(data):
    findings = []

    for result in data.get("Results", []):
        scan_type = _infer_trivy_scan_type(data, result)
        result_type = result.get("Type")

        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "title": vuln.get("Title") or vuln.get("PkgName") or vuln.get("VulnerabilityID"),
                "severity": vuln.get("Severity"),
                "cvss": (
                    vuln.get("CVSS", {})
                    .get("nvd", {})
                    .get("V3Score", 0)
                ),
                "description": vuln.get("Description"),
                "fix": vuln.get("FixedVersion"),
                "cve": vuln.get("VulnerabilityID"),
                "tool": "Trivy",
                "scan_type": scan_type,
                "trivy_result_type": result_type,
            })

        for misconfig in result.get("Misconfigurations", []):
            findings.append({
                "title": misconfig.get("Title") or misconfig.get("ID") or "Trivy misconfiguration",
                "severity": misconfig.get("Severity"),
                "cvss": 0,
                "description": misconfig.get("Description") or misconfig.get("Message"),
                "fix": misconfig.get("Resolution"),
                "cve": misconfig.get("ID") or "",
                "tool": "Trivy",
                "scan_type": "Filesystem Scan",
                "trivy_result_type": result_type,
            })

        for secret in result.get("Secrets", []):
            findings.append({
                "title": secret.get("Title") or secret.get("RuleID") or "Trivy secret finding",
                "severity": secret.get("Severity") or "High",
                "cvss": 0,
                "description": secret.get("Match") or secret.get("Category") or "Secret detected",
                "fix": secret.get("RecommendedActions") or "Rotate and revoke exposed secret.",
                "cve": secret.get("RuleID") or "",
                "tool": "Trivy",
                "scan_type": "Filesystem Scan",
                "trivy_result_type": result_type,
            })

    return findings