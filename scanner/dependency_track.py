import requests, base64, time

def _sanitize_for_cyclonedx(sbom_dict):
    """Strip non-schema fields before sending to Dependency-Track."""
    import copy
    clean = copy.deepcopy(sbom_dict)
    clean.pop("ecosystems", None)
    clean["metadata"].pop("ecosystems", None)
    clean["metadata"].pop("source_files", None)
    for c in clean.get("components", []):
        c.pop("ecosystem", None)
        c.pop("dev", None)
    return clean

def upload_sbom(sbom_dict, project_name, project_version="1.0.0"):
    """
    Uploads a CycloneDX SBOM to Dependency-Track.
    Creates the project automatically if it doesn't exist.
    Returns the upload token used to poll processing status.
    """
    import config, json
    headers = {
        "X-Api-Key": config.DTRACK_API_KEY,
        "Content-Type": "application/json",
    }
    clean_sbom = _sanitize_for_cyclonedx(sbom_dict)
    bom_json = json.dumps(clean_sbom)
    bom_b64  = base64.b64encode(bom_json.encode("utf-8")).decode("utf-8")

    payload = {
        "projectName": project_name,
        "projectVersion": project_version,
        "autoCreate": True,
        "bom": bom_b64,
    }

    resp = requests.put(
        f"{config.DTRACK_BASE_URL}/api/v1/bom",
        json=payload,
        headers=headers,
        timeout=30,
    )
    if resp.status_code != 200:
        print("DTRACK BOM UPLOAD REJECTED:")
        print(f"  Status: {resp.status_code}")
        print(f"  Body:   {resp.text}")
    resp.raise_for_status()
    return resp.json().get("token")


def wait_for_processing(token, timeout=60, interval=2):
    """Polls Dependency-Track until BOM processing finishes."""
    import config
    headers = {"X-Api-Key": config.DTRACK_API_KEY}
    elapsed = 0
    while elapsed < timeout:
        resp = requests.get(
            f"{config.DTRACK_BASE_URL}/api/v1/bom/token/{token}",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            if not resp.json().get("processing", True):
                return True
        time.sleep(interval)
        elapsed += interval
    return False


def get_project_uuid(project_name, project_version="1.0.0"):
    import config
    headers = {"X-Api-Key": config.DTRACK_API_KEY}
    resp = requests.get(
        f"{config.DTRACK_BASE_URL}/api/v1/project/lookup",
        headers=headers,
        params={"name": project_name, "version": project_version},
        timeout=10,
    )
    if resp.status_code != 200:
        return None
    return resp.json().get("uuid")


def get_project_findings(project_uuid):
    """Returns vulnerability findings for a project from Dependency-Track."""
    import config
    headers = {"X-Api-Key": config.DTRACK_API_KEY}
    resp = requests.get(
        f"{config.DTRACK_BASE_URL}/api/v1/finding/project/{project_uuid}",
        headers=headers,
        timeout=15,
    )
    if resp.status_code != 200:
        return []

    findings = []
    for f in resp.json():
        vuln = f.get("vulnerability", {})
        component = f.get("component", {})
        analysis = f.get("analysis", {})

        findings.append({
            "id": vuln.get("vulnId", ""),
            "aliases": [a.get("vulnId") for a in vuln.get("aliases", [])] if vuln.get("aliases") else [vuln.get("vulnId", "")],
            "summary": vuln.get("description", vuln.get("title", "No description")) or "No description",
            "severity": (vuln.get("severity") or "UNKNOWN").upper(),
            "component": component.get("name", ""),
            "version": component.get("version", ""),
            "ecosystem": component.get("purl", "").split(":")[1].split("/")[0] if component.get("purl") else "unknown",
            "purl": component.get("purl", ""),
            "cvss_score": vuln.get("cvssV3BaseScore") or vuln.get("cvssV2BaseScore"),
            "is_suppressed": analysis.get("isSuppressed", False),
            "references": [vuln.get("source", "")],
        })
    return findings


def get_project_metrics(project_uuid):
    """Returns summary metrics (risk score, counts) for a project."""
    import config
    headers = {"X-Api-Key": config.DTRACK_API_KEY}
    resp = requests.get(
        f"{config.DTRACK_BASE_URL}/api/v1/metrics/project/{project_uuid}/current",
        headers=headers,
        timeout=10,
    )
    if resp.status_code != 200:
        return {}
    return resp.json()


def get_project_components(project_uuid):
    """Returns the component inventory Dependency-Track parsed from the SBOM."""
    import config
    headers = {"X-Api-Key": config.DTRACK_API_KEY}
    resp = requests.get(
        f"{config.DTRACK_BASE_URL}/api/v1/component/project/{project_uuid}",
        headers=headers,
        params={"pageSize": 500},
        timeout=15,
    )
    if resp.status_code != 200:
        return []

    components = []
    for c in resp.json():
        components.append({
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "purl": c.get("purl", ""),
            "ecosystem": c.get("purl", "").split(":")[1].split("/")[0] if c.get("purl") else "unknown",
        })
    return components


def scan_via_dependency_track(sbom, project_name, project_version="1.0.0"):
    """
    Full pipeline: upload SBOM, wait for processing, pull back
    findings/components/metrics. Returns the same shape your
    Flask /scan route already expects from the old OSV-based path.
    """
    token = upload_sbom(sbom, project_name, project_version)
    wait_for_processing(token)

    project_uuid = get_project_uuid(project_name, project_version)
    if not project_uuid:
        raise RuntimeError("Dependency-Track did not create the project as expected")

    vulns = get_project_findings(project_uuid)
    components = get_project_components(project_uuid)
    metrics = get_project_metrics(project_uuid)

    return {
        "vulnerabilities": vulns,
        "components": components,
        "metrics": metrics,
        "project_uuid": project_uuid,
        "dtrack_url": f"{__import__('config').DTRACK_BASE_URL.replace('8081','8082')}/projects/{project_uuid}",
    }