import os, re, json

LICENSE_RISK = {
    "MIT": "LOW", "Apache-2.0": "LOW", "BSD-2-Clause": "LOW",
    "BSD-3-Clause": "LOW", "ISC": "LOW", "Unlicense": "LOW",
    "CC0-1.0": "LOW", "0BSD": "LOW", "Python-2.0": "LOW",
    "GPL-2.0": "HIGH", "GPL-3.0": "HIGH", "AGPL-3.0": "HIGH",
    "LGPL-2.0": "MEDIUM", "LGPL-2.1": "MEDIUM", "LGPL-3.0": "MEDIUM",
    "MPL-2.0": "MEDIUM", "CDDL-1.0": "MEDIUM", "EPL-1.0": "MEDIUM",
    "EPL-2.0": "MEDIUM", "CC-BY-SA-4.0": "HIGH", "SSPL-1.0": "HIGH",
    "BUSL-1.1": "HIGH", "UNKNOWN": "MEDIUM",
}

LICENSE_PATTERNS = [
    (r"MIT License|Permission is hereby granted, free of charge", "MIT"),
    (r"Apache License.*Version 2\.0", "Apache-2.0"),
    (r"BSD 2-Clause", "BSD-2-Clause"),
    (r"BSD 3-Clause|Neither the name", "BSD-3-Clause"),
    (r"GNU GENERAL PUBLIC LICENSE.*Version 3", "GPL-3.0"),
    (r"GNU GENERAL PUBLIC LICENSE.*Version 2", "GPL-2.0"),
    (r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 3", "LGPL-3.0"),
    (r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 2\.1", "LGPL-2.1"),
    (r"Mozilla Public License.*2\.0", "MPL-2.0"),
    (r"ISC License|ISC", "ISC"),
    (r"The Unlicense|This is free and unencumbered software", "Unlicense"),
    (r"GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0"),
]

def detect_license_from_text(text):
    text_upper = text[:2000]
    for pattern, license_id in LICENSE_PATTERNS:
        if re.search(pattern, text_upper, re.IGNORECASE):
            return license_id
    return "UNKNOWN"

def scan_project_license_files(project_path):
    results = []
    license_filenames = {"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE",
                         "COPYING", "COPYING.txt", "NOTICE", "NOTICE.txt"}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__", "venv", ".venv")]
        for fname in files:
            if fname.upper() in {lf.upper() for lf in license_filenames}:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                    detected = detect_license_from_text(text)
                    rel_path = os.path.relpath(fpath, project_path)
                    results.append({
                        "file": rel_path,
                        "license": detected,
                        "risk": LICENSE_RISK.get(detected, "MEDIUM"),
                        "component": rel_path.split(os.sep)[0] if os.sep in rel_path else os.path.basename(project_path),
                    })
                except Exception:
                    pass
    return results

def get_npm_licenses(project_path):
    pkg_json = os.path.join(project_path, "package.json")
    if not os.path.exists(pkg_json):
        return []
    results = []
    try:
        with open(pkg_json) as f:
            data = json.load(f)
        node_modules = os.path.join(project_path, "node_modules")
        if os.path.isdir(node_modules):
            for pkg_name in os.listdir(node_modules):
                pkg_info = os.path.join(node_modules, pkg_name, "package.json")
                if os.path.exists(pkg_info):
                    try:
                        with open(pkg_info) as f:
                            pkg_data = json.load(f)
                        license_id = pkg_data.get("license", "UNKNOWN")
                        if isinstance(license_id, dict):
                            license_id = license_id.get("type", "UNKNOWN")
                        results.append({
                            "component": pkg_name,
                            "license": license_id or "UNKNOWN",
                            "risk": LICENSE_RISK.get(license_id, "MEDIUM"),
                            "file": f"node_modules/{pkg_name}/package.json",
                        })
                    except Exception:
                        pass
    except Exception:
        pass
    return results

def scan_licenses(project_path):
    results = []
    results.extend(scan_project_license_files(project_path))
    results.extend(get_npm_licenses(project_path))

    if not results:
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__", "venv")]
            for fname in files:
                if fname in ("requirements.txt", "package.json", "go.mod", "Cargo.toml"):
                    results.append({
                        "file": os.path.relpath(os.path.join(root, fname), project_path),
                        "license": "NOT_DETECTED",
                        "risk": "MEDIUM",
                        "component": os.path.basename(project_path),
                        "note": "No LICENSE file found near this manifest",
                    })

    return results

def get_license_summary(licenses):
    counts = {}
    for l in licenses:
        lic = l.get("license", "UNKNOWN")
        counts[lic] = counts.get(lic, 0) + 1
    return counts
