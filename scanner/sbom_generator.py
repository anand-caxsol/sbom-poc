import os, json, subprocess, hashlib
from datetime import datetime

ECOSYSTEM_FILES = {
    "npm": ["package.json", "package-lock.json"],
    "pip": ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py"],
    "maven": ["pom.xml"],
    "gradle": ["build.gradle", "build.gradle.kts"],
    "nuget": [".csproj", "packages.config"],
    "go": ["go.mod"],
    "cargo": ["Cargo.toml"],
    "ruby": ["Gemfile", "Gemfile.lock"],
}

def detect_ecosystems(project_path):
    found = []
    for root, _, files in os.walk(project_path):
        for ecosystem, markers in ECOSYSTEM_FILES.items():
            for marker in markers:
                if any(f == marker or f.endswith(marker) for f in files):
                    if ecosystem not in found:
                        found.append(ecosystem)
    return found

def parse_requirements_txt(path):
    components = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for sep in ["==", ">=", "<=", "~=", "!="]:
                    if sep in line:
                        name, version = line.split(sep, 1)
                        version = version.split(",")[0].strip()
                        components.append({
                            "name": name.strip(),
                            "version": version,
                            "type": "library",
                            "ecosystem": "pip",
                            "purl": f"pkg:pypi/{name.strip().lower()}@{version}",
                        })
                        break
                else:
                    if line and not line.startswith("-"):
                        components.append({
                            "name": line,
                            "version": "unknown",
                            "type": "library",
                            "ecosystem": "pip",
                            "purl": f"pkg:pypi/{line.lower()}@unknown",
                        })
    except Exception:
        pass
    return components

def parse_package_json(path):
    components = []
    try:
        with open(path) as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies"]:
            for name, version in data.get(section, {}).items():
                clean_ver = version.lstrip("^~>=<")
                components.append({
                    "name": name,
                    "version": clean_ver,
                    "type": "library",
                    "ecosystem": "npm",
                    "purl": f"pkg:npm/{name}@{clean_ver}",
                    "dev": section == "devDependencies",
                })
    except Exception:
        pass
    return components

def parse_go_mod(path):
    components = []
    try:
        with open(path) as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                if in_require or line.startswith("require "):
                    parts = line.replace("require ", "").split()
                    if len(parts) >= 2:
                        name, version = parts[0], parts[1]
                        components.append({
                            "name": name,
                            "version": version,
                            "type": "library",
                            "ecosystem": "go",
                            "purl": f"pkg:golang/{name}@{version}",
                        })
    except Exception:
        pass
    return components

def parse_cargo_toml(path):
    components = []
    try:
        with open(path) as f:
            in_deps = False
            for line in f:
                line = line.strip()
                if line in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
                    in_deps = True
                    continue
                if line.startswith("[") and in_deps:
                    in_deps = False
                if in_deps and "=" in line and not line.startswith("#"):
                    name, rest = line.split("=", 1)
                    name = name.strip()
                    version = rest.strip().strip('"').strip("'").split('"')[0]
                    components.append({
                        "name": name,
                        "version": version,
                        "type": "library",
                        "ecosystem": "cargo",
                        "purl": f"pkg:cargo/{name}@{version}",
                    })
    except Exception:
        pass
    return components

def generate_sbom(project_path):
    components = []
    metadata_files = []

    for root, _, files in os.walk(project_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname == "requirements.txt":
                comps = parse_requirements_txt(fpath)
                components.extend(comps)
                metadata_files.append(fpath)
            elif fname == "package.json" and "node_modules" not in root:
                comps = parse_package_json(fpath)
                components.extend(comps)
                metadata_files.append(fpath)
            elif fname == "go.mod":
                comps = parse_go_mod(fpath)
                components.extend(comps)
                metadata_files.append(fpath)
            elif fname == "Cargo.toml":
                comps = parse_cargo_toml(fpath)
                components.extend(comps)
                metadata_files.append(fpath)

    # Deduplicate
    seen = set()
    unique = []
    for c in components:
        key = f"{c['name']}@{c['version']}"
        if key not in seen:
            seen.add(key)
            unique.append(c)

    sbom_id = hashlib.md5(project_path.encode()).hexdigest()[:8]
    ecosystems = detect_ecosystems(project_path)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:sbom-{sbom_id}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "component": {
                "name": os.path.basename(project_path),
                "type": "application",
            },
            "ecosystems": ecosystems,
            "source_files": metadata_files,
        },
        "components": unique,
    }
