import subprocess, json, tempfile, shutil, os
from pathlib import Path

LICENSE_FILENAME_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE")

LICENSE_EXACT_NAMES = {
    "license", "licence", "copying", "notice",
    "license.txt", "licence.txt", "copying.txt", "notice.txt",
    "license.md", "licence.md", "notice.md",
    "license-mit", "license-apache", "license-bsd",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".next", "vendor", "target", ".tox",
}

def _resolve_scancode():
    import shutil as sh
    exe = sh.which("scancode")
    if not exe:
        raise RuntimeError(
            "scancode not found in PATH. Run: pip install scancode-toolkit"
        )
    return exe

def _is_license_file(fname: str) -> bool:
    lower = fname.lower()
    if lower in LICENSE_EXACT_NAMES:
        return True
    if any(lower.startswith(p.lower()) for p in LICENSE_FILENAME_PREFIXES):
        return True
    return False

def _collect_scannable_files(source_path: str) -> list:
    matches = []
    for root, dirs, files in os.walk(source_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            if _is_license_file(fname):
                matches.append(os.path.join(root, fname))
    return matches

def run_scancode_on_path(source_path: str, policy_path: str = None) -> dict:
    from scanner.scancode_core import normalize_scan
    from scanner.report_generator import load_policy

    policy       = load_policy(Path(policy_path) if policy_path else None)
    exe          = _resolve_scancode()
    target_files = _collect_scannable_files(source_path)

    print(f"[SCANCODE] Found {len(target_files)} license files to scan:")
    for f in target_files:
        print(f"  → {f}")

    if not target_files:
        return {
            "files": [], 
            "stats": {"pass": 0, "review": 0, "fail": 0, "total": 0},
            "gate_status": "pass"
        }

    with tempfile.TemporaryDirectory(prefix="sbom_scancode_") as tmpdir:
        raw_output  = Path(tmpdir) / "scancode_raw.json"

        # Write file list to a text file — avoids Windows command line
        # length limit (WinError 206) when there are many files
        # filelist_path = Path(tmpdir) / "filelist.txt"
        # filelist_path.write_text(
        #     "\n".join(target_files), encoding="utf-8"
        # )
        import shutil as _shutil
        for fpath in target_files:
            rel      = os.path.relpath(fpath, source_path)
            dest     = os.path.join(tmpdir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            _shutil.copy2(fpath, dest)

        cmd = [
            exe,
            "--license",
            "--copyright",
            "--json-pp", str(raw_output),
            "--processes", "1",
            "--timeout", "10",
            "--quiet",
            # "--from-list", str(filelist_path),
            tmpdir,
        ]

        print(f"[SCANCODE] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, timeout=60,
                capture_output=True, text=True
            )
            # ScanCode exits non-zero on scan errors but still
            # produces output — only raise if no output at all
            if result.returncode != 0 and not raw_output.exists():
                raise RuntimeError(f"ScanCode failed: {result.stderr[:300]}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("ScanCode timed out after 60s")

        if not raw_output.exists():
            raise RuntimeError("ScanCode produced no output file")

        with open(raw_output, encoding="utf-8") as f:
            raw_scan = json.load(f)
            print(f"[SCANCODE] Scan complete. Files in result: {len(raw_scan.get('files', []))}")
            print(f"[SCANCODE] Gate status: {normalized.get('gate')} | Files scanned: {len(raw_scan.get('files', []))}")
            print(f"[SCANCODE] Counts: {normalized.get('counts')}")

    return normalize_scan(raw_scan, policy)

def run_scancode_on_repo_files(file_contents: dict, policy_path: str = None) -> dict:

    tmpdir = tempfile.mkdtemp(prefix="sbom_sc_repo_")
    try:
        for rel_path, content in file_contents.items():
            full_path = os.path.join(tmpdir, rel_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
        return run_scancode_on_path(tmpdir, policy_path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def run_scancode_on_github_repo(access_token, full_name, branch="main", policy_path=None):
    """
    Fetches only license files from GitHub repo and runs ScanCode on them.
    Much faster than downloading everything.
    """
    from scanner.scancode_core import normalize_scan
    from scanner.report_generator import load_policy
    from scanner.github_fetcher import fetch_license_files, fetch_file_content

    policy        = load_policy(Path(policy_path) if policy_path else None)
    exe           = _resolve_scancode()
    license_paths = fetch_license_files(access_token, full_name, branch)

    print(f"[SCANCODE] Found {len(license_paths)} license files in {full_name}:")
    for p in license_paths:
        print(f"  → {p}")

    if not license_paths:
        return {
            "files": [],
            "stats": {"pass": 0, "review": 0, "fail": 0, "total": 0},
            "gate_status": "pass"
        }

    tmpdir = tempfile.mkdtemp(prefix="sbom_sc_gh_")
    try:
        # Write fetched license files to temp dir
        written = []
        for path in license_paths:
            content = fetch_file_content(access_token, full_name, path)
            if content is None:
                continue
            local_path = os.path.join(tmpdir, path)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(content)
            written.append(local_path)

        print(f"[SCANCODE] Written {len(written)} files to temp dir, running scan...")

        if not written:
            return {"files": [], "stats": {"pass":0,"review":0,"fail":0,"total":0}, "gate_status": "pass"}

        raw_output    = Path(tmpdir) / "scancode_raw.json"
        # filelist_path = Path(tmpdir) / "filelist.txt"
        # filelist_path.write_text("\n".join(written), encoding="utf-8")

        cmd = [
            exe,
            "--license", "--copyright",
            "--json-pp", str(raw_output),
            "--processes", "1",
            "--timeout", "10",
            "--quiet",
            # "--from-list", str(filelist_path),
            tmpdir,
        ]

        print(f"[SCANCODE] Command: {' '.join(cmd)}")

        result = subprocess.run(cmd, timeout=60, capture_output=True, text=True)
        if result.returncode != 0 and not raw_output.exists():
            raise RuntimeError(f"ScanCode failed: {result.stderr[:300]}")

        if not raw_output.exists():
            raise RuntimeError("ScanCode produced no output")

        with open(raw_output, encoding="utf-8") as f:
            raw_scan = json.load(f)

        normalized = normalize_scan(raw_scan, policy)
        normalized = normalize_scan(raw_scan, policy)
        print(f"[SCANCODE] Full normalized keys: {list(normalized.keys())}")
        print(f"[SCANCODE] Stats: {normalized.get('stats')}")
        print(f"[SCANCODE] Gate: {normalized.get('gate_status')}")
        print(f"[SCANCODE] First file sample: {normalized.get('files', [{}])[0]}")

        print(f"[SCANCODE] Gate status: {normalized.get('gate')} | Files scanned: {len(raw_scan.get('files', []))}")
        print(f"[SCANCODE] Counts: {normalized.get('counts')}")

        print(f"[SCANCODE] Gate value: {normalized.get('gate')}")
        print(f"[SCANCODE] Counts: {normalized.get('counts')}")
        print(f"[SCANCODE] Findings count: {len(normalized.get('findings', []))}")
        print(f"[SCANCODE] Components count: {len(normalized.get('components', []))}")
        if normalized.get('findings'):
            print(f"[SCANCODE] First finding: {normalized['findings'][0]}")

        return normalized

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def format_for_dashboard(normalized: dict) -> list:
    """
    Converts normalized ScanCode report to dashboard license list.
    Handles both key naming conventions.
    """
    STATUS_TO_RISK = {"fail": "HIGH", "review": "MEDIUM", "pass": "LOW"}

    # support both naming conventions
    findings = normalized.get("findings") or normalized.get("files", [])
    results  = []

    for finding in findings:
        licenses = (
            finding.get("license_expressions")
            or finding.get("licenses")
            or []
        )
        status = (
            finding.get("policy_status")
            or finding.get("status")
            or "review"
        )
        risk = STATUS_TO_RISK.get(status, "MEDIUM")

        results.append({
            "file":      finding.get("path", finding.get("file", "")),
            "component": finding.get("component", ""),
            "license":   ", ".join(licenses) if licenses else "NOT_DETECTED",
            "risk":      risk,
            "copyrights": finding.get("copyrights", []),
            "holders":    finding.get("holders", []),
            "reasons":    finding.get("reasons", []),
            "status":     status,
        })

    return results

def get_summary(normalized: dict) -> dict:
    """Returns gate status + counts. Handles both key naming conventions."""

    # actual keys from their normalize_scan output
    gate   = normalized.get("gate") or normalized.get("gate_status") or "unknown"
    counts = normalized.get("counts") or normalized.get("stats") or {}

    return {
        "gate_status": gate,
        "pass":        counts.get("pass", 0),
        "review":      counts.get("review", 0),
        "fail":        counts.get("fail", 0),
        "total":       counts.get("total", 0),
    }