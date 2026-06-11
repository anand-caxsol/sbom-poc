# SBOM Vulnerability Scanner — POC

A Python-based SBOM toolchain POC with a real-time vulnerability dashboard.

## Stack
- **Backend**: Python + Flask
- **SBOM Generation**: Custom parser (requirements.txt, package.json, go.mod, Cargo.toml)
- **Vulnerability Scanning**: OSV.dev API (free, no key needed)
- **License Detection**: File-based regex scanner
- **Frontend**: Vanilla JS + Chart.js dashboard

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
python app.py

# 3. Open browser
http://localhost:5000

# 4. Enter a project path and click Scan
```

## Supported Ecosystems

| File | Ecosystem |
|------|-----------|
| requirements.txt | Python (PyPI) |
| package.json | Node.js (npm) |
| go.mod | Go modules |
| Cargo.toml | Rust (crates.io) |

## Dashboard Features

- **Summary cards** — total components, critical/high/medium/low CVEs, license issues
- **Severity chart** — doughnut breakdown of vulnerability severity
- **Ecosystem chart** — bar chart of detected package ecosystems
- **Vulnerabilities table** — filterable by severity, links to NVD/OSV
- **Component inventory** — all packages with PURL, filterable by ecosystem
- **License compliance** — detected licenses with risk level (GPL = HIGH, MIT = LOW, etc.)
- **Export SBOM** — download CycloneDX JSON

## Architecture

```
Project Path (input)
      ↓
sbom_generator.py   → Parses manifest files → CycloneDX SBOM JSON
      ↓
vuln_scanner.py     → Queries OSV.dev API per component (concurrent)
      ↓
license_scanner.py  → Scans LICENSE files + node_modules
      ↓
Flask /scan API     → Returns combined JSON to dashboard
      ↓
index.html          → Renders charts, tables, filters
```

## Next Steps (beyond POC)
- Add Dependency-Track integration (upload SBOM via REST API)
- Add Syft for container image scanning
- Add ScanCode for deeper license analysis
- Add SPDX 3.0 export format
- Add CI/CD webhook endpoint
- Add historical scan storage (SQLite → PostgreSQL)
