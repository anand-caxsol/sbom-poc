from flask import Flask, render_template, request, jsonify
import subprocess, json, os, tempfile, shutil, sys
from scanner.sbom_generator import generate_sbom
from scanner.vuln_scanner import scan_vulnerabilities
from scanner.license_scanner import scan_licenses

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    project_path = data.get("path", "").strip()

    if not project_path or not os.path.exists(project_path):
        return jsonify({"error": f"Path not found: {project_path}"}), 400

    try:
        sbom = generate_sbom(project_path)
        vulns = scan_vulnerabilities(sbom)
        licenses = scan_licenses(project_path)

        summary = {
            "total_components": len(sbom.get("components", [])),
            "critical": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
            "high": sum(1 for v in vulns if v["severity"] == "HIGH"),
            "medium": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "low": sum(1 for v in vulns if v["severity"] == "LOW"),
            "license_issues": sum(1 for l in licenses if l.get("risk") == "HIGH"),
        }

        return jsonify({
            "summary": summary,
            "components": sbom.get("components", []),
            "vulnerabilities": vulns,
            "licenses": licenses,
            "sbom_raw": sbom,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/export/sbom", methods=["POST"])
def export_sbom():
    data = request.get_json()
    sbom = data.get("sbom", {})
    return jsonify(sbom)

@app.route("/tree", methods=["POST"])
def tree():
    data = request.get_json()
    project_path = data.get("path", "").strip()
    if not project_path or not os.path.exists(project_path):
        return jsonify({"error": "Path not found"}), 400

    IGNORE = {"node_modules", ".git", "__pycache__", "venv", ".venv", ".idea", "dist", "build", ".next"}

    def walk(path, depth=0, max_depth=4):
        items = []
        try:
            entries = sorted(os.scandir(path), key=lambda e: (not e.is_dir(), e.name.lower()))
        except PermissionError:
            return items
        for entry in entries:
            if entry.name.startswith(".") or entry.name in IGNORE:
                continue
            node = {"name": entry.name, "type": "dir" if entry.is_dir() else "file", "children": []}
            if entry.is_dir() and depth < max_depth:
                node["children"] = walk(entry.path, depth + 1, max_depth)
            items.append(node)
        return items

    return jsonify({"tree": walk(project_path), "root": os.path.basename(project_path)})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
