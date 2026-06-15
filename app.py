from flask import Flask, render_template, request, jsonify,  redirect, session, url_for
import os, secrets, requests as req
import subprocess, json, os, tempfile, shutil, sys
from scanner.sbom_generator import generate_sbom
from scanner.vuln_scanner import scan_vulnerabilities
from scanner.license_scanner import scan_licenses
from scanner.github_fetcher import (
    get_user_repos, download_repo_manifests, build_repo_tree_structure
)
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
# ── Auth helpers ──────────────────────────────────────────────
def get_token():
    return session.get("github_token")
def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_token():
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated

# ── Pages 
@app.route("/")
def index():
    user = session.get("github_user")
    return render_template("index.html", user=user)

# ── GitHub OAuth 
@app.route("/auth/github")
def github_login():
    state = secrets.token_hex(16)
    session["oauth_state"] = state
    params = {
        "client_id": config.GITHUB_CLIENT_ID,
        "redirect_uri": url_for("github_callback", _external=True),
        "scope": config.GITHUB_SCOPE,
        "state": state,
    }
    url = config.GITHUB_AUTHORIZE_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    return redirect(url)

@app.route("/auth/github/callback")
def github_callback():
    error = request.args.get("error")
    if error:
        return redirect("/?auth_error=" + error)

    state = request.args.get("state")
    if state != session.get("oauth_state"):
        return redirect("/?auth_error=state_mismatch")

    code = request.args.get("code")
    token_resp = req.post(
        config.GITHUB_TOKEN_URL,
        data={
            "client_id": config.GITHUB_CLIENT_ID,
            "client_secret": config.GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": url_for("github_callback", _external=True),
        },
        headers={"Accept": "application/json"},
        timeout=10,
    )
    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return redirect("/?auth_error=no_token")

    # Fetch GitHub user info
    user_resp = req.get(
        f"{config.GITHUB_API_BASE}/user",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
        timeout=10,
    )
    user_data = user_resp.json()

    session["github_token"] = access_token
    session["github_user"] = {
        "login":      user_data.get("login"),
        "name":       user_data.get("name") or user_data.get("login"),
        "avatar_url": user_data.get("avatar_url"),
    }
    return redirect("/")

@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/auth/user")
def auth_user():
    user = session.get("github_user")
    if not user:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "user": user})

# ── Repos ─────────────────────────────────────────────────────
@app.route("/repos")
@require_auth
def repos():
    try:
        repo_list = get_user_repos(get_token())
        return jsonify({"repos": repo_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Scan (GitHub repo OR local path) ──────────────────────────
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    project_path = data.get("path", "").strip()
    repo_full_name = data.get("repo")          # e.g. "torvalds/linux"
    repo_branch = data.get("branch", "main")

    tmpdir = None

    try:
        if repo_full_name:
            if not get_token():
                return jsonify({"error": "Not authenticated"}), 401
            tmpdir, actual_branch, fetched_files = download_repo_manifests(
                get_token(), repo_full_name, repo_branch
            )
            scan_path = tmpdir
            scan_label = repo_full_name
        elif project_path:
            if not os.path.exists(project_path):
                return jsonify({"error": f"Path not found: {project_path}"}), 400
            scan_path = project_path
            scan_label = project_path
        else:
            return jsonify({"error": "Provide either a repo or a local path"}), 400

        sbom = generate_sbom(scan_path)
        sbom["metadata"]["component"]["name"] = scan_label
        vulns = scan_vulnerabilities(sbom)
        licenses = scan_licenses(scan_path)

        summary = {
            "total_components": len(sbom.get("components", [])),
            "critical": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
            "high":     sum(1 for v in vulns if v["severity"] == "HIGH"),
            "medium":   sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "low":      sum(1 for v in vulns if v["severity"] == "LOW"),
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
    finally:
        if tmpdir:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

# ── Tree (GitHub repo OR local) ────────────────────────────────
@app.route("/tree", methods=["POST"])
def tree():
    data = request.get_json()
    repo_full_name = data.get("repo")
    repo_branch    = data.get("branch", "main")
    project_path   = data.get("path", "").strip()

    IGNORE = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build", ".next"}

    try:
        if repo_full_name:
            if not get_token():
                return jsonify({"error": "Not authenticated"}), 401
            tree_data = build_repo_tree_structure(get_token(), repo_full_name, repo_branch)
            root_name = repo_full_name
        elif project_path and os.path.exists(project_path):
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
            tree_data = walk(project_path)
            root_name = os.path.basename(project_path)
        else:
            return jsonify({"error": "No valid path or repo"}), 400

        return jsonify({"tree": tree_data, "root": root_name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Export ─────────────────────────────────────────────────────
@app.route("/export/sbom", methods=["POST"])
def export_sbom():
    return jsonify(request.get_json().get("sbom", {}))

if __name__ == "__main__":
    app.run(debug=True, port=5000)