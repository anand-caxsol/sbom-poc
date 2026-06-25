import requests, os, base64, tempfile
import re

def get_user_repos(access_token):
    headers = {"Accept": "application/vnd.github+json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
        
    repos = []
    page = 1
    while True:
        resp = requests.get(
            f"https://api.github.com/user/repos",
            headers=headers,
            params={"per_page": 100, "page": page, "sort": "updated", "type": "all"},
            timeout=10
        )
        if resp.status_code != 200:
            break
        data = resp.json()
        if not data:
            break
        for r in data:
            repos.append({
                "id":          r["id"],
                "name":        r["name"],
                "full_name":   r["full_name"],
                "description": r.get("description") or "",
                "private":     r["private"],
                "language":    r.get("language") or "Unknown",
                "stars":       r["stargazers_count"],
                "updated_at":  r["updated_at"],
                "url":         r["html_url"],
                "default_branch": r.get("default_branch", "main"),
            })
        page += 1
        if len(data) < 100:
            break
    return repos

MANIFEST_FILES = [
    "requirements.txt", "Pipfile", "pyproject.toml",
    "package.json", "package-lock.json",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "*.csproj", "packages.config",
    "Gemfile", "Gemfile.lock",
]

def parse_github_url(url):
    """
    Accepts:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/branch
      github.com/owner/repo
      owner/repo
    Returns (full_name, branch_or_none)
    """
    url = url.strip().rstrip("/")
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^github\.com/", "", url)
    url = re.sub(r"\.git$", "", url)

    parts = url.split("/")
    if len(parts) < 2:
        return None, None

    owner, repo = parts[0], parts[1]
    branch = None
    if len(parts) >= 4 and parts[2] == "tree":
        branch = parts[3]

    return f"{owner}/{repo}", branch

def fetch_repo_tree(access_token, full_name, branch="main"):
    headers = {"Accept": "application/vnd.github+json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    resp = requests.get(
        f"https://api.github.com/repos/{full_name}/git/trees/{branch}",
        headers=headers,
        params={"recursive": "1"},
        timeout=15
    )
    if resp.status_code == 404:
        # try main vs master
        alt = "master" if branch == "main" else "main"
        resp = requests.get(
            f"https://api.github.com/repos/{full_name}/git/trees/{alt}",
            headers=headers,
            params={"recursive": "1"},
            timeout=15
        )
    if resp.status_code != 200:
        return [], branch
    data = resp.json()
    return data.get("tree", []), data.get("sha", branch)

def fetch_file_content(access_token, full_name, file_path):
    headers = {"Accept": "application/vnd.github+json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    resp = requests.get(
        f"https://api.github.com/repos/{full_name}/contents/{file_path}",
        headers=headers,
        timeout=10
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    if data.get("encoding") == "base64":
        return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
    return data.get("content", "")

MANIFEST_NAMES = {
    "requirements.txt", "pipfile", "pyproject.toml",
    "package.json", "go.mod", "cargo.toml",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "gemfile", "gemfile.lock", "packages.config",
}

def download_repo_manifests(access_token, full_name, branch="main"):
    """
    Fetches only manifest files from the repo via GitHub API.
    Returns a temp directory path with those files written to disk.
    """
    tree, actual_branch = fetch_repo_tree(access_token, full_name, branch)

    # Filter to only manifest files (skip node_modules etc.)
    manifest_paths = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item["path"]
        filename = os.path.basename(path).lower()
        parts = path.split("/")
        # Skip vendor/node_modules directories
        skip_dirs = {"node_modules", "vendor", ".git", "dist", "build", "venv", ".venv"}
        if any(p in skip_dirs for p in parts):
            continue
        if filename in MANIFEST_NAMES:
            manifest_paths.append(path)

    # Write fetched files into a temp directory (mirrors repo structure)
    tmpdir = tempfile.mkdtemp(prefix="sbom_github_")
    for path in manifest_paths:
        content = fetch_file_content(access_token, full_name, path)
        if content is None:
            continue
        local_path = os.path.join(tmpdir, path)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(content)

    return tmpdir, actual_branch, manifest_paths

def fetch_license_files(access_token, full_name, branch="main"):
    """Fetches LICENSE/COPYING/NOTICE files from repo root and subdirs."""
    tree, _ = fetch_repo_tree(access_token, full_name, branch)

    LICENSE_PREFIXES = ("license", "licence", "copying", "notice")
    _SKIP = {"node_modules", "vendor", ".git", "dist", "build", "venv", ".venv"}
    license_paths = []

    for item in tree:
        if item.get("type") != "blob":
            continue
        path  = item["path"]
        fname = os.path.basename(path).lower()
        parts = path.split("/")

        if any(p in _SKIP for p in parts):
            continue
        if any(fname.startswith(p) for p in LICENSE_PREFIXES):
            license_paths.append(path)

    return license_paths

def build_repo_tree_structure(access_token, full_name, branch="main"):
    """Returns tree structure for the frontend project-structure panel."""
    tree, _ = fetch_repo_tree(access_token, full_name, branch)
    IGNORE = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build"}

    def insert(root_dict, parts, is_file):
        if not parts:
            return
        name = parts[0]
        if name in IGNORE:
            return
        if len(parts) == 1:
            if is_file:
                root_dict.setdefault("__files__", []).append(name)
        else:
            root_dict.setdefault(name, {})
            insert(root_dict[name], parts[1:], is_file)

    nested = {}
    for item in tree:
        parts = item["path"].split("/")
        insert(nested, parts, item["type"] == "blob")

    def to_list(d):
        result = []
        for key, val in sorted(d.items()):
            if key == "__files__":
                for f in sorted(val):
                    result.append({"name": f, "type": "file", "children": []})
            else:
                result.append({"name": key, "type": "dir", "children": to_list(val)})
        return result

    return to_list(nested)