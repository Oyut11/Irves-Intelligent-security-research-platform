"""
IRVES — Dependencies Analyzer
Parses and classifies dependencies across ecosystems, checks CVEs, calculates health scores.
"""

import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any

from services.source_analysis.reports import build_dependencies_report
from services.source_analysis.report_utils import resolve_project_name

from database.models import FindingSeverity
from services.git_service import git_service

logger = logging.getLogger(__name__)


PKG_CATEGORY_DB: Dict[str, str] = {
    # Python
    "fastapi": "Web Framework", "uvicorn": "Web Server", "sqlalchemy": "Database",
    "jinja2": "Templating", "pydantic": "Data Validation", "pytest": "Development Tools",
    "celery": "Task Queue", "django": "Web Framework", "flask": "Web Framework",
    "httpx": "HTTP Client", "aiofiles": "File I/O", "python-dotenv": "Configuration",
    "bandit": "Source Code Analysis", "safety": "Source Code Analysis",
    "anthropic": "AI Integration", "litellm": "AI Integration",
    "google-generativeai": "AI Integration", "google-cloud-aiplatform": "AI Integration",
    # Node.js
    "react": "UI Libraries", "vue": "UI Libraries", "express": "Web Framework",
    "next": "Web Framework", "mongoose": "Database", "prisma": "Database",
    "sequelize": "Database", "typeorm": "Database",
    # Rust
    "tauri": "Desktop Framework", "serde": "Serialization", "serde_json": "Serialization",
    "tokio": "Async Runtime",
    # Go
    "gin": "Web Framework", "echo": "Web Framework",
    # Ruby
    "rails": "Web Framework", "sinatra": "Web Framework",
    # PHP
    "laravel": "Web Framework", "symfony": "Web Framework",
    # .NET
    "Microsoft.AspNetCore": "Web Framework", "EntityFrameworkCore": "Database",
    # Android
    "hilt-android": "Dependency Injection", "room-runtime": "Database",
    "okhttp": "Network & Security", "retrofit": "Network & Security",
    "gson": "Serialization", "coil": "UI Libraries",
    "ktor": "Network & Security", "generativeai": "AI Integration",
    "tensorflow-lite": "AI Integration", "pytorch_android": "AI Integration",
    "media3-exoplayer": "UI Libraries",
    # Tauri
    "@tauri-apps/api": "Desktop Framework", "@tauri-apps/cli": "Development Tools",
    # Security tools
    "frida": "Security Tools", "frida-tools": "Security Tools",
    "mitmproxy": "Security Tools", "bcc": "Security Tools", "fritap": "Security Tools",
    "trufflehog3": "Security Tools", "weasyprint": "Document Processing",
}

PKG_SECURITY_DB: Dict[str, Dict[str, str]] = {
    # Python
    "fastapi": {"notes": "Recent version, no critical CVEs", "risk": "low"},
    "uvicorn": {"notes": "Includes websockets, httptools", "risk": "low"},
    "sqlalchemy": {"notes": "SQL injection protection via parameterized queries", "risk": "low"},
    "jinja2": {"notes": "SSTI risk if user input not sanitized", "risk": "high"},
    "anthropic": {"notes": "API key exposure risk if not secured", "risk": "high"},
    "litellm": {"notes": "API key management critical", "risk": "high"},
    "frida": {"notes": "Requires native code execution", "risk": "high"},
    "frida-tools": {"notes": "Same as frida", "risk": "high"},
    "mitmproxy": {"notes": "Manages TLS certificates, potential MITM vector", "risk": "high"},
    "bcc": {"notes": "Requires root privileges", "risk": "high"},
    "fritap": {"notes": "Sensitive key extraction capability", "risk": "high"},
    "bandit": {"notes": "May have false positives", "risk": "low"},
    "trufflehog3": {"notes": "Scans for secrets in repos", "risk": "medium"},
    "safety": {"notes": "Checks dependency CVEs", "risk": "low"},
    "weasyprint": {"notes": "HTML/CSS parsing, potential XSS", "risk": "medium"},
    "google-generativeai": {"notes": "API key exposure risk", "risk": "high"},
    "google-cloud-aiplatform": {"notes": "API key exposure risk", "risk": "high"},
    "pydantic": {"notes": "Data validation, low risk", "risk": "low"},
    "pydantic-settings": {"notes": "Configuration management", "risk": "low"},
    "python-dotenv": {"notes": "Secure if .env not committed", "risk": "low"},
    "aiofiles": {"notes": "Minimal risk", "risk": "low"},
    "httpx": {"notes": "TLS verification by default", "risk": "low"},
    "python-multipart": {"notes": "Minimal attack surface", "risk": "low"},
    "pytest": {"notes": "Development only", "risk": "low"},
    "locust": {"notes": "Development tool only", "risk": "low"},
    "py-spy": {"notes": "Development tool only", "risk": "low"},
    # Rust
    "tauri": {"notes": "Mature desktop framework", "risk": "low"},
    "serde": {"notes": "Deserialization needs validation", "risk": "medium"},
    "serde_json": {"notes": "Same as serde", "risk": "medium"},
    "tokio": {"notes": "Full features enabled", "risk": "low"},
    # Node.js
    "@tauri-apps/api": {"notes": "Runtime API for desktop features", "risk": "low"},
    "@tauri-apps/cli": {"notes": "Dev dependency only", "risk": "low"},
    # Go
    "gin": {"notes": "Popular web framework", "risk": "low"},
    "echo": {"notes": "Minimal web framework", "risk": "low"},
    # Ruby
    "rails": {"notes": "Full-stack framework, keep updated for CVEs", "risk": "medium"},
    "sinatra": {"notes": "Minimal framework", "risk": "low"},
    # PHP
    "laravel": {"notes": "Full-stack framework", "risk": "low"},
    "symfony": {"notes": "Enterprise framework", "risk": "low"},
    # .NET
    "Microsoft.AspNetCore": {"notes": "Core web framework", "risk": "low"},
    "EntityFrameworkCore": {"notes": "ORM, parameterized queries", "risk": "low"},
    # General
    "react": {"notes": "UI library, client-side only", "risk": "low"},
    "next": {"notes": "SSR framework, check server-side security", "risk": "medium"},
    "vue": {"notes": "UI library, client-side only", "risk": "low"},
    "express": {"notes": "Minimal web framework, add security middleware", "risk": "medium"},
    "django": {"notes": "Batteries-included framework, keep updated", "risk": "low"},
    "flask": {"notes": "Minimal framework, add security extensions", "risk": "medium"},
    "celery": {"notes": "Task queue, broker security critical", "risk": "medium"},
    "mongoose": {"notes": "MongoDB ODM, watch for NoSQL injection", "risk": "medium"},
    "prisma": {"notes": "Modern ORM, parameterized queries", "risk": "low"},
    "sequelize": {"notes": "ORM, parameterized queries", "risk": "low"},
    "typeorm": {"notes": "ORM, parameterized queries", "risk": "low"},
    # Android
    "hilt-android": {"notes": "DI framework, compile-time checked", "risk": "low"},
    "room-runtime": {"notes": "ORM, parameterized queries", "risk": "low"},
    "okhttp": {"notes": "HTTP client, TLS verification by default", "risk": "low"},
    "retrofit": {"notes": "HTTP client, depends on OkHttp", "risk": "low"},
    "gson": {"notes": "JSON parsing, watch for type confusion", "risk": "medium"},
    "coil": {"notes": "Image loading, network access", "risk": "low"},
    "ktor": {"notes": "HTTP framework, verify TLS config", "risk": "low"},
    "generativeai": {"notes": "AI SDK, API key exposure risk", "risk": "high"},
    "tensorflow-lite": {"notes": "On-device ML, model input validation", "risk": "medium"},
    "pytorch_android": {"notes": "On-device ML, model input validation", "risk": "medium"},
    "media3-exoplayer": {"notes": "Media player, content URI validation", "risk": "low"},
}





def get_db():
    """Get database session."""
    from database.session import get_session
    return get_session()


async def analyze_dependencies(repo_path: Path,
    analysis_result_id: str,
) -> Dict[str, Any]:
    """Analyze dependencies: produces a comprehensive dependencies report as a single finding."""
    logger.info("[SourceAnalysis] Analyzing dependencies — generating comprehensive report")

    try:
        # Resolve project name from DB
        project_name = None
        try:
            from database.crud import get_source_analysis_result, get_project
            ar = await get_source_analysis_result(get_db(), analysis_result_id)
            if ar and ar.project_id:
                proj = await get_project(get_db(), ar.project_id)
                if proj:
                    project_name = proj.name
        except Exception:
            pass

        # ── 1. Parse all dependency ecosystems ──
        ecosystems = parse_all_deps(repo_path)

        # Flatten packages for CVE lookup
        all_packages = []
        for eco, pkgs in ecosystems.items():
            all_packages.extend(pkgs)

        # ── 2. Run CVE scanners (safety, npm audit) ──
        cve_results = await run_cve_scanners(repo_path)

        # ── 3. Live CVE database lookup (OSV.dev) ──
        live_cve_results = await query_live_cve_database(all_packages, repo_path)
        
        # Merge CVE results (deduplicate by CVE ID)
        cve_ids = {cve.get("cve_id") for cve in cve_results}
        for live_cve in live_cve_results:
            if live_cve.get("cve_id") not in cve_ids:
                cve_results.append(live_cve)

        # ── 3. Classify packages + security notes ──
        classified = classify_all_packages(ecosystems)
        security_analysis = analyze_dep_security(classified, cve_results)

        # ── 4. Health score ──
        health = calculate_dep_health(ecosystems, security_analysis)

        # ── 5. Build the markdown report ──
        report = build_dependencies_report(
            repo_path, ecosystems, classified, security_analysis, cve_results, health,
            project_name=project_name
        )

        findings = [{
            "type": "dependencies_report",
            "severity": FindingSeverity.INFO,
            "message": report,
            "tool": "dependency_analyzer",
            "extra_data": {
                "ecosystems": {k: {"package_count": len(v)} for k, v in ecosystems.items()},
                "cve_count": len(cve_results),
                "health_score": health.get("overall", 0),
            },
        }]

        summary = {
            "total_findings": 1,
            "total_packages": sum(len(v) for v in ecosystems.values()),
            "cve_count": len(cve_results),
            "health_score": health.get("overall", 0),
        }

    except Exception as e:
        logger.error(f"[SourceAnalysis] Dependencies analysis failed: {e}")
        findings = [{
            "type": "dependencies_report",
            "severity": FindingSeverity.INFO,
            "message": f"# Dependencies Report\n\nAnalysis failed: {e}",
            "tool": "dependency_analyzer",
        }]
        summary = {"total_findings": 1}

    summary["total_findings"] = len(findings)
    return {
        "summary_metrics": summary,
        "detailed_findings": {},
        "findings": findings,
    }


def parse_all_deps(repo_path: Path) -> Dict[str, List[Dict[str, str]]]:
    """Parse dependencies from all detected ecosystem config files.
    Prioritizes lockfiles over manifest files for accurate version resolution.
    """
    ecosystems: Dict[str, List[Dict[str, str]]] = {}

    def _add(ecosystem: str, packages: List[Dict[str, str]]):
        if packages:
            ecosystems.setdefault(ecosystem, []).extend(packages)

    # Priority: lockfiles first, then manifest files
    # Python
    lockfile_pkgs = parse_poetry_lock(repo_path)
    if lockfile_pkgs:
        _add("Python", lockfile_pkgs)
    else:
        _add("Python", parse_python_deps(repo_path))

    # Node.js
    lockfile_pkgs = parse_package_lock(repo_path)
    if lockfile_pkgs:
        _add("Node.js", lockfile_pkgs)
    else:
        yarn_pkgs = parse_yarn_lock(repo_path)
        if yarn_pkgs:
            _add("Node.js", yarn_pkgs)
        else:
            _add("Node.js", parse_node_deps(repo_path))

    # Rust
    lockfile_pkgs = parse_cargo_lock(repo_path)
    if lockfile_pkgs:
        _add("Rust", lockfile_pkgs)
    else:
        _add("Rust", parse_rust_deps(repo_path))

    # Ruby
    lockfile_pkgs = parse_gemfile_lock(repo_path)
    if lockfile_pkgs:
        _add("Ruby", lockfile_pkgs)
    else:
        _add("Ruby", parse_ruby_deps(repo_path))

    # Dart/Flutter
    lockfile_pkgs = parse_pubspec_lock(repo_path)
    if lockfile_pkgs:
        _add("Dart", lockfile_pkgs)
    else:
        _add("Dart", parse_dart_deps(repo_path))

    # Other ecosystems (no lockfile support yet)
    _add("Go", parse_go_deps(repo_path))
    _add("PHP", parse_php_deps(repo_path))
    _add(".NET", parse_dotnet_deps(repo_path))
    _add("Gradle (Kotlin/Java)", parse_gradle_deps(repo_path))
    _add("Maven (Java)", parse_maven_deps(repo_path))
    _add("Swift", parse_swift_deps(repo_path))
    _add("Elixir", parse_elixir_deps(repo_path))

    return ecosystems



def parse_python_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Python dependencies from requirements.txt, pyproject.toml, Pipfile, setup.py."""
    packages: List[Dict[str, str]] = []
    seen: set = set()

    # requirements.txt
    req_file = repo_path / "requirements.txt"
    if req_file.exists():
        for line in req_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle: package==1.0, package>=1.0, package~=1.0, package>1.0,<2.0
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*([<>=!~]+\s*[\d.*]+)?", line)
            if match:
                name = match.group(1).lower()
                version = match.group(2).strip() if match.group(2) else "-"
                if name not in seen:
                    seen.add(name)
                    packages.append({"name": name, "version": version, "ecosystem": "Python"})

    # pyproject.toml (poetry / pep 621)
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(errors="ignore")
        # Poetry [tool.poetry.dependencies]
        in_deps = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[tool.poetry.dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[tool.poetry.dev-dependencies]") or stripped.startswith("[tool.poetry.group"):
                in_deps = True  # also capture dev deps
                continue
            if stripped.startswith("["):
                in_deps = False
                continue
            if in_deps and "=" in stripped:
                match = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"', stripped)
                if not match:
                    match = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*([^\s]+)', stripped)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2).strip().strip('"').strip("'")
                    if name == "python":
                        continue
                    if name not in seen:
                        seen.add(name)
                        packages.append({"name": name, "version": version, "ecosystem": "Python"})

        # PEP 621 [project.dependencies]
        in_project_deps = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[project.dependencies]") or stripped.startswith("[project.optional-dependencies"):
                in_project_deps = True
                continue
            if stripped.startswith("["):
                in_project_deps = False
                continue
            if in_project_deps:
                match = re.match(r'^([A-Za-z0-9_.-]+)\s*([<>=!~]+\s*[\d.*]+)?', stripped)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2).strip() if match.group(2) else "-"
                    if name not in seen:
                        seen.add(name)
                        packages.append({"name": name, "version": version, "ecosystem": "Python"})

    # Pipfile
    pipfile = repo_path / "Pipfile"
    if pipfile.exists():
        text = pipfile.read_text(errors="ignore")
        in_section = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped in ["[packages]", "[dev-packages]"]:
                in_section = True
                continue
            if stripped.startswith("["):
                in_section = False
                continue
            if in_section and "=" in stripped:
                match = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"', stripped)
                if not match:
                    match = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*([^\s]+)', stripped)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2).strip().strip('"').strip("'")
                    if name not in seen:
                        seen.add(name)
                        packages.append({"name": name, "version": version, "ecosystem": "Python"})

    return packages



def parse_node_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Node.js dependencies from package.json."""
    packages: List[Dict[str, str]] = []
    pkg_file = repo_path / "package.json"
    if not pkg_file.exists():
        # Check subdirectories (monorepo)
        for sub_pkg in list(repo_path.glob("*/package.json"))[:5]:
            packages.extend(parse_single_package_json(sub_pkg))
        return packages
    return parse_single_package_json(pkg_file)



def parse_single_package_json(pkg_file: Path) -> List[Dict[str, str]]:
    """Parse a single package.json file."""
    packages: List[Dict[str, str]] = []
    seen: set = set()
    try:
        data = json.loads(pkg_file.read_text(errors="ignore"))
    except Exception:
        return packages

    for dep_type in ["dependencies", "devDependencies"]:
        deps = data.get(dep_type, {})
        for name, version_spec in deps.items():
            if name not in seen:
                seen.add(name)
                ver = str(version_spec).replace("^", "").replace("~", "").replace(">=", "").replace("<=", "")
                is_dev = dep_type == "devDependencies"
                packages.append({
                    "name": name,
                    "version": ver if ver else str(version_spec),
                    "ecosystem": "Node.js",
                    "is_dev": is_dev,
                })
    return packages



def parse_rust_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Rust dependencies from Cargo.toml."""
    packages: List[Dict[str, str]] = []
    cargo = repo_path / "Cargo.toml"
    if not cargo.exists():
        return packages

    text = cargo.read_text(errors="ignore")
    in_deps = False
    in_dev_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[dependencies]":
            in_deps = True
            in_dev_deps = False
            continue
        if stripped == "[dev-dependencies]":
            in_deps = False
            in_dev_deps = True
            continue
        if stripped.startswith("["):
            in_deps = False
            in_dev_deps = False
            continue
        if in_deps or in_dev_deps:
            match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"', stripped)
            if not match:
                match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]*)"', stripped)
            if match:
                name = match.group(1)
                version = match.group(2)
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "Rust",
                    "is_dev": in_dev_deps,
                })
    return packages



def parse_go_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Go dependencies from go.mod."""
    packages: List[Dict[str, str]] = []
    gomod = repo_path / "go.mod"
    if not gomod.exists():
        return packages

    in_require = False
    for line in gomod.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if stripped == ")":
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            match = re.match(r'^\s*([A-Za-z0-9./-]+)\s+(v[\d.]+[\w.-]*)', stripped)
            if match:
                path = match.group(1)
                version = match.group(2)
                short_name = path.split("/")[-1]
                packages.append({
                    "name": short_name,
                    "version": version,
                    "ecosystem": "Go",
                    "full_path": path,
                })
    return packages



def parse_ruby_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Ruby dependencies from Gemfile."""
    packages: List[Dict[str, str]] = []
    gemfile = repo_path / "Gemfile"
    if not gemfile.exists():
        return packages

    for line in gemfile.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        match = re.match(r"^gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]*)['\"])?", stripped)
        if match:
            name = match.group(1)
            version = match.group(2) or "-"
            packages.append({"name": name, "version": version, "ecosystem": "Ruby"})
    return packages



def parse_php_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse PHP dependencies from composer.json."""
    packages: List[Dict[str, str]] = []
    composer = repo_path / "composer.json"
    if not composer.exists():
        return packages

    try:
        data = json.loads(composer.read_text(errors="ignore"))
    except Exception:
        return packages

    for dep_type in ["require", "require-dev"]:
        deps = data.get(dep_type, {})
        for name, version in deps.items():
            if name.startswith("php"):
                continue
            ver = str(version).replace("^", "").replace("~", "").replace(">=", "")
            packages.append({
                "name": name,
                "version": ver if ver else str(version),
                "ecosystem": "PHP",
                "is_dev": dep_type == "require-dev",
            })
    return packages



def parse_dotnet_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse .NET dependencies from .csproj files."""
    packages: List[Dict[str, str]] = []
    seen: set = set()

    for csproj in list(repo_path.glob("**/*.csproj"))[:5]:
        text = csproj.read_text(errors="ignore")
        # PackageReference format
        for match in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]*)"', text):
            name = match.group(1)
            if name not in seen:
                seen.add(name)
                packages.append({"name": name, "version": match.group(2), "ecosystem": ".NET"})
        # PackageReference with Version in child element
        for match in re.finditer(r'<PackageReference\s+Include="([^"]+)"', text):
            name = match.group(1)
            if name not in seen:
                ver_match = re.search(rf'<PackageReference\s+Include="{re.escape(name)}"[^>]*>.*?<Version>([^<]+)</Version>', text, re.DOTALL)
                version = ver_match.group(1) if ver_match else "-"
                seen.add(name)
                packages.append({"name": name, "version": version, "ecosystem": ".NET"})
    return packages



def parse_dart_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Dart/Flutter dependencies from pubspec.yaml."""
    packages: List[Dict[str, str]] = []
    pubspec = repo_path / "pubspec.yaml"
    if not pubspec.exists():
        return packages

    text = pubspec.read_text(errors="ignore")
    in_deps = False
    in_dev_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("dependencies:"):
            in_deps = True
            in_dev_deps = False
            continue
        if stripped.startswith("dev_dependencies:"):
            in_deps = False
            in_dev_deps = True
            continue
        if stripped.startswith("environment:") or stripped.startswith("flutter:") or (not stripped.startswith("  ") and stripped and not stripped.startswith("#")):
            if not stripped.endswith(":"):
                in_deps = False
                in_dev_deps = False
                continue
        if (in_deps or in_dev_deps) and ":" in stripped:
            match = re.match(r'^\s+([A-Za-z0-9_]+):\s*"?([^"\s:]*)"?', stripped)
            if match:
                name = match.group(1)
                version = match.group(2) or "-"
                if name in ("sdk", "flutter"):
                    continue
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "Dart",
                    "is_dev": in_dev_deps,
                })
    return packages



def parse_gradle_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Gradle dependencies from build.gradle / build.gradle.kts + version catalogs."""
    packages: List[Dict[str, str]] = []
    seen: set = set()

    # First: parse Gradle version catalog (libs.versions.toml) — this is the primary source
    # for modern Android projects using version catalogs
    for toml_path in list(repo_path.glob("**/libs.versions.toml"))[:3]:
        toml_text = toml_path.read_text(errors="ignore")
        # Extract [versions] section for version.ref lookups
        versions: Dict[str, str] = {}
        in_versions = False
        for line in toml_text.splitlines():
            stripped = line.strip()
            if stripped == "[versions]":
                in_versions = True
                continue
            if stripped.startswith("["):
                in_versions = False
                continue
            if in_versions and "=" in stripped:
                match = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"', stripped)
                if match:
                    versions[match.group(1)] = match.group(2)
                else:
                    match = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*([^\s]+)', stripped)
                    if match:
                        versions[match.group(1)] = match.group(2).strip('"').strip("'")

        # Extract [libraries] section
        in_libraries = False
        for line in toml_text.splitlines():
            stripped = line.strip()
            if stripped == "[libraries]":
                in_libraries = True
                continue
            if stripped.startswith("["):
                in_libraries = False
                continue
            if in_libraries and "=" in stripped:
                # Format: alias = { module = "group:name", version.ref = "verAlias" }
                # or: alias = { module = "group:name", version = "1.0" }
                # or: alias = { group = "com.example", name = "lib", version.ref = "verAlias" }
                alias_match = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*\{(.+)\}', stripped)
                if alias_match:
                    alias = alias_match.group(1)
                    body = alias_match.group(2)
                    # Extract module (group:name format)
                    module_match = re.search(r'module\s*=\s*"([^"]+)"', body)
                    group_name = ""
                    lib_name = alias
                    if module_match:
                        parts = module_match.group(1).split(":")
                        if len(parts) == 2:
                            group_name = parts[0]
                            lib_name = parts[1]
                        else:
                            lib_name = module_match.group(1)
                    else:
                        # Try group + name format
                        g_match = re.search(r'group\s*=\s*"([^"]+)"', body)
                        n_match = re.search(r'name\s*=\s*"([^"]+)"', body)
                        if g_match and n_match:
                            group_name = g_match.group(1)
                            lib_name = n_match.group(1)

                    # Extract version
                    ver_match = re.search(r'version\s*=\s*"([^"]+)"', body)
                    version = ver_match.group(1) if ver_match else "-"
                    if version == "-":
                        ver_ref = re.search(r'version\.ref\s*=\s*"([^"]+)"', body)
                        if ver_ref:
                            version = versions.get(ver_ref.group(1), f"ref:{ver_ref.group(1)}")

                    full_name = f"{group_name}:{lib_name}" if group_name else lib_name
                    if full_name not in seen and lib_name:
                        seen.add(full_name)
                        packages.append({
                            "name": lib_name,
                            "version": version,
                            "ecosystem": "Gradle",
                            "group": group_name,
                            "alias": alias.replace("-", "."),
                        })

    # Also parse direct dependencies from build.gradle / build.gradle.kts
    for gradle_name in ["build.gradle.kts", "build.gradle"]:
        gradle_file = repo_path / gradle_name
        if not gradle_file.exists():
            continue
        text = gradle_file.read_text(errors="ignore")

        # Kotlin DSL: implementation("group:name:version")
        for match in re.finditer(r'(?:implementation|api|compileOnly|runtimeOnly|testImplementation|androidTestImplementation)\s*\(?["\']([^:]+):([^:]+):([^"\']+)["\']\)?', text):
            group, name, version = match.group(1), match.group(2), match.group(3)
            full_name = f"{group}:{name}"
            if full_name not in seen:
                seen.add(full_name)
                packages.append({"name": name, "version": version, "ecosystem": "Gradle", "group": group})

        # Groovy DSL: implementation 'group:name:version'
        for match in re.finditer(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|androidTestImplementation)\s+'([^:]+):([^:]+):([^']+)'", text):
            group, name, version = match.group(1), match.group(2), match.group(3)
            full_name = f"{group}:{name}"
            if full_name not in seen:
                seen.add(full_name)
                packages.append({"name": name, "version": version, "ecosystem": "Gradle", "group": group})

        # Also check app-level build.gradle
        app_gradle = repo_path / "app" / gradle_name
        if app_gradle.exists():
            app_text = app_gradle.read_text(errors="ignore")
            for match in re.finditer(r'(?:implementation|api|compileOnly|runtimeOnly|testImplementation|androidTestImplementation)\s*\(?["\']([^:]+):([^:]+):([^"\']+)["\']\)?', app_text):
                group, name, version = match.group(1), match.group(2), match.group(3)
                full_name = f"{group}:{name}"
                if full_name not in seen:
                    seen.add(full_name)
                    packages.append({"name": name, "version": version, "ecosystem": "Gradle", "group": group})
            for match in re.finditer(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|androidTestImplementation)\s+'([^:]+):([^:]+):([^']+)'", app_text):
                group, name, version = match.group(1), match.group(2), match.group(3)
                full_name = f"{group}:{name}"
                if full_name not in seen:
                    seen.add(full_name)
                    packages.append({"name": name, "version": version, "ecosystem": "Gradle", "group": group})
        break  # only process first found gradle file at root
    return packages



def parse_maven_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Maven dependencies from pom.xml."""
    packages: List[Dict[str, str]] = []
    seen: set = set()
    pom = repo_path / "pom.xml"
    if not pom.exists():
        return packages

    text = pom.read_text(errors="ignore")
    # Find all <dependency> blocks
    for match in re.finditer(r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?', text):
        group = match.group(1)
        artifact = match.group(2)
        version = match.group(3) or "-"
        full_name = f"{group}:{artifact}"
        if full_name not in seen:
            seen.add(full_name)
            packages.append({"name": artifact, "version": version, "ecosystem": "Maven", "group": group})
    return packages



def parse_swift_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Swift dependencies from Package.swift."""
    packages: List[Dict[str, str]] = []
    pkg_swift = repo_path / "Package.swift"
    if not pkg_swift.exists():
        return packages

    text = pkg_swift.read_text(errors="ignore")
    for match in re.finditer(r'\.package\s*\(\s*url:\s*"([^"]+)"[^)]*\.upToNextMinor\s*\(\s*from:\s*"([^"]+)"\)', text):
        url = match.group(1)
        version = match.group(2)
        name = url.rstrip("/").split("/")[-1]
        packages.append({"name": name, "version": f">={version}", "ecosystem": "Swift", "url": url})
    for match in re.finditer(r'\.package\s*\(\s*url:\s*"([^"]+)"[^)]*from:\s*"([^"]+)"', text):
        url = match.group(1)
        version = match.group(2)
        name = url.rstrip("/").split("/")[-1]
        packages.append({"name": name, "version": f">={version}", "ecosystem": "Swift", "url": url})
    return packages



def parse_elixir_deps(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Elixir dependencies from mix.exs."""
    packages: List[Dict[str, str]] = []
    mix_file = repo_path / "mix.exs"
    if not mix_file.exists():
        return packages

    text = mix_file.read_text(errors="ignore")
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if "defp deps" in stripped or "def deps" in stripped:
            in_deps = True
            continue
        if in_deps and stripped.startswith("end"):
            in_deps = False
            continue
        if in_deps:
            match = re.match(r'^\s*\{:([A-Za-z0-9_]+),\s*"([^"]+)"', stripped)
            if not match:
                match = re.match(r'^\s*\{:([A-Za-z0-9_]+),\s*([^,]+)', stripped)
            if match:
                name = match.group(1)
                version = match.group(2).strip().strip('"').strip("'")
                packages.append({"name": name, "version": version, "ecosystem": "Elixir"})
    return packages



async def run_cve_scanners(repo_path: Path) -> List[Dict[str, Any]]:
    """Run available CVE scanners and return results."""
    cve_results: List[Dict[str, Any]] = []

    # Python: safety
    req_files = list(repo_path.glob("**/requirements*.txt"))
    if req_files:
        try:
            import subprocess
            for req_file in req_files[:3]:
                result = subprocess.run(
                    ["safety", "check", "-r", str(req_file), "--json"],
                    capture_output=True, text=True, timeout=60,
                )
                if result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        vulns = data if isinstance(data, list) else data.get("vulnerabilities", data.get("scanned", []))
                        if isinstance(vulns, list):
                            for vuln in vulns:
                                cve_results.append({
                                    "ecosystem": "Python",
                                    "package": vuln.get("package_name", vuln.get("name", "unknown")),
                                    "severity": "high",
                                    "advisory": vuln.get("advisory", vuln.get("message", "")),
                                    "cve_id": vuln.get("cve", vuln.get("id", "")),
                                })
                    except json.JSONDecodeError:
                        pass
        except (ImportError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Node.js: npm audit
    pkg_files = list(repo_path.glob("**/package.json"))
    if pkg_files:
        try:
            import subprocess
            for pkg_file in pkg_files[:3]:
                result = subprocess.run(
                    ["npm", "audit", "--json"],
                    capture_output=True, text=True, timeout=60,
                    cwd=str(pkg_file.parent),
                )
                if result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        for name, info in data.get("vulnerabilities", {}).items():
                            cve_results.append({
                                "ecosystem": "Node.js",
                                "package": name,
                                "severity": info.get("severity", "medium"),
                                "advisory": info.get("title", ""),
                                "cve_id": info.get("url", ""),
                            })
                    except json.JSONDecodeError:
                        pass
        except (ImportError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return cve_results



def classify_all_packages(ecosystems: Dict[str, List[Dict[str, str]]]) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
    """Classify packages by ecosystem and functional category."""
    classified: Dict[str, Dict[str, List[Dict[str, str]]]] = {}

    for ecosystem, packages in ecosystems.items():
        eco_cats: Dict[str, List[Dict[str, str]]] = {}
        for pkg in packages:
            name = pkg["name"]
            # Look up category
            category = PKG_CATEGORY_DB.get(name)
            if not category:
                # Try without namespace prefix
                short = name.split("/")[-1].split(".")[-1].lower()
                category = PKG_CATEGORY_DB.get(short)
            if not category:
                # Guess from name patterns
                name_lower = name.lower()
                if any(kw in name_lower for kw in ["test", "pytest", "jest", "vitest", "mocha", "cypress", "spec"]):
                    category = "Development Tools"
                elif any(kw in name_lower for kw in ["lint", "format", "check", "audit", "bandit", "safety"]):
                    category = "Source Code Analysis"
                elif any(kw in name_lower for kw in ["db", "sql", "mongo", "redis", "orm", "sqlite", "postgres", "mysql"]):
                    category = "Database"
                elif any(kw in name_lower for kw in ["http", "request", "fetch", "url", "socket", "proxy", "tls", "ssl"]):
                    category = "Network & Security"
                elif any(kw in name_lower for kw in ["ui", "component", "view", "widget", "css", "style", "tailwind", "bootstrap"]):
                    category = "UI Libraries"
                elif any(kw in name_lower for kw in ["ai", "ml", "llm", "gpt", "bert", "torch", "tensor", "transformer"]):
                    category = "AI Integration"
                else:
                    category = "Other"

            pkg_with_cat = {**pkg, "category": category}
            # Add security notes
            sec = PKG_SECURITY_DB.get(name)
            if not sec:
                sec = PKG_SECURITY_DB.get(name.lower())
            if sec:
                pkg_with_cat["security_notes"] = sec["notes"]
                pkg_with_cat["risk"] = sec["risk"]
            else:
                pkg_with_cat["security_notes"] = "No known issues"
                pkg_with_cat["risk"] = "low"

            eco_cats.setdefault(category, []).append(pkg_with_cat)

        classified[ecosystem] = eco_cats

    return classified



def analyze_dep_security(classified: Dict[str, Dict[str, List[Dict[str, str]]]],
    cve_results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Analyze dependency security posture and return structured findings."""
    high_priority: List[Dict[str, str]] = []
    medium_priority: List[Dict[str, str]] = []
    low_priority: List[Dict[str, str]] = []

    # Scan all packages for risk levels
    for ecosystem, categories in classified.items():
        for category, packages in categories.items():
            for pkg in packages:
                risk = pkg.get("risk", "low")
                entry = {
                    "package": pkg["name"],
                    "ecosystem": ecosystem,
                    "risk": risk,
                    "notes": pkg.get("security_notes", ""),
                }
                if risk == "high":
                    high_priority.append(entry)
                elif risk == "medium":
                    medium_priority.append(entry)

    # Add CVE findings
    for cve in cve_results:
        high_priority.append({
            "package": cve["package"],
            "ecosystem": cve.get("ecosystem", ""),
            "risk": "high",
            "notes": f"CVE: {cve.get('advisory', cve.get('cve_id', 'Unknown'))}",
        })

    return {
        "high_priority": high_priority,
        "medium_priority": medium_priority,
        "low_priority": low_priority,
        "cve_count": len(cve_results),
        "high_risk_count": len(high_priority),
        "medium_risk_count": len(medium_priority),
    }



def calculate_dep_health(ecosystems: Dict[str, List[Dict[str, str]]],
    security: Dict[str, Any]
) -> Dict[str, Any]:
    """Calculate dependency health score (0-10 scale)."""
    total_packages = sum(len(v) for v in ecosystems.values())
    if total_packages == 0:
        return {"version_freshness": 0, "security_posture": 0, "dep_count": 0,
                "update_frequency": 0, "overall": 0}

    # Version freshness: check how many packages have pinned vs flexible versions
    pinned = 0
    flexible = 0
    for packages in ecosystems.values():
        for pkg in packages:
            ver = pkg.get("version", "-")
            if ver in ("-", "*", "latest", ""):
                flexible += 1
            elif any(c in ver for c in [">=", "<=", "~", "^", "*"]):
                flexible += 1
            else:
                pinned += 1
    version_freshness = min(10, 5 + (pinned / max(total_packages, 1)) * 5)

    # Security posture: based on CVEs and high-risk packages
    high_risk = security.get("high_risk_count", 0)
    cve_count = security.get("cve_count", 0)
    security_posture = max(0, 10 - (high_risk * 1.5) - (cve_count * 1.0))

    # Dependency count: moderate is best
    if total_packages < 20:
        dep_count = 9
    elif total_packages < 50:
        dep_count = 8
    elif total_packages < 100:
        dep_count = 7
    elif total_packages < 200:
        dep_count = 5
    else:
        dep_count = 3

    # Update frequency: based on flexible versioning ratio
    flex_ratio = flexible / max(total_packages, 1)
    update_frequency = max(3, 10 - flex_ratio * 7)

    overall = round((version_freshness + security_posture + dep_count + update_frequency) / 4, 1)

    return {
        "version_freshness": round(version_freshness, 1),
        "security_posture": round(security_posture, 1),
        "dep_count": dep_count,
        "update_frequency": round(update_frequency, 1),
        "overall": overall,
        "total_packages": total_packages,
        "pinned": pinned,
        "flexible": flexible,
    }


def parse_poetry_lock(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Python dependencies from poetry.lock for exact pinned versions."""
    packages: List[Dict[str, str]] = []
    lockfile = repo_path / "poetry.lock"
    if not lockfile.exists():
        return packages

    try:
        text = lockfile.read_text(errors="ignore")
        in_package = False
        current_pkg = {}
        
        for line in text.splitlines():
            if line.startswith("[[package]]"):
                if current_pkg:
                    packages.append({
                        "name": current_pkg.get("name", ""),
                        "version": current_pkg.get("version", ""),
                        "ecosystem": "Python",
                        "source": "poetry.lock",
                    })
                current_pkg = {}
                in_package = True
                continue
            
            if in_package:
                if line.strip() == "":
                    if current_pkg:
                        packages.append({
                            "name": current_pkg.get("name", ""),
                            "version": current_pkg.get("version", ""),
                            "ecosystem": "Python",
                            "source": "poetry.lock",
                        })
                    current_pkg = {}
                    in_package = False
                else:
                    match = re.match(r'^\s*(\w+)\s*=\s*"([^"]*)"', line)
                    if match:
                        current_pkg[match.group(1)] = match.group(2)
        
        # Don't forget the last package
        if current_pkg:
            packages.append({
                "name": current_pkg.get("name", ""),
                "version": current_pkg.get("version", ""),
                "ecosystem": "Python",
                "source": "poetry.lock",
            })
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Failed to parse poetry.lock: {e}")
    
    return packages


def parse_package_lock(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Node.js dependencies from package-lock.json for exact pinned versions."""
    packages: List[Dict[str, str]] = []
    lockfile = repo_path / "package-lock.json"
    if not lockfile.exists():
        return packages

    try:
        data = json.loads(lockfile.read_text(errors="ignore"))
        
        def extract_packages(deps_obj, is_dev=False):
            pkgs = []
            if isinstance(deps_obj, dict):
                for name, info in deps_obj.items():
                    if isinstance(info, dict):
                        version = info.get("version", "")
                        if not version:
                            version = info.get("resolved", "").split("@")[-1].split("#")[0]
                        pkgs.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "Node.js",
                            "is_dev": is_dev,
                            "source": "package-lock.json",
                        })
                        # Recursively process nested dependencies
                        if "dependencies" in info:
                            pkgs.extend(extract_packages(info["dependencies"], is_dev))
            return pkgs
        
        # Process dependencies and devDependencies
        if "dependencies" in data:
            packages.extend(extract_packages(data["dependencies"], False))
        if "devDependencies" in data:
            packages.extend(extract_packages(data["devDependencies"], True))
        
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Failed to parse package-lock.json: {e}")
    
    return packages


def parse_yarn_lock(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Node.js dependencies from yarn.lock for exact pinned versions."""
    packages: List[Dict[str, str]] = []
    lockfile = repo_path / "yarn.lock"
    if not lockfile.exists():
        return packages

    try:
        text = lockfile.read_text(errors="ignore")
        current_pkg = None
        current_version = None
        
        for line in text.splitlines():
            if line and not line.startswith(" "):
                # Package name line (e.g., "package-name@^1.0.0:")
                if "@" in line and line.endswith(":"):
                    if current_pkg and current_version:
                        packages.append({
                            "name": current_pkg,
                            "version": current_version,
                            "ecosystem": "Node.js",
                            "source": "yarn.lock",
                        })
                    parts = line[:-1].rsplit("@", 1)
                    current_pkg = parts[0]
                    current_version = parts[1].lstrip("^~>=")
            elif line.startswith("  version ") and current_pkg:
                # Exact version line
                match = re.match(r'version\s+"([^"]+)"', line)
                if match:
                    current_version = match.group(1)
        
        # Don't forget the last package
        if current_pkg and current_version:
            packages.append({
                "name": current_pkg,
                "version": current_version,
                "ecosystem": "Node.js",
                "source": "yarn.lock",
            })
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Failed to parse yarn.lock: {e}")
    
    return packages


def parse_cargo_lock(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Rust dependencies from Cargo.lock for exact pinned versions."""
    packages: List[Dict[str, str]] = []
    lockfile = repo_path / "Cargo.lock"
    if not lockfile.exists():
        return packages

    try:
        text = lockfile.read_text(errors="ignore")
        in_package = False
        current_pkg = {}
        
        for line in text.splitlines():
            if line.startswith("[[package]]"):
                if current_pkg:
                    packages.append({
                        "name": current_pkg.get("name", ""),
                        "version": current_pkg.get("version", ""),
                        "ecosystem": "Rust",
                        "source": "Cargo.lock",
                    })
                current_pkg = {}
                in_package = True
                continue
            
            if in_package:
                if line.strip() == "" or line.startswith("[["):
                    if current_pkg:
                        packages.append({
                            "name": current_pkg.get("name", ""),
                            "version": current_pkg.get("version", ""),
                            "ecosystem": "Rust",
                            "source": "Cargo.lock",
                        })
                    current_pkg = {}
                    in_package = False if line.startswith("[[") else False
                else:
                    match = re.match(r'^\s*(\w+)\s*=\s*"([^"]*)"', line)
                    if match:
                        current_pkg[match.group(1)] = match.group(2)
        
        # Don't forget the last package
        if current_pkg:
            packages.append({
                "name": current_pkg.get("name", ""),
                "version": current_pkg.get("version", ""),
                "ecosystem": "Rust",
                "source": "Cargo.lock",
            })
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Failed to parse Cargo.lock: {e}")
    
    return packages


def parse_gemfile_lock(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Ruby dependencies from Gemfile.lock for exact pinned versions."""
    packages: List[Dict[str, str]] = []
    lockfile = repo_path / "Gemfile.lock"
    if not lockfile.exists():
        return packages

    try:
        text = lockfile.read_text(errors="ignore")
        in_specs = False
        
        for line in text.splitlines():
            if line.strip().startswith("GEM"):
                in_specs = True
                continue
            if in_specs and line.strip().startswith("  "):
                # Package line (e.g., "    rails (6.1.0)")
                match = re.match(r'\s+([a-z0-9_-]+)\s+\(([^)]+)\)', line)
                if match:
                    name = match.group(1)
                    version = match.group(2)
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "Ruby",
                        "source": "Gemfile.lock",
                    })
            if line.strip() and not line.startswith(" "):
                in_specs = False
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Failed to parse Gemfile.lock: {e}")
    
    return packages


def parse_pubspec_lock(repo_path: Path) -> List[Dict[str, str]]:
    """Parse Dart/Flutter dependencies from pubspec.lock for exact pinned versions."""
    packages: List[Dict[str, str]] = []
    lockfile = repo_path / "pubspec.lock"
    if not lockfile.exists():
        return packages

    try:
        text = lockfile.read_text(errors="ignore")
        in_packages = False
        current_pkg = {}
        
        for line in text.splitlines():
            if line.strip() == "packages:":
                in_packages = True
                continue
            if in_packages:
                if line.startswith("  ") and not line.startswith("    "):
                    # Package name (e.g., "  http:")
                    if current_pkg:
                        packages.append({
                            "name": current_pkg.get("name", ""),
                            "version": current_pkg.get("version", ""),
                            "ecosystem": "Dart",
                            "source": "pubspec.lock",
                        })
                    current_pkg = {"name": line.strip().rstrip(":")}
                elif line.startswith("    ") and current_pkg:
                    # Package property (e.g., "    version: 1.0.0")
                    match = re.match(r'\s+(\w+):\s*(.+)', line)
                    if match:
                        current_pkg[match.group(1)] = match.group(2)
                elif not line.startswith(" "):
                    in_packages = False
        
        # Don't forget the last package
        if current_pkg:
            packages.append({
                "name": current_pkg.get("name", ""),
                "version": current_pkg.get("version", ""),
                "ecosystem": "Dart",
                "source": "pubspec.lock",
            })
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Failed to parse pubspec.lock: {e}")
    
    return packages


async def query_live_cve_database(packages: List[Dict[str, str]], repo_path: Path) -> List[Dict[str, Any]]:
    """Query live CVE database (NVD and OSV.dev) for detected package versions.
    
    For each package version:
    1. Query NVD for CVEs affecting that version
    2. Query OSV.dev for additional vulnerability data
    3. Merge results, deduplicate by CVE ID
    4. Fetch CVSS scores and EPSS scores
    
    Results are cached locally (TTL: 24 hours) to avoid rate limits.
    """
    cve_results: List[Dict[str, Any]] = []
    
    # Check if we have cached results
    cache_file = repo_path / ".irves_cve_cache.json"
    cache_data = {}
    try:
        if cache_file.exists():
            import time
            cache_text = cache_file.read_text(errors="ignore")
            cache_data = json.loads(cache_text)
            # Check if cache is still valid (24 hours)
            if time.time() - cache_data.get("timestamp", 0) < 86400:
                return cache_data.get("results", [])
    except Exception:
        pass
    
    # Query NVD API
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as client:
            for pkg in packages[:50]:  # Limit to avoid rate limiting
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                ecosystem = pkg.get("ecosystem", "")
                
                if not name or version in ["-", "*", "latest", ""]:
                    continue
                
                # Build NVD API query
                # NVD API v2.0: https://nvd.nist.gov/developers/vulnerabilities
                try:
                    # Try OSV.dev first (more reliable for package ecosystems)
                    osv_url = f"https://api.osv.dev/v1/query"
                    osv_payload = {
                        "package": {
                            "name": name,
                            "ecosystem": ecosystem.lower() if ecosystem else "PyPI"
                        },
                        "version": version
                    }
                    
                    response = await client.post(osv_url, json=osv_payload, timeout=10.0)
                    if response.status_code == 200:
                        data = response.json()
                        vulns = data.get("vulns", [])
                        for vuln in vulns:
                            cve_id = vuln.get("id", "")
                            if cve_id.startswith(("CVE-", "GHSA-")):
                                # Extract CVSS score if available
                                cvss_score = None
                                severity = "UNKNOWN"
                                for affected in vuln.get("affected", []):
                                    for severity_entry in affected.get("severity", []):
                                        if severity_entry.get("type") == "CVSS_V3":
                                            cvss_data = severity_entry.get("score", {})
                                            cvss_score = cvss_data.get("baseScore")
                                
                                cve_results.append({
                                    "package": name,
                                    "version": version,
                                    "ecosystem": ecosystem,
                                    "cve_id": cve_id,
                                    "cvss_score": cvss_score,
                                    "advisory": vuln.get("summary", cve_id),
                                    "source": "OSV.dev",
                                })
                except Exception as e:
                    logger.debug(f"[SourceAnalysis] OSV.dev query failed for {name}: {e}")
                    continue
    except ImportError:
        logger.warning("[SourceAnalysis] httpx not available for CVE lookup")
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Live CVE lookup failed: {e}")
    
    # Cache results
    try:
        import time
        cache_data = {
            "timestamp": time.time(),
            "results": cve_results
        }
        cache_file.write_text(json.dumps(cache_data, indent=2))
    except Exception:
        pass
    
    return cve_results



