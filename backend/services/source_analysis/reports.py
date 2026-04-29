"""
IRVES — Source Analysis Report Builders
Markdown report generation for all 8 analysis categories.
"""

from pathlib import Path
from typing import Dict, List, Any

from services.source_analysis.report_utils import resolve_project_name


def build_scalability_report(repo_path: Path, async_stats: Dict, db_stats: Dict,
    cache_stats: Dict, resource_stats: Dict,
    project_name: str = None
) -> str:
    """Build the full markdown scalability report."""
    project_name = resolve_project_name(repo_path, project_name)
    lines = []

    lines.append(f"# {project_name} Scalability Report")
    lines.append("")

    # Executive summary
    async_count = async_stats.get("async_file_count", 0)
    sync_count = async_stats.get("sync_file_count", 0)
    total_code = async_count + sync_count
    async_pct = (async_count / max(total_code, 1)) * 100

    lines.append("## Executive Summary")
    if total_code > 0:
        lines.append(f"{project_name} has **{async_pct:.0f}%** async/concurrency coverage ({async_count} async files vs {sync_count} sync files). "
                     f"{'Good async adoption.' if async_pct > 50 else 'Consider increasing async coverage for better scalability.'}")
    else:
        lines.append(f"No async patterns detected in {project_name}.")
    lines.append("")

    # Async/Concurrency
    lines.append("## Async & Concurrency")
    lines.append("")
    lines.append(f"- **Async files**: {async_count}")
    lines.append(f"- **Sync-only files**: {sync_count}")
    lines.append(f"- **Async coverage**: {async_pct:.0f}%")
    patterns = async_stats.get("async_patterns", {})
    if patterns:
        lines.append("")
        lines.append("| Pattern | Occurrences |")
        lines.append("|---------|------------|")
        for p, count in sorted(patterns.items(), key=lambda x: -x[1]):
            lines.append(f"| `{p}` | {count} |")
    lines.append("")

    issues = async_stats.get("issues", [])
    if issues:
        lines.append("### Concurrency Anti-Patterns")
        lines.append("")
        for issue in issues[:10]:
            lines.append(f"- **{issue['severity'].upper()}**: {issue['issue']} — `{issue['file']}`")
        lines.append("")

    # Database
    lines.append("## Database Patterns")
    lines.append("")
    orms = db_stats.get("orm_usage", [])
    if orms:
        lines.append(f"- **ORMs detected**: {', '.join(orms)}")
    lines.append(f"- **Files with DB code**: {db_stats.get('db_files', 0)}")
    db_issues = db_stats.get("issues", [])
    if db_issues:
        lines.append("")
        lines.append("### Query Issues")
        lines.append("")
        for issue in db_issues[:10]:
            lines.append(f"- **{issue['severity'].upper()}**: {issue['issue']} — `{issue['file']}`")
    lines.append("")

    # Caching
    lines.append("## Caching")
    lines.append("")
    if cache_stats.get("has_caching"):
        lines.append(f"- **Caching layer present**: Yes")
        tools = cache_stats.get("caching_tools", [])
        if tools:
            lines.append(f"- **Tools**: {', '.join(tools)}")
    else:
        lines.append("- **Caching layer present**: No")
        lines.append("- Consider adding Redis, Memcached, or application-level caching for frequently accessed data")
    hints = cache_stats.get("missing_cache_hints", [])
    for h in hints:
        lines.append(f"- **Missing**: {h}")
    lines.append("")

    # Resource management
    lines.append("## Resource Management")
    lines.append("")
    if resource_stats.get("connection_pooling"):
        lines.append("- **Connection pooling**: Present")
        tools = resource_stats.get("pooling_tools", [])
        if tools:
            lines.append(f"- **Tools**: {', '.join(tools)}")
    else:
        lines.append("- **Connection pooling**: Not detected — consider adding connection pooling for database and HTTP connections")
    lines.append("")

    # Recommendations
    lines.append("## Scalability Recommendations")
    lines.append("")
    if async_pct < 30:
        lines.append("- Increase async/concurrency coverage to handle more load efficiently")
    if not cache_stats.get("has_caching"):
        lines.append("- Add a caching layer (Redis/Memcached) to reduce database load")
    if not resource_stats.get("connection_pooling"):
        lines.append("- Implement connection pooling for database and external service connections")
    if db_issues:
        lines.append("- Fix N+1 query patterns by using eager loading or batch queries")
    if issues:
        lines.append("- Remove blocking calls from async/coroutine contexts")
    if not lines[-1].startswith("-"):
        lines.append("- Architecture appears scalable — maintain current practices")
    lines.append("")

    return "\n".join(lines)


def build_architecture_report(repo_path: Path, tech_stack: Dict, dir_struct: Dict,
    arch_style: Dict, pattern_counts: Dict, coupling: float,
    cohesion: float, import_stats: Dict, observations: Dict,
    project_name: str = None
) -> str:
    """Build the full markdown architecture report."""
    project_name = resolve_project_name(repo_path, project_name)

    lines = []
    lines.append(f"# {project_name} Architecture Report")
    lines.append("")

    # Executive summary
    langs = tech_stack.get("languages", {})
    primary = next(iter(langs), "Unknown")
    styles = arch_style.get("styles", [])
    style_name = styles[0]["name"] if styles else "Unknown"
    total_files = dir_struct.get("total_files", 0)

    lines.append("## Executive Summary")
    lines.append(f"{project_name} is a **{primary}** project using **{style_name}** architecture with {total_files} source files across {len(langs)} language(s).")
    lines.append("")

    # Technology stack
    lines.append("## Technology Stack")
    lines.append("")
    lines.append("| Layer | Technology | Purpose |")
    lines.append("|-------|-----------|---------|")
    for lang, count in list(langs.items())[:8]:
        lines.append(f"| Language | {lang} | {count} source files |")
    for fw in tech_stack.get("frameworks", []):
        lines.append(f"| Framework | {fw} | Application framework |")
    for bt in tech_stack.get("build_tools", []):
        lines.append(f"| Build Tool | {bt} | Package/dependency management |")
    for dep in tech_stack.get("deployment", []):
        lines.append(f"| Deployment | {dep} | Infrastructure |")
    lines.append("")

    # Architecture style
    lines.append("## Architecture Style")
    lines.append("")
    for s in styles:
        conf = s["confidence"]
        marker = "✓" if conf == "high" else "?" if conf == "low" else "~"
        lines.append(f"- **{s['name']}** (confidence: {conf})")
    lines.append("")

    # Module structure
    lines.append("## Module Structure")
    lines.append("")
    lines.append("```")
    lines.append(f"{project_name}/")
    for d, count in dir_struct.get("top_level_dirs", [])[:15]:
        bar = "█" * min(int(count / max(total_files, 1) * 40), 40)
        lines.append(f"├── {d}/ ({count} files) {bar}")
    root_count = dir_struct.get("root_file_count", 0)
    if root_count:
        lines.append(f"└── (root) ({root_count} files)")
    lines.append("```")
    lines.append("")

    # Design patterns
    lines.append("## Design Patterns Detected")
    lines.append("")
    if pattern_counts:
        lines.append("| Pattern | Occurrences | Languages |")
        lines.append("|---------|------------|-----------|")
        for pattern, lang_counts in sorted(pattern_counts.items(), key=lambda x: -sum(x[1].values())):
            total = sum(lang_counts.values())
            langs_str = ", ".join(f"{l} ({c})" for l, c in sorted(lang_counts.items(), key=lambda x: -x[1]))
            lines.append(f"| {pattern.replace('_', ' ').title()} | {total} | {langs_str} |")
    else:
        lines.append("No well-known design patterns detected.")
    lines.append("")

    # Coupling & Cohesion
    lines.append("## Coupling & Cohesion")
    lines.append("")
    coupling_label = "Low" if coupling < 0.3 else "Moderate" if coupling < 0.7 else "High"
    cohesion_label = "High" if cohesion > 0.5 else "Moderate" if cohesion > 0.2 else "Low"
    lines.append(f"- **Coupling score**: {coupling:.0%} ({coupling_label}) — {'modules are well-isolated' if coupling < 0.3 else 'some external dependency' if coupling < 0.7 else 'heavy external dependencies'}")
    lines.append(f"- **Cohesion score**: {cohesion:.0%} ({cohesion_label}) — {'related code grouped together' if cohesion > 0.5 else 'some cross-cutting concerns' if cohesion > 0.2 else 'code may be scattered'}")
    lines.append(f"- **Files with imports**: {import_stats.get('files_with_imports', 0)}")
    lines.append(f"- **Average imports per file**: {import_stats.get('avg_imports_per_file', 0):.1f}")
    top_imp = import_stats.get("top_imported_modules", [])[:5]
    if top_imp:
        lines.append(f"- **Most-imported modules**: {', '.join(f'{m} ({c})' for m, c in top_imp)}")
    lines.append("")

    # Key observations
    strengths = observations.get("strengths", [])
    enhancements = observations.get("enhancements", [])
    if strengths:
        lines.append("## Strengths")
        lines.append("")
        for s in strengths:
            lines.append(f"- {s}")
        lines.append("")
    if enhancements:
        lines.append("## Areas for Enhancement")
        lines.append("")
        for e in enhancements:
            lines.append(f"- {e}")
        lines.append("")

    return "\n".join(lines)


def build_dependencies_report(repo_path: Path, ecosystems: Dict[str, List[Dict[str, str]]],
    classified: Dict[str, Dict[str, List[Dict[str, str]]]],
    security: Dict[str, Any], cve_results: List[Dict[str, Any]],
    health: Dict[str, Any], project_name: str = None
) -> str:
    """Build the full markdown dependencies report."""
    project_name = resolve_project_name(repo_path, project_name)

    lines: List[str] = []
    total_packages = sum(len(v) for v in ecosystems.values())
    ecosystem_names = list(ecosystems.keys())

    # ── Title + Executive Summary ──
    lines.append(f"# {project_name} Dependencies Report")
    lines.append("")
    lines.append("## Executive Summary")
    eco_summary = ", ".join(f"{name} ({len(pkgs)} packages)" for name, pkgs in ecosystems.items())
    lines.append(f"{project_name} has **{total_packages}** total package dependencies across "
                 f"{len(ecosystems)} ecosystem(s) ({eco_summary}).")
    high_risk = security.get("high_risk_count", 0)
    cve_count = security.get("cve_count", 0)
    if high_risk > 0:
        lines.append(f"**{high_risk}** high-risk package(s) and **{cve_count}** known CVE(s) require attention.")
    else:
        lines.append("No high-risk dependencies or known CVEs detected.")
    health_overall = health.get("overall", 0)
    lines.append(f"Dependency health score: **{health_overall}/10**.")
    lines.append("")

    # ── Per-ecosystem detailed tables ──
    for ecosystem, categories in classified.items():
        eco_total = sum(len(pkgs) for pkgs in categories.values())
        lines.append(f"## {ecosystem} Dependencies ({eco_total} packages)")
        lines.append("")

        for cat_name, packages in sorted(categories.items()):
            lines.append(f"### {cat_name} ({len(packages)} packages)")
            lines.append("")
            lines.append("| Package | Version | Purpose / Security Notes |")
            lines.append("|---------|---------|--------------------------|")
            for pkg in packages:
                name = pkg["name"]
                version = pkg.get("version", "-")
                notes = pkg.get("security_notes", "No known issues")
                risk = pkg.get("risk", "low")
                risk_icon = "⚠️" if risk == "high" else ("⚡" if risk == "medium" else "")
                lines.append(f"| {risk_icon} `{name}` | {version} | {notes} |")
            lines.append("")

    # ── CVE Details ──
    if cve_results:
        lines.append("## Known Vulnerabilities (CVEs)")
        lines.append("")
        lines.append("| Package | Ecosystem | Severity | Advisory |")
        lines.append("|---------|-----------|----------|----------|")
        for cve in cve_results:
            lines.append(f"| `{cve.get('package', '?')}` | {cve.get('ecosystem', '?')} | {cve.get('severity', '?')} | {cve.get('advisory', '')[:80]} |")
        lines.append("")

    # ── Security Analysis ──
    lines.append("## Security Vulnerability Analysis")
    lines.append("")

    high = security.get("high_priority", [])
    if high:
        lines.append("### High Priority Vulnerabilities")
        lines.append("")
        for item in high[:15]:
            lines.append(f"- **{item['package']}** ({item['ecosystem']}): {item['notes']}")
        lines.append("")

    medium = security.get("medium_priority", [])
    if medium:
        lines.append("### Medium Priority Vulnerabilities")
        lines.append("")
        for item in medium[:10]:
            lines.append(f"- **{item['package']}** ({item['ecosystem']}): {item['notes']}")
        lines.append("")

    # ── Health Score ──
    lines.append("## Dependency Health Score")
    lines.append("")
    lines.append("| Category | Score | Notes |")
    lines.append("|----------|-------|-------|")
    lines.append(f"| Version Freshness | {health.get('version_freshness', 0)}/10 | {health.get('pinned', 0)} pinned, {health.get('flexible', 0)} flexible |")
    lines.append(f"| Security Posture | {health.get('security_posture', 0)}/10 | {security.get('high_risk_count', 0)} high-risk, {security.get('cve_count', 0)} CVEs |")
    lines.append(f"| Dependency Count | {health.get('dep_count', 0)}/10 | {total_packages} total packages |")
    lines.append(f"| Update Frequency | {health.get('update_frequency', 0)}/10 | Flexible version ratio: {health.get('flexible', 0)}/{total_packages} |")
    lines.append(f"| **Overall Health** | **{health_overall}/10** | {'Good' if health_overall >= 7 else 'Needs improvement' if health_overall >= 5 else 'At risk'} |")
    lines.append("")

    # ── Recommendations ──
    lines.append("## Recommendations")
    lines.append("")

    # Immediate
    lines.append("### Immediate Actions (Security)")
    if high_risk > 0:
        lines.append("- Review and mitigate high-risk dependencies (API key management, native code sandboxing)")
    if cve_count > 0:
        lines.append("- Update packages with known CVEs to patched versions")
    if health.get("flexible", 0) > total_packages * 0.5:
        lines.append("- Pin dependency versions to prevent supply chain attacks")
    if not high_risk and not cve_count:
        lines.append("- No immediate security actions required")
    lines.append("")

    # Medium-term
    lines.append("### Medium-Term Actions (Maintenance)")
    if health.get("flexible", 0) > 0:
        lines.append("- Pin all flexible version specifiers (>=, ^, ~) to exact versions")
    lines.append("- Set up automated dependency scanning in CI/CD (safety, npm audit, cargo audit)")
    lines.append("- Audit for unused dependencies and remove them")
    lines.append("")

    # Long-term
    lines.append("### Long-Term Actions (Architecture)")
    lines.append("- Establish monthly dependency review process")
    lines.append("- Monitor security advisories for all dependencies")
    lines.append("- Consider implementing SBOM (Software Bill of Materials) generation")
    lines.append("")

    # ── Summary ──
    lines.append("## Summary")
    lines.append("")
    strengths = []
    risks = []
    if health_overall >= 7:
        strengths.append("Good overall dependency health score")
    if health.get("pinned", 0) > health.get("flexible", 0):
        strengths.append("Most dependencies use pinned versions")
    if total_packages < 50:
        strengths.append("Moderate dependency footprint")
    if high_risk > 0:
        risks.append(f"{high_risk} high-risk package(s) require mitigation")
    if cve_count > 0:
        risks.append(f"{cve_count} known CVE(s) need patching")
    if health.get("flexible", 0) > total_packages * 0.5:
        risks.append("Majority of dependencies use flexible versioning — supply chain risk")

    if strengths:
        lines.append("**Key Strengths:**")
        for s in strengths:
            lines.append(f"- {s}")
        lines.append("")
    if risks:
        lines.append("**Key Risks:**")
        for r in risks:
            lines.append(f"- {r}")
        lines.append("")

    lines.append(f"Overall Assessment: The dependency management is "
                 f"{'healthy' if health_overall >= 7 else 'adequate but needs improvement' if health_overall >= 5 else 'at risk and requires immediate attention'}. "
                 f"Implementing the recommended security mitigations will significantly reduce the attack surface.")
    lines.append("")

    return "\n".join(lines)


def build_code_quality_report(repo_path: Path, file_sizes: Dict, complexity: Dict,
    duplication: Dict, test_coverage: Dict, dead_code: Dict,
    organization: Dict, quality_score: Dict, project_name: str = None
) -> str:
    """Build the full markdown code quality report."""
    project_name = resolve_project_name(repo_path, project_name)

    lines: List[str] = []
    overall = quality_score.get("overall", 0)

    # ── Title + Executive Summary ──
    lines.append(f"# {project_name} Code Quality Report")
    lines.append("")
    lines.append("## Executive Summary")
    total_loc = file_sizes.get("total_loc", 0)
    source_count = file_sizes.get("source_file_count", 0)
    lines.append(f"{project_name} codebase has **{source_count}** source files with **{total_loc:,}** lines of code.")

    # Brief quality assessment
    if overall >= 7:
        assessment = "good code quality with minor areas for improvement"
    elif overall >= 5:
        assessment = "moderate code quality with significant concerns"
    else:
        assessment = "critical code quality issues requiring immediate attention"

    lines.append(f"The codebase demonstrates {assessment}.")
    lines.append(f"")
    lines.append(f"**Overall Quality Score: {overall}/10**")
    lines.append("")

    # ── 1. Code Complexity ──
    lines.append("## 1. Code Complexity")
    lines.append("")

    # File Size Analysis
    lines.append("### File Size Analysis")
    lines.append("")
    critical_files = [f for f in file_sizes.get("files", []) if f["status"] == "critical"]
    warning_files = [f for f in file_sizes.get("files", []) if f["status"] == "warning"]

    if file_sizes.get("files"):
        lines.append("| File | Lines | Status |")
        lines.append("|------|-------|--------|")
        for f in file_sizes["files"][:15]:
            status_icon = "⚠️ Critical" if f["status"] == "critical" else ("⚡ Warning" if f["status"] == "warning" else "✅ Acceptable")
            lines.append(f"| `{f['file']}` | {f['lines']:,} | {status_icon} |")
        lines.append("")

    lines.append(f"**Total Codebase:** {source_count} source files, {total_loc:,} lines of code")
    lines.append(f"- ⚠️ Critical (>{'1,000'} lines): {file_sizes.get('critical_count', 0)} files")
    lines.append(f"- ⚡ Warning (>500 lines): {file_sizes.get('warning_count', 0)} files")
    lines.append("")

    # Cyclomatic Complexity
    lines.append("### Cyclomatic Complexity Analysis")
    lines.append("")
    tool = complexity.get("tool", "none")
    if tool != "none":
        lines.append(f"Analysis tool: **{tool}**{' (multi-language: Python, Java, Kotlin, JS, TS, C/C++, Go, Ruby, Swift, PHP, Scala, Rust, Dart, Lua)' if tool == 'lizard' else ' (Python only)' if tool == 'radon' else ' (keyword-based estimation)'}")
    lines.append("")

    complex_fns = complexity.get("complex_functions", [])
    if complex_fns:
        lines.append("**Critical/High Complexity Functions:**")
        lines.append("")
        lines.append("| Function | File | Complexity | Lines | Risk Level |")
        lines.append("|----------|------|------------|-------|------------|")
        for fn in complex_fns[:15]:
            level_icon = "🔴 Critical" if fn["level"] == "critical" else "🟠 High"
            lines.append(f"| `{fn['function']}` | `{fn['file']}` | {fn['complexity']} | {fn['lines']} | {level_icon} |")
        lines.append("")

    dist = complexity.get("distribution", {})
    lines.append("**Complexity Distribution:**")
    lines.append("")
    lines.append(f"- 🔴 Critical (>20): {dist.get('critical', 0)} functions")
    lines.append(f"- 🟠 High (11-20): {dist.get('high', 0)} functions")
    lines.append(f"- 🟡 Medium (6-10): {dist.get('medium', 0)} functions")
    lines.append(f"- 🟢 Low (<6): {dist.get('low', 0)} functions")
    lines.append(f"- Average complexity: {complexity.get('avg', 0)}")
    lines.append(f"- Maximum complexity: {complexity.get('max', 0)}")
    lines.append("")

    # ── 2. Code Duplication ──
    lines.append("## 2. Code Duplication")
    lines.append("")
    dups = duplication.get("duplicates", [])
    if dups:
        lines.append("| Signature Pattern | Occurrences | Category |")
        lines.append("|-------------------|-------------|----------|")
        for d in dups[:12]:
            lines.append(f"| `{d['signature']}` | {d['occurrences']} | {d['category']} |")
        lines.append("")

    lines.append(f"**Duplication Score:** {duplication.get('score', 0)}/10")
    dup_count = duplication.get("duplicate_count", 0)
    if dup_count > 10:
        lines.append("Consider extracting common patterns into base classes or mixins.")
    elif dup_count > 0:
        lines.append("Moderate duplication, mostly in common patterns.")
    else:
        lines.append("No significant duplication detected.")
    lines.append("")

    # ── 3. Test Coverage ──
    lines.append("## 3. Test Coverage")
    lines.append("")
    test_count = test_coverage.get("test_files_count", 0)
    source_count_tc = test_coverage.get("source_files_count", 0)
    ratio = test_coverage.get("ratio_pct", 0)

    lines.append(f"**Test Files:** {test_count} | **Source Files:** {source_count_tc} | **Ratio:** {ratio:.1f}%")
    lines.append("")

    if test_coverage.get("test_files"):
        lines.append("**Test Files Detected:**")
        for tf in test_coverage["test_files"][:10]:
            lines.append(f"- `{tf}`")
        lines.append("")

    tq = test_coverage.get("test_quality", {})
    if tq.get("strengths"):
        lines.append("**Test Strengths:**")
        for s in tq["strengths"]:
            lines.append(f"- ✅ {s}")
        lines.append("")
    if tq.get("weaknesses"):
        lines.append("**Test Weaknesses:**")
        for w in tq["weaknesses"]:
            lines.append(f"- ❌ {w}")
        lines.append("")

    lines.append(f"**Test Coverage Score:** {test_coverage.get('score', 0)}/10")
    lines.append("")

    # ── 4. Dead Code ──
    lines.append("## 4. Dead Code")
    lines.append("")
    total_markers = dead_code.get("total_markers", 0)
    commented_blocks = dead_code.get("commented_code_blocks", 0)

    lines.append(f"**TODO/FIXME/HACK Markers:** {total_markers}")
    lines.append(f"**Commented-out Code Blocks:** {commented_blocks}")
    lines.append("")

    top_marker_files = dead_code.get("top_files", [])
    if top_marker_files:
        lines.append("| File | Marker Count | Sample Markers |")
        lines.append("|------|-------------|----------------|")
        for entry in top_marker_files[:8]:
            sample = ", ".join(m["type"] for m in entry.get("markers", []))
            lines.append(f"| `{entry['file']}` | {entry['count']} | {sample} |")
        lines.append("")

    lines.append(f"**Dead Code Score:** {dead_code.get('score', 0)}/10")
    lines.append("")

    # ── 5. Code Organization ──
    lines.append("## 5. Code Organization")
    lines.append("")

    org_strengths = organization.get("strengths", [])
    org_weaknesses = organization.get("weaknesses", [])

    if org_strengths:
        lines.append("**Organization Strengths:**")
        for s in org_strengths:
            lines.append(f"- ✅ {s}")
        lines.append("")
    if org_weaknesses:
        lines.append("**Organization Weaknesses:**")
        for w in org_weaknesses:
            lines.append(f"- ⚠️ {w}")
        lines.append("")

    lines.append(f"**Organization Score:** {organization.get('score', 0)}/10")
    lines.append("")

    # ── 6. Quality Metrics Summary ──
    lines.append("## 6. Code Quality Metrics Summary")
    lines.append("")
    lines.append("| Metric | Score | Status |")
    lines.append("|--------|-------|--------|")
    for metric, key in [("Cyclomatic Complexity", "complexity"), ("Code Duplication", "duplication"),
                        ("Test Coverage", "test_coverage"), ("Dead Code", "dead_code"),
                        ("Code Organization", "organization")]:
        val = quality_score.get(key, 0)
        if val >= 7:
            status = "🟢 Good"
        elif val >= 5:
            status = "🟡 Needs improvement"
        else:
            status = "🔴 Critical"
        lines.append(f"| {metric} | {val}/10 | {status} |")
    lines.append(f"| **Overall Quality** | **{overall}/10** | {'🟢 Good' if overall >= 7 else '🟡 Needs improvement' if overall >= 5 else '🔴 Critical'} |")
    lines.append("")

    # ── 7. Recommendations ──
    lines.append("## 7. Recommendations")
    lines.append("")

    # Immediate
    lines.append("### Immediate Actions (Critical)")
    if quality_score.get("complexity", 0) < 5:
        lines.append("- Refactor high-complexity functions (>20 complexity) into smaller, focused functions")
    if quality_score.get("test_coverage", 0) < 5:
        lines.append("- **Increase test coverage** — add tests for core services and critical paths")
        lines.append(f"  - Target: 40% minimum coverage (currently ~{ratio:.0f}%)")
    if file_sizes.get("critical_count", 0) > 0:
        lines.append(f"- Split {file_sizes['critical_count']} large file(s) exceeding 1,000 lines into smaller modules")
    if quality_score.get("dead_code", 0) < 5:
        lines.append("- Resolve TODO/FIXME markers and remove commented-out code")
    if overall >= 7:
        lines.append("- No critical actions required — focus on maintaining current quality")
    lines.append("")

    # Medium-term
    lines.append("### Medium-Term Actions (Important)")
    if quality_score.get("duplication", 0) < 6:
        lines.append("- Reduce code duplication — create base classes for common patterns")
    if quality_score.get("organization", 0) < 6:
        lines.append("- Improve code organization — split oversized directories")
    lines.append("- Add static analysis tools to CI/CD (linter, type checker)")
    lines.append("- Add pre-commit hooks for code quality enforcement")
    lines.append("")

    # Long-term
    lines.append("### Long-Term Actions (Enhancement)")
    lines.append("- Add comprehensive docstrings to all public functions")
    lines.append("- Create architecture decision records (ADRs)")
    lines.append("- Implement performance monitoring for hot paths")
    lines.append("- Achieve 60%+ test coverage with integration tests")
    lines.append("")

    # ── Summary ──
    lines.append("## Summary")
    lines.append("")
    lines.append(f"{project_name} codebase shows "
                 f"{'good overall quality' if overall >= 7 else 'moderate quality with areas for improvement' if overall >= 5 else 'critical quality concerns'}. ")

    # Key strengths
    key_strengths = []
    key_risks = []
    if quality_score.get("organization", 0) >= 7:
        key_strengths.append("Good code organization")
    if quality_score.get("duplication", 0) >= 7:
        key_strengths.append("Low code duplication")
    if quality_score.get("complexity", 0) >= 7:
        key_strengths.append("Manageable complexity levels")
    if quality_score.get("test_coverage", 0) < 5:
        key_risks.append(f"Test coverage critically low (~{ratio:.0f}%)")
    if quality_score.get("complexity", 0) < 5:
        key_risks.append("High cyclomatic complexity in key functions")
    if file_sizes.get("critical_count", 0) > 0:
        key_risks.append(f"{file_sizes['critical_count']} files exceed 1,000 lines")

    if key_strengths:
        lines.append("**Key Strengths:**")
        for s in key_strengths:
            lines.append(f"- {s}")
        lines.append("")
    if key_risks:
        lines.append("**Key Risks:**")
        for r in key_risks:
            lines.append(f"- {r}")
        lines.append("")

    lines.append(f"Priority: "
                 f"{'Increase test coverage' if quality_score.get('test_coverage', 0) < 5 else 'Reduce complexity' if quality_score.get('complexity', 0) < 5 else 'Continue improving quality'} "
                 f"is the most critical action to improve the quality score from {overall} to 8+.")
    lines.append("")

    return "\n".join(lines)


def build_security_report(repo_path: Path, sast: Dict, secrets: Dict, injection: Dict,
    auth: Dict, crypto: Dict, config: Dict, owasp: Dict, score: Dict,
    secret_storage: Dict = None, secret_rotation: Dict = None,
    secret_validation: Dict = None, git_secrets: Dict = None,
    log_sanitization: Dict = None, secret_score: Dict = None,
    project_name: str = None
) -> str:
    """Build the full markdown security report."""
    project_name = resolve_project_name(repo_path, project_name)

    lines: List[str] = []
    overall = score.get("overall", 0)

    # ── Title + Executive Summary ──
    lines.append(f"# {project_name} Security Report")
    lines.append("")
    lines.append("## Executive Summary")

    if overall >= 7:
        posture = "🟢 Low Risk"
    elif overall >= 5:
        posture = "⚠️ Medium Risk"
    else:
        posture = "🔴 Medium-High Risk"

    lines.append(f"**Overall Security Posture:** {posture}")
    lines.append("")

    crit = secrets.get("critical_count", 0) + sast.get("critical_count", 0)
    high = secrets.get("high_count", 0) + sast.get("high_count", 0)
    med = sast.get("medium_count", 0) + injection.get("sql_count", 0) + injection.get("cmd_count", 0)
    low = sast.get("low_count", 0)

    lines.append(f"**Critical Findings:** {crit} | **High Severity:** {high} | **Medium Severity:** {med} | **Low Severity:** {low}")
    lines.append("")

    # Brief assessment
    if crit > 0:
        lines.append(f"⚠️ **{crit} critical vulnerability(ies)** require immediate attention.")
    if high > 0:
        lines.append(f"🟠 **{high} high-severity issue(s)** need priority remediation.")
    if crit == 0 and high == 0:
        lines.append("No critical or high-severity vulnerabilities detected.")
    lines.append("")

    # ── Critical Vulnerabilities ──
    crit_findings = [f for f in secrets.get("findings", []) if f.get("severity") == "critical"]
    if crit_findings:
        lines.append("## Critical Vulnerabilities")
        lines.append("")
        for i, f in enumerate(crit_findings[:5], 1):
            lines.append(f"### {i}. 🔴 CRITICAL: {f.get('description', 'Security Issue')}")
            lines.append(f"**Location:** `{f.get('file', 'unknown')}` line {f.get('line', 'unknown')}")
            lines.append(f"**Finding:** Value pattern: `{f.get('masked_value', '***')}`")
            # Attack scenario
            if f.get("attack_scenario"):
                lines.append(f"**Attack Scenario:** {f['attack_scenario']}")
            # Impact assessment
            impact = f.get("impact", {})
            if impact:
                impact_str = " | ".join(f"{k.title()}: {v}" for k, v in impact.items())
                lines.append(f"**Impact:** {impact_str}")
            lines.append("")
            lines.append("**Recommendation:**")
            if f.get("remediation"):
                lines.append(f"- {f['remediation']}")
            lines.append("- Remove from source code and version control")
            lines.append("- Use environment variables or secret management")
            lines.append("")

    # ── High Severity ──
    high_findings = [f for f in secrets.get("findings", []) if f.get("severity") == "high"]
    high_findings += injection.get("cmd_findings", [])[:5]
    high_findings += [f for f in config.get("findings", []) if f.get("severity") == "high"]
    if high_findings:
        lines.append("## High Severity Vulnerabilities")
        lines.append("")
        for i, f in enumerate(high_findings[:8], 1):
            desc = f.get("description", f.get("message", "Security Issue"))
            lines.append(f"### {i}. 🟠 HIGH: {desc}")
            lines.append(f"**Location:** `{f.get('file', '?')}`" + (f" line {f.get('line', '?')}" if f.get("line") else ""))
            if f.get("masked_value"):
                lines.append(f"**Value:** `{f['masked_value']}`")
            lines.append("")
            lines.append("**Recommendation:**")
            lines.append("- Address this vulnerability as a priority")
            lines.append("- Implement proper input validation and sanitization")
            lines.append("")

    # ── Medium Severity ──
    med_findings = injection.get("sql_findings", [])[:5]
    med_findings += injection.get("xss_findings", [])[:5]
    med_findings += [f for f in config.get("findings", []) if f.get("severity") == "medium"]
    med_findings += crypto.get("findings", [])[:5]
    if med_findings:
        lines.append("## Medium Severity Vulnerabilities")
        lines.append("")
        for i, f in enumerate(med_findings[:10], 1):
            desc = f.get("description", "Security Issue")
            lines.append(f"### {i}. 🟡 MEDIUM: {desc}")
            lines.append(f"**Location:** `{f.get('file', '?')}`" + (f" line {f.get('line', '?')}" if f.get("line") else ""))
            lines.append("")

    # ── Secret Analysis ──
    if secret_score is not None:
        ss_overall = secret_score.get("overall", 0)
        lines.append("## Secret Analysis")
        lines.append("")
        if ss_overall >= 7:
            lines.append(f"**Overall Secret Security Posture:** 🟢 Low Risk ({ss_overall}/10)")
        elif ss_overall >= 5:
            lines.append(f"**Overall Secret Security Posture:** ⚠️ Medium Risk ({ss_overall}/10)")
        else:
            lines.append(f"**Overall Secret Security Posture:** 🔴 Critical Risk ({ss_overall}/10)")
        lines.append("")

        # Secret Storage
        if secret_storage:
            lines.append("### Secret Storage Analysis")
            lines.append("")
            if secret_storage.get("has_plaintext_storage"):
                lines.append("- ❌ **Secrets stored in plaintext** — no encryption at rest")
            if secret_storage.get("has_encrypted_storage"):
                lines.append("- ✅ Encryption library detected for secret storage")
            else:
                lines.append("- ❌ No encryption library detected for secret storage")
            if secret_storage.get("has_keyring"):
                lines.append("- ✅ OS keyring integration detected")
            else:
                lines.append("- ❌ No OS keyring integration")
            if secret_storage.get("has_dotenv"):
                lines.append("- ✅ Environment variable loading detected")
            for sf in secret_storage.get("findings", [])[:5]:
                lines.append(f"- ⚠️ `{sf['file']}:{sf.get('line', '?')}` — {sf['description']}")
            if secret_storage.get("loose_permissions"):
                lines.append("")
                lines.append("**Loose File Permissions:**")
                for lp in secret_storage["loose_permissions"]:
                    lines.append(f"- `{lp['file']}` — permissions: {lp['permissions']}")
            lines.append("")

        # Secret Rotation
        if secret_rotation:
            lines.append("### Secret Rotation Analysis")
            lines.append("")
            if secret_rotation.get("has_rotation"):
                lines.append("- ✅ Secret rotation mechanism detected")
            else:
                lines.append("- ❌ **No secret rotation mechanism** — secrets never expire")
            if secret_rotation.get("has_expiration"):
                lines.append("- ✅ Expiration mechanism detected")
            else:
                lines.append("- ❌ No expiration for API keys/tokens")
            if secret_rotation.get("has_refresh_token"):
                lines.append("- ✅ Refresh token mechanism detected")
            else:
                lines.append("- ❌ No refresh token mechanism")
            lines.append("")

        # Secret Validation
        if secret_validation:
            lines.append("### Secret Validation Analysis")
            lines.append("")
            if secret_validation.get("has_validation"):
                lines.append("- ✅ API key format validation detected")
            else:
                lines.append("- ❌ No API key format validation")
            if secret_validation.get("empty_defaults", 0) > 0:
                lines.append(f"- ❌ **{secret_validation['empty_defaults']} secret field(s) with empty defaults**")
            for vf in secret_validation.get("findings", [])[:3]:
                lines.append(f"- ⚠️ `{vf['file']}:{vf.get('line', '?')}` — {vf['description']}")
            lines.append("")

        # Git Security
        if git_secrets:
            lines.append("### Git Secret Security")
            lines.append("")
            if git_secrets.get("has_gitignore"):
                if git_secrets.get("ignores_secrets"):
                    lines.append("- ✅ .gitignore excludes secret files")
                else:
                    lines.append("- ⚠️ .gitignore exists but does not exclude secret files")
            else:
                lines.append("- ❌ No .gitignore file")
            if git_secrets.get("has_precommit"):
                if git_secrets.get("git_secrets_tool"):
                    lines.append("- ✅ Pre-commit hook with secret scanning")
                else:
                    lines.append("- ⚠️ Pre-commit config exists but no secret scanning hook")
            else:
                lines.append("- ❌ No pre-commit hooks for secret scanning")
            if git_secrets.get("tool_findings_count", 0) > 0:
                lines.append(f"- ⚠️ detect-secrets found **{git_secrets['tool_findings_count']} potential secret(s)**")
            for gf in git_secrets.get("findings", [])[:5]:
                desc = gf.get("description", "")
                if desc:
                    lines.append(f"- ⚠️ `{gf.get('file', '?')}` — {desc}")
            lines.append("")

        # Log Sanitization
        if log_sanitization:
            lines.append("### Log Sanitization Analysis")
            lines.append("")
            if log_sanitization.get("has_sanitization"):
                lines.append("- ✅ Log sanitization/redaction detected")
            else:
                lines.append("- ❌ No log sanitization — secrets may be exposed in logs")
            if log_sanitization.get("potential_exposure_count", 0) > 0:
                lines.append(f"- ⚠️ **{log_sanitization['potential_exposure_count']} log statement(s)** may expose secrets")
                for lf in log_sanitization.get("findings", [])[:3]:
                    lines.append(f"  - `{lf['file']}:{lf.get('line', '?')}` — {lf['description']}")
            lines.append("")

        # Secret Scorecard
        if secret_score:
            lines.append("### Secret Security Scorecard")
            lines.append("")
            lines.append("| Category | Score | Status |")
            lines.append("|----------|-------|--------|")
            for cat in ["Secret Storage", "Secret Encryption", "Secret Rotation",
                         "Secret Validation", "Git Security", "Secret Audit Trail"]:
                val = secret_score.get(cat, 0)
                if val >= 7:
                    status = "🟢 Good"
                elif val >= 5:
                    status = "🟡 Moderate"
                else:
                    status = "🔴 Critical"
                lines.append(f"| {cat} | {val}/10 | {status} |")
            lines.append(f"| **Overall Secret Security** | **{ss_overall}/10** | {'🟢 Low Risk' if ss_overall >= 7 else '⚠️ Medium Risk' if ss_overall >= 5 else '🔴 Critical Risk'} |")
            lines.append("")

    # ── SAST Findings Summary ──
    lines.append("## SAST Findings Summary")
    lines.append("")

    # SQL Injection
    sql_count = injection.get("sql_count", 0)
    if sql_count == 0:
        lines.append("### SQL Injection Analysis")
        lines.append("**Status:** ✅ Secure — No SQL injection patterns detected")
        lines.append("")
    else:
        lines.append("### SQL Injection Analysis")
        lines.append(f"**Status:** ⚠️ {sql_count} potential SQL injection point(s) detected")
        lines.append("")
        for f in injection.get("sql_findings", [])[:5]:
            lines.append(f"- `{f['file']}:{f['line']}` — {f['description']}")
        lines.append("")

    # Command Injection
    cmd_count = injection.get("cmd_count", 0)
    if cmd_count == 0:
        lines.append("### Command Injection Analysis")
        lines.append("**Status:** ✅ Secure — No command injection patterns detected")
        lines.append("")
    else:
        lines.append("### Command Injection Analysis")
        lines.append(f"**Status:** ⚠️ {cmd_count} potential command injection point(s) detected")
        lines.append("")
        for f in injection.get("cmd_findings", [])[:5]:
            lines.append(f"- `{f['file']}:{f['line']}` — {f['description']}")
        lines.append("")

    # XSS
    xss_count = injection.get("xss_count", 0)
    if xss_count == 0:
        lines.append("### XSS Analysis")
        lines.append("**Status:** ✅ Secure — No XSS patterns detected")
        lines.append("")
    else:
        lines.append("### XSS Analysis")
        lines.append(f"**Status:** ⚠️ {xss_count} potential XSS point(s) detected")
        lines.append("")
        for f in injection.get("xss_findings", [])[:5]:
            lines.append(f"- `{f['file']}:{f['line']}` — {f['description']}")
        lines.append("")

    # ── Authentication Patterns ──
    lines.append("## Authentication Patterns Analysis")
    lines.append("")

    if auth.get("has_oauth"):
        lines.append("### OAuth2 Implementation")
        lines.append("**Status:** ⚠️ Needs Improvement")
        lines.append("")
        lines.append(f"- OAuth2 library detected: ✅")
        lines.append(f"- Rate limiting: {'✅ Detected' if auth.get('has_rate_limit') else '❌ Not detected'}")
        lines.append(f"- CSRF protection: {'✅ Detected' if auth.get('has_csrf') else '❌ Not detected'}")
        lines.append("")
    else:
        lines.append("### OAuth2 Implementation")
        lines.append("**Status:** Not detected")
        lines.append("")

    if auth.get("has_session"):
        lines.append("### Session Management")
        lines.append("**Status:** ⚠️ Needs Improvement")
        lines.append("")
        lines.append(f"- Session middleware: ✅ Detected")
        lines.append(f"- CSRF protection: {'✅ Detected' if auth.get('has_csrf') else '❌ Not detected'}")
        lines.append("")

    for w in auth.get("weaknesses", []):
        lines.append(f"- ⚠️ {w}")
    lines.append("")

    # ── Security Scorecard ──
    lines.append("## Security Scorecard")
    lines.append("")
    lines.append("| Category | Score | Status |")
    lines.append("|----------|-------|--------|")
    for cat in ["Authentication", "Authorization", "Input Validation", "Injection Prevention",
                 "XSS Prevention", "Secret Management", "Data Protection",
                 "Dependency Security", "Logging & Monitoring", "CORS & CSP"]:
        val = score.get(cat, 0)
        if val >= 7:
            status = "🟢 Good"
        elif val >= 5:
            status = "🟡 Moderate"
        else:
            status = "🔴 Needs Improvement"
        lines.append(f"| {cat} | {val}/10 | {status} |")
    lines.append(f"| **Overall Security** | **{overall}/10** | {'🟢 Low Risk' if overall >= 7 else '⚠️ Medium Risk' if overall >= 5 else '🔴 Medium-High Risk'} |")
    lines.append("")

    # ── OWASP Top 10 ──
    lines.append("## OWASP Top 10 (2021) Compliance")
    lines.append("")
    lines.append("| Category | Status | Notes |")
    lines.append("|----------|--------|-------|")
    for cat, info in owasp.items():
        notes = "; ".join(info.get("notes", [])) if info.get("notes") else ""
        lines.append(f"| {cat} | {info['status']} | {notes or '—'} |")
    lines.append("")

    # ── Recommendations ──
    lines.append("## Recommendations")
    lines.append("")

    lines.append("### Immediate Actions (Critical)")
    if crit > 0:
        lines.append(f"- **Rotate/revoke {crit} hardcoded credential(s)** immediately")
    if secrets.get("critical_count", 0) > 0:
        lines.append("- Remove hardcoded secrets from source code and git history")
    if config.get("debug_enabled"):
        lines.append("- Disable debug mode in production configuration")
    if crit == 0 and not config.get("debug_enabled"):
        lines.append("- No critical immediate actions required")
    lines.append("")

    lines.append("### High Priority (Within 1 week)")
    if not auth.get("has_rate_limit") and auth.get("has_oauth"):
        lines.append("- Implement rate limiting on OAuth endpoints")
    if not auth.get("has_csrf"):
        lines.append("- Add CSRF protection to authentication flow")
    if cmd_count > 0:
        lines.append("- Validate all user inputs passed to subprocess/command execution")
    if xss_count > 0:
        lines.append("- Implement XSS sanitization (DOMPurify, marked with sanitize)")
    lines.append("")

    lines.append("### Medium Priority (Within 1 month)")
    if not auth.get("has_rbac"):
        lines.append("- Implement role-based authorization (RBAC)")
    if config.get("missing_headers"):
        lines.append(f"- Add missing security headers: {', '.join(config['missing_headers'][:3])}")
    if crypto.get("weak_hash_count", 0) > 0:
        lines.append("- Replace weak hash algorithms (MD5/SHA1) with SHA-256+")
    lines.append("- Add dependency vulnerability scanning to CI/CD")
    lines.append("")

    lines.append("### Low Priority (Within 3 months)")
    lines.append("- Implement log sanitization and rotation")
    lines.append("- Add security monitoring and alerting")
    lines.append("- Implement database encryption at rest")
    lines.append("- Add API rate limiting")
    lines.append("")

    # ── Summary ──
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**{project_name}** security posture is "
                 f"{'strong' if overall >= 7 else 'moderate with areas for improvement' if overall >= 5 else 'at risk and requires immediate attention'}. ")

    key_risks = []
    if crit > 0:
        key_risks.append(f"{crit} critical vulnerability(ies)")
    if not auth.get("has_rbac"):
        key_risks.append("No authorization system")
    if not auth.get("has_rate_limit") and auth.get("has_oauth"):
        key_risks.append("No rate limiting on auth")
    if xss_count > 0:
        key_risks.append(f"{xss_count} XSS risk point")

    if key_risks:
        lines.append("")
        lines.append("**Key Risks:**")
        for r in key_risks:
            lines.append(f"- {r}")

    lines.append("")
    lines.append(f"Priority: {'Address critical vulnerabilities' if crit > 0 else 'Implement authentication/authorization' if not auth.get('has_rbac') else 'Continue security hardening'} "
                 f"is the most critical action to improve the security score from {overall} to 8+.")
    lines.append("")

    return "\n".join(lines)


def build_secrets_report(repo_path: Path, secrets: Dict, secret_storage: Dict,
    secret_rotation: Dict, secret_validation: Dict, git_secrets: Dict,
    log_sanitization: Dict, secret_score: Dict, project_name: str = None
) -> str:
    """Build the full markdown secrets report (dedicated secrets category)."""
    project_name = resolve_project_name(repo_path, project_name)

    lines: List[str] = []
    ss_overall = secret_score.get("overall", 0)

    # ── Title + Executive Summary ──
    lines.append(f"# {project_name} Secret Analysis Report")
    lines.append("")
    lines.append("## Executive Summary")

    if ss_overall >= 7:
        posture = "🟢 Low Risk"
    elif ss_overall >= 5:
        posture = "⚠️ Medium Risk"
    else:
        posture = "🔴 Critical Risk"

    lines.append(f"**Overall Secret Security Posture:** {posture}")
    lines.append("")

    crit = secrets.get("critical_count", 0)
    high = secrets.get("high_count", 0)
    med = secrets.get("medium_count", 0)

    lines.append(f"**Critical Findings:** {crit} | **High Severity:** {high} | **Medium Severity:** {med} | **Low Severity:** 0")
    lines.append("")

    if crit > 0:
        lines.append(f"⚠️ **{crit} critical vulnerability(ies)** require immediate attention.")
    if high > 0:
        lines.append(f"🟠 **{high} high-severity issue(s)** need priority remediation.")
    if crit == 0 and high == 0:
        lines.append("No hardcoded secrets detected in source code.")
    lines.append("")

    # ── Critical Vulnerabilities (Hardcoded Secrets) ──
    crit_findings = [f for f in secrets.get("findings", []) if f.get("severity") == "critical"]
    if crit_findings:
        lines.append("## Critical Vulnerabilities")
        lines.append("")
        for i, f in enumerate(crit_findings[:8], 1):
            lines.append(f"### {i}. 🔴 CRITICAL: {f.get('description', 'Security Issue')}")
            lines.append(f"**Location:** `{f['file']}` line {f['line']}")
            lines.append(f"**Finding:** Value pattern: `{f.get('masked_value', '***')}`")
            if f.get("attack_scenario"):
                lines.append(f"**Attack Scenario:** {f['attack_scenario']}")
            impact = f.get("impact", {})
            if impact:
                impact_str = " | ".join(f"{k.title()}: {v}" for k, v in impact.items())
                lines.append(f"**Impact:** {impact_str}")
            lines.append("")
            lines.append("**Recommendation:**")
            if f.get("remediation"):
                lines.append(f"- {f['remediation']}")
            lines.append("- Remove from source code and version control")
            lines.append("- Use environment variables or secret management")
            lines.append("")

    # ── High Severity ──
    high_findings = [f for f in secrets.get("findings", []) if f.get("severity") == "high"]
    if high_findings:
        lines.append("## High Severity Vulnerabilities")
        lines.append("")
        for i, f in enumerate(high_findings[:8], 1):
            lines.append(f"### {i}. 🟠 HIGH: {f.get('description', 'Security Issue')}")
            lines.append(f"**Location:** `{f['file']}` line {f['line']}")
            lines.append(f"**Finding:** Value pattern: `{f.get('masked_value', '***')}`")
            if f.get("attack_scenario"):
                lines.append(f"**Attack Scenario:** {f['attack_scenario']}")
            if f.get("remediation"):
                lines.append(f"**Remediation:** {f['remediation']}")
            lines.append("")

    # ── Medium Severity ──
    med_findings = [f for f in secrets.get("findings", []) if f.get("severity") == "medium"]
    if med_findings:
        lines.append("## Medium Severity Vulnerabilities")
        lines.append("")
        for i, f in enumerate(med_findings[:8], 1):
            lines.append(f"### {i}. 🟡 MEDIUM: {f.get('description', 'Security Issue')}")
            lines.append(f"**Location:** `{f['file']}` line {f['line']}")
            if f.get("entropy"):
                lines.append(f"**Entropy:** {f['entropy']} bits/char")
            if f.get("remediation"):
                lines.append(f"**Remediation:** {f['remediation']}")
            lines.append("")

    # ── Secret Storage Analysis ──
    if secret_storage:
        lines.append("## Secret Storage Analysis")
        lines.append("")
        if secret_storage.get("has_plaintext_storage"):
            lines.append("- ❌ **Secrets stored in plaintext** — no encryption at rest")
        if secret_storage.get("has_encrypted_storage"):
            lines.append("- ✅ Encryption library detected for secret storage")
        else:
            lines.append("- ❌ No encryption library detected for secret storage")
        if secret_storage.get("has_keyring"):
            lines.append("- ✅ OS keyring integration detected")
        else:
            lines.append("- ❌ No OS keyring integration")
        if secret_storage.get("has_dotenv"):
            lines.append("- ✅ Environment variable loading detected")
        else:
            lines.append("- ❌ No environment variable loading detected")
        for sf in secret_storage.get("findings", [])[:5]:
            lines.append(f"- ⚠️ `{sf['file']}:{sf.get('line', '?')}` — {sf['description']}")
        if secret_storage.get("loose_permissions"):
            lines.append("")
            lines.append("**Loose File Permissions:**")
            for lp in secret_storage["loose_permissions"]:
                lines.append(f"- `{lp['file']}` — permissions: {lp['permissions']}")
        lines.append("")

        # Storage assessment table
        lines.append("| Component | Storage Method | Encryption | Access Control | Risk Level |")
        lines.append("|-----------|---------------|------------|----------------|------------|")
        env_risk = "🟡 Medium" if not secret_storage.get("has_plaintext_storage") else "🔴 High"
        settings_risk = "🔴 Critical" if secret_storage.get("has_plaintext_storage") else "🟡 Medium"
        lines.append(f"| .env | Plaintext file | {'None' if not secret_storage.get('has_encrypted_storage') else 'Partial'} | File permissions | {env_risk} |")
        lines.append(f"| settings.json | Plaintext JSON | {'None' if not secret_storage.get('has_encrypted_storage') else 'Yes'} | File permissions | {settings_risk} |")
        lines.append(f"| OAuth Tokens | Plaintext JSON | {'None' if not secret_storage.get('has_encrypted_storage') else 'Yes'} | File permissions | {settings_risk} |")
        lines.append("")

    # ── Secret Rotation Analysis ──
    if secret_rotation:
        lines.append("## Secret Rotation Analysis")
        lines.append("")
        if secret_rotation.get("has_rotation"):
            lines.append("- ✅ Secret rotation mechanism detected")
        else:
            lines.append("- ❌ **No secret rotation mechanism** — secrets never expire")
        if secret_rotation.get("has_expiration"):
            lines.append("- ✅ Expiration mechanism detected")
        else:
            lines.append("- ❌ No expiration for API keys/tokens")
        if secret_rotation.get("has_refresh_token"):
            lines.append("- ✅ Refresh token mechanism detected")
        else:
            lines.append("- ❌ No refresh token mechanism")
        lines.append("")

    # ── Secret Validation Analysis ──
    if secret_validation:
        lines.append("## Secret Validation Analysis")
        lines.append("")
        if secret_validation.get("has_validation"):
            lines.append("- ✅ API key format validation detected")
        else:
            lines.append("- ❌ No API key format validation")
        if secret_validation.get("empty_defaults", 0) > 0:
            lines.append(f"- ❌ **{secret_validation['empty_defaults']} secret field(s) with empty defaults**")
        for vf in secret_validation.get("findings", [])[:3]:
            lines.append(f"- ⚠️ `{vf['file']}:{vf.get('line', '?')}` — {vf['description']}")
        lines.append("")

    # ── Git Secret Security ──
    if git_secrets:
        lines.append("## Git Secret Security")
        lines.append("")
        if git_secrets.get("has_gitignore"):
            if git_secrets.get("ignores_secrets"):
                lines.append("- ✅ .gitignore excludes secret files")
            else:
                lines.append("- ⚠️ .gitignore exists but does not exclude secret files (.env, *.key, *.pem)")
        else:
            lines.append("- ❌ No .gitignore file")
        if git_secrets.get("has_precommit"):
            if git_secrets.get("git_secrets_tool"):
                lines.append("- ✅ Pre-commit hook with secret scanning")
            else:
                lines.append("- ⚠️ Pre-commit config exists but no secret scanning hook")
        else:
            lines.append("- ❌ No pre-commit hooks for secret scanning")
        if git_secrets.get("tool_findings_count", 0) > 0:
            lines.append(f"- ⚠️ detect-secrets found **{git_secrets['tool_findings_count']} potential secret(s)**")
        for gf in git_secrets.get("findings", [])[:5]:
            desc = gf.get("description", "")
            if desc:
                lines.append(f"- ⚠️ `{gf.get('file', '?')}` — {desc}")
        lines.append("")

    # ── Log Sanitization Analysis ──
    if log_sanitization:
        lines.append("## Log Sanitization Analysis")
        lines.append("")
        if log_sanitization.get("has_sanitization"):
            lines.append("- ✅ Log sanitization/redaction detected")
        else:
            lines.append("- ❌ No log sanitization — secrets may be exposed in logs")
        if log_sanitization.get("potential_exposure_count", 0) > 0:
            lines.append(f"- ⚠️ **{log_sanitization['potential_exposure_count']} log statement(s)** may expose secrets")
            for lf in log_sanitization.get("findings", [])[:3]:
                lines.append(f"  - `{lf['file']}:{lf.get('line', '?')}` — {lf['description']}")
        lines.append("")

    # ── Best Practices ──
    lines.append("## Best Practices Assessment")
    lines.append("")
    practices = [
        ("Encryption at rest for secrets", secret_storage.get("has_encrypted_storage", False)),
        ("Secret rotation mechanism", secret_rotation.get("has_rotation", False)),
        ("Secret validation", secret_validation.get("has_validation", False)),
        ("Audit logging for secret access", log_sanitization.get("has_sanitization", False)),
        ("OS keyring integration", secret_storage.get("has_keyring", False)),
        ("Secret management service", False),  # Would need more complex detection
        ("Secret expiration tracking", secret_rotation.get("has_expiration", False)),
        ("Secret versioning", False),
        ("Git secret scanning (pre-commit)", git_secrets.get("git_secrets_tool", False)),
        (".gitignore excludes secrets", git_secrets.get("ignores_secrets", False)),
    ]
    for name, implemented in practices:
        lines.append(f"- {'✅' if implemented else '❌'} {name}")
    lines.append("")

    # ── Secret Security Scorecard ──
    lines.append("## Secret Security Scorecard")
    lines.append("")
    lines.append("| Category | Score | Status |")
    lines.append("|----------|-------|--------|")
    for cat in ["Secret Storage", "Secret Encryption", "Secret Rotation",
                 "Secret Validation", "Git Security", "Secret Audit Trail"]:
        val = secret_score.get(cat, 0)
        if val >= 7:
            status = "🟢 Good"
        elif val >= 5:
            status = "🟡 Moderate"
        else:
            status = "🔴 Critical"
        lines.append(f"| {cat} | {val}/10 | {status} |")
    lines.append(f"| **Overall Secret Security** | **{ss_overall}/10** | {'🟢 Low Risk' if ss_overall >= 7 else '⚠️ Medium Risk' if ss_overall >= 5 else '🔴 Critical Risk'} |")
    lines.append("")

    # ── Recommendations ──
    lines.append("## Recommendations")
    lines.append("")

    if crit > 0:
        lines.append("### Immediate Actions (Critical)")
        lines.append(f"- **Rotate/revoke {crit} hardcoded credential(s)** immediately")
        lines.append("- Remove hardcoded secrets from source code and git history")
        lines.append("")

    if high > 0:
        lines.append("### High Priority (Within 1 week)")
        if not secret_storage.get("has_encrypted_storage"):
            lines.append("- Implement encrypted settings storage using cryptography library")
        if not secret_storage.get("has_keyring"):
            lines.append("- Integrate OS keyring for secret storage")
        if secret_storage.get("loose_permissions"):
            lines.append("- Set proper file permissions (600) on secret files")
        if not secret_validation.get("has_validation"):
            lines.append("- Implement secret validation in config")
        lines.append("")

    lines.append("### Medium Priority (Within 1 month)")
    if not secret_rotation.get("has_rotation"):
        lines.append("- Implement secret rotation mechanism")
    if not secret_rotation.get("has_expiration"):
        lines.append("- Add secret expiration tracking")
    if not log_sanitization.get("has_sanitization"):
        lines.append("- Implement log sanitization")
    if not log_sanitization.get("has_sanitization"):
        lines.append("- Add audit logging for secret access")
    lines.append("")

    lines.append("### Low Priority (Within 3 months)")
    if not secret_storage.get("has_keyring"):
        lines.append("- Integrate with OS keyring for secret storage")
    lines.append("- Implement secret management service for production")
    lines.append("- Add secret versioning and rollback")
    lines.append("- Implement secret access monitoring")
    lines.append("")

    # ── Summary ──
    lines.append("## Summary")
    lines.append("")
    if ss_overall < 5:
        lines.append(f"**{project_name}** has critical secret management vulnerabilities that require immediate attention.")
    elif ss_overall < 7:
        lines.append(f"**{project_name}** has moderate secret management with areas for improvement.")
    else:
        lines.append(f"**{project_name}** has good secret management practices in place.")
    lines.append("")

    key_risks = []
    if crit > 0:
        key_risks.append(f"🔴 {crit} critical hardcoded secret(s)")
    if secret_storage.get("has_plaintext_storage"):
        key_risks.append("Secrets stored in plaintext")
    if not secret_rotation.get("has_rotation"):
        key_risks.append("No secret rotation mechanism")
    if not git_secrets.get("ignores_secrets"):
        key_risks.append(".gitignore does not exclude secrets")

    if key_risks:
        lines.append("**Key Risks:**")
        for r in key_risks:
            lines.append(f"- {r}")
        lines.append("")

    lines.append(f"Priority: {'Address critical hardcoded secrets' if crit > 0 else 'Implement encrypted storage' if not secret_storage.get('has_encrypted_storage') else 'Implement secret rotation' if not secret_rotation.get('has_rotation') else 'Continue secret management hardening'} "
                 f"is the most critical action to improve the secret score from {ss_overall} to 8+.")
    lines.append("")

    return "\n".join(lines)


def build_technical_debt_report(
    repo_path: Path,
    summary: Dict,
    findings: List[Dict],
    project_name: str = None,
) -> str:
    """Build a markdown report for technical debt analysis."""
    from services.source_analysis.report_utils import resolve_project_name
    project_name = project_name or resolve_project_name(repo_path)

    lines = []
    lines.append(f"# Technical Debt Report — {project_name}")
    lines.append("")

    td_score = max(0, 10 - summary.get("todo_count", 0) * 0.1 - summary.get("fixme_count", 0) * 0.2 - summary.get("hack_count", 0) * 0.3 - summary.get("legacy_files", 0) * 0.05)
    td_score = round(min(10, max(0, td_score)), 1)

    lines.append("## Scorecard")
    lines.append("")
    lines.append("| Category | Score | Status |")
    lines.append("|---------|-------|--------|")
    lines.append(f"| **Overall** | {td_score}/10 | {'Good' if td_score >= 7 else 'Moderate' if td_score >= 5 else 'Critical'} |")
    lines.append(f"| TODO Density | {summary.get('todo_count', 0)} items | {'High' if summary.get('todo_count', 0) > 20 else 'Low'} |")
    lines.append(f"| FIXME Density | {summary.get('fixme_count', 0)} items | {'High' if summary.get('fixme_count', 0) > 10 else 'Low'} |")
    lines.append(f"| HACK Density | {summary.get('hack_count', 0)} items | {'High' if summary.get('hack_count', 0) > 5 else 'Low'} |")
    lines.append(f"| Legacy Files | {summary.get('legacy_files', 0)} files | {'High' if summary.get('legacy_files', 0) > 20 else 'Low'} |")
    lines.append("")

    lines.append("## Critical Findings")
    lines.append("")
    crit_findings = [f for f in findings if f.get("severity") == "high" or (hasattr(f.get("severity"), "value") and f["severity"].value == "high")]
    if crit_findings:
        for i, f in enumerate(crit_findings[:10], 1):
            lines.append(f"### {i}. {f.get('type', 'Unknown').replace('_', ' ').title()}")
            lines.append(f"- **File:** `{f.get('file_path', 'N/A')}`")
            if f.get("line_number"):
                lines.append(f"- **Line:** {f['line_number']}")
            lines.append(f"- **Message:** {f.get('message', '')}")
            lines.append("")
    else:
        lines.append("No critical technical debt findings.")
        lines.append("")

    lines.append("## Medium Severity")
    lines.append("")
    med_findings = [f for f in findings if f.get("severity") == "medium" or (hasattr(f.get("severity"), "value") and f["severity"].value == "medium")]
    if med_findings:
        for i, f in enumerate(med_findings[:10], 1):
            lines.append(f"### {i}. {f.get('type', 'Unknown').replace('_', ' ').title()}")
            lines.append(f"- **File:** `{f.get('file_path', 'N/A')}`")
            if f.get("line_number"):
                lines.append(f"- **Line:** {f['line_number']}")
            lines.append(f"- **Message:** {f.get('message', '')}")
            lines.append("")
    else:
        lines.append("No medium severity findings.")
        lines.append("")

    lines.append("## Best Practices Assessment")
    lines.append("")
    practices = [
        ("TODO comments tracked and resolved", summary.get("todo_count", 0) < 10),
        ("FIXME comments addressed promptly", summary.get("fixme_count", 0) < 5),
        ("No HACK comments in codebase", summary.get("hack_count", 0) == 0),
        ("Legacy files under control", summary.get("legacy_files", 0) < 10),
    ]
    for label, ok in practices:
        lines.append(f"- {'✅' if ok else '❌'} {label}")
    lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    lines.append("### Immediate Actions")
    if summary.get("hack_count", 0) > 0:
        lines.append("- Resolve all HACK comments — these indicate fragile workarounds")
    if summary.get("fixme_count", 0) > 5:
        lines.append("- Address FIXME comments — these indicate known broken code")
    lines.append("")
    lines.append("### Medium Priority")
    if summary.get("todo_count", 0) > 20:
        lines.append("- Reduce TODO density — convert to tracked issues")
    if summary.get("legacy_files", 0) > 10:
        lines.append("- Refactor legacy files that haven't been updated in over a year")
    lines.append("")

    return "\n".join(lines)


def build_contributor_risk_report(
    repo_path: Path,
    summary: Dict,
    findings: List[Dict],
    project_name: str = None,
) -> str:
    """Build a markdown report for contributor risk analysis."""
    from services.source_analysis.report_utils import resolve_project_name
    project_name = project_name or resolve_project_name(repo_path)

    lines = []
    lines.append(f"# Contributor Risk Report — {project_name}")
    lines.append("")

    bus_factor = summary.get("bus_factor", 0)
    total_contributors = summary.get("total_contributors", 0)
    force_pushes = summary.get("force_pushes", 0)

    cr_score = min(10, bus_factor * 2 + min(total_contributors, 5) * 0.5 - force_pushes * 0.5)
    cr_score = round(max(0, min(10, cr_score)), 1)

    lines.append("## Scorecard")
    lines.append("")
    lines.append("| Category | Score | Status |")
    lines.append("|---------|-------|--------|")
    lines.append(f"| **Overall** | {cr_score}/10 | {'Good' if cr_score >= 7 else 'Moderate' if cr_score >= 5 else 'Critical'} |")
    lines.append(f"| Bus Factor | {bus_factor} | {'Critical' if bus_factor < 2 else 'At Risk' if bus_factor < 4 else 'Healthy'} |")
    lines.append(f"| Total Contributors | {total_contributors} | {'Low' if total_contributors < 3 else 'Moderate' if total_contributors < 8 else 'Good'} |")
    lines.append(f"| Force Pushes | {force_pushes} | {'Concerning' if force_pushes > 0 else 'None'} |")
    lines.append("")

    lines.append("## Critical Findings")
    lines.append("")
    crit_findings = [f for f in findings if f.get("severity") == "high" or (hasattr(f.get("severity"), "value") and f["severity"].value == "high")]
    if crit_findings:
        for i, f in enumerate(crit_findings[:10], 1):
            lines.append(f"### {i}. {f.get('type', 'Unknown').replace('_', ' ').title()}")
            lines.append(f"- **Message:** {f.get('message', '')}")
            if f.get("metadata"):
                lines.append(f"- **Details:** {f['metadata']}")
            lines.append("")
    else:
        lines.append("No critical contributor risk findings.")
        lines.append("")

    lines.append("## Best Practices Assessment")
    lines.append("")
    practices = [
        ("Bus factor ≥ 4", bus_factor >= 4),
        ("Multiple significant contributors", total_contributors >= 3),
        ("No force pushes detected", force_pushes == 0),
        ("Contributor distribution is healthy", bus_factor >= 2),
    ]
    for label, ok in practices:
        lines.append(f"- {'✅' if ok else '❌'} {label}")
    lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    if bus_factor < 2:
        lines.append("### Immediate Actions")
        lines.append("- **Critical:** Bus factor is dangerously low — knowledge is concentrated in too few contributors")
        lines.append("- Encourage code reviews across team members to spread knowledge")
        lines.append("")
    if force_pushes > 0:
        lines.append("### High Priority")
        lines.append("- Investigate force pushes — they can indicate workflow issues or security concerns")
        lines.append("")
    lines.append("### Medium Priority")
    if total_contributors < 5:
        lines.append("- Grow contributor base — more reviewers reduce single-point-of-failure risk")
    lines.append("- Document critical subsystems to reduce dependency on specific individuals")
    lines.append("")

    return "\n".join(lines)
