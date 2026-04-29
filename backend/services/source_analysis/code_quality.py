"""
IRVES — Code Quality Analyzer
Analyzes file sizes, complexity, duplication, test coverage, dead code, and organization.
"""

import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any

from services.source_analysis.reports import build_code_quality_report
from services.source_analysis.report_utils import resolve_project_name
from services.source_analysis.tech_detection import analyze_directory_structure

from database.models import FindingSeverity
from services.git_service import git_service

logger = logging.getLogger(__name__)


SOURCE_EXTS: set = {
    ".py", ".js", ".mjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte",
    ".kt", ".kts", ".java", ".scala", ".groovy",
    ".rs", ".go", ".rb", ".php",
    ".cs", ".fs", ".fsi", ".fsx",
    ".swift", ".m", ".mm",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx",
    ".zig", ".dart", ".ex", ".exs", ".erl",
    ".clj", ".cljs", ".hs", ".lua", ".pl", ".pm", ".r", ".R",
    ".sh", ".bash", ".zsh",
}


TEST_PATTERNS: Dict[str, List[str]] = {
    "Python": ["test_", "_test.py", "tests/", "test/"],
    "JavaScript": [".test.js", ".spec.js", "__tests__/", "__test__/"],
    "TypeScript": [".test.ts", ".spec.ts", ".test.tsx", ".spec.tsx"],
    "Kotlin": ["Test.kt", "Tests.kt", "test/", "androidTest/"],
    "Java": ["Test.java", "Tests.java", "test/", "IT.java"],
    "Go": ["_test.go"],
    "Rust": ["tests/", "#[test]"],
    "Ruby": ["_test.rb", "_spec.rb", "spec/", "test/"],
    "PHP": ["Test.php", "Tests.php", "tests/"],
    "C#": ["Test.cs", "Tests.cs", "TestFixture"],
    "Swift": ["Test.swift", "Tests.swift", "XCTestCase"],
    "Dart": ["_test.dart", "test/"],
    "C/C++": ["Test.cpp", "test.cpp", "TEST_", "catch_", "BOOST_AUTO_TEST"],
}



def get_db():
    """Get database session."""
    from database.session import get_session
    return get_session()


async def analyze_code_quality(repo_path: Path,
    analysis_result_id: str,
) -> Dict[str, Any]:
    """Analyze code quality: produces a comprehensive code quality report as a single finding."""
    logger.info("[SourceAnalysis] Analyzing code quality — generating comprehensive report")

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

        files = await git_service.get_file_list(repo_path)

        # ── 1. File Size Analysis ──
        file_sizes = analyze_file_sizes(repo_path, files)

        # ── 2. Cyclomatic Complexity ──
        complexity = await analyze_cyclomatic_complexity(repo_path, files)

        # ── 3. Code Duplication ──
        duplication = analyze_code_duplication(repo_path, files)

        # ── 4. Test Coverage ──
        test_coverage = analyze_test_coverage(repo_path, files)

        # ── 5. Dead Code ──
        dead_code = analyze_dead_code(repo_path, files)

        # ── 6. Code Organization ──
        dir_structure = analyze_directory_structure(repo_path, files)
        organization = analyze_code_organization(repo_path, dir_structure)

        # ── 7. Code Churn Analysis ──
        code_churn = analyze_code_churn(repo_path, files)

        # ── 8. Defect Density Estimation ──
        defect_density = estimate_defect_density(repo_path, files, complexity)

        # ── 9. Maintainability Index ──
        maintainability_index = calculate_maintainability_index(complexity, duplication, file_sizes)

        # ── 10. Quality Score ──
        quality_score = calculate_quality_score(complexity, duplication, test_coverage, dead_code, organization)

        # ── 11. Build the markdown report ──
        report = build_code_quality_report(
            repo_path, file_sizes, complexity, duplication, test_coverage,
            dead_code, organization, quality_score, project_name=project_name,
            code_churn=code_churn, defect_density=defect_density,
            maintainability_index=maintainability_index
        )

        findings = [{
            "type": "code_quality_report",
            "severity": FindingSeverity.INFO,
            "message": report,
            "tool": "code_quality_analyzer",
            "extra_data": {
                "quality_score": quality_score.get("overall", 0),
                "complexity_score": quality_score.get("complexity", 0),
                "test_score": quality_score.get("test_coverage", 0),
                "maintainability_index": maintainability_index.get("mi_score", 0),
                "high_churn_count": code_churn.get("critical_count", 0) + code_churn.get("high_count", 0),
                "high_defect_count": defect_density.get("critical_count", 0) + defect_density.get("high_count", 0),
            },
        }]

        summary = {
            "total_findings": 1,
            "quality_score": quality_score.get("overall", 0),
            "avg_complexity": complexity.get("avg", 0),
            "test_coverage_pct": test_coverage.get("ratio_pct", 0),
            "maintainability_index": maintainability_index.get("mi_score", 0),
            "high_churn_files": code_churn.get("critical_count", 0) + code_churn.get("high_count", 0),
            "high_defect_files": defect_density.get("critical_count", 0) + defect_density.get("high_count", 0),
        }

    except Exception as e:
        logger.error(f"[SourceAnalysis] Code quality analysis failed: {e}")
        findings = [{
            "type": "code_quality_report",
            "severity": FindingSeverity.INFO,
            "message": f"# Code Quality Report\n\nAnalysis failed: {e}",
            "tool": "code_quality_analyzer",
        }]
        summary = {"total_findings": 1}

    summary["total_findings"] = len(findings)
    return {
        "summary_metrics": summary,
        "detailed_findings": {},
        "findings": findings,
    }


def analyze_file_sizes(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze file sizes across all source files."""
    file_data: List[Dict[str, Any]] = []
    total_loc = 0
    source_file_count = 0

    for f in files:
        ext = Path(f).suffix.lower()
        if ext not in SOURCE_EXTS:
            continue
        full_path = repo_path / f
        try:
            if not full_path.exists():
                continue
            line_count = sum(1 for _ in full_path.open(errors="ignore"))
            total_loc += line_count
            source_file_count += 1

            if line_count > 1000:
                status = "critical"
            elif line_count > 500:
                status = "warning"
            else:
                status = "acceptable"

            file_data.append({
                "file": f,
                "lines": line_count,
                "status": status,
                "ext": ext,
            })
        except Exception:
            continue

    # Sort by line count descending
    file_data.sort(key=lambda x: -x["lines"])

    critical = [f for f in file_data if f["status"] == "critical"]
    warning = [f for f in file_data if f["status"] == "warning"]

    return {
        "files": file_data[:30],  # top 30
        "total_loc": total_loc,
        "source_file_count": source_file_count,
        "critical_count": len(critical),
        "warning_count": len(warning),
        "acceptable_count": len(file_data) - len(critical) - len(warning),
    }


async def analyze_cyclomatic_complexity(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze cyclomatic complexity using Lizard (multi-language) or Radon (Python) or heuristic fallback."""
    complex_functions: List[Dict[str, Any]] = []
    distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    avg_complexity = 0.0
    max_complexity = 0
    tool_used = "none"

    # ── Try Lizard first (supports 15+ languages) ──
    try:
        import subprocess, sys
        venv_bin = Path(sys.executable).parent
        lizard_cmd = str(venv_bin / "lizard") if (venv_bin / "lizard").exists() else "lizard"
        result = subprocess.run(
            [lizard_cmd, str(repo_path)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode in [0, 1] and result.stdout:
            total_cc = 0
            func_count = 0
            # Lizard text format per line:
            # NLOC  CCN  token  PARAM  length  function_name@start-end@/full/path/to/file.ext
            # Header lines start with = or - or "NLOC"
            lizard_line_re = re.compile(
                r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)@(\d+-\d+)@(\S+)'
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("-") or line.startswith("Total"):
                    continue
                match = lizard_line_re.search(line)
                if not match:
                    continue

                func_name = match.group(6)
                lines_range = match.group(7)
                file_path = match.group(8)
                nloc = int(match.group(1))
                cc = int(match.group(2))

                total_cc += cc
                func_count += 1
                max_complexity = max(max_complexity, cc)

                if cc > 20:
                    level = "critical"
                elif cc > 10:
                    level = "high"
                elif cc > 5:
                    level = "medium"
                else:
                    level = "low"

                distribution[level] += 1

                if cc > 10:
                    # Make file path relative
                    if file_path.startswith(str(repo_path)):
                        file_path = file_path[len(str(repo_path)):].lstrip("/")
                    complex_functions.append({
                        "function": func_name,
                        "file": file_path,
                        "complexity": cc,
                        "lines": nloc,
                        "level": level,
                    })

            if func_count > 0:
                avg_complexity = round(total_cc / func_count, 1)
            tool_used = "lizard"
    except (ImportError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # ── Fallback: Radon (Python only) ──
    if tool_used == "none":
        try:
            import subprocess, sys
            venv_bin = Path(sys.executable).parent
            radon_cmd = str(venv_bin / "radon") if (venv_bin / "radon").exists() else "radon"
            result = subprocess.run(
                [radon_cmd, "cc", str(repo_path), "-a", "-s"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0 and result.stdout:
                total_cc = 0
                func_count = 0
                for line in result.stdout.splitlines():
                    # Radon format: "F function_name (file.py:line) - A complexity (X)"
                    match = re.search(r'\((\d+)\)\s*-\s*[A-F]\s+(\d+)', line)
                    if match:
                        cc = int(match.group(2))
                        total_cc += cc
                        func_count += 1
                        max_complexity = max(max_complexity, cc)

                        if cc > 20:
                            level = "critical"
                        elif cc > 10:
                            level = "high"
                        elif cc > 5:
                            level = "medium"
                        else:
                            level = "low"
                        distribution[level] += 1

                        if cc > 10:
                            name_match = re.search(r'^\s*\w+\s+(\S+)', line)
                            complex_functions.append({
                                "function": name_match.group(1) if name_match else "?",
                                "file": "?",
                                "complexity": cc,
                                "lines": 0,
                                "level": level,
                            })

                if func_count > 0:
                    avg_complexity = round(total_cc / func_count, 1)
                tool_used = "radon"
        except (ImportError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # ── Fallback: heuristic (count branching keywords per function) ──
    if tool_used == "none":
        total_cc = 0
        func_count = 0
        branch_pattern = re.compile(
            r'\b(if|elif|else|for|while|case|catch|except|and|or|&&|\|\|)\b'
        )
        for f in files[:200]:
            ext = Path(f).suffix.lower()
            if ext not in SOURCE_EXTS:
                continue
            full_path = repo_path / f
            if not full_path.exists():
                continue
            try:
                text = full_path.read_text(errors="ignore")
                # Rough heuristic: count branch keywords in entire file
                branches = len(branch_pattern.findall(text))
                if branches > 0:
                    # Estimate ~5 functions per file on average
                    est_cc = max(1, branches // 5)
                    total_cc += est_cc * 5
                    func_count += 5
                    max_complexity = max(max_complexity, est_cc)
                    if est_cc > 20:
                        distribution["critical"] += 1
                        complex_functions.append({"function": f"(in {f})", "file": f, "complexity": est_cc, "lines": 0, "level": "critical"})
                    elif est_cc > 10:
                        distribution["high"] += 1
                    elif est_cc > 5:
                        distribution["medium"] += 1
                    else:
                        distribution["low"] += 1
            except Exception:
                continue
        if func_count > 0:
            avg_complexity = round(total_cc / func_count, 1)
        tool_used = "heuristic"

    # Sort complex functions by complexity descending
    complex_functions.sort(key=lambda x: -x["complexity"])

    return {
        "complex_functions": complex_functions[:20],
        "distribution": distribution,
        "avg": avg_complexity,
        "max": max_complexity,
        "tool": tool_used,
    }


def analyze_code_duplication(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze code duplication via heuristic pattern detection across all languages."""
    # Track function/method signatures
    sig_counts: Dict[str, int] = {}
    sig_files: Dict[str, List[str]] = {}

    # Regex patterns per language for function definitions
    func_patterns = [
        # Python: def name(args)
        re.compile(r'^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)', re.MULTILINE),
        # Kotlin/Java/Scala: fun name(args) / void name(args) / Type name(args)
        re.compile(r'^\s*(?:fun|public|private|protected|internal|override|static|suspend)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)', re.MULTILINE),
        # JavaScript/TypeScript: function name(args) / const name = (args) => / name(args) {
        re.compile(r'(?:function\s+|const\s+|let\s+|var\s+)([A-Za-z_][A-Za-z0-9_]*)\s*[=\(]\s*(?:\(([^)]*)\)|([^)]*))', re.MULTILINE),
        # Go: func name(args) / func (r Type) name(args)
        re.compile(r'func\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)', re.MULTILINE),
        # Rust: fn name(args) / pub fn name(args)
        re.compile(r'(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)', re.MULTILINE),
        # Ruby: def name(args)
        re.compile(r'def\s+([A-Za-z_][A-Za-z0-9_!?]*)\s*\(?([^)]*)\)?', re.MULTILINE),
        # PHP: function name(args)
        re.compile(r'function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)', re.MULTILINE),
        # C#: Type Name(args) / void Name(args)
        re.compile(r'(?:public|private|protected|internal|static)\s+\w+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)', re.MULTILINE),
        # Swift: func name(args)
        re.compile(r'func\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)', re.MULTILINE),
        # Dart: Type name(args) / void name(args)
        re.compile(r'(?:void|static|async)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)', re.MULTILINE),
    ]

    for f in files[:300]:
        ext = Path(f).suffix.lower()
        if ext not in SOURCE_EXTS:
            continue
        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        for pattern in func_patterns:
            for match in pattern.finditer(text):
                name = match.group(1)
                args_str = match.group(2) if match.group(2) else ""
                arg_count = len([a.strip() for a in args_str.split(",") if a.strip()]) if args_str else 0
                # Create a signature key: name(arg_count)
                sig = f"{name}({arg_count} args)"
                sig_counts[sig] = sig_counts.get(sig, 0) + 1
                sig_files.setdefault(sig, []).append(f)

    # Find duplicate signatures (appearing 3+ times)
    duplicates = []
    for sig, count in sorted(sig_counts.items(), key=lambda x: -x[1]):
        if count >= 3 and not sig.startswith("__"):
            category = "Boilerplate"
            name = sig.split("(")[0]
            if name in ("run", "execute", "process", "handle", "perform"):
                category = "Tool runner pattern"
            elif name in ("parse", "can_parse", "validate", "transform"):
                category = "Parser pattern"
            elif name in ("to_dict", "to_json", "from_dict", "from_json", "serialize"):
                category = "Serialization pattern"
            elif name in ("get", "set", "update", "delete", "create"):
                category = "CRUD pattern"
            elif name in ("on_message", "on_error", "on_connect", "on_close"):
                category = "Handler pattern"
            duplicates.append({
                "signature": sig,
                "occurrences": count,
                "files": sig_files[sig][:5],
                "category": category,
            })

    # Duplication score: 10 = no duplication, 0 = heavy duplication
    dup_count = len(duplicates)
    if dup_count == 0:
        score = 9
    elif dup_count < 5:
        score = 7
    elif dup_count < 10:
        score = 6
    elif dup_count < 20:
        score = 4
    else:
        score = 3

    return {
        "duplicates": duplicates[:15],
        "duplicate_count": dup_count,
        "score": score,
    }


def analyze_test_coverage(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze test coverage across all languages."""
    test_files: List[str] = []
    source_files: List[str] = []
    covered_dirs: set = set()
    uncovered_dirs: set = set()

    for f in files:
        ext = Path(f).suffix.lower()
        if ext not in SOURCE_EXTS:
            continue

        f_lower = f.lower()
        is_test = False

        # Check language-specific test patterns
        for lang, patterns in TEST_PATTERNS.items():
            for pattern in patterns:
                if pattern in f_lower:
                    is_test = True
                    break
            if is_test:
                break

        # Generic test detection
        if not is_test:
            if any(kw in f_lower for kw in ["test", "spec", "__test", "mock", "fixture", "stub"]):
                is_test = True

        if is_test:
            test_files.append(f)
            # Mark parent directory as covered
            parts = Path(f).parts
            for i in range(1, len(parts)):
                covered_dirs.add("/".join(parts[:i]))
        else:
            source_files.append(f)
            parts = Path(f).parts
            for i in range(1, len(parts)):
                uncovered_dirs.add("/".join(parts[:i]))

    # Directories that have source but no tests
    truly_uncovered = uncovered_dirs - covered_dirs

    ratio = len(test_files) / max(len(source_files), 1) * 100

    # Test coverage score
    if ratio >= 40:
        score = 9
    elif ratio >= 20:
        score = 7
    elif ratio >= 10:
        score = 5
    elif ratio >= 5:
        score = 3
    else:
        score = 2

    # Detect test quality indicators
    test_quality = {"strengths": [], "weaknesses": []}
    has_async_test = False
    has_fixture = False
    for tf in test_files[:20]:
        full_path = repo_path / tf
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
            if "async" in text or "await" in text or "asyncio" in text:
                has_async_test = True
            if "fixture" in text or "setUp" in text or "beforeEach" in text or "@Before" in text:
                has_fixture = True
        except Exception:
            continue

    if has_async_test:
        test_quality["strengths"].append("Async test support detected")
    if has_fixture:
        test_quality["strengths"].append("Test fixtures detected")
    if len(test_files) > 0:
        test_quality["strengths"].append(f"{len(test_files)} test file(s) present")
    if ratio < 10:
        test_quality["weaknesses"].append("Critically low test coverage")
    if len(test_files) == 0:
        test_quality["weaknesses"].append("No test files found")
    if not has_fixture:
        test_quality["weaknesses"].append("No test fixtures detected")

    return {
        "test_files": test_files[:20],
        "source_files_count": len(source_files),
        "test_files_count": len(test_files),
        "ratio_pct": round(ratio, 1),
        "uncovered_dirs": sorted(truly_uncovered)[:10],
        "score": score,
        "test_quality": test_quality,
    }


def analyze_dead_code(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze dead code markers across all languages."""
    marker_patterns = [
        (re.compile(r'\b(TODO|FIXME|HACK|XXX|DEPRECATED|NOSONAR|OPTIMIZE|REFACTOR)\b', re.IGNORECASE), "marker"),
    ]

    markers_by_file: Dict[str, List[Dict[str, str]]] = {}
    total_markers = 0
    commented_code_blocks = 0

    for f in files[:300]:
        ext = Path(f).suffix.lower()
        if ext not in SOURCE_EXTS:
            continue
        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        # Find TODO/FIXME/HACK markers
        for pattern, mtype in marker_patterns:
            for match in pattern.finditer(text):
                marker_text = match.group(1).upper()
                # Get surrounding context (the rest of the line)
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                context = text[line_start:line_end].strip()[:100]

                markers_by_file.setdefault(f, []).append({
                    "type": marker_text,
                    "context": context,
                })
                total_markers += 1

        # Detect commented-out code blocks (3+ consecutive comment lines that look like code)
        comment_prefix = "#"  # default Python
        if ext in (".js", ".mjs", ".ts", ".jsx", ".tsx", ".java", ".kt", ".kts",
                   ".go", ".rs", ".swift", ".c", ".h", ".cpp", ".hpp", ".cs",
                   ".scala", ".dart", ".php"):
            comment_prefix = "//"
        elif ext in (".rb", ".ex", ".exs", ".lua", ".pl", ".r", ".R", ".sh", ".bash", ".zsh"):
            comment_prefix = "#"

        consecutive_comments = 0
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(comment_prefix) and len(stripped) > len(comment_prefix) + 3:
                # Check if it looks like code (contains =, (), {}, [], import, return, if, for)
                content = stripped[len(comment_prefix):].strip()
                if any(kw in content for kw in ["=", "(", "import", "return", "if ", "for ", "def ", "fun ", "func ", "var ", "let ", "const "]):
                    consecutive_comments += 1
                else:
                    consecutive_comments = 0
            else:
                if consecutive_comments >= 3:
                    commented_code_blocks += 1
                consecutive_comments = 0

    # Score: 10 = no dead code, lower = more dead code
    if total_markers == 0 and commented_code_blocks == 0:
        score = 9
    elif total_markers < 5:
        score = 7
    elif total_markers < 15:
        score = 5
    elif total_markers < 30:
        score = 4
    else:
        score = 3

    # Sort files by marker count
    top_files = sorted(markers_by_file.items(), key=lambda x: -len(x[1]))[:10]

    return {
        "total_markers": total_markers,
        "commented_code_blocks": commented_code_blocks,
        "top_files": [{"file": f, "count": len(m), "markers": m[:3]} for f, m in top_files],
        "score": score,
    }


def analyze_code_organization(repo_path: Path, dir_structure: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze code organization quality."""
    strengths: List[str] = []
    weaknesses: List[str] = []

    # Check for common good patterns
    top_dirs = dir_structure.get("top_level", {})

    good_patterns = {
        "src": "Source code separation",
        "lib": "Library separation",
        "app": "Application module",
        "test": "Test directory",
        "tests": "Test directory",
        "config": "Configuration separation",
        "docs": "Documentation directory",
        "scripts": "Script separation",
        "utils": "Utility module separation",
        "models": "Model/data layer separation",
        "routes": "Route/controller separation",
        "services": "Service/business logic layer",
        "controllers": "Controller separation",
        "views": "View/presentation layer",
    }

    for dirname, desc in good_patterns.items():
        if dirname in top_dirs:
            strengths.append(f"{desc} ({dirname}/)")

    # Check for oversized directories
    for dirname, info in top_dirs.items():
        file_count = info.get("file_count", 0) if isinstance(info, dict) else info
        if file_count > 30:
            weaknesses.append(f"`{dirname}/` directory is large ({file_count} files) — consider splitting")

    # Check for empty directories
    empty_dirs = []
    for dirname, info in top_dirs.items():
        file_count = info.get("file_count", 0) if isinstance(info, dict) else info
        if file_count == 0 or (isinstance(info, dict) and info.get("total_files", 0) == 0):
            empty_dirs.append(dirname)

    if empty_dirs:
        weaknesses.append(f"Empty directories found: {', '.join(empty_dirs[:3])}")

    # Check naming consistency
    has_snake_case = any(d == d.lower() and "_" in d for d in top_dirs)
    has_kebab_case = any("-" in d for d in top_dirs)
    has_camel_case = any(d[0].isupper() and any(c.isupper() for c in d[1:]) for d in top_dirs)
    naming_styles = sum(1 for x in [has_snake_case, has_kebab_case, has_camel_case] if x)
    if naming_styles > 1:
        weaknesses.append("Inconsistent directory naming conventions")
    else:
        strengths.append("Consistent directory naming conventions")

    # Score
    score = 5  # base
    score += min(2, len(strengths))
    score -= min(2, len(weaknesses))
    score = max(1, min(10, score))

    return {
        "strengths": strengths,
        "weaknesses": weaknesses,
        "empty_dirs": empty_dirs,
        "score": score,
    }



def analyze_code_churn(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze code churn: how frequently files change relative to their size.
    
    Churn metric: (commits_last_90_days / lines_of_code) * 1000
    High churn + high complexity = elevated risk.
    """
    churn_data: List[Dict[str, Any]] = []
    
    try:
        # Get commit history for files
        from services.git_service import GitService
        git_service = GitService()
        
        for f in files[:200]:
            ext = Path(f).suffix.lower()
            if ext not in SOURCE_EXTS:
                continue
            
            full_path = repo_path / f
            if not full_path.exists():
                continue
            
            try:
                # Get line count
                line_count = sum(1 for _ in full_path.open(errors="ignore"))
                
                # Get commit count for last 90 days
                commits = git_service.get_file_commit_count(repo_path, f, days=90)
                
                # Calculate churn metric
                if line_count > 0:
                    churn = (commits / line_count) * 1000
                else:
                    churn = 0
                
                # Determine risk level
                if churn > 50:
                    risk = "critical"
                elif churn > 20:
                    risk = "high"
                elif churn > 10:
                    risk = "medium"
                else:
                    risk = "low"
                
                if risk in ["critical", "high", "medium"]:
                    churn_data.append({
                        "file": f,
                        "lines": line_count,
                        "commits_90d": commits,
                        "churn": round(churn, 2),
                        "risk": risk,
                    })
            except Exception:
                continue
        
        # Sort by churn descending
        churn_data.sort(key=lambda x: -x["churn"])
        
        critical_count = sum(1 for c in churn_data if c["risk"] == "critical")
        high_count = sum(1 for c in churn_data if c["risk"] == "high")
        medium_count = sum(1 for c in churn_data if c["risk"] == "medium")
        
        return {
            "high_churn_files": churn_data[:20],
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "total_analyzed": len(churn_data),
        }
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Code churn analysis failed: {e}")
        return {
            "high_churn_files": [],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "total_analyzed": 0,
        }


def estimate_defect_density(repo_path: Path, files: List[str], complexity: Dict) -> Dict[str, Any]:
    """Estimate defect density: bug-prone patterns per 1,000 lines.
    
    Identifies bug-prone patterns: TODO/FIXME density, except without exception type,
    mutable default arguments, etc. Weighted by complexity.
    """
    defect_patterns: List[Dict[str, Any]] = []
    
    # Bug-prone patterns
    bug_patterns = [
        # TODO/FIXME comments
        (re.compile(r'(?:TODO|FIXME|HACK|XXX|BUG)\s*[:]', re.IGNORECASE), "Technical debt marker"),
        # Bare except clauses
        (re.compile(r'except\s*:', re.IGNORECASE), "Bare except clause"),
        # Mutable default arguments
        (re.compile(r'def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\())', re.IGNORECASE), "Mutable default argument"),
        # Print statements in production code
        (re.compile(r'print\s*\(', re.IGNORECASE), "Print statement (potential debug leftover)"),
        # Commented out code
        (re.compile(r'^\s*#\s*(?:def|class|if|for|while|import|from)', re.IGNORECASE), "Commented code"),
    ]
    
    for f in files[:200]:
        ext = Path(f).suffix.lower()
        if ext not in SOURCE_EXTS:
            continue
        
        full_path = repo_path / f
        if not full_path.exists():
            continue
        
        try:
            text = full_path.read_text(errors="ignore")
            line_count = sum(1 for _ in full_path.open(errors="ignore"))
            
            if line_count == 0:
                continue
            
            file_defects = []
            for pattern, desc in bug_patterns:
                matches = list(pattern.finditer(text))
                if matches:
                    for match in matches:
                        line_num = text[:match.start()].count("\n") + 1
                        file_defects.append({
                            "line": line_num,
                            "pattern": desc,
                        })
            
            if file_defects:
                # Calculate defect density per 1,000 lines
                defect_density = (len(file_defects) / line_count) * 1000
                
                # Get complexity for this file (if available)
                file_complexity = "medium"
                for func in complexity.get("complex_functions", []):
                    if func.get("file") == f:
                        if func.get("level") in ["critical", "high"]:
                            file_complexity = "high"
                        break
                
                # Risk level based on defect density and complexity
                if defect_density > 50 or (defect_density > 30 and file_complexity == "high"):
                    risk = "critical"
                elif defect_density > 30 or (defect_density > 20 and file_complexity == "high"):
                    risk = "high"
                elif defect_density > 15:
                    risk = "medium"
                else:
                    risk = "low"
                
                if risk in ["critical", "high", "medium"]:
                    defect_patterns.append({
                        "file": f,
                        "lines": line_count,
                        "defect_count": len(file_defects),
                        "defect_density": round(defect_density, 2),
                        "complexity": file_complexity,
                        "risk": risk,
                        "defects": file_defects[:5],
                    })
        except Exception:
            continue
    
    # Sort by defect density descending
    defect_patterns.sort(key=lambda x: -x["defect_density"])
    
    critical_count = sum(1 for d in defect_patterns if d["risk"] == "critical")
    high_count = sum(1 for d in defect_patterns if d["risk"] == "high")
    medium_count = sum(1 for d in defect_patterns if d["risk"] == "medium")
    
    return {
        "high_defect_files": defect_patterns[:20],
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "total_analyzed": len(defect_patterns),
    }


def calculate_maintainability_index(complexity: Dict, duplication: Dict, 
                                  file_sizes: Dict) -> Dict[str, Any]:
    """Calculate Microsoft's Maintainability Index (MI) for the codebase.
    
    MI = 171 - 5.2 * ln(Halstead Volume) - 0.23 * Cyclomatic Complexity - 16.2 * ln(Lines of Code)
    
    Scale:
    - 0-20: Unmaintainable
    - 20-40: Difficult
    - 40-60: Moderate
    - 60-80: Good
    - 80-100: Excellent
    """
    import math
    
    # Get average complexity
    avg_complexity = complexity.get("avg", 0)
    if avg_complexity == 0:
        avg_complexity = 5  # Default if not available
    
    # Get total lines of code
    total_loc = file_sizes.get("total_loc", 0)
    if total_loc == 0:
        total_loc = 1000  # Default if not available
    
    # Estimate Halstead Volume (simplified)
    # HV = N * log2(n) where N is total operators/operands, n is unique operators/operands
    # Since we don't have Halstead analysis, we'll estimate based on LOC
    # Typical HV is roughly 0.5-2x LOC depending on language
    estimated_hv = total_loc * 1.5
    
    # Calculate MI
    try:
        mi = 171 - (5.2 * math.log(estimated_hv)) - (0.23 * avg_complexity) - (16.2 * math.log(total_loc))
    except (ValueError, ZeroDivisionError):
        mi = 50  # Default if calculation fails
    
    # Normalize to 0-100 scale
    mi = max(0, min(100, mi))
    
    # Determine rating
    if mi >= 80:
        rating = "Excellent"
        rating_desc = "Highly maintainable code"
    elif mi >= 60:
        rating = "Good"
        rating_desc = "Maintainable with moderate effort"
    elif mi >= 40:
        rating = "Moderate"
        rating_desc = "Requires significant maintenance effort"
    elif mi >= 20:
        rating = "Difficult"
        rating_desc = "Difficult to maintain"
    else:
        rating = "Unmaintainable"
        rating_desc = "Code is difficult to maintain"
    
    return {
        "mi_score": round(mi, 2),
        "rating": rating,
        "description": rating_desc,
        "avg_complexity": avg_complexity,
        "total_loc": total_loc,
    }


def calculate_quality_score(complexity: Dict, duplication: Dict, test_coverage: Dict,
    dead_code: Dict, organization: Dict
) -> Dict[str, Any]:
    """Calculate overall code quality score (0-10 scale)."""
    # Complexity score: based on % of high-complexity functions
    dist = complexity.get("distribution", {})
    total_funcs = sum(dist.values())
    if total_funcs > 0:
        critical_ratio = dist.get("critical", 0) / total_funcs
        high_ratio = dist.get("high", 0) / total_funcs
        complexity_score = max(0, min(10, 10 - critical_ratio * 50 - high_ratio * 20))
    else:
        complexity_score = 7  # default if no analysis available

    complexity_score = round(complexity_score, 1)
    duplication_score = duplication.get("score", 5)
    test_score = test_coverage.get("score", 2)
    dead_code_score = dead_code.get("score", 5)
    org_score = organization.get("score", 5)

    overall = round((complexity_score + duplication_score + test_score + dead_code_score + org_score) / 5, 1)

    return {
        "complexity": complexity_score,
        "duplication": duplication_score,
        "test_coverage": test_score,
        "dead_code": dead_code_score,
        "organization": org_score,
        "overall": overall,
    }



