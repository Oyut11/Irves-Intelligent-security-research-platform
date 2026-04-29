"""
IRVES — Technology Stack & Pattern Detection
Detects tech stack, architectural style, design patterns, and import analysis.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any


EXT_LANG: Dict[str, str] = {
    ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".ts": "TypeScript",
    ".kt": "Kotlin", ".kts": "Kotlin", ".java": "Java", ".scala": "Scala",
    ".rs": "Rust", ".go": "Go", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".swift": "Swift", ".m": "Objective-C", ".mm": "Objective-C++",
    ".c": "C", ".h": "C/C++ Header", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".zig": "Zig", ".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".clj": "Clojure", ".cljs": "ClojureScript",
    ".hs": "Haskell", ".r": "R", ".R": "R", ".lua": "Lua",
    ".pl": "Perl", ".pm": "Perl", ".sh": "Shell", ".bash": "Shell",
    ".sql": "SQL", ".html": "HTML", ".htm": "HTML",
    ".css": "CSS", ".scss": "SCSS", ".less": "Less",
    ".vue": "Vue", ".svelte": "Svelte", ".jsx": "JSX (React)", ".tsx": "TSX (React)",
    ".xml": "XML", ".json": "JSON", ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML",
    ".gradle": "Gradle", ".md": "Markdown",
}


def detect_tech_stack(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Detect technology stack from config files and file extension census."""
    stack: Dict[str, Any] = {"languages": {}, "frameworks": [], "build_tools": [], "deployment": []}

    # ── File extension census ──
    lang_counts: Dict[str, int] = {}
    for f in files:
        ext = Path(f).suffix.lower()
        lang = EXT_LANG.get(ext)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    stack["languages"] = dict(sorted(lang_counts.items(), key=lambda x: -x[1]))

    # ── Config-based framework detection ──
    def _read_json(p: Path) -> dict:
        try:
            return json.loads(p.read_text(errors="ignore"))
        except Exception:
            return {}

    def _read_text(p: Path) -> str:
        try:
            return p.read_text(errors="ignore")
        except Exception:
            return ""

    # package.json → JS/TS frameworks
    pkg = _read_json(repo_path / "package.json")
    if pkg:
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        fw_map = {
            "react": "React", "react-dom": "React", "next": "Next.js",
            "vue": "Vue.js", "nuxt": "Nuxt.js", "@angular/core": "Angular",
            "svelte": "Svelte", "@sveltejs/kit": "SvelteKit",
            "express": "Express", "fastify": "Fastify", "koa": "Koa",
            "hapi": "Hapi", "@hapi/hapi": "Hapi", "nestjs": "NestJS",
            "@nestjs/core": "NestJS", "gatsby": "Gatsby", "remix": "Remix",
            "electron": "Electron", "capacitor": "Capacitor",
            "@ionic/react": "Ionic", "tailwindcss": "Tailwind CSS",
            "bootstrap": "Bootstrap", "material-ui": "MUI",
            "@mui/material": "MUI", "antd": "Ant Design",
            "prisma": "Prisma", "drizzle-orm": "Drizzle ORM",
            "typeorm": "TypeORM", "sequelize": "Sequelize",
            "mongoose": "Mongoose", "jest": "Jest", "vitest": "Vitest",
            "cypress": "Cypress", "playwright": "Playwright",
        }
        for dep, name in fw_map.items():
            if dep in deps:
                ver = deps[dep].replace("^", "").replace("~", "")
                stack["frameworks"].append(f"{name} ({ver})")
        if pkg.get("workspaces") or "workspaces" in _read_text(repo_path / "package.json").lower():
            stack["build_tools"].append("Monorepo (npm/yarn workspaces)")

    # build.gradle / build.gradle.kts → Android/Kotlin/Java
    for gradle_name in ["build.gradle.kts", "build.gradle"]:
        gradle_text = _read_text(repo_path / gradle_name)
        if gradle_text:
            stack["build_tools"].append("Gradle")
            if "com.android.application" in gradle_text or "android {" in gradle_text:
                stack["frameworks"].append("Android SDK")
            if "org.jetbrains.kotlin" in gradle_text:
                stack["frameworks"].append("Kotlin Android")
            if "io.ktor" in gradle_text:
                stack["frameworks"].append("Ktor")
            if "org.springframework" in gradle_text:
                stack["frameworks"].append("Spring Boot")
            break

    # pom.xml → Java/Maven
    pom = _read_text(repo_path / "pom.xml")
    if pom:
        stack["build_tools"].append("Maven")
        if "spring-boot" in pom:
            stack["frameworks"].append("Spring Boot")
        if "jakarta" in pom:
            stack["frameworks"].append("Jakarta EE")

    # Python
    for cfg_name, cfg_type in [
        ("requirements.txt", "pip"), ("Pipfile", "pipenv"),
        ("pyproject.toml", "poetry/pip"), ("setup.py", "setuptools"),
    ]:
        cfg_text = _read_text(repo_path / cfg_name)
        if cfg_text:
            stack["build_tools"].append(cfg_type)
            fw_map_py = {
                "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
                "celery": "Celery", "sqlalchemy": "SQLAlchemy",
                "pydantic": "Pydantic", "pytest": "pytest",
                "scrapy": "Scrapy", "numpy": "NumPy", "pandas": "Pandas",
                "tensorflow": "TensorFlow", "torch": "PyTorch",
            }
            for kw, name in fw_map_py.items():
                if kw in cfg_text.lower():
                    stack["frameworks"].append(name)
            break

    # Cargo.toml → Rust
    cargo = _read_text(repo_path / "Cargo.toml")
    if cargo:
        stack["build_tools"].append("Cargo")
        if "actix" in cargo:
            stack["frameworks"].append("Actix Web")
        if "axum" in cargo:
            stack["frameworks"].append("Axum")
        if "tokio" in cargo:
            stack["frameworks"].append("Tokio")
        if "warp" in cargo:
            stack["frameworks"].append("Warp")

    # go.mod → Go
    gomod = _read_text(repo_path / "go.mod")
    if gomod:
        stack["build_tools"].append("Go Modules")
        if "gin-gonic" in gomod:
            stack["frameworks"].append("Gin")
        if "labstack/echo" in gomod:
            stack["frameworks"].append("Echo")
        if "gofiber" in gomod:
            stack["frameworks"].append("Fiber")

    # Gemfile → Ruby
    gemfile = _read_text(repo_path / "Gemfile")
    if gemfile:
        stack["build_tools"].append("Bundler")
        if "rails" in gemfile.lower():
            stack["frameworks"].append("Ruby on Rails")
        if "sinatra" in gemfile.lower():
            stack["frameworks"].append("Sinatra")

    # composer.json → PHP
    composer = _read_json(repo_path / "composer.json")
    if composer:
        stack["build_tools"].append("Composer")
        req = composer.get("require", {})
        if "laravel/framework" in req:
            stack["frameworks"].append("Laravel")
        if "symfony/symfony" in req or "symfony/framework-bundle" in req:
            stack["frameworks"].append("Symfony")

    # .csproj / .sln → .NET
    for csproj in repo_path.glob("*.csproj"):
        csproj_text = _read_text(csproj)
        if csproj_text:
            stack["build_tools"].append(".NET SDK")
            if "Microsoft.AspNetCore" in csproj_text:
                stack["frameworks"].append("ASP.NET Core")
            if "Blazor" in csproj_text:
                stack["frameworks"].append("Blazor")
            break

    # pubspec.yaml → Dart/Flutter
    pubspec = _read_text(repo_path / "pubspec.yaml")
    if pubspec:
        stack["build_tools"].append("Dart Pub")
        if "flutter" in pubspec.lower():
            stack["frameworks"].append("Flutter")

    # CMakeLists.txt → C/C++
    cmake = _read_text(repo_path / "CMakeLists.txt")
    if cmake:
        stack["build_tools"].append("CMake")

    # Makefile
    makefile = _read_text(repo_path / "Makefile")
    if makefile:
        stack["build_tools"].append("Make")

    # mix.exs → Elixir
    mix = _read_text(repo_path / "mix.exs")
    if mix:
        stack["build_tools"].append("Mix")
        if "phoenix" in mix.lower():
            stack["frameworks"].append("Phoenix")

    # Podfile → iOS
    podfile = _read_text(repo_path / "Podfile")
    if podfile:
        stack["build_tools"].append("CocoaPods")

    # Deployment
    if (repo_path / "Dockerfile").exists():
        stack["deployment"].append("Docker")
    if (repo_path / "docker-compose.yml").exists() or (repo_path / "docker-compose.yaml").exists():
        stack["deployment"].append("Docker Compose")
    for tf in repo_path.glob("*.tf"):
        stack["deployment"].append("Terraform")
        break
    if (repo_path / "serverless.yml").exists():
        stack["deployment"].append("Serverless Framework")
    if (repo_path / "kubernetes").is_dir() or (repo_path / "k8s").is_dir():
        stack["deployment"].append("Kubernetes")

    # Deduplicate
    stack["frameworks"] = list(dict.fromkeys(stack["frameworks"]))
    stack["build_tools"] = list(dict.fromkeys(stack["build_tools"]))
    stack["deployment"] = list(dict.fromkeys(stack["deployment"]))
    return stack


def analyze_directory_structure(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Map directory structure with file counts per directory."""
    dir_counts: Dict[str, int] = {}
    dir_extensions: Dict[str, set] = {}

    for f in files:
        parts = Path(f).parts
        # Top-level directory (or root files)
        top = parts[0] if len(parts) > 1 else "(root)"
        dir_counts[top] = dir_counts.get(top, 0) + 1
        ext = Path(f).suffix.lower()
        if top not in dir_extensions:
            dir_extensions[top] = set()
        dir_extensions[top].add(ext)

        # Second-level
        if len(parts) > 2:
            second = f"{parts[0]}/{parts[1]}"
            dir_counts[second] = dir_counts.get(second, 0) + 1

    # Sort by file count
    sorted_dirs = sorted(dir_counts.items(), key=lambda x: -x[1])
    top_dirs = [(d, c) for d, c in sorted_dirs if d != "(root)"][:20]

    return {
        "total_files": len(files),
        "top_level_dirs": top_dirs,
        "root_file_count": dir_counts.get("(root)", 0),
        "dir_extensions": {k: sorted(v) for k, v in dir_extensions.items()},
    }


def detect_arch_style(repo_path: Path, dir_struct: Dict, tech_stack: Dict) -> Dict[str, Any]:
    """Detect architectural style from directory structure and tech stack."""
    top_dirs = {d for d, _ in dir_struct.get("top_level_dirs", [])}
    # Also check second-level dirs for ViewModel/Repository patterns
    all_dir_names = set(top_dirs)
    for d, _ in dir_struct.get("top_level_dirs", []):
        parts = d.split("/")
        for p in parts:
            all_dir_names.add(p)
    frameworks = " ".join(tech_stack.get("frameworks", []))
    langs = tech_stack.get("languages", {})

    styles = []
    primary_lang = next(iter(langs), "Unknown")

    # Android MVVM
    if "app" in top_dirs and ("Kotlin" in langs or "Java" in langs):
        has_viewmodel = any("viewmodel" in d.lower() for d in all_dir_names)
        has_repo = any("repository" in d.lower() for d in all_dir_names)
        has_gradle = "Gradle" in tech_stack.get("build_tools", [])
        if has_viewmodel or has_repo or has_gradle:
            styles.append({"name": "Android MVVM", "confidence": "high" if (has_viewmodel and has_repo) else "medium"})

    # React SPA
    if "React" in frameworks or "Next.js" in frameworks:
        if "src" in top_dirs or "components" in top_dirs or "pages" in top_dirs or "app" in top_dirs:
            name = "Next.js Full-Stack" if "Next.js" in frameworks else "React SPA"
            styles.append({"name": name, "confidence": "high"})

    # Vue SPA
    if "Vue.js" in frameworks or "Nuxt.js" in frameworks:
        styles.append({"name": "Nuxt.js Full-Stack" if "Nuxt.js" in frameworks else "Vue SPA", "confidence": "high"})

    # Angular
    if "Angular" in frameworks:
        styles.append({"name": "Angular SPA", "confidence": "high"})

    # Django
    if "Django" in frameworks:
        styles.append({"name": "Django MVC (MVT)", "confidence": "high"})

    # Flask/FastAPI
    if "Flask" in frameworks or "FastAPI" in frameworks:
        style = "Flask Microservice" if "Flask" in frameworks else "FastAPI Service"
        if "routes" in top_dirs or "api" in top_dirs:
            style += " (Layered)"
        styles.append({"name": style, "confidence": "high"})

    # Express API
    if "Express" in frameworks or "Fastify" in frameworks:
        if "routes" in top_dirs and "middleware" in top_dirs:
            styles.append({"name": "Express Layered API", "confidence": "high"})
        else:
            styles.append({"name": "Express API", "confidence": "medium"})

    # Spring Boot
    if "Spring Boot" in frameworks:
        styles.append({"name": "Spring Boot Layered", "confidence": "high"})

    # Laravel
    if "Laravel" in frameworks:
        styles.append({"name": "Laravel MVC", "confidence": "high"})

    # Rails
    if "Ruby on Rails" in frameworks:
        styles.append({"name": "Rails MVC", "confidence": "high"})

    # Monorepo
    if "packages" in top_dirs or any("workspaces" in f for f in tech_stack.get("build_tools", [])):
        styles.append({"name": "Monorepo", "confidence": "high"})

    # Microservices
    dockerfiles = list(repo_path.glob("**/Dockerfile"))
    if len(dockerfiles) > 1:
        styles.append({"name": "Microservices", "confidence": "medium"})

    # Go service
    if "Go" in langs and "Go Modules" in tech_stack.get("build_tools", []):
        if "cmd" in top_dirs and "internal" in top_dirs:
            styles.append({"name": "Go Standard Layout", "confidence": "high"})
        elif "api" in top_dirs or "handler" in top_dirs:
            styles.append({"name": "Go API Service", "confidence": "medium"})

    # Rust service
    if "Rust" in langs and "Cargo" in tech_stack.get("build_tools", []):
        if "src" in top_dirs:
            styles.append({"name": "Rust Application", "confidence": "high"})

    # Flutter
    if "Flutter" in frameworks:
        styles.append({"name": "Flutter Cross-Platform", "confidence": "high"})

    # Generic fallback
    if not styles:
        if "src" in top_dirs and "test" in top_dirs:
            styles.append({"name": "Layered Architecture", "confidence": "low"})
        elif primary_lang in ("Python", "JavaScript", "TypeScript"):
            styles.append({"name": f"{primary_lang} Project", "confidence": "low"})
        else:
            styles.append({"name": "Unknown / Custom", "confidence": "low"})

    return {"styles": styles, "primary_language": primary_lang}


def detect_all_patterns(repo_path: Path, files: List[str]) -> Dict[str, Dict[str, int]]:
    """Detect design patterns across all source files, returning aggregated counts."""
    pattern_counts: Dict[str, Dict[str, int]] = {}  # pattern -> {language: count}

    # Group files by language
    lang_files: Dict[str, List[str]] = {}
    for f in files:
        ext = Path(f).suffix.lower()
        if ext in (".py",):
            lang_files.setdefault("python", []).append(f)
        elif ext in (".kt", ".java", ".kts"):
            lang_files.setdefault("kotlin", []).append(f)
        elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
            lang_files.setdefault("javascript", []).append(f)
        elif ext in (".go",):
            lang_files.setdefault("go", []).append(f)
        elif ext in (".rs",):
            lang_files.setdefault("rust", []).append(f)
        elif ext in (".rb",):
            lang_files.setdefault("ruby", []).append(f)
        elif ext in (".php",):
            lang_files.setdefault("php", []).append(f)
        elif ext in (".cs",):
            lang_files.setdefault("csharp", []).append(f)
        elif ext in (".swift",):
            lang_files.setdefault("swift", []).append(f)
        elif ext in (".dart",):
            lang_files.setdefault("dart", []).append(f)
        elif ext in (".c", ".cpp", ".cc", ".h", ".hpp"):
            lang_files.setdefault("cpp", []).append(f)

    # Analyze each language
    for lang, lang_file_list in lang_files.items():
        # Limit to first 100 files per language for performance
        for file_path in lang_file_list[:100]:
            full = repo_path / file_path
            if not full.exists():
                continue
            try:
                text = full.read_text(errors="ignore")
                if lang == "python":
                    tree = safe_parse_python(text)
                    detected = detect_python_patterns(tree, file_path) if tree else []
                elif lang == "kotlin":
                    detected = detect_jvm_patterns(text, file_path)
                elif lang == "javascript":
                    detected = detect_js_patterns(text, file_path)
                elif lang == "go":
                    detected = detect_go_patterns(text)
                elif lang == "rust":
                    detected = detect_rust_patterns(text)
                elif lang == "ruby":
                    detected = detect_ruby_patterns(text)
                elif lang == "php":
                    detected = detect_php_patterns(text)
                elif lang == "csharp":
                    detected = detect_csharp_patterns(text)
                elif lang == "swift":
                    detected = detect_swift_patterns(text)
                elif lang == "dart":
                    detected = detect_dart_patterns(text)
                elif lang == "cpp":
                    detected = detect_cpp_patterns(text)
                else:
                    detected = []
                for p in detected:
                    if p not in pattern_counts:
                        pattern_counts[p] = {}
                    pattern_counts[p][lang] = pattern_counts[p].get(lang, 0) + 1
            except Exception:
                continue

    return pattern_counts


def detect_go_patterns(source: str) -> List[str]:
    """Detect design patterns in Go source."""
    detected: List[str] = []
    # Singleton: sync.Once, init()
    if re.search(r"\bsync\.Once\b|\binit\s*\(\s*\)", source):
        detected.append("singleton")
    # Factory: NewXxx constructor functions
    if re.search(r"\bfunc\s+New\w+\s*\(", source):
        detected.append("factory")
    # Strategy: interface with Execute/Run + multiple implementations
    if re.search(r"\btype\s+\w+\s+interface\s*\{", source) and re.search(r"\bfunc\s*\(\w+\s+\*?\w+\)\s+(Execute|Run|Handle)\b", source):
        detected.append("strategy")
    # Observer: channels, pub/sub patterns
    if re.search(r"\bchan\s+", source) and re.search(r"\bselect\s*\{", source):
        detected.append("observer")
    # Repository: struct with DB methods
    if re.search(r"\btype\s+\w*Repository\s+struct\b", source):
        detected.append("repository")
    # Middleware pattern (common in Go HTTP)
    if re.search(r"\bfunc\s*\([^)]*\)\s*\([^)]*\)\s*\(\s*http\.HandlerFunc", source) or re.search(r"\bMiddleware\b", source):
        detected.append("middleware")
    return list(dict.fromkeys(detected))


def detect_rust_patterns(source: str) -> List[str]:
    """Detect design patterns in Rust source."""
    detected: List[str] = []
    # Singleton: lazy_static, OnceCell, OnceLock
    if re.search(r"\blazy_static!|\bOnceCell\b|\bOnceLock\b", source):
        detected.append("singleton")
    # Factory: From/TryFrom traits, new() constructors
    if re.search(r"\bimpl\s+From\b|\bimpl\s+TryFrom\b|\bfn\s+new\s*\(", source):
        detected.append("factory")
    # Strategy: trait with multiple impls
    if re.search(r"\btrait\s+\w+\s*\{", source) and re.search(r"\bimpl\s+\w+\s+for\s+", source):
        detected.append("strategy")
    # Observer: channels, watch
    if re.search(r"\bmpsc::|\bwatch::|\bbroadcast::", source):
        detected.append("observer")
    # Builder pattern
    if re.search(r"\bfn\s+\w+\s*\([^)]*\)\s*->\s*(?:Self|&?\s*Self)", source) and re.search(r"struct\s+\w*Builder", source):
        detected.append("builder")
    return list(dict.fromkeys(detected))


def detect_ruby_patterns(source: str) -> List[str]:
    """Detect design patterns in Ruby source."""
    detected: List[str] = []
    if re.search(r"require\s+['\"]singleton['\"]|include\s+Singleton", source):
        detected.append("singleton")
    if re.search(r"def\s+self\.(create|build|new_instance)", source):
        detected.append("factory")
    if re.search(r"def\s+(execute|run|call)", source) and re.search(r"attr_accessor\s+:\w*(?:strategy|algorithm)", source):
        detected.append("strategy")
    if re.search(r"def\s+(subscribe|on|attach)|Observable", source):
        detected.append("observer")
    return list(dict.fromkeys(detected))


def detect_php_patterns(source: str) -> List[str]:
    """Detect design patterns in PHP source."""
    detected: List[str] = []
    if re.search(r"private\s+static\s+\$instance|Singleton::class", source):
        detected.append("singleton")
    if re.search(r"public\s+static\s+function\s+(create|build|make)", source):
        detected.append("factory")
    if re.search(r"interface\s+\w*(?:Strategy|Handler)", source):
        detected.append("strategy")
    if re.search(r"function\s+attach|SplSubject|SplObserver", source):
        detected.append("observer")
    if re.search(r"class\s+\w*Repository", source):
        detected.append("repository")
    if re.search(r"#[Inject]|#[Autowired]", source):
        detected.append("dependency_injection")
    return list(dict.fromkeys(detected))


def detect_csharp_patterns(source: str) -> List[str]:
    """Detect design patterns in C# source."""
    detected: List[str] = []
    if re.search(r"private\s+static\s+\w+\s+_instance|Lazy<\w+>", source):
        detected.append("singleton")
    if re.search(r"static\s+\w+\s+(Create|Build|Make)\b", source):
        detected.append("factory")
    if re.search(r"interface\s+I\w*(?:Strategy|Handler)", source):
        detected.append("strategy")
    if re.search(r"event\s+EventHandler|IObservable|IObserver", source):
        detected.append("observer")
    if re.search(r"class\s+\w*Repository\b", source):
        detected.append("repository")
    if re.search(r"\[Inject\]|\[FromServices\]|IServiceCollection", source):
        detected.append("dependency_injection")
    return list(dict.fromkeys(detected))


def detect_swift_patterns(source: str) -> List[str]:
    """Detect design patterns in Swift source."""
    detected: List[str] = []
    if re.search(r"static\s+(let|var)\s+shared|static\s+let\s+instance", source):
        detected.append("singleton")
    if re.search(r"protocol\s+\w*(?:Strategy|Handler|Factory)", source):
        detected.append("strategy")
    if re.search(r"@Published|ObservableObject|Combine", source):
        detected.append("observer")
    if re.search(r"@Environment|@Injected|@Dependency", source):
        detected.append("dependency_injection")
    return list(dict.fromkeys(detected))


def detect_dart_patterns(source: str) -> List[str]:
    """Detect design patterns in Dart/Flutter source."""
    detected: List[str] = []
    if re.search(r"static\s+final\s+\w+\s+_instance|factory\s+\w+\.\w+\(", source):
        detected.append("singleton")
    if re.search(r"factory\s+\w+\.from\w*|factory\s+\w+\.create", source):
        detected.append("factory")
    if re.search(r"abstract\s+class\s+\w*(?:Strategy|Repository)", source):
        detected.append("strategy")
    if re.search(r"StreamController|Stream<|ValueNotifier|ChangeNotifier", source):
        detected.append("observer")
    if re.search(r"class\s+\w*Repository\b", source):
        detected.append("repository")
    if re.search(r"class\s+\w*Provider\b|ChangeNotifierProvider|Riverpod", source):
        detected.append("dependency_injection")
    return list(dict.fromkeys(detected))


def detect_cpp_patterns(source: str) -> List[str]:
    """Detect design patterns in C/C++ source."""
    detected: List[str] = []
    if re.search(r"static\s+\w+\*\s+instance|getInstance\s*\(\s*\)", source):
        detected.append("singleton")
    if re.search(r"static\s+\w+\s+(create|build|make)\s*\(", source):
        detected.append("factory")
    if re.search(r"class\s+\w*(?:Strategy|Handler)", source):
        detected.append("strategy")
    if re.search(r"std::function|notifyObservers|addListener|Observer", source):
        detected.append("observer")
    return list(dict.fromkeys(detected))


def analyze_imports(repo_path: Path, files: List[str]) -> tuple:
    """Analyze import statements across all source files for coupling/cohesion metrics."""
    import_graph: Dict[str, set] = {}  # file -> set of imported modules
    ext_lang = {
        ".py": "python", ".js": "javascript", ".mjs": "javascript", ".ts": "javascript",
        ".jsx": "javascript", ".tsx": "javascript",
        ".kt": "kotlin", ".java": "java", ".kts": "kotlin",
        ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
        ".cs": "csharp", ".swift": "swift", ".dart": "dart",
        ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".h": "c", ".hpp": "cpp",
        ".scala": "scala", ".ex": "elixir", ".erl": "erlang",
    }

    import_patterns = {
        "python": [
            r"^\s*(?:from|import)\s+([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)",
        ],
        "javascript": [
            r"""(?:import\s+.*?\s+from\s+['"]([^'"]+)['"])""",
            r"""(?:require\s*\(\s*['"]([^'"]+)['"]\s*\))""",
        ],
        "kotlin": [r"^\s*import\s+([\w.]+)"],
        "java": [r"^\s*import\s+([\w.]+)"],
        "go": [r"""^\s*(?:\w+\s+)?"([^"]+)"\s*$"""],  # import block items
        "rust": [r"^\s*use\s+([\w:]+)"],
        "ruby": [r"""^\s*require\s+['"]([^'"]+)['"]"""],
        "php": [r"^\s*use\s+([\w\\]+)"],
        "csharp": [r"^\s*using\s+([\w.]+)"],
        "swift": [r"^\s*import\s+(\w+)"],
        "dart": [r"""^\s*import\s+['"]([^'"]+)['"]"""],
        "c": [r'^\s*#\s*include\s*"([^"]+)"'],
        "cpp": [r'^\s*#\s*include\s*"([^"]+)"'],
        "scala": [r"^\s*import\s+([\w.]+)"],
        "elixir": [r"""^\s*alias\s+([\w.]+)"""],
    }

    for f in files[:200]:  # limit for performance
        ext = Path(f).suffix.lower()
        lang = ext_lang.get(ext)
        if not lang or lang not in import_patterns:
            continue
        full = repo_path / f
        if not full.exists():
            continue
        try:
            text = full.read_text(errors="ignore")
            imports = set()
            for pattern in import_patterns[lang]:
                for m in re.finditer(pattern, text, re.MULTILINE):
                    imports.add(m.group(1))
            if imports:
                import_graph[f] = imports
        except Exception:
            continue

    # Calculate coupling (external imports / total imports)
    total_imports = 0
    external_imports = 0
    internal_imports = 0
    most_imported: Dict[str, int] = {}

    # Build set of internal module names from file paths
    internal_modules = set()
    for f in files:
        parts = Path(f).parts
        for i in range(len(parts)):
            internal_modules.add("/".join(parts[:i+1]))
            internal_modules.add(parts[-1].split(".")[0])

    for f, imports in import_graph.items():
        for imp in imports:
            total_imports += 1
            # Check if import is internal
            base = imp.split("/")[0].split(".")[0].split(":")[0]
            if base in internal_modules or any(base in m for m in internal_modules):
                internal_imports += 1
            else:
                external_imports += 1
            most_imported[base] = most_imported.get(base, 0) + 1

    coupling = external_imports / max(total_imports, 1)
    cohesion = internal_imports / max(total_imports, 1)

    # Detect circular dependencies (simplified)
    circular_deps = []
    file_dirs = {}
    for f in import_graph:
        parts = Path(f).parts
        file_dirs[f] = parts[0] if len(parts) > 1 else "(root)"

    # Files in same directory importing each other = high cohesion
    same_dir_imports = 0
    for f, imports in import_graph.items():
        f_dir = file_dirs.get(f, "")
        for imp in imports:
            for other_f in import_graph:
                if other_f != f and file_dirs.get(other_f) == f_dir:
                    base = Path(other_f).stem
                    if base in imp:
                        same_dir_imports += 1

    top_imported = sorted(most_imported.items(), key=lambda x: -x[1])[:10]

    import_stats = {
        "total_imports": total_imports,
        "external_imports": external_imports,
        "internal_imports": internal_imports,
        "files_with_imports": len(import_graph),
        "top_imported_modules": top_imported,
        "avg_imports_per_file": total_imports / max(len(import_graph), 1),
    }

    return round(coupling, 3), round(cohesion, 3), import_stats


def generate_arch_observations(tech_stack: Dict, arch_style: Dict,
    coupling: float, cohesion: float, import_stats: Dict, dir_struct: Dict
) -> Dict[str, List[str]]:
    """Generate architectural observations (strengths and areas for enhancement)."""
    strengths = []
    enhancements = []

    # Language diversity
    langs = tech_stack.get("languages", {})
    if len(langs) >= 3:
        strengths.append(f"Multi-language project ({len(langs)} languages) — good for polyglot architecture")
    elif len(langs) == 1:
        primary = next(iter(langs))
        strengths.append(f"Focused {primary} codebase — consistent tooling and expertise")

    # Framework usage
    fws = tech_stack.get("frameworks", [])
    if fws:
        strengths.append(f"Uses established frameworks ({', '.join(fws[:3])})")
    else:
        enhancements.append("No major frameworks detected — consider adopting established frameworks for maintainability")

    # Coupling
    if coupling < 0.3:
        strengths.append(f"Low coupling ({coupling:.0%}) — modules are well-isolated")
    elif coupling > 0.7:
        enhancements.append(f"High coupling ({coupling:.0%}) — consider reducing external dependencies and introducing interfaces")
    else:
        strengths.append(f"Moderate coupling ({coupling:.0%}) — reasonable module isolation")

    # Cohesion
    if cohesion > 0.5:
        strengths.append(f"Good cohesion ({cohesion:.0%}) — related code is grouped together")
    elif cohesion < 0.2:
        enhancements.append(f"Low cohesion ({cohesion:.0%}) — consider reorganizing modules by domain/feature")

    # Test coverage signal
    test_dirs = [d for d, _ in dir_struct.get("top_level_dirs", []) if "test" in d.lower()]
    if test_dirs:
        strengths.append(f"Test directories present ({', '.join(test_dirs)})")
    else:
        enhancements.append("No test directories detected — consider adding automated tests")

    # Deployment
    deploy = tech_stack.get("deployment", [])
    if deploy:
        strengths.append(f"Containerized deployment ({', '.join(deploy)})")
    else:
        enhancements.append("No deployment configuration found — consider adding Dockerfile/docker-compose")

    # Architectural style
    styles = arch_style.get("styles", [])
    high_conf = [s for s in styles if s.get("confidence") == "high"]
    if high_conf:
        strengths.append(f"Clear architectural style ({high_conf[0]['name']})")
    elif styles:
        enhancements.append(f"Unclear architecture ({styles[0]['name']}, low confidence) — consider adopting a well-defined pattern")

    # Import stats
    avg_imp = import_stats.get("avg_imports_per_file", 0)
    if avg_imp > 10:
        enhancements.append(f"High average imports per file ({avg_imp:.1f}) — files may have too many responsibilities")

    return {"strengths": strengths, "enhancements": enhancements}


def safe_parse_python(source: str) -> Any:
    """Safely parse Python source into an AST, returning None on failure."""
    try:
        import ast
        return ast.parse(source)
    except SyntaxError:
        return None


def detect_python_patterns(tree: Any, file_path: str) -> List[str]:
    """Detect design patterns in a Python AST. Returns list of pattern names."""
    import ast
    detected: List[str] = []
    classes: List[ast.ClassDef] = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]

    # Singleton: class overriding __new__ or using a metaclass, with getInstance/get_instance
    for cls in classes:
        methods = {n.name for n in cls.body if isinstance(n, ast.FunctionDef)}
        has_getinstance = any(m.startswith("get") and "instance" in m.lower() for m in methods)
        has_new = "__new__" in methods
        if has_getinstance or has_new:
            detected.append("singleton")

    # Factory: method named create/build that returns instances
    for cls in classes:
        for node in cls.body:
            if isinstance(node, ast.FunctionDef) and node.name in ("create", "build", "make"):
                # Check if body contains a return with a Call
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Call):
                        detected.append("factory")
                        break

    # Strategy: class holding a callable/algorithm attribute, execute/run method
    for cls in classes:
        methods = {n.name for n in cls.body if isinstance(n, ast.FunctionDef)}
        if "execute" in methods and any(
            isinstance(n, ast.FunctionDef) and n.name == "execute"
            for n in cls.body
        ):
            # Check if constructor takes a function/algorithm parameter
            init = next((n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"), None)
            if init and init.args.args:
                detected.append("strategy")

    # Observer: subscribe/unsubscribe/notify methods
    for cls in classes:
        methods = {n.name for n in cls.body if isinstance(n, ast.FunctionDef)}
        if methods & {"subscribe", "attach"} and methods & {"notify", "update"}:
            detected.append("observer")

    return list(dict.fromkeys(detected))  # preserve order, remove dups


def detect_jvm_patterns(source: str, file_path: str) -> List[str]:
    """Detect design patterns in Kotlin/Java source using structured analysis."""
    detected: List[str] = []

    has_classes = bool(re.search(r"\b(class|object|interface|enum)\s+\w+", source))

    # Singleton: Kotlin object declaration, companion object with getInstance, or Java singleton
    if re.search(r"\bobject\s+\w+", source) and "companion" not in source:
        detected.append("singleton")
    if re.search(r"\bgetInstance\b|\bcompanion\s+object\b", source):
        if "singleton" not in detected:
            detected.append("singleton")

    # Factory: companion/object with create/build returning instances
    if re.search(r"fun\s+(create|build|make|newInstance)\s*\([^)]*\)\s*:\s*\w+", source):
        detected.append("factory")

    # Strategy: interface with execute/run + implementations
    if re.search(r"\binterface\s+\w*(?:Strategy|Handler|Executor|Algorithm)\b", source):
        detected.append("strategy")
    elif re.search(r"\bfun\s+execute\b|\bfun\s+run\b", source) and re.search(r"\boverride\b", source):
        detected.append("strategy")

    # Observer: LiveData, StateFlow, Flow, EventListener patterns
    if re.search(r"\bMutable(Live|State|Shared)?Flow\b|\bLiveData\b|\bStateFlow\b|\bSharedFlow\b", source):
        detected.append("observer")
    elif re.search(r"\baddListener\b|\bremoveListener\b|\bonEvent\b|\bnotifyObservers\b", source):
        detected.append("observer")

    # Repository pattern (common in Android)
    if re.search(r"\bclass\s+\w*Repository\b", source):
        detected.append("repository")

    # ViewModel pattern (MVVM)
    if re.search(r"\bclass\s+\w*ViewModel\b", source):
        detected.append("mvvm")

    # Dependency Injection: @Inject, @Module, Hilt/Dagger annotations
    if re.search(r"@(Inject|Provides|Binds|Module|Component|Singleton|HiltViewModel)\b", source):
        detected.append("dependency_injection")

    return list(dict.fromkeys(detected))


def detect_js_patterns(source: str, file_path: str) -> List[str]:
    """Detect design patterns in JS/TS source using structured analysis.
    Covers both class-based and functional (React hooks, modules) patterns."""
    detected: List[str] = []

    has_classes = bool(re.search(r"\bclass\s+\w+", source))
    has_functions = bool(re.search(r"(?:function\s+\w+|\bconst\s+\w+\s*=\s*(?:async\s*)?\(|\bexport\s+(?:default\s+)?(?:function|class|const)", source))

    # ── Class-based patterns ──
    if has_classes:
        # Singleton: private constructor, static getInstance, or Object.freeze
        if re.search(r"\bgetInstance\b|\bget_instance\b|Object\.freeze\s*\(", source):
            detected.append("singleton")

        # Factory: class with static create/build methods returning new instances
        factory_methods = re.findall(
            r"(?:static\s+)?(?:create|build|make)\s*\([^)]*\)\s*\{[^}]*return\s+new\s+\w+",
            source, re.DOTALL
        )
        if len(factory_methods) >= 1:
            detected.append("factory")

        # Strategy: class with setStrategy / execute pattern
        if re.search(r"\bsetStrategy\b|\bset_strategy\b|\bexecute\s*\([^)]*\)\s*\{[^}]*\balgorithm\b|\bstrategy\b", source, re.IGNORECASE):
            detected.append("strategy")

        # Observer: on/subscribe/emit/unsubscribe pattern
        observer_signals = sum(1 for kw in ["subscribe", "unsubscribe", "emit", "notify", "addEventListener"] if kw in source)
        if observer_signals >= 2:
            detected.append("observer")

    # ── Functional / React patterns ──
    if has_functions:
        # React Context / Provider pattern (dependency injection for components)
        if "createContext" in source and ("Provider" in source or "useContext" in source):
            detected.append("dependency_injection")

        # Custom Hooks (strategy-like interchangeable behavior)
        if re.search(r"\buse\w+\s*\(", source) and "return" in source:
            detected.append("strategy")

        # Higher-Order Component (factory-like wrapper)
        if re.search(r"(?:function|const)\s+\w+\s*\([^)]*\)\s*\{[^}]*return\s*\(?\s*\w+\s*\(\s*\{[^}]*\}\s*\)", source, re.DOTALL):
            detected.append("factory")

        # Event Emitter / PubSub (observer pattern via functions)
        if re.search(r"\bon\s*\(\s*['\"]\w+['\"]|\bemit\s*\(|\baddEventListener\s*\(|\buseEffect\s*\(\s*\(\)\s*=>\s*\{[^}]*\bsubscribe\b", source):
            detected.append("observer")

        # React.memo / useMemo singleton-like caching
        if re.search(r"\bReact\.memo\b|\buseMemo\b|\buseCallback\b|\bmemo\s*\(", source):
            detected.append("singleton")

    return list(dict.fromkeys(detected))
