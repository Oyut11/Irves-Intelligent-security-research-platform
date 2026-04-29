"""
IRVES — Scalability Analyzer
Analyzes async patterns, database patterns, caching, and resource management.
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Any

from services.source_analysis.reports import build_scalability_report
from services.source_analysis.report_utils import resolve_project_name

from database.models import FindingSeverity
from services.git_service import git_service

logger = logging.getLogger(__name__)



def get_db():
    """Get database session."""
    from database.session import get_session
    return get_session()


async def analyze_scalability(repo_path: Path,
    analysis_result_id: str,
) -> Dict[str, Any]:
    """Analyze scalability: produces a comprehensive scalability report as a single finding."""
    logger.info("[SourceAnalysis] Analyzing scalability — generating comprehensive report")

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

        # ── 1. Async/concurrency patterns ──
        async_stats = analyze_async_patterns(repo_path, files)

        # ── 2. Database query patterns ──
        db_stats = analyze_db_patterns(repo_path, files)

        # ── 3. Caching patterns ──
        cache_stats = analyze_caching_patterns(repo_path, files)

        # ── 4. Resource management ──
        resource_stats = analyze_resource_patterns(repo_path, files)

        # ── 5. Build the markdown report ──
        report = build_scalability_report(
            repo_path, async_stats, db_stats, cache_stats, resource_stats,
            project_name=project_name
        )

        findings = [{
            "type": "scalability_report",
            "severity": FindingSeverity.INFO,
            "message": report,
            "tool": "scalability_analyzer",
            "extra_data": {
                "async_stats": async_stats,
                "db_stats": db_stats,
                "cache_stats": cache_stats,
                "resource_stats": resource_stats,
            },
        }]

        summary = {
            "total_findings": 1,
            "async_coverage": async_stats.get("async_file_count", 0),
            "db_issues": len(db_stats.get("issues", [])),
            "caching_present": cache_stats.get("has_caching", False),
        }

    except Exception as e:
        logger.error(f"[SourceAnalysis] Scalability analysis failed: {e}")
        findings = [{
            "type": "scalability_report",
            "severity": FindingSeverity.INFO,
            "message": f"# Scalability Report\n\nAnalysis failed: {e}",
            "tool": "scalability_analyzer",
        }]
        summary = {"total_findings": 1}

    summary["total_findings"] = len(findings)
    return {
        "summary_metrics": summary,
        "detailed_findings": {},
        "findings": findings,
    }


def analyze_async_patterns(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze async/concurrency patterns across all languages."""
    stats: Dict[str, Any] = {
        "async_file_count": 0, "sync_file_count": 0,
        "async_patterns": {}, "issues": [],
    }
    # Language-specific async markers
    async_markers = {
        ".py": [r"\basync\s+def\b", r"\bawait\b"],
        ".js": [r"\basync\s+function\b", r"\bawait\b", r"\.then\s*\("],
        ".mjs": [r"\basync\s+function\b", r"\bawait\b"],
        ".ts": [r"\basync\s+function\b", r"\bawait\b", r"Promise<"],
        ".jsx": [r"\basync\s+function\b", r"\bawait\b"],
        ".tsx": [r"\basync\s+function\b", r"\bawait\b"],
        ".kt": [r"\bsuspend\s+fun\b", r"\bwithContext\b", r"\blaunch\s*\{", r"\basync\s*\{"],
        ".kts": [r"\bsuspend\s+fun\b", r"\bwithContext\b"],
        ".java": [r"\bCompletableFuture\b", r"\bForkJoinPool\b", r"\b@Async\b"],
        ".cs": [r"\basync\s+\w+\s+", r"\bawait\b", r"\bTask\b"],
        ".go": [r"\bgo\s+func\b", r"\bgo\s+\w+\(", r"\bsync\b"],
        ".rs": [r"\basync\s+fn\b", r"\b\.await\b", r"\btokio::"],
        ".rb": [r"\bThread\b", r"\bFiber\b", r"\bConcurrent\b"],
        ".swift": [r"\basync\s+", r"\bawait\b", r"\bTask\b"],
        ".dart": [r"\basync\s+", r"\bawait\b", r"\bFuture<", r"\bStream<"],
        ".php": [r"\basync\s+function\b", r"\bSwoole\b", r"\bReact\\Promise"],
        ".scala": [r"\bFuture\b", r"\bimplicit\s+ec\b"],
        ".ex": [r"\bTask\b", r"\bGenServer\b", r"\basync\b"],
        ".erl": [r"\bspawn\b", r"\bgen_server\b"],
    }

    # Anti-patterns (sync blocking in async context)
    blocking_patterns = {
        ".py": [(r"\btime\.sleep\b", "time.sleep in async context"), (r"\brequests\.\w+\(", "sync HTTP in async context"), (r"\burllib\b", "sync urllib in async context")],
        ".kt": [(r"\bThread\.sleep\b", "Thread.sleep in coroutine"), (r"\brunBlocking\b", "runBlocking blocks dispatcher"), (r"\bGlobalScope\b", "GlobalScope — unstructured concurrency")],
        ".js": [(r"\bfs\.readFileSync\b", "sync filesystem in Node.js"), (r"\bfs\.writeFileSync\b", "sync filesystem in Node.js"), (r"\bchild_process\.execSync\b", "sync subprocess in Node.js")],
        ".ts": [(r"\bfs\.readFileSync\b", "sync filesystem in Node.js"), (r"\bfs\.writeFileSync\b", "sync filesystem in Node.js")],
        ".go": [(r"\bsync\.Mutex\b.*\bLock\b", "mutex lock — consider channels"), (r"\btime\.Sleep\b", "time.Sleep blocks goroutine")],
        ".rs": [(r"\bstd::thread::sleep\b", "thread::sleep in async context"), (r"\bblock_on\b", "block_on inside async context")],
        ".cs": [(r"\bThread\.Sleep\b", "Thread.Sleep in async context"), (r"\b\.Result\b", "Accessing .Result blocks thread")],
        ".dart": [(r"\bFuture\.value\b.*\bsync\b", "sync in async context")],
    }

    for f in files[:200]:
        ext = Path(f).suffix.lower()
        markers = async_markers.get(ext)
        if not markers:
            continue
        full = repo_path / f
        if not full.exists():
            continue
        try:
            text = full.read_text(errors="ignore")
            has_async = any(re.search(p, text) for p in markers)
            if has_async:
                stats["async_file_count"] += 1
                for p_name in markers:
                    if re.search(p_name, text):
                        stats["async_patterns"][p_name] = stats["async_patterns"].get(p_name, 0) + 1
            else:
                stats["sync_file_count"] += 1

            # Check anti-patterns
            blockers = blocking_patterns.get(ext, [])
            for pattern, msg in blockers:
                if re.search(pattern, text) and has_async:
                    stats["issues"].append({"file": f, "issue": msg, "severity": "high"})
        except Exception:
            continue

    return stats


def analyze_db_patterns(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze database query patterns for N+1 and missing indexes."""
    stats: Dict[str, Any] = {"db_files": 0, "orm_usage": [], "issues": []}

    db_markers = {
        ".py": [(r"\bdjango\.db\b|\bmodels\.Model\b", "Django ORM"), (r"\bsqlalchemy\b|\bSession\b", "SQLAlchemy"), (r"\bmongoengine\b", "MongoEngine")],
        ".kt": [(r"\b@Dao\b|\b@Query\b|\b@Insert\b", "Room ORM"), (r"\bRealm\b", "Realm")],
        ".java": [(r"\b@Dao\b|\b@Query\b|\bJpaRepository\b", "JPA/Room")],
        ".js": [(r"\bmongoose\b", "Mongoose"), (r"\bsequelize\b", "Sequelize"), (r"\bprisma\b", "Prisma"), (r"\bknex\b", "Knex")],
        ".ts": [(r"\bmongoose\b", "Mongoose"), (r"\bprisma\b", "Prisma"), (r"\bdrizzle\b", "Drizzle"), (r"\bTypeORM\b", "TypeORM")],
        ".rb": [(r"\bActiveRecord\b|\bActiveRecord::Base\b", "ActiveRecord")],
        ".go": [(r"\bgorm\b", "GORM"), (r"\bsqlx\b", "sqlx")],
        ".rs": [(r"\bdiesel\b", "Diesel"), (r"\bsqlx\b", "sqlx")],
        ".cs": [(r"\bDbContext\b|\bEntityFramework\b", "Entity Framework")],
        ".php": [(r"\bEloquent\b", "Eloquent"), (r"\bDoctrine\b", "Doctrine")],
    }

    n1_patterns = [
        (r"for\s+\w+\s+in\s+.*:\s+.*\.get\(", "N+1: DB query inside loop"),
        (r"for\s*\(.+\)\s*\{[^}]*(@Query|@Insert|dao\.)", "N+1: Room DAO call inside loop"),
        (r"\.forEach\s*\([^)]*\)\s*=>\s*[^{]*\{[^}]*(find|findOne|query|select)", "N+1: DB query inside forEach"),
    ]

    for f in files[:200]:
        ext = Path(f).suffix.lower()
        markers = db_markers.get(ext)
        if not markers:
            continue
        full = repo_path / f
        if not full.exists():
            continue
        try:
            text = full.read_text(errors="ignore")
            for pattern, orm_name in markers:
                if re.search(pattern, text):
                    stats["db_files"] += 1
                    if orm_name not in stats["orm_usage"]:
                        stats["orm_usage"].append(orm_name)
            for pattern, msg in n1_patterns:
                if re.search(pattern, text, re.DOTALL):
                    stats["issues"].append({"file": f, "issue": msg, "severity": "medium"})
        except Exception:
            continue

    return stats


def analyze_caching_patterns(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Detect caching mechanisms and missing cache opportunities."""
    stats: Dict[str, Any] = {"has_caching": False, "caching_tools": [], "missing_cache_hints": []}

    cache_markers = [
        (r"\bredis\b|\bRedis\b", "Redis"),
        (r"\bmemcached\b|\bMemcached\b", "Memcached"),
        (r"\b@Cacheable\b|\b@CacheEvict\b", "Spring Cache"),
        (r"\bcache_page\b|\b@cache\b", "Django Cache"),
        (r"\bLRU\b|\blru_cache\b", "LRU Cache"),
        (r"\bWeakHashMap\b|\bConcurrentHashMap\b.*cache", "Java HashMap Cache"),
        (r"\bCache\b.*\bBuilder\b|\bCaffeine\b", "Caffeine Cache"),
        (r"\bNSCache\b|\bURLCache\b", "iOS Cache"),
        (r"\bLruCache\b|\bDiskLruCache\b", "Android LRU Cache"),
        (r"\bnode-cache\b|\bmemory-cache\b", "Node.js Cache"),
        (r"\bCache::store\b|\bCache::get\b", "Laravel Cache"),
        (r"\bCache::put\b|\bCache::remember\b", "Laravel Cache"),
    ]

    all_text = ""
    for f in files[:100]:
        full = repo_path / f
        if full.exists():
            try:
                all_text += full.read_text(errors="ignore") + "\n"
            except Exception:
                continue

    for pattern, name in cache_markers:
        if re.search(pattern, all_text):
            stats["has_caching"] = True
            if name not in stats["caching_tools"]:
                stats["caching_tools"].append(name)

    # Check for missing caching hints (frequent DB reads without cache)
    if not stats["has_caching"] and any("ORM" in orm or "Room" in orm for orm in stats.get("caching_tools", [])):
        stats["missing_cache_hints"].append("Database queries detected but no caching layer found")

    return stats


def analyze_resource_patterns(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze resource management patterns (connection pooling, file handles, etc.)."""
    stats: Dict[str, Any] = {"connection_pooling": False, "resource_issues": []}

    pool_markers = [
        (r"\bConnectionPool\b|\bpool\b.*\bconnection\b", "Connection Pooling"),
        (r"\bThreadPool\b|\bExecutorService\b|\bForkJoinPool\b", "Thread Pool"),
        (r"\bCoroutineScope\b|\bSupervisorJob\b", "Coroutine Scope"),
        (r"\bHikariCP\b|\bc3p0\b|\bdbcp\b", "DB Connection Pool"),
        (r"\bpgbouncer\b|\bPgPool\b", "PostgreSQL Pooler"),
    ]

    leak_markers = [
        (r"\bopen\s*\([^)]*\)(?!.*close)", "File opened without explicit close"),
        (r"\bnew\s+Socket\b(?!.*close)", "Socket created without explicit close"),
        (r"\bCursor\b(?!.*close)", "Cursor without close"),
    ]

    all_text = ""
    for f in files[:100]:
        full = repo_path / f
        if full.exists():
            try:
                all_text += full.read_text(errors="ignore") + "\n"
            except Exception:
                continue

    for pattern, name in pool_markers:
        if re.search(pattern, all_text):
            stats["connection_pooling"] = True
            if "pooling" not in stats:
                stats["pooling_tools"] = []
            stats.setdefault("pooling_tools", []).append(name)

    return stats


