"""
IRVES — Source Code Analysis Service
Coordinates multiple analysis tools across 8 categories for comprehensive source code analysis.

Categories:
1. Architecture - Design patterns, coupling/cohesion, module structure
2. Scalability - Bottleneck hotspots, async usage, DB patterns
3. Code Quality - Complexity, duplication, test coverage, dead code
4. Security - SAST findings, injection risks, auth patterns
5. Dependencies - CVEs, outdated packages, license risks
6. Secrets - Hardcoded keys, exposed credentials
7. Technical Debt - TODO density, refactor candidates, legacy age
8. Contributor Risk - Bus factor, commit patterns, force pushes
"""

import asyncio
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from database.models import AnalysisCategory, AnalysisStatus, FindingSeverity
from database.crud import (
    create_source_analysis_result,
    get_latest_source_analysis,
    update_source_analysis_result,
    create_category_finding,
    delete_category_findings,
    delete_source_analysis_results,
)
from services.git_service import git_service
from config import settings
from services.source_analysis.reports import (
    build_scalability_report,
    build_architecture_report,
    build_dependencies_report,
    build_code_quality_report,
    build_security_report,
    build_secrets_report,
)
from services.source_analysis.tech_detection import EXT_LANG

logger = logging.getLogger(__name__)


class SourceAnalysisService:
    """Service for coordinating source code analysis across multiple tools."""

    def __init__(self, session=None):
        self._analysis_cache: Dict[str, Dict] = {}  # In-memory cache for active analyses
        self._session = session  # Injected AsyncSession for DB operations

    # ── Public API ──────────────────────────────────────────────────────────────

    async def run_full_analysis(
        self,
        project_id: str,
        repo_path: Path,
        session=None,
        scan_id: str = None,
        progress_callback=None,
    ) -> Dict[str, Any]:
        """Run a complete source code analysis across all categories."""
        logger.info(f"[SourceAnalysis] Starting full analysis for project {project_id}")

        # Compute code hash for cache invalidation
        code_hash = await self._compute_code_hash(repo_path)

        # Check cache (needs its own short session)
        from database.connection import get_db as _get_db
        async with _get_db() as cache_session:
            cached = await self._check_cache(project_id, code_hash, cache_session)
        if cached:
            logger.info(f"[SourceAnalysis] Returning cached results for project {project_id}")
            return cached

        results: Dict[str, Any] = {}
        errors: List[str] = []
        last_analysis_result_id: Optional[str] = None
        all_categories = list(AnalysisCategory)

        for i, category in enumerate(all_categories):
            # Each category gets its own short-lived session to avoid holding
            # a SQLite write lock across the entire analysis run.
            async with _get_db() as cat_session:
                try:
                    # Create one DB record per category (category column is NOT NULL)
                    analysis_result = await create_source_analysis_result(
                        cat_session,
                        project_id=project_id,
                        category=category,
                        scan_id=scan_id,
                        code_hash=code_hash,
                        status=AnalysisStatus.RUNNING,
                    )
                    await cat_session.commit()
                    analysis_result_id = str(analysis_result.id)
                    last_analysis_result_id = analysis_result_id

                    if progress_callback:
                        progress_callback(
                            int(i / len(all_categories) * 100),
                            category.value,
                        )

                    result = await self._analyze_category(
                        category, repo_path, analysis_result_id, cat_session
                    )
                    results[category.value] = result

                    # Persist findings
                    if result.get("findings"):
                        for finding in result["findings"]:
                            if isinstance(finding, dict):
                                await create_category_finding(
                                    cat_session,
                                    analysis_result_id=analysis_result_id,
                                    finding_type=finding.get("finding_type") or finding.get("type", category.value),
                                    severity=finding.get("severity", FindingSeverity.INFO),
                                    message=finding.get("message", ""),
                                    tool=finding.get("tool", "source_analysis"),
                                    extra_data=finding.get("extra_data") or finding.get("metadata"),
                                )

                    await update_source_analysis_result(
                        cat_session,
                        result_id=analysis_result_id,
                        status=AnalysisStatus.COMPLETED,
                        summary_metrics=result.get("summary_metrics", {}),
                        detailed_findings=result.get("detailed_findings", {}),
                    )
                    await cat_session.commit()

                except Exception as e:
                    logger.error(f"[SourceAnalysis] {category.value} analysis failed: {e}")
                    errors.append(f"{category.value}: {str(e)}")
                    results[category.value] = {
                        "summary_metrics": {"error": str(e)},
                        "detailed_findings": {},
                        "findings": [],
                    }
                    try:
                        await cat_session.rollback()
                    except Exception:
                        pass
                    try:
                        await update_source_analysis_result(
                            cat_session,
                            result_id=analysis_result_id,
                            status=AnalysisStatus.FAILED,
                            error_message=str(e),
                        )
                        await cat_session.commit()
                    except Exception:
                        pass

        final_status = AnalysisStatus.COMPLETED if not errors else AnalysisStatus.FAILED
        return {
            "analysis_result_id": last_analysis_result_id or "",
            "project_id": project_id,
            "code_hash": code_hash,
            "status": final_status.value,
            "results": results,
            "errors": errors,
        }

    async def run_selective_analysis(
        self,
        project_id: str,
        repo_path: Path,
        categories: List[str],
        session=None,
        scan_id: str = None,
        progress_callback=None,
    ) -> Dict[str, Any]:
        """Run analysis for specific categories only."""
        logger.info(f"[SourceAnalysis] Starting selective analysis for project {project_id}: {categories}")

        code_hash = await self._compute_code_hash(repo_path)

        results: Dict[str, Any] = {}
        errors: List[str] = []
        last_analysis_result_id: Optional[str] = None

        for cat_name in categories:
            try:
                category = AnalysisCategory(cat_name)
            except ValueError:
                logger.warning(f"[SourceAnalysis] Unknown category: {cat_name}")
                continue

            # Each category gets its own short-lived session to avoid holding
            # a SQLite write lock across the entire analysis run.
            from database.connection import get_db as _get_db
            async with _get_db() as cat_session:
                try:
                    # Create one DB record per category to satisfy NOT NULL constraint
                    analysis_result = await create_source_analysis_result(
                        cat_session,
                        project_id=project_id,
                        category=category,
                        scan_id=scan_id,
                        code_hash=code_hash,
                        status=AnalysisStatus.RUNNING,
                    )
                    await cat_session.commit()
                    analysis_result_id = str(analysis_result.id)
                    last_analysis_result_id = analysis_result_id

                    if progress_callback:
                        progress_callback(
                            int(categories.index(cat_name) / max(len(categories), 1) * 100),
                            category.value,
                        )

                    result = await self._analyze_category(
                        category, repo_path, analysis_result_id, cat_session
                    )
                    results[category.value] = result

                    if result.get("findings"):
                        for finding in result["findings"]:
                            if isinstance(finding, dict):
                                await create_category_finding(
                                    cat_session,
                                    analysis_result_id=analysis_result_id,
                                    finding_type=finding.get("finding_type") or finding.get("type", category.value),
                                    severity=finding.get("severity", FindingSeverity.INFO),
                                    message=finding.get("message", ""),
                                    tool=finding.get("tool", "source_analysis"),
                                    extra_data=finding.get("extra_data") or finding.get("metadata"),
                                )

                    await update_source_analysis_result(
                        cat_session,
                        result_id=analysis_result_id,
                        status=AnalysisStatus.COMPLETED,
                        summary_metrics=result.get("summary_metrics", {}),
                        detailed_findings=result.get("detailed_findings", {}),
                    )
                    await cat_session.commit()

                except Exception as e:
                    logger.error(f"[SourceAnalysis] {category.value} analysis failed: {e}")
                    errors.append(f"{category.value}: {str(e)}")
                    results[category.value] = {
                        "summary_metrics": {"error": str(e)},
                        "detailed_findings": {},
                        "findings": [],
                    }
                    try:
                        await cat_session.rollback()
                    except Exception:
                        pass
                    try:
                        await update_source_analysis_result(
                            cat_session,
                            result_id=analysis_result_id,
                            status=AnalysisStatus.FAILED,
                            error_message=str(e),
                        )
                        await cat_session.commit()
                    except Exception:
                        pass

        final_status = AnalysisStatus.COMPLETED if not errors else AnalysisStatus.FAILED
        return {
            "analysis_result_id": last_analysis_result_id or "",
            "project_id": project_id,
            "code_hash": code_hash,
            "status": final_status.value,
            "results": results,
            "errors": errors,
        }

    async def get_cached_analysis(self, project_id: str, session=None) -> Optional[Dict]:
        """Get the latest cached analysis for a project if available."""
        effective_session = session or self._session
        if not effective_session:
            return None
        try:
            result = await get_latest_source_analysis(effective_session, project_id)
            if result and result.status == AnalysisStatus.COMPLETED:
                return {
                    "analysis_result_id": str(result.id),
                    "project_id": project_id,
                    "code_hash": result.code_hash,
                    "status": result.status.value,
                    "results": result.detailed_findings or {},
                }
        except Exception as e:
            logger.error(f"[SourceAnalysis] Cache retrieval failed: {e}")
        return None

    async def invalidate_cache(self, project_id: str, session=None) -> None:
        """Invalidate both in-memory and DB cached analysis for a project."""
        self._analysis_cache.pop(project_id, None)
        effective_session = session or self._session
        if effective_session:
            deleted = await delete_source_analysis_results(effective_session, project_id)
            await effective_session.commit()
            logger.info(f"[SourceAnalysis] Invalidated cache for project {project_id}, deleted {deleted} DB records")
        else:
            logger.warning(f"[SourceAnalysis] No session available to delete DB cache for {project_id}")

    # ── Category-Specific Analysis ───────────────────────────────────────────────

    async def _analyze_category(
        self,
        category: AnalysisCategory,
        repo_path: Path,
        analysis_result_id: str,
        session,
    ) -> Dict[str, Any]:
        """Dispatch to the appropriate category analyzer."""
        dispatch = {
            AnalysisCategory.ARCHITECTURE: self._analyze_architecture,
            AnalysisCategory.SCALABILITY: self._analyze_scalability,
            AnalysisCategory.CODE_QUALITY: self._analyze_code_quality,
            AnalysisCategory.SECURITY: self._analyze_security,
            AnalysisCategory.DEPENDENCIES: self._analyze_dependencies,
            AnalysisCategory.SECRETS: self._analyze_secrets,
            AnalysisCategory.TECHNICAL_DEBT: self._analyze_technical_debt,
            AnalysisCategory.CONTRIBUTOR_RISK: self._analyze_contributor_risk,
        }
        handler = dispatch.get(category)
        if not handler:
            return {"summary_metrics": {}, "detailed_findings": {}, "findings": []}

        result = await handler(
            repo_path=repo_path,
            analysis_result_id=analysis_result_id,
        )

        return result

    # ── Architecture ────────────────────────────────────────────────────────────

    async def _analyze_architecture(self, repo_path: Path, analysis_result_id: str) -> Dict[str, Any]:
        from services.source_analysis.architecture import analyze_architecture
        return await analyze_architecture(repo_path, analysis_result_id)

    # ── Scalability ─────────────────────────────────────────────────────────────

    async def _analyze_scalability(self, repo_path: Path, analysis_result_id: str) -> Dict[str, Any]:
        from services.source_analysis.scalability import analyze_scalability
        return await analyze_scalability(repo_path, analysis_result_id)

    def _analyze_async_patterns(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.scalability import analyze_async_patterns
        return analyze_async_patterns(repo_path, files)

    def _analyze_db_patterns(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.scalability import analyze_db_patterns
        return analyze_db_patterns(repo_path, files)

    def _analyze_caching_patterns(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.scalability import analyze_caching_patterns
        return analyze_caching_patterns(repo_path, files)

    def _analyze_resource_patterns(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.scalability import analyze_resource_patterns
        return analyze_resource_patterns(repo_path, files)

    def _build_scalability_report(self, repo_path: Path, async_stats: Dict, db_stats: Dict,
        cache_stats: Dict, resource_stats: Dict, project_name: str = None
    ) -> str:
        from services.source_analysis.reports import build_scalability_report
        return build_scalability_report(repo_path, async_stats, db_stats, cache_stats, resource_stats, project_name)

    # ── Code Quality ────────────────────────────────────────────────────────────

    async def _analyze_code_quality(self, repo_path: Path, analysis_result_id: str) -> Dict[str, Any]:
        from services.source_analysis.code_quality import analyze_code_quality
        return await analyze_code_quality(repo_path, analysis_result_id)

    def _analyze_file_sizes(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.code_quality import analyze_file_sizes
        return analyze_file_sizes(repo_path, files)

    async def _analyze_cyclomatic_complexity(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.code_quality import analyze_cyclomatic_complexity
        return await analyze_cyclomatic_complexity(repo_path, files)

    def _analyze_code_duplication(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.code_quality import analyze_code_duplication
        return analyze_code_duplication(repo_path, files)

    def _analyze_test_coverage(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.code_quality import analyze_test_coverage
        return analyze_test_coverage(repo_path, files)

    def _analyze_dead_code(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.code_quality import analyze_dead_code
        return analyze_dead_code(repo_path, files)

    def _analyze_code_organization(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.code_quality import analyze_code_organization
        return analyze_code_organization(repo_path, files)

    def _calculate_quality_score(self, file_sizes: Dict, complexity: Dict, duplication: Dict,
        test_coverage: Dict, dead_code: Dict, organization: Dict) -> Dict[str, Any]:
        from services.source_analysis.code_quality import calculate_quality_score
        return calculate_quality_score(file_sizes, complexity, duplication, test_coverage, dead_code, organization)

    def _build_code_quality_report(self, repo_path: Path, file_sizes: Dict, complexity: Dict,
        duplication: Dict, test_coverage: Dict, dead_code: Dict,
        organization: Dict, quality_score: Dict, project_name: str = None
    ) -> str:
        from services.source_analysis.reports import build_code_quality_report
        return build_code_quality_report(repo_path, file_sizes, complexity, duplication, test_coverage, dead_code, organization, quality_score, project_name)

    # ── Security ────────────────────────────────────────────────────────────────

    async def _analyze_security(self, repo_path: Path, analysis_result_id: str) -> Dict[str, Any]:
        from services.source_analysis.security import analyze_security
        return await analyze_security(repo_path, analysis_result_id)

    async def _run_sast_scanners(self, repo_path: Path) -> Dict[str, Any]:
        from services.source_analysis.security import run_sast_scanners
        return await run_sast_scanners(repo_path)

    def _detect_hardcoded_secrets(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.security import detect_hardcoded_secrets
        return detect_hardcoded_secrets(repo_path, files)

    def _shannon_entropy(self, data: str) -> float:
        from services.source_analysis.security import shannon_entropy
        return shannon_entropy(data)

    def _analyze_injection_risks(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.security import analyze_injection_risks
        return analyze_injection_risks(repo_path, files)

    def _analyze_auth_patterns(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.security import analyze_auth_patterns
        return analyze_auth_patterns(repo_path, files)

    def _analyze_crypto_weaknesses(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.security import analyze_crypto_weaknesses
        return analyze_crypto_weaknesses(repo_path, files)

    def _analyze_security_config(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.security import analyze_security_config
        return analyze_security_config(repo_path, files)

    def _map_owasp(self, findings: Dict) -> Dict[str, List[str]]:
        from services.source_analysis.security import map_owasp
        return map_owasp(findings)

    def _calculate_security_score(self, sast: Dict, secrets: Dict, injection: Dict,
        auth: Dict, crypto: Dict, config: Dict, owasp: Dict) -> Dict[str, Any]:
        from services.source_analysis.security import calculate_security_score
        return calculate_security_score(sast, secrets, injection, auth, crypto, config, owasp)

    def _build_security_report(self, repo_path: Path, sast: Dict, secrets: Dict, injection: Dict,
        auth: Dict, crypto: Dict, config: Dict, owasp: Dict, score: Dict,
        secret_storage: Dict = None, secret_rotation: Dict = None,
        secret_validation: Dict = None, git_secrets: Dict = None,
        log_sanitization: Dict = None, secret_score: Dict = None,
        project_name: str = None
    ) -> str:
        from services.source_analysis.reports import build_security_report
        return build_security_report(repo_path, sast, secrets, injection, auth, crypto, config, owasp, score, secret_storage, secret_rotation, secret_validation, git_secrets, log_sanitization, secret_score, project_name)

    # ── Dependencies ────────────────────────────────────────────────────────────

    async def _analyze_dependencies(self, repo_path: Path, analysis_result_id: str) -> Dict[str, Any]:
        from services.source_analysis.dependencies import analyze_dependencies
        return await analyze_dependencies(repo_path, analysis_result_id)

    def _build_dependencies_report(self, repo_path: Path, ecosystems: Dict[str, List[Dict[str, str]]],
        classified: Dict[str, Dict[str, List[Dict[str, str]]]],
        security: Dict[str, Any], cve_results: List[Dict[str, Any]],
        health: Dict[str, Any], project_name: str = None
    ) -> str:
        from services.source_analysis.reports import build_dependencies_report
        return build_dependencies_report(repo_path, ecosystems, classified, security, cve_results, health, project_name)

    # ── Secrets ─────────────────────────────────────────────────────────────────

    async def _analyze_secrets(self, repo_path: Path, analysis_result_id: str) -> Dict[str, Any]:
        from services.source_analysis.secrets import analyze_secrets
        return await analyze_secrets(repo_path, analysis_result_id)

    def _analyze_secret_storage(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.secrets import analyze_secret_storage
        return analyze_secret_storage(repo_path, files)

    def _analyze_secret_rotation(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.secrets import analyze_secret_rotation
        return analyze_secret_rotation(repo_path, files)

    def _analyze_secret_validation(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.secrets import analyze_secret_validation
        return analyze_secret_validation(repo_path, files)

    def _analyze_git_secrets(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.secrets import analyze_git_secrets
        return analyze_git_secrets(repo_path, files)

    def _analyze_log_sanitization(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.secrets import analyze_log_sanitization
        return analyze_log_sanitization(repo_path, files)

    def _calculate_secret_score(self, secrets: Dict, storage: Dict, rotation: Dict,
                                 validation: Dict, git: Dict, log: Dict) -> Dict[str, Any]:
        from services.source_analysis.secrets import calculate_secret_score
        return calculate_secret_score(secrets, storage, rotation, validation, git, log)

    def _build_secrets_report(self, repo_path: Path, secrets: Dict, secret_storage: Dict,
        secret_rotation: Dict, secret_validation: Dict, git_secrets: Dict,
        log_sanitization: Dict, secret_score: Dict, project_name: str = None
    ) -> str:
        from services.source_analysis.reports import build_secrets_report
        return build_secrets_report(repo_path, secrets, secret_storage, secret_rotation, secret_validation, git_secrets, log_sanitization, secret_score, project_name)

    # ── Technical Debt ──────────────────────────────────────────────────────────

    async def _analyze_technical_debt(self, repo_path: Path, analysis_result_id: str) -> Dict[str, Any]:
        from services.source_analysis.technical_debt import analyze_technical_debt
        return await analyze_technical_debt(repo_path, analysis_result_id)

    # ── Contributor Risk ────────────────────────────────────────────────────────

    async def _analyze_contributor_risk(self, repo_path: Path, analysis_result_id: str) -> Dict[str, Any]:
        from services.source_analysis.contributor_risk import analyze_contributor_risk
        return await analyze_contributor_risk(repo_path, analysis_result_id)

    # ── Helper Methods ───────────────────────────────────────────────────────────

    async def _compute_code_hash(self, repo_path: Path) -> str:
        """Compute SHA256 hash of all source files for cache invalidation."""
        hash_obj = hashlib.sha256()

        try:
            files = await git_service.get_file_list(repo_path)
            for f in sorted(files)[:500]:  # Limit for performance
                full = repo_path / f
                if full.exists():
                    try:
                        content = full.read_bytes()
                        hash_obj.update(content)
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"[SourceAnalysis] Failed to compute code hash: {e}")

        return hash_obj.hexdigest()

    async def _check_cache(
        self,
        project_id: str,
        code_hash: str,
        session,
    ) -> Optional[Dict]:
        """Check if we have a recent analysis with the same code hash."""
        try:
            from database.crud import get_source_analysis_results_by_project
            all_results = await get_source_analysis_results_by_project(session, project_id)
            completed = [r for r in all_results if r.code_hash == code_hash and r.status == AnalysisStatus.COMPLETED]
            if len(completed) >= len(list(AnalysisCategory)):
                cached = {}
                for r in completed:
                    cached[r.category.value] = r.detailed_findings or {}
                return {
                    "analysis_result_id": str(completed[0].id),
                    "results": cached,
                    "status": AnalysisStatus.COMPLETED.value,
                }
        except Exception as e:
            logger.error(f"[SourceAnalysis] Cache check failed: {e}")

        return None

    # ── Architecture Analysis Helpers (delegated) ──────────────────────────────

    _EXT_LANG = EXT_LANG  # Re-export for backward compatibility

    def _detect_tech_stack(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.tech_detection import detect_tech_stack
        return detect_tech_stack(repo_path, files)

    def _analyze_directory_structure(self, repo_path: Path, files: List[str]) -> Dict[str, Any]:
        from services.source_analysis.tech_detection import analyze_directory_structure
        return analyze_directory_structure(repo_path, files)

    def _detect_arch_style(self, repo_path: Path, dir_struct: Dict, tech_stack: Dict) -> Dict[str, Any]:
        from services.source_analysis.tech_detection import detect_arch_style
        return detect_arch_style(repo_path, dir_struct, tech_stack)

    def _detect_all_patterns(self, repo_path: Path, files: List[str]) -> Dict[str, Dict[str, int]]:
        from services.source_analysis.tech_detection import detect_all_patterns
        return detect_all_patterns(repo_path, files)

    def _detect_go_patterns(self, source: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_go_patterns
        return detect_go_patterns(source)

    def _detect_rust_patterns(self, source: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_rust_patterns
        return detect_rust_patterns(source)

    def _detect_ruby_patterns(self, source: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_ruby_patterns
        return detect_ruby_patterns(source)

    def _detect_php_patterns(self, source: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_php_patterns
        return detect_php_patterns(source)

    def _detect_csharp_patterns(self, source: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_csharp_patterns
        return detect_csharp_patterns(source)

    def _detect_swift_patterns(self, source: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_swift_patterns
        return detect_swift_patterns(source)

    def _detect_dart_patterns(self, source: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_dart_patterns
        return detect_dart_patterns(source)

    def _detect_cpp_patterns(self, source: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_cpp_patterns
        return detect_cpp_patterns(source)

    def _analyze_imports(self, repo_path: Path, files: List[str]) -> tuple:
        from services.source_analysis.tech_detection import analyze_imports
        return analyze_imports(repo_path, files)

    def _generate_arch_observations(
        self, tech_stack: Dict, arch_style: Dict,
        coupling: float, cohesion: float, import_stats: Dict, dir_struct: Dict
    ) -> Dict[str, List[str]]:
        from services.source_analysis.tech_detection import generate_arch_observations
        return generate_arch_observations(tech_stack, arch_style, coupling, cohesion, import_stats, dir_struct)

    def _safe_parse_python(self, source: str) -> Any:
        from services.source_analysis.tech_detection import safe_parse_python
        return safe_parse_python(source)

    def _detect_python_patterns(self, tree: Any, file_path: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_python_patterns
        return detect_python_patterns(tree, file_path)

    def _detect_jvm_patterns(self, source: str, file_path: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_jvm_patterns
        return detect_jvm_patterns(source, file_path)

    def _detect_js_patterns(self, source: str, file_path: str) -> List[str]:
        from services.source_analysis.tech_detection import detect_js_patterns
        return detect_js_patterns(source, file_path)

    # ── Shared Utility Methods ──────────────────────────────────────────────────

    @staticmethod
    def _relative_path(file_path: Optional[str], repo_path: Path) -> Optional[str]:
        """Make an absolute file path relative to repo_path."""
        if not file_path:
            return file_path
        prefix = str(repo_path) + "/"
        if file_path.startswith(prefix):
            return file_path[len(prefix):]
        return file_path

    def _map_semgrep_severity(self, severity: str) -> FindingSeverity:
        """Map Semgrep severity to FindingSeverity."""
        mapping = {
            "ERROR": FindingSeverity.HIGH,
            "WARNING": FindingSeverity.MEDIUM,
            "INFO": FindingSeverity.LOW,
        }
        return mapping.get(severity.upper(), FindingSeverity.MEDIUM)

    def _map_bandit_severity(self, severity: str) -> FindingSeverity:
        """Map Bandit severity to FindingSeverity."""
        mapping = {
            "HIGH": FindingSeverity.HIGH,
            "MEDIUM": FindingSeverity.MEDIUM,
            "LOW": FindingSeverity.LOW,
        }
        return mapping.get(severity.upper(), FindingSeverity.MEDIUM)

    def _map_npm_severity(self, severity: str) -> FindingSeverity:
        """Map npm audit severity to FindingSeverity."""
        mapping = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "moderate": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
        }
        return mapping.get(severity.lower(), FindingSeverity.MEDIUM)

    # ── Dependencies helpers (delegated) ────────────────────────────────────────

    _PKG_SECURITY_DB: Dict[str, Dict[str, str]] = {}  # Replaced by dependencies.PKG_SECURITY_DB

    def _parse_all_deps(self, repo_path: Path) -> Dict[str, List[Dict[str, str]]]:
        from services.source_analysis.dependencies import parse_all_deps
        return parse_all_deps(repo_path)

    def _parse_python_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_python_deps
        return parse_python_deps(repo_path)

    def _parse_node_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_node_deps
        return parse_node_deps(repo_path)

    def _parse_single_package_json(self, pkg_file: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_single_package_json
        return parse_single_package_json(pkg_file)

    def _parse_rust_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_rust_deps
        return parse_rust_deps(repo_path)

    def _parse_go_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_go_deps
        return parse_go_deps(repo_path)

    def _parse_ruby_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_ruby_deps
        return parse_ruby_deps(repo_path)

    def _parse_php_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_php_deps
        return parse_php_deps(repo_path)

    def _parse_dotnet_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_dotnet_deps
        return parse_dotnet_deps(repo_path)

    def _parse_dart_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_dart_deps
        return parse_dart_deps(repo_path)

    def _parse_gradle_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_gradle_deps
        return parse_gradle_deps(repo_path)

    def _parse_maven_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_maven_deps
        return parse_maven_deps(repo_path)

    def _parse_swift_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_swift_deps
        return parse_swift_deps(repo_path)

    def _parse_elixir_deps(self, repo_path: Path) -> List[Dict[str, str]]:
        from services.source_analysis.dependencies import parse_elixir_deps
        return parse_elixir_deps(repo_path)

    async def _run_cve_scanners(self, repo_path: Path) -> List[Dict[str, Any]]:
        from services.source_analysis.dependencies import run_cve_scanners
        return await run_cve_scanners(repo_path)

    def _classify_all_packages(self, ecosystems: Dict[str, List[Dict[str, str]]]) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
        from services.source_analysis.dependencies import classify_all_packages
        return classify_all_packages(ecosystems)

    def _analyze_dep_security(self, classified: Dict, cve_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        from services.source_analysis.dependencies import analyze_dep_security
        return analyze_dep_security(classified, cve_results)

    def _calculate_dep_health(self, ecosystems: Dict, security: Dict) -> Dict[str, Any]:
        from services.source_analysis.dependencies import calculate_dep_health
        return calculate_dep_health(ecosystems, security)

    def _get_db(self):
        """Get database session."""
        return self._session


# Singleton instance
source_analysis_service = SourceAnalysisService()
