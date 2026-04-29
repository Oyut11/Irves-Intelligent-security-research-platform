"""
IRVES — Security Analyzer
Analyzes SAST, hardcoded secrets, injection risks, auth patterns, crypto, config, OWASP.
"""

import json
import logging
import math
import re


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any

from services.source_analysis.reports import build_security_report
from services.source_analysis.report_utils import resolve_project_name

from database.models import FindingSeverity
from services.git_service import git_service

logger = logging.getLogger(__name__)


def _relative_path(file_path, repo_path: Path) -> str:
    """Make an absolute file path relative to repo_path."""
    if not file_path:
        return file_path or ""
    prefix = str(repo_path) + "/"
    if str(file_path).startswith(prefix):
        return str(file_path)[len(prefix):]
    return str(file_path)



def get_db():
    """Get database session."""
    from database.session import get_session
    return get_session()


def get_path_risk_multiplier(file_path: str) -> float:
    """Determine severity multiplier based on file path risk tier.
    
    Path risk tiers:
    - src/, lib/, app/, internal/: Full severity (1.0x)
    - config/, env/: Elevated severity (1.2x)
    - tests/, test/, spec/: Reduced severity (0.3x)
    - docs/, examples/, samples/: Minimal severity (0.1x)
    - scripts/, tools/, dev/: Medium severity (0.5x)
    
    Returns:
        float: Severity multiplier (0.0 to 1.2)
    """
    if not file_path:
        return 1.0
    
    path_lower = file_path.lower()
    
    # Elevated risk paths
    if any(path_lower.startswith(p) for p in ['config/', 'env/', '.env', 'settings/']):
        return 1.2
    
    # Minimal risk paths
    if any(path_lower.startswith(p) for p in ['docs/', 'documentation/', 'examples/', 'samples/', 'demo/']):
        return 0.1
    
    # Reduced risk paths (tests)
    if any(path_lower.startswith(p) for p in ['tests/', 'test/', 'spec/', '__tests__', '__test__']):
        return 0.3
    
    # Medium risk paths (dev tools)
    if any(path_lower.startswith(p) for p in ['scripts/', 'tools/', 'dev/', 'hack/', 'utils/']):
        return 0.5
    
    # Full risk paths (source code)
    if any(path_lower.startswith(p) for p in ['src/', 'lib/', 'app/', 'internal/', 'core/', 'main/']):
        return 1.0
    
    # Default: assume source code
    return 1.0


def apply_path_weighting_to_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply path-aware severity weighting to a list of findings.
    
    This function adjusts the severity of findings based on their file path context.
    Findings in low-risk directories (docs, tests) are down-weighted, while
    findings in high-risk directories (config, env) are up-weighted.
    
    Args:
        findings: List of finding dictionaries with 'file' and 'severity' keys
        
    Returns:
        List of findings with adjusted severity and added 'path_weight' metadata
    """
    weighted_findings = []
    
    for finding in findings:
        file_path = finding.get('file', '')
        original_severity = finding.get('severity', '').upper()
        
        # Get path risk multiplier
        multiplier = get_path_risk_multiplier(file_path)
        
        # Store original severity and multiplier for transparency
        weighted_finding = finding.copy()
        weighted_finding['original_severity'] = original_severity
        weighted_finding['path_weight'] = multiplier
        
        # Adjust severity based on multiplier
        # Critical -> High -> Medium -> Low -> Info
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        if multiplier >= 1.0:
            # No change or up-weight (rare, only for config/env)
            adjusted_severity = original_severity
        elif multiplier >= 0.5:
            # Down-weight by 1 level
            try:
                idx = severity_order.index(original_severity)
                if idx < len(severity_order) - 1:
                    adjusted_severity = severity_order[idx + 1]
                else:
                    adjusted_severity = original_severity
            except ValueError:
                adjusted_severity = original_severity
        elif multiplier >= 0.3:
            # Down-weight by 2 levels (tests)
            try:
                idx = severity_order.index(original_severity)
                new_idx = min(idx + 2, len(severity_order) - 1)
                adjusted_severity = severity_order[new_idx]
            except ValueError:
                adjusted_severity = 'LOW' if original_severity in ['CRITICAL', 'HIGH', 'MEDIUM'] else original_severity
        else:
            # Down-weight significantly (docs/examples)
            adjusted_severity = 'INFO'
        
        weighted_finding['severity'] = adjusted_severity
        weighted_findings.append(weighted_finding)
    
    return weighted_findings


async def analyze_security(repo_path: Path,
    analysis_result_id: str,
) -> Dict[str, Any]:
    """Analyze security: produces a comprehensive security report as a single finding."""
    logger.info("[SourceAnalysis] Analyzing security — generating comprehensive report")

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

        # ── 1. SAST Scanner Results (Semgrep + Bandit) ──
        sast_results = await run_sast_scanners(repo_path)

        # ── 2. Hardcoded Secret Detection ──
        secrets = detect_hardcoded_secrets(repo_path, files)

        # ── 3. Injection Risk Analysis ──
        injection = analyze_injection_risks(repo_path, files)

        # ── 4. Auth Pattern Analysis ──
        auth = analyze_auth_patterns(repo_path, files)

        # ── 5. Crypto Weakness Detection ──
        crypto = analyze_crypto_weaknesses(repo_path, files)

        # ── 6. Security Config Analysis ──
        config = analyze_security_config(repo_path, files)

        # ── 7-11. Secret sub-analyses (lazy import to avoid circular dependency) ──
        from services.source_analysis.secrets import (
            analyze_secret_storage, analyze_secret_rotation,
            analyze_secret_validation, analyze_git_secrets,
            analyze_log_sanitization, calculate_secret_score,
        )
        secret_storage = analyze_secret_storage(repo_path, files)

        # ── 8. Secret Rotation Analysis ──
        secret_rotation = analyze_secret_rotation(repo_path, files)

        # ── 9. Secret Validation Analysis ──
        secret_validation = analyze_secret_validation(repo_path, files)

        # ── 10. Git Secret Analysis ──
        git_secrets = analyze_git_secrets(repo_path, files)

        # ── 11. Log Sanitization Analysis ──
        log_sanitization = analyze_log_sanitization(repo_path, files)

        # ── 12. OWASP Mapping ──
        owasp = map_owasp(secrets, injection, auth, crypto, config)

        # ── 13. Security Score ──
        score = calculate_security_score(secrets, injection, auth, crypto, config, sast_results)

        # ── 14. Secret Score ──
        secret_score = calculate_secret_score(secrets, secret_storage, secret_rotation,
                                                     secret_validation, git_secrets, log_sanitization)

        # ── 15. Build the markdown report ──
        report = build_security_report(
            repo_path, sast_results, secrets, injection, auth, crypto,
            config, owasp, score, secret_storage=secret_storage,
            secret_rotation=secret_rotation, secret_validation=secret_validation,
            git_secrets=git_secrets, log_sanitization=log_sanitization,
            secret_score=secret_score, project_name=project_name
        )

        findings = [{
            "type": "security_report",
            "severity": FindingSeverity.INFO,
            "message": report,
            "tool": "security_analyzer",
            "extra_data": {
                "security_score": score.get("overall", 0),
                "critical_count": secrets.get("critical_count", 0) + sast_results.get("critical_count", 0),
                "high_count": secrets.get("high_count", 0) + sast_results.get("high_count", 0),
            },
        }]

        summary = {
            "total_findings": 1,
            "security_score": score.get("overall", 0),
            "injection_risks": injection.get("sql_count", 0) + injection.get("cmd_count", 0),
            "auth_issues": len(auth.get("findings", [])),
            "crypto_issues": len(crypto.get("findings", [])),
        }

    except Exception as e:
        logger.error(f"[SourceAnalysis] Security analysis failed: {e}")
        findings = [{
            "type": "security_report",
            "severity": FindingSeverity.INFO,
            "message": f"# Security Report\n\nAnalysis failed: {e}",
            "tool": "security_analyzer",
        }]
        summary = {"total_findings": 1}

    summary["total_findings"] = len(findings)
    return {
        "summary_metrics": summary,
        "detailed_findings": {},
        "findings": findings,
    }


async def run_sast_scanners(repo_path: Path) -> Dict[str, Any]:
    """Run Semgrep and Bandit SAST scanners, return structured results."""
    findings: List[Dict[str, Any]] = []
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    # ── Semgrep (multi-language) ──
    try:
        import subprocess, sys
        venv_bin = Path(sys.executable).parent
        semgrep_cmd = str(venv_bin / "semgrep") if (venv_bin / "semgrep").exists() else "semgrep"
        result = subprocess.run(
            [semgrep_cmd, "--config", "auto", str(repo_path), "--json"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode in [0, 1] and result.stdout:
            data = json.loads(result.stdout)
            for item in data.get("results", []):
                sev = item.get("extra", {}).get("severity", "WARNING").upper()
                f = {
                    "tool": "semgrep",
                    "check_id": item.get("check_id", ""),
                    "file": _relative_path(item.get("path"), repo_path) or "",
                    "line": item.get("start", {}).get("line", 0),
                    "message": item.get("extra", {}).get("message", ""),
                    "severity": sev,
                }
                findings.append(f)
                if sev == "ERROR":
                    critical_count += 1
                elif sev == "WARNING":
                    high_count += 1
                else:
                    medium_count += 1
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Semgrep not available: {e}")

    # ── Bandit (Python only) ──
    try:
        import subprocess, sys
        venv_bin = Path(sys.executable).parent
        bandit_cmd = str(venv_bin / "bandit") if (venv_bin / "bandit").exists() else "bandit"
        result = subprocess.run(
            [bandit_cmd, "-r", str(repo_path), "-f", "json"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode in [0, 1] and result.stdout:
            data = json.loads(result.stdout)
            for issue in data.get("results", []):
                sev = issue.get("issue_severity", "MEDIUM").upper()
                f = {
                    "tool": "bandit",
                    "check_id": issue.get("test_id", ""),
                    "file": _relative_path(issue.get("filename"), repo_path) or "",
                    "line": issue.get("line_number", 0),
                    "message": issue.get("issue_text", ""),
                    "severity": sev,
                }
                findings.append(f)
                if sev == "HIGH":
                    high_count += 1
                elif sev == "MEDIUM":
                    medium_count += 1
                else:
                    low_count += 1
    except Exception as e:
        logger.warning(f"[SourceAnalysis] Bandit not available: {e}")

    # Apply path-aware severity weighting
    weighted_findings = apply_path_weighting_to_findings(findings)
    
    # Recalculate counts based on weighted severity
    weighted_critical = sum(1 for f in weighted_findings if f.get('severity') == 'CRITICAL')
    weighted_high = sum(1 for f in weighted_findings if f.get('severity') == 'HIGH')
    weighted_medium = sum(1 for f in weighted_findings if f.get('severity') == 'MEDIUM')
    weighted_low = sum(1 for f in weighted_findings if f.get('severity') == 'LOW')

    return {
        "findings": weighted_findings[:50],
        "critical_count": weighted_critical,
        "high_count": weighted_high,
        "medium_count": weighted_medium,
        "low_count": weighted_low,
    }



def detect_hardcoded_secrets(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Detect hardcoded secrets, API keys, tokens, and credentials across all languages.
    Includes entropy analysis, attack scenarios, and impact assessment."""
    findings: List[Dict[str, Any]] = []
    critical_count = 0
    high_count = 0
    medium_count = 0

    # Attack scenario and impact data per category
    attack_info = {
        "Hardcoded OAuth/API credential": {
            "attack": "Attacker extracts credentials from source, uses them to access OAuth-protected resources",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
            "remediation": "Revoke credential, remove from source, use environment variables or secret manager",
        },
        "Hardcoded OAuth Client ID": {
            "attack": "Attacker uses client ID to initiate unauthorized OAuth flows",
            "impact": {"confidentiality": "MEDIUM", "integrity": "MEDIUM", "availability": "LOW"},
            "remediation": "Move to environment variables, rotate if compromised",
        },
        "GitHub token detected": {
            "attack": "Attacker uses token to access repositories, issues, and org data",
            "impact": {"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "HIGH"},
            "remediation": "Revoke token immediately at github.com/settings/tokens, use GitHub Apps instead",
        },
        "AWS Access Key ID detected": {
            "attack": "Attacker uses key to access AWS resources (S3, EC2, IAM)",
            "impact": {"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "CRITICAL"},
            "remediation": "Revoke in AWS IAM console, use IAM roles or instance profiles",
        },
        "AWS Secret Access Key detected": {
            "attack": "Attacker gains full access to AWS account",
            "impact": {"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "CRITICAL"},
            "remediation": "Revoke immediately in AWS IAM, use IAM roles, enable MFA for CLI",
        },
        "Private key detected in source": {
            "attack": "Attacker uses private key to decrypt traffic, sign code, or impersonate services",
            "impact": {"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "HIGH"},
            "remediation": "Revoke certificate, remove key from source and git history, use HSM or vault",
        },
        "Hardcoded secret key": {
            "attack": "Attacker forges session cookies, bypasses auth, performs CSRF",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
            "remediation": "Generate strong random secret (32+ bytes), use environment variables",
        },
        "Hardcoded password": {
            "attack": "Attacker uses password to access accounts, databases, or services",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
            "remediation": "Remove hardcoded password, use environment variables, implement password hashing",
        },
        "Hardcoded JWT token": {
            "attack": "Attacker decodes JWT, may forge tokens if algorithm is weak",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "LOW"},
            "remediation": "Use short-lived tokens, implement token rotation, use RS256 algorithm",
        },
        "Database URL with credentials": {
            "attack": "Attacker connects to database directly using extracted credentials",
            "impact": {"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "HIGH"},
            "remediation": "Use environment variables, implement connection pooling with IAM auth",
        },
        "Hardcoded Bearer token": {
            "attack": "Attacker uses bearer token to access API endpoints",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
            "remediation": "Revoke token, use OAuth2 flow with refresh tokens",
        },
        "Weak/default secret value": {
            "attack": "Attacker guesses or knows default secret, forges sessions or CSRF tokens",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
            "remediation": "Generate strong random secret (32+ bytes), never use default values in production",
        },
        "Slack token detected": {
            "attack": "Attacker reads/modifies Slack messages, accesses files",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "LOW"},
            "remediation": "Revoke token at api.slack.com/authentication, use OAuth2 bot tokens",
        },
        "Stripe API key detected": {
            "attack": "Attacker processes refunds, accesses customer data, or creates charges",
            "impact": {"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "HIGH"},
            "remediation": "Revoke key in Stripe dashboard, use restricted keys with minimal permissions",
        },
        "Google API key detected": {
            "attack": "Attacker uses key to access Google APIs (Maps, Drive, etc.)",
            "impact": {"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "MEDIUM"},
            "remediation": "Restrict API key in Google Cloud Console, set referrer restrictions",
        },
        "SendGrid API key detected": {
            "attack": "Attacker sends phishing emails through your account",
            "impact": {"confidentiality": "MEDIUM", "integrity": "HIGH", "availability": "LOW"},
            "remediation": "Revoke key in SendGrid settings, use restricted API keys",
        },
        "Twilio API key detected": {
            "attack": "Attacker makes calls/sends SMS through your account",
            "impact": {"confidentiality": "MEDIUM", "integrity": "HIGH", "availability": "LOW"},
            "remediation": "Revoke key in Twilio console, use API key with minimal scope",
        },
        "Heroku API key detected": {
            "attack": "Attacker accesses Heroku apps, env vars, and addons",
            "impact": {"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "HIGH"},
            "remediation": "Revoke in Heroku account settings, use Heroku CI keys with limited scope",
        },
        "High-entropy string (potential secret)": {
            "attack": "Potential secret — could be API key, token, or encrypted value",
            "impact": {"confidentiality": "MEDIUM", "integrity": "MEDIUM", "availability": "LOW"},
            "remediation": "Verify if this is a secret, if so move to environment variables",
        },
        "Debug mode enabled in config": {
            "attack": "Attacker gains access to detailed error messages and internal state",
            "impact": {"confidentiality": "MEDIUM", "integrity": "LOW", "availability": "LOW"},
            "remediation": "Disable debug mode in production, use environment-specific configuration",
        },
    }

    # Secret patterns (language-agnostic — scan all text files)
    secret_patterns = [
        # OAuth / API keys
        (re.compile(r'(?:CLIENT_SECRET|API_KEY|APP_SECRET|APP_KEY)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE), "Hardcoded OAuth/API credential", "critical"),
        (re.compile(r'CLIENT_ID\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE), "Hardcoded OAuth Client ID", "high"),
        # GitHub tokens
        (re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}'), "GitHub token detected", "critical"),
        # AWS keys
        (re.compile(r'AKIA[A-Z0-9]{16}'), "AWS Access Key ID detected", "critical"),
        (re.compile(r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.IGNORECASE), "AWS Secret Access Key detected", "critical"),
        # Private keys
        (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), "Private key detected in source", "critical"),
        # Generic secrets
        (re.compile(r'(?:SECRET_KEY|SECRET_TOKEN|SECRET_PASSWORD|ENCRYPTION_KEY)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?', re.IGNORECASE), "Hardcoded secret key", "high"),
        # Passwords
        (re.compile(r'(?:PASSWORD|PASSWD|PASS)\s*[=:]\s*["\']([^\s"\']{4,})["\']', re.IGNORECASE), "Hardcoded password", "high"),
        # JWT tokens
        (re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'), "Hardcoded JWT token", "high"),
        # Database URLs with credentials
        (re.compile(r'(?:postgres|mysql|mongodb|redis)://[^\s"\']+:([^\s"\']+)@[^\s"\']+', re.IGNORECASE), "Database URL with credentials", "high"),
        # Bearer tokens
        (re.compile(r'Bearer\s+[A-Za-z0-9_\-\.]{20,}'), "Hardcoded Bearer token", "high"),
        # Slack tokens
        (re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,}'), "Slack token detected", "critical"),
        # Stripe keys
        (re.compile(r'(?:sk|rk)_(?:test|live)_[A-Za-z0-9]{24,}'), "Stripe API key detected", "critical"),
        # Google API keys
        (re.compile(r'AIza[A-Za-z0-9_\\-]{35}'), "Google API key detected", "high"),
        # SendGrid keys
        (re.compile(r'SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}'), "SendGrid API key detected", "high"),
        # Twilio keys
        (re.compile(r'SK[A-Za-z0-9]{32}'), "Twilio API key detected", "high"),
        # Heroku keys
        (re.compile(r'(?:heroku_|HEROKU_)?API_KEY\s*[=:]\s*["\']?([0-9a-f-]{36})["\']?', re.IGNORECASE), "Heroku API key detected", "high"),
        # GitLab tokens
        (re.compile(r'glpat-[A-Za-z0-9\-]{20,}'), "GitLab token detected", "critical"),
        # Firebase
        (re.compile(r'AIza[A-Za-z0-9_\-]{35}'), "Firebase key detected", "high"),
        # Shopify tokens
        (re.compile(r'shpat_[A-Za-z0-9\-]{32,}'), "Shopify access token detected", "critical"),
        # NuGet API keys
        (re.compile(r'oy2[a-z0-9]{43}'), "NuGet API key detected", "high"),
    ]

    # Weak/default value patterns
    weak_patterns = [
        (re.compile(r'(?:SECRET_KEY|SECRET)\s*[=:]\s*["\']?(?:change[-_]?this|default|test|example|secret|123|abc|password|todo|fixme|insecure|please-change|changeme)["\']?', re.IGNORECASE), "Weak/default secret value", "critical"),
        (re.compile(r'DEBUG\s*[=:]\s*(?:True|true|1|yes)', re.IGNORECASE), "Debug mode enabled in config", "medium"),
    ]

    # Entropy-based detection for high-entropy strings that look like secrets
    # (Only scan config/env files for entropy to reduce false positives)
    config_extensions = {".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties"}
    config_filenames = {".env", ".env.example", ".env.local", ".env.production", ".env.development",
                       "config.py", "config.js", "config.ts", "config.json", "config.yaml", "config.yml",
                       "settings.py", "settings.json", "settings.yaml", "application.properties",
                       "application.yml", "appsettings.json", "app.config", "web.config"}



    # shannon_entropy is now a top-level function

    scanned = 0
    for f in files[:500]:
        ext = Path(f).suffix.lower()
        fname = Path(f).name
        # Skip binary files, images, etc.
        if ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                   ".mp3", ".mp4", ".zip", ".tar", ".gz", ".so", ".dll", ".exe", ".o", ".pyc", ".class",
                   ".aab", ".apk", ".dex", ".jar", ".aar", ".gradle", ".svg", ".webp"}:
            continue

        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        scanned += 1
        all_patterns = secret_patterns + weak_patterns

        for pattern, desc, severity in all_patterns:
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                # Mask the actual secret value
                if match.lastindex and match.lastindex >= 1:
                    val = match.group(1)
                    if len(val) > 4:
                        masked = val[:2] + "***" + val[-2:]
                    else:
                        masked = "***"
                else:
                    masked = "***"

                info = attack_info.get(desc, {})
                
                # Active secret validation: check structural validity
                validation_result = {"valid": True, "confidence": 0.5, "reason": "Not validated"}
                try:
                    from services.source_analysis.secrets import validate_secret_structure
                    # Use the actual matched value if available (not masked)
                    actual_value = match.group(1) if match.lastindex and match.lastindex >= 1 else masked
                    validation_result = validate_secret_structure(actual_value, desc)
                except Exception:
                    pass
                
                # Downgrade severity if validation fails with low confidence
                adjusted_severity = severity
                if not validation_result["valid"] and validation_result["confidence"] < 0.5:
                    if severity == "critical":
                        adjusted_severity = "medium"
                    elif severity == "high":
                        adjusted_severity = "low"
                
                findings.append({
                    "type": "hardcoded_secret",
                    "severity": adjusted_severity,
                    "description": desc,
                    "file": f,
                    "line": line_num,
                    "masked_value": masked,
                    "attack_scenario": info.get("attack", ""),
                    "impact": info.get("impact", {}),
                    "remediation": info.get("remediation", ""),
                    "validation": validation_result,
                })
                if adjusted_severity == "critical":
                    critical_count += 1
                elif adjusted_severity == "high":
                    high_count += 1
                else:
                    medium_count += 1

        # Entropy-based detection for config files
        if ext in config_extensions or fname in config_filenames:
            # Look for key=value pairs with high-entropy values
            for line_num_0, line in enumerate(text.splitlines()):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                m = re.match(r'[\w.]+\s*[=:]\s*["\']?([A-Za-z0-9+/=]{30,})["\']?', line)
                if m:
                    val = m.group(1)
                    entropy = shannon_entropy(val)
                    # High entropy threshold (>4.5) suggests a secret
                    if entropy > 4.5:
                        # Skip if already detected by specific patterns
                        already_found = any(
                            f_["file"] == f and f_["line"] == line_num_0 + 1
                            for f_ in findings
                        )
                        if not already_found:
                            masked = val[:2] + "***" + val[-2:]
                            info = attack_info.get("High-entropy string (potential secret)", {})
                            findings.append({
                                "type": "entropy_secret",
                                "severity": "medium",
                                "description": "High-entropy string (potential secret)",
                                "file": f,
                                "line": line_num_0 + 1,
                                "masked_value": masked,
                                "entropy": round(entropy, 2),
                                "attack_scenario": info.get("attack", ""),
                                "impact": info.get("impact", {}),
                                "remediation": info.get("remediation", ""),
                            })
                            medium_count += 1

    # Apply path-aware severity weighting
    weighted_findings = apply_path_weighting_to_findings(findings)
    
    # Recalculate counts based on weighted severity
    weighted_critical = sum(1 for f in weighted_findings if f.get('severity') == 'critical')
    weighted_high = sum(1 for f in weighted_findings if f.get('severity') == 'high')
    weighted_medium = sum(1 for f in weighted_findings if f.get('severity') == 'medium')

    return {
        "findings": weighted_findings[:40],
        "critical_count": weighted_critical,
        "high_count": weighted_high,
        "medium_count": weighted_medium,
        "total_count": len(weighted_findings),
        "files_scanned": scanned,
    }



def analyze_injection_risks(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze injection risks: SQL injection, command injection, XSS across all languages."""
    sql_findings: List[Dict] = []
    cmd_findings: List[Dict] = []
    xss_findings: List[Dict] = []

    # SQL injection patterns per language
    sql_patterns = [
        # Python
        (re.compile(r'(?:execute|cursor\.execute)\s*\(\s*(?:f["\']|["\'].*%s|format\()', re.IGNORECASE), "Python: Potential SQL injection via string formatting", ".py"),
        (re.compile(r'text\s*\(\s*f["\']', re.IGNORECASE), "Python: SQLAlchemy text() with f-string", ".py"),
        # JS/TS
        (re.compile(r'\.query\s*\(\s*(?:`|\+|[\'"].*\+)', re.IGNORECASE), "JS/TS: SQL query with string concatenation", ".js"),
        # Java/Kotlin
        (re.compile(r'(?:createQuery|createNativeQuery|executeQuery)\s*\(\s*"', re.IGNORECASE), "Java/Kotlin: Potential SQL injection in query", ".java"),
        # Go
        (re.compile(r'(?:Query|Exec)\s*\(\s*fmt\.Sprintf', re.IGNORECASE), "Go: SQL query with fmt.Sprintf", ".go"),
        # PHP
        (re.compile(r'mysqli?_query\s*\([^,]*\$', re.IGNORECASE), "PHP: SQL query with variable interpolation", ".php"),
        # Ruby
        (re.compile(r'(?:execute|find_by_sql)\s*\(.*#\{', re.IGNORECASE), "Ruby: SQL with string interpolation", ".rb"),
        # C#
        (re.compile(r'(?:FromSqlRaw|ExecuteSqlRaw)\s*\(', re.IGNORECASE), "C#: Raw SQL query (potential injection)", ".cs"),
    ]

    # Command injection patterns per language
    cmd_patterns = [
        # Python
        (re.compile(r'(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True)', re.IGNORECASE), "Python: shell=True subprocess call", ".py"),
        (re.compile(r'subprocess\.\w+\s*\([^)]*(?:f["\']|format\()', re.IGNORECASE), "Python: subprocess with formatted command", ".py"),
        # JS/TS
        (re.compile(r'(?:exec|execSync|spawn)\s*\(\s*(?:`|\+|[\'"].*\+)', re.IGNORECASE), "JS/TS: child_process with string concatenation", ".js"),
        # Java/Kotlin
        (re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(', re.IGNORECASE), "Java/Kotlin: Runtime.exec() (potential injection)", ".java"),
        # Go
        (re.compile(r'exec\.Command\s*\([^)]*\.\.\.', re.IGNORECASE), "Go: exec.Command with spread args", ".go"),
        # PHP
        (re.compile(r'(?:exec|system|shell_exec|passthru|popen)\s*\(', re.IGNORECASE), "PHP: Command execution function", ".php"),
        # Ruby
        (re.compile(r'(?:system|exec|`|\%x\{)', re.IGNORECASE), "Ruby: Command execution", ".rb"),
        # C#
        (re.compile(r'Process\.Start\s*\(', re.IGNORECASE), "C#: Process.Start() (potential injection)", ".cs"),
        # Swift
        (re.compile(r'Process\s*\(\)', re.IGNORECASE), "Swift: Process execution", ".swift"),
        # Dart
        (re.compile(r'Process\.run\s*\(', re.IGNORECASE), "Dart: Process.run() (potential injection)", ".dart"),
    ]

    # XSS patterns per language
    xss_patterns = [
        # JS/TS/HTML
        (re.compile(r'\.innerHTML\s*=', re.IGNORECASE), "JS: innerHTML assignment (XSS risk)", ".js"),
        (re.compile(r'dangerouslySetInnerHTML', re.IGNORECASE), "React: dangerouslySetInnerHTML (XSS risk)", ".js"),
        (re.compile(r'v-html', re.IGNORECASE), "Vue: v-html directive (XSS risk)", ".js"),
        (re.compile(r'document\.write\s*\(', re.IGNORECASE), "JS: document.write() (XSS risk)", ".js"),
        # Python/Jinja2
        (re.compile(r'\|\s*safe\b', re.IGNORECASE), "Jinja2: |safe filter (XSS risk)", ".py"),
        (re.compile(r'Markup\s*\(', re.IGNORECASE), "Jinja2: Markup() (XSS risk)", ".py"),
        # PHP
        (re.compile(r'echo\s*\$', re.IGNORECASE), "PHP: Unescaped echo (XSS risk)", ".php"),
        # Ruby/ERB
        (re.compile(r'<%=\s*(?!(?:h\(|escape|sanitize))', re.IGNORECASE), "ERB: Unescaped output (XSS risk)", ".rb"),
        # Java/JSP
        (re.compile(r'escapeXml\s*=\s*["\']false["\']', re.IGNORECASE), "JSP: escapeXml disabled (XSS risk)", ".java"),
    ]

    for f in files[:400]:
        ext = Path(f).suffix.lower()
        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        # SQL injection
        for pattern, desc, target_ext in sql_patterns:
            if ext != target_ext and not (ext in {".ts", ".tsx"} and target_ext == ".js"):
                continue
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                sql_findings.append({"file": f, "line": line_num, "description": desc})

        # Command injection
        for pattern, desc, target_ext in cmd_patterns:
            if ext != target_ext and not (ext in {".ts", ".tsx"} and target_ext == ".js") and not (ext in {".kts", ".kt"} and target_ext == ".java"):
                continue
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                cmd_findings.append({"file": f, "line": line_num, "description": desc})

        # XSS
        for pattern, desc, target_ext in xss_patterns:
            if ext != target_ext and not (ext in {".ts", ".tsx"} and target_ext == ".js") and not (ext in {".html"} and target_ext == ".js"):
                continue
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                xss_findings.append({"file": f, "line": line_num, "description": desc})

    return {
        "sql_findings": sql_findings[:15],
        "sql_count": len(sql_findings),
        "cmd_findings": cmd_findings[:15],
        "cmd_count": len(cmd_findings),
        "xss_findings": xss_findings[:15],
        "xss_count": len(xss_findings),
    }



def analyze_auth_patterns(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze authentication and authorization patterns across all languages."""
    findings: List[Dict] = []

    auth_patterns = [
        # OAuth2 implementations
        (re.compile(r'(?:authlib|oauth2client|requests_oauthlib|OAuth2Session|from_oauthlib)', re.IGNORECASE), "Python: OAuth2 library detected", ".py"),
        (re.compile(r'(?:passport|oauth2|openid-client|node-oidc-provider)', re.IGNORECASE), "JS/TS: OAuth library detected", ".js"),
        (re.compile(r'(?:spring-security|oauth2|spring-boot-starter-oauth2)', re.IGNORECASE), "Java: Spring Security OAuth detected", ".java"),
        (re.compile(r'(?:devise|omniauth|doorkeeper)', re.IGNORECASE), "Ruby: Auth library detected", ".rb"),
        (re.compile(r'(?:laravel/passport|laravel/sanctum|oauth2-server)', re.IGNORECASE), "PHP: OAuth library detected", ".php"),
        (re.compile(r'(?:Microsoft\.AspNetCore\.Identity|IdentityServer)', re.IGNORECASE), "C#: ASP.NET Identity detected", ".cs"),
        (re.compile(r'(?:Accounts|AccountManager|Keychain)', re.IGNORECASE), "Kotlin/Swift: Platform auth API detected", ".kt"),
        # Session management
        (re.compile(r'SessionMiddleware|session\s*=\s*|SESSION_', re.IGNORECASE), "Session management detected", ".py"),
        (re.compile(r'express-session|cookie-session|session\(\)', re.IGNORECASE), "JS: Session middleware detected", ".js"),
        (re.compile(r'HttpSession|session\.getAttribute', re.IGNORECASE), "Java: HTTP session detected", ".java"),
        # Rate limiting (absence is a finding)
        (re.compile(r'(?:rate_limit|throttle|slowapi|RateLimiter|@limiter)', re.IGNORECASE), "Rate limiting detected", ".py"),
        (re.compile(r'(?:rate-limit|express-rate-limit|rateLimit)', re.IGNORECASE), "JS: Rate limiting detected", ".js"),
        # RBAC
        (re.compile(r'(?:role|permission|authorize|is_admin|check_role|RBAC|ABAC)', re.IGNORECASE), "Authorization pattern detected", ".py"),
        # CSRF
        (re.compile(r'(?:csrf|CSRFToken|xsrf|_csrf_token)', re.IGNORECASE), "CSRF protection detected", ".py"),
        (re.compile(r'(?:csurf|csrf-csrf|csurf)', re.IGNORECASE), "JS: CSRF protection detected", ".js"),
    ]

    has_oauth = False
    has_rate_limit = False
    has_csrf = False
    has_rbac = False
    has_session = False

    for f in files[:400]:
        ext = Path(f).suffix.lower()
        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        for pattern, desc, target_ext in auth_patterns:
            if ext != target_ext and not (ext in {".ts", ".tsx"} and target_ext == ".js") and not (ext in {".kts"} and target_ext == ".kt"):
                continue
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                findings.append({"file": f, "line": line_num, "description": desc})

                if "oauth" in desc.lower():
                    has_oauth = True
                if "rate" in desc.lower():
                    has_rate_limit = True
                if "csrf" in desc.lower():
                    has_csrf = True
                if "authorization" in desc.lower() or "rbac" in desc.lower():
                    has_rbac = True
                if "session" in desc.lower():
                    has_session = True

    # Generate negative findings (things that are missing)
    weaknesses = []
    if has_oauth and not has_rate_limit:
        weaknesses.append("No rate limiting detected on OAuth endpoints")
    if has_oauth and not has_csrf:
        weaknesses.append("No CSRF protection detected on OAuth flow")
    if not has_rbac:
        weaknesses.append("No role-based authorization (RBAC) detected")
    if has_session and not has_csrf:
        weaknesses.append("Session management without CSRF protection")

    return {
        "findings": findings[:20],
        "has_oauth": has_oauth,
        "has_rate_limit": has_rate_limit,
        "has_csrf": has_csrf,
        "has_rbac": has_rbac,
        "has_session": has_session,
        "weaknesses": weaknesses,
    }



def analyze_crypto_weaknesses(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Detect cryptographic weaknesses across all languages."""
    findings: List[Dict] = []

    crypto_patterns = [
        # Weak hash algorithms
        (re.compile(r'(?:hashlib\.md5|hashlib\.sha1|MD5\.Create|SHA1\.Create|MessageDigest\.getInstance\(["\']MD5|MessageDigest\.getInstance\(["\']SHA-?1)', re.IGNORECASE), "Weak hash algorithm (MD5/SHA1)", ".py"),
        (re.compile(r'(?:crypto\.createHash\(["\']md5|crypto\.createHash\(["\']sha1|createHash\(["\']md5)', re.IGNORECASE), "JS: Weak hash algorithm (MD5/SHA1)", ".js"),
        (re.compile(r'(?:DigestUtils\.md5|DigestUtils\.sha1|MD5Digest|SHA1Digest)', re.IGNORECASE), "Java: Weak hash algorithm", ".java"),
        (re.compile(r'(?:Digest::MD5|Digest::SHA1)', re.IGNORECASE), "Ruby: Weak hash algorithm", ".rb"),
        (re.compile(r'(?:md5\(|sha1\()', re.IGNORECASE), "PHP: Weak hash algorithm", ".php"),
        # Weak encryption
        (re.compile(r'(?:DES|RC4|Blowfish|ECB)', re.IGNORECASE), "Weak encryption algorithm or mode", ".py"),
        (re.compile(r'(?:DES|RC4|Blowfish|ECB)', re.IGNORECASE), "JS: Weak encryption algorithm or mode", ".js"),
        # Insecure random
        (re.compile(r'\brandom\.\w+\s*\(', re.IGNORECASE), "Python: Use `secrets` module instead of `random` for security", ".py"),
        (re.compile(r'Math\.random\s*\(', re.IGNORECASE), "JS: Math.random() is not cryptographically secure", ".js"),
        (re.compile(r'java\.util\.Random\s', re.IGNORECASE), "Java: Use SecureRandom instead of Random", ".java"),
        (re.compile(r'arc4random', re.IGNORECASE), "Swift/Kotlin: arc4random is not CSPRNG", ".swift"),
        # TLS issues
        (re.compile(r'verify\s*=\s*False|verify=False|CERT_NONE|ssl\._create_unverified_context', re.IGNORECASE), "TLS certificate verification disabled", ".py"),
        (re.compile(r'rejectUnauthorized\s*:\s*false|rejectUnauthorized:\s*0', re.IGNORECASE), "JS: TLS certificate verification disabled", ".js"),
        (re.compile(r'TrustAllCertificates|TrustManager|X509TrustManager', re.IGNORECASE), "Java: Custom trust manager (TLS bypass risk)", ".java"),
        (re.compile(r'CURLOPT_SSL_VERIFYPEER\s*=\s*false', re.IGNORECASE), "PHP: TLS verification disabled", ".php"),
    ]

    for f in files[:400]:
        ext = Path(f).suffix.lower()
        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        for pattern, desc, target_ext in crypto_patterns:
            if ext != target_ext and not (ext in {".ts", ".tsx"} and target_ext == ".js") and not (ext in {".kts"} and target_ext == ".kt"):
                continue
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                findings.append({"file": f, "line": line_num, "description": desc})

    return {
        "findings": findings[:20],
        "weak_hash_count": sum(1 for f in findings if "Weak hash" in f["description"]),
        "weak_encryption_count": sum(1 for f in findings if "Weak encryption" in f["description"]),
        "insecure_random_count": sum(1 for f in findings if "random" in f["description"].lower() or "CSPRNG" in f["description"]),
        "tls_issues_count": sum(1 for f in findings if "TLS" in f["description"] or "certificate" in f["description"].lower()),
    }



def analyze_security_config(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze security configuration: CSP, CORS, headers, debug mode, file upload."""
    findings: List[Dict] = []
    has_csp = False
    has_cors = False
    has_hsts = False
    has_x_frame = False
    has_x_content_type = False
    debug_enabled = False

    for f in files[:400]:
        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        fname = Path(f).name.lower()

        # CSP detection
        if "content-security-policy" in text.lower() or "content_security_policy" in text.lower():
            has_csp = True
            # Check for unsafe-inline / unsafe-eval
            if "unsafe-inline" in text.lower() or "unsafe-eval" in text.lower():
                findings.append({"file": f, "description": "CSP allows unsafe-inline or unsafe-eval", "severity": "medium"})

        # CORS detection
        if "cors" in text.lower() or "access-control-allow" in text.lower():
            has_cors = True
            if "allow_origins" in text.lower() and "*" in text:
                findings.append({"file": f, "description": "CORS allows all origins (*)", "severity": "high"})

        # Security headers
        if "x-content-type-options" in text.lower() or "x_content_type_options" in text.lower():
            has_x_content_type = True
        if "x-frame-options" in text.lower() or "x_frame_options" in text.lower():
            has_x_frame = True
        if "strict-transport-security" in text.lower() or "hsts" in text.lower():
            has_hsts = True

        # Debug mode
        if re.search(r'DEBUG\s*=\s*True|DEBUG\s*=\s*true|debug\s*=\s*true|debug\s*:\s*true', text, re.IGNORECASE):
            if not any(x in fname for x in ["test", "spec", "__test"]):
                debug_enabled = True
                findings.append({"file": f, "description": "Debug mode enabled in production config", "severity": "medium"})

        # File upload without validation
        if re.search(r'UploadFile|file\.filename|multipart/form-data|$_FILES|multer', text, re.IGNORECASE):
            if not re.search(r'safe_filename|sanitize|validate.*ext|allowed_ext|path_traversal', text, re.IGNORECASE):
                findings.append({"file": f, "description": "File upload without path/validation checks", "severity": "medium"})

        # Path traversal risk (skip binary files)
        ext = Path(f).suffix.lower()
        if ext not in {'.aab', '.apk', '.ttf', '.woff', '.woff2', '.eot', '.png', '.jpg', '.jpeg', '.gif', '.mp3', '.mp4', '.zip', '.so', '.dll', '.exe', '.o', '.class', '.pyc'}:
            if re.search(r'\.\./|\.\.\\\\', text):
                findings.append({"file": f, "description": "Potential path traversal sequence", "severity": "high"})

    missing_headers = []
    if not has_csp:
        missing_headers.append("Content-Security-Policy")
    if not has_cors:
        missing_headers.append("CORS configuration")
    if not has_hsts:
        missing_headers.append("Strict-Transport-Security")
    if not has_x_frame:
        missing_headers.append("X-Frame-Options")
    if not has_x_content_type:
        missing_headers.append("X-Content-Type-Options")

    return {
        "findings": findings[:15],
        "has_csp": has_csp,
        "has_cors": has_cors,
        "has_hsts": has_hsts,
        "has_x_frame": has_x_frame,
        "has_x_content_type": has_x_content_type,
        "debug_enabled": debug_enabled,
        "missing_headers": missing_headers,
    }



def map_owasp(secrets: Dict, injection: Dict, auth: Dict, crypto: Dict, config: Dict) -> Dict[str, Any]:
    """Map findings to OWASP Top 10 (2021) categories."""
    owasp = {
        "A01: Broken Access Control": {"status": "⚠️", "notes": []},
        "A02: Cryptographic Failures": {"status": "⚠️", "notes": []},
        "A03: Injection": {"status": "✅", "notes": []},
        "A04: Insecure Design": {"status": "⚠️", "notes": []},
        "A05: Security Misconfiguration": {"status": "⚠️", "notes": []},
        "A06: Vulnerable Components": {"status": "⚠️", "notes": []},
        "A07: Auth Failures": {"status": "⚠️", "notes": []},
        "A08: Data Integrity": {"status": "⚠️", "notes": []},
        "A09: Logging & Monitoring": {"status": "⚠️", "notes": []},
        "A10: SSRF": {"status": "✅", "notes": []},
    }

    # A01: Broken Access Control
    if not auth.get("has_rbac"):
        owasp["A01: Broken Access Control"]["status"] = "❌"
        owasp["A01: Broken Access Control"]["notes"].append("No RBAC/authorization detected")
    else:
        owasp["A01: Broken Access Control"]["status"] = "✅"

    # A02: Cryptographic Failures
    if crypto.get("weak_hash_count", 0) > 0:
        owasp["A02: Cryptographic Failures"]["status"] = "❌"
        owasp["A02: Cryptographic Failures"]["notes"].append(f"{crypto['weak_hash_count']} weak hash usage(s)")
    if crypto.get("tls_issues_count", 0) > 0:
        owasp["A02: Cryptographic Failures"]["status"] = "❌"
        owasp["A02: Cryptographic Failures"]["notes"].append(f"{crypto['tls_issues_count']} TLS verification issue(s)")
    if not crypto.get("findings"):
        owasp["A02: Cryptographic Failures"]["status"] = "✅"

    # A03: Injection
    sql = injection.get("sql_count", 0)
    cmd = injection.get("cmd_count", 0)
    if sql > 0 or cmd > 0:
        owasp["A03: Injection"]["status"] = "⚠️"
        owasp["A03: Injection"]["notes"].append(f"{sql} SQL injection risk(s), {cmd} command injection risk(s)")
    else:
        owasp["A03: Injection"]["status"] = "✅"
        owasp["A03: Injection"]["notes"].append("No injection patterns detected")

    # A05: Security Misconfiguration
    if config.get("debug_enabled"):
        owasp["A05: Security Misconfiguration"]["status"] = "❌"
        owasp["A05: Security Misconfiguration"]["notes"].append("Debug mode enabled")
    if config.get("missing_headers"):
        owasp["A05: Security Misconfiguration"]["status"] = "❌"
        owasp["A05: Security Misconfiguration"]["notes"].append(f"Missing: {', '.join(config['missing_headers'][:3])}")

    # A07: Auth Failures
    if not auth.get("has_rate_limit") and auth.get("has_oauth"):
        owasp["A07: Auth Failures"]["status"] = "❌"
        owasp["A07: Auth Failures"]["notes"].append("No rate limiting on auth endpoints")
    if not auth.get("has_csrf"):
        owasp["A07: Auth Failures"]["status"] = "❌"
        owasp["A07: Auth Failures"]["notes"].append("No CSRF protection")

    # A08: Data Integrity
    if secrets.get("critical_count", 0) > 0:
        owasp["A08: Data Integrity"]["status"] = "❌"
        owasp["A08: Data Integrity"]["notes"].append(f"{secrets['critical_count']} hardcoded secret(s)")

    return owasp



def calculate_security_score(secrets: Dict, injection: Dict, auth: Dict,
                               crypto: Dict, config: Dict, sast: Dict) -> Dict[str, Any]:
    """Calculate security score (0-10 scale) across 10 categories."""
    # Authentication
    auth_score = 5
    if auth.get("has_oauth"):
        auth_score += 2
    if auth.get("has_rate_limit"):
        auth_score += 1
    if auth.get("has_csrf"):
        auth_score += 1
    auth_score = min(10, auth_score)

    # Authorization
    authz_score = 2 if not auth.get("has_rbac") else 7

    # Input Validation
    input_score = 8
    if injection.get("sql_count", 0) > 0:
        input_score -= 2
    if injection.get("cmd_count", 0) > 0:
        input_score -= 2
    input_score = max(1, input_score)

    # Injection Prevention
    inj_score = 8
    if injection.get("sql_count", 0) > 0:
        inj_score -= 2
    if injection.get("cmd_count", 0) > 0:
        inj_score -= 2
    inj_score = max(1, inj_score)

    # XSS Prevention
    xss_score = 7
    if injection.get("xss_count", 0) > 0:
        xss_score -= 3
    xss_score = max(1, xss_score)

    # Secret Management
    secret_score = 8
    if secrets.get("critical_count", 0) > 0:
        secret_score -= 4
    if secrets.get("high_count", 0) > 0:
        secret_score -= 2
    secret_score = max(1, secret_score)

    # Data Protection
    data_score = 6
    if crypto.get("tls_issues_count", 0) > 0:
        data_score -= 2
    if config.get("debug_enabled"):
        data_score -= 1
    data_score = max(1, data_score)

    # Dependency Security
    dep_score = 5  # neutral without specific dep scan data

    # Logging & Monitoring
    log_score = 4  # default low

    # CORS & CSP
    cors_score = 4
    if config.get("has_csp"):
        cors_score += 2
    if config.get("has_cors"):
        cors_score += 1
    if config.get("has_hsts"):
        cors_score += 1
    cors_score = min(10, cors_score)

    scores = {
        "Authentication": auth_score,
        "Authorization": authz_score,
        "Input Validation": input_score,
        "Injection Prevention": inj_score,
        "XSS Prevention": xss_score,
        "Secret Management": secret_score,
        "Data Protection": data_score,
        "Dependency Security": dep_score,
        "Logging & Monitoring": log_score,
        "CORS & CSP": cors_score,
    }
    overall = round(sum(scores.values()) / len(scores), 1)

    return {**scores, "overall": overall}



