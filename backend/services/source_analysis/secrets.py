"""
IRVES — Secrets Analyzer
Analyzes secret storage, rotation, validation, git secrets, and log sanitization.
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Any

from services.source_analysis.reports import build_secrets_report
from services.source_analysis.report_utils import resolve_project_name
from services.source_analysis.security import detect_hardcoded_secrets

from database.models import FindingSeverity
from services.git_service import git_service

logger = logging.getLogger(__name__)



def get_db():
    """Get database session."""
    from database.session import get_session
    return get_session()


async def analyze_secrets(repo_path: Path,
    analysis_result_id: str,
) -> Dict[str, Any]:
    """Analyze secrets: comprehensive secret management report."""
    logger.info("[SourceAnalysis] Analyzing secrets — generating comprehensive report")

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

        from services.git_service import GitService
        git_service = GitService()
        files = await git_service.get_file_list(repo_path)

        # ── 1. Hardcoded Secret Detection ──
        secrets = detect_hardcoded_secrets(repo_path, files)

        # ── 2. Secret Storage Analysis ──
        secret_storage = analyze_secret_storage(repo_path, files)

        # ── 3. Secret Rotation Analysis ──
        secret_rotation = analyze_secret_rotation(repo_path, files)

        # ── 4. Secret Validation Analysis ──
        secret_validation = analyze_secret_validation(repo_path, files)

        # ── 5. Git Secret Analysis ──
        git_secrets = analyze_git_secrets(repo_path, files)

        # ── 6. Log Sanitization Analysis ──
        log_sanitization = analyze_log_sanitization(repo_path, files)

        # ── 7. Secret Score ──
        secret_score = calculate_secret_score(secrets, secret_storage, secret_rotation,
                                                     secret_validation, git_secrets, log_sanitization)

        # ── 8. Build the markdown report ──
        report = build_secrets_report(
            repo_path, secrets, secret_storage, secret_rotation,
            secret_validation, git_secrets, log_sanitization,
            secret_score, project_name=project_name
        )

        findings = [{
            "type": "secrets_report",
            "severity": FindingSeverity.INFO,
            "message": report,
            "tool": "secret_analyzer",
            "extra_data": {
                "secret_score": secret_score.get("overall", 0),
                "critical_count": secrets.get("critical_count", 0),
                "high_count": secrets.get("high_count", 0),
            },
        }]

        summary = {
            "total_findings": 1,
            "secret_score": secret_score.get("overall", 0),
            "hardcoded_secrets": secrets.get("total_count", 0),
            "critical_secrets": secrets.get("critical_count", 0),
        }

    except Exception as e:
        logger.error(f"[SourceAnalysis] Secrets analysis failed: {e}")
        findings = [{
            "type": "secrets_report",
            "severity": FindingSeverity.INFO,
            "message": f"# Secrets Report\n\nAnalysis failed: {e}",
            "tool": "secret_analyzer",
        }]
        summary = {"total_findings": 1}

    summary["total_findings"] = len(findings)
    return {
        "summary_metrics": summary,
        "detailed_findings": {},
        "findings": findings,
    }


def analyze_secret_storage(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze how secrets are stored: plaintext detection, encryption, file permissions."""
    findings: List[Dict] = []
    has_encrypted_storage = False
    has_plaintext_storage = False
    has_keyring = False
    has_dotenv = False

    storage_patterns = [
        # Plaintext JSON/YAML settings with secret keys
        (re.compile(r'(?:api_key|access_token|secret_key|password|private_key|auth_token)\s*[:=]', re.IGNORECASE),
         "Plaintext secret in config/settings file"),
        # Python: json.dumps / json.loads for settings
        (re.compile(r'(?:read_text|write_text|json\.loads|json\.dumps).*settings', re.IGNORECASE),
         "Plaintext file I/O for settings (no encryption)"),
        # Encryption libraries (positive finding)
        (re.compile(r'(?:Fernet|cryptography|cipher|encrypt|decrypt|AES|RSA)', re.IGNORECASE),
         "Encryption library detected (positive)"),
        # OS keyring (positive finding)
        (re.compile(r'(?:keyring|Keychain|CredentialManager)', re.IGNORECASE),
         "OS keyring integration detected (positive)"),
        # dotenv usage (positive finding)
        (re.compile(r'(?:load_dotenv|dotenv|python-dotenv)', re.IGNORECASE),
         "Environment variable loading detected (positive)"),
    ]

    config_like_files = []
    for f in files:
        fname = Path(f).name.lower()
        ext = Path(f).suffix.lower()
        if fname in {".env", ".env.example", ".env.local", ".env.production", "settings.json",
                     "settings.yaml", "settings.yml", "config.json", "config.yaml", "config.yml",
                     "application.properties", "application.yml", "appsettings.json"}:
            config_like_files.append(f)
        elif ext in {".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties"}:
            if "config" in fname or "setting" in fname or "secret" in fname:
                config_like_files.append(f)

    for f in files[:400]:
        ext = Path(f).suffix.lower()
        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        for pattern, desc in storage_patterns:
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                if "Encryption library" in desc:
                    has_encrypted_storage = True
                elif "OS keyring" in desc:
                    has_keyring = True
                elif "Environment variable" in desc:
                    has_dotenv = True
                elif "Plaintext" in desc:
                    has_plaintext_storage = True
                    findings.append({"file": f, "line": line_num, "description": desc})

    # Check file permissions on config files
    loose_perms = []
    for f in config_like_files[:20]:
        full_path = repo_path / f
        if full_path.exists():
            try:
                mode = full_path.stat().st_mode & 0o777
                if mode & 0o044:  # readable by group/others
                    loose_perms.append({"file": f, "permissions": oct(mode)})
            except Exception:
                pass

    return {
        "findings": findings[:15],
        "has_encrypted_storage": has_encrypted_storage,
        "has_plaintext_storage": has_plaintext_storage,
        "has_keyring": has_keyring,
        "has_dotenv": has_dotenv,
        "loose_permissions": loose_perms[:5],
    }



def analyze_secret_rotation(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Detect secret rotation, expiration, and refresh token mechanisms."""
    has_rotation = False
    has_expiration = False
    has_refresh_token = False
    findings: List[Dict] = []

    rotation_patterns = [
        (re.compile(r'(?:rotate|rotation|refresh_token|expires_at|expiration|exp_\w+|token_expiry)', re.IGNORECASE),
         "Rotation/expiration mechanism detected"),
        (re.compile(r'(?:timedelta|expires_delta|EXPIRES|MAX_AGE|session_expiry)', re.IGNORECASE),
         "Expiration/timing mechanism detected"),
    ]

    for f in files[:400]:
        full_path = repo_path / f
        if not full_path.exists():
            continue
        try:
            text = full_path.read_text(errors="ignore")
        except Exception:
            continue

        for pattern, desc in rotation_patterns:
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                if "Rotation" in desc or "refresh" in desc.lower():
                    has_rotation = True
                if "expiration" in desc.lower() or "expir" in desc.lower():
                    has_expiration = True
                if "refresh_token" in match.group(0).lower():
                    has_refresh_token = True
                findings.append({"file": f, "line": line_num, "description": desc})

    return {
        "findings": findings[:10],
        "has_rotation": has_rotation,
        "has_expiration": has_expiration,
        "has_refresh_token": has_refresh_token,
    }



def analyze_secret_validation(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Detect API key validation, format checks, and empty default detection."""
    findings: List[Dict] = []
    has_validation = False
    empty_defaults = 0

    validation_patterns = [
        # Pydantic validators
        (re.compile(r'(?:@field_validator|@validator|field_validator)\s*\(', re.IGNORECASE),
         "Pydantic field validator detected (positive)"),
        # Format validation
        (re.compile(r'(?:startswith\(["\']sk|validate.*key|check.*format|verify.*token)', re.IGNORECASE),
         "API key format validation detected (positive)"),
        # Empty defaults for secrets
        (re.compile(r'(?:API_KEY|SECRET|TOKEN|PASSWORD)\s*(?::\s*\w+\s*=\s*["\']{2}|:\s*str\s*=\s*["\']{2})', re.IGNORECASE),
         "Empty default for secret field"),
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

        for pattern, desc in validation_patterns:
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                if "positive" in desc:
                    has_validation = True
                elif "Empty default" in desc:
                    empty_defaults += 1
                    findings.append({"file": f, "line": line_num, "description": desc})

    return {
        "findings": findings[:10],
        "has_validation": has_validation,
        "empty_defaults": empty_defaults,
    }



def analyze_git_secrets(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Analyze git security: .gitignore for secrets, pre-commit hooks, git history scanning."""
    has_gitignore = False
    ignores_secrets = False
    has_precommit = False
    git_secrets_tool = False
    findings: List[Dict] = []

    # Check .gitignore
    gitignore_path = repo_path / ".gitignore"
    if gitignore_path.exists():
        has_gitignore = True
        try:
            gitignore_text = gitignore_path.read_text(errors="ignore")
            secret_patterns_in_gitignore = [".env", "secret", "credential", "token", "key", "*.pem", "*.key"]
            for p in secret_patterns_in_gitignore:
                if p in gitignore_text.lower():
                    ignores_secrets = True
                    break
            if not ignores_secrets:
                findings.append({"file": ".gitignore", "description": ".gitignore does not exclude secret files (.env, *.key, *.pem)"})
        except Exception:
            pass

    # Check pre-commit config
    precommit_path = repo_path / ".pre-commit-config.yaml"
    if precommit_path.exists():
        has_precommit = True
        try:
            precommit_text = precommit_path.read_text(errors="ignore")
            if "git-secrets" in precommit_text or "detect-secrets" in precommit_text or "trufflehog" in precommit_text:
                git_secrets_tool = True
            else:
                findings.append({"file": ".pre-commit-config.yaml", "description": "Pre-commit config exists but no secret scanning hook"})
        except Exception:
            pass

    # Try running detect-secrets / truffleHog
    tool_findings = []
    try:
        import subprocess, sys
        venv_bin = Path(sys.executable).parent
        ds_cmd = str(venv_bin / "detect-secrets") if (venv_bin / "detect-secrets").exists() else "detect-secrets"
        result = subprocess.run(
            [ds_cmd, "scan", str(repo_path)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)
                for fname, secrets in data.get("results", {}).items():
                    for s in secrets[:3]:
                        tool_findings.append({
                            "file": relative_path(fname, repo_path) or fname,
                            "type": s.get("type", "unknown"),
                            "line": s.get("line_number", 0),
                        })
                if tool_findings:
                    git_secrets_tool = True
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return {
        "findings": findings + tool_findings[:10],
        "has_gitignore": has_gitignore,
        "ignores_secrets": ignores_secrets,
        "has_precommit": has_precommit,
        "git_secrets_tool": git_secrets_tool,
        "tool_findings_count": len(tool_findings),
    }



def analyze_log_sanitization(repo_path: Path, files: List[str]) -> Dict[str, Any]:
    """Detect potential secret exposure in logging statements."""
    findings: List[Dict] = []
    has_sanitization = False

    # Patterns that suggest logging of potentially sensitive data
    log_patterns = [
        (re.compile(r'logger\.\w+\(.*(?:token|key|secret|password|credential|auth)', re.IGNORECASE),
         "Potential secret in log statement"),
        (re.compile(r'print\s*\(\s*(?:f?["\'].*(?:token|key|secret|password))', re.IGNORECASE),
         "Potential secret in print statement"),
        (re.compile(r'console\.log\s*\(\s*(?:.*(?:token|key|secret|password))', re.IGNORECASE),
         "Potential secret in console.log"),
    ]

    # Sanitization patterns (positive)
    sanitize_patterns = [
        re.compile(r'(?:sanitize|redact|mask|REDACTED|\[REDACTED\])', re.IGNORECASE),
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

        # Check for sanitization
        for pattern in sanitize_patterns:
            if pattern.search(text):
                has_sanitization = True

        # Check for potential exposure
        for pattern, desc in log_patterns:
            for match in pattern.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                findings.append({"file": f, "line": line_num, "description": desc})

    return {
        "findings": findings[:10],
        "has_sanitization": has_sanitization,
        "potential_exposure_count": len(findings),
    }



def validate_secret_structure(secret_value: str, secret_type: str) -> Dict[str, Any]:
    """Perform structural validation of a detected secret credential.
    
    Validates whether the detected credential pattern is structurally valid
    (correct length, character set, format) before flagging as Critical.
    
    Args:
        secret_value: The detected secret value (masked or partial)
        secret_type: The type of secret (e.g., "AWS Access Key ID detected", "JWT token", etc.)
    
    Returns:
        Dict with 'valid' (bool), 'confidence' (float), and 'reason' (str)
    """
    if not secret_value or secret_value in ["***", "****"]:
        return {"valid": False, "confidence": 0.0, "reason": "Value is masked/unavailable"}
    
    value_lower = secret_value.lower()
    value_len = len(secret_value)
    
    # AWS Access Key ID: AKIA[A-Z0-9]{16}
    if "aws access key" in secret_type.lower():
        if secret_value.startswith("AKIA") and value_len == 20:
            if secret_value[4:].isalnum() and secret_value[4:].isupper():
                return {"valid": True, "confidence": 0.95, "reason": "Valid AWS Access Key ID format"}
        return {"valid": False, "confidence": 0.8, "reason": "Invalid AWS Access Key ID format"}
    
    # AWS Secret Access Key: 40 characters, base64-like
    if "aws secret" in secret_type.lower():
        if value_len == 40:
            # Should be base64-like characters
            if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in secret_value):
                return {"valid": True, "confidence": 0.9, "reason": "Valid AWS Secret Access Key format"}
        return {"valid": False, "confidence": 0.7, "reason": "Invalid AWS Secret Access Key format"}
    
    # GitHub token: ghp_[A-Za-z0-9_]{36} or ghs_[A-Za-z0-9_]{36} (fine-grained)
    if "github token" in secret_type.lower():
        if (secret_value.startswith("ghp_") or secret_value.startswith("ghs_") or 
            secret_value.startswith("gho_") or secret_value.startswith("ghu_")):
            if value_len == 40 and all(c.isalnum() or c == "_" for c in secret_value):
                return {"valid": True, "confidence": 0.95, "reason": "Valid GitHub token format"}
        return {"valid": False, "confidence": 0.6, "reason": "Invalid GitHub token format"}
    
    # JWT token: header.payload.signature (3 parts separated by dots)
    if "jwt" in secret_type.lower():
        parts = secret_value.split(".")
        if len(parts) == 3:
            # Check if parts are base64-like
            try:
                import base64
                # Try to decode header to verify it's valid base64
                base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4))
                return {"valid": True, "confidence": 0.85, "reason": "Valid JWT structure (3 parts, base64-encoded)"}
            except Exception:
                pass
        return {"valid": False, "confidence": 0.5, "reason": "Invalid JWT structure"}
    
    # Stripe API key: sk_test_ or sk_live_ followed by 24 chars
    if "stripe" in secret_type.lower():
        if (secret_value.startswith("sk_test_") or secret_value.startswith("sk_live_") or
            secret_value.startswith("rk_test_") or secret_value.startswith("rk_live_")):
            if value_len >= 29 and secret_value[8:].isalnum():
                return {"valid": True, "confidence": 0.95, "reason": "Valid Stripe API key format"}
        return {"valid": False, "confidence": 0.7, "reason": "Invalid Stripe API key format"}
    
    # Google API key: AIza[A-Za-z0-9_-]{35}
    if "google api" in secret_type.lower() or "firebase" in secret_type.lower():
        if secret_value.startswith("AIza") and value_len == 39:
            if all(c.isalnum() or c in "_-" for c in secret_value[4:]):
                return {"valid": True, "confidence": 0.9, "reason": "Valid Google API key format"}
        return {"valid": False, "confidence": 0.6, "reason": "Invalid Google API key format"}
    
    # Slack token: xox[baprs]-[A-Za-z0-9\-]{10,}
    if "slack" in secret_type.lower():
        if secret_value.startswith(("xoxb-", "xoxp-", "xoxa-", "xoxr-")):
            if value_len >= 15:
                return {"valid": True, "confidence": 0.9, "reason": "Valid Slack token format"}
        return {"valid": False, "confidence": 0.6, "reason": "Invalid Slack token format"}
    
    # SendGrid API key: SG.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}
    if "sendgrid" in secret_type.lower():
        if secret_value.startswith("SG.") and "." in secret_value[3:]:
            parts = secret_value[3:].split(".")
            if len(parts) == 2 and len(parts[0]) >= 22 and len(parts[1]) >= 43:
                return {"valid": True, "confidence": 0.9, "reason": "Valid SendGrid API key format"}
        return {"valid": False, "confidence": 0.6, "reason": "Invalid SendGrid API key format"}
    
    # Twilio API key: SK[A-Za-z0-9]{32}
    if "twilio" in secret_type.lower():
        if secret_value.startswith("SK") and value_len == 34:
            if secret_value[2:].isalnum():
                return {"valid": True, "confidence": 0.9, "reason": "Valid Twilio API key format"}
        return {"valid": False, "confidence": 0.6, "reason": "Invalid Twilio API key format"}
    
    # GitLab token: glpat-[A-Za-z0-9\-]{20,}
    if "gitlab" in secret_type.lower():
        if secret_value.startswith("glpat-") and value_len >= 26:
            return {"valid": True, "confidence": 0.9, "reason": "Valid GitLab token format"}
        return {"valid": False, "confidence": 0.6, "reason": "Invalid GitLab token format"}
    
    # Shopify token: shpat_[A-Za-z0-9\-]{32,}
    if "shopify" in secret_type.lower():
        if secret_value.startswith("shpat_") and value_len >= 38:
            return {"valid": True, "confidence": 0.9, "reason": "Valid Shopify token format"}
        return {"valid": False, "confidence": 0.6, "reason": "Invalid Shopify token format"}
    
    # Database URL: postgres://, mysql://, mongodb://, redis://
    if "database" in secret_type.lower() or "postgres" in secret_type.lower() or "mysql" in secret_type.lower():
        if "://" in secret_value and "@" in secret_value:
            # Parse to check structure
            try:
                from urllib.parse import urlparse
                parsed = urlparse(secret_value)
                if parsed.scheme in ["postgres", "postgresql", "mysql", "mongodb", "redis"]:
                    if parsed.username and parsed.password and parsed.hostname:
                        return {"valid": True, "confidence": 0.85, "reason": "Valid database URL structure"}
            except Exception:
                pass
        return {"valid": False, "confidence": 0.5, "reason": "Invalid database URL structure"}
    
    # Generic API key: Check for reasonable length and character set
    if "api key" in secret_type.lower() or "api_key" in secret_type.lower():
        if value_len >= 16 and value_len <= 128:
            # Should have mix of characters, not just numbers or just letters
            has_alpha = any(c.isalpha() for c in secret_value)
            has_digit = any(c.isdigit() for c in secret_value)
            if has_alpha and has_digit:
                return {"valid": True, "confidence": 0.6, "reason": "Plausible API key format (length and character mix)"}
        return {"valid": False, "confidence": 0.3, "reason": "Unlikely API key format"}
    
    # Generic secret: Check for reasonable length
    if "secret" in secret_type.lower():
        if value_len >= 16 and value_len <= 256:
            return {"valid": True, "confidence": 0.4, "reason": "Plausible secret length"}
        return {"valid": False, "confidence": 0.2, "reason": "Unlikely secret length"}
    
    # Default: Unknown type, low confidence
    return {"valid": False, "confidence": 0.1, "reason": "Unknown secret type, cannot validate"}


def calculate_secret_score(secrets: Dict, storage: Dict, rotation: Dict,
                             validation: Dict, git: Dict, log: Dict) -> Dict[str, Any]:
    """Calculate secret management score (0-10 scale) across 6 categories."""

    # Secret Storage
    storage_score = 3
    if storage.get("has_encrypted_storage"):
        storage_score += 4
    if storage.get("has_keyring"):
        storage_score += 2
    if storage.get("has_dotenv"):
        storage_score += 1
    if storage.get("has_plaintext_storage"):
        storage_score -= 2
    storage_score = max(0, min(10, storage_score))

    # Secret Encryption
    encryption_score = 1
    if storage.get("has_encrypted_storage"):
        encryption_score += 5
    if storage.get("has_keyring"):
        encryption_score += 3
    if not storage.get("has_plaintext_storage"):
        encryption_score += 1
    encryption_score = max(0, min(10, encryption_score))

    # Secret Rotation
    rotation_score = 0
    if rotation.get("has_rotation"):
        rotation_score += 4
    if rotation.get("has_expiration"):
        rotation_score += 3
    if rotation.get("has_refresh_token"):
        rotation_score += 3
    rotation_score = max(0, min(10, rotation_score))

    # Secret Validation
    val_score = 3
    if validation.get("has_validation"):
        val_score += 4
    if validation.get("empty_defaults", 0) > 0:
        val_score -= 2
    val_score = max(0, min(10, val_score))

    # Git Security
    git_score = 3
    if git.get("has_gitignore"):
        git_score += 1
    if git.get("ignores_secrets"):
        git_score += 2
    if git.get("has_precommit"):
        git_score += 2
    if git.get("git_secrets_tool"):
        git_score += 2
    git_score = max(0, min(10, git_score))

    # Secret Audit Trail
    audit_score = 2
    if log.get("has_sanitization"):
        audit_score += 3
    if log.get("potential_exposure_count", 0) == 0:
        audit_score += 2
    if rotation.get("has_rotation"):
        audit_score += 2
    audit_score = max(0, min(10, audit_score))

    scores = {
        "Secret Storage": storage_score,
        "Secret Encryption": encryption_score,
        "Secret Rotation": rotation_score,
        "Secret Validation": val_score,
        "Git Security": git_score,
        "Secret Audit Trail": audit_score,
    }
    overall = round(sum(scores.values()) / len(scores), 1)

    return {**scores, "overall": overall}



