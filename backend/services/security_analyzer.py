"""
IRVES — Security Analyzer
Automated security test suite for intercepted network flows.
Detects common vulnerabilities: IDOR, mass assignment, auth bypass, injection, info disclosure.
"""

import re
import json
import logging
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Automated security test suite for intercepted flows."""
    
    def __init__(self):
        self.tests = {
            "idor": self._test_idor,
            "mass_assignment": self._test_mass_assignment,
            "auth_bypass": self._test_auth_bypass,
            "information_disclosure": self._test_info_disclosure,
            "injection": self._test_injection,
            "missing_security_headers": self._test_security_headers,
            "sensitive_data_exposure": self._test_sensitive_data_exposure,
        }
    
    def analyze_flow(self, flow: dict) -> List[dict]:
        """Run all security tests on a flow and return findings."""
        findings = []
        
        for test_name, test_func in self.tests.items():
            try:
                result = test_func(flow)
                if result:
                    findings.append(result)
            except Exception as e:
                logger.warning(f"Security test {test_name} failed: {e}")
        
        return findings
    
    def analyze_all_flows(self, flows: Dict[str, dict]) -> Dict[str, List[dict]]:
        """Analyze all flows and return findings grouped by severity."""
        all_findings = []
        
        for flow_id, flow_data in flows.items():
            findings = self.analyze_flow(flow_data)
            for finding in findings:
                finding["flow_id"] = flow_id
                finding["url"] = flow_data.get("url", "")
                finding["host"] = flow_data.get("host", "")
                finding["method"] = flow_data.get("method", "")
                all_findings.append(finding)
        
        # Group by severity
        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for finding in all_findings:
            sev = finding.get("severity", "low").lower()
            if sev in by_severity:
                by_severity[sev].append(finding)
        
        return {
            "total_findings": len(all_findings),
            "by_severity": by_severity,
            "findings": all_findings,
            "risk_score": self._calculate_risk_score(all_findings),
        }
    
    def _calculate_risk_score(self, findings: List[dict]) -> int:
        """Calculate overall risk score based on findings."""
        weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1,
            "info": 0,
        }
        return sum(weights.get(f.get("severity", "").lower(), 0) for f in findings)
    
    def _test_idor(self, flow: dict) -> Optional[dict]:
        """Test for Insecure Direct Object Reference vulnerabilities."""
        url = flow.get("url", "")
        path = flow.get("path", "")
        method = flow.get("method", "GET")
        
        # Only test state-changing methods and GET requests
        if method not in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            return None
        
        findings = []
        
        # Pattern 1: Numeric IDs in path
        path_patterns = [
            (r"/api/(?:v\d+/)?(?:users?|accounts?|orders?|invoices?|items?|products?|documents?|files?)/?(\d+)(?:/|$)", "Resource ID in path"),
            (r"/(\d{6,})(?:/|$)", "Potential ID (6+ digits)"),
            (r"/([a-f0-9]{8,})(?:/|$)", "UUID-like ID in path"),
        ]
        
        for pattern, desc in path_patterns:
            matches = re.findall(pattern, path, re.IGNORECASE)
            for match in matches:
                # Generate adjacent IDs to test
                try:
                    if match.isdigit():
                        current_id = int(match)
                        suggestions = [current_id - 1, current_id + 1]
                    else:
                        # For UUIDs, suggest changing last char
                        suggestions = [f"Modify character in: {match}"]
                    
                    findings.append({
                        "type": "idor",
                        "description": f"{desc}: {match}",
                        "resource_id": match,
                        "suggested_tests": [
                            url.replace(str(match), str(sid))
                            for sid in (suggestions if isinstance(suggestions[0], int) else [])
                        ],
                    })
                except ValueError:
                    continue
        
        # Pattern 2: IDs in query parameters
        query_patterns = [
            (r"[?&](?:id|user_id|account_id|order_id|doc_id|file_id)=(\d+)", "ID parameter"),
            (r"[?&](?:user|owner|created_by)=(\d+)", "User reference parameter"),
        ]
        
        for pattern, desc in query_patterns:
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                try:
                    current_id = int(match)
                    findings.append({
                        "type": "idor",
                        "description": f"{desc}: {match}",
                        "resource_id": match,
                        "suggested_tests": [
                            url.replace(f"={match}", f"={current_id - 1}"),
                            url.replace(f"={match}", f"={current_id + 1}"),
                        ],
                    })
                except ValueError:
                    continue
        
        if findings:
            return {
                "test": "idor",
                "severity": "high",
                "title": "Insecure Direct Object Reference (IDOR)",
                "description": f"Found {len(findings)} potential IDOR vectors. The application may allow unauthorized access to resources by modifying IDs.",
                "evidence": findings,
                "remediation": "Implement proper authorization checks to ensure users can only access their own resources. Use indirect reference maps or verify ownership server-side.",
                "cwe": "CWE-639",
                "owasp": "A01:2021-Broken Access Control",
            }
        
        return None
    
    def _test_mass_assignment(self, flow: dict) -> Optional[dict]:
        """Test for mass assignment vulnerabilities."""
        method = flow.get("method", "")
        request = flow.get("request", {})
        body = request.get("body", "")
        
        if method not in ["POST", "PUT", "PATCH"]:
            return None
        
        if not body:
            return None
        
        try:
            json_body = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            # Try form-encoded
            if "=" in body:
                try:
                    from urllib.parse import parse_qs
                    json_body = parse_qs(body)
                    # Flatten single-value lists
                    json_body = {k: v[0] if len(v) == 1 else v for k, v in json_body.items()}
                except:
                    return None
            else:
                return None
        
        sensitive_fields = [
            "role", "admin", "is_admin", "is_staff", "is_superuser",
            "permissions", "privileges", "access_level", "user_type",
            "password", "password_hash", "encrypted_password",
            "verified", "is_verified", "email_verified",
            "banned", "is_banned", "suspended", "is_active",
            "credit_balance", "wallet_balance", "points",
            "subscription_tier", "plan", "billing_tier",
        ]
        
        found_fields = []
        body_str = str(json_body).lower()
        
        for field in sensitive_fields:
            if field.lower() in body_str:
                # Find the actual key
                for key in (json_body.keys() if isinstance(json_body, dict) else []):
                    if field.lower() in key.lower():
                        found_fields.append({
                            "field": key,
                            "value": str(json_body[key])[:100],
                        })
        
        if found_fields:
            return {
                "test": "mass_assignment",
                "severity": "high",
                "title": "Mass Assignment Vulnerability",
                "description": f"Request contains {len(found_fields)} sensitive field(s) that could allow privilege escalation.",
                "evidence": {
                    "sensitive_fields": found_fields,
                    "request_body_preview": str(body)[:500],
                },
                "remediation": "Use allowlists (permit lists) for acceptable fields. Never blindly assign user input to model attributes.",
                "suggested_tests": [
                    "Try adding 'role': 'admin' to request body",
                    "Try adding 'is_admin': true to request body",
                    "Try modifying 'subscription_tier' to 'premium'",
                ],
                "cwe": "CWE-915",
                "owasp": "A01:2021-Broken Access Control",
            }
        
        return None
    
    def _test_auth_bypass(self, flow: dict) -> Optional[dict]:
        """Test for authentication bypass patterns."""
        request = flow.get("request", {})
        response = flow.get("response", {})
        headers = request.get("headers", {})
        url = flow.get("url", "")
        method = flow.get("method", "")
        
        issues = []
        
        # Check 1: Sensitive endpoints without auth headers
        sensitive_patterns = [
            r"/admin", r"/api/admin", r"/dashboard", r"/settings",
            r"/api/users", r"/api/accounts", r"/api/internal",
            r"/config", r"/api/config", r"/debug", r"/api/debug",
        ]
        
        auth_headers = ["authorization", "x-api-key", "x-auth-token", "cookie"]
        has_auth = any(h.lower() in [k.lower() for k in headers.keys()] for h in auth_headers)
        
        for pattern in sensitive_patterns:
            if re.search(pattern, url, re.IGNORECASE) and not has_auth:
                issues.append({
                    "type": "missing_auth",
                    "endpoint": url,
                    "issue": f"Sensitive endpoint matches '{pattern}' without authentication header",
                })
        
        # Check 2: CORS misconfigurations
        response_headers = response.get("headers", {})
        cors_origin = response_headers.get("Access-Control-Allow-Origin", "")
        if cors_origin == "*" and method == "GET":
            issues.append({
                "type": "cors_wildcard",
                "issue": "Wildcard CORS origin allows any domain to access API",
                "header": "Access-Control-Allow-Origin: *",
            })
        
        # Check 3: Authentication endpoints without rate limiting indicators
        auth_endpoints = [r"/login", r"/signin", r"/auth", r"/token", r"/oauth"]
        for pattern in auth_endpoints:
            if re.search(pattern, url, re.IGNORECASE):
                # Check for rate limit headers
                rate_limit_headers = ["X-RateLimit-Limit", "Retry-After", "X-RateLimit-Remaining"]
                has_rate_limit = any(h in response_headers for h in rate_limit_headers)
                
                if not has_rate_limit and response.get("status_code") == 200:
                    issues.append({
                        "type": "missing_rate_limit",
                        "issue": "Authentication endpoint lacks rate limiting headers",
                        "recommendation": "Implement rate limiting to prevent brute force attacks",
                    })
        
        if issues:
            return {
                "test": "auth_bypass",
                "severity": "critical" if any(i["type"] == "missing_auth" for i in issues) else "medium",
                "title": "Authentication/Authorization Issues",
                "description": f"Found {len(issues)} potential authentication or authorization weakness(es).",
                "evidence": issues,
                "remediation": "Enforce authentication on all sensitive endpoints. Implement proper CORS policies. Add rate limiting to auth endpoints.",
                "cwe": "CWE-306",
                "owasp": "A01:2021-Broken Access Control",
            }
        
        return None
    
    def _test_info_disclosure(self, flow: dict) -> Optional[dict]:
        """Test for information disclosure in responses."""
        response = flow.get("response", {})
        body = response.get("body", "")
        headers = response.get("headers", {})
        
        findings = []
        
        # Pattern-based detection
        patterns = {
            "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "critical"),
            "AWS Secret Key": (r"['\"](?:aws)?_?(?:secret)?_?(?:access)?_?key['\"]\s*[:=]\s*['\"]([a-zA-Z0-9/+=]{40})['\"]", "critical"),
            "Private Key": (r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", "critical"),
            "GitHub Token": (r"gh[pousr]_[A-Za-z0-9_]{36}", "high"),
            "Slack Token": (r"xox[baprs]-[0-9A-Za-z\-]+", "high"),
            "Internal IP": (r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", "medium"),
            "Stack Trace": (r"(Traceback|Exception|Error).*\n\s+at\s+|File \".*?\", line \d+,", "medium"),
            "SQL Error": (r"(SQL|PostgreSQL|MySQL|SQLite|Oracle|JDBC).*?(Error|Exception|syntax)", "medium"),
            "Debug Mode": (r"(DEBUG|debug)\s*=\s*True|debug_enabled|show_debug", "medium"),
        }
        
        body_str = str(body)
        
        for name, (pattern, severity) in patterns.items():
            matches = re.findall(pattern, body_str, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": name,
                    "severity": severity,
                    "matches": len(matches),
                    "sample": str(matches[0])[:100] if matches else None,
                })
        
        # Check for sensitive headers
        sensitive_headers = {
            "x-powered-by": "Server technology disclosure",
            "server": "Server version disclosure",
            "x-aspnet-version": "ASP.NET version disclosure",
            "x-generator": "Framework generator disclosure",
            "x-runtime": "Runtime version disclosure",
        }
        
        header_findings = []
        for header, desc in sensitive_headers.items():
            if any(h.lower() == header for h in headers.keys()):
                header_value = next((v for k, v in headers.items() if k.lower() == header), "")
                header_findings.append({
                    "header": header,
                    "description": desc,
                    "value": header_value[:50],
                })
        
        if header_findings:
            findings.append({
                "type": "Information Disclosure Headers",
                "severity": "low",
                "headers": header_findings,
            })
        
        if findings:
            return {
                "test": "information_disclosure",
                "severity": max((f.get("severity", "low") for f in findings), key=lambda x: ["info", "low", "medium", "high", "critical"].index(x)),
                "title": "Information Disclosure",
                "description": f"Found {len(findings)} potential information disclosure(s) in response.",
                "evidence": findings,
                "remediation": "Remove debug information, stack traces, and sensitive data from production responses. Use generic error messages.",
                "cwe": "CWE-200",
                "owasp": "A01:2021-Broken Access Control",
            }
        
        return None
    
    def _test_injection(self, flow: dict) -> Optional[dict]:
        """Test for injection vulnerabilities."""
        request = flow.get("request", {})
        url = request.get("url", "")
        body = request.get("body", "")
        headers = request.get("headers", {})
        method = flow.get("method", "")
        
        # Only test requests with parameters
        if method not in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            return None
        
        injection_points = []
        
        # Check URL parameters
        if re.search(r"[?&]\w+=[^&]+", url):
            injection_points.append({
                "location": "URL query parameters",
                "vulnerable_params": self._extract_params(url),
            })
        
        # Check body for common injection patterns
        if body:
            # SQL injection patterns
            sql_patterns = [
                r"(\w+)\s*=\s*['\"].*?['\"]\s*--",
                r"(\w+)\s*=\s*\d+\s*(?:AND|OR)\s*\d+\s*=\s*\d+",
                r"(\w+)\s*=\s*['\"].*?(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP)",
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, str(body), re.IGNORECASE):
                    injection_points.append({
                        "location": "Request body",
                        "type": "Potential SQL injection pattern",
                    })
                    break
            
            # Command injection patterns
            cmd_patterns = [
                r";\s*\w+",
                r"\|\s*\w+",
                r"`\s*\w+",
                r"\$\(\s*\w+",
            ]
            
            for pattern in cmd_patterns:
                if re.search(pattern, str(body)):
                    injection_points.append({
                        "location": "Request body",
                        "type": "Potential command injection pattern",
                    })
                    break
        
        if injection_points:
            return {
                "test": "injection",
                "severity": "high",
                "title": "Injection Vulnerability",
                "description": f"Found {len(injection_points)} potential injection point(s).",
                "evidence": injection_points,
                "remediation": "Use parameterized queries/prepared statements. Sanitize all user input. Implement input validation.",
                "suggested_tests": [
                    "SQL: ' OR '1'='1' --",
                    "SQL: 1 AND 1=1",
                    "SQL: 1 AND 1=2",
                    "Command: ; cat /etc/passwd",
                    "Command: | whoami",
                    "XSS: <script>alert(1)</script>",
                    "XSS: <img src=x onerror=alert(1)>",
                ],
                "cwe": "CWE-89",
                "owasp": "A03:2021-Injection",
            }
        
        return None
    
    def _test_security_headers(self, flow: dict) -> Optional[dict]:
        """Test for missing security headers."""
        response = flow.get("response", {})
        headers = response.get("headers", {})
        
        if not headers:
            return None
        
        required_headers = {
            "Strict-Transport-Security": "HSTS - prevents downgrade attacks",
            "Content-Security-Policy": "CSP - prevents XSS",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "X-Frame-Options": "Clickjacking protection",
            "Referrer-Policy": "Controls referrer information",
        }
        
        missing = []
        for header, description in required_headers.items():
            if not any(k.lower() == header.lower() for k in headers.keys()):
                missing.append({"header": header, "description": description})
        
        if missing:
            return {
                "test": "missing_security_headers",
                "severity": "low",
                "title": "Missing Security Headers",
                "description": f"Response is missing {len(missing)} security header(s).",
                "evidence": missing,
                "remediation": "Add the missing security headers to all HTTP responses.",
                "cwe": "CWE-693",
                "owasp": "A05:2021-Security Misconfiguration",
            }
        
        return None
    
    def _test_sensitive_data_exposure(self, flow: dict) -> Optional[dict]:
        """Test for sensitive data exposure in transit."""
        url = flow.get("url", "")
        request = flow.get("request", {})
        body = request.get("body", "")
        
        # Check if HTTPS is used
        is_https = url.startswith("https://")
        
        # Check for sensitive data patterns
        sensitive_patterns = {
            "password": r"password\s*[:=]\s*['\"]([^'\"]+)['\"]",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        }
        
        exposed_data = []
        body_str = str(body)
        
        for data_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, body_str, re.IGNORECASE)
            if matches:
                exposed_data.append({
                    "type": data_type,
                    "count": len(matches),
                    "insecure_transport": not is_https,
                })
        
        if exposed_data and not is_https:
            return {
                "test": "sensitive_data_exposure",
                "severity": "high",
                "title": "Sensitive Data Exposure (Insecure Transport)",
                "description": f"Found {len(exposed_data)} type(s) of sensitive data transmitted over HTTP (not HTTPS).",
                "evidence": exposed_data,
                "remediation": "Use HTTPS for all communications. Encrypt sensitive data. Consider using certificate pinning for mobile apps.",
                "cwe": "CWE-319",
                "owasp": "A02:2021-Cryptographic Failures",
            }
        
        return None
    
    def _extract_params(self, url: str) -> List[str]:
        """Extract parameter names from URL query string."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []


# Global analyzer instance
security_analyzer = SecurityAnalyzer()
