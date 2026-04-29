"""
IRVES — Network Routes: Security
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import StreamingResponse
import asyncio
import json
import logging
import time
import uuid
from services.network_service import network_service
from services.root_wrapper import root_wrapper
from services.ebpf_service import ebpf_service
from services.frida_service import frida_service
from services.ai_service import ai_service
from services.security_analyzer import security_analyzer
from services.ct_monitor import ct_monitor
from services.fritap_capture import fritap_service

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/security/test/{flow_id}")
async def run_security_test(flow_id: str):
    """Run automated security tests on a specific flow."""
    flow = network_service.flows.get(flow_id)
    if not flow:
        return {"status": "error", "message": "Flow not found"}
    
    try:
        findings = security_analyzer.analyze_flow(flow)
        
        return {
            "status": "success",
            "flow_id": flow_id,
            "findings": findings,
            "findings_count": len(findings),
            "risk_score": security_analyzer._calculate_risk_score(findings),
        }
    except Exception as e:
        logger.error(f"[Network] Security test error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/security/scan-all")
async def scan_all_flows():
    """Run security tests on all captured flows."""
    try:
        result = security_analyzer.analyze_all_flows(network_service.flows)
        
        return {
            "status": "success",
            "total_flows": len(network_service.flows),
            "total_findings": result["total_findings"],
            "risk_score": result["risk_score"],
            "by_severity": result["by_severity"],
            "findings": result["findings"],
            "summary": {
                "critical": len(result["by_severity"]["critical"]),
                "high": len(result["by_severity"]["high"]),
                "medium": len(result["by_severity"]["medium"]),
                "low": len(result["by_severity"]["low"]),
                "info": len(result["by_severity"]["info"]),
            },
        }
    except Exception as e:
        logger.error(f"[Network] Security scan error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/security/summary")
async def get_security_summary():
    """Get a quick security summary without full details."""
    try:
        result = security_analyzer.analyze_all_flows(network_service.flows)
        
        # Calculate per-test-type statistics
        test_types = {}
        for finding in result["findings"]:
            test = finding.get("test", "unknown")
            if test not in test_types:
                test_types[test] = {"count": 0, "max_severity": "info"}
            test_types[test]["count"] += 1
            sev = finding.get("severity", "info")
            if ["info", "low", "medium", "high", "critical"].index(sev) > \
               ["info", "low", "medium", "high", "critical"].index(test_types[test]["max_severity"]):
                test_types[test]["max_severity"] = sev
        
        return {
            "status": "success",
            "total_flows": len(network_service.flows),
            "total_findings": result["total_findings"],
            "risk_score": result["risk_score"],
            "severity_summary": {
                "critical": len(result["by_severity"]["critical"]),
                "high": len(result["by_severity"]["high"]),
                "medium": len(result["by_severity"]["medium"]),
                "low": len(result["by_severity"]["low"]),
                "info": len(result["by_severity"]["info"]),
            },
            "test_type_summary": test_types,
            "recommendations": _generate_security_recommendations(result),
        }
    except Exception as e:
        logger.error(f"[Network] Security summary error: {e}")
        return {"status": "error", "message": str(e)}


def _generate_security_recommendations(result: dict) -> list:
    """Generate security recommendations based on findings."""
    recommendations = []
    
    critical_high = len(result["by_severity"]["critical"]) + len(result["by_severity"]["high"])
    
    if critical_high > 0:
        recommendations.append({
            "priority": "immediate",
            "action": f"Address {critical_high} critical/high severity issues before production deployment",
        })
    
    # Check for specific test types
    tests_found = set()
    for finding in result["findings"]:
        tests_found.add(finding.get("test"))
    
    if "idor" in tests_found:
        recommendations.append({
            "priority": "high",
            "action": "Implement proper authorization checks for all resource endpoints",
        })
    
    if "mass_assignment" in tests_found:
        recommendations.append({
            "priority": "high",
            "action": "Use allowlists for request parameters to prevent mass assignment",
        })
    
    if "injection" in tests_found:
        recommendations.append({
            "priority": "high",
            "action": "Implement parameterized queries and input validation",
        })
    
    if "information_disclosure" in tests_found:
        recommendations.append({
            "priority": "medium",
            "action": "Remove debug information and stack traces from production responses",
        })
    
    if "missing_security_headers" in tests_found:
        recommendations.append({
            "priority": "low",
            "action": "Add recommended security headers (CSP, HSTS, X-Frame-Options)",
        })
    
    return recommendations


# ── Certificate Transparency Monitoring ──────────────────────────────────

@router.get("/ct/analyze/{domain}")
async def analyze_ct_domain(domain: str):
    """Analyze a domain for Certificate Transparency information."""
    try:
        info = await ct_monitor.analyze_domain(domain)
        
        return {
            "status": "success",
            "domain": info.domain,
            "has_ct_logs": info.has_ct_logs,
            "subdomains_found": list(info.subdomains),
            "certificate_issuers": info.certificate_issuers,
            "san_entries": info.san_entries,
            "subdomain_takeover_risks": info.subdomain_takeover_risks,
            "takeover_risk_count": len(info.subdomain_takeover_risks),
            "high_risk_takeovers": [r for r in info.subdomain_takeover_risks if r["risk_level"] == "high"],
        }
    except Exception as e:
        logger.error(f"[Network] CT analysis error for {domain}: {e}")
        return {"status": "error", "message": str(e)}


@router.post("/ct/analyze-all")
async def analyze_all_ct_domains():
    """Analyze all unique domains from captured flows."""
    try:
        # Extract unique domains from flows
        domains = set()
        for flow in network_service.flows.values():
            host = flow.get("host", "")
            if host and "." in host and not host.endswith(('.local', '.internal')):
                domains.add(host)
                # Also add parent domains
                parts = host.split(".")
                if len(parts) > 2:
                    domains.add(".".join(parts[-2:]))
        
        if not domains:
            return {
                "status": "success",
                "message": "No domains found in captured flows",
                "domains_analyzed": 0,
                "results": [],
            }
        
        # Analyze all domains
        results = await ct_monitor.analyze_domains(domains)
        
        # Format results
        formatted_results = []
        takeover_targets = []
        
        for domain, info in results.items():
            if info.has_ct_logs or info.subdomain_takeover_risks:
                formatted_results.append({
                    "domain": info.domain,
                    "has_ct_logs": info.has_ct_logs,
                    "subdomains_found": len(info.subdomains),
                    "takeover_risks": len(info.subdomain_takeover_risks),
                    "high_risk_takeovers": [r for r in info.subdomain_takeover_risks if r["risk_level"] == "high"],
                })
                
                for risk in info.subdomain_takeover_risks:
                    if risk["risk_level"] == "high":
                        takeover_targets.append({
                            "domain": domain,
                            **risk,
                        })
        
        return {
            "status": "success",
            "domains_analyzed": len(domains),
            "results": formatted_results,
            "takeover_targets": takeover_targets,
            "takeover_count": len(takeover_targets),
            "summary": {
                "domains_with_ct_logs": sum(1 for r in formatted_results if r["has_ct_logs"]),
                "domains_with_takeover_risks": sum(1 for r in formatted_results if r["takeover_risks"] > 0),
                "high_risk_takeovers": len(takeover_targets),
            },
        }
    except Exception as e:
        logger.error(f"[Network] CT bulk analysis error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/ct/takeover-targets")
async def get_ct_takeover_targets():
    """Get high-risk subdomain takeover targets."""
    try:
        targets = ct_monitor.get_takeover_targets()
        
        return {
            "status": "success",
            "count": len(targets),
            "targets": targets,
        }
    except Exception as e:
        logger.error(f"[Network] CT takeover targets error: {e}")
