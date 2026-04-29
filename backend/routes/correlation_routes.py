"""
IRVES — Cross-Phase Correlation Routes
Phase E: API endpoints for finding correlation and attack chains.

Endpoints:
- POST /api/scans/{scan_id}/correlate - Run correlation analysis
- GET /api/scans/{scan_id}/correlations - Get correlated findings
- GET /api/scans/{scan_id}/attack-chains - Get attack chains
- GET /api/findings/{finding_id}/correlations - Get finding correlations
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from database.connection import get_db_session
from database.models import Finding, Scan
from services.correlation_service import correlator, FindingCorrelator

router = APIRouter(prefix="/api", tags=["correlation"])


@router.post("/scans/{scan_id}/correlate")
async def correlate_scan_findings(
    scan_id: str = Path(..., description="Scan ID to correlate"),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """
    Run cross-phase correlation on a scan's findings.

    Analyzes all findings from static, dynamic, and network phases
    to identify correlations and build attack chains.

    Returns:
        Correlated findings grouped by phase, attack chains, summary
    """
    # Verify scan exists
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        # Get all findings for this scan
        result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        findings = result.scalars().all()

        if not findings:
            return {
                "success": True,
                "scan_id": scan_id,
                "message": "No findings to correlate",
                "static": [],
                "dynamic": [],
                "network": [],
                "attack_chains": [],
                "correlation_summary": {
                    "total_correlations": 0,
                    "high_confidence": 0,
                    "attack_chains_found": 0,
                },
            }

        # Categorize findings by phase (based on tool or evidence)
        static_findings = []
        dynamic_findings = []
        network_findings = []

        for f in findings:
            tool = f.tool.lower() if f.tool else ""

            # Categorize by tool type
            if any(t in tool for t in ["apk_analyzer", "ios_analyzer", "semgrep", "apktool", "jadx"]):
                static_findings.append(f)
            elif any(t in tool for t in ["frida", "runtime", "hook"]):
                dynamic_findings.append(f)
            elif any(t in tool for t in ["mitm", "network", "proxy", "traffic"]):
                network_findings.append(f)
            else:
                # Default to static for unknown tools
                static_findings.append(f)

        # Run correlation
        result = correlator.correlate_findings(
            static_findings=static_findings,
            dynamic_findings=dynamic_findings,
            network_findings=network_findings,
        )

        return {
            "success": True,
            "scan_id": scan_id,
            **result,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Correlation failed: {str(e)}")


@router.get("/scans/{scan_id}/correlations")
async def get_scan_correlations(
    scan_id: str = Path(..., description="Scan ID"),
    confidence: Optional[str] = None,  # high, medium, low
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """
    Get correlated findings for a scan.

    Args:
        confidence: Filter by confidence level (optional)

    Returns:
        List of correlated findings with their relationships
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        # Get findings
        result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        findings = result.scalars().all()

        # Run correlation
        correlation_result = correlator.correlate_findings(
            static_findings=[f for f in findings if "frida" not in f.tool.lower()],
            dynamic_findings=[f for f in findings if "frida" in f.tool.lower()],
            network_findings=[f for f in findings if "mitm" in f.tool.lower()],
        )

        # Filter by confidence if specified
        if confidence:
            for phase in ["static", "dynamic", "network"]:
                correlation_result[phase] = [
                    f for f in correlation_result[phase]
                    if f.get("confidence") == confidence
                ]

        return {
            "success": True,
            "scan_id": scan_id,
            "findings": correlation_result,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/attack-chains")
async def get_attack_chains(
    scan_id: str = Path(..., description="Scan ID"),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """
    Get attack chains for a scan.

    Returns multi-step attack paths discovered through correlation.
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        # Get findings and correlate
        result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        findings = result.scalars().all()

        correlation_result = correlator.correlate_findings(
            static_findings=[f for f in findings if "frida" not in f.tool.lower()],
            dynamic_findings=[f for f in findings if "frida" in f.tool.lower()],
            network_findings=[f for f in findings if "mitm" in f.tool.lower()],
        )

        return {
            "success": True,
            "scan_id": scan_id,
            "attack_chains": correlation_result.get("attack_chains", []),
            "count": len(correlation_result.get("attack_chains", [])),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/findings/{finding_id}/correlations")
async def get_finding_correlations(
    finding_id: str = Path(..., description="Finding ID"),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """
    Get correlations for a specific finding.

    Returns related findings and correlation details.
    """
    # Get finding
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        # Get all findings from same scan for correlation context
        result = await db.execute(
            select(Finding).where(Finding.scan_id == finding.scan_id)
        )
        all_findings = result.scalars().all()

        # Run correlation to get context
        correlation_result = correlator.correlate_findings(
            static_findings=[f for f in all_findings if "frida" not in f.tool.lower()],
            dynamic_findings=[f for f in all_findings if "frida" in f.tool.lower()],
            network_findings=[f for f in all_findings if "mitm" in f.tool.lower()],
        )

        # Find this finding in results
        correlated_finding = None
        for phase in ["static", "dynamic", "network"]:
            for f in correlation_result.get(phase, []):
                if f.get("finding_id") == finding_id:
                    correlated_finding = f
                    break
            if correlated_finding:
                break

        # Get related findings
        related = []
        if correlated_finding and correlated_finding.get("correlated_with"):
            for fid in correlated_finding["correlated_with"]:
                related_f = next((f for f in all_findings if f.id == fid), None)
                if related_f:
                    related.append({
                        "finding_id": related_f.id,
                        "title": related_f.title,
                        "severity": related_f.severity.value if hasattr(related_f.severity, 'value') else str(related_f.severity),
                        "phase": "unknown",  # Would need to track this
                    })

        return {
            "success": True,
            "finding_id": finding_id,
            "finding": correlated_finding,
            "related_findings": related,
            "attack_chain": None,  # Would track this in correlation
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
