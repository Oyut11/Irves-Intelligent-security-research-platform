"""
IRVES — Three-Module AI API Routes
Phase 3: Endpoints for Parsing, Reasoning, and Generation modules.

Endpoints:
- POST /api/ai/parse - Parse tool output
- POST /api/ai/analyze - Analyze attack paths and risk
- POST /api/ai/strategy - Generate analysis strategy
- POST /api/ai/generate-fix - Generate code fix
- POST /api/ai/generate-script - Generate Frida script
- POST /api/ai/generate-report - Generate security report
- GET /api/ai/costs - Get cost statistics
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ai_modules import (
    ParsingModule, ReasoningModule, GenerationModule,
    CostTracker, cost_tracker
)

router = APIRouter(prefix="/api/ai", tags=["ai-modules"])


# Request/Response Models
class ParseRequest(BaseModel):
    tool_name: str
    raw_output: str
    output_format: str = "auto"
    platform: str = "android"


class AnalyzeRequest(BaseModel):
    findings: List[Dict[str, Any]]
    platform: str = "android"
    context: Optional[Dict[str, Any]] = None


class StrategyRequest(BaseModel):
    current_findings: List[Dict[str, Any]]
    completed_phases: List[str] = []
    platform: str = "android"
    goals: Optional[List[str]] = None


class GenerateFixRequest(BaseModel):
    finding: Dict[str, Any]
    language: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class GenerateScriptRequest(BaseModel):
    target: str
    purpose: str
    platform: str = "android"
    additional_context: Optional[str] = None


class GenerateReportRequest(BaseModel):
    findings: List[Dict[str, Any]]
    title: str
    report_type: str = "technical"
    metadata: Optional[Dict[str, Any]] = None


# Module instances (singletons)
parsing_module: Optional[ParsingModule] = None
reasoning_module: Optional[ReasoningModule] = None
generation_module: Optional[GenerationModule] = None


def get_parsing_module() -> ParsingModule:
    """Get or create ParsingModule instance."""
    global parsing_module
    if parsing_module is None:
        parsing_module = ParsingModule(cost_tracker=cost_tracker)
    return parsing_module


def get_reasoning_module() -> ReasoningModule:
    """Get or create ReasoningModule instance."""
    global reasoning_module
    if reasoning_module is None:
        reasoning_module = ReasoningModule(cost_tracker=cost_tracker)
    return reasoning_module


def get_generation_module() -> GenerationModule:
    """Get or create GenerationModule instance."""
    global generation_module
    if generation_module is None:
        generation_module = GenerationModule(cost_tracker=cost_tracker)
    return generation_module


@router.post("/parse")
async def parse_tool_output(request: ParseRequest) -> Dict[str, Any]:
    """
    Parse raw tool output into structured findings.

    Uses the Parsing Module to extract structured data from raw tool output.
    """
    module = get_parsing_module()

    result = await module.parse_output(
        tool_name=request.tool_name,
        raw_output=request.raw_output,
        output_format=request.output_format,
        platform=request.platform,
    )

    return {
        "success": True,
        "findings": result.get("findings", []),
        "summary": result.get("summary", ""),
        "tool_info": result.get("tool_info", {}),
    }


@router.post("/analyze")
async def analyze_findings(request: AnalyzeRequest) -> Dict[str, Any]:
    """
    Analyze findings to generate attack paths and risk assessment.

    Uses the Reasoning Module for:
    - Attack path construction
    - Risk scoring
    - Finding correlation
    """
    module = get_reasoning_module()

    # Run analyses in parallel
    attack_paths_task = module.analyze_attack_paths(
        request.findings,
        request.platform,
        request.context,
    )
    risk_task = module.assess_risk(
        request.findings,
        request.context,
    )

    import asyncio
    attack_paths, risk = await asyncio.gather(attack_paths_task, risk_task)

    # Convert dataclasses to dicts
    attack_paths_dict = [
        {
            "path_id": p.path_id,
            "name": p.name,
            "description": p.description,
            "steps": p.steps,
            "entry_point": p.entry_point,
            "target_asset": p.target_asset,
            "difficulty": p.difficulty,
            "likelihood": p.likelihood,
            "impact": p.impact,
            "prerequisites": p.prerequisites,
            "mitigations": p.mitigations,
            "tools_needed": p.tools_needed,
        }
        for p in attack_paths
    ]

    return {
        "success": True,
        "attack_paths": attack_paths_dict,
        "risk_assessment": {
            "overall_risk": risk.overall_risk,
            "risk_score": risk.risk_score,
            "likelihood": risk.likelihood,
            "business_impact": risk.business_impact,
            "technical_impact": risk.technical_impact,
            "cvss_score": risk.cvss_score,
            "factors": risk.factors,
        } if risk else None,
    }


@router.post("/strategy")
async def generate_strategy(request: StrategyRequest) -> Dict[str, Any]:
    """
    Generate analysis strategy for what to investigate next.

    Uses the Reasoning Module to suggest next steps based on current findings.
    """
    module = get_reasoning_module()

    strategy = await module.generate_strategy(
        current_findings=request.current_findings,
        completed_phases=request.completed_phases,
        platform=request.platform,
        goals=request.goals,
    )

    return {
        "success": True,
        "strategy": strategy,
    }


@router.post("/generate-fix")
async def generate_fix(request: GenerateFixRequest) -> Dict[str, Any]:
    """
    Generate a secure code fix for a finding.

    Uses the Generation Module to create remediation code.
    """
    module = get_generation_module()

    fix = await module.generate_fix(
        finding=request.finding,
        language=request.language,
        context=request.context,
    )

    if not fix:
        raise HTTPException(status_code=500, detail="Failed to generate fix")

    return {
        "success": True,
        "fix": {
            "finding_id": fix.finding_id,
            "language": fix.language,
            "original_code": fix.original_code,
            "fixed_code": fix.fixed_code,
            "explanation": fix.explanation,
            "testing_notes": fix.testing_notes,
            "confidence": fix.confidence,
        },
    }


@router.post("/generate-script")
async def generate_script(request: GenerateScriptRequest) -> Dict[str, Any]:
    """
    Generate a Frida script for dynamic analysis.

    Uses the Generation Module to create hook scripts.
    """
    module = get_generation_module()

    script = await module.generate_frida_script(
        target=request.target,
        purpose=request.purpose,
        platform=request.platform,
        additional_context=request.additional_context,
    )

    if not script:
        raise HTTPException(status_code=500, detail="Failed to generate script")

    return {
        "success": True,
        "script": {
            "script_id": script.script_id,
            "name": script.name,
            "target": script.target,
            "script_type": script.script_type,
            "code": script.code,
            "description": script.description,
            "usage_instructions": script.usage_instructions,
            "expected_output": script.expected_output,
        },
    }


@router.post("/generate-report")
async def generate_report(request: GenerateReportRequest) -> Dict[str, Any]:
    """
    Generate a security analysis report.

    Uses the Generation Module to create professional reports.
    """
    module = get_generation_module()

    report = await module.generate_report(
        findings=request.findings,
        title=request.title,
        report_type=request.report_type,
        metadata=request.metadata,
    )

    return {
        "success": True,
        "report": report,
    }


@router.get("/costs")
async def get_costs() -> Dict[str, Any]:
    """
    Get AI cost tracking statistics.

    Returns breakdown of token usage and estimated costs per module.
    """
    return {
        "success": True,
        "by_module": cost_tracker.get_module_stats(),
        "daily_usage": cost_tracker.get_daily_usage(),
    }


@router.get("/costs/{module}")
async def get_module_costs(module: str) -> Dict[str, Any]:
    """
    Get cost statistics for a specific module.

    Modules: parsing, reasoning, generation, chat
    """
    try:
        from ai_modules import AIModule
        ai_module = AIModule(module)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid module: {module}")

    return {
        "success": True,
        "module": module,
        "stats": cost_tracker.get_stats(ai_module),
    }
