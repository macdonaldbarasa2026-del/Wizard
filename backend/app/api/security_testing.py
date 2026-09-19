from __future__ import annotations

from typing import Literal
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.analyzers.security import analyze_security
from app.models.schemas import Finding, SecurityTestingResult, TargetScope
from app.security.scope import ScopeError, validate_target_scope
from app.services.store import get_project, source_root

router = APIRouter(prefix="/api/security-testing", tags=["security-testing"])


class SecurityAnalysisRequest(BaseModel):
    project_id: str
    scope: TargetScope | None = None
    analysis_type: Literal["static", "dependencies", "configuration", "all"] = "all"


@router.post("/analyze", response_model=SecurityTestingResult)
async def api_security_analyze(payload: SecurityAnalysisRequest) -> SecurityTestingResult:
    """Run authorized ethical security testing on a project with strict scope verification."""
    try:
        get_project(payload.project_id)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    # Scope validation
    if payload.scope:
        try:
            validated = validate_target_scope(payload.scope)
            scope_desc = f"Authorized target: {validated.target} (mode: {validated.mode})"
        except ScopeError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    else:
        scope_desc = f"Local imported project {payload.project_id} (static code inspection only)"

    root = source_root(payload.project_id)
    raw_result = analyze_security(root)
    raw_result["scope"] = scope_desc

    findings_objs = [Finding(**f) for f in raw_result.get("findings", [])]

    return SecurityTestingResult(
        tool_used=raw_result.get("tool_used", "wizard-static-security"),
        scope=scope_desc,
        status="completed",
        finding_count=len(findings_objs),
        severity_counts=raw_result.get("severity_counts", {}),
        findings=findings_objs,
        dependency_vulnerabilities=raw_result.get("dependency_vulnerabilities", []),
        configuration_issues=raw_result.get("configuration_issues", []),
        errors=raw_result.get("errors", []),
        timestamp=raw_result.get("timestamp", ""),
    )


@router.get("/sarif/{project_id}")
async def api_security_sarif(project_id: str) -> dict[str, Any]:
    """Export project static security analysis findings to standard OASIS SARIF v2.1.0."""
    try:
        get_project(project_id)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    from app.services.sarif import findings_to_sarif
    root = source_root(project_id)
    raw_result = analyze_security(root)
    findings = raw_result.get("findings", [])
    return findings_to_sarif(findings, target_uri=str(root))
