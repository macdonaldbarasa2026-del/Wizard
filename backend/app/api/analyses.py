from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Query, status

from app.models.schemas import Finding, Severity
from app.services.store import get_analysis, list_analyses

router = APIRouter(prefix="/api/analyses", tags=["analyses"])


@router.get("")
async def api_list_analyses() -> list[dict[str, Any]]:
    return list_analyses()


@router.get("/{analysis_id}")
async def api_get_analysis(analysis_id: str) -> dict[str, Any]:
    analysis = get_analysis(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")
    return analysis


@router.get("/{analysis_id}/findings", response_model=list[Finding])
async def api_get_analysis_findings(
    analysis_id: str,
    severity: Severity | None = Query(default=None, description="Filter findings by severity"),
    module: str | None = Query(default=None, description="Filter findings by module"),
) -> list[Finding]:
    analysis = get_analysis(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    raw_findings = analysis.get("findings", [])
    filtered: list[Finding] = []

    for item in raw_findings:
        if severity and item.get("severity") != severity:
            continue
        if module and item.get("module") != module:
            continue
        try:
            filtered.append(Finding(**item))
        except Exception:
            continue

    return filtered
