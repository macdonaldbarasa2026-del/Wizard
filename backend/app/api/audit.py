from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Query
from app.services.store import get_audit_logs

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def api_get_audit_logs(limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
    return get_audit_logs(limit=limit)
