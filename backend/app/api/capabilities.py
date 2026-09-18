from __future__ import annotations

from fastapi import APIRouter
from app.models.schemas import CapabilityReport
from app.security.capabilities import detect_capabilities

router = APIRouter(prefix="/api/capabilities", tags=["capabilities"])


@router.get("", response_model=CapabilityReport)
async def get_capabilities() -> dict[str, bool]:
    """Expose available security and reverse engineering tools gracefully."""
    return detect_capabilities()
