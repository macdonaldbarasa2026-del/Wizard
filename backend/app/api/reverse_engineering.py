from __future__ import annotations

import tempfile
from pathlib import Path
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status

from app.analyzers.reverse_engineering import analyze_binary
from app.models.schemas import ReverseEngineeringResult
from app.services.store import get_project, source_root

router = APIRouter(prefix="/api/reverse-engineering", tags=["reverse-engineering"])


@router.post("/analyze", response_model=ReverseEngineeringResult)
async def api_re_analyze(
    project_id: str | None = Form(default=None),
    file: UploadFile | None = File(default=None),
) -> ReverseEngineeringResult:
    """Run Reverse Engineering analysis directly on an uploaded binary or an existing project."""
    if file is not None:
        with tempfile.NamedTemporaryFile(suffix=f"_{file.filename}", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            try:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    tmp.write(chunk)
                tmp.flush()
                return analyze_binary(tmp_path)
            finally:
                if tmp_path.exists():
                    tmp_path.unlink()

    if project_id is not None:
        try:
            get_project(project_id)
        except FileNotFoundError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

        root = source_root(project_id)
        # Find first binary or largest file
        candidates = sorted(root.rglob("*"), key=lambda p: p.stat().st_size if p.is_file() else 0, reverse=True)
        files = [p for p in candidates if p.is_file()]
        if not files:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Project contains no files to analyze.")
        return analyze_binary(files[0])

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Must provide either an uploaded binary file or an existing project_id.",
    )
