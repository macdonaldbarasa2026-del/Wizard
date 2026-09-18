from __future__ import annotations

import tempfile
from pathlib import Path
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.analyzers.inventory import analyze_inventory
from app.models.schemas import AnalysisRequest, Project, ProjectCreate
from app.orchestrator.orchestrator import run_analysis_pipeline
from app.security.scope import ScopeError
from app.services.archive import ArchiveError, extract_zip
from app.services.store import (
    create_project,
    delete_project,
    get_project,
    get_report,
    list_projects,
    project_root,
    source_root,
    update_project,
)

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.post("", response_model=Project, status_code=status.HTTP_201_CREATED)
async def api_create_project(payload: ProjectCreate) -> dict:
    try:
        return create_project(name=payload.name, description=payload.description)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("", response_model=list[Project])
async def api_list_projects() -> list[dict]:
    return list_projects()


@router.get("/{project_id}", response_model=Project)
async def api_get_project(project_id: str) -> dict:
    try:
        return get_project(project_id)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")


@router.delete("/{project_id}")
async def api_delete_project(project_id: str) -> dict[str, str]:
    success = delete_project(project_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return {"status": "deleted", "id": project_id}


@router.post("/{project_id}/upload", status_code=status.HTTP_201_CREATED)
async def api_upload_project(
    project_id: str,
    archive: UploadFile = File(...),
) -> dict:
    try:
        get_project(project_id)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    target_dir = source_root(project_id)

    # Save uploaded bytes to a temporary file before extraction
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_archive:
        temp_path = Path(temp_archive.name)
        try:
            while True:
                chunk = await archive.read(1024 * 1024)
                if not chunk:
                    break
                temp_archive.write(chunk)
            temp_archive.flush()

            # Safely extract archive with path traversal and zip bomb protection
            extract_zip(temp_path, target_dir)
        except ArchiveError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        finally:
            if temp_path.exists():
                temp_path.unlink()

    # Update project stats with inventory
    inv = analyze_inventory(target_dir)
    updated = update_project(
        project_id,
        status="uploaded",
        file_count=inv.get("total_files", 0),
        total_bytes=inv.get("total_bytes", 0),
    )

    return {
        "status": "uploaded",
        "project_id": project_id,
        "file_count": updated.get("file_count", 0),
        "total_bytes": updated.get("total_bytes", 0),
    }


@router.post("/{project_id}/analyze", status_code=status.HTTP_200_OK)
async def api_analyze_project(
    project_id: str,
    payload: AnalysisRequest | None = None,
) -> dict:
    try:
        get_project(project_id)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    modules = payload.modules if payload else None
    scope = payload.scope if payload else None
    notes = payload.user_notes if payload else None

    try:
        return run_analysis_pipeline(
            project_id=project_id,
            modules=modules,
            scope=scope,
            user_notes=notes,
        )
    except ScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("/{project_id}/report", status_code=status.HTTP_200_OK)
async def api_get_project_report(project_id: str) -> dict:
    try:
        get_project(project_id)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    report = get_report(project_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No analysis report found for this project. Run analysis first.",
        )

    return report
