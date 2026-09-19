from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status

from app.analyzers.diff import diff_binaries
from app.analyzers.entropy import analyze_sliding_entropy
from app.analyzers.reverse_engineering import analyze_binary
from app.analyzers.rop import analyze_rop_gadgets
from app.analyzers.signatures import scan_signatures
from app.models.schemas import ReverseEngineeringResult
from app.native.bridge import get_native_bridge
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
        candidates = sorted(root.rglob("*"), key=lambda p: p.stat().st_size if p.is_file() else 0, reverse=True)
        files = [p for p in candidates if p.is_file()]
        if not files:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Project contains no files to analyze.")
        return analyze_binary(files[0])

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Must provide either an uploaded binary file or an existing project_id.",
    )


@router.post("/gadgets")
async def api_rop_gadgets(
    file: UploadFile = File(...),
    reg: str | None = Form(default=None),
    cat: str | None = Form(default=None),
    max_gadgets: int = Form(default=200),
) -> dict[str, Any]:
    """Extract ROP (Return-Oriented Programming) gadgets from an uploaded binary."""
    with tempfile.NamedTemporaryFile(suffix=f"_{file.filename}", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
            tmp.flush()
            return analyze_rop_gadgets(tmp_path, filter_reg=reg, filter_category=cat, max_gadgets=max_gadgets)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


@router.post("/entropy")
async def api_sliding_entropy(
    file: UploadFile = File(...),
    window_size: int = Form(default=512),
    step_size: int = Form(default=128),
) -> dict[str, Any]:
    """Calculate Shannon and sliding-window entropy with sparkline and metrics."""
    with tempfile.NamedTemporaryFile(suffix=f"_{file.filename}", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
            tmp.flush()
            return analyze_sliding_entropy(tmp_path, window_size=window_size, step_size=step_size, visualize=True)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


@router.post("/diff")
async def api_binary_diff(
    file1: UploadFile = File(...),
    file2: UploadFile = File(...),
) -> dict[str, Any]:
    """Perform structural, cryptographic, and byte-similarity diffing between two binaries."""
    with tempfile.NamedTemporaryFile(suffix=f"_{file1.filename}", delete=False) as tmp1, \
         tempfile.NamedTemporaryFile(suffix=f"_{file2.filename}", delete=False) as tmp2:
        path1 = Path(tmp1.name)
        path2 = Path(tmp2.name)
        try:
            path1.write_bytes(await file1.read())
            path2.write_bytes(await file2.read())
            return diff_binaries(path1, path2)
        finally:
            if path1.exists():
                path1.unlink()
            if path2.exists():
                path2.unlink()


@router.post("/scan")
async def api_signature_scan(
    file: UploadFile = File(...),
    rule_filter: str | None = Form(default=None),
) -> dict[str, Any]:
    """Run YARA-style signature patterns and malware heuristics on uploaded binary."""
    with tempfile.NamedTemporaryFile(suffix=f"_{file.filename}", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
            tmp.flush()
            return scan_signatures(tmp_path, rule_filter=rule_filter)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


@router.get("/native")
def api_native_core_status() -> dict[str, Any]:
    """Get C++ Native Core engine status, library details, and performance benchmark."""
    bridge = get_native_bridge()
    bench = bridge.benchmark(500000)
    return {
        "native_loaded": bridge.is_native_loaded,
        "library_path": str(bridge.so_path),
        "version": bridge.get_version(),
        "benchmark": bench,
    }
