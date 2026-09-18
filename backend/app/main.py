from __future__ import annotations

import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api import (
    analyses,
    audit,
    capabilities,
    projects,
    reverse_engineering,
    security_testing,
)

app = FastAPI(
    title="Wizard",
    description="AI-assisted reverse engineering and authorized security analysis platform.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(capabilities.router)
app.include_router(projects.router)
app.include_router(reverse_engineering.router)
app.include_router(security_testing.router)
app.include_router(analyses.router)
app.include_router(audit.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "wizard-api",
        "version": "0.1.0",
    }


@app.get("/api/modules")
async def modules() -> dict[str, list[dict[str, str]]]:
    return {
        "modules": [
            {
                "id": "reverse-engineering",
                "name": "Reverse Engineering",
                "description": "Analyze authorized source code and binaries.",
            },
            {
                "id": "security-testing",
                "name": "Ethical Security Testing",
                "description": "Perform authorized defensive security analysis.",
            },
        ]
    }


# Mount Frontend Dist if built
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="static")
