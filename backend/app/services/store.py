from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def data_root() -> Path:
    configured = os.environ.get("WIZARD_DATA_DIR")
    root = Path(configured) if configured else Path(__file__).resolve().parents[3] / "data"
    root.mkdir(parents=True, exist_ok=True)
    return root


def projects_root() -> Path:
    root = data_root() / "projects"
    root.mkdir(parents=True, exist_ok=True)
    return root


def analyses_root() -> Path:
    root = data_root() / "analyses"
    root.mkdir(parents=True, exist_ok=True)
    return root


def audit_root() -> Path:
    root = data_root() / "audit"
    root.mkdir(parents=True, exist_ok=True)
    return root


def project_root(project_id: str) -> Path:
    return projects_root() / project_id


def project_json(project_id: str) -> Path:
    return project_root(project_id) / "project.json"


def report_json(project_id: str) -> Path:
    return project_root(project_id) / "report.json"


def source_root(project_id: str) -> Path:
    root = project_root(project_id) / "source"
    root.mkdir(parents=True, exist_ok=True)
    return root


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary.replace(path)


def load_json(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(str(path))

    value = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object in {path}")

    return value


def create_project(name: str, description: str | None = None) -> dict:
    clean_name = " ".join(name.strip().split())

    if not clean_name:
        raise ValueError("Project name cannot be empty.")

    project_id = uuid4().hex[:12]
    created_at = datetime.now(timezone.utc).isoformat()

    project = {
        "id": project_id,
        "name": clean_name,
        "description": description.strip() if description else "",
        "status": "created",
        "created_at": created_at,
        "file_count": 0,
        "total_bytes": 0,
    }

    root = project_root(project_id)
    root.mkdir(parents=True, exist_ok=False)
    source_root(project_id)
    save_json(project_json(project_id), project)

    return project


def get_project(project_id: str) -> dict:
    return load_json(project_json(project_id))


def list_projects() -> list[dict]:
    projects: list[dict] = []
    root = projects_root()
    for item in sorted(root.iterdir()):
        if item.is_dir() and (item / "project.json").is_file():
            try:
                projects.append(load_json(item / "project.json"))
            except Exception:
                continue
    return projects


def update_project(project_id: str, **changes: object) -> dict:
    project = get_project(project_id)
    project.update(changes)
    save_json(project_json(project_id), project)
    return project


def delete_project(project_id: str) -> bool:
    target = project_root(project_id)
    if target.is_dir():
        shutil.rmtree(target)
        return True
    return False


def save_report(project_id: str, report: dict) -> None:
    save_json(report_json(project_id), report)


def get_report(project_id: str) -> dict | None:
    path = report_json(project_id)
    if not path.is_file():
        return None
    return load_json(path)


def save_analysis(analysis_id: str, analysis: dict) -> None:
    path = analyses_root() / f"{analysis_id}.json"
    save_json(path, analysis)


def get_analysis(analysis_id: str) -> dict | None:
    path = analyses_root() / f"{analysis_id}.json"
    if not path.is_file():
        return None
    return load_json(path)


def list_analyses() -> list[dict]:
    analyses: list[dict] = []
    root = analyses_root()
    for item in sorted(root.glob("*.json")):
        try:
            analyses.append(load_json(item))
        except Exception:
            continue
    return analyses


def save_audit_log(entry: dict) -> None:
    log_file = audit_root() / "audit.jsonl"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def get_audit_logs(limit: int = 100) -> list[dict]:
    log_file = audit_root() / "audit.jsonl"
    if not log_file.is_file():
        return []
    lines = log_file.read_text(encoding="utf-8").splitlines()
    entries = []
    for line in reversed(lines[-limit:]):
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries
