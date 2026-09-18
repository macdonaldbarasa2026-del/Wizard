from io import BytesIO
from zipfile import ZipFile

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def make_zip(*files: tuple[str, str]) -> bytes:
    buffer = BytesIO()

    with ZipFile(buffer, "w") as archive:
        for filename, content in files:
            archive.writestr(filename, content)

    return buffer.getvalue()


def test_health() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "wizard-api",
        "version": "0.1.0",
    }


def test_modules() -> None:
    response = client.get("/api/modules")

    assert response.status_code == 200

    modules = response.json()["modules"]

    assert len(modules) == 2
    assert modules[0]["id"] == "reverse-engineering"
    assert modules[1]["id"] == "security-testing"


def test_project_upload_and_analysis(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))

    project_response = client.post(
        "/api/projects",
        json={
            "name": "Test Project",
            "description": "Authorized security analysis test",
        },
    )

    assert project_response.status_code == 201

    project = project_response.json()
    project_id = project["id"]

    zip_data = make_zip(
        ("src/example.py", "print('hello')\n"),
        ("README.md", "# Test Project\n"),
    )

    upload_response = client.post(
        f"/api/projects/{project_id}/upload",
        files={
            "archive": (
                "test-project.zip",
                zip_data,
                "application/zip",
            )
        },
    )

    assert upload_response.status_code == 201

    analyze_response = client.post(
        f"/api/projects/{project_id}/analyze"
    )

    assert analyze_response.status_code == 200

    report = analyze_response.json()

    assert report["project_id"] == project_id
    assert "inventory" in report
    assert "reverse_engineering" in report
    assert "security" in report


def test_path_traversal_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))

    project_response = client.post(
        "/api/projects",
        json={
            "name": "Traversal Test",
            "description": "Archive security test",
        },
    )

    assert project_response.status_code == 201

    project_id = project_response.json()["id"]

    malicious_zip = make_zip(
        ("../../outside.txt", "should never be extracted"),
    )

    upload_response = client.post(
        f"/api/projects/{project_id}/upload",
        files={
            "archive": (
                "malicious.zip",
                malicious_zip,
                "application/zip",
            )
        },
    )

    assert upload_response.status_code == 400
