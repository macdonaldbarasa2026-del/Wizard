from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch
import pytest

from app.cli import (
    cmd_capabilities,
    cmd_doctor,
    cmd_projects,
    cmd_reverse,
    cmd_security,
    cmd_version,
    main,
    print_banner,
)


def test_cli_banner_output() -> None:
    captured = StringIO()
    with patch("sys.stdout", captured):
        print_banner(full=True)
    out = captured.getvalue()
    assert "W I Z A R D" in out or "WIZARD" in out
    assert "Security" in out or "SECURITY" in out or "S E C U R I T Y" in out




def test_cli_version(capsys: pytest.CaptureFixture) -> None:
    cmd_version()
    captured = capsys.readouterr().out
    assert "WIZARD" in captured
    assert "0.1.0" in captured


def test_cli_capabilities(capsys: pytest.CaptureFixture) -> None:
    cmd_capabilities()
    captured = capsys.readouterr().out
    assert "WIZARD CAPABILITIES" in captured
    assert "ELF parser" in captured
    assert "Static analysis" in captured
    assert "Scope validator" in captured


def test_cli_doctor(capsys: pytest.CaptureFixture) -> None:
    cmd_doctor()
    captured = capsys.readouterr().out
    assert "WIZARD SYSTEM DIAGNOSTIC (DOCTOR)" in captured
    assert "Python 3" in captured
    assert "Core platform engines are operational" in captured


def test_cli_project_lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))

    # 1. Create project
    cmd_projects("create", name="CLI Test Lab", desc="CLI testing")
    created_out = capsys.readouterr().out
    assert "Project created successfully" in created_out
    assert "CLI Test Lab" in created_out

    # 2. List projects
    cmd_projects("list")
    list_out = capsys.readouterr().out
    assert "CLI Test Lab" in list_out

    # Parse project ID
    from app.services.store import list_projects
    projs = list_projects()
    assert len(projs) == 1
    proj_id = projs[0]["id"]

    # 3. Delete project
    cmd_projects("delete", project_id=proj_id)
    del_out = capsys.readouterr().out
    assert f"Deleted project {proj_id}" in del_out

    # Verify deleted
    cmd_projects("list")
    empty_list = capsys.readouterr().out
    assert "No projects created yet" in empty_list


def test_cli_reverse_command(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    from tests.test_platform import create_sample_elf
    elf_file = tmp_path / "test_elf.bin"
    elf_file.write_bytes(create_sample_elf())

    cmd_reverse(str(elf_file))
    captured = capsys.readouterr().out
    assert "Analyzing Binary Artifact" in captured
    assert "Format:" in captured
    assert "ELF" in captured
    assert "Architecture:" in captured
    assert "x86_64" in captured


def test_cli_security_command(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "vuln.py").write_text("import os\nos.system('ls')\neval('1+1')\n")

    cmd_security(str(src_dir), authorized=True)
    captured = capsys.readouterr().out
    assert "Running Ethical Security Analysis" in captured
    assert "Total Observations:" in captured
    assert "eval()" in captured
    assert "os.system()" in captured


def test_cli_findings_and_report_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    from app.cli import cmd_analyze, cmd_findings, cmd_report
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))

    # Create project and analyze
    cmd_projects("create", name="Report Project")
    capsys.readouterr()

    from app.services.store import list_projects
    p_id = list_projects()[0]["id"]

    # Analyze project
    cmd_analyze(p_id)
    analyze_out = capsys.readouterr().out
    assert "Running Orchestrator Analysis" in analyze_out

    # Test report text format
    cmd_report(p_id, output_format="text")
    rep_text = capsys.readouterr().out
    assert "WIZARD ASSESSMENT REPORT" in rep_text
    assert "Executive Summary:" in rep_text

    # Test report md format
    cmd_report(p_id, output_format="md")
    rep_md = capsys.readouterr().out
    assert "# WIZARD Security & Reverse Engineering Report" in rep_md

    # Test findings command
    cmd_findings(p_id)
    find_out = capsys.readouterr().out
    assert "WIZARD FINDINGS" in find_out or "No findings recorded yet" in find_out


def test_cli_main_entrypoint(capsys: pytest.CaptureFixture) -> None:
    with patch("sys.argv", ["wizard", "--version"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr().out
        assert "WIZARD" in captured


def test_installer_and_launcher_files_exist() -> None:
    project_root = Path(__file__).resolve().parents[2]
    assert (project_root / "bin" / "wizard").is_file()
    assert (project_root / "install.sh").is_file()
    assert (project_root / "uninstall.sh").is_file()
    assert (project_root / "start_backend.sh").is_file()
    assert (project_root / "README.md").is_file()
    assert (project_root / "LICENSE").is_file()
    assert (project_root / ".gitignore").is_file()
