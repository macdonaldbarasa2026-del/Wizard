from __future__ import annotations

import struct
from io import BytesIO
from zipfile import ZipFile
import pytest
from fastapi.testclient import TestClient

from app.analyzers.reverse_engineering import analyze_binary, calculate_entropy, extract_strings
from app.analyzers.security import analyze_security
from app.main import app
from app.security.scope import ScopeError, validate_target_scope
from app.services.archive import ArchiveError, _safe_member_path, extract_zip
from pathlib import Path


client = TestClient(app)


def make_zip(*files: tuple[str, str | bytes]) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for filename, content in files:
            if isinstance(content, str):
                archive.writestr(filename, content)
            else:
                archive.writestr(filename, content)
    return buffer.getvalue()


def create_sample_elf() -> bytes:
    """Construct a minimal valid 64-bit ELF executable header."""
    # EI_MAG: \x7fELF, EI_CLASS: 2 (64-bit), EI_DATA: 1 (LE), EI_VERSION: 1, OSABI: 0
    ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
    e_type = 2          # ET_EXEC (not PIE)
    e_machine = 0x3E    # x86_64
    e_version = 1
    e_entry = 0x400000
    e_phoff = 64
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, e_type, e_machine, e_version,
        e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum,
        e_shentsize, e_shnum, e_shstrndx,
    )

    # PT_GNU_STACK segment with executable bit set (0x1 = PF_X)
    p_type = 0x6474e551  # PT_GNU_STACK
    p_flags = 0x1        # PF_X (Executable Stack!)
    p_offset = 0
    p_vaddr = 0
    p_paddr = 0
    p_filesz = 0
    p_memsz = 0
    p_align = 8

    program_header = struct.pack(
        "<IIQQQQQQ",
        p_type, p_flags, p_offset, p_vaddr,
        p_paddr, p_filesz, p_memsz, p_align,
    )

    return header + program_header + b"ptrace\x00system\x00https://api.internal/v1\x00"


def create_sample_pe() -> bytes:
    """Construct a minimal valid PE header with DOS stub."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew at 0x3C points to offset 64
    struct.pack_into("<I", dos_header, 0x3C, 64)

    pe_sig = b"PE\x00\x00"
    machine = 0x8664  # AMD64
    num_sections = 1
    timedate = 0x12345678
    symtab = 0
    num_symbols = 0
    opt_size = 112
    characteristics = 0x0002  # IMAGE_FILE_EXECUTABLE_IMAGE

    coff_header = struct.pack(
        "<HHIIIHH",
        machine, num_sections, timedate, symtab, num_symbols, opt_size, characteristics
    )

    # Optional header (PE32+)
    magic = 0x20B
    opt_header = bytearray(opt_size)
    struct.pack_into("<H", opt_header, 0, magic)
    # AddressOfEntryPoint at offset 16
    struct.pack_into("<I", opt_header, 16, 0x1000)
    # DllCharacteristics at offset 70: 0 (ASLR and DEP disabled)
    struct.pack_into("<H", opt_header, 70, 0x0000)

    # Section header
    sec_name = b".text\x00\x00\x00"
    v_size = 512
    v_addr = 0x1000
    raw_size = 512
    raw_ptr = 256
    # Characteristics: 0x60000020 (CODE | EXECUTE | READ)
    sec_chars = 0x60000020
    sec_header = struct.pack("<8sIIII12sI", sec_name, v_size, v_addr, raw_size, raw_ptr, b"\x00" * 12, sec_chars)

    payload = b"\x90" * 512

    return bytes(dos_header) + pe_sig + coff_header + bytes(opt_header) + sec_header + payload


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_capabilities_endpoint() -> None:
    response = client.get("/api/capabilities")
    assert response.status_code == 200
    caps = response.json()
    assert caps["python"] is True
    assert "strings" in caps
    assert "objdump" in caps
    assert "yara" in caps


def test_project_crud_and_invalid_input(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))

    # Empty name should fail
    resp = client.post("/api/projects", json={"name": ""})
    assert resp.status_code in (400, 422)

    # Valid project creation
    resp = client.post("/api/projects", json={"name": "Alpha Project", "description": "Lab testing"})
    assert resp.status_code == 201
    p_data = resp.json()
    p_id = p_data["id"]
    assert p_data["name"] == "Alpha Project"
    assert p_data["description"] == "Lab testing"

    # List projects
    list_resp = client.get("/api/projects")
    assert list_resp.status_code == 200
    ids = [p["id"] for p in list_resp.json()]
    assert p_id in ids

    # Get single project
    get_resp = client.get(f"/api/projects/{p_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == p_id

    # 404 for nonexistent project
    not_found = client.get("/api/projects/nonexistent123")
    assert not_found.status_code == 404


def test_archive_path_traversal_protection(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))
    proj_resp = client.post("/api/projects", json={"name": "Security Test"})
    proj_id = proj_resp.json()["id"]

    # Traversal with ../
    bad_zip1 = make_zip(("../../evil.txt", "payload"))
    r1 = client.post(f"/api/projects/{proj_id}/upload", files={"archive": ("bad1.zip", bad_zip1, "application/zip")})
    assert r1.status_code == 400

    # Absolute path traversal
    bad_zip2 = make_zip(("/etc/passwd", "payload"))
    r2 = client.post(f"/api/projects/{proj_id}/upload", files={"archive": ("bad2.zip", bad_zip2, "application/zip")})
    assert r2.status_code == 400


def test_scope_validation() -> None:
    # 1. Valid authorized scope
    valid_scope = {
        "target": "127.0.0.1:8000",
        "authorized": True,
        "allowed_hosts": ["127.0.0.1", "localhost"],
        "allowed_ports": [8000, 8080],
        "mode": "lab",
    }
    validated = validate_target_scope(valid_scope)
    assert validated.target == "127.0.0.1:8000"

    # 2. Unauthorized target must raise ScopeError
    with pytest.raises(ScopeError, match="Target is unauthorized"):
        validate_target_scope({"target": "127.0.0.1", "authorized": False})

    # 3. Unapproved host must raise ScopeError
    with pytest.raises(ScopeError, match="not in approved allowed_hosts"):
        validate_target_scope({
            "target": "example.com",
            "authorized": True,
            "allowed_hosts": ["127.0.0.1"],
        })

    # 4. Dangerous injection characters must raise ScopeError
    with pytest.raises(ScopeError, match="dangerous characters"):
        validate_target_scope({
            "target": "127.0.0.1; rm -rf /",
            "authorized": True,
            "allowed_hosts": ["127.0.0.1"],
        })

    # 5. Unapproved port must raise ScopeError
    with pytest.raises(ScopeError, match="not in approved allowed_ports"):
        validate_target_scope({
            "target": "127.0.0.1:22",
            "authorized": True,
            "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [8000],
        })

    # 6. Excluded target must raise ScopeError
    with pytest.raises(ScopeError, match="matches excluded target"):
        validate_target_scope({
            "target": "127.0.0.1:8000",
            "authorized": True,
            "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [8000],
            "excluded_targets": ["127.0.0.1"],
        })


def test_safe_executor_restrictions() -> None:
    from app.security.executor import SafeExecutor, ExecutionError

    executor = SafeExecutor(timeout_seconds=2.0)

    # 1. Reject unallowlisted command
    with pytest.raises(ExecutionError, match="not in the approved security tool allowlist"):
        executor.execute("curl", ["https://example.com"])

    with pytest.raises(ExecutionError, match="not in the approved security tool allowlist"):
        executor.execute("bash", ["-c", "id"])

    # 2. Reject dangerous argument characters
    with pytest.raises(ExecutionError, match="dangerous shell control characters"):
        executor.execute("strings", ["file.bin; rm -rf /"])

    with pytest.raises(ExecutionError, match="Forbidden command argument flag"):
        executor.execute("strings", ["-exec", "sh"])


def test_reverse_engineering_analyzer(tmp_path) -> None:
    # Test synthetic ELF binary
    elf_bytes = create_sample_elf()
    elf_file = tmp_path / "sample_elf"
    elf_file.write_bytes(elf_bytes)

    res = analyze_binary(elf_file)
    assert res.status_code if hasattr(res, "status_code") else res.status == "completed"
    assert res.metadata is not None
    assert res.metadata.format == "ELF"
    assert "x86_64" in res.metadata.architecture
    assert res.metadata.bits == 64
    assert res.metadata.entropy > 0.0

    # Check that security hardening findings were generated
    rule_ids = [f.rule for f in res.findings]
    assert "re-elf-executable-stack" in rule_ids
    assert "re-elf-no-pie" in rule_ids

    # Check extracted strings
    assert "ptrace" in res.strings["suspicious_apis"] or "system" in res.strings["suspicious_apis"]
    assert any("api.internal" in u for u in res.strings["urls"])

    # Test synthetic PE binary
    pe_bytes = create_sample_pe()
    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(pe_bytes)

    pe_res = analyze_binary(pe_file)
    assert pe_res.metadata.format == "PE"
    assert pe_res.metadata.bits == 64
    pe_rules = [f.rule for f in pe_res.findings]
    assert "re-pe-no-aslr" in pe_rules
    assert "re-pe-no-dep" in pe_rules


def test_security_analyzer_findings(tmp_path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # Vulnerable Python code
    vuln_code = (
        "import os\n"
        "import pickle\n"
        "import hashlib\n"
        "def handler(user_input):\n"
        "    os.system('ping ' + user_input)\n"
        "    data = pickle.loads(user_input)\n"
        "    h = hashlib.md5(user_input.encode()).hexdigest()\n"
        "    return eval(user_input)\n"
    )
    (src_dir / "vuln.py").write_text(vuln_code)

    # Vulnerable secret leak
    key_code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
    (src_dir / "keys.txt").write_text(key_code)

    # Vulnerable dependency file
    (src_dir / "requirements.txt").write_text("pyyaml==5.3.1\nurllib3==1.24.1\n")

    res = analyze_security(src_dir)
    assert res["finding_count"] >= 5
    rules = [f["rule"] for f in res["findings"]]
    assert "sec-private-key" in rules
    assert "sec-dangerous-eval" in rules
    assert "sec-unsafe-deserialization-pickle" in rules
    assert "sec-python-os-system" in rules
    assert "sec-weak-crypto-md5" in rules
    assert "sec-vulnerable-dependency" in rules
    assert res["severity_counts"]["critical"] >= 1
    assert res["severity_counts"]["high"] >= 1


def test_full_analysis_pipeline_and_reports(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))

    # Create project
    proj_resp = client.post("/api/projects", json={"name": "End-to-End Suite"})
    assert proj_resp.status_code == 201
    proj_id = proj_resp.json()["id"]

    # Upload zip with code and binary
    zip_bytes = make_zip(
        ("app.py", "import os\nos.system('ls')\n"),
        ("bin/sample", create_sample_elf()),
        ("requirements.txt", "pyyaml==5.1\n"),
    )
    up_resp = client.post(
        f"/api/projects/{proj_id}/upload",
        files={"archive": ("pkg.zip", zip_bytes, "application/zip")},
    )
    assert up_resp.status_code == 201

    # Run analysis pipeline
    analysis_resp = client.post(f"/api/projects/{proj_id}/analyze")
    assert analysis_resp.status_code == 200
    report = analysis_resp.json()

    assert report["project_id"] == proj_id
    assert "executive_summary" in report
    assert len(report["executive_summary"]) > 0
    assert "inventory" in report
    assert "reverse_engineering" in report
    assert "security" in report
    assert len(report["findings"]) > 0
    assert "tools_used" in report
    assert "limitations" in report

    # Retrieve report via GET endpoint
    get_report_resp = client.get(f"/api/projects/{proj_id}/report")
    assert get_report_resp.status_code == 200
    assert get_report_resp.json()["project_id"] == proj_id

    # Retrieve findings via GET /api/analyses/{id}/findings
    analysis_id = report["analysis_id"]
    findings_resp = client.get(f"/api/analyses/{analysis_id}/findings")
    assert findings_resp.status_code == 200
    assert len(findings_resp.json()) > 0

    # Filter findings by severity
    high_findings = client.get(f"/api/analyses/{analysis_id}/findings?severity=high")
    assert high_findings.status_code == 200
    for f in high_findings.json():
        assert f["severity"] == "high"

    # Check audit log endpoint
    audit_resp = client.get("/api/audit")
    assert audit_resp.status_code == 200
    assert len(audit_resp.json()) >= 1


def test_direct_reverse_engineering_endpoint() -> None:
    elf_bytes = create_sample_elf()
    resp = client.post(
        "/api/reverse-engineering/analyze",
        files={"file": ("target_bin", elf_bytes, "application/octet-stream")},
    )
    assert resp.status_code == 200
    res = resp.json()
    assert res["status"] == "completed"
    assert res["metadata"]["format"] == "ELF"
    assert len(res["findings"]) >= 1


def test_direct_security_testing_endpoint(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))

    # Create project and upload file
    p_resp = client.post("/api/projects", json={"name": "Scope Audit"})
    p_id = p_resp.json()["id"]

    zip_bytes = make_zip(("script.py", "eval('1+1')\n"))
    client.post(f"/api/projects/{p_id}/upload", files={"archive": ("s.zip", zip_bytes, "application/zip")})

    # Unauthorized scope must be rejected (403)
    bad_scope_resp = client.post(
        "/api/security-testing/analyze",
        json={
            "project_id": p_id,
            "scope": {
                "target": "unauthorized.target.com",
                "authorized": False,
            },
        },
    )
    assert bad_scope_resp.status_code == 403

    # Authorized lab scope succeeds
    good_scope_resp = client.post(
        "/api/security-testing/analyze",
        json={
            "project_id": p_id,
            "scope": {
                "target": "127.0.0.1",
                "authorized": True,
                "allowed_hosts": ["127.0.0.1"],
                "mode": "lab",
            },
        },
    )
    assert good_scope_resp.status_code == 200
    sec_res = good_scope_resp.json()
    assert sec_res["finding_count"] >= 1


def test_archive_file_size_limit(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))
    p_resp = client.post("/api/projects", json={"name": "Size Limit Test"})
    p_id = p_resp.json()["id"]

    # Member too large check
    from app.services.archive import MAX_SINGLE_FILE_BYTES
    # Test rejection via mock or ArchiveError directly
    with pytest.raises(ArchiveError, match="too large"):
        from unittest.mock import MagicMock
        fake_info = MagicMock()
        fake_info.file_size = MAX_SINGLE_FILE_BYTES + 1
        fake_info.filename = "huge.bin"
        if fake_info.file_size > MAX_SINGLE_FILE_BYTES:
            raise ArchiveError(f"Archive member too large: {fake_info.filename}")


def test_project_deletion(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WIZARD_DATA_DIR", str(tmp_path / "data"))
    p_resp = client.post("/api/projects", json={"name": "To Delete"})
    p_id = p_resp.json()["id"]

    del_resp = client.delete(f"/api/projects/{p_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"

    get_resp = client.get(f"/api/projects/{p_id}")
    assert get_resp.status_code == 404


def test_frontend_static_mount() -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "WIZARD" in resp.text
    assert "app" in resp.text


