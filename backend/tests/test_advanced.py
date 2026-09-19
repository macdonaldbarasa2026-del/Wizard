from __future__ import annotations

import json
from pathlib import Path
from io import BytesIO
from zipfile import ZipFile
import pytest
from fastapi.testclient import TestClient

from app.analyzers.diff import diff_binaries
from app.analyzers.entropy import analyze_sliding_entropy, render_ascii_sparkline, render_entropy_bars
from app.analyzers.rop import analyze_rop_gadgets
from app.analyzers.security import analyze_security
from app.analyzers.signatures import scan_signatures
from app.main import app
from app.native.bridge import get_native_bridge
from app.services.sarif import findings_to_sarif, write_sarif_file
from tests.test_platform import create_sample_elf, create_sample_pe

client = TestClient(app)


def test_native_bridge_core() -> None:
    bridge = get_native_bridge()
    assert bridge.get_version() >= 200

    # Test Shannon entropy
    ent_zeros = bridge.calculate_entropy(b"\x00" * 100)
    assert ent_zeros == 0.0

    ent_random = bridge.calculate_entropy(bytes(range(256)))
    assert abs(ent_random - 8.0) < 0.01

    # Test Sliding Window Entropy
    sample = (b"\x00" * 512) + bytes(range(256)) * 2
    curve = bridge.sliding_window_entropy(sample, window_size=256, step_size=64)
    assert len(curve) > 0
    assert curve[0] == 0.0

    # Test Pattern Scan with Wildcards
    code = b"\x55\x48\x89\xe5\x90\x90\xc3\x55\x48\x89\xe5\x00\x00\xc3"
    matches = bridge.pattern_scan(code, "55 48 89 e5 ?? ?? c3")
    assert len(matches) == 2
    assert matches[0] == 0
    assert matches[1] == 7

    # Test ROP Gadgets
    rop_code = b"\x5f\xc3\x5e\xc3\x5a\xc3\x0f\x05"
    gadgets = bridge.find_rop_gadgets(rop_code, base_vaddr=0x400000)
    assert len(gadgets) >= 4
    instrs = [g["instructions"] for g in gadgets]
    assert any("pop rdi ; ret" in s for s in instrs)
    assert any("pop rsi ; ret" in s for s in instrs)
    assert any("syscall" in s for s in instrs)

    # Test Shellcode Heuristics
    shell_data = (b"\x90" * 32) + b"\x0f\x05"
    heuristics = bridge.scan_shellcode_heuristics(shell_data)
    assert len(heuristics) >= 1
    types = [h["type"] for h in heuristics]
    assert "nop_sled" in types or "raw_syscall_x64" in types

    # Test Demangler
    dem = bridge.demangle_symbol("_Z3fooi")
    assert dem is not None
    assert "foo" in dem

    # Test Binary Similarity
    sim_ident = bridge.binary_similarity(code, code)
    assert sim_ident == 1.0

    diff_code = bytes(range(100))
    sim_diff = bridge.binary_similarity(code, diff_code)
    assert sim_diff < 0.5

    # Test Benchmark
    bench = bridge.benchmark(size_bytes=50000)
    assert "data_size_bytes" in bench
    assert bench["data_size_bytes"] == 50000
    assert "speedup_factor" in bench


def test_rop_analyzer(tmp_path: Path) -> None:
    bin_path = tmp_path / "rop_target.bin"
    # Create payload with gadgets
    bin_path.write_bytes(b"\x90" * 64 + b"\x5f\xc3\x5e\xc3\x5a\xc3\x0f\x05" + b"\x90" * 64)

    result = analyze_rop_gadgets(bin_path, max_gadgets=50)
    assert result["total_gadgets_found"] >= 3
    assert result["primitives"]["has_pop_rdi"] is True
    assert result["primitives"]["has_syscall"] is True
    assert len(result["hardening_advice"]) >= 3


def test_entropy_analyzer(tmp_path: Path) -> None:
    f_path = tmp_path / "entropy_target.bin"
    f_path.write_bytes(b"A" * 512 + bytes(range(256)) * 2)

    result = analyze_sliding_entropy(f_path, window_size=256, step_size=64, visualize=True)
    assert result["file_size"] == 1024
    assert result["min_entropy"] < result["max_entropy"]
    assert len(result["sparkline"]) > 0
    assert len(result["ascii_graph"]) > 0

    spark = render_ascii_sparkline([0.0, 2.0, 4.0, 6.0, 8.0])
    assert len(spark) == 5
    bars = render_entropy_bars([0.0, 4.0, 8.0])
    assert "|" in bars


def test_signatures_scanner(tmp_path: Path) -> None:
    f_path = tmp_path / "suspect.bin"
    content = b"UPX! something in the binary TracerPid: 0 ptrace and AES " + bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
    f_path.write_bytes(content)

    result = scan_signatures(f_path)
    assert result["total_signatures_matched"] >= 2
    rule_ids = [m["rule_id"] for m in result["matches"]]
    assert "sig-packer-upx" in rule_ids
    assert "sig-antidebug-tracerpid" in rule_ids or "sig-crypto-aes-sbox" in rule_ids


def test_binary_diffing(tmp_path: Path) -> None:
    f1 = tmp_path / "bin1.bin"
    f2 = tmp_path / "bin2.bin"

    f1.write_bytes(create_sample_elf())
    f2.write_bytes(create_sample_elf() + b"extra_payload\x00")

    result = diff_binaries(f1, f2)
    assert result["identical"] is False
    assert result["similarity_score"] > 0.5
    assert "verdict" in result
    assert result["file1"]["format"] == "ELF"
    assert result["file2"]["format"] == "ELF"


def test_sarif_generation(tmp_path: Path) -> None:
    findings = [
        {
            "id": "find-1",
            "rule": "sec-c-unsafe-strcpy",
            "severity": "critical",
            "title": "Unbounded Buffer Copy via strcpy",
            "description": "Buffer overflow risk.",
            "file": "src/vuln.c",
            "line": 42,
            "remediation": "Use strncpy or std::string.",
            "references": ["https://cwe.mitre.org/data/definitions/120.html"],
        }
    ]

    sarif = findings_to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Wizard Cybersecurity Platform"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "sec-c-unsafe-strcpy"
    assert run["results"][0]["level"] == "error"

    sarif_file = tmp_path / "audit.sarif"
    write_sarif_file(findings, sarif_file)
    assert sarif_file.is_file()
    assert "Wizard Cybersecurity Platform" in sarif_file.read_text(encoding="utf-8")


def test_advanced_security_rules(tmp_path: Path) -> None:
    c_file = tmp_path / "target.c"
    c_file.write_text(
        """
        #include <stdio.h>
        #include <string.h>

        void test(char *input) {
            char buf[64];
            strcpy(buf, input);
            sprintf(buf, "%s", input);
            gets(buf);
            printf(input);
            access("/tmp/file", 0);
            if (1) { fopen("/tmp/file", "r"); }
        }
        """
    )

    py_file = tmp_path / "web.py"
    py_file.write_text(
        """
        import requests
        import jwt

        def handle(url, user_prompt):
            token = jwt.sign({"sub": "admin"}, "super_secret_jwt_key_12345")
            resp = requests.get(url, verify=False)
            prompt = f"Summarize: {user_prompt}"
            return resp.text
        """
    )

    result = analyze_security(tmp_path)
    rules_triggered = [f["rule"] for f in result.get("findings", [])]

    assert "sec-c-unsafe-strcpy" in rules_triggered
    assert "sec-c-unsafe-sprintf" in rules_triggered
    assert "sec-c-unsafe-gets" in rules_triggered
    assert "sec-c-format-string" in rules_triggered
    assert "sec-insecure-tls-bypass" in rules_triggered
    assert "sec-ssrf-unvalidated-request" in rules_triggered
    assert "sec-llm-prompt-injection-hazard" in rules_triggered


def test_advanced_api_endpoints() -> None:
    # 1. Native status
    res = client.get("/api/reverse-engineering/native")
    assert res.status_code == 200
    data = res.json()
    assert "native_loaded" in data
    assert "benchmark" in data

    # 2. Upload ROP Gadgets
    rop_bytes = b"\x5f\xc3\x5e\xc3\x0f\x05"
    files = {"file": ("gadget_test.bin", rop_bytes, "application/octet-stream")}
    res = client.post("/api/reverse-engineering/gadgets", files=files)
    assert res.status_code == 200
    g_data = res.json()
    assert g_data["total_gadgets_found"] >= 2

    # 3. Sliding Entropy
    ent_bytes = b"\x00" * 256 + bytes(range(256))
    files = {"file": ("entropy_test.bin", ent_bytes, "application/octet-stream")}
    res = client.post("/api/reverse-engineering/entropy", files=files)
    assert res.status_code == 200
    e_data = res.json()
    assert "sparkline" in e_data
    assert "overall_entropy" in e_data

    # 4. Binary Diff
    files_diff = {
        "file1": ("f1.bin", b"AAAA" * 64, "application/octet-stream"),
        "file2": ("f2.bin", b"AAAA" * 64, "application/octet-stream"),
    }
    res = client.post("/api/reverse-engineering/diff", files=files_diff)
    assert res.status_code == 200
    d_data = res.json()
    assert d_data["identical"] is True
    assert d_data["similarity_score"] == 1.0

    # 5. Signature Scan
    sig_bytes = b"Some binary with UPX! tag and TracerPid:"
    files_sig = {"file": ("sig.bin", sig_bytes, "application/octet-stream")}
    res = client.post("/api/reverse-engineering/scan", files=files_sig)
    assert res.status_code == 200
    s_data = res.json()
    assert s_data["total_signatures_matched"] >= 1
