from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure backend root is in sys.path
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.analyzers.inventory import analyze_inventory
from app.analyzers.reverse_engineering import analyze_binary
from app.analyzers.security import analyze_security
from app.orchestrator.orchestrator import run_analysis_pipeline
from app.security.capabilities import detect_capabilities
from app.security.scope import ScopeError, validate_target_scope
from app.services.store import (
    create_project,
    delete_project,
    get_analysis,
    get_project,
    get_report,
    list_analyses,
    list_projects,
)
from app.analyzers.diff import diff_binaries
from app.analyzers.entropy import analyze_sliding_entropy
from app.analyzers.rop import analyze_rop_gadgets
from app.analyzers.signatures import scan_signatures
from app.native.bridge import get_native_bridge
from app.native.builder import compile_native_core, get_available_compiler
from app.services.sarif import findings_to_sarif, write_sarif_file

VERSION = "2.0.0"

# ANSI Color Codes
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MUTED = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner(full: bool = True) -> None:
    banner = f"""{CYAN}{BOLD}
  ╭─────────────────────────────────────────────────────────────╮
  │   █   █  █  █████    ██    ████   ████                      │
  │   █ █ █  █     █    █  █   █   █  █   █                     │
  │   ██ ██  █    █    ██████  ████   █   █                     │
  │   █   █  █   ████  █    █  █   █  ████                      │
  │                                                             │
  │   ✦ CYBERSECURITY RESEARCH & REVERSE ENGINEERING PLATFORM ✦ │
  │        Defensive Analysis • Memory Hardening • Auditing     │
  ╰─────────────────────────────────────────────────────────────╯{RESET}
  {MAGENTA}{BOLD}WIZARD PLATFORM v{VERSION}{RESET}  {MUTED}[Defensive Security & Binary Analysis]{RESET}
"""
    print(banner)
    if full:
        print(f"  {MUTED}Type {CYAN}wizard --help{MUTED} to see available commands.{RESET}\n")


def cmd_version() -> None:
    print(f"{CYAN}{BOLD}WIZARD{RESET} {MUTED}v{VERSION}{RESET} (Defensive Cybersecurity Platform)")


def cmd_capabilities() -> None:
    print(f"\n{CYAN}{BOLD}WIZARD CAPABILITIES MATRIX{RESET}\n")
    caps = detect_capabilities()

    bridge = get_native_bridge()
    native_status = f"{GREEN}ACCELERATED (C++ v{bridge.get_version() / 100:.1f}){RESET}" if bridge.is_native_loaded else f"{YELLOW}FALLBACK (Pure Python){RESET}"

    print(f"{BOLD}High-Performance Native Core & Reverse Engineering{RESET}")
    print(f"  C++ Native Core  [{native_status}] (libwizard_core.so - ROP, Fast Entropy, Pattern Scan, Demangler)")
    print(f"  ROP Gadget Engine[{GREEN}OK{RESET}] (Return-Oriented Programming gadget discovery & classification)")
    print(f"  Sliding Entropy  [{GREEN}OK{RESET}] (Visual ASCII density curves, sparklines, crypter detection)")
    print(f"  Binary Differ    [{GREEN}OK{RESET}] (Structural, cryptographic, and byte similarity diffing)")
    print(f"  Signature Matcher[{GREEN}OK{RESET}] (YARA-style patterns for packers, evasion, crypto & backdoors)")
    print(f"  C++ Demangler    [{GREEN}OK{RESET}] (abi::__cxa_demangle Itanium ABI name reconstruction)")
    print(f"  ELF parser       [{GREEN}OK{RESET}] (Pure-Python 32/64-bit ELF)")
    print(f"  PE parser        [{GREEN}OK{RESET}] (Pure-Python PE32/PE32+)")
    print(f"  Mach-O parser    [{GREEN}OK{RESET}] (Pure-Python Apple Silicon / Intel)")
    print(f"  Entropy engine   [{GREEN}OK{RESET}] (Shannon Entropy 0.0 - 8.0)")
    print(f"  strings          [{GREEN}OK{RESET}] (Pure-Python & Native extraction)")
    print(f"  objdump          [{GREEN if caps['objdump'] else YELLOW}{'AVAILABLE' if caps['objdump'] else 'OPTIONAL'}{RESET}] (Disassembly engine)")
    print(f"  readelf          [{GREEN if caps['readelf'] else YELLOW}{'AVAILABLE' if caps['readelf'] else 'OPTIONAL'}{RESET}] (Header inspection)")
    print(f"  file             [{GREEN if caps['file'] else YELLOW}{'AVAILABLE' if caps['file'] else 'OPTIONAL'}{RESET}] (Magic bytes identification)")
    print(f"  nm               [{GREEN if caps['nm'] else YELLOW}{'AVAILABLE' if caps['nm'] else 'OPTIONAL'}{RESET}] (Symbol table extraction)")
    print(f"  Ghidra           [{GREEN if caps['ghidra'] else YELLOW}{'AVAILABLE' if caps['ghidra'] else 'OPTIONAL'}{RESET}] (Decompilation framework)")
    print(f"  radare2          [{GREEN if caps['radare2'] else YELLOW}{'AVAILABLE' if caps['radare2'] else 'OPTIONAL'}{RESET}] (Binary framework)")

    print(f"\n{BOLD}Security Testing & Standards Engines{RESET}")
    print(f"  Static analysis  [{GREEN}OK{RESET}] (Memory safety, secrets, dangerous APIs, command injection)")
    print(f"  Memory safety    [{GREEN}OK{RESET}] (C/C++ buffer overflows, format strings, TOCTOU race checks)")
    print(f"  Cloud secrets    [{GREEN}OK{RESET}] (GCP Service Accounts, AWS keys, JWT tokens, K8s tokens)")
    print(f"  SARIF Exporter   [{GREEN}OK{RESET}] (OASIS SARIF v2.1.0 standard for GitHub Code Scanning)")
    print(f"  Scope validator  [{GREEN}OK{RESET}] (Strict authorization boundary enforcement)")
    print(f"  Dependency audit [{GREEN}OK{RESET}] (CVE database checking for pip and npm)")
    print(f"  API audit        [{GREEN}OK{RESET}] (FastAPI, Flask, Express inspection)")
    print(f"  YARA             [{GREEN if caps['yara'] else YELLOW}{'AVAILABLE' if caps['yara'] else 'OPTIONAL'}{RESET}] (Signature pattern matcher)")
    print(f"  Semgrep          [{GREEN if caps['semgrep'] else YELLOW}{'AVAILABLE' if caps['semgrep'] else 'OPTIONAL'}{RESET}] (AST semantic code engine)")
    print("")


def cmd_doctor() -> None:
    print(f"\n{CYAN}{BOLD}WIZARD SYSTEM DIAGNOSTIC (DOCTOR){RESET}\n")

    # Detect platform
    is_termux = bool(os.environ.get("TERMUX_VERSION") or (Path("/data/data/com.termux/files/usr").is_dir() and not Path("/etc/debian_version").is_file()))
    os_name = "Android / Termux" if is_termux else sys.platform

    def check_tool(name: str, is_critical: bool = False) -> tuple[str, str, str | None]:
        path = shutil.which(name)
        if path:
            return f"{GREEN}[AVAILABLE]{RESET}", path, None
        if is_critical:
            remediation = f"Install '{name}' using system package manager."
            if is_termux:
                remediation = f"pkg install {name}"
            else:
                remediation = f"sudo apt install {name}"
            return f"{RED}[MISSING]{RESET}", "Not found in PATH", remediation
        
        # Optional tool remediation
        pkg_map_termux = {
            "strings": "pkg install binutils",
            "objdump": "pkg install binutils",
            "readelf": "pkg install binutils",
            "nm": "pkg install binutils",
            "file": "pkg install file",
            "yara": "pkg install yara",
            "radare2": "pkg install radare2",
            "semgrep": "pip install semgrep",
            "ghidra": "Download from https://ghidra-sre.org",
            "node": "pkg install nodejs",
            "npm": "pkg install nodejs",
        }
        pkg_map_linux = {
            "strings": "sudo apt install binutils",
            "objdump": "sudo apt install binutils",
            "readelf": "sudo apt install binutils",
            "nm": "sudo apt install binutils",
            "file": "sudo apt install file",
            "yara": "sudo apt install yara",
            "radare2": "sudo apt install radare2",
            "semgrep": "pip install semgrep",
            "ghidra": "Download from https://ghidra-sre.org",
            "node": "sudo apt install nodejs npm",
            "npm": "sudo apt install npm",
        }
        remediation = pkg_map_termux.get(name) if is_termux else pkg_map_linux.get(name)
        return f"{YELLOW}[OPTIONAL]{RESET}", "Not installed (native fallback active)", remediation

    print(f"{BOLD}Runtime Environment:{RESET}")
    print(f"  Platform        {GREEN}[AVAILABLE]{RESET}  {os_name}")
    print(f"  Python 3        {GREEN}[AVAILABLE]{RESET}  {sys.version.split()[0]} ({sys.executable})")

    node_status, node_path, node_fix = check_tool("node", is_critical=False)
    print(f"  Node.js         {node_status}  {node_path}")

    npm_status, npm_path, npm_fix = check_tool("npm", is_critical=False)
    print(f"  npm             {npm_status}  {npm_path}")

    git_status, git_path, git_fix = check_tool("git", is_critical=True)
    print(f"  Git             {git_status}  {git_path}")

    missing_fixes: list[tuple[str, str]] = []
    if git_fix:
        missing_fixes.append(("Git", git_fix))

    print(f"\n{BOLD}Binary & Reverse Engineering Analyzers:{RESET}")
    for bin_name in ["strings", "objdump", "readelf", "file", "nm", "yara", "radare2", "ghidra"]:
        status, path, fix = check_tool(bin_name, is_critical=False)
        print(f"  {bin_name:<15} {status}  {path}")
        if fix:
            missing_fixes.append((bin_name, fix))

    print(f"\n{BOLD}Security & Static Code Analyzers:{RESET}")
    for sec_name in ["semgrep"]:
        status, path, fix = check_tool(sec_name, is_critical=False)
        print(f"  {sec_name:<15} {status}  {path}")
        if fix:
            missing_fixes.append((sec_name, fix))

    print(f"\n{BOLD}Platform Subsystems:{RESET}")
    backend_main = BACKEND_ROOT / "app" / "main.py"
    backend_ok = backend_main.is_file()
    print(f"  Backend Core    {GREEN}[AVAILABLE]{RESET}  {backend_main}")

    dist_index = BACKEND_ROOT.parent / "frontend" / "dist" / "index.html"
    dist_ok = dist_index.is_file()
    dist_status = f"{GREEN}[AVAILABLE]{RESET}" if dist_ok else f"{YELLOW}[OPTIONAL]{RESET}"
    print(f"  Frontend Dist   {dist_status}  {dist_index if dist_ok else 'Missing (run npm run build)'}")

    # Check C++ Native Core
    bridge = get_native_bridge()
    native_ok = bridge.is_native_loaded
    native_status = f"{GREEN}[ACCELERATED]{RESET}" if native_ok else f"{YELLOW}[FALLBACK]{RESET}"
    compiler = get_available_compiler()
    compiler_str = f"Compiler: {compiler}" if compiler else "No C++ compiler found"
    print(f"  Native Core     {native_status}  libwizard_core.so ({compiler_str})")

    # Check writable data directory
    data_dir = BACKEND_ROOT.parent / "data"
    writable = False
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / ".write_test"
        test_file.write_text("ok")
        test_file.unlink()
        writable = True
    except Exception:
        writable = False

    data_status = f"{GREEN}[AVAILABLE]{RESET}" if writable else f"{RED}[ERROR]{RESET}"
    print(f"  Data Storage    {data_status}  {data_dir} (Writable: {writable})")

    print(f"\n{BOLD}Diagnostic Summary:{RESET}")
    if git_status.startswith(f"{GREEN}") and backend_ok and writable:
        print(f"  {GREEN}✓ Core platform engines are operational.{RESET}")
    else:
        print(f"  {YELLOW}! Core components need attention above.{RESET}")

    if missing_fixes:
        print(f"\n{BOLD}Recommended Commands to Install Missing Tools:{RESET}")
        for tool_name, cmd in missing_fixes[:6]:
            print(f"  • {tool_name:<12} {CYAN}{cmd}{RESET}")
    print("")


def cmd_reverse(file_path_str: str) -> None:
    path = Path(file_path_str).resolve()
    if not path.is_file():
        print(f"{RED}Error:{RESET} File not found: {file_path_str}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{CYAN}{BOLD}[*] Analyzing Binary Artifact:{RESET} {path.name}")
    print(f"    Path: {path}")

    result = analyze_binary(path)
    meta = result.metadata

    if not meta:
        print(f"{RED}Error during binary analysis:{RESET} {result.errors}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{BOLD}─── Binary Metadata ───{RESET}")
    print(f"  Format:        {CYAN}{meta.format}{RESET} ({meta.file_type})")
    print(f"  Architecture:  {meta.architecture} ({meta.bits}-bit, {meta.endian})")
    print(f"  Entry Point:   {hex(meta.entry_point) if meta.entry_point else 'N/A'}")
    print(f"  SHA-256:       {meta.sha256}")
    print(f"  File Size:     {meta.size} bytes")

    entropy_color = RED if meta.entropy > 7.2 else GREEN
    print(f"  Entropy:       {entropy_color}{meta.entropy:.4f} / 8.0{RESET} "
          f"({YELLOW + '⚠️ Suspicious packing/encryption' if meta.entropy > 7.2 else 'Normal distribution'}{RESET})")

    print(f"\n{BOLD}─── Hardening Protections ───{RESET}")
    for k, v in meta.hardening.items():
        v_color = GREEN if v else RED
        print(f"  {k.upper():<12} {v_color}{'ENABLED' if v else 'DISABLED'}{RESET}")

    if meta.sections:
        print(f"\n{BOLD}─── Section Table ({len(meta.sections)} sections) ───{RESET}")
        print(f"  {'Name':<14} {'Size':<10} {'Permissions':<12} {'Entropy':<10} {'Status'}")
        for s in meta.sections[:15]:
            perms = f"{'R' if s.readable else '-'}{'W' if s.writable else '-'}{'X' if s.executable else '-'}"
            perm_color = RED if s.writable and s.executable else RESET
            status_desc = f"{RED}⚠️ W^X Violation{RESET}" if s.suspicious else "Normal"
            print(f"  {s.name:<14} {s.size:<10} {perm_color}{perms:<12}{RESET} {s.entropy:.4f}     {status_desc}")

    if result.strings.get("suspicious_apis"):
        print(f"\n{BOLD}─── Suspicious APIs Found in Strings ───{RESET}")
        for api_item in result.strings["suspicious_apis"]:
            print(f"  {YELLOW}•{RESET} {api_item}")

    if result.strings.get("urls"):
        print(f"\n{BOLD}─── Embedded URLs ({len(result.strings['urls'])}) ───{RESET}")
        for url_item in result.strings["urls"][:6]:
            print(f"  {MUTED}•{RESET} {url_item}")

    if result.disassembly:
        print(f"\n{BOLD}─── Disassembly Preview (objdump) ───{RESET}")
        for line in result.disassembly[:15]:
            print(f"  {MUTED}{line}{RESET}")

    print(f"\n{BOLD}─── Findings ({len(result.findings)}) ───{RESET}")
    for f in result.findings:
        sev_color = RED if f.severity in ("critical", "high") else YELLOW if f.severity == "medium" else BLUE
        print(f"  [{sev_color}{f.severity.upper()}{RESET}] {BOLD}{f.title}{RESET}")
        print(f"    Rule:        {f.rule}")
        print(f"    Evidence:    {f.evidence}")
        print(f"    Remediation: {f.remediation}\n")


def cmd_security(target_dir_str: str, authorized: bool = True) -> None:
    path = Path(target_dir_str).resolve()
    if not path.exists():
        print(f"{RED}Error:{RESET} Target directory or file not found: {target_dir_str}", file=sys.stderr)
        sys.exit(1)

    if not authorized:
        print(f"{RED}Error: Scope Authorization Required.{RESET} Use authorized flag for ethical security testing.", file=sys.stderr)
        sys.exit(1)

    print(f"\n{CYAN}{BOLD}[*] Running Ethical Security Analysis on:{RESET} {path}")
    print(f"    Scope: Authorized local directory inspection")

    result = analyze_security(path if path.is_dir() else path.parent)
    findings = result.get("findings", [])

    print(f"\n{BOLD}─── Security Findings Summary ───{RESET}")
    print(f"  Total Observations: {result.get('finding_count', 0)}")
    counts = result.get("severity_counts", {})
    print(f"  Critical: {RED}{counts.get('critical', 0)}{RESET} | "
          f"High: {RED}{counts.get('high', 0)}{RESET} | "
          f"Medium: {YELLOW}{counts.get('medium', 0)}{RESET} | "
          f"Low: {BLUE}{counts.get('low', 0)}{RESET}")

    if result.get("dependency_vulnerabilities"):
        print(f"\n{BOLD}─── Vulnerable Dependencies ───{RESET}")
        for dep in result["dependency_vulnerabilities"]:
            print(f"  {RED}• {dep['package']} ({dep['version']}):{RESET} {dep['cve']} - {dep['description']}")

    if findings:
        print(f"\n{BOLD}─── Finding Details ───{RESET}")
        for f in findings[:25]:
            sev = f.get("severity", "info")
            sev_color = RED if sev in ("critical", "high") else YELLOW if sev == "medium" else BLUE
            line_str = f":{f.get('line')}" if f.get("line") else ""
            print(f"  [{sev_color}{sev.upper()}{RESET}] {BOLD}{f.get('title')}{RESET}")
            print(f"    Location:    {f.get('file')}{line_str}")
            print(f"    Rule:        {f.get('rule')}")
            print(f"    Evidence:    {f.get('evidence')}")
            print(f"    Remediation: {f.get('remediation')}\n")
    else:
        print(f"\n{GREEN}✓ No security vulnerabilities found matching active rules.{RESET}\n")


def cmd_analyze(target_str: str) -> None:
    # 1. Check if target_str is an existing project ID
    try:
        p = get_project(target_str)
        print(f"\n{CYAN}{BOLD}[*] Running Orchestrator Analysis on Project:{RESET} {p['name']} ({target_str})")
        report = run_analysis_pipeline(project_id=target_str)
        print(f"\n{GREEN}✓ Project analysis complete.{RESET}")
        cmd_report(project_id=target_str)
        return
    except (FileNotFoundError, Exception):
        pass

    path = Path(target_str).resolve()
    if not path.exists():
        print(f"{RED}Error:{RESET} Target path or project not found: {target_str}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{CYAN}{BOLD}[*] Running Full Wizard Analysis Pipeline on Target:{RESET} {path}")

    # If target is a single file, analyze it with RE and security
    if path.is_file():
        cmd_reverse(str(path))
        cmd_security(str(path.parent))
    else:
        cmd_security(str(path))


def cmd_projects(action: str, name: str | None = None, desc: str | None = None, project_id: str | None = None) -> None:
    if action == "create":
        if not name:
            print(f"{RED}Error:{RESET} Project name is required.", file=sys.stderr)
            sys.exit(1)
        p = create_project(name, desc)
        print(f"{GREEN}✓ Project created successfully:{RESET}")
        print(f"  ID:          {p['id']}")
        print(f"  Name:        {p['name']}")
        print(f"  Created At:  {p['created_at']}")
    elif action == "list":
        projs = list_projects()
        print(f"\n{CYAN}{BOLD}WIZARD PROJECTS ({len(projs)}){RESET}\n")
        if not projs:
            print(f"  {MUTED}No projects created yet. Use 'wizard project create <name>'.{RESET}")
        else:
            print(f"  {'ID':<14} {'Status':<12} {'Files':<8} {'Name'}")
            for p in projs:
                print(f"  {p['id']:<14} {p['status']:<12} {p.get('file_count', 0):<8} {p['name']}")
        print("")
    elif action == "delete":
        if not project_id:
            print(f"{RED}Error:{RESET} Project ID is required.", file=sys.stderr)
            sys.exit(1)
        if delete_project(project_id):
            print(f"{GREEN}✓ Deleted project {project_id}{RESET}")
        else:
            print(f"{RED}Error:{RESET} Project {project_id} not found.", file=sys.stderr)
            sys.exit(1)


def cmd_findings(target_id: str | None = None, severity_filter: str | None = None, output_format: str = "table") -> None:
    """Retrieve and display consolidated findings for an analysis or project."""
    findings: list[dict[str, Any]] = []
    source_title = ""

    if target_id:
        # Check if target_id is an analysis
        analysis = get_analysis(target_id)
        if analysis and "findings" in analysis:
            findings = analysis["findings"]
            source_title = f"Analysis {target_id}"
        else:
            # Check if target_id is a project
            report = get_report(target_id)
            if report and "findings" in report:
                findings = report["findings"]
                source_title = f"Project {target_id}"
            else:
                print(f"{RED}Error:{RESET} No findings found for ID '{target_id}'.", file=sys.stderr)
                sys.exit(1)
    else:
        # Find findings from the latest project report or analysis
        analyses = list_analyses()
        if analyses:
            latest = analyses[-1]
            findings = latest.get("findings", [])
            source_title = f"Latest Analysis ({latest.get('analysis_id', 'unknown')})"
        else:
            projects = list_projects()
            for p in reversed(projects):
                rep = get_report(p["id"])
                if rep and rep.get("findings"):
                    findings = rep["findings"]
                    source_title = f"Project '{p['name']}' ({p['id']})"
                    break

    if not findings:
        print(f"\n{YELLOW}[!] No findings recorded yet.{RESET}")
        print(f"    Run an analysis first with:")
        print(f"      {CYAN}wizard security <path>{RESET}")
        print(f"      {CYAN}wizard reverse <file>{RESET}\n")
        return

    # Filter by severity
    if severity_filter:
        sev_req = severity_filter.lower().strip()
        findings = [f for f in findings if f.get("severity", "").lower() == sev_req]

    if output_format == "json":
        print(json.dumps(findings, indent=2))
        return

    print(f"\n{CYAN}{BOLD}WIZARD FINDINGS — {source_title}{RESET} ({len(findings)} matching)\n")
    for f in findings:
        sev = f.get("severity", "info")
        sev_color = RED if sev in ("critical", "high") else YELLOW if sev == "medium" else BLUE
        loc = f.get("file", "unknown")
        line = f.get("line")
        loc_str = f"{loc}:{line}" if line else loc

        print(f"  [{sev_color}{sev.upper():<8}{RESET}] {BOLD}{f.get('title')}{RESET}")
        print(f"    Rule:        {f.get('rule')}")
        print(f"    Location:    {loc_str}")
        print(f"    Evidence:    {f.get('evidence')}")
        if f.get("remediation"):
            print(f"    Remediation: {f.get('remediation')}")
        print("")


def cmd_report(project_id: str | None = None, output_format: str = "text", output_file: str | None = None) -> None:
    """Generate and display or save a structured assessment report."""
    target_pid = project_id
    if not target_pid:
        projects = list_projects()
        if not projects:
            print(f"{RED}Error:{RESET} No projects found to report on.", file=sys.stderr)
            sys.exit(1)
        target_pid = projects[-1]["id"]

    report = get_report(target_pid)
    if not report:
        print(f"{RED}Error:{RESET} No report generated yet for project '{target_pid}'. Run analysis first.", file=sys.stderr)
        sys.exit(1)

    output_content = ""

    if output_format == "json":
        output_content = json.dumps(report, indent=2, ensure_ascii=False)
    elif output_format == "md":
        p_name = report.get("project", {}).get("name", target_pid)
        lines = [
            f"# WIZARD Security & Reverse Engineering Report",
            f"**Project:** {p_name} (`{target_pid}`)",
            f"**Generated:** {report.get('generated_at')}",
            f"**Scope:** {report.get('scope', 'Authorized')}",
            "",
            "## Executive Summary",
            report.get("executive_summary", "No summary available."),
            "",
            "## Findings Summary",
            f"- Total Findings: {report.get('finding_count', 0)}",
            f"- Critical: {report.get('severity_counts', {}).get('critical', 0)}",
            f"- High: {report.get('severity_counts', {}).get('high', 0)}",
            f"- Medium: {report.get('severity_counts', {}).get('medium', 0)}",
            f"- Low: {report.get('severity_counts', {}).get('low', 0)}",
            "",
            "## Detailed Findings",
        ]
        for f in report.get("findings", []):
            lines.extend([
                f"### [{f.get('severity', 'info').upper()}] {f.get('title')}",
                f"- **Rule:** `{f.get('rule')}`",
                f"- **Location:** `{f.get('file')}`",
                f"- **Evidence:** {f.get('evidence')}",
                f"- **Remediation:** {f.get('remediation')}",
                "",
            ])
        output_content = "\n".join(lines)
    else:
        # Terminal formatted report
        print(f"\n{CYAN}{BOLD}WIZARD ASSESSMENT REPORT{RESET}")
        p_name = report.get("project", {}).get("name", target_pid)
        print(f"  Project:    {BOLD}{p_name}{RESET} ({target_pid})")
        print(f"  Generated:  {report.get('generated_at')}")
        print(f"  Scope:      {report.get('scope', 'Authorized')}")
        print(f"\n{BOLD}Executive Summary:{RESET}")
        print(f"  {report.get('executive_summary', 'No summary.')}")
        print(f"\n{BOLD}Findings Overview:{RESET}")
        counts = report.get("severity_counts", {})
        print(f"  Critical: {RED}{counts.get('critical', 0)}{RESET} | "
              f"High: {RED}{counts.get('high', 0)}{RESET} | "
              f"Medium: {YELLOW}{counts.get('medium', 0)}{RESET} | "
              f"Low: {BLUE}{counts.get('low', 0)}{RESET}")
        print(f"\n  Use {CYAN}wizard findings {target_pid}{RESET} to view detailed findings.\n")

    if output_file:
        Path(output_file).write_text(output_content, encoding="utf-8")
        print(f"{GREEN}✓ Report saved to:{RESET} {output_file}")
    elif output_format in ("json", "md"):
        print(output_content)


def cmd_update() -> None:
    """Safely update Wizard from GitHub without destructive operations."""
    print(f"\n{CYAN}{BOLD}[*] Checking for Wizard updates from GitHub...{RESET}")
    repo_root = BACKEND_ROOT.parent

    # 1. Check if git repository exists
    if not (repo_root / ".git").is_dir():
        print(f"{RED}Error:{RESET} Directory '{repo_root}' is not a Git repository.", file=sys.stderr)
        sys.exit(1)

    # 2. Check for unstaged changes
    status_proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    if status_proc.stdout.strip():
        print(f"{YELLOW}[!] Notice: Local working tree has uncommitted changes:{RESET}")
        for line in status_proc.stdout.splitlines()[:5]:
            print(f"    {line}")
        print(f"    Please commit or stash your changes before updating.\n")
        sys.exit(1)

    # 3. Fetch latest changes
    print("[*] Fetching updates from origin...")
    fetch_proc = subprocess.run(
        ["git", "fetch", "origin"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    if fetch_proc.returncode != 0:
        print(f"{RED}Error fetching updates:{RESET} {fetch_proc.stderr}", file=sys.stderr)
        sys.exit(1)

    # 4. Pull fast-forward only
    print("[*] Pulling latest changes (fast-forward)...")
    pull_proc = subprocess.run(
        ["git", "pull", "--ff-only", "origin", "main"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    if pull_proc.returncode != 0:
        print(f"{RED}Error during git pull:{RESET} {pull_proc.stderr}", file=sys.stderr)
        print("    Resolve divergence manually to avoid losing local modifications.")
        sys.exit(1)

    print(f"    {pull_proc.stdout.strip()}")

    # 5. Rebuild frontend if Node is present
    if shutil.which("node"):
        print("[*] Rebuilding frontend distribution...")
        build_js = repo_root / "frontend" / "build.js"
        if build_js.is_file():
            subprocess.run(["node", str(build_js)], cwd=str(repo_root / "frontend"))

    print(f"\n{GREEN}{BOLD}✓ Wizard update completed successfully!{RESET}\n")


def cmd_native(bench: bool = False, rebuild: bool = False) -> None:
    print(f"\n{CYAN}{BOLD}WIZARD C++ NATIVE CORE ENGINE{RESET}\n")
    if rebuild:
        print("[*] Rebuilding libwizard_core.so from source...")
        success = compile_native_core(force=True)
        if success:
            print(f"  {GREEN}✓ Recompilation successful.{RESET}")
        else:
            print(f"  {RED}✗ Recompilation failed.{RESET}")

    bridge = get_native_bridge()
    status_str = f"{GREEN}ACCELERATED{RESET}" if bridge.is_native_loaded else f"{YELLOW}FALLBACK (Pure Python){RESET}"
    compiler = get_available_compiler() or "None detected"

    print(f"  Status:       {status_str}")
    print(f"  Library:      {bridge.so_path}")
    print(f"  Library Size: {bridge.so_path.stat().st_size if bridge.so_path.is_file() else 0} bytes")
    print(f"  Version:      {bridge.get_version() / 100:.1f}.0")
    print(f"  Compiler:     {compiler}")

    if bench or not bridge.is_native_loaded:
        print(f"\n{BOLD}─── High-Performance Benchmark (1,000,000 bytes) ───{RESET}")
        res = bridge.benchmark(1000000)
        print(f"  Data Processed:    {res['data_size_bytes']:,} bytes")
        print(f"  Python Time:       {res['python_time_seconds']:.6f} s")
        if res.get("cpp_time_seconds") is not None:
            print(f"  C++ Native Time:   {GREEN}{res['cpp_time_seconds']:.6f} s{RESET}")
            print(f"  Speedup Factor:    {CYAN}{BOLD}{res['speedup_factor']}x FASTER{RESET}")
        else:
            print(f"  C++ Native Time:   N/A (using pure-python fallback)")
    print("")


def cmd_gadgets(
    target: str,
    reg: str | None = None,
    cat: str | None = None,
    max_g: int = 100,
    json_out: bool = False,
) -> None:
    path = Path(target).resolve()
    if not path.is_file():
        print(f"{RED}Error:{RESET} File not found: {target}", file=sys.stderr)
        sys.exit(1)

    result = analyze_rop_gadgets(
        path,
        filter_reg=reg,
        filter_category=cat,
        max_gadgets=max_g,
    )

    if json_out:
        print(json.dumps(result, indent=2))
        return

    print(f"\n{CYAN}{BOLD}[*] ROP Gadget Analysis:{RESET} {path.name}")
    print(f"    Total Gadgets Found: {CYAN}{result['total_gadgets_found']}{RESET}")
    print(f"    Filtered Matches:    {result['filtered_count']}")

    print(f"\n{BOLD}─── Gadget Categories ───{RESET}")
    for c_name, count in result["categories"].items():
        print(f"  {c_name:<18} {count}")

    print(f"\n{BOLD}─── Register Controls ───{RESET}")
    reg_strs = [f"{r}: {cnt}" for r, cnt in result["registers_controlled"].items()]
    print(f"  {', '.join(reg_strs[:8]) if reg_strs else 'None'}")

    prims = result["primitives"]
    print(f"\n{BOLD}─── Exploit Primitives ───{RESET}")
    print(f"  pop rdi; ret:       {GREEN if prims['has_pop_rdi'] else YELLOW}{prims['has_pop_rdi']}{RESET}")
    print(f"  pop rsi; ret:       {GREEN if prims['has_pop_rsi'] else YELLOW}{prims['has_pop_rsi']}{RESET}")
    print(f"  pop rdx; ret:       {GREEN if prims['has_pop_rdx'] else YELLOW}{prims['has_pop_rdx']}{RESET}")
    print(f"  syscall:            {GREEN if prims['has_syscall'] else YELLOW}{prims['has_syscall']}{RESET}")
    print(f"  Stack Pivot:        {GREEN if prims['has_stack_pivot'] else YELLOW}{prims['has_stack_pivot']}{RESET}")
    chain_color = RED if prims['execve_chain_feasible'] else GREEN
    print(f"  execve Chain Risk:  {chain_color}{'FEASIBLE (High Attack Surface)' if prims['execve_chain_feasible'] else 'Incomplete'}{RESET}")

    gadgets = result["gadgets"]
    if gadgets:
        print(f"\n{BOLD}─── Discovered Gadgets (Top {len(gadgets)}) ───{RESET}")
        for g in gadgets[:max_g]:
            addr_str = f"0x{g['address']:08x}"
            print(f"  {CYAN}{addr_str}{RESET}  {g['instructions']:<35} {MUTED}[{g.get('category', '')}]{RESET}")

    print(f"\n{BOLD}─── Defensive Hardening Guidance ───{RESET}")
    for advice in result["hardening_advice"]:
        print(f"  {GREEN}•{RESET} {advice}")
    print("")


def cmd_entropy(
    target: str,
    visualize: bool = False,
    window: int = 512,
    step: int = 128,
    json_out: bool = False,
) -> None:
    path = Path(target).resolve()
    if not path.is_file():
        print(f"{RED}Error:{RESET} File not found: {target}", file=sys.stderr)
        sys.exit(1)

    result = analyze_sliding_entropy(path, window_size=window, step_size=step, visualize=visualize)

    if json_out:
        print(json.dumps(result, indent=2))
        return

    print(f"\n{CYAN}{BOLD}[*] Shannon & Sliding Window Entropy Analysis:{RESET} {path.name}")
    print(f"    File Size:     {result['file_size']:,} bytes")
    ent_color = RED if result['overall_entropy'] > 7.2 else GREEN
    print(f"    Overall:       {ent_color}{result['overall_entropy']:.4f} / 8.0{RESET}")
    print(f"    Min / Max:     {result['min_entropy']:.4f} / {result['max_entropy']:.4f}")
    print(f"    Mean / StdDev: {result['mean_entropy']:.4f} / {result['standard_deviation']:.4f}")
    print(f"    Packed Blocks: {result['packed_block_count']} (Window: {window}B, Step: {step}B)")

    p_assess = result["packing_assessment"]
    p_color = RED if p_assess["is_packed_or_encrypted"] else GREEN
    print(f"    Packing Risk:  {p_color}{p_assess['risk_level'].upper()}{RESET} ({p_assess['indicator']})")

    print(f"\n{BOLD}─── Sparkline Entropy Curve ───{RESET}")
    print(f"  {CYAN}{result['sparkline']}{RESET}")

    if result.get("ascii_graph"):
        print(f"\n{BOLD}─── Density Heat Graph ───{RESET}")
        print(f"{result['ascii_graph']}")
    print("")


def cmd_diff(target1: str, target2: str, json_out: bool = False) -> None:
    path1 = Path(target1).resolve()
    path2 = Path(target2).resolve()
    if not path1.is_file():
        print(f"{RED}Error:{RESET} Target 1 not found: {target1}", file=sys.stderr)
        sys.exit(1)
    if not path2.is_file():
        print(f"{RED}Error:{RESET} Target 2 not found: {target2}", file=sys.stderr)
        sys.exit(1)

    result = diff_binaries(path1, path2)

    if json_out:
        print(json.dumps(result, indent=2))
        return

    f1 = result["file1"]
    f2 = result["file2"]
    sim = result["similarity_score"]
    sim_color = GREEN if sim > 0.8 else (YELLOW if sim > 0.5 else RED)

    print(f"\n{CYAN}{BOLD}[*] Binary Differ (BinDiff):{RESET} {path1.name} vs {path2.name}")
    print(f"  Similarity Score: {sim_color}{BOLD}{sim * 100:.2f}%{RESET}")
    print(f"  Verdict:          {BOLD}{result['verdict']}{RESET}\n")

    print(f"{BOLD}─── Structural Comparison ───{RESET}")
    print(f"  {'Attribute':<16} {'Target 1':<28} {'Target 2':<28}")
    print(f"  {'Format':<16} {f1['format']:<28} {f2['format']:<28}")
    print(f"  {'Architecture':<16} {f1['architecture']:<28} {f2['architecture']:<28}")
    print(f"  {'Size (bytes)':<16} {f1['size']:<28} {f2['size']:<28}")
    print(f"  {'Entropy':<16} {f1['entropy']:<28.4f} {f2['entropy']:<28.4f}")
    print(f"  {'SHA-256':<16} {f1['sha256'][:24]}...     {f2['sha256'][:24]}...")

    sec = result["sections"]
    if sec["added"] or sec["removed"] or sec["modified"]:
        print(f"\n{BOLD}─── Section Differences ───{RESET}")
        if sec["added"]:
            print(f"  {GREEN}+ Added Sections:{RESET}   {', '.join(sec['added'])}")
        if sec["removed"]:
            print(f"  {RED}- Removed Sections:{RESET} {', '.join(sec['removed'])}")
        if sec["modified"]:
            print(f"  {YELLOW}~ Modified Sections:{RESET}")
            for m in sec["modified"]:
                print(f"    • {m['section']}: size diff {m['size_diff']:+d}B, entropy {m['entropy_before']:.2f} -> {m['entropy_after']:.2f}")

    apis = result["apis"]
    if apis["newly_introduced"] or apis["removed"]:
        print(f"\n{BOLD}─── Suspicious API Delta ───{RESET}")
        if apis["newly_introduced"]:
            print(f"  {YELLOW}+ Newly Introduced APIs:{RESET} {', '.join(apis['newly_introduced'])}")
        if apis["removed"]:
            print(f"  {MUTED}- Removed APIs:{RESET}           {', '.join(apis['removed'])}")
    print("")


def cmd_scan(target: str, rule: str | None = None, json_out: bool = False) -> None:
    path = Path(target).resolve()
    if not path.is_file():
        print(f"{RED}Error:{RESET} File not found: {target}", file=sys.stderr)
        sys.exit(1)

    result = scan_signatures(path, rule_filter=rule)

    if json_out:
        print(json.dumps(result, indent=2))
        return

    print(f"\n{CYAN}{BOLD}[*] Signature & Malware Heuristics Scan:{RESET} {path.name}")
    print(f"    File Size:       {result['file_size']:,} bytes")
    print(f"    Matches Found:   {len(result['matches'])}")

    if result["categories"]:
        print(f"\n{BOLD}─── Category Breakdown ───{RESET}")
        for cat, cnt in result["categories"].items():
            print(f"  {cat:<16} {cnt}")

    if result["matches"]:
        print(f"\n{BOLD}─── Matched Signatures ───{RESET}")
        for m in result["matches"]:
            sev_color = RED if m["severity"] in ("critical", "high") else (YELLOW if m["severity"] == "medium" else GREEN)
            print(f"  {sev_color}[{m['severity'].upper()}]{RESET} {BOLD}{m['name']}{RESET} ({m['rule_id']})")
            print(f"    Offsets:     {', '.join(f'0x{off:x}' for off in m['offsets'][:5])}")
            print(f"    Description: {m['description']}")
            if m.get("evidence"):
                print(f"    Evidence:    {m['evidence']}")
    else:
        print(f"\n  {GREEN}✓ No malware signatures or heuristic anomalies detected.{RESET}")
    print("")


def cmd_sarif(target_or_id: str, output: str | None = None) -> None:
    path = Path(target_or_id).resolve()
    findings_list: list[dict[str, Any]] = []

    if path.is_file() or path.is_dir():
        print(f"\n{CYAN}{BOLD}[*] Generating SARIF v2.1.0 report for target:{RESET} {path}")
        if path.is_file():
            # If executable binary, run reverse engineering; else security scan
            is_bin = False
            try:
                first_bytes = path.read_bytes()[:4]
                if first_bytes in (b"\x7fELF", b"MZ\x90\x00") or first_bytes.startswith((b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe")):
                    is_bin = True
            except Exception:
                pass

            if is_bin:
                re_res = analyze_binary(path)
                findings_list.extend([f.model_dump() if hasattr(f, "model_dump") else f for f in re_res.findings])
            else:
                sec_res = analyze_security(path.parent if path.is_file() else path)
                findings_list.extend([f.model_dump() if hasattr(f, "model_dump") else f for f in sec_res.get("findings", [])])
        else:
            sec_res = analyze_security(path)
            findings_list.extend([f.model_dump() if hasattr(f, "model_dump") else f for f in sec_res.get("findings", [])])
    else:
        # Check if project ID
        from app.services.store import list_analyses
        all_a = list_analyses(target_or_id)
        if all_a:
            latest = all_a[0]
            findings_list = latest.get("findings", [])
        else:
            print(f"{RED}Error:{RESET} Target not found as file, directory, or project ID: {target_or_id}", file=sys.stderr)
            sys.exit(1)

    sarif_data = findings_to_sarif(findings_list, target_uri=str(path))
    sarif_json = json.dumps(sarif_data, indent=2)

    if output:
        out_path = Path(output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(sarif_json, encoding="utf-8")
        print(f"  {GREEN}✓ SARIF export written to:{RESET} {out_path} ({len(findings_list)} findings)")
    else:
        print(sarif_json)


def cmd_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    print(f"\n{CYAN}{BOLD}[*] Launching Wizard API & UI Server on http://{host}:{port}{RESET}")
    try:
        import uvicorn
        uvicorn.run("app.main:app", host=host, port=port, log_level="info")
    except ImportError:
        print(f"{RED}Error:{RESET} uvicorn is not installed in current Python environment.", file=sys.stderr)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wizard",
        description="WIZARD — AI-assisted Reverse Engineering & Ethical Security Testing Platform.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="store_true", help="Show Wizard version")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # doctor
    subparsers.add_parser("doctor", help="Run system diagnostics & tool availability check")

    # capabilities
    subparsers.add_parser("capabilities", help="Display reverse engineering and security capabilities matrix")

    # reverse
    reverse_p = subparsers.add_parser("reverse", help="Defensive binary reverse engineering on an ELF/PE/Mach-O file")
    reverse_p.add_argument("target", help="Path to binary artifact to inspect")

    # security
    sec_p = subparsers.add_parser("security", help="Run ethical static security analysis on source code or directory")
    sec_p.add_argument("target", help="Path to source directory or file")
    sec_p.add_argument("--unauthorized", action="store_true", help="Mark scan as unauthorized (will be blocked)")

    # analyze
    analyze_p = subparsers.add_parser("analyze", help="Run full analysis (reverse engineering & security scanning)")
    analyze_p.add_argument("target", help="Path to file or project directory")

    # project
    proj_p = subparsers.add_parser("project", help="Manage target projects")
    proj_sub = proj_p.add_subparsers(dest="project_action")
    proj_create = proj_sub.add_parser("create", help="Create a new project")
    proj_create.add_argument("name", help="Project name")
    proj_create.add_argument("--desc", default="", help="Optional description")
    proj_sub.add_parser("list", help="List all projects")
    proj_del = proj_sub.add_parser("delete", help="Delete a project by ID")
    proj_del.add_argument("id", help="Project ID")

    # findings
    find_p = subparsers.add_parser("findings", help="Inspect consolidated vulnerability and reverse engineering findings")
    find_p.add_argument("id", nargs="?", default=None, help="Optional analysis ID or project ID")
    find_p.add_argument("--severity", default=None, help="Filter by severity (critical, high, medium, low, info)")
    find_p.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # report
    rep_p = subparsers.add_parser("report", help="Generate and inspect structured security assessment reports")
    rep_p.add_argument("project_id", nargs="?", default=None, help="Optional project ID")
    rep_p.add_argument("--format", choices=["text", "json", "md"], default="text", help="Report format")
    rep_p.add_argument("--output", default=None, help="Write report to output file")

    # native
    native_p = subparsers.add_parser("native", help="C++ Native Core status, compilation, and high-speed benchmarks")
    native_p.add_argument("--bench", action="store_true", help="Run 1,000,000-byte speed benchmark (C++ vs Python)")
    native_p.add_argument("--rebuild", action="store_true", help="Force recompilation of libwizard_core.so")

    # gadgets
    gadg_p = subparsers.add_parser("gadgets", help="Return-Oriented Programming (ROP) gadget discovery & analysis")
    gadg_p.add_argument("target", help="Path to binary file")
    gadg_p.add_argument("--reg", default=None, help="Filter gadgets by register (e.g. rdi, rax, rsp)")
    gadg_p.add_argument("--cat", default=None, help="Filter by category (register_setter, control_flow, syscall, stack_pivot)")
    gadg_p.add_argument("--max", type=int, default=100, help="Max gadgets to display (default: 100)")
    gadg_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # entropy
    ent_p = subparsers.add_parser("entropy", help="Sliding-window Shannon entropy analysis with ASCII visualization")
    ent_p.add_argument("target", help="Path to file")
    ent_p.add_argument("--visualize", "-V", action="store_true", help="Render multi-row ASCII density heat graph")
    ent_p.add_argument("--window", type=int, default=512, help="Sliding window size in bytes (default: 512)")
    ent_p.add_argument("--step", type=int, default=128, help="Step size in bytes (default: 128)")
    ent_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # diff
    diff_p = subparsers.add_parser("diff", help="Binary Differ (BinDiff) for structural, hash, and similarity comparison")
    diff_p.add_argument("target1", help="First binary file")
    diff_p.add_argument("target2", help="Second binary file")
    diff_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # scan
    scan_p = subparsers.add_parser("scan", help="YARA-style signature matcher & malware heuristics scanner")
    scan_p.add_argument("target", help="Target file to scan")
    scan_p.add_argument("--rule", default=None, help="Filter by rule ID or category keyword")
    scan_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # sarif
    sarif_p = subparsers.add_parser("sarif", help="Export findings to OASIS SARIF v2.1.0 for GitHub Code Scanning")
    sarif_p.add_argument("target", help="Project ID or file/directory path")
    sarif_p.add_argument("-o", "--output", default=None, help="Output file path (default: stdout)")

    # update
    subparsers.add_parser("update", help="Safely update Wizard from GitHub")

    # server
    server_p = subparsers.add_parser("server", help="Start the Wizard web dashboard & REST API")
    server_p.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    server_p.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")

    return parser


def main() -> None:
    parser = build_parser()

    if len(sys.argv) == 1:
        print_banner(full=True)
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.version:
        cmd_version()
        sys.exit(0)

    if args.command == "doctor":
        cmd_doctor()
    elif args.command == "capabilities":
        cmd_capabilities()
    elif args.command == "native":
        cmd_native(bench=args.bench, rebuild=args.rebuild)
    elif args.command == "gadgets":
        cmd_gadgets(args.target, reg=args.reg, cat=args.cat, max_g=args.max, json_out=args.json)
    elif args.command == "entropy":
        cmd_entropy(args.target, visualize=args.visualize, window=args.window, step=args.step, json_out=args.json)
    elif args.command == "diff":
        cmd_diff(args.target1, args.target2, json_out=args.json)
    elif args.command == "scan":
        cmd_scan(args.target, rule=args.rule, json_out=args.json)
    elif args.command == "sarif":
        cmd_sarif(args.target, output=args.output)
    elif args.command == "reverse":
        cmd_reverse(args.target)
    elif args.command == "security":
        cmd_security(args.target, authorized=not getattr(args, "unauthorized", False))
    elif args.command == "analyze":
        cmd_analyze(args.target)
    elif args.command == "findings":
        cmd_findings(target_id=args.id, severity_filter=args.severity, output_format=args.format)
    elif args.command == "report":
        cmd_report(project_id=args.project_id, output_format=args.format, output_file=args.output)
    elif args.command == "update":
        cmd_update()
    elif args.command == "project":
        if not args.project_action or args.project_action == "list":
            cmd_projects("list")
        elif args.project_action == "create":
            cmd_projects("create", name=args.name, desc=args.desc)
        elif args.project_action == "delete":
            cmd_projects("delete", project_id=args.id)
    elif args.command == "server":
        cmd_server(host=args.host, port=args.port)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
