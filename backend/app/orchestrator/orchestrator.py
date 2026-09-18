from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from typing import Any

from app.analyzers.inventory import analyze_inventory
from app.analyzers.reverse_engineering import analyze_binary
from app.analyzers.security import analyze_security
from app.models.schemas import Finding, TargetScope, ToolExecutionRecord
from app.security.capabilities import detect_capabilities
from app.security.scope import validate_target_scope, ScopeError
from app.services.store import (
    get_project,
    save_analysis,
    save_audit_log,
    save_report,
    source_root,
    update_project,
)


def run_analysis_pipeline(
    project_id: str,
    modules: list[str] | None = None,
    scope: TargetScope | dict | None = None,
    user_notes: str | None = None,
) -> dict[str, Any]:
    """Execute the AI Orchestrator analysis pipeline across 8 structured steps:
    1. Understand request & inspect target
    2. Select appropriate analyzers
    3. Validate scope
    4. Execute approved analyzers
    5. Collect evidence
    6. Correlate findings
    7. Explain findings & risk
    8. Produce structured report
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    analysis_id = uuid4().hex[:12]
    project = get_project(project_id)
    root = source_root(project_id)

    # 1. Understand Request
    if modules is None:
        modules = ["reverse-engineering", "security-testing"]

    tools_used: list[str] = []
    audit_trail: list[ToolExecutionRecord] = []
    limitations: list[str] = []

    caps = detect_capabilities()
    missing_caps = [k for k, v in caps.items() if not v and k in ("objdump", "yara", "ghidra", "radare2", "semgrep")]
    if missing_caps:
        limitations.append(f"External binary tools not present on host: {', '.join(missing_caps)}. Native fallback parsers were used.")

    # 2. Select Analyzers
    # Always run inventory to classify files
    inventory_res = analyze_inventory(root)
    tools_used.append("wizard-inventory")

    # 3. Validate Scope
    if scope is not None:
        # Validate explicit authorization
        validated_scope = validate_target_scope(scope)
        scope_str = f"Authorized: {validated_scope.target} (mode: {validated_scope.mode})"
    else:
        scope_str = f"Local imported project {project_id} (defensive static inspection only)"

    # 4. Execute Approved Analyzers
    re_results: dict[str, Any] = {}
    sec_results: dict[str, Any] = {}
    all_findings: list[dict[str, Any]] = []

    # A. Reverse Engineering Analysis
    if "reverse-engineering" in modules:
        tools_used.append("wizard-re-engine")
        # Identify binaries from inventory
        binary_files = [f["path"] for f in inventory_res.get("files", []) if f.get("binary")]
        if not binary_files and inventory_res.get("files"):
            # If no compiled binary was found, analyze the largest file for metadata/strings
            sorted_files = sorted(inventory_res["files"], key=lambda x: x.get("size", 0), reverse=True)
            if sorted_files:
                binary_files = [sorted_files[0]["path"]]

        re_file_reports: list[dict[str, Any]] = []
        for rel_path in binary_files[:5]:  # Limit to 5 files
            target_path = root / rel_path
            if target_path.is_file():
                res = analyze_binary(target_path)
                res_dict = res.model_dump()
                re_file_reports.append(res_dict)
                for f in res.findings:
                    all_findings.append(f.model_dump())

        re_results = {
            "status": "completed",
            "binaries_analyzed": len(re_file_reports),
            "reports": re_file_reports,
            # For test compatibility, surface first binary or empty dict
            "metadata": re_file_reports[0]["metadata"] if re_file_reports else {},
            "strings": re_file_reports[0]["strings"] if re_file_reports else {},
            "findings": [f for f in all_findings if f["module"] == "reverse-engineering"],
        }

    # B. Security Testing Analysis
    if "security-testing" in modules:
        tools_used.append("wizard-static-security")
        sec_results = analyze_security(root)
        sec_results["scope"] = scope_str
        for f in sec_results.get("findings", []):
            all_findings.append(f)

    # 5. Collect Evidence & 6. Correlate Findings
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in all_findings:
        sev = f.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["info"] += 1

    # 7. Explain Findings (AI Synthesis)
    critical_or_high = [f for f in all_findings if f.get("severity") in ("critical", "high")]
    summary_parts = []
    if critical_or_high:
        summary_parts.append(
            f"Analysis identified {len(critical_or_high)} critical/high-severity security concern(s) requiring immediate attention."
        )
    else:
        summary_parts.append(
            "No immediate critical or high vulnerabilities were detected under current static rules."
        )

    if re_results.get("binaries_analyzed", 0) > 0:
        summary_parts.append(
            f"Reverse engineering inspected {re_results['binaries_analyzed']} binary/data artifact(s) for hardening headers, memory protections, and suspicious API indicators."
        )

    if sec_results.get("finding_count", 0) > 0:
        summary_parts.append(
            f"Static security scanning generated {sec_results['finding_count']} total observation(s) across imported source and config files."
        )

    executive_summary = " ".join(summary_parts)

    # 8. Produce Final Report
    report = {
        "analysis_id": analysis_id,
        "project_id": project_id,
        "project": project,
        "generated_at": timestamp,
        "status": "completed",
        "scope": scope_str,
        "tools_used": tools_used,
        "limitations": limitations,
        "inventory": inventory_res,
        "reverse_engineering": re_results,
        "security": sec_results,
        "findings": all_findings,
        "severity_counts": severity_counts,
        "finding_count": len(all_findings),
        "executive_summary": executive_summary,
        "audit_trail": [a.model_dump() for a in audit_trail],
    }

    # Save to store
    save_report(project_id, report)
    save_analysis(analysis_id, report)

    # Update project stats
    update_project(
        project_id,
        status="analyzed",
        file_count=inventory_res.get("total_files", 0),
        total_bytes=inventory_res.get("total_bytes", 0),
    )

    # Log audit entry
    save_audit_log({
        "analysis_id": analysis_id,
        "project_id": project_id,
        "timestamp": timestamp,
        "tools_used": tools_used,
        "finding_count": len(all_findings),
        "scope": scope_str,
    })

    return report
