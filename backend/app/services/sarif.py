from __future__ import annotations

import json
from typing import Any
from pathlib import Path

from app.models.schemas import Finding


def convert_severity_to_sarif(sev: str) -> str:
    """Map Wizard severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(sev.lower(), "warning")


def findings_to_sarif(findings: list[Finding | dict[str, Any]], target_uri: str = "workspace") -> dict[str, Any]:
    """Export Wizard security and reverse engineering findings to standard OASIS SARIF v2.1.0."""
    rules_dict: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        if isinstance(f, Finding):
            f_id = f.id
            rule_id = f.rule
            sev = f.severity
            title = f.title
            desc = f.description
            file_path = f.file
            line_num = f.line or 1
            remediation = f.remediation
            refs = f.references
        else:
            f_id = f.get("id", "")
            rule_id = f.get("rule", "wizard-rule")
            sev = f.get("severity", "medium")
            title = f.get("title", "")
            desc = f.get("description", "")
            file_path = f.get("file", "unknown")
            line_num = f.get("line") or 1
            remediation = f.get("remediation", "")
            refs = f.get("references", [])

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": title.replace(" ", "_"),
                "shortDescription": {"text": title},
                "fullDescription": {"text": desc},
                "help": {
                    "text": f"{remediation}\n\nReferences:\n" + "\n".join(f"- {r}" for r in refs),
                    "markdown": f"### Remediation\n{remediation}\n\n### References\n"
                    + "\n".join(f"- [{r}]({r})" for r in refs),
                },
                "defaultConfiguration": {
                    "level": convert_severity_to_sarif(sev),
                },
            }

        clean_path = file_path.replace("\\", "/")
        if clean_path.startswith("/"):
            clean_path = clean_path.lstrip("/")

        result_entry = {
            "ruleId": rule_id,
            "level": convert_severity_to_sarif(sev),
            "message": {"text": f"{title}: {desc}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": clean_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line_num,
                            "startColumn": 1,
                        },
                    }
                }
            ],
        }
        results.append(result_entry)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Wizard Cybersecurity Platform",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/macdonaldbarasa2026-del/Wizard",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_file(findings: list[Finding | dict[str, Any]], out_path: Path | str) -> Path:
    """Write findings to a SARIF v2.1.0 JSON file."""
    path = Path(out_path)
    sarif_data = findings_to_sarif(findings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
    return path
