from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
AnalysisModule = Literal["reverse-engineering", "security-testing", "inventory"]


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)


class Project(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = ""
    status: str
    created_at: str
    file_count: int = 0
    total_bytes: int = 0


class TargetScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(default="localhost")
    authorized: bool = Field(default=False)
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443, 8000, 8080, 5173])
    excluded_targets: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(
        default_factory=lambda: [
            "strings", "objdump", "readelf", "file", "nm",
            "wizard-re-engine", "wizard-static-security", "wizard-inventory"
        ]
    )
    max_time_seconds: float = Field(default=60.0)
    mode: Literal["lab", "defensive", "audit"] = "lab"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    module: str
    severity: Severity
    title: str
    description: str
    evidence: str
    file: str
    line: int | None = None
    rule: str
    confidence: Confidence = "high"
    remediation: str
    references: list[str] = Field(default_factory=list)


class ToolExecutionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: list[str] = Field(default_factory=list)
    scope_decision: str = "approved"
    start_time: str
    end_time: str
    exit_status: int
    output: str = ""
    errors: str | None = None


class SectionDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    size: int
    virtual_address: int = 0
    offset: int = 0
    flags: str = ""
    readable: bool = True
    writable: bool = False
    executable: bool = False
    entropy: float = 0.0
    suspicious: bool = False
    suspicious_reason: str | None = None


class BinaryMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")

    file_type: str
    format: str
    architecture: str
    bits: int
    endian: str
    entry_point: int | None = None
    sha256: str
    size: int
    entropy: float
    sections: list[SectionDetail] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    symbols: list[str] = Field(default_factory=list)
    hardening: dict[str, bool] = Field(default_factory=dict)
    suspicious_indicators: list[str] = Field(default_factory=list)


class ReverseEngineeringResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tool_used: str = "wizard-re-engine"
    input_file: str
    status: str = "completed"
    metadata: BinaryMetadata | None = None
    strings: dict[str, list[str]] = Field(default_factory=dict)
    disassembly: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    timestamp: str


class SecurityTestingResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tool_used: str = "wizard-static-security"
    scope: str
    status: str = "completed"
    finding_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    dependency_vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    configuration_issues: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    timestamp: str


class CapabilityReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    python: bool = True
    strings: bool = False
    objdump: bool = False
    readelf: bool = False
    file: bool = False
    nm: bool = False
    yara: bool = False
    ghidra: bool = False
    radare2: bool = False
    semgrep: bool = False


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    modules: list[str] = Field(default_factory=lambda: ["reverse-engineering", "security-testing"])
    scope: TargetScope | None = None
    user_notes: str | None = None


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    analysis_id: str
    project_id: str
    project: Project
    generated_at: str
    status: str = "completed"
    inventory: dict[str, Any] = Field(default_factory=dict)
    reverse_engineering: dict[str, Any] = Field(default_factory=dict)
    security: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    tools_used: list[str] = Field(default_factory=list)
    audit_trail: list[ToolExecutionRecord] = Field(default_factory=list)
    executive_summary: str = ""
    limitations: list[str] = Field(default_factory=list)
