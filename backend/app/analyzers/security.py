from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.models.schemas import Confidence, Finding, SecurityTestingResult, Severity


# Rule definition: (rule_id, severity, confidence, title, regex_pattern, description, remediation, references)
SECURITY_RULES = (
    # Secrets & Credentials
    (
        "sec-private-key",
        "critical",
        "high",
        "Embedded Private Key Detected",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "A plaintext cryptographic private key is embedded directly within project files.",
        "Remove private keys from source code immediately, store them in a secure secrets manager, and rotate affected keys.",
        ["https://cwe.mitre.org/data/definitions/798.html", "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"],
    ),
    (
        "sec-aws-key",
        "critical",
        "high",
        "AWS Access Key ID Detected",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "An Amazon Web Services access key identifier was found in plaintext in project files.",
        "Remove AWS credentials from source code, revoke the exposed key in the AWS IAM Console, and use IAM roles.",
        ["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    (
        "sec-github-token",
        "critical",
        "high",
        "GitHub Personal Access Token Detected",
        re.compile(r"\bgh[pousr]_[0-9a-zA-Z]{36}\b"),
        "A GitHub authentication token was discovered embedded in repository files.",
        "Revoke the token in GitHub Developer Settings and use environment variables.",
        ["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    (
        "sec-slack-token",
        "high",
        "high",
        "Slack Bot/User Token Detected",
        re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
        "A Slack API token was found in plaintext.",
        "Revoke the token in the Slack App Management dashboard.",
        ["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    (
        "sec-db-connection-string",
        "high",
        "medium",
        "Database Connection String with Embedded Password",
        re.compile(r"(?:postgres|mysql|mongodb|redis)://[^:]+:([^@\s]{3,})@"),
        "A database connection URI containing hardcoded credentials was found.",
        "Extract database credentials to environment variables or secret management services.",
        ["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    (
        "sec-generic-secret",
        "medium",
        "low",
        "Potential Hardcoded Secret or API Key",
        re.compile(r"(?:api[_-]?key|secret|token|password)\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]", re.IGNORECASE),
        "A variable assignment matching an API key or password pattern was detected.",
        "Ensure secrets are not committed to source control; use environment configuration.",
        ["https://cwe.mitre.org/data/definitions/798.html"],
    ),

    # Dangerous APIs & Code Execution
    (
        "sec-dangerous-eval",
        "high",
        "high",
        "Dynamic Code Evaluation via eval()",
        re.compile(r"\beval\s*\("),
        "Use of dynamic eval() enables arbitrary code execution if untrusted input is evaluated.",
        "Refactor to avoid eval(); use structured parsers like json.loads() or static dispatch dictionaries.",
        ["https://cwe.mitre.org/data/definitions/95.html", "https://owasp.org/www-community/attacks/Code_Injection"],
    ),
    (
        "sec-dangerous-exec",
        "high",
        "high",
        "Dynamic Code Execution via exec()",
        re.compile(r"\bexec\s*\("),
        "Dynamic execution of Python statements via exec() creates severe code injection risks.",
        "Replace dynamic exec calls with explicit callable functions or predefined logic branches.",
        ["https://cwe.mitre.org/data/definitions/95.html"],
    ),
    (
        "sec-unsafe-deserialization-pickle",
        "high",
        "high",
        "Insecure Deserialization via Python pickle",
        re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        "Python's pickle module is inherently unsafe against untrusted data, allowing arbitrary code execution.",
        "Use safer serialization formats such as JSON, Protocol Buffers, or HMAC-authenticated payloads.",
        ["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    (
        "sec-unsafe-yaml-load",
        "high",
        "high",
        "Unsafe YAML Deserialization",
        re.compile(r"\byaml\.(?:unsafe_load|load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?Loader)"),
        "PyYAML's default or unsafe loader can instantiate arbitrary Python objects leading to remote code execution.",
        "Use yaml.safe_load() to restrict deserialization to standard data types.",
        ["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    (
        "sec-xss-innerhtml",
        "medium",
        "high",
        "DOM Cross-Site Scripting via innerHTML",
        re.compile(r"\.(?:innerHTML|outerHTML)\s*="),
        "Direct assignment to innerHTML bypasses HTML encoding and exposes the application to DOM XSS.",
        "Use textContent or framework-managed safe data binding (e.g. React JSX expressions).",
        ["https://cwe.mitre.org/data/definitions/79.html"],
    ),

    # Shell Execution & Subprocesses
    (
        "sec-python-os-system",
        "high",
        "high",
        "Shell Command Execution via os.system()",
        re.compile(r"\bos\.system\s*\("),
        "Executing commands via os.system passes strings directly to the system shell, vulnerable to command injection.",
        "Use subprocess.run with an argument list and shell=False.",
        ["https://cwe.mitre.org/data/definitions/78.html"],
    ),
    (
        "sec-python-shell-true",
        "high",
        "high",
        "Unsafe Subprocess Call with shell=True",
        re.compile(r"\bshell\s*=\s*True\b"),
        "A subprocess invocation explicitly enables shell interpretation, creating command injection hazards.",
        "Pass arguments as a list with shell=False, e.g.: subprocess.run(['cmd', arg1, arg2]).",
        ["https://cwe.mitre.org/data/definitions/78.html"],
    ),
    (
        "sec-node-child-process-exec",
        "medium",
        "high",
        "Node.js Shell Execution via child_process.exec",
        re.compile(r"\b(?:child_process\.)?exec\s*\("),
        "Node.js child_process.exec executes commands in a system shell without argument escaping.",
        "Use child_process.execFile or child_process.spawn with an array of arguments.",
        ["https://cwe.mitre.org/data/definitions/78.html"],
    ),

    # Injection Hazards
    (
        "sec-sql-injection-fstring",
        "high",
        "medium",
        "Potential SQL Injection via Formatted String",
        re.compile(r"""(?:execute|raw)\s*\(\s*f["'].*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE)""", re.IGNORECASE),
        "SQL query construction uses formatted f-strings, which may incorporate unescaped user input.",
        "Use parameterized queries or prepared statements (e.g., cursor.execute('SELECT ... WHERE id = %s', [id])).",
        ["https://cwe.mitre.org/data/definitions/89.html"],
    ),

    # Cryptography Weaknesses
    (
        "sec-weak-crypto-md5",
        "low",
        "medium",
        "Weak Cryptographic Hash Algorithm: MD5",
        re.compile(r"\b(?:hashlib\.md5|crypto\.createHash\(['\"]md5['\"]\))"),
        "MD5 is cryptographically broken and vulnerable to collision attacks.",
        "Use SHA-256, SHA-3, or Argon2/bcrypt for password hashing.",
        ["https://cwe.mitre.org/data/definitions/327.html"],
    ),
    (
        "sec-weak-crypto-sha1",
        "low",
        "medium",
        "Weak Cryptographic Hash Algorithm: SHA-1",
        re.compile(r"\b(?:hashlib\.sha1|crypto\.createHash\(['\"]sha1['\"]\))"),
        "SHA-1 has known collision attacks and should not be used in security-sensitive contexts.",
        "Upgrade to SHA-256 or stronger algorithms.",
        ["https://cwe.mitre.org/data/definitions/327.html"],
    ),
    (
        "sec-crypto-ecb-mode",
        "medium",
        "high",
        "Insecure AES Cipher Mode: ECB",
        re.compile(r"\b(?:AES\.MODE_ECB|mode_ecb)\b", re.IGNORECASE),
        "Electronic Codebook (ECB) mode produces identical ciphertext for identical plaintext blocks, leaking structural data.",
        "Use authenticated encryption modes like AES-GCM or ChaCha20-Poly1305.",
        ["https://cwe.mitre.org/data/definitions/327.html"],
    ),

    # Configuration & Permissions
    (
        "sec-insecure-cors-wildcard",
        "medium",
        "high",
        "Overly Permissive CORS Policy (Wildcard Origin)",
        re.compile(r"""allow_origins\s*=\s*\[\s*["']\*["']\s*\]"""),
        "CORS middleware allows all origins ('*'), which may expose internal APIs to cross-site request forgery.",
        "Explicitly list trusted origin domains instead of wildcard.",
        ["https://cwe.mitre.org/data/definitions/942.html"],
    ),
    (
        "sec-flask-debug-mode",
        "medium",
        "high",
        "Application Running with Debug Mode Enabled",
        re.compile(r"\b(?:app\.debug\s*=\s*True|DEBUG\s*=\s*True)\b"),
        "Debug mode provides interactive tracebacks or debug consoles, which can allow remote command execution.",
        "Ensure DEBUG mode is strictly disabled in production environments.",
        ["https://cwe.mitre.org/data/definitions/489.html"],
    ),
    (
        "sec-insecure-chmod-777",
        "medium",
        "high",
        "Insecure File Permissions (chmod 777)",
        re.compile(r"\b(?:chmod\s+777|0o777)\b"),
        "File permissions are set to world-readable, world-writable, and world-executable (777).",
        "Follow the principle of least privilege; restrict permissions to 600 or 700.",
        ["https://cwe.mitre.org/data/definitions/732.html"],
    ),

    # C / C++ Memory Safety Vulnerabilities
    (
        "sec-c-unsafe-strcpy",
        "critical",
        "high",
        "Unbounded Buffer Copy via strcpy/strcat",
        re.compile(r"\b(?:strcpy|strcat)\s*\("),
        "Use of unbounded string copy functions leads to classic stack and heap buffer overflows.",
        "Replace strcpy/strcat with bounded alternatives like strncpy, snprintf, or std::string in C++.",
        ["https://cwe.mitre.org/data/definitions/120.html", "https://cwe.mitre.org/data/definitions/676.html"],
    ),
    (
        "sec-c-unsafe-sprintf",
        "high",
        "high",
        "Unbounded String Formatting via sprintf",
        re.compile(r"\b(?:sprintf|vsprintf)\s*\("),
        "sprintf does not check destination buffer boundaries, enabling arbitrary buffer overflows.",
        "Use snprintf with explicit destination buffer capacity.",
        ["https://cwe.mitre.org/data/definitions/120.html"],
    ),
    (
        "sec-c-unsafe-gets",
        "critical",
        "high",
        "Inherently Dangerous gets() Function",
        re.compile(r"\bgets\s*\("),
        "gets() cannot check buffer bounds and is impossible to use safely; deprecated and removed in C11.",
        "Replace gets() with fgets() specifying exact buffer limit.",
        ["https://cwe.mitre.org/data/definitions/242.html"],
    ),
    (
        "sec-c-format-string",
        "high",
        "medium",
        "Uncontrolled Format String Vulnerability",
        re.compile(r"\b(?:printf|fprintf|syslog)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)"),
        "Passing non-constant user string directly as format string parameter allows memory read/write via %x and %n.",
        "Always provide a format string literal: printf('%s', user_input).",
        ["https://cwe.mitre.org/data/definitions/134.html"],
    ),
    (
        "sec-c-toctou-race",
        "medium",
        "medium",
        "Time-of-Check Time-of-Use (TOCTOU) Race Hazard",
        re.compile(r"\baccess\s*\([^)]*\)\s*;\s*(?:if|while)"),
        "Checking file permissions with access() prior to opening creates a TOCTOU race window for symlink attacks.",
        "Open the file directly with appropriate flags (e.g. O_CREAT | O_EXCL) and inspect file descriptor safely.",
        ["https://cwe.mitre.org/data/definitions/367.html"],
    ),

    # Cloud Secrets & Modern Authentication
    (
        "sec-gcp-service-account",
        "critical",
        "high",
        "Google Cloud Service Account Private Key Detected",
        re.compile(r'"type":\s*"service_account"[^}]*"private_key"'),
        "A plaintext GCP Service Account private key JSON document was discovered.",
        "Revoke service account credentials immediately in GCP IAM and manage keys via KMS or Workload Identity.",
        ["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    (
        "sec-jwt-hardcoded-secret",
        "high",
        "medium",
        "Hardcoded JSON Web Token (JWT) Secret",
        re.compile(r"""(?:jwt\.sign|jwt\.verify|jwt\.decode)\s*\([^,]+,\s*['"][a-zA-Z0-9_!@#$%^&*-]{6,}['"]"""),
        "JWT signing or verification uses a hardcoded symmetric secret key in source code.",
        "Load JWT secret keys from protected environment variables or AWS Secrets Manager / HashiCorp Vault.",
        ["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    (
        "sec-insecure-tls-bypass",
        "high",
        "high",
        "Insecure TLS/SSL Certificate Validation Disabled",
        re.compile(r"""\b(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)\b"""),
        "Disabling TLS certificate verification renders HTTPS connections vulnerable to Man-in-the-Middle (MitM) attacks.",
        "Always enable strict certificate validation; provision legitimate certificates or trust custom CA bundles.",
        ["https://cwe.mitre.org/data/definitions/295.html"],
    ),

    # Modern Web & AI Vulnerabilities
    (
        "sec-ssrf-unvalidated-request",
        "high",
        "medium",
        "Potential Server-Side Request Forgery (SSRF)",
        re.compile(r"""(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|axios\.(?:get|post))\s*\(\s*(?:url|target_url|dest_url|user_url|req\.query)"""),
        "An outgoing HTTP request is constructed using variable target parameters without origin validation.",
        "Validate target URLs against a strict allowlist of domains and block internal/loopback IP ranges (127.0.0.1, 169.254.169.254).",
        ["https://cwe.mitre.org/data/definitions/918.html"],
    ),
    (
        "sec-llm-prompt-injection-hazard",
        "medium",
        "medium",
        "Unsanitized LLM Prompt Template Concatenation",
        re.compile(r"""(?:prompt|messages)\s*=\s*f["'].*?\{(?:user_input|user_prompt|query|input_text)\}.*?["']"""),
        "Direct f-string concatenation of untrusted user input into LLM system or task prompts enables prompt injection.",
        "Use structured system/user role separation message payloads and input sanitizers instead of raw string interpolation.",
        ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
)


KNOWN_VULNERABLE_PACKAGES = {
    "pyyaml": {"threshold": "5.4", "cve": "CVE-2020-14343", "note": "PyYAML arbitrary code execution via load()"},
    "urllib3": {"threshold": "1.26.5", "cve": "CVE-2021-33503", "note": "ReDoS via Catastrophic Backtracking in Authority"},
    "requests": {"threshold": "2.20.0", "cve": "CVE-2018-18074", "note": "Session redirect credential leakage"},
    "flask": {"threshold": "0.12.3", "cve": "CVE-2018-1000656", "note": "Denial of service vulnerability"},
    "django": {"threshold": "2.2.28", "cve": "CVE-2022-28346", "note": "SQL injection in QuerySet.aggregate()"},
    "lodash": {"threshold": "4.17.21", "cve": "CVE-2021-23337", "note": "Prototype pollution via template"},
    "express": {"threshold": "4.16.0", "cve": "CVE-2017-16119", "note": "Prototype pollution in qs dependency"},
}


TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go",
    ".rs", ".c", ".h", ".cpp", ".cc", ".hpp", ".cs", ".php",
    ".rb", ".swift", ".dart", ".html", ".css", ".scss", ".json",
    ".xml", ".yaml", ".yml", ".sql", ".sh", ".env",
    ".txt", ".md", ".cfg", ".ini", ".conf",
}

MAX_TEXT_FILE_BYTES = 4 * 1024 * 1024
MAX_FINDINGS = 500


def analyze_security(root: Path) -> dict:
    """Analyze source code, configurations, and dependencies for security risks and vulnerabilities."""
    timestamp = datetime.now(timezone.utc).isoformat()
    findings: list[Finding] = []
    dep_vulns: list[dict] = []
    config_issues: list[dict] = []
    errors: list[str] = []

    # 1. Dependency Analysis (requirements.txt, package.json)
    req_files = list(root.rglob("requirements.txt"))
    for req_file in req_files:
        try:
            for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-]+)(?:==|<=|>=|<|>)(.*)$", line)
                if match:
                    pkg_name = match.group(1).lower()
                    pkg_ver = match.group(2).strip()
                    if pkg_name in KNOWN_VULNERABLE_PACKAGES:
                        info = KNOWN_VULNERABLE_PACKAGES[pkg_name]
                        finding = Finding(
                            id=uuid4().hex[:12],
                            module="security-testing",
                            severity="high",
                            title=f"Vulnerable Dependency Detected: {pkg_name} ({pkg_ver})",
                            description=f"Package '{pkg_name}' may be vulnerable: {info['note']} ({info['cve']}).",
                            evidence=f"Dependency entry: {line}",
                            file=req_file.relative_to(root).as_posix(),
                            line=None,
                            rule="sec-vulnerable-dependency",
                            confidence="medium",
                            remediation=f"Upgrade '{pkg_name}' to version > {info['threshold']}.",
                            references=[f"https://nvd.nist.gov/vuln/detail/{info['cve']}"],
                        )
                        findings.append(finding)
                        dep_vulns.append({
                            "package": pkg_name,
                            "version": pkg_ver,
                            "cve": info["cve"],
                            "description": info["note"],
                        })
        except Exception as exc:
            errors.append(f"Failed parsing {req_file.name}: {exc}")

    # 2. Configuration Analysis (.env files in repository)
    env_files = list(root.rglob(".env*"))
    for env_file in env_files:
        if env_file.is_file():
            finding = Finding(
                id=uuid4().hex[:12],
                module="security-testing",
                severity="medium",
                title=f"Environment Secret File Committed: {env_file.name}",
                description="An environment configuration file (.env) was found committed to the repository, which often leaks operational secrets.",
                evidence=f"File present: {env_file.relative_to(root).as_posix()}",
                file=env_file.relative_to(root).as_posix(),
                line=None,
                rule="sec-env-file-committed",
                confidence="high",
                remediation="Add '.env*' to .gitignore and rotate any committed secrets.",
                references=["https://cwe.mitre.org/data/definitions/200.html"],
            )
            findings.append(finding)
            config_issues.append({"file": env_file.name, "issue": "Environment file present in source control"})

    # 3. Static Source Code Scanning
    for path in sorted(root.rglob("*")):
        if len(findings) >= MAX_FINDINGS:
            break

        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size > MAX_TEXT_FILE_BYTES
            or path.suffix.lower() not in TEXT_SUFFIXES
        ):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        relative = path.relative_to(root).as_posix()

        for line_number, line in enumerate(text.splitlines(), start=1):
            for (
                rule_id, severity, confidence, title,
                pattern, description, remediation, refs
            ) in SECURITY_RULES:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            id=uuid4().hex[:12],
                            module="security-testing",
                            severity=severity,
                            confidence=confidence,
                            title=title,
                            description=description,
                            evidence=line.strip()[:160],
                            file=relative,
                            line=line_number,
                            rule=rule_id,
                            remediation=remediation,
                            references=refs,
                        )
                    )
                    if len(findings) >= MAX_FINDINGS:
                        break

            if len(findings) >= MAX_FINDINGS:
                break

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity_counts[finding.severity] += 1

    # Return dictionary compatible with both legacy tests and rich responses
    return {
        "tool_used": "wizard-static-security",
        "scope": "local imported project only",
        "status": "completed",
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "findings": [f.model_dump() for f in findings],
        "dependency_vulnerabilities": dep_vulns,
        "configuration_issues": config_issues,
        "errors": errors,
        "timestamp": timestamp,
    }
