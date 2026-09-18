# Wizard

```text
  ╭─────────────────────────────────────────────────────────────╮
  │   █   █  █  █████    ██    ████   ████                      │
  │   █ █ █  █     █    █  █   █   █  █   █                     │
  │   ██ ██  █    █    ██████  ████   █   █                     │
  │   █   █  █   ████  █    █  █   █  ████                      │
  │                                                             │
  │   ✦ CYBERSECURITY RESEARCH & REVERSE ENGINEERING PLATFORM ✦ │
  │        Defensive Analysis • Memory Hardening • Auditing     │
  ╰─────────────────────────────────────────────────────────────╯
```

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux%20%7C%20Debian%20proot-cyan.svg)](#)
[![Defensive](https://img.shields.io/badge/security-defensive%20authorized-green.svg)](#)

---

## What Wizard Is

**Wizard** is an AI-assisted cybersecurity research and defensive analysis platform designed for vulnerability analysts, security researchers, reverse engineers, defensive auditors, and lab/educational environments.

Wizard unites two primary security domains:
1. **Reverse Engineering Engine:** In-depth binary header parsing (ELF, PE, Mach-O), Shannon entropy calculation, memory hardening evaluation, string categorization, section permissions, and disassembly integration.
2. **Ethical Security Testing Engine:** Safe static analysis scanning for hardcoded secrets, dangerous APIs, command execution hazards, SQL/template injections, weak cryptography, insecure permissions, and vulnerable dependencies.

All capabilities are bound by strict authorization controls and an allowlisted command execution harness. Wizard is defensive-only: **it never executes arbitrary AI-generated shell commands or targets unauthorized systems.**

---

## Features

- **Universal Multi-Platform Support:** Runs natively on standard Linux distributions (Debian, Ubuntu, Fedora, Arch) and Android Termux.
- **Pure-Python Binary Parsers:** Zero external C-library dependency requirement to parse ELF (32/64-bit, ARM, AArch64, x86_64, RISC-V, MIPS), PE (PE32/PE32+), and Mach-O (Apple Silicon/Intel).
- **Shannon Entropy Analysis:** Per-file and per-section entropy scoring ($0.0$ to $8.0$ bits/byte) to spot packed, compressed, or encrypted payloads ($>7.2$ bits).
- **Hardening Evaluation:** Checks for Position Independent Executables (**PIE**), Data Execution Prevention (**NX/DEP**), and Address Space Layout Randomization (**ASLR**).
- **Memory Violation Detection:** Automatically flags W^X violations (sections that are simultaneously **Writable and Executable**).
- **Categorized Strings Extraction:** Identifies suspicious APIs (`ptrace`, `execve`, `VirtualAlloc`, `system`, `mprotect`), URLs, IPs, system paths, and cryptographic signatures.
- **Static Security Auditing:** Detects AWS keys (`AKIA...`), RSA/SSH private keys, GitHub tokens, Slack tokens, `eval()`, `exec()`, `pickle.loads()`, and dangerous subprocess invocations.
- **Strict Scope Verification:** Mandatory authorization checks restricting scans to approved hosts and ports, with excluded-target blocking and audit logging.
- **Safe Subprocess Harness (`SafeExecutor`):** Allowlisted binary commands with strict argument sanitization, clean environment isolation, and execution timeouts.
- **Comprehensive CLI & Web UI:** Fast command-line interface (`wizard`) alongside a responsive, dark-mode single-page application dashboard hosted at `http://127.0.0.1:8000`.

---

## Architecture

```text
                             WIZARD CLI & WEB UI
                                      ↓
                           AI ORCHESTRATION LAYER
    (Scope Enforcement → Analyzer Selection → Execution → Correlated Evidence)
                                      ↓
                               ANALYSIS ENGINES
    ├── Reverse Engineering (ELF / PE / Mach-O / Entropy / Hardening / Strings)
    ├── Static Security Engine (Secrets / Dangerous APIs / Subprocess / Sinks)
    ├── Artifact Classifier & Inventory (SHA-256 / Languages / File Metadata)
    └── Safe Subprocess Executor (Command Allowlist / Timeouts / Output Caps)
                                      ↓
                      FINDINGS & AUDIT TRAIL STORE
                                      ↓
                    STRUCTURED ASSESSMENT REPORTS
```

---

## Requirements

### Standard Linux (Debian / Ubuntu / Fedora / Arch)
- Python 3.10 or higher (`python3`, `python3-venv`, `python3-pip`)
- Git (`git`)
- Node.js & npm (`nodejs`, `npm`) — optional, for compiling frontend UI assets
- Binary utilities (`binutils`, `file`) — optional, for native `strings`, `objdump`, `readelf`

### Android (Termux)
- Termux app (from F-Droid or GitHub Releases)
- `pkg update && pkg install -y git python proot-distro nodejs`

---

## Installation

### Quick Start (All Environments)

A completely new user can install Wizard in minutes:

```bash
git clone https://github.com/macdonaldbarasa2026-del/Wizard.git
cd Wizard
./install.sh
```

Then verify the installation:

```bash
wizard --version
wizard doctor
wizard --help
```

---

## Termux Installation Details

In Android Termux, Wizard detects the mobile environment and configures the launcher in `$PREFIX/bin/wizard`. Because Python C-extensions on rolling Termux releases may lack precompiled wheels, the installer seamlessly coordinates with `proot-distro debian` for backend packages:

```bash
# In Termux:
pkg update && pkg install -y git python proot-distro nodejs
git clone https://github.com/macdonaldbarasa2026-del/Wizard.git
cd Wizard
./install.sh

# Verify
wizard --version
wizard doctor
```

---

## Linux Installation Details

On Debian, Ubuntu, Linux Mint, or Raspberry Pi OS:

```bash
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip binutils file nodejs npm
git clone https://github.com/macdonaldbarasa2026-del/Wizard.git
cd Wizard
./install.sh

# Verify
wizard --version
wizard doctor
```

---

## Usage & CLI Commands

```text
usage: wizard [-h] [-v]
              {doctor,capabilities,reverse,security,analyze,project,findings,report,update,server} ...
```

### 1. System Diagnostics
Inspect all runtimes, host tools, analyzers, and storage readiness:
```bash
wizard doctor
```

### 2. Capabilities Matrix
Inspect reverse engineering and security testing capabilities:
```bash
wizard capabilities
```

### 3. Binary Reverse Engineering
Analyze an ELF, PE, or Mach-O executable:
```bash
wizard reverse /path/to/binary
```

Output includes:
- Architecture, bitness, endianness, entry point address
- SHA-256 hash and file size
- Shannon Entropy score and packing detection
- Hardening checks (PIE, NX/DEP, ASLR)
- Section permissions (R, W, X) and W^X violation detection
- Categorized strings and suspicious process APIs
- Disassembly preview via `objdump` (if present)

### 4. Ethical Security Testing
Run defensive static code analysis on a directory:
```bash
wizard security /path/to/source_dir
```

### 5. Full Analysis Pipeline
Analyze a binary artifact or project directory:
```bash
wizard analyze /path/to/target
```
Or analyze an existing project by ID:
```bash
wizard analyze <project_id>
```

### 6. Project Management
```bash
# Create a new project
wizard project create "PaymentGateway" --desc "Authorized pre-release review"

# List all projects
wizard project list

# Delete a project
wizard project delete <project_id>
```

### 7. Findings Inspection
Query recorded findings from analyses:
```bash
# View all recent findings
wizard findings

# Filter by severity
wizard findings --severity high

# Output as JSON
wizard findings <project_id> --format json
```

### 8. Structured Reports
Generate comprehensive assessment reports:
```bash
# View terminal summary report
wizard report <project_id>

# Export as Markdown report
wizard report <project_id> --format md --output report.md

# Export as JSON
wizard report <project_id> --format json --output report.json
```

### 9. Web Server & Dashboard
Launch the interactive web UI and REST API:
```bash
wizard server --host 0.0.0.0 --port 8000
```
Then visit:
- **Web UI:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive API Docs (Swagger):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Scope & Authorization Model

Wizard enforces strict safety boundaries:
- **Authorization Required:** Security tests require explicit authorization (`authorized=True`).
- **Strict Host & Port Allowlist:** Restricts network scopes to approved hosts (`127.0.0.1`, `localhost`) and ports.
- **Excluded Targets:** Any host or IP matching `excluded_targets` is strictly blocked.
- **No Arbitrary Shell Invocations:** AI orchestration passes commands through `SafeExecutor` allowlists (`strings`, `objdump`, `readelf`, `file`, `nm`), with argument sanitization and timeouts.
- **Data Privacy & Redaction:** Private keys, access tokens, and passwords are automatically scrubbed from command outputs and logs.

---

## Updating

Update Wizard safely from GitHub without losing local files:

```bash
wizard update
```

Or manually:
```bash
git fetch origin
git pull --ff-only origin main
./install.sh
```

---

## Uninstalling

To cleanly remove Wizard from your system PATH:

```bash
./uninstall.sh
```

To also remove the backend virtual environment:
```bash
./uninstall.sh --clean-env
```
*(User project data and reports are preserved by default).*

---

## Development & Testing

Run the full automated test suite:
```bash
# When running in Termux with proot-distro:
wizard doctor

# Or run pytest directly within the backend directory:
cd backend
pytest -v
```

Rebuild the frontend single-page application:
```bash
cd frontend
npm run build
```

---

## Security Principles

1. **Defensive Research Only:** Wizard is intended for authorized security audits, malware defensive triage, vulnerability analysis, and education.
2. **Never Attack Unapproved Targets:** Do not scan, probe, or test systems without written owner authorization.
3. **No Weaponization:** Wizard does not generate exploit payloads, evasion techniques, persistence backdoors, or credential harvesting scripts.

---

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
