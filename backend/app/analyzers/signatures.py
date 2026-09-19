from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.native.bridge import get_native_bridge

# Built-in signature definitions:
# (id, name, category, severity, pattern_type, pattern, description)
SIGNATURE_RULES = (
    # Packers & Crypters
    (
        "sig-packer-upx",
        "UPX Executable Packer",
        "packer",
        "medium",
        "bytes",
        b"UPX!",
        "Executable is packed with UPX (Ultimate Packer for eXecutables). Analysis of the real code requires unpacking.",
    ),
    (
        "sig-packer-aspack",
        "ASPack Win32 Packer",
        "packer",
        "medium",
        "bytes",
        b".aspack",
        "ASPack compression detected. Sections are obscured to hinder reverse engineering.",
    ),
    (
        "sig-packer-themida",
        "Themida / WinLicense Protector",
        "packer",
        "high",
        "bytes",
        b".themida",
        "Advanced virtualization protector Themida detected. Features heavy anti-debugging and anti-VM.",
    ),
    (
        "sig-packer-vmprotect",
        "VMProtect Virtualization Packer",
        "packer",
        "high",
        "bytes",
        b".vmp0",
        "VMProtect bytecode virtualization detected. Native code is converted to virtualized bytecode.",
    ),
    (
        "sig-packer-mpress",
        "MPRESS Executable Compressor",
        "packer",
        "medium",
        "bytes",
        b".MPRESS1",
        "MPRESS packing detected.",
    ),

    # Anti-Debugging & Evasion
    (
        "sig-antidebug-tracerpid",
        "Linux TracerPid Anti-Debugging Check",
        "evasion",
        "high",
        "bytes",
        b"TracerPid:",
        "Inspects /proc/self/status for TracerPid to detect attached debuggers (like GDB/LLDB).",
    ),
    (
        "sig-antidebug-ptrace",
        "PTRACE_TRACEME Anti-Debugging Attachment",
        "evasion",
        "high",
        "regex",
        rb"\bptrace\b",
        "Calls ptrace(PTRACE_TRACEME) to prevent another debugger or analysis tool from attaching.",
    ),
    (
        "sig-antidebug-win32-api",
        "Windows IsDebuggerPresent Detection",
        "evasion",
        "high",
        "bytes",
        b"IsDebuggerPresent",
        "Windows API call used to detect debugging environments and alter execution flow.",
    ),
    (
        "sig-evasion-rdtsc",
        "RDTSC Hardware Timing Check",
        "evasion",
        "medium",
        "hex",
        "0f 31",
        "Reads Time-Stamp Counter (RDTSC). Typically used in timing side-channel checks to detect single-stepping in a debugger.",
    ),

    # Cryptographic Constants
    (
        "sig-crypto-aes-sbox",
        "AES Forward S-Box Lookup Table",
        "cryptography",
        "low",
        "hex",
        "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76",
        "Standard AES Rijndael substitution box (S-box) byte sequence identified.",
    ),
    (
        "sig-crypto-sha256-constants",
        "SHA-256 Initialization Vector Constants",
        "cryptography",
        "low",
        "hex",
        "6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a",
        "SHA-256 initial digest constants (first 32 bits of the fractional parts of the square roots of the first 8 primes).",
    ),
    (
        "sig-crypto-chacha20-constant",
        "ChaCha20 'expand 32-byte k' Magic Constant",
        "cryptography",
        "low",
        "bytes",
        b"expand 32-byte k",
        "ChaCha20 stream cipher constant found.",
    ),

    # Web Shells & Backdoors
    (
        "sig-backdoor-python-pty",
        "Interactive Python Reverse Shell (PTY Spawn)",
        "backdoor",
        "critical",
        "bytes",
        b"pty.spawn",
        "Interactive PTY allocation frequently used in Python reverse shell one-liners.",
    ),
    (
        "sig-backdoor-meterpreter-tag",
        "Metasploit Meterpreter Artifact",
        "backdoor",
        "critical",
        "bytes",
        b"meterpreter",
        "Meterpreter remote access tool artifact detected.",
    ),
    (
        "sig-backdoor-php-system",
        "PHP System Execution Backdoor Construct",
        "backdoor",
        "critical",
        "regex",
        rb"(?:\$_(?:GET|POST|REQUEST)\[.*?\]\s*\(\s*\$_(?:GET|POST|REQUEST)|eval\s*\(\s*base64_decode)",
        "Obfuscated PHP webshell dynamic evaluation construct.",
    ),
)


def scan_signatures(file_path: Path | str, rule_filter: str | None = None) -> dict[str, Any]:
    """Scan a target file with the signature & heuristics engine."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    data = path.read_bytes()
    bridge = get_native_bridge()

    matches: list[dict[str, Any]] = []
    category_counts: dict[str, int] = {}

    for rule_id, name, cat, severity, p_type, pattern, desc in SIGNATURE_RULES:
        if rule_filter and rule_filter.lower() not in rule_id.lower() and rule_filter.lower() not in cat.lower():
            continue

        offsets: list[int] = []
        if p_type == "bytes":
            idx = 0
            while True:
                found = data.find(pattern, idx)
                if found == -1:
                    break
                offsets.append(found)
                idx = found + len(pattern)
                if len(offsets) >= 10:
                    break
        elif p_type == "hex":
            offsets = bridge.pattern_scan(data, pattern, max_matches=10)
        elif p_type == "regex":
            reg = pattern if hasattr(pattern, "finditer") else re.compile(pattern)
            for m in reg.finditer(data):
                offsets.append(m.start())
                if len(offsets) >= 10:
                    break

        if offsets:
            category_counts[cat] = category_counts.get(cat, 0) + 1
            matches.append({
                "rule_id": rule_id,
                "name": name,
                "category": cat,
                "severity": severity,
                "offsets": offsets,
                "description": desc,
            })

    # Also run heuristic shellcode analysis from native core
    shellcode_hits = bridge.scan_shellcode_heuristics(data)
    for hit in shellcode_hits:
        cat = "shellcode"
        category_counts[cat] = category_counts.get(cat, 0) + 1
        matches.append({
            "rule_id": f"heur-{hit['type']}",
            "name": hit["type"].replace("_", " ").title(),
            "category": cat,
            "severity": "high" if hit.get("confidence") == "high" else "medium",
            "offsets": [hit["offset"]],
            "description": hit["description"],
            "evidence": hit.get("evidence", ""),
        })

    return {
        "file": str(path),
        "file_size": len(data),
        "total_signatures_matched": len(matches),
        "categories": category_counts,
        "matches": matches,
    }
