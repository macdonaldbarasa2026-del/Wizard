from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.models.schemas import (
    BinaryMetadata,
    Finding,
    ReverseEngineeringResult,
    SectionDetail,
)
from app.security.capabilities import detect_capabilities
from app.security.executor import safe_executor


# ---------------------------------------------------------------------------
# Entropy Calculation
# ---------------------------------------------------------------------------

def calculate_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence (0.0 to 8.0 bits/byte)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


# ---------------------------------------------------------------------------
# Strings Extraction & Classification
# ---------------------------------------------------------------------------

URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9_\-./?&=%#:+~]+")
IPV4_PATTERN = re.compile(r"\b(?:[1-9]\d{0,2}\.){3}[1-9]\d{0,2}\b")
PATH_PATTERN = re.compile(
    r"(?:/(?:usr|bin|sbin|etc|var|tmp|home|lib|dev|opt|data)/[a-zA-Z0-9_.\-]+)|(?:[A-Za-z]:\\[a-zA-Z0-9_.\\]+)"
)
SUSPICIOUS_API_PATTERN = re.compile(
    r"\b(ptrace|execve|system|mprotect|VirtualAlloc|VirtualProtect|WriteProcessMemory|"
    r"CreateRemoteThread|LoadLibrary[AW]?|GetProcAddress|fork|socket|connect|bind|dlopen|chmod|setuid)\b"
)
CRYPTO_KEY_PATTERN = re.compile(r"(?:BEGIN [A-Z ]*KEY|AES_|RSA_|SHA256)", re.IGNORECASE)


def extract_strings(data: bytes, min_len: int = 4, max_strings: int = 300) -> dict[str, list[str]]:
    """Extract and categorize ASCII and UTF-16LE printable strings from raw bytes."""
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    extracted_raw = [m.group(0).decode("ascii", errors="ignore") for m in ascii_pattern.finditer(data)]

    # Also search for basic UTF-16LE strings
    utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for m in utf16_pattern.finditer(data):
        try:
            extracted_raw.append(m.group(0).decode("utf-16le", errors="ignore"))
        except Exception:
            pass

    urls: set[str] = set()
    ips: set[str] = set()
    paths: set[str] = set()
    apis: set[str] = set()
    crypto: set[str] = set()
    general: list[str] = []

    for s in extracted_raw:
        s_clean = s.strip()
        if not s_clean:
            continue

        matched = False
        for url in URL_PATTERN.findall(s_clean):
            urls.add(url)
            matched = True
        for ip in IPV4_PATTERN.findall(s_clean):
            # Ignore broadcast and localhost from raw match noise if desired, but keep for RE
            ips.add(ip)
            matched = True
        for p in PATH_PATTERN.findall(s_clean):
            paths.add(p)
            matched = True
        for api in SUSPICIOUS_API_PATTERN.findall(s_clean):
            apis.add(api)
            matched = True
        for cr in CRYPTO_KEY_PATTERN.findall(s_clean):
            crypto.add(cr)
            matched = True

        if not matched and len(general) < max_strings:
            general.append(s_clean)

    return {
        "urls": sorted(urls)[:50],
        "ips": sorted(ips)[:50],
        "paths": sorted(paths)[:50],
        "suspicious_apis": sorted(apis)[:50],
        "crypto_indicators": sorted(crypto)[:50],
        "sample": general[:100],
    }


# ---------------------------------------------------------------------------
# ELF Binary Parser (Pure Python)
# ---------------------------------------------------------------------------

ELF_MACHINES = {
    0x03: "x86",
    0x08: "MIPS",
    0x28: "ARM",
    0x3E: "x86_64 (AMD64)",
    0xB7: "AArch64 (ARM64)",
    0xF3: "RISC-V",
}

ELF_TYPES = {
    1: "ET_REL (Relocatable object)",
    2: "ET_EXEC (Executable file)",
    3: "ET_DYN (Shared object / PIE Executable)",
    4: "ET_CORE (Core dump)",
}


def parse_elf(data: bytes, file_path_str: str) -> tuple[BinaryMetadata, list[Finding], list[str]]:
    findings: list[Finding] = []
    suspicious_indicators: list[str] = []
    errors: list[str] = []

    if len(data) < 52:
        raise ValueError("File too small for valid ELF header.")

    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]   # 1 = LE, 2 = BE

    bits = 64 if ei_class == 2 else 32
    endian_fmt = "<" if ei_data == 1 else ">"
    endian_name = "little-endian" if ei_data == 1 else "big-endian"

    try:
        if bits == 64:
            header_fmt = f"{endian_fmt}16sHHIQQQIHHHHHH"
            (
                ident, e_type, e_machine, e_version,
                e_entry, e_phoff, e_shoff, e_flags,
                e_ehsize, e_phentsize, e_phnum,
                e_shentsize, e_shnum, e_shstrndx
            ) = struct.unpack_from(header_fmt, data, 0)
        else:
            header_fmt = f"{endian_fmt}16sHHIIIIIHHHHHH"
            (
                ident, e_type, e_machine, e_version,
                e_entry, e_phoff, e_shoff, e_flags,
                e_ehsize, e_phentsize, e_phnum,
                e_shentsize, e_shnum, e_shstrndx
            ) = struct.unpack_from(header_fmt, data, 0)
    except Exception as exc:
        raise ValueError(f"Corrupt or unsupported ELF header: {exc}")

    arch = ELF_MACHINES.get(e_machine, f"Unknown (0x{e_machine:x})")
    type_desc = ELF_TYPES.get(e_type, f"Type {e_type}")

    # Security Hardening Flags
    hardening = {
        "pie": e_type == 3,  # ET_DYN is PIE if executable
        "nx": True,          # Assume NX until checked via PT_GNU_STACK
        "canary": False,
        "relro": False,
    }

    if not hardening["pie"]:
        findings.append(
            Finding(
                id=uuid4().hex[:12],
                module="reverse-engineering",
                severity="medium",
                title="Position Independent Executable (PIE) Disabled",
                description="Binary was compiled as a fixed-position executable (ET_EXEC), preventing full ASLR randomization.",
                evidence=f"ELF e_type is {type_desc} (0x{e_type:x}).",
                file=file_path_str,
                rule="re-elf-no-pie",
                confidence="high",
                remediation="Compile with '-fPIE -pie' to enable Address Space Layout Randomization (ASLR).",
                references=["https://cwe.mitre.org/data/definitions/119.html"],
            )
        )
        suspicious_indicators.append("PIE disabled (fixed memory layout)")

    # Parse Program Headers (Segments)
    pt_gnu_stack = 0x6474e551
    if e_phoff > 0 and e_phnum > 0 and e_phoff + (e_phnum * e_phentsize) <= len(data):
        for i in range(e_phnum):
            ph_offset = e_phoff + (i * e_phentsize)
            if bits == 64:
                p_type, p_flags = struct.unpack_from(f"{endian_fmt}II", data, ph_offset)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags = struct.unpack_from(
                    f"{endian_fmt}IIIIIII", data, ph_offset
                )
            if p_type == pt_gnu_stack:
                # PF_X is bit 0 (0x1)
                if p_flags & 0x1:
                    hardening["nx"] = False
                    findings.append(
                        Finding(
                            id=uuid4().hex[:12],
                            module="reverse-engineering",
                            severity="high",
                            title="Executable Stack Detected (NX Protection Disabled)",
                            description="The GNU_STACK program segment has execute permissions enabled, exposing the binary to stack buffer overflow exploitation.",
                            evidence=f"PT_GNU_STACK flags: 0x{p_flags:x} (PF_X executable bit is set).",
                            file=file_path_str,
                            rule="re-elf-executable-stack",
                            confidence="high",
                            remediation="Compile with '-z noexecstack' to prevent execution of code on the stack.",
                            references=["https://cwe.mitre.org/data/definitions/119.html"],
                        )
                    )
                    suspicious_indicators.append("Executable stack (NX disabled)")

    # Read Section String Table (.shstrtab)
    shstrtab_bytes = b""
    if 0 <= e_shstrndx < e_shnum:
        shstr_offset = e_shoff + (e_shstrndx * e_shentsize)
        if shstr_offset + e_shentsize <= len(data):
            if bits == 64:
                sh_offset, sh_size = struct.unpack_from(f"{endian_fmt}QQ", data, shstr_offset + 24)
            else:
                sh_offset, sh_size = struct.unpack_from(f"{endian_fmt}II", data, shstr_offset + 16)
            if sh_offset + sh_size <= len(data):
                shstrtab_bytes = data[sh_offset:sh_offset + sh_size]

    def get_sh_name(offset: int) -> str:
        if not shstrtab_bytes or offset >= len(shstrtab_bytes):
            return f"sec_{offset}"
        null_pos = shstrtab_bytes.find(b"\x00", offset)
        if null_pos != -1:
            return shstrtab_bytes[offset:null_pos].decode("ascii", errors="replace")
        return shstrtab_bytes[offset:].decode("ascii", errors="replace")

    sections: list[SectionDetail] = []
    section_names: set[str] = set()

    if e_shoff > 0 and e_shnum > 0 and e_shoff + (e_shnum * e_shentsize) <= len(data):
        for i in range(e_shnum):
            s_offset = e_shoff + (i * e_shentsize)
            if bits == 64:
                sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                    f"{endian_fmt}IIQQQQ", data, s_offset
                )
            else:
                sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                    f"{endian_fmt}IIIIII", data, s_offset
                )

            name = get_sh_name(sh_name_idx)
            section_names.add(name)

            sec_data = b""
            if sh_offset + sh_size <= len(data):
                sec_data = data[sh_offset:sh_offset + sh_size]

            sec_entropy = calculate_entropy(sec_data) if sec_data else 0.0

            # Flags: 1=WRITE, 2=ALLOC, 4=EXEC
            writable = bool(sh_flags & 0x1)
            alloc = bool(sh_flags & 0x2)
            executable = bool(sh_flags & 0x4)

            suspicious = False
            reason = None

            # W^X check (writable and executable)
            if writable and executable:
                suspicious = True
                reason = "Writable and Executable section (W^X memory violation)"
                suspicious_indicators.append(f"W+X section '{name}' detected")
                findings.append(
                    Finding(
                        id=uuid4().hex[:12],
                        module="reverse-engineering",
                        severity="high",
                        title=f"W^X Violation: Section '{name}' is Writable and Executable",
                        description=f"Section '{name}' has both write and execute permissions, enabling self-modifying code or in-memory shellcode execution.",
                        evidence=f"Section flags: 0x{sh_flags:x} (WRITE | EXECINSTR). Size: {sh_size} bytes.",
                        file=file_path_str,
                        rule="re-wx-section",
                        confidence="high",
                        remediation="Ensure code sections are read-only (.rodata, .text) and data sections are non-executable.",
                        references=["https://cwe.mitre.org/data/definitions/119.html"],
                    )
                )

            # High entropy section (> 7.2 bits) check
            if sec_entropy > 7.2 and sh_size > 1024:
                suspicious = True
                reason = f"High entropy ({sec_entropy} bits), potential packing or encryption"
                suspicious_indicators.append(f"Section '{name}' has high entropy ({sec_entropy})")
                findings.append(
                    Finding(
                        id=uuid4().hex[:12],
                        module="reverse-engineering",
                        severity="medium",
                        title=f"High Entropy Section: '{name}' (Entropy {sec_entropy})",
                        description=f"Section '{name}' exhibits high Shannon entropy, indicating compressed, encrypted, or packed payload code.",
                        evidence=f"Calculated entropy: {sec_entropy:.4f} / 8.0, Size: {sh_size} bytes.",
                        file=file_path_str,
                        rule="re-high-entropy-section",
                        confidence="medium",
                        remediation="Inspect section content for packing (e.g. UPX), embedded encrypted payloads, or obfuscation.",
                        references=["https://cwe.mitre.org/data/definitions/506.html"],
                    )
                )

            flag_desc = []
            if alloc:
                flag_desc.append("A")
            if writable:
                flag_desc.append("W")
            if executable:
                flag_desc.append("X")

            sections.append(
                SectionDetail(
                    name=name or f"unnamed_{i}",
                    size=sh_size,
                    virtual_address=sh_addr,
                    offset=sh_offset,
                    flags="".join(flag_desc),
                    readable=True,
                    writable=writable,
                    executable=executable,
                    entropy=sec_entropy,
                    suspicious=suspicious,
                    suspicious_reason=reason,
                )
            )

    # Check for symbols table
    is_stripped = ".symtab" not in section_names
    if is_stripped:
        suspicious_indicators.append("Stripped binary (symbol table removed)")

    # Overall file entropy
    overall_entropy = calculate_entropy(data)
    if overall_entropy > 7.3:
        findings.append(
            Finding(
                id=uuid4().hex[:12],
                module="reverse-engineering",
                severity="medium",
                title=f"High Overall File Entropy ({overall_entropy})",
                description="The entire binary file exhibits very high entropy, strongly suggesting a packed, compressed, or encrypted executable.",
                evidence=f"File entropy is {overall_entropy} / 8.0.",
                file=file_path_str,
                rule="re-binary-packed-entropy",
                confidence="medium",
                remediation="Analyze binary with unpackers or dynamic sandbox observation to inspect unpacked memory.",
                references=["https://cwe.mitre.org/data/definitions/506.html"],
            )
        )

    metadata = BinaryMetadata(
        file_type="ELF Executable / Shared Object",
        format="ELF",
        architecture=arch,
        bits=bits,
        endian=endian_name,
        entry_point=e_entry,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        entropy=overall_entropy,
        sections=sections,
        imports=[],
        exports=[],
        symbols=["[stripped]"] if is_stripped else list(section_names)[:30],
        hardening=hardening,
        suspicious_indicators=suspicious_indicators,
    )

    return metadata, findings, errors


# ---------------------------------------------------------------------------
# PE Binary Parser (Pure Python)
# ---------------------------------------------------------------------------

PE_MACHINES = {
    0x14C: "Intel 386 (i386)",
    0x8664: "AMD64 (x86_64)",
    0xAA64: "ARM64",
}


def parse_pe(data: bytes, file_path_str: str) -> tuple[BinaryMetadata, list[Finding], list[str]]:
    findings: list[Finding] = []
    suspicious_indicators: list[str] = []
    errors: list[str] = []

    if len(data) < 64:
        raise ValueError("File too small for valid PE header.")

    # Offset to PE header at 0x3C
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        raise ValueError("Invalid PE header offset.")

    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature.")

    # COFF File Header
    coff_offset = e_lfanew + 4
    machine, num_sections, timedate, symtab_offset, num_symbols, opt_hdr_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff_offset
    )

    arch = PE_MACHINES.get(machine, f"Unknown PE Machine (0x{machine:x})")
    opt_offset = coff_offset + 20

    bits = 32
    entry_point = 0
    dll_characteristics = 0

    if opt_hdr_size >= 28 and opt_offset + opt_hdr_size <= len(data):
        magic = struct.unpack_from("<H", data, opt_offset)[0]
        if magic == 0x20B:  # PE32+ (64-bit)
            bits = 64
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            if opt_hdr_size >= 70:
                dll_characteristics = struct.unpack_from("<H", data, opt_offset + 70)[0]
        elif magic == 0x10B:  # PE32 (32-bit)
            bits = 32
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            if opt_hdr_size >= 70:
                dll_characteristics = struct.unpack_from("<H", data, opt_offset + 70)[0]

    # Hardening indicators
    aslr = bool(dll_characteristics & 0x0040)
    dep_nx = bool(dll_characteristics & 0x0100)
    hardening = {
        "aslr": aslr,
        "dep_nx": dep_nx,
        "no_seh": bool(dll_characteristics & 0x0400),
    }

    if not aslr:
        findings.append(
            Finding(
                id=uuid4().hex[:12],
                module="reverse-engineering",
                severity="medium",
                title="PE ASLR (Dynamic Base) Disabled",
                description="PE optional header DllCharacteristics lacks IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag.",
                evidence=f"DllCharacteristics: 0x{dll_characteristics:04x}.",
                file=file_path_str,
                rule="re-pe-no-aslr",
                confidence="high",
                remediation="Link with '/DYNAMICBASE' in MSVC or '--dynamicbase' in MinGW.",
                references=["https://cwe.mitre.org/data/definitions/119.html"],
            )
        )
        suspicious_indicators.append("ASLR disabled in PE header")

    if not dep_nx:
        findings.append(
            Finding(
                id=uuid4().hex[:12],
                module="reverse-engineering",
                severity="high",
                title="PE Data Execution Prevention (DEP/NX) Disabled",
                description="PE optional header lacks IMAGE_DLLCHARACTERISTICS_NX_COMPAT flag.",
                evidence=f"DllCharacteristics: 0x{dll_characteristics:04x}.",
                file=file_path_str,
                rule="re-pe-no-dep",
                confidence="high",
                remediation="Link with '/NXCOMPAT' in MSVC or '--nxcompat' in MinGW.",
                references=["https://cwe.mitre.org/data/definitions/119.html"],
            )
        )
        suspicious_indicators.append("DEP/NX disabled in PE header")

    # Section Headers
    sec_offset = opt_offset + opt_hdr_size
    sections: list[SectionDetail] = []

    for i in range(num_sections):
        s_pos = sec_offset + (i * 40)
        if s_pos + 40 > len(data):
            break

        sec_name_raw, v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<8sIIII", data, s_pos)
        sec_chars = struct.unpack_from("<I", data, s_pos + 36)[0]

        sec_name = sec_name_raw.rstrip(b"\x00").decode("ascii", errors="replace")

        sec_data = b""
        if raw_ptr + raw_size <= len(data):
            sec_data = data[raw_ptr:raw_ptr + raw_size]

        sec_entropy = calculate_entropy(sec_data) if sec_data else 0.0

        # PE Characteristics flags: 0x20000000 = EXECUTE, 0x40000000 = READ, 0x80000000 = WRITE
        executable = bool(sec_chars & 0x20000000)
        writable = bool(sec_chars & 0x80000000)
        readable = bool(sec_chars & 0x40000000)

        suspicious = False
        reason = None

        if executable and writable:
            suspicious = True
            reason = "Writable and Executable PE section"
            suspicious_indicators.append(f"W+X section '{sec_name}'")
            findings.append(
                Finding(
                    id=uuid4().hex[:12],
                    module="reverse-engineering",
                    severity="high",
                    title=f"W^X Violation: PE Section '{sec_name}' is Writable and Executable",
                    description=f"PE section '{sec_name}' contains both write and execute characteristics.",
                    evidence=f"Characteristics: 0x{sec_chars:08x}.",
                    file=file_path_str,
                    rule="re-pe-wx-section",
                    confidence="high",
                    remediation="Configure section characteristics to prevent simultaneous write and execute permissions.",
                    references=["https://cwe.mitre.org/data/definitions/119.html"],
                )
            )

        if sec_entropy > 7.2 and raw_size > 1024:
            suspicious = True
            reason = f"High entropy ({sec_entropy} bits)"
            suspicious_indicators.append(f"High entropy section '{sec_name}'")

        sections.append(
            SectionDetail(
                name=sec_name,
                size=raw_size,
                virtual_address=v_addr,
                offset=raw_ptr,
                flags=f"0x{sec_chars:08x}",
                readable=readable,
                writable=writable,
                executable=executable,
                entropy=sec_entropy,
                suspicious=suspicious,
                suspicious_reason=reason,
            )
        )

    overall_entropy = calculate_entropy(data)

    metadata = BinaryMetadata(
        file_type="PE / Windows Executable",
        format="PE",
        architecture=arch,
        bits=bits,
        endian="little-endian",
        entry_point=entry_point,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        entropy=overall_entropy,
        sections=sections,
        imports=[],
        exports=[],
        symbols=[],
        hardening=hardening,
        suspicious_indicators=suspicious_indicators,
    )

    return metadata, findings, errors


# ---------------------------------------------------------------------------
# Mach-O Binary Parser (Pure Python)
# ---------------------------------------------------------------------------

MACHO_CPUS = {
    7: "x86",
    7 | 0x01000000: "x86_64",
    12: "ARM",
    12 | 0x01000000: "ARM64 (Apple Silicon)",
}


def parse_macho(data: bytes, file_path_str: str) -> tuple[BinaryMetadata, list[Finding], list[str]]:
    findings: list[Finding] = []
    suspicious_indicators: list[str] = []
    errors: list[str] = []

    magic = struct.unpack_from(">I", data, 0)[0]
    little_endian = magic in (0xCEFAEDFE, 0xCFFAEDFE)
    endian_fmt = "<" if little_endian else ">"
    magic_val = struct.unpack_from(f"{endian_fmt}I", data, 0)[0]

    bits = 64 if magic_val in (0xFEEDFACF, 0xCFFAEDFE) else 32
    cputype, cpusubtype, filetype, ncmds, sizeofcmds = struct.unpack_from(
        f"{endian_fmt}IIIII", data, 4
    )

    arch = MACHO_CPUS.get(cputype, f"Mach-O CPU 0x{cputype:x}")
    overall_entropy = calculate_entropy(data)

    metadata = BinaryMetadata(
        file_type="Mach-O Binary (macOS / iOS)",
        format="Mach-O",
        architecture=arch,
        bits=bits,
        endian="little-endian" if little_endian else "big-endian",
        entry_point=None,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        entropy=overall_entropy,
        sections=[],
        imports=[],
        exports=[],
        symbols=[],
        hardening={"pie": True},
        suspicious_indicators=suspicious_indicators,
    )

    return metadata, findings, errors


# ---------------------------------------------------------------------------
# Main Reverse Engineering Analyzer
# ---------------------------------------------------------------------------

def analyze_binary(path: Path) -> ReverseEngineeringResult:
    """Perform full defensive reverse engineering analysis on a binary or source file."""
    timestamp = datetime.now(timezone.utc).isoformat()
    caps = detect_capabilities()
    errors: list[str] = []

    if not path.is_file():
        return ReverseEngineeringResult(
            tool_used="wizard-re-engine",
            input_file=path.name,
            status="error",
            errors=[f"File not found: {path}"],
            timestamp=timestamp,
        )

    try:
        data = path.read_bytes()
    except OSError as exc:
        return ReverseEngineeringResult(
            tool_used="wizard-re-engine",
            input_file=path.name,
            status="error",
            errors=[f"Failed to read file: {exc}"],
            timestamp=timestamp,
        )

    header_16 = data[:16]
    metadata: BinaryMetadata | None = None
    findings: list[Finding] = []

    # Detect Binary Format
    if header_16.startswith(b"\x7fELF"):
        try:
            metadata, findings, parse_errs = parse_elf(data, path.name)
            errors.extend(parse_errs)
        except Exception as exc:
            errors.append(f"ELF parse error: {exc}")
    elif header_16.startswith(b"MZ"):
        try:
            metadata, findings, parse_errs = parse_pe(data, path.name)
            errors.extend(parse_errs)
        except Exception as exc:
            errors.append(f"PE parse error: {exc}")
    elif header_16[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        try:
            metadata, findings, parse_errs = parse_macho(data, path.name)
            errors.extend(parse_errs)
        except Exception as exc:
            errors.append(f"Mach-O parse error: {exc}")
    else:
        # Non-executable file (script, archive, text, etc.)
        entropy = calculate_entropy(data)
        metadata = BinaryMetadata(
            file_type="Non-executable / Data / Source",
            format="Generic",
            architecture="N/A",
            bits=0,
            endian="N/A",
            entry_point=None,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            entropy=entropy,
            sections=[],
            imports=[],
            exports=[],
            symbols=[],
            hardening={},
            suspicious_indicators=[],
        )

    # Strings extraction
    strings_dict = extract_strings(data)

    # Disassembly integration (safe check via objdump if available and executable)
    disassembly_lines: list[str] = []
    if caps["objdump"] and metadata and metadata.format in ("ELF", "PE"):
        try:
            record = safe_executor.execute(
                command="objdump",
                arguments=["-d", "--no-show-raw-insn", str(path)],
            )
            if record.output:
                # Capture top 60 lines of disassembled code
                disassembly_lines = [
                    line for line in record.output.splitlines()[:60] if line.strip()
                ]
        except Exception as exc:
            errors.append(f"Disassembly via objdump failed: {exc}")
    elif not caps["objdump"]:
        errors.append("objdump is not installed; disassembly skipped without failure.")

    # Correlate suspicious strings with findings
    if strings_dict.get("suspicious_apis"):
        apis_found = strings_dict["suspicious_apis"]
        findings.append(
            Finding(
                id=uuid4().hex[:12],
                module="reverse-engineering",
                severity="medium",
                title=f"Suspicious Process Manipulation APIs Found in Strings",
                description=f"Binary strings reference potentially sensitive or privileged APIs: {', '.join(apis_found[:8])}.",
                evidence=f"Referenced APIs: {apis_found}",
                file=path.name,
                rule="re-suspicious-apis",
                confidence="medium",
                remediation="Verify if these system or process manipulation calls are legitimate for the application's intended functionality.",
                references=["https://cwe.mitre.org/data/definitions/250.html"],
            )
        )

    return ReverseEngineeringResult(
        tool_used="wizard-re-engine",
        input_file=path.name,
        status="completed" if not errors or len(findings) > 0 else "warning",
        metadata=metadata,
        strings=strings_dict,
        disassembly=disassembly_lines,
        findings=findings,
        errors=errors,
        timestamp=timestamp,
    )
