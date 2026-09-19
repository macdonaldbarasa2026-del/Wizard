from __future__ import annotations

from pathlib import Path
from typing import Any

from app.native.bridge import get_native_bridge


def analyze_rop_gadgets(
    file_path: Path | str,
    arch: str = "x86_64",
    filter_reg: str | None = None,
    filter_category: str | None = None,
    max_gadgets: int = 200,
) -> dict[str, Any]:
    """Extract and analyze ROP gadgets from a binary file or raw machine code."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    data = path.read_bytes()
    bridge = get_native_bridge()

    base_vaddr = 0x400000
    code_bytes = data

    # Attempt to extract the executable code sections if ELF or PE
    if data.startswith(b"\x7fELF"):
        # Basic 64-bit ELF entry search or .text section offset
        try:
            e_entry = int.from_bytes(data[24:32], "little") if len(data) >= 32 else 0x400000
            if e_entry > 0:
                base_vaddr = e_entry
        except Exception:
            pass
    elif data.startswith(b"MZ"):
        try:
            e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
            if len(data) >= e_lfanew + 44:
                entry = int.from_bytes(data[e_lfanew + 40 : e_lfanew + 44], "little")
                base_vaddr = 0x140000000 + entry
        except Exception:
            pass

    all_gadgets = bridge.find_rop_gadgets(code_bytes, base_vaddr=base_vaddr, arch=arch)

    filtered: list[dict[str, Any]] = []
    category_counts: dict[str, int] = {}
    register_counts: dict[str, int] = {}

    for g in all_gadgets:
        cat = g.get("category", "general")
        category_counts[cat] = category_counts.get(cat, 0) + 1

        instr = g.get("instructions", "")
        for reg in ("rdi", "rsi", "rdx", "rax", "rcx", "rbx", "rsp", "rbp", "r8", "r9", "r10", "r11"):
            if reg in instr:
                register_counts[reg] = register_counts.get(reg, 0) + 1

        if filter_reg and filter_reg.lower() not in instr.lower():
            continue
        if filter_category and filter_category.lower() != cat.lower():
            continue

        filtered.append(g)

    # Key exploit primitives
    has_pop_rdi = any("pop rdi" in g.get("instructions", "") for g in all_gadgets)
    has_pop_rsi = any("pop rsi" in g.get("instructions", "") for g in all_gadgets)
    has_pop_rdx = any("pop rdx" in g.get("instructions", "") for g in all_gadgets)
    has_syscall = any("syscall" in g.get("instructions", "") for g in all_gadgets)
    has_stack_pivot = any(g.get("category") == "stack_pivot" for g in all_gadgets)

    execve_chain_ready = has_pop_rdi and (has_pop_rsi or has_pop_rdx) and has_syscall

    return {
        "file": str(path),
        "total_gadgets_found": len(all_gadgets),
        "filtered_count": len(filtered),
        "categories": category_counts,
        "registers_controlled": register_counts,
        "primitives": {
            "has_pop_rdi": has_pop_rdi,
            "has_pop_rsi": has_pop_rsi,
            "has_pop_rdx": has_pop_rdx,
            "has_syscall": has_syscall,
            "has_stack_pivot": has_stack_pivot,
            "execve_chain_feasible": execve_chain_ready,
        },
        "hardening_advice": [
            "Enable Position Independent Executable (-fPIE -pie) to randomize gadget addresses via ASLR.",
            "Enable Control-flow Enforcement Technology (CET / -fcf-protection) for shadow stack protection.",
            "Enable Stack Smashing Protector (-fstack-protector-strong / -fstack-protector-all).",
            "Enable Non-Executable stack & heap (NX / DEP) with W^X enforcement.",
        ],
        "gadgets": filtered[:max_gadgets],
    }
