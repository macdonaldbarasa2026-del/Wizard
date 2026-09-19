from __future__ import annotations

import ctypes
import json
import math
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

from app.native.builder import SO_PATH, compile_native_core


class NativeBridge:
    """Seamless Python <-> C++ Native Core Bridge.
    Uses libwizard_core.so for maximum performance, with 100% pure Python fallbacks.
    """

    _instance: NativeBridge | None = None

    def __init__(self) -> None:
        self.so_path = SO_PATH
        self.lib: ctypes.CDLL | None = None
        self.is_native_loaded = False
        self._load_library()

    def _load_library(self) -> None:
        if not self.so_path.is_file():
            compile_native_core()

        if self.so_path.is_file():
            try:
                self.lib = ctypes.CDLL(str(self.so_path))
                self._setup_signatures()
                self.is_native_loaded = True
            except Exception:
                self.lib = None
                self.is_native_loaded = False

    def _setup_signatures(self) -> None:
        if not self.lib:
            return

        # int wizard_native_version(void);
        self.lib.wizard_native_version.argtypes = []
        self.lib.wizard_native_version.restype = ctypes.c_int

        # double wizard_calculate_entropy(const uint8_t* data, size_t len);
        self.lib.wizard_calculate_entropy.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        self.lib.wizard_calculate_entropy.restype = ctypes.c_double

        # int wizard_sliding_window_entropy(...)
        self.lib.wizard_sliding_window_entropy.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_double),
            ctypes.c_size_t,
        ]
        self.lib.wizard_sliding_window_entropy.restype = ctypes.c_int

        # int wizard_pattern_scan(...)
        self.lib.wizard_pattern_scan.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
        ]
        self.lib.wizard_pattern_scan.restype = ctypes.c_int

        # int wizard_find_rop_gadgets(...)
        self.lib.wizard_find_rop_gadgets.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self.lib.wizard_find_rop_gadgets.restype = ctypes.c_int

        # int wizard_scan_shellcode_heuristics(...)
        self.lib.wizard_scan_shellcode_heuristics.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self.lib.wizard_scan_shellcode_heuristics.restype = ctypes.c_int

        # int wizard_demangle_symbol(...)
        self.lib.wizard_demangle_symbol.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self.lib.wizard_demangle_symbol.restype = ctypes.c_int

        # double wizard_binary_similarity(...)
        self.lib.wizard_binary_similarity.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self.lib.wizard_binary_similarity.restype = ctypes.c_double

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def get_version(self) -> int:
        if self.is_native_loaded and self.lib:
            try:
                return int(self.lib.wizard_native_version())
            except Exception:
                pass
        return 200

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy (0.0 - 8.0 bits/byte)."""
        if not data:
            return 0.0
        if self.is_native_loaded and self.lib:
            try:
                return float(self.lib.wizard_calculate_entropy(data, len(data)))
            except Exception:
                pass

        # Python fallback
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def sliding_window_entropy(
        self, data: bytes, window_size: int = 256, step_size: int = 64, max_points: int = 4096
    ) -> list[float]:
        """Compute sliding window entropy curve."""
        if not data:
            return []

        if self.is_native_loaded and self.lib:
            try:
                out_arr = (ctypes.c_double * max_points)()
                pts = self.lib.wizard_sliding_window_entropy(
                    data, len(data), window_size, step_size, out_arr, max_points
                )
                if pts >= 0:
                    return [round(float(out_arr[i]), 4) for i in range(pts)]
            except Exception:
                pass

        # Python fallback
        points: list[float] = []
        data_len = len(data)
        offset = 0
        while offset + window_size <= data_len and len(points) < max_points:
            chunk = data[offset : offset + window_size]
            points.append(self.calculate_entropy(chunk))
            offset += step_size

        if not points and data_len > 0:
            points.append(self.calculate_entropy(data))
        return points

    def pattern_scan(self, data: bytes, pattern_hex: str, max_matches: int = 1000) -> list[int]:
        """Fast byte pattern search with wildcards ('??')."""
        if not data or not pattern_hex:
            return []

        if self.is_native_loaded and self.lib:
            try:
                out_offsets = (ctypes.c_uint64 * max_matches)()
                count = self.lib.wizard_pattern_scan(
                    data, len(data), pattern_hex.encode("utf-8"), out_offsets, max_matches
                )
                if count >= 0:
                    return [int(out_offsets[i]) for i in range(count)]
            except Exception:
                pass

        # Python fallback
        tokens = pattern_hex.strip().split()
        if not tokens:
            return []
        pattern_bytes: list[int | None] = []
        for t in tokens:
            if t in ("??", "?"):
                pattern_bytes.append(None)
            else:
                try:
                    pattern_bytes.append(int(t, 16))
                except ValueError:
                    return []

        pat_len = len(pattern_bytes)
        matches: list[int] = []
        for i in range(len(data) - pat_len + 1):
            matched = True
            for j in range(pat_len):
                if pattern_bytes[j] is not None and data[i + j] != pattern_bytes[j]:
                    matched = False
                    break
            if matched:
                matches.append(i)
                if len(matches) >= max_matches:
                    break
        return matches

    def find_rop_gadgets(
        self, code: bytes, base_vaddr: int = 0x400000, arch: str = "x86_64"
    ) -> list[dict[str, Any]]:
        """Find ROP gadgets in binary code."""
        if not code:
            return []

        if self.is_native_loaded and self.lib:
            try:
                max_buf = 512 * 1024  # 512 KB
                out_buf = ctypes.create_string_buffer(max_buf)
                ret = self.lib.wizard_find_rop_gadgets(
                    code, len(code), base_vaddr, arch.encode("utf-8"), out_buf, max_buf
                )
                if ret > 0:
                    return json.loads(out_buf.value.decode("utf-8", errors="replace"))
            except Exception:
                pass

        # Python fallback
        gadgets: list[dict[str, Any]] = []
        seen: set[str] = set()

        # Common x86/x64 sequences ending with RET (0xC3)
        prefix_ops = [
            (b"\x5f", "pop rdi"),
            (b"\x5e", "pop rsi"),
            (b"\x5a", "pop rdx"),
            (b"\x58", "pop rax"),
            (b"\x59", "pop rcx"),
            (b"\x5b", "pop rbx"),
            (b"\x5d", "pop rbp"),
            (b"\x41\x58", "pop r8"),
            (b"\x41\x59", "pop r9"),
            (b"\x41\x5a", "pop r10"),
            (b"\x41\x5b", "pop r11"),
            (b"\x41\x5c", "pop r12"),
            (b"\x41\x5d", "pop r13"),
            (b"\x41\x5e", "pop r14"),
            (b"\x41\x5f", "pop r15"),
            (b"\x5f\x5e", "pop rdi ; pop rsi"),
            (b"\xc9", "leave"),
            (b"\x48\x31\xc0", "xor rax, rax"),
            (b"\x48\x31\xff", "xor rdi, rdi"),
            (b"\x48\x31\xf6", "xor rsi, rsi"),
            (b"\x48\x31\xd2", "xor rdx, rdx"),
            (b"\x31\xc0", "xor eax, eax"),
            (b"\x31\xdb", "xor ebx, ebx"),
            (b"\x90", "nop"),
        ]

        for i, b in enumerate(code):
            if b == 0xC3:
                if "ret" not in seen:
                    seen.add("ret")
                    gadgets.append({
                        "address": base_vaddr + i,
                        "instructions": "ret",
                        "bytes": "c3",
                        "category": "control_flow",
                        "length": 1,
                    })

                for op_bytes, op_text in prefix_ops:
                    op_len = len(op_bytes)
                    if i >= op_len and code[i - op_len : i] == op_bytes:
                        instr = f"{op_text} ; ret"
                        if instr not in seen:
                            seen.add(instr)
                            hex_b = " ".join(f"{x:02x}" for x in (op_bytes + b"\xc3"))
                            gadgets.append({
                                "address": base_vaddr + i - op_len,
                                "instructions": instr,
                                "bytes": hex_b,
                                "category": "register_setter" if "pop" in op_text else "control_flow",
                                "length": op_len + 1,
                            })

            elif i + 1 < len(code) and code[i : i + 2] == b"\x0f\x05":
                if "syscall" not in seen:
                    seen.add("syscall")
                    gadgets.append({
                        "address": base_vaddr + i,
                        "instructions": "syscall",
                        "bytes": "0f 05",
                        "category": "syscall",
                        "length": 2,
                    })
            elif i + 1 < len(code) and code[i : i + 2] == b"\xcd\x80":
                if "int 0x80" not in seen:
                    seen.add("int 0x80")
                    gadgets.append({
                        "address": base_vaddr + i,
                        "instructions": "int 0x80",
                        "bytes": "cd 80",
                        "category": "syscall",
                        "length": 2,
                    })

        return gadgets

    def scan_shellcode_heuristics(self, data: bytes) -> list[dict[str, Any]]:
        """Scan byte sequence for shellcode artifacts."""
        if not data:
            return []

        if self.is_native_loaded and self.lib:
            try:
                max_buf = 256 * 1024
                out_buf = ctypes.create_string_buffer(max_buf)
                ret = self.lib.wizard_scan_shellcode_heuristics(data, len(data), out_buf, max_buf)
                if ret > 0:
                    return json.loads(out_buf.value.decode("utf-8", errors="replace"))
            except Exception:
                pass

        # Python fallback
        hits: list[dict[str, Any]] = []

        # NOP sled
        nop_matches = list(re.finditer(rb"\x90{16,}", data))
        for m in nop_matches:
            hits.append({
                "type": "nop_sled",
                "offset": m.start(),
                "confidence": "high" if len(m.group(0)) > 64 else "medium",
                "description": "Detected consecutive NOP sled sequence often used in exploit landing pads.",
                "evidence": f"Consecutive NOP count: {len(m.group(0))}",
            })

        # Syscall byte signatures
        for m in re.finditer(rb"\x0f\x05", data):
            hits.append({
                "type": "raw_syscall_x64",
                "offset": m.start(),
                "confidence": "medium",
                "description": "Direct x86_64 syscall instruction found in byte stream.",
                "evidence": "0f 05 (syscall)",
            })
            if len(hits) > 50:
                break

        return hits

    def demangle_symbol(self, mangled: str) -> str | None:
        """Demangle C++ symbol name."""
        if not mangled or not mangled.startswith(("_Z", "?")):
            return None

        if self.is_native_loaded and self.lib:
            try:
                buf = ctypes.create_string_buffer(2048)
                res = self.lib.wizard_demangle_symbol(mangled.encode("utf-8"), buf, 2048)
                if res == 0:
                    val = buf.value.decode("utf-8", errors="replace")
                    if val and val != mangled:
                        return val
            except Exception:
                pass

        # Python basic demangling fallback
        if mangled.startswith("_Z"):
            name = mangled[2:]
            # Basic parser for simple _ZN... or _Z...
            digits = ""
            for ch in name:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if digits:
                idx = len(digits)
                sz = int(digits)
                if idx + sz <= len(name):
                    return name[idx : idx + sz]
        return None

    def binary_similarity(self, data1: bytes, data2: bytes) -> float:
        """Calculate structural byte similarity (0.0 to 1.0)."""
        if not data1 or not data2:
            return 0.0
        if data1 == data2:
            return 1.0

        if self.is_native_loaded and self.lib:
            try:
                return round(float(self.lib.wizard_binary_similarity(data1, len(data1), data2, len(data2))), 4)
            except Exception:
                pass

        # Python fallback: 32-byte chunk hashing
        chunk_size = 32
        if len(data1) < chunk_size or len(data2) < chunk_size:
            min_len = min(len(data1), len(data2))
            max_len = max(len(data1), len(data2))
            same = sum(1 for i in range(min_len) if data1[i] == data2[i])
            return round(same / max_len, 4)

        chunks1: Counter[bytes] = Counter()
        for i in range(0, len(data1) - chunk_size + 1, chunk_size):
            chunks1[data1[i : i + chunk_size]] += 1

        matches = 0
        total2 = 0
        for i in range(0, len(data2) - chunk_size + 1, chunk_size):
            total2 += 1
            chunk = data2[i : i + chunk_size]
            if chunks1[chunk] > 0:
                matches += 1
                chunks1[chunk] -= 1

        total1 = len(data1) // chunk_size
        return round((2.0 * matches) / (total1 + total2), 4)

    def benchmark(self, size_bytes: int = 500000) -> dict[str, Any]:
        """Benchmark C++ Native Core vs Pure-Python execution time."""
        sample_data = bytes((i * 37 + 13) % 256 for i in range(size_bytes))

        # Benchmark Entropy in Python
        t0 = time.perf_counter()
        counts = Counter(sample_data)
        ent = 0.0
        for c in counts.values():
            p = c / size_bytes
            ent -= p * math.log2(p)
        py_time = time.perf_counter() - t0

        # Benchmark Entropy in C++ Native Core
        cpp_time = None
        speedup = 1.0
        if self.is_native_loaded and self.lib:
            t0 = time.perf_counter()
            self.lib.wizard_calculate_entropy(sample_data, len(sample_data))
            cpp_time = time.perf_counter() - t0
            if cpp_time > 0:
                speedup = round(py_time / cpp_time, 2)

        return {
            "native_loaded": self.is_native_loaded,
            "data_size_bytes": size_bytes,
            "python_time_seconds": round(py_time, 6),
            "cpp_time_seconds": round(cpp_time, 6) if cpp_time is not None else None,
            "speedup_factor": speedup,
        }


def get_native_bridge() -> NativeBridge:
    if NativeBridge._instance is None:
        NativeBridge._instance = NativeBridge()
    return NativeBridge._instance
