from __future__ import annotations

import shutil
from typing import TypedDict


class CapabilitiesDict(TypedDict):
    python: bool
    strings: bool
    objdump: bool
    readelf: bool
    file: bool
    nm: bool
    yara: bool
    ghidra: bool
    radare2: bool
    semgrep: bool


def detect_capabilities() -> CapabilitiesDict:
    """Detect available security and reverse engineering tools in the current environment."""
    return {
        "python": True,
        "strings": shutil.which("strings") is not None,
        "objdump": shutil.which("objdump") is not None,
        "readelf": shutil.which("readelf") is not None,
        "file": shutil.which("file") is not None,
        "nm": shutil.which("nm") is not None,
        "yara": shutil.which("yara") is not None,
        "ghidra": shutil.which("ghidra") is not None or shutil.which("ghidraRun") is not None,
        "radare2": shutil.which("radare2") is not None or shutil.which("r2") is not None,
        "semgrep": shutil.which("semgrep") is not None,
    }
