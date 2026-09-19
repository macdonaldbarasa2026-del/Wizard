from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

NATIVE_DIR = Path(__file__).resolve().parent
SO_PATH = NATIVE_DIR / "libwizard_core.so"
CPP_SOURCE = NATIVE_DIR / "wizard_core.cpp"
HPP_HEADER = NATIVE_DIR / "wizard_core.hpp"


def get_available_compiler() -> str | None:
    """Find available C++ compiler."""
    for compiler in ("g++", "clang++", "c++"):
        if shutil.which(compiler):
            return compiler
    return None


def compile_native_core(force: bool = False) -> bool:
    """Compile libwizard_core.so if not present or forced.
    Returns True if compiled successfully, False otherwise.
    """
    if SO_PATH.is_file() and not force:
        return True

    compiler = get_available_compiler()
    if not compiler:
        return False

    cmd = [
        compiler,
        "-O3",
        "-fPIC",
        "-std=c++17",
        "-Wall",
        "-Wextra",
        "-shared",
        "-o",
        str(SO_PATH),
        str(CPP_SOURCE),
    ]

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return SO_PATH.is_file()
    except Exception:
        return False


if __name__ == "__main__":
    success = compile_native_core(force=True)
    if success:
        print(f"[+] Native core compiled successfully: {SO_PATH}")
    else:
        print("[!] Native core compilation failed or no compiler available.")
