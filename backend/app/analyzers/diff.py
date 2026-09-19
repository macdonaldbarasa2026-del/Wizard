from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from app.analyzers.reverse_engineering import analyze_binary, extract_strings
from app.native.bridge import get_native_bridge


def diff_binaries(file1: Path | str, file2: Path | str) -> dict[str, Any]:
    """Perform in-depth structural and byte-level diffing between two binary files."""
    path1 = Path(file1)
    path2 = Path(file2)

    if not path1.is_file():
        raise FileNotFoundError(f"Target file 1 does not exist: {file1}")
    if not path2.is_file():
        raise FileNotFoundError(f"Target file 2 does not exist: {file2}")

    data1 = path1.read_bytes()
    data2 = path2.read_bytes()

    sha256_1 = hashlib.sha256(data1).hexdigest()
    sha256_2 = hashlib.sha256(data2).hexdigest()

    bridge = get_native_bridge()
    similarity_score = bridge.binary_similarity(data1, data2)

    identical = sha256_1 == sha256_2

    # Reverse engineering metadata
    re1 = analyze_binary(path1)
    re2 = analyze_binary(path2)

    meta1 = re1.metadata
    meta2 = re2.metadata

    # Section comparison
    sections1 = {s.name: s for s in meta1.sections} if meta1 else {}
    sections2 = {s.name: s for s in meta2.sections} if meta2 else {}

    added_sections = [name for name in sections2 if name not in sections1]
    removed_sections = [name for name in sections1 if name not in sections2]
    common_sections = [name for name in sections1 if name in sections2]

    modified_sections: list[dict[str, Any]] = []
    for name in common_sections:
        s1 = sections1[name]
        s2 = sections2[name]
        if s1.size != s2.size or abs(s1.entropy - s2.entropy) > 0.05 or s1.flags != s2.flags:
            modified_sections.append({
                "section": name,
                "size_before": s1.size,
                "size_after": s2.size,
                "size_diff": s2.size - s1.size,
                "entropy_before": s1.entropy,
                "entropy_after": s2.entropy,
                "flags_before": s1.flags,
                "flags_after": s2.flags,
            })

    # Strings comparison
    str1 = extract_strings(data1, min_len=5, max_strings=200)
    str2 = extract_strings(data2, min_len=5, max_strings=200)

    apis1 = set(str1.get("suspicious_apis", []))
    apis2 = set(str2.get("suspicious_apis", []))

    new_apis = sorted(apis2 - apis1)
    removed_apis = sorted(apis1 - apis2)

    # Verdict
    if identical:
        verdict = "Identical (Hashes match)"
    elif similarity_score > 0.90:
        verdict = "Minor Patch / Localized Modification"
    elif similarity_score > 0.60:
        verdict = "Moderate Refactoring / Variant Codebase"
    else:
        verdict = "Substantially Divergent or Distinct Binaries"

    return {
        "file1": {
            "path": str(path1),
            "size": len(data1),
            "sha256": sha256_1,
            "format": meta1.format if meta1 else "unknown",
            "architecture": meta1.architecture if meta1 else "unknown",
            "entropy": meta1.entropy if meta1 else bridge.calculate_entropy(data1),
        },
        "file2": {
            "path": str(path2),
            "size": len(data2),
            "sha256": sha256_2,
            "format": meta2.format if meta2 else "unknown",
            "architecture": meta2.architecture if meta2 else "unknown",
            "entropy": meta2.entropy if meta2 else bridge.calculate_entropy(data2),
        },
        "identical": identical,
        "similarity_score": similarity_score,
        "verdict": verdict,
        "sections": {
            "added": added_sections,
            "removed": removed_sections,
            "modified": modified_sections,
        },
        "apis": {
            "newly_introduced": new_apis,
            "removed": removed_apis,
        },
    }
