from __future__ import annotations

import hashlib
from pathlib import Path


LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C/C++",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".php": "PHP",
    ".rb": "Ruby",
    ".swift": "Swift",
    ".dart": "Dart",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".json": "JSON",
    ".xml": "XML",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".sql": "SQL",
    ".sh": "Shell",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def detect_binary(path: Path) -> tuple[bool, str | None]:
    with path.open("rb") as handle:
        header = handle.read(16)

    if header.startswith(b"\x7fELF"):
        return True, "ELF"

    if header.startswith(b"MZ"):
        return True, "PE/COFF"

    if header[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }:
        return True, "Mach-O"

    return False, None


def analyze_inventory(root: Path) -> dict:
    files: list[dict] = []
    language_counts: dict[str, int] = {}
    binary_counts: dict[str, int] = {}
    total_bytes = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue

        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        binary, binary_type = detect_binary(path)
        language = None if binary else LANGUAGES.get(path.suffix.lower())

        total_bytes += size

        if language:
            language_counts[language] = language_counts.get(language, 0) + 1

        if binary_type:
            binary_counts[binary_type] = binary_counts.get(binary_type, 0) + 1

        files.append(
            {
                "path": relative,
                "size": size,
                "sha256": sha256_file(path),
                "binary": binary,
                "binary_type": binary_type,
                "language": language,
            }
        )

    return {
        "total_files": len(files),
        "total_bytes": total_bytes,
        "languages": dict(sorted(language_counts.items())),
        "binary_types": dict(sorted(binary_counts.items())),
        "files": files,
    }
