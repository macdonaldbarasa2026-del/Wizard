from __future__ import annotations

from pathlib import Path, PurePosixPath
import zipfile


MAX_ZIP_FILES = 10_000
MAX_SINGLE_FILE_BYTES = 25 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 250 * 1024 * 1024


class ArchiveError(ValueError):
    pass


def _safe_member_path(target: Path, name: str) -> Path:
    if not name or "\x00" in name:
        raise ArchiveError("Invalid archive member name.")

    relative = PurePosixPath(name)

    if relative.is_absolute():
        raise ArchiveError("Absolute archive paths are not allowed.")

    if any(part == ".." for part in relative.parts):
        raise ArchiveError("Path traversal detected in archive.")

    destination = (target / Path(*relative.parts)).resolve()
    target_resolved = target.resolve()

    try:
        destination.relative_to(target_resolved)
    except ValueError as exc:
        raise ArchiveError("Archive member escapes the extraction directory.") from exc

    return destination


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return (mode & 0o170000) == 0o120000


def extract_zip(zip_path: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()

        if len(infos) > MAX_ZIP_FILES:
            raise ArchiveError("Archive contains too many files.")

        total_size = 0

        for info in infos:
            if info.file_size > MAX_SINGLE_FILE_BYTES:
                raise ArchiveError(f"Archive member too large: {info.filename}")

            total_size += info.file_size

            if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ArchiveError("Archive exceeds the uncompressed size limit.")

            if _is_symlink(info):
                raise ArchiveError("Symbolic links are not allowed in uploaded archives.")

            destination = _safe_member_path(target, info.filename)

            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)

            with archive.open(info) as source, destination.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
