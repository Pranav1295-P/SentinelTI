"""Opens containers before analysis, so agents and hash lookups see the sample inside.

Extraction runs in the isolated parser process. Files land in quarantine under their hash,
read-only, exactly like a direct upload, and archive paths are never used as filesystem paths.
"""

import os
import shutil
import uuid
from pathlib import Path

from app.analysis import identify, isolated
from app.services.storage import clean_filename, quarantine_path, storage_root

MAX_NESTED = 3
MAX_EXTRA_MEMBERS = 5
OPAQUE_KINDS = {"RAR": "RAR", "7Z": "7-Zip", "GZIP": "GZIP"}
# Most likely to be the payload first. Ties go to the largest file.
KIND_RANK = {"PE": 0, "ELF": 0, "MACHO": 0, "SCRIPT": 1, "OLE": 2, "PDF": 2, "ZIP": 3, "DATA": 4}


def _sniff(path: Path) -> str:
    with path.open("rb") as handle:
        return identify.sniff_type(handle.read(16))[0]


def _opaque(filename: str, reason: str, **extra) -> dict:
    return {"primary": None, "extra": [], "container": {"filename": filename, "opaque": True, "reason": reason, **extra}}


def _extract(path: Path) -> dict:
    workdir = storage_root() / "tmp" / uuid.uuid4().hex
    workdir.mkdir(parents=True, mode=0o700)
    try:
        result = isolated.unzip(path, workdir)
        for member in result.get("members", []):
            final = quarantine_path(member["sha256"])
            final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(workdir / member["file"], 0o400)
            os.replace(workdir / member["file"], final)
            member["path"] = str(final)
            member["name"] = clean_filename(member["name"])
            member["kind"] = identify.sniff_type(bytes.fromhex(member["head"]))[0]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return result


def open_container(path: Path, filename: str) -> dict | None:
    """Return None for ordinary files, or what was found inside a container."""
    kind = _sniff(path)
    if kind in OPAQUE_KINDS:
        return _opaque(filename, f"{OPAQUE_KINDS[kind]} archives are not unpacked yet. Extract the files and upload them directly.")
    if kind != "ZIP":
        return None

    container = {"filename": filename}
    current = path
    for _ in range(MAX_NESTED):
        result = _extract(current)
        status = result.get("status")
        if status == "document":
            macros = bool(result.get("macros"))
            reason = "This Office document's compressed contents were not fully inspected."
            return {"primary": None, "extra": [], "container": {"filename": filename, "opaque": True, "macros": macros, "reason": reason}}
        if status == "locked":
            return _opaque(filename, "This archive is encrypted with an unknown password. Extract it and upload the files directly.", locked=True)
        if status != "extracted":
            return _opaque(filename, "This archive could not be opened, so its contents were not inspected.")
        members = sorted(result["members"], key=lambda m: (KIND_RANK.get(m["kind"], 4), -m["size"]))
        if not members:
            return _opaque(filename, "No files could be extracted from this archive, so nothing was inspected.")

        container.update(password=result.get("password") or container.get("password"), encrypted=result.get("encrypted") or container.get("encrypted", False),
                         member_count=len(members), skipped=result.get("skipped", 0))
        primary = members[0]
        if primary["kind"] != "ZIP":
            seen = {primary["sha256"]}
            extra = []
            for member in members[1:]:
                if member["sha256"] not in seen and member["kind"] != "ZIP" and len(extra) < MAX_EXTRA_MEMBERS:
                    seen.add(member["sha256"])
                    extra.append({"name": member["name"], "sha256": member["sha256"], "size": member["size"]})
            return {"primary": primary, "extra": extra, "container": container}
        current = Path(primary["path"])  # An archive inside an archive: go one level deeper.
    return _opaque(filename, "This archive is nested too deeply, so its contents were not inspected.")

