"""Quarantine storage for uploaded samples.

Samples are content-addressed, read-only and non-executable. No API route ever
serves them back, and nothing outside the isolated parser process loads them.
"""

import hashlib
import os
import re
import tempfile
from pathlib import Path

from fastapi import UploadFile

from app.core.config import settings

CHUNK_SIZE = 1024 * 1024
_UNSAFE_NAME = re.compile(r"[\x00-\x1f\x7f]")


class UploadTooLarge(Exception):
    pass


class EmptyUpload(Exception):
    pass


def storage_root() -> Path:
    return Path(settings.storage_path).resolve()


def quarantine_path(sha256: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{64}", sha256):
        raise ValueError("invalid sha256")
    return storage_root() / "quarantine" / sha256[:2] / f"{sha256}.bin"


def report_path(analysis_id: str) -> Path:
    return storage_root() / "reports" / f"{analysis_id}.pdf"


def clean_filename(name: str | None) -> str:
    """Keep the name for display and extension checks; drop any path and control characters."""
    base = (name or "sample").replace("\\", "/").rsplit("/", 1)[-1]
    base = _UNSAFE_NAME.sub("", base).strip()
    return base[:255] or "sample"


async def save_upload(upload: UploadFile) -> tuple[str, int]:
    """Stream an upload into quarantine, enforcing the size limit. Returns (sha256, size)."""
    digest = hashlib.sha256()
    size = 0
    tmp_dir = storage_root() / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(dir=tmp_dir)
    try:
        with os.fdopen(fd, "wb") as tmp:
            while chunk := await upload.read(CHUNK_SIZE):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise UploadTooLarge
                digest.update(chunk)
                tmp.write(chunk)
        if size == 0:
            raise EmptyUpload

        sha256 = digest.hexdigest()
        final = quarantine_path(sha256)
        final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(tmp_name, 0o400)
        os.replace(tmp_name, final)
        return sha256, size
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
