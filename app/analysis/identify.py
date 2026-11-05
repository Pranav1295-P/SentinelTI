"""File identification: real type from magic bytes, fingerprints and entropy."""

import hashlib
import math
from pathlib import Path

import ppdeep

FUZZY_HASH_MAX_BYTES = 32 * 1024 * 1024
HIGH_ENTROPY = 7.2

MAGIC = [
    (b"MZ", "PE", "Windows Portable Executable (MZ)"),
    (b"\x7fELF", "ELF", "ELF executable"),
    (b"\xcf\xfa\xed\xfe", "MACHO", "Mach-O binary (64-bit)"),
    (b"\xce\xfa\xed\xfe", "MACHO", "Mach-O binary (32-bit)"),
    (b"\xca\xfe\xba\xbe", "MACHO", "Mach-O universal binary"),
    (b"%PDF", "PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP", "ZIP / Office Open XML container"),
    (b"\xd0\xcf\x11\xe0", "OLE", "OLE2 compound document (legacy Office)"),
    (b"Rar!", "RAR", "RAR archive"),
    (b"7z\xbc\xaf", "7Z", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP", "GZIP archive"),
    (b"#!", "SCRIPT", "Script with shebang"),
]

# Real type -> extensions that honestly describe it.
EXPECTED_EXTENSIONS = {
    "PE": {"exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "efi", "mui", "bin"},
    "ELF": {"", "so", "elf", "bin", "o", "ko"},
    "MACHO": {"", "dylib", "bundle", "macho", "bin"},
    "PDF": {"pdf"},
    "ZIP": {"zip", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "jar", "apk", "odt", "ods"},
    "OLE": {"doc", "xls", "ppt", "msi", "msg", "dot", "xlt"},
    "RAR": {"rar"},
    "7Z": {"7z"},
    "GZIP": {"gz", "tgz"},
    "SCRIPT": {"", "sh", "py", "pl", "rb", "bash"},
}
EXECUTABLE_TYPES = {"PE", "ELF", "MACHO"}
DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4"}
RUNNABLE_EXTENSIONS = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "vbs", "ps1", "msi", "hta", "lnk"}


def sniff_type(header: bytes) -> tuple[str, str]:
    for magic, kind, label in MAGIC:
        if header.startswith(magic):
            return kind, label
    return "DATA", "Unknown / raw data"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for byte in range(256):
        count = data.count(byte)
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def identify_file(path: Path, filename: str) -> dict:
    with path.open("rb") as handle:
        header = handle.read(4096)
    kind, label = sniff_type(header)

    name = filename.lower()
    parts = name.split(".")
    extension = parts[-1] if len(parts) > 1 else ""
    expected = EXPECTED_EXTENSIONS.get(kind)

    mismatch = expected is not None and extension not in expected
    double_extension = (
        len(parts) >= 3 and parts[-2] in DECOY_EXTENSIONS and parts[-1] in RUNNABLE_EXTENSIONS
    )
    # MZ files also cover installers and resource DLLs, so this only fires on clear decoys.
    disguised = (kind in EXECUTABLE_TYPES and extension in DECOY_EXTENSIONS) or double_extension

    return {
        "kind": kind,
        "label": label,
        "extension": extension,
        "extension_mismatch": mismatch,
        "double_extension": double_extension,
        "disguised": disguised,
        "is_executable": kind in EXECUTABLE_TYPES,
        "magic_hex": header[:8].hex(),
    }


def compute_hashes(path: Path) -> dict:
    md5, sha1, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False), hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    # ppdeep is pure Python, so very large files skip the fuzzy hash rather than stall.
    ssdeep = ppdeep.hash_from_file(str(path)) if size <= FUZZY_HASH_MAX_BYTES else None
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "ssdeep": ssdeep,
        "size_bytes": size,
    }


def file_entropy(path: Path, max_bytes: int = 64 * 1024 * 1024) -> float:
    with path.open("rb") as handle:
        return shannon_entropy(handle.read(max_bytes))
