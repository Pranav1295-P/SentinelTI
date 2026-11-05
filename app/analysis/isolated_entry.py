"""Runs LIEF and YARA against an untrusted file, in a throwaway process.

Native parsers are the riskiest code that touches a sample. This module runs as
its own process with resource limits and an environment holding no secrets, so a
parser crash or hang costs one tool call and never the worker. It must not import
app.core.config.

Usage: python -m app.analysis.isolated_entry {pe|yara} <file> [rules_dir]
"""

import json
import math
import resource
import sys
from datetime import UTC, datetime
from pathlib import Path

MAX_SECTIONS = 96
MAX_IMPORTS = 4000
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".themida": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma", ".nsp0": "NsPack",
}
STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc", ".tls", ".pdata", ".crt",
    ".xdata", ".gfids", ".00cfg", ".didat", ".sxdata", "code", "data", ".code", "bss", ".init", ".fini",
    ".plt", ".got", ".dynamic", ".symtab", ".strtab", ".shstrtab", ".comment", ".debug",
}


def apply_limits() -> None:
    memory_mb = int(sys.argv[-1]) if sys.argv[-1].isdigit() else 2048
    cpu_seconds = 300
    for limit, value in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, cpu_seconds),
        (resource.RLIMIT_AS, memory_mb * 1024 * 1024),
    ):
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):
            pass  # macOS refuses RLIMIT_AS; Linux (the worker image) enforces it.


def section_info(section, file_size: int) -> dict:
    raw_size = getattr(section, "sizeof_raw_data", None)
    if raw_size is None:
        raw_size = section.size
    entropy = section.entropy
    return {
        "name": section.name[:32],
        "virtual_size": int(getattr(section, "virtual_size", section.size) or 0),
        "raw_size": int(raw_size or 0),
        "entropy": 0.0 if math.isnan(entropy) else round(entropy, 3),
    }


def parse_pe(binary, lief, file_size: int) -> dict:
    header = binary.header
    optional = binary.optional_header
    chars = lief.PE.Section.CHARACTERISTICS

    sections = []
    for section in list(binary.sections)[:MAX_SECTIONS]:
        info = section_info(section, file_size)
        info["executable"] = section.has_characteristic(chars.MEM_EXECUTE)
        info["writable"] = section.has_characteristic(chars.MEM_WRITE)
        sections.append(info)

    imports: dict[str, list[str]] = {}
    total = 0
    for library in list(binary.imports) + list(binary.delay_imports):
        names = imports.setdefault(library.name.lower(), [])
        for entry in library.entries:
            if total >= MAX_IMPORTS:
                break
            names.append(entry.name or f"ordinal_{getattr(entry, 'ordinal', 0)}")
            total += 1

    exports = []
    if binary.has_exports:
        exports = [e.name for e in binary.get_export().entries if e.name][:500]

    entry_rva = optional.addressof_entrypoint
    entry_section = None
    for section in binary.sections:
        size = max(section.virtual_size, section.sizeof_raw_data)
        if section.virtual_address <= entry_rva < section.virtual_address + size:
            entry_section = section.name
            break

    stamp = header.time_date_stamps
    compiled = datetime.fromtimestamp(stamp, UTC).isoformat() if stamp else None
    tls_callbacks = len(binary.tls.callbacks) if binary.has_tls else 0
    is_dll = header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)

    result = {
        "format": "PE",
        "machine": header.machine.name,
        "subsystem": optional.subsystem.name,
        "is_dll": is_dll,
        "entrypoint_rva": entry_rva,
        "entry_section": entry_section,
        "image_base": optional.imagebase,
        "compile_timestamp": compiled,
        "compile_timestamp_raw": stamp,
        "signed": binary.has_signatures,
        "imphash": lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE) if binary.has_imports else None,
        "overlay_size": len(binary.overlay),
        "tls_callbacks": tls_callbacks,
        "has_resources": binary.has_resources,
        "sections": sections,
        "imports": imports,
        "import_count": total,
        "exports": exports,
    }
    result["anomalies"] = pe_anomalies(result)
    return result


def pe_anomalies(pe: dict) -> list[dict]:
    anomalies: list[dict] = []

    def add(code: str, title: str, detail: str, severity: str = "medium") -> None:
        anomalies.append({"code": code, "title": title, "detail": detail, "severity": severity})

    packers = sorted({PACKER_SECTIONS[s["name"].lower()] for s in pe["sections"] if s["name"].lower() in PACKER_SECTIONS})
    if packers:
        add("packer_section", f"Packer section names ({', '.join(packers)})", "Section names match a known packer.", "high")

    for section in pe["sections"]:
        name = section["name"] or "(unnamed)"
        if section["entropy"] >= 7.2 and section["raw_size"] > 512:
            add(f"high_entropy:{name}", f"High entropy section {name}",
                f"Entropy {section['entropy']} suggests compressed or encrypted content.", "medium")
        if section["executable"] and section["writable"]:
            add(f"rwx:{name}", f"Writable and executable section {name}",
                "Code that can rewrite itself; common in unpacking stubs.", "medium")
        if section["raw_size"] == 0 and section["virtual_size"] > 4096 and section["executable"]:
            add(f"empty_raw:{name}", f"Empty executable section {name}",
                f"0 bytes on disk but {section['virtual_size']} bytes in memory: filled at runtime.", "high")
        if name.lower() not in STANDARD_SECTIONS and name.lower() not in PACKER_SECTIONS:
            add(f"nonstandard:{name}", f"Non-standard section name {name}", "Not a linker default.", "low")

    entry = (pe["entry_section"] or "").lower()
    if pe["entry_section"] is None:
        add("entry_outside", "Entry point outside all sections", "The entry point maps to no section.", "high")
    elif entry not in {".text", "code", ".code", "text"} and not pe["is_dll"]:
        add("entry_section", f"Entry point in {pe['entry_section']}", "Code normally starts in .text.", "low")

    if pe["import_count"] == 0 and not pe["is_dll"]:
        add("no_imports", "No import table", "APIs must be resolved at runtime, which hides capabilities.", "high")
    elif pe["import_count"] <= 5 and not pe["is_dll"]:
        add("few_imports", f"Minimal import table ({pe['import_count']})",
            "So few imports usually means a loader stub resolving the rest at runtime.", "medium")

    raw = pe["compile_timestamp_raw"]
    if raw and raw > datetime.now(UTC).timestamp():
        add("future_timestamp", "Compile timestamp in the future", "The PE timestamp has been forged.", "medium")
    elif raw and raw < 631152000:  # before 1990
        add("old_timestamp", "Implausibly old compile timestamp", "The PE timestamp has been forged or zeroed.", "low")

    if pe["tls_callbacks"]:
        add("tls_callbacks", f"{pe['tls_callbacks']} TLS callback(s)", "Code runs before the entry point.", "low")
    if pe["overlay_size"] > 1024 * 1024 and not pe["signed"]:
        add("overlay", f"Large overlay ({pe['overlay_size']} bytes)", "Data appended after the PE image.", "low")
    return anomalies


def parse_generic(binary, kind: str, file_size: int) -> dict:
    sections = [section_info(s, file_size) for s in list(binary.sections)[:MAX_SECTIONS]]
    imported = [f.name for f in binary.imported_functions if f.name][:MAX_IMPORTS]
    exported = [f.name for f in binary.exported_functions if f.name][:500]
    libraries = [str(lib if isinstance(lib, str) else getattr(lib, "name", lib)) for lib in binary.libraries][:200]
    anomalies = []
    for section in sections:
        if section["entropy"] >= 7.2 and section["raw_size"] > 512:
            anomalies.append({
                "code": f"high_entropy:{section['name']}",
                "title": f"High entropy section {section['name']}",
                "detail": f"Entropy {section['entropy']} suggests compressed or encrypted content.",
                "severity": "medium",
            })
    return {
        "format": kind,
        "sections": sections,
        "imports": {"(all)": imported},
        "import_count": len(imported),
        "libraries": libraries,
        "exports": exported,
        "anomalies": anomalies,
        "signed": False,
        "imphash": None,
    }


def command_pe(path: str) -> dict:
    import lief

    lief.logging.disable()
    binary = lief.parse(path)
    if binary is None:
        return {"format": None, "error": "not a parsable PE, ELF or Mach-O file"}
    size = Path(path).stat().st_size
    if isinstance(binary, lief.PE.Binary):
        return parse_pe(binary, lief, size)
    if isinstance(binary, lief.ELF.Binary):
        return parse_generic(binary, "ELF", size)
    return parse_generic(binary, "MACHO", size)


def command_yara(path: str, rules_dir: str) -> dict:
    import yara

    sources = {p.stem: str(p) for p in sorted(Path(rules_dir).glob("*.yar"))}
    if not sources:
        return {"matches": [], "rule_files": 0}
    rules = yara.compile(filepaths=sources)
    matches = []
    for match in rules.match(path, timeout=60):
        strings = []
        for string in match.strings[:6]:
            instance = string.instances[0] if string.instances else None
            if instance is None:
                continue
            strings.append({
                "identifier": string.identifier,
                "offset": instance.offset,
                "text": bytes(instance.matched_data[:64]).decode("latin-1"),
            })
        meta = match.meta
        matches.append({
            "rule": match.rule,
            "tags": list(match.tags),
            "description": str(meta.get("description", "")),
            "family": str(meta.get("family", "")),
            "score": int(meta.get("score", 10)),
            "technique": str(meta.get("technique", "")),
            "strings": strings,
        })
    return {"matches": matches, "rule_files": len(sources)}


def main() -> None:
    apply_limits()
    command, path = sys.argv[1], sys.argv[2]
    try:
        if command == "pe":
            output = command_pe(path)
        elif command == "yara":
            output = command_yara(path, sys.argv[3])
        else:
            raise ValueError(f"unknown command {command}")
    except Exception as exc:  # A hostile file may break any parser; report it as data.
        output = {"error": f"{type(exc).__name__}: {exc}"[:300]}
    json.dump(output, sys.stdout, default=str)


if __name__ == "__main__":
    main()
