"""LangChain tools the agents can call.

Inputs are Pydantic-validated. The sample path comes from injected graph state, so
the LLM can choose which tool to run but can never point a tool at another file.
Each tool returns (compact text for the LLM, full artifact for the graph state).
"""

import hashlib
import json
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState
from pydantic import Field

from app.agents.knowledge import get_retriever
from app.agents.prompts import untrusted
from app.analysis import capabilities as caps
from app.analysis import identify, isolated, mitre
from app.analysis import strings as strs
from app.core.config import settings
from app.services.reputation import lookup_hash

FLOSS_TIMEOUT_SECONDS = 180
State = Annotated[dict, InjectedState]


def fact(id: str, tool_name: str, kind: str, title: str, detail: str = "", severity: str = "info",
         literal: str | None = None, **data: Any) -> dict:
    return {
        "id": id, "tool": tool_name, "kind": kind, "title": title, "detail": detail,
        "severity": severity, "literal": literal, "data": data,
    }


def _short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:10]


def _sample(state: dict) -> Path:
    return Path(state["ctx"]["sample_path"])


def _reply(line: str, output: dict, facts: list[dict], llm_view: Any = None) -> tuple[str, dict]:
    """The LLM sees the summary, the fact ids it may cite, and fenced file data."""
    content = {"summary": line, "facts": [{"id": f["id"], "title": f["title"]} for f in facts[:60]]}
    if llm_view is not None:
        content["data"] = llm_view
    return untrusted(content), {"line": line, "output": output, "facts": facts}


@lru_cache(maxsize=4)
def _strings_for(path: str) -> tuple[str, ...]:
    return tuple(strs.extract_strings(Path(path)))


# ---------- Agent 1: Triage ----------


@tool(response_format="content_and_artifact")
def identify_file_type(state: State) -> tuple[str, dict]:
    """Identify the real file type from magic bytes and compare it with the file extension."""
    info = identify.identify_file(_sample(state), state["ctx"]["filename"])
    facts = [fact("file:type", "identify_file_type", "file", f"Real type: {info['label']}",
                  f"Magic bytes {info['magic_hex']}.")]
    if info["disguised"]:
        facts.append(fact("file:disguised", "identify_file_type", "file", "File disguises its real type",
                          f".{info['extension']} name on a {info['label']}.", "high"))
    elif info["extension_mismatch"]:
        facts.append(fact("file:extension-mismatch", "identify_file_type", "file", "Extension mismatch",
                          f".{info['extension'] or '(none)'} does not match {info['label']}.", "low"))
    line = f"Magic bytes → {info['label']}"
    if info["disguised"]:
        line += f" (disguised as .{info['extension']})"
    return _reply(line, info, facts, info)


@tool(response_format="content_and_artifact")
def compute_file_hashes(state: State) -> tuple[str, dict]:
    """Compute MD5, SHA-1, SHA-256 and the ssdeep fuzzy hash of the sample."""
    hashes = identify.compute_hashes(_sample(state))
    facts = [fact("file:sha256", "compute_file_hashes", "file", "SHA-256 fingerprint", hashes["sha256"])]
    return _reply(f"SHA-256 → {hashes['sha256']}", hashes, facts, hashes)


@tool(response_format="content_and_artifact")
def check_file_size(state: State) -> tuple[str, dict]:
    """Check the file size against the limit and measure overall entropy."""
    path = _sample(state)
    size = path.stat().st_size
    entropy = identify.file_entropy(path)
    output = {"size_bytes": size, "entropy": entropy, "within_limit": size <= settings.max_upload_bytes}
    facts = [fact("file:size", "check_file_size", "file", f"Size {size} bytes", f"Overall entropy {entropy}.")]
    if entropy >= identify.HIGH_ENTROPY:
        facts.append(fact("file:high-entropy", "check_file_size", "file", f"High overall entropy ({entropy})",
                          "Suggests packed or encrypted content.", "medium"))
    line = f"Size {size:,} bytes · entropy {entropy}"
    return _reply(line + (" (likely packed or encrypted)" if entropy >= identify.HIGH_ENTROPY else ""), output, facts, output)


# ---------- Agent 2: Evidence ----------


@tool(response_format="content_and_artifact")
def parse_binary_metadata(state: State) -> tuple[str, dict]:
    """Parse PE, ELF or Mach-O metadata with LIEF: headers, sections, imports, exports, anomalies."""
    parsed = isolated.parse_binary(_sample(state))
    if parsed.get("error") or not parsed.get("format"):
        reason = parsed.get("error", "unsupported format")
        return _reply(f"No structural metadata: {reason}", parsed, [], {"error": reason})

    facts = [fact("file:format", "parse_binary_metadata", "file", f"{parsed['format']} binary",
                  f"{parsed.get('machine', '')} with {len(parsed['sections'])} sections and {parsed['import_count']} imports.".strip())]
    if parsed.get("imphash"):
        facts.append(fact("file:imphash", "parse_binary_metadata", "file", "Import hash", parsed["imphash"]))
    facts.append(fact("file:signature", "parse_binary_metadata", "file",
                      "Authenticode signature present" if parsed.get("signed") else "No code signature",
                      "Presence only; the certificate chain is not validated."))
    for section in parsed["sections"]:
        facts.append(fact(f"section:{section['name'] or 'unnamed'}", "parse_binary_metadata", "section",
                          f"Section {section['name']}",
                          f"Entropy {section['entropy']}, raw {section['raw_size']} bytes, virtual {section['virtual_size']} bytes.",
                          literal=section["name"] if parsed["format"] == "PE" and section["name"] else None))
    for anomaly in parsed.get("anomalies", []):
        facts.append(fact(f"anomaly:{anomaly['code']}", "parse_binary_metadata", "anomaly",
                          anomaly["title"], anomaly["detail"], anomaly["severity"], code=anomaly["code"]))

    line = f"{parsed['format']} {parsed.get('machine', '')} · {len(parsed['sections'])} sections · {parsed['import_count']} imports".replace("  ", " ")
    view = {k: parsed.get(k) for k in ("format", "machine", "subsystem", "entry_section", "compile_timestamp", "signed", "imphash", "import_count")}
    view["sections"] = parsed["sections"][:16]
    view["anomalies"] = [a["title"] for a in parsed.get("anomalies", [])]
    return _reply(line, parsed, facts, view)


@tool(response_format="content_and_artifact")
def scan_yara_rules(state: State) -> tuple[str, dict]:
    """Match the sample against the YARA rule set."""
    result = isolated.scan_yara(_sample(state))
    if result.get("error"):
        return _reply(f"YARA scan failed: {result['error']}", result, [], {"error": result["error"]})
    facts = [
        fact(f"yara:{m['rule']}", "scan_yara_rules", "yara", f"YARA rule {m['rule']}", m["description"],
             "high" if m["score"] >= 15 else "medium", rule=m["rule"], family=m["family"])
        for m in result["matches"]
    ]
    names = ", ".join(m["rule"] for m in result["matches"]) or "no matches"
    return _reply(f"YARA → {names}", result, facts, {"matches": [m["rule"] for m in result["matches"]]})


@tool(response_format="content_and_artifact")
def extract_strings_and_iocs(state: State) -> tuple[str, dict]:
    """Extract ASCII and UTF-16 strings and recover URLs, IPs, domains, registry keys and file paths."""
    strings = _strings_for(str(_sample(state)))
    iocs = strs.extract_iocs(list(strings))
    facts = []
    for kind, values in iocs.items():
        for value in values:
            severity = "low" if kind in ("urls", "domains") and strs.is_benign_host(_host(value)) else "medium"
            if kind in ("file_paths", "registry_keys"):
                severity = "low"
            facts.append(fact(f"ioc:{kind}:{value}", "extract_strings_and_iocs", "ioc", f"{kind[:-1].replace('_', ' ')}: {value}",
                              "Found in the file's strings.", severity, literal=value, ioc_type=kind, value=value))
    output = {"string_count": len(strings), "iocs": iocs}
    network = len(iocs["urls"]) + len(iocs["ips"]) + len(iocs["domains"])
    line = f"{len(strings):,} strings · {network} network indicators"
    return _reply(line, output, facts, {"string_count": len(strings), "iocs": {k: v[:15] for k, v in iocs.items()}})


def _host(value: str) -> str:
    if "://" in value:
        value = value.split("://", 1)[1]
    return value.split("/")[0].split(":")[0]


@tool(response_format="content_and_artifact")
def decode_obfuscated_strings(state: State) -> tuple[str, dict]:
    """Recover stack, tight and decoded strings with FLARE FLOSS. Slow; use on packed or obfuscated samples."""
    binary = shutil.which("floss")
    if not binary:
        return _reply("FLOSS not installed on this worker", {"status": "not_installed"}, [], {"status": "not_installed"})
    try:
        proc = subprocess.run(
            [binary, "-j", "--no", "static", "--", str(_sample(state))],
            capture_output=True, timeout=FLOSS_TIMEOUT_SECONDS, check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
        )
        data = json.loads(proc.stdout).get("strings", {})
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return _reply(f"FLOSS failed: {type(exc).__name__}", {"status": "error"}, [], {"status": "error"})

    decoded = []
    for key in ("stack_strings", "tight_strings", "decoded_strings"):
        decoded.extend(item["string"] for item in data.get(key, []) if item.get("string"))
    decoded = list(dict.fromkeys(decoded))[:500]
    facts = [
        fact(f"decoded:{_short(text)}", "decode_obfuscated_strings", "string", f"Decoded string: {text[:120]}",
             "Recovered by FLOSS emulation; not literally present in the file.", "medium")
        for text in decoded[:50]
    ]
    return _reply(f"FLOSS recovered {len(decoded)} hidden strings", {"status": "ok", "strings": decoded}, facts, {"strings": decoded[:40]})


# ---------- Agent 3: Behaviour ----------


@tool(response_format="content_and_artifact")
def correlate_capabilities(state: State) -> tuple[str, dict]:
    """Correlate imports, strings and section anomalies into capabilities with their evidence chains."""
    ctx = state["ctx"]
    parsed = ctx.get("parsed") or {}
    strings = list(_strings_for(ctx["sample_path"]))
    facts: list[dict] = []
    capabilities: list[dict] = []

    for match in caps.correlate(parsed, strings):
        rule, evidence_ids = match["rule"], []
        for hit in match["hits"]:
            if hit["type"] == "api":
                fact_id = f"import:{hit['value']}"
                how = "Imported" if hit["source"] == "import" else "Named in strings (not imported)"
                facts.append(fact(fact_id, "correlate_capabilities", "import", f"API {hit['value']}", how + ".", "medium",
                                  literal=hit["value"], source=hit["source"]))
            else:
                fact_id = f"string:{_short(hit['value'])}"
                facts.append(fact(fact_id, "correlate_capabilities", "string", f"String: {hit['value'][:120]}",
                                  "Found in the file's strings.", "medium", literal=hit["value"]))
            evidence_ids.append(fact_id)
        capabilities.append({
            "id": rule.id, "name": rule.name, "status": match["status"], "confidence": match["confidence"],
            "weight": rule.weight if match["status"] == "proven" else 0, "techniques": list(rule.techniques),
            "evidence_ids": evidence_ids, "explanation": rule.explanation,
        })

    anomalies = parsed.get("anomalies", [])
    triage = ctx.get("triage") or {}
    packing = caps.packing_capability(anomalies)
    if packing:
        capabilities.append(packing)
    if triage.get("disguised"):
        # Already scored by triage, so this one only supplies the ATT&CK mapping.
        capabilities.append({
            "id": "masquerading", "name": "File Type Masquerading", "status": "proven", "confidence": 0.95, "weight": 0,
            "techniques": ["T1036.007" if triage.get("double_extension") else "T1036.008"],
            "evidence_ids": ["file:disguised"], "explanation": "The file name hides what the file really is.",
        })

    injected = caps.find_prompt_injection(strings)
    if injected:
        ids = []
        for text in injected:
            fact_id = f"string:{_short(text)}"
            ids.append(fact_id)
            facts.append(fact(fact_id, "correlate_capabilities", "string", f"Text aimed at AI analysts: {text[:120]}",
                              "Written to manipulate automated analysis.", "high", literal=text))
        capabilities.append({
            "id": "llm_prompt_injection", "name": "Prompt Injection Against Analysis Tools", "status": "proven",
            "confidence": 0.9, "weight": 15, "techniques": [], "evidence_ids": ids,
            "explanation": "The file contains instructions aimed at AI analysts.",
        })

    proven = [c["name"] for c in capabilities if c["status"] == "proven"]
    line = f"{len(proven)} capabilities proven" + (f": {', '.join(proven[:4])}" if proven else "")
    view = [{"id": c["id"], "status": c["status"], "evidence_ids": c["evidence_ids"]} for c in capabilities]
    return _reply(line, {"capabilities": capabilities}, facts, view)


@tool(response_format="content_and_artifact")
def inspect_imports(
    state: State,
    query: Annotated[str, Field(min_length=2, max_length=64, description="Case-insensitive part of an API or DLL name")],
) -> tuple[str, dict]:
    """Look through the import table for an API or DLL name."""
    parsed = state["ctx"].get("parsed") or {}
    needle = query.lower()
    hits = [
        {"library": lib, "name": name}
        for lib, names in parsed.get("imports", {}).items() for name in names
        if needle in name.lower() or needle in lib.lower()
    ][:40]
    facts = [
        fact(f"import:{h['name']}", "inspect_imports", "import", f"API {h['name']}", f"Imported from {h['library']}.",
             literal=h["name"], source="import")
        for h in hits if not h["name"].startswith("ordinal_")
    ]
    return _reply(f"Imports matching '{query}': {len(hits)}", {"query": query, "hits": hits}, facts, hits)


@tool(response_format="content_and_artifact")
def search_strings(
    state: State,
    query: Annotated[str, Field(min_length=3, max_length=64, description="Case-insensitive literal text, not a regex")],
) -> tuple[str, dict]:
    """Search the extracted strings for literal text."""
    needle = query.lower()
    hits = [s[:256] for s in _strings_for(state["ctx"]["sample_path"]) if needle in s.lower()][:25]
    facts = [
        fact(f"string:{_short(text)}", "search_strings", "string", f"String: {text[:120]}", "Found in the file's strings.",
             "low", literal=text)
        for text in hits
    ]
    return _reply(f"Strings matching '{query}': {len(hits)}", {"query": query, "hits": hits}, facts, hits)


# ---------- Agent 4: Threat context ----------


@tool(response_format="content_and_artifact")
def map_attack_techniques(state: State) -> tuple[str, dict]:
    """Map proven capabilities to MITRE ATT&CK techniques from the local catalogue."""
    techniques: dict[str, dict] = {}
    for capability in state["ctx"].get("capabilities", []):
        if capability["status"] != "proven":
            continue
        for technique_id in capability["techniques"]:
            if technique_id not in mitre.TECHNIQUES:
                continue
            name, tactic = mitre.TECHNIQUES[technique_id]
            entry = techniques.setdefault(technique_id, {
                "id": technique_id, "name": name, "tactic": tactic, "confidence": 0.0,
                "capability_ids": [], "evidence_ids": [],
            })
            entry["confidence"] = max(entry["confidence"], capability["confidence"])
            entry["capability_ids"].append(capability["id"])
            entry["evidence_ids"].extend(capability["evidence_ids"])
    result = sorted(techniques.values(), key=lambda t: -t["confidence"])
    ids = ", ".join(t["id"] for t in result) or "no techniques"
    return _reply(f"ATT&CK → {ids}", {"techniques": result}, [], [{"id": t["id"], "name": t["name"]} for t in result])


@tool(response_format="content_and_artifact")
def search_threat_notes(
    state: State,
    query: Annotated[str, Field(min_length=3, max_length=200, description="Search terms, e.g. technique names or API names")],
) -> tuple[str, dict]:
    """Search internal threat intelligence notes and curated reference documents."""
    documents = get_retriever().invoke(query)
    notes = [
        {"id": d.metadata["id"], "title": d.metadata["title"], "source": d.metadata["source"], "excerpt": d.page_content[:700]}
        for d in documents
    ]
    facts = [fact(f"note:{n['id']}", "search_threat_notes", "note", f"Internal note: {n['title']}", n["excerpt"][:200]) for n in notes]
    return _reply(f"{len(notes)} internal notes matched", {"notes": notes}, facts, notes)


@tool(response_format="content_and_artifact")
def lookup_hash_reputation(state: State) -> tuple[str, dict]:
    """Look the sample's SHA-256 up on VirusTotal and AlienVault OTX. The file itself is never uploaded."""
    sha256 = state["ctx"]["triage"]["sha256"]
    reputation = lookup_hash(sha256)
    facts = []
    vt, otx = reputation["virustotal"], reputation["otx"]
    if vt["status"] == "found":
        facts.append(fact("reputation:virustotal", "lookup_hash_reputation", "reputation",
                          f"VirusTotal: {vt['malicious']} engines flag this hash", vt.get("label") or "No family label.",
                          "high" if vt["malicious"] >= 5 else "low"))
    if otx["status"] == "found":
        facts.append(fact("reputation:otx", "lookup_hash_reputation", "reputation",
                          f"OTX: {otx['pulse_count']} threat pulses", ", ".join(otx["pulses"][:3]), "medium"))
    return _reply(f"Reputation → VirusTotal {vt['status']}, OTX {otx['status']}", reputation, facts, reputation)
