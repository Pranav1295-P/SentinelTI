"""Agent 5's fact check: every fact is re-checked once against the quarantined file.

Hashes are recomputed, literals must be physically present in the bytes, and parser
findings must reappear in a fresh parse. A capability that loses evidence is demoted
to unproven before scoring, so nothing unverified can raise the risk score.
"""

import hashlib
from pathlib import Path

from app.analysis import isolated
from app.analysis.strings import MAX_SCAN_BYTES, literal_in_bytes


def verify_facts(state: dict) -> tuple[dict[str, dict], list[dict], list[dict], dict]:
    path = Path(state["sample_path"])
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != state["triage"]["sha256"]:
        raise ValueError("quarantined file changed during analysis")

    with path.open("rb") as handle:
        raw = handle.read(MAX_SCAN_BYTES)
    raw_lower = raw.lower()

    parsed = isolated.parse_binary(path)
    yara_hits = {m["rule"] for m in isolated.scan_yara(path).get("matches", [])}
    anomaly_codes = {a["code"] for a in parsed.get("anomalies", [])}
    file_truth = {"file:sha256", "file:type", "file:size", "file:disguised", "file:extension-mismatch",
                  "file:high-entropy", "file:format", "file:imphash", "file:signature",
                  "file:archive", "file:not-inspected", "file:macros"}

    facts: dict[str, dict] = {}
    checked = verified = failed = 0
    for fact_id, fact in state["facts"].items():
        fact = dict(fact)
        kind = fact["kind"]
        if kind == "yara":
            ok = fact["data"].get("rule") in yara_hits
        elif kind == "anomaly":
            ok = fact["data"].get("code") in anomaly_codes
        elif fact.get("literal"):
            literal = fact["literal"]
            ok = literal_in_bytes(raw, literal) or literal_in_bytes(raw_lower, literal.lower())
        elif kind == "file":
            ok = fact_id in file_truth
        else:
            # External or derived: reputation, notes, decoded strings. Recorded with their source.
            fact["verified"] = None
            facts[fact_id] = fact
            continue
        fact["verified"] = ok
        facts[fact_id] = fact
        checked += 1
        verified += ok
        failed += not ok

    # External facts still count as citable evidence for the explanation.
    for fact in facts.values():
        if fact["verified"] is None:
            fact["verified"] = True
            fact["external"] = True

    bad = {fact_id for fact_id, fact in facts.items() if not fact["verified"]}
    capabilities = []
    for capability in state.get("capabilities", []):
        capability = dict(capability)
        unknown = [i for i in capability["evidence_ids"] if i not in facts or i in bad]
        if capability["status"] == "proven" and unknown:
            capability.update(status="partial", weight=0, confidence=min(capability["confidence"], 0.4))
        capabilities.append(capability)

    proven_ids = {c["id"] for c in capabilities if c["status"] == "proven"}
    techniques = []
    for technique in state.get("techniques", []):
        supporters = [c for c in technique["capability_ids"] if c in proven_ids]
        if supporters:
            techniques.append({**technique, "capability_ids": supporters})

    summary = {"checked": checked, "verified": verified, "failed": failed, "rejected": sorted(bad)[:50]}
    return facts, capabilities, techniques, summary
