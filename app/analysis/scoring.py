"""The verdict is arithmetic over verified evidence. No LLM can change it."""

from app.analysis.strings import is_benign_host

VERDICTS = ((80, "Critical", "crit"), (50, "Malicious", "crit"), (20, "Suspicious", "warn"), (0, "Clean", "ok"))


def verdict_for(risk: int) -> tuple[str, str]:
    for threshold, verdict, tone in VERDICTS:
        if risk >= threshold:
            return verdict, tone
    return "Clean", "ok"


def score(state: dict) -> dict:
    """Return the risk, verdict and an itemised breakdown the analyst can check."""
    breakdown: list[dict] = []

    def add(points: int, reason: str, evidence_ids: list[str] | None = None) -> None:
        if points:
            breakdown.append({"points": points, "reason": reason, "evidence_ids": evidence_ids or []})

    triage = state.get("triage") or {}
    container = state.get("container") or {}
    if container.get("macros"):
        add(25, "Office document contains macros", ["file:macros"])
    if triage.get("disguised"):
        add(25, "File disguises its real type behind its name", ["file:disguised"])
    elif triage.get("extension_mismatch") and triage.get("is_executable"):
        add(8, "Extension does not match the real file type", ["file:extension-mismatch"])

    for capability in state.get("capabilities", []):
        if capability["status"] == "proven":
            add(capability["weight"], f"Capability proven: {capability['name']}", capability["evidence_ids"])

    for match in (state.get("yara") or {}).get("matches", []):
        add(match["score"], f"YARA rule {match['rule']}", [f"yara:{match['rule']}"])

    parsed = state.get("parsed") or {}
    anomalies = parsed.get("anomalies", [])
    points = {"high": 5, "medium": 2, "low": 0}
    anomaly_points = min(sum(points.get(a["severity"], 0) for a in anomalies), 12)
    add(anomaly_points, "Structural anomalies", [f"anomaly:{a['code']}" for a in anomalies if a["severity"] != "low"])

    iocs = state.get("iocs") or {}
    bad_ips = iocs.get("ips", [])
    if bad_ips and triage.get("is_executable"):
        add(min(len(bad_ips) * 3, 9), "Hard-coded public IP addresses", [f"ioc:ips:{i}" for i in bad_ips[:3]])
    if iocs.get("crypto_wallets"):
        add(10, "Embedded cryptocurrency wallet", [f"ioc:crypto_wallets:{w}" for w in iocs["crypto_wallets"][:2]])

    reputation = state.get("reputation") or {}
    vt = reputation.get("virustotal") or {}
    malicious = vt.get("malicious") or 0
    if malicious:
        add(80 if malicious >= 30 else 60 if malicious >= 10 else 35 if malicious >= 3 else 10,
            f"VirusTotal: {malicious} engines flag this hash", ["reputation:virustotal"])
    pulses = (reputation.get("otx") or {}).get("pulse_count") or 0
    if pulses:
        # Community pulses also mention harmless files, so one or two prove little.
        add(10 if pulses >= 5 else 3, f"AlienVault OTX: hash appears in {pulses} threat pulses", ["reputation:otx"])

    # Finding nothing only means something if the contents could actually be read.
    if sum(item["points"] for item in breakdown) < 20 and not inspected(state):
        add(20, "Contents could not be inspected, so this file is not cleared", ["file:not-inspected"])
        risk = max(0, min(100, sum(item["points"] for item in breakdown)))
        return {"risk": risk, "verdict": "Inconclusive", "tone": "warn", "breakdown": breakdown}

    risk = max(0, min(100, sum(item["points"] for item in breakdown)))
    verdict, tone = verdict_for(risk)
    return {"risk": risk, "verdict": verdict, "tone": tone, "breakdown": breakdown}


def inspected(state: dict) -> bool:
    """False for locked or compressed containers, and for encrypted-looking blobs."""
    triage = state.get("triage") or {}
    if (state.get("container") or {}).get("opaque"):
        return False
    return not (triage.get("kind") == "DATA" and triage.get("entropy", 0) >= 7.2)


def attribute_family(state: dict) -> str | None:
    """A family name needs a rule hit or a reputation label behind it, or stays empty."""
    for match in (state.get("yara") or {}).get("matches", []):
        if match.get("family"):
            return match["family"]
    label = ((state.get("reputation") or {}).get("virustotal") or {}).get("label")
    return label or None


def public_hosts(iocs: dict) -> list[str]:
    return [d for d in iocs.get("domains", []) if not is_benign_host(d)]
