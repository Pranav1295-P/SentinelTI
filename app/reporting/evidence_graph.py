"""Builds the graph the Attack Graph page draws: {nodes:[{id,label,type,x,y,detail}], edges:[[a,b]]}."""

import math

from app.analysis.strings import is_benign_host

MAX_CAPABILITY_NODES = 8
MAX_EVIDENCE_NODES = 4
MAX_NOTE_NODES = 2


def _node(id: str, label: str, type_: str, kind: str, title: str, rows: list, text: str) -> dict:
    return {
        "id": id, "label": label.strip() if len(label) <= 34 else label[:33].strip() + "…", "type": type_, "x": 0, "y": 0,
        "detail": {"title": title, "kind": kind, "rows": [[str(k), str(v)] for k, v in rows], "text": text},
    }


def _human_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    return f"{size / 1024:.1f} KB"


def _layout(nodes: list[dict]) -> None:
    """Sample in the middle, everything else evenly around it on two alternating rings."""
    others = [n for n in nodes if n["id"] != "sample"]
    count = max(len(others), 1)
    for index, node in enumerate(others):
        angle = -math.pi / 2 + 2 * math.pi * index / count
        radius = 250 if index % 2 == 0 else 330
        node["x"] = round(math.cos(angle) * radius * 1.15)
        node["y"] = round(math.sin(angle) * radius * 0.85)


def build_evidence_graph(state: dict) -> dict:
    triage = state["triage"]
    assessment = state["assessment"]
    facts = state["facts"]
    parsed = state.get("parsed") or {}
    iocs = state.get("iocs") or {}
    nodes: list[dict] = []
    edges: list[list[str]] = []

    nodes.append(_node(
        "sample", state["filename"], "sample", "Sample", state["filename"],
        [("Type", triage["label"]), ("SHA-256", triage["sha256"]), ("Size", _human_size(triage["size_bytes"])),
         ("Entropy", triage["entropy"]), ("Compiled", parsed.get("compile_timestamp") or "n/a"),
         *([("Unpacked from", state["container"]["filename"])] if (state.get("container") or {}).get("filename") else [])],
        f"Rated {assessment['verdict']} with risk {assessment['risk']}. Every fact was checked against the file by the Explainability Agent.",
    ))

    # Structural evidence, most severe first.
    order = {"high": 0, "medium": 1, "low": 2}
    anomalies = sorted(parsed.get("anomalies", []), key=lambda a: order.get(a["severity"], 3))
    packing_node = None
    for anomaly in [a for a in anomalies if a["severity"] != "low"][:MAX_EVIDENCE_NODES]:
        node_id = f"anomaly-{len(nodes)}"
        nodes.append(_node(node_id, anomaly["title"], "evidence", "Evidence · Structure", anomaly["title"],
                           [("Severity", anomaly["severity"])], anomaly["detail"]))
        edges.append(["sample", node_id])
        if packing_node is None and anomaly["code"].split(":")[0] in ("packer_section", "high_entropy", "empty_raw"):
            packing_node = node_id

    # Network indicators, as one node.
    network = [u for u in iocs.get("urls", []) if not is_benign_host(u.split("://", 1)[-1].split("/")[0].split(":")[0])] + iocs.get("ips", [])
    network_id = None
    if network:
        network_id = "network"
        rows = [("Endpoint", value) for value in network[:6]]
        if len(network) > 6:
            rows.append(("More", f"{len(network) - 6} further indicators in the report"))
        nodes.append(_node(network_id, f"{len(network)} network indicators", "network", "Network", "Network indicators", rows,
                           "Recovered from the file's strings. Presence shows what the sample references, not that it connected."))
        edges.append(["sample", network_id])

    # Proven capabilities.
    capability_ids: dict[str, str] = {}
    proven = sorted((c for c in state.get("capabilities", []) if c["status"] == "proven"), key=lambda c: -c["weight"])
    for capability in proven[:MAX_CAPABILITY_NODES]:
        node_id = f"cap-{capability['id']}"
        capability_ids[capability["id"]] = node_id
        evidence = [facts[i]["title"] for i in capability["evidence_ids"] if i in facts]
        techniques = ", ".join(capability["techniques"]) or "n/a"
        nodes.append(_node(node_id, capability["name"], "capability", f"Capability · {techniques}", capability["name"],
                           [("Confidence", capability["confidence"]), ("ATT&CK", techniques), ("Risk points", capability["weight"]),
                            *[("Evidence", e) for e in evidence[:5]]],
                           capability["explanation"]))
        edges.append(["sample", node_id])
        if network_id and capability["id"] in ("http_c2", "raw_socket", "downloader"):
            edges.append([node_id, network_id])
        if packing_node and capability["id"] == "software_packing":
            edges.append([packing_node, node_id])

    # Intel: rule hits, reputation, family and notes.
    yara_nodes = []
    for match in (state.get("yara") or {}).get("matches", [])[:4]:
        node_id = f"yara-{match['rule']}"
        yara_nodes.append(node_id)
        nodes.append(_node(node_id, f"YARA: {match['rule']}", "intel", "Pattern · Rule hit", match["rule"],
                           [("Rule", match["rule"]), ("Risk points", match["score"]), *[("Match", s["text"]) for s in match["strings"][:3]]],
                           match["description"]))
        edges.append(["sample", node_id])

    vt = (state.get("reputation") or {}).get("virustotal") or {}
    if vt.get("status") == "found":
        nodes.append(_node("virustotal", f"VirusTotal: {vt['malicious']} engines", "intel", "Threat context · Reputation", "VirusTotal",
                           [("Malicious", vt["malicious"]), ("Suspicious", vt["suspicious"]), ("Label", vt.get("label") or "none")],
                           "Existing detections for this hash. The file was not uploaded."))
        edges.append(["sample", "virustotal"])

    family = state.get("family")
    if family:
        nodes.append(_node("family", family, "intel", "Threat context · Attribution", f"Attribution: {family}",
                           [("Family", family)], "Attribution comes from a matching rule or reputation label, not from the LLM."))
        edges.append(["sample", "family"])
        edges.extend([node_id, "family"] for node_id in yara_nodes)

    for index, note in enumerate((state.get("notes") or [])[:MAX_NOTE_NODES]):
        node_id = f"note-{index}"
        nodes.append(_node(node_id, note["title"], "intel", "Threat context · Internal note", note["title"],
                           [("Source", note["source"])], note["excerpt"]))
        edges.append(["sample", node_id])

    for index, related in enumerate((state.get("related") or [])[:3]):
        node_id = f"related-{index}"
        nodes.append(_node(node_id, related["filename"], "intel", "Graph match · Related sample", related["filename"],
                           [("Analysis", related["analysis_id"]), *[("Shared", s) for s in related["shared"][:5]]],
                           "An earlier sample of yours shares these indicators."))
        edges.append(["sample", node_id])

    _layout(nodes)
    return {"nodes": nodes, "edges": edges}
