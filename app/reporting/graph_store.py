"""Graph database step of Agent 5: store the evidence, then match it against earlier samples.

Matching only uses specific indicators (not capabilities, which many samples share)
and is always scoped to the analysis owner, so one user's samples never surface for another.
"""

import logging

from langchain_neo4j import Neo4jGraph

from app.core.config import settings

logger = logging.getLogger(__name__)

MAX_INDICATORS = 200

_SCHEMA = [
    "CREATE CONSTRAINT analysis_id IF NOT EXISTS FOR (a:Analysis) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT indicator_key IF NOT EXISTS FOR (i:Indicator) REQUIRE i.key IS UNIQUE",
    "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
]

_UPSERT = """
MERGE (a:Analysis {id: $id})
SET a.owner = $owner, a.filename = $filename, a.sha256 = $sha256
WITH a
UNWIND $indicators AS item
MERGE (i:Indicator {key: item.key}) SET i.type = item.type, i.value = item.value
MERGE (a)-[:OBSERVED]->(i)
"""

_TECHNIQUES = """
MATCH (a:Analysis {id: $id})
UNWIND $techniques AS technique
MERGE (t:Technique {id: technique})
MERGE (a)-[:USES]->(t)
"""

_MATCH = """
MATCH (a:Analysis {id: $id})-[:OBSERVED]->(i:Indicator)<-[:OBSERVED]-(other:Analysis {owner: $owner})
WHERE other.id <> $id
RETURN other.id AS analysis_id, other.filename AS filename, collect(i.value)[..8] AS shared, count(i) AS score
ORDER BY score DESC LIMIT 5
"""


def _indicators(state: dict) -> list[dict]:
    triage = state["triage"]
    items = [{"type": "sha256", "value": triage["sha256"]}]
    imphash = (state.get("parsed") or {}).get("imphash")
    if imphash:
        items.append({"type": "imphash", "value": imphash})
    iocs = state.get("iocs") or {}
    for kind in ("urls", "ips", "domains", "emails", "crypto_wallets"):
        items.extend({"type": kind, "value": value} for value in iocs.get(kind, []))
    for item in items:
        item["key"] = f"{item['type']}:{item['value']}"
    return items[:MAX_INDICATORS]


def sync_and_match(state: dict) -> tuple[list[dict], str]:
    """Returns (related samples, status). Status is 'ok', 'disabled' or 'error'; never raises."""
    if not settings.neo4j_uri:
        return [], "disabled"
    try:
        graph = Neo4jGraph(
            url=settings.neo4j_uri, username=settings.neo4j_username,
            password=settings.neo4j_password.get_secret_value(), refresh_schema=False,
        )
        for statement in _SCHEMA:
            graph.query(statement)
        params = {"id": state["analysis_id"], "owner": state["owner_id"]}
        graph.query(_UPSERT, {**params, "filename": state["filename"], "sha256": state["triage"]["sha256"], "indicators": _indicators(state)})
        graph.query(_TECHNIQUES, {"id": state["analysis_id"], "techniques": [t["id"] for t in state.get("techniques", [])]})
        rows = graph.query(_MATCH, params)
        return [dict(row) for row in rows], "ok"
    except Exception:
        logger.warning("Graph database step failed", extra={"analysis_id": state["analysis_id"]}, exc_info=True)
        return [], "error"
