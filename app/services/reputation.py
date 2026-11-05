"""Hash reputation lookups. Only the SHA-256 is sent; the sample never leaves the server."""

import httpx

from app.core.config import settings

TIMEOUT = httpx.Timeout(15.0)
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/file/{}/general"


def lookup_virustotal(sha256: str, client: httpx.Client | None = None) -> dict:
    key = settings.virustotal_api_key.get_secret_value()
    if not key:
        return {"status": "not_configured"}
    http = client or httpx.Client(timeout=TIMEOUT)
    try:
        response = http.get(VT_URL.format(sha256), headers={"x-apikey": key})
        if response.status_code == 404:
            return {"status": "unknown"}
        response.raise_for_status()
        attrs = response.json()["data"]["attributes"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return {"status": "error", "error": type(exc).__name__}
    finally:
        if client is None:
            http.close()

    stats = attrs.get("last_analysis_stats", {})
    return {
        "status": "found",
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "first_seen": attrs.get("first_submission_date"),
    }


def lookup_otx(sha256: str, client: httpx.Client | None = None) -> dict:
    key = settings.otx_api_key.get_secret_value()
    if not key:
        return {"status": "not_configured"}
    http = client or httpx.Client(timeout=TIMEOUT)
    try:
        response = http.get(OTX_URL.format(sha256), headers={"X-OTX-API-KEY": key})
        if response.status_code == 404:
            return {"status": "unknown"}
        response.raise_for_status()
        info = response.json().get("pulse_info") or {}
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": "error", "error": type(exc).__name__}
    finally:
        if client is None:
            http.close()

    pulses = info.get("pulses") or []
    return {
        "status": "found" if pulses else "unknown",
        "pulse_count": int(info.get("count", len(pulses))),
        "pulses": [str(p.get("name", ""))[:120] for p in pulses[:5]],
    }


def lookup_hash(sha256: str) -> dict:
    return {"virustotal": lookup_virustotal(sha256), "otx": lookup_otx(sha256)}
