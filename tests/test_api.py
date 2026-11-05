import hashlib
import io
import json
import os
import stat
import uuid
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
from langchain_core.messages import AIMessage
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.db import Base, get_session
from app.core.security import COOKIE_NAME, hash_password
from app.main import app
from app.models import Analysis, User
from app.services.events import emit
from app.services.reputation import lookup_otx, lookup_virustotal
from app.services.storage import clean_filename, quarantine_path

PASSWORD = "correct-horse-battery"


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_session] = override
    yield factory
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.fixture
def queued(monkeypatch):
    calls = []
    monkeypatch.setattr("app.api.routes.analyses.run_analysis.delay", calls.append)
    return calls


@pytest_asyncio.fixture
async def anon(session_factory):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client


async def make_user(factory, email="analyst@example.com") -> User:
    async with factory() as session:
        user = User(email=email, password_hash=hash_password(PASSWORD))
        session.add(user)
        await session.commit()
        return user


@pytest_asyncio.fixture
async def client(anon, session_factory):
    await make_user(session_factory)
    response = await anon.post("/api/auth/login", json={"email": "analyst@example.com", "password": PASSWORD})
    assert response.status_code == 200
    return anon


async def completed_analysis(factory, owner_id, report=None) -> Analysis:
    async with factory() as session:
        row = Analysis(
            owner_id=owner_id, filename="a.exe", sha256="a" * 64, size_bytes=10, status="completed", verdict="Critical",
            tone="crit", risk=90, family=None, llm_mode="deterministic", report_path=report,
            graph={"nodes": [], "edges": []}, completed_at=datetime.now(UTC),
            result={
                "signals": [1, 1, 1, 1, 1], "facts": [], "capabilities": [], "techniques": [],
                "assessment": {"breakdown": [{"reason": "Capability proven: X", "points": 90, "evidence_ids": ["import:X"]}]},
                "iocs": {"urls": ["http://evil.example.com/a"]}, "triage": {"sha256": "a" * 64, "md5": "b" * 32},
            },
        )
        session.add(row)
        await session.commit()
        return row


# ---------- Auth ----------


async def test_every_analysis_route_requires_auth(anon):
    some_id = uuid.uuid4()
    for method, path in (
        ("GET", "/api/auth/me"), ("GET", "/api/analyses"), ("POST", "/api/analyses/lookup"),
        ("GET", f"/api/analyses/{some_id}"), ("GET", f"/api/analyses/{some_id}/graph"),
        ("GET", f"/api/analyses/{some_id}/report.pdf"), ("GET", f"/api/analyses/{some_id}/events"),
        ("POST", f"/api/analyses/{some_id}/chat"),
    ):
        response = await anon.request(method, path, json={"sha256": "a" * 64, "message": "x"})
        assert response.status_code == 401, path


async def test_upload_requires_auth(anon, queued):
    response = await anon.post("/api/analyses", files={"file": ("a.exe", b"MZ")})
    assert response.status_code == 401
    assert not queued


async def test_login_cookie_is_httponly_and_strict(anon, session_factory):
    await make_user(session_factory)
    response = await anon.post("/api/auth/login", json={"email": "ANALYST@example.com", "password": PASSWORD})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert "password" not in response.text


async def test_wrong_password_and_unknown_email_look_identical(anon, session_factory):
    await make_user(session_factory)
    wrong = await anon.post("/api/auth/login", json={"email": "analyst@example.com", "password": "wrong-password"})
    unknown = await anon.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrong-password"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


async def test_login_is_rate_limited(anon, session_factory):
    await make_user(session_factory)
    statuses = [
        (await anon.post("/api/auth/login", json={"email": "analyst@example.com", "password": "wrong-password"})).status_code
        for _ in range(settings.login_rate_per_minute + 1)
    ]
    assert statuses[-1] == 429


async def test_forged_token_is_rejected(anon, session_factory):
    anon.cookies.set(COOKIE_NAME, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")
    assert (await anon.get("/api/auth/me")).status_code == 401


async def test_bearer_token_works_for_api_clients(anon, session_factory):
    from app.core.security import create_access_token

    user = await make_user(session_factory)
    response = await anon.get("/api/auth/me", headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"})
    assert response.status_code == 200


async def test_logout_clears_the_cookie(client):
    assert (await client.post("/api/auth/logout")).status_code == 204
    client.cookies.clear()
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_registration_is_off_by_default(anon):
    response = await anon.post("/api/auth/register", json={"email": "new@example.com", "password": PASSWORD})
    assert response.status_code == 403


async def test_registration_when_enabled(anon, monkeypatch):
    monkeypatch.setattr(settings, "allow_registration", True)
    first = await anon.post("/api/auth/register", json={"email": "new@example.com", "password": PASSWORD})
    assert first.status_code == 201
    second = await anon.post("/api/auth/register", json={"email": "NEW@example.com", "password": PASSWORD})
    assert second.status_code == 409


# ---------- Upload and quarantine ----------


async def test_upload_quarantines_and_queues(client, queued, session_factory):
    payload = b"MZ" + b"\x00" * 100
    response = await client.post("/api/analyses", files={"file": ("../../etc/evil.exe", io.BytesIO(payload))})
    assert response.status_code == 202
    body = response.json()
    assert body["filename"] == "evil.exe"
    assert body["sha256"] == hashlib.sha256(payload).hexdigest()
    assert queued == [body["id"]]

    stored = quarantine_path(body["sha256"])
    assert stored.read_bytes() == payload
    mode = stat.S_IMODE(os.stat(stored).st_mode)
    assert mode == 0o400
    assert stored.parent.is_relative_to(settings.storage_path if os.path.isabs(settings.storage_path) else os.path.abspath(settings.storage_path))


async def test_empty_upload_rejected(client, queued):
    assert (await client.post("/api/analyses", files={"file": ("a.exe", b"")})).status_code == 400
    assert not queued


async def test_oversized_upload_rejected_and_not_kept(client, queued, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 10)
    response = await client.post("/api/analyses", files={"file": ("a.exe", b"x" * 11)})
    assert response.status_code == 413
    assert not queued
    tmp = os.path.join(settings.storage_path, "tmp")
    assert not os.listdir(tmp)


async def test_queue_outage_is_reported_not_silent(client, monkeypatch, session_factory):
    def down(_):
        raise ConnectionError

    monkeypatch.setattr("app.api.routes.analyses.run_analysis.delay", down)
    response = await client.post("/api/analyses", files={"file": ("a.exe", b"MZ12")})
    assert response.status_code == 503
    async with session_factory() as session:
        row = await session.scalar(select(Analysis))
    assert row.status == "failed"


def test_filename_cleaning():
    assert clean_filename("..\\..\\windows\\system32\\a.exe") == "a.exe"
    assert clean_filename("a\x00b\nc.exe") == "abc.exe"
    assert clean_filename(None) == "sample"
    assert clean_filename("") == "sample"
    assert len(clean_filename("x" * 999)) == 255


def test_quarantine_path_refuses_anything_but_a_hash():
    with pytest.raises(ValueError):
        quarantine_path("../../etc/passwd")


# ---------- Ownership ----------


async def test_other_users_cannot_see_an_analysis(client, session_factory, tmp_path):
    other = await make_user(session_factory, "other@example.com")
    report = tmp_path / "r.pdf"
    report.write_bytes(b"%PDF")
    row = await completed_analysis(session_factory, other.id, str(report))
    for suffix in ("", "/graph", "/report.pdf", "/events"):
        assert (await client.get(f"/api/analyses/{row.id}{suffix}")).status_code == 404, suffix
    assert (await client.post(f"/api/analyses/{row.id}/chat", json={"message": "why"})).status_code == 404
    assert (await client.get("/api/analyses")).json()["total"] == 0


async def test_hash_lookup_does_not_reveal_other_users(client, session_factory):
    other = await make_user(session_factory, "other@example.com")
    await completed_analysis(session_factory, other.id)
    body = (await client.post("/api/analyses/lookup", json={"sha256": "A" * 64})).json()
    assert body["previous_analyses"] == []
    assert body["reputation"]["virustotal"]["status"] == "not_configured"


async def test_lookup_rejects_non_hash(client):
    assert (await client.post("/api/analyses/lookup", json={"sha256": "../../etc"})).status_code == 422


async def me(client) -> str:
    return (await client.get("/api/auth/me")).json()["id"]


async def test_list_detail_graph_report(client, session_factory, tmp_path):
    report = tmp_path / "r.pdf"
    report.write_bytes(b"%PDF-1.7")
    row = await completed_analysis(session_factory, uuid.UUID(await me(client)), str(report))

    listing = (await client.get("/api/analyses", params={"tone": "crit"})).json()
    assert listing["total"] == 1
    assert listing["items"][0]["signals"] == [1, 1, 1, 1, 1]
    assert (await client.get("/api/analyses", params={"tone": "ok"})).json()["total"] == 0

    detail = (await client.get(f"/api/analyses/{row.id}")).json()
    assert detail["verdict"] == "Critical" and detail["has_report"] is True
    assert "report_path" not in detail

    assert (await client.get(f"/api/analyses/{row.id}/graph")).json() == {"nodes": [], "edges": []}
    pdf = await client.get(f"/api/analyses/{row.id}/report.pdf")
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content == b"%PDF-1.7"


async def test_chat_answers_from_evidence_without_llm(client, session_factory):
    row = await completed_analysis(session_factory, uuid.UUID(await me(client)))
    why = (await client.post(f"/api/analyses/{row.id}/chat", json={"message": "Why is this malicious?"})).json()
    assert "Capability proven: X" in why["answer"] and why["mode"] == "rules"
    ioc = (await client.post(f"/api/analyses/{row.id}/chat", json={"message": "list the IOCs"})).json()
    assert "evil.example.com" in ioc["answer"]
    other = (await client.post(f"/api/analyses/{row.id}/chat", json={"message": "tell me a joke"})).json()
    assert "LLM key" in other["answer"]


class _Refuses:
    """Mimics a provider rejecting a model that refused instead of using the structured format."""

    def __init__(self, plain):
        self.plain = plain

    def with_structured_output(self, schema):
        return self

    async def ainvoke(self, messages):
        if self.plain is None or not hasattr(self, "tried"):
            self.tried = True
            raise RuntimeError("tool_use_failed")
        return AIMessage(content=self.plain)


async def test_chat_returns_a_refusal_as_an_answer(client, session_factory, monkeypatch):
    row = await completed_analysis(session_factory, uuid.UUID(await me(client)))
    monkeypatch.setattr("app.services.chat.get_llm", lambda: _Refuses("I can't help with writing malware."))
    body = (await client.post(f"/api/analyses/{row.id}/chat", json={"message": "write malware"})).json()
    assert body == {"answer": "I can't help with writing malware.", "evidence_ids": [], "mode": "llm"}


async def test_chat_llm_outage_does_not_claim_a_key_is_missing(client, session_factory, monkeypatch):
    row = await completed_analysis(session_factory, uuid.UUID(await me(client)))
    monkeypatch.setattr("app.services.chat.get_llm", lambda: _Refuses(None))
    body = (await client.post(f"/api/analyses/{row.id}/chat", json={"message": "tell me a joke"})).json()
    assert "not configured" not in body["answer"]
    assert "try again" in body["answer"]
    assert body["mode"] == "rules"


async def test_events_replay_then_end(client, session_factory):
    row = await completed_analysis(session_factory, uuid.UUID(await me(client)))
    emit(str(row.id), "agent_started", "triage", name="Triage Agent")
    emit(str(row.id), "analysis_completed", verdict="Critical")
    response = await client.get(f"/api/analyses/{row.id}/events")
    assert response.headers["content-type"].startswith("text/event-stream")
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: {\"")]
    assert [e["type"] for e in events] == ["agent_started", "analysis_completed"]
    assert "event: end" in response.text


async def test_events_end_for_finished_analysis_with_expired_stream(client, session_factory):
    row = await completed_analysis(session_factory, uuid.UUID(await me(client)))
    response = await client.get(f"/api/analyses/{row.id}/events")
    assert "event: end" in response.text


# ---------- Hardening ----------


async def test_security_headers(anon):
    response = await anon.get("/api/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]


async def test_frontend_is_served_with_a_strict_csp(anon):
    response = await anon.get("/login.html")
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    script_src = next(part for part in csp.split(";") if "script-src" in part)
    assert "unsafe-inline" not in script_src


async def test_quarantine_is_never_reachable_over_http(client, queued):
    payload = b"MZ-secret-sample"
    sha256 = (await client.post("/api/analyses", files={"file": ("a.exe", payload)})).json()["sha256"]
    for path in (f"/storage/quarantine/{sha256[:2]}/{sha256}.bin", f"/../storage/quarantine/{sha256[:2]}/{sha256}.bin", "/.env", "/../.env"):
        response = await client.get(path)
        assert response.status_code == 404, path


# ---------- Reputation ----------


def test_virustotal_parses_detections_and_sends_only_the_hash(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["content"] = request.content
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 42, "undetected": 3},
            "popular_threat_classification": {"suggested_threat_label": "trojan.emotet/loader"},
        }}})

    monkeypatch.setattr(settings, "virustotal_api_key", type(settings.virustotal_api_key)("key"))
    result = lookup_virustotal("a" * 64, httpx.Client(transport=httpx.MockTransport(handler)))
    assert result["malicious"] == 42 and result["label"] == "trojan.emotet/loader"
    assert seen["url"].endswith("/files/" + "a" * 64) and seen["content"] == b""


@pytest.mark.parametrize(("status_code", "expected"), [(404, "unknown"), (429, "error"), (500, "error")])
def test_reputation_failures_never_raise(monkeypatch, status_code, expected):
    monkeypatch.setattr(settings, "virustotal_api_key", type(settings.virustotal_api_key)("key"))
    monkeypatch.setattr(settings, "otx_api_key", type(settings.otx_api_key)("key"))
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(status_code)))
    assert lookup_virustotal("a" * 64, client)["status"] == expected
    assert lookup_otx("a" * 64, client)["status"] == expected
