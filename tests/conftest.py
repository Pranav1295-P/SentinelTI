"""Tests run with no services: SQLite for the database, fakeredis for Redis, no real keys."""

import os

os.environ.update({
    "ENVIRONMENT": "test",
    "DATABASE_URL_ASYNC": "sqlite+aiosqlite:///:memory:",
    "DATABASE_URL_SYNC": "sqlite:///:memory:",
    "REDIS_URL": "redis://test/0",
    "CELERY_BROKER_URL": "memory://",
    "CELERY_RESULT_BACKEND": "cache+memory://",
    "SECRET_KEY": "test-secret-key-that-is-long-enough-for-hs256",
    "LLM_API_KEY": "",
    "VIRUSTOTAL_API_KEY": "",
    "OTX_API_KEY": "",
    "NEO4J_URI": "",
    "LANGSMITH_TRACING": "false",
})

import fakeredis  # noqa: E402
import fakeredis.aioredis  # noqa: E402
import pytest  # noqa: E402

from app.core.config import settings  # noqa: E402
from tests.factory import build_pe  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "storage_path", str(tmp_path / "storage"))
    server = fakeredis.FakeServer()
    sync_client = fakeredis.FakeRedis(server=server, decode_responses=True)
    async_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    monkeypatch.setattr("app.services.events.get_sync_redis", lambda: sync_client)
    monkeypatch.setattr("app.services.ratelimit.get_async_redis", lambda: async_client)
    monkeypatch.setattr("app.api.routes.analyses.get_async_redis", lambda: async_client)
    monkeypatch.setattr("app.api.routes.health.get_async_redis", lambda: async_client)
    return sync_client


@pytest.fixture
def malicious_pe(tmp_path):
    """A harmless synthetic PE: never runnable, but it carries a full evidence chain."""
    path = tmp_path / "invoice_0923.pdf"
    path.write_bytes(build_pe(
        imports={
            "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent"],
            "advapi32.dll": ["RegSetValueExW", "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueW"],
            "wininet.dll": ["InternetOpenA", "HttpSendRequestA"],
            "urlmon.dll": ["URLDownloadToFileA"],
        },
        extra_strings=[
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "http://185.244.25.14:8080/gate.php",
            "91.92.109.3",
            "cmd.exe /c del",
            "UPX!",
        ],
        packed=True,
    ))
    return path


@pytest.fixture
def benign_pe(tmp_path):
    path = tmp_path / "hello.exe"
    path.write_bytes(build_pe(
        imports={"kernel32.dll": ["GetStdHandle", "WriteFile", "ExitProcess", "GetLastError", "HeapAlloc", "HeapFree"]},
        extra_strings=["Hello, world", "See https://www.microsoft.com/ for details"],
        packed=False,
    ))
    return path
