"""Containers: the agents must see the sample inside, and an unreadable file is never Clean."""

import hashlib
import io
import os
import stat
import uuid
import zipfile

import pyzipper
from langchain_core.messages import AIMessage

from app.agents.graph import build_pipeline
from app.analysis import archive, capabilities, scoring
from app.core.config import settings
from app.services.storage import quarantine_path, storage_root
from tests.factory import build_pe

INJECTOR = build_pe(
    imports={"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]},
    extra_strings=["http://185.244.25.14:8080/gate.php"],
)


def aes_zip(members: dict[str, bytes], password: bytes | None = b"infected") -> bytes:
    """The format MalwareBazaar publishes: AES-256 with a known password."""
    buffer = io.BytesIO()
    encryption = pyzipper.WZ_AES if password else None
    with pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=encryption) as z:
        if password:
            z.setpassword(password)
        for name, data in members.items():
            z.writestr(name, data)
    return buffer.getvalue()


def plain_zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buffer.getvalue()


def stored(tmp_path, data: bytes, name="sample.zip"):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def run(data: bytes, filename: str) -> dict:
    sha256 = hashlib.sha256(data).hexdigest()
    target = quarantine_path(sha256)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    analysis_id = str(uuid.uuid4())
    return build_pipeline().invoke(
        {"analysis_id": analysis_id, "owner_id": "owner", "filename": filename, "sample_path": str(target),
         "expected_sha256": sha256, "facts": {}, "warnings": [], "trace": []},
        {"configurable": {"thread_id": analysis_id}, "recursion_limit": 60},
    )


# ---------- The bug: a sample in a password-protected ZIP was reported as Clean ----------


def test_malwarebazaar_style_zip_is_analysed_as_the_sample_inside():
    state = run(aes_zip({"payload.exe": INJECTOR}), "145ebbda.zip")
    assert state["filename"] == "payload.exe"
    assert state["expected_sha256"] == hashlib.sha256(INJECTOR).hexdigest()
    assert state["triage"]["kind"] == "PE"
    assert state["container"]["password"] == "infected"
    assert "process_injection" in {c["id"] for c in state["capabilities"] if c["status"] == "proven"}
    assert state["assessment"]["verdict"] != "Clean"
    assert state["facts"]["file:archive"]["verified"] is True


def test_hash_lookups_use_the_inner_sample_not_the_zip(monkeypatch):
    asked = []
    monkeypatch.setattr("app.agents.tools.lookup_hash", lambda sha: asked.append(sha) or {
        "virustotal": {"status": "found", "malicious": 60, "suspicious": 0, "label": "trojan.remcos/rat"},
        "otx": {"status": "unknown", "pulse_count": 0},
    })
    state = run(aes_zip({"quiet.exe": build_pe(imports={"kernel32.dll": ["ExitProcess"]})}), "x.zip")
    assert asked == [state["expected_sha256"]]
    assert state["assessment"]["verdict"] == "Critical"
    assert state["family"] == "trojan.remcos/rat"


def test_remcos_strings_attribute_the_family():
    sample = build_pe(imports={"kernel32.dll": ["ExitProcess"]}, extra_strings=["Remcos_Mutex_Inj", "Initializing connection to C&C", "licence_code.txt"])
    state = run(aes_zip({"a.exe": sample}), "a.zip")
    assert state["family"] == "Remcos RAT"
    assert state["assessment"]["verdict"] in ("Malicious", "Critical")


# ---------- Never Clean without having looked ----------


def test_locked_archive_is_inconclusive_not_clean():
    state = run(aes_zip({"payload.exe": INJECTOR}, password=b"a-password-we-do-not-know"), "locked.zip")
    assert state["assessment"]["verdict"] == "Inconclusive"
    assert state["assessment"]["tone"] == "warn"
    assert state["facts"]["file:not-inspected"]["verified"] is True
    assert all(p["evidence_ids"] for p in state["narrative"]["summary"])


def test_rar_is_inconclusive_not_clean():
    state = run(b"Rar!\x1a\x07\x00" + os.urandom(4096), "a.rar")
    assert state["assessment"]["verdict"] == "Inconclusive"


def test_encrypted_looking_blob_is_inconclusive_not_clean():
    state = run(os.urandom(8192), "mystery.bin")
    assert state["assessment"]["verdict"] == "Inconclusive"
    assert state["facts"]["file:not-inspected"]["verified"] is True


def test_low_entropy_text_is_still_clean():
    state = run(b"just some meeting notes\n" * 40, "notes.txt")
    assert state["assessment"]["verdict"] == "Clean"
    assert scoring.inspected(state)


def test_office_macros_are_flagged_and_document_is_not_cleared():
    doc = plain_zip({"[Content_Types].xml": b"<x/>", "word/vbaProject.bin": b"\xd0\xcf\x11\xe0macro"})
    state = run(doc, "invoice.docm")
    assert state["container"]["macros"] is True
    assert state["assessment"]["verdict"] != "Clean"
    assert any("macros" in b["reason"] for b in state["assessment"]["breakdown"])


# ---------- Choosing what to analyse ----------


def test_executable_is_chosen_over_a_larger_decoy_and_others_are_queued(tmp_path):
    other = build_pe(imports={"kernel32.dll": ["ExitProcess"]}, extra_strings=["second"])
    data = aes_zip({"readme.txt": b"hello there " * 50000, "first.exe": INJECTOR, "second.exe": other})
    outcome = archive.open_container(stored(tmp_path, data), "s.zip")
    assert outcome["primary"]["kind"] == "PE"
    names = {m["name"] for m in outcome["extra"]}
    assert "readme.txt" in names and len(names) == 2
    assert outcome["container"]["member_count"] == 3


def test_nested_archive_is_followed(tmp_path):
    inner = aes_zip({"deep.exe": INJECTOR})
    outcome = archive.open_container(stored(tmp_path, plain_zip({"inner.zip": inner})), "outer.zip")
    assert outcome["primary"]["name"] == "deep.exe"


def test_endless_nesting_stops_and_is_not_cleared(tmp_path):
    data = INJECTOR
    for i in range(6):
        data = plain_zip({f"layer{i}.zip" if i else "x.exe": data})
    outcome = archive.open_container(stored(tmp_path, data), "deep.zip")
    assert outcome["container"]["opaque"] is True


# ---------- Hostile archives ----------


def test_path_traversal_names_cannot_escape_quarantine(tmp_path):
    data = plain_zip({"../../../../tmp/evil.exe": INJECTOR, "..\\..\\windows\\evil2.exe": INJECTOR + b"x"})
    outcome = archive.open_container(stored(tmp_path, data), "t.zip")
    primary = outcome["primary"]
    assert "/" not in primary["name"] and "\\" not in primary["name"]
    assert primary["path"] == str(quarantine_path(primary["sha256"]))
    assert not os.path.exists("/tmp/evil.exe")  # noqa: S108


def test_extracted_files_are_read_only_and_leave_no_temp_files(tmp_path):
    outcome = archive.open_container(stored(tmp_path, aes_zip({"a.exe": INJECTOR})), "a.zip")
    assert stat.S_IMODE(os.stat(outcome["primary"]["path"]).st_mode) == 0o400
    leftovers = storage_root() / "tmp"
    assert not leftovers.exists() or not any(leftovers.iterdir())


def test_zip_bomb_member_is_skipped_not_extracted(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 1024 * 1024)
    data = plain_zip({"bomb.bin": b"\0" * (8 * 1024 * 1024), "real.exe": INJECTOR})
    assert len(data) < 200_000
    outcome = archive.open_container(stored(tmp_path, data), "bomb.zip")
    assert outcome["primary"]["name"] == "real.exe"
    assert outcome["container"]["skipped"] == 1


def test_corrupt_zip_is_not_cleared(tmp_path):
    outcome = archive.open_container(stored(tmp_path, b"PK\x03\x04" + b"garbage" * 100), "bad.zip")
    assert outcome["container"]["opaque"] is True


def test_ordinary_files_pass_straight_through(tmp_path):
    assert archive.open_container(stored(tmp_path, INJECTOR, "a.exe"), "a.exe") is None


# ---------- Static evidence alone must flag a packed loader, for samples nobody has seen yet ----------


def _anomaly(code: str) -> dict:
    return {"code": code, "title": code, "detail": "", "severity": "medium"}


def test_packed_loader_is_proven_without_any_reputation_data():
    # The shape of the real sample that scored Clean without VirusTotal.
    capability = capabilities.packing_capability([_anomaly("high_entropy:.text"), _anomaly("rwx:.text"), _anomaly("few_imports")])
    assert capability["status"] == "proven" and capability["weight"] == 25
    assert "anomaly:few_imports" in capability["evidence_ids"]
    state = {"capabilities": [capability], "parsed": {"anomalies": [_anomaly("high_entropy:.text"), _anomaly("rwx:.text"), _anomaly("few_imports")]}}
    assert scoring.score(state)["verdict"] == "Suspicious"


def test_one_high_entropy_section_alone_is_not_packing():
    assert capabilities.packing_capability([_anomaly("high_entropy:.rsrc")]) is None


def test_clean_file_has_no_packing_capability():
    assert capabilities.packing_capability([_anomaly("nonstandard:.foo")]) is None


def test_narrative_format_failure_is_retried(monkeypatch):
    from langchain_core.runnables import RunnableLambda

    from app.schemas.evidence import Narrative, NarrativePoint

    calls = []

    class Flaky:
        def bind_tools(self, tools):
            return RunnableLambda(lambda messages: AIMessage(content="Done."))

        def with_structured_output(self, schema):
            def respond(messages):
                if schema is not Narrative:
                    return schema()
                calls.append(1)
                if len(calls) == 1:
                    raise RuntimeError("tool_use_failed")
                return Narrative(summary=[NarrativePoint(text="It can inject into other processes.", evidence_ids=["import:VirtualAllocEx"])])
            return RunnableLambda(respond)

    monkeypatch.setattr("app.agents.loop.get_llm", lambda: Flaky())
    monkeypatch.setattr("app.agents.graph.get_llm", lambda: Flaky())
    state = run(INJECTOR, "a.exe")
    assert len(calls) == 2
    assert state["narrative"]["source"] == "llm"
    assert not any("LLM unavailable" in w for w in state["warnings"])
