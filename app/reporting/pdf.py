"""Renders the explainable PDF report (reportlab for layout, pypdf for metadata).

All file-derived text is escaped before layout, and indicators are defanged so nothing
in the report is a live link.
"""

import hashlib
import io
from datetime import UTC, datetime
from xml.sax.saxutils import escape

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.services.storage import report_path

INK = colors.HexColor("#0D052B")
MUTED = colors.HexColor("#6b6880")
RULE = colors.HexColor("#ddd9ea")
TONES = {"crit": colors.HexColor("#c0263b"), "warn": colors.HexColor("#b87a10"), "ok": colors.HexColor("#1f8a4c")}

_base = getSampleStyleSheet()["BodyText"]
BODY = ParagraphStyle("body", parent=_base, fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=8.5, leading=11.5, wordWrap="CJK")
MONO = ParagraphStyle("mono", parent=CELL, fontName="Courier", fontSize=8, leading=11)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, textColor=MUTED, leading=11)
H1 = ParagraphStyle("h1", parent=BODY, fontName="Helvetica-Bold", fontSize=21, leading=25, spaceAfter=2)
H2 = ParagraphStyle("h2", parent=BODY, fontName="Helvetica-Bold", fontSize=12, leading=16, spaceBefore=14, spaceAfter=6)


def text(value) -> str:
    return escape(str(value))


def defang(value: str) -> str:
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace("ftp://", "fxp://").replace(".", "[.]")


def _table(rows: list[list], widths: list[float], head: bool = False) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if head else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]
    if head:
        style.append(("LINEBELOW", (0, 0), (-1, 0), 0.9, INK))
    table.setStyle(TableStyle(style))
    return table


def _header_row(*labels: str) -> list:
    return [Paragraph(f"<b>{text(label)}</b>", CELL) for label in labels]


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "SentinelTI · Autonomous Threat Intelligence Platform by Relativity")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _build_story(state: dict) -> list:
    triage, assessment = state["triage"], state["assessment"]
    parsed = state.get("parsed") or {}
    width = A4[0] - 36 * mm
    tone = TONES.get(assessment["tone"], INK)
    story = [
        Paragraph("SentinelTI malware analysis report", SMALL),
        Paragraph(text(state["filename"]), H1),
        Spacer(1, 4),
        Paragraph(f'<font color="{tone.hexval().replace("0x", "#")}"><b>{text(assessment["verdict"])}</b></font> · risk {assessment["risk"]}/100'
                  + (f' · {text(state["family"])}' if state.get("family") else ""), BODY),
        Paragraph(f"Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC · static analysis only; the sample was never executed.", SMALL),
    ]

    story += [Paragraph("Summary", H2)]
    narrative = state.get("narrative") or {}
    for point in narrative.get("summary", []):
        story.append(Paragraph(text(point["text"]), BODY))
        story.append(Spacer(1, 3))
    if narrative.get("recommended_actions"):
        story += [Paragraph("Recommended actions", H2)]
        story += [Paragraph("• " + text(action), BODY) for action in narrative["recommended_actions"]]

    file_rows = [
        ("Real type", triage["label"]), ("Size", f"{triage['size_bytes']:,} bytes"), ("Entropy", triage["entropy"]),
        ("MD5", triage["md5"]), ("SHA-1", triage["sha1"]), ("SHA-256", triage["sha256"]), ("ssdeep", triage.get("ssdeep") or "n/a"),
        ("Import hash", parsed.get("imphash") or "n/a"), ("Compiled", parsed.get("compile_timestamp") or "n/a"),
    ]
    story += [Paragraph("File", H2), _table(
        [[Paragraph(text(k), CELL), Paragraph(text(v), MONO)] for k, v in file_rows], [28 * mm, width - 28 * mm])]

    breakdown = assessment["breakdown"]
    if breakdown:
        rows = [_header_row("Why this score", "Points")] + [
            [Paragraph(text(item["reason"]), CELL), Paragraph(str(item["points"]), CELL)] for item in breakdown
        ]
        story += [Paragraph("Risk breakdown", H2), _table(rows, [width - 20 * mm, 20 * mm], head=True)]

    capabilities = state.get("capabilities") or []
    proven = [c for c in capabilities if c["status"] == "proven"]
    if proven:
        facts = state["facts"]
        rows = [_header_row("Capability", "ATT&CK", "Proof")]
        for capability in proven:
            proof = "; ".join(facts[i]["title"] for i in capability["evidence_ids"] if i in facts)
            rows.append([Paragraph(text(capability["name"]), CELL), Paragraph(text(", ".join(capability["techniques"]) or "n/a"), CELL), Paragraph(text(proof), CELL)])
        story += [Paragraph("Proven capabilities", H2), _table(rows, [46 * mm, 24 * mm, width - 70 * mm], head=True)]

    techniques = state.get("techniques") or []
    if techniques:
        rows = [_header_row("ID", "Technique", "Tactic", "Conf.")] + [
            [Paragraph(text(t["id"]), MONO), Paragraph(text(t["name"]), CELL), Paragraph(text(t["tactic"]), CELL), Paragraph(f"{t['confidence']:.2f}", CELL)]
            for t in techniques
        ]
        story += [Paragraph("MITRE ATT&amp;CK mapping", H2), _table(rows, [20 * mm, width - 74 * mm, 40 * mm, 14 * mm], head=True)]

    hypotheses = state.get("hypotheses") or []
    if hypotheses:
        story += [Paragraph("Unproven hypotheses", H2), Paragraph("These did not affect the score.", SMALL)]
        story += [Paragraph("• " + text(h["statement"]), BODY) for h in hypotheses]

    iocs = state.get("iocs") or {}
    rows = []
    for kind in ("urls", "ips", "domains", "emails", "registry_keys", "file_paths", "crypto_wallets"):
        for value in iocs.get(kind, [])[:25]:
            shown = defang(value) if kind in ("urls", "ips", "domains", "emails") else value
            rows.append([Paragraph(text(kind.replace("_", " ")), CELL), Paragraph(text(shown), MONO)])
    if rows:
        story += [Paragraph("Indicators", H2), _table([_header_row("Type", "Value (defanged)"), *rows], [28 * mm, width - 28 * mm], head=True)]

    sections = parsed.get("sections") or []
    if sections:
        rows = [_header_row("Section", "Raw", "Virtual", "Entropy")] + [
            [Paragraph(text(s["name"]), MONO), Paragraph(str(s["raw_size"]), CELL), Paragraph(str(s["virtual_size"]), CELL), Paragraph(str(s["entropy"]), CELL)]
            for s in sections[:30]
        ]
        story += [Paragraph("Sections", H2), _table(rows, [width - 66 * mm, 22 * mm, 22 * mm, 22 * mm], head=True)]

    notes = state.get("notes") or []
    if notes:
        story += [Paragraph("Internal threat notes", H2), Paragraph("General references on these techniques, not findings about this file.", SMALL)]
        for note in notes:
            story += [Paragraph(f"<b>{text(note['title'])}</b>", BODY), Paragraph(text(note["excerpt"]), CELL), Spacer(1, 4)]

    verification = state.get("verification") or {}
    story += [
        Paragraph("Verification", H2),
        Paragraph(f"{verification.get('verified', 0)} of {verification.get('checked', 0)} facts were re-checked against the quarantined file. "
                  f"{verification.get('failed', 0)} were rejected. The verdict and score are computed in code from verified evidence, not by an LLM.", BODY),
    ]
    return story


def render_pdf(state: dict) -> tuple[str, str]:
    """Write the report and return (path, sha256)."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm)
    doc.build(_build_story(state), onFirstPage=_footer, onLaterPages=_footer)

    buffer.seek(0)
    writer = PdfWriter(clone_from=PdfReader(buffer))
    writer.add_metadata({
        "/Title": f"SentinelTI report: {state['filename']}"[:200],
        "/Author": "SentinelTI by Relativity",
        "/Subject": f"SHA-256 {state['triage']['sha256']}",
    })
    output = io.BytesIO()
    writer.write(output)
    data = output.getvalue()

    path = report_path(state["analysis_id"])
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    return str(path), hashlib.sha256(data).hexdigest()
