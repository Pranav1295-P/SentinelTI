"""Launches isolated_entry as a limited, secret-free child process."""

import json
import os
import subprocess
import sys
from pathlib import Path

from app.core.config import settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = Path(__file__).resolve().parent / "rules"
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


def _run(*args: str) -> dict:
    command = [sys.executable, "-m", "app.analysis.isolated_entry", *args, str(settings.parser_memory_mb)]
    # Only what Python needs: no API keys or database URLs reach the parser.
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(PROJECT_ROOT), "HOME": "/tmp"}
    try:
        proc = subprocess.run(
            command, capture_output=True, env=env, cwd=PROJECT_ROOT,
            timeout=settings.parser_timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"parser timed out after {settings.parser_timeout_seconds}s"}
    if proc.returncode != 0:
        return {"error": f"parser exited with code {proc.returncode}"}
    if len(proc.stdout) > MAX_OUTPUT_BYTES:
        return {"error": "parser output too large"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "parser returned invalid output"}


def parse_binary(path: Path) -> dict:
    return _run("pe", str(path))


def scan_yara(path: Path, rules_dir: Path = RULES_DIR) -> dict:
    return _run("yara", str(path), str(rules_dir))
