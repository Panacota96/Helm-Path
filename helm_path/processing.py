from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helm_path.constants import COMMAND_MARKER_END, COMMAND_MARKER_START

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
NOISE_PATTERNS = [
    re.compile(r"^\s*$"),
    re.compile(r"^Script started on .*"),
    re.compile(r"^Script done on .*"),
    re.compile(r"^(clear|reset)\s*$"),
    re.compile(r"^ls\s*$"),
    re.compile(r"^cd \.\.\s*$"),
    re.compile(rf"^{re.escape(COMMAND_MARKER_START)}::.*$"),
    re.compile(rf"^{re.escape(COMMAND_MARKER_END)}::.*$"),
]
SECRET_PATTERNS = [
    (re.compile(r"password\s*=\s*\S+", re.IGNORECASE), "password=[REDACTED]"),
    (re.compile(r"API_KEY\s*=\s*\S+", re.IGNORECASE), "API_KEY=[REDACTED]"),
    (re.compile(r"Authorization:\s*Bearer\s+\S+", re.IGNORECASE), "Authorization: Bearer [REDACTED]"),
    (re.compile(r"--password\s+\S+", re.IGNORECASE), "--password [REDACTED]"),
    (re.compile(r"(^|\s)-p\s+\S+", re.IGNORECASE), r"\1-p [REDACTED]"),
]


def calculate_file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clean_sensitive_data(content: str) -> tuple[str, int]:
    redactions = 0
    cleaned = content
    for pattern, replacement in SECRET_PATTERNS:
        cleaned, count = pattern.subn(replacement, cleaned)
        redactions += count
    return cleaned, redactions


def normalize_log_content(content: str) -> tuple[str, int]:
    without_ansi = ANSI_ESCAPE.sub("", content)
    filtered_lines: list[str] = []
    removed = 0
    for line in without_ansi.splitlines():
        if any(pattern.match(line) for pattern in NOISE_PATTERNS):
            removed += 1
            continue
        filtered_lines.append(line)
    normalized = "\n".join(filtered_lines).strip()
    if normalized:
        normalized += "\n"
    return normalized, removed


def build_clean_log(raw_path: Path, clean_path: Path) -> dict[str, Any]:
    raw_content = raw_path.read_text(encoding="utf-8", errors="ignore")
    normalized, removed_lines = normalize_log_content(raw_content)
    cleaned, redactions = clean_sensitive_data(normalized)
    clean_path.write_text(cleaned, encoding="utf-8")
    return {
        "processed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "removed_lines": removed_lines,
        "redactions": redactions,
        "noise_filter_version": "ffr-v1",
        "redaction_version": "ffr-v1",
    }


def write_json_file(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_report_manifest(
    challenge_path: Path,
    run_ids: list[str],
    model: str,
    prompt_version: str,
    outputs: dict[str, Path],
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "challenge_path": str(challenge_path),
        "run_ids": run_ids,
        "model": model,
        "prompt_version": prompt_version,
        "outputs": {name: calculate_file_hash(path) for name, path in outputs.items() if path.exists()},
    }
