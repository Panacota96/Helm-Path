from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helm_path.constants import (
    AUDIT_DIRNAME,
    FAILURES_FILENAME,
    METADATA_FILENAME,
    REPORT_MANIFEST_FILENAME,
    WORKING_NOTES_FILENAME,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "challenge"


def resolve_challenge_path(challenge_path: Path) -> Path:
    path = challenge_path.resolve()
    if not (path / METADATA_FILENAME).exists():
        raise ValueError(f"{path} is not an initialized Helm-Path challenge workspace.")
    return path


def challenge_identifier(competition: str, category: str, challenge: str) -> str:
    return "__".join([slugify(competition), slugify(category), slugify(challenge)])


def init_challenge_workspace(root: Path, competition: str, category: str, challenge: str) -> Path:
    competition_slug = slugify(competition)
    category_slug = slugify(category)
    challenge_slug = slugify(challenge)
    challenge_path = root.resolve() / competition_slug / category_slug / challenge_slug
    for path in (
        challenge_path / "sessions",
        challenge_path / "reports",
        challenge_path / "notes",
        challenge_path / "artifacts",
        challenge_path / AUDIT_DIRNAME,
    ):
        path.mkdir(parents=True, exist_ok=True)

    metadata = {
        "schema_version": 1,
        "challenge_id": challenge_identifier(competition, category, challenge),
        "competition": competition,
        "category": category,
        "challenge_name": challenge,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "status": "initialized",
    }
    save_challenge_metadata(challenge_path, metadata)
    (challenge_path / ".gitignore").write_text(".ffr/\n*.pdf\n__pycache__/\n", encoding="utf-8")
    (challenge_path / "artifacts" / ".gitkeep").write_text("", encoding="utf-8")
    (challenge_path / "notes" / WORKING_NOTES_FILENAME).write_text(
        "# Working Notes\n\n## Target Summary\n\n## Hypotheses\n\n## Evidence\n\n## Final Chain\n",
        encoding="utf-8",
    )
    (challenge_path / "notes" / FAILURES_FILENAME).write_text(
        "# Failure Analysis\n\n| Attempt | Reason It Failed | Evidence |\n| --- | --- | --- |\n",
        encoding="utf-8",
    )
    return challenge_path


def ensure_challenge_workspace(challenge_path: Path) -> dict[str, Any]:
    path = resolve_challenge_path(challenge_path)
    return load_challenge_metadata(path)


def load_challenge_metadata(challenge_path: Path) -> dict[str, Any]:
    return json.loads((challenge_path / METADATA_FILENAME).read_text(encoding="utf-8"))


def save_challenge_metadata(challenge_path: Path, metadata: dict[str, Any]) -> None:
    (challenge_path / METADATA_FILENAME).write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def create_run_layout(challenge_path: Path, metadata: dict[str, Any], image_tag: str, image_id: str) -> tuple[Path, dict[str, Any]]:
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    run_dir = challenge_path / "sessions" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    manifest = {
        "schema_version": 1,
        "challenge_id": metadata["challenge_id"],
        "run_id": run_id,
        "captured_at": {"start": utc_now(), "end": None},
        "environment": {
            "image_tag": image_tag,
            "image_id": image_id,
            "container_hostname": f"helm-path-{run_id}",
        },
        "files": {
            "raw_log": f"sessions/{run_id}/raw.log",
            "clean_log": f"sessions/{run_id}/clean.log",
            "manifest": f"sessions/{run_id}/manifest.json",
        },
        "hashes": {"raw_log": None, "clean_log": None},
        "processing": {},
    }
    return run_dir, manifest


def list_run_directories(challenge_path: Path) -> list[Path]:
    sessions_dir = resolve_challenge_path(challenge_path) / "sessions"
    return sorted([path for path in sessions_dir.iterdir() if path.is_dir()])


def run_file_paths(challenge_path: Path, run_id: str) -> dict[str, Path]:
    run_dir = resolve_challenge_path(challenge_path) / "sessions" / run_id
    return {
        "run_dir": run_dir,
        "raw_log": run_dir / "raw.log",
        "clean_log": run_dir / "clean.log",
        "manifest": run_dir / "manifest.json",
    }


def load_manifest(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))


def report_output_paths(challenge_path: Path) -> dict[str, Path]:
    report_dir = resolve_challenge_path(challenge_path) / "reports"
    return {
        "DRAFT_WRITEUP.md": report_dir / "DRAFT_WRITEUP.md",
        "PATH_SUMMARY.md": report_dir / "PATH_SUMMARY.md",
        "FAILURE_ANALYSIS.md": report_dir / "FAILURE_ANALYSIS.md",
        "payloads.json": report_dir / "payloads.json",
        "timeline.json": report_dir / "timeline.json",
        "DRAFT_WRITEUP.pdf": report_dir / "DRAFT_WRITEUP.pdf",
        REPORT_MANIFEST_FILENAME: report_dir / REPORT_MANIFEST_FILENAME,
    }


def load_report_manifest(challenge_path: Path) -> dict[str, Any] | None:
    path = report_output_paths(challenge_path)[REPORT_MANIFEST_FILENAME]
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
