from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from helm_path.processing import calculate_file_hash


def init_audit_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id TEXT NOT NULL,
                run_id TEXT UNIQUE NOT NULL,
                manifest_path TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def calculate_chain_hash(challenge_id: str, run_id: str, manifest_path: str, manifest_hash: str, previous_hash: str) -> str:
    payload = f"{challenge_id}|{run_id}|{manifest_path}|{manifest_hash}|{previous_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_run(db_path: Path, challenge_id: str, run_id: str, manifest_path: Path) -> str:
    init_audit_db(db_path)
    manifest_hash = calculate_file_hash(manifest_path)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = row[0] if row else "0" * 64
        chain_hash = calculate_chain_hash(challenge_id, run_id, manifest_path.as_posix(), manifest_hash, previous_hash)
        conn.execute(
            """
            INSERT INTO audit_log
            (challenge_id, run_id, manifest_path, manifest_hash, previous_hash, chain_hash, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                challenge_id,
                run_id,
                manifest_path.as_posix(),
                manifest_hash,
                previous_hash,
                chain_hash,
                datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            ),
        )
        conn.commit()
        return chain_hash


def verify_chain(db_path: Path) -> list[str]:
    if not db_path.exists():
        return ["Audit database is missing."]

    findings: list[str] = []
    expected_previous_hash = "0" * 64
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT challenge_id, run_id, manifest_path, manifest_hash, previous_hash, chain_hash
            FROM audit_log
            ORDER BY id ASC
            """
        ).fetchall()

    for challenge_id, run_id, manifest_path, manifest_hash, previous_hash, chain_hash in rows:
        path = Path(manifest_path)
        if previous_hash != expected_previous_hash:
            findings.append(f"Broken audit chain before run {run_id}.")
        if not path.exists():
            findings.append(f"Manifest missing for audited run {run_id}: {path}")
        else:
            actual_manifest_hash = calculate_file_hash(path)
            if actual_manifest_hash != manifest_hash:
                findings.append(f"Manifest hash mismatch for run {run_id}.")
        recomputed = calculate_chain_hash(challenge_id, run_id, manifest_path, manifest_hash, previous_hash)
        if recomputed != chain_hash:
            findings.append(f"Audit chain hash mismatch for run {run_id}.")
        expected_previous_hash = chain_hash
    return findings
