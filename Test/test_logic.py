import json

from helm_path.ai import extract_json, render_report_prompt
from helm_path.audit import init_audit_db, record_run, verify_chain
from helm_path.processing import (
    build_clean_log,
    calculate_file_hash,
    clean_sensitive_data,
    write_json_file,
    write_report_manifest,
)
from helm_path.workspace import (
    create_run_layout,
    init_challenge_workspace,
    load_challenge_metadata,
    load_manifest,
    report_output_paths,
    run_file_paths,
)


def test_init_challenge_workspace_creates_expected_layout(tmp_path):
    challenge_path = init_challenge_workspace(tmp_path, "HTB Apocalypse", "Web", "Flag Command Injection")

    assert challenge_path.exists()
    assert (challenge_path / ".metadata.json").exists()
    assert (challenge_path / "sessions").is_dir()
    assert (challenge_path / "reports").is_dir()
    assert (challenge_path / "notes" / "FAILURES.md").exists()
    assert (challenge_path / "notes" / "WORKING_NOTES.md").exists()
    metadata = load_challenge_metadata(challenge_path)
    assert metadata["challenge_name"] == "Flag Command Injection"
    assert metadata["status"] == "initialized"


def test_clean_sensitive_data_and_log_processing(tmp_path):
    raw_log = tmp_path / "raw.log"
    clean_log = tmp_path / "clean.log"
    raw_log.write_text(
        "\x1b[31mScript started on 2026-03-13\x1b[0m\n"
        "ls\n"
        "ffuf -u http://target/FUZZ --password secret123\n"
        "API_KEY=abc-123\n",
        encoding="utf-8",
    )

    stats = build_clean_log(raw_log, clean_log)
    content = clean_log.read_text(encoding="utf-8")

    assert "Script started" not in content
    assert "ls" not in content
    assert "secret123" not in content
    assert "abc-123" not in content
    assert "[REDACTED]" in content
    assert stats["removed_lines"] >= 2
    assert stats["redactions"] >= 2


def test_report_manifest_hashes_outputs(tmp_path):
    report_file = tmp_path / "DRAFT_WRITEUP.md"
    report_file.write_text("# Draft\n", encoding="utf-8")

    manifest = write_report_manifest(
        challenge_path=tmp_path,
        run_ids=["run-1"],
        model="llama3.2:3b",
        prompt_version="ffr-report-v1",
        outputs={"DRAFT_WRITEUP.md": report_file},
    )

    assert manifest["run_ids"] == ["run-1"]
    assert manifest["outputs"]["DRAFT_WRITEUP.md"] == calculate_file_hash(report_file)


def test_render_report_prompt_and_json_extraction():
    prompt = render_report_prompt(
        {"challenge_name": "Flag Command Injection"},
        "[run:abc123]\nffuf -u http://target/FUZZ",
    )

    assert "Flag Command Injection" in prompt
    assert "[run:abc123]" in prompt

    payload = extract_json(
        """```json
        {
          "path_summary_md": "# Path Summary",
          "failure_analysis_md": "# Failure Analysis",
          "draft_writeup_md": "# Draft Writeup",
          "payloads": [],
          "timeline": []
        }
        ```"""
    )
    assert payload["draft_writeup_md"] == "# Draft Writeup"


def test_audit_chain_detects_manifest_tampering(tmp_path):
    challenge_path = init_challenge_workspace(tmp_path, "HTB", "Pwn", "Echo")
    metadata = load_challenge_metadata(challenge_path)
    run_dir, manifest = create_run_layout(challenge_path, metadata, image_tag="helm-path:lite", image_id="sha256:test")
    paths = run_file_paths(challenge_path, manifest["run_id"])

    paths["raw_log"].write_text("nc target 31337\n", encoding="utf-8")
    paths["clean_log"].write_text("nc target 31337\n", encoding="utf-8")
    manifest["captured_at"]["end"] = "2026-03-13T10:00:00+00:00"
    manifest["hashes"]["raw_log"] = calculate_file_hash(paths["raw_log"])
    manifest["hashes"]["clean_log"] = calculate_file_hash(paths["clean_log"])
    write_json_file(paths["manifest"], manifest)

    db_path = challenge_path / ".ffr" / "audit.db"
    init_audit_db(db_path)
    record_run(db_path, metadata["challenge_id"], manifest["run_id"], paths["manifest"])
    assert verify_chain(db_path) == []

    mutated = load_manifest(run_dir)
    mutated["environment"]["image_tag"] = "tampered"
    write_json_file(paths["manifest"], mutated)

    findings = verify_chain(db_path)
    assert findings
    assert "Manifest hash mismatch" in findings[0]


def test_report_manifest_can_be_written_to_workspace(tmp_path):
    challenge_path = init_challenge_workspace(tmp_path, "HTB", "Misc", "Recorder")
    outputs = report_output_paths(challenge_path)
    outputs["PATH_SUMMARY.md"].write_text("# Summary\n", encoding="utf-8")
    outputs["FAILURE_ANALYSIS.md"].write_text("# Failure Analysis\n", encoding="utf-8")
    outputs["payloads.json"].write_text(json.dumps([]), encoding="utf-8")
    outputs["timeline.json"].write_text(json.dumps([]), encoding="utf-8")

    manifest = write_report_manifest(
        challenge_path=challenge_path,
        run_ids=["run-1", "run-2"],
        model="llama3.2:3b",
        prompt_version="ffr-report-v1",
        outputs={
            "PATH_SUMMARY.md": outputs["PATH_SUMMARY.md"],
            "FAILURE_ANALYSIS.md": outputs["FAILURE_ANALYSIS.md"],
            "payloads.json": outputs["payloads.json"],
            "timeline.json": outputs["timeline.json"],
        },
    )

    assert manifest["model"] == "llama3.2:3b"
    assert set(manifest["outputs"]) == {
        "PATH_SUMMARY.md",
        "FAILURE_ANALYSIS.md",
        "payloads.json",
        "timeline.json",
    }
