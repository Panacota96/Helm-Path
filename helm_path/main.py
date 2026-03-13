from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel

from helm_path import __version__
from helm_path.ai import generate_report_bundle
from helm_path.audit import init_audit_db, record_run, verify_chain
from helm_path.constants import (
    APP_NAME,
    AUDIT_DB_FILENAME,
    CHALLENGES_DIRNAME,
    COMMAND_LOG_FILENAME,
    DEFAULT_MODEL,
    FULL_IMAGE_TAG,
    LITE_IMAGE_TAG,
    REPORT_MANIFEST_FILENAME,
)
from helm_path.graph.cli import app as graph_app
from helm_path.processing import (
    build_clean_log,
    calculate_file_hash,
    write_json_file,
    write_report_manifest,
)
from helm_path.workspace import (
    create_run_layout,
    ensure_challenge_workspace,
    graph_output_paths,
    init_challenge_workspace,
    list_run_directories,
    load_graph_manifest,
    load_manifest,
    load_report_manifest,
    report_output_paths,
    resolve_challenge_path,
    run_file_paths,
    save_challenge_metadata,
)

docker = None
pypandoc = None

app = typer.Typer(help="Helm-Path: local-first CTF flight recorder and writeup generator")
app.add_typer(graph_app, name="graph")
console = Console()


def get_docker_client():
    global docker
    if docker is None:
        import docker as docker_module

        docker = docker_module
    try:
        return docker.from_env()
    except Exception as exc:
        console.print(f"[bold red]Docker unavailable:[/bold red] {exc}")
        raise typer.Exit(1) from exc


def get_pypandoc():
    global pypandoc
    if pypandoc is None:
        import pypandoc as pypandoc_module

        pypandoc = pypandoc_module
    return pypandoc


def build_image_if_needed(client: Any, image_tag: str, lite: bool) -> Any:
    dockerfile = "docker/Dockerfile.lite" if lite else "docker/Dockerfile.kali"
    try:
        return client.images.get(image_tag)
    except docker.errors.ImageNotFound:
        console.print(f"[bold yellow]Building image[/bold yellow] {image_tag} from {dockerfile}")
        image, _ = client.images.build(path=".", dockerfile=dockerfile, tag=image_tag)
        return image


def select_run_dirs(challenge_path: Path, run_id: str | None, all_runs: bool) -> list[Path]:
    runs = list_run_directories(challenge_path)
    if not runs:
        raise typer.BadParameter("No recorded runs found in this challenge workspace.")
    if run_id:
        target = challenge_path / "sessions" / run_id
        if not target.exists():
            raise typer.BadParameter(f"Run '{run_id}' does not exist.")
        if not (target / "manifest.json").exists():
            raise typer.BadParameter(f"Run '{run_id}' is incomplete because manifest.json is missing.")
        return [target]
    complete_runs = [run for run in runs if (run / "manifest.json").exists()]
    if not complete_runs:
        raise typer.BadParameter("No complete recorded runs found. Remove incomplete session folders or rerun capture.")
    if all_runs or len(runs) == 1:
        return complete_runs
    return [complete_runs[-1]]


def verify_manifest_files(challenge_path: Path, run_dirs: list[Path]) -> list[str]:
    findings: list[str] = []
    for run_dir in run_dirs:
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            findings.append(f"Incomplete run directory is missing manifest.json: {run_dir}")
            continue
        manifest = load_manifest(run_dir)
        paths = run_file_paths(challenge_path, manifest["run_id"])
        required = {
            "raw log": paths["raw_log"],
            "clean log": paths["clean_log"],
            "manifest": paths["manifest"],
        }
        if manifest.get("files", {}).get("commands_log") or manifest.get("hashes", {}).get("commands_log") is not None:
            required["commands log"] = paths["commands_log"]
        missing = False
        for label, path in required.items():
            if not path.exists():
                findings.append(f"Missing {label} for run {manifest['run_id']}: {path}")
                missing = True
        if missing:
            continue
        raw_hash = calculate_file_hash(paths["raw_log"])
        clean_hash = calculate_file_hash(paths["clean_log"])
        if raw_hash != manifest["hashes"]["raw_log"]:
            findings.append(f"Hash mismatch for raw log in run {manifest['run_id']}.")
        if clean_hash != manifest["hashes"]["clean_log"]:
            findings.append(f"Hash mismatch for clean log in run {manifest['run_id']}.")
        if manifest.get("hashes", {}).get("commands_log") is not None:
            commands_hash = calculate_file_hash(paths["commands_log"])
            if commands_hash != manifest["hashes"].get("commands_log"):
                findings.append(f"Hash mismatch for commands log in run {manifest['run_id']}.")
    return findings


def verify_report_outputs(challenge_path: Path) -> list[str]:
    findings: list[str] = []
    report_manifest = load_report_manifest(challenge_path)
    report_paths = report_output_paths(challenge_path)
    if not report_manifest:
        orphaned = [path for name, path in report_paths.items() if name != REPORT_MANIFEST_FILENAME and path.exists()]
        for path in orphaned:
            findings.append(f"Orphaned report output not referenced by report manifest: {path}")
        return findings

    outputs = report_manifest.get("outputs", {})
    for filename, expected_hash in outputs.items():
        path = challenge_path / "reports" / filename
        if not path.exists():
            findings.append(f"Missing report output referenced in report manifest: {path}")
            continue
        actual_hash = calculate_file_hash(path)
        if actual_hash != expected_hash:
            findings.append(f"Hash mismatch for report output {filename}.")

    tracked = {challenge_path / "reports" / name for name in outputs}
    for name, path in report_paths.items():
        if name == REPORT_MANIFEST_FILENAME:
            continue
        if path.exists() and path not in tracked:
            findings.append(f"Orphaned report output not referenced by report manifest: {path}")
    return findings


def verify_graph_outputs(challenge_path: Path) -> list[str]:
    findings: list[str] = []
    graph_manifest = load_graph_manifest(challenge_path)
    if not graph_manifest:
        return findings
    output_paths = graph_output_paths(challenge_path)
    for filename, expected_hash in graph_manifest.get("outputs", {}).items():
        path = challenge_path / "graph" / filename
        if not path.exists():
            findings.append(f"Missing graph output referenced in graph manifest: {path}")
            continue
        actual_hash = calculate_file_hash(path)
        if actual_hash != expected_hash:
            findings.append(f"Hash mismatch for graph output {filename}.")
    return findings


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show the version and exit"),
):
    if version:
        console.print(f"{APP_NAME} {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@app.command()
def init(
    competition: str = typer.Argument(..., help="Competition name"),
    category: str = typer.Argument(..., help="Category name"),
    challenge: str = typer.Argument(..., help="Challenge name"),
    root: Path = typer.Option(Path(CHALLENGES_DIRNAME), "--root", help="Root folder for challenge workspaces"),
):
    """Create a challenge workspace with templates and local audit storage."""
    challenge_path = init_challenge_workspace(root, competition, category, challenge)
    init_audit_db(challenge_path / ".ffr" / AUDIT_DB_FILENAME)
    console.print(Panel.fit(f"Workspace created at\n[bold cyan]{challenge_path}[/bold cyan]", title="Challenge Initialized"))


@app.command()
def start(
    challenge_path: Path = typer.Argument(..., help="Path to an initialized challenge workspace"),
    lite: bool = typer.Option(False, "--lite", help="Use the lightweight capture image"),
    command: str | None = typer.Option(
        None,
        "--command",
        help="Run a single shell command and exit. Useful for non-interactive smoke tests.",
    ),
):
    """Record a new challenge run inside the Helm-Path container."""
    challenge_path = resolve_challenge_path(challenge_path)
    metadata = ensure_challenge_workspace(challenge_path)
    client = get_docker_client()
    image_tag = LITE_IMAGE_TAG if lite else FULL_IMAGE_TAG
    image = build_image_if_needed(client, image_tag, lite)

    _, manifest = create_run_layout(challenge_path, metadata, image_tag=image_tag, image_id=image.id)
    paths = run_file_paths(challenge_path, manifest["run_id"])
    paths["commands_log"].touch()
    raw_log_relative = Path("sessions") / manifest["run_id"] / "raw.log"
    commands_log_relative = Path("sessions") / manifest["run_id"] / COMMAND_LOG_FILENAME
    interactive = command is None
    if interactive and not (sys.stdin.isatty() and sys.stdout.isatty()):
        shutil.rmtree(paths["run_dir"], ignore_errors=True)
        raise typer.BadParameter("Interactive capture requires a TTY. Re-run in a terminal or pass --command for a smoke test.")

    docker_command = [
        "docker",
        "run",
    ]
    if interactive:
        docker_command.append("-it")
    docker_command.extend(
        [
            "--rm",
            "-v",
            f"{challenge_path.resolve()}:/workspace",
            "--workdir",
            "/workspace",
            "-e",
            f"LOG_FILE={raw_log_relative.as_posix()}",
            "-e",
            f"COMMANDS_FILE={commands_log_relative.as_posix()}",
            "-e",
            f"RUN_ID={manifest['run_id']}",
            "--name",
            f"helm-path-{manifest['run_id']}",
            image_tag,
        ]
    )
    if command is not None:
        docker_command.extend(["/usr/bin/zsh", "-ic", command])

    console.print(
        Panel.fit(
            f"Challenge: [bold]{metadata['challenge_name']}[/bold]\n"
            f"Run ID: [bold cyan]{manifest['run_id']}[/bold cyan]\n"
            f"Recording to: [bold]{raw_log_relative.as_posix()}[/bold]",
            title="Recording Active",
        )
    )

    result = subprocess.run(docker_command, check=False)

    if not paths["raw_log"].exists():
        shutil.rmtree(paths["run_dir"], ignore_errors=True)
        console.print("[bold red]No raw log was captured. The container likely exited before the recorder started.[/bold red]")
        if result.returncode != 0:
            console.print(f"[yellow]Docker exited with status {result.returncode}.[/yellow]")
        raise typer.Exit(1)

    stats = build_clean_log(paths["raw_log"], paths["clean_log"])
    manifest["captured_at"]["end"] = stats["processed_at"]
    manifest["hashes"]["raw_log"] = calculate_file_hash(paths["raw_log"])
    manifest["hashes"]["clean_log"] = calculate_file_hash(paths["clean_log"])
    manifest["hashes"]["commands_log"] = calculate_file_hash(paths["commands_log"])
    manifest["processing"] = stats
    write_json_file(paths["manifest"], manifest)

    init_audit_db(challenge_path / ".ffr" / AUDIT_DB_FILENAME)
    record_run(
        challenge_path / ".ffr" / AUDIT_DB_FILENAME,
        challenge_id=metadata["challenge_id"],
        run_id=manifest["run_id"],
        manifest_path=paths["manifest"],
    )
    metadata["updated_at"] = stats["processed_at"]
    metadata["status"] = "recorded"
    save_challenge_metadata(challenge_path, metadata)
    console.print(f"[bold green]Run captured:[/bold green] {manifest['run_id']}")


@app.command()
def report(
    challenge_path: Path = typer.Argument(..., help="Path to an initialized challenge workspace"),
    run_id: str = typer.Option(None, "--run-id", help="Generate outputs from a single run"),
    all_runs: bool = typer.Option(False, "--all-runs", help="Aggregate every recorded run"),
    model: str = typer.Option(DEFAULT_MODEL, "--model", help="Host Ollama model"),
    format: str = typer.Option("markdown", "--format", help="markdown or pdf"),
):
    """Generate deterministic writeup artifacts from one or more recorded runs."""
    challenge_path = resolve_challenge_path(challenge_path)
    metadata = ensure_challenge_workspace(challenge_path)
    run_dirs = select_run_dirs(challenge_path, run_id=run_id, all_runs=all_runs)
    run_contexts: list[dict[str, Any]] = []
    for run_dir in run_dirs:
        manifest = load_manifest(run_dir)
        clean_log = (run_dir / "clean.log").read_text(encoding="utf-8")
        run_contexts.append({"manifest": manifest, "clean_log": clean_log})

    bundle = generate_report_bundle(metadata, run_contexts, model=model)
    report_paths = report_output_paths(challenge_path)
    report_paths["DRAFT_WRITEUP.md"].write_text(bundle["draft_writeup_md"], encoding="utf-8")
    report_paths["PATH_SUMMARY.md"].write_text(bundle["path_summary_md"], encoding="utf-8")
    report_paths["FAILURE_ANALYSIS.md"].write_text(bundle["failure_analysis_md"], encoding="utf-8")
    write_json_file(report_paths["payloads.json"], bundle["payloads"])
    write_json_file(report_paths["timeline.json"], bundle["timeline"])

    if format == "pdf":
        try:
            pandoc = get_pypandoc()
            pandoc.convert_file(
                str(report_paths["DRAFT_WRITEUP.md"]),
                "pdf",
                format="md",
                outputfile=str(report_paths["DRAFT_WRITEUP.pdf"]),
            )
        except Exception as exc:
            console.print(f"[yellow]PDF export skipped:[/yellow] {exc}")

    outputs = {
        "DRAFT_WRITEUP.md": report_paths["DRAFT_WRITEUP.md"],
        "PATH_SUMMARY.md": report_paths["PATH_SUMMARY.md"],
        "FAILURE_ANALYSIS.md": report_paths["FAILURE_ANALYSIS.md"],
        "payloads.json": report_paths["payloads.json"],
        "timeline.json": report_paths["timeline.json"],
    }
    if report_paths["DRAFT_WRITEUP.pdf"].exists():
        outputs["DRAFT_WRITEUP.pdf"] = report_paths["DRAFT_WRITEUP.pdf"]

    report_manifest = write_report_manifest(
        challenge_path=challenge_path,
        run_ids=[context["manifest"]["run_id"] for context in run_contexts],
        model=model,
        prompt_version=bundle["prompt_version"],
        outputs=outputs,
    )
    write_json_file(report_paths[REPORT_MANIFEST_FILENAME], report_manifest)

    metadata["updated_at"] = report_manifest["generated_at"]
    metadata["status"] = "reported"
    save_challenge_metadata(challenge_path, metadata)
    console.print(f"[bold green]Report artifacts generated in[/bold green] {challenge_path / 'reports'}")


@app.command()
def verify(
    challenge_path: Path = typer.Argument(..., help="Path to an initialized challenge workspace"),
    run_id: str = typer.Option(None, "--run-id", help="Verify a single run"),
):
    """Verify audit chain, run manifests, and generated report outputs."""
    challenge_path = resolve_challenge_path(challenge_path)
    ensure_challenge_workspace(challenge_path)
    run_dirs = select_run_dirs(challenge_path, run_id=run_id, all_runs=run_id is None)
    audit_findings = verify_chain(challenge_path / ".ffr" / AUDIT_DB_FILENAME)
    manifest_findings = verify_manifest_files(challenge_path, run_dirs)
    report_findings = verify_report_outputs(challenge_path)
    graph_findings = verify_graph_outputs(challenge_path)

    findings = audit_findings + manifest_findings + report_findings + graph_findings
    if findings:
        console.print("[bold red]Verification failed[/bold red]")
        for finding in findings:
            console.print(f" - {finding}")
        raise typer.Exit(1)

    console.print("[bold green]Verification passed[/bold green]")


@app.command()
def doctor(
    model: str = typer.Option(DEFAULT_MODEL, "--model", help="Model name to validate"),
):
    """Check local prerequisites for capture and report generation."""
    checks: list[tuple[str, bool, str]] = []

    try:
        get_docker_client().ping()
        checks.append(("Docker", True, "reachable"))
    except Exception as exc:
        checks.append(("Docker", False, str(exc)))

    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "ollama list failed")
        model_present = model in result.stdout
        checks.append(("Ollama", True, "reachable"))
        checks.append((f"Model {model}", model_present, "installed" if model_present else "missing"))
    except Exception as exc:
        checks.append(("Ollama", False, str(exc)))

    try:
        pandoc = get_pypandoc()
        version = pandoc.get_pandoc_version()
        checks.append(("Pandoc", True, str(version)))
    except Exception as exc:
        checks.append(("Pandoc", False, f"optional: {exc}"))

    passed = True
    for label, ok, detail in checks:
        status = "[green]OK[/green]" if ok else "[yellow]WARN[/yellow]"
        console.print(f"{status} {label}: {detail}")
        if label in {"Docker", "Ollama"} and not ok:
            passed = False
        if label.startswith("Model ") and not ok:
            passed = False

    if not passed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
