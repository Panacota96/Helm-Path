from __future__ import annotations

import json
import time
from pathlib import Path

import typer
from rich.console import Console

from helm_path.constants import GRAPH_COMMANDS_FILENAME, GRAPH_HTML_FILENAME, GRAPH_JSON_FILENAME, GRAPH_MANIFEST_FILENAME
from helm_path.graph.build import select_run_dirs, write_graph_artifacts
from helm_path.graph.server import serve_graph_dir
from helm_path.workspace import graph_output_paths, resolve_challenge_path

GRAPH_HELP = "Build and inspect discovery graphs for challenge workspaces"
GRAPH_EPILOG = """Examples:
  helm-path graph build challenges/htb/web/flag-command-injection
  helm-path graph serve challenges/htb/web/flag-command-injection
  helm-path graph export challenges/htb/web/flag-command-injection --format json
"""
GRAPH_BUILD_EPILOG = """Examples:
  helm-path graph build challenges/htb/web/flag-command-injection
  helm-path graph build challenges/htb/web/flag-command-injection --all-runs
  helm-path graph build challenges/htb/web/flag-command-injection --run-id 20260313-020136-abcd12
"""
GRAPH_SERVE_EPILOG = """Examples:
  helm-path graph serve challenges/htb/web/flag-command-injection
  helm-path graph serve challenges/htb/web/flag-command-injection --host 0.0.0.0 --port 9000
"""
GRAPH_EXPORT_EPILOG = """Examples:
  helm-path graph export challenges/htb/web/flag-command-injection
  helm-path graph export challenges/htb/web/flag-command-injection --format json
"""

app = typer.Typer(
    help=GRAPH_HELP,
    epilog=GRAPH_EPILOG,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()


@app.command("build", epilog=GRAPH_BUILD_EPILOG)
def build_graph(
    challenge_path: Path = typer.Argument(..., help="Path to an initialized challenge workspace"),
    run_id: str = typer.Option(None, "--run-id", help="Build from a single run"),
    all_runs: bool = typer.Option(False, "--all-runs", help="Aggregate all recorded runs"),
):
    challenge_path = resolve_challenge_path(challenge_path)
    run_dirs = select_run_dirs(challenge_path, run_id=run_id, all_runs=all_runs)
    manifest = write_graph_artifacts(challenge_path, run_dirs)
    console.print(f"[bold green]Graph artifacts generated in[/bold green] {challenge_path / 'graph'}")
    console.print(f"Runs: {', '.join(manifest['run_ids'])}")


@app.command("serve", epilog=GRAPH_SERVE_EPILOG)
def serve_graph(
    challenge_path: Path = typer.Argument(..., help="Path to an initialized challenge workspace"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8765, "--port", help="Bind port"),
):
    challenge_path = resolve_challenge_path(challenge_path)
    output_paths = graph_output_paths(challenge_path)
    if not output_paths[GRAPH_HTML_FILENAME].exists():
        raise typer.BadParameter("Graph UI not built yet. Run 'helm-path graph build' first.")
    with serve_graph_dir(challenge_path / "graph", host=host, port=port, open_browser=True) as (_, url):
        console.print(f"[bold cyan]Serving discovery graph at[/bold cyan] {url}")
        console.print("[dim]Press Ctrl+C to stop the local server.[/dim]")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Graph server stopped.[/bold yellow]")


@app.command("export", epilog=GRAPH_EXPORT_EPILOG)
def export_graph(
    challenge_path: Path = typer.Argument(..., help="Path to an initialized challenge workspace"),
    format: str = typer.Option("json", "--format", help="Export format"),
):
    challenge_path = resolve_challenge_path(challenge_path)
    output_paths = graph_output_paths(challenge_path)
    if format != "json":
        raise typer.BadParameter("Only JSON export is supported in graph v1.")
    if not output_paths[GRAPH_JSON_FILENAME].exists():
        raise typer.BadParameter("Graph artifacts not built yet. Run 'helm-path graph build' first.")
    payload = {
        GRAPH_JSON_FILENAME: json.loads(output_paths[GRAPH_JSON_FILENAME].read_text(encoding="utf-8")),
        GRAPH_COMMANDS_FILENAME: json.loads(output_paths[GRAPH_COMMANDS_FILENAME].read_text(encoding="utf-8"))
        if output_paths[GRAPH_COMMANDS_FILENAME].exists()
        else {},
        GRAPH_MANIFEST_FILENAME: json.loads(output_paths[GRAPH_MANIFEST_FILENAME].read_text(encoding="utf-8"))
        if output_paths[GRAPH_MANIFEST_FILENAME].exists()
        else {},
    }
    console.print_json(data=payload)
