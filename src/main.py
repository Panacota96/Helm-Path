import typer
from rich.console import Console
from rich.panel import Panel
import os
import docker
import time
from datetime import datetime

app = typer.Typer(help="Helm-Path: Dockerized Security Session Orchestrator & AI Report Generator")
console = Console()
client = docker.from_env()

SESSION_DIR = "sessions"

@app.command()
def start(
    image_tag: str = typer.Option("helm-path:kali", help="Custom tag for the Helm image"),
    session_name: str = typer.Option(None, help="Optional name for this session")
):
    """
    Starts a new security session in a Docker container.
    """
    if not session_name:
        session_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    session_path = os.path.abspath(os.path.join(SESSION_DIR, session_name))
    os.makedirs(session_path, exist_ok=True)
    
    try:
        # Check for image
        try:
            client.images.get(image_tag)
            console.print(f"✅ [bold green]Found image:[/bold green] {image_tag}")
        except docker.errors.ImageNotFound:
            console.print(f"🔨 [bold yellow]Image not found. Building '{image_tag}' from Dockerfile...[/bold yellow]")
            client.images.build(path=".", dockerfile="docker/Dockerfile.kali", tag=image_tag)
            console.print(f"✅ [bold green]Image built successfully.[/bold green]")

        console.print(Panel(f"🚀 [bold blue]Starting Helm Session:[/bold blue] {session_name}\n[bold green]Logs mapping:[/bold green] {session_path} -> /helm-path", title="Helm-Path", expand=False))

        # We need to run the container and attach to it. 
        # Using docker-py for interactive shell is tricky. 
        # For a "portable CLI", we'll use a subprocess call to 'docker run' 
        # to ensure the terminal handles the -it (interactive tty) correctly.
        
        import subprocess
        docker_command = [
            "docker", "run", "-it", "--rm",
            "-v", f"{session_path}:/helm-path",
            "--name", session_name,
            image_tag
        ]
        
        console.print("[dim]Attaching to session... Use 'exit' to finish and save the path.[/dim]\n")
        subprocess.run(docker_command)
        
        console.print(f"\n✅ [bold green]Session completed.[/bold green]")
        console.print(f"📄 Raw log saved to: [yellow]{os.path.join(session_path, 'session.log')}[/yellow]")
        console.print(f"👉 Run [bold blue]helm-path report {session_name}[/bold blue] to generate your write-up.")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")

import re
try:
    import ollama
except ImportError:
    ollama = None

def clean_log(log_path):
    """
    Strips ANSI escape codes and other terminal artifacts from the script log.
    """
    if not os.path.exists(log_path):
        return None
    
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    
    # Remove ANSI escape sequences
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', content)
    
    # Remove repeated prompts and noise
    # This is a basic filter; more complex filtering can be added later
    return cleaned

@app.command()
def report(
    session_id: str = typer.Argument(..., help="The session ID to generate a report for"),
    model: str = typer.Option("llama3", help="Local AI model name (requires Ollama)"),
    format: str = typer.Option("markdown", help="Report output format (markdown or pdf)")
):
    """
    Generates an AI-driven report from the specified session logs.
    """
    session_path = os.path.join(SESSION_DIR, session_id)
    log_file = os.path.join(session_path, "session.log")
    
    if not os.path.exists(log_file):
        console.print(f"[bold red]Error:[/bold red] Log file not found for session '{session_id}'.")
        return

    console.print(Panel(f"📝 [bold blue]Scribe Engine:[/bold blue] Generating Report\n[bold green]Session:[/bold green] {session_id}\n[bold yellow]Model:[/bold yellow] {model}", expand=False))

    with console.status("[bold cyan]Cleaning 'The Path' logs...[/bold cyan]"):
        cleaned_logs = clean_log(log_file)
        if not cleaned_logs:
            console.print("[red]Could not read logs.[/red]")
            return

    if not ollama:
        console.print("[bold red]Error:[/bold red] The 'ollama' library is missing. Please run 'pip install ollama'.")
        return

    try:
        with console.status(f"[bold magenta]Querying local AI ({model})...[/bold magenta]"):
            prompt = f"""
            You are an expert CTF Write-up Assistant. 
            Analyze the following terminal session log and generate a professional, academic CTF write-up.
            
            Structure the report as follows:
            1. Table of Contents
            2. Overview (Summary of the session)
            3. Task Sets (Detail each phase: Reconnaissance, Exploitation, Post-Exploitation, etc.)
            4. Conclusion (Final thoughts and lessons learned)
            
            Use clean Markdown formatting. Focus on the commands executed and their outcomes.
            
            LOG DATA:
            {cleaned_logs}
            """
            
            response = ollama.chat(model=model, messages=[
                {'role': 'system', 'content': 'You are a cybersecurity educator specializing in CTF reports.'},
                {'role': 'user', 'content': prompt},
            ])
            
            report_content = response['message']['content']
            
            report_file = os.path.join(session_path, "WRITEUP.md")
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report_content)
                
            console.print(f"\n✅ [bold green]Report generated successfully![/bold green]")
            console.print(f"📖 Write-up saved to: [yellow]{report_file}[/yellow]")
            
            if format == "pdf":
                console.print("[dim]PDF conversion triggered (requires pypandoc/pandoc)...[/dim]")
                # Placeholder for PDF conversion logic

    except Exception as e:
        console.print(f"[bold red]AI Generation Failed:[/bold red] {str(e)}")
        console.print("[dim]Make sure Ollama is running and you have the model downloaded ('ollama pull llama3').[/dim]")

@app.command()
def list_sessions():
    """
    Lists all previous sessions.
    """
    if not os.path.exists(SESSION_DIR):
        console.print("[red]No sessions found.[/red]")
        return
    
    sessions = os.listdir(SESSION_DIR)
    console.print("[bold blue]Available Sessions:[/bold blue]")
    for s in sessions:
        console.print(f" - {s}")

if __name__ == "__main__":
    app()
