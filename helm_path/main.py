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
    image_tag: str = typer.Option("helm-path:kali", help="Tag for the Vigil environment"),
    session_name: str = typer.Option(None, help="Name for this Vigil (session)")
):
    """
    Commences a new Vigil (security session) in the Watcher's Helm.
    """
    if not session_name:
        session_name = f"vigil_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    session_path = os.path.abspath(os.path.join(SESSION_DIR, session_name))
    os.makedirs(session_path, exist_ok=True)
    
    try:
        # Check for image
        try:
            client.images.get(image_tag)
            console.print(f"👁️ [bold blue]The Watcher is ready.[/bold blue]")
        except docker.errors.ImageNotFound:
            console.print(f"🔨 [bold yellow]Forging the Helm... Building '{image_tag}'...[/bold yellow]")
            client.images.build(path=".", dockerfile="docker/Dockerfile.kali", tag=image_tag)
            console.print(f"✅ [bold green]Helm forged successfully.[/bold green]")

        console.print(Panel(
            f"🛡️ [bold yellow]The Vigil Commences:[/bold yellow] {session_name}\n"
            f"📘 [bold cyan]Chronicle mapping:[/bold cyan] {session_path} -> /helm-path", 
            title="[bold blue]Helm-Path: The Watcher's Eye[/bold blue]", 
            expand=False,
            border_style="yellow"
        ))

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
        
        console.print("[dim]Attaching to the Helm... Your path is being recorded. Type 'exit' to finish the vigil.[/dim]\n")
        subprocess.run(docker_command)
        
        console.print(f"\n✅ [bold yellow]The Vigil has concluded.[/bold yellow]")
        console.print(f"📄 [italic]The Watcher's Path[/italic] is preserved at: [yellow]{os.path.join(session_path, 'session.log')}[/yellow]")
        console.print(f"✍️ Run [bold blue]helm-path report {session_name}[/bold blue] to let the Scribe chronicle your journey.")

    except Exception as e:
        console.print(f"[bold red]Desecration (Error):[/bold red] {str(e)}")

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
    session_id: str = typer.Argument(..., help="The Vigil ID to chronicle"),
    model: str = typer.Option("llama3", help="AI Oracle name (Ollama model)"),
    format: str = typer.Option("markdown", help="Chronicle output format")
):
    """
    Summons the Scribe to generate an AI chronicle from the Watcher's Path.
    """
    session_path = os.path.join(SESSION_DIR, session_id)
    log_file = os.path.join(session_path, "session.log")
    
    if not os.path.exists(log_file):
        console.print(f"[bold red]The Path is missing for vigil '{session_id}'.[/bold red]")
        return

    console.print(Panel(
        f"✍️ [bold yellow]Scribe of the Watcher:[/bold yellow] Chronicling Experience\n"
        f"📘 [bold blue]Vigil:[/bold blue] {session_id}\n"
        f"🔮 [bold magenta]Oracle Model:[/bold magenta] {model}", 
        expand=False,
        border_style="blue"
    ))

    with console.status("[bold cyan]Sanitizing the Watcher's Path...[/bold cyan]"):
        cleaned_logs = clean_log(log_file)
        if not cleaned_logs:
            console.print("[red]The Chronicle is unreadable.[/red]")
            return

    if not ollama:
        console.print("[bold red]The Scribe is missing. Run 'pip install ollama'.[/bold red]")
        return

    try:
        with console.status(f"[bold magenta]Consulting the Oracle ({model})...[/bold magenta]"):
            prompt = f"""
            You are the Scribe of the Watcher, inspired by the deity Helm. 
            Analyze the following terminal session log (The Watcher's Path) and generate a professional, academic CTF write-up.
            
            Structure the chronicle with the precision of a master guardian:
            1. Table of Contents
            2. Overview (Summary of the Vigil)
            3. Task Sets (Chronicle each phase: Reconnaissance, Exploitation, Post-Exploitation, etc.)
            4. Conclusion (Final thoughts and lessons of the guard)
            
            Use clean Markdown formatting. Focus on the commands executed and their outcomes.
            Maintain an academic, serious, and vigilant tone.
            
            PATH DATA:
            {cleaned_logs}
            """
            
            response = ollama.chat(model=model, messages=[
                {'role': 'system', 'content': 'You are the Scribe of Helm, chronicling the deeds of security agents with academic precision.'},
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
