import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
import os
import time
import json
import re
import subprocess
import hashlib
from datetime import datetime

# Heavy imports deferred for speed
docker = None
pypandoc = None
ollama = None

app = typer.Typer(help="Helm-Path: Dockerized Security Session Orchestrator & AI Report Generator")
console = Console()

SESSION_DIR = "sessions"
WRITEUPS_DIR = "writeups"
VERBOSE_MODE = False

def get_docker_client():
    global docker
    if docker is None:
        import docker as docker_module
        docker = docker_module
    try:
        return docker.from_env()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Could not connect to Docker. Is it running? ({str(e)})")
        raise typer.Exit(1)

def get_ollama():
    global ollama
    if ollama is None:
        try:
            import ollama as ollama_module
            ollama = ollama_module
        except ImportError:
            return None
    return ollama

def get_pypandoc():
    global pypandoc
    if pypandoc is None:
        import pypandoc as pypandoc_module
        pypandoc = pypandoc_module
    return pypandoc

@app.callback()
def main_callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging")
):
    """Global configuration for Helm-Path."""
    global VERBOSE_MODE
    VERBOSE_MODE = verbose
    if VERBOSE_MODE:
        console.print("[dim]🔍 Verbose mode enabled. The Watcher's eye is wider.[/dim]")

def load_metadata(session_path):
    meta_file = os.path.join(session_path, "metadata.json")
    if os.path.exists(meta_file):
        with open(meta_file, "r") as f:
            return json.load(f)
    return {
        "session_id": os.path.basename(session_path),
        "is_complete": False,
        "logs": [],
        "created_at": datetime.now().isoformat(),
        "total_vigils": 0
    }

def save_metadata(session_path, metadata):
    meta_file = os.path.join(session_path, "metadata.json")
    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=4)

def calculate_file_hash(filepath):
    """Calculates SHA-256 hash of a file."""
    if not os.path.exists(filepath):
        return None
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def clean_sensitive_data(content):
    """Redacts sensitive information from logs."""
    patterns = [
        (r'password\s*=\s*[\S]+', 'password=[REDACTED]'),
        (r'API_KEY\s*=\s*[\S]+', 'API_KEY=[REDACTED]'),
        (r'Authorization:\s*Bearer\s*[\S]+', 'Authorization: Bearer [REDACTED]'),
        (r'--password\s+[\S]+', '--password [REDACTED]'),
        (r'-p\s+[\S]+', '-p [REDACTED]'), 
    ]
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
    return content

def clean_log(log_path):
    """
    Strips ANSI escape codes and filters out terminal noise.
    """
    if not os.path.exists(log_path):
        return None
    
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    
    # Remove ANSI escape sequences
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', content)
    
    # Filter out common noise to save tokens
    noise_patterns = [
        r'^# clear\n',             # Clear command
        r'^# ls\s*$',              # Empty ls
        r'^# cd \.\.\n',           # Simple cd up
        r'^\s*$',                  # Empty lines
    ]
    
    lines = cleaned.splitlines()
    filtered_lines = []
    for line in lines:
        if not any(re.match(p, line) for p in noise_patterns):
            filtered_lines.append(line)
            
    return "\n".join(filtered_lines)

def summarize_path_if_needed(log_content, model="llama3", max_chars=12000):
    """
    If the path is too long for the Oracle's eye, we summarize it in chunks.
    """
    oracle = get_ollama()
    if not oracle:
        return log_content

    if len(log_content) < max_chars:
        return log_content

    console.print(f"🕯️  [italic]The Path is long. The Scribe is summarizing the journey...[/italic]")
    
    # Split into chunks of ~10k chars
    chunks = [log_content[i:i+max_chars] for i in range(0, len(log_content), max_chars)]
    summaries = []
    
    for i, chunk in enumerate(chunks):
        with console.status(f"[bold magenta]Oracle Summarizing Part {i+1}/{len(chunks)}...[/bold magenta]"):
            summary_prompt = f"Summarize the following terminal log chunk, focusing on successful commands and key findings for a CTF write-up:\n\n{chunk}"
            response = oracle.chat(model=model, messages=[{'role': 'user', 'content': summary_prompt}])
            summaries.append(response['message']['content'])
            
    return "\n\n--- CHRONICLE SUMMARY ---\n\n" + "\n\n".join(summaries)

@app.command()
def start(
    image_tag: str = typer.Option(None, help="Tag for the Vigil environment"),
    session_name: str = typer.Option(None, help="Name for this Vigil (session)"),
    auto_report: bool = typer.Option(False, "--auto-report", help="Automatically summon the Scribe upon completion"),
    no_record: bool = typer.Option(False, "--no-record", help="Disable session recording (Audit logs will not be generated)"),
    lite: bool = typer.Option(False, "--lite", help="Use a lightweight environment (fewer tools, faster start)")
):
    """
    Commences a new Vigil (security session) in the Watcher's Helm.
    """
    client = get_docker_client()
    
    # Set default image tags based on lite mode
    if not image_tag:
        image_tag = "helm-path:lite" if lite else "helm-path:kali"
    
    dockerfile = "docker/Dockerfile.lite" if lite else "docker/Dockerfile.kali"
    
    if not session_name:
        session_name = f"vigil_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    session_path = os.path.abspath(os.path.join(SESSION_DIR, session_name))
    os.makedirs(session_path, exist_ok=True)
    
    metadata = load_metadata(session_path)
    if metadata["is_complete"]:
        console.print(f"[bold yellow]⚠️ This vigil was previously marked as complete.[/bold yellow]")
        if not Confirm.ask("Do you wish to reopen this chronicle and add more to your path?"):
            return

    try:
        # Check for image
        try:
            client.images.get(image_tag)
            if VERBOSE_MODE:
                console.print(f"👁️ [dim]Image '{image_tag}' found locally.[/dim]")
        except docker.errors.ImageNotFound:
            if not os.path.exists(dockerfile):
                 # Fallback to standard if lite is missing but requested
                 if lite:
                     console.print("⚠️ [yellow]Lite Dockerfile not found. Falling back to Kali standard...[/yellow]")
                     dockerfile = "docker/Dockerfile.kali"
                     image_tag = "helm-path:kali"
            
            console.print(f"🔨 [bold yellow]Forging the Helm... Building '{image_tag}'...[/bold yellow]")
            client.images.build(path=".", dockerfile=dockerfile, tag=image_tag)
            console.print(f"✅ [bold green]Helm forged successfully.[/bold green]")

        # Prepare unique log for this part
        metadata["total_vigils"] += 1
        part_num = metadata["total_vigils"]
        log_filename = f"path_part_{part_num}.log"
        start_time = datetime.now().isoformat()
        
        console.print(Panel(
            f"🛡️ [bold yellow]The Vigil Commences:[/bold yellow] {session_name} (Part {part_num})\n"
            f"📘 [bold cyan]Chronicle mapping:[/bold cyan] {session_path} -> /helm-path", 
            title=f"[bold blue]Helm-Path: {'Lite' if lite else 'Full'} Vigil[/bold blue]", 
            expand=False,
            border_style="yellow"
        ))

        env_vars = {f"LOG_FILE": log_filename}
        if no_record:
            env_vars["SCRIPT_LOGGED"] = "1" # Bypass script recording in .zshrc
            console.print("[bold red]⚠️  RECORDING DISABLED: This session will not be chronicled.[/bold red]")
        else:
            console.print("[bold green]🔴 RECORDING ACTIVE: All terminal output is being logged for the chronicle.[/bold green]")
            console.print("[dim]Type 'exit' to finish the vigil.[/dim]\n")

        docker_command = [
            "docker", "run", "-it", "--rm",
            "-v", f"{session_path}:/helm-path",
            "--name", f"{session_name}_part_{part_num}",
            image_tag
        ]
        
        # Add env vars to command
        for k, v in env_vars.items():
            docker_command.insert(2, "-e")
            docker_command.insert(3, f"{k}={v}")

        subprocess.run(docker_command)
        
        end_time = datetime.now().isoformat()
        
        # Log this part in metadata
        log_entry = {
            "file": log_filename,
            "start_time": start_time,
            "end_time": end_time
        }

        if not no_record:
            full_log_path = os.path.join(session_path, log_filename)
            file_hash = calculate_file_hash(full_log_path)
            if file_hash:
                log_entry["integrity_hash"] = file_hash
                if VERBOSE_MODE:
                    console.print(f"🔒 [dim]Log Integrity Hash:[/dim] {file_hash}")
        
        metadata["logs"].append(log_entry)
        
        console.print(f"\n✅ [bold yellow]The current vigil has paused.[/bold yellow]")
        
        # Ask if complete
        is_complete = Confirm.ask("Is this vigil complete? (If yes, the Scribe can now create the final chronicle)")
        if is_complete:
            metadata["is_complete"] = True
            console.print(f"🛡️ [bold green]The Chronicle of {session_name} is marked as complete.[/bold green]")
        else:
            metadata["is_complete"] = False
            console.print(f"👁️ [bold blue]The Watcher remains vigilant. The path will continue later.[/bold blue]")

        save_metadata(session_path, metadata)
        
        if is_complete and auto_report and not no_record:
            console.print(f"📜 [bold cyan]Auto-Report active. Summoning the Scribe...[/bold cyan]")
            # Direct call to the report logic
            report(session_id=session_name)
        elif no_record and auto_report:
             console.print(f"⚠️ [bold yellow]Auto-Report skipped: Recording was disabled.[/bold yellow]")
        else:
            console.print(f"✍️ Run [bold blue]helm-path report {session_name}[/bold blue] whenever you are ready.")

    except Exception as e:
        console.print(f"[bold red]Desecration (Error):[/bold red] {str(e)}")

@app.command()
def verify(session_id: str):
    """
    Verifies the integrity of the session logs using stored SHA-256 hashes.
    """
    session_path = os.path.join(SESSION_DIR, session_id)
    if not os.path.exists(session_path):
        console.print(f"[bold red]Error:[/bold red] Vigil '{session_id}' not found.")
        return

    metadata = load_metadata(session_path)
    console.print(f"🔍 Verifying integrity for Vigil: [bold]{session_id}[/bold]")

    all_valid = True
    for log in metadata["logs"]:
        if "integrity_hash" in log:
            log_path = os.path.join(session_path, log["file"])
            current_hash = calculate_file_hash(log_path)
            
            if current_hash == log["integrity_hash"]:
                console.print(f"  ✅ {log['file']}: [green]VERIFIED[/green]")
            else:
                console.print(f"  ❌ {log['file']}: [bold red]MODIFIED[/bold red] (Expected {log['integrity_hash'][:8]}..., got {current_hash[:8]}...)")
                all_valid = False
        else:
            console.print(f"  ⚠️ {log['file']}: [yellow]NO HASH FOUND[/yellow] (Legacy log?)")
    
    if all_valid:
        console.print("\n🛡️  [bold green]Integrity Check Passed: The Chronicle is untainted.[/bold green]")
    else:
        console.print("\n🚨 [bold red]Integrity Check Failed: Some logs have been altered![/bold red]")

@app.command()
def report(
    session_id: str = typer.Argument(..., help="The Vigil ID to chronicle"),
    model: str = typer.Option("llama3", help="AI Oracle name (Ollama model)"),
    format: str = typer.Option("markdown", help="Chronicle output format (markdown or pdf)")
):
    """
    Summons the Scribe to generate an AI chronicle from the Watcher's Path.
    """
    oracle = get_ollama()
    if not oracle:
        console.print("[bold red]The Scribe is missing. Run 'pip install ollama'.[/bold red]")
        return

    session_path = os.path.join(SESSION_DIR, session_id)
    if not os.path.exists(session_path):
        console.print(f"[bold red]Error:[/bold red] Vigil '{session_id}' not found.")
        return

    metadata = load_metadata(session_path)
    
    if not metadata["logs"]:
        console.print(f"[bold red]The Path is empty for vigil '{session_id}'.[/bold red]")
        return

    console.print(Panel(
        f"✍️ [bold yellow]Scribe of the Watcher:[/bold yellow] Chronicling Experience\n"
        f"📘 [bold blue]Vigil:[/bold blue] {session_id}\n"
        f"🔮 [bold magenta]Oracle Model:[/bold magenta] {model}", 
        expand=False,
        border_style="blue"
    ))

    all_logs_content = ""
    with console.status("[bold cyan]Sanitizing the Watcher's Path...[/bold cyan]"):
        for log_entry in metadata["logs"]:
            log_file = os.path.join(session_path, log_entry["file"])
            cleaned = clean_log(log_file)
            if cleaned:
                # Apply redaction
                cleaned = clean_sensitive_data(cleaned)
                all_logs_content += f"\n--- VIGIL START: {log_entry['start_time']} ---\n"
                all_logs_content += cleaned
                all_logs_content += f"\n--- VIGIL END: {log_entry['end_time']} ---\n"

    if not all_logs_content:
        console.print("[red]The Chronicle is unreadable or empty.[/red]")
        return

    try:
        # Handle large logs with summarization
        processed_path = summarize_path_if_needed(all_logs_content, model=model)

        with console.status(f"[bold magenta]Consulting the Oracle ({model})...[/bold magenta]"):
            prompt = f"""
            You are the Scribe of the Watcher, inspired by the deity Helm. 
            Analyze the following terminal session logs (The Watcher's Path) and generate a professional, academic CTF write-up.
            
            Structure the chronicle with the precision of a master guardian:
            1. Table of Contents
            2. Overview (Summary of the Vigil)
            3. Task Sets (Chronicle each phase: Reconnaissance, Exploitation, Post-Exploitation, etc.)
            4. Conclusion (Final thoughts and lessons of the guard)
            
            Use clean Markdown formatting. Focus on the commands executed and their outcomes.
            Maintain an academic, serious, and vigilant tone.
            
            VIGIL METADATA:
            - Session ID: {metadata['session_id']}
            - Total Vigils: {metadata['total_vigils']}
            - Created At: {metadata['created_at']}
            
            PATH DATA:
            {processed_path}
            """
            
            response = oracle.chat(model=model, messages=[
                {'role': 'system', 'content': 'You are the Scribe of Helm, chronicling the deeds of security agents with academic precision.'},
                {'role': 'user', 'content': prompt},
            ])
            
            report_content = response['message']['content']
            
            # Save to session dir
            report_file = os.path.join(session_path, "WRITEUP.md")
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report_content)
                
            console.print(f"\n✅ [bold green]Chronicle created in session directory![/bold green]")
            
            # Promotion to global writeups
            if metadata["is_complete"]:
                os.makedirs(WRITEUPS_DIR, exist_ok=True)
                global_report_file = os.path.join(WRITEUPS_DIR, f"{session_id}_WRITEUP.md")
                with open(global_report_file, "w", encoding="utf-8") as f:
                    f.write(report_content)
                
                if format == "pdf":
                    try:
                        pandoc = get_pypandoc()
                        with console.status("[bold blue]Forging the PDF Chronicle...[/bold blue]"):
                            pdf_file = os.path.join(WRITEUPS_DIR, f"{session_id}_WRITEUP.pdf")
                            pandoc.convert_text(report_content, 'pdf', format='md', outputfile=pdf_file)
                            console.print(f"📜 [bold yellow]PDF Chronicled at:[/bold yellow] [yellow]{pdf_file}[/yellow]")
                    except Exception as pdf_err:
                        console.print(f"[bold red]PDF Forging Failed:[/bold red] {str(pdf_err)}")
                        console.print("[dim]Ensure 'pandoc' and a LaTeX engine like 'pdflatex' are installed on your system.[/dim]")

                console.print(f"🏆 [bold yellow]Vigil Complete! Final chronicle preserved at:[/bold yellow] [yellow]{global_report_file}[/yellow]")
            else:
                console.print(f"📖 Partial chronicle preserved at: [yellow]{report_file}[/yellow]")

    except Exception as e:
        console.print(f"[bold red]AI Generation Failed:[/bold red] {str(e)}")

@app.command()
def list_sessions():
    """
    Lists all previous sessions and their status.
    """
    if not os.path.exists(SESSION_DIR):
        console.print("[red]No sessions found.[/red]")
        return
    
    sessions = os.listdir(SESSION_DIR)
    console.print("[bold blue]The Watcher's Archive:[/bold blue]")
    for s in sessions:
        s_path = os.path.join(SESSION_DIR, s)
        if os.path.isdir(s_path):
            metadata = load_metadata(s_path)
            status = "[green]Complete[/green]" if metadata["is_complete"] else "[yellow]In Progress[/yellow]"
            console.print(f" - {s} ({status}) | Vigils: {metadata['total_vigils']}")

if __name__ == "__main__":
    app()

@app.command()
def verify(session_id: str):
    """
    Verifies the integrity of the session logs using stored SHA-256 hashes.
    """
    session_path = os.path.join(SESSION_DIR, session_id)
    if not os.path.exists(session_path):
        console.print(f"[bold red]Error:[/bold red] Vigil '{session_id}' not found.")
        return

    metadata = load_metadata(session_path)
    console.print(f"🔍 Verifying integrity for Vigil: [bold]{session_id}[/bold]")

    all_valid = True
    for log in metadata["logs"]:
        if "integrity_hash" in log:
            log_path = os.path.join(session_path, log["file"])
            current_hash = calculate_file_hash(log_path)
            
            if current_hash == log["integrity_hash"]:
                console.print(f"  ✅ {log['file']}: [green]VERIFIED[/green]")
            else:
                console.print(f"  ❌ {log['file']}: [bold red]MODIFIED[/bold red] (Expected {log['integrity_hash'][:8]}..., got {current_hash[:8]}...)")
                all_valid = False
        else:
            console.print(f"  ⚠️ {log['file']}: [yellow]NO HASH FOUND[/yellow] (Legacy log?)")
    
    if all_valid:
        console.print("\n🛡️  [bold green]Integrity Check Passed: The Chronicle is untainted.[/bold green]")
    else:
        console.print("\n🚨 [bold red]Integrity Check Failed: Some logs have been altered![/bold red]")

@app.command()
def report(
    session_id: str = typer.Argument(..., help="The Vigil ID to chronicle"),
    model: str = typer.Option("llama3", help="AI Oracle name (Ollama model)"),
    format: str = typer.Option("markdown", help="Chronicle output format (markdown or pdf)")
):
    """
    Summons the Scribe to generate an AI chronicle from the Watcher's Path.
    """
    session_path = os.path.join(SESSION_DIR, session_id)
    if not os.path.exists(session_path):
        console.print(f"[bold red]Error:[/bold red] Vigil '{session_id}' not found.")
        return

    metadata = load_metadata(session_path)
    
    if not metadata["logs"]:
        console.print(f"[bold red]The Path is empty for vigil '{session_id}'.[/bold red]")
        return

    console.print(Panel(
        f"✍️ [bold yellow]Scribe of the Watcher:[/bold yellow] Chronicling Experience\n"
        f"📘 [bold blue]Vigil:[/bold blue] {session_id}\n"
        f"🔮 [bold magenta]Oracle Model:[/bold magenta] {model}", 
        expand=False,
        border_style="blue"
    ))

    all_logs_content = ""
    with console.status("[bold cyan]Sanitizing the Watcher's Path...[/bold cyan]"):
        for log_entry in metadata["logs"]:
            log_file = os.path.join(session_path, log_entry["file"])
            cleaned = clean_log(log_file)
            if cleaned:
                # Apply redaction
                cleaned = clean_sensitive_data(cleaned)
                all_logs_content += f"\n--- VIGIL START: {log_entry['start_time']} ---\n"
                all_logs_content += cleaned
                all_logs_content += f"\n--- VIGIL END: {log_entry['end_time']} ---\n"

    if not all_logs_content:
        console.print("[red]The Chronicle is unreadable or empty.[/red]")
        return

    if not ollama:
        console.print("[bold red]The Scribe is missing. Run 'pip install ollama'.[/bold red]")
        return

    try:
        # Handle large logs with summarization
        processed_path = summarize_path_if_needed(all_logs_content, model=model)

        with console.status(f"[bold magenta]Consulting the Oracle ({model})...[/bold magenta]"):
            prompt = f"""
            You are the Scribe of the Watcher, inspired by the deity Helm. 
            Analyze the following terminal session logs (The Watcher's Path) and generate a professional, academic CTF write-up.
            
            Structure the chronicle with the precision of a master guardian:
            1. Table of Contents
            2. Overview (Summary of the Vigil)
            3. Task Sets (Chronicle each phase: Reconnaissance, Exploitation, Post-Exploitation, etc.)
            4. Conclusion (Final thoughts and lessons of the guard)
            
            Use clean Markdown formatting. Focus on the commands executed and their outcomes.
            Maintain an academic, serious, and vigilant tone.
            
            VIGIL METADATA:
            - Session ID: {metadata['session_id']}
            - Total Vigils: {metadata['total_vigils']}
            - Created At: {metadata['created_at']}
            
            PATH DATA:
            {processed_path}
            """
            
            response = ollama.chat(model=model, messages=[
                {'role': 'system', 'content': 'You are the Scribe of Helm, chronicling the deeds of security agents with academic precision.'},
                {'role': 'user', 'content': prompt},
            ])
            
            report_content = response['message']['content']
            
            # Save to session dir
            report_file = os.path.join(session_path, "WRITEUP.md")
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report_content)
                
            console.print(f"\n✅ [bold green]Chronicle created in session directory![/bold green]")
            
            # Promotion to global writeups
            if metadata["is_complete"]:
                os.makedirs(WRITEUPS_DIR, exist_ok=True)
                global_report_file = os.path.join(WRITEUPS_DIR, f"{session_id}_WRITEUP.md")
                with open(global_report_file, "w", encoding="utf-8") as f:
                    f.write(report_content)
                
                if format == "pdf":
                    try:
                        with console.status("[bold blue]Forging the PDF Chronicle...[/bold blue]"):
                            pdf_file = os.path.join(WRITEUPS_DIR, f"{session_id}_WRITEUP.pdf")
                            pypandoc.convert_text(report_content, 'pdf', format='md', outputfile=pdf_file)
                            console.print(f"📜 [bold yellow]PDF Chronicled at:[/bold yellow] [yellow]{pdf_file}[/yellow]")
                    except Exception as pdf_err:
                        console.print(f"[bold red]PDF Forging Failed:[/bold red] {str(pdf_err)}")
                        console.print("[dim]Ensure 'pandoc' and a LaTeX engine like 'pdflatex' are installed on your system.[/dim]")

                console.print(f"🏆 [bold yellow]Vigil Complete! Final chronicle preserved at:[/bold yellow] [yellow]{global_report_file}[/yellow]")
            else:
                console.print(f"📖 Partial chronicle preserved at: [yellow]{report_file}[/yellow]")

    except Exception as e:
        console.print(f"[bold red]AI Generation Failed:[/bold red] {str(e)}")

@app.command()
def list_sessions():
    """
    Lists all previous sessions and their status.
    """
    if not os.path.exists(SESSION_DIR):
        console.print("[red]No sessions found.[/red]")
        return
    
    sessions = os.listdir(SESSION_DIR)
    console.print("[bold blue]The Watcher's Archive:[/bold blue]")
    for s in sessions:
        s_path = os.path.join(SESSION_DIR, s)
        if os.path.isdir(s_path):
            metadata = load_metadata(s_path)
            status = "[green]Complete[/green]" if metadata["is_complete"] else "[yellow]In Progress[/yellow]"
            console.print(f" - {s} ({status}) | Vigils: {metadata['total_vigils']}")

if __name__ == "__main__":
    app()
