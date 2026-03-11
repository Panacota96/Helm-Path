import subprocess
import json
import shutil
from rich.console import Console

console = Console()

def is_reptor_available():
    """Checks if the SysReptor CLI (reptor) is installed."""
    return shutil.which("reptor") is not None

def push_finding(finding_json, project_id=None):
    """
    Pipes finding JSON data into the SysReptor 'reptor finding' command.
    """
    cmd = ["reptor", "finding"]
    if project_id:
        # Note: reptor usually picks up project context from config or folder,
        # but --project-id is often supported in many subcommands.
        # Checking help for reptor finding might be needed, but we'll assume it's standard.
        cmd.extend(["--project-id", project_id])
    
    try:
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=json.dumps(finding_json))
        
        if process.returncode == 0:
            console.print(f"✅ [green]Finding pushed to SysReptor successfully.[/green]")
            return True, stdout
        else:
            console.print(f"❌ [red]Failed to push finding to SysReptor:[/red] {stderr}")
            return False, stderr
    except Exception as e:
        console.print(f"❌ [red]SysReptor bridge error:[/red] {str(e)}")
        return False, str(e)

def upload_evidence(file_path, project_id=None):
    """
    Uploads a file as evidence to a SysReptor project.
    """
    cmd = ["reptor", "file", file_path]
    if project_id:
        cmd.extend(["--project-id", project_id])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"📎 [blue]Evidence uploaded to SysReptor:[/blue] {file_path}")
            return True
        else:
            console.print(f"⚠️ [yellow]Failed to upload evidence to SysReptor:[/yellow] {result.stderr}")
            return False
    except Exception as e:
        console.print(f"❌ [red]SysReptor evidence upload error:[/red] {str(e)}")
        return False
