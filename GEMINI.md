# Helm-Path

**Helm-Path** is a security-focused CLI tool inspired by the D&D deity Helm. It orchestrates isolated hacking environments (Docker), records terminal sessions, and uses local LLMs (Ollama) to automatically generate professional CTF write-ups.

## Project Overview

- **Language:** Python 3.10+
- **Core Frameworks:** `typer` (CLI), `docker` (SDK), `rich` (UI), `ollama` (AI).
- **Purpose:** Automate the setup of Kali/Exegol-style containers and the documentation of security assessments.

## Building and Installation

This project uses a `Makefile` and `deploy.sh` to handle installation and directory restructuring (moving source to a `src/` layout).

### Prerequisites
- **Docker:** Must be running.
- **Ollama:** Required for AI report generation.
- **Pandoc & LaTeX:** Required for PDF report generation.
- **Python 3.10+**
### Installation Command
To install the tool globally (and restructure the project to use a `src` layout):

```bash
make deploy
```

## 🔇 Offline Reproducibility
Helm-Path can be deployed in air-gapped environments by pre-caching assets:
1. **Docker:** Use `docker save helm-path:lite > lite.tar` and `docker load` on the target.
2. **Ollama:** Copy the `~/.ollama/models` folder to the target machine.
3. **Python:** Use `pip download -r requirements.txt -d wheels` to bundle dependencies.

## Key Commands

The `Makefile` provides shortcuts for common `helm-path` operations:

| Task | Command | Description |
| :--- | :--- | :--- |
| **Start Session** | `make vigil name=<session_name>` | Spins up the Docker container and starts logging. |
| **Start (No Audit)**| `helm-path start --no-record` | Spins up the container without recording logs (Practice Mode). |
| **Generate Report** | `make chronicle id=<session_name>` | Uses AI to generate a write-up from logs. |
| **Verify Integrity**| `helm-path verify <session_name>` | Checks if session logs have been tampered with using SHA-256 hashes. |
| **List Sessions** | `make list-vigils` | Shows all past sessions and their status. |
| **Clean Build** | `make clean` | Removes build artifacts. |

## Development & Architecture

### Directory Structure
- **`helm_path/` (or `src/helm_path/`)**: Main application logic.
    - `main.py`: Entry point using `typer`. Handles Docker interactions, logging, and Ollama calls.
- **`docker/`**: Contains `Dockerfile.kali` for building the hacking environment.
- **`sessions/`**: Stores raw logs (`path_part_N.log`) and metadata (`metadata.json`) for each session.
- **`writeups/`**: Output directory for generated Markdown and PDF reports.

### Key Features
- **The Watcher:** A Docker container with security tools (`nmap`, `metasploit`, etc.).
- **The Path:** Session logging via `script` and `zsh`.
- **The Scribe:** AI-powered reporting using `ollama`. It chunks large logs to fit context windows.

### Conventions
- **CLI Style:** Uses `rich` for colored, semantic output.
- **AI Integration:** Fails gracefully if `ollama` is not present, but required for core reporting features.
- **State Management:** Session state is tracked in `sessions/<id>/metadata.json`.
