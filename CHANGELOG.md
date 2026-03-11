# Changelog 📜🛡️

All notable changes to the **Helm-Path** project will be documented in this file.

## [0.1.0] - 2026-03-10

### ✨ Added (Lore & Identity)
- **Mythology Integration:** Rebranded the project under the D&D mythology of **Helm, the Watcher**.
- **The Vigil:** Terminal sessions are now termed "Vigils."
- **The Watcher's Path:** Refined terminology for session logging.
- **The Scribe of the Watcher:** AI-driven report generation engine.

### 🛡️ Added (The Watcher's Arsenal)
- **Comprehensive Toolset:** Updated `Dockerfile.kali` with 166+ pre-installed security tools (`nmap`, `metasploit`, `sqlmap`, `ffuf`, etc.).
- **Interactive Interface:** Integrated `zsh` and `oh-my-zsh` for advanced tab-completion and terminal accessibility.
- **Specialized Tooling:** Automated installation of `netexec`, `arjun`, `linpeas`, `pspy`, `chisel`, `SecretFinder`, and `Responder`.

### 🧠 Added (AI & Intelligence)
- **Intelligent Summarization:** Implemented chunking and summarization for large session logs.
- **Noise Filtering:** Advanced log cleaning to remove terminal escape codes and redundant command output.
- **PDF Export:** Support for generating professional PDF chronicles via `pypandoc`.

### ⚙️ Added (Orchestration & Automation)
- **Session State Management:** Persistent `metadata.json` for tracking vigil duration, multi-part logs, and completion status.
- **Multi-Part Logging:** Support for resuming vigils with linked log parts.
- **Automated Chronicling:** Added `--auto-report` flag to trigger AI generation upon vigil completion.
- **Promotion to Sanctuary:** Completed reports are automatically saved in the root-level `writeups/` directory.

### 🏗️ Added (Deployment)
- **Installation Framework:** Added `Makefile` and `deploy.sh` for one-command installation and environment preparation.
- **src-layout Migration:** Moved to a modern Python package structure for robust installation.

### 🛠️ Fixed
- Resolved `ModuleNotFoundError` during installation by implementing `src-layout`.
- Fixed Docker volume mounting and path handling for WSL/Kali environments.
- Corrected `pyproject.toml` package discovery rules.

### 🤝 Accessibility
- Implemented **High-Contrast CLI Theming** using the `rich` library (Gold, Azure, Silver).
- Enforced **Semantic Markdown** structures in AI-generated reports for screen-reader compatibility.
- Added **Interactive Exit Dialogues** for clear workflow transitions.
