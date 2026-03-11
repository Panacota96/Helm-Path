# Helm-Path 🛡️👁️

**Helm-Path** is a security-focused CLI tool inspired by the D&D deity **Helm, the Watcher**. It is designed for those who value vigilance, protection, and the duty of the chronicler. It orchestrates isolated hacking environments (**The Helm**), records the journey of the agent (**The Watcher's Path**), and transforms those logs into professional, AI-generated CTF write-ups (**The Scribe of the Watcher**).

## 🛡️ The Mythology
In the Forgotten Realms, **Helm** is the god of guardians, protection, and vigilance—the "Great Guard" who never sleeps. 
- **The Helm (Vigilance):** Your environment is a fortified tower, isolated and secure.
- **The Path (Duty):** Every command is a step in your vigil, recorded with the precision of a divine sentry.
- **The Scribe (Knowledge):** The Scribe ensures that the lessons of the watch are never forgotten, crafting academic reports from raw experience.

---

## 🛠️ Features
- **The Vigilant Helm:** Spin up customized Kali Linux or Exegol-style containers instantly.
- **The Watcher's Arsenal:** 166+ pre-installed security tools including `nmap`, `metasploit`, `sqlmap`, `ffuf`, `linpeas`, `pspy`, `chisel`, and more.
- **The Watcher's Path (Logging):** Transparent, multi-part command logging using the `script` utility in a `zsh` environment.
- **Scribe Engine (AI):** Uses local LLMs (via Ollama) to chronicle your terminal history into structured reports.
- **Intelligent Summarization:** Automatically handles large logs by chunking and summarizing the journey for the AI.
- **Session State Tracking:** Persistent `metadata.json` tracks vigil duration, completion status, and log parts.
- **Automated Chronicling:** Use the `--auto-report` flag to generate your write-up immediately upon completing a vigil.
- **The Scribe's Sanctuary:** Completed chronicles are automatically preserved in the `writeups/` directory in both Markdown and PDF formats.

---

## 📋 Prerequisites
- **Docker:** Must be installed and running. (WSL 2 supported with Docker Desktop integration).
- **Ollama:** Required for local AI report generation. [Download Ollama](https://ollama.ai/).
- **Pandoc & LaTeX:** Required for PDF generation (e.g., `sudo apt install pandoc texlive-latex-base`).
- **Python 3.10+**

---

## 💻 Installation (The Forging)
To install Helm-Path globally as a standalone application:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/Helm-Path.git
   cd Helm-Path
   ```

2. **Forge and Deploy:**
   ```bash
   make deploy
   ```
   *This will restructure the project, verify dependencies, and install the `helm-path` command globally.*

---

## 🛡️ The Watcher's Workflow

### 1. Commence a Vigil
Launch your environment. Use `--auto-report` to automate the final chronicle.
```bash
helm-path start --session-name "operation_overlord" --auto-report
```
*Upon exiting (`exit`), the Watcher will ask if your vigil is complete.*

### 2. Resume the Watch
If a vigil is not marked as complete, you can return to it later. Helm-Path will link the new logs (`path_part_N.log`) to the existing metadata.

### 3. Summon the Scribe
Generate your academic report at any time. If the vigil is complete, the Scribe will promote the final chronicle to the `writeups/` sanctuary.
```bash
helm-path report "operation_overlord" --format pdf
```

---

## 📂 Project Structure
- `helm_path/`: The core logic of the Watcher.
- `docker/`: The forge where the Helm is shaped (Dockerfile).
- `sessions/`: Raw logs and metadata of every vigil.
- `writeups/`: The final sanctuary for completed chronicles (.md and .pdf).
- `Makefile` & `deploy.sh`: Automation for installation and management.

---

## 🤝 Accessibility & Design
Helm-Path is designed with **Universal Accessibility** in mind:
- **Semantic CLI:** Uses `rich` for high-contrast, text-hierarchical terminal feedback (Gold, Azure, Silver).
- **Navigable Reports:** All generated Markdown follows strict heading hierarchies for screen-reader compatibility.
- **Standardized Environment:** Pre-configured `zsh` with `oh-my-zsh` for robust tab-completion and accessible terminal interaction.

---

## ⚖️ License
MIT License. Created for educational and ethical hacking purposes.
