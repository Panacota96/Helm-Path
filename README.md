# Helm-Path 🚢🛠️

**Helm-Path** is a security-focused CLI tool that orchestrates Dockerized hacking environments ("The Helm"), captures every step of your execution ("The Path"), and transforms those logs into professional, AI-generated CTF write-ups ("The Write-up").

## 🚀 Vision
Built for CTF agents and cybersecurity educators, Helm-Path automates the tedious parts of documentation. By using a local AI model, it ensures that your sensitive exploitation logs stay on your machine while producing high-quality, academic-style reports.

---

## 🛠️ Features
- **Isolated Helm:** Spin up customized Kali Linux or Exegol-style containers instantly.
- **The Path (Logging):** Transparent, real-time command logging using the `script` utility.
- **Scribe Engine (AI):** Uses local LLMs (via Ollama) to analyze terminal history and generate structured reports.
- **Academic Structure:** Automatically generates Table of Contents, Overview, Task-by-Task breakdowns, and Conclusions.

---

## 📋 Prerequisites
- **Docker:** Must be installed and running.
- **Ollama:** Required for local AI report generation. [Download Ollama](https://ollama.ai/).
- **Python 3.10+**

---

## 💻 Installation as an App (Recommended)
To install Helm-Path globally as a standalone application in your Kali or WSL environment:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/Helm-Path.git
   cd Helm-Path
   ```

2. **Install globally:**
   ```bash
   pip install .
   ```
   *Now you can run the `helm-path` command from anywhere in your terminal.*

---

## 🐧 WSL Support (Windows Subsystem for Linux)
Helm-Path is fully compatible with WSL 2. To use it in a WSL environment:
1. **Docker Integration:** Ensure "WSL Integration" is enabled in your **Docker Desktop** settings (Settings > Resources > WSL Integration).
2. **Environment:** Run all commands natively within your WSL terminal (e.g., Ubuntu, Kali-WSL).
3. **Paths:** Volume mounting automatically handles the transition between Windows and Linux file systems.

---

## 🚀 Quick Start

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start a Session:**
   ```bash
   python src/main.py start --session-name "hackthebox_machine"
   ```
   *This will build/run the Kali environment and drop you into a shell. Every command you run will be recorded.*

3. **Complete Your Work:**
   Once you've finished the machine, simply type `exit`.

4. **Generate the Report:**
   ```bash
   # Ensure Ollama is running and you have a model (e.g., llama3)
   ollama pull llama3
   python src/main.py report "hackthebox_machine" --model llama3
   ```

---

## 🧠 Brainstorming: The Future of Helm-Path

### 1. **Multi-Image Support**
- Add flags for `--exegol` to pull specific Exegol wrappers.
- Support for Alpine-based "Micro-Helms" for lightweight reconnaissance.

### 2. **Context-Aware Logging**
- **Network Capture:** Automatically start a `tcpdump` session that saves to the session folder. The AI can then analyze `.pcap` data for the report.
- **Teaching Moments:** Use a special prefix (e.g., `#! NOTE: This is for privilege escalation`) that the AI prioritizes as an educational highlight.

### 3. **Visual Scribe**
- Integrate a headless browser or X11 forwarding to capture screenshots of web-based exploits (like Burp Suite or browser-based bypasses).

### 4. **GitHub Automator**
- A `helm-path push` command that automatically formats the `WRITEUP.md` and pushes it to your "Public Write-ups" repository with appropriate tags.

---

## 🤝 Accessibility & Design
Helm-Path is designed with **Universal Accessibility** in mind:
- **Semantic CLI:** Uses `rich` for high-contrast, text-hierarchical terminal feedback.
- **Navigable Reports:** All generated Markdown follows strict heading hierarchies for screen-reader compatibility.
- **Text-First Design:** Avoids reliance on color-only status indicators.

---

## ⚖️ License
MIT License. Created for educational and ethical hacking purposes.
