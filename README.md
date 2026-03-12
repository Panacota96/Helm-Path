# Helm-Path

Helm-Path is a local-first CTF flight recorder. It scaffolds a per-challenge workspace, records terminal sessions inside a Dockerized hacking environment, cleans and hashes the logs, and asks a host-local Ollama model to turn the evidence into structured writeup artifacts.

## Workflow

1. Initialize a challenge workspace.
2. Record one or more runs in the container.
3. Generate report artifacts from a selected run or from all runs.
4. Verify the audit chain, manifests, and generated outputs.

## Challenge Layout

```text
challenges/<competition>/<category>/<challenge>/
├── .metadata.json
├── .gitignore
├── .ffr/
│   └── audit.db
├── artifacts/
├── notes/
│   ├── FAILURES.md
│   └── WORKING_NOTES.md
├── reports/
│   ├── DRAFT_WRITEUP.md
│   ├── FAILURE_ANALYSIS.md
│   ├── PATH_SUMMARY.md
│   ├── payloads.json
│   ├── report_manifest.json
│   └── timeline.json
└── sessions/
    └── <run-id>/
        ├── clean.log
        ├── manifest.json
        └── raw.log
```

## Commands

```bash
helm-path init "HTB Cyber Apocalypse" Web "Flag Command Injection"
helm-path start challenges/htb-cyber-apocalypse/web/flag-command-injection --lite
helm-path report challenges/htb-cyber-apocalypse/web/flag-command-injection --all-runs
helm-path verify challenges/htb-cyber-apocalypse/web/flag-command-injection
helm-path doctor
```

## Requirements

- Docker Desktop with Linux containers enabled
- Python 3.10+
- Host-local Ollama installation with a lightweight model such as `llama3.2:3b`
- Optional: Pandoc and a PDF engine for `--format pdf`

The Docker images are for terminal capture only. AI generation now runs on the host.

## Notes

- `report` defaults to the latest run unless `--all-runs` or `--run-id` is provided.
- `verify` checks the append-only audit chain, log hashes, and report output hashes.
- PDF export is best-effort and does not block the Markdown workflow.

## CI/CD

- `CI` runs on every push and pull request.
- It installs the package, compiles the code, runs the test suite, checks the CLI help output, validates challenge workspace scaffolding, and builds the lite Docker image.
- `Release` runs on tags matching `v*` and on manual dispatch.
- It builds Python distribution artifacts, uploads them to the GitHub release, and publishes `helm-path-lite` and `helm-path-kali` images to GitHub Container Registry.

## Support

Support the project: [buymeacoffee.com/santiagogow](https://buymeacoffee.com/santiagogow)
