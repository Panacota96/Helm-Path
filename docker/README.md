# Docker Images

Helm-Path ships two capture images:

- `docker/Dockerfile.lite`
- `docker/Dockerfile.kali`

Both images exist to provide a reproducible shell for CTF work and to capture the terminal session with `script`. They mount the selected challenge workspace at `/workspace` and write raw logs into `sessions/<run-id>/raw.log`.

The images do **not** run Ollama. AI report generation is handled by the host machine after the run completes.

Build manually if needed:

```bash
docker build -t helm-path:lite -f docker/Dockerfile.lite .
docker build -t helm-path:kali -f docker/Dockerfile.kali .
```
