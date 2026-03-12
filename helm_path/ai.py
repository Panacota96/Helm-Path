from __future__ import annotations

import json
from importlib import resources
from typing import Any

from helm_path.constants import PROMPT_VERSION

MAX_CONTEXT_CHARS = 16000
CHUNK_SIZE = 7000


def get_ollama_client():
    try:
        import ollama
    except ImportError as exc:
        raise RuntimeError("The ollama Python package is required for report generation.") from exc
    return ollama


def load_prompt_template() -> str:
    return resources.files("helm_path.prompts").joinpath("ffr_report_prompt.txt").read_text(encoding="utf-8")


def render_report_prompt(challenge_metadata: dict[str, Any], context_text: str) -> str:
    template = load_prompt_template()
    return template.format(
        challenge_metadata=json.dumps(challenge_metadata, indent=2),
        context_text=context_text,
    )


def extract_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[1]
        stripped = stripped.rsplit("```", 1)[0]
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("Model response did not contain a JSON object.")
    return json.loads(stripped[start : end + 1])


def chunk_context(run_contexts: list[dict[str, Any]]) -> list[str]:
    chunks: list[str] = []
    for context in run_contexts:
        run_id = context["manifest"]["run_id"]
        clean_log = context["clean_log"]
        lines = clean_log.splitlines()
        current: list[str] = []
        current_len = 0
        chunk_index = 1
        for line in lines:
            candidate = f"{line}\n"
            if current_len + len(candidate) > CHUNK_SIZE and current:
                header = f"[run:{run_id} chunk:{chunk_index}]\n"
                chunks.append(header + "\n".join(current))
                current = []
                current_len = 0
                chunk_index += 1
            current.append(line)
            current_len += len(candidate)
        if current:
            header = f"[run:{run_id} chunk:{chunk_index}]\n"
            chunks.append(header + "\n".join(current))
    return chunks


def summarize_chunks(ollama_module: Any, model: str, chunks: list[str]) -> str:
    summaries: list[str] = []
    for chunk in chunks:
        response = ollama_module.chat(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "Summarize terminal evidence for a CTF coach. Preserve citations exactly as provided.",
                },
                {
                    "role": "user",
                    "content": (
                        "Summarize the successful path, failed attempts, unique payloads, and evidence.\n"
                        "Use concise bullet points and preserve the citation label from the chunk header.\n\n"
                        f"{chunk}"
                    ),
                },
            ],
            options={"temperature": 0},
        )
        summaries.append(response["message"]["content"].strip())
    return "\n\n".join(summaries)


def build_context(run_contexts: list[dict[str, Any]], model: str) -> str:
    raw_context = []
    for context in run_contexts:
        raw_context.append(
            f"[run:{context['manifest']['run_id']}]\n"
            f"Manifest:\n{json.dumps(context['manifest'], indent=2)}\n"
            f"Clean log:\n{context['clean_log']}"
        )
    joined = "\n\n".join(raw_context)
    if len(joined) <= MAX_CONTEXT_CHARS:
        return joined

    ollama_module = get_ollama_client()
    return summarize_chunks(ollama_module, model, chunk_context(run_contexts))


def generate_report_bundle(challenge_metadata: dict[str, Any], run_contexts: list[dict[str, Any]], model: str) -> dict[str, Any]:
    if not run_contexts:
        raise RuntimeError("No run contexts were provided for report generation.")
    ollama_module = get_ollama_client()
    context_text = build_context(run_contexts, model=model)
    prompt = render_report_prompt(challenge_metadata, context_text)
    response = ollama_module.chat(
        model=model,
        messages=[
            {"role": "system", "content": "You are a senior CTF scribe. Output JSON only."},
            {"role": "user", "content": prompt},
        ],
        options={"temperature": 0},
    )
    payload = extract_json(response["message"]["content"])
    payload["prompt_version"] = PROMPT_VERSION
    return payload
