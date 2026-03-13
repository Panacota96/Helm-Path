from __future__ import annotations

import json
import ipaddress
import re
import shlex
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from helm_path.constants import (
    COMMAND_MARKER_END,
    COMMAND_MARKER_START,
    GRAPH_COMMANDS_FILENAME,
    GRAPH_HTML_FILENAME,
    GRAPH_JSON_FILENAME,
    GRAPH_MANIFEST_FILENAME,
    GRAPH_PROMPT_VERSION,
)
from helm_path.processing import calculate_file_hash, clean_sensitive_data, normalize_log_content, write_json_file
from helm_path.workspace import graph_output_paths, list_run_directories, load_manifest, resolve_challenge_path, run_file_paths

from helm_path.graph.models import CommandRecord, DiscoveryGraphBuilder, ParserResult

NMAP_HOST_RE = re.compile(r"^Nmap scan report for (?:(?P<hostname>[^\s(]+) \()?(?P<ip>[0-9a-fA-F:\.]+)\)?$")
NMAP_PORT_RE = re.compile(r"^(?P<port>\d+)\/(?P<proto>\w+)\s+open\s+(?P<service>\S+)(?:\s+(?P<rest>.+))?$")
WHATWEB_TOKEN_RE = re.compile(r"([A-Za-z0-9_-]+)\[([^\]]+)\]")
START_MARKER_RE = re.compile(rf"^{re.escape(COMMAND_MARKER_START)}::(?P<command_id>[^\s]+)\s*$")
END_MARKER_RE = re.compile(rf"^{re.escape(COMMAND_MARKER_END)}::(?P<command_id>[^\s:]+)::(?P<exit_code>-?\d+)\s*$")
VERSION_TOKEN_RE = re.compile(r"^\d[\w\.\-_:]*$")
SSH_PRODUCT_RE = re.compile(r"(OpenSSH)[_ /-]?([0-9][\w\.\-p]+)")


def select_run_dirs(challenge_path: Path, run_id: str | None, all_runs: bool) -> list[Path]:
    runs = list_run_directories(challenge_path)
    if not runs:
        raise ValueError("No recorded runs found in this challenge workspace.")
    if run_id:
        target = challenge_path / "sessions" / run_id
        if not target.exists():
            raise ValueError(f"Run '{run_id}' does not exist.")
        return [target]
    if all_runs or len(runs) == 1:
        return runs
    return [runs[-1]]


def detect_executable(command_raw: str) -> str:
    try:
        parts = shlex.split(command_raw, posix=True)
    except ValueError:
        parts = command_raw.strip().split()
    if not parts:
        return "__unknown__"
    return Path(parts[0]).name


def load_command_records(commands_log: Path, run_id: str) -> list[CommandRecord]:
    records: list[CommandRecord] = []
    if not commands_log.exists():
        return records
    for line in commands_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        records.append(
            CommandRecord(
                command_id=payload["command_id"],
                run_id=payload.get("run_id", run_id),
                started_at=payload.get("started_at", ""),
                finished_at=payload.get("finished_at", ""),
                cwd=payload.get("cwd", "/workspace"),
                command_raw=payload.get("command_raw", ""),
                exit_code=int(payload.get("exit_code", 0)),
                executable=detect_executable(payload.get("command_raw", "")),
            )
        )
    return records


def segment_raw_log(raw_log: Path) -> dict[str, str]:
    if not raw_log.exists():
        return {}
    segments: dict[str, list[str]] = {}
    current_id: str | None = None
    for line in raw_log.read_text(encoding="utf-8", errors="ignore").splitlines():
        start_match = START_MARKER_RE.match(line)
        if start_match:
            current_id = start_match.group("command_id")
            segments.setdefault(current_id, [])
            continue
        end_match = END_MARKER_RE.match(line)
        if end_match:
            current_id = None
            continue
        if current_id is not None:
            segments.setdefault(current_id, []).append(line)
    return {command_id: sanitize_output("\n".join(lines)) for command_id, lines in segments.items()}


def sanitize_output(content: str) -> str:
    normalized, _ = normalize_log_content(content)
    cleaned, _ = clean_sensitive_data(normalized)
    return cleaned.strip()


def synthesize_transcript_command(run_id: str, clean_log: Path) -> list[CommandRecord]:
    content = clean_log.read_text(encoding="utf-8") if clean_log.exists() else ""
    return [
        CommandRecord(
            command_id=f"{run_id}-transcript",
            run_id=run_id,
            started_at="",
            finished_at="",
            cwd="/workspace",
            command_raw="__session_transcript__",
            exit_code=0,
            executable="__transcript__",
            output_excerpt=content,
        )
    ]


def attach_outputs(commands: list[CommandRecord], segments: dict[str, str], clean_log: Path) -> list[CommandRecord]:
    if not commands:
        return synthesize_transcript_command(clean_log.parent.name, clean_log)
    for command in commands:
        command.output_excerpt = segments.get(command.command_id, "")
    if not any(command.output_excerpt for command in commands) and clean_log.exists():
        commands[0].output_excerpt = sanitize_output(clean_log.read_text(encoding="utf-8"))
    return commands


def split_product_version(text: str) -> tuple[str | None, str | None, str | None]:
    cleaned = text.strip().strip(",")
    if not cleaned:
        return None, None, None
    tokens = cleaned.split()
    for index, token in enumerate(tokens):
        candidate = token.strip("(),;")
        if VERSION_TOKEN_RE.match(candidate):
            product = " ".join(tokens[:index]).strip(" ,")
            return (product or None), candidate, cleaned
    return cleaned, None, cleaned


def parse_url_target(command_raw: str) -> tuple[str | None, int | None, str | None]:
    try:
        parts = shlex.split(command_raw, posix=True)
    except ValueError:
        parts = command_raw.split()
    for part in parts[1:]:
        if "://" not in part:
            continue
        parsed = urlparse(part)
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        return parsed.hostname, port, scheme
    return None, None, None


def split_host_identifier(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    try:
        ipaddress.ip_address(value)
        return value, None
    except ValueError:
        return None, value


def resolve_container_path(challenge_path: Path, cwd: str, location: str) -> Path:
    base = Path(cwd)
    if location.startswith("/workspace/"):
        return challenge_path / Path(location).relative_to("/workspace")
    if location.startswith("/workspace"):
        return challenge_path / Path(location).relative_to("/workspace")
    if base.is_absolute() and str(base).startswith("/workspace"):
        rel = Path(str(base).replace("/workspace", "", 1).lstrip("/"))
        return challenge_path / rel / location
    return challenge_path / location


def parse_nmap_sidecar_paths(command: CommandRecord, challenge_path: Path) -> list[Path]:
    try:
        parts = shlex.split(command.command_raw, posix=True)
    except ValueError:
        parts = command.command_raw.split()

    sidecars: list[Path] = []
    for index, part in enumerate(parts):
        if part == "-oX" and index + 1 < len(parts) and parts[index + 1] != "-":
            sidecars.append(resolve_container_path(challenge_path, command.cwd, parts[index + 1]))
        elif part == "-oA" and index + 1 < len(parts):
            base = resolve_container_path(challenge_path, command.cwd, parts[index + 1])
            sidecars.append(base.with_suffix(".xml"))
    return sidecars


def normalize_host_observation(
    *,
    ip: str | None = None,
    hostname: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
    product: str | None = None,
    version: str | None = None,
    banner: str | None = None,
) -> dict[str, Any]:
    return {
        "ip": ip,
        "hostname": hostname,
        "port": port,
        "protocol": protocol or "tcp",
        "service": service,
        "product": product,
        "version": version,
        "banner": banner,
    }


def parse_nmap_xml(path: Path) -> ParserResult:
    result = ParserResult(parser_id="nmap-xml", sidecar_files=[str(path)])
    root = ET.parse(path).getroot()
    for host in root.findall("host"):
        ip = None
        hostnames: list[str] = []
        for address in host.findall("address"):
            if address.get("addrtype") in {"ipv4", "ipv6"}:
                ip = address.get("addr")
        for hostname in host.findall("./hostnames/hostname"):
            if hostname.get("name"):
                hostnames.append(hostname.get("name"))
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            service_name = service.get("name") if service is not None else None
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            banner = " ".join(part for part in [product, version] if part).strip() or None
            targets = hostnames or [None]
            for hostname in targets:
                result.observations.append(
                    normalize_host_observation(
                        ip=ip,
                        hostname=hostname,
                        port=int(port.get("portid", "0")),
                        protocol=port.get("protocol", "tcp"),
                        service=service_name,
                        product=product,
                        version=version,
                        banner=banner,
                    )
                )
    return result


def parse_nmap_transcript(command: CommandRecord) -> ParserResult:
    result = ParserResult(parser_id="nmap-transcript")
    current_ip = None
    current_hostname = None
    for line in command.output_excerpt.splitlines():
        host_match = NMAP_HOST_RE.match(line.strip())
        if host_match:
            current_ip = host_match.group("ip")
            current_hostname = host_match.group("hostname")
            continue
        port_match = NMAP_PORT_RE.match(line.strip())
        if port_match and current_ip:
            product, version, banner = split_product_version(port_match.group("rest") or "")
            result.observations.append(
                normalize_host_observation(
                    ip=current_ip,
                    hostname=current_hostname,
                    port=int(port_match.group("port")),
                    protocol=port_match.group("proto"),
                    service=port_match.group("service"),
                    product=product,
                    version=version,
                    banner=banner,
                )
            )
    return result


def parse_whatweb(command: CommandRecord) -> ParserResult:
    target, port, scheme = parse_url_target(command.command_raw)
    url_ip, hostname = split_host_identifier(target)
    service = "https" if scheme == "https" else "http"
    result = ParserResult(parser_id="whatweb")
    for line in command.output_excerpt.splitlines():
        ip = None
        tokens = WHATWEB_TOKEN_RE.findall(line)
        for key, value in tokens:
            if key == "IP":
                ip = value
            elif key in {"HTTPServer", "Server"}:
                product, version, banner = split_product_version(value.replace("/", " "))
                result.observations.append(
                    normalize_host_observation(
                        ip=ip or url_ip,
                        hostname=hostname,
                        port=port,
                        service=service,
                        product=product,
                        version=version,
                        banner=banner or value,
                    )
                )
            elif key not in {"Title", "Country"} and value and any(ch.isdigit() for ch in value):
                result.observations.append(
                    normalize_host_observation(
                        ip=ip or url_ip,
                        hostname=hostname,
                        port=port,
                        service=service,
                        product=key,
                        version=value,
                        banner=f"{key} {value}",
                    )
                )
    if not result.observations and (hostname or url_ip):
        result.observations.append(normalize_host_observation(ip=url_ip, hostname=hostname, port=port, service=service))
    return result


def parse_curl_headers(command: CommandRecord) -> ParserResult:
    target, port, scheme = parse_url_target(command.command_raw)
    ip, hostname = split_host_identifier(target)
    service = "https" if scheme == "https" else "http"
    result = ParserResult(parser_id="curl-headers")
    server_header = None
    for line in command.output_excerpt.splitlines():
        lower = line.lower()
        if lower.startswith("server:"):
            server_header = line.split(":", 1)[1].strip()
            product, version, banner = split_product_version(server_header.replace("/", " "))
            result.observations.append(
                normalize_host_observation(
                    ip=ip,
                    hostname=hostname,
                    port=port,
                    service=service,
                    product=product,
                    version=version,
                    banner=banner or server_header,
                )
            )
        elif lower.startswith("x-powered-by:"):
            powered = line.split(":", 1)[1].strip()
            product, version, banner = split_product_version(powered.replace("/", " "))
            result.observations.append(
                normalize_host_observation(
                    ip=ip,
                    hostname=hostname,
                    port=port,
                    service=service,
                    product=product,
                    version=version,
                    banner=banner or powered,
                )
            )
    if not result.observations and (hostname or ip):
        result.observations.append(normalize_host_observation(ip=ip, hostname=hostname, port=port, service=service, banner=server_header))
    return result


def parse_openssl_s_client(command: CommandRecord) -> ParserResult:
    result = ParserResult(parser_id="openssl-s-client")
    try:
        parts = shlex.split(command.command_raw, posix=True)
    except ValueError:
        parts = command.command_raw.split()
    hostname = None
    port = 443
    for index, part in enumerate(parts):
        if part == "-connect" and index + 1 < len(parts):
            target = parts[index + 1]
            if ":" in target:
                hostname, port_text = target.rsplit(":", 1)
                if port_text.isdigit():
                    port = int(port_text)
            else:
                hostname = target
    banner_lines = []
    for line in command.output_excerpt.splitlines():
        if line.startswith("Protocol") or line.startswith("Cipher") or line.startswith("subject="):
            banner_lines.append(line.strip())
    banner = " | ".join(banner_lines) if banner_lines else next((line.strip() for line in command.output_excerpt.splitlines() if line.strip()), None)
    ip, hostname = split_host_identifier(hostname)
    if hostname or ip:
        result.observations.append(normalize_host_observation(ip=ip, hostname=hostname, port=port, service="tls", banner=banner))
    return result


def parse_ssh_banner(command: CommandRecord) -> ParserResult:
    result = ParserResult(parser_id="ssh-banner")
    try:
        parts = shlex.split(command.command_raw, posix=True)
    except ValueError:
        parts = command.command_raw.split()
    hostname = None
    port = 22
    for index, part in enumerate(parts[1:], start=1):
        if part == "-p" and index + 1 < len(parts) and parts[index + 1].isdigit():
            port = int(parts[index + 1])
            continue
        if part.startswith("-"):
            continue
        hostname = part
    if hostname and "@" in hostname:
        hostname = hostname.split("@", 1)[1]
    banner_match = SSH_PRODUCT_RE.search(command.output_excerpt)
    product = banner_match.group(1) if banner_match else "OpenSSH" if "openssh" in command.output_excerpt.lower() else None
    version = banner_match.group(2) if banner_match else None
    banner = banner_match.group(0) if banner_match else next((line.strip() for line in command.output_excerpt.splitlines() if line.strip()), None)
    ip, hostname = split_host_identifier(hostname)
    if hostname or ip:
        result.observations.append(
            normalize_host_observation(
                ip=ip,
                hostname=hostname,
                port=port,
                service="ssh",
                product=product,
                version=version,
                banner=banner,
            )
        )
    return result


def parse_nc_banner(command: CommandRecord) -> ParserResult:
    result = ParserResult(parser_id="nc-banner")
    try:
        parts = shlex.split(command.command_raw, posix=True)
    except ValueError:
        parts = command.command_raw.split()
    hostname = None
    port = None
    plain_parts = [part for part in parts[1:] if not part.startswith("-")]
    if plain_parts:
        hostname = plain_parts[0]
    if len(plain_parts) > 1 and plain_parts[1].isdigit():
        port = int(plain_parts[1])

    first_nonempty = next((line.strip() for line in command.output_excerpt.splitlines() if line.strip()), "")
    service = None
    product = None
    version = None
    banner = first_nonempty or None
    if first_nonempty.startswith("SSH-"):
        service = "ssh"
        product_match = SSH_PRODUCT_RE.search(first_nonempty)
        product = product_match.group(1) if product_match else "OpenSSH"
        version = product_match.group(2) if product_match else None
        port = port or 22
    elif "smtp" in first_nonempty.lower():
        service = "smtp"
        port = port or 25
        if "postfix" in first_nonempty.lower():
            product = "Postfix"
    ip, hostname = split_host_identifier(hostname)
    if hostname or ip:
        result.observations.append(
            normalize_host_observation(
                ip=ip,
                hostname=hostname,
                port=port,
                service=service,
                product=product,
                version=version,
                banner=banner,
            )
        )
    return result


def dispatch_parser(command: CommandRecord, challenge_path: Path) -> ParserResult:
    if command.executable == "nmap":
        for sidecar in parse_nmap_sidecar_paths(command, challenge_path):
            if sidecar.exists():
                return parse_nmap_xml(sidecar)
        return parse_nmap_transcript(command)
    if command.executable == "whatweb":
        return parse_whatweb(command)
    if command.executable == "curl":
        return parse_curl_headers(command)
    if command.executable == "openssl" and "s_client" in command.command_raw:
        return parse_openssl_s_client(command)
    if command.executable == "ssh":
        return parse_ssh_banner(command)
    if command.executable in {"nc", "netcat", "ncat"}:
        return parse_nc_banner(command)
    return ParserResult(parser_id="unsupported", warnings=[f"No parser for executable '{command.executable}'."])


def copy_static_assets(target_assets_dir: Path) -> None:
    target_assets_dir.mkdir(parents=True, exist_ok=True)
    assets_root = resources.files("helm_path.graph.static")
    for name in ("app.js", "graph.css", "vis-network.min.js", "vis-network.min.css"):
        with resources.as_file(assets_root.joinpath(name)) as asset_path:
            shutil.copy(asset_path, target_assets_dir / name)


def write_graph_html(target_path: Path) -> None:
    template = resources.files("helm_path.graph.static").joinpath("index.html").read_text(encoding="utf-8")
    target_path.write_text(template, encoding="utf-8")


def build_graph_bundle(challenge_path: Path, run_dirs: list[Path]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    challenge_path = resolve_challenge_path(challenge_path)
    builder = DiscoveryGraphBuilder()
    command_records: list[CommandRecord] = []
    parser_versions: set[str] = set()

    for run_dir in run_dirs:
        manifest = load_manifest(run_dir)
        paths = run_file_paths(challenge_path, manifest["run_id"])
        commands = load_command_records(paths["commands_log"], manifest["run_id"])
        segments = segment_raw_log(paths["raw_log"])
        commands = attach_outputs(commands, segments, paths["clean_log"])
        for command in commands:
            result = dispatch_parser(command, challenge_path)
            parser_versions.add(result.parser_id)
            command.parser_id = result.parser_id
            command.warnings.extend(result.warnings)
            command.sidecar_files.extend(result.sidecar_files)
            evidence_source = paths["raw_log"].as_posix() if command.output_excerpt else paths["manifest"].as_posix()
            evidence_excerpt = command.output_excerpt[:2000] if command.output_excerpt else command.command_raw
            evidence_id = builder.add_evidence(
                run_id=command.run_id,
                command_id=command.command_id,
                parser_id=result.parser_id,
                source_file=evidence_source,
                raw_excerpt=evidence_excerpt,
                confidence=1.0 if result.parser_id != "unsupported" else 0.2,
            )
            command.evidence_ids.append(evidence_id)
            for observation in result.observations:
                nodes, edges = builder.ingest_observation(observation, evidence_id)
                command.extracted_node_ids.extend(sorted(nodes))
                command.extracted_edge_ids.extend(sorted(edges))
            command_records.append(command)

    graph = builder.to_dict()
    commands_payload = {
        "commands": [command.to_dict() for command in command_records],
        "summary": {
            "commands": len(command_records),
            "parsed_commands": sum(1 for command in command_records if command.parser_id != "unsupported"),
            "unsupported_commands": sum(1 for command in command_records if command.parser_id == "unsupported"),
        },
    }
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "challenge_path": str(challenge_path),
        "run_ids": [run_dir.name for run_dir in run_dirs],
        "parser_versions": sorted(parser_versions),
        "graph_version": GRAPH_PROMPT_VERSION,
    }
    return graph, commands_payload, manifest


def write_graph_artifacts(challenge_path: Path, run_dirs: list[Path]) -> dict[str, Any]:
    graph, commands_payload, manifest = build_graph_bundle(challenge_path, run_dirs)
    output_paths = graph_output_paths(challenge_path)
    output_paths["assets_dir"].mkdir(parents=True, exist_ok=True)
    copy_static_assets(output_paths["assets_dir"])
    write_graph_html(output_paths[GRAPH_HTML_FILENAME])
    write_json_file(output_paths[GRAPH_JSON_FILENAME], graph)
    write_json_file(output_paths[GRAPH_COMMANDS_FILENAME], commands_payload)
    manifest["outputs"] = {
        GRAPH_JSON_FILENAME: calculate_file_hash(output_paths[GRAPH_JSON_FILENAME]),
        GRAPH_COMMANDS_FILENAME: calculate_file_hash(output_paths[GRAPH_COMMANDS_FILENAME]),
        GRAPH_HTML_FILENAME: calculate_file_hash(output_paths[GRAPH_HTML_FILENAME]),
    }
    write_json_file(output_paths[GRAPH_MANIFEST_FILENAME], manifest)
    manifest["assets"] = sorted(path.name for path in output_paths["assets_dir"].iterdir() if path.is_file())
    return manifest
