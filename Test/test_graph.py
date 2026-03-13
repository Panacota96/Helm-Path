import json
from urllib.request import urlopen

from helm_path.constants import COMMAND_MARKER_END, COMMAND_MARKER_START
from helm_path.graph.build import (
    build_graph_bundle,
    load_command_records,
    parse_curl_headers,
    parse_nc_banner,
    parse_nmap_xml,
    parse_openssl_s_client,
    parse_ssh_banner,
    parse_whatweb,
    segment_raw_log,
    write_graph_artifacts,
)
from helm_path.graph.models import CommandRecord
from helm_path.graph.server import serve_graph_dir
from helm_path.processing import build_clean_log, calculate_file_hash, write_json_file
from helm_path.workspace import create_run_layout, graph_output_paths, init_challenge_workspace, load_challenge_metadata, run_file_paths


def create_recorded_run(challenge_path, metadata, command_raw, output_excerpt, command_id, extra_files=None):
    run_dir, manifest = create_run_layout(challenge_path, metadata, image_tag="helm-path:lite", image_id="sha256:test")
    paths = run_file_paths(challenge_path, manifest["run_id"])
    raw_content = (
        f"{COMMAND_MARKER_START}::{command_id}\n"
        f"{output_excerpt}\n"
        f"{COMMAND_MARKER_END}::{command_id}::0\n"
    )
    paths["raw_log"].write_text(raw_content, encoding="utf-8")
    build_clean_log(paths["raw_log"], paths["clean_log"])
    paths["commands_log"].write_text(
        json.dumps(
            {
                "schema_version": 1,
                "command_id": command_id,
                "run_id": manifest["run_id"],
                "started_at": "2026-03-13T10:00:00Z",
                "finished_at": "2026-03-13T10:00:05Z",
                "cwd": "/workspace",
                "command_raw": command_raw,
                "exit_code": 0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    if extra_files:
        for relative_path, content in extra_files.items():
            target = challenge_path / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    manifest["captured_at"]["end"] = "2026-03-13T10:00:05Z"
    manifest["hashes"]["raw_log"] = calculate_file_hash(paths["raw_log"])
    manifest["hashes"]["clean_log"] = calculate_file_hash(paths["clean_log"])
    manifest["hashes"]["commands_log"] = calculate_file_hash(paths["commands_log"])
    write_json_file(paths["manifest"], manifest)
    return run_dir


def test_load_command_records_and_segment_raw_log(tmp_path):
    commands_log = tmp_path / "commands.jsonl"
    raw_log = tmp_path / "raw.log"
    commands_log.write_text(
        json.dumps(
            {
                "command_id": "run-1-1",
                "run_id": "run-1",
                "started_at": "2026-03-13T10:00:00Z",
                "finished_at": "2026-03-13T10:00:03Z",
                "cwd": "/workspace",
                "command_raw": "nmap -sV 10.10.11.42",
                "exit_code": 0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    raw_log.write_text(
        f"{COMMAND_MARKER_START}::run-1-1\n22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n{COMMAND_MARKER_END}::run-1-1::0\n",
        encoding="utf-8",
    )

    commands = load_command_records(commands_log, "run-1")
    segments = segment_raw_log(raw_log)

    assert commands[0].executable == "nmap"
    assert "OpenSSH 8.2p1" in segments["run-1-1"]


def test_core_parsers_extract_expected_observations(tmp_path):
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(
        """<nmaprun><host><address addr="10.10.11.42" addrtype="ipv4"/><hostnames><hostname name="target.htb"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port></ports></host></nmaprun>""",
        encoding="utf-8",
    )
    xml_result = parse_nmap_xml(xml_file)
    assert xml_result.observations[0]["ip"] == "10.10.11.42"
    assert xml_result.observations[0]["product"] == "OpenSSH"

    whatweb_result = parse_whatweb(
        CommandRecord(
            command_id="c1",
            run_id="r1",
            started_at="",
            finished_at="",
            cwd="/workspace",
            command_raw="whatweb http://10.10.11.42",
            exit_code=0,
            executable="whatweb",
            output_excerpt="http://10.10.11.42 [200 OK] HTTPServer[nginx/1.18.0], IP[10.10.11.42]",
        )
    )
    assert whatweb_result.observations[0]["service"] == "http"
    assert whatweb_result.observations[0]["product"] == "nginx"

    curl_result = parse_curl_headers(
        CommandRecord(
            command_id="c2",
            run_id="r1",
            started_at="",
            finished_at="",
            cwd="/workspace",
            command_raw="curl -I http://10.10.11.42",
            exit_code=0,
            executable="curl",
            output_excerpt="HTTP/1.1 200 OK\nServer: nginx/1.18.0\nX-Powered-By: PHP/8.1.2",
        )
    )
    assert any(item["product"] == "nginx" for item in curl_result.observations)
    assert any(item["product"] == "PHP" for item in curl_result.observations)

    openssl_result = parse_openssl_s_client(
        CommandRecord(
            command_id="c3",
            run_id="r1",
            started_at="",
            finished_at="",
            cwd="/workspace",
            command_raw="openssl s_client -connect 10.10.11.42:443",
            exit_code=0,
            executable="openssl",
            output_excerpt="Protocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384",
        )
    )
    assert openssl_result.observations[0]["service"] == "tls"

    ssh_result = parse_ssh_banner(
        CommandRecord(
            command_id="c4",
            run_id="r1",
            started_at="",
            finished_at="",
            cwd="/workspace",
            command_raw="ssh 10.10.11.42",
            exit_code=0,
            executable="ssh",
            output_excerpt="debug1: remote software version OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        )
    )
    assert ssh_result.observations[0]["product"] == "OpenSSH"

    nc_result = parse_nc_banner(
        CommandRecord(
            command_id="c5",
            run_id="r1",
            started_at="",
            finished_at="",
            cwd="/workspace",
            command_raw="nc 10.10.11.42 22",
            exit_code=0,
            executable="nc",
            output_excerpt="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        )
    )
    assert nc_result.observations[0]["service"] == "ssh"


def test_graph_bundle_deduplicates_entities_across_runs(tmp_path):
    challenge_path = init_challenge_workspace(tmp_path, "HTB", "Pwn", "Graphbox")
    metadata = load_challenge_metadata(challenge_path)
    run1 = create_recorded_run(
        challenge_path,
        metadata,
        "nmap -sV 10.10.11.42",
        "Nmap scan report for 10.10.11.42\n22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n80/tcp open http nginx 1.18.0",
        "cmd-1",
    )
    run2 = create_recorded_run(
        challenge_path,
        metadata,
        "nc 10.10.11.42 22",
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "cmd-2",
    )

    graph, commands_payload, manifest = build_graph_bundle(challenge_path, [run1, run2])

    ip_nodes = [node for node in graph["nodes"] if node["type"] == "IPAddress" and node["label"] == "10.10.11.42"]
    ssh_services = [node for node in graph["nodes"] if node["type"] == "Service" and node["label"] == "ssh"]
    assert len(ip_nodes) == 1
    assert len(ssh_services) == 1
    assert commands_payload["summary"]["commands"] == 2
    assert manifest["run_ids"] == [run1.name, run2.name]


def test_write_graph_artifacts_and_serve(tmp_path):
    challenge_path = init_challenge_workspace(tmp_path, "HTB", "Web", "Render")
    metadata = load_challenge_metadata(challenge_path)
    run_dir = create_recorded_run(
        challenge_path,
        metadata,
        "curl -I http://10.10.11.42",
        "HTTP/1.1 200 OK\nServer: nginx/1.18.0",
        "cmd-1",
    )

    manifest = write_graph_artifacts(challenge_path, [run_dir])
    output_paths = graph_output_paths(challenge_path)

    assert output_paths["graph.json"].exists()
    assert output_paths["assets_dir"].is_dir()
    assert "graph.json" in manifest["outputs"]

    with serve_graph_dir(challenge_path / "graph", host="127.0.0.1", port=0, open_browser=False) as (_, url):
        html = urlopen(url).read().decode("utf-8")
        assert "Discovery Graph" in html
