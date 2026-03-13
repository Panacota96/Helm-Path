from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CommandRecord:
    command_id: str
    run_id: str
    started_at: str
    finished_at: str
    cwd: str
    command_raw: str
    exit_code: int
    executable: str
    output_excerpt: str = ""
    parser_id: str = "unsupported"
    warnings: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    extracted_node_ids: list[str] = field(default_factory=list)
    extracted_edge_ids: list[str] = field(default_factory=list)
    sidecar_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "cwd": self.cwd,
            "command_raw": self.command_raw,
            "exit_code": self.exit_code,
            "executable": self.executable,
            "output_excerpt": self.output_excerpt,
            "parser_id": self.parser_id,
            "warnings": self.warnings,
            "evidence_ids": self.evidence_ids,
            "extracted_node_ids": self.extracted_node_ids,
            "extracted_edge_ids": self.extracted_edge_ids,
            "sidecar_files": self.sidecar_files,
        }


@dataclass
class ParserResult:
    parser_id: str
    observations: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sidecar_files: list[str] = field(default_factory=list)


class DiscoveryGraphBuilder:
    def __init__(self) -> None:
        self._node_counter = 0
        self._edge_counter = 0
        self._evidence_counter = 0
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.evidence: dict[str, dict[str, Any]] = {}
        self._node_key_to_id: dict[str, str] = {}
        self._edge_key_to_id: dict[str, str] = {}
        self._evidence_key_to_id: dict[str, str] = {}
        self._evidence_node_ids: dict[str, str] = {}

    def add_evidence(
        self,
        run_id: str,
        command_id: str,
        parser_id: str,
        source_file: str,
        raw_excerpt: str,
        confidence: float,
    ) -> str:
        evidence_key = hashlib.sha1(
            f"{run_id}|{command_id}|{parser_id}|{source_file}|{raw_excerpt}|{confidence}".encode("utf-8")
        ).hexdigest()
        if evidence_key in self._evidence_key_to_id:
            return self._evidence_key_to_id[evidence_key]

        self._evidence_counter += 1
        evidence_id = f"ev{self._evidence_counter}"
        record = {
            "evidence_id": evidence_id,
            "run_id": run_id,
            "command_id": command_id,
            "parser_id": parser_id,
            "source_file": source_file,
            "raw_excerpt": raw_excerpt,
            "confidence": confidence,
        }
        self.evidence[evidence_id] = record
        self._evidence_key_to_id[evidence_key] = evidence_id
        evidence_node_id = self.ensure_node(
            "Evidence",
            evidence_id,
            f"Evidence {self._evidence_counter}",
            {
                "run_id": run_id,
                "command_id": command_id,
                "parser_id": parser_id,
                "confidence": confidence,
                "source_file": source_file,
            },
        )
        self._evidence_node_ids[evidence_id] = evidence_node_id
        return evidence_id

    def ensure_node(
        self,
        node_type: str,
        key: str,
        label: str,
        properties: dict[str, Any] | None = None,
        evidence_id: str | None = None,
    ) -> str:
        node_key = f"{node_type}:{key}"
        if node_key in self._node_key_to_id:
            node_id = self._node_key_to_id[node_key]
            if properties:
                self.nodes[node_id]["properties"].update({k: v for k, v in properties.items() if v not in (None, "", [])})
            if evidence_id:
                self._append_unique(self.nodes[node_id]["evidence_ids"], evidence_id)
            return node_id

        self._node_counter += 1
        node_id = f"n{self._node_counter}"
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "key": key,
            "label": label,
            "properties": properties or {},
            "evidence_ids": [evidence_id] if evidence_id else [],
        }
        self._node_key_to_id[node_key] = node_id
        return node_id

    def ensure_edge(
        self,
        edge_type: str,
        source_id: str,
        target_id: str,
        properties: dict[str, Any] | None = None,
        evidence_id: str | None = None,
    ) -> str:
        edge_key = f"{edge_type}:{source_id}:{target_id}"
        if edge_key in self._edge_key_to_id:
            edge_id = self._edge_key_to_id[edge_key]
            if properties:
                self.edges[edge_id]["properties"].update({k: v for k, v in properties.items() if v not in (None, "", [])})
            if evidence_id:
                self._append_unique(self.edges[edge_id]["evidence_ids"], evidence_id)
            return edge_id

        self._edge_counter += 1
        edge_id = f"e{self._edge_counter}"
        self.edges[edge_id] = {
            "id": edge_id,
            "type": edge_type,
            "source": source_id,
            "target": target_id,
            "properties": properties or {},
            "evidence_ids": [evidence_id] if evidence_id else [],
        }
        self._edge_key_to_id[edge_key] = edge_id
        return edge_id

    def link_node_to_evidence(self, node_id: str, evidence_id: str) -> str:
        evidence_node_id = self._evidence_node_ids[evidence_id]
        self._append_unique(self.nodes[node_id]["evidence_ids"], evidence_id)
        return self.ensure_edge("observed_in", node_id, evidence_node_id, evidence_id=evidence_id)

    def ingest_observation(
        self,
        observation: dict[str, Any],
        evidence_id: str,
    ) -> tuple[set[str], set[str]]:
        touched_nodes: set[str] = set()
        touched_edges: set[str] = set()

        ip = observation.get("ip")
        hostname = observation.get("hostname")
        port = observation.get("port")
        protocol = observation.get("protocol") or "tcp"
        service = observation.get("service")
        product = observation.get("product")
        version = observation.get("version")
        banner = observation.get("banner")

        ip_id = None
        host_id = None
        port_id = None
        service_id = None
        product_id = None
        release_id = None

        if ip:
            ip_id = self.ensure_node("IPAddress", ip, ip, {"value": ip}, evidence_id=evidence_id)
            touched_nodes.add(ip_id)
        if hostname:
            host_id = self.ensure_node("Hostname", hostname.lower(), hostname, {"value": hostname.lower()}, evidence_id=evidence_id)
            touched_nodes.add(host_id)
        if host_id and ip_id:
            touched_edges.add(self.ensure_edge("resolves_to", host_id, ip_id, evidence_id=evidence_id))

        base_target_id = ip_id or host_id
        base_target_key = ip or hostname
        if port and base_target_id and base_target_key:
            port_key = f"{base_target_key}:{port}/{protocol}"
            port_id = self.ensure_node(
                "Port",
                port_key,
                f"{port}/{protocol}",
                {"port": port, "protocol": protocol, "target": base_target_key},
                evidence_id=evidence_id,
            )
            touched_nodes.add(port_id)
            touched_edges.add(self.ensure_edge("exposes_port", base_target_id, port_id, evidence_id=evidence_id))

        if service:
            service_id = self.ensure_node("Service", service.lower(), service, {"name": service.lower()}, evidence_id=evidence_id)
            touched_nodes.add(service_id)
            if port_id:
                touched_edges.add(self.ensure_edge("speaks_service", port_id, service_id, evidence_id=evidence_id))

        if product:
            product_id = self.ensure_node("Product", product.lower(), product, {"name": product}, evidence_id=evidence_id)
            touched_nodes.add(product_id)
            if service_id:
                touched_edges.add(self.ensure_edge("identified_as", service_id, product_id, evidence_id=evidence_id))

        if product and version:
            release_id = self.ensure_node(
                "ProductRelease",
                f"{product.lower()}:{version}",
                f"{product} {version}",
                {"product": product, "version": version},
                evidence_id=evidence_id,
            )
            touched_nodes.add(release_id)
            if product_id:
                touched_edges.add(self.ensure_edge("runs_release", product_id, release_id, evidence_id=evidence_id))

        if banner:
            banner_id = self.ensure_node(
                "Banner",
                hashlib.sha1(banner.encode("utf-8")).hexdigest()[:16],
                banner.splitlines()[0][:80],
                {"value": banner},
                evidence_id=evidence_id,
            )
            touched_nodes.add(banner_id)
            if port_id:
                touched_edges.add(self.ensure_edge("presented_banner", port_id, banner_id, evidence_id=evidence_id))
            if release_id:
                touched_edges.add(self.ensure_edge("derived_from", release_id, banner_id, evidence_id=evidence_id))
            elif product_id:
                touched_edges.add(self.ensure_edge("derived_from", product_id, banner_id, evidence_id=evidence_id))
            elif service_id:
                touched_edges.add(self.ensure_edge("derived_from", service_id, banner_id, evidence_id=evidence_id))

        for node_id in list(touched_nodes):
            touched_edges.add(self.link_node_to_evidence(node_id, evidence_id))
        return touched_nodes, touched_edges

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": sorted(self.nodes.values(), key=lambda item: item["id"]),
            "edges": sorted(self.edges.values(), key=lambda item: item["id"]),
            "evidence": sorted(self.evidence.values(), key=lambda item: item["evidence_id"]),
        }

    @staticmethod
    def _append_unique(items: list[str], value: str) -> None:
        if value not in items:
            items.append(value)
