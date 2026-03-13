const colors = {
  IPAddress: "#1f77b4",
  Hostname: "#2ca02c",
  Port: "#17becf",
  Service: "#ff7f0e",
  Product: "#d62728",
  ProductRelease: "#9467bd",
  Banner: "#8c564b",
  Evidence: "#7f7f7f",
};

let rawGraph = null;
let commandMap = new Map();
let evidenceMap = new Map();
let network = null;

async function loadData() {
  const [graphResponse, commandsResponse] = await Promise.all([
    fetch("graph.json"),
    fetch("commands.json"),
  ]);
  rawGraph = await graphResponse.json();
  const commandsPayload = await commandsResponse.json();
  commandMap = new Map(commandsPayload.commands.map((command) => [command.command_id, command]));
  evidenceMap = new Map(rawGraph.evidence.map((evidence) => [evidence.evidence_id, evidence]));
  populateFilters();
  initializeNetwork();
  renderGraph();
}

function populateFilters() {
  const runFilter = document.getElementById("run-filter");
  const typeFilter = document.getElementById("type-filter");
  const parserFilter = document.getElementById("parser-filter");
  fillSelect(runFilter, ["all", ...new Set(rawGraph.evidence.map((item) => item.run_id))]);
  fillSelect(typeFilter, ["all", ...new Set(rawGraph.nodes.map((item) => item.type))]);
  fillSelect(parserFilter, ["all", ...new Set(rawGraph.evidence.map((item) => item.parser_id))]);
}

function fillSelect(select, values) {
  select.innerHTML = "";
  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });
}

function initializeNetwork() {
  const container = document.getElementById("network");
  network = new vis.Network(container, { nodes: [], edges: [] }, {
    layout: {
      hierarchical: {
        enabled: true,
        direction: "LR",
        sortMethod: "directed",
      },
    },
    physics: false,
    nodes: {
      shape: "dot",
      size: 18,
      font: { face: "Segoe UI", size: 14, color: "#13212b" },
      borderWidth: 1,
    },
    edges: {
      arrows: { to: { enabled: true, scaleFactor: 0.7 } },
      smooth: { type: "cubicBezier", forceDirection: "horizontal" },
      color: { color: "#7d8d9c", highlight: "#143a52" },
      font: { align: "top", size: 11 },
    },
    interaction: {
      hover: true,
    },
  });

  network.on("click", (params) => {
    if (params.nodes.length) {
      const node = currentNodes.get(params.nodes[0]);
      renderDetails("node", node);
      return;
    }
    if (params.edges.length) {
      const edge = currentEdges.get(params.edges[0]);
      renderDetails("edge", edge);
      return;
    }
    document.getElementById("details-content").textContent = "Select a node or edge to inspect evidence.";
  });
}

let currentNodes = new Map();
let currentEdges = new Map();

function renderGraph() {
  const filters = getFilters();
  const nodes = rawGraph.nodes.filter((node) => matchesNode(node, filters));
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = rawGraph.edges.filter((edge) => matchesEdge(edge, nodeIds, filters));

  currentNodes = new Map(nodes.map((node) => [node.id, node]));
  currentEdges = new Map(edges.map((edge) => [edge.id, edge]));

  const visNodes = nodes.map((node) => ({
    id: node.id,
    label: node.label,
    color: colors[node.type] || "#4f6b80",
    title: `${node.type}: ${node.label}`,
    value: node.type === "Evidence" ? 1 : 2,
  }));
  const visEdges = edges.map((edge) => ({
    id: edge.id,
    from: edge.source,
    to: edge.target,
    label: edge.type,
  }));

  network.setOptions({ physics: { enabled: filters.physics } });
  network.setData({ nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) });
  updateSummary(nodes, edges);
}

function getFilters() {
  return {
    search: document.getElementById("search").value.trim().toLowerCase(),
    runId: document.getElementById("run-filter").value,
    nodeType: document.getElementById("type-filter").value,
    parserId: document.getElementById("parser-filter").value,
    confidence: Number(document.getElementById("confidence-filter").value),
    physics: document.getElementById("physics-toggle").checked,
  };
}

function matchesEvidence(evidence, filters) {
  if (filters.runId !== "all" && evidence.run_id !== filters.runId) {
    return false;
  }
  if (filters.parserId !== "all" && evidence.parser_id !== filters.parserId) {
    return false;
  }
  if (Number(evidence.confidence) < filters.confidence) {
    return false;
  }
  return true;
}

function nodeSearchText(node) {
  return `${node.label} ${JSON.stringify(node.properties || {})}`.toLowerCase();
}

function matchesNode(node, filters) {
  if (filters.nodeType !== "all" && node.type !== filters.nodeType) {
    return false;
  }
  if (filters.search && !nodeSearchText(node).includes(filters.search)) {
    return false;
  }
  if (!node.evidence_ids || !node.evidence_ids.length) {
    return true;
  }
  return node.evidence_ids.some((evidenceId) => {
    const evidence = evidenceMap.get(evidenceId);
    return evidence && matchesEvidence(evidence, filters);
  });
}

function matchesEdge(edge, nodeIds, filters) {
  if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) {
    return false;
  }
  if (!edge.evidence_ids || !edge.evidence_ids.length) {
    return true;
  }
  return edge.evidence_ids.some((evidenceId) => {
    const evidence = evidenceMap.get(evidenceId);
    return evidence && matchesEvidence(evidence, filters);
  });
}

function updateSummary(nodes, edges) {
  document.getElementById("summary").innerHTML = `
    <div><strong>Visible nodes:</strong> ${nodes.length}</div>
    <div><strong>Visible edges:</strong> ${edges.length}</div>
    <div><strong>Evidence items:</strong> ${rawGraph.evidence.length}</div>
  `;
}

function renderDetails(kind, item) {
  const container = document.getElementById("details-content");
  const evidenceBlocks = (item.evidence_ids || [])
    .map((evidenceId) => {
      const evidence = evidenceMap.get(evidenceId);
      if (!evidence) return "";
      const command = commandMap.get(evidence.command_id);
      return `
        <div class="details-block">
          <h3>Evidence ${evidence.evidence_id}</h3>
          <div class="tag">${evidence.parser_id}</div>
          <div class="tag">${evidence.run_id}</div>
          <div class="tag">confidence ${Number(evidence.confidence).toFixed(1)}</div>
          <p><strong>Command:</strong> ${command ? escapeHtml(command.command_raw) : evidence.command_id}</p>
          <pre>${escapeHtml(evidence.raw_excerpt)}</pre>
        </div>
      `;
    })
    .join("");

  container.innerHTML = `
    <div class="details-block">
      <h3>${escapeHtml(item.label || item.type)}</h3>
      <div class="tag">${escapeHtml(kind)}</div>
      <div class="tag">${escapeHtml(item.type || "")}</div>
      <pre>${escapeHtml(JSON.stringify(item.properties || {}, null, 2))}</pre>
    </div>
    ${evidenceBlocks || "<div class='details-block'>No evidence attached.</div>"}
  `;
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

document.getElementById("search").addEventListener("input", renderGraph);
document.getElementById("run-filter").addEventListener("change", renderGraph);
document.getElementById("type-filter").addEventListener("change", renderGraph);
document.getElementById("parser-filter").addEventListener("change", renderGraph);
document.getElementById("confidence-filter").addEventListener("input", (event) => {
  document.getElementById("confidence-value").textContent = Number(event.target.value).toFixed(1);
  renderGraph();
});
document.getElementById("physics-toggle").addEventListener("change", renderGraph);
document.getElementById("reset-filters").addEventListener("click", () => {
  document.getElementById("search").value = "";
  document.getElementById("run-filter").value = "all";
  document.getElementById("type-filter").value = "all";
  document.getElementById("parser-filter").value = "all";
  document.getElementById("confidence-filter").value = "0";
  document.getElementById("confidence-value").textContent = "0.0";
  document.getElementById("physics-toggle").checked = false;
  renderGraph();
});

loadData().catch((error) => {
  document.getElementById("details-content").textContent = `Failed to load graph assets: ${error}`;
});
