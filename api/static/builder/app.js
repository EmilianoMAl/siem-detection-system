// Builder de dashboards estilo Power BI para SENTINEL.
// Vanilla JS, sin build step. Siempre habla con la API vía /api/... —
// eso hace que funcione igual en localhost:8000/builder (sin Nginx)
// que en la VM detrás de Nginx (que enruta /api/ al backend).

const API_BASE = "/api";

const grid = GridStack.init({
  cellHeight: 90,
  margin: 8,
  float: true,
  animate: true,
});

// Redimensionar (o arrastrar y soltar, que también dispara 'resize' en
// float mode) debe hacer que Plotly recalcule el tamaño de la gráfica —
// si no, se queda con las dimensiones del render anterior.
grid.on("resize", (event, items) => {
  for (const item of items) resizeWidgetChart(item.id);
});

let dimensionsByDataset = { events: [], alerts: [] };
let widgetConfigs = {};   // id -> config
let nextWidgetId = 1;
let editingWidgetId = null;
let currentDashboardId = null;

const el = (id) => document.getElementById(id);

function updateEmptyState() {
  const hasWidgets = grid.engine.nodes.length > 0;
  el("empty-state").style.display = hasWidgets ? "none" : "block";
}

async function apiGet(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

async function apiSend(path, method, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------------
// Modal de configuración de widget
// ---------------------------------------------------------------------

function populateGroupByOptions() {
  const dataset = el("cfg-dataset").value;
  const select = el("cfg-group-by");
  select.innerHTML = "";
  for (const dim of dimensionsByDataset[dataset] || []) {
    const opt = document.createElement("option");
    opt.value = dim;
    opt.textContent = dim;
    select.appendChild(opt);
  }
  el("cfg-log-source-wrap").style.display = dataset === "events" ? "block" : "none";
  el("cfg-severity-wrap").style.display = dataset === "alerts" ? "block" : "none";
}

function openModal(existingConfig = null) {
  editingWidgetId = existingConfig ? existingConfig.id : null;
  const cfg = existingConfig || {
    title: "", dataset: "events", logSource: "ALL", severity: "ALL",
    groupBy: dimensionsByDataset.events[0], chartType: "bar", limit: 10,
  };

  el("cfg-title").value = cfg.title;
  el("cfg-dataset").value = cfg.dataset;
  populateGroupByOptions();
  el("cfg-log-source").value = cfg.logSource;
  el("cfg-severity").value = cfg.severity;
  el("cfg-group-by").value = cfg.groupBy;
  el("cfg-chart-type").value = cfg.chartType;
  el("cfg-limit").value = cfg.limit;

  el("btn-confirm-widget").textContent = existingConfig ? "Guardar cambios" : "Agregar";
  el("widget-modal").style.display = "flex";
}

function closeModal() {
  el("widget-modal").style.display = "none";
  editingWidgetId = null;
}

function readConfigFromModal() {
  return {
    title: el("cfg-title").value.trim() || "Sin título",
    dataset: el("cfg-dataset").value,
    logSource: el("cfg-log-source").value,
    severity: el("cfg-severity").value,
    groupBy: el("cfg-group-by").value,
    chartType: el("cfg-chart-type").value,
    limit: parseInt(el("cfg-limit").value, 10) || 10,
  };
}

// ---------------------------------------------------------------------
// Widgets: creación + render de datos
// ---------------------------------------------------------------------

function widgetHTML(id, title) {
  return `
    <div class="widget-card">
      <div class="widget-header">
        <span class="widget-title" data-edit="${id}" style="cursor:pointer">${title}</span>
        <button class="widget-remove" data-remove="${id}">✕</button>
      </div>
      <div class="widget-body">
        <div id="chart-${id}" class="plot-container"></div>
      </div>
    </div>
  `;
}

function addWidgetToGrid(id, config, position = {}) {
  widgetConfigs[id] = config;
  grid.addWidget({
    id,
    w: position.w || 4,
    h: position.h || 4,
    x: position.x,
    y: position.y,
    content: widgetHTML(id, config.title),
  });
  updateEmptyState();
  renderWidget(id);
}

async function renderWidget(id) {
  const config = widgetConfigs[id];
  const container = document.getElementById(`chart-${id}`);
  if (!container) return;

  let data;
  try {
    const params = new URLSearchParams({
      dataset: config.dataset,
      group_by: config.groupBy,
      log_source: config.logSource,
      severity: config.severity,
      limit: String(config.limit),
    });
    data = await apiGet(`/query?${params.toString()}`);
  } catch (err) {
    container.innerHTML = `<div class="muted-text">Error cargando datos</div>`;
    return;
  }

  if (config.chartType === "number") {
    const total = data.reduce((acc, d) => acc + d.value, 0);
    container.innerHTML = `<div class="kpi-value">${total.toLocaleString()}</div>`;
    return;
  }

  container.innerHTML = "";
  const sorted = config.chartType === "line"
    ? [...data].sort((a, b) => String(a.label).localeCompare(String(b.label)))
    : data;

  const labels = sorted.map((d) => d.label ?? "(vacío)");
  const values = sorted.map((d) => d.value);
  const theme = {
    paper_bgcolor: "rgba(0,0,0,0)",
    plot_bgcolor: "rgba(0,0,0,0)",
    font: { color: "#ABA9A3", size: 10 },
    margin: { l: 40, r: 10, t: 10, b: 60 },
    xaxis: { tickangle: -30, gridcolor: "#2B2C31" },
    yaxis: { gridcolor: "#2B2C31" },
  };

  let trace;
  if (config.chartType === "pie") {
    trace = [{
      type: "pie", labels, values,
      marker: { colors: ["#5B8CF0", "#8C7AE0", "#5FD09A", "#E5A63C", "#F0685E", "#6B93D6"] },
      textfont: { color: "#17181C" },
    }];
  } else if (config.chartType === "line") {
    trace = [{ type: "scatter", mode: "lines+markers", x: labels, y: values, line: { color: "#5B8CF0" } }];
  } else {
    trace = [{ type: "bar", x: labels, y: values, marker: { color: "#5B8CF0" } }];
  }

  Plotly.newPlot(container, trace, theme, { responsive: true, displayModeBar: false });
  // El contenedor puede no tener su alto final todavía cuando se llama
  // newPlot (recién insertado por GridStack) -> forzamos un resize en el
  // siguiente frame para que Plotly recalcule contra el tamaño real.
  requestAnimationFrame(() => Plotly.Plots.resize(container));
}

function resizeWidgetChart(id) {
  const container = document.getElementById(`chart-${id}`);
  if (container && container.data) Plotly.Plots.resize(container);
}

function removeWidget(id) {
  const node = grid.engine.nodes.find((n) => n.id === id);
  if (node) grid.removeWidget(node.el);
  delete widgetConfigs[id];
  updateEmptyState();
}

// ---------------------------------------------------------------------
// Guardar / cargar dashboards
// ---------------------------------------------------------------------

async function refreshDashboardList() {
  const dashboards = await apiGet("/dashboards");
  const select = el("dashboard-select");
  select.innerHTML = '<option value="">— Nuevo dashboard —</option>';
  for (const d of dashboards) {
    const opt = document.createElement("option");
    opt.value = d.id;
    opt.textContent = d.name;
    select.appendChild(opt);
  }
}

function currentLayout() {
  return grid.save(false).map((item) => ({
    ...item,
    config: widgetConfigs[item.id],
  }));
}

async function saveDashboard() {
  const name = el("dashboard-name").value.trim() || "Sin nombre";
  const layout = currentLayout();
  if (currentDashboardId) {
    await apiSend(`/dashboards/${currentDashboardId}`, "PUT", { name, layout });
  } else {
    const created = await apiSend("/dashboards", "POST", { name, layout });
    currentDashboardId = created.id;
  }
  await refreshDashboardList();
  el("dashboard-select").value = currentDashboardId;
  el("btn-delete").style.display = "inline-flex";
}

async function loadDashboard(id) {
  if (!id) {
    grid.removeAll();
    widgetConfigs = {};
    currentDashboardId = null;
    el("dashboard-name").value = "Mi dashboard";
    el("btn-delete").style.display = "none";
    updateEmptyState();
    return;
  }
  const dashboard = await apiGet(`/dashboards/${id}`);
  grid.removeAll();
  widgetConfigs = {};
  currentDashboardId = dashboard.id;
  el("dashboard-name").value = dashboard.name;
  el("btn-delete").style.display = "inline-flex";

  for (const item of dashboard.layout) {
    addWidgetToGrid(item.id, item.config, { x: item.x, y: item.y, w: item.w, h: item.h });
  }
  updateEmptyState();
}

async function deleteDashboard() {
  if (!currentDashboardId) return;
  if (!confirm("¿Eliminar este dashboard guardado?")) return;
  await apiSend(`/dashboards/${currentDashboardId}`, "DELETE", {});
  await refreshDashboardList();
  await loadDashboard(null);
}

function refreshAllWidgets() {
  for (const id of Object.keys(widgetConfigs)) renderWidget(id);
}

// ---------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------

el("btn-add-widget").addEventListener("click", () => openModal());
el("btn-cancel-widget").addEventListener("click", closeModal);
el("cfg-dataset").addEventListener("change", populateGroupByOptions);

el("btn-confirm-widget").addEventListener("click", () => {
  const config = readConfigFromModal();
  if (editingWidgetId) {
    widgetConfigs[editingWidgetId] = config;
    document.querySelector(`[data-edit="${editingWidgetId}"]`).textContent = config.title;
    renderWidget(editingWidgetId);
  } else {
    const id = `w${nextWidgetId++}`;
    addWidgetToGrid(id, config);
  }
  closeModal();
});

document.querySelector(".grid-stack").addEventListener("click", (evt) => {
  const removeId = evt.target.getAttribute("data-remove");
  if (removeId) { removeWidget(removeId); return; }
  const editId = evt.target.getAttribute("data-edit");
  if (editId) { openModal({ id: editId, ...widgetConfigs[editId] }); }
});

el("btn-refresh").addEventListener("click", refreshAllWidgets);
el("btn-save").addEventListener("click", () => saveDashboard().catch((e) => alert(e.message)));
el("btn-delete").addEventListener("click", () => deleteDashboard().catch((e) => alert(e.message)));
el("dashboard-select").addEventListener("change", (evt) => loadDashboard(evt.target.value || null));

(async function init() {
  dimensionsByDataset = await apiGet("/query-dimensions");
  await refreshDashboardList();
  updateEmptyState();
})();
