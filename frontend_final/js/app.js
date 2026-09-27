// js/app.js
Auth.requireAuth();
document.getElementById("sessionUser").textContent = Auth.getUsername() || "";

const MAX_FEED_ROWS = 60;
const MAX_ALERTS = 40;

let events = [];
let alerts = [];
let severityDist = [];
let attackDist = [];
let timeline = [];
let focusedUser = null;
let feedSearchTerm = "";
let alertSearchTerm = "";
let streaming = true;
let eventsPerSecond = 4;

const SEV_COLOR = { LOW: "#3ea86b", MEDIUM: "#e0a83f", HIGH: "#e0703f", CRITICAL: "#ef4a5c" };

function timeOnly(ts) {
  if (!ts) return "";
  const d = new Date(String(ts).replace(" ", "T"));
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString([], { hour12: false });
}
function esc(s) {
  const div = document.createElement("div");
  div.textContent = s == null ? "" : String(s);
  return div.innerHTML;
}

function renderFeed() {
  let rows = events;
  if (focusedUser) rows = rows.filter((e) => e.user === focusedUser || e.source_ip === focusedUser);
  if (feedSearchTerm.trim()) {
    const q = feedSearchTerm.toLowerCase();
    rows = rows.filter(
      (e) =>
        (e.user || "").toLowerCase().includes(q) ||
        (e.source_ip || "").toLowerCase().includes(q) ||
        (e.threat_category || "").toLowerCase().includes(q) ||
        (e.predicted_attack_type || "").toLowerCase().includes(q)
    );
  }
  document.getElementById("feedCount").textContent = `${rows.length} shown${focusedUser ? " · filtered: " + focusedUser : ""}`;
  document.getElementById("clearFocusBtn").style.display = focusedUser ? "inline-block" : "none";

  const tbody = document.getElementById("feedBody");
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state">${events.length === 0 ? "Waiting for events…" : "No events match this filter."}</div></td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map((e) => {
      const entity = e.user !== "unknown" ? e.user : e.source_ip;
      return `<tr>
        <td class="mono">${esc(timeOnly(e.timestamp))}</td>
        <td>${esc(e.log_source)}</td>
        <td class="mono user-link" data-entity="${esc(entity)}">${esc(entity)}</td>
        <td>${esc(e.predicted_attack_type !== "none" ? e.predicted_attack_type : e.event_type)}</td>
        <td class="mono">${Math.round(e.risk_score ?? 0)}</td>
        <td><span class="badge ${esc(e.severity)}">${esc(e.severity)}</span></td>
        <td>${esc(e.threat_category)}</td>
      </tr>`;
    })
    .join("");

  tbody.querySelectorAll(".user-link").forEach((el) => {
    el.addEventListener("click", () => {
      focusedUser = el.dataset.entity;
      renderFeed();
    });
  });
}

function renderAlerts() {
  let rows = alerts;
  if (alertSearchTerm.trim()) {
    const q = alertSearchTerm.toLowerCase();
    rows = rows.filter(
      (a) =>
        (a.user || "").toLowerCase().includes(q) ||
        (a.source_ip || "").toLowerCase().includes(q) ||
        (a.threat_category || "").toLowerCase().includes(q)
    );
  }
  document.getElementById("alertCount").textContent = rows.length;
  const list = document.getElementById("alertsList");
  if (rows.length === 0) {
    list.innerHTML = `<div class="empty-state">${alerts.length === 0 ? "No alerts yet — the correlation engine surfaces one once an incident crosses the risk threshold." : "No alerts match this search."}</div>`;
    return;
  }
  list.innerHTML = rows
    .map(
      (a, i) => `<div class="alert-item" data-idx="${i}" data-id="${esc(a.alert_id)}">
        <div class="alert-top">
          <span class="alert-id">${esc(a.alert_id)}</span>
          <span class="alert-risk" style="color:${SEV_COLOR[a.severity] || "#e7ebf0"}">${Math.round(a.risk_score)}</span>
        </div>
        <div class="alert-category">${esc(a.threat_category)}</div>
        <div class="alert-meta">${esc(a.user && a.user !== "N/A" ? a.user : a.source_ip)} · ${esc(timeOnly(a.timestamp))}</div>
        <div style="margin-top:6px;display:flex;gap:6px;align-items:center">
          <span class="badge ${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="badge" style="color:#8b96a5;background:transparent;border:1px solid #23293155">${esc((a.status || "OPEN").replace("_", " "))}</span>
        </div>
      </div>`
    )
    .join("");

  list.querySelectorAll(".alert-item").forEach((el) => {
    el.addEventListener("click", () => openDrawer(rows[Number(el.dataset.idx)]));
  });
}

function openDrawer(alert) {
  let explanation = [];
  try { explanation = JSON.parse(alert.explanation || "[]"); } catch (e) {}
  let mitre = null;
  try { mitre = alert.mitre_technique ? JSON.parse(alert.mitre_technique) : null; } catch (e) {}

  const explainHtml = explanation.length
    ? `<div class="drawer-field"><div class="drawer-field-label">Why Flagged</div><div>${explanation
        .map((ex) => `<span class="explain-chip">${esc(ex.label)}: ${esc(ex.value)}</span>`)
        .join("")}</div></div>`
    : "";
  const mitreBadge = mitre
    ? `<span class="badge" style="color:#8b96a5;background:transparent;border:1px solid #232b37">${esc(mitre.technique_id)} · ${esc(mitre.technique).toUpperCase()}</span>`
    : "";
  const mitreField = mitre
    ? `<div class="drawer-field"><div class="drawer-field-label">MITRE ATT&amp;CK</div><div class="drawer-field-value">${esc(mitre.tactic)} → ${esc(mitre.technique_id)} (${esc(mitre.technique)})</div></div>`
    : "";

  const drawer = document.getElementById("drawerContent");
  drawer.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:flex-start">
      <div>
        <h3>${esc(alert.threat_category)}</h3>
        <div style="margin-top:6px;display:flex;gap:6px">
          <span class="badge ${esc(alert.severity)}">${esc(alert.severity)}</span>
          ${mitreBadge}
        </div>
      </div>
      <button class="close-x" id="drawerClose">&times;</button>
    </div>
    <div class="drawer-field"><div class="drawer-field-label">Alert / Incident ID</div><div class="drawer-field-value">${esc(alert.alert_id)} · ${esc(alert.incident_id)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Risk Score</div><div class="drawer-field-value">${esc(alert.risk_score)} / 100</div></div>
    <div class="drawer-field"><div class="drawer-field-label">User</div><div class="drawer-field-value">${esc(alert.user)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Source IP(s)</div><div class="drawer-field-value">${esc(alert.source_ip || "—")}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Detected At</div><div class="drawer-field-value">${esc(alert.timestamp)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Correlated Events</div><div class="drawer-field-value">${esc(alert.correlated_events)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Evidence / Event Chain</div><div class="drawer-field-value">${esc(alert.evidence)}</div></div>
    ${mitreField}
    ${explainHtml}
    <div class="drawer-field"><div class="drawer-field-label">Simulated Response</div><div class="drawer-field-value">${esc(alert.response_actions)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Response Status</div><div class="drawer-field-value">${esc(alert.response_status)}</div></div>
    <div class="drawer-field">
      <div class="drawer-field-label">Investigation Status</div>
      <select class="status-select" id="drawerStatus">
        ${["OPEN", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"]
          .map((s) => `<option value="${s}" ${s === (alert.status || "OPEN") ? "selected" : ""}>${s.replace("_", " ")}</option>`)
          .join("")}
      </select>
      <textarea class="notes-textarea" id="drawerNotes" placeholder="Analyst notes...">${esc(alert.analyst_notes || "")}</textarea>
      <button class="btn primary" style="width:100%;margin-top:8px" id="drawerSave">Save</button>
    </div>
  `;
  document.getElementById("drawerOverlay").style.display = "flex";
  document.getElementById("drawerClose").addEventListener("click", closeDrawer);
  document.getElementById("drawerSave").addEventListener("click", async () => {
    const btn = document.getElementById("drawerSave");
    const status = document.getElementById("drawerStatus").value;
    const notes = document.getElementById("drawerNotes").value;
    btn.disabled = true;
    btn.textContent = "Saving…";
    try {
      await Api.updateAlert(alert.alert_id, { status, analyst_notes: notes });
      const target = alerts.find((a) => a.alert_id === alert.alert_id);
      if (target) { target.status = status; target.analyst_notes = notes; }
      renderAlerts();
      btn.textContent = "Saved";
    } catch (e) {
      btn.textContent = "Save";
    } finally {
      btn.disabled = false;
    }
  });
}
function closeDrawer() {
  document.getElementById("drawerOverlay").style.display = "none";
}
document.getElementById("drawerOverlay").addEventListener("click", (e) => {
  if (e.target.id === "drawerOverlay") closeDrawer();
});

let riskChart, severityChart, attackChart;
const chartFont = { color: "#8b96a5", font: { family: "JetBrains Mono, monospace", size: 10 } };

function initCharts() {
  riskChart = new Chart(document.getElementById("riskChart"), {
    type: "line",
    data: { labels: [], datasets: [{ label: "Avg Risk", data: [], borderColor: "#35d0c2", backgroundColor: "transparent", tension: 0.3, pointRadius: 0 }] },
    options: {
      plugins: { legend: { display: false } },
      scales: { x: { ticks: chartFont, grid: { color: "#1b212b" } }, y: { min: 0, max: 100, ticks: chartFont, grid: { color: "#1b212b" } } },
    },
  });
  severityChart = new Chart(document.getElementById("severityChart"), {
    type: "bar",
    data: { labels: ["LOW", "MEDIUM", "HIGH", "CRITICAL"], datasets: [{ data: [0, 0, 0, 0], backgroundColor: ["#3ea86b", "#e0a83f", "#e0703f", "#ef4a5c"] }] },
    options: { plugins: { legend: { display: false } }, scales: { x: { ticks: chartFont, grid: { display: false } }, y: { ticks: chartFont, grid: { color: "#1b212b" } } } },
  });
  attackChart = new Chart(document.getElementById("attackChart"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: ["#35d0c2", "#e0a83f", "#e0703f", "#ef4a5c", "#7c8cf8", "#3ea86b", "#c084fc"] }] },
    options: { plugins: { legend: { position: "bottom", labels: { color: "#8b96a5", font: { size: 10 } } } } },
  });
}

function updateCharts() {
  if (!riskChart || !severityChart || !attackChart) return; // charts unavailable, skip gracefully
  const order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  severityChart.data.datasets[0].data = order.map((s) => severityDist.find((d) => d.severity === s)?.count || 0);
  severityChart.update();

  attackChart.data.labels = attackDist.map((d) => d.predicted_attack_type);
  attackChart.data.datasets[0].data = attackDist.map((d) => d.count);
  attackChart.update();

  riskChart.data.labels = timeline.map((d) => String(d.bucket).slice(11, 16));
  riskChart.data.datasets[0].data = timeline.map((d) => d.avg_risk);
  riskChart.update();
}

function renderKpis(stats) {
  document.getElementById("kpiEvents").textContent = (stats.total_events ?? 0).toLocaleString();
  document.getElementById("kpiAnomalies").textContent = (stats.total_anomalies ?? 0).toLocaleString();
  document.getElementById("kpiAttacks").textContent = (stats.total_attacks ?? 0).toLocaleString();
  document.getElementById("kpiCritical").textContent = (stats.total_critical ?? 0).toLocaleString();
  document.getElementById("kpiIncidents").textContent = (stats.open_incidents ?? 0).toLocaleString();
}

async function loadInitial() {
  try {
    const [stats, ev, al, sd, ad, tl, status, settings] = await Promise.all([
      Api.getStats(), Api.getEvents({ limit: MAX_FEED_ROWS }), Api.getAlerts({ limit: MAX_ALERTS }),
      Api.getSeverityDistribution(), Api.getAttackDistribution(), Api.getTimeline(),
      Api.streamStatus(), Api.getSettings(),
    ]);
    renderKpis(stats);
    events = ev; renderFeed();
    alerts = al; renderAlerts();
    severityDist = sd; attackDist = ad; timeline = tl; updateCharts();
    streaming = status.running;
    eventsPerSecond = Math.round(status.events_per_second || 4);
    document.getElementById("rateSlider").value = eventsPerSecond;
    document.getElementById("rateValue").textContent = `${eventsPerSecond}/s`;
    updateStreamButton();
    document.getElementById("settingAlertThreshold").value = settings.alert_threshold;
    document.getElementById("settingCorrelationThreshold").value = settings.correlation_signal_threshold;
  } catch (e) {
    console.error("initial load failed", e);
  }
}

function refreshCharts() {
  Promise.all([Api.getSeverityDistribution(), Api.getAttackDistribution(), Api.getTimeline()])
    .then(([sd, ad, tl]) => { severityDist = sd; attackDist = ad; timeline = tl; updateCharts(); })
    .catch(() => {});
}
setInterval(refreshCharts, 10000);

LiveSocket.onStatusChange((connected) => {
  document.getElementById("connDot").className = connected ? "dot" : "dot off";
  document.getElementById("connLabel").textContent = connected ? "LIVE" : "DISCONNECTED";
});
LiveSocket.onMessage((msg) => {
  if (msg.type === "event") {
    if (!events.length || events[0].event_id !== msg.data.event_id) {
      events = [msg.data, ...events].slice(0, MAX_FEED_ROWS);
      renderFeed();
    }
  } else if (msg.type === "alert") {
    if (!alerts.some((a) => a.alert_id === msg.data.alert_id)) {
      alerts = [msg.data, ...alerts].slice(0, MAX_ALERTS);
      renderAlerts();
    }
  } else if (msg.type === "stats") {
    renderKpis(msg.data);
  }
});
LiveSocket.connect();

document.getElementById("feedSearch").addEventListener("input", (e) => { feedSearchTerm = e.target.value; renderFeed(); });
document.getElementById("alertSearch").addEventListener("input", (e) => { alertSearchTerm = e.target.value; renderAlerts(); });
document.getElementById("clearFocusBtn").addEventListener("click", () => { focusedUser = null; renderFeed(); });
document.getElementById("exportEventsBtn").addEventListener("click", () => Api.exportEventsCsv({ search: feedSearchTerm || undefined }));
document.getElementById("exportAlertsBtn").addEventListener("click", () => Api.exportAlertsCsv({ search: alertSearchTerm || undefined }));
document.getElementById("logoutBtn").addEventListener("click", () => Auth.logout());

function updateStreamButton() {
  const btn = document.getElementById("streamToggle");
  btn.textContent = streaming ? "■ Stop Feed" : "▶ Start Feed";
  btn.className = `btn ${streaming ? "danger" : "primary"}`;
}
document.getElementById("streamToggle").addEventListener("click", async () => {
  if (streaming) { await Api.streamStop(); streaming = false; } else { await Api.streamStart(); streaming = true; }
  updateStreamButton();
});
document.getElementById("rateSlider").addEventListener("change", async (e) => {
  const val = Number(e.target.value);
  eventsPerSecond = val;
  document.getElementById("rateValue").textContent = `${val}/s`;
  try { await Api.streamSpeed(val); } catch (e) {}
});
document.getElementById("saveSettingsBtn").addEventListener("click", async (e) => {
  const btn = e.target;
  const alert_threshold = Number(document.getElementById("settingAlertThreshold").value);
  const correlation_signal_threshold = Number(document.getElementById("settingCorrelationThreshold").value);
  btn.textContent = "Saving…";
  try {
    await Api.updateSettings({ alert_threshold, correlation_signal_threshold });
    btn.textContent = "✓ Saved";
    setTimeout(() => (btn.textContent = "Save Settings"), 1500);
  } catch (e) {
    btn.textContent = "Save Settings";
  }
});

// Charts are a nice-to-have visualization; a failure there (e.g. Chart.js
// not loading for any reason) must never block the critical data load
// below (feed, alerts, settings) — hence the try/catch and the ordering:
// loadInitial() runs regardless of chart init success.
try {
  initCharts();
} catch (e) {
  console.error("chart init failed, dashboard will run without charts:", e);
}
loadInitial();
