// js/api.js
const Api = (() => {
  const BASE = () => window.SENTINEL_CONFIG.API_BASE;

  function authHeaders(extra = {}) {
    const token = Auth.getToken();
    return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
  }

  function toQuery(params) {
    const clean = Object.entries(params || {}).filter(
      ([, v]) => v !== undefined && v !== null && v !== ""
    );
    if (!clean.length) return "";
    return "?" + new URLSearchParams(clean).toString();
  }

  async function handle401(res) {
    if (res.status === 401) {
      Auth.logout();
      throw new Error("Session expired");
    }
    return res;
  }

  async function get(path, params) {
    const res = await fetch(`${BASE()}/api${path}${toQuery(params)}`, {
      headers: authHeaders(),
    });
    await handle401(res);
    if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
    return res.json();
  }

  async function post(path, body) {
    const res = await fetch(`${BASE()}/api${path}`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: body ? JSON.stringify(body) : undefined,
    });
    await handle401(res);
    if (!res.ok) throw new Error(`POST ${path} failed: ${res.status}`);
    return res.json();
  }

  async function patch(path, body) {
    const res = await fetch(`${BASE()}/api${path}`, {
      method: "PATCH",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    await handle401(res);
    if (!res.ok) throw new Error(`PATCH ${path} failed: ${res.status}`);
    return res.json();
  }

  async function downloadCsv(path, params, filenamePrefix) {
    const res = await fetch(`${BASE()}/api${path}${toQuery(params)}`, {
      headers: authHeaders(),
    });
    await handle401(res);
    if (!res.ok) throw new Error(`Export failed: ${res.status}`);
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${filenamePrefix}_${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  return {
    getEvents: (params) => get("/events", params),
    getAlerts: (params) => get("/alerts", params),
    getIncidents: (limit = 100) => get("/incidents", { limit }),
    getOpenIncidents: () => get("/incidents/open"),
    getStats: () => get("/stats"),
    getSeverityDistribution: () => get("/stats/severity-distribution"),
    getAttackDistribution: () => get("/stats/attack-distribution"),
    getTimeline: () => get("/stats/timeline"),
    streamStatus: () => get("/stream/status"),
    streamStart: () => post("/stream/start"),
    streamStop: () => post("/stream/stop"),
    streamSpeed: (events_per_second) => post("/stream/speed", { events_per_second }),
    updateAlert: (alertId, payload) => patch(`/alerts/${alertId}`, payload),
    exportAlertsCsv: (params) => downloadCsv("/alerts/export.csv", params, "alerts_export"),
    exportEventsCsv: (params) => downloadCsv("/events/export.csv", params, "events_export"),
    getSettings: () => get("/settings"),
    updateSettings: (payload) => patch("/settings", payload),
    getUserSummary: (entity) => get(`/users/${encodeURIComponent(entity)}/summary`),
  };
})();
