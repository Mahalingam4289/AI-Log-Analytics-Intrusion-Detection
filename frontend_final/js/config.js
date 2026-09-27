// js/config.js
// Point this at wherever the FastAPI backend is running. Since this is a
// plain static frontend (no build step, no dev-server proxy), every
// request needs an absolute URL — CORS on the backend (already configured
// with allow_origins=["*"]) is what makes cross-origin calls from a static
// file server work.
window.SENTINEL_CONFIG = {
  API_BASE: "http://localhost:8000",
};
