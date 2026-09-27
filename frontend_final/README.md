# Sentinel Dashboard — Plain HTML/CSS/JS Frontend

No React, no npm, no build step. Pure HTML/CSS/vanilla JS, talking to the
same FastAPI backend as before.

## Run

1. Start the backend (see the backend package's own README):
   `uvicorn backend.app.main:app --port 8000`
2. Serve this folder with any static file server, e.g.:
   `python3 -m http.server 8080`
3. Open `http://localhost:8080/login.html` — admin / admin123

If your backend runs somewhere other than `localhost:8000`, edit
`js/config.js`.

## Structure
- `login.html`, `index.html` — the two pages
- `css/styles.css` — same dark SOC-console design as before
- `js/config.js` — backend URL
- `js/auth.js` — login/logout, token storage
- `js/api.js` — REST calls
- `js/ws.js` — WebSocket client
- `js/app.js` — all dashboard rendering/interaction logic
- `js/vendor/chart.umd.js` — Chart.js, vendored locally (no CDN dependency)
