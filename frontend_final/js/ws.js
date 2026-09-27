// js/ws.js
const LiveSocket = (() => {
  let ws = null;
  let retryTimer = null;
  let handlers = [];
  let statusHandlers = [];

  function notifyStatus(connected) {
    statusHandlers.forEach((h) => h(connected));
  }

  function connect() {
    const token = Auth.getToken();
    const httpBase = window.SENTINEL_CONFIG.API_BASE;
    const wsBase = httpBase.replace(/^http/, "ws");
    const url = `${wsBase}/ws/live${token ? `?token=${encodeURIComponent(token)}` : ""}`;

    ws = new WebSocket(url);

    ws.onopen = () => notifyStatus(true);
    ws.onclose = () => {
      notifyStatus(false);
      retryTimer = setTimeout(connect, 2000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        handlers.forEach((h) => h(msg));
      } catch (e) {
        // ignore malformed frames
      }
    };
  }

  function onMessage(handler) {
    handlers.push(handler);
  }

  function onStatusChange(handler) {
    statusHandlers.push(handler);
  }

  function stop() {
    clearTimeout(retryTimer);
    if (ws) ws.close();
  }

  return { connect, onMessage, onStatusChange, stop };
})();
