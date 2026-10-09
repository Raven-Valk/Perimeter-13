// The server's JSON API and the live WebSocket feed.

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || `The server answered ${res.status}`);
  return data;
}

/** Keeps a WebSocket to /ws open; reconnects with backoff. */
export function live({ onMessage, onState, onSignedOut }) {
  let ws = null, delay = 1000, stopped = false;
  const open = () => {
    onState("connecting");
    ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
    ws.onopen = () => { delay = 1000; onState("live"); };
    ws.onmessage = (ev) => {
      try { onMessage(JSON.parse(ev.data)); } catch (err) { console.error("bad message", err); }
    };
    ws.onclose = (ev) => {
      if (stopped) return;
      if (ev.code === 4401 || ev.code === 1008) { onSignedOut(); return; }
      onState("lost");
      setTimeout(async () => {
        try {                                    // a 401 here means the sign-in expired
          const s = await api("GET", "/api/session");
          if (!s.signed_in) { onSignedOut(); return; }
        } catch { /* server down: keep trying */ }
        open();
      }, delay);
      delay = Math.min(delay * 2, 15000);
    };
  };
  open();
  return { close() { stopped = true; if (ws) ws.close(); } };
}
