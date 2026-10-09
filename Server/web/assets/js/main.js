// Perimeter 13 dashboard: sign-in, the live feed, and drawing each part of the page.

import { $, clockTime } from "./dom.js";
import { api, live } from "./api.js";
import { posture } from "./posture.js";
import { flashZone, renderPlan } from "./plan.js";
import { renderUnits } from "./units.js";
import { initControl, renderControl } from "./control.js";
import { addEvent, initLog, setEvents } from "./log.js";
import { renderIntegrity } from "./integrity.js";

const state = { link: null, nodes: { G: {}, A: {}, B: {} }, control: null, session: null, events: [], audit: [], rejects: {} };
let feed = null;
let frame = 0;

const NOTICES = {
  emulator: "Emulated gateway: no hardware is connected. Everything on this page comes from a test program on the server.",
  wokwi: "Wokwi simulator over a public MQTT broker. Packets are signed, but anyone can read them.",
};

function render() {
  frame = 0;
  const p = posture(state);
  const title = $("#statement");
  title.textContent = p.title;
  title.dataset.level = p.level;
  $("#statement-detail").textContent = p.detail;
  document.title = p.level === "alarm" ? `${p.title} Perimeter 13` : "Perimeter 13";
  renderPlan(state);
  renderUnits(state);
  renderControl(state);
  renderIntegrity(state);
  const mode = state.link && state.link.mode;
  $("#notice").hidden = !NOTICES[mode];
  $("#notice").textContent = NOTICES[mode] || "";
  $("#site").textContent = state.link ? `Site ${state.link.site}` : "";
}
const soon = () => { if (!frame) frame = requestAnimationFrame(render); };

function onMessage(msg) {
  const d = msg.data;
  switch (msg.type) {
    case "snapshot":
      Object.assign(state, { link: d.link, nodes: d.nodes, control: d.control, session: d.session,
                             events: d.events, audit: d.audit, rejects: d.link.rejected || {} });
      setEvents(state.events);
      showWho();
      break;
    case "node":
      state.nodes[d.node] = d;
      break;
    case "link":
      state.link = d;
      break;
    case "control":
      state.control = d.control;
      state.session = d.session;
      break;
    case "event":
      state.events.unshift(d);
      if (state.events.length > 600) state.events.length = 600;
      addEvent(d);
      flashZone(d);
      break;
    case "audit":
      state.audit.unshift(d);
      if (state.audit.length > 60) state.audit.length = 60;
      break;
    case "rejects":
      state.rejects = d;
      break;
    case "command":
      break;
  }
  soon();
}

function showWho() {
  const s = state.session;
  $("#who").hidden = !s || !s.signed_in;
  $("#who-name").textContent = s && s.signed_in ? s.user : "";
}

function showConsole(session) {
  state.session = session;
  $("#gate").hidden = true;
  $("#console").hidden = false;
  showWho();
  if (!feed) {
    feed = live({
      onMessage,
      onState: (s) => {
        const el = $("#feed");
        el.dataset.state = s;
        el.textContent = { live: "Live", connecting: "Connecting", lost: "Reconnecting" }[s];
      },
      onSignedOut: () => showGate("Your sign-in ended. Sign in again."),
    });
  }
  render();
}

function showGate(message = "") {
  if (feed) { feed.close(); feed = null; }
  state.session = null;
  $("#console").hidden = true;
  $("#who").hidden = true;
  $("#gate").hidden = false;
  const out = $("#sign-in-result");
  out.textContent = message;
  out.dataset.tone = message ? "bad" : "";
  api("GET", "/api/session").then((s) => {
    $("#gate-status").textContent = s.gateway_online ? "The gateway is online."
      : "The gateway is offline: only accounts that signed in here before can sign in, to view.";
    $("#notice").hidden = !NOTICES[s.mode];
    $("#notice").textContent = NOTICES[s.mode] || "";
  }).catch(() => { $("#gate-status").textContent = "The server isn't answering."; });
  $("#user").focus();
}

$("#sign-in").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#sign-in-result");
  const btn = ev.submitter || $("#sign-in button");
  out.textContent = "Checking with the gateway…";
  out.dataset.tone = "busy";
  btn.disabled = true;
  try {
    const s = await api("POST", "/api/session", { user: $("#user").value.trim(), password: $("#password").value });
    $("#password").value = "";
    out.textContent = "";
    showConsole(s);
  } catch (err) {
    out.textContent = err.message;
    out.dataset.tone = "bad";
  } finally {
    btn.disabled = false;
  }
});

$("#sign-out").addEventListener("click", async () => {
  try { await api("DELETE", "/api/session"); } catch { /* already gone */ }
  showGate();
});

initControl(() => state, (s) => { state.session = s; soon(); });
initLog(() => state);

const tick = () => { $("#clock").textContent = clockTime(); };
tick();
setInterval(tick, 1000);
setInterval(soon, 15000);          // relative times ("4 min ago") stay current

api("GET", "/api/session").then((s) => (s.signed_in ? showConsole(s) : showGate()))
  .catch(() => showGate("The server isn't answering. Reload in a moment."));
