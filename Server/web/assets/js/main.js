// Perimeter 13 dashboard: sign-in, the live feed, the menu and the two views,
// and drawing each part of the page.

import { $, $$, clockTime } from "./dom.js";
import { api, live } from "./api.js";
import { posture } from "./posture.js";
import { flashZone, renderPlan } from "./plan.js";
import { renderUnits } from "./units.js";
import { initControl, renderControl } from "./control.js";
import { addEvent, initLog, setEvents } from "./log.js";
import { renderIntegrity } from "./integrity.js";
import { alarmActive, alertForEvent, initAlerts, unlockAudio, updateAlerts } from "./alerts.js";

const state = { link: null, nodes: { G: {}, A: {}, B: {}, C: {}, D: {} }, control: null, session: null,
                events: [], audit: [], rejects: {}, view: "overview" };
let feed = null;
let frame = 0;

const NOTICES = {
  emulator: "Emulated gateway: no hardware is connected. Everything on this page comes from a test program on the server.",
  wokwi: "Wokwi simulator over a public MQTT broker. Packets are signed, but anyone can read them.",
};
const VIEWS = { overview: "Overview", log: "Log" };

function render() {
  frame = 0;
  const p = posture(state);
  const title = $("#statement");
  title.textContent = p.title;
  title.dataset.level = p.level;
  $("#statement-detail").textContent = p.detail;
  document.title = p.level === "alarm" ? `${p.title} Perimeter 13` : "Perimeter 13";
  updateAlerts(state);
  const alarm = p.level === "alarm";
  $("#log-badge").hidden = !alarm;
  $("#menu-dot").hidden = !alarm;
  if (state.view === "overview") { renderPlan(state); renderControl(state); }
  else { renderUnits(state); renderIntegrity(state); }
  const mode = state.link && state.link.mode;
  $("#notice").hidden = !NOTICES[mode];
  $("#notice").textContent = NOTICES[mode] || "";
  $("#site").textContent = state.link ? `Site ${state.link.site}` : "";
  $("#drawer-foot").textContent = state.link ? `Server ${state.link.version} · ${{ hardware: "gateway over MQTT/TLS", wokwi: "Wokwi", emulator: "emulated gateway" }[mode] || mode}` : "";
}
const soon = () => { if (!frame) frame = requestAnimationFrame(render); };

// ---------------------------------------------------------------- views + menu
function setView(view, focus = false) {
  if (!VIEWS[view]) view = "overview";
  state.view = view;
  document.body.dataset.view = view;
  $("#view-name").textContent = VIEWS[view];
  for (const b of $$(".nav-item[data-view]")) {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  }
  try { localStorage.setItem("p13.view", view); } catch { /* not kept */ }
  if (location.hash !== `#${view}`) history.replaceState(null, "", `#${view}`);
  render();
  if (focus) $("#statement").focus({ preventScroll: true });
}

function openMenu(open) {
  const d = $("#drawer");
  d.classList.toggle("open", open);
  d.setAttribute("aria-hidden", String(!open));
  d.inert = !open;
  $("#scrim").hidden = !open;
  $("#menu-button").setAttribute("aria-expanded", String(open));
  document.body.classList.toggle("menu-open", open);
  if (open) (d.querySelector('[aria-current="page"]') || d.querySelector("button")).focus();
  else $("#menu-button").focus({ preventScroll: true });
}

$("#menu-button").addEventListener("click", () => openMenu(true));
$("#menu-close").addEventListener("click", () => openMenu(false));
$("#scrim").addEventListener("click", () => openMenu(false));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && $("#drawer").classList.contains("open")) openMenu(false);
});
for (const b of $$(".nav-item[data-view]")) {
  b.addEventListener("click", () => { setView(b.dataset.view, true); openMenu(false); });
}
window.addEventListener("hashchange", () => setView(location.hash.slice(1)));

// ---------------------------------------------------------------- the feed
function onMessage(msg) {
  const d = msg.data;
  switch (msg.type) {
    case "snapshot":
      Object.assign(state, { link: d.link, nodes: { ...state.nodes, ...d.nodes }, control: d.control, session: d.session,
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
      showWho();
      break;
    case "event":
      state.events.unshift(d);
      if (state.events.length > 600) state.events.length = 600;
      addEvent(d);
      if (state.view === "overview") flashZone(d);
      alertForEvent(d);
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
  const signed = !!(s && s.signed_in);
  $("#drawer-who").textContent = !signed ? "" :
    `Signed in as ${s.user}, ${s.role === "MAINTENANCE" ? "maintenance" : "operator"} role${s.control ? ", in control." : ", view only."}`;
  $("#sign-out").hidden = !signed;
}

function showConsole(session) {
  state.session = session;
  $("#gate").hidden = true;
  $("#console").hidden = false;
  $("#menu-button").hidden = false;
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
  openMenu(false);
  $("#console").hidden = true;
  $("#menu-button").hidden = true;
  $("#gate").hidden = false;
  $("#siren-bar").hidden = true;
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
  unlockAudio();                                  // a click: the siren may sound later
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

initControl(() => state, (s) => { state.session = s; showWho(); soon(); });
initLog(() => state);
initAlerts(() => state);

let saved = "overview";
try { saved = localStorage.getItem("p13.view") || saved; } catch { /* default */ }
setView(VIEWS[location.hash.slice(1)] ? location.hash.slice(1) : saved);

const tick = () => {
  $("#clock").textContent = clockTime();
  if (alarmActive()) document.title = (Math.floor(Date.now() / 1000) % 2) ? "!! INTRUSION !! Perimeter 13" : posture(state).title;
};
tick();
setInterval(tick, 1000);
setInterval(soon, 15000);          // relative times ("4 min ago") stay current

api("GET", "/api/session").then((s) => (s.signed_in ? showConsole(s) : showGate()))
  .catch(() => showGate("The server isn't answering. Reload in a moment."));
