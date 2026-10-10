// Updates the plan drawing: unit states, PIR curtains, walls in alarm, buzzers,
// the ten radio links of the mesh (and the way round when one is relayed),
// the server link and the title block.

import { $, eventTime } from "./dom.js";
import { alarmZones, moduleState, MODULES, sounding, zonesIn } from "./posture.js";
import { linkName, meshLinks, meshSummary, PAIRS, short } from "./mesh.js";

const SVG = "http://www.w3.org/2000/svg";
const UNIT = {
  ARMED: ["armed", "Armed"], DISARMED: ["disarmed", "Disarmed"], INTRUSION: ["intrusion", "Intrusion"],
  TAMPER_FAULT: ["tamper", "Tamper"], MAINTENANCE: ["maintenance", "Maintenance"],
  BOOT: ["starting", "Starting"], RECOVERY: ["starting", "Self-test"], offline: ["offline", "Not reporting"],
  unknown: ["unknown", "—"],
};
const GATEWAY = { READY: ["armed", "Ready"], GW_TAMPER: ["tamper", "Lid open"], BOOT: ["starting", "Starting"] };
const PIRS = ["A-Z2", "B-Z2", "A-Z1", "D-Z1", "B-Z3", "C-Z3"];
const PIR_NAME = /[A-D]-Z[1-3]/g;
const WARN_FOR = 20;                         // seconds a single trigger stays a warning (CORROBORATION_MS)

// Box centres, and the path each link is drawn along (diagonals curve round the gateway)
const AT = { A: [230, 154], B: [770, 154], C: [770, 476], D: [230, 476], G: [500, 315] };
const CURVE = { "A-C": [610, 205], "B-D": [390, 205] };

let built = false;
const paths = {};

function el(tag, attrs) {
  const e = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

function buildMesh() {
  const g = $("#mesh");
  const routes = el("g", { class: "routes" });
  const lines = el("g", { class: "lines" });
  const labels = el("g", { class: "labels" });
  for (const [a, b] of PAIRS) {
    const key = `${a}-${b}`;
    const [x1, y1] = AT[a], [x2, y2] = AT[b];
    const c = CURVE[key];
    const d = c ? `M${x1} ${y1} Q${c[0]} ${c[1]} ${x2} ${y2}` : `M${x1} ${y1} L${x2} ${y2}`;
    const line = el("path", { d, class: "radio", id: `link-${key}` });
    const route = el("path", { d: "", class: "route", id: `route-${key}` });
    const label = el("text", { class: "link-label", id: `label-${key}` });
    lines.append(line);
    routes.append(route);
    labels.append(label);
    paths[key] = { line, route, label };
  }
  g.append(lines, routes, labels);
  built = true;
}

function placeLabel(p, text) {
  if (!text) { p.label.textContent = ""; return; }
  const len = p.line.getTotalLength();
  const at = p.line.getPointAtLength(len / 2);
  p.label.setAttribute("x", at.x.toFixed(1));
  p.label.setAttribute("y", (at.y - 6).toFixed(1));
  p.label.textContent = text;
}

/** The way round: from one end, through the relay, to the other end. */
function routePath(a, via, b) {
  const [x1, y1] = AT[a], [x2, y2] = AT[via], [x3, y3] = AT[b];
  return `M${x1} ${y1} L${x2} ${y2} L${x3} ${y3}`;
}

export function renderPlan(st) {
  if (!built) buildMesh();
  const { nodes, link, events } = st;
  const now = Date.now() / 1000;
  const gw = !!(link && link.gateway);

  for (const k of MODULES) {
    const s = moduleState(nodes[k]);
    const [cls, label] = UNIT[s] || UNIT.unknown;
    $(`#unit-${k}`).dataset.state = gw ? cls : "unknown";
    $(`#unit-${k}-state`).textContent = gw ? label : "—";
  }
  const g = nodes.G || {};
  const [gcls, glabel] = !gw ? UNIT.offline : GATEWAY[g.state] || UNIT.unknown;
  $("#unit-G").dataset.state = gcls;
  $("#unit-G-state").textContent = glabel;

  // Zones in alarm (from the modules' ALM fields), PIRs with a recent single trigger
  const alarm = gw ? alarmZones(nodes) : [];
  const warn = new Set();
  for (const k of MODULES) {
    const n = nodes[k] || {};
    if (moduleState(n) === "ARMED") zonesIn(n.HIT).forEach((z) => warn.add(`${k}-Z${z}`));
  }
  for (const e of events) {
    const t = eventTime(e);
    if (now - t > WARN_FOR) break;
    if (e.type === "ALERT" && e.priority === 1) (`${e.event} ${e.zone || ""}`.match(PIR_NAME) || []).forEach((z) => warn.add(z));
  }

  for (const p of PIRS) {
    const k = p[0], zone = Number(p.slice(-1));
    const n = nodes[k] || {};
    const s = gw ? moduleState(n) : "unknown";
    const health = n[`Z${zone}`] || "";
    const inAlarm = alarm.includes(zone);
    let cls = "";
    if (s === "ARMED") cls = warn.has(p) ? "on warn" : "on";
    else if (s === "INTRUSION") cls = inAlarm ? "alarm" : "on";
    else if (s === "MAINTENANCE") cls = "maint";
    else if (s === "TAMPER_FAULT") cls = "fault";
    $(`#fan-${p}`).setAttribute("class", `fan ${cls}`.trim());
    $(`#tag-${p}`).setAttribute("class", ["tag", s === "INTRUSION" && inAlarm ? "alarm" : s === "ARMED" && warn.has(p) ? "warn" : "",
      health === "STUCK" || health === "OFFLINE" ? "stuck" : ""].join(" ").trim());
  }
  for (const z of [1, 2, 3]) {
    $(`#wall-z${z}`).setAttribute("class", alarm.includes(z) ? "alarm" : "");
    $(`#dim-z${z}`).setAttribute("class", alarm.includes(z) ? "alarm" : "");
  }
  const buzz = sounding(nodes, alarm);
  for (const k of ["A", "B"]) $(`#buzz-${k}`).setAttribute("class", `buzzer${buzz.includes(k) ? " on" : ""}`);

  // The mesh
  const links = meshLinks(nodes, gw);
  for (const l of links) {
    const p = paths[`${l.a}-${l.b}`];
    const cls = { direct: "up", relayed: "relayed", partial: "partial", down: "down", unknown: "" }[l.state];
    p.line.setAttribute("class", `radio ${cls}${l.test ? " test" : ""}`.trim());
    if (l.state === "relayed" && AT[l.via]) {
      p.route.setAttribute("d", routePath(l.a, l.via, l.b));
      p.route.setAttribute("class", "route on");
      placeLabel(p, `via ${short(l.via)}${l.test ? " · test" : ""}`);
    } else {
      p.route.setAttribute("d", "");
      p.route.setAttribute("class", "route");
      placeLabel(p, l.state === "down" ? "no link" : l.state === "partial" ? "one way" : "");
    }
    p.line.setAttribute("aria-label", `${linkName(l)}: ${l.state}${l.via ? ` through ${l.via}` : ""}`);
  }
  $("#link-GS").setAttribute("class", `radio wifi ${gw ? "up" : "down"}`);

  const wifi = link && link.mode === "emulator" ? "emulated link"
    : link && link.mode === "wokwi" ? "Wokwi, public broker"
    : g.WIFI && g.WIFI !== "-" ? `Wi-Fi ch ${g.CH}, ${String(g.WIFI).replace("-", "−")} dBm, TLS` : "Wi-Fi";
  $("#wifi-label").textContent = wifi;

  $("#tb-site").textContent = link ? link.site : "—";
  $("#tb-gw-boot").textContent = (link && link.gateway_boot) || "—";
  $("#tb-mesh").textContent = gw ? meshSummary(links) : "—";
  $("#tb-fw").textContent = g.FW ? `gateway ${g.FW}` : "—";
  $("#tb-link").textContent = !link ? "—" : link.mode === "hardware" ? "MQTT, TLS" : link.mode === "wokwi" ? "MQTT, public" : "emulated";
  $("#tb-ch").textContent = g.CH ? `channel ${g.CH}` : "—";
}

/** A PIR's curtain flashes once when a new alert names it. */
export function flashZone(event) {
  if (event.type !== "ALERT") return;
  const names = new Set(`${event.event} ${event.zone || ""}`.match(PIR_NAME) || []);
  for (const z of names) {
    const fan = document.getElementById(`fan-${z}`);
    if (!fan) continue;
    fan.classList.remove("flash");
    void fan.getBoundingClientRect();          // restart the animation
    fan.classList.add("flash");
  }
}
