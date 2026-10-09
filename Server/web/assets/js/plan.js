// Updates the plan drawing: unit states, sensor coverage, radio links, title block.

import { $, eventTime } from "./dom.js";
import { moduleState } from "./posture.js";

const UNIT = {
  ARMED: ["armed", "Armed"], DISARMED: ["disarmed", "Disarmed"], INTRUSION: ["intrusion", "Intrusion"],
  TAMPER_FAULT: ["tamper", "Tamper / fault"], MAINTENANCE: ["maintenance", "Maintenance"],
  BOOT: ["starting", "Starting"], RECOVERY: ["starting", "Self-test"], offline: ["offline", "Not reporting"],
  unknown: ["unknown", "—"],
};
const GATEWAY = { READY: ["armed", "Ready"], GW_TAMPER: ["tamper", "Lid open"], BOOT: ["starting", "Starting"] };
const ZONES = ["A-WALL", "B-WALL", "A-SIDE", "B-SIDE"];
const WARN_FOR = 20;                        // seconds a single trigger stays a warning (CORROBORATION_MS)

export function renderPlan(st) {
  const { nodes, link, events } = st;
  const now = Date.now() / 1000;

  for (const k of ["A", "B"]) {
    const s = moduleState(nodes[k]);
    const [cls, label] = UNIT[s] || UNIT.unknown;
    $(`#unit-${k}`).dataset.state = cls;
    $(`#unit-${k}-state`).textContent = label;
  }
  const g = nodes.G || {};
  const [gcls, glabel] = !link || !link.gateway ? UNIT.offline : GATEWAY[g.state] || UNIT.unknown;
  $("#unit-G").dataset.state = gcls;
  $("#unit-G-state").textContent = glabel;

  // Which zones were named in this alarm, and which fired recently
  const alarmZones = new Set();
  const warnZones = new Set();
  for (const e of events) {
    const t = eventTime(e);
    if (now - t > 900) break;
    if (e.type !== "ALERT") continue;
    const named = (e.event.match(/[AB]-(WALL|SIDE)/g) || []).concat(e.zone && e.zone !== "-" ? [e.zone] : []);
    if (e.priority >= 2) named.forEach((z) => alarmZones.add(z));
    else if (e.priority === 1 && now - t < WARN_FOR) named.forEach((z) => warnZones.add(z));
  }

  for (const z of ZONES) {
    const k = z[0];
    const n = nodes[k] || {};
    const s = moduleState(n);
    const health = n[z.slice(2)] || "";        // WALL / SIDE: OK, WARMUP, STUCK, OFFLINE
    let cls = "";
    if (s === "ARMED") cls = warnZones.has(z) ? "on warn" : "on";
    else if (s === "INTRUSION") cls = alarmZones.has(z) ? "alarm" : "on";
    else if (s === "MAINTENANCE") cls = "maint";
    else if (s === "TAMPER_FAULT") cls = "fault";
    $(`#fan-${z}`).setAttribute("class", `fan ${cls}`.trim());
    const tag = $(`#tag-${z}`);
    tag.setAttribute("class", ["tag", (s === "INTRUSION" && alarmZones.has(z)) ? "alarm" : warnZones.has(z) && s === "ARMED" ? "warn" : "",
      health === "STUCK" || health === "OFFLINE" ? "stuck" : ""].join(" ").trim());
  }

  const up = (el, on) => $(el).setAttribute("class", `radio ${on ? "up" : "down"}${el === "#link-GS" ? " wifi" : ""}`);
  const gw = !!(link && link.gateway);
  const aUp = gw && moduleState(nodes.A) !== "offline" && nodes.A && nodes.A.state !== undefined;
  const bUp = gw && moduleState(nodes.B) !== "offline" && nodes.B && nodes.B.state !== undefined;
  up("#link-AG", aUp);
  up("#link-BG", bUp);
  up("#link-AB", (nodes.A && nodes.A.PEER === "UP") || (nodes.B && nodes.B.PEER === "UP"));
  up("#link-GS", gw);

  const wifi = link && link.mode === "emulator" ? "emulated link"
    : link && link.mode === "wokwi" ? "Wokwi, public broker"
    : g.WIFI && g.WIFI !== "-" ? `Wi-Fi ch ${g.CH}, ${String(g.WIFI).replace("-", "\u2212")} dBm, MQTT over TLS` : "Wi-Fi";
  $("#wifi-label").textContent = wifi;

  $("#tb-site").textContent = link ? link.site : "—";
  $("#tb-gw-boot").textContent = (link && link.gateway_boot) || "—";
  $("#tb-srv-boot").textContent = (link && link.server_boot) || "—";
  $("#tb-fw").textContent = g.FW ? `gateway ${g.FW}` : "—";
  $("#tb-link").textContent = !link ? "—" : link.mode === "hardware" ? "MQTT, TLS" : link.mode === "wokwi" ? "MQTT, public" : "emulated";
  $("#tb-ch").textContent = g.CH ? `channel ${g.CH}` : "—";
}

/** A zone's coverage flashes once when a new alert names it. */
export function flashZone(event) {
  if (event.type !== "ALERT") return;
  const names = new Set((event.event.match(/[AB]-(WALL|SIDE)/g) || []).concat(event.zone && event.zone !== "-" ? [event.zone] : []));
  for (const z of names) {
    const fan = document.getElementById(`fan-${z}`);
    if (!fan) continue;
    fan.classList.remove("flash");
    void fan.getBoundingClientRect();          // restart the animation
    fan.classList.add("flash");
  }
}
