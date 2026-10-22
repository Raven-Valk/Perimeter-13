// The Units table: one row per reading, one column per unit (gateway + four modules).

import { $, h } from "./dom.js";
import { moduleState, MODULES } from "./posture.js";
import { meshLinks } from "./mesh.js";

const STATE = { ARMED: "Armed", DISARMED: "Disarmed", INTRUSION: "Intrusion", TAMPER_FAULT: "Tamper",
                MAINTENANCE: "Maint.", BOOT: "Starting", RECOVERY: "Self-test", READY: "Ready",
                GW_TAMPER: "Lid open", offline: "Silent", unknown: "—" };
const tone = {
  state: (v) => ({ ARMED: "good", READY: "good", INTRUSION: "bad", TAMPER_FAULT: "bad", GW_TAMPER: "bad",
                   offline: "bad", MAINTENANCE: "warn", BOOT: "warn", RECOVERY: "warn" })[v] || "",
  health: (v) => ({ OK: "good", WARMUP: "warn", STUCK: "bad", OFFLINE: "bad" })[v] || "",
  lid: (v) => ({ SHUT: "good", OPEN: "bad" })[v] || "",
  ok: (v) => ({ OK: "good", OFFLINE: "bad" })[v] || "",
  beam: (v) => ({ OK: "good", TX: "good", BRK: "warn", WARMUP: "warn", STUCK: "bad", NOSIG: "bad" })[v] || "",
};
const words = {
  health: (v) => ({ OK: "OK", WARMUP: "Warming", STUCK: "Stuck", OFFLINE: "Unplugged" })[v] || v,
  lid: (v) => ({ SHUT: "Shut", OPEN: "Open", NONE: "None" })[v] || v,
  ok: (v) => ({ OK: "OK", OFFLINE: "Missing" })[v] || v,
  lock: (v) => (v === undefined ? undefined : Number(v) > 0 ? `${v} s` : "No"),
  beam: (v) => ({ OK: "Intact", BRK: "Broken", WARMUP: "Searching", STUCK: "Blocked", NOSIG: "No signal", TX: "Sending" })[v] || v,
};

function cell(value, cls = "") {
  if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length))
    return h("td", { class: "dim" }, "—");
  if (Array.isArray(value)) return h("td", {}, ...value.map(([v, c]) => h("span", { class: `line ${c || ""}`.trim() }, v)));
  return h("td", { class: cls }, value);
}

export function renderUnits(st) {
  const { nodes, link } = st;
  const gw = !!(link && link.gateway);
  const g = (gw ? nodes.G : {}) || {};
  const m = Object.fromEntries(MODULES.map((k) => [k, nodes[k] || {}]));
  const sOf = (k) => moduleState(m[k]);
  const live = (k) => gw && !["offline", "unknown"].includes(sOf(k));
  const gs = gw ? g.state : "offline";
  const dbm = (v) => (v && v !== "-" ? `${String(v).replace("-", "−")}` : undefined);
  const links = meshLinks(nodes, gw);
  const mesh = (k) => {                          // this unit's four links: "4" or "3 + 1r"
    const mine = links.filter((l) => l.a === k || l.b === k);
    const direct = mine.filter((l) => l.state === "direct").length;
    const relayed = mine.filter((l) => l.state === "relayed").length;
    if (!mine.some((l) => l.state !== "unknown")) return [undefined];
    return [relayed ? `${direct} + ${relayed} relayed` : `${direct} direct`, relayed ? "warn" : direct < 4 ? "bad" : "good"];
  };
  const each = (fn) => MODULES.map((k) => (live(k) ? fn(k) : [undefined]));

  const rows = [
    ["State", [STATE[gs] || gs, tone.state(gs)], ...MODULES.map((k) => [gw ? STATE[sOf(k)] || sOf(k) : undefined, tone.state(sOf(k))])],
    ["Priority", [gw && g.system_priority !== undefined ? `P${g.system_priority}` : undefined],
      ...each((k) => [m[k].priority !== undefined ? `P${m[k].priority}` : undefined,
                      Number(m[k].priority) >= 2 ? "bad" : Number(m[k].priority) === 1 ? "warn" : ""])],
    ["PIRs", [], ...each((k) => [Object.keys(m[k]).filter((x) => /^Z[1-3]$/.test(x)).sort()
      .map((z) => [`${z} ${words.health(m[k][z])}`, tone.health(m[k][z])])])],
    ["IR beam", [], ...each((k) => [m[k].IR ? words.beam(m[k].IR) : undefined, tone.beam(m[k].IR)])],
    ["Alarm zones", [], ...each((k) => [m[k].ALM && m[k].ALM !== "-" ? m[k].ALM : undefined, "bad"])],
    ["Enclosure", [words.lid(g.LID), tone.lid(g.LID)], ...each((k) => [words.lid(m[k].LID), tone.lid(m[k].LID)])],
    ["Display", [words.ok(g.LCD), tone.ok(g.LCD)], ...each((k) => [words.ok(m[k].LCD), tone.ok(m[k].LCD)])],
    ["Card reader", [words.ok(g.RFID), tone.ok(g.RFID)], [], [], [], []],
    ["Mesh links", gw ? mesh("G") : [undefined], ...each((k) => mesh(k))],
    ["Relayed", [gw ? g.FWD : undefined], ...each((k) => [m[k].FWD])],
    ["Signal dBm", [dbm(g.WIFI)], ...each((k) => [dbm(m[k].RSSI)])],
    ["Keypad lock", [words.lock(g.KPLOCK), Number(g.KPLOCK) > 0 ? "warn" : ""],
      ...each((k) => [words.lock(m[k].LOCK), Number(m[k].LOCK) > 0 ? "warn" : ""])],
    ["Web lock", [words.lock(g.PCLOCK), Number(g.PCLOCK) > 0 ? "warn" : ""], [], [], [], []],
    ["Real time", [g.TIME ? (g.TIME === "Y" ? "Synced" : "Not yet") : undefined, g.TIME === "N" ? "warn" : ""], [], [], [], []],
    ["Log line", [g.LOGNO], ...each((k) => [m[k].LOGNO])],
  ];
  const body = $("#spec tbody");
  body.replaceChildren(...rows.map(([label, ...cols]) =>
    h("tr", {}, h("th", { scope: "row" }, label), ...cols.map(([v, c]) => cell(v, c)))));
}
