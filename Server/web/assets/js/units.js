// The Units table: one row per reading, one column per unit.

import { $, h } from "./dom.js";
import { moduleState } from "./posture.js";

const STATE = { ARMED: "Armed", DISARMED: "Disarmed", INTRUSION: "Intrusion", TAMPER_FAULT: "Tamper / fault",
                MAINTENANCE: "Maintenance", BOOT: "Starting", RECOVERY: "Self-test", READY: "Ready",
                GW_TAMPER: "Lid open", offline: "Not reporting", unknown: "—" };
const tone = {
  state: (v) => ({ ARMED: "good", READY: "good", INTRUSION: "bad", TAMPER_FAULT: "bad", GW_TAMPER: "bad",
                   offline: "bad", MAINTENANCE: "warn", BOOT: "warn", RECOVERY: "warn" })[v] || "",
  health: (v) => ({ OK: "good", WARMUP: "warn", STUCK: "bad", OFFLINE: "bad" })[v] || "",
  lid: (v) => ({ SHUT: "good", OPEN: "bad" })[v] || "",
  ok: (v) => ({ OK: "good", OFFLINE: "bad" })[v] || "",
};
const words = {
  health: (v) => ({ OK: "OK", WARMUP: "Warming up", STUCK: "Stuck", OFFLINE: "Unplugged" })[v] || v,
  lid: (v) => ({ SHUT: "Shut", OPEN: "Open" })[v] || v,
  ok: (v) => ({ OK: "OK", OFFLINE: "Missing" })[v] || v,
  lock: (v) => (v === undefined ? undefined : Number(v) > 0 ? `${v} s left` : "None"),
};

function cell(value, cls = "") {
  if (value === undefined || value === null || value === "") return h("td", { class: "dim" }, "—");
  return h("td", { class: cls }, value);
}

export function renderUnits(st) {
  const { nodes, link } = st;
  const g = (link && link.gateway ? nodes.G : {}) || {};
  const m = { A: nodes.A || {}, B: nodes.B || {} };
  const sOf = (k) => moduleState(m[k]);
  const live = (k) => !["offline", "unknown"].includes(sOf(k));
  const gs = link && link.gateway ? g.state : "offline";
  const dbm = (v) => (v && v !== "-" ? `${String(v).replace("-", "\u2212")} dBm` : undefined);
  const radio = (k) => (live(k) ? dbm(m[k].RSSI) : undefined);

  const rows = [
    ["State", [STATE[gs] || gs, tone.state(gs)], ...["A", "B"].map((k) => [STATE[sOf(k)] || sOf(k), tone.state(sOf(k))])],
    ["Priority", [g.system_priority !== undefined ? `P${g.system_priority}` : undefined],
      ...["A", "B"].map((k) => [live(k) && m[k].priority !== undefined ? `P${m[k].priority}` : undefined,
                               Number(m[k].priority) >= 2 ? "bad" : Number(m[k].priority) === 1 ? "warn" : ""])],
    ["Wall sensor", [], ...["A", "B"].map((k) => [live(k) ? words.health(m[k].WALL) : undefined, tone.health(m[k].WALL)])],
    ["Side sensor", [], ...["A", "B"].map((k) => [live(k) ? words.health(m[k].SIDE) : undefined, tone.health(m[k].SIDE)])],
    ["Enclosure", [words.lid(g.LID), tone.lid(g.LID)], ...["A", "B"].map((k) => [live(k) ? words.lid(m[k].LID) : undefined, tone.lid(m[k].LID)])],
    ["Display", [words.ok(g.LCD), tone.ok(g.LCD)], ...["A", "B"].map((k) => [live(k) ? words.ok(m[k].LCD) : undefined, tone.ok(m[k].LCD)])],
    ["Card reader", [words.ok(g.RFID), tone.ok(g.RFID)], [], []],
    ["Other module", [], ...["A", "B"].map((k) => [live(k) ? ({ UP: "Linked", DOWN: "No link" })[m[k].PEER] : undefined,
                                                   m[k].PEER === "DOWN" ? "bad" : ""])],
    ["Signal", [dbm(g.WIFI)], [radio("A")], [radio("B")]],
    ["Keypad lock", [words.lock(g.KPLOCK), Number(g.KPLOCK) > 0 ? "warn" : ""],
      ...["A", "B"].map((k) => [live(k) ? words.lock(m[k].LOCK) : undefined, Number(m[k].LOCK) > 0 ? "warn" : ""])],
    ["Dashboard lock", [words.lock(g.PCLOCK), Number(g.PCLOCK) > 0 ? "warn" : ""], [], []],
    ["Real time", [g.TIME ? (g.TIME === "Y" ? "Synced" : "Not yet") : undefined, g.TIME === "N" ? "warn" : ""], [], []],
    ["Log line", [g.LOGNO], [live("A") ? m.A.LOGNO : undefined], [live("B") ? m.B.LOGNO : undefined]],
  ];
  const body = $("#spec tbody");
  body.replaceChildren(...rows.map(([label, ...cols]) =>
    h("tr", {}, h("th", { scope: "row" }, label), ...cols.map(([v, c]) => cell(v, c)))));
}
