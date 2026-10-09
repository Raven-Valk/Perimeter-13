// The event log: the newest 300 lines live, older ones on request, and
// server-side search and filters across the whole history.

import { $, $$, eventTime, h, when } from "./dom.js";
import { api } from "./api.js";

const TYPES = {
  all: null,
  alerts: ["ALERT", "SENSOR", "TAMPER", "FAULT"],
  access: ["AUTH"],
  commands: ["CMD"],
  system: ["SYSTEM", "COMM", "TEST", "HEALTH", "STATE", "MAINT", "INPUT"],
};
const GOOD = new Set(["OK", "PASS", "SUCCESS", "SENT"]);
const BAD = new Set(["FAIL", "REFUSED", "DENIED", "REJECTED", "LOCKED", "ERROR", "LOST", "BAD"]);
const unitName = { G: "GW", A: "A", B: "B" };
const blank = (v) => (v && v !== "-" ? v : "");

const view = { filter: "all", unit: "", q: "", rows: [], filtered: false, more: true };
let searchTimer = null;

export function initLog(getState) {
  for (const b of $$(".filters button")) {
    b.addEventListener("click", () => {
      $$(".filters button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      view.filter = b.dataset.filter;
      reload(getState);
    });
  }
  $("#unit-filter").addEventListener("change", (e) => { view.unit = e.target.value; reload(getState); });
  $("#search").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { view.q = e.target.value.trim(); reload(getState); }, 250);
  });
  $("#more").addEventListener("click", () => older());
}

function params(extra = {}) {
  const p = new URLSearchParams({ limit: "200", ...extra });
  if (TYPES[view.filter]) p.set("types", TYPES[view.filter].join(","));
  if (view.unit) p.set("module", view.unit);
  if (view.q) p.set("q", view.q);
  return p;
}

async function reload(getState) {
  view.filtered = view.filter !== "all" || view.unit || view.q;
  if (!view.filtered) { view.rows = getState().events.slice(); view.more = true; draw(); return; }
  try {
    view.rows = await api("GET", `/api/events?${params()}`);
    view.more = view.rows.length === 200;
  } catch { view.rows = []; }
  draw();
}

async function older() {
  const oldest = view.rows.length ? view.rows[view.rows.length - 1].gw_no : 0;
  if (!oldest) return;
  const rows = await api("GET", `/api/events?${params({ before: String(oldest) })}`);
  view.rows.push(...rows);
  view.more = rows.length === 200;
  draw();
}

function matches(e) {
  if (TYPES[view.filter] && !TYPES[view.filter].includes(e.type)) return false;
  if (view.unit && e.module !== view.unit) return false;
  if (view.q) {
    const q = view.q.toLowerCase();
    if (![e.event, e.user, e.type].some((v) => (v || "").toLowerCase().includes(q))) return false;
  }
  return true;
}

function row(e, fresh = false) {
  const res = blank(e.result);
  return h("tr", { "data-p": String(e.priority), class: fresh ? "fresh" : "" },
    h("td", { class: "c-no" }, e.gw_no),
    h("td", { class: "c-time", title: e.unix_time > 1600000000 ? "unit clock" : "time received" }, when(eventTime(e))),
    h("td", { class: "c-unit" }, unitName[e.module] || e.module),
    h("td", { class: "c-p" }, `P${e.priority}`),
    h("td", { class: "c-type" }, e.type),
    h("td", { class: "c-event" }, e.event.replace(/->/g, " \u2192 ")),
    h("td", { class: "c-zone" }, blank(e.zone)),
    h("td", { class: "c-by" }, blank(e.user)),
    h("td", { class: `c-res ${GOOD.has(res) ? "good" : BAD.has(res) ? "bad" : ""}` }, res));
}

function draw() {
  $("#events tbody").replaceChildren(...view.rows.map((e) => row(e)));
  $("#log-empty").hidden = view.rows.length > 0;
  $("#more").hidden = !view.more || view.rows.length === 0;
}

/** From the snapshot: the newest lines. */
export function setEvents(events) {
  if (view.filtered) return;
  view.rows = events.slice();
  draw();
}

/** One new line, live. */
export function addEvent(e) {
  if (!matches(e)) return;
  const pos = view.rows.findIndex((r) => r.gw_no < e.gw_no);
  if (pos === -1) { view.rows.push(e); } else { view.rows.splice(pos, 0, e); }
  const body = $("#events tbody");
  const tr = row(e, pos === 0);
  if (pos === -1) body.append(tr); else body.insertBefore(tr, body.children[pos]);
  $("#log-empty").hidden = true;
}
