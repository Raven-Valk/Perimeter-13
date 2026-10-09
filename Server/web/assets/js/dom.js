// Small DOM and formatting helpers. Text from devices is only ever set as text.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("data-")) el.setAttribute(k, v);
    else if (k in el) el[k] = v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const shortFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
const dayFmt = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short" });

/** Seconds since 1970 -> "14:31:07", "Yesterday 14:31" or "8 Oct 14:31". */
export function when(sec, seconds = true) {
  if (!sec) return "";
  const d = new Date(sec * 1000);
  const now = new Date();
  const days = Math.round((startOfDay(now) - startOfDay(d)) / 86400000);
  const t = seconds ? timeFmt.format(d) : shortFmt.format(d);
  if (days === 0) return t;
  if (days === 1) return `Yesterday ${shortFmt.format(d)}`;
  return `${dayFmt.format(d)} ${shortFmt.format(d)}`;
}
const startOfDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();

export function clockTime() { return timeFmt.format(new Date()); }

/** "just now", "4 min ago", "2 h ago", "3 days ago" */
export function ago(sec) {
  const s = Date.now() / 1000 - sec;
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400 * 2) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

/** When an event happened: the device's clock if it had the real time, else when the server got it. */
export const eventTime = (e) => (e.unix_time > 1600000000 ? e.unix_time : e.received_at);
