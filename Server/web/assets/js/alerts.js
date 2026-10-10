// Alerts on this device: browser notifications, the siren, and small in-page notes.
//
//   * Intrusion (P2): a notification, and a loud two-tone siren that repeats
//     until the alarm is acknowledged or someone presses Silence here. A new
//     zone joining the alarm sounds it again.
//   * Warning (P1, one sensor fired): a notification only.
// The choices are kept in this browser only (localStorage).

import { $, h } from "./dom.js";
import { alarmZones, moduleState, MODULES, WALL } from "./posture.js";

const KEY = "p13.alerts";
const DEFAULTS = { notify: false, warnings: true, siren: true, volume: 80 };
const prefs = load();

function load() {
  try { return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) || "{}") }; } catch { return { ...DEFAULTS }; }
}
function save() {
  try { localStorage.setItem(KEY, JSON.stringify(prefs)); } catch { /* private window: settings last this visit */ }
}

// ---------------------------------------------------------------- the siren
let ctx = null;
let siren = null;
let testTimer = null;

/** Browsers only allow sound after a click or key press on the page: call this from one. */
export function unlockAudio() {
  const C = window.AudioContext || window.webkitAudioContext;
  if (!C) return;
  if (!ctx) ctx = new C();
  if (ctx.state === "suspended") ctx.resume().catch(() => {});
}
const audioReady = () => !!ctx && ctx.state === "running";
const gainFor = (v) => Math.pow(v / 100, 1.6) * 0.9;

function startSiren() {
  unlockAudio();
  if (!ctx || siren) return;
  const now = ctx.currentTime;
  const out = ctx.createGain();
  out.gain.setValueAtTime(0, now);
  out.gain.linearRampToValueAtTime(gainFor(prefs.volume), now + 0.05);
  const comp = ctx.createDynamicsCompressor();
  comp.threshold.value = -10; comp.ratio.value = 4;
  const tone = ctx.createBiquadFilter();
  tone.type = "lowpass"; tone.frequency.value = 3200;
  // Two detuned voices swept by a slow wave: the classic wail, hard to ignore.
  const a = ctx.createOscillator(), b = ctx.createOscillator();
  a.type = "sawtooth"; b.type = "square";
  a.frequency.value = 880; b.frequency.value = 886;
  const lfo = ctx.createOscillator(), depth = ctx.createGain();
  lfo.type = "triangle"; lfo.frequency.value = 0.85; depth.gain.value = 380;
  lfo.connect(depth); depth.connect(a.frequency); depth.connect(b.frequency);
  const mix = ctx.createGain(); mix.gain.value = 0.5;
  a.connect(mix); b.connect(mix); mix.connect(tone); tone.connect(comp); comp.connect(out); out.connect(ctx.destination);
  for (const o of [a, b, lfo]) o.start(now);
  siren = { out, oscs: [a, b, lfo] };
}

function stopSiren() {
  if (!siren || !ctx) return;
  const { out, oscs } = siren;
  siren = null;
  const now = ctx.currentTime;
  out.gain.cancelScheduledValues(now);
  out.gain.setValueAtTime(out.gain.value, now);
  out.gain.linearRampToValueAtTime(0, now + 0.15);
  for (const o of oscs) o.stop(now + 0.2);
}

// ---------------------------------------------------------------- notifications
const canNotify = () => "Notification" in window && window.isSecureContext;
let lastWarn = 0;

function notify(title, body, tag, urgent) {
  toast(title, body, urgent ? "alarm" : "warn");
  if (!prefs.notify || !canNotify() || Notification.permission !== "granted") return;
  try {
    const n = new Notification(title, { body, tag, renotify: true, requireInteraction: urgent, icon: "/assets/img/mark.svg" });
    n.onclick = () => { window.focus(); n.close(); };
  } catch { /* some browsers only allow notifications from a service worker */ }
}

export function toast(title, body, tone = "") {
  const box = $("#toasts");
  const t = h("div", { class: `toast ${tone}`.trim(), role: tone === "alarm" ? "alert" : "status" },
    h("strong", {}, title), body ? h("span", {}, body) : null);
  box.prepend(t);
  while (box.children.length > 3) box.lastChild.remove();
  setTimeout(() => t.classList.add("leaving"), tone === "alarm" ? 12000 : 7000);
  setTimeout(() => t.remove(), tone === "alarm" ? 12600 : 7600);
}

// ---------------------------------------------------------------- following the state
let alarmSig = null;              // which zones are in alarm ("" = none, null = not known yet)
let silenced = false;

export function updateAlerts(st) {
  const gw = !!(st.link && st.link.gateway);
  const intrusion = gw ? MODULES.filter((k) => moduleState(st.nodes[k]) === "INTRUSION") : [];
  const zones = intrusion.length ? alarmZones(st.nodes) : [];
  const sig = intrusion.length ? zones.join("+") || "?" : "";
  if (sig && sig !== alarmSig) {                       // a new alarm, or another zone joined it
    const fresh = alarmSig ? zones.filter((z) => !alarmSig.split("+").includes(String(z))) : zones;
    const z = fresh.length ? fresh : zones;
    const where = z.length === 1 ? `zone ${z[0]}, wall ${WALL[z[0]]}` : z.length ? `zones ${z.join(" and ")}` : "the perimeter";
    notify(`Intrusion: ${where}`, alarmSig ? "The alarm has spread to another wall." : "Confirmed by two sensors. Check the area, then acknowledge.",
           "p13-alarm", true);
    silenced = false;
  }
  if (!sig) silenced = false;
  alarmSig = sig;

  const want = !!sig && prefs.siren && !silenced;
  if (want) startSiren(); else if (!testTimer) stopSiren();

  const bar = $("#siren-bar");
  bar.hidden = !sig || !prefs.siren;
  $("#siren-text").textContent = silenced ? "Intrusion. Siren silenced on this device."
    : !audioReady() ? "Intrusion. Click anywhere on the page to let the siren sound."
    : "Intrusion. Siren sounding until the alarm is acknowledged.";
  $("#siren-silence").textContent = silenced ? "Sound again" : "Silence";
  bar.dataset.state = silenced ? "silenced" : "sounding";
}

/** A new log line, as it arrives (not the history). */
export function alertForEvent(e) {
  if (e.type !== "ALERT" || e.priority !== 1 || !/^Motion warning/.test(e.event) || !prefs.warnings) return;
  const now = Date.now();
  if (now - lastWarn < 8000) return;
  lastWarn = now;
  const z = Number((e.zone || "").slice(-1));
  notify(`Warning: motion at ${e.zone}`, `One sensor on wall ${WALL[z] || "?"} fired. Not confirmed yet.`, `p13-warn-${e.zone}`, false);
}

// ---------------------------------------------------------------- the settings in the menu
function setSwitch(el, on) { el.setAttribute("aria-checked", String(!!on)); }

function showSettings() {
  setSwitch($("#notify-switch"), prefs.notify && canNotify() && Notification.permission === "granted");
  setSwitch($("#warn-switch"), prefs.warnings);
  setSwitch($("#siren-switch"), prefs.siren);
  $("#volume").value = String(prefs.volume);
  $("#volume").disabled = !prefs.siren;
  const note = $("#notify-note");
  if (!("Notification" in window)) note.textContent = "Not available in this browser";
  else if (!window.isSecureContext) note.textContent = "Needs the HTTPS address of the dashboard";
  else if (Notification.permission === "denied") note.textContent = "Blocked: allow them in the browser's site settings";
  else note.textContent = prefs.notify && Notification.permission === "granted" ? "On: intrusions and warnings" : "Off";
}

export function initAlerts(getState) {
  showSettings();
  $("#notify-switch").addEventListener("click", async () => {
    if (prefs.notify) { prefs.notify = false; save(); showSettings(); return; }
    if (!canNotify()) { showSettings(); return; }
    let perm = Notification.permission;
    if (perm === "default") perm = await Notification.requestPermission();
    prefs.notify = perm === "granted";
    save();
    showSettings();
    if (prefs.notify) toast("Notifications on", "You'll get one for each intrusion and warning.", "");
  });
  $("#warn-switch").addEventListener("click", () => { prefs.warnings = !prefs.warnings; save(); showSettings(); });
  $("#siren-switch").addEventListener("click", () => {
    prefs.siren = !prefs.siren; save(); showSettings(); updateAlerts(getState());
  });
  $("#volume").addEventListener("input", (e) => {
    prefs.volume = Number(e.target.value); save();
    if (siren && ctx) siren.out.gain.setTargetAtTime(gainFor(prefs.volume), ctx.currentTime, 0.05);
  });
  $("#siren-test").addEventListener("click", () => {
    unlockAudio();
    clearTimeout(testTimer);
    startSiren();
    testTimer = setTimeout(() => { testTimer = null; updateAlerts(getState()); if (!alarmSig || silenced || !prefs.siren) stopSiren(); }, 2500);
  });
  $("#siren-silence").addEventListener("click", () => { unlockAudio(); silenced = !silenced; updateAlerts(getState()); });
  for (const type of ["pointerdown", "keydown"]) {
    document.addEventListener(type, () => { const was = audioReady(); unlockAudio(); if (!was) setTimeout(() => updateAlerts(getState()), 50); }, { passive: true });
  }
}

export const alarmActive = () => !!alarmSig;
