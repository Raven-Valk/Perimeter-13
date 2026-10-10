// The control panel: commands for the units, and taking control back.

import { $, $$, h } from "./dom.js";
import { api } from "./api.js";
import { moduleState, MODULES } from "./posture.js";
import { linkName, PAIRS } from "./mesh.js";

const VERB = { arm: "Arm", disarm: "Disarm", ack: "Acknowledge", maint_start: "Maintenance", maint_end: "End maintenance",
               clear: "Clear", test_cut: "Relay test" };
const DONE = { arm: "Armed", disarm: "Disarmed", ack: "Alarm acknowledged", maint_start: "Maintenance started",
               maint_end: "Maintenance ended", clear: "Fault cleared", test_cut: "Relay test" };
const FAILED = { REFUSED: "refused", DENIED: "not allowed", BAD: "not understood", TIMEOUT: "got no answer", OFFLINE: "not sent" };

let confirmTimer = null;

export function initControl(getState, onSession) {
  for (const btn of $$("[data-command]")) {
    btn.dataset.label = btn.textContent;
    btn.addEventListener("click", () => press(btn));
  }
  $$('input[name="target"]').forEach((r) => r.addEventListener("change", () => renderControl(getState())));
  $("#cut-link").replaceChildren(...PAIRS.map(([a, b]) => h("option", { value: `${a}-${b}` }, `Link ${linkName({ a, b })}`)));

  $("#take").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const out = $("#take-result");
    const pw = $("#take-password");
    say(out, "Asking the gateway…", "busy");
    try {
      const s = await api("POST", "/api/control", { password: pw.value });
      pw.value = "";
      say(out, "");
      onSession(s);
    } catch (err) {
      say(out, err.message, "bad");
    }
  });

  async function press(btn) {
    const cmd = btn.dataset.command;
    if (btn.dataset.confirm && !btn.classList.contains("armed-confirm")) {
      clearConfirm();
      btn.classList.add("armed-confirm");
      btn.textContent = btn.dataset.confirm;
      confirmTimer = setTimeout(clearConfirm, 5000);
      return;
    }
    clearConfirm();
    const body = { command: cmd, target: target() };
    if (cmd === "maint_start") body.seconds = Number($("#maint-seconds").value);
    if (cmd === "clear") body.target = $("#clear-target").value;
    if (cmd === "test_cut") { delete body.target; body.link = $("#cut-link").value; body.seconds = Number($("#cut-seconds").value); }
    const out = $("#result");
    say(out, `${VERB[cmd]}: sent, waiting for the units…`, "busy");
    $$("[data-command]").forEach((b) => (b.disabled = true));
    try {
      const r = await api("POST", "/api/commands", body);
      const detail = (r.text || "").replace(/\b([A-D]):/g, "$1: ").trim().replace(/ (?=[A-D]: )/g, ", ");
      const head = r.result === "OK" ? DONE[cmd] : `${VERB[cmd]} ${FAILED[r.result] || r.result.toLowerCase()}`;
      say(out, `${head}${detail ? `. ${detail}` : ""}`, r.result === "OK" ? "ok" : "bad");
    } catch (err) {
      say(out, err.message, "bad");
    } finally {
      renderControl(getState());
    }
  }
}

const target = () => ($('input[name="target"]:checked') || {}).value || "all";

function clearConfirm() {
  clearTimeout(confirmTimer);
  for (const b of $$(".armed-confirm")) { b.classList.remove("armed-confirm"); b.textContent = b.dataset.label; }
}

function say(el, text, tone = "") {
  el.textContent = text;
  if (tone) el.dataset.tone = tone; else delete el.dataset.tone;
}

export function renderControl(st) {
  const s = st.session || {};
  const ctl = st.control;
  const gwUp = !!(st.link && st.link.gateway);
  const has = !!s.control;
  const maint = s.role === "MAINTENANCE";

  $("#control-who").textContent = has
    ? `${s.user}, ${s.role === "MAINTENANCE" ? "maintenance" : "operator"} role. You have control.`
    : ctl ? `${ctl.user} has control.` : gwUp ? "No one has control." : "The gateway is offline.";

  $("#control-live").hidden = !has;
  $("#take").hidden = has;
  if (!has) {
    $("#take-user").textContent = s.user || "";
    $("#take-why").textContent = !gwUp ? "Commands need the gateway, which is offline."
      : s.view_only_reason ? `${s.view_only_reason}. Enter your password to send commands.`
      : "Control ends after 5 minutes without a command, after 30 minutes, or when someone else signs in. Enter your password to take it back.";
    $("#take button").disabled = !gwUp;
    return;
  }

  const t = target();
  const keys = t === "all" ? MODULES : [t];
  const states = keys.map((k) => moduleState(st.nodes[k]));
  const any = (...wanted) => states.some((x) => wanted.includes(x) || x === "unknown");
  const set = (cmd, ok, why) => {
    const b = $(`[data-command="${cmd}"]`);
    b.disabled = !ok;
    if (ok) delete b.dataset.why; else b.dataset.why = why;
  };
  set("arm", any("DISARMED"), states.every((x) => x === "ARMED") ? "Already armed" : "Only from disarmed");
  set("disarm", any("ARMED", "INTRUSION", "RECOVERY", "BOOT"), states.every((x) => x === "DISARMED") ? "Already disarmed" : "Clear or end maintenance first");
  set("ack", any("INTRUSION"), "No alarm");
  set("maint_end", any("MAINTENANCE"), "Not in maintenance");
  set("maint_start", maint, "Needs the maintenance role");
  set("clear", maint, "Needs the maintenance role");
  set("test_cut", maint && gwUp, "Needs the maintenance role");
  $("#maint").classList.toggle("locked", !maint);
}
