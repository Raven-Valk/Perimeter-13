// What is going on, in one sentence and one line of detail. The order of the
// checks is the order of importance.

import { ago, eventTime, when } from "./dom.js";

const name = (k) => `Module ${k}`;
const both = (list) => (list.length === 2 ? "both modules" : name(list[0]));

export function moduleState(n) {
  if (!n || n.state === undefined) return "unknown";
  if (n.online === false) return "offline";
  return n.state;
}

/** Most recent event matching a test, from the newest-first list. */
const latest = (events, test) => events.find(test);

export function posture(st) {
  const { link, nodes, events } = st;
  const mods = ["A", "B"].map((k) => ({ k, s: moduleState(nodes[k]), n: nodes[k] || {} }));
  const inState = (s) => mods.filter((m) => m.s === s).map((m) => m.k);

  if (!link) return { level: "lost", title: "Connecting to the server", detail: "" };
  if (!link.broker && link.mode !== "emulator") {
    return { level: "lost", title: "The server can't reach its message broker.",
             detail: "Check that Mosquitto is running on the server. The modules keep detecting and sounding on their own." };
  }
  if (!link.gateway) {
    const since = link.since ? `Since ${when(link.since, false)}. ` : "";
    return { level: "lost", title: "No contact with the gateway.",
             detail: `${since}The modules keep detecting and sounding on their own; this page catches up when the gateway is back.` };
  }
  if (nodes.G && nodes.G.state === "GW_TAMPER") {
    return { level: "alarm", title: "The gateway's lid has been opened.",
             detail: "It refuses every command until a maintenance user clears it with the lid shut." };
  }

  const intrusion = inState("INTRUSION");
  if (intrusion.length) {
    const e = latest(events, (e) => e.priority >= 2 && e.type === "ALERT" && /Intrusion: /.test(e.event));
    const why = e ? `${e.event.replace("Intrusion: ", "Confirmed by ")} at ${when(eventTime(e), false)}. ` : "";
    return { level: "alarm", title: `Intrusion confirmed at ${both(intrusion)}.`,
             detail: `${why}Acknowledge once the area has been checked.` };
  }
  const fault = inState("TAMPER_FAULT");
  if (fault.length) {
    const e = latest(events, (e) => e.priority >= 3 && fault.includes(e.module));
    return { level: "alarm", title: `${cap(both(fault))} ${fault.length === 2 ? "report" : "reports"} a tamper or fault.`,
             detail: e ? `${e.event}, ${ago(eventTime(e))}. Check the unit, close it, then clear the fault.` :
                         "Check the unit, close it, then clear the fault." };
  }
  const offline = inState("offline");
  if (offline.length) {
    return { level: "warn", title: `${cap(both(offline))} ${offline.length === 2 ? "aren't" : "isn't"} reporting.`,
             detail: "The gateway hasn't heard from it for a few seconds. If it was armed, check it in person." };
  }
  const maint = inState("MAINTENANCE");
  if (maint.length) {
    return { level: "warn", title: `${cap(both(maint))} ${maint.length === 2 ? "are" : "is"} in maintenance.`,
             detail: "Sensors log but won't raise an alarm. Maintenance ends by itself." };
  }
  const starting = mods.filter((m) => m.s === "BOOT" || m.s === "RECOVERY" || m.s === "unknown").map((m) => m.k);
  if (starting.length) {
    return { level: "warn", title: `${cap(both(starting))} ${starting.length === 2 ? "are" : "is"} starting up.`,
             detail: "Sensors warm up and the unit tests itself before it returns to its last mode." };
  }

  const armed = inState("ARMED");
  if (armed.length === 2) {
    const warn = mods.find((m) => Number(m.n.priority) === 1);
    if (warn) {
      const e = latest(events, (e) => e.type === "ALERT" && e.priority === 1 && e.zone && e.zone !== "-");
      const where = e ? `the ${e.zone.replace("-", " ").toLowerCase().replace(/^([ab]) /, (_, l) => l.toUpperCase() + " ")}` : "the wall";
      return { level: "warn", title: `Armed. Motion at ${where}, not confirmed.`,
               detail: "One sensor fired. A second sensor within 20 seconds confirms an intrusion." };
    }
    const e = latest(events, (e) => e.type === "ALERT" && e.zone && e.zone !== "-");
    return { level: "quiet", title: "Armed. The perimeter is quiet.",
             detail: e ? `Last motion: ${e.zone} at ${when(eventTime(e), false)}, ${ago(eventTime(e))}.` : "No motion recorded yet." };
  }
  if (inState("DISARMED").length === 2) {
    return { level: "quiet", title: "Disarmed.", detail: "Sensors still log motion, but nothing raises an alarm." };
  }
  return { level: "warn", title: `Module ${armed[0] || "?"} armed, the other disarmed.`,
           detail: "Only part of the wall raises an alarm." };
}

const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
