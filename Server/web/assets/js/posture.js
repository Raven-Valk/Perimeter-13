// What is going on, in one sentence and one line of detail. The order of the
// checks is the order of importance.

import { ago, eventTime, when } from "./dom.js";
import { linkName, meshLinks, NAME } from "./mesh.js";

export const MODULES = ["A", "B", "C", "D"];
export const WALL = { 1: "A\u2060–\u2060D", 2: "A\u2060–\u2060B", 3: "B\u2060–\u2060C" };   // never split across lines
const ENDS = { 1: ["A", "D"], 2: ["A", "B"], 3: ["B", "C"] };
const BUZZERS = { A: [1, 2], B: [2, 3] };          // modules with a buzzer, and the zones they sound for

export function moduleState(n) {
  if (!n || n.state === undefined) return "unknown";
  if (n.online === false) return "offline";
  return n.state;
}

/** [1, 3] from "1+3" / "13" / "-" */
export const zonesIn = (text) => [...new Set(String(text || "").match(/[1-3]/g) || [])].map(Number).sort();

/** "A", "A and B", "A, B and D", "all four modules" */
export function list(keys, noun = true) {
  if (keys.length === 4) return "all four modules";
  const names = keys.length > 2 ? `${keys.slice(0, -1).join(", ")} and ${keys[keys.length - 1]}`
    : keys.join(" and ");
  return noun ? `${keys.length === 1 ? "Module" : "Modules"} ${names}` : names;
}
const verb = (keys, one, many) => (keys.length === 1 ? one : many);
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

/** The PIR at the other end of the wall: partner("A-Z1") = "D-Z1" */
export function partnerPir(name) {
  const m = /^([A-D])-Z([1-3])$/.exec(name || "");
  if (!m) return null;
  const other = ENDS[m[2]].find((k) => k !== m[1]);
  return `${other}-Z${m[2]}`;
}

export function alarmZones(nodes) {
  const z = new Set();
  for (const k of MODULES) if (moduleState(nodes[k]) === "INTRUSION") zonesIn(nodes[k].ALM).forEach((x) => z.add(x));
  return [...z].sort();
}

/** Modules whose buzzer is sounding: in INTRUSION, with an alarm on one of their walls. */
export function sounding(nodes, zones = alarmZones(nodes)) {
  return Object.entries(BUZZERS).filter(([k, walls]) => moduleState(nodes[k]) === "INTRUSION" && walls.some((w) => zones.includes(w)))
    .map(([k]) => k);
}

function meshNote(st) {
  const links = meshLinks(st.nodes, !!(st.link && st.link.gateway));
  const relayed = links.filter((l) => l.state === "relayed");
  if (!relayed.length) return "";
  const l = relayed[0];
  const via = l.via === "G" ? "the gateway" : `Module ${l.via}`;
  return relayed.length === 1 ? ` Radio: link ${linkName(l)} is relayed through ${via}${l.test ? " (relay test)" : ""}.`
    : ` Radio: ${relayed.length} links are relayed through other boards.`;
}

/** Most recent event matching a test, from the newest-first list. */
const latest = (events, test) => events.find(test);

export function posture(st) {
  const { link, nodes, events } = st;
  const mods = MODULES.map((k) => ({ k, s: moduleState(nodes[k]), n: nodes[k] || {} }));
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
    const zones = alarmZones(nodes);
    const title = zones.length === 0 ? "Intrusion confirmed."
      : zones.length === 1 ? `Intrusion on zone ${zones[0]}, wall ${WALL[zones[0]]}.`
      : `Intrusion on zones ${zones.slice(0, -1).join(", ")} and ${zones[zones.length - 1]}.`;
    const e = latest(events, (e) => e.priority >= 2 && e.type === "ALERT" && /^Intrusion zone/.test(e.event));
    const what = e ? e.event.replace(/^Intrusion zone [\d+]+( \(escalated\))?: /, "") : "";
    const at = e ? when(eventTime(e), false) : "";
    const why = !e ? "" : /\(escalated\)/.test(e.event) ? `Latest: ${what.replace(" during the alarm", " fired during the alarm")}, ${at}. `
      : `Confirmed by ${what} at ${at}. `;
    const buzz = sounding(nodes, zones);
    const sound = buzz.length ? ` ${buzz.length === 1 ? "Buzzer" : "Buzzers"} sounding at ${list(buzz, false)}.` : "";
    return { level: "alarm", title,
             detail: `${why}Until it is acknowledged, any single sensor raises the alarm at once.${sound}` };
  }
  const fault = inState("TAMPER_FAULT");
  if (fault.length) {
    const e = latest(events, (e) => e.priority >= 3 && fault.includes(e.module));
    return { level: "alarm", title: `${list(fault)} ${verb(fault, "reports", "report")} a tamper or fault.`,
             detail: e ? `${e.event}, ${ago(eventTime(e))}. Check the unit, close it, then clear the fault.`
                       : "Check the unit, close it, then clear the fault." };
  }
  const offline = inState("offline");
  if (offline.length) {
    return { level: "warn", title: `${list(offline)} ${verb(offline, "isn't", "aren't")} reporting.`,
             detail: "Neither the gateway nor any relay hears it. If it was armed, check it in person; the others still watch their walls." };
  }
  const maint = inState("MAINTENANCE");
  if (maint.length) {
    return { level: "warn", title: `${list(maint)} ${verb(maint, "is", "are")} in maintenance.`,
             detail: "Its sensors log but won't raise an alarm. Maintenance ends by itself." };
  }
  const starting = mods.filter((m) => ["BOOT", "RECOVERY", "unknown"].includes(m.s)).map((m) => m.k);
  if (starting.length) {
    return { level: "warn", title: `${list(starting)} ${verb(starting, "is", "are")} starting up.`,
             detail: "Sensors warm up and each unit tests itself before it returns to its last mode." };
  }

  const armed = inState("ARMED");
  const radio = meshNote(st);
  if (armed.length === 4) {
    if (mods.some((m) => Number(m.n.priority) === 1)) {
      const e = latest(events, (e) => e.type === "ALERT" && e.priority === 1 && /^[A-D]-Z[1-3]$/.test(e.zone || ""));
      const pirName = e ? e.zone : null;
      const zone = pirName ? Number(pirName.slice(-1)) : null;
      const where = pirName ? `${pirName}, wall ${WALL[zone]}` : "a wall";
      return { level: "warn", title: `Armed. Motion at ${where}, not confirmed.`,
               detail: `One sensor fired. ${pirName ? `${partnerPir(pirName)}, at the other end of the wall,` : "The sensor at the other end of the wall"} within 20 seconds, or 3 hits, confirms an intrusion.${radio}` };
    }
    const e = latest(events, (e) => e.type === "ALERT" && /^[A-D]-Z[1-3]$/.test(e.zone || ""));
    return { level: "quiet", title: "Armed. The perimeter is quiet.",
             detail: (e ? `Last motion: ${e.zone} at ${when(eventTime(e), false)}, ${ago(eventTime(e))}.` : "No motion recorded yet.") + radio };
  }
  if (inState("DISARMED").length === 4) {
    return { level: "quiet", title: "Disarmed.", detail: `Sensors still log motion, but nothing raises an alarm.${radio}` };
  }
  const others = MODULES.filter((k) => !armed.includes(k));
  const watched = Object.entries(ENDS).filter(([, ends]) => ends.some((k) => armed.includes(k))).map(([z]) => z);
  return { level: "warn", title: `${cap(list(armed))} armed; ${list(others, false)} not.`,
           detail: watched.length ? `Watched: zone ${watched.join(", ")}. A zone with one armed end only warns, it can still confirm by 3 hits.${radio}`
                                  : `No zone is watched.${radio}` };
}

export const nodeName = (k) => NAME[k] || k;
