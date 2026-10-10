// Link integrity: the ten radio links of the mesh, how the server reaches the
// gateway, refused packets, and the server's own audit trail.

import { $, h, when } from "./dom.js";
import { linkName, meshLinks, NAME } from "./mesh.js";

const PATH = { direct: "Direct", relayed: "Relayed", partial: "One way", down: "No link", unknown: "—" };
const PATH_TONE = { direct: "good", relayed: "warn", partial: "warn", down: "bad", unknown: "dim" };

const REJECT_NAMES = { signature: "Bad signature", replay: "Replayed", stale: "Stale", malformed: "Malformed",
                       sender: "Unknown sender", type: "Unexpected type" };

export function renderIntegrity(st) {
  const l = st.link || {};
  const links = meshLinks(st.nodes, !!l.gateway);
  $("#mesh-table tbody").replaceChildren(...links.map((m) =>
    h("tr", { "data-state": m.state },
      h("th", { scope: "row" }, linkName(m)),
      h("td", { class: PATH_TONE[m.state] }, PATH[m.state]),
      h("td", { class: "note" }, m.via ? `through ${m.via === "G" ? "gateway" : NAME[m.via]}${m.test ? ", test" : ""}` : m.test ? "test" : ""))));
  const transport = { hardware: "MQTT over TLS from the gateway, signed packets",
                      wokwi: "Public MQTT broker (Wokwi): signed, not encrypted",
                      emulator: "Emulated gateway in the server process" }[l.mode] || "—";
  const facts = [
    ["Broker", l.broker ? "Connected" : "Not connected", l.broker ? "good" : "bad"],
    ["Gateway", l.gateway ? `Up since ${when(l.since, false)}` : l.since ? `Down since ${when(l.since, false)}` : "Waiting", l.gateway ? "good" : "bad"],
  ];
  if (l.mode === "hardware" && l.presence) facts.push(["Broker sees gateway", l.presence === "online" ? "Online" : "Offline", l.presence === "online" ? "good" : "bad"]);
  facts.push(["Transport", transport, ""]);
  $("#facts").replaceChildren(...facts.flatMap(([k, v, c]) => [h("dt", {}, k), h("dd", { class: c }, v)]));

  const r = st.rejects || l.rejected || {};
  const names = Object.keys(REJECT_NAMES);
  $("#rejects").replaceChildren(...names.flatMap((k) => [h("dt", {}, REJECT_NAMES[k]), h("dd", { class: r[k] ? "bad" : "" }, String(r[k] || 0))]));

  $("#audit").replaceChildren(...(st.audit || []).slice(0, 10).map((a) =>
    h("li", { "data-outcome": a.outcome || "" },
      h("span", { class: "when" }, when(a.at, false)),
      h("span", { class: "what" }, `${a.action.toLowerCase()}${a.actor && a.actor !== "server" ? `, ${a.actor}` : ""}${a.ip && a.ip !== "-" ? ` from ${a.ip}` : ""}`),
      h("span", { class: "detail" }, a.detail))));
}
