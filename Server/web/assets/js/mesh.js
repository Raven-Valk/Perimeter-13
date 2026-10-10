// The radio mesh, worked out from each board's NET status field.
//
// Every board reports, for each of the other four (order A B C D G), how it
// reaches it: "D" straight, a lower-case letter = through that board, "?" =
// heard but no way back yet, "-" = not heard. A link is judged from both ends.

export const ORDER = ["A", "B", "C", "D", "G"];
export const PAIRS = [["A", "B"], ["B", "C"], ["C", "D"], ["A", "D"], ["A", "C"], ["B", "D"],
                      ["A", "G"], ["B", "G"], ["C", "G"], ["D", "G"]];
export const NAME = { A: "Module A", B: "Module B", C: "Module C", D: "Module D", G: "Gateway" };
export const short = (k) => (k === "G" ? "GW" : k);

/** How board `from` says it reaches board `to`, or undefined if it isn't reporting. */
function view(nodes, from, to) {
  const n = nodes[from];
  if (!n || n.online === false || typeof n.NET !== "string" || n.NET.length !== 5) return undefined;
  return n.NET[ORDER.indexOf(to)];
}

const cutBy = (nodes, a, b) => String((nodes[a] || {}).CUT || "").includes(b) || String((nodes[b] || {}).CUT || "").includes(a);

/**
 * One entry per link: { a, b, state: "direct" | "relayed" | "partial" | "down" | "unknown", via, test }.
 * via = the relay board's letter when relayed.
 */
export function meshLinks(nodes, gatewayOnline) {
  return PAIRS.map(([a, b]) => {
    const link = { a, b, state: "unknown", via: null, test: cutBy(nodes, a, b) };
    if (!gatewayOnline) return link;
    const seen = [view(nodes, a, b), view(nodes, b, a)].filter((v) => v !== undefined);
    if (!seen.length) return link;
    const relay = seen.find((v) => /^[abcdg]$/.test(v));
    if (seen.every((v) => v === "D")) link.state = "direct";
    else if (relay) { link.state = "relayed"; link.via = relay.toUpperCase(); }
    else if (seen.includes("D") || seen.includes("?")) link.state = "partial";
    else link.state = "down";
    return link;
  });
}

/** "9 direct, 1 relayed" */
export function meshSummary(links) {
  const count = (s) => links.filter((l) => l.state === s).length;
  const parts = [];
  if (count("direct")) parts.push(`${count("direct")} direct`);
  if (count("relayed")) parts.push(`${count("relayed")} relayed`);
  if (count("partial")) parts.push(`${count("partial")} one-way`);
  if (count("down")) parts.push(`${count("down")} down`);
  return parts.join(", ") || "—";
}

export const linkName = (l) => `${short(l.a)}–${short(l.b)}`;
