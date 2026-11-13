/* AEGIS — Threat Detection dashboard
   Vanilla JS, no build step, no external libraries. */
"use strict";

/* ------------------------------------------------------------------ utils */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const esc = (v) =>
  String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

const num = (v) => (v === null || v === undefined ? "–" : Number(v).toLocaleString("en-US"));
const pct = (v, d = 2) => (v === null || v === undefined ? "–" : `${(v * 100).toFixed(d)}%`);
const pct4 = (v) => (v === null || v === undefined ? "–" : `${(v * 100).toFixed(4)}%`);
const dt = (v) => (v ? String(v).replace("T", " ").replace(/:00$/, "") : "–");
function bytes(n) {
  if (n === null || n === undefined) return "–";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return `${n.toFixed(n >= 100 ? 0 : 1)} ${units[i]}`;
}

/* --------------------------------------------------------------- export */
function downloadBlob(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}
function toCsv(rows) {
  if (!rows || !rows.length) return "";
  const keys = Object.keys(rows[0]);
  const escCsv = (v) => {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [keys.join(","), ...rows.map((r) => keys.map((k) => escCsv(r[k])).join(","))].join("\n");
}
function exportJson(filename, data) {
  downloadBlob(filename, JSON.stringify(data, null, 2), "application/json");
}
function exportCsv(filename, rows) {
  downloadBlob(filename, toCsv(rows), "text/csv");
}

/* ------------------------------------------------------------------ state */
const state = {
  overview: null,
  alerts: null,
  incidents: null,
  reports: null,
  hard: null,
  coreAt: 0,
  filters: { q: "", severity: "all", attack: "all" },
  hardVariant: "no_port",
  logOffset: 0,
  logRaw: "",
  logTimer: null,
  statusTimer: null,
  autoScroll: true,
  drawerAlert: null,
};

const CLASS_COLORS = {
  BENIGN: "var(--surface-3)",
  PortScan: "var(--gold)",
  DDoS: "var(--red)",
  "FTP-Patator": "var(--blue)",
  "SSH-Patator": "var(--cyan)",
};

const NAV_TITLES = {
  overview: "Overview",
  alerts: "Alerts",
  incidents: "Incidents",
  reports: "AI Reports",
  evaluation: "Evaluation",
  pipeline: "Pipeline",
};

/* -------------------------------------------------------------------- api */
const cache = new Map();
async function api(path, { force = false } = {}) {
  if (!force) {
    const hit = cache.get(path);
    if (hit && Date.now() - hit.t < 8000) return hit.v;
  }
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (_) {}
    throw new Error(msg);
  }
  const v = await res.json();
  cache.set(path, { v, t: Date.now() });
  return v;
}
function clearCache() { cache.clear(); }

/* ---------------------------------------------------------------- helpers */
function sevBadge(sev) {
  const s = String(sev || "unknown").toLowerCase();
  const cls = ["critical", "high", "medium", "low"].includes(s) ? s : "muted";
  return `<span class="badge ${cls}">${esc(s)}</span>`;
}

function pageHead(eyebrow, title, sub, right = "") {
  return `<div class="page-head">
    <div>
      <div class="eyebrow">${esc(eyebrow)}</div>
      <h1>${esc(title)}</h1>
      <p>${sub}</p>
    </div>
    ${right ? `<div class="head-meta">${right}</div>` : ""}
  </div>`;
}

function emptyState(title, text, icon = "shield") {
  const icons = {
    shield: `<path d="M12 3l9 4.5v5c0 5.2-3.7 8.6-9 9.5-5.3-.9-9-4.3-9-9.5v-5L12 3z"/><path d="M12 8v4"/><circle cx="12" cy="16" r=".6"/>`,
    search: `<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>`,
    file: `<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z"/><path d="M14 3v5h5"/>`,
    terminal: `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>`,
  };
  return `<div class="empty-state">
    <div class="es-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${icons[icon] || icons.shield}</svg></div>
    <h3>${esc(title)}</h3><p>${text}</p>
  </div>`;
}

function kpi(label, value, sub, cls = "") {
  return `<div class="kpi ${cls}">
    <div class="k-label">${esc(label)}</div>
    <div class="k-value">${value}</div>
    <div class="k-sub">${sub}</div>
  </div>`;
}

function metricRow(label, value, cls = "green") {
  const width = Math.max(1.2, Math.min(100, Number(value) * 100));
  return `<div class="metric-row">
    <span class="m-label">${esc(label)}</span>
    <span class="track"><i class="${cls}" style="width:${width}%"></i></span>
    <span class="m-val">${pct(value)}</span>
  </div>`;
}

/* --------------------------------------------------------------- markdown */
function mdToHtml(md) {
  const inline = (s) =>
    esc(s)
      .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
      .replace(/`([^`]+)`/g, "<code>$1</code>");
  const out = [];
  let inList = false;
  for (const raw of String(md || "").split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (/^- /.test(line)) {
      if (!inList) { out.push("<ul>"); inList = true; }
      out.push(`<li>${inline(line.slice(2))}</li>`);
      continue;
    }
    if (inList) { out.push("</ul>"); inList = false; }
    if (/^### /.test(line)) out.push(`<h3>${inline(line.slice(4))}</h3>`);
    else if (/^## /.test(line)) out.push(`<h2>${inline(line.slice(3))}</h2>`);
    else if (/^# /.test(line)) out.push(`<h1>${inline(line.slice(2))}</h1>`);
    else if (/^---+$/.test(line)) out.push("<hr>");
    else if (line.trim()) out.push(`<p>${inline(line.trim())}</p>`);
  }
  if (inList) out.push("</ul>");
  return out.join("\n");
}

/* ---------------------------------------------------------------- routing */
function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [name = "overview", id = null] = raw.split("/");
  return { name: name || "overview", id };
}

function setActiveNav(name) {
  $$(".nav-item").forEach((el) => {
    el.classList.toggle("active", el.dataset.nav === name);
  });
}

function crumbFor(name, id) {
  const base = NAV_TITLES[name] || "Overview";
  return id ? `${base} / ${id}` : base;
}

/* ------------------------------------------------------------------ chrome */
function updateChrome() {
  const d = state.overview;
  if (!d) return;
  const c = d.counts || {};
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  set("#nav-alerts", c.alerts ?? "–");
  set("#nav-incidents", c.incidents ?? "–");
  set("#nav-reports", c.reports ?? "–");
  updateRunPill(d.pipeline);
}

function updateRunPill(p) {
  const pill = $("#run-pill");
  const text = $("#run-pill-text");
  const dot = $("#nav-pipeline-dot");
  if (!pill || !text) return;
  if (!p) {
    pill.dataset.state = "idle";
    text.textContent = "Idle";
  } else if (p.running) {
    pill.dataset.state = "running";
    text.textContent = p.external ? "Pipeline running (external)" : "Pipeline running";
  } else if (p.exit_code !== null && p.exit_code !== undefined && p.exit_code !== 0) {
    pill.dataset.state = "error";
    text.textContent = `Last run failed (${p.exit_code})`;
  } else if (p.exit_code === 0) {
    pill.dataset.state = "done";
    text.textContent = "Last run completed";
  } else {
    pill.dataset.state = "idle";
    text.textContent = "Idle";
  }
  if (dot) dot.hidden = !(p && p.running);
}

/* ---------------------------------------------------------------- loading */
async function ensureCore(force = false) {
  if (!force && state.overview && Date.now() - state.coreAt < 8000) return;
  const [overview, alerts, incidents, reports] = await Promise.all([
    api("/api/overview", { force }),
    api("/api/alerts", { force }),
    api("/api/incidents", { force }),
    api("/api/reports", { force }),
  ]);
  state.overview = overview;
  state.alerts = alerts;
  state.incidents = incidents;
  state.reports = reports;
  state.coreAt = Date.now();
  updateChrome();
}

/* --------------------------------------------------------------- overview */
async function viewOverview() {
  await ensureCore();
  const d = state.overview;
  const m = d.metrics || {};
  const check = d.dataset || {};
  const classes = check.attack_classes || {};
  const total = check.rows || Object.values(classes).reduce((a, b) => a + b, 0);
  const attackFlows = d.counts.attack_flows || 0;
  const tp = m.tp ?? 0, fp = m.fp ?? 0, fn = m.fn ?? 0, tn = m.tn ?? 0;

  const kpis = `<div class="kpis">
    ${kpi("Clean flows", num(total), `${num(Object.keys(classes).length)} classes · ${num(check.duplicate_rows)} duplicates`)}
    ${kpi("Attack flows", num(attackFlows), `${total ? pct(attackFlows / total, 1) : "–"} of dataset`, "warn")}
    ${kpi("Precision", pct(m.precision), `TP ${num(tp)} · FP ${num(fp)}`, "good")}
    ${kpi("Recall", pct(m.recall), `TP ${num(tp)} · FN ${num(fn)}`, "good")}
    ${kpi("F1 score", pct(m.f1), "out-of-fold · all flows", "accent")}
    ${kpi("Incidents", num(d.counts.incidents), `${num(d.counts.alerts)} correlated alerts`, "accent")}
  </div>`;

  const steps = (d.pipeline && d.pipeline.steps) || [];
  const strip = `<section class="panel mb">
    <div class="panel-head">
      <span class="dot"></span><h2>Pipeline</h2>
      <span class="hint">${steps.filter((s) => s.status === "done").length}/${steps.length} stages complete</span>
    </div>
    <div class="strip">
      ${steps.map((s, i) => `
        <div class="strip-step ${s.status}" data-href="#/pipeline" title="${esc(s.detail)}">
          <div class="strip-top">
            <span class="strip-dot">${s.status === "done" ? "✓" : i + 1}</span>
            <span class="strip-name">${esc(s.label)}</span>
          </div>
          <span class="strip-meta">${s.status === "done" ? "complete" : s.status === "partial" ? "partial" : "pending"}</span>
        </div>`).join("")}
    </div>
  </section>`;

  const composition = Object.entries(classes)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count, share: total ? count / total : 0 }));

  const compositionPanel = `<section class="panel">
    <div class="panel-head"><span class="dot"></span><h2>Dataset composition</h2>
      <span class="hint">${num(total)} flows</span></div>
    <div class="stacked">
      ${composition.map((c) => `<span style="width:${(c.share * 100).toFixed(3)}%;background:${CLASS_COLORS[c.name] || "var(--surface-3)"}" title="${esc(c.name)} ${num(c.count)}"></span>`).join("")}
    </div>
    <div class="legend">
      ${composition.map((c) => `<span class="legend-item"><i style="background:${CLASS_COLORS[c.name] || "var(--surface-3)"}"></i>
        <b>${esc(c.name)}</b><em>${num(c.count)} · ${pct(c.share, 1)}</em></span>`).join("")}
    </div>
    <div style="margin-top:18px;padding-top:16px;border-top:1px solid var(--border-soft)" class="chips">
      <span class="chip"><b>${num(Object.keys(check.capture_files || {}).length)}</b> capture files</span>
      <span class="chip"><b>${num(check.columns)}</b> raw columns</span>
      <span class="chip"><b>${num(check.duplicate_rows)}</b> duplicate rows</span>
      <span class="chip blue"><b>dest. port</b> excluded</span>
    </div>
  </section>`;

  const qualityPanel = `<section class="panel">
    <div class="panel-head"><span class="dot"></span><h2>Detection quality</h2>
      <span class="hint">3-fold OOF</span></div>
    ${metricRow("Precision", m.precision, "green")}
    ${metricRow("Recall", m.recall, "green")}
    ${metricRow("F1 score", m.f1, "green")}
    <div class="metric-row">
      <span class="m-label">False positives</span>
      <span class="track"><i class="gold" style="width:${Math.max(1, (fp / Math.max(1, tn + fp)) * 100 * 100)}%"></i></span>
      <span class="m-val">${num(fp)}</span>
    </div>
    <p class="faint" style="font-size:11.5px;margin-top:6px">
      FPR ${pct4(m.false_positive_rate)} — ${num(fp)} false positives out of ${num(tn + fp)} benign flows.
    </p>
  </section>`;

  const anomaly = d.anomaly || {};
  const fused = anomaly.fused || {};
  const iso = anomaly.isolation_forest_only || {};
  const ccAnom = anomaly.cross_capture_anomaly || {};
  const anomalyPanel = Object.keys(fused).length ? `<section class="panel">
    <div class="panel-head"><span class="dot"></span><h2>Anomaly layer</h2>
      <span class="hint">IsolationForest · fused with XGBoost</span></div>
    ${metricRow("XGBoost F1", (d.metrics || {}).f1, "green")}
    ${metricRow("Fused F1", fused.f1, "gold")}
    ${metricRow("Fused FPR", fused.fpr, "gold")}
    <div class="metric-row">
      <span class="m-label">Anomaly layer alone</span>
      <span class="m-val">R ${pct(iso.recall)} · FPR ${pct4(iso.fpr)}</span>
    </div>
    ${Object.keys(ccAnom).length ? `<details style="margin-top:10px">
      <summary class="faint" style="cursor:pointer;font-size:12px">Unseen-capture anomaly recall (${Object.keys(ccAnom).length} captures)</summary>
      <table>
        <thead><tr><th>Capture</th><th class="num">Attack recall</th><th class="num">Benign FPR</th></tr></thead>
        <tbody>${Object.entries(ccAnom).map(([f, v]) => `<tr>
          <td class="mono">${esc(f.replace(/\.pcap_ISCX\.csv$/, ""))}</td>
          <td class="num">${pct(v.unseen_capture_attack_recall)}</td>
          <td class="num">${pct4(v.benign_fpr)}</td></tr>`).join("")}</tbody>
      </table>
    </details>` : ""}
    <p class="faint" style="font-size:11.5px;margin-top:8px">
      Fused = XGBoost alert OR anomaly flag. See the hard-evaluation page for why the anomaly layer matters.
    </p>
  </section>` : "";

  const matrixPanel = `<section class="panel">
    <div class="panel-head"><span class="dot"></span><h2>Confusion matrix</h2>
      <span class="hint">all ${num(tp + fp + fn + tn)} flows</span></div>
    <div class="cm">
      <span></span><span class="cm-h">Predicted attack</span><span class="cm-h">Predicted benign</span>
      <span class="cm-s">Actual attack</span>
      <div class="cell tp"><b>${num(tp)}</b><small>true positive</small></div>
      <div class="cell fn"><b>${num(fn)}</b><small>false negative</small></div>
      <span class="cm-s">Actual benign</span>
      <div class="cell fp"><b>${num(fp)}</b><small>false positive</small></div>
      <div class="cell tn"><b>${num(tn)}</b><small>true negative</small></div>
    </div>
    <p class="faint" style="font-size:11.5px;margin-top:12px">
      Honest evaluation: out-of-fold predictions on every flow, destination port excluded so the model cannot shortcut on 21/22/80.
    </p>
  </section>`;

  const recent = (d.recent_incidents || []);
  const incidentsPanel = `<section class="panel">
    <div class="panel-head"><span class="dot"></span><h2>Recent incidents</h2>
      <span class="hint"><a href="#/incidents" style="color:var(--blue)">View all →</a></span></div>
    ${recent.length ? `<div class="table-wrap" style="border:none;background:transparent">
      <table>
        <thead><tr><th>Incident</th><th>Summary</th><th class="num">Flows</th><th>Last seen</th></tr></thead>
        <tbody>
          ${recent.map((i) => `<tr class="clickable" data-href="#/incidents/${esc(i.incident_id)}">
            <td class="nowrap">${sevBadge(i.severity)} <span class="mono faint">${esc(i.incident_id)}</span></td>
            <td>${esc(i.summary)}</td>
            <td class="num">${num(i.total_flows)}</td>
            <td class="nowrap muted">${dt(i.last_seen)}</td>
          </tr>`).join("")}
        </tbody>
      </table></div>` : emptyState("No incidents yet", "Run the pipeline to correlate alerts into incidents.", "shield")}
  </section>`;

  const tacticCounts = {};
  const techniqueCounts = {};
  (state.alerts || []).forEach((a) => {
    tacticCounts[a.tactic] = (tacticCounts[a.tactic] || 0) + 1;
    const key = `${a.technique_id} ${a.technique}`;
    techniqueCounts[key] = (techniqueCounts[key] || 0) + 1;
  });
  const mitrePanel = `<section class="panel">
    <div class="panel-head"><span class="dot"></span><h2>MITRE ATT&amp;CK coverage</h2>
      <span class="hint">${num(state.alerts.length)} alerts</span></div>
    <div class="d-sec" style="margin-top:0">
      <h4>Tactics observed</h4>
      <div class="chips">
        ${Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
          `<span class="chip gold"><b>${esc(k)}</b> ×${v}</span>`).join("") || `<span class="chip">none</span>`}
      </div>
    </div>
    <div class="d-sec">
      <h4>Techniques observed</h4>
      <div class="chips">
        ${Object.entries(techniqueCounts).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
          `<span class="chip blue"><b>${esc(k)}</b> ×${v}</span>`).join("") || `<span class="chip">none</span>`}
      </div>
    </div>
    <p class="faint" style="font-size:11.5px;margin-top:14px">
      Mapping is rules-based on the detected attack class (T1595 scanning, T1498 flooding, T1110.001 brute force).
    </p>
  </section>`;

  return `${pageHead("Live overview", "Detection at a glance",
    `CICIDS2017 · ${num(total)} flows · ${num(Object.keys(classes).length)} classes · fully offline`,
    `<span class="chip green">Updated ${new Date(d.generated_at).toLocaleTimeString()}</span>`)}
    ${kpis}${strip}
    <div class="grid two mb">${compositionPanel}${qualityPanel}</div>
    <div class="grid two mb">${matrixPanel}${anomalyPanel || mitrePanel}</div>
    ${anomalyPanel ? `<div class="grid mb">${mitrePanel}</div>` : ""}
    ${incidentsPanel}`;
}

/* ----------------------------------------------------------------- alerts */
function alertMatches(a) {
  const f = state.filters;
  const q = f.q.trim().toLowerCase();
  if (f.severity !== "all" && a.severity !== f.severity) return false;
  if (f.attack !== "all" && a.attack_type !== f.attack) return false;
  if (!q) return true;
  return [a.alert_id, a.source_ip, a.attack_type, a.technique_id, a.technique, a.tactic,
    a.top_target, a.severity]
    .some((v) => String(v ?? "").toLowerCase().includes(q));
}

function alertRows() {
  const rows = (state.alerts || []).filter(alertMatches);
  if (!rows.length) {
    return `<tr><td colspan="8">${emptyState("No matching alerts", "Adjust the filters or run the pipeline to generate alerts.", "search")}</td></tr>`;
  }
  return rows.map((a) => `<tr class="clickable" data-alert="${esc(a.alert_id)}">
    <td class="mono">${esc(a.alert_id)}</td>
    <td class="nowrap muted">${dt(a.first_seen)}</td>
    <td class="mono">${esc(a.source_ip)}</td>
    <td><b>${esc(a.attack_type)}</b></td>
    <td><span class="chip blue">${esc(a.technique_id)}</span></td>
    <td class="muted nowrap">${esc(a.tactic)}</td>
    <td class="num">${num(a.flows)}</td>
    <td>${sevBadge(a.severity)}</td>
  </tr>`).join("");
}

async function viewAlerts() {
  await ensureCore();
  const alerts = state.alerts || [];
  const attacks = [...new Set(alerts.map((a) => a.attack_type))].sort();
  const severities = ["critical", "high", "medium", "low"].filter((s) => alerts.some((a) => a.severity === s));

  return `${pageHead("Detection layer", "Alerts",
    "Bursts of malicious flows grouped by source and attack type, each mapped to a MITRE ATT&amp;CK technique.",
    `<span class="chip">${num(alerts.length)} total</span>`)}

  <div class="toolbar">
    <label class="search">
      <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
      <input id="alert-search" type="search" placeholder="Search IP, attack, technique…" value="${esc(state.filters.q)}">
    </label>
    <select id="alert-sev" aria-label="Filter by severity">
      <option value="all">All severities</option>
      ${severities.map((s) => `<option value="${s}" ${state.filters.severity === s ? "selected" : ""}>${s[0].toUpperCase() + s.slice(1)}</option>`).join("")}
    </select>
    <select id="alert-attack" aria-label="Filter by attack type">
      <option value="all">All attack types</option>
      ${attacks.map((s) => `<option value="${esc(s)}" ${state.filters.attack === s ? "selected" : ""}>${esc(s)}</option>`).join("")}
    </select>
    <button class="btn ghost" data-action="reset-alert-filters">Reset</button>
    <span class="spacer"></span>
    <button class="btn ghost" data-action="export-alerts-json">Export JSON</button>
    <button class="btn ghost" data-action="export-alerts-csv">Export CSV</button>
    <span class="count-label" id="alert-count"></span>
  </div>

  <div class="table-wrap">
    <table>
      <thead><tr><th>Alert</th><th>First seen</th><th>Source</th><th>Attack</th><th>Technique</th><th>Tactic</th><th class="num">Flows</th><th>Severity</th></tr></thead>
      <tbody id="alert-rows">${alertRows()}</tbody>
    </table>
  </div>`;
}

function refreshAlertTable() {
  const rows = $("#alert-rows");
  if (!rows) return;
  rows.innerHTML = alertRows();
  const count = $("#alert-count");
  if (count) count.textContent = `${(state.alerts || []).filter(alertMatches).length} of ${(state.alerts || []).length} alerts`;
}

/* -------------------------------------------------------------- incidents */
async function viewIncidents() {
  await ensureCore();
  const incidents = state.incidents || [];
  if (!incidents.length) {
    return `${pageHead("Correlation layer", "Incidents", "Alerts chained by source into multi-stage incidents.")}
      <section class="panel">${emptyState("No incidents yet", "Run the pipeline to correlate alerts into incidents.", "shield")}</section>`;
  }
  const cards = incidents.map((i) => `<article class="incident-card" data-sev="${esc(i.severity)}" data-href="#/incidents/${esc(i.incident_id)}">
    <div class="ic-top">${sevBadge(i.severity)}<span class="ic-id">${esc(i.incident_id)}</span></div>
    <h3>${esc(i.summary)}</h3>
    <div class="ic-meta">
      <span>Source <b class="mono">${esc(i.source_ip)}</b></span>
      <span>Flows <b>${num(i.total_flows)}</b></span>
      <span>Alerts <b>${num((i.alert_ids || []).length)}</b></span>
      <span>Targets <b>${esc((i.targets || []).join(", "))}</b></span>
    </div>
    <div class="ic-foot">
      ${(i.tactics || []).map((t) => `<span class="chip gold">${esc(t)}</span>`).join("")}
      <span class="spacer"></span>
      <span class="faint" style="font-size:11px">${dt(i.first_seen)}</span>
    </div>
  </article>`).join("");
  return `${pageHead("Correlation layer", "Incidents",
    "Alerts from the same source chained across time into multi-stage incidents, with severity escalation.",
    `<span class="chip">${num(incidents.length)} incidents</span>
     <button class="btn ghost" data-action="export-incidents-json">Export JSON</button>
     <button class="btn ghost" data-action="export-incidents-csv">Export CSV</button>`)}
    <div class="cards-grid">${cards}</div>`;
}

async function viewIncidentDetail(id) {
  await ensureCore();
  let data;
  try { data = await api(`/api/incidents/${encodeURIComponent(id)}`); }
  catch (_) {
    return `<a class="back-link" href="#/incidents"><svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>Back to incidents</a>
      ${emptyState("Incident not found", `No incident with id ${esc(id)}.`, "search")}`;
  }
  const inc = data.incident;
  const linked = data.alerts || [];
  const offline = data.reports && data.reports.offline;
  const llm = data.reports && data.reports.llm;
  const hasReport = offline || llm;

  const alertsTable = linked.length ? `<div class="table-wrap">
    <table>
      <thead><tr><th>Alert</th><th>Attack</th><th>Technique</th><th class="num">Flows</th><th class="num">Confidence</th><th>Severity</th></tr></thead>
      <tbody>${linked.map((a) => `<tr class="clickable" data-alert="${esc(a.alert_id)}">
        <td class="mono">${esc(a.alert_id)}</td>
        <td><b>${esc(a.attack_type)}</b></td>
        <td><span class="chip blue">${esc(a.technique_id)}</span> <span class="muted">${esc(a.technique)}</span></td>
        <td class="num">${num(a.flows)}</td>
        <td class="num">${(Number(a.avg_confidence) * 100).toFixed(2)}%</td>
        <td>${sevBadge(a.severity)}</td>
      </tr>`).join("")}</tbody>
    </table></div>` : `<p class="muted">No linked alerts.</p>`;

  const tabButtons = [
    offline ? `<button class="tab active" data-tab="offline">Knowledge base</button>` : "",
    llm ? `<button class="tab ${offline ? "" : "active"}" data-tab="llm">LLM report</button>` : "",
  ].join("");
  const tabPanels = [
    offline ? `<div data-panel="offline" class="md">${mdToHtml(offline)}</div>` : "",
    llm ? `<div data-panel="llm" class="md" ${offline ? "hidden" : ""}>${mdToHtml(llm)}</div>` : "",
  ].join("");

  return `<a class="back-link" href="#/incidents"><svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>Back to incidents</a>
  <div class="detail-head">
    <div>
      <div class="chips mb" style="margin-bottom:8px">${sevBadge(inc.severity)}<span class="chip mono">${esc(inc.incident_id)}</span></div>
      <h1>${esc(inc.summary)}</h1>
      <p class="sub">${esc(inc.source_ip)} → ${esc((inc.targets || []).join(", "))} · ${dt(inc.first_seen)} → ${dt(inc.last_seen)}</p>
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-box"><div class="m-label">Total flows</div><div class="m-value">${num(inc.total_flows)}</div></div>
    <div class="meta-box"><div class="m-label">Alerts</div><div class="m-value">${num((inc.alert_ids || []).length)}</div></div>
    <div class="meta-box"><div class="m-label">Tactics</div><div class="m-value" style="font-size:12px">${esc((inc.tactics || []).join(" → "))}</div></div>
    <div class="meta-box"><div class="m-label">Techniques</div><div class="m-value mono" style="font-size:12px">${esc((inc.techniques || []).join(", "))}</div></div>
  </div>

  <div class="grid two-eq">
    <section class="panel">
      <div class="panel-head"><span class="dot"></span><h2>Linked alerts</h2><span class="hint">${linked.length}</span></div>
      ${alertsTable}
    </section>
    <section class="panel">
      <div class="panel-head"><span class="dot"></span><h2>AI SOC assistant</h2><span class="hint">analyst report</span></div>
      ${hasReport ? `<div class="tabs">${tabButtons}</div>${tabPanels}` :
        emptyState("No report yet", `Generate one with <code>python step4_assistant.py --incident ${esc(inc.incident_id)} --mode offline</code>.`, "file")}
    </section>
  </div>`;
}

/* ---------------------------------------------------------------- reports */
async function viewReports() {
  await ensureCore();
  const reports = state.reports || [];
  if (!reports.length) {
    return `${pageHead("AI layer", "AI analyst reports", "Offline knowledge-base reports written per incident.")}
      <section class="panel">${emptyState("No reports yet", "Run step 4 to generate analyst reports.", "file")}</section>`;
  }
  return `${pageHead("AI layer", "AI analyst reports",
    "Deterministic, offline knowledge-base reports: summary, timeline, ATT&amp;CK mapping, actions and caveats.",
    `<span class="chip">${num(reports.length)} reports</span>
     <button class="btn ghost" data-action="export-reports-json">Export JSON</button>
     <button class="btn ghost" data-action="export-reports-csv">Export CSV</button>`)}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Report</th><th>Incident</th><th>Mode</th><th class="num">Size</th><th>Updated</th></tr></thead>
        <tbody>${reports.map((r) => `<tr class="clickable" data-href="#/reports/${esc(r.id)}">
          <td class="mono">${esc(r.id)}</td>
          <td>${esc(r.incident_id)}</td>
          <td><span class="badge ${r.mode === "llm" ? "info" : "muted"}">${esc(r.mode)}</span></td>
          <td class="num muted">${bytes(r.size)}</td>
          <td class="nowrap muted">${dt(r.updated)}</td>
        </tr>`).join("")}</tbody>
      </table>
    </div>`;
}

async function viewReportDetail(id) {
  await ensureCore();
  let data;
  try { data = await api(`/api/reports/${encodeURIComponent(id)}`); }
  catch (_) {
    return `<a class="back-link" href="#/reports"><svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>Back to reports</a>
      ${emptyState("Report not found", `No report with id ${esc(id)}.`, "search")}`;
  }
  return `<a class="back-link" href="#/reports"><svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>Back to reports</a>
    <div class="detail-head">
      <div>
        <div class="chips mb" style="margin-bottom:8px"><span class="chip blue">AI report</span><span class="chip mono">${esc(data.id)}</span></div>
        <h1>${esc(data.id)}</h1>
        <p class="sub">Updated ${dt(data.updated)}</p>
      </div>
      <span class="spacer"></span>
      <a class="btn" href="#/incidents/${esc(data.id.split("_")[0])}">Open incident</a>
    </div>
    <section class="panel md">${mdToHtml(data.markdown)}</section>`;
}

/* ------------------------------------------------------------- evaluation */
function hardSummaryBlock(h, label) {
  if (!h || !h.overall) return "";
  const o = h.overall;
  return `<div class="kpis" style="grid-template-columns:repeat(4,1fr);margin-bottom:0">
    ${kpi("Precision", pct(o.precision), label, "good")}
    ${kpi("Recall", pct(o.recall), label, "good")}
    ${kpi("F1", pct(o.f1), label, "accent")}
    ${kpi("FPR", pct4(o.fpr), label, "warn")}
  </div>`;
}

async function viewEvaluation() {
  const data = await api("/api/hard-eval");
  const noPort = data.hard_eval;
  const withPort = data.hard_eval_with_port;
  state.hard = { no_port: noPort, with_port: withPort };
  const hard = state.hardVariant === "with_port" && withPort && Object.keys(withPort).length ? withPort : noPort;
  if (!hard || !Object.keys(hard).length) {
    return `${pageHead("Rigour", "Evaluation", "Chronological, leave-one-attack-out and cross-capture evaluation.")}
      <section class="panel">${emptyState("No evaluation yet", "Run step 5 to produce hard_eval.json.", "terminal")}</section>`;
  }
  const chrono = hard.chronological || {};
  const loo = hard.leave_one_attack_out || {};
  const cc = hard.cross_capture || {};
  const variantToggle = withPort && Object.keys(withPort).length ? `<div class="chips">
      <button class="btn ${state.hardVariant === "no_port" ? "primary" : ""}" data-action="hard-variant" data-variant="no_port">No dest. port</button>
      <button class="btn ${state.hardVariant === "with_port" ? "primary" : ""}" data-action="hard-variant" data-variant="with_port">With dest. port</button>
    </div>` : "";

  const chronoPanel = `<section class="panel">
    <div class="panel-head"><span class="dot"></span><h2>Chronological split</h2>
      <span class="hint">train early, test later</span></div>
    ${hardSummaryBlock(chrono, "held-out period")}
    ${chrono.per_attack_recall ? `<div class="table-wrap mt">
      <table><thead><tr><th>Attack</th><th class="num">Test flows</th><th class="num">Recall</th><th>In training</th></tr></thead>
      <tbody>${Object.entries(chrono.per_attack_recall).map(([k, v]) => `<tr>
        <td><b>${esc(k)}</b></td><td class="num">${num(v.test_flows)}</td>
        <td class="num">${pct(v.recall)}</td>
        <td><span class="badge ${v.flag === "NOT TESTED" ? "medium" : "muted"}">${esc(v.flag || "–")}</span></td>
      </tr>`).join("")}</tbody></table></div>` : ""}
  </section>`;

  const looEntries = Object.entries(loo);
  const maxRecall = Math.max(...looEntries.map(([, v]) => v.unseen_attack_recall), 0.0001);
  const looPanel = `<section class="panel">
    <div class="panel-head"><span class="dot"></span><h2>Leave-one-attack-out</h2>
      <span class="hint">attack type never seen in training</span></div>
    ${looEntries.length ? looEntries.map(([k, v]) => `
      <div class="metric-row" style="grid-template-columns:130px 1fr 118px">
        <span class="m-label">${esc(k)}</span>
        <span class="track"><i class="gold" style="width:${Math.max(1.5, (v.unseen_attack_recall / maxRecall) * 100)}%"></i></span>
        <span class="m-val">${pct(v.unseen_attack_recall)} <span class="faint" style="font-weight:500">recall</span></span>
      </div>
      <div class="faint" style="font-size:11px;margin:-4px 0 12px 142px">benign FPR ${pct4(v.benign_fpr)}</div>
    `).join("") : `<p class="muted">No LOAO data.</p>`}
    <p class="note faint" style="font-size:11.5px;margin-top:8px;padding-left:10px;border-left:2px solid var(--gold)">
      This is the honest weak spot: a supervised model generalises poorly to attacks it has never seen.
      PortScan drops to almost zero. The roadmap fix is an unsupervised anomaly layer.
    </p>
  </section>`;

  const ccBlocks = Object.entries(cc).map(([capture, c]) => {
    const per = c.per_attack_recall || {};
    return `<details class="panel" style="padding:0;overflow:hidden">
      <summary style="cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <b style="font-size:13px">${esc(capture)}</b>
        <span class="spacer"></span>
        <span class="chip">P ${pct(c.overall.precision)}</span>
        <span class="chip">R ${pct(c.overall.recall)}</span>
        <span class="chip">F1 ${pct(c.overall.f1)}</span>
      </summary>
      <div style="padding:0 20px 18px">
        <div class="table-wrap"><table>
          <thead><tr><th>Class</th><th class="num">Test flows</th><th class="num">Recall</th><th>Flag</th></tr></thead>
          <tbody>${Object.entries(per).map(([k, v]) => `<tr>
            <td><b>${esc(k)}</b></td><td class="num">${num(v.test_flows)}</td>
            <td class="num">${pct(v.recall)}</td>
            <td><span class="badge ${v.flag === "NOT TESTED" ? "medium" : "muted"}">${esc(v.flag || "–")}</span></td>
          </tr>`).join("")}</tbody>
        </table></div>
      </div>
    </details>`;
  }).join("");

  return `${pageHead("Rigour", "Evaluation",
    "Three harder tests than a random split: time-based holdout, unseen attack classes, and unseen captures.",
    variantToggle)}
    ${chronoPanel}
    <div class="mt">${looPanel}</div>
    <h2 style="font-size:14px;margin:22px 0 10px">Cross-capture</h2>
    <p class="muted" style="font-size:12.5px;margin-bottom:12px">Train on the other days and test on a completely held-out capture. "NOT TESTED" means the class was absent from training — a real zero-shot test.</p>
    <div style="display:flex;flex-direction:column;gap:10px">${ccBlocks || `<p class="muted">No cross-capture data.</p>`}</div>`;
}

/* --------------------------------------------------------------- pipeline */
function stepNumber(label) {
  const m = String(label).match(/^Step (\d+[a-z]?)/i);
  return m ? m[1] : null;
}

function renderSteps(pipeline) {
  const steps = (pipeline && pipeline.steps) || [];
  const runningStep = pipeline && pipeline.running ? extractRunningStep(state.logRaw) : null;
  return steps.map((s) => {
    const isRunning = runningStep && stepNumber(`Step ${s.id.replace("step", "")}`) === runningStep;
    const status = isRunning ? "running" : s.status;
    return `<div class="step ${status}">
      <span class="st-dot">${status === "done" ? "✓" : isRunning ? "▶" : status === "partial" ? "•" : ""}</span>
      <div class="st-body">
        <div class="st-title">${esc(s.label)}
          ${isRunning ? `<span class="badge info">running</span>` : status === "done" ? `<span class="badge low">done</span>` : status === "partial" ? `<span class="badge medium">partial</span>` : `<span class="badge muted">pending</span>`}
        </div>
        <div class="st-detail">${esc(s.detail)}</div>
        <div class="st-artifacts">
          ${(s.artifacts || []).map((a) => `<span class="artifact ${a.exists ? "" : "missing"}" title="${esc(a.path)}">${esc(a.path)}${a.exists && a.size ? ` · ${bytes(a.size)}` : ""}</span>`).join("")}
        </div>
      </div>
    </div>`;
  }).join("");
}

function extractRunningStep(text) {
  if (!text) return null;
  const re = /Running: Step (\d+[a-z]?):/g;
  let m, last = null;
  while ((m = re.exec(text))) last = m[1];
  return last;
}

async function viewPipeline() {
  await ensureCore();
  const pipeline = state.overview.pipeline || {};
  return `${pageHead("Orchestration", "Pipeline",
    "Run the six-step pipeline from here and watch every stage stream its output live.",
    `<span class="chip">${(pipeline.steps || []).filter((s) => s.status === "done").length}/${(pipeline.steps || []).length} stages complete</span>`)}
  <div class="pipe-layout">
    <section class="panel">
      <div class="panel-head"><span class="dot"></span><h2>Stages</h2>
        <span class="hint" id="pipe-state-label">${pipeline.running ? (pipeline.external ? "external run" : "running") : "idle"}</span></div>
      <div class="controls mb">
        <button class="btn primary" data-action="run-pipeline" ${pipeline.running ? "disabled" : ""}>
          <svg viewBox="0 0 24 24"><path d="M7 4l13 8-13 8V4z"/></svg>Run pipeline
        </button>
        <button class="btn danger" data-action="stop-pipeline" ${!pipeline.running || pipeline.external ? "disabled" : ""}>
          <svg viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>Stop
        </button>
        <span class="spacer"></span>
        <a class="btn ghost" href="/demo.html" target="_blank" rel="noopener">Open demo page</a>
      </div>
      <div class="step-list" id="step-list">${renderSteps(pipeline)}</div>
    </section>
    <section>
      <div class="console-wrap">
        <div class="console-head">
          <span class="lights"><i></i><i></i><i></i></span>
          <span class="c-title">pipeline.log</span>
          <span class="c-actions">
            <button data-action="toggle-autoscroll" id="autoscroll-btn">auto-scroll: on</button>
            <button data-action="clear-console">clear</button>
          </span>
        </div>
        <pre class="console" id="console">${pipeline.external
          ? '<span class="empty">A pipeline is running outside the dashboard, so its output is not captured here. This view refreshes from the artifact files.</span>'
          : '<span class="empty">Pipeline output will appear here. Press “Run pipeline” to start.</span>'}</pre>
      </div>
    </section>
  </div>`;
}

/* --------------------------------------------------------------- log view */
function appendLog(text) {
  const con = $("#console");
  if (!con) return;
  if (con.querySelector(".empty")) con.innerHTML = "";
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (i === lines.length - 1 && line === "") continue;
    const span = document.createElement("span");
    span.className = "ln " + (/SUCCESS|saved|completed/i.test(line) ? "ok"
      : /ERROR|Traceback|failed with return code/i.test(line) ? "err"
      : /Running: Step|^=+$/i.test(line) ? "step"
      : /^Found |skipping/i.test(line) ? "dim" : "");
    span.textContent = line;
    con.appendChild(span);
  }
  if (state.autoScroll) con.scrollTop = con.scrollHeight;
}

function updatePipelineUi(pipeline) {
  updateRunPill(pipeline);
  const list = $("#step-list");
  if (list) list.innerHTML = renderSteps(pipeline);
  const label = $("#pipe-state-label");
  if (label) label.textContent = pipeline.running ? (pipeline.external ? "external run" : "running") : (pipeline.exit_code === 0 ? "last run ok" : pipeline.exit_code ? "last run failed" : "idle");
  const runBtn = $('[data-action="run-pipeline"]');
  const stopBtn = $('[data-action="stop-pipeline"]');
  if (runBtn) runBtn.disabled = !!pipeline.running;
  if (stopBtn) stopBtn.disabled = !pipeline.running || pipeline.external;
  if (pipeline.running && !pipeline.external) startLogPolling();
}

async function pollLog() {
  if (parseRoute().name !== "pipeline") { stopLogPolling(); return; }
  try {
    const res = await api(`/api/pipeline/log?offset=${state.logOffset}`, { force: true });
    if (res.text) {
      state.logOffset = res.offset;
      state.logRaw = (state.logRaw + res.text).slice(-400000);
      appendLog(res.text);
    }
    const st = await api("/api/pipeline", { force: true });
    updateRunPill(st);
    if (!st.running) {
      stopLogPolling();
      updatePipelineUi(st);
      clearCache();
    }
  } catch (err) {
    stopLogPolling();
  }
}

let _eventSource = null;
function stopLogPolling() {
  if (state.logTimer) clearInterval(state.logTimer);
  state.logTimer = null;
  if (_eventSource) { try { _eventSource.close(); } catch (_) {} _eventSource = null; }
}
function startLogPolling() {
  if (state.logTimer || _eventSource) return;
  if (typeof EventSource !== "undefined") {
    try {
      _eventSource = new EventSource("/api/pipeline/events");
      _eventSource.addEventListener("log", (e) => {
        let text = "";
        try { text = JSON.parse(e.data); } catch (_) { text = e.data; }
        if (text) {
          state.logOffset += text.length;
          state.logRaw = (state.logRaw + text).slice(-400000);
          appendLog(text);
        }
      });
      _eventSource.addEventListener("status", (e) => {
        try {
          const st = JSON.parse(e.data);
          updateRunPill(st);
          const list = $("#step-list");
          if (list) list.innerHTML = renderSteps(st);
          const label = $("#pipe-state-label");
          if (label) label.textContent = st.running ? (st.external ? "external run" : "running") : (st.exit_code === 0 ? "last run ok" : st.exit_code ? "last run failed" : "idle");
          const runBtn = $('[data-action="run-pipeline"]');
          const stopBtn = $('[data-action="stop-pipeline"]');
          if (runBtn) runBtn.disabled = !!st.running;
          if (stopBtn) stopBtn.disabled = !st.running || st.external;
        } catch (_) {}
      });
      _eventSource.addEventListener("done", (e) => {
        try {
          const st = JSON.parse(e.data);
          updatePipelineUi(st);
          clearCache();
        } catch (_) {}
        stopLogPolling();
      });
      _eventSource.onerror = () => {
        // Fall back to polling if SSE fails.
        if (_eventSource) { try { _eventSource.close(); } catch (_) {} _eventSource = null; }
        state.logTimer = setInterval(pollLog, 1200);
        pollLog();
      };
      return;
    } catch (_) { /* fall through to polling */ }
  }
  state.logTimer = setInterval(pollLog, 1200);
  pollLog();
}

/* ----------------------------------------------------------------- draw */
function openAlertDrawer(id) {
  const a = (state.alerts || []).find((x) => x.alert_id === id);
  if (!a) return;
  state.drawerAlert = id;
  const rows = [
    ["Alert", a.alert_id], ["Source IP", a.source_ip], ["Attack", a.attack_type],
    ["First seen", dt(a.first_seen)], ["Last seen", dt(a.last_seen)],
    ["Flows", num(a.flows)], ["Top target", a.top_target],
    ["Target hosts", num(a.target_hosts)], ["Target ports", num(a.target_ports)],
    ["Avg confidence", `${(Number(a.avg_confidence) * 100).toFixed(2)}%`],
    ["Technique", `${a.technique_id} · ${a.technique}`], ["Tactic", a.tactic],
  ];
  $("#drawer-body").innerHTML = `
    <div class="chips" style="margin-bottom:10px">${sevBadge(a.severity)}<span class="chip mono">${esc(a.alert_id)}</span></div>
    <h2 id="drawer-title">${esc(a.attack_type)} from ${esc(a.source_ip)}</h2>
    <p class="d-sub">Detected burst mapped to ${esc(a.technique_id)} (${esc(a.tactic)}).</p>
    <div class="d-sec"><h4>Details</h4><div class="d-rows">
      ${rows.map(([k, v]) => `<div class="d-row"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join("")}
    </div></div>
    <div class="d-sec"><h4>Response hint</h4>
      <p class="muted" style="font-size:12.5px">Confirm with firewall and server logs, then block or rate-limit the source. Source IPs can be NAT or shared, so attribution is not implied.</p>
    </div>`;
  $("#drawer").hidden = false;
  document.body.style.overflow = "hidden";
}

function closeDrawer() {
  $("#drawer").hidden = true;
  state.drawerAlert = null;
  document.body.style.overflow = "";
}

/* ------------------------------------------------------------------ toast */
let toastTimer = null;
function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.toggle("error", isError);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
}

/* ------------------------------------------------------------- rendering */
let renderToken = 0;

async function render() {
  const token = ++renderToken;
  const { name, id } = parseRoute();
  setActiveNav(name in NAV_TITLES ? name : "overview");
  $("#crumb").textContent = crumbFor(name, id);
  document.title = `AEGIS · ${crumbFor(name, id)}`;

  let html;
  try {
    if (name === "alerts") html = await viewAlerts();
    else if (name === "incidents") html = id ? await viewIncidentDetail(id) : await viewIncidents();
    else if (name === "reports") html = id ? await viewReportDetail(id) : await viewReports();
    else if (name === "evaluation") html = await viewEvaluation();
    else if (name === "pipeline") html = await viewPipeline();
    else html = await viewOverview();
  } catch (err) {
    html = `${pageHead("Error", "Could not load data", "The dashboard could not reach its API or read the artifacts.")}
      <section class="panel">${emptyState("Request failed", esc(err.message), "terminal")}</section>`;
  }
  if (token !== renderToken) return;
  $("#view").innerHTML = html;

  if (name === "alerts") {
    const count = $("#alert-count");
    if (count) count.textContent = `${(state.alerts || []).filter(alertMatches).length} of ${(state.alerts || []).length} alerts`;
  }
  if (name === "pipeline") {
    state.logOffset = 0;
    state.logRaw = "";
    await refreshPipeline();
  }
  if (name === "evaluation") { /* toggle handled by re-render */ }
  updateChrome();
}

async function refreshPipeline() {
  try {
    const st = await api("/api/pipeline", { force: true });
    if (parseRoute().name !== "pipeline") return;
    updatePipelineUi(st);
    const hasLog = st.log_available;
    if ((st.running && !st.external) || (!st.running && hasLog)) {
      if (!state.logTimer) startLogPolling();
    }
  } catch (_) {}
}

/* -------------------------------------------------------------- actions */
async function runPipeline() {
  try {
    const res = await fetch("/api/pipeline/start", { method: "POST" });
    const data = await res.json();
    if (!res.ok || !data.ok) { toast(data.message || "Could not start pipeline", true); return; }
    toast("Pipeline started");
    state.logOffset = 0;
    state.logRaw = "";
    const con = $("#console");
    if (con) con.innerHTML = "";
    startLogPolling();
    clearCache();
    setTimeout(refreshPipeline, 600);
  } catch (err) {
    toast(err.message, true);
  }
}

async function stopPipeline() {
  try {
    const res = await fetch("/api/pipeline/stop", { method: "POST" });
    const data = await res.json();
    if (!res.ok || !data.ok) { toast(data.message || "Could not stop pipeline", true); return; }
    toast("Pipeline stopped");
    clearCache();
    setTimeout(refreshPipeline, 600);
  } catch (err) {
    toast(err.message, true);
  }
}

/* ------------------------------------------------------------------ events */
document.addEventListener("click", (e) => {
  const close = e.target.closest("[data-close-drawer]");
  if (close) { closeDrawer(); return; }

  const href = e.target.closest("[data-href]");
  if (href) { location.hash = href.dataset.href; return; }

  const alertEl = e.target.closest("[data-alert]");
  if (alertEl) { openAlertDrawer(alertEl.dataset.alert); return; }

  const tab = e.target.closest("[data-tab]");
  if (tab) {
    $$(".tab").forEach((t) => t.classList.toggle("active", t === tab));
    $$("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== tab.dataset.tab; });
    return;
  }

  const action = e.target.closest("[data-action]");
  if (!action) return;
  const a = action.dataset.action;
  if (a === "run-pipeline") runPipeline();
  else if (a === "stop-pipeline") stopPipeline();
  else if (a === "reset-alert-filters") {
    state.filters = { q: "", severity: "all", attack: "all" };
    render();
  } else if (a === "hard-variant") {
    state.hardVariant = action.dataset.variant;
    render();
  } else if (a === "clear-console") {
    const con = $("#console");
    if (con) con.innerHTML = "";
    state.logRaw = "";
  } else if (a.startsWith("export-")) {
    if (a === "export-alerts-json") exportJson("alerts.json", (state.alerts || []).filter(alertMatches));
    else if (a === "export-alerts-csv") exportCsv("alerts.csv", (state.alerts || []).filter(alertMatches));
    else if (a === "export-incidents-json") exportJson("incidents.json", state.incidents || []);
    else if (a === "export-incidents-csv") exportCsv("incidents.csv", state.incidents || []);
    else if (a === "export-reports-json") exportJson("reports.json", state.reports || []);
    else if (a === "export-reports-csv") exportCsv("reports.csv", state.reports || []);
  } else if (a === "toggle-autoscroll") {
    state.autoScroll = !state.autoScroll;
    action.textContent = `auto-scroll: ${state.autoScroll ? "on" : "off"}`;
    if (state.autoScroll) {
      const con = $("#console");
      if (con) con.scrollTop = con.scrollHeight;
    }
  }
});

document.addEventListener("input", (e) => {
  if (e.target.id === "alert-search") { state.filters.q = e.target.value; refreshAlertTable(); }
});
document.addEventListener("change", (e) => {
  if (e.target.id === "alert-sev") { state.filters.severity = e.target.value; refreshAlertTable(); }
  if (e.target.id === "alert-attack") { state.filters.attack = e.target.value; refreshAlertTable(); }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("#drawer").hidden) closeDrawer();
});

$("#theme-btn").addEventListener("click", () => {
  const root = document.documentElement;
  const next = root.dataset.theme === "dark" ? "light" : "dark";
  root.dataset.theme = next;
  try { localStorage.setItem("aegis-theme", next); } catch (_) {}
});

$("#refresh-btn").addEventListener("click", async () => {
  clearCache();
  state.coreAt = 0;
  await render();
  toast("Data refreshed");
});

$("#menu-btn").addEventListener("click", () => {
  $("#sidebar").classList.toggle("open");
});

window.addEventListener("hashchange", () => {
  stopLogPolling();
  $("#sidebar").classList.remove("open");
  render();
});

/* periodic status check (keeps the run pill honest everywhere) */
setInterval(async () => {
  try {
    const st = await api("/api/pipeline", { force: true });
    updateRunPill(st);
  } catch (_) {}
}, 5000);

/* ------------------------------------------------------------------- boot */
(function boot() {
  let theme = "dark";
  try { theme = localStorage.getItem("aegis-theme") || theme; } catch (_) {}
  if (!localStorage.getItem("aegis-theme") && window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: light)").matches) theme = "light";
  document.documentElement.dataset.theme = theme;

  if (!location.hash) location.hash = "#/overview";
  render();
})();
