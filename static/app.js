// ZeroWatch console. Plain JavaScript, no build step: every view is a function
// that fetches JSON from the FastAPI service and renders HTML.
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pct = (v) => (v * 100).toFixed(1) + "%";
const VERDICT = { benign: "Benign", attack: "Known attack", zero_day_suspect: "Possible zero-day", uncertain: "Not sure, needs review" };
const TONE = { benign: "benign", attack: "attack", zero_day_suspect: "suspect", uncertain: "uncertain" };
const GROUPS = [
  ["Connection", ["protocol_type", "service", "flag", "duration", "logged_in"]],
  ["Payload and host activity", ["src_bytes", "dst_bytes", "wrong_fragment", "hot", "num_failed_logins", "root_shell"]],
  ["Same source, last two seconds", ["count", "srv_count", "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate"]],
  ["Destination host history", ["dst_host_count", "dst_host_srv_count", "dst_host_serror_rate"]],
];
let contract = null, lastFlow = null, lastResult = null;

async function api(path, body) {
  const res = await fetch(path, body === undefined ? {} : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error("HTTP " + res.status), { status: res.status, data });
  return data;
}

// ---------- theme ----------
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("zw-theme", t); } catch (e) { /* private mode */ }
  $("#theme").textContent = t === "dark" ? "Light theme" : "Dark theme";
}
$("#theme").onclick = () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
setTheme(document.documentElement.dataset.theme);

// ---------- tabs ----------
const loaders = { model: loadModel, monitor: loadMonitor, hunt: loadHunt, assets: loadAssets };
document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => show(b.dataset.view)));
function show(view) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.view === view));
  document.querySelectorAll("main > section").forEach((s) => (s.hidden = s.id !== "view-" + view));
  if (loaders[view]) loaders[view]();
}

// ---------- trace ----------
function trace(result) {
  const bars = $("#trace"), i = document.createElement("i");
  i.className = result.verdict;
  i.style.height = Math.max(4, result.risk_score) + "%";
  bars.appendChild(i);
  while (bars.children.length > 180) bars.firstChild.remove();
}

// ---------- analyze ----------
function buildForm() {
  const byName = Object.fromEntries(contract.features.map((f) => [f.name, f]));
  $("#fieldsets").innerHTML = GROUPS.map(([title, names]) => `<fieldset><legend>${title}</legend><div class="fields">${names.map((n) => {
    const f = byName[n];
    const control = f.type === "cat"
      ? `<select id="f-${n}" name="${n}">${f.values.map((v) => `<option>${esc(v)}</option>`).join("")}</select>`
      : `<input id="f-${n}" name="${n}" inputmode="decimal" autocomplete="off">`;
    const hint = f.type === "cat" ? `${f.values.length} allowed values` : `${f.type}, ${f.min} to ${f.max}`;
    return `<div class="field" data-field="${n}" title="${esc(f.why)}"><label for="f-${n}">${n}</label>${control}<small>${hint}</small></div>`;
  }).join("")}</div></fieldset>`).join("");
  $("#presets").innerHTML = contract.presets.map((p, i) => `<button type="button" class="chip" data-i="${i}" title="${esc(p.description)}">${esc(p.name)}</button>`).join("");
  $("#presets").onclick = (e) => {
    const b = e.target.closest(".chip"); if (!b) return;
    fill(contract.presets[b.dataset.i].flow);
    document.querySelectorAll("#presets .chip").forEach((c) => c.classList.toggle("on", c === b));
    $("#flow-form").requestSubmit();
  };
  fill(contract.presets[0].flow);
}
function fill(flow) {
  for (const [k, v] of Object.entries(flow)) { const el = $("#f-" + k); if (el) el.value = v; }
  clearErrors();
}
function readForm() {
  const flow = {};
  for (const f of contract.features) {
    const raw = $("#f-" + f.name).value.trim();
    flow[f.name] = f.type === "cat" ? raw : raw === "" ? null : Number.isNaN(Number(raw)) ? raw : Number(raw);
  }
  return flow;
}
function clearErrors() {
  document.querySelectorAll(".field.bad").forEach((el) => {
    el.classList.remove("bad");
    const f = contract.features.find((x) => x.name === el.dataset.field);
    $("small", el).textContent = f.type === "cat" ? `${f.values.length} allowed values` : `${f.type}, ${f.min} to ${f.max}`;
  });
  $("#form-error").innerHTML = "";
}
function showValidation(err, target) {
  const items = Array.isArray(err.data.detail) ? err.data.detail : [{ loc: [], msg: err.data.detail || err.message }];
  for (const d of items) {
    const name = d.loc[d.loc.length - 1], el = document.querySelector(`.field[data-field="${name}"]`);
    if (el && target === "#form-error") { el.classList.add("bad"); $("small", el).textContent = d.msg; }
  }
  $(target).innerHTML = `<div class="error-box"><b>Rejected with HTTP ${err.status}.</b> ${err.status === 422 ? "The input breaks the data contract, so the model was never called." : ""}
    <ul>${items.slice(0, 8).map((d) => `<li><span class="mono">${esc(d.loc.filter((x) => x !== "body").join("."))}</span> ${esc(d.msg)}</li>`).join("")}</ul></div>`;
}
$("#flow-form").onsubmit = async (e) => {
  e.preventDefault();
  clearErrors();
  const flow = readForm(), btn = $("#submit");
  btn.disabled = true;
  try {
    const r = await api("/predict", flow);
    lastFlow = flow; lastResult = r;
    renderResult(r); trace(r);
  } catch (err) {
    $("#result").innerHTML = `<div class="empty"><b>Nothing was scored</b>The input was rejected before it reached the model. Fix the highlighted fields and score the flow again.</div>`;
    if (err.status) showValidation(err, "#form-error");
    else $("#form-error").innerHTML = `<div class="error-box"><b>Could not reach the API.</b> Check that the service is running, then score the flow again.</div>`;
  } finally { btn.disabled = false; }
};
$("#break").onclick = () => { $("#f-serror_rate").value = "1.7"; $("#f-count").value = "-4"; $("#flow-form").requestSubmit(); };

function dial(risk, verdict) {
  const c = 2 * Math.PI * 52, color = `var(--${TONE[verdict]})`;
  return `<svg class="dial" viewBox="0 0 132 132" role="img" aria-label="Risk score ${risk} out of 100">
    <circle class="track" cx="66" cy="66" r="52"/><circle class="val" cx="66" cy="66" r="52" stroke="${color}" stroke-dasharray="${c}" stroke-dashoffset="${c}" transform="rotate(-90 66 66)" data-to="${c * (1 - risk / 100)}"/>
    <text x="66" y="72" text-anchor="middle">${risk}</text><text class="unit" x="66" y="90" text-anchor="middle">risk / 100</text></svg>`;
}
function meter(label, v, mark) {
  return `<div class="meter"><span>${label}</span><div class="bar"><b style="width:${v * 100}%"></b><em style="left:${mark * 100}%" title="alert threshold"></em></div><span>${v.toFixed(2)}</span></div>`;
}
function renderResult(r) {
  const max = Math.max(0.01, ...r.top_factors.map((f) => Math.abs(f.impact)));
  const fam = Object.entries(r.family_probabilities).sort((a, b) => b[1] - a[1]);
  $("#result").innerHTML = `
    <div class="verdict ${r.verdict}">${dial(r.risk_score, r.verdict)}
      <div><h2>${VERDICT[r.verdict]}</h2><p style="margin-top:8px">${esc(r.summary)}</p>
        <div class="tags"><span class="tag ${r.verdict}">${r.severity} severity</span>
        ${r.attack_family ? `<span class="tag">family: ${r.attack_family}</span>` : ""}
        ${r.mitre_attack.map((m) => `<a class="tag" href="https://attack.mitre.org/techniques/${m.id}/" target="_blank" rel="noopener">${m.id} ${esc(m.name)}</a>`).join("")}</div></div></div>
    <div class="block"><h3>How the two models scored it</h3>
      ${meter("Known-attack probability", r.attack_probability, 0.5)}${meter("Novelty vs normal traffic", r.novelty_score, 0.5)}
      <p class="muted" style="font-size:.82rem;margin-top:6px">The tick marks the alert threshold. A flow the classifier passes but the novelty model flags is reported as a possible zero-day.</p>
      ${fam.length ? `<p style="font-size:.85rem;margin-top:8px">Closest attack family: ${fam.map(([k, v]) => `${k} ${(v * 100).toFixed(0)}%`).join(", ")}</p>` : ""}</div>
    ${r.asset_context ? `<div class="block"><h3>Asset under attack: ${esc(r.asset_context.asset)}</h3>
      ${meter("Asset exposure", r.asset_context.exposure / 100, 0.5)}
      <p style="font-size:.9rem;margin-top:6px">Alert priority <b>${r.asset_context.priority}</b> (model risk ${r.risk_score}, ${r.asset_context.priority > r.risk_score ? "raised" : r.asset_context.priority < r.risk_score ? "lowered" : "unchanged"} because this asset is graded ${r.asset_context.grade} for exposure).${r.asset_context.top_finding ? " Worst finding: " + esc(r.asset_context.top_finding) : ""}</p></div>` : ""}
    <div class="block"><h3>What to do</h3><ul class="tips">${r.tips.map((t) => `<li>${esc(t)}</li>`).join("")}</ul></div>
    <div class="block"><h3>Why the model decided this</h3>
      ${r.top_factors.length ? r.top_factors.map((f) => `<div class="factor"><span class="name">${f.feature} = ${esc(f.value)}<small>typical normal flow: ${esc(f.typical)}</small></span>
        <div class="lane"><b class="${f.impact > 0 ? "up" : "down"}" style="width:${(Math.abs(f.impact) / max) * 50}%"></b></div><span>${f.impact > 0 ? "+" : ""}${f.impact.toFixed(2)}</span></div>`).join("")
        + `<p class="muted" style="font-size:.82rem;margin-top:6px">Each bar is that value's share of the gap between this flow's score and a typical normal flow's score. Red pushes toward attack, green toward benign.</p>`
      : `<p class="muted">No single value moves the score. The flow sits close to typical normal traffic.</p>`}</div>
    <div class="block"><div class="form-foot" style="margin-top:0">
      ${r.verdict !== "benign" ? `<button class="btn" id="whatif">What would make this benign?</button><button class="btn" id="redteam">Can an attacker evade this?</button>` : ""}
      <span class="muted">Was this verdict right?</span><button class="btn" data-fb="1">Yes</button><button class="btn" data-fb="0">No</button><span id="fb-note" class="muted"></span></div>
      <div id="whatif-out"></div>
      <p class="muted mono" style="margin-top:12px">request ${r.request_id}, ${r.latency_ms} ms, model ${esc(r.model_version)}</p></div>`;
  requestAnimationFrame(() => { const v = $(".dial .val"); if (v) v.style.strokeDashoffset = v.dataset.to; });
  const w = $("#whatif");
  if (w) w.onclick = async () => {
    w.disabled = true;
    const c = await api("/counterfactual", lastFlow).catch(() => null);
    w.disabled = false;
    if (!c) return;
    $("#whatif-out").innerHTML = `<table style="margin-top:12px"><thead><tr><th>Change</th><th>From</th><th>To</th></tr></thead><tbody>${c.changes.map((x) => `<tr><td class="mono">${x.feature}</td><td class="mono">${esc(x.from)}</td><td class="mono">${esc(x.to)}</td></tr>`).join("")}</tbody></table>
      <p style="margin-top:8px;font-size:.9rem">${c.flips_to_benign ? `With these ${c.changes.length} change(s) the risk drops from ${c.start_risk} to ${c.final_risk} and the flow passes as benign.` : `Even after ${c.changes.length} change(s) the risk is still ${c.final_risk}. This flow is anomalous across many features at once.`}</p>`;
  };
  const rt = $("#redteam");
  if (rt) rt.onclick = async () => {
    rt.disabled = true;
    const c = await api("/redteam", lastFlow).catch(() => null);
    rt.disabled = false;
    if (!c) return;
    const word = { robust: "Robust", moderate: "Evadable with effort", fragile: "Fragile" }[c.robustness];
    $("#whatif-out").innerHTML = `<p style="margin-top:12px"><b>${word}.</b> ${c.evaded ? `Changing ${c.changes.length} value(s) the attacker controls drops the risk from ${c.start_risk} to ${c.final_risk} and the flow passes as benign.` : `Changing only values the attacker controls, the best result after ${c.changes.length} change(s) is risk ${c.final_risk} (${VERDICT[c.final_verdict].toLowerCase()}). The flow is still caught.`}</p>
      ${c.changes.length ? `<table style="margin-top:8px"><thead><tr><th>Attacker changes</th><th>From</th><th>To</th><th class="num">Risk after</th></tr></thead><tbody>${c.changes.map((x) => `<tr><td class="mono">${x.feature}</td><td class="mono">${esc(x.from)}</td><td class="mono">${esc(x.to)}</td><td class="num">${x.risk_after}</td></tr>`).join("")}</tbody></table>` : ""}
      <p class="note">Only ${c.attacker_controlled.join(", ")} are searched. Flags, login state and destination-host history are observed by the defender.</p>`;
  };
  document.querySelectorAll("[data-fb]").forEach((b) => (b.onclick = async () => {
    await api("/feedback", { request_id: r.request_id, correct: b.dataset.fb === "1" }).catch(() => null);
    $("#fb-note").textContent = "Saved for the next retraining review.";
  }));
}

// ---------- live ----------
let liveTimer = null;
const live = { flows: 0, flagged: 0, zero: 0, missed: 0, false_alarm: 0, unseen: 0, review: 0 };
function liveStats() {
  const s = [[live.flows, "flows replayed"], [live.flagged, "flagged"], [`${live.zero} of ${live.unseen}`, "unseen attack types flagged"], [live.review, "sent to review"], [live.missed, "attacks missed"], [live.false_alarm, "false alarms"]];
  $("#live-stats").innerHTML = s.map(([v, l]) => `<div class="stat"><b>${v}</b><span>${l}</span></div>`).join("");
}
async function liveTick() {
  const data = await api("/simulate?n=8").catch(() => null);
  if (!data) return;
  const body = $("#live-rows");
  if (!live.flows) body.innerHTML = "";
  for (const ev of data.events) {
    const { flow, truth, result: r } = ev, isAttack = truth.label !== "normal", flagged = r.verdict !== "benign";
    live.flows++;
    if (r.verdict === "uncertain") live.review++;
    else {
      if (flagged) live.flagged++;
      if (isAttack && !flagged) live.missed++;
      if (!isAttack && flagged) live.false_alarm++;
    }
    if (isAttack && !truth.seen_in_training) { live.unseen++; if (flagged) live.zero++; }
    const review = r.verdict === "uncertain";
    const outcome = review ? "sent to review" : isAttack ? (flagged ? "caught" : "missed") : flagged ? "false alarm" : "correct";
    const tr = document.createElement("tr");
    tr.className = "click"; tr.tabIndex = 0;
    tr.innerHTML = `<td class="mono">${flow.protocol_type}/${esc(flow.service)} ${flow.flag}</td><td>${esc(truth.label)} <span class="muted">${truth.family}</span></td>
      <td>${isAttack ? (truth.seen_in_training ? "yes" : "<b>no, new type</b>") : ""}</td><td><span class="tag ${r.verdict}">${VERDICT[r.verdict]}</span></td><td class="num">${r.risk_score}</td><td>${outcome}</td>`;
    tr.onclick = () => { show("analyze"); fill(flow); $("#flow-form").requestSubmit(); };
    tr.onkeydown = (e) => { if (e.key === "Enter") tr.onclick(); };
    body.prepend(tr); trace(r);
  }
  while (body.children.length > 60) body.lastChild.remove();
  liveStats();
}
$("#live-toggle").onclick = () => {
  if (liveTimer) { clearInterval(liveTimer); liveTimer = null; $("#live-toggle").textContent = "Resume replay"; }
  else { liveTick(); liveTimer = setInterval(liveTick, 1400); $("#live-toggle").textContent = "Pause replay"; }
};
liveStats();

// ---------- capture ----------
function graphSvg(g) {
  const srcs = g.sources.slice(0, 12), ips = new Set(srcs.map((s) => s.ip));
  const edges = g.edges.filter((e) => ips.has(e.src));
  const dsts = [...new Set(edges.map((e) => e.dst))].slice(0, 12);
  const H = Math.max(srcs.length, dsts.length, 3) * 34 + 40, y = (i, n) => 34 + (i + 0.5) * ((H - 44) / n);
  const tone = (r) => (r >= 65 ? "var(--attack)" : r >= 40 ? "var(--suspect)" : "var(--benign)");
  const sy = Object.fromEntries(srcs.map((s, i) => [s.ip, y(i, srcs.length)])), dy = Object.fromEntries(dsts.map((d, i) => [d, y(i, dsts.length)]));
  return `<svg class="graph" viewBox="0 0 760 ${H}" role="img" aria-label="Host graph: sources on the left, destinations on the right">
    <text class="lbl" x="150" y="16" text-anchor="end">Sources</text><text class="lbl" x="610" y="16">Destinations</text>
    ${edges.filter((e) => e.dst in dy).map((e) => `<line x1="160" y1="${sy[e.src]}" x2="600" y2="${dy[e.dst]}" stroke="${tone(e.max_risk)}" stroke-width="${Math.min(7, 1 + Math.log2(e.flows + 1))}"><title>${e.src} to ${e.dst}: ${e.flows} flows, highest risk ${e.max_risk}</title></line>`).join("")}
    ${srcs.map((s) => `<circle cx="160" cy="${sy[s.ip]}" r="${s.behaviour === "normal" ? 6 : 9}" fill="${tone(s.source_risk)}"/><text x="146" y="${sy[s.ip] + 4}" text-anchor="end">${esc(s.ip)}${s.behaviour !== "normal" ? " (" + s.behaviour + ")" : ""}</text>`).join("")}
    ${dsts.map((d) => `<circle cx="600" cy="${dy[d]}" r="7" fill="var(--muted)"/><text x="614" y="${dy[d] + 4}">${esc(d)}</text>`).join("")}</svg>`;
}
function renderCapture(d) {
  const bad = d.graph.sources.filter((s) => s.behaviour !== "normal");
  $("#cap-out").innerHTML = `
    <div class="stats"><div class="stat"><b>${d.flows.toLocaleString()}</b><span>connections rebuilt from ${esc(d.name)}, ${d.span_seconds} s</span></div>
      ${["attack", "zero_day_suspect", "uncertain", "benign"].map((v) => `<div class="stat"><b>${d.verdicts[v] || 0}</b><span>${VERDICT[v]}</span></div>`).join("")}</div>
    <div class="grid-2"><div class="panel"><h3>Host graph</h3><p class="note">Line colour is the highest risk seen on that path, line width the number of flows.</p>${graphSvg(d.graph)}</div>
      <div class="panel table-wrap"><h3 style="margin-bottom:6px">Sources ranked by behaviour</h3>
        <p class="note" style="margin-bottom:8px">${bad.length ? `${bad.length} source(s) behave like a scanner or flooder across their flows.` : "No source behaves like a scanner or flooder."}</p>
        <table><thead><tr><th>Source</th><th>Behaviour</th><th class="num">Flows</th><th class="num">Ports</th><th class="num">Failed</th><th class="num">Risk</th></tr></thead><tbody>
        ${d.graph.sources.slice(0, 10).map((s) => `<tr><td class="mono">${esc(s.ip)}</td><td>${s.behaviour === "normal" ? "normal" : `<span class="tag attack">${s.behaviour}</span>`}</td><td class="num">${s.flows}</td><td class="num">${s.distinct_ports}</td><td class="num">${pct(s.failed_share)}</td><td class="num">${s.source_risk}</td></tr>`).join("")}</tbody></table></div></div>
    <div class="panel table-wrap" style="margin-top:16px"><h3 style="margin-bottom:10px">Riskiest connections</h3><table><thead><tr><th>Source</th><th>Destination</th><th>Service</th><th>State</th><th>Verdict</th><th class="num">Risk</th>${d.rows.some((r) => r.priority != null) ? '<th class="num">Priority</th>' : ""}</tr></thead><tbody>
      ${d.rows.slice(0, 15).map((r, i) => `<tr class="click" data-row="${i}"><td class="mono">${esc(r.src)}</td><td class="mono">${esc(r.dst)}:${r.dport}</td><td class="mono">${esc(r.service)}</td><td class="mono">${r.flag}</td><td><span class="tag ${r.verdict}">${VERDICT[r.verdict]}</span></td><td class="num">${r.risk}</td>${d.rows.some((x) => x.priority != null) ? `<td class="num">${r.priority ?? ""}</td>` : ""}</tr>`).join("")}</tbody></table>
      <p class="note">Select a row to open that connection in Analyze. Session-content features (failed logins, root shell) cannot be read from packets and are set to 0.</p></div>`;
  document.querySelectorAll("#cap-out [data-row]").forEach((tr) => (tr.onclick = () => { show("analyze"); fill(d.rows[tr.dataset.row].flow); $("#flow-form").requestSubmit(); }));
}
async function runCapture(promise) {
  $("#cap-out").innerHTML = `<div class="panel"><div class="empty"><b>Rebuilding connections...</b></div></div>`;
  try { renderCapture(await promise); }
  catch (e) { $("#cap-out").innerHTML = `<div class="error-box"><b>Could not analyze that file${e.status ? " (HTTP " + e.status + ")" : ""}.</b> ${esc((e.data && e.data.detail) || "Check that the service is running.")}</div>`; }
}
$("#cap-sample").onclick = () => runCapture(api("/capture/sample"));
$("#cap-file").onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return;
  runCapture(fetch("/capture", { method: "POST", headers: { "content-type": "application/octet-stream" }, body: f }).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error("HTTP " + res.status), { status: res.status, data });
    return data;
  }));
};

// ---------- assets ----------
async function loadAssets() {
  const d = await api("/assets");
  $("#asset-out").innerHTML = d.assets.length ? d.assets.map((a) => `<div class="panel"><div class="campaign"><div>
      <h3>${esc(a.name)} <span class="tag ${a.exposure >= 60 ? "attack" : a.exposure >= 35 ? "zero_day_suspect" : "benign"}">exposure ${a.exposure}/100, grade ${a.grade}</span></h3>
      <p class="note mono">${esc(a.url)}${a.tls ? `, ${esc(a.tls.version)}, certificate valid ${a.tls.days_left} more days` : ""}. Applies to alerts on: ${a.services.map(esc).join(", ")}</p>
      ${a.findings.length ? `<ul class="brief">${a.findings.map((f) => `<li><b>${f.severity}</b> ${esc(f.text)}</li>`).join("")}</ul>` : `<p style="margin-top:8px">No exposure findings from the passive check.</p>`}
      </div><div class="side"><button class="btn" data-del="${esc(a.name)}">Remove</button></div></div></div>`).join("")
    : `<div class="panel"><div class="empty"><b>No assets registered</b>${d.enabled ? "Add the first one above. Alerts on its services will then show a priority." : "Asset scanning is switched off on this deployment."}</div></div>`;
  document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = async () => { await fetch("/assets/" + encodeURIComponent(b.dataset.del), { method: "DELETE" }); loadAssets(); }));
}
$("#asset-form").onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#a-submit"); btn.disabled = true; $("#asset-error").innerHTML = "";
  try {
    await api("/assets", { name: $("#a-name").value.trim(), url: $("#a-url").value.trim(), services: $("#a-services").value.split(",").map((s) => s.trim()).filter(Boolean) });
    loadAssets();
  } catch (err) { showValidation(err, "#asset-error"); }
  btn.disabled = false;
};

// ---------- hunt ----------
let lastRetrain = null;
async function loadHunt() {
  const d = await api("/campaigns").catch((e) => ({ error: e }));
  if (d.error) { $("#hunt-out").innerHTML = `<div class="error-box"><b>Campaigns are unavailable.</b> ${esc(d.error.data.detail || d.error.message)}</div>`; return; }
  const labelled = d.labelled.attack + d.labelled.benign;
  $("#hunt-steps").innerHTML = [[d.suspects, "distinct possible zero-days in the log", d.suspects > 0], [d.campaigns.length, "campaigns found", d.campaigns.length > 0], [labelled, "flows labelled by an analyst", labelled > 0], [lastRetrain && lastRetrain.promoted ? "Promoted" : lastRetrain ? "Rejected" : "None yet", "last challenger", lastRetrain && lastRetrain.promoted]]
    .map(([v, l, done]) => `<div class="${done ? "done" : ""}"><b>${v}</b>${l}</div>`).join("");
  const report = lastRetrain ? `<div class="report ${lastRetrain.promoted ? "good" : ""}"><h3>${lastRetrain.promoted ? "Challenger promoted. The live model has learned these flows." : "Challenger not promoted"}</h3>
      <p style="margin-top:6px">${esc(lastRetrain.reason)}</p>
      ${lastRetrain.champion ? `<table style="margin-top:10px;max-width:640px"><thead><tr><th></th><th class="num">Held-back labelled flows correct</th><th class="num">Validation F1</th></tr></thead><tbody>
        <tr><td>Champion (previous model)</td><td class="num">${pct(lastRetrain.champion.labelled_holdout_accuracy)}</td><td class="num">${lastRetrain.champion.validation_f1.toFixed(4)}</td></tr>
        <tr class="best"><td>Challenger</td><td class="num">${pct(lastRetrain.challenger.labelled_holdout_accuracy)}</td><td class="num">${lastRetrain.challenger.validation_f1.toFixed(4)}</td></tr></tbody></table>
        <p class="note">${lastRetrain.holdout_flows} labelled flows were held back from training to measure this. ${lastRetrain.quarantined_labels ? lastRetrain.quarantined_labels + " suspicious label(s) were quarantined." : ""} Live model: ${esc(lastRetrain.model_version)}</p>` : ""}</div>` : "";
  const retrainBar = `<div class="panel"><div class="form-foot" style="margin-top:0"><button class="btn primary" id="retrain" ${labelled < 10 ? "disabled" : ""}>Retrain with ${labelled} labelled flows</button>
      <span class="muted">${labelled < 10 ? "Label at least 10 flows to enable retraining." : "Trains a challenger with the same settings as the live model. Takes 10 to 20 seconds."}</span></div></div>`;
  const cards = d.campaigns.map((c, i) => {
    const truth = Object.entries(c.true_labels), mixed = truth.some(([k]) => k === "normal");
    return `<div class="panel"><div class="campaign"><div>
      <h3>Campaign ${i + 1}: ${c.size} flows, mostly ${esc(c.common.protocol_type.value)}/${esc(c.common.service.value)} with flag ${esc(c.common.flag.value)}</h3>
      <div class="rule">${esc(c.signature.rule)}</div>
      <p style="font-size:.88rem">This generated rule matches ${pct(c.signature.coverage)} of the campaign and ${pct(c.signature.false_match_rate)} of normal training traffic. Mean risk ${c.mean_risk}.</p>
      ${truth.length ? `<p class="note ${mixed ? "warn" : ""}">True labels, known only because this is a labelled replay: ${truth.map(([k, v]) => `${esc(k)} ${v}`).join(", ")}.${mixed ? " This group contains normal traffic, so check it before labelling it all as an attack." : ""}</p>` : ""}
      </div><div class="side"><button class="btn primary" data-label="attack" data-id="${c.id}">Label as attack</button><button class="btn" data-label="benign" data-id="${c.id}">Label as benign</button><button class="btn" data-open="${i}">Open an example</button></div></div></div>`;
  }).join("");
  $("#hunt-out").innerHTML = report + retrainBar + (cards || `<div class="panel"><div class="empty"><b>No campaigns right now</b>${d.suspects ? `${d.suspects} possible zero-days are in the log, but a campaign needs at least 8 similar flows.` : "The current model flags nothing in the log as a possible zero-day."} Run the live replay for a minute, then refresh.</div></div>`);
  document.querySelectorAll("[data-label]").forEach((b) => (b.onclick = async () => {
    b.disabled = true;
    await api(`/campaigns/${b.dataset.id}/label`, { label: b.dataset.label }).catch(() => null);
    loadHunt();
  }));
  document.querySelectorAll("[data-open]").forEach((b) => (b.onclick = () => { show("analyze"); fill(d.campaigns[b.dataset.open].example); $("#flow-form").requestSubmit(); }));
  const rb = $("#retrain");
  if (rb) rb.onclick = async () => {
    rb.disabled = true; rb.textContent = "Training the challenger...";
    lastRetrain = await api("/learning/retrain", {}).catch((e) => ({ promoted: false, reason: (e.data && e.data.detail) || "Retraining failed. Check the service log." }));
    if (lastRetrain.model_version) $("#foot-version").textContent = "model " + lastRetrain.model_version;
    loadHunt();
  };
}
$("#hunt-refresh").onclick = loadHunt;

// ---------- batch ----------
let batchResults = null;
function parseCsv(text) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) throw new Error("Add a header row and at least one data row.");
  const head = lines[0].split(",").map((s) => s.trim());
  const types = Object.fromEntries(contract.features.map((f) => [f.name, f.type]));
  return lines.slice(1).map((line) => {
    const cells = line.split(","), row = {};
    head.forEach((h, i) => { if (h in types) { const v = (cells[i] ?? "").trim(); row[h] = types[h] === "cat" ? v : v === "" || Number.isNaN(Number(v)) ? v : Number(v); } });
    return row;
  });
}
$("#batch-sample").onclick = async () => {
  const d = await api("/simulate?n=25"), names = contract.features.map((f) => f.name);
  $("#batch-text").value = [names.join(","), ...d.events.map((e) => names.map((n) => e.flow[n]).join(","))].join("\n");
};
$("#batch-file").onchange = async (e) => { const f = e.target.files[0]; if (f) $("#batch-text").value = await f.text(); };
$("#batch-run").onclick = async () => {
  $("#batch-error").innerHTML = ""; $("#batch-out").innerHTML = "";
  let flows;
  try { flows = parseCsv($("#batch-text").value); } catch (err) { $("#batch-error").innerHTML = `<div class="error-box"><b>Nothing to score.</b> ${esc(err.message)}</div>`; return; }
  try {
    const d = await api("/predict/batch", { flows });
    batchResults = d.results.map((r, i) => ({ ...flows[i], verdict: r.verdict, risk_score: r.risk_score, attack_family: r.attack_family || "" }));
    d.results.forEach(trace);
    $("#batch-out").innerHTML = `<div class="stats" style="margin-top:16px">${["attack", "zero_day_suspect", "uncertain", "benign"].map((v) => `<div class="stat"><b>${d.verdicts[v] || 0}</b><span>${VERDICT[v]}</span></div>`).join("")}</div>
      <div class="panel table-wrap"><table><thead><tr><th>#</th><th>Connection</th><th>Verdict</th><th>Family</th><th class="num">Risk</th><th class="num">Attack prob.</th><th class="num">Novelty</th></tr></thead><tbody>
      ${d.results.map((r, i) => `<tr><td class="num">${i + 1}</td><td class="mono">${esc(flows[i].protocol_type)}/${esc(flows[i].service)} ${esc(flows[i].flag)}</td><td><span class="tag ${r.verdict}">${VERDICT[r.verdict]}</span></td><td>${r.attack_family || ""}</td><td class="num">${r.risk_score}</td><td class="num">${r.attack_probability.toFixed(2)}</td><td class="num">${r.novelty_score.toFixed(2)}</td></tr>`).join("")}</tbody></table></div>`;
    $("#batch-download").hidden = false;
  } catch (err) { showValidation(err, "#batch-error"); }
};
$("#batch-download").onclick = () => {
  const cols = Object.keys(batchResults[0]);
  const csv = [cols.join(","), ...batchResults.map((r) => cols.map((c) => r[c]).join(","))].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); a.download = "zerowatch_results.csv"; a.click();
};

// ---------- model ----------
async function loadModel() {
  const m = await api("/model/info"), t = m.metrics, z = t.zero_day_recall;
  const imp = Object.entries(m.feature_importance).sort((a, b) => b[1] - a[1]).slice(0, 10), top = imp.length ? imp[0][1] : 1;
  const params = Object.entries(m.params).filter(([k]) => !["algorithm", "seed", "train_rows"].includes(k)).map(([k, v]) => `${k}=${v}`).join(", ");
  $("#model-out").innerHTML = `
    <div class="stats">
      <div class="stat"><b>${t.validation.f1.toFixed(3)}</b><span>F1 on validation (known attacks)</span></div>
      <div class="stat"><b>${t.test.f1.toFixed(3)}</b><span>F1 on KDDTest+, classifier alone</span></div>
      <div class="stat"><b>${t.ensemble_test.f1.toFixed(3)}</b><span>F1 on KDDTest+, with novelty model</span></div>
      <div class="stat"><b>${pct(t.ensemble_test.fpr)}</b><span>false-positive rate, ensemble</span></div>
      ${t.conformal ? `<div class="stat"><b>${pct(t.conformal.missed_attacks_sent_to_review)}</b><span>of missed attacks caught by the "not sure" review queue</span></div>` : ""}
    </div>
    <div class="cols">
      <div class="panel"><h3>Recall on attack types absent from training</h3>
        <p class="muted" style="margin:6px 0 14px;font-size:.88rem">${z.unseen_attack_flows.toLocaleString()} test flows belong to 17 attack types the model never saw. This is the zero-day measurement.</p>
        <div class="pair"><div class="row"><span>Classifier alone</span><div class="bar"><b style="width:${z.detector_only * 100}%"></b></div><span>${pct(z.detector_only)}</span></div>
        <div class="row hi"><span>With novelty model</span><div class="bar"><b style="width:${z.ensemble * 100}%"></b></div><span>${pct(z.ensemble)}</span></div></div></div>
      <div class="panel"><h3>Deployed model</h3><dl class="kv" style="margin-top:10px">
        <dt>Version</dt><dd>${esc(m.model_version)}</dd><dt>Algorithm</dt><dd>${esc(m.algorithm)}</dd><dt>Hyperparameters</dt><dd>${esc(params)}</dd>
        <dt>Trained</dt><dd>${esc(m.trained_at)}</dd><dt>Rows</dt><dd>fit ${m.rows.fit.toLocaleString()}, validation ${m.rows.validation.toLocaleString()}, test ${m.rows.test.toLocaleString()}</dd>
        <dt>Model SHA-256</dt><dd>${esc(m.model_sha256.slice(0, 32))}, verified at startup</dd><dt>Data hash</dt><dd>${esc(m.data_sha256)}</dd><dt>Git commit</dt><dd>${esc(m.git_sha)}</dd><dt>scikit-learn</dt><dd>${esc(m.sklearn)}</dd></dl></div>
    </div>
    ${m.experiments.length ? `<div class="panel table-wrap" style="margin-top:16px"><h3 style="margin-bottom:10px">Experiments tracked in MLflow</h3><table><thead><tr><th>Run</th><th>Algorithm</th><th>Hyperparameters</th><th class="num">Val F1</th><th class="num">Test acc.</th><th class="num">Test F1</th><th class="num">Ensemble F1</th><th class="num">Zero-day recall</th></tr></thead><tbody>
      ${m.experiments.map((e) => `<tr class="${e.promoted ? "best" : ""}"><td class="mono">${esc(e.run)}${e.promoted ? " (deployed)" : ""}</td><td>${esc(e.algorithm)}</td><td class="mono">${esc(e.hyperparameters)}</td><td class="num">${e.val_f1.toFixed(4)}</td><td class="num">${e.test_accuracy.toFixed(4)}</td><td class="num">${e.test_f1.toFixed(4)}</td><td class="num">${e.ensemble_test_f1.toFixed(4)}</td><td class="num">${pct(e.zero_day_recall_ensemble)}</td></tr>`).join("")}</tbody></table></div>` : ""}
    ${m.cross_dataset ? (() => { const x = m.cross_dataset.results, cell = (tr, te) => x.find((r) => r.trained_on === tr && r.tested_on === te).f1;
      const td = (v) => `<td class="cell" style="background:color-mix(in srgb, var(--${v >= 0.75 ? "benign" : v >= 0.5 ? "suspect" : "attack"}) ${Math.round(12 + v * 18)}%, transparent)">${v.toFixed(3)}</td>`;
      return `<div class="panel table-wrap" style="margin-top:16px"><h3>Does it generalise to another network?</h3>
        <p class="muted" style="margin:6px 0 12px;font-size:.88rem;max-width:80ch">The same algorithm trained on one dataset and tested on the other, using only the six measurements NSL-KDD and UNSW-NB15 share (${m.cross_dataset.features.join(", ")}). F1 score.</p>
        <table class="heat" style="max-width:560px"><thead><tr><th>Trained on</th><th class="num" style="text-align:center">Tested on NSL-KDD</th><th class="num" style="text-align:center">Tested on UNSW-NB15</th></tr></thead><tbody>
        ${["NSL-KDD", "UNSW-NB15", "Both"].map((tr) => `<tr><td>${tr}</td>${td(cell(tr, "NSL-KDD"))}${td(cell(tr, "UNSW-NB15"))}</tr>`).join("")}</tbody></table>
        <p class="note">A model trained on one network barely works on the other; training on both recovers both. A detector has to be retrained on the traffic it will actually see.</p></div>`; })() : ""}
    <div class="cols" style="margin-top:16px">
      ${imp.length ? `<div class="panel"><h3 style="margin-bottom:12px">Features the classifier relies on most</h3><div class="pair">${imp.map(([k, v]) => `<div class="row hi"><span class="mono">${k}</span><div class="bar"><b style="width:${(v / top) * 100}%"></b></div><span>${v.toFixed(3)}</span></div>`).join("")}</div></div>` : ""}
      <div class="panel table-wrap"><h3 style="margin-bottom:10px">Data contract</h3><table><thead><tr><th>Feature</th><th>Type</th><th>Allowed</th></tr></thead><tbody>
        ${contract.features.map((f) => `<tr title="${esc(f.why)}"><td class="mono">${f.name}</td><td>${f.type === "cat" ? "category" : f.type}</td><td class="mono">${f.type === "cat" ? (f.values.length > 12 ? f.values.length + " service names" : f.values.join(", ")) : f.min + " to " + f.max}</td></tr>`).join("")}</tbody></table></div>
    </div>`;
}

// ---------- monitoring ----------
async function loadMonitor() {
  const [d, r, a, b] = await Promise.all([api("/monitoring/drift"), api("/monitoring/recent?limit=15"), api("/audit/verify"), api("/brief")]);
  const word = { ok: "No drift", warn: "Early drift", drift: "Drift detected", waiting: "Collecting data" }[d.status];
  const drift = d.enough_data ? `<div class="table-wrap"><table><thead><tr><th>Feature</th><th class="num">Training</th><th class="num">Live</th><th>Shift</th><th>Status</th></tr></thead><tbody>
    ${d.features.slice(0, 12).map((f) => `<tr><td class="mono">${f.feature}</td><td class="num">${f.kind === "num" ? f.train_mean : pct(f.train_top_share)}</td><td class="num">${f.kind === "num" ? f.live_mean : esc(f.live_top) + " " + pct(f.live_top_share)}</td>
      <td><span class="mini"><b class="${f.status}" style="width:${Math.min(100, f.shift * 100)}%"></b></span><span class="mono">${f.shift.toFixed(2)}</span></td><td>${f.status}</td></tr>`).join("")}</tbody></table></div>
    <p class="muted" style="font-size:.82rem;margin-top:10px">Shift is the distance between live and training means in training standard deviations (or the change in category shares). Above 0.25 is a warning, above 0.5 is drift and a reason to retrain.</p>`
    : `<p class="muted">Drift needs at least 30 logged predictions. ${d.rows} logged so far. Run the live replay for a few seconds, then refresh.</p>`;
  $("#monitor-out").innerHTML = `
    <div class="stats"><div class="stat"><b>${word}</b><span>from ${d.rows.toLocaleString()} logged inputs</span></div>
      ${["attack", "zero_day_suspect", "uncertain"].map((v) => `<div class="stat"><b>${r.verdicts[v] || 0}</b><span>${VERDICT[v]}, recent</span></div>`).join("")}
      <div class="stat"><b>${a.valid ? "Intact" : "Broken"}</b><span>log hash chain, ${a.entries.toLocaleString()} entries${a.valid ? "" : ", line " + a.broken_at_line}</span></div></div>
    <div class="panel"><h3>Shift report</h3><p style="margin-top:8px"><b>${esc(b.headline)}</b></p>
      <ul class="brief">${b.points.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>
      ${b.actions.length ? `<h3 style="margin:14px 0 8px">Do first</h3><ul class="tips">${b.actions.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}</div>
    <div class="panel"><h3>Ask the copilot</h3>
      <div class="chips" style="margin-top:10px">${["What happened recently?", "What should I do first?", "Any possible zero-days?", "Which services are being attacked?", "Can I trust the log?"].map((q) => `<button class="chip" data-q="${q}">${q}</button>`).join("")}</div>
      <form class="ask" id="ask-form"><input id="ask-q" maxlength="300" placeholder="Ask about the traffic this service has scored" aria-label="Question"><button class="btn primary">Ask</button></form>
      <div id="ask-out"></div></div>
    <div class="panel"><h3 style="margin-bottom:10px">Input drift against training data</h3>${drift}</div>
    <div class="panel table-wrap"><h3 style="margin-bottom:10px">Latest predictions in the log</h3>
      ${r.items.length ? `<table><thead><tr><th>Time (UTC)</th><th>Request</th><th>Connection</th><th>Verdict</th><th class="num">Risk</th></tr></thead><tbody>${r.items.map((e) => `<tr><td class="mono">${esc(e.ts.slice(11, 19))}</td><td class="mono">${esc(e.request_id)}</td><td class="mono">${esc(e.input.protocol_type)}/${esc(e.input.service)} ${esc(e.input.flag)}</td><td><span class="tag ${e.output.verdict}">${VERDICT[e.output.verdict]}</span></td><td class="num">${e.output.risk_score}</td></tr>`).join("")}</tbody></table>`
      : `<p class="muted">Nothing scored since the service started.</p>`}</div>`;
}
async function ask(q) {
  if (!q || q.length < 3) return;
  $("#ask-out").innerHTML = `<div class="answer muted">Thinking...</div>`;
  const r = await api("/copilot", { question: q }).catch(() => null);
  $("#ask-out").innerHTML = r ? `<div class="answer">${esc(r.answer)}<p class="note">${r.engine === "llm" ? "Answered by the configured LLM (" + esc(r.model) + ") from a summary of the log." : "Answered by the built-in rules. Set LLM_BASE_URL to use Ollama or another OpenAI-compatible model."}</p></div>` : `<div class="error-box"><b>The copilot did not answer.</b> Check that the service is running.</div>`;
}
document.addEventListener("click", (e) => { const b = e.target.closest("[data-q]"); if (b) { $("#ask-q").value = b.dataset.q; ask(b.dataset.q); } });
document.addEventListener("submit", (e) => { if (e.target.id === "ask-form") { e.preventDefault(); ask($("#ask-q").value.trim()); } });
$("#monitor-refresh").onclick = loadMonitor;

// ---------- boot ----------
(async function boot() {
  try {
    const h = await api("/health");
    $("#health").innerHTML = `<i class="dot ok"></i>model online`;
    $("#foot-version").textContent = "model " + h.model_version;
    contract = await api("/contract");
    buildForm();
  } catch (e) {
    $("#health").innerHTML = `<i class="dot bad"></i>API unreachable`;
  }
})();
