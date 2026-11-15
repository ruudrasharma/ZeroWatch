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
let contract = null, lastFlow = null, lastResult = null, liveTimer = null, me = { role: "viewer", user: "anonymous", open_mode: false };

function apiKey() { try { return sessionStorage.getItem("zw-key") || ""; } catch (e) { return ""; } }
async function api(path, body, method) {
  const headers = {}, key = apiKey();
  if (key) headers["x-api-key"] = key;
  if (body !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, { method: method || (body === undefined ? "GET" : "POST"), headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) toast("That action needs an API key. Use Sign in at the top.", true);
    if (res.status === 403) toast("That action needs the admin key.", true);
    if (res.status === 429) toast("Too many requests. Wait a minute and try again.", true);
    throw Object.assign(new Error("HTTP " + res.status), { status: res.status, data });
  }
  return data;
}
function toast(text, bad) {
  const t = document.createElement("div");
  t.className = "toast" + (bad ? " bad" : ""); t.textContent = text;
  const x = document.createElement("button"); x.textContent = "Dismiss"; x.onclick = () => t.remove(); t.appendChild(x);
  $("#toasts").appendChild(t);
  if (!bad) setTimeout(() => t.remove(), 5000);  // errors stay until dismissed
  while ($("#toasts").children.length > 4) $("#toasts").firstChild.remove();
}
const skeleton = (sel) => { $(sel).innerHTML = '<div class="skeleton"></div><div class="skeleton tall"></div>'; };
function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: type || "text/plain" })); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
// Sortable, filterable, paged table. columns: [{key, label, num, render(row)}]
function dataTable(sel, columns, rows, opts = {}) {
  const el = $(sel), size = opts.pageSize || 15, st = { q: "", sort: null, dir: 1, page: 0 };
  function draw() {
    let view = rows.filter((r) => !st.q || columns.some((c) => String(r[c.key] ?? "").toLowerCase().includes(st.q)));
    if (st.sort) view = [...view].sort((a, b) => (a[st.sort] > b[st.sort] ? 1 : a[st.sort] < b[st.sort] ? -1 : 0) * st.dir);
    const pages = Math.max(1, Math.ceil(view.length / size)); st.page = Math.min(st.page, pages - 1);
    const shown = view.slice(st.page * size, st.page * size + size);
    el.innerHTML = `<div class="tools"><input type="search" placeholder="Filter ${rows.length} rows" aria-label="Filter rows" value="${esc(st.q)}">
        <div class="pager"><span>${view.length ? st.page * size + 1 : 0} to ${st.page * size + shown.length} of ${view.length}</span><button class="btn" data-pg="-1" ${st.page ? "" : "disabled"}>Previous</button><button class="btn" data-pg="1" ${st.page < pages - 1 ? "" : "disabled"}>Next</button></div></div>
      <div class="table-wrap"><table><thead><tr>${columns.map((c) => `<th class="sortable ${c.num ? "num" : ""}" data-k="${c.key}" ${st.sort === c.key ? `aria-sort="${st.dir > 0 ? "ascending" : "descending"}"` : ""}>${c.label}</th>`).join("")}</tr></thead>
      <tbody>${shown.map((r) => `<tr class="${opts.onRow ? "click" : ""}" data-i="${rows.indexOf(r)}" ${opts.onRow ? 'tabindex="0"' : ""}>${columns.map((c) => `<td class="${c.num ? "num" : c.mono ? "mono" : ""}">${c.render ? c.render(r) : esc(r[c.key] ?? "")}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="${columns.length}" class="empty">No rows match that filter.</td></tr>`}</tbody></table></div>`;
    const input = $("input[type=search]", el);
    input.oninput = () => { st.q = input.value.toLowerCase(); st.page = 0; draw(); const n = $("input[type=search]", el); n.focus(); n.setSelectionRange(n.value.length, n.value.length); };
    el.querySelectorAll("[data-pg]").forEach((b) => (b.onclick = () => { st.page += Number(b.dataset.pg); draw(); }));
    el.querySelectorAll("th[data-k]").forEach((th) => (th.onclick = () => { st.dir = st.sort === th.dataset.k ? -st.dir : 1; st.sort = th.dataset.k; draw(); }));
    if (opts.onRow) el.querySelectorAll("tbody tr[data-i]").forEach((tr) => {
      tr.onclick = (e) => { if (!e.target.closest("select,button,a,input")) opts.onRow(rows[tr.dataset.i]); };
      tr.onkeydown = (e) => { if (e.key === "Enter" && e.target === tr) opts.onRow(rows[tr.dataset.i]); };
    });
    if (opts.after) opts.after(el);
  }
  draw();
}
function openFlow(flow) { show("analyze"); fill(flow); $("#flow-form").requestSubmit(); }
async function openAlert(id) { const a = await api("/alerts/" + id).catch(() => null); if (a) openFlow(a.input); }
// Views that need a key when the service is protected show a sign-in prompt instead of an error.
async function guarded(sel, fn) {
  try { await fn(); }
  catch (e) {
    $(sel).innerHTML = e.status === 401 ? `<div class="panel"><div class="empty"><b>Sign in to see this</b>This view shows analyst data. Use Sign in at the top with an analyst or admin key.</div></div>`
      : `<div class="error-box"><b>This view could not be loaded${e.status ? " (HTTP " + e.status + ")" : ""}.</b> Check that the service is running, then try again.</div>`;
  }
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
const loaders = { model: loadModel, monitor: loadMonitor, hunt: loadHunt, assets: loadAssets, overview: loadOverview, queue: loadQueue };
document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => show(b.dataset.view)));
// Each view has its own #hash, so the back button and shared links work.
function show(view, fromHash, keepFocus) {
  if (!document.getElementById("view-" + view)) view = "analyze";
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.view === view));
  document.querySelectorAll("main > section").forEach((s) => (s.hidden = s.id !== "view-" + view));
  if (!fromHash && location.hash !== "#" + view) history.pushState(null, "", "#" + view);
  document.title = $("#tab-" + view).textContent + " | ZeroWatch";
  if (view !== "live" && liveTimer) $("#live-toggle").click();  // do not keep replaying in the background
  if (loaders[view] && contract) loaders[view]();
  if (fromHash !== "boot" && !keepFocus) $("#view-" + view).focus({ preventScroll: true });
  $("#tab-" + view).scrollIntoView({ block: "nearest", inline: "nearest" });
}
window.addEventListener("popstate", () => show(location.hash.slice(1) || "analyze", true));

// ---------- sign in ----------
async function refreshAuth() {
  const w = await api("/auth/whoami").catch(() => null);
  if (!w) return;
  me = w;
  $("#auth-btn").textContent = w.open_mode ? "Open mode" : w.role === "viewer" ? "Sign in" : `Signed in: ${w.user} (${w.role})`;
  $("#auth-note").textContent = w.open_mode ? "No keys are configured on this service, so every action is allowed. Set ANALYST_TOKEN and ADMIN_TOKEN before exposing it."
    : w.role === "viewer" ? "Scoring works without a key. Labelling and triage need the analyst key; retraining, rollback, assets and settings need the admin key."
    : `You are signed in as ${w.role}. The key is kept for this browser tab only.`;
}
$("#auth-btn").onclick = () => { const p = $("#auth-pop"); p.hidden = !p.hidden; $("#auth-btn").setAttribute("aria-expanded", !p.hidden); if (!p.hidden) $("#auth-key").focus(); };
$("#auth-pop").onsubmit = async (e) => {
  e.preventDefault();
  try { sessionStorage.setItem("zw-key", $("#auth-key").value.trim()); } catch (err) { /* private mode */ }
  $("#auth-key").value = ""; await refreshAuth();
  toast($("#auth-btn").textContent.startsWith("Signed in") ? $("#auth-btn").textContent : "That key was not recognised.", !$("#auth-btn").textContent.startsWith("Signed in"));
};
$("#auth-clear").onclick = async () => { try { sessionStorage.removeItem("zw-key"); } catch (err) { /* private mode */ } await refreshAuth(); toast("Signed out."); };

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
    if ($("#result").getBoundingClientRect().top > innerHeight * 0.6) $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
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
    const f = await api("/feedback", { request_id: r.request_id, correct: b.dataset.fb === "1" }).catch(() => null);
    if (f) toast(f.queued_for_retraining ? "Saved. This flow is now labelled for the next retrain." : "Saved. Thanks for confirming.");
  }));
}

// ---------- live ----------
const live = { flows: 0, flagged: 0, zero: 0, missed: 0, false_alarm: 0, unseen: 0, review: 0 };
function liveStats() {
  if (!$("#live-note")) $("#live-stats").insertAdjacentHTML("afterend", '<p class="note warn" id="live-note" style="margin:-6px 0 12px"></p>');
  const s = [[live.flows, "flows replayed"], [live.flagged, "flagged"], [`${live.zero} of ${live.unseen}`, "unseen attack types flagged"], [live.review, "sent to review"], [live.missed, "attacks missed"], [live.false_alarm, "false alarms"]];
  $("#live-stats").innerHTML = s.map(([v, l]) => `<div class="stat"><b>${v}</b><span>${l}</span></div>`).join("");
}
function liveRender(data) {
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
    tr.onclick = () => openFlow(flow);
    tr.onkeydown = (e) => { if (e.key === "Enter") tr.onclick(); };
    body.prepend(tr); trace(r);
  }
  while (body.children.length > 60) body.lastChild.remove();
  liveStats();
}
// The replay is pushed by the server (Server-Sent Events read with fetch, so the API key can be sent).
async function liveStream(signal) {
  const res = await fetch("/simulate/stream?n=8", { signal, headers: apiKey() ? { "x-api-key": apiKey() } : {} });
  const reader = res.body.getReader(), dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let cut;
    while ((cut = buf.indexOf("\n\n")) >= 0) {
      const line = buf.slice(0, cut); buf = buf.slice(cut + 2);
      if (line.startsWith("data: ")) { const d = JSON.parse(line.slice(6)); liveRender(d); $("#live-note").textContent = d.logged ? "" : "Not written to the log: sign in to keep replayed traffic for Hunt and the queue."; }
    }
  }
}
$("#live-toggle").onclick = () => {
  if (liveTimer) { liveTimer.abort(); liveTimer = null; $("#live-toggle").textContent = "Resume replay"; }
  else { liveTimer = new AbortController(); liveStream(liveTimer.signal).catch(() => {}); $("#live-toggle").textContent = "Pause replay"; }
};
$("#live-reset").onclick = () => {
  for (const k of Object.keys(live)) live[k] = 0;
  $("#live-rows").innerHTML = `<tr><td colspan="6" class="empty">Counters reset. Start the replay to stream flows through the model.</td></tr>`;
  liveStats();
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
function timelineSvg(t) {
  const n = t.sources[0] ? t.sources[0].buckets.length : 0, w = 14, rowH = 22, left = 110, peak = Math.max(1, ...t.sources.flatMap((s) => s.buckets.map((b) => b[0])));
  const tone = (r) => (r >= 65 ? "var(--attack)" : r >= 40 ? "var(--suspect)" : "var(--benign)");
  return `<svg class="tl" viewBox="0 0 ${left + n * w + 10} ${t.sources.length * rowH + 22}" role="img" aria-label="Flows per source over time">
    ${t.sources.map((s, i) => `<text x="${left - 8}" y="${i * rowH + 15}" text-anchor="end">${esc(s.ip)}</text>` + s.buckets.map((b, k) => b[0] ? `<rect x="${left + k * w}" y="${i * rowH + 3}" width="${w - 2}" height="${rowH - 6}" rx="2" fill="${tone(b[1])}" opacity="${0.3 + 0.7 * Math.sqrt(b[0] / peak)}"><title>${s.ip}: ${b[0]} flows, highest risk ${b[1]}</title></rect>` : "").join("")).join("")}
    <text x="${left}" y="${t.sources.length * rowH + 16}">0 s</text><text x="${left + n * w}" y="${t.sources.length * rowH + 16}" text-anchor="end">${t.span_seconds} s</text></svg>`;
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
    <div class="cols" style="margin-top:16px">
      <div class="panel"><h3>Activity over time</h3><p class="note">One row per source; each cell is ${d.timeline.bucket_seconds} s, darker means more flows, colour is the highest risk in that cell.</p>${timelineSvg(d.timeline)}</div>
      <div class="panel"><h3>Block list</h3>${d.blocklist.sources.length ? `<p class="note">Firewall rules for the ${d.blocklist.sources.length} source(s) that behaved like a scanner or flooder. Review before applying: they drop all traffic from each source.</p>
        <pre class="code">${esc(d.blocklist.iptables)}</pre><div class="form-foot"><button class="btn" id="bl-ipt">Download iptables rules</button><button class="btn" id="bl-nft">Download nftables rules</button></div>` : `<p class="muted" style="margin-top:8px">No source behaved like a scanner or flooder, so there is nothing to block.</p>`}</div></div>
    ${d.logged ? "" : `<p class="note warn" style="margin-top:12px">This capture was scored but not written to the log, because you are not signed in.</p>`}
    <div class="panel" style="margin-top:16px"><h3 style="margin-bottom:10px">Connections</h3><div id="cap-table"></div>
      <p class="note">Select a row to open that connection in Analyze. Session-content features (failed logins, root shell) cannot be read from packets and are set to 0.</p></div>`;
  const rows = d.rows.map((r) => ({ ...r, dest: `${r.dst}:${r.dport}`, verdict_label: VERDICT[r.verdict] }));
  dataTable("#cap-table", [{ key: "src", label: "Source", mono: 1 }, { key: "dest", label: "Destination", mono: 1 }, { key: "service", label: "Service", mono: 1 }, { key: "flag", label: "State", mono: 1 },
    { key: "verdict_label", label: "Verdict", render: (r) => `<span class="tag ${r.verdict}">${VERDICT[r.verdict]}</span>` }, { key: "risk", label: "Risk", num: 1 },
    ...(rows.some((r) => r.priority != null) ? [{ key: "priority", label: "Priority", num: 1 }] : [])], rows, { onRow: (r) => openFlow(r.flow) });
  [...d.rows].reverse().slice(-60).forEach((r) => trace({ verdict: r.verdict, risk_score: r.risk }));
  if ($("#bl-ipt")) { $("#bl-ipt").onclick = () => download("zerowatch-block.iptables.sh", d.blocklist.iptables); $("#bl-nft").onclick = () => download("zerowatch-block.nft.sh", d.blocklist.nftables); }
}
async function runCapture(promise) {
  $("#cap-out").innerHTML = `<div class="panel"><div class="empty"><b>Rebuilding connections...</b></div></div>`;
  try { renderCapture(await promise); }
  catch (e) { $("#cap-out").innerHTML = `<div class="error-box"><b>Could not analyze that file${e.status ? " (HTTP " + e.status + ")" : ""}.</b> ${esc((e.data && e.data.detail) || "Check that the service is running.")}</div>`; }
}
$("#cap-sample").onclick = () => runCapture(api("/capture/sample"));
$("#cap-file").onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return;
  runCapture(fetch("/capture", { method: "POST", headers: { "content-type": "application/octet-stream", ...(apiKey() ? { "x-api-key": apiKey() } : {}) }, body: f }).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error("HTTP " + res.status), { status: res.status, data });
    return data;
  }));
};

// ---------- assets ----------
async function loadAssets() {
  if (!$("#asset-out").children.length) skeleton("#asset-out");
  const d = await api("/assets");
  $("#asset-out").innerHTML = d.assets.length ? d.assets.map((a) => `<div class="panel"><div class="campaign"><div>
      <h3>${esc(a.name)} <span class="tag ${a.exposure >= 60 ? "attack" : a.exposure >= 35 ? "zero_day_suspect" : "benign"}">exposure ${a.exposure}/100, grade ${a.grade}</span></h3>
      <p class="note mono">${esc(a.url)}${a.tls ? `, ${esc(a.tls.version)}, certificate valid ${a.tls.days_left} more days` : ""}. Applies to alerts on: ${a.services.map(esc).join(", ")}</p>
      ${a.findings.length ? `<ul class="brief">${a.findings.map((f) => `<li><b>${f.severity}</b> ${esc(f.text)}</li>`).join("")}</ul>` : `<p style="margin-top:8px">No exposure findings from the passive check.</p>`}
      </div><div class="side"><button class="btn" data-del="${esc(a.name)}">Remove</button></div></div></div>`).join("")
    : `<div class="panel"><div class="empty"><b>No assets registered</b>${d.enabled ? "Add the first one above. Alerts on its services will then show a priority." : "Asset scanning is switched off on this deployment."}</div></div>`;
  document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = async () => { const ok = await api("/assets/" + encodeURIComponent(b.dataset.del), undefined, "DELETE").catch(() => null); if (ok) toast("Asset removed."); loadAssets(); }));
}
$("#asset-form").onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#a-submit"); btn.disabled = true; $("#asset-error").innerHTML = "";
  try {
    const a = await api("/assets", { name: $("#a-name").value.trim(), url: $("#a-url").value.trim(), services: $("#a-services").value.split(",").map((s) => s.trim()).filter(Boolean) });
    toast(`${a.name} registered: exposure ${a.exposure}/100.`);
    loadAssets();
  } catch (err) { if (err.status && ![401, 403, 429].includes(err.status)) showValidation(err, "#asset-error"); }
  btn.disabled = false;
};

// ---------- hunt ----------
let lastRetrain = null;
function loadHunt() { return guarded("#hunt-out", loadHuntInner); }
async function loadHuntInner() {
  if (!$("#hunt-out").children.length) skeleton("#hunt-out");
  const d = await api("/campaigns");
  const labelled = d.labelled.attack + d.labelled.benign;
  const inShadow = lastRetrain && lastRetrain.mode === "shadow" && lastRetrain.champion && !lastRetrain.promoted;
  $("#hunt-steps").innerHTML = [[d.suspects, "distinct possible zero-days in the log", d.suspects > 0], [d.campaigns.length, "campaigns found", d.campaigns.length > 0], [labelled, "flows labelled by an analyst", labelled > 0], [lastRetrain && lastRetrain.promoted ? "Promoted" : inShadow ? "In shadow" : lastRetrain ? "Rejected" : "None yet", "last challenger", lastRetrain && lastRetrain.promoted]]
    .map(([v, l, done]) => `<div class="${done ? "done" : ""}"><b>${v}</b>${l}</div>`).join("");
  const report = lastRetrain ? `<div class="report ${lastRetrain.promoted ? "good" : ""}"><h3>${lastRetrain.promoted ? "Challenger promoted. The live model has learned these flows." : inShadow ? "Challenger passed its checks and is running in shadow" : "Challenger not promoted"}</h3>
      <p style="margin-top:6px">${esc(lastRetrain.reason)}</p>
      ${lastRetrain.champion ? `<table style="margin-top:10px;max-width:640px"><thead><tr><th></th><th class="num">Held-back labelled flows correct</th><th class="num">Validation F1</th></tr></thead><tbody>
        <tr><td>Champion (previous model)</td><td class="num">${pct(lastRetrain.champion.labelled_holdout_accuracy)}</td><td class="num">${lastRetrain.champion.validation_f1.toFixed(4)}</td></tr>
        <tr class="best"><td>Challenger</td><td class="num">${pct(lastRetrain.challenger.labelled_holdout_accuracy)}</td><td class="num">${lastRetrain.challenger.validation_f1.toFixed(4)}</td></tr></tbody></table>
        <p class="note">${lastRetrain.holdout_flows} labelled flows were held back from training to measure this. ${lastRetrain.quarantined_labels ? lastRetrain.quarantined_labels + " suspicious label(s) were quarantined." : ""} Live model: ${esc(lastRetrain.model_version)}</p>` : ""}</div>` : "";
  const st = await api("/learning/status").catch(() => ({ versions: [], active: 0 }));
  const done = d.labelled_campaigns.length ? `<div class="panel table-wrap"><h3 style="margin-bottom:10px">Labelled campaigns</h3><table><thead><tr><th>Rule</th><th>Label</th><th class="num">Flows</th><th></th></tr></thead><tbody>
      ${d.labelled_campaigns.map((c) => `<tr><td class="mono">${esc(c.rule || c.id)}</td><td>${c.label}</td><td class="num">${c.flows}</td><td><button class="btn" data-undo="${c.id}">Undo label</button></td></tr>`).join("")}</tbody></table></div>` : "";
  const versions = st.versions.length ? `<div class="panel table-wrap"><h3 style="margin-bottom:10px">Model versions</h3><table><thead><tr><th>Version</th><th>Promoted</th><th class="num">Labelled flows</th><th class="num">Held-back correct</th><th class="num">Validation F1</th><th></th></tr></thead><tbody>
      <tr class="${st.active === 0 ? "best" : ""}"><td>Shipped model${st.active === 0 ? " (live)" : ""}</td><td>at build time</td><td class="num"></td><td class="num"></td><td class="num"></td><td>${st.active === 0 ? "" : '<button class="btn" data-roll="0">Roll back to this</button>'}</td></tr>
      ${st.versions.map((v) => `<tr class="${st.active === v.generation ? "best" : ""}"><td>Learned ${v.generation}${st.active === v.generation ? " (live)" : ""}</td><td class="mono">${new Date(v.promoted_at * 1000).toISOString().slice(0, 16).replace("T", " ")}</td><td class="num">${v.report.labelled}</td><td class="num">${pct(v.report.challenger.labelled_holdout_accuracy)}</td><td class="num">${v.report.challenger.validation_f1.toFixed(4)}</td><td>${st.active === v.generation ? "" : `<button class="btn" data-roll="${v.generation}">Make live</button>`}</td></tr>`).join("")}</tbody></table>
      <p class="note">Promoted models are saved to disk with their hash, so they survive a restart.</p></div>` : "";
  const sh = await api("/learning/shadow").catch(() => ({ active: false }));
  const shadow = sh.active ? `<div class="report"><h3>A challenger is running in shadow</h3>
      <p style="margin-top:6px">It scores the same traffic as the live model, but only its disagreements are counted. Run the live replay to give it traffic.</p>
      <div class="stats" style="margin:12px 0 0"><div class="stat"><b>${sh.stats.flows.toLocaleString()}</b><span>flows scored by both</span></div><div class="stat"><b>${sh.stats.flows ? pct(sh.stats.agree / sh.stats.flows) : "n/a"}</b><span>same decision</span></div>
        <div class="stat"><b>${sh.stats.only_shadow_flags}</b><span>only the challenger flags: ${sh.stats.only_shadow_flags_true_attack} real attacks, ${sh.stats.only_shadow_flags_true_normal} normal</span></div>
        <div class="stat"><b>${sh.stats.only_live_flags}</b><span>only the live model flags: ${sh.stats.only_live_flags_true_attack} real attacks, ${sh.stats.only_live_flags_true_normal} normal</span></div></div>
      <p class="note">True labels are known only for replayed traffic. Promote when the challenger's extra flags are mostly real attacks.</p>
      <div class="form-foot"><button class="btn primary" id="shadow-promote">Promote the challenger</button><button class="btn" id="shadow-discard">Discard it</button></div></div>` : "";
  const retrainBar = shadow + `<div class="panel"><div class="form-foot" style="margin-top:0"><span id="retrain-slot"><button class="btn primary" id="retrain" ${labelled < 10 ? "disabled" : ""}>Retrain with ${labelled} labelled flows</button> <button class="btn" id="retrain-shadow" ${labelled < 10 || sh.active ? "disabled" : ""}>Retrain and run in shadow first</button></span>
      <span class="muted">${labelled < 10 ? "Label at least 10 flows to enable retraining." : "Trains a challenger with the same settings as the live model. Takes 10 to 20 seconds."}</span></div></div>`;
  const cards = d.campaigns.map((c, i) => {
    const truth = Object.entries(c.true_labels), mixed = truth.some(([k]) => k === "normal");
    return `<div class="panel"><div class="campaign"><div>
      <h3>Campaign ${i + 1}: ${c.size} flows, mostly ${esc(c.common.protocol_type.value)}/${esc(c.common.service.value)} with flag ${esc(c.common.flag.value)}</h3>
      <div class="rule">${esc(c.signature.rule)}</div>
      <p style="font-size:.88rem">This generated rule matches ${pct(c.signature.coverage)} of the campaign and ${pct(c.signature.false_match_rate)} of normal training traffic. Mean risk ${c.mean_risk}.</p>
      ${truth.length ? `<p class="note ${mixed ? "warn" : ""}">True labels, known only because this is a labelled replay: ${truth.map(([k, v]) => `${esc(k)} ${v}`).join(", ")}.${mixed ? " This group contains normal traffic, so check it before labelling it all as an attack." : ""}</p>` : ""}
      <div class="chips" style="margin-top:10px"><a class="chip" href="/campaigns/${c.id}/rule" download>Download Sigma rule</a><button class="chip" data-test="${c.id}">Test rule on the log</button><a class="chip" href="/campaigns/${c.id}/stix" download>Download STIX bundle</a><a class="chip" href="/campaigns/${c.id}/report" download>Download incident report</a></div>
      <p class="note" id="test-${c.id}"></p>
      </div><div class="side"><button class="btn primary" data-label="attack" data-id="${c.id}">Label as attack</button><button class="btn" data-label="benign" data-id="${c.id}">Label as benign</button><button class="btn" data-open="${i}">Open an example</button></div></div></div>`;
  }).join("");
  $("#hunt-out").innerHTML = report + retrainBar + done + versions + (cards || `<div class="panel"><div class="empty"><b>No campaigns right now</b>${d.suspects ? `${d.suspects} possible zero-days are in the log, but a campaign needs at least 8 similar flows.` : "The current model flags nothing in the log as a possible zero-day."} Run the live replay for a minute, then refresh.</div></div>`);
  document.querySelectorAll("[data-label]").forEach((b) => (b.onclick = async () => {
    b.disabled = true;
    const r = await api(`/campaigns/${b.dataset.id}/label`, { label: b.dataset.label }).catch(() => null);
    if (r) toast(`${r.labelled} flows labelled as ${r.label}. Undo is in the list of labelled campaigns.`);
    loadHunt();
  }));
  document.querySelectorAll("[data-undo]").forEach((b) => (b.onclick = async () => {
    const r = await api(`/campaigns/${b.dataset.undo}/label`, undefined, "DELETE").catch(() => null);
    if (r) toast(`Label removed from ${r.removed} flows.`);
    loadHunt();
  }));
  document.querySelectorAll("[data-roll]").forEach((b) => (b.onclick = async () => {
    const r = await api("/learning/rollback", { generation: Number(b.dataset.roll) }).catch(() => null);
    if (r) { toast("Live model is now " + r.model_version); $("#foot-version").textContent = "model " + r.model_version; }
    loadHunt();
  }));
  document.querySelectorAll("[data-test]").forEach((b) => (b.onclick = async () => {
    const t = await api(`/campaigns/${b.dataset.test}/rule/test`).catch(() => null);
    if (t) $("#test-" + b.dataset.test).textContent = `On the ${t.flows} distinct flows in the log the rule matches ${t.matched}: ${Object.entries(t.matched_by_verdict).map(([k, v]) => `${v} ${VERDICT[k].toLowerCase()}`).join(", ") || "none"}.` + (t.matched_true_attack + t.matched_true_normal ? ` By true label: ${t.matched_true_attack} attacks, ${t.matched_true_normal} normal.` : "");
  }));
  document.querySelectorAll("[data-open]").forEach((b) => (b.onclick = () => openFlow(d.campaigns[b.dataset.open].example)));
  const rb = $("#retrain");
  if (rb) rb.onclick = () => {
    // confirm in place instead of a browser dialog
    $("#retrain-slot").innerHTML = `<span class="confirm"><b>Replace the live model if the challenger wins?</b><button class="btn primary" id="retrain-go">Yes, retrain</button><button class="btn" id="retrain-no">Cancel</button></span>`;
    $("#retrain-no").onclick = loadHunt;
    $("#retrain-go").onclick = () => runRetrain("promote");
  };
  const rs = $("#retrain-shadow");
  if (rs) rs.onclick = () => runRetrain("shadow", rs);
  if ($("#shadow-promote")) {
    $("#shadow-promote").onclick = async () => { const r = await api("/learning/shadow/promote", {}).catch(() => null); if (r) { if (lastRetrain) lastRetrain.promoted = true; toast("Challenger promoted. Live model is now " + r.model_version); $("#foot-version").textContent = "model " + r.model_version; } loadHunt(); };
    $("#shadow-discard").onclick = async () => { const r = await api("/learning/shadow", undefined, "DELETE").catch(() => null); if (r) { lastRetrain = null; toast("Challenger discarded."); } loadHunt(); };
  }
  async function runRetrain(mode, btn) {
    const rb = btn || $("#retrain-go");
    rb.disabled = true; rb.textContent = "Training the challenger...";
    lastRetrain = await api("/learning/retrain", { mode: mode === "shadow" ? "shadow" : "promote" }).catch((e) => ({ promoted: false, reason: (e.data && e.data.detail) || "Retraining failed. Check the service log." }));
    toast(lastRetrain.promoted ? "Challenger promoted." : lastRetrain.mode === "shadow" && lastRetrain.champion ? "Challenger is running in shadow." : "Challenger not promoted.", !lastRetrain.promoted && lastRetrain.mode !== "shadow");
    if (lastRetrain.model_version) $("#foot-version").textContent = "model " + lastRetrain.model_version;
    loadHunt();
  }
}
$("#hunt-refresh").onclick = loadHunt;

// ---------- overview ----------
let overviewTimer = null;
async function loadOverview(quiet) {
  if (!quiet) skeleton("#overview-out");
  clearTimeout(overviewTimer);
  overviewTimer = setTimeout(() => { if (!$("#view-overview").hidden && !document.hidden) loadOverview(true); }, 15000);  // keeps itself current
  const o = await api("/overview").catch(() => null);
  if (!o) { $("#overview-out").innerHTML = `<div class="error-box"><b>The overview could not be loaded.</b> Check that the service is running, then refresh.</div>`; return; }
  const order = ["attack", "zero_day_suspect", "uncertain", "benign"], total = o.flows || 1;
  const check = (state, text, go, label) => `<li><i class="mark ${state}"></i><span>${text}</span>${go ? `<button class="chip" data-go="${go}">${label}</button>` : ""}</li>`;
  const src = Object.entries(o.sources).map(([k, v]) => `${v.toLocaleString()} ${k}`).join(", ");
  $("#overview-out").innerHTML = `
    <div class="stats">
      <button class="stat link" data-go="queue"><b>${o.open_alerts}</b><span>open alerts in the queue</span></button>
      <button class="stat link" data-go="hunt"><b>${o.campaigns}</b><span>zero-day campaigns to review</span></button>
      <button class="stat link" data-go="monitor"><b>${{ ok: "No drift", warn: "Early drift", drift: "Drift", waiting: "Waiting" }[o.drift]}</b><span>real traffic vs training data</span></button>
      <button class="stat link" data-go="monitor"><b>${o.chain.valid ? "Intact" : "Broken"}</b><span>log integrity, ${o.chain.entries.toLocaleString()} entries</span></button>
      <button class="stat link" data-go="hunt"><b>${o.model.generation ? "Learned " + o.model.generation : "Shipped"}</b><span>live model, threshold ${o.model.threshold}</span></button>
    </div>
    <div class="ov-grid">
      <div class="panel"><h3>Traffic scored</h3>
        ${o.flows ? `<div class="mix" role="img" aria-label="Verdict mix">${order.map((v) => `<i class="${v}" style="width:${((o.verdicts[v] || 0) / total) * 100}%"></i>`).join("")}</div>
        <div class="legend">${order.map((v) => `<span><i style="background:var(--${TONE[v]})"></i>${VERDICT[v]} ${(o.verdicts[v] || 0).toLocaleString()}</span>`).join("")}</div>
        <p class="note">${o.flows.toLocaleString()} flows in the current log: ${esc(src)}.</p>` : `<div class="empty"><b>Nothing scored yet</b>Start the live replay, analyze the sample capture, or score a flow.</div>`}
        ${o.timeline.length > 1 ? `<h3 style="margin:18px 0 0">Verdicts per minute</h3>${minuteChart(o.timeline)}` : ""}
        <h3 style="margin:18px 0 6px">Highest-priority open alerts</h3>
        ${o.top_alerts.length ? `<div class="table-wrap"><table><thead><tr><th>Connection</th><th>Verdict</th><th class="num">Risk</th><th class="num">Priority</th><th>State</th></tr></thead><tbody>${o.top_alerts.map((a, i) => `<tr class="click" data-alert="${i}" tabindex="0"><td class="mono">${esc(a.connection)}</td><td><span class="tag ${a.verdict}">${VERDICT[a.verdict]}</span></td><td class="num">${a.risk_score}</td><td class="num">${a.priority}</td><td>${a.state}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">The queue is empty.</p>`}</div>
      <div class="panel"><h3 style="margin-bottom:12px">Health checks</h3><ul class="checks">
        ${check(o.chain.valid ? "" : "bad", o.chain.valid ? "Prediction and action logs pass their hash-chain check." : "A log failed its hash-chain check. Treat it as tampered.", "monitor", "Details")}
        ${check(o.drift === "drift" ? "bad" : o.drift === "warn" ? "warn" : "", { ok: "Real traffic matches the training data.", warn: "Real traffic is starting to move away from the training data.", drift: "Real traffic has drifted from the training data. Retrain.", waiting: "Drift needs 30 real predictions (replay and sample traffic do not count)." }[o.drift], "monitor", "Drift")}
        ${check(o.open_mode ? "warn" : "", o.open_mode ? "Open mode: no API keys are set, so anyone can label and retrain." : "Labelling and retraining require an API key.", null)}
        ${o.shadow ? check("warn", "A challenger model is running in shadow and waiting for a decision.", "hunt", "Hunt") : ""}
        ${check(o.labelled.attack + o.labelled.benign >= 10 ? "warn" : "", `${o.labelled.attack + o.labelled.benign} flows are labelled and waiting for a retrain.`, "hunt", "Hunt")}
        ${check(o.assets.some((a) => a.exposure >= 60) ? "bad" : o.assets.length ? "" : "warn", o.assets.length ? o.assets.map((a) => `${esc(a.name)} exposure ${a.exposure}`).join(", ") + "." : "No assets registered, so alerts have no priority context.", "assets", "Assets")}
      </ul>
      <h3 style="margin:18px 0 8px">Start here</h3><div class="chips"><button class="chip" data-go="live">Replay labelled traffic</button><button class="chip" data-go="capture">Analyze a capture</button><button class="chip" data-go="analyze">Score one flow</button></div></div>
    </div>`;
  document.querySelectorAll("#overview-out [data-go]").forEach((b) => (b.onclick = () => show(b.dataset.go)));
  document.querySelectorAll("#overview-out [data-alert]").forEach((tr) => { tr.onclick = () => openAlert(o.top_alerts[tr.dataset.alert].request_id); tr.onkeydown = (e) => { if (e.key === "Enter") tr.onclick(); }; });
}
$("#overview-refresh").onclick = () => loadOverview();
function minuteChart(tl) {
  const order = ["benign", "uncertain", "zero_day_suspect", "attack"], W = 640, H = 120, bw = Math.min(28, (W - 30) / tl.length), peak = Math.max(1, ...tl.map((m) => order.reduce((a, k) => a + m[k], 0)));
  return `<svg class="tl" viewBox="0 0 ${W} ${H + 18}" role="img" aria-label="Flows per minute, stacked by verdict">${tl.map((m, i) => { let y = H; return order.map((k) => { const h = (m[k] / peak) * (H - 6); y -= h; return h ? `<rect x="${30 + i * bw}" y="${y}" width="${bw - 3}" height="${h}" fill="var(--${TONE[k]})"><title>${m.minute} ${VERDICT[k]}: ${m[k]}</title></rect>` : ""; }).join(""); }).join("")}
    <text x="26" y="10" text-anchor="end">${peak}</text><text x="26" y="${H}" text-anchor="end">0</text><text x="30" y="${H + 14}">${tl[0].minute}</text><text x="${30 + tl.length * bw}" y="${H + 14}" text-anchor="end">${tl[tl.length - 1].minute} UTC</text></svg>`;
}

// ---------- alert queue ----------
let queueState = "open", queueMine = false;
function loadQueue() { return guarded("#queue-out", loadQueueInner); }
async function loadQueueInner() {
  skeleton("#queue-out");
  const d = await api(`/alerts?state=${queueState}&limit=500`);
  if (queueMine) d.items = d.items.filter((a) => a.assignee === me.user);
  const names = { open: "Open", new: "New", investigating: "Investigating", confirmed: "Confirmed", false_positive: "False alarms", all: "All" };
  const n = { ...d.counts, open: d.counts.new + d.counts.investigating, all: Object.values(d.counts).reduce((a, b) => a + b, 0) };
  $("#queue-filter").innerHTML = Object.keys(names).map((k) => `<button class="chip ${k === queueState ? "on" : ""}" data-qs="${k}">${names[k]} ${n[k]}</button>`).join("") + `<button class="chip ${queueMine ? "on" : ""}" id="q-mine">Assigned to me</button>`;
  document.querySelectorAll("[data-qs]").forEach((b) => (b.onclick = () => { queueState = b.dataset.qs; loadQueue(); }));
  $("#q-mine").onclick = () => { queueMine = !queueMine; loadQueue(); };
  if (!d.items.length) { $("#queue-out").innerHTML = `<div class="panel"><div class="empty"><b>Nothing in this view</b>${queueState === "open" ? "Every alert has been triaged, or no traffic has been flagged yet." : "No alerts have this state."}</div></div>`; return; }
  $("#queue-out").innerHTML = `<div class="panel"><div class="form-foot" style="margin:0 0 12px"><span class="muted" id="q-count">Tick alerts to change several at once.</span>
      <select class="inline" id="q-bulk" aria-label="Set the state of the ticked alerts"><option value="">Set ticked alerts to...</option>${["investigating", "confirmed", "false_positive", "new"].map((s) => `<option value="${s}">${s.replace("_", " ")}</option>`).join("")}</select>
      <button class="btn" id="q-take">Assign ticked to me</button></div>
    <div id="queue-table"></div><p class="note">Priority is the model's risk scaled by the exposure of the asset under attack. Select a row to open the flow in Analyze.</p></div>`;
  const ticked = new Set();
  const patch = (id, body) => api("/alerts/" + id, body, "PATCH").catch(() => null);
  const byId = Object.fromEntries(d.items.map((a) => [a.request_id, a]));
  $("#q-bulk").onchange = async (e) => {
    const state = e.target.value; if (!state || !ticked.size) { e.target.value = ""; return; }
    const done = await Promise.all([...ticked].map((id) => patch(id, { state, assignee: byId[id].assignee || "" })));
    toast(`${done.filter(Boolean).length} alerts set to ${state.replace("_", " ")}.`); loadQueue();
  };
  $("#q-take").onclick = async () => {
    if (!ticked.size) return;
    const done = await Promise.all([...ticked].map((id) => patch(id, { state: byId[id].state === "new" ? "investigating" : byId[id].state, assignee: me.user })));
    toast(`${done.filter(Boolean).length} alerts assigned to ${me.user}.`); loadQueue();
  };
  const rows = d.items.map((a) => ({ ...a, time: a.ts.slice(11, 19), verdict_label: VERDICT[a.verdict] }));
  dataTable("#queue-table", [{ key: "request_id", label: "", render: (r) => `<input type="checkbox" data-tick="${r.request_id}" aria-label="Select alert ${r.request_id}" ${ticked.has(r.request_id) ? "checked" : ""}>` }, { key: "time", label: "Time (UTC)", mono: 1 }, { key: "connection", label: "Connection", mono: 1 }, { key: "source", label: "Source" },
    { key: "verdict_label", label: "Verdict", render: (r) => `<span class="tag ${r.verdict}">${VERDICT[r.verdict]}</span>` }, { key: "risk_score", label: "Risk", num: 1 }, { key: "priority", label: "Priority", num: 1 },
    { key: "state", label: "State", render: (r) => `<select class="inline" data-rid="${r.request_id}" aria-label="State of alert ${r.request_id}">${["new", "investigating", "confirmed", "false_positive"].map((s) => `<option value="${s}" ${s === r.state ? "selected" : ""}>${s.replace("_", " ")}</option>`).join("")}</select>` },
    { key: "assignee", label: "Assignee", render: (r) => `<input class="inline" data-as="${r.request_id}" value="${esc(r.assignee)}" maxlength="40" placeholder="unassigned" aria-label="Assignee of alert ${r.request_id}">` }],
    rows, { pageSize: 20, onRow: (r) => openAlert(r.request_id), after: (el) => { el.querySelectorAll("[data-tick]").forEach((c) => (c.onchange = () => { c.checked ? ticked.add(c.dataset.tick) : ticked.delete(c.dataset.tick); $("#q-count").textContent = ticked.size ? ticked.size + " ticked." : "Tick alerts to change several at once."; }));
      el.querySelectorAll("[data-as]").forEach((inp) => (inp.onchange = async () => { const r = await patch(inp.dataset.as, { state: byId[inp.dataset.as].state, assignee: inp.value.trim() }); if (r) { byId[inp.dataset.as].assignee = r.assignee; toast(r.assignee ? "Assigned to " + r.assignee + "." : "Assignee cleared."); } }));
      el.querySelectorAll("select[data-rid]").forEach((s) => (s.onchange = async () => {
      const r = await api("/alerts/" + s.dataset.rid, { state: s.value, assignee: byId[s.dataset.rid].assignee || "" }, "PATCH").catch(() => null);
      if (r) toast(s.value === "confirmed" ? "Confirmed. The flow is labelled as an attack for the next retrain." : s.value === "false_positive" ? "Closed as a false alarm. The flow is labelled benign for the next retrain." : "Alert updated.");
      loadQueue();
    })); } });
}

// ---------- batch ----------
let batchResults = null;
function parseCsv(text) {
  // RFC 4180 parsing: quoted fields may contain commas, quotes ("") and line breaks
  const table = []; let row = [], cell = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) { if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (ch === '"') quoted = false; else cell += ch; }
    else if (ch === '"') quoted = true;
    else if (ch === ",") { row.push(cell); cell = ""; }
    else if (ch === "\n" || ch === "\r") { if (ch === "\r" && text[i + 1] === "\n") i++; row.push(cell); cell = ""; if (row.some((c) => c.trim() !== "")) table.push(row); row = []; }
    else cell += ch;
  }
  row.push(cell); if (row.some((c) => c.trim() !== "")) table.push(row);
  if (table.length < 2) throw new Error("Add a header row and at least one data row.");
  const head = table[0].map((s) => s.trim());
  if (!contract.features.every((f) => head.includes(f.name))) throw new Error("The header row is missing: " + contract.features.filter((f) => !head.includes(f.name)).map((f) => f.name).join(", ") + ".");
  const lines = [null, ...table.slice(1)];
  const types = Object.fromEntries(contract.features.map((f) => [f.name, f.type]));
  return lines.slice(1).map((cells) => {
    const row = {};
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
      <div class="panel"><div id="batch-table"></div></div>`;
    const rows = d.results.map((r, i) => ({ n: i + 1, connection: `${flows[i].protocol_type}/${flows[i].service} ${flows[i].flag}`, verdict: r.verdict, verdict_label: VERDICT[r.verdict], family: r.attack_family || "", risk: r.risk_score, p: Number(r.attack_probability.toFixed(2)), nov: Number(r.novelty_score.toFixed(2)), flow: flows[i] }));
    dataTable("#batch-table", [{ key: "n", label: "#", num: 1 }, { key: "connection", label: "Connection", mono: 1 }, { key: "verdict_label", label: "Verdict", render: (r) => `<span class="tag ${r.verdict}">${VERDICT[r.verdict]}</span>` }, { key: "family", label: "Family" }, { key: "risk", label: "Risk", num: 1 }, { key: "p", label: "Attack prob.", num: 1 }, { key: "nov", label: "Novelty", num: 1 }], rows, { onRow: (r) => openFlow(r.flow) });
    $("#batch-download").hidden = false;
  } catch (err) { showValidation(err, "#batch-error"); }
};
$("#batch-download").onclick = () => {
  const cols = Object.keys(batchResults[0]);
  // quote every field, and neutralise cells a spreadsheet would run as a formula (=, +, -, @)
  const safe = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s) && Number.isNaN(Number(s))) s = "'" + s; return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  download("zerowatch_results.csv", [cols.join(","), ...batchResults.map((r) => cols.map((c) => safe(r[c])).join(","))].join("\n"), "text/csv");
};

// ---------- model ----------
async function loadModel() {
  skeleton("#model-out");
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
    ${m.evaluation ? (() => { const c = m.evaluation.confusion, fr = Object.entries(m.evaluation.family_recall), roc = m.evaluation.roc, P = (pt) => `${30 + pt.fpr * 250},${260 - pt.tpr * 250}`;
      return `<div class="cols" style="margin-top:16px">
        <div class="panel"><h3 style="margin-bottom:8px">What it gets right and wrong</h3><p class="note" style="margin-bottom:8px">Full verdict on ${(c.tp + c.fp + c.fn + c.tn).toLocaleString()} held-out KDDTest+ flows.</p>
          <table class="matrix"><thead><tr><th></th><th>Flagged</th><th>Passed</th></tr></thead><tbody>
          <tr><th>Really an attack</th><td class="good">${c.tp.toLocaleString()}<small>caught</small></td><td class="bad">${c.fn.toLocaleString()}<small>missed</small></td></tr>
          <tr><th>Really normal</th><td class="bad">${c.fp.toLocaleString()}<small>false alarms</small></td><td class="good">${c.tn.toLocaleString()}<small>correctly passed</small></td></tr></tbody></table></div>
        <div class="panel"><h3 style="margin-bottom:12px">Attacks caught, by family</h3><div class="pair">${fr.map(([k, v]) => `<div class="row hi" title="${v.flows} flows; classifier alone ${pct(v.caught_by_classifier)}"><span>${k} <span class="muted">${v.flows.toLocaleString()}</span></span><div class="bar"><b style="width:${v.caught * 100}%"></b></div><span>${pct(v.caught)}</span></div>`).join("")}</div>
          <p class="note">R2L attacks (password guessing and similar) look like normal flows in these features, which is why most are missed.</p></div>
        <div class="panel"><h3 style="margin-bottom:8px">ROC curve, classifier alone</h3><svg class="roc" viewBox="0 0 300 290" role="img" aria-label="ROC curve, area ${t.test.roc_auc}">
          <rect x="30" y="10" width="250" height="250" fill="none" stroke="var(--line)"/><line x1="30" y1="260" x2="280" y2="10" stroke="var(--line)" stroke-dasharray="4 4"/>
          <polyline fill="none" stroke="var(--accent)" stroke-width="2.5" points="${roc.map(P).join(" ")}"/>
          <text x="155" y="282" text-anchor="middle">false alarms on normal traffic</text><text x="12" y="135" text-anchor="middle" transform="rotate(-90 12 135)">attacks caught</text>
          <text x="270" y="250" text-anchor="end">area ${t.test.roc_auc.toFixed(3)}</text></svg></div></div>`; })() : ""}
    ${m.threshold_curve.length ? `<div class="panel" style="margin-top:16px"><h3>Decision threshold</h3>
      <p class="muted" style="margin:6px 0 12px;font-size:.88rem;max-width:80ch">A flow is called a known attack when its attack probability reaches this value. Lower it to catch more attacks at the cost of more false alarms. Figures are for the full verdict on held-out KDDTest+.</p>
      <input class="slider" id="thr" type="range" min="0.05" max="0.95" step="0.05" value="${m.threshold}" aria-label="Decision threshold">
      <div class="stats" style="margin:12px 0 0"><div class="stat"><b id="thr-v"></b><span>threshold</span></div><div class="stat"><b id="thr-r"></b><span>attacks caught</span></div><div class="stat"><b id="thr-f"></b><span>false alarms on normal traffic</span></div><div class="stat"><b id="thr-p"></b><span>flagged flows that are real attacks</span></div></div>
      <div class="form-foot"><button class="btn primary" id="thr-apply">Apply to the live model</button><span class="muted" id="thr-note"></span></div></div>` : ""}
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
  wireThreshold(m);
}

function wireThreshold(m) {
  const s = $("#thr"); if (!s) return;
  const paint = () => {
    const c = m.threshold_curve.reduce((a, b) => (Math.abs(b.threshold - s.value) < Math.abs(a.threshold - s.value) ? b : a));
    $("#thr-v").textContent = Number(s.value).toFixed(2); $("#thr-r").textContent = pct(c.recall); $("#thr-f").textContent = pct(c.fpr); $("#thr-p").textContent = pct(c.precision);
    $("#thr-note").textContent = Number(s.value) === m.threshold ? "This is the live setting." : `Live setting is ${m.threshold}.`;
  };
  s.oninput = paint; paint();
  $("#thr-apply").onclick = async () => {
    const r = await api("/settings/threshold", { threshold: Number(s.value) }).catch((e) => { if (e.status === 422) toast("That value is not allowed: it must stay above the review band.", true); return null; });
    if (r) { m.threshold = r.threshold; paint(); toast("Threshold is now " + r.threshold + ". The change is recorded in the action log."); }
  };
}

// ---------- monitoring ----------
async function loadMonitor() {
  if (!$("#monitor-out").children.length) skeleton("#monitor-out");
  const [d, r, a, b, al, ac] = await Promise.all([api("/monitoring/drift"), api("/monitoring/recent?limit=15"), api("/audit/verify"), api("/brief"), api("/monitoring/alarm"), api("/audit/actions?limit=12").catch(() => ({ items: [], locked: true }))]);
  const word = { ok: "No drift", warn: "Early drift", drift: "Drift detected", waiting: "Collecting data" }[d.status];
  const drift = d.enough_data ? `<div class="table-wrap"><table><thead><tr><th>Feature</th><th class="num">Training</th><th class="num">Live</th><th>Shift</th><th>Status</th></tr></thead><tbody>
    ${d.features.slice(0, 12).map((f) => `<tr><td class="mono">${f.feature}</td><td class="num">${f.kind === "num" ? f.train_mean : pct(f.train_top_share)}</td><td class="num">${f.kind === "num" ? f.live_mean : esc(f.live_top) + " " + pct(f.live_top_share)}</td>
      <td><span class="mini"><b class="${f.status}" style="width:${Math.min(100, f.shift * 100)}%"></b></span><span class="mono">${f.shift.toFixed(2)}</span></td><td>${f.status}</td></tr>`).join("")}</tbody></table></div>
    <p class="muted" style="font-size:.82rem;margin-top:10px">Shift is the distance between live and training means in training standard deviations (or the change in category shares). Above 0.25 is a warning, above 0.5 is drift and a reason to retrain.</p>`
    : `<p class="muted">Drift needs at least 30 real predictions and has ${d.rows}. Replayed and sample traffic are left out on purpose, so a demo cannot look like drift. Score flows, run a batch or upload a capture.</p>`;
  $("#monitor-out").innerHTML = `
    <div class="stats"><div class="stat"><b>${word}</b><span>from ${d.rows.toLocaleString()} logged inputs</span></div>
      ${["attack", "zero_day_suspect", "uncertain"].map((v) => `<div class="stat"><b>${r.verdicts[v] || 0}</b><span>${VERDICT[v]}, recent</span></div>`).join("")}
      <div class="stat"><b>${a.valid ? "Intact" : "Broken"}</b><span>log hash chains, ${a.entries.toLocaleString()} predictions and ${a.actions.entries} actions${a.valid ? "" : ", problem at line " + (a.broken_at_line || a.actions.broken_at_line)}</span></div></div>
    <div class="panel"><h3>Shift report</h3><p style="margin-top:8px"><b>${esc(b.headline)}</b></p>
      <ul class="brief">${b.points.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>
      ${b.actions.length ? `<h3 style="margin:14px 0 8px">Do first</h3><ul class="tips">${b.actions.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}</div>
    <div class="panel"><h3>Ask the copilot</h3>
      <div class="chips" style="margin-top:10px">${["What happened recently?", "What should I do first?", "Any possible zero-days?", "Which services are being attacked?", "Can I trust the log?"].map((q) => `<button class="chip" data-q="${q}">${q}</button>`).join("")}</div>
      <form class="ask" id="ask-form"><input id="ask-q" maxlength="300" placeholder="Ask about the traffic this service has scored" aria-label="Question"><button class="btn primary">Ask</button></form>
      <div id="ask-out"></div></div>
    <div class="panel"><h3 style="margin-bottom:10px">Input drift against training data</h3>${drift}</div>
    <div class="cols"><div class="panel"><h3>Alarm</h3>
      <p style="font-size:.9rem;margin-top:8px">${al.interval_seconds > 0 ? `Drift and log integrity are checked every ${Math.round(al.interval_seconds / 60)} minutes.` : "The timed check is switched off."} ${al.webhook ? "A message is sent to the configured webhook when drift appears or a log chain breaks." : "No webhook is configured, so nothing is sent. Set ALERT_WEBHOOK_URL to a Slack-style webhook."}</p>
      <p class="note">${al.last_check ? "Last check " + new Date(al.last_check * 1000).toISOString().slice(11, 19) + " UTC: drift " + al.drift + ", log " + (al.chain_valid ? "intact" : "broken") + "." : "No check has run yet."}${al.last_sent ? " Last message sent " + new Date(al.last_sent * 1000).toISOString().slice(11, 19) + " UTC." : ""}</p>
      <div class="form-foot"><button class="btn" id="alarm-test">Run the check now and send a test message</button></div></div>
    <div class="panel table-wrap"><h3 style="margin-bottom:10px">Analyst and admin actions</h3>
      ${ac.items.length ? `<table><thead><tr><th>Time (UTC)</th><th>Role</th><th>Action</th><th>Detail</th></tr></thead><tbody>${ac.items.map((e) => `<tr><td class="mono">${esc(e.ts.slice(11, 19))}</td><td>${esc(e.role)}</td><td class="mono">${esc(e.action)}</td><td class="mono">${esc(Object.entries(e.detail).map(([k, v]) => k + "=" + v).join(" "))}</td></tr>`).join("")}</tbody></table><p class="note">This log is hash-chained too, so an action cannot be quietly removed.</p>` : `<p class="muted">${ac.locked ? "Sign in with an analyst or admin key to see who did what." : "No labels, retrains or setting changes yet."}</p>`}</div></div>
    <div class="panel table-wrap" style="margin-top:16px"><h3 style="margin-bottom:10px">Latest predictions in the log</h3>
      ${r.items.length ? `<table><thead><tr><th>Time (UTC)</th><th>Request</th><th>Connection</th><th>Verdict</th><th class="num">Risk</th></tr></thead><tbody>${r.items.map((e) => `<tr><td class="mono">${esc(e.ts.slice(11, 19))}</td><td class="mono">${esc(e.request_id)}</td><td class="mono">${esc(e.input.protocol_type)}/${esc(e.input.service)} ${esc(e.input.flag)}</td><td><span class="tag ${e.output.verdict}">${VERDICT[e.output.verdict]}</span></td><td class="num">${e.output.risk_score}</td></tr>`).join("")}</tbody></table>`
      : `<p class="muted">Nothing scored since the service started.</p>`}</div>`;
}
document.addEventListener("click", async (e) => {
  if (e.target.id !== "alarm-test") return;
  const r = await api("/monitoring/alarm/test", {}).catch(() => null);
  if (r) { toast(r.webhook ? (r.sent ? "Check done and test message sent." : "Check done, but the webhook did not accept the message.") : "Check done. No webhook is configured.", r.webhook && !r.sent); loadMonitor(); }
});
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
    await refreshAuth();
    show(location.hash.slice(1) || "analyze", "boot");
    const recent = await api("/monitoring/recent?limit=120").catch(() => null);  // history in the trace from the first paint
    if (recent) recent.items.reverse().forEach((e) => trace(e.output));
  } catch (e) {
    $("#health").innerHTML = `<i class="dot bad"></i>API unreachable`;
  }
})();

// ---------- keyboard ----------
const tabs = [...document.querySelectorAll(".tabs button")];
$(".tabs").addEventListener("keydown", (e) => {  // arrow keys move between tabs, as the tab pattern expects
  const i = tabs.indexOf(document.activeElement); if (i < 0) return;
  const to = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
  if (to === undefined) return;
  e.preventDefault(); const t = tabs[(to + tabs.length) % tabs.length]; show(t.dataset.view, false, true); t.focus();
});
const KEYS = "Keys: 1 to 9 and 0 open a view, left and right arrows move between tabs, / jumps to the table filter, T switches theme.";
$("#keys-help").onclick = () => toast(KEYS);
document.addEventListener("keydown", (e) => {
  if (e.target.closest("input, select, textarea") || e.ctrlKey || e.metaKey || e.altKey) return;
  if (/^[0-9]$/.test(e.key)) { const t = tabs[e.key === "0" ? 9 : Number(e.key) - 1]; if (t) { show(t.dataset.view, false, true); t.focus(); } }
  else if (e.key === "/") { const f = document.querySelector("main > section:not([hidden]) input[type=search]"); if (f) { e.preventDefault(); f.focus(); } }
  else if (e.key === "t" || e.key === "T") $("#theme").click();
  else if (e.key === "?") toast(KEYS);
});
