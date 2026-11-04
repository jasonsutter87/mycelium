// The Mycelium dashboard. Plain JS, no build step. Everything from the server goes through esc() or safeUrl().
"use strict";

const TOKEN = document.querySelector('meta[name="mycelium-token"]').content;
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const safeUrl = (u) => (/^https?:\/\//i.test(String(u ?? "")) ? esc(u) : "#");
const store = {
  get(k, d) { try { return JSON.parse(localStorage.getItem("mycelium." + k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem("mycelium." + k, JSON.stringify(v)); } catch { /* private mode: not remembered */ } },
};

async function api(path, body) {
  const r = await fetch(path, body === undefined
    ? { headers: { "x-mycelium-token": TOKEN } }
    : { method: "POST", headers: { "content-type": "application/json", "x-mycelium-token": TOKEN }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { location.href = "/login"; throw new Error("sign in first"); }
  if (r.status === 403 && j.error === "bad token") { location.reload(); throw new Error("page was out of date, reloading"); }
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}

const SEV_ORDER = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"];
const STEP_LABEL = { check: "Check", pull: "Pull", branch: "Branch", fix: "Fix", verify: "Test", commit: "Commit", push: "Push", pr: "PR" };

const state = {
  view: "projects",
  data: null,
  tabs: {}, // lazily loaded findings / audit / infra
  selected: null, // project name
  detail: null,
  checked: new Set(), // projects checked since the page loaded: Fix stays locked until then
  checking: false,
  checkError: null,
  job: null,
  q: store.get("q", ""),
  status: store.get("status", "all"),
  exposure: store.get("exposure", "all"),
  sort: store.get("sort", { key: "worst", dir: "desc" }),
  sevFilter: "ALL",
};

function banner(msg, isErr) {
  const b = $("banner");
  b.hidden = !msg;
  b.textContent = msg || "";
  b.classList.toggle("err", !!isErr);
}

const ago = (iso) => {
  if (!iso) return "never";
  const m = Math.round((Date.now() - Date.parse(iso)) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return `${Math.round(m / 1440)} d ago`;
};

// ---------------------------------------------------------------- top + stats

function renderTop() {
  const d = state.data;
  $("checked").textContent = `Checked ${ago(d.lastChecked)}`;
  $("user").innerHTML = d.signIn ? `${esc(d.user)} · <a href="/auth/logout">Sign out</a>` : "This computer only";
  $("rescan").disabled = !!d.busy;
  document.querySelectorAll("#views button").forEach((b) => b.classList.toggle("on", b.dataset.view === state.view));
}

function renderStats() {
  const t = state.data.totals;
  const cards = [
    ["open", "", t.open, "open findings", { status: "attention" }],
    ["crit", "crit", t.critical, "critical", { view: "findings", sev: "CRITICAL" }],
    ["high", "high", t.high, "high", { view: "findings", sev: "HIGH" }],
    ["mod", "mod", t.moderate, "moderate", { view: "findings", sev: "MODERATE" }],
    ["clean", "ok", t.clean, "clean projects", { status: "clean" }],
    ["accepted", "", t.accepted, "accepted", { status: "accepted" }],
    ["prs", "", t.prs, "PRs open", { status: "prs" }],
  ];
  $("stats").innerHTML = cards.map(([id, cls, n, label]) => `<button class="stat ${cls}" data-stat="${id}"><b>${n}</b><span>${label}</span></button>`).join("");
  document.querySelectorAll("[data-stat]").forEach((el, i) => {
    el.onclick = () => {
      const go = cards[i][4];
      if (go.view) { state.view = go.view; state.sevFilter = go.sev; loadTab(); }
      else { state.view = "projects"; setStatus(go.status); }
      renderAll();
    };
  });
}

function setStatus(s) { state.status = s; store.set("status", s); }

// ---------------------------------------------------------------- projects view

const COLUMNS = [
  { key: "name", label: "Project" },
  { key: "status", label: "Status", sm: true },
  { key: "open", label: "Findings", right: true },
  { key: "worst", label: "Severity" },
  { key: "accepted", label: "Accepted", right: true, sm: true, wide: true },
  { key: "packages", label: "Packages", right: true, sm: true, wide: true },
  { key: "exposure", label: "Exposure", sm: true, wide: true },
  { key: "scannedAt", label: "Scanned", sm: true, wide: true },
];
const STATUS_RANK = { attention: 0, accepted: 1, clean: 2 };

function visibleProjects() {
  const q = state.q.trim().toLowerCase();
  const { key, dir } = state.sort;
  // Worst first means critical, then high, then moderate: one critical outranks any number of lows.
  const worst = (s) => s.CRITICAL * 1e9 + s.HIGH * 1e6 + s.MODERATE * 1e3 + s.LOW + s.UNKNOWN;
  const val = (p) => (key === "worst" ? worst(p.bySeverity) : key === "status" ? STATUS_RANK[p.status] : key === "scannedAt" ? Date.parse(p.scannedAt || 0) : p[key]);
  const list = state.data.projects.filter((p) => {
    if (q && !`${p.name} ${p.path} ${p.hosts.join(" ")}`.toLowerCase().includes(q)) return false;
    if (state.exposure !== "all" && p.exposure !== state.exposure) return false;
    if (state.status === "prs") return p.prs.some((s) => !s.needsPull);
    return state.status === "all" || p.status === state.status;
  });
  return list.sort((a, b) => {
    const x = val(a), y = val(b);
    const c = typeof x === "string" ? x.localeCompare(y) : x - y;
    return (dir === "asc" ? c : -c) || a.name.localeCompare(b.name);
  });
}

const counts = (s) => SEV_ORDER.filter((k) => s[k]).map((k) => `<span class="sev ${k}" title="${k.toLowerCase()}">${s[k]} ${k === "MODERATE" ? "mod" : k === "UNKNOWN" ? "info" : k.toLowerCase()}</span>`).join("");
const STATUS_LABEL = { attention: "Needs attention", clean: "Clean", accepted: "Accepted" };

function renderProjects() {
  const all = state.data.projects;
  const n = (fn) => all.filter(fn).length;
  const tabs = [
    ["all", "All", all.length],
    ["attention", "Needs attention", n((p) => p.status === "attention")],
    ["clean", "Clean", n((p) => p.status === "clean")],
    ["accepted", "Accepted", n((p) => p.status === "accepted")],
    ["prs", "PRs open", n((p) => p.prs.some((s) => !s.needsPull))],
  ];
  const exposures = [...new Set(all.map((p) => p.exposure))].sort();
  const list = visibleProjects();
  const { key, dir } = state.sort;
  const th = (c) => `<th class="sortable ${c.right ? "right" : ""} ${c.sm ? "hide-sm" : ""} ${c.wide ? "hide-narrow" : ""} ${key === c.key ? "sorted" : ""}" ${key === c.key ? `aria-sort="${dir === "asc" ? "ascending" : "descending"}"` : ""}>
    <button data-sort="${c.key}">${c.label}${key === c.key ? (dir === "asc" ? " ↑" : " ↓") : ""}</button></th>`;
  $("canvas").innerHTML = `
    <div class="filters">
      <input class="field" id="q" type="search" placeholder="Search projects, paths, hosts" aria-label="Search projects" value="${esc(state.q)}">
      <div class="chips" role="group" aria-label="Filter by status">${tabs.map(([id, label, c]) => `<button data-status="${id}" class="${state.status === id ? "on" : ""}">${label}<i>${c}</i></button>`).join("")}</div>
      <select class="field" id="exposure" aria-label="Filter by exposure">
        <option value="all">All exposure</option>${exposures.map((e) => `<option value="${esc(e)}" ${state.exposure === e ? "selected" : ""}>${esc(e)}</option>`).join("")}
      </select>
      <select class="field" id="sort" aria-label="Sort by">
        ${[["worst", "Worst first"], ["open", "Findings"], ["name", "Name"], ["accepted", "Accepted"], ["packages", "Packages"], ["scannedAt", "Last scanned"], ["status", "Status"]].map(([k, l]) => `<option value="${k}" ${key === k ? "selected" : ""}>Sort: ${l}</option>`).join("")}
      </select>
      <button class="btn small" id="dir" title="Flip the sort order" aria-label="Sort ${dir === "asc" ? "ascending" : "descending"}, click to flip">${dir === "asc" ? "↑ Asc" : "↓ Desc"}</button>
      <span class="count">${list.length} of ${all.length}</span>
    </div>
    <div class="tablewrap"><table>
      <thead><tr>${COLUMNS.map(th).join("")}</tr></thead>
      <tbody>${list.map((p) => `<tr class="row ${state.selected === p.name ? "on" : ""}" data-project="${esc(p.name)}" tabindex="0">
        <td><div class="pname">${esc(p.name)}</div><div class="path">${esc(p.path.replace(/^\/Users\/[^/]+/, "~"))}</div></td>
        <td class="hide-sm"><span class="pill ${p.status}"><span class="dot"></span>${STATUS_LABEL[p.status]}</span>${p.prs.length ? ` <span class="small muted">${p.prs.length} PR${p.prs.length > 1 ? "s" : ""}</span>` : ""}</td>
        <td class="right num"><b>${p.open || "–"}</b></td>
        <td><span class="counts">${counts(p.bySeverity) || '<span class="muted">–</span>'}</span></td>
        <td class="right num hide-sm hide-narrow">${p.accepted || '<span class="muted">–</span>'}</td>
        <td class="right num hide-sm hide-narrow">${p.packages.toLocaleString()}</td>
        <td class="hide-sm hide-narrow">${esc(p.exposure)}</td>
        <td class="hide-sm hide-narrow muted small">${ago(p.scannedAt)}</td></tr>`).join("") || `<tr><td colspan="8" class="empty">No projects match these filters.</td></tr>`}</tbody>
    </table></div>`;

  const q = $("q");
  q.oninput = () => {
    state.q = q.value; store.set("q", q.value);
    const pos = q.selectionStart;
    renderProjects();
    const again = $("q"); again.focus(); again.setSelectionRange(pos, pos);
  };
  document.querySelectorAll("[data-status]").forEach((b) => (b.onclick = () => { setStatus(b.dataset.status); renderProjects(); }));
  $("exposure").onchange = (e) => { state.exposure = e.target.value; store.set("exposure", state.exposure); renderProjects(); };
  const setSort = (k) => {
    const textual = k === "name" || k === "exposure" || k === "status";
    state.sort = state.sort.key === k ? { key: k, dir: state.sort.dir === "asc" ? "desc" : "asc" } : { key: k, dir: textual ? "asc" : "desc" };
    store.set("sort", state.sort);
    renderProjects();
  };
  document.querySelectorAll("[data-sort]").forEach((b) => (b.onclick = () => setSort(b.dataset.sort)));
  $("sort").onchange = (e) => setSort(e.target.value);
  $("dir").onclick = () => { state.sort = { ...state.sort, dir: dir === "asc" ? "desc" : "asc" }; store.set("sort", state.sort); renderProjects(); };
  document.querySelectorAll("tr.row[data-project]").forEach((r) => {
    r.onclick = () => selectProject(r.dataset.project);
    r.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectProject(r.dataset.project); } };
  });
}

// ---------------------------------------------------------------- other views

async function loadTab() {
  if (state.view === "projects" || state.tabs[state.view]) return;
  try {
    state.tabs[state.view] = await api("/api/" + state.view);
    renderCanvas();
  } catch (e) { banner(`Couldn't load ${state.view}: ${e.message}`, true); }
}

function table(headers, rows, emptyText) {
  return `<div class="tablewrap"><table><thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("") || `<tr><td colspan="${headers.length}" class="empty">${emptyText}</td></tr>`}</tbody></table></div>`;
}

function renderFindings() {
  const list = state.tabs.findings;
  if (!list) return ($("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading findings</div>`);
  const shown = list.filter((f) => state.sevFilter === "ALL" || f.severity === state.sevFilter);
  $("canvas").innerHTML = `<div class="filters"><div class="chips" role="group" aria-label="Filter by severity">
      ${["ALL", ...SEV_ORDER].map((s) => `<button data-sev="${s}" class="${state.sevFilter === s ? "on" : ""}">${s === "ALL" ? "All" : s[0] + s.slice(1).toLowerCase()}<i>${s === "ALL" ? list.length : list.filter((f) => f.severity === s).length}</i></button>`).join("")}
    </div><span class="count">Ranked by blast radius · ${shown.length} shown</span></div>` +
    table(["Severity", "Package", "Advisory", "Projects"], shown.map((f) => `<tr>
      <td><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td><b>${esc(f.name)}</b> <span class="mono muted">${esc(f.version)}</span><div class="small muted">${esc(f.ecosystem)} · ${f.fixed ? `fixed in ${esc(f.fixed)}` : "no fix yet"}</div></td>
      <td class="wrap">${esc(f.summary)}<div class="small"><a href="${safeUrl(f.url)}" target="_blank" rel="noopener noreferrer">${esc(f.id)}</a></div></td>
      <td>${f.projects.map((p) => `<button class="btn small" data-goto="${esc(p)}">${esc(p)}</button>`).join(" ")}</td></tr>`), "No open findings. 🍄");
  document.querySelectorAll("[data-sev]").forEach((b) => (b.onclick = () => { state.sevFilter = b.dataset.sev; renderFindings(); }));
  document.querySelectorAll("[data-goto]").forEach((b) => (b.onclick = () => { state.view = "projects"; selectProject(b.dataset.goto); renderAll(); }));
}

function renderAudit() {
  const list = state.tabs.audit;
  if (!list) return ($("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading audit</div>`);
  $("canvas").innerHTML = `<div class="filters"><span class="muted">Everything that isn't a CVE: licenses, deprecated and abandoned packages, CI config, committed secrets.</span><span class="count">${list.length} issues</span></div>` +
    table(["Severity", "Category", "Project", "Issue", "Source"], list.map((i) => `<tr><td><span class="sev ${esc(i.severity)}">${esc(i.severity)}</span></td><td>${esc(i.category)}</td><td><b>${esc(i.project)}</b></td>
      <td class="wrap">${esc(i.title)}${i.detail ? `<div class="small muted">${esc(i.detail)}</div>` : ""}</td><td class="small muted mono">${esc(i.source)}</td></tr>`), "Nothing found.");
}

function renderInfra() {
  const list = state.tabs.infra;
  if (!list) return ($("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading infrastructure</div>`);
  $("canvas").innerHTML = `<div class="filters"><span class="muted">Warnings from hosts, domains, images and CI actions.</span><span class="count">${list.length} warnings</span></div>` +
    table(["Project", "Kind", "Value", "Warning", "Source"], list.map((i) => `<tr><td><b>${esc(i.project)}</b></td><td>${esc(i.kind)}</td><td class="mono">${esc(i.value)}</td><td class="wrap">${esc(i.warning)}</td><td class="small muted mono">${esc(i.source)}</td></tr>`), "No warnings.");
}

function renderCanvas() {
  ({ projects: renderProjects, findings: renderFindings, audit: renderAudit, infra: renderInfra })[state.view]();
}

// ---------------------------------------------------------------- inspector: Check → Fix

async function selectProject(name) {
  if (state.selected !== name) state.checkError = null;
  state.selected = name;
  state.detail = null;
  renderInspector();
  document.querySelectorAll("tr.row").forEach((r) => r.classList.toggle("on", r.dataset.project === name));
  try {
    const d = await api("/api/project?name=" + encodeURIComponent(name));
    if (state.selected === name) { state.detail = d; renderInspector(); }
  } catch (e) { state.checkError = e.message; renderInspector(); }
}

function closeInspector() {
  state.selected = null;
  state.detail = null;
  renderInspector();
  document.querySelectorAll("tr.row.on").forEach((r) => r.classList.remove("on"));
}

function pipelineHtml(job, wasChecked) {
  const pipe = ["check", ...(job?.pipeline ?? ["pull", "branch", "fix", "verify", "commit", "push", "pr"])];
  const reached = new Set(job?.reached ?? []);
  const lastIdx = Math.max(-1, ...[...reached].map((s) => pipe.indexOf(s)));
  return `<ol class="steps">${pipe.map((s, i) => {
    let cls = "";
    if (s === "check") cls = wasChecked || job ? "done" : "";
    else if (job && i <= lastIdx) cls = "done";
    if (job?.state === "running" && i === lastIdx + 1 && s !== "check") cls = "now";
    if (job?.state === "failed" && i === Math.max(lastIdx + 1, 1)) cls = "bad";
    return `<li class="${cls}">${STEP_LABEL[s]}</li>`;
  }).join("")}</ol>`;
}

function jobResultHtml(job) {
  if (!job.detail) return "";
  const { result: r, error, lines } = job.detail;
  let out = "";
  if (job.state === "failed") out += `<div class="errbox">${esc(error || "The fix failed.")}</div>`;
  if (r) {
    for (const p of r.prs ?? []) out += `<div class="okbox">PR opened into <span class="mono">${esc(p.base)}</span>: <a href="${safeUrl(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.url.replace("https://github.com/", ""))}</a>. Nothing merges without you.</div>`;
    if (r.fixed?.length) out += `<p class="note"><b>${r.fixed.length} fixed</b>${r.branch ? ` on <span class="mono">${esc(r.branch)}</span>` : ""}.</p>`;
    if (r.stillVulnerable?.length) out += `<p class="warn">Still vulnerable: ${esc(r.stillVulnerable.join(", "))}</p>`;
    if (r.failed?.length) out += `<p class="warn">Couldn't fix: ${esc([...new Set(r.failed.map((f) => f.fix.name))].join(", "))}</p>`;
    if (r.verifyFailedRepos?.length) out += `<p class="warn">Build or tests broke, so no PR was opened. The branch was kept for you to look at.</p>`;
    for (const n of r.noPr ?? []) out += `<p class="warn">No PR: ${esc(n)}</p>`;
    if (r.verify?.length) out += `<p class="note">${r.verify.map((v) => `${v.ok ? "✓" : v.preexisting ? "≈" : "✗"} ${esc(v.command)}${!v.ok && v.preexisting ? " (already failing before this)" : ""}`).join("<br>")}</p>`;
    const stuck = (r.skipped ?? []).filter((x) => x.human);
    if (stuck.length) out += `<div class="warn"><b>Can't be fixed from this repo yet:</b> ${stuck.map((x) => esc(x.fix.name)).filter((n, i, a) => a.indexOf(n) === i).join(", ")}. It's waiting on an upstream release, so nothing here is broken. If the risk is acceptable, record it: <span class="mono">mycelium accept &lt;package&gt; --project ${esc(job.project)} --reason "…"</span></div>`;
    else if (!r.fixed?.length && !r.failed?.length && !r.stillVulnerable?.length) out += `<p class="note">Nothing changed.</p>`;
  }
  if (lines?.length) out += `<details ${job.state === "running" ? "open" : ""}><summary>Log (${lines.length})</summary><pre class="log" id="joblog">${esc(lines.join("\n").replace(/\S*\/mycelium-(?:wt|base)-\w+(?:\/up)*\/repo\/?/g, "(temp copy)/"))}</pre></details>`;
  return out;
}

function renderInspector() {
  const el = $("inspector");
  el.hidden = !state.selected;
  $("workspace").classList.toggle("has-inspector", !!state.selected);
  if (!state.selected) return;
  const name = state.selected;
  const head = (sub) => `<div class="ihead"><div class="grow"><h2>${esc(name)}</h2>${sub}</div><button class="iclose" id="iclose" aria-label="Close details">×</button></div>`;
  const d = state.detail;
  if (!d) {
    el.innerHTML = head("") + (state.checkError ? `<div class="isec"><div class="errbox">${esc(state.checkError)}</div></div>` : `<div class="isec muted"><span class="spin"></span>Loading</div>`);
    $("iclose").onclick = closeInspector;
    return;
  }
  const p = d.project;
  const checked = state.checked.has(name);
  const job = state.job && state.job.project === name ? state.job : null;
  const running = state.job?.state === "running";
  const busy = state.data?.busy;
  const fixable = d.packages.filter((f) => f.kind !== "manual");

  // Remember ticks across re-renders while the job view refreshes.
  const prevTicks = new Map([...el.querySelectorAll("input[data-pkg]")].map((i) => [i.value, i.checked]));
  const tick = (f) => (prevTicks.has(f.name) ? prevTicks.get(f.name) : f.kind === "auto");

  const git = d.git;
  const hasGithub = !!git?.onGithub;
  const gitNote = git ? `${git.branch ? `<span class="mono">${esc(git.branch)}</span>` : `${git.repos} repos`}${git.uncommitted ? ` · ${git.uncommitted} uncommitted` : ""}` : "not in git";

  let checkSec;
  if (state.checking) checkSec = `<p class="muted"><span class="spin"></span>Re-reading lockfiles and asking OSV. Your repo isn't touched.</p>`;
  else if (state.checkError) checkSec = `<div class="errbox">${esc(state.checkError)}</div><button class="btn wide mt8" id="check">Try again</button>`;
  else checkSec = `<button class="btn wide ${checked ? "" : "primary"}" id="check" ${busy ? "disabled" : ""}>${checked ? "Check again" : "Check for vulnerabilities"}</button>
    <p class="note">Read-only: nothing in your repo changes.</p>`;

  let matchSec = "";
  if (checked && !state.checking) {
    matchSec = d.packages.length
      ? `<div class="isec"><h3>Matches · ${d.packages.length} package${d.packages.length > 1 ? "s" : ""}</h3>
          ${d.packages.map((f) => `<label class="pkg"><input type="checkbox" data-pkg data-kind="${f.kind}" value="${esc(f.name)}" ${tick(f) && f.kind !== "manual" ? "checked" : ""} ${f.kind === "manual" || running ? "disabled" : ""}>
            <div class="pb"><div class="pt"><span class="tag ${f.kind}">${f.kind}</span><span class="sev ${f.severity}">${f.severity}</span><b>${esc(f.name)}</b></div>
            <div class="small"><span class="mono">${esc(f.from)} → ${esc(f.to ?? "no fix yet")}</span> <span class="muted">· ${f.vulns.length} advisor${f.vulns.length > 1 ? "ies" : "y"}${f.lockfiles.length > 1 ? ` · ${f.lockfiles.length} lockfiles` : ""}</span></div>
            ${f.note ? `<div class="small muted">${esc(f.note)}</div>` : ""}
            ${f.downgrade ? `<div class="hint"><b>Possible older version: ${esc(f.downgrade.version)}</b>. The advisory says this began in ${esc(f.downgrade.introduced)}. ${esc(f.downgrade.note)}</div>` : ""}</div></label>`).join("")}</div>`
      : `<div class="isec"><div class="okbox">No open matches.${d.acceptances.length ? " The accepted items below are still tracked." : ""}</div></div>`;
  }

  let fixSec = "";
  if (checked && fixable.length && !state.checking) {
    fixSec = `<div class="isec"><h3>Fix</h3>
      <div class="opts">
        <label><input type="checkbox" id="optVerify" ${state.optVerify === false ? "" : "checked"} ${running ? "disabled" : ""}> Build &amp; test</label>
        ${hasGithub ? `<label><input type="checkbox" id="optPr" ${state.optPr === false ? "" : "checked"} ${running ? "disabled" : ""}> Open a PR</label>` : ""}
      </div>
      <button class="btn primary wide" id="fix" ${running || busy ? "disabled" : ""}>${running ? "Working…" : "Fix selected on a new branch"}</button>
      <p class="note">${hasGithub
        ? "Runs in a throwaway copy from GitHub. Your folder and uncommitted work aren't touched, and nothing merges without you."
        : "This repo isn't on GitHub, so the fix lands on a local branch with no PR. Your folder and uncommitted work aren't touched."}</p>
      ${!git ? `<p class="warn">This folder isn't in git, so fixes can't be applied.</p>` : ""}</div>`;
  } else if (!checked && !state.checking) {
    fixSec = `<div class="isec"><p class="note">Run a check first. Fixing unlocks when it finds something fixable.</p></div>`;
  }

  const prs = p.prs.length ? `<div class="isec"><h3>Pull requests</h3>${p.prs.map((s) => `<div class="small mb4"><a href="${safeUrl(s.url)}" target="_blank" rel="noopener noreferrer">#${s.number}</a> ${s.needsPull ? (s.ready ? "merged, ready to pull" : `merged · can't pull: ${esc(s.reason || "")}`) : "open"}</div>`).join("")}
      ${p.prs.some((s) => s.needsPull && s.ready) ? `<button class="btn small" id="pull" ${busy ? "disabled" : ""}>Pull merged fixes &amp; rescan</button>` : ""}</div>` : "";

  const acc = d.acceptances.length ? `<div class="isec"><h3>Accepted · ${d.acceptances.length}</h3>${d.acceptances.map((a) => `<div class="acc"><b>${esc(a.name)}</b> <span class="small ${a.expired ? "" : "muted"}">${a.expired ? "expired" : "until"} ${esc(a.expires.slice(0, 10))}</span><div class="small muted">${esc(a.reason)}</div></div>`).join("")}</div>` : "";

  const logOpen = el.querySelector("details[open]") !== null;
  const scroll = el.scrollTop;
  el.innerHTML = head(`<div class="small muted">${esc(p.exposure)} · ${p.packages.toLocaleString()} packages · ${gitNote}</div>`) +
    `<div class="isec">${pipelineHtml(job, checked)}</div>` +
    `<div class="isec">${checkSec}</div>` + matchSec + fixSec +
    (job ? `<div class="isec" aria-live="polite"><h3>${job.state === "running" ? '<span class="spin"></span>Running' : job.state === "failed" ? "Failed" : job.detail?.result?.fixed?.length ? "Finished" : "Finished: nothing fixed"}</h3>${jobResultHtml(job)}</div>` : "") +
    prs + acc;
  el.scrollTop = scroll;
  if (logOpen) el.querySelector("details")?.setAttribute("open", "");
  const log = $("joblog");
  if (log) log.scrollTop = log.scrollHeight;

  $("iclose").onclick = closeInspector;
  const checkBtn = $("check");
  if (checkBtn) checkBtn.onclick = runCheck;
  const fixBtn = $("fix");
  if (fixBtn) fixBtn.onclick = runFix;
  const pullBtn = $("pull");
  if (pullBtn) pullBtn.onclick = runPull;
  const v = $("optVerify"), pr = $("optPr");
  if (v) v.onchange = () => (state.optVerify = v.checked);
  if (pr) pr.onchange = () => (state.optPr = pr.checked);
  el.querySelectorAll("input[data-pkg]").forEach((i) => (i.onchange = updateFixButton));
  updateFixButton();
}

function updateFixButton() {
  const fixBtn = $("fix");
  if (!fixBtn || state.job?.state === "running" || state.data?.busy) return;
  fixBtn.disabled = !$("inspector").querySelector("input[data-pkg]:checked") || !state.detail?.git;
}

async function runCheck() {
  const name = state.selected;
  state.checking = true; state.checkError = null;
  renderInspector();
  try {
    const d = await api("/api/check", { project: name });
    state.checked.add(name);
    if (state.selected === name) state.detail = d;
    await refresh();
  } catch (e) { state.checkError = e.message; }
  state.checking = false;
  renderInspector();
}

async function runFix() {
  const boxes = [...$("inspector").querySelectorAll("input[data-pkg]:checked")];
  if (!boxes.length) return;
  try {
    const job = await api("/api/fix", {
      project: state.selected,
      only: [...new Set(boxes.map((b) => b.value))],
      allowMajor: boxes.some((b) => b.dataset.kind === "major"),
      verify: state.optVerify !== false,
      pr: state.optPr !== false && !!state.detail?.git?.onGithub,
    });
    state.job = { ...job, detail: null };
    renderInspector();
    $("inspector").scrollTop = 0; // the pipeline is at the top
    pollJob();
  } catch (e) { banner(e.message, true); }
}

async function pollJob() {
  try {
    const j = await api("/api/job");
    if (!j) return;
    state.job = { ...j, detail: j };
    if (j.project === state.selected) renderInspector();
    if (j.state === "running") return void setTimeout(pollJob, 1200);
    state.tabs = {};
    await refresh();
    if (j.project === state.selected) {
      state.detail = await api("/api/project?name=" + encodeURIComponent(j.project));
      renderInspector();
    }
  } catch (e) { banner(`Lost track of the fix: ${e.message}`, true); setTimeout(pollJob, 4000); }
}

async function runPull() {
  try {
    const r = await api("/api/pull", { project: state.selected });
    banner(r.pulled.length ? `Pulled ${r.pulled.join(", ")}.` : `Nothing pulled${r.refused.length ? `: ${r.refused.join("; ")}` : "."}`, !r.pulled.length);
    state.tabs = {};
    await refresh();
    await selectProject(state.selected);
  } catch (e) { banner(e.message, true); }
}

// ---------------------------------------------------------------- data + shell

async function refresh() {
  state.data = await api("/api/overview");
  renderAll();
}

function renderAll() {
  renderTop();
  renderStats();
  const q = document.activeElement?.id === "q";
  renderCanvas();
  if (q) $("q")?.focus();
}

$("views").addEventListener("click", (e) => {
  const v = e.target.dataset.view;
  if (!v) return;
  state.view = v;
  loadTab();
  renderAll();
});

$("rescan").onclick = async () => {
  const b = $("rescan");
  b.disabled = true; b.textContent = "Rescanning…";
  try {
    await api("/api/refresh", {});
    state.tabs = {};
    await refresh();
    banner("Rescan finished.");
    setTimeout(() => banner(""), 4000);
  } catch (e) { banner(e.message, true); }
  b.textContent = "Rescan all";
  b.disabled = !!state.data?.busy;
};

function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
applyTheme(store.get("theme", null));
$("theme").onclick = () => {
  const dark = document.documentElement.dataset.theme ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  store.set("theme", next);
};

document.addEventListener("keydown", (e) => { if (e.key === "Escape" && state.selected) closeInspector(); });

(async () => {
  $("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading your projects</div>`;
  try {
    await refresh();
    const j = await api("/api/job");
    if (j) {
      state.job = { ...j, detail: j };
      if (j.state === "running") { pollJob(); }
    }
  } catch (e) {
    banner(`Couldn't load the dashboard: ${e.message}`, true);
    $("canvas").innerHTML = `<div class="empty">Couldn't load your projects.</div>`;
  }
})();
