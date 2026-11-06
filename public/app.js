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
  tabs: {}, // lazily loaded findings / fixed / audit / infra / repos / alerts
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
  fixedState: "all",
  fixedQ: "",
  repoQ: "",
  repoOwner: "all",
  repoDraft: null, // the user's unsaved changes: { add, remove, auto } sets. Never a copy of the list, which can change underneath it.
  repoTab: null, // watching / available / problems; null picks one from what's there
  repoJob: null,
  alertDraft: null,
  alertMsg: null,
  reviewFilter: "all",
  reviewMsg: null,
  reviewOpen: new Set(), // which reviews are expanded: the page re-renders while work is running
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
  const days = Math.round(m / 1440);
  if (days < 60) return `${days} d ago`;
  if (days < 730) return `${Math.round(days / 30)} mo ago`;
  return `${Math.round(days / 365)} yr ago`;
};

// ---------------------------------------------------------------- top + stats

function renderTop() {
  const d = state.data;
  $("checked").textContent = `Checked ${ago(d.lastChecked)}`;
  $("user").innerHTML = `<button class="profilebtn ${state.view === "profile" ? "on" : ""}" id="profileBtn" title="Your profile">${d.signIn ? esc(d.user) : "This computer only"}</button>`;
  $("profileBtn").onclick = () => { state.view = "profile"; loadTab(); renderAll(); };
  $("company").textContent = d.company ? `· ${d.company}` : "";
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
  if (!all.length) {
    $("canvas").innerHTML = `<div class="welcome"><h2>Welcome to Mycelium</h2>
      <p class="muted">Mycelium watches your dependencies for known vulnerabilities and opens pull requests to fix them. Nothing merges without you.</p>
      <ol><li>Choose the repos to watch.</li><li>Mycelium scans them and shows what needs attention.</li><li>Get an email when something urgent appears.</li></ol>
      <button class="btn primary big" id="start">Choose your repos</button></div>`;
    $("start").onclick = () => { state.view = "repos"; loadTab(); renderAll(); };
    return;
  }
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

const day = (iso) => (iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "–");

function renderFixed() {
  const list = state.tabs.fixed;
  if (!list) return ($("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading fixes</div>`);
  const q = state.fixedQ.trim().toLowerCase();
  const shown = list.filter((f) => {
    if (state.fixedState !== "all" && f.state !== state.fixedState) return false;
    return !q || `${f.name ?? f.title} ${f.project} ${f.repo} ${f.severity ?? ""} ${f.advisories.map((a) => a.id).join(" ")}`.toLowerCase().includes(q);
  });
  const prCount = new Set(shown.map((f) => f.url)).size;
  const projectCount = new Set(shown.map((f) => f.project)).size;
  const known = new Set(state.data.projects.map((p) => p.name));
  const chips = [["all", "All", list.length], ["MERGED", "Merged", list.filter((f) => f.state === "MERGED").length], ["OPEN", "Awaiting merge", list.filter((f) => f.state === "OPEN").length]];
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  $("canvas").innerHTML = `<div class="filters">
      <input class="field" id="fq" type="search" placeholder="Search fixes" aria-label="Search fixes" value="${esc(state.fixedQ)}">
      <div class="chips" role="group" aria-label="Filter by PR state">${chips.map(([id, label, c]) => `<button data-fstate="${id}" class="${state.fixedState === id ? "on" : ""}">${label}<i>${c}</i></button>`).join("")}</div>
      <span class="count">${plural(shown.filter((f) => f.name).length, "upgrade")} · ${plural(prCount, "PR")} · ${plural(projectCount, "project")}</span></div>` +
    table(["Date", "Severity", "Package", "Advisories", "Project", "PR"], shown.map((f) => `<tr>
      <td class="small muted">${day(f.at)}</td>
      <td>${f.severity ? `<span class="sev ${esc(f.severity)}">${esc(f.severity)}</span>` : '<span class="muted">–</span>'}</td>
      <td>${f.name ? `<b>${esc(f.name)}</b> <span class="mono muted">${esc(f.from)} → ${esc(f.to ?? "removed")}</span>${f.major ? ' <span class="tag major">major</span>' : ""}<div class="small muted">${f.lockfiles.length === 1 ? esc(f.lockfiles[0]) : `${f.lockfiles.length} lockfiles`}</div>` : `${esc(f.title)}<div class="small muted">No package list in this PR's description</div>`}</td>
      <td class="small">${f.advisories.map((a) => `<a href="${safeUrl(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.id)}</a>`).join("<br>") || '<span class="muted">–</span>'}${f.moreAdvisories ? `<div class="muted">+${f.moreAdvisories} more</div>` : ""}</td>
      <td>${known.has(f.project) ? `<button class="btn small" data-goto="${esc(f.project)}">${esc(f.project)}</button>` : esc(f.project)}</td>
      <td class="small"><a href="${safeUrl(f.url)}" target="_blank" rel="noopener noreferrer">${esc(f.repo.split("/")[1])}#${f.number}</a>${f.state === "OPEN" ? '<div class="muted">awaiting merge</div>' : ""}</td></tr>`),
    list.length ? "No fixes match these filters." : "No fixes recorded yet. <b>Rescan all</b> reads your Mycelium PRs from GitHub.");
  const fq = $("fq");
  fq.oninput = () => {
    state.fixedQ = fq.value;
    const pos = fq.selectionStart;
    renderFixed();
    const again = $("fq"); again.focus(); again.setSelectionRange(pos, pos);
  };
  document.querySelectorAll("[data-fstate]").forEach((b) => (b.onclick = () => { state.fixedState = b.dataset.fstate; renderFixed(); }));
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

// ---------------------------------------------------------------- repos

const JOB_STEP = { fetching: "Getting the code", scanning: "Reading dependencies", checking: "Checking for vulnerabilities", finished: "Finished" };

function repoJobHtml() {
  const j = state.repoJob;
  if (!j || j.state !== "running") return "";
  const fetching = j.step === "fetching";
  return `<div class="jobbox" role="status" aria-live="polite">
    <div><span class="spin"></span><b>${JOB_STEP[j.step]}</b> <span class="muted">${fetching ? `${j.finished} of ${j.total}` : ""}${fetching && j.current.length ? ` · ${esc(j.current.join(", "))}` : ""}</span></div>
    <progress class="bar" max="${j.total}" value="${fetching ? j.finished : j.total}" aria-label="Import progress"></progress>
    <div class="small muted">This keeps going if you leave this page.</div></div>`;
}

async function pollRepoJob() {
  try {
    const j = await api("/api/repos/job");
    state.repoJob = j;
    if (j?.state === "running") {
      const el = $("rjob");
      if (el) el.innerHTML = repoJobHtml();
      return void setTimeout(pollRepoJob, 1200);
    }
    if (j) {
      const failed = j.failed.length ? `${j.failed.length} couldn't be updated: see Problems.` : "";
      const what = j.kind === "import" ? `Imported ${j.total - j.failed.length} of ${j.total}.` : "Scan finished.";
      if (j.state === "failed") banner(`That didn't finish: ${j.error}`, true);
      else banner([what, failed, ...j.warnings].filter(Boolean).join(" "), !!(failed || j.warnings.length));
      if (j.failed.length) state.repoTab = "problems";
    }
    state.tabs = {};
    await refresh();
  } catch (e) { banner(`Lost track of the import: ${e.message}`, true); setTimeout(pollRepoJob, 4000); }
}

function renderRepos() {
  const d = state.tabs.repos;
  if (!d) return ($("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading your repos from GitHub</div>`);
  if (!d.managed) {
    $("canvas").innerHTML = `<div class="page"><h2>Repos</h2><p class="muted">This install scans folders on this computer, so repos are whatever's in them. To change that, run <span class="mono">mycelium scan &lt;folders&gt;</span>.</p>
      ${d.roots.length ? `<ul class="plain mono">${d.roots.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}</div>`;
    return;
  }
  const watchedNow = new Set(d.watched.map((w) => w.slug));
  if (!state.repoDraft) state.repoDraft = { add: new Set(), remove: new Set(), auto: new Set(d.autoOwners) };
  const draft = state.repoDraft;
  const isOn = (s) => draft.add.has(s) || (watchedNow.has(s) && !draft.remove.has(s));
  const setOn = (s, on) => {
    draft.add.delete(s); draft.remove.delete(s);
    if (on && !watchedNow.has(s)) draft.add.add(s);
    if (!on && watchedNow.has(s)) draft.remove.add(s);
  };
  const running = state.repoJob?.state === "running";
  const projects = new Map(state.data.projects.map((p) => [p.name, p]));
  const projectOf = new Map(d.watched.map((w) => [w.slug, w.project]));
  // Watched repos GitHub no longer shows (deleted, or access lost) stay listed, or they could never be removed.
  const hidden = new Set(d.hiddenAccounts);
  const rows = [...d.available.filter((r) => watchedNow.has(r.slug) || (!r.archived && !hidden.has(r.owner))),
    ...d.watched.filter((w) => !d.available.some((r) => r.slug === w.slug)).map((w) => ({ slug: w.slug, owner: w.slug.split("/")[0], missing: true, description: "" }))];
  const problem = (r) => d.issues[r.slug] || r.missing;
  const problems = rows.filter((r) => watchedNow.has(r.slug) && problem(r));
  const repoCount = (o) => d.available.filter((r) => r.owner === o).length;
  const allOwners = [...new Set(d.available.map((r) => r.owner))].sort((a, b) => repoCount(b) - repoCount(a) || a.localeCompare(b));
  const owners = allOwners.filter((o) => !hidden.has(o));
  if (hidden.has(state.repoOwner)) state.repoOwner = "all";
  // Open on what's useful: your watched repos, or the picker when there aren't any yet.
  const tab = state.repoTab ?? (watchedNow.size ? "watching" : "available");
  const inTab = { watching: (r) => watchedNow.has(r.slug), available: (r) => !watchedNow.has(r.slug), problems: (r) => watchedNow.has(r.slug) && problem(r) };
  const q = state.repoQ.trim().toLowerCase();
  const shown = rows.filter((r) => inTab[tab](r) && (state.repoOwner === "all" || r.owner === state.repoOwner) && (!q || `${r.slug} ${r.description}`.toLowerCase().includes(q)))
    // Most recently active first: what someone's likely looking for isn't a ten-year-old fork.
    .sort((a, b) => Date.parse(b.pushedAt || 0) - Date.parse(a.pushedAt || 0) || a.slug.localeCompare(b.slug));
  const add = [...draft.add].filter((s) => !watchedNow.has(s));
  const remove = [...draft.remove].filter((s) => watchedNow.has(s));
  const autoChanged = owners.some((o) => draft.auto.has(o) !== d.autoOwners.includes(o));
  const dirty = add.length || remove.length || autoChanged;
  const statusOfRepo = (r) => {
    if (!watchedNow.has(r.slug)) return '<span class="muted">Not watched</span>';
    const p = projects.get(projectOf.get(r.slug));
    if (!p) return '<span class="muted">No dependencies found</span>';
    return p.open ? `<button class="linkish" data-goto="${esc(p.name)}"><span class="counts">${counts(p.bySeverity)}</span></button>` : `<button class="linkish" data-goto="${esc(p.name)}"><span class="pill clean"><span class="dot"></span>Clean</span></button>`;
  };
  const scanned = (r) => {
    const p = projects.get(projectOf.get(r.slug));
    return watchedNow.has(r.slug) && p ? `<div class="small muted">Scanned ${ago(p.scannedAt)}</div>` : "";
  };
  const issueLine = (r) => (d.issues[r.slug] && watchedNow.has(r.slug) ? `<div class="small warn-text">Couldn't update ${esc(ago(d.issues[r.slug].at))}: ${esc(d.issues[r.slug].error)}</div>` : "");
  const repoWord = (n) => `${n} repo${n === 1 ? "" : "s"}`;
  const saveLabel = [add.length && `import ${repoWord(add.length)}`, remove.length && `stop watching ${repoWord(remove.length)}`].filter(Boolean).join(", ");
  const tabs = [["watching", "Watching", watchedNow.size], ["available", "Not watching", rows.length - rows.filter((r) => watchedNow.has(r.slug)).length], ["problems", "Problems", problems.length]];
  const tip = { watching: "These are checked every night and whenever you rescan. Untick one to stop watching it; its fix history stays.", available: "Tick the repos to import. Only repos this GitHub account can push to are listed, since Mycelium fixes through pull requests.", problems: "Mycelium couldn't update these, so their results may be out of date." }[tab];
  const empty = { watching: "You aren't watching any repos yet.", available: "Nothing else to import.", problems: "No problems." }[tab];

  $("canvas").innerHTML = `${d.error ? `<div class="errbox m12">${esc(d.error)}</div>` : ""}
    <div id="rjob">${repoJobHtml()}</div>
    <div class="filters">
      <div class="chips" role="group" aria-label="Which repos">${tabs.map(([id, label, c]) => `<button data-rtab="${id}" class="${tab === id ? "on" : ""}">${label}<i>${c}</i></button>`).join("")}</div>
      <input class="field" id="rq" type="search" placeholder="Search repos" aria-label="Search repos" value="${esc(state.repoQ)}">
      <select class="field" id="rowner" aria-label="Filter by GitHub account"><option value="all">All accounts</option>${owners.map((o) => `<option value="${esc(o)}" ${state.repoOwner === o ? "selected" : ""}>${esc(o)} (${repoCount(o)})</option>`).join("")}</select>
      ${state.repoOwner !== "all" ? `<button class="btn small" id="rhide" title="Leave this account out of this list">Hide this account</button>` : ""}
      ${tab === "available" ? `<button class="btn small" id="rselect" title="Tick every repo shown here">Select shown</button><button class="btn small" id="rclear" title="Untick every repo shown here">Clear shown</button>` : ""}
      ${tab === "problems" && problems.length ? `<button class="btn small" id="rretry" ${running || state.data.busy ? "disabled" : ""}>Retry all</button>` : ""}
      <span class="count">${shown.length} shown</span></div>
    <div class="savebar ${dirty ? "on" : ""}" role="status">
      ${dirty ? `<span>${saveLabel ? esc(saveLabel[0].toUpperCase() + saveLabel.slice(1)) : "Change automatic watching"}.</span>
          <span class="grow"></span><button class="btn small" id="rcancel">Cancel</button><button class="btn small primary" id="rsave" ${running || state.data.busy ? "disabled" : ""}>${add.length ? "Import" : "Save"}</button>`
        : `<span class="muted">${tip}</span>`}
    </div>` +
    table(["", "Repository", "Last push", "Status", ""], shown.map((r) => `<tr>
      <td class="tick"><input type="checkbox" data-repo="${esc(r.slug)}" aria-label="Watch ${esc(r.slug)}" ${isOn(r.slug) ? "checked" : ""}></td>
      <td class="wrap"><b>${esc(r.slug)}</b>${r.private ? ' <span class="tag try">private</span>' : ""}${r.fork ? ' <span class="tag try">fork</span>' : ""}${r.archived ? ' <span class="tag try">archived</span>' : ""}
        ${r.missing ? `<div class="small warn-text">GitHub no longer shows this repo to this account</div>` : r.description ? `<div class="small muted">${esc(r.description)}</div>` : ""}${issueLine(r)}</td>
      <td class="small muted nowrap">${r.pushedAt ? ago(r.pushedAt) : "–"}</td>
      <td class="nowrap">${statusOfRepo(r)}${scanned(r)}</td>
      <td class="right nowrap">${watchedNow.has(r.slug) ? `<button class="btn small" data-scan="${esc(r.slug)}" ${running || state.data.busy ? "disabled" : ""}>${d.issues[r.slug] ? "Retry" : "Scan now"}</button>` : ""}</td></tr>`), d.error ? "No repos to show." : q || state.repoOwner !== "all" ? "No repos match these filters." : empty) +
    `<details class="page border-top" ${state.repoPasteOpen ? "open" : ""} id="rpaste"><summary><b>Paste a list of repos</b></summary>
      <p class="small muted">GitHub URLs or owner/name, one per line. They're ticked for you to review before anything is imported.</p>
      <textarea class="field area" id="rtext" rows="4" placeholder="acme/storefront&#10;https://github.com/acme/api" aria-label="Repos to import">${esc(state.repoPaste || "")}</textarea>
      <div class="actions"><button class="btn small" id="rparse">Add to selection</button></div></details>` +
    (owners.length ? `<details class="page border-top" ${state.repoAutoOpen ? "open" : ""} id="rautod"><summary><b>Watch new repos automatically</b>${draft.auto.size ? ` <span class="muted">· ${draft.auto.size} account${draft.auto.size === 1 ? "" : "s"}</span>` : ""}</summary>
      <p class="small muted">New repos from these accounts are added at the next rescan or nightly check. Repos you've unticked stay unticked.</p>
      <div class="opts">${owners.map((o) => `<label><input type="checkbox" data-auto="${esc(o)}" ${draft.auto.has(o) ? "checked" : ""}> ${esc(o)}</label>`).join("")}</div></details>` : "") +
    (allOwners.length ? `<details class="page border-top" ${state.repoHideOpen ? "open" : ""} id="rhided"><summary><b>Hide accounts</b>${hidden.size ? ` <span class="muted">· ${hidden.size} hidden</span>` : ""}</summary>
      <p class="small muted">Hidden accounts aren't offered for import or automatic watching. Repos you already watch from them stay watched until you untick them.</p>
      <div class="opts">${allOwners.map((o) => `<label><input type="checkbox" data-hide="${esc(o)}" ${hidden.has(o) ? "checked" : ""}> ${esc(o)} <span class="muted">(${repoCount(o)})</span></label>`).join("")}</div></details>` : "");

  const rq = $("rq");
  rq.oninput = () => {
    state.repoQ = rq.value;
    const pos = rq.selectionStart;
    renderRepos();
    const again = $("rq"); again.focus(); again.setSelectionRange(pos, pos);
  };
  $("rowner").onchange = (e) => { state.repoOwner = e.target.value; renderRepos(); };
  document.querySelectorAll("[data-rtab]").forEach((b) => (b.onclick = () => { state.repoTab = b.dataset.rtab; renderRepos(); }));
  const sel = $("rselect"), clr = $("rclear");
  if (sel) sel.onclick = () => { shown.forEach((r) => setOn(r.slug, true)); renderRepos(); };
  if (clr) clr.onclick = () => { shown.forEach((r) => setOn(r.slug, false)); renderRepos(); };
  document.querySelectorAll("[data-repo]").forEach((c) => (c.onchange = () => { setOn(c.dataset.repo, c.checked); renderRepos(); }));
  document.querySelectorAll("[data-auto]").forEach((c) => (c.onchange = () => { c.checked ? draft.auto.add(c.dataset.auto) : draft.auto.delete(c.dataset.auto); renderRepos(); }));
  document.querySelectorAll("[data-goto]").forEach((b) => (b.onclick = () => { state.view = "projects"; selectProject(b.dataset.goto); renderAll(); }));
  $("rpaste").ontoggle = (e) => { state.repoPasteOpen = e.target.open; };
  const setHidden = async (next, message) => {
    try {
      const out = await api("/api/repos/hidden", { accounts: [...next] });
      d.hiddenAccounts = out.hiddenAccounts;
      d.autoOwners = out.autoOwners;
      // Unsaved ticks for repos that just went out of sight would otherwise be imported unseen.
      for (const s of [...draft.add]) if (out.hiddenAccounts.includes(s.split("/")[0])) draft.add.delete(s);
      for (const o of out.hiddenAccounts) draft.auto.delete(o);
      banner(message);
    } catch (e) { banner(e.message, true); }
    renderRepos();
  };
  document.querySelectorAll("[data-hide]").forEach((c) => (c.onchange = () => {
    const next = new Set(hidden);
    c.checked ? next.add(c.dataset.hide) : next.delete(c.dataset.hide);
    setHidden(next, c.checked ? `Hid ${c.dataset.hide}.` : `${c.dataset.hide} is back in the list.`);
  }));
  const hideBtn = $("rhide");
  if (hideBtn) hideBtn.onclick = () => {
    const name = state.repoOwner;
    state.repoHideOpen = true;
    setHidden(new Set([...hidden, name]), `Hid ${name}. You can bring it back under Hide accounts, below the list.`);
  };
  const hided = $("rhided");
  if (hided) hided.ontoggle = (e) => { state.repoHideOpen = e.target.open; };
  const autod = $("rautod");
  if (autod) autod.ontoggle = (e) => { state.repoAutoOpen = e.target.open; };
  $("rtext").oninput = (e) => { state.repoPaste = e.target.value; };
  $("rparse").onclick = async () => {
    try {
      const r = await api("/api/repos/parse", { text: state.repoPaste || "" });
      r.add.forEach((s) => setOn(s, true));
      const parts = [r.add.length && `${r.add.length} ready to import`, r.already.length && `${r.already.length} already watched`, r.notVisible.length && `can't reach ${r.notVisible.join(", ")}`, r.invalid.length && `didn't understand ${r.invalid.join(", ")}`].filter(Boolean);
      // In the banner: this section sits below the list, which can be hundreds of rows long.
      banner(parts.join(" · ") || "Nothing to add.", !!(r.notVisible.length || r.invalid.length));
      window.scrollTo(0, 0);
      if (r.add.length) { state.repoPaste = ""; state.repoTab = "available"; state.repoOwner = "all"; state.repoQ = ""; }
    } catch (e) { banner(e.message, true); }
    renderRepos();
  };
  const startJob = async (path, payload) => {
    banner("");
    const job = await api(path, payload);
    state.repoDraft = null;
    state.repoPaste = "";
    if (job.state === "running") {
      state.repoJob = job;
      state.data.busy = "working";
      state.tabs.repos = await api("/api/repos"); // the new repos count as watched from here on
      renderRepos();
      pollRepoJob();
    } else {
      banner("Saved.");
      state.tabs = {};
      await refresh();
    }
  };
  document.querySelectorAll("[data-scan]").forEach((b) => (b.onclick = () => startJob("/api/repos/scan", { slugs: [b.dataset.scan] }).catch((e) => banner(e.message, true))));
  const retry = $("rretry");
  if (retry) retry.onclick = () => startJob("/api/repos/scan", { slugs: problems.filter((r) => !r.missing).map((r) => r.slug) }).catch((e) => banner(e.message, true));
  const cancel = $("rcancel");
  if (cancel) cancel.onclick = () => { state.repoDraft = null; renderRepos(); };
  const save = $("rsave");
  if (save) save.onclick = () => {
    if (add.length) state.repoTab = "watching";
    startJob("/api/repos", { add, remove, autoOwners: [...draft.auto] }).catch((e) => banner(e.message, true));
  };
}

// ---------------------------------------------------------------- profile

function renderProfile() {
  const d = state.tabs.profile;
  if (!d) return ($("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading your profile</div>`);
  const gh = d.github;
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const title = d.company || "Your company";
  const initial = (d.company || d.user || "M").trim()[0].toUpperCase();
  const tile = (go, value, label, cls = "") => `<button class="ptile" data-go="${go}"><b class="${cls}">${esc(value)}</b><span>${esc(label)}</span></button>`;
  const SHOWN = 6;
  $("canvas").innerHTML = `<div class="profile">
    <header class="phead">
      <div class="pavatar" aria-hidden="true">${esc(initial)}</div>
      <div class="pwho"><h2 class="${d.company ? "" : "muted"}">${esc(title)}</h2><p class="muted">${d.signIn ? esc(d.user) : "This computer only"}</p></div>
    </header>
    <div class="ptiles">
      ${d.install.managed ? tile("repos", d.install.watched, d.install.watched === 1 ? "repo watched" : "repos watched") : tile("repos", "Folders", "scanned on this computer")}
      ${tile("projects", d.install.projects, d.install.projects === 1 ? "project" : "projects")}
      ${tile("alerts", d.alerts.enabled ? "On" : "Off", d.alerts.enabled ? `alerts to ${plural(d.alerts.recipients.length, "recipient")}` : "email alerts", d.alerts.enabled ? "ok-text" : "")}
    </div>
    <div class="pgrid">
      <div class="pcol">
      <section class="pcard">
        <h3>Company</h3>
        <div class="pform"><input class="field" id="pCompany" maxlength="80" placeholder="Your company name" aria-label="Company name" value="${esc(state.profileDraft ?? d.company)}"><button class="btn" id="pSave">Save</button></div>
        ${state.profileMsg ? `<p class="small ${state.profileMsg.err ? "warn-text" : "ok-text"}" role="status">${esc(state.profileMsg.text)}</p>` : `<p class="small muted">Shown in the top bar and in the subject of alert emails.</p>`}
      </section>
      <section class="pcard">
        <h3>Your account</h3>
        ${d.signIn ? `<p class="pline"><span>Signed in as <b>${esc(d.user)}</b></span><a class="btn small" href="/auth/logout">Sign out</a></p>
          <p class="small muted">Can sign in here</p>
          <ul class="pchips">${d.allowedEmails.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
          <p class="small muted">This list is set when Mycelium is installed.</p>`
          : `<p>No sign-in is needed, because this install can only be reached from this computer.</p>`}
      </section>
      </div>
      <section class="pcard">
        <h3>GitHub connection</h3>
        ${gh.login ? `<div class="pidentity"><span class="pill clean"><span class="dot"></span>Connected</span><span><b>${esc(gh.login)}</b>${gh.name ? ` <span class="muted">${esc(gh.name)}</span>` : ""}</span></div>
          <p class="small muted">Mycelium reads repos and opens fix pull requests as this account, so PRs show its name.</p>
          ${gh.accounts.length ? `<ul class="prows">${gh.accounts.slice(0, SHOWN).map((a) => `<li><span>${esc(a.owner)}</span><span class="muted">${plural(a.repos, "repo")}</span></li>`).join("")}</ul>
            ${gh.accounts.length > SHOWN ? `<p class="small muted">and ${gh.accounts.length - SHOWN} more</p>` : ""}` : ""}`
          : `<div class="warn-box"><b>GitHub isn't connected.</b> On the machine running Mycelium, run <span class="mono">gh auth login</span>, then reload this page.</div>`}
      </section>
    </div>
  </div>`;
  $("pCompany").oninput = (e) => { state.profileDraft = e.target.value; };
  $("pSave").onclick = async () => {
    try {
      const out = await api("/api/profile", { company: $("pCompany").value });
      d.company = out.company; state.data.company = out.company; state.profileDraft = null;
      state.profileMsg = { text: "Saved." };
      renderTop();
    } catch (e) { state.profileMsg = { text: e.message, err: true }; }
    renderProfile();
  };
  document.querySelectorAll("[data-go]").forEach((b) => (b.onclick = () => { state.view = b.dataset.go; loadTab(); renderAll(); }));
}

// ---------------------------------------------------------------- alerts

function renderAlerts() {
  const d = state.tabs.alerts;
  if (!d) return ($("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading alerts</div>`);
  if (!state.alertDraft) state.alertDraft = { ...d.settings, recipients: d.settings.recipients.join("\n"), highOn: d.settings.highThreshold > 0, highN: d.settings.highThreshold || 3 };
  const a = state.alertDraft;
  const on = d.settings.enabled;
  const st = d.status;
  const waiting = d.waiting.critical + d.waiting.high;
  $("canvas").innerHTML = `<div class="profile">
    <button class="backlink" id="aBack">← Profile</button>
    <header class="phead">
      <div class="pavatar" aria-hidden="true">✉</div>
      <div class="pwho"><h2>Email alerts</h2><p class="muted">Get an email when something urgent shows up, so nobody has to keep checking this page.</p></div>
    </header>
    ${d.configured ? "" : `<div class="warn-box"><b>Email isn't set up on this server yet.</b> Add <span class="mono">RESEND_API_KEY</span> and <span class="mono">MYCELIUM_EMAIL_FROM</span> to Mycelium's environment, then restart it.</div>`}
    ${st.lastError ? `<div class="errbox">The last email failed ${esc(ago(st.lastErrorAt))}: ${esc(st.lastError)} The next check tries again.</div>` : ""}
    <div class="ptiles">
      <div class="ptile static"><b class="${on ? "ok-text" : ""}">${on ? "On" : "Off"}</b><span>${on ? `to ${d.settings.recipients.length} recipient${d.settings.recipients.length === 1 ? "" : "s"}` : "email alerts"}</span></div>
      <button class="ptile" id="aWaiting"><b>${waiting}</b><span>${d.waiting.critical} critical, ${d.waiting.high} high not emailed</span></button>
      <div class="ptile static"><b>${st.lastSentAt ? esc(ago(st.lastSentAt)) : "None yet"}</b><span>${st.lastSentAt ? `last email, about ${st.lastCount} finding${st.lastCount === 1 ? "" : "s"}` : "last email"}</span></div>
    </div>
    <div class="pgrid">
      <section class="pcard">
        <h3>Send to</h3>
        <label class="row"><input type="checkbox" id="aOn" ${a.enabled ? "checked" : ""} ${d.configured ? "" : "disabled"}> <b>Send email alerts</b></label>
        <textarea class="field area" id="aTo" rows="3" placeholder="security@yourcompany.com" aria-label="Email addresses, one per line">${esc(a.recipients)}</textarea>
        <p class="small muted">One address per line.${d.from ? ` Sent from ${esc(d.from)}.` : ""}</p>
        ${!on && waiting ? `<p class="small muted">Turning alerts on treats what's open now as already known, so you're only emailed about what's new.</p>` : ""}
      </section>
      <section class="pcard">
        <h3>Send when</h3>
        <label class="row"><input type="checkbox" id="aCrit" ${a.critical ? "checked" : ""}> <span>A new <span class="sev CRITICAL">critical</span> appears</span></label>
        <label class="row"><input type="checkbox" id="aHigh" ${a.highOn ? "checked" : ""}> <span><input class="field num-in" id="aN" type="number" min="1" max="1000" value="${esc(a.highN)}" aria-label="Number of new highs" ${a.highOn ? "" : "disabled"}> or more new <span class="sev HIGH">high</span> are waiting</span></label>
        <p class="small muted">Highs below that number keep counting until they reach it. A malicious package always counts as critical. You get one email per check, and accepted risks are left out.</p>
      </section>
    </div>
    <div class="actions"><button class="btn primary" id="aSave">Save</button><button class="btn" id="aTest" ${d.configured ? "" : "disabled"}>Send a test email</button>${state.alertMsg ? `<span class="small ${state.alertMsg.err ? "warn-text" : "ok-text"}" role="status">${esc(state.alertMsg.text)}</span>` : ""}</div>
  </div>`;
  $("aBack").onclick = () => { state.view = "profile"; loadTab(); renderAll(); };
  $("aWaiting").onclick = () => { state.view = "findings"; state.sevFilter = "ALL"; loadTab(); renderAll(); };
  const read = () => { a.enabled = $("aOn").checked; a.recipients = $("aTo").value; a.critical = $("aCrit").checked; a.highOn = $("aHigh").checked; a.highN = $("aN").value; };
  const addresses = () => a.recipients.split(/[\s,;]+/).filter(Boolean);
  ["aOn", "aCrit"].forEach((id) => ($(id).onchange = read));
  $("aTo").oninput = read;
  $("aN").oninput = read;
  $("aHigh").onchange = () => { read(); $("aN").disabled = !a.highOn; };
  $("aSave").onclick = async () => {
    read();
    try {
      const out = await api("/api/alerts", { enabled: a.enabled, recipients: addresses(), critical: a.critical, highThreshold: a.highOn ? Number(a.highN) : 0 });
      state.tabs.alerts = out.view; state.alertDraft = null;
      state.alertMsg = { text: out.baselined ? `Alerts on. ${out.baselined} open findings count as already known.` : "Saved." };
    } catch (e) { state.alertMsg = { text: e.message, err: true }; }
    renderAlerts();
  };
  $("aTest").onclick = async () => {
    read();
    try {
      await api("/api/alerts/test", { recipients: addresses() });
      state.alertMsg = { text: `Test sent to ${addresses().join(", ")}.` };
    } catch (e) { state.alertMsg = { text: e.message, err: true }; }
    renderAlerts();
  };
}

// ---------------------------------------------------------------- PR reviews

const REVIEW_STATE = { passed: ["Ready to merge", "ok"], sent_back: ["Sent back", "bad"], queued: ["Waiting", "wait"], running: ["Reviewing", "wait"], error: ["Couldn't review", "warn"], skipped: ["Not reviewed", "off"] };
const FINDING_SEV = { critical: "CRITICAL", high: "HIGH", medium: "MODERATE", low: "LOW" };

function renderReviews() {
  const d = state.tabs.reviews;
  if (!d) return ($("canvas").innerHTML = `<div class="empty"><span class="spin"></span>Loading reviews</div>`);
  const on = d.settings.enabled;
  const t = d.totals;
  const money = (n) => (n > 0 && n < 0.01 ? "under $0.01" : `$${n.toFixed(2)}`);
  const matches = (r) => state.reviewFilter === "all" || r.state === state.reviewFilter || (state.reviewFilter === "queued" && r.state === "running");
  const chips = [["all", "All", d.reviews.length], ["sent_back", "Sent back", t.sentBack], ["passed", "Ready to merge", t.passed], ["queued", "Waiting", t.waiting], ["error", "Couldn't review", d.reviews.filter((r) => r.state === "error").length]];
  const shown = d.reviews.filter(matches);
  const findingHtml = (f) => `<li class="rfinding"><div><span class="sev ${FINDING_SEV[f.severity]}">${esc(f.severity)}</span> <b>${esc(f.title)}</b></div>
    <div class="small muted mono">${esc(f.category)}${f.file ? ` · ${esc(f.file)}${f.line > 0 ? `:${f.line}` : ""}` : ""}</div>
    <p>${esc(f.detail)}</p>${f.suggestion ? `<p><b>Fix:</b> ${esc(f.suggestion)}</p>` : ""}</li>`;
  const row = (r) => {
    const [label, tone] = REVIEW_STATE[r.state] ?? [r.state, "off"];
    const key = `${r.repo}#${r.number}@${r.sha}`;
    const blockers = r.findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
    const counts = r.findings.length ? `${blockers} to fix${r.findings.length > blockers ? `, ${r.findings.length - blockers} minor` : ""}` : "";
    return `<li class="rrow">
      <div class="rmain">
        <span class="rstate ${tone}">${r.state === "running" ? '<span class="spin"></span>' : ""}${esc(label)}</span>
        <div class="rtitle"><a href="${safeUrl(r.url)}" target="_blank" rel="noopener noreferrer"><b>${esc(r.title)}</b></a>
          <div class="small muted">${esc(r.repo)}#${r.number}${r.author ? ` · ${esc(r.author)}` : ""} · <span class="mono">${esc(r.sha.slice(0, 7))}</span> · ${esc(ago(r.at))}${r.costUsd != null ? ` · ${money(r.costUsd)}` : ""}${counts ? ` · ${esc(counts)}` : ""}</div></div>
        ${["queued", "running"].includes(r.state) ? "" : `<button class="btn small" data-again="${esc(r.repo)}" data-num="${r.number}" ${on && d.configured ? "" : "disabled"}>${r.state === "skipped" ? "Review now" : "Review again"}</button>`}
      </div>
      ${r.note ? `<p class="small ${r.state === "error" ? "warn-text" : "muted"}">${esc(r.note)}</p>` : ""}
      ${r.summary || r.findings.length ? `<details data-rkey="${esc(key)}" ${state.reviewOpen.has(key) ? "open" : ""}><summary>${r.findings.length ? `${r.findings.length} note${r.findings.length === 1 ? "" : "s"}` : "Summary"}</summary>
        ${r.summary ? `<p>${esc(r.summary)}</p>` : ""}${r.findings.length ? `<ul class="plain">${r.findings.map(findingHtml).join("")}</ul>` : ""}</details>` : ""}
    </li>`;
  };
  $("canvas").innerHTML = `<div class="profile">
    <header class="phead">
      <div class="pavatar" aria-hidden="true">✓</div>
      <div class="pwho"><h2>PR reviews</h2><p class="muted">An AI reviewer tries to break every pull request on your watched repos. It either clears the PR for a person to merge or sends it back with notes. It never merges.</p></div>
    </header>
    ${d.managed ? "" : `<div class="warn-box"><b>Reviews run on a server install.</b> They use the repo list and clones from the Repos page, which this install doesn't have.</div>`}
    ${d.managed && !d.configured ? `<div class="warn-box"><b>Reviews need Claude.</b> Log in to Claude Code on this server, or add <span class="mono">ANTHROPIC_API_KEY</span> to Mycelium's environment and restart it.</div>` : ""}
    ${d.lastError ? `<div class="errbox">The last check for PRs failed: ${esc(d.lastError)} It tries again in a couple of minutes.</div>` : ""}
    <div class="ptiles">
      <div class="ptile static"><b class="${on ? "ok-text" : ""}">${on ? "On" : "Off"}</b><span>${on ? (d.lastPollAt ? `checked for PRs ${esc(ago(d.lastPollAt))}` : "checking every 2 minutes") : "PR reviews"}</span></div>
      <div class="ptile static"><b>${t.sentBack + t.passed}</b><span>${t.sentBack} sent back, ${t.passed} ready to merge</span></div>
      ${d.engine === "api" ? `<div class="ptile static"><b>${money(t.costDay)}</b><span>last 24 hours, about ${money(t.cost)} in all</span></div>` : `<div class="ptile static"><b>${t.reviewedDay}</b><span>${d.engine === "claude-code" ? "reviews in 24 hours, on your Claude plan" : "reviews in 24 hours"}</span></div>`}
    </div>
    <section class="pcard">
      <h3>Settings</h3>
      <label class="row"><input type="checkbox" id="rOn" ${on ? "checked" : ""} ${d.configured && d.managed ? "" : "disabled"}> <b>Review new pull requests</b></label>
      <label class="row"><span>Stop after <input class="field num-in" id="rLimit" type="number" min="1" max="1000" value="${esc(d.settings.dailyLimit)}" aria-label="Most reviews in 24 hours"> reviews in 24 hours</span></label>
      <label class="row"><input type="checkbox" id="rEmail" ${d.settings.emailSentBack ? "checked" : ""}> <span>Email the alert list when a PR is sent back</span></label>
      <p class="small muted">PRs already open when you turn this on aren't reviewed until they change. PRs from forks and dependency bots like Dependabot are skipped, but you can still review one by hand. PR code goes to Anthropic (${esc(d.model)}${d.engine === "claude-code" ? ", through Claude Code on this server" : ""}), without files that may hold secrets. To block merging on a failed review, make the <span class="mono">Mycelium review</span> check required in GitHub's branch rules.</p>
      <div class="actions"><button class="btn primary" id="rSave">Save</button>${state.reviewMsg ? `<span class="small ${state.reviewMsg.err ? "warn-text" : "ok-text"}" role="status">${esc(state.reviewMsg.text)}</span>` : ""}</div>
    </section>
    <div class="filters rfilters"><div class="chips" role="group" aria-label="Filter reviews">${chips.map(([id, label, c]) => `<button data-rfilter="${id}" class="${state.reviewFilter === id ? "on" : ""}">${label}<i>${c}</i></button>`).join("")}</div></div>
    ${shown.length ? `<ul class="plain rlist">${shown.map(row).join("")}</ul>` : `<div class="empty">${d.reviews.length ? "No reviews match this filter." : on ? "No PRs yet. New ones show up here within a couple of minutes." : "Turn reviews on, and new PRs show up here."}</div>`}
  </div>`;
  $("rSave").onclick = async () => {
    try {
      state.tabs.reviews = await api("/api/reviews", { enabled: $("rOn").checked, dailyLimit: Number($("rLimit").value), emailSentBack: $("rEmail").checked });
      state.reviewMsg = { text: "Saved." };
    } catch (e) { state.reviewMsg = { text: e.message, err: true }; }
    renderReviews();
  };
  document.querySelectorAll("[data-rfilter]").forEach((b) => (b.onclick = () => { state.reviewFilter = b.dataset.rfilter; renderReviews(); }));
  document.querySelectorAll("details[data-rkey]").forEach((el) => (el.ontoggle = () => { el.open ? state.reviewOpen.add(el.dataset.rkey) : state.reviewOpen.delete(el.dataset.rkey); }));
  document.querySelectorAll("[data-again]").forEach((b) => (b.onclick = async () => {
    try { state.tabs.reviews = await api("/api/reviews/again", { repo: b.dataset.again, number: Number(b.dataset.num) }); }
    catch (e) { state.reviewMsg = { text: e.message, err: true }; }
    renderReviews();
  }));
}

// Reviews take minutes and finish on their own, so this page keeps itself current, unless someone's mid-edit in its settings.
setInterval(async () => {
  if (state.view !== "reviews" || !state.tabs.reviews || !state.tabs.reviews.settings.enabled || document.hidden) return;
  if (["rLimit", "rOn", "rEmail"].includes(document.activeElement?.id)) return;
  try {
    const next = await api("/api/reviews");
    if (state.view === "reviews") { state.tabs.reviews = next; renderReviews(); }
  } catch { /* the next tick tries again */ }
}, 15_000);

function renderCanvas() {
  ({ projects: renderProjects, findings: renderFindings, fixed: renderFixed, reviews: renderReviews, audit: renderAudit, infra: renderInfra, repos: renderRepos, profile: renderProfile, alerts: renderAlerts })[state.view]();
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
  loadTab(); // a rescan or fix clears the tab caches; without this the open tab would spin forever
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
    const out = await api("/api/refresh", {});
    state.tabs = {};
    await refresh();
    if (out?.warnings?.length) banner(`Rescan finished. ${out.warnings.join(" ")}`, true);
    else {
      banner("Rescan finished.");
      setTimeout(() => banner(""), 4000);
    }
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
    // Links in alert emails: /#project=name opens that project.
    const linked = new URLSearchParams(location.hash.slice(1)).get("project");
    if (linked && state.data.projects.some((p) => p.name === linked)) selectProject(linked);
    // An import started earlier may still be running: pick its progress back up.
    const rj = await api("/api/repos/job");
    if (rj?.state === "running") { state.repoJob = rj; pollRepoJob(); }
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
