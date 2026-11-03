// Self-contained HTML report: open it in a browser, no server, no dependencies.

import { writeFileSync } from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import { fixCommand, whyPaths, type Finding } from "./graph.ts";
import { audit, CATEGORY_LABEL } from "./audit.ts";
import { prFixIndex, projectPrs } from "./prs.ts";

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);

export function writeHtmlReport(db: DatabaseSync, list: Finding[], out: string) {
  writeFileSync(out, renderHtmlReport(db, list));
}

/** With a token (from `mycelium serve`), the page gets Fix buttons that call the local API. */
export function renderHtmlReport(db: DatabaseSync, list: Finding[], opts: { token?: string } = {}): string {
  const live = !!opts.token;
  const projects = db.prepare(`
    SELECT pr.id, pr.name, pr.path, pr.exposure,
      (SELECT count(DISTINCT u.package_id) FROM uses u JOIN components c ON c.id = u.component_id WHERE c.project_id = pr.id) AS pkgs
    FROM projects pr ORDER BY pr.name`).all() as any[];
  const infraRows = db.prepare(`
    SELECT pr.name AS project, i.kind, i.value, i.source, i.warning FROM infra i JOIN projects pr ON pr.id = i.project_id
    ORDER BY pr.name, i.kind`).all() as any[];

  const vulnsByProject = new Map<string, Finding[]>();
  for (const f of list) for (const p of new Set(f.hits.map((h) => h.project))) vulnsByProject.set(p, [...(vulnsByProject.get(p) ?? []), f]);
  const count = (s: string) => list.filter((f) => f.severity === s).length;

  const prIdx = live ? prFixIndex(db) : new Map();
  const prBadge = (h: Finding["hits"][number], f: Finding) => {
    const pr = prIdx.get(`${h.projectPath}|${h.component}|${f.name}@${f.version}`);
    if (!pr) return "";
    return pr.state === "MERGED"
      ? `<a class="prbadge merged" href="${esc(pr.url)}" target="_blank" rel="noopener">✅ merged in #${pr.number}, pull to apply</a>`
      : `<a class="prbadge" href="${esc(pr.url)}" target="_blank" rel="noopener">🔀 fix in PR #${pr.number}</a>`;
  };
  const findingRows = list.map((f) => {
    const byProject = new Map<string, (typeof f.hits)[number]>();
    for (const h of f.hits) if (!byProject.has(h.project) || h.direct) byProject.set(h.project, h);
    const where = [...byProject.values()].map((h) => {
      const chain = h.direct ? [] : whyPaths(db, h.componentId, f.packageId, 1)[0] ?? [];
      return `<div class="hit"><b>${esc(h.project)}</b> <span class="muted">${esc(h.exposure)} · ${h.direct ? "direct" : "transitive"}</span>
        ${live ? prBadge(h, f) || `<button class="fixbtn small-btn" data-project="${esc(h.project)}" data-only="${esc(f.name)}">fix</button>` : ""}
        ${chain.length > 1 ? `<div class="chain">${chain.map(esc).join(" → ")}</div>` : ""}
        <code>${esc(fixCommand(f, h.direct, chain[0]))}</code></div>`;
    }).join("");
    return `<tr data-sev="${f.severity}">
      <td><span class="sev ${f.severity}">${f.severity}</span><div class="muted">risk ${f.risk}</div></td>
      <td><b>${esc(f.name)}</b>@${esc(f.version)}<div class="muted">${esc(f.ecosystem)}${f.fixed ? ` · fixed in ${esc(f.fixed)}` : " · no fix yet"}</div></td>
      <td>${esc(f.summary)}<div><a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.cve ?? f.vulnId)}</a></div></td>
      <td>${where}</td></tr>`;
  }).join("");

  const issues = audit(db);
  const projectCards = projects.map((p) => {
    const vs = vulnsByProject.get(p.name) ?? [];
    const mine = issues.filter((i) => i.project === p.name && i.severity !== "LOW");
    const sevs = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"];
    const worst = sevs.find((s) => vs.some((v) => v.severity === s) || mine.some((i) => i.severity === s));
    const urgent = mine.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH");
    const auditLine = mine.length
      ? `<div class="small" style="margin-top:2px">${urgent.length ? `<span class="sev ${urgent[0].severity}">${urgent.length} ${urgent[0].severity.toLowerCase()}</span> ` : ""}${mine.length} audit issue${mine.length > 1 ? "s" : ""}</div>${urgent.slice(0, 2).map((i) => `<div class="muted small">⚠ ${esc(i.title)}</div>`).join("")}`
      : "";
    const hosts = infraRows.filter((i) => i.project === p.name && ["host", "domain", "distribution"].includes(i.kind)).map((i) => i.value);
    return `<div class="card ${worst ? "bad-" + worst : "clean"}">
      <div class="name">${esc(p.name)}</div>
      <div class="muted">${p.pkgs} packages · ${esc(p.exposure)}</div>
      <div class="vcount">${vs.length ? `${vs.length} CVE finding${vs.length > 1 ? "s" : ""}` : mine.length ? "no CVEs" : "clean"}</div>
      ${auditLine}
      <div class="muted small">${esc([...new Set(hosts)].join(", "))}</div>
      ${live ? prLines(db, p) : ""}
      ${live && vs.length ? `<button class="fixbtn" data-project="${esc(p.name)}">🔧 Fix</button>` : ""}</div>`;
  }).join("");

  const issueCount = (cat: string) => issues.filter((i) => i.category === cat).length;
  const auditRows = issues.map((i) => `<tr data-cat="${i.category}">
      <td><span class="sev ${i.severity}">${i.severity}</span></td><td>${esc(CATEGORY_LABEL[i.category])}</td>
      <td><b>${esc(i.project)}</b></td><td>${esc(i.title)}${i.detail ? `<div class="muted small">${esc(i.detail)}</div>` : ""}</td>
      <td class="muted small">${esc(i.source ?? "")}</td></tr>`).join("");

  const infraWarn = infraRows.filter((i) => i.warning).map((i) =>
    `<tr><td>${esc(i.project)}</td><td>${esc(i.kind)}</td><td><code>${esc(i.value)}</code></td><td>${esc(i.warning)}</td><td class="muted">${esc(i.source)}</td></tr>`,
  ).join("");

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mycelium Report</title><style>
:root{--bg:#f7f6f2;--fg:#1d1b16;--muted:#6b675d;--card:#fff;--line:#e4e1d8;--crit:#b3261e;--high:#d0532a;--mod:#b7861b;--low:#7a7a7a;--ok:#2f7d4f;--accent:#6d4aa8}
@media (prefers-color-scheme:dark){:root{--bg:#15140f;--fg:#ece9e1;--muted:#9c978a;--card:#1f1d17;--line:#33302a;--crit:#ff6b5e;--high:#ff8a57;--mod:#e6b84a;--low:#9a9a9a;--ok:#5fc48a;--accent:#b79cf0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,sans-serif}
main{max-width:1200px;margin:0 auto;padding:32px 16px}h1{margin:0;font-size:28px}h2{margin:40px 0 12px;font-size:18px}
.muted{color:var(--muted)}.small{font-size:12px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}
.stat b{display:block;font-size:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--ok);border-radius:8px;padding:10px 12px}
.card .name{font-weight:600}.card .vcount{font-weight:600;margin-top:4px}
.bad-CRITICAL{border-left-color:var(--crit)}.bad-HIGH{border-left-color:var(--high)}.bad-MODERATE{border-left-color:var(--mod)}.bad-LOW,.bad-UNKNOWN{border-left-color:var(--low)}
.clean .vcount{color:var(--ok)}
.table-wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}td,th{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.sev{font-weight:700;font-size:12px;padding:2px 8px;border-radius:99px;color:#fff;background:var(--low)}
.sev.CRITICAL{background:var(--crit)}.sev.HIGH{background:var(--high)}.sev.MODERATE{background:var(--mod)}
code{font:12px ui-monospace,Menlo,monospace;background:color-mix(in srgb,var(--fg) 7%,transparent);padding:2px 6px;border-radius:4px;display:inline-block;margin-top:4px;word-break:break-all}
.hit{margin-bottom:10px}.chain{font:12px ui-monospace,Menlo,monospace;color:var(--muted)}
a{color:var(--accent)}.filters{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
.filters button{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:99px;padding:4px 12px;cursor:pointer}
.filters button.on{background:var(--fg);color:var(--bg)}
.fixbtn{margin-top:8px;border:1px solid var(--accent);background:transparent;color:var(--accent);border-radius:6px;padding:4px 10px;cursor:pointer;font-weight:600}
.fixbtn:hover{background:var(--accent);color:var(--bg)}
.prline{margin-top:4px}.prline a{color:var(--accent)}.pullbtn{border-color:var(--ok);color:var(--ok)}.pullbtn:hover{background:var(--ok)}
.prbadge{font-size:12px;margin-left:6px;text-decoration:none;border:1px solid var(--line);border-radius:99px;padding:0 8px;color:var(--accent)}
.prbadge.merged{color:var(--ok);border-color:var(--ok)}.small-btn{margin:0 0 0 6px;padding:0 8px;font-size:12px}
dialog{border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--fg);width:min(860px,calc(100vw - 32px));max-height:85vh;padding:0}
dialog::backdrop{background:rgb(0 0 0/.45)}.dlg-head,.dlg-foot{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.dlg-foot{border-bottom:0;border-top:1px solid var(--line)}.dlg-body{padding:6px 18px;overflow:auto;max-height:55vh}
.fx{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--line);align-items:flex-start}.fx:last-child{border:0}
.tag{font-size:11px;font-weight:700;padding:1px 6px;border-radius:4px;border:1px solid currentColor}.tag.auto{color:var(--ok)}.tag.major{color:var(--accent)}.tag.manual{color:var(--mod)}
.primary{background:var(--fg);color:var(--bg);border:0;border-radius:6px;padding:8px 16px;font-weight:600;cursor:pointer}
.primary:disabled{opacity:.5;cursor:wait}.ghost{background:transparent;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:8px 14px;cursor:pointer}
pre.out{white-space:pre-wrap;font:12px ui-monospace,Menlo,monospace;background:color-mix(in srgb,var(--fg) 6%,transparent);padding:10px;border-radius:6px}
</style></head><body><main>
<div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap"><h1 style="flex:1">🍄 Mycelium</h1>
${live ? `<button class="fixbtn" id="rescan" style="margin:0">↻ Rescan</button>` : ""}</div>
<div class="muted">${live ? `Last checked ${esc(lastChecked(db))}` : `Generated ${esc(new Date().toLocaleString())}`} · production dependencies only unless run with --dev</div>
<div class="stats">
<div class="stat"><b>${projects.length}</b>projects</div>
<div class="stat"><b>${list.length}</b>findings</div>
<div class="stat"><b style="color:var(--crit)">${count("CRITICAL")}</b>critical</div>
<div class="stat"><b style="color:var(--high)">${count("HIGH")}</b>high</div>
<div class="stat"><b style="color:var(--mod)">${count("MODERATE")}</b>moderate</div>
<div class="stat"><b>${infraRows.filter((i) => i.warning).length}</b>infra warnings</div>
</div>
<h2>Projects</h2><div class="grid">${projectCards}</div>
<h2>Findings, ranked by blast radius</h2>
<div class="filters">${["ALL", "CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"].map((s, i) => `<button class="${i ? "" : "on"}" data-f="${s}">${s.toLowerCase()}</button>`).join("")}</div>
<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Where · path · fix</th></tr></thead>
<tbody id="findings">${findingRows || `<tr><td colspan="4">No known vulnerabilities. 🍄</td></tr>`}</tbody></table></div>
<h2>Supply-chain audit <span class="muted small">everything that isn't a CVE</span></h2>
<div class="filters" id="catfilters"><button class="on" data-c="ALL">all (${issues.length})</button>${Object.entries(CATEGORY_LABEL)
  .map(([k, label]) => `<button data-c="${k}">${esc(label.toLowerCase())} (${issueCount(k)})</button>`).join("")}</div>
<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Category</th><th>Project</th><th>Issue</th><th>Source</th></tr></thead>
<tbody id="audit">${auditRows || `<tr><td colspan="5">Nothing found. Run <code>mycelium audit</code> to fetch registry data.</td></tr>`}</tbody></table></div>
<h2>Infrastructure warnings</h2>
<div class="table-wrap"><table><thead><tr><th>Project</th><th>Kind</th><th>Value</th><th>Warning</th><th>Source</th></tr></thead>
<tbody>${infraWarn || `<tr><td colspan="5">None.</td></tr>`}</tbody></table></div>
</main>${live ? FIX_DIALOG : ""}<script>
document.querySelectorAll(".filters:not(#catfilters) button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll(".filters:not(#catfilters) button").forEach(x=>x.classList.toggle("on",x===b));
  document.querySelectorAll("#findings tr[data-sev]").forEach(r=>r.style.display=(b.dataset.f==="ALL"||r.dataset.sev===b.dataset.f)?"":"none");
});
document.querySelectorAll("#catfilters button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#catfilters button").forEach(x=>x.classList.toggle("on",x===b));
  document.querySelectorAll("#audit tr[data-cat]").forEach(r=>r.style.display=(b.dataset.c==="ALL"||r.dataset.cat===b.dataset.c)?"":"none");
});
${live ? fixScript(opts.token!) : ""}
</script></body></html>`;
}

const FIX_DIALOG = `<dialog id="fixdlg">
  <div class="dlg-head"><b id="dlg-title">Fix</b><span class="muted small" id="dlg-sub"></span></div>
  <div class="dlg-body" id="dlg-body"></div>
  <div class="dlg-foot">
    <label><input type="checkbox" id="opt-verify" checked> run build/test</label>
    <span class="muted small" title="Fixes run in a separate git worktree and are committed to a new branch. Uncommitted work in your folder is never touched.">🌿 new branch · your folder untouched</span>
    <label title="Commits, pushes the branch, and opens a GitHub PR into the branch you were on. Never merges."><input type="checkbox" id="opt-pr"> open PR</label>
    <span style="flex:1"></span>
    <button class="ghost" id="dlg-close">Close</button>
    <button class="primary" id="dlg-apply">Apply on new branch</button>
  </div>
</dialog>`;

/** Card lines for this project's open / merged-not-pulled Mycelium PRs, with a ⬇ Pull button when it's safe. */
function prLines(db: DatabaseSync, p: { name: string; path: string }): string {
  const list = projectPrs(db, p.path);
  if (!list.length) return "";
  const fixedBy = (n: number) =>
    (db.prepare("SELECT count(*) AS c FROM pr_fixes f JOIN prs r ON r.id = f.pr_id WHERE r.number = ? AND f.project_path = ?").get(n, p.path) as { c: number }).c;
  const lines = list.map((s) => {
    const n = fixedBy(s.pr.number);
    const what = n ? ` · fixes ${n}` : "";
    if (!s.needsPull) return `<div class="small prline">🔀 <a href="${esc(s.pr.url)}" target="_blank" rel="noopener">PR #${s.pr.number}</a> open${what}</div>`;
    return `<div class="small prline">✅ <a href="${esc(s.pr.url)}" target="_blank" rel="noopener">PR #${s.pr.number}</a> merged${what} · ${s.ready ? "ready to pull" : `<span class="muted">can't pull: ${esc(s.reason)}</span>`}</div>`;
  });
  const canPull = list.some((s) => s.needsPull && s.ready);
  return lines.join("") + (canPull ? `<button class="fixbtn pullbtn" data-project="${esc(p.name)}">⬇ Pull &amp; rescan</button> ` : "");
}

function lastChecked(db: DatabaseSync): string {
  const r = db.prepare("SELECT max(checked_at) AS t FROM packages").get() as { t: string | null };
  if (!r.t) return "never";
  const mins = Math.round((Date.now() - Date.parse(r.t)) / 60000);
  return mins < 1 ? "just now" : mins < 60 ? `${mins} min ago` : mins < 1440 ? `${Math.round(mins / 60)} h ago` : `${Math.round(mins / 1440)} days ago`;
}

function fixScript(token: string) {
  return `
document.querySelectorAll(".pullbtn").forEach(b=>b.onclick=async()=>{
  b.disabled=true;b.textContent="Pulling + rescanning…";
  try{const r=await api("/api/pull",{project:b.dataset.project});
    if(r.refused.length&&!r.pulled.length){b.textContent="Couldn't pull: "+r.refused.join("; ");return;}
    location.reload();
  }catch(e){b.textContent="Pull failed: "+e.message;b.disabled=false;}
});
const rescan=document.getElementById("rescan");
if(rescan)rescan.onclick=async()=>{rescan.disabled=true;rescan.textContent="Rescanning… (~30s)";
  try{await api("/api/refresh");location.reload();}catch(e){rescan.textContent="↻ Rescan (failed: "+e.message+")";rescan.disabled=false;}};
const TOKEN=${JSON.stringify(token)};
const api=(p,b)=>fetch(p,{method:"POST",headers:{"content-type":"application/json","x-mycelium-token":TOKEN},body:JSON.stringify(b||{})}).then(async r=>{const j=await r.json();
  // Page older than the server's token (e.g. server reinstalled): reload to pick up the current one.
  if(r.status===403&&j.error==="bad token"){location.reload();throw new Error("page was out of date, reloading…");}
  if(!r.ok)throw new Error(j.error||r.status);return j;});
const h=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
const dlg=document.getElementById("fixdlg"),body=document.getElementById("dlg-body"),applyBtn=document.getElementById("dlg-apply");
let current=null;
document.getElementById("dlg-close").onclick=()=>dlg.close();
const prBox=document.getElementById("opt-pr");
// Only real Fix buttons: Rescan and Pull share the .fixbtn look but have their own handlers.
document.querySelectorAll(".fixbtn[data-project]:not(.pullbtn)").forEach(b=>b.onclick=async()=>{
  current={project:b.dataset.project,only:b.dataset.only};
  document.getElementById("dlg-title").textContent="Fix "+current.project;
  document.getElementById("dlg-sub").textContent=current.only?"only "+current.only:"";
  body.innerHTML="<p class=muted>Planning…</p>";applyBtn.disabled=true;applyBtn.style.display="";dlg.showModal();
  try{
    const plan=await api("/api/plan",{project:current.project});
    let fixes=plan.fixes;if(current.only)fixes=fixes.filter(f=>f.name===current.only);
    // One row per package (it may appear in several lockfiles).
    const seen=new Map();for(const f of fixes){const k=f.name;if(!seen.has(k))seen.set(k,{...f,count:0});seen.get(k).count++;}
    body.innerHTML=[...seen.values()].map(f=>{
      const kind=f.strategy==="manual"?"manual":f.breaking?"major":"auto";
      return '<label class="fx"><input type="checkbox" value="'+h(f.name)+'" '+(kind==="auto"?"checked":"")+(kind==="manual"?" disabled":"")+' data-kind="'+kind+'">'+
        '<div><span class="tag '+kind+'">'+kind+'</span> <span class="sev '+f.severity+'">'+f.severity+'</span> <b>'+h(f.name)+'</b> '+h(f.from)+' → '+h(f.to??"?")+
        ' <span class="muted small">'+f.vulns.length+' advisories'+(f.count>1?' · '+f.count+' lockfiles':'')+'</span><div class="muted small">'+h(f.note)+'</div></div></label>';
    }).join("")||"<p>Nothing to fix.</p>";
    applyBtn.disabled=!fixes.some(f=>f.strategy!=="manual");
  }catch(e){body.innerHTML='<pre class="out">'+h(e.message)+'</pre>';}
});
applyBtn.onclick=async()=>{
  const boxes=[...body.querySelectorAll("input[type=checkbox]:checked")];
  if(!boxes.length)return;
  const only=boxes.map(b=>b.value),allowMajor=boxes.some(b=>b.dataset.kind==="major");
  applyBtn.disabled=true;applyBtn.textContent="Working… (package manager running)";
  try{
    const r=await api("/api/apply",{project:current.project,only,allowMajor,verify:document.getElementById("opt-verify").checked,pr:prBox.checked});
    body.innerHTML=
      (r.prs&&r.prs.length?r.prs.map(p=>'<p>🚀 <b>PR opened</b> into <code>'+h(p.base)+'</code>: <a href="'+h(p.url)+'" target="_blank" rel="noopener">'+h(p.url)+'</a></p>').join(""):'')+
      (r.fixed.length?'<p>✅ <b>Fixed '+r.fixed.length+'</b></p><pre class="out">'+h(r.fixed.join("\\n"))+'</pre>':'')+
      (r.stillVulnerable.length?'<p>⚠️ <b>Still vulnerable</b> (the package manager kept the old version)</p><pre class="out">'+h(r.stillVulnerable.join("\\n"))+'</pre>':'')+
      (r.failed.length?'<p>❌ <b>Failed</b></p>'+(()=>{const g=new Map();for(const f of r.failed){if(!g.has(f.error))g.set(f.error,[]);g.get(f.error).push(f.fix.name);}
        return [...g].map(([err,names])=>'<p class="small"><b>'+h([...new Set(names)].join(", "))+'</b></p><pre class="out">'+h(err)+'</pre>').join("");})():'')+
      (r.verify.length?'<p><b>Verify</b></p><pre class="out">'+h(r.verify.map(v=>(v.ok?"✓ ":v.preexisting?"≈ ":"✗ ")+v.command+(v.ok?"":v.preexisting?"  (already failing before the upgrade: not blocking)":"\\n"+v.output.slice(-600))).join("\\n"))+'</pre>':'')+
      (r.branch?'<p>Committed on branch <code>'+h(r.branch)+'</code>. Your working folder wasn\\'t touched.'+(r.prs&&r.prs.length?'':' Review with <code>git log -p '+h(r.branch)+' -1</code>.')+'</p>':'')+
      (prBox.checked&&!(r.prs&&r.prs.length)?'<p>⚠️ <b>No PR opened</b>, see log for why.</p>':'')+
      '<details '+(prBox.checked&&!(r.prs&&r.prs.length)?'open':'')+'><summary class="muted">log</summary><pre class="out">'+h(r.log.join("\\n"))+'</pre></details>';
    applyBtn.style.display="none";
    dlg.addEventListener("close",()=>location.reload(),{once:true});
  }catch(e){body.innerHTML='<pre class="out">'+h(e.message)+'</pre>';}
  applyBtn.textContent="Apply on new branch";
};`;
}
