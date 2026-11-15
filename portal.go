package main

import (
	"strconv"
	"strings"
)

// portalHTML renders the dashboard with the force_https flag baked in. When
// false, every generated link reuses the protocol the visitor used to reach
// apps.<host>.local (location.protocol) — the plain-http twins serve content,
// so navigation stays consistent end to end. When true, links are always
// https:// regardless of how the portal was opened. The page itself is served
// ONLY on apps.<host>.local and fetches /api/domains + /api/static live, so
// data is always current with zero file churn.
func portalHTML(force bool) string {
	return strings.NewReplacer(
		"__FORCE_HTTPS__", strconv.FormatBool(force),
		"__VERSION__", version,
	).Replace(portalHTMLRaw)
}

// authFormHTML is served to browsers that hit the portal without a valid
// session: it POSTs the token to /api/login, which sets an HttpOnly session
// cookie — the token itself never appears in any URL. __LOGIN_FAILED__ is
// replaced with an error note when the last login attempt was rejected.
const authFormHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<!-- no-referrer: never leak the portal origin to app targets -->
<meta name="referrer" content="no-referrer">
<title>ProxDnx · access token</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#14161a;color:#e8e8ea;font:15px/1.5 system-ui,sans-serif}
form{background:#1e2126;border:1px solid #2a2e34;border-radius:12px;padding:28px 30px;max-width:360px}
h1{margin:0 0 6px;font-size:22px}h1 span{color:#E64804}
p{color:#9aa0a6;font-size:13px;margin:6px 0 16px}
input{width:100%;box-sizing:border-box;background:#14161a;border:1px solid #2a2e34;border-radius:8px;color:#e8e8ea;padding:9px 12px;font-size:14px}
button{width:100%;margin-top:10px;background:#E64804;border:0;border-radius:8px;color:#fff;font-weight:600;padding:10px 0;font-size:14px;cursor:pointer}
button:hover{filter:brightness(1.1)}
.h{font-size:12px;margin-top:14px}
</style></head><body>
<form method="post" action="/api/login">
  <h1>🧭 Prox<span>Dnx</span></h1>
  <p>This dashboard requires an access token.</p>
  <input name="token" type="password" autocomplete="off" autofocus placeholder="access token">
  <button type="submit">Open dashboard</button>
  __LOGIN_FAILED__
  <p class="h">The token is the <b>api_token</b> line of the server config (on first start it is generated and printed to the startup log). You stay logged in for 30 days.</p>
</form>
</body></html>
`

const portalHTMLRaw = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- no-referrer: never leak the portal origin to app targets -->
<meta name="referrer" content="no-referrer">
<title>ProxDnx · published services</title>
<style>
  :root{--bg:#14161a;--card:#1e2126;--border:#2a2e34;--text:#e8e8ea;--muted:#9aa0a6;--accent:#E64804;--link:#6cb2ff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
  header{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px;padding:26px 32px 8px}
  header h1{margin:0;font-size:22px;letter-spacing:.3px}
  header h1 span{color:var(--accent)}
  header p{margin:0;color:var(--muted);font-size:13px}
  header .n{color:var(--accent);font-weight:700}
  main,#staticgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:14px}
  main{padding:18px 32px 26px}
  section#static{padding:0 32px 30px}
  section#static h2{margin:0 0 12px;font-size:12px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted)}
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px;transition:border-color .15s,transform .15s;-webkit-user-select:none;user-select:none}
  .card:hover{border-color:var(--accent);transform:translateY(-1px)}
  .card a.domain{display:block;font-size:16px;font-weight:600;color:var(--link);text-decoration:none;word-break:break-word}
  .card a.domain:hover{text-decoration:underline}
  .card .svc{color:var(--muted);font-size:13px;margin-top:2px}
  .chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
  .chip{background:#262a30;border:1px solid var(--border);border-radius:6px;padding:2px 8px;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted)}
  .chip b{color:var(--text);font-weight:600}
  .chip.bad{color:#ff6b6b;border-color:#7a3a3a;background:#2a1a1a}
  .chip.warn{color:#ffb86b;border-color:#7a5c2a;background:#2a2318}
  .card.dim{opacity:.55}
  .editrow{margin-top:10px}
  .nameinput{width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:8px 10px;font:14px ui-monospace,SFMono-Regular,Menlo,monospace;-webkit-user-select:text;user-select:text}
  .editactions{display:flex;gap:6px;margin-top:8px}
  .ebtn{background:#262a30;border:1px solid var(--border);border-radius:6px;color:var(--muted);font:12px system-ui,sans-serif;padding:5px 10px;cursor:pointer}
  .ebtn:hover{color:var(--text)}
  .ebtn.save{color:#7ee787;border-color:#2a4a2a}
  footer{padding:0 32px 26px;color:var(--muted);font-size:12px}
  .empty{padding:40px 32px;color:var(--muted)}
</style>
</head>
<body>
<header>
  <h1>🧭 Prox<span>Dnx</span></h1>
  <p><span class="n" id="n">…</span> published services · updated <span id="updated">…</span></p>
</header>
<main id="grid"><div class="empty">loading…</div></main>
<section id="static">
  <h2>Infrastructure</h2>
  <div id="staticgrid"></div>
</section>
<footer>generated by proxdnx <b id="ver">__VERSION__</b> · <a style="color:var(--link)" href="/api/domains">/api/domains</a> · <a style="color:var(--link)" href="/api/static">/api/static</a> · <a style="color:var(--link)" href="/api/status">/api/status</a></footer>
<script>
function esc(s){const d=document.createElement("div");d.textContent=s==null?"":String(s);return d.innerHTML}
const FORCE_HTTPS=__FORCE_HTTPS__;
function api(p){return p}
function proto(){return FORCE_HTTPS?"https:":location.protocol}
// click-to-edit: rename the published URL (service name never changes);
// auto-refresh pauses while an edit is open
let EDITING=false;
function startEdit(card,x,link){
  if(EDITING)return;EDITING=true;
  const row=document.createElement("div");row.className="editrow";
  const inp=document.createElement("input");inp.className="nameinput";
  inp.value=x.domain.replace(/\.local$/,"");inp.maxLength=63;inp.autocomplete="off";inp.spellcheck=false;
  row.appendChild(inp);
  const actions=document.createElement("div");actions.className="editactions";
  const save=document.createElement("button");save.className="ebtn save";save.textContent="✓ save";
  const def=document.createElement("button");def.className="ebtn";def.textContent="↺ default";
  const cancel=document.createElement("button");cancel.className="ebtn";cancel.textContent="✕ discard";
  save.onclick=async()=>{
    const r=await fetch(api("/api/names"),{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({slug:x.slug,name:inp.value})});
    if(!r.ok){const j=await r.json().catch(()=>({}));save.textContent=j.error||"error";return}
    EDITING=false;load();
  };
  def.onclick=async()=>{
    await fetch(api("/api/names"),{method:"DELETE",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({slug:x.slug})});
    EDITING=false;load();
  };
  cancel.onclick=()=>{EDITING=false;load();};
  inp.onkeydown=(ev)=>{
    if(ev.key==="Enter"){ev.preventDefault();save.onclick();}
    else if(ev.key==="Escape"){ev.preventDefault();cancel.onclick();}
  };
  actions.append(save,def,cancel);
  link.replaceWith(inp);
  card.appendChild(actions);
  inp.focus();
}
async function load(){
  try{
    const d=await (await fetch(api("/api/domains"))).json();
    const g=document.getElementById("grid");
    g.innerHTML="";
    (d.domains||[]).forEach(x=>{
      const c=document.createElement("div");c.className="card"+(x.stale?" dim":"");
      const flags=(x.stale?'<span class="chip bad">⚠ stale — port closed</span>':'')
        +(x.mismatch?'<span class="chip warn">⚠ name mismatch — page title: "'+esc(x.title||"?")+'"</span>':'');
      const link=document.createElement("a");link.className="domain";link.href=proto()+"//"+esc(x.domain)+"/";
      link.textContent=x.domain;
      // the URL is a plain link: it always opens in a new tab; editing the
      // URL name is a double-click on the card itself
      link.target="_blank";link.rel="noopener noreferrer";
      c.appendChild(link);
      const svc=document.createElement("div");svc.className="svc";svc.textContent=x.service;
      c.appendChild(svc);
      if(flags){const fl=document.createElement("div");fl.className="chips";fl.innerHTML=flags;c.appendChild(fl)}
      const ch=document.createElement("div");ch.className="chips";
      ch.innerHTML='<span class="chip">🖥 <b>'+esc(x.name)+'</b></span><span class="chip"><b>'+esc(x.ip)+'</b>:'+esc(x.port)+'</span>';
      c.appendChild(ch);
      c.title="double-click to edit the URL name";
      // click-count detection (ev.detail===2) is steadier than the native
      // dblclick event; links and the edit row are exempt
      c.addEventListener("click",(ev)=>{
        if(ev.target.closest("a")||ev.target.closest(".editrow"))return;
        if(ev.detail===2)startEdit(c,x,link);
      });
      g.appendChild(c);
    });
    document.getElementById("n").textContent=d.count;
    document.getElementById("updated").textContent=new Date(d.updated_at).toLocaleString();
  }catch(e){document.getElementById("grid").innerHTML='<div class="empty">failed to load: '+esc(e)+'</div>'}
}
async function loadStatic(){
  try{
    const s=await (await fetch(api("/api/static"))).json();
    const sec=document.getElementById("static");
    if(!s.enabled){sec.hidden=true;return}
    const g=document.getElementById("staticgrid");
    g.innerHTML="";
    (s.routes||[]).forEach(r=>{
      const c=document.createElement("div");c.className="card";
      c.innerHTML='<a class="domain" target="_blank" rel="noopener noreferrer" href="'+proto()+'//'+esc(r.names[0])+'/">'+esc(r.label)+'</a>'
        +'<div class="svc">'+esc(r.desc)+' → <b style="color:var(--text)">'+esc(r.upstream)+'</b></div>'
        +'<div class="chips">'+(r.names||[]).map(n=>'<span class="chip">🏷 <b>'+esc(n)+'</b></span>').join("")+'</div>';
      g.appendChild(c);
    });
    sec.hidden=false;
  }catch(e){/* static section stays hidden */}
}
load();loadStatic();setInterval(()=>{load();loadStatic()},30000);
</script>
</body>
</html>
`
