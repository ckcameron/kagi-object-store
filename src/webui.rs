// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi node operations-console support.
//!
//! The console uses a local Argon2id user database, role checks, lightweight host telemetry,
//! bounded log tailing, and an embedded dark browser UI. Cluster-wide views are assembled by
//! the daemon through authenticated internal endpoints; this module deliberately keeps local
//! authentication and presentation helpers independent of Raft/data-path state.

use anyhow::{bail, Context, Result};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the WebConsoleConfig path.
pub struct WebConsoleConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_userdb")]
    pub userdb: PathBuf,
    #[serde(default = "default_log_path")]
    pub log_path: PathBuf,
    #[serde(default = "default_log_lines")]
    pub max_log_lines: usize,
}
/// Implements the default enabled step and keeps its validation and state transitions visible at the call site.
fn default_enabled() -> bool {
    true
}
/// Implements the default userdb step and keeps its validation and state transitions visible at the call site.
fn default_userdb() -> PathBuf {
    PathBuf::from("/etc/kagi/users.yaml")
}
/// Implements the default log path step and keeps its validation and state transitions visible at the call site.
fn default_log_path() -> PathBuf {
    PathBuf::from("/var/log/kagi/kagi.log")
}
/// Implements the default log lines step and keeps its validation and state transitions visible at the call site.
fn default_log_lines() -> usize {
    500
}
impl Default for WebConsoleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            userdb: default_userdb(),
            log_path: default_log_path(),
            max_log_lines: default_log_lines(),
        }
    }
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Supported ConsoleRole states or operations.
pub enum ConsoleRole {
    Viewer,
    Admin,
}
impl ConsoleRole {
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
/// Kagi state or configuration used by the ConsoleUser path.
pub struct ConsoleUser {
    pub username: String,
    pub password_hash: String,
    pub role: ConsoleRole,
}
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
/// Kagi state or configuration used by the ConsoleUserDb path.
pub struct ConsoleUserDb {
    #[serde(default)]
    pub users: Vec<ConsoleUser>,
}
#[derive(Debug, Clone, Serialize)]
/// Kagi state or configuration used by the ConsoleIdentity path.
pub struct ConsoleIdentity {
    pub username: String,
}
/// Implements the load userdb step and keeps its validation and state transitions visible at the call site.
pub fn load_userdb(path: &Path) -> Result<ConsoleUserDb> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(serde_yaml::from_str(&s).context("parse Kagi console userdb")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConsoleUserDb::default()),
        Err(e) => Err(e.into()),
    }
}
/// Implements the upsert user step and keeps its validation and state transitions visible at the call site.
pub fn upsert_user(path: &Path, username: &str, password: &str, role: ConsoleRole) -> Result<()> {
    if username.trim().is_empty() {
        bail!("username must not be empty")
    }
    let mut db = load_userdb(path)?;
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?
        .to_string();
    if let Some(u) = db.users.iter_mut().find(|u| u.username == username) {
        u.password_hash = hash;
        u.role = role;
    } else {
        db.users.push(ConsoleUser {
            username: username.into(),
            password_hash: hash,
            role,
        });
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_yaml::to_string(&db)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}
/// Implements the authenticate basic step and keeps its validation and state transitions visible at the call site.
pub fn authenticate_basic(
    headers: &axum::http::HeaderMap,
    userdb: &Path,
    admin: bool,
) -> Option<ConsoleIdentity> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let enc = auth.strip_prefix("Basic ")?;
    let raw = B64.decode(enc).ok()?;
    let pair = String::from_utf8(raw).ok()?;
    let (username, password) = pair.split_once(':')?;
    let db = load_userdb(userdb).ok()?;
    let user = db.users.into_iter().find(|u| u.username == username)?;
    let parsed = PasswordHash::new(&user.password_hash).ok()?;
    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_err()
    {
        return None;
    }
    if admin && !user.role.is_admin() {
        return None;
    }
    Some(ConsoleIdentity {
        username: user.username,
    })
}
/// Implements the unauthorized step and keeps its validation and state transitions visible at the call site.
pub fn unauthorized() -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut r = (
        axum::http::StatusCode::UNAUTHORIZED,
        "Kagi console authentication required",
    )
        .into_response();
    r.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Basic realm=\"Kagi\", charset=\"UTF-8\""),
    );
    r
}
/// Implements the append log step and keeps its validation and state transitions visible at the call site.
pub fn append_log(path: &Path, node: &str, message: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = writeln!(f, "{ts} [{node}] {message}");
    }
}
/// Implements the tail log step and keeps its validation and state transitions visible at the call site.
pub fn tail_log(path: &Path, max_lines: usize) -> Vec<String> {
    let Ok(mut f) = fs::File::open(path) else {
        return vec![];
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return vec![];
    };
    let take = len.min(1024 * 1024);
    let _ = f.seek(SeekFrom::End(-(take as i64)));
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let mut lines = s.lines().map(str::to_string).collect::<Vec<_>>();
    if lines.len() > max_lines {
        lines.drain(0..lines.len() - max_lines);
    }
    lines
}
#[derive(Debug, Clone, Serialize)]
/// Kagi state or configuration used by the SystemStats path.
pub struct SystemStats {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub uptime_seconds: f64,
}
/// Implements the system stats step and keeps its validation and state transitions visible at the call site.
pub fn system_stats() -> SystemStats {
    let loads = fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .split_whitespace()
        .take(3)
        .filter_map(|x| x.parse().ok())
        .collect::<Vec<f64>>();
    let mut total = 0;
    let mut avail = 0;
    for line in fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
    {
        if let Some(v) = line.strip_prefix("MemTotal:") {
            total = v
                .split_whitespace()
                .next()
                .and_then(|x| x.parse::<u64>().ok())
                .unwrap_or(0)
                * 1024;
        }
        if let Some(v) = line.strip_prefix("MemAvailable:") {
            avail = v
                .split_whitespace()
                .next()
                .and_then(|x| x.parse::<u64>().ok())
                .unwrap_or(0)
                * 1024;
        }
    }
    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0);
    SystemStats {
        load1: *loads.first().unwrap_or(&0.0),
        load5: *loads.get(1).unwrap_or(&0.0),
        load15: *loads.get(2).unwrap_or(&0.0),
        mem_total_bytes: total,
        mem_available_bytes: avail,
        uptime_seconds: uptime,
    }
}
pub const INDEX_HTML: &str = r###"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kagi Console</title><style>
:root{color-scheme:dark;--bg:#071019;--panel:#0d1a26;--panel2:#102333;--line:#1c3b4d;--text:#e8f6ff;--muted:#8cb2c7;--accent:#19d3e6;--accent2:#3388ff;--good:#3be28c;--warn:#ffc857;--bad:#ff667a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#0c2d38 0,#071019 34%);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,sans-serif}header{position:sticky;top:0;z-index:4;display:flex;align-items:center;gap:18px;padding:14px 22px;background:#071019e8;border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}.brand{font-size:24px;font-weight:800;letter-spacing:.08em;color:var(--accent)}.sub{color:var(--muted)}main{padding:20px;display:grid;gap:16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:12px;padding:14px}.kpi{font-size:26px;font-weight:750}.muted{color:var(--muted)}h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:#bdefff;margin:0 0 10px}input,button,select,textarea{background:#07131d;color:var(--text);border:1px solid #28516a;border-radius:8px;padding:9px 10px}button{cursor:pointer;background:linear-gradient(180deg,#116c80,#0c5268);font-weight:700}button:hover{border-color:var(--accent)}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #173143;vertical-align:top}th{color:#9fe9f5}.tabs{display:flex;gap:8px;flex-wrap:wrap}.tab.active{outline:2px solid var(--accent)}section[data-page]{display:none}section[data-page].active{display:block}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.grow{flex:1;min-width:220px}pre{white-space:pre-wrap;overflow:auto;max-height:420px;background:#050b11;padding:12px;border-radius:8px;border:1px solid #183244}.badge{display:inline-block;padding:2px 7px;border-radius:999px;background:#123246;color:#aeeefa}.bar{height:8px;border-radius:99px;background:#0a1620;overflow:hidden}.bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--accent2),var(--accent))}@media(max-width:600px){header{padding:12px}main{padding:12px}th:nth-child(n+4),td:nth-child(n+4){display:none}}
</style></head><body><header><div class="brand">KAGI</div><div><b>Distributed Object Storage Console</b><div id="node" class="sub">loading…</div></div><div style="margin-left:auto" id="status" class="badge">connecting</div></header><main><div class="tabs"><button class="tab active" data-tab="overview">Overview</button><button class="tab" data-tab="objects">Objects</button><button class="tab" data-tab="buckets">Buckets & Lifecycle</button><button class="tab" data-tab="logs">Logs</button><button class="tab" data-tab="security">Security & Integrity</button></div>
<section data-page="overview" class="active"><div id="kpis" class="grid"></div><div class="card"><h2>Cluster nodes</h2><div id="nodes"></div></div></section>
<section data-page="objects"><div class="card"><h2>Object explorer</h2><div class="row"><input id="prefix" class="grow" placeholder="prefix / bucket / object key"><button id="search">Search</button></div><div id="objects"></div></div><div class="card"><h2>Object detail</h2><div id="objectDetail" class="muted">Select an object.</div></div></section>
<section data-page="buckets"><div class="grid"><div class="card"><h2>Create/update bucket</h2><div class="row"><input id="bucketName" placeholder="bucket name"><select id="wormMode"><option>none</option><option>governance</option><option>compliance</option></select><input id="retainMs" placeholder="retain until epoch ms"><label><input id="legalHold" type="checkbox"> legal hold</label><label><input id="versioning" type="checkbox" checked> versioning</label><button id="saveBucket">Save</button></div></div><div class="card"><h2>Buckets</h2><div id="buckets"></div></div></div></section>
<section data-page="logs"><div class="card"><h2>Log console</h2><div class="row"><select id="logScope"><option value="local">local</option><option value="cluster">keyspace-wide</option></select><button id="refreshLogs">Refresh</button></div><pre id="logs"></pre></div></section>
<section data-page="security"><div class="card"><h2>Security and integrity findings</h2><button id="refreshAudit">Refresh</button><pre id="auditFindings"></pre></div><div class="card"><h2>Live node events</h2><pre id="securityEvents"></pre></div></section>
</main><script>
const q=s=>document.querySelector(s),fmt=n=>new Intl.NumberFormat().format(n||0),bytes=n=>{let x=Number(n||0),u=['B','KiB','MiB','GiB','TiB','PiB'],i=0;while(x>=1024&&i<u.length-1){x/=1024;i++}return x.toFixed(i?1:0)+' '+u[i]};async function api(p,o){let r=await fetch(p,o);if(!r.ok)throw new Error(await r.text());let t=await r.text();return t?JSON.parse(t):null}
async function overview(){try{let d=await api('/ui/api/summary');q('#node').textContent=d.local.node_id+' · '+d.local.role+' · '+d.local.site+'/'+d.local.rack;q('#status').textContent='online';q('#kpis').innerHTML=[['Objects',fmt(d.cluster.objects)],['Logical data',bytes(d.cluster.logical_bytes)],['Physical data',bytes(d.cluster.physical_bytes)],['Capacity',bytes(d.cluster.capacity_bytes)],['Fragments',fmt(d.cluster.fragments)],['Healthy resources',fmt(d.cluster.healthy_resources)],['Load',d.local.system.load1.toFixed(2)],['Memory free',bytes(d.local.system.mem_available_bytes)]].map(x=>`<div class=card><div class=muted>${x[0]}</div><div class=kpi>${x[1]}</div></div>`).join('');q('#nodes').innerHTML='<table><tr><th>Node</th><th>Role</th><th>Objects</th><th>Load</th><th>Memory</th></tr>'+d.nodes.map(n=>`<tr><td>${n.node_id}</td><td>${n.role}</td><td>${fmt(n.objects)}</td><td>${n.system.load1.toFixed(2)}</td><td>${bytes(n.system.mem_available_bytes)}</td></tr>`).join('')+'</table>'}catch(e){q('#status').textContent='error';}}
async function objects(){let p=encodeURIComponent(q('#prefix').value);let d=await api('/ui/api/objects?prefix='+p);q('#objects').innerHTML='<table><tr><th>Key</th><th>Bytes</th><th>Version</th><th>EC</th></tr>'+d.map(o=>`<tr><td><button class=obj data-k="${encodeURIComponent(o.key)}">${o.key}</button></td><td>${bytes(o.bytes)}</td><td>${o.version}</td><td>${o.erasure_scheme} ${o.data_shards}+${o.parity_shards}</td></tr>`).join('')+'</table>';document.querySelectorAll('.obj').forEach(b=>b.addEventListener('click',()=>detail(decodeURIComponent(b.dataset.k))))}
async function detail(k){let d=await api('/ui/api/object/'+k.split('/').map(encodeURIComponent).join('/'));q('#objectDetail').innerHTML=`<div class=row><span class=badge>${d.manifest.erasure_scheme}</span><b>${d.manifest.key}</b><span>${bytes(d.manifest.bytes)}</span></div><h3>Chunks / localities</h3><table><tr><th>Chunk</th><th>Host</th><th>Rack / Site</th><th>Disk</th><th>Health</th></tr>`+d.chunks.flatMap(c=>c.replicas.map(r=>`<tr><td>${c.chunk}</td><td>${r.host}</td><td>${r.rack||'-'} / ${r.site||'-'}</td><td>${r.disk}</td><td>${r.health}</td></tr>`)).join('')+'</table><h3>Pending operations</h3><pre>'+JSON.stringify(d.pending_operations,null,2)+'</pre><h3>Manifest</h3><pre>'+JSON.stringify(d.manifest,null,2)+'</pre>'}
async function buckets(){let d=await api('/ui/api/buckets');q('#buckets').innerHTML='<table><tr><th>Name</th><th>WORM</th><th>Versioning</th></tr>'+Object.values(d).map(b=>`<tr><td>${b.name}</td><td>${b.default_worm.mode}${b.default_worm.legal_hold?' + hold':''}</td><td>${b.versioning}</td></tr>`).join('')+'</table>'}
async function saveBucket(){let body={name:q('#bucketName').value,default_worm:{mode:q('#wormMode').value,retain_until_unix_ms:q('#retainMs').value?Number(q('#retainMs').value):null,legal_hold:q('#legalHold').checked},versioning:q('#versioning').checked,tags:{}};await api('/ui/api/buckets',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});buckets()}
async function logs(){let d=await api('/ui/api/logs?scope='+q('#logScope').value);q('#logs').textContent=d.lines.join('\n')}
async function securityAudit(){try{const d=await api('/v1/monitor/audit');q('#auditFindings').textContent=d.findings.map(f=>f.severity.toUpperCase()+' · '+f.resource+' · '+f.message+'\n'+f.recommendation).join('\n\n')}catch(e){q('#auditFindings').textContent=e.message}}
q('#refreshAudit').addEventListener('click',securityAudit);
const eventSource=new EventSource('/v1/monitor/stream');
eventSource.addEventListener('kagi',e=>{const d=JSON.parse(e.data),el=q('#securityEvents');el.textContent=(el.textContent+'\n'+d.severity+' '+d.category+' '+d.resource+' '+d.message).split('\n').slice(-100).join('\n')});
eventSource.addEventListener('gap',e=>{q('#securityEvents').textContent+='\nEvent gap: '+e.data});
document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('section[data-page]').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelector(`[data-page="${b.dataset.tab}"]`).classList.add('active');if(b.dataset.tab==='buckets')buckets();if(b.dataset.tab==='logs')logs();if(b.dataset.tab==='security')securityAudit();}));q('#search').addEventListener('click',objects);q('#saveBucket').addEventListener('click',saveBucket);q('#refreshLogs').addEventListener('click',logs);overview();setInterval(overview,2000);setInterval(()=>{if(document.querySelector('[data-page=\"logs\"]')?.classList.contains('active'))logs()},2000);
</script></body></html>"###;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_userdb_hashes_and_authenticates() {
        let p = std::env::temp_dir().join(format!("kagi-userdb-{}.yaml", std::process::id()));
        let _ = fs::remove_file(&p);
        upsert_user(
            &p,
            "alice",
            "correct horse battery staple",
            ConsoleRole::Admin,
        )
        .unwrap();
        let raw = B64.encode("alice:correct horse battery staple");
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {raw}").parse().unwrap(),
        );
        let id = authenticate_basic(&h, &p, true).unwrap();
        assert_eq!(id.username, "alice");
        let _ = fs::remove_file(&p);
    }
}
