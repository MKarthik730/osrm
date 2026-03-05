"""
Void Tracker — Web Server + Dashboard
Appended to void_tracker.py — run this file directly.
"""

import asyncio, json, socket, sys, os, time, logging
log = logging.getLogger("Void.Server")

try:
    import websockets
except ImportError:
    print("pip install websockets"); sys.exit(1)

# Import tracker engine
sys.path.insert(0, os.path.dirname(__file__))
from void_tracker import VoidTracker, HTTP_PORT, WS_PORT

TRACKER = VoidTracker()

# ─────────────────────────────────────────────
#  Dashboard HTML
# ─────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Void — LAN Tracker</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#07090c;--s:#0d1117;--s2:#111820;--b:#1a2535;--a:#0ea5e9;--a2:#06b6d4;--g:#22c55e;--r:#ef4444;--y:#f59e0b;--p:#a855f7;--t:#e2e8f0;--d:#475569}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:'Syne',sans-serif;min-height:100vh;overflow-x:hidden}

/* ── TOPBAR ── */
.top{display:flex;align-items:center;gap:12px;padding:12px 24px;border-bottom:1px solid var(--b);background:rgba(13,17,23,.95);position:sticky;top:0;z-index:100;backdrop-filter:blur(16px)}
.logo{font-size:22px;font-weight:800;color:var(--a);letter-spacing:-.02em}
.tag{font-family:'Share Tech Mono';font-size:10px;padding:2px 8px;border-radius:2px;border:1px solid}
.tag-blue{color:var(--a);border-color:rgba(14,165,233,.3);background:rgba(14,165,233,.08)}
.tag-green{color:var(--g);border-color:rgba(34,197,94,.3);background:rgba(34,197,94,.08)}
.tag-red{color:var(--r);border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.08)}
.tag-yellow{color:var(--y);border-color:rgba(245,158,11,.3);background:rgba(245,158,11,.08)}
.sp{flex:1}
.top-btn{font-family:'Share Tech Mono';font-size:11px;padding:5px 12px;border-radius:3px;border:1px solid var(--b);background:transparent;color:var(--d);cursor:pointer;transition:all .2s}
.top-btn:hover{border-color:var(--a);color:var(--a)}

/* ── STATS STRIP ── */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;background:var(--b);border-bottom:1px solid var(--b)}
.stat{background:var(--s);padding:14px 20px}
.stat-l{font-family:'Share Tech Mono';font-size:9px;color:var(--d);letter-spacing:.1em;margin-bottom:4px}
.stat-v{font-size:24px;font-weight:800}
.stat-v.blue{color:var(--a)}.stat-v.green{color:var(--g)}.stat-v.red{color:var(--r)}.stat-v.yellow{color:var(--y)}

/* ── LAYOUT ── */
.layout{display:grid;grid-template-columns:1fr 340px;height:calc(100vh - 101px)}
@media(max-width:900px){.layout{grid-template-columns:1fr}.sidebar{display:none}}

/* ── DEVICE LIST ── */
.main{overflow-y:auto;padding:16px}
.sh{font-family:'Share Tech Mono';font-size:10px;color:var(--a);letter-spacing:.15em;margin-bottom:10px;display:flex;align-items:center;gap:10px}
.sh::after{content:'';flex:1;height:1px;background:linear-gradient(to right,var(--b),transparent)}

.filters{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.filter-btn{font-family:'Share Tech Mono';font-size:10px;padding:4px 12px;border-radius:20px;border:1px solid var(--b);background:transparent;color:var(--d);cursor:pointer;transition:all .2s}
.filter-btn.active{background:var(--a);color:#000;border-color:var(--a)}
.search{font-family:'Share Tech Mono';font-size:11px;flex:1;min-width:180px;background:var(--s2);border:1px solid var(--b);color:var(--t);padding:5px 12px;border-radius:20px;outline:none}
.search:focus{border-color:var(--a)}

.dlist{display:flex;flex-direction:column;gap:6px}

.dcard{background:var(--s);border:1px solid var(--b);border-radius:6px;padding:12px 14px;display:grid;grid-template-columns:36px 1fr auto;gap:10px;align-items:center;cursor:pointer;transition:all .2s;animation:fadeUp .25s ease}
.dcard:hover{border-color:rgba(14,165,233,.4);background:var(--s2)}
.dcard.selected{border-color:var(--a);background:rgba(14,165,233,.06)}
.dcard.offline{opacity:.45}
.dcard.rogue{border-color:rgba(239,68,68,.5);animation:rogueFlash 2s ease infinite}
@keyframes rogueFlash{0%,100%{border-color:rgba(239,68,68,.5)}50%{border-color:var(--r)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}

.d-icon{font-size:22px;text-align:center}
.d-name{font-weight:700;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.d-meta{font-family:'Share Tech Mono';font-size:9px;color:var(--d);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.d-right{text-align:right;min-width:100px}
.d-speed{font-family:'Share Tech Mono';font-size:10px}
.d-speed.down{color:var(--g)}.d-speed.up{color:var(--a)}
.d-dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-left:6px}
.d-dot.on{background:var(--g);box-shadow:0 0 6px var(--g)}
.d-dot.off{background:var(--d)}

/* ── SIDEBAR ── */
.sidebar{border-left:1px solid var(--b);overflow-y:auto;background:var(--s)}
.panel{padding:16px}
.panel-title{font-family:'Share Tech Mono';font-size:10px;color:var(--a);letter-spacing:.12em;margin-bottom:12px}

.detail-header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.detail-icon{font-size:32px}
.detail-name{font-size:16px;font-weight:800}
.detail-mac{font-family:'Share Tech Mono';font-size:10px;color:var(--d)}

.info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--b);font-size:12px}
.info-row:last-child{border:none}
.info-key{font-family:'Share Tech Mono';font-size:10px;color:var(--d)}
.info-val{font-size:11px;font-family:'Share Tech Mono';color:var(--t);text-align:right;max-width:180px;word-break:break-all}

.spark-wrap{margin:10px 0}
.spark-label{font-family:'Share Tech Mono';font-size:9px;color:var(--d);margin-bottom:3px}
canvas.spark{width:100%;height:40px;display:block}

.actions{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:14px}
.action-btn{font-family:'Share Tech Mono';font-size:10px;padding:7px;border-radius:4px;border:1px solid var(--b);background:var(--s2);color:var(--t);cursor:pointer;text-align:center;transition:all .2s}
.action-btn:hover{border-color:var(--a);color:var(--a)}
.action-btn.danger:hover{border-color:var(--r);color:var(--r)}
.action-btn.success:hover{border-color:var(--g);color:var(--g)}

.label-input{width:100%;font-family:'Share Tech Mono';font-size:11px;background:var(--s2);border:1px solid var(--b);color:var(--t);padding:6px 10px;border-radius:4px;margin-top:8px;outline:none}
.label-input:focus{border-color:var(--a)}

.evlog{margin-top:10px;max-height:180px;overflow-y:auto}
.ev{font-family:'Share Tech Mono';font-size:10px;padding:4px 0;border-bottom:1px solid var(--b);display:flex;gap:8px}
.ev-ts{color:var(--d);min-width:60px}
.ev-kind{color:var(--a)}
.ev-kind.offline{color:var(--r)}.ev-kind.online{color:var(--g)}.ev-kind.discovered{color:var(--y)}

/* ── ALERTS ── */
.alert-banner{position:fixed;top:60px;right:16px;z-index:999;display:flex;flex-direction:column;gap:6px;pointer-events:none}
.alert{background:var(--s2);border:1px solid var(--r);border-radius:6px;padding:10px 14px;font-size:12px;animation:slideAlert .3s ease;pointer-events:all;max-width:300px}
@keyframes slideAlert{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
.alert-title{font-weight:700;color:var(--r);margin-bottom:3px}
.alert-body{font-family:'Share Tech Mono';font-size:10px;color:var(--d)}

/* ── EMPTY ── */
.empty{text-align:center;padding:60px 20px;font-family:'Share Tech Mono';color:var(--d)}
.dot{animation:blink 1.2s ease infinite;display:inline-block}
.dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,80%,100%{opacity:.2}40%{opacity:1}}
</style>
</head>
<body>

<!-- Top bar -->
<div class="top">
  <div class="logo">▸▸ VOID</div>
  <span class="tag tag-blue">LAN TRACKER</span>
  <span class="sp"></span>
  <button class="top-btn" onclick="scanNow()">⟳ Scan Now</button>
  <button class="top-btn" onclick="exportJSON()">↓ Export</button>
  <span id="wsTag" class="tag tag-red">● CONNECTING</span>
</div>

<!-- Stats strip -->
<div class="stats">
  <div class="stat"><div class="stat-l">TOTAL DEVICES</div><div class="stat-v blue" id="sTotal">—</div></div>
  <div class="stat"><div class="stat-l">ONLINE NOW</div><div class="stat-v green" id="sOnline">—</div></div>
  <div class="stat"><div class="stat-l">OFFLINE</div><div class="stat-v red" id="sOffline">—</div></div>
  <div class="stat"><div class="stat-l">DOWNLOAD</div><div class="stat-v blue" id="sTotalDown">—</div></div>
  <div class="stat"><div class="stat-l">UPLOAD</div><div class="stat-v blue" id="sTotalUp">—</div></div>
  <div class="stat"><div class="stat-l">LAST SCAN</div><div class="stat-v" style="font-size:14px;color:var(--d)" id="sTime">—</div></div>
</div>

<!-- Main layout -->
<div class="layout">

  <!-- Device list -->
  <div class="main">
    <div class="sh">▸ DEVICES</div>
    <div class="filters">
      <button class="filter-btn active" onclick="setFilter('all',this)">All</button>
      <button class="filter-btn" onclick="setFilter('online',this)">Online</button>
      <button class="filter-btn" onclick="setFilter('offline',this)">Offline</button>
      <button class="filter-btn" onclick="setFilter('rogue',this)">⚠ Unknown</button>
      <input class="search" id="search" placeholder="Search name, IP, MAC, vendor..." oninput="renderList()">
    </div>
    <div class="dlist" id="dlist">
      <div class="empty">Scanning your network<span class="dot">.</span><span class="dot">.</span><span class="dot">.</span></div>
    </div>
  </div>

  <!-- Sidebar detail -->
  <div class="sidebar" id="sidebar">
    <div class="panel">
      <div class="panel-title">▸ SELECT A DEVICE</div>
      <div style="font-family:'Share Tech Mono';font-size:11px;color:var(--d)">
        Click any device to see full details, history, and controls.
      </div>
    </div>
  </div>
</div>

<!-- Alert banners -->
<div class="alert-banner" id="alertBanner"></div>

<script>
const WS = `ws://${location.hostname}:__WS_PORT__`;
let ws, allDevices=[], filter='all', selected=null, trusted=new Set();

// ── WebSocket ───────────────────────────────
function connect(){
  ws = new WebSocket(WS);
  ws.onopen = ()=>{ document.getElementById('wsTag').className='tag tag-green'; document.getElementById('wsTag').textContent='● LIVE'; };
  ws.onmessage = e=>{
    const d = JSON.parse(e.data);
    if(d.type==='update') onUpdate(d);
    else if(d.type==='cmd_resp') console.log('cmd resp',d);
  };
  ws.onclose = ()=>{ document.getElementById('wsTag').className='tag tag-red'; document.getElementById('wsTag').textContent='● DISCONNECTED'; setTimeout(connect,3000); };
  ws.onerror = ()=>ws.close();
}

function send(obj){ if(ws && ws.readyState===1) ws.send(JSON.stringify(obj)); }

// ── Data update ─────────────────────────────
function onUpdate(d){
  allDevices = d.devices;
  document.getElementById('sTotal').textContent   = d.total;
  document.getElementById('sOnline').textContent  = d.online;
  document.getElementById('sOffline').textContent = d.offline;
  document.getElementById('sTotalDown').textContent = fmt(d.total_in);
  document.getElementById('sTotalUp').textContent   = fmt(d.total_out);
  document.getElementById('sTime').textContent = new Date().toLocaleTimeString();

  renderList();
  if(selected) updateSidebar(allDevices.find(x=>x.mac===selected));

  // Show alerts for new unknown devices
  if(d.alerts) d.alerts.forEach(showAlert);
}

// ── Render device list ──────────────────────
let filterMode = 'all';
function setFilter(f, btn){
  filterMode = f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderList();
}

function renderList(){
  const q = document.getElementById('search').value.toLowerCase();
  let devs = [...allDevices];

  // Filter
  if(filterMode==='online')  devs = devs.filter(d=>d.online);
  if(filterMode==='offline') devs = devs.filter(d=>!d.online);
  if(filterMode==='rogue')   devs = devs.filter(d=>!trusted.has(d.mac));

  // Search
  if(q) devs = devs.filter(d=>
    (d.name+d.ip+d.mac+d.vendor+d.hostname).toLowerCase().includes(q)
  );

  // Sort: online first, then by speed
  devs.sort((a,b)=>{
    if(a.online!==b.online) return b.online-a.online;
    return (b.speed_in+b.speed_out)-(a.speed_in+a.speed_out);
  });

  const list = document.getElementById('dlist');
  if(!devs.length){
    list.innerHTML='<div class="empty">No devices found</div>';
    return;
  }

  list.innerHTML = devs.map(d=>{
    const rogue = !trusted.has(d.mac) && d.first_seen > Date.now()/1000-300;
    return `
    <div class="dcard ${d.online?'':'offline'} ${rogue?'rogue':''} ${selected===d.mac?'selected':''}"
         onclick="selectDevice('${d.mac}')">
      <div class="d-icon">${d.icon}</div>
      <div>
        <div class="d-name">${d.label||d.name} ${rogue?'<span style="color:var(--r);font-size:10px">⚠ UNKNOWN</span>':''}</div>
        <div class="d-meta">${d.ip} · ${d.mac} · ${d.vendor||'Unknown vendor'}</div>
        <div class="d-meta">${d.os_guess?'OS: '+d.os_guess+' · ':''} Sessions: ${d.session_count} · Uptime: ${d.uptime_pct}%</div>
      </div>
      <div class="d-right">
        <span class="d-dot ${d.online?'on':'off'}"></span>
        <div class="d-speed down">↓ ${fmt(d.speed_in)}</div>
        <div class="d-speed up">↑ ${fmt(d.speed_out)}</div>
      </div>
    </div>`;
  }).join('');
}

// ── Device detail sidebar ───────────────────
function selectDevice(mac){
  selected = mac;
  renderList();
  const d = allDevices.find(x=>x.mac===mac);
  if(d) updateSidebar(d);
}

function updateSidebar(d){
  if(!d) return;
  const sb = document.getElementById('sidebar');
  sb.innerHTML = `
  <div class="panel">
    <div class="panel-title">▸ DEVICE DETAIL</div>
    <div class="detail-header">
      <div class="detail-icon">${d.icon}</div>
      <div>
        <div class="detail-name">${d.label||d.name}</div>
        <div class="detail-mac">${d.mac}</div>
      </div>
    </div>

    <div class="info-row"><span class="info-key">STATUS</span>
      <span class="info-val" style="color:${d.online?'var(--g)':'var(--r)'}">
        ${d.online?'● ONLINE':'○ OFFLINE'}</span></div>
    <div class="info-row"><span class="info-key">IP ADDRESS</span><span class="info-val">${d.ip||'—'}</span></div>
    <div class="info-row"><span class="info-key">HOSTNAME</span><span class="info-val">${d.hostname||'—'}</span></div>
    <div class="info-row"><span class="info-key">VENDOR</span><span class="info-val">${d.vendor||'Unknown'}</span></div>
    <div class="info-row"><span class="info-key">OS</span><span class="info-val">${d.os_guess||'—'}</span></div>
    <div class="info-row"><span class="info-key">OPEN PORTS</span>
      <span class="info-val">${d.open_ports.length?d.open_ports.join(', '):'—'}</span></div>
    <div class="info-row"><span class="info-key">SERVICES</span>
      <span class="info-val">${Object.values(d.services).join(', ')||'—'}</span></div>
    <div class="info-row"><span class="info-key">SESSIONS</span><span class="info-val">${d.session_count}</span></div>
    <div class="info-row"><span class="info-key">UPTIME</span><span class="info-val">${d.uptime_pct}%</span></div>
    <div class="info-row"><span class="info-key">FIRST SEEN</span><span class="info-val">${fmtTs(d.first_seen)}</span></div>
    <div class="info-row"><span class="info-key">LAST SEEN</span><span class="info-val">${fmtTs(d.last_seen)}</span></div>
    <div class="info-row"><span class="info-key">DOWNLOAD</span><span class="info-val" style="color:var(--g)">${fmtBytes(d.bytes_in)}</span></div>
    <div class="info-row"><span class="info-key">UPLOAD</span><span class="info-val" style="color:var(--a)">${fmtBytes(d.bytes_out)}</span></div>

    <div class="spark-wrap">
      <div class="spark-label">↓ DOWNLOAD SPEED</div>
      <canvas class="spark" id="sp-down" height="40"></canvas>
      <div class="spark-label" style="margin-top:6px">↑ UPLOAD SPEED</div>
      <canvas class="spark" id="sp-up" height="40"></canvas>
    </div>

    <div class="panel-title" style="margin-top:12px">▸ LABEL THIS DEVICE</div>
    <input class="label-input" id="labelInput" placeholder="Custom name..." value="${d.label||''}"
      onkeydown="if(event.key==='Enter')saveLabel('${d.mac}')">

    <div class="actions">
      <button class="action-btn success" onclick="trustDevice('${d.mac}')">✓ Trust</button>
      <button class="action-btn danger"  onclick="untrustDevice('${d.mac}')">✗ Untrust</button>
      <button class="action-btn" onclick="wol('${d.mac}')">⚡ Wake</button>
      <button class="action-btn" onclick="saveLabel('${d.mac}')">💾 Save Label</button>
    </div>

    <div class="panel-title" style="margin-top:14px">▸ EVENT LOG</div>
    <div class="evlog">
      ${(d.events||[]).slice().reverse().map(e=>`
        <div class="ev">
          <span class="ev-ts">${fmtTs(e.ts,true)}</span>
          <span class="ev-kind ${e.kind}">${e.kind}</span>
          <span style="color:var(--d)">${e.detail||''}</span>
        </div>`).join('')||'<div style="font-family:Share Tech Mono;font-size:10px;color:var(--d)">No events yet</div>'}
    </div>
  </div>`;

  // Draw sparklines
  setTimeout(()=>{
    drawSpark('sp-down', d.history_in,  '#22c55e');
    drawSpark('sp-up',   d.history_out, '#0ea5e9');
  }, 10);
}

function drawSpark(id, data, color){
  const c = document.getElementById(id);
  if(!c||!data||data.length<2) return;
  c.width = c.offsetWidth;
  const ctx = c.getContext('2d');
  ctx.clearRect(0,0,c.width,c.height);
  const max = Math.max(...data,1);
  const w = c.width/(data.length-1);
  // Fill
  ctx.beginPath();
  ctx.moveTo(0,c.height);
  data.forEach((v,i)=>ctx.lineTo(i*w, c.height-(v/max)*c.height*.9));
  ctx.lineTo((data.length-1)*w,c.height);
  ctx.closePath();
  ctx.fillStyle=color+'22';
  ctx.fill();
  // Line
  ctx.beginPath();
  ctx.strokeStyle=color; ctx.lineWidth=1.5;
  data.forEach((v,i)=>{ const x=i*w,y=c.height-(v/max)*c.height*.9; i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
  ctx.stroke();
}

// ── Actions ──────────────────────────────────
function saveLabel(mac){ send({action:'label',mac,label:document.getElementById('labelInput').value}); }
function trustDevice(mac){ trusted.add(mac); send({action:'trust',mac}); renderList(); }
function untrustDevice(mac){ trusted.delete(mac); send({action:'untrust',mac}); renderList(); }
function wol(mac){ send({action:'wol',mac}); showToast('⚡ Magic packet sent!'); }
function scanNow(){ send({action:'scan_now'}); showToast('⟳ Scanning...'); }
function exportJSON(){
  const blob=new Blob([JSON.stringify(allDevices,null,2)],{type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download='void_devices.json'; a.click();
}

// ── Alerts ───────────────────────────────────
const shownAlerts = new Set();
function showAlert(a){
  const key = a.mac+a.ts;
  if(shownAlerts.has(key)) return;
  shownAlerts.add(key);
  const banner = document.getElementById('alertBanner');
  const el = document.createElement('div');
  el.className = 'alert';
  el.innerHTML = `<div class="alert-title">🚨 NEW UNKNOWN DEVICE</div>
    <div class="alert-body">${a.name} · ${a.ip}<br>${a.mac} · ${a.vendor||'Unknown vendor'}</div>`;
  banner.appendChild(el);
  setTimeout(()=>el.remove(), 8000);
}

function showToast(msg){
  const banner = document.getElementById('alertBanner');
  const el = document.createElement('div');
  el.className='alert'; el.style.borderColor='var(--a)';
  el.innerHTML=`<div class="alert-body" style="color:var(--t)">${msg}</div>`;
  banner.appendChild(el);
  setTimeout(()=>el.remove(),3000);
}

// ── Formatters ───────────────────────────────
function fmt(b){ if(b<1024) return b+'B/s'; if(b<1048576) return (b/1024).toFixed(1)+'KB/s'; return (b/1048576).toFixed(2)+'MB/s'; }
function fmtBytes(b){ if(b<1024) return b+'B'; if(b<1048576) return (b/1024).toFixed(1)+'KB'; if(b<1073741824) return (b/1048576).toFixed(2)+'MB'; return (b/1073741824).toFixed(2)+'GB'; }
function fmtTs(ts,short=false){
  if(!ts) return '—';
  const d=new Date(ts*1000);
  return short ? d.toLocaleTimeString() : d.toLocaleString();
}

connect();
</script>
</body>
</html>"""

# ─────────────────────────────────────────────
#  HTTP + WebSocket servers
# ─────────────────────────────────────────────

async def http_handler(reader, writer):
    try:
        await reader.read(4096)
        html = HTML.replace("__WS_PORT__", str(WS_PORT))
        body = html.encode()
        writer.write(
            f"HTTP/1.1 200 OK\r\nContent-Type:text/html;charset=utf-8\r\n"
            f"Content-Length:{len(body)}\r\nConnection:close\r\n\r\n".encode() + body
        )
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def ws_handler(websocket):
    TRACKER._ws_clients.add(websocket)
    log.info("Browser connected  (%d clients)", len(TRACKER._ws_clients))
    try:
        await websocket.send(TRACKER._snapshot())
        async for msg in websocket:
            try:
                cmd  = json.loads(msg)
                resp = await TRACKER.handle_command(cmd)
                await websocket.send(json.dumps({"type":"cmd_resp","result":resp}))
            except Exception as e:
                log.error("WS cmd error: %s", e)
    except Exception:
        pass
    finally:
        TRACKER._ws_clients.discard(websocket)
        log.info("Browser disconnected  (%d clients)", len(TRACKER._ws_clients))

async def main():
    my_ip = socket.gethostbyname(socket.gethostname())
    print(f"""
  ██╗   ██╗ ██████╗ ██╗██████╗     ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗
  ██║   ██║██╔═══██╗██║██╔══██╗    ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
  ██║   ██║██║   ██║██║██║  ██║       ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
  ╚██╗ ██╔╝██║   ██║██║██║  ██║       ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
   ╚████╔╝ ╚██████╔╝██║██████╔╝       ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
    ╚═══╝   ╚═════╝ ╚═╝╚═════╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
""")
    await TRACKER.start()

    http  = await asyncio.start_server(http_handler, "0.0.0.0", HTTP_PORT)
    wss   = await websockets.serve(ws_handler, "0.0.0.0", WS_PORT)

    log.info("━"*60)
    log.info("Dashboard  →  http://localhost:%d", HTTP_PORT)
    log.info("LAN access →  http://%s:%d", my_ip, HTTP_PORT)
    log.info("Tracking   →  %d known device(s)", len(TRACKER.devices))
    log.info("Subnet     →  %s", TRACKER.subnet)
    log.info("━"*60)

    await asyncio.gather(http.serve_forever(), wss.wait_closed())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
