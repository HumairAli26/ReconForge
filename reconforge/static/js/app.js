// ReconForge v4 — Frontend Controller
// Key fixes: background scan polling, dual engine, non-blocking UI

const API = '';
let devices       = [];
let selectedDev   = null;
let logCount      = 0;
let activeEngine  = 'msf';
let netScanTimer  = null;
let portScanTimer = {};

const $ = id => document.getElementById(id);

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  startBgCanvas();
  detectSubnet();
  loadMsfModules();
  pollEngineStatus();   // polls both MSF + Nuclei every 5s
  log('info', 'ReconForge v4.0 initialised.');
  log('dim',  'Web app is fully functional while MSF boots in background.');
});

// ── Clock ─────────────────────────────────────────────────────────────────────
function startClock() {
  const tick = () => {
    const n = new Date();
    $('sys-time').textContent = n.toTimeString().slice(0,8);
    $('sys-date').textContent = n.toISOString().slice(0,10);
  };
  tick(); setInterval(tick, 1000);
}

// ── Particle canvas ───────────────────────────────────────────────────────────
function startBgCanvas() {
  const c = $('bg-canvas'); if (!c) return;
  const ctx = c.getContext('2d');
  let W, H, pts = [];
  const resize = () => { W = c.width = innerWidth; H = c.height = innerHeight; };
  resize(); addEventListener('resize', resize);
  for (let i = 0; i < 55; i++) pts.push({
    x: Math.random()*W, y: Math.random()*H,
    vx:(Math.random()-.5)*.25, vy:(Math.random()-.5)*.25, r:Math.random()*1.4+.3
  });
  const draw = () => {
    ctx.clearRect(0,0,W,H);
    pts.forEach(p => {
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<0)p.x=W; if(p.x>W)p.x=0;
      if(p.y<0)p.y=H; if(p.y>H)p.y=0;
      ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle='rgba(0,255,157,0.55)'; ctx.fill();
    });
    for(let i=0;i<pts.length;i++) for(let j=i+1;j<pts.length;j++){
      const dx=pts[i].x-pts[j].x, dy=pts[i].y-pts[j].y, d=Math.sqrt(dx*dx+dy*dy);
      if(d<120){ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);
        ctx.strokeStyle=`rgba(0,255,157,${.1*(1-d/120)})`;ctx.lineWidth=.5;ctx.stroke();}
    }
    requestAnimationFrame(draw);
  }; draw();
}

// ── Logger ────────────────────────────────────────────────────────────────────
function log(type, msg) {
  logCount++;
  $('log-count').textContent = `${logCount} entries`;
  const div = document.createElement('div');
  div.className = 'log-line';
  const ts = new Date().toTimeString().slice(0,8);
  const pre = {ok:'[+]',info:'[*]',warn:'[-]',err:'[!]',dim:'   ',nuc:'[N]'}[type]||'[*]';
  div.innerHTML = `<span class="log-ts">${ts}</span><span class="log-${type}">${pre} ${esc(msg)}</span>`;
  const b = $('console-out');
  b.appendChild(div);
  b.scrollTop = b.scrollHeight;
}
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
$('btn-clear-log').addEventListener('click', () => {
  $('console-out').innerHTML = ''; logCount = 0; $('log-count').textContent = '0 entries';
});

// ── Activity HUD ──────────────────────────────────────────────────────────────
function setActivity(label, state='idle') {
  $('act-label').textContent = label;
  const dot = $('act-dot');
  dot.className = 'act-dot';
  if (state === 'scan')   dot.classList.add('active');
  if (state === 'nuclei') dot.classList.add('nuclei-active');
}

// ── Subnet detect ─────────────────────────────────────────────────────────────
$('btn-detect').addEventListener('click', detectSubnet);
function detectSubnet() {
  fetch(`${API}/api/network/detect`)
    .then(r=>r.json())
    .then(d=>{ $('inp-subnet').value=d.network; log('ok',`Auto-detected: ${d.network}`); })
    .catch(()=>log('warn','Auto-detect failed — check Flask server.'));
}

// ── Engine selector ───────────────────────────────────────────────────────────
function switchEngine(eng) {
  activeEngine = eng;
  $('tab-msf').classList.toggle('active', eng==='msf');
  $('tab-nuclei').classList.toggle('active', eng==='nuclei');
  $('engine-msf-panel').style.display    = eng==='msf'    ? '' : 'none';
  $('engine-nuclei-panel').style.display = eng==='nuclei' ? '' : 'none';

  fetch(`${API}/api/engine/select`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({engine: eng})
  }).catch(()=>{});

  log('info', `Active engine → ${eng.toUpperCase()}`);
  updateExploitButton();
}

// ── Poll both engines every 5s ────────────────────────────────────────────────
function pollEngineStatus() {
  const check = () => {
    fetch(`${API}/api/engine/status`)
      .then(r=>r.json())
      .then(d=>{
        updateMsfUI(d.msf);
        updateNucleiUI(d.nuclei);
        updateExploitButton();
      })
      .catch(()=>{});
  };
  check(); setInterval(check, 5000);
}

function updateMsfUI(msf) {
  const dot   = $('msf-dot');
  const badge = $('msf-badge');
  const label = $('msf-label');
  const hint  = $('msf-hint');
  const was   = dot.classList.contains('ready');

  if (msf.available) {
    dot.className = 'status-dot ready';
    badge.className = 'status-badge badge-on'; badge.textContent = 'ONLINE';
    label.textContent = 'CONNECTED';
    hint.className = 'engine-hint ok'; hint.textContent = 'msfconsole ready ✓';
    if (!was) log('ok', 'Metasploit engine is ONLINE.');
  } else if (msf.installed) {
    dot.className = 'status-dot booting';
    badge.className = 'status-badge badge-boot'; badge.textContent = 'BOOTING';
    label.textContent = 'STARTING...';
    hint.className = 'engine-hint'; hint.textContent = 'msfdb + msfconsole starting (~30-120s)';
  } else {
    dot.className = 'status-dot offline';
    badge.className = 'status-badge badge-off'; badge.textContent = 'OFFLINE';
    label.textContent = 'NOT FOUND';
    hint.className = 'engine-hint err'; hint.textContent = 'Install Metasploit or use Nuclei engine';
    if (!was) log('warn', 'Metasploit not found — switch to Nuclei engine.');
  }
}

function updateNucleiUI(nuc) {
  const dot   = $('nuclei-dot');
  const badge = $('nuclei-badge');
  const label = $('nuclei-label');
  const hint  = $('nuclei-hint');

  if (nuc.available) {
    dot.className = 'status-dot online nuclei';
    badge.className = 'status-badge badge-nuc'; badge.textContent = 'READY';
    label.textContent = nuc.version || 'Installed';
    hint.className = 'engine-hint nuc'; hint.textContent = 'Instant-start • thousands of templates';
    $('btn-run-nuclei').disabled = !selectedDev;
  } else {
    dot.className = 'status-dot offline';
    badge.className = 'status-badge badge-off'; badge.textContent = 'OFFLINE';
    label.textContent = 'NOT INSTALLED';
    hint.className = 'engine-hint err'; hint.textContent = 'sudo apt install nuclei';
    $('btn-run-nuclei').disabled = true;
  }
}

function updateExploitButton() {
  const msfReady    = $('msf-dot').classList.contains('ready');
  const nucleiReady = $('nuclei-dot').classList.contains('online');
  $('btn-run-msf').disabled    = !(msfReady && selectedDev);
  $('btn-run-nuclei').disabled = !(nucleiReady && selectedDev);
}

// ── Load MSF modules ──────────────────────────────────────────────────────────
function loadMsfModules() {
  fetch(`${API}/api/msf/modules`)
    .then(r=>r.json())
    .then(data=>{
      const sel = $('msf-module-sel');
      sel.innerHTML = '<option value="">— select module —</option>';
      const cats = {};
      data.modules.forEach(m=>{
        if(!cats[m.category]) cats[m.category]=[];
        cats[m.category].push(m);
      });
      Object.entries(cats).forEach(([c,mods])=>{
        const g = document.createElement('optgroup'); g.label = c;
        mods.forEach(m=>{
          const o = document.createElement('option');
          o.value = m.key; o.textContent = m.key; g.appendChild(o);
        });
        sel.appendChild(g);
      });
      log('dim', `${data.modules.length} MSF modules loaded.`);
    }).catch(()=>{});
}

// ── Network Scan ──────────────────────────────────────────────────────────────
$('btn-scan-net').addEventListener('click', startNetScan);

function startNetScan() {
  const net = $('inp-subnet').value.trim();
  if (!net) return;

  log('info', `Starting host discovery on: ${net}`);
  setActivity('SWEEPING', 'scan');
  $('btn-scan-net').disabled = true;
  $('btn-scan-net').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> SCANNING...';
  $('net-progress-wrap').classList.remove('hidden');
  $('net-progress-fill').style.width = '0%';
  $('net-progress-label').textContent = 'Initialising...';
  devices = [];

  // Kick off background scan
  fetch(`${API}/api/scan/network`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({network: net})
  })
  .then(r=>r.json())
  .then(d=>{
    if (d.success || d.status === 'scanning') {
      // Poll progress
      netScanTimer = setInterval(pollNetScan, 1500);
    } else {
      log('err', d.error || 'Scan failed to start.');
      resetNetScanUI();
    }
  })
  .catch(e=>{ log('err', e.message); resetNetScanUI(); });
}

function pollNetScan() {
  fetch(`${API}/api/scan/network/status`)
    .then(r=>r.json())
    .then(d=>{
      const pct = d.total > 0 ? Math.round((d.progress/d.total)*100) : 0;
      $('net-progress-fill').style.width = pct + '%';
      $('net-progress-label').textContent = `${d.count} hosts found — ${pct}% complete`;

      // Add newly found devices
      if (d.devices && d.devices.length > devices.length) {
        const newDevs = d.devices.slice(devices.length);
        newDevs.forEach(dev => {
          devices.push(dev);
          log('dim', `  ${dev.ip.padEnd(16)} ${(dev.hostname||'Unknown').padEnd(24)} ${dev.vendor||''}`);
        });
        updateStats();
        if (typeof updateNetworkTopology === 'function') updateNetworkTopology(devices);
      }

      if (!d.scanning) {
        clearInterval(netScanTimer);
        devices = d.devices || devices;
        log('ok', `Sweep complete — ${devices.length} host(s) on the network.`);
        if (typeof updateNetworkTopology === 'function') updateNetworkTopology(devices);
        updateStats();
        resetNetScanUI();
        setActivity('IDLE', 'idle');
      }
    })
    .catch(()=>{});
}

function resetNetScanUI() {
  $('btn-scan-net').disabled = false;
  $('btn-scan-net').innerHTML = '<i class="fa-solid fa-radar"></i> DISCOVER HOSTS';
  setTimeout(()=>$('net-progress-wrap').classList.add('hidden'), 2000);
}

// ── Host card ─────────────────────────────────────────────────────────────────
window.showHostDetails = function(dev) {
  if (!dev || dev.ip === 'Gateway') {
    $('host-card').classList.add('hidden');
    selectedDev = null; updateExploitButton(); return;
  }
  selectedDev = dev;
  $('host-card').classList.remove('hidden');
  $('hc-ip').textContent     = dev.ip       || '—';
  $('hc-mac').textContent    = dev.mac       || '—';
  $('hc-host').textContent   = dev.hostname  || 'Unknown';
  $('hc-vendor').textContent = dev.vendor    || 'Unknown';
  $('hc-type').textContent   = dev.device_type || 'Unknown';

  const risk = dev.risk || 'Clean';
  const rb = $('hc-risk');
  rb.textContent = risk;
  rb.className = 'risk-badge ' + ({
    'Exploited':'risk-exp','Vulnerable':'risk-vuln',
    'Critical':'risk-crit','Open':'risk-vuln'
  }[risk] || 'risk-clean');

  // Ports
  const pb = $('ports-body');
  if (dev.open_ports?.length) {
    pb.innerHTML = dev.open_ports.map(p=>`
      <div class="port-row">
        <span class="port-n">${p}</span>
        <span class="port-s">${esc(dev.services?.[p]?.service||'?')}</span>
        <span class="port-b">${esc((dev.services?.[p]?.banner||'').slice(0,45))}</span>
      </div>`).join('');
  } else {
    pb.innerHTML = '<span class="dim-txt">No scan yet</span>';
  }

  // Vulns
  const vb = $('vulns-block');
  if (dev.vulns?.length) {
    vb.classList.remove('hidden');
    $('vulns-body').innerHTML = dev.vulns.map(v=>`
      <div class="vuln-row">
        <span class="vuln-sev sev-${v.severity?.toLowerCase()}">${(v.severity||'').toUpperCase()}</span>
        <span class="vuln-name">${esc(v.name)}</span>
        <span class="vuln-cve">${esc(v.cve||'')}</span>
      </div>`).join('');
  } else { vb.classList.add('hidden'); }

  // Nuclei findings
  const nb = $('nuclei-block');
  if (dev.nuclei_findings?.length) {
    nb.classList.remove('hidden');
    $('nuclei-body').innerHTML = dev.nuclei_findings.map(f=>`
      <div class="nuclei-row">
        <span class="vuln-sev sev-${f.severity}">${f.severity?.toUpperCase()}</span>
        <span class="vuln-name">${esc(f.name)}</span>
        <span class="vuln-cve">${esc(f.cve||'')}</span>
      </div>`).join('');
  } else { nb.classList.add('hidden'); }

  updateExploitButton();
};

$('btn-hc-close').addEventListener('click', ()=>{
  $('host-card').classList.add('hidden');
  selectedDev = null; updateExploitButton();
});

// ── Port scan — non-blocking with polling ─────────────────────────────────────
$('btn-scan-ports').addEventListener('click', startPortScan);

function startPortScan() {
  if (!selectedDev) return;
  const ip = selectedDev.ip;

  log('info', `Port scan starting on ${ip}...`);
  setActivity('PORT SCAN', 'scan');
  $('btn-scan-ports').disabled = true;
  $('btn-scan-ports').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> SCANNING...';
  $('port-progress-wrap').classList.remove('hidden');
  $('port-progress-fill').style.width = '5%';
  $('port-progress-label').textContent = 'Scanning ports...';

  fetch(`${API}/api/scan/ports`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ip})
  })
  .then(r=>r.json())
  .then(d=>{
    if (d.success || d.status === 'scanning') {
      // Animate progress while polling
      let pct = 10;
      const anim = setInterval(()=>{ pct = Math.min(pct+3,90); $('port-progress-fill').style.width=pct+'%'; }, 800);
      portScanTimer[ip] = setInterval(()=>pollPortScan(ip, anim), 1500);
    } else {
      log('err', d.error || 'Port scan failed.'); resetPortScanUI();
    }
  })
  .catch(e=>{ log('err', e.message); resetPortScanUI(); });
}

function pollPortScan(ip, animTimer) {
  fetch(`${API}/api/scan/ports/status?ip=${encodeURIComponent(ip)}`)
    .then(r=>r.json())
    .then(d=>{
      if (d.done) {
        clearInterval(portScanTimer[ip]);
        clearInterval(animTimer);
        $('port-progress-fill').style.width = '100%';

        if (d.device) {
          const dev = d.device;
          const idx = devices.findIndex(x=>x.ip===ip);
          if (idx!==-1) devices[idx]=dev; else devices.push(dev);
          if (selectedDev?.ip===ip) { selectedDev=dev; showHostDetails(dev); }
          if (typeof updateNetworkTopology==='function') updateNetworkTopology(devices);

          const op = (dev.open_ports||[]).length;
          const vn = (dev.vulns||[]).length;
          log('ok', `Port scan complete for ${ip} — ${op} open port(s), ${vn} vuln(s)`);
          updateStats();
        }
        setTimeout(()=>{ $('port-progress-wrap').classList.add('hidden'); }, 1500);
        resetPortScanUI();
        setActivity('IDLE','idle');
      }
    })
    .catch(()=>{});
}

function resetPortScanUI() {
  $('btn-scan-ports').disabled = false;
  $('btn-scan-ports').innerHTML = '<i class="fa-solid fa-circle-nodes"></i> SCAN PORTS';
}

// ── MSF exploit ───────────────────────────────────────────────────────────────
$('btn-run-msf').addEventListener('click', runMsf);

function runMsf() {
  const mod = $('msf-module-sel').value;
  if (!selectedDev || !mod) { log('warn','Select a target and module first.'); return; }
  const ip = selectedDev.ip;
  log('info', `MSF module [${mod}] → ${ip}`);
  $('btn-run-msf').disabled = true;
  $('btn-run-msf').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> RUNNING...';
  setActivity('EXPLOITING','scan');

  fetch(`${API}/api/msf/exploit`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ip, module:mod})
  })
  .then(r=>r.json())
  .then(d=>{
    $('btn-run-msf').disabled = false;
    $('btn-run-msf').innerHTML = '<i class="fa-solid fa-bolt-lightning"></i> RUN ASSESSMENT';
    setActivity('IDLE','idle');
    if (d.success) {
      log('ok', `Module complete: ${mod}`);
      if (d.output) d.output.split('\n').forEach(l=>l.trim()&&log('dim',l));
      const idx = devices.findIndex(x=>x.ip===ip);
      if (idx!==-1) { devices[idx].exploited=true; devices[idx].risk='Exploited'; }
      if (selectedDev?.ip===ip) showHostDetails(devices[idx]||selectedDev);
      if (typeof updateNetworkTopology==='function') updateNetworkTopology(devices);
    } else {
      log('err', `Module failed: ${d.error||'check MSF status'}`);
    }
  })
  .catch(e=>{ $('btn-run-msf').disabled=false; $('btn-run-msf').innerHTML='<i class="fa-solid fa-bolt-lightning"></i> RUN ASSESSMENT'; log('err',e.message); });
}

// ── Nuclei scan ───────────────────────────────────────────────────────────────
$('btn-run-nuclei').addEventListener('click', runNuclei);
$('btn-nuclei-update').addEventListener('click', ()=>{
  log('info','Updating Nuclei templates...');
  fetch(`${API}/api/nuclei/update`, {method:'POST'})
    .then(r=>r.json())
    .then(d=>d.success ? log('ok','Templates updated.') : log('err','Update failed.'))
    .catch(()=>log('err','Update request failed.'));
});

function runNuclei() {
  if (!selectedDev) { log('warn','Select a target first.'); return; }
  const ip   = selectedDev.ip;
  const sevs = $('nuclei-sev-sel').value;
  log('nuc', `Nuclei scan starting on ${ip}${sevs ? ` [${sevs}]` : ''}...`);
  $('btn-run-nuclei').disabled = true;
  $('btn-run-nuclei').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> SCANNING...';
  setActivity('NUCLEI SCAN','nuclei');

  fetch(`${API}/api/nuclei/scan`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ip, severities: sevs ? sevs.split(',') : null})
  })
  .then(r=>r.json())
  .then(d=>{
    $('btn-run-nuclei').disabled = false;
    $('btn-run-nuclei').innerHTML = '<i class="fa-solid fa-atom"></i> RUN NUCLEI SCAN';
    setActivity('IDLE','idle');
    if (d.success) {
      log('nuc', `Nuclei found ${d.count} finding(s) on ${ip}`);
      d.findings.forEach(f=>log('nuc', `  [${f.severity.toUpperCase()}] ${f.name} ${f.cve||''}`));
      const idx = devices.findIndex(x=>x.ip===ip);
      if (idx!==-1) {
        devices[idx].nuclei_findings = d.findings;
        if (d.count > 0) devices[idx].risk = d.findings.some(f=>f.severity==='critical') ? 'Critical' : 'Vulnerable';
        if (selectedDev?.ip===ip) showHostDetails(devices[idx]);
        if (typeof updateNetworkTopology==='function') updateNetworkTopology(devices);
      }
      updateStats();
    } else {
      log('err', d.error || 'Nuclei scan failed.');
    }
  })
  .catch(e=>{ $('btn-run-nuclei').disabled=false; $('btn-run-nuclei').innerHTML='<i class="fa-solid fa-atom"></i> RUN NUCLEI SCAN'; log('err',e.message); });
}

// ── Stats ─────────────────────────────────────────────────────────────────────
function updateStats() {
  $('s-hosts').textContent = devices.length;
  $('s-vuln').textContent  = devices.filter(d=>d.vulns?.length||d.nuclei_findings?.length).length;
  $('s-ports').textContent = devices.reduce((s,d)=>s+(d.open_ports||[]).length, 0);
  $('s-crit').textContent  = devices.reduce((s,d)=>s+(d.nuclei_findings||[]).filter(f=>f.severity==='critical').length, 0);
}

// ── Graceful shutdown ping when tab closes ────────────────────────────────────
window.addEventListener('beforeunload', () => {
  navigator.sendBeacon(`${API}/api/shutdown`, JSON.stringify({}));
});
